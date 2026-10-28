from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.interchange import ResultSelector, observation_metadata_from_mapping
from appsec_review.jobs.job_artifact_security_analysis.findings import scan_records
from appsec_review.jobs.job_artifact_security_analysis.scanners import parse_json, parse_spotbugs
from appsec_review.jobs.job_evidence_collection.adapters import adapter_registry
from appsec_review.jobs.job_evidence_collection.evidence import build_envelope
from appsec_review.observability.events import EventLog
from appsec_review.provenance import (
    artifact_reference, common_metadata, consume_native_references, json_selector,
    retain_native_output, select_native, validate_observation_provenance, verify_native_reference,
)
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json
from appsec_review.storage import shared


def make_owner(root: Path, number: int = 1) -> shared.SharedArtifacts:
    attempt = root / "data" / "jobs" / "job_fixture" / "attempts" / f"attempt_{number:04d}"
    claim = {"schema": "appsec-review/attempt-claim/1", "run_id": root.name, "job_id": "job_fixture",
             "attempt_id": attempt.name, "attempt_path": attempt.relative_to(root).as_posix(),
             "source_fingerprint": "a" * 64, "orchestration": {"system": "fixture", "run_id": str(number)},
             "dataset_contract": dataset_contract("job_fixture", ("work",), ())}
    atomic_json(attempt / "claim.json", claim)
    return shared.SharedArtifacts.for_job(SimpleNamespace(
        run_root=root, attempt_root=attempt, run_id=root.name, attempt_id=attempt.name,
        orchestration=claim["orchestration"], config=SimpleNamespace(job_id="job_fixture")))


@pytest.fixture
def owner(tmp_path, monkeypatch):
    value = make_owner(tmp_path)
    monkeypatch.setattr(shared, "current", lambda: value)
    return value


def retained(root: Path, payload: bytes, *, owner=None, complete=True, events=None):
    path = root / "report.bin"
    path.write_bytes(payload)
    execution = root / "execution.json"
    atomic_json(execution, {"status": "SUCCEEDED"})
    return retain_native_output(
        root, path, parser_identity="fixture-parser/1", complete=complete, native_result_count=1,
        owner=owner, execution_reference=shared.reference(root, execution), events=events)


def test_native_output_is_detached_and_old_bytes_survive_scope_report_overwrite(tmp_path, owner):
    native = retained(tmp_path, b'{"results":[{"id":"original"}]}')
    (tmp_path / "report.bin").write_bytes(b"overwritten mutable scanner scratch")
    selected = select_native(native, json_selector("results", 0))
    assert verify_native_reference(tmp_path, selected, resolve=True) == {"id": "original"}
    assert native.artifact.path == f"data/shared/objects/{native.artifact.sha256}"
    receipt = shared.verify_receipt(tmp_path, native.retention_receipt.as_dict())
    assert receipt["namespace"] == "native-output"
    assert native.execution_reference != native.retention_receipt
    assert receipt["computation"]["retained_bytes"] == native.artifact.size_bytes


def test_retention_reuse_preserves_original_computation_identity(tmp_path, owner):
    first = retained(tmp_path, b'{"a":1}')
    original = shared.verify_receipt(tmp_path, first.retention_receipt.as_dict())
    consumer = make_owner(tmp_path, 2)
    second = retained(tmp_path, b'{"a":1}', owner=consumer)
    reused = shared.verify_receipt(tmp_path, second.retention_receipt.as_dict())
    assert reused["mode"] == "reused"
    assert reused["computation"] == original["computation"]
    assert reused["producer_receipt"] == first.retention_receipt.as_dict()
    consumed = consume_native_references(tmp_path, [first.as_dict()], owner=consumer)
    assert shared.verify_receipt(tmp_path, consumed[0])["producer_receipt"] == first.retention_receipt.as_dict()


def test_native_reuse_counts_both_referenced_objects_and_bytes(tmp_path, owner, monkeypatch):
    from appsec_review import provenance
    native = retained(tmp_path, b'{"a":1}')
    counters = []
    monkeypatch.setattr(provenance, "count_work", lambda name, value=1: counters.append((name, value)))
    consume_native_references(tmp_path, [native.as_dict()], owner=make_owner(tmp_path, 2))
    assert counters == [("native_output_references", 1), ("native_output_bytes", native.artifact.size_bytes)]


@pytest.mark.parametrize("damage", ["tamper", "missing", "receipt", "execution"])
def test_native_verification_rejects_missing_or_tampered_bytes(tmp_path, owner, damage):
    native = retained(tmp_path, b'{"a":1}')
    target = tmp_path / native.artifact.path
    if damage == "missing":
        target.unlink()
    elif damage == "receipt":
        (tmp_path / native.retention_receipt.path).write_bytes(b"{}")
    elif damage == "execution":
        (tmp_path / native.execution_reference.path).write_bytes(b"{}")
    else:
        target.write_bytes(b'{"a":2}')
    with pytest.raises(ValueError):
        verify_native_reference(tmp_path, native)


@pytest.mark.parametrize("path", ["../escape.json", "/absolute.json", "data\\escape.json", "data/../escape.json"])
def test_pinned_native_identity_rejects_path_escape(tmp_path, path):
    with pytest.raises(ValueError):
        artifact_reference(tmp_path, {"path": path, "sha256": "a" * 64})


def test_native_identity_rejects_symlink_components_where_supported(tmp_path, owner):
    source = tmp_path / "source"
    source.mkdir()
    (source / "report").write_bytes(b"{}")
    link = tmp_path / "alias"
    try:
        link.symlink_to(source, target_is_directory=True)
    except OSError:
        pytest.skip("host cannot create symlinks")
    with pytest.raises(ValueError, match="symlink"):
        artifact_reference(tmp_path, {"path": "alias/report", "sha256": hashlib.sha256(b"{}").hexdigest()})


def test_pinned_hash_is_not_replaced_by_a_live_hash(tmp_path, owner):
    path = tmp_path / "native.json"
    path.write_bytes(b'{"changed":true}')
    with pytest.raises(ValueError, match="identity|mismatch"):
        retain_native_output(tmp_path, path, parser_identity="fixture/1", complete=True, native_result_count=1,
                             expected={"path": path.name, "sha256": "a" * 64})


def test_rfc6901_dynamic_php_keys_resolve_exactly(tmp_path, owner):
    key = "/target/a~b/c.php"
    document = {"files": {key: {"messages": [{"identifier": "bad", "message": "failure", "line": 2}]}}}
    payload = json.dumps(document).encode()
    record, = adapter_registry()["tool-phpstan"].parse(payload)
    native = retained(tmp_path, payload)
    selected = select_native(native, record["_native_selector"])
    assert selected.selector.value == "/files/~1target~1a~0b~1c.php/messages/0"
    assert verify_native_reference(tmp_path, selected, resolve=True)["identifier"] == "bad"


def test_json_pointer_array_indices_require_rfc6901_ascii_digits(tmp_path, owner):
    native = retained(tmp_path, b'{"results":[{"id":"one"}]}')
    with pytest.raises(ValueError, match="array index"):
        verify_native_reference(
            tmp_path, select_native(native, json_selector("results", "\u0660")), resolve=True)


@pytest.mark.parametrize("tool,payload,expected", [
    ("tool-semgrep", {"results": [{"check_id": "a"}, {"check_id": "b"}]}, "/results/1"),
    ("tool-grype", {"matches": [{"vulnerability": {"id": "a"}}, {"vulnerability": {"id": "b"}}]}, "/matches/1"),
    ("tool-osv-scanner", {"results": [{"packages": [{}, {"vulnerabilities": [{"id": "b"}]}]}]},
     "/results/0/packages/1/vulnerabilities/0"),
    ("tool-pmd", {"files": [{}, {"filename": "a.java", "violations": [{"rule": "b"}]}]},
     "/files/1/violations/0"),
    ("tool-gosec", {"Issues": [{"rule_id": "a"}, {"rule_id": "b"}]}, "/Issues/1"),
    ("tool-trivy", {"Results": [{}, {"Misconfigurations": [{"ID": "b"}]}]},
     "/Results/1/Misconfigurations/0"),
    ("tool-mobsfscan", {"results": {"r/~": {"files": [{"file_path": "one"}, {"file_path": "two"}]}}},
     "/results/r~1~0/files/1"),
    ("tool-checkov", [{}, {"results": {"failed_checks": [{"check_id": "b"}]}}],
     "/1/results/failed_checks/0"),
    ("tool-gitleaks", [{"RuleID": "a"}, {"RuleID": "b"}], "/1"),
    ("tool-shellcheck", {"comments": [{"code": 1071, "message": "unsupported shell"},
                                     {"code": 2086, "message": "quote"}]}, "/comments/1"),
])
def test_static_selectors_keep_original_result_ordinals(tmp_path, owner, tool, payload, expected):
    encoded = json.dumps(payload).encode()
    records = adapter_registry()[tool].parse(encoded)
    selector = records[-1]["_native_selector"]
    assert selector["value"] == expected
    native = retained(tmp_path, encoded)
    resolved = verify_native_reference(tmp_path, select_native(native, selector), resolve=True)
    assert isinstance(resolved, dict)


def test_xml_expanded_tag_and_original_matching_ordinal(tmp_path, owner):
    payload = (b'<BugCollection xmlns="urn:bugs"><BugInstance priority="3"/>'
               b'<BugInstance type="X" priority="1"><SourceLine sourcepath="A.java"/></BugInstance></BugCollection>')
    records = parse_spotbugs(payload)
    selector = records["findings"][1]["_native_selector"]
    assert selector == {"kind": "xml_ordinal", "value": {"element": "{urn:bugs}BugInstance", "ordinal": 1}}
    native = retained(tmp_path, payload)
    resolved = verify_native_reference(tmp_path, select_native(native, selector), resolve=True)
    assert resolved.get("type") == "X"
    static = adapter_registry()["tool-spotbugs"].parse(payload)
    assert static[1]["_native_selector"] == selector
    _, findings = scan_records({"capability": "spotbugs", "fingerprint": "a" * 64, "artifact": {},
                               "observation": records, "native_output": native.as_dict(), "gaps": []})
    finding, = findings
    assert finding.payload["common"]["observation_class"] == "source_sast"
    assert finding.payload["common"]["reported_severity"]["value"] == "high"
    assert finding.payload["common"]["evidence_refs"][0]["selector"] == selector


def test_byte_range_selectors_refer_to_actual_plain_output(tmp_path, owner):
    native = retained(tmp_path, b"one\ntwo\n")
    assert verify_native_reference(
        tmp_path, select_native(native, ResultSelector("byte_range", {"start": 4, "end": 7})), resolve=True) == b"two"
    with pytest.raises(ValueError, match="exceeds"):
        select_native(native, ResultSelector("byte_range", {"start": 0, "end": 99}))


def test_duplicate_collapse_merges_sorted_native_references_without_changing_semantic_identity(tmp_path, owner):
    native = retained(tmp_path, b'{"results":[{"id":"same"},{"id":"same"}]}')
    rows = [{"rule_id": "same", "severity": "surprising", "message": "same",
             "_native_refs": [select_native(native, json_selector("results", index)).as_dict()]}
            for index in (1, 0, 1)]
    envelope = build_envelope(
        tool={"id": "tool-semgrep"}, target_fingerprint="a" * 64, applicability={},
        coverage_scope={}, gaps=(), raw_artifacts=(), parser_identity="fixture/1",
        observations=rows, cataloged_paths=(), terminal_status="SUCCEEDED", run_root=tmp_path)
    row, = envelope["records"]
    metadata = observation_metadata_from_mapping(row["common"])
    assert metadata.reported_severity["value"] == "unknown"
    assert [ref.selector.value for ref in metadata.evidence_refs] == ["/results/0", "/results/1"]
    assert envelope["schema"].endswith("/2")


def test_provenance_events_are_ref_only_and_counts_are_hash_bound(tmp_path, owner):
    events = EventLog(tmp_path / "events.jsonl")
    native = retained(tmp_path, b'{"results":[{"secret":"never-in-events"}]}', events=events)
    reference = select_native(native, json_selector("results", 0)).as_dict()
    payload = {"tool_id": "tool-gitleaks", "native_rule_id": "leak", "category": "secret_detection"}
    payload["common"] = common_metadata(payload, evidence_refs=[reference], payload_schema="fixture/1")
    receipt = validate_observation_provenance(tmp_path, [payload], parser_identity="fixture/1", events=events)
    records = [json.loads(line) for line in events.path.read_text().splitlines()]
    assert [item["event"] for item in records] == ["NATIVE_OUTPUT_RETAINED", "OBSERVATION_PROVENANCE_VALIDATED"]
    assert all({key: record[key] for key in ("run_id", "job_id", "attempt_id")} == {
        key: owner.actor[key] for key in ("run_id", "job_id", "attempt_id")} for record in records)
    assert "never-in-events" not in events.path.read_text()
    proof = shared.verify_receipt(tmp_path, receipt)
    assert proof["computation"]["observation_count"] == 1
    assert proof["computation"]["native_reference_count"] == 1
    assert json.loads((tmp_path / proof["object"]["path"]).read_bytes()) == proof["computation"]


def test_batch_validation_parses_each_retained_document_only_once(tmp_path, owner, monkeypatch):
    native = retained(tmp_path, b'{"results":[{"id":1},{"id":2}]}')
    records = []
    for index in range(2):
        payload = {"tool_id": "fixture", "rule_id": "r"}
        payload["common"] = common_metadata(payload, evidence_refs=[
            select_native(native, json_selector("results", index)).as_dict()], payload_schema="fixture/1")
        records.append(payload)
    original = Path.read_bytes
    count = 0
    def read(path):
        nonlocal count
        if path == tmp_path / native.artifact.path:
            count += 1
        return original(path)
    monkeypatch.setattr(Path, "read_bytes", read)
    validate_observation_provenance(tmp_path, records, parser_identity="fixture/1")
    assert count == 1


def test_invalid_selector_fails_before_success_shaped_provenance_receipt(tmp_path, owner):
    native = retained(tmp_path, b'{"results":[]}')
    payload = {"tool_id": "fixture", "rule_id": "r"}
    payload["common"] = common_metadata(payload, evidence_refs=[
        select_native(native, json_selector("results", 2)).as_dict()], payload_schema="fixture/1")
    with pytest.raises(ValueError, match="resolve"):
        validate_observation_provenance(tmp_path, [payload], parser_identity="fixture/1")


def test_json_and_xml_parser_bounds_are_observable():
    bounded = parse_json(json.dumps({"matches": list(range(20_001)), "nested": {"message": "x" * 65_537}}).encode())
    assert bounded["_parser_truncated"]
    assert bounded["_parser_bounds"] == ["array_items", "string"]
    assert bounded["_native_result_count"] == 20_001
    xml = b"<BugCollection>" + b'<BugInstance type="X"/>' * 20_001 + b"</BugCollection>"
    parsed = parse_spotbugs(xml)
    assert parsed["_parser_truncated"] and parsed["finding_count_reported"] == 20_001


@pytest.mark.parametrize("packages", [None, "invalid", {}, [None, {"vulnerabilities": None}]])
def test_native_result_counts_handle_unknown_osv_shapes_without_inventing_findings(packages):
    observation = parse_json(json.dumps({"results": [{"packages": packages}]}).encode())
    assert observation["_native_result_count"] == 0
    summary, findings = scan_records({"capability": "osv", "fingerprint": "a" * 64, "artifact": {},
                                     "observation": observation, "gaps": []})
    assert not findings and summary.kind == "scan_summary"
    assert summary.payload["common"]["observation_class"] == "diagnostic"


def test_incomplete_retention_stays_incomplete_in_records_and_receipts(tmp_path, owner):
    native = retained(tmp_path, b'{"matches":[]}', complete=False)
    scan = {"capability": "grype", "fingerprint": "a" * 64, "artifact": {},
            "observation": {"matches": []}, "native_output": native.as_dict(),
            "gaps": ["truncated native input"]}
    summary, findings = scan_records(scan)
    assert not findings and summary.payload["finding_count"] == 0
    assert summary.payload["findings_complete"] is False
    assert summary.payload["common"]["evidence_refs"][0]["complete"] is False
    receipt = validate_observation_provenance(tmp_path, [summary.payload], parser_identity="fixture/1")
    proof = shared.verify_receipt(tmp_path, receipt)["computation"]
    assert not proof["complete"] and proof["truncated"]


def test_filtered_artifact_findings_keep_the_original_osv_selector(tmp_path, owner):
    document = {"results": [{"packages": [{"package": {"name": "p"}, "vulnerabilities": [
        {}, {"id": "CVE-real", "database_specific": {"severity": "HIGH"}}]}]}]}
    native = retained(tmp_path, json.dumps(document).encode())
    scan = {"capability": "osv", "fingerprint": "a" * 64, "artifact": {},
            "observation": document, "native_output": native.as_dict(), "gaps": []}
    summary, findings = scan_records(scan)
    assert len(findings) == 1 and summary.payload["finding_count"] == 1
    reference = findings[0].payload["common"]["evidence_refs"][0]
    assert reference["selector"]["value"] == "/results/0/packages/0/vulnerabilities/1"
    assert verify_native_reference(tmp_path, reference, resolve=True)["id"] == "CVE-real"


def test_no_native_input_is_an_explicit_provenance_gap_not_a_fabricated_reference():
    summary, findings = scan_records({"capability": "grype", "fingerprint": "a" * 64, "artifact": {},
                                     "observation": {"matches": []}, "gaps": ["scanner failed"]})
    assert not findings and summary.payload["common"]["gap_ids"]
    assert not summary.payload["common"]["evidence_refs"]


def test_partitioned_osv_invocations_keep_their_own_native_output_and_execution(tmp_path, owner):
    from appsec_review.jobs.job_evidence_collection.adapters import Applicability, ScanCatalog
    from appsec_review.jobs.job_evidence_collection.job import _Invocation, _run_invocation
    adapter = adapter_registry()["tool-osv-scanner"]
    unit_root = owner.attempt_root / "steps" / "vulnerability_matching" / "tasks" / "osv_scanner_scan"
    events = EventLog(owner.attempt_root / "events.jsonl")
    unit = SimpleNamespace(
        unit_id="vulnerability_matching.osv_scanner_scan", unit_root=unit_root,
        job=SimpleNamespace(run_root=tmp_path, run_id=tmp_path.name, attempt_id=owner.attempt_root.name,
                            target_root=tmp_path, tools=SimpleNamespace(enable_swift=False), events=events))
    class Executor:
        def execute(self, request):
            root = request.scratch_root
            root.mkdir(parents=True, exist_ok=True)
            advisory = "CVE-A" if "project-a" in request.argv[-1] else "CVE-B"
            atomic_json(root / "output.json", {"results": [{"packages": [{
                "package": {"name": advisory}, "vulnerabilities": [{"id": advisory}]}]}]})
            (root / "stdout.bin").write_bytes(b"")
            (root / "stderr.bin").write_bytes(b"")
            atomic_json(root / "execution.json", {"tool": "osv", "subject": advisory})
            return SimpleNamespace(
                stdout_path=(root / "stdout.bin").relative_to(tmp_path).as_posix(),
                stderr_path=(root / "stderr.bin").relative_to(tmp_path).as_posix(),
                receipt_path=(root / "execution.json").relative_to(tmp_path).as_posix(),
                stdout_truncated=False, stderr_truncated=False, timed_out=False, oom_killed=False, exit_code=0)
    catalog = ScanCatalog("a" * 64, "b" * 64, (), ())
    outcomes = []
    for index, project in enumerate(("project-a", "project-b")):
        selection = Applicability(True, "fixture", (f"{project}/Cargo.lock",), "lockfiles")
        outcomes.append(_run_invocation(
            unit, adapter, catalog, _Invocation(selection, (), project), index,
            executor=Executor(), tool=SimpleNamespace(name="osv", version="1", executable="/osv", output_bytes=4096),
            image_id="sha256:" + "a" * 64, fail_tool=None, retries=0, swift_present=False,
            environment={}, memory=None, input_identities={}))
    references = [outcome.observations[0]["_native_refs"][0] for outcome in outcomes]
    assert references[0]["artifact"] != references[1]["artifact"]
    assert references[0]["execution_reference"] != references[1]["execution_reference"]
    assert [verify_native_reference(tmp_path, ref, resolve=True)["id"] for ref in references] == ["CVE-A", "CVE-B"]
    assert all(ref["selector"]["value"] == "/results/0/packages/0/vulnerabilities/0" for ref in references)


@pytest.mark.parametrize("exit_code,timed_out", [(2, False), (0, True), (128, False)])
def test_static_failed_and_no_package_invocations_retain_exact_native_output(tmp_path, owner, exit_code, timed_out):
    from appsec_review.jobs.job_evidence_collection.adapters import Applicability, ScanCatalog
    from appsec_review.jobs.job_evidence_collection.job import _Invocation, _run_invocation
    adapter = adapter_registry()["tool-osv-scanner"]
    unit = SimpleNamespace(
        unit_id="vulnerability_matching.osv_scanner_scan",
        unit_root=owner.attempt_root / "steps" / "vulnerability_matching" / "tasks" / "osv_scanner_scan",
        job=SimpleNamespace(run_root=tmp_path, run_id=tmp_path.name, attempt_id=owner.attempt_root.name,
                            target_root=tmp_path, tools=SimpleNamespace(enable_swift=False),
                            events=EventLog(owner.attempt_root / "events.jsonl")))
    payload = b'{"results":[]}'
    class Executor:
        def execute(self, request):
            root = request.scratch_root
            root.mkdir(parents=True, exist_ok=True)
            (root / "output.json").write_bytes(payload)
            (root / "stdout.bin").write_bytes(b"")
            (root / "stderr.bin").write_bytes(
                b"Scanned /target/Cargo.lock file and found 0 packages\nNo package sources found")
            atomic_json(root / "execution.json", {"exit_code": exit_code, "timed_out": timed_out})
            return SimpleNamespace(
                stdout_path=(root / "stdout.bin").relative_to(tmp_path).as_posix(),
                stderr_path=(root / "stderr.bin").relative_to(tmp_path).as_posix(),
                receipt_path=(root / "execution.json").relative_to(tmp_path).as_posix(),
                stdout_truncated=False, stderr_truncated=False, timed_out=timed_out,
                oom_killed=False, exit_code=exit_code)
    outcome = _run_invocation(
        unit, adapter, ScanCatalog("a" * 64, "b" * 64, (), ()),
        _Invocation(Applicability(True, "fixture", ("Cargo.lock",), "lockfiles"), (), None), 0,
        executor=Executor(), tool=SimpleNamespace(name="osv", version="1", executable="/osv", output_bytes=4096),
        image_id="sha256:" + "a" * 64, fail_tool=None, retries=0, swift_present=False,
        environment={}, memory=None, input_identities={})
    native, = outcome.native_outputs
    assert (tmp_path / native["artifact"]["path"]).read_bytes() == payload
    assert native["complete"] is (exit_code == 128)
    assert native["execution_reference"] and native["retention_receipt"]
    assert not outcome.observations
    assert bool(outcome.not_applicable) is (exit_code == 128)


def test_static_source_hash_mismatch_rejects_even_cached_indexing(tmp_path, owner):
    from appsec_review.jobs.job_evidence_collection.job import _build_producer_shard
    target = tmp_path / "target"
    target.mkdir()
    source = target / "main.py"
    source.write_bytes(b"original\n")
    evidence_path = owner.attempt_root / "evidence.json"
    atomic_json(evidence_path, {"records": [{"evidence_id": "one", "native_rule_id": "r", "location": {
        "path": "main.py", "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "start_line": 1, "end_line": 1}}]})
    artifact = shared.reference(tmp_path, evidence_path)
    output = {"tool_id": "tool-semgrep", "normalized_artifact": artifact, "artifact": artifact,
              "terminal_status": "SUCCEEDED", "record_count": 1, "gaps": []}
    unit = SimpleNamespace(job=SimpleNamespace(
        run_root=tmp_path, target_root=target, source_fingerprint="a" * 64,
        events=EventLog(owner.attempt_root / "events.jsonl")),
        output=lambda _: output, unit_id="source_sast.semgrep_index")
    _build_producer_shard(unit, "source_sast.semgrep_normalize")
    source.write_bytes(b"changed!\n")
    with pytest.raises(ValueError, match="source hash differs"):
        _build_producer_shard(unit, "source_sast.semgrep_normalize")


def test_artifact_parser_input_is_retained_whole_not_as_diagnostic_head_tail(tmp_path, owner):
    from appsec_review.jobs.job_artifact_security_analysis.job import _scan_one
    path = tmp_path / "data" / "artifact.bin"
    path.write_bytes(b"\0asm\x01\0\0\0")
    artifact = {**shared.reference(tmp_path, path), "artifact_id": "artifact-one",
                "canonical_identity": "asr:wasm_module:one", "producer": {}, "kind": "wasm-module"}
    document = {"artifacts": [{"name": "pkg", "version": "1", "metadata": "x" * 200}]}
    payload = json.dumps(document).encode()
    settings = {"archive_member_limit": 10, "archive_expanded_bytes": 4096, "archive_member_bytes": 4096,
                "archive_ratio_limit": 10, "archive_depth_limit": 2, "scanner_identities": {"syft": "fixture/1"},
                "timeout_seconds": 10, "stream_limit_bytes": 32, "diagnostic_tail_bytes": 8,
                "parser_input_limit_bytes": 4096}
    unit = SimpleNamespace(
        unit_id="analyze.syft",
        job=SimpleNamespace(config=SimpleNamespace(settings=settings), run_root=tmp_path,
                            attempt_root=owner.attempt_root, run_id=tmp_path.name, attempt_id=owner.attempt_root.name,
                            events=EventLog(owner.attempt_root / "events.jsonl")),
        output=lambda _: {"language_build_handoff_sha256": "a" * 64,
                          "artifact_index": {"sha256": "b" * 64}})
    scan = _scan_one(unit, artifact, "syft", lambda *args: {
        "stdout": b"diagnostic" * 10, "stderr": b"", "exit_code": 0, "payload": payload})
    native = scan["native_output"]
    assert (tmp_path / native["artifact"]["path"]).read_bytes() == payload
    assert native["complete"] is True
    assert scan["result_artifact"]["sha256"] == shared.reference(
        tmp_path, tmp_path / scan["result_artifact"]["path"])["sha256"]
    assert "result_artifact" not in json.loads((tmp_path / scan["result_artifact"]["path"]).read_bytes())
    settings["parser_input_limit_bytes"] = 32
    truncated = _scan_one(unit, artifact, "syft", lambda *args: {
        "stdout": b"", "stderr": b"", "exit_code": 0, "payload": payload})
    assert truncated["native_output"]["complete"] is False
    assert truncated["observation"] == {} and truncated["gaps"]
    summary, findings = scan_records(truncated)
    assert not findings and summary.payload["scan_outcome"] == "not_completed"


def test_blint_assembly_reports_bounds_and_keeps_original_pre_filter_selectors(tmp_path, monkeypatch):
    from appsec_review import blint_report
    monkeypatch.setattr(blint_report, "MAX_ITEMS", 2)
    atomic_json(tmp_path / "findings.json", {"findings": [None, {"id": "X"}, {"id": "omitted"}]})
    atomic_json(tmp_path / "one-metadata.json", {"file_path": "one"})
    assembled = blint_report.assemble(tmp_path)
    assert assembled["truncated"] and assembled["reported_counts"]["findings"] == 3
    finding, = assembled["findings"]
    assert finding["_native_selector"]["value"] == "/findings/1"
    assert finding["_native_report"] == "findings.json"


def test_empty_scanner_output_is_not_a_complete_zero_finding_scan():
    with pytest.raises(ValueError, match="empty"):
        parse_json(b" \n")
    with pytest.raises(ValueError, match="parser failed"):
        adapter_registry()["tool-gitleaks"].parse(b"")


def test_grype_legacy_projection_is_small_and_full_match_remains_native(tmp_path, owner):
    match = {"artifact": {"name": "pkg", "version": "1", "purl": "pkg:generic/pkg@1"},
             "vulnerability": {"id": "CVE-A", "severity": "High", "description": "x" * 60_000},
             "matchDetails": ["x" * 60_000]}
    document = {"matches": [match]}
    native = retained(tmp_path, json.dumps(document).encode())
    _, findings = scan_records({"capability": "grype", "fingerprint": "a" * 64, "artifact": {},
                                "observation": document, "native_output": native.as_dict(), "gaps": []})
    finding, = findings
    assert len(json.dumps(finding.payload)) < 4096
    reference, = finding.payload["common"]["evidence_refs"]
    assert verify_native_reference(tmp_path, reference, resolve=True) == match


def test_syft_summary_keeps_inventory_semantics_without_native_inventory_copy(tmp_path, owner):
    document = {"artifacts": [{"name": "one"}, {"name": "two"}]}
    native = retained(tmp_path, json.dumps(document).encode())
    summary, findings = scan_records({"capability": "syft", "fingerprint": "a" * 64, "artifact": {},
                                     "observation": document, "native_output": native.as_dict(), "gaps": []})
    assert not findings and summary.kind == "scan_summary"
    assert summary.payload["common"]["observation_class"] == "inventory"
    assert "artifacts" not in summary.payload["observation"]
    assert summary.payload["observation"]["artifact_count_reported"] == 2
