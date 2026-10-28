from __future__ import annotations

from dataclasses import replace
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
