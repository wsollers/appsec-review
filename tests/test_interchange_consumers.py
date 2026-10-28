from __future__ import annotations

from copy import deepcopy
import importlib
import json
from pathlib import Path

import pytest

from appsec_review.interchange import (
    ArtifactReference, NativeResultReference, ObservationMetadata, ResultSelector,
)
from appsec_review.observability.spans import OperationSpan
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RetrievalCore,
    sanitize_producer_data, write_manifest,
)
from appsec_review.retrieval.observations import (
    classify, native_severity_of, normalize_reported_severity, observation_projection, rule_of, scanner_of,
)
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff


JOB = "job_evidence_collection"
ATTEMPT = "attempt_0001"
SNAPSHOT = "target-sha256:" + "1" * 64


def _common(*, kind="finding"):
    native = NativeResultReference(
        ArtifactReference("data/shared/objects/" + "a" * 64, "a" * 64, 10),
        ResultSelector("json_pointer", "/runs/0/results/0"), "scanner-parser/1",
        retention_receipt=ArtifactReference(
            f"data/jobs/{JOB}/attempts/{ATTEMPT}/shared/native-output/" + "b" * 64 + ".json", "b" * 64, 20),
    )
    return ObservationMetadata(
        "source_sast", kind, "tool-semgrep", "security.rule",
        {"value": "high", "native": "ERROR", "basis": "native-label", "rule": "reported-severity/1"},
        (native,), (), "scanner-record/1",
    ).as_dict()


def test_common_metadata_has_one_authority_over_legacy_payload():
    common = _common()
    payload = {"common": common, "producer": "codeql", "rule": "wrong", "severity": "LOW",
               "category": "secret", "security_severity": 10}
    assert scanner_of(payload) == "tool-semgrep"
    assert rule_of(payload) == "security.rule"
    assert classify(payload) == "source_sast"
    assert native_severity_of(payload) == "ERROR"
    assert normalize_reported_severity(payload) == common["reported_severity"]
    assert observation_projection(payload).as_dict() == common


@pytest.mark.parametrize("bad", [None, {}, {"schema": "wrong"}, {**_common(), "record_kind": "confirmed"},
                                      {**_common(), "raw": "secret"}])
@pytest.mark.parametrize("reader", [scanner_of, rule_of, classify, native_severity_of,
                                    normalize_reported_severity, observation_projection])
def test_malformed_common_never_falls_back_to_legacy(reader, bad):
    with pytest.raises(ValueError):
        reader({"common": bad, "producer": "codeql", "rule_id": "valid-legacy", "severity": "HIGH"})


@pytest.mark.parametrize(("payload", "scanner", "kind", "severity"), [
    ({"producer": "codeql", "rule_id": "cpp/rule", "producer_level": "error"}, "codeql", "source_sast", "high"),
    ({"tool_id": "tool-spotbugs", "category": "binary", "severity": 1}, "tool-spotbugs", "binary", "high"),
    ({"scanner_identity": "custom", "category": "secret_detection", "severity": "unmapped"},
     "custom", "secret", "unknown"),
])
def test_legacy_parity_projects_explicit_provenance_gap_without_invented_native_refs(payload, scanner, kind, severity):
    common = observation_projection(payload)
    assert (common.scanner, common.observation_class, common.reported_severity["value"]) == (scanner, kind, severity)
    assert common.evidence_refs == () and len(common.gap_ids) == 1
    assert common.record_kind == "observation"


def test_safe_projection_keeps_only_validated_common_reference_paths():
    common = _common()
    payload = {"common": common, "path": "hidden", "nested": {"path": "hidden"},
               "stdout": "secret-native-bytes", "argv": ["secret-command"], "environment": {"TOKEN": "secret"}}
    safe = RetrievalCore._safe_payload(payload)
    assert safe["common"]["evidence_refs"][0]["artifact"]["path"] == common["evidence_refs"][0]["artifact"]["path"]
    assert safe["common"]["evidence_refs"][0]["retention_receipt"]["path"].endswith(".json")
    assert "hidden" not in json.dumps(safe) and "secret-native-bytes" not in json.dumps(safe)
    assert set(safe) == {"common", "nested"}
    bad = deepcopy(common)
    bad["evidence_refs"][0]["artifact"]["path"] = "data/configuration/resolved.json"
    with pytest.raises(ValueError, match="namespace"):
        RetrievalCore._safe_payload({"common": bad})
    bad = deepcopy(common)
    bad["evidence_refs"][0]["artifact"]["path"] = "../target/secrets"
    with pytest.raises(ValueError, match="canonical"):
        RetrievalCore._safe_payload({"common": bad})


def test_common_projection_preserves_typed_secret_labels_selectors_and_execution_references():
    common = _common()
    common["observation_class"] = "secret"
    native = common["evidence_refs"][0]
    native["selector"]["value"] = "/files/customer-secret.json/findings/0"
    native["execution_reference"] = {
        "path": f"data/jobs/{JOB}/attempts/{ATTEMPT}/steps/scan/tasks/semgrep/"
                "scratch/invocation_001/attempt_01/execution.json",
        "sha256": "c" * 64, "size_bytes": 100,
    }
    native["retention_receipt"]["path"] = native["retention_receipt"]["path"].replace(
        JOB, "job_artifact_security_analysis")
    assert RetrievalCore._safe_payload({"common": common})["common"] == common
    assert sanitize_producer_data({"common": common, "password": "do-not-copy"}) == {
        "common": common, "password": "<redacted>"}


def test_common_metadata_round_trips_indexing_without_weakening_arbitrary_payload_redaction(tmp_path):
    common = _common()
    common["observation_class"] = "secret"
    common["evidence_refs"][0]["selector"]["value"] = "/files/secret.json/results/0"
    common["evidence_refs"][0]["retention_receipt"]["path"] = common["evidence_refs"][0][
        "retention_receipt"]["path"].replace(JOB, "job_artifact_security_analysis")
    core = _query_core(tmp_path, [{"common": common, "password": "do-not-copy",
                                  "nested": {"path": "hidden", "API_TOKEN": "do-not-copy"}}])
    item = core.query_observations(observation_class="secret")["results"][0]["payload"]
    assert item["common"] == common
    assert "do-not-copy" not in json.dumps(item) and "hidden" not in json.dumps(item)


GENERIC_READERS = (
    ("indexing.store", "accepted_handoff"),
    ("jobs.job_change_context_analysis.job", "_accepted_handoff"),
    ("jobs.job_tree_sitter_ast.job", "_accepted_handoff"),
    ("jobs.job_profile_data.job", "_accepted_handoff"),
    ("jobs.job_dependency_intelligence.job", "_accepted_job"),
    ("jobs.job_source_history_analysis.job", "_accepted_handoff"),
    ("jobs.job_review_prioritization.inputs", "accepted_handoff"),
    ("jobs.job_test_coverage.job", "_accepted_handoff"),
)


def _publish(root: Path, job: str = JOB):
    path = root / "data" / "jobs" / job / "attempts" / ATTEMPT / "handoff.json"
    write_fixture_handoff(root, path, {"job_id": job, "outputs": {}, "source_fingerprint": SNAPSHOT})
    _point(root, path, job)
    return path


def _point(root, path, job):
    (root / "data" / "jobs" / job / "latest.json").write_text(json.dumps({
        "handoff_path": path.relative_to(root).as_posix(), "handoff_sha256": file_sha256(path)}), encoding="utf-8")


@pytest.mark.parametrize(("module", "name"), GENERIC_READERS)
def test_operational_consumers_accept_real_v2_and_reject_v1_forged_identity_and_input_hash(tmp_path, module, name):
    root = tmp_path / "2026-10-28-0001"
    path = _publish(root)
    reader = getattr(importlib.import_module("appsec_review." + module), name)
    options = {"required": True} if module == "jobs.job_change_context_analysis.job" else {}
    original = json.loads(path.read_bytes())
    assert reader(root, JOB, **options) is not None
    for update in ({"schema": "appsec-review/job-handoff/1"}, {"run_id": "other-run"},
                   {"job_id": "job_other"}, {"input_set_sha256": "0" * 64},
                   {"status": "REJECTED"}, {"coverage": {"disposition": "clean"}}):
        path.write_text(json.dumps({**original, **update}), encoding="utf-8")
        _point(root, path, JOB)
        historical = path.read_bytes()
        with pytest.raises(ValueError):
            reader(root, JOB, **options)
        assert path.read_bytes() == historical
    path.write_text(json.dumps(original), encoding="utf-8")
    _point(root, path, JOB)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError):
        reader(root, JOB, **options)


def _query_core(tmp_path, payloads):
    root = tmp_path / "2026-10-28-0001"
    shard = root / "data" / "indices" / "observations.sqlite"
    builder = IndexBuilder(shard, name="observations", fingerprint="c" * 64, target_snapshot=SNAPSHOT)
    for number, payload in enumerate(payloads):
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAPSHOT, {"row": number})
        builder.add_entity(EntityRecord(identity, str(number), "observation", "indexed-only", payload))
    sha = builder.build()
    manifest = root / "data" / "indices" / "manifest.json"
    target = tmp_path / "target"
    target.mkdir()
    write_manifest(manifest, run_id=root.name, target_snapshot=SNAPSHOT, target_root=target, indexes=[
        IndexIdentity("observations", "appsec-review/retrieval-index/2", sha, "c" * 64,
                      shard.relative_to(root).as_posix(), {"job": JOB})])
    return RetrievalCore(tmp_path, root.name, manifest_path=manifest)


def test_queries_use_common_metadata_preserve_summary_and_never_resolve_native_reports(tmp_path, monkeypatch):
    core = _query_core(tmp_path, [
        {"common": _common()}, {"common": _common(kind="scan_summary")},
        {"producer": "legacy", "category": "source_sast", "severity": "HIGH"},
    ])
    original = Path.read_bytes

    def forbid_native(path):
        assert "objects" not in path.parts, "query opened a native scanner report"
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", forbid_native)
    response = core.query_observations(scanner="tool-semgrep", severity="high")
    assert len(response["results"]) == 2
    assert {row["payload"]["common"]["record_kind"] for row in response["results"]} == {"finding", "scan_summary"}
    assert all("not an adjudicated finding" in row["authority"] for row in response["results"])
    legacy = core.query_observations(scanner="legacy")["results"][0]["payload"]
    assert legacy["common"]["evidence_refs"] == []
    assert legacy["provenance_gaps"] == ["provenance_unavailable"]


def test_indexing_rejects_malformed_common_explicitly(tmp_path):
    with pytest.raises(ValueError, match="common observation metadata"):
        _query_core(tmp_path, [{"common": None, "producer": "codeql"}])


def test_fixed_interchange_span_counters_remain_closed():
    span = OperationSpan("interchange")
    for name in ("handoff_validations", "native_output_references", "native_output_bytes",
                 "observation_references", "provenance_gaps"):
        span.count(name)
    assert len(span.counters) == 5
    for name in ("native-rule/customer-secret", "data/native/result.json"):
        with pytest.raises(ValueError):
            span.count(name)
