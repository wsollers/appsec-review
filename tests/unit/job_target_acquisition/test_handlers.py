"""Each real handler, with only the source-control acquisition module replaced."""

from __future__ import annotations

import hashlib
import json

import pytest

from appsec_review.interchange import producer_gap, validate_unit_output
from appsec_review.jobs.job_target_acquisition.job import TargetAcquisitionFailed
from appsec_review.runtime.launch import SYSTEM_ENVIRONMENT
from tests.unit.job_target_acquisition.support import (
    ACQUISITION, ATTEMPT, CONFIGURATION, PUBLICATION, SCHEMA, SELECTION, SYSTEM_SCHEMA,
    artifact_document, backend_result, fake_backend, frozen_text, handler, plan, unit_context,
)


def test_resolve_without_a_request_publishes_only_the_frozen_configuration_identity(tmp_path):
    unit, events = unit_context(tmp_path, SELECTION)
    result = handler(SELECTION, environ={})(unit)
    assert result == {"schema": SCHEMA, "artifact": result["artifact"], "requested": False, "system_id": None}
    assert artifact_document(unit, result["artifact"]) == {
        "schema": SCHEMA, "configuration": {
            "path": CONFIGURATION, "sha256": hashlib.sha256(frozen_text().encode()).hexdigest(),
        }, "requested": False, "system_id": None,
    }
    assert result["artifact"]["path"] == (
        f"{ATTEMPT}/steps/selection/tasks/resolve_system/target-acquisition-plan.json"
    )
    assert events == []
    assert not (tmp_path / "checkouts").exists()


@pytest.mark.parametrize(("parallel", "expected"), [(1, 1), (2, 2), (7, 2)],
                         ids=["below-count", "equal-count", "above-count"])
@pytest.mark.parametrize("target_bound", [False, True], ids=["unbound", "bound"])
def test_resolve_pins_component_specs_target_and_bounded_concurrency(tmp_path, parallel, expected, target_bound):
    target = tmp_path / "checkouts" / "sys" if target_bound else None
    unit, events = unit_context(tmp_path, SELECTION, target_root=target, frozen=frozen_text(parallel=parallel))
    result = handler(SELECTION, environ={SYSTEM_ENVIRONMENT: "sys"})(unit)
    document = artifact_document(unit, result["artifact"])
    assert result["requested"] is True and result["system_id"] == "sys"
    assert document["schema"] == SCHEMA and document["requested"] is True
    assert document["system_id"] == "sys" and document["target_path"] == "checkouts/sys"
    assert document["max_parallel_components"] == expected
    assert document["spec"]["system"] == "sys"
    assert set(document["spec"]["components"]) == {"service", "library"}
    for name in ("library", "service"):
        component = document["spec"]["components"][name]
        assert component["kind"] == "git"
        assert component["commit"] == "a" * 40 and component["url"] == f"https://example.invalid/{name}.git"
    assert events == [] and not (tmp_path / "checkouts").exists()


def test_resolve_refuses_an_unknown_system_before_writing_a_plan(tmp_path):
    unit, events = unit_context(tmp_path, SELECTION)
    with pytest.raises(ValueError, match=r"not configured under \[\[target_acquisition.systems\]\]: unknown$"):
        handler(SELECTION, environ={SYSTEM_ENVIRONMENT: "unknown"})(unit)
    assert list(unit.unit_root.iterdir()) == [] and events == []


def test_resolve_refuses_a_target_other_than_the_requested_composed_root(tmp_path):
    unit, events = unit_context(tmp_path, SELECTION, target_root=tmp_path / "checkouts" / "other")
    with pytest.raises(ValueError, match="the review target is not the composed root of the requested system"):
        handler(SELECTION, environ={SYSTEM_ENVIRONMENT: "sys"})(unit)
    assert list(unit.unit_root.iterdir()) == [] and events == []


def test_acquire_not_requested_never_reads_configuration_or_calls_the_backend(tmp_path, monkeypatch):
    from appsec_review.target_acquisition import acquire

    selected = plan(requested=False, system_id=None)
    unit, events = unit_context(tmp_path, ACQUISITION, outputs={SELECTION: selected})
    (unit.job.run_root / CONFIGURATION).unlink()

    def forbidden(**kwargs):
        pytest.fail("unrequested acquisition reached the source-control boundary")

    monkeypatch.setattr(acquire, "acquire_system", forbidden)
    result = handler(ACQUISITION, environ={})(unit)
    assert result == {
        "schema": SCHEMA, "status": "NOT_REQUESTED", "terminal_status": "NOT_APPLICABLE",
        "artifact": result["artifact"], "gaps": [],
    }
    assert artifact_document(unit, result["artifact"]) == {
        "schema": SCHEMA, "status": "NOT_REQUESTED", "plan": selected["artifact"],
    }
    assert events == [] and not (tmp_path / "checkouts").exists()
    validate_unit_output(result, unit_id=ACQUISITION, strict_gaps=True)


def test_acquire_passes_frozen_settings_environment_and_fetcher_and_records_exact_summary(tmp_path, monkeypatch):
    selected = plan()
    unit, events = unit_context(tmp_path, ACQUISITION, outputs={SELECTION: selected})
    backend = backend_result()
    calls, _ = fake_backend(monkeypatch, unit, backend)
    environ = {SYSTEM_ENVIRONMENT: "sys", "FIXTURE_TOKEN": "do-not-publish"}
    fetcher_factory = object()
    result = handler(ACQUISITION, environ=environ, fetcher_factory=fetcher_factory)(unit)
    assert len(calls) == 2
    _, kwargs = calls[0]
    assert set(kwargs) == {"repository_root", "settings", "system", "environ", "fetcher_factory"}
    assert kwargs["repository_root"] == tmp_path
    assert kwargs["environ"] is environ and kwargs["fetcher_factory"] is fetcher_factory
    settings = kwargs["settings"]
    assert settings.targets_dir == "checkouts" and settings.max_parallel_components == 4
    assert kwargs["system"] is settings.system("sys")
    assert calls[1] == ("paths", tmp_path, settings, "sys")
    fields = ("status", "action", "acquisition_id", "target_path", "manifest", "manifest_sha256",
              "tree_sha256", "error", "failure_record")
    components = {key: {field: value.get(field) for field in fields} for key, value in backend["components"].items()}
    assert result == {
        "schema": SCHEMA, "status": "COMPLETE", "artifact": result["artifact"], "manifest": None,
        "system_id": "sys", "acquisition_id": "sys@fixture", "tree_sha256": "2" * 64,
        "target_path": "checkouts/sys", "components": components, "gaps": [], "terminal_status": "SUCCEEDED",
    }
    document = artifact_document(unit, result["artifact"])
    assert document == {
        "schema": SCHEMA, "plan": selected["artifact"], "system_id": "sys",
        "status": "COMPLETE", "acquisition_id": "sys@fixture", "target_path": "checkouts/sys",
        "manifest": None, "manifest_sha256": None, "tree_sha256": "2" * 64,
        "verification": "acquisition-records/sys/verification.json", "completed_at": "2026-01-02T03:04:05Z",
        "components": components, "acquisition_gaps": [], "gaps": [], "error": None,
    }
    assert "do-not-publish" not in json.dumps(document)
    assert events == [
        ("TARGET_ACQUISITION_STARTED", {"unit_id": ACQUISITION, "system_id": "sys",
                                        "components": ["service", "library"]}),
        ("TARGET_ACQUISITION_COMPLETED", {
            "unit_id": ACQUISITION, "system_id": "sys", "status": "COMPLETE",
            "gap_count": 0, "component_count": 2, "verified_count": 1, "acquired_count": 1,
        }),
    ]
    assert result["artifact"]["path"] == (
        f"{ATTEMPT}/steps/acquisition/tasks/acquire_components/target-acquisition-result.json"
    )
    validate_unit_output(result, unit_id=ACQUISITION, strict_gaps=True)


@pytest.mark.parametrize(("reason", "code", "retryable"), [
    ("component_acquisition_failed", "producer_failed", True),
    ("component_not_acquired", "producer_reported_gap", True),
    ("submodule_not_materialized", "producer_reported_gap", False),
    ("unconfigured_system_entry", "producer_reported_gap", False),
], ids=["failed", "not-acquired", "submodule", "unconfigured"])
def test_acquire_partial_maps_every_gap_policy_to_a_typed_component_scope(
        tmp_path, monkeypatch, reason, code, retryable):
    unit, events = unit_context(tmp_path, ACQUISITION, outputs={SELECTION: plan()})
    raw = {"path": "library/dependency", "reason": reason, "detail": " fixture detail "}
    backend = backend_result(status="PARTIAL", gaps=[raw])
    fake_backend(monkeypatch, unit, backend)
    result = handler(ACQUISITION, environ={})(unit)
    assert result["status"] == "PARTIAL" and result["terminal_status"] == "COMPLETED_WITH_GAPS"
    [gap] = result["gaps"]
    assert gap["schema"] == "appsec-review/producer-gap/1"
    assert gap["code"] == code and gap["scope_id"] == "library/dependency"
    assert gap["unit_id"] == ACQUISITION and gap["retryable"] is retryable
    assert gap["reason"] == f"library/dependency: {reason}: fixture detail"
    document = artifact_document(unit, result["artifact"])
    assert document["acquisition_gaps"] == [raw] and document["gaps"] == [gap]
    assert events[-1][1]["gap_count"] == 1 and events[-1][1]["status"] == "PARTIAL"
    validate_unit_output(result, unit_id=ACQUISITION, strict_gaps=True)


@pytest.mark.parametrize(("has_reference", "has_file"), [(False, False), (False, True), (True, False)],
                         ids=["absent", "unreferenced", "missing-file"])
def test_acquire_does_not_invent_a_manifest_copy(tmp_path, monkeypatch, has_reference, has_file):
    unit, _ = unit_context(tmp_path, ACQUISITION, outputs={SELECTION: plan()})
    backend = backend_result()
    if has_reference:
        backend["manifest"] = "acquisition-records/sys/manifest.json"
    _, records = fake_backend(monkeypatch, unit, backend)
    if has_file:
        (records / "manifest.json").write_bytes(b"not to be read")
    result = handler(ACQUISITION, environ={})(unit)
    assert result["manifest"] is None
    assert sorted(path.name for path in unit.unit_root.iterdir()) == ["target-acquisition-result.json"]
    assert artifact_document(unit, result["artifact"])["manifest"] == backend["manifest"]


def test_acquire_copies_verified_manifest_bytes_without_reserializing(tmp_path, monkeypatch):
    unit, _ = unit_context(tmp_path, ACQUISITION, outputs={SELECTION: plan()})
    backend = backend_result()
    data = b'{ "schema": "appsec-review/target-system-acquisition/1", "system_id": "sys" }\n'
    digest = hashlib.sha256(data).hexdigest()
    backend.update(manifest="acquisition-records/sys/manifest.json", manifest_sha256=digest)
    _, records = fake_backend(monkeypatch, unit, backend)
    (records / "manifest.json").write_bytes(data)
    result = handler(ACQUISITION, environ={})(unit)
    assert result["manifest"] == {
        "name": "system-manifest.json", "sha256": digest,
        "path": f"{ATTEMPT}/steps/acquisition/tasks/acquire_components/system-manifest.json",
    }
    assert (unit.job.run_root / result["manifest"]["path"]).read_bytes() == data
    assert artifact_document(unit, result["manifest"])["schema"] == SYSTEM_SCHEMA
    assert artifact_document(unit, result["artifact"])["manifest_sha256"] == digest


def test_acquire_refuses_manifest_hash_drift_but_preserves_the_result_evidence(tmp_path, monkeypatch):
    unit, events = unit_context(tmp_path, ACQUISITION, outputs={SELECTION: plan()})
    backend = backend_result()
    backend.update(manifest="acquisition-records/sys/manifest.json", manifest_sha256="0" * 64)
    _, records = fake_backend(monkeypatch, unit, backend)
    (records / "manifest.json").write_bytes(b'{"changed": true}\n')
    with pytest.raises(RuntimeError, match="the system manifest changed while it was being recorded"):
        handler(ACQUISITION, environ={})(unit)
    document = json.loads((unit.unit_root / "target-acquisition-result.json").read_text())
    assert document["system_id"] == "sys"
    assert document["manifest_sha256"] == "0" * 64
    assert not (unit.unit_root / "system-manifest.json").exists()
    assert [event for event, _ in events] == ["TARGET_ACQUISITION_STARTED"]


@pytest.mark.parametrize("status", ["FAILED", "MISMATCH", "REFUSED"])
@pytest.mark.parametrize("explicit_error", [False, True], ids=["default-error", "explicit-error"])
def test_acquire_unavailable_system_fails_typed_after_writing_scoped_evidence(
        tmp_path, monkeypatch, status, explicit_error):
    selected = plan()
    unit, events = unit_context(tmp_path, ACQUISITION, outputs={SELECTION: selected})
    backend = backend_result(status=status, gaps=[{"path": "library", "reason": "component_acquisition_failed"}])
    backend["components"]["library"].update(status="FAILED", error="revision unavailable",
                                             failure_record="library-failure.json")
    backend["error"] = "fixture refused" if explicit_error else None
    fake_backend(monkeypatch, unit, backend)
    with pytest.raises(TargetAcquisitionFailed) as caught:
        handler(ACQUISITION, environ={})(unit)
    assert str(caught.value).splitlines() == [
        f"target acquisition of system sys is {status}: "
        + ("fixture refused" if explicit_error else "no component is available"),
        "library: FAILED: revision unavailable",
        f"acquisition record: {unit.unit_root / 'target-acquisition-result.json'}",
    ]
    document = json.loads((unit.unit_root / "target-acquisition-result.json").read_text())
    assert document["status"] == status and document["system_id"] == "sys"
    [gap] = document["gaps"]
    assert (gap["code"], gap["scope_id"], gap["unit_id"], gap["retryable"]) == (
        "producer_failed", "library", ACQUISITION, True,
    )
    assert document["components"]["library"]["failure_record"] == "library-failure.json"
    assert events[-1] == ("TARGET_ACQUISITION_FAILED", {
        "unit_id": ACQUISITION, "system_id": "sys", "status": status,
        "record": f"{ATTEMPT}/steps/acquisition/tasks/acquire_components/target-acquisition-result.json",
    })
    assert len(events) == 2


def test_acquire_handles_minimal_failed_backend_result_without_optional_fields(tmp_path, monkeypatch):
    unit, events = unit_context(tmp_path, ACQUISITION, outputs={SELECTION: plan()})
    fake_backend(monkeypatch, unit, {"status": "FAILED"})
    with pytest.raises(TargetAcquisitionFailed, match="system sys is FAILED: no component is available"):
        handler(ACQUISITION, environ={})(unit)
    document = json.loads((unit.unit_root / "target-acquisition-result.json").read_text())
    assert document["components"] == {} and document["gaps"] == []
    assert document["acquisition_gaps"] == [] and document["error"] is None
    assert events[-1][0] == "TARGET_ACQUISITION_FAILED" and events[-1][1]["system_id"] == "sys"


def test_acquire_passes_through_backend_exceptions_without_fabricating_success(tmp_path, monkeypatch):
    from appsec_review.target_acquisition import acquire
    from appsec_review.target_acquisition.safety import AcquisitionError

    unit, events = unit_context(tmp_path, ACQUISITION, outputs={SELECTION: plan()})
    failure = AcquisitionError("sys: fixture source refused")

    def fail(**kwargs):
        raise failure

    monkeypatch.setattr(acquire, "acquire_system", fail)
    with pytest.raises(AcquisitionError, match="sys: fixture source refused") as caught:
        handler(ACQUISITION, environ={})(unit)
    assert caught.value is failure
    assert list(unit.unit_root.iterdir()) == []
    assert [event for event, _ in events] == ["TARGET_ACQUISITION_STARTED"]


@pytest.mark.parametrize("unit_id, dependency", [(ACQUISITION, SELECTION), (PUBLICATION, ACQUISITION)],
                         ids=["acquisition", "publication"])
def test_handlers_refuse_missing_dependency_outputs(tmp_path, unit_id, dependency):
    unit, events = unit_context(tmp_path, unit_id)
    with pytest.raises(KeyError, match=f"unit output is unavailable: {dependency}"):
        handler(unit_id, environ={})(unit)
    assert events == [] and list(unit.unit_root.iterdir()) == []


@pytest.mark.parametrize("requested", [False, True], ids=["not-requested", "partial"])
def test_publish_preserves_evidence_and_gaps_in_the_document_but_never_duplicates_unit_gaps(tmp_path, requested):
    acquired = {
        "schema": SCHEMA, "status": "PARTIAL" if requested else "NOT_REQUESTED",
        "artifact": {"path": "result.json", "sha256": "a" * 64, "size_bytes": 17},
        "gaps": [producer_gap("producer_reported_gap", "library: component_not_acquired",
                              unit_id=ACQUISITION, scope_id="library", retryable=True)] if requested else [],
        "terminal_status": "COMPLETED_WITH_GAPS" if requested else "NOT_APPLICABLE",
        "ignored": "internal",
    }
    if requested:
        acquired.update(
            manifest={"path": "manifest.json", "sha256": "b" * 64}, system_id="sys",
            acquisition_id="sys@fixture", tree_sha256="c" * 64, target_path="checkouts/sys",
            components={"library": {"status": "NOT_ACQUIRED"}},
        )
    unit, events = unit_context(tmp_path, PUBLICATION, outputs={ACQUISITION: acquired})
    result = handler(PUBLICATION, environ={})(unit)
    document = {key: acquired.get(key) for key in (
        "schema", "status", "artifact", "manifest", "system_id", "acquisition_id", "tree_sha256",
        "target_path", "components", "gaps",
    )}
    assert artifact_document(unit, result["artifact"]) == document
    assert result == {
        **document, "artifact": result["artifact"], "result": acquired["artifact"],
        "gaps": [], "terminal_status": "SUCCEEDED",
    }
    assert result["artifact"]["path"] == (
        f"{ATTEMPT}/steps/publication/tasks/publish_handoff/target-acquisition-handoff.json"
    )
    assert acquired["gaps"] == document["gaps"] and acquired["ignored"] == "internal"
    assert events == []
    validate_unit_output(result, unit_id=PUBLICATION, strict_gaps=True)
