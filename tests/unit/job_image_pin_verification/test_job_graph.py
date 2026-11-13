"""Code-level graph metadata, admission and handlers; no runner executes a job graph."""

import hashlib
import json
import logging
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from appsec_review.jobs.job_image_pin_verification import build_job
from appsec_review.jobs.job_image_pin_verification import job as gate
from tests.unit.job_image_pin_verification.support import (
    PIN_A, PIN_B, UNITS, artifact, config, context, matching_runner, pin, write_inputs,
)


def handler(unit_id, runner=matching_runner):
    return next(unit.handler for unit in build_job(runner=runner).units if unit.unit_id == unit_id)


def test_graph_ids_dependencies_validators_and_result_transform():
    job = build_job(runner=matching_runner)
    assert (job.job_id, job.name, job.schema_identity) == (
        "job_image_pin_verification", "image_pin_verification", "appsec-review/image-pin-verification-job/3")
    assert gate.TOPOLOGY == {
        "selection": ("resolve_pins",), "verification": ("inspect_images",),
        "publication": ("publish_handoff",),
    }
    assert [(unit.unit_id, unit.dependencies, unit.input_validators, unit.output_validators)
            for unit in job.units] == [
        (UNITS[0], (), (), ()), (UNITS[1], (UNITS[0],), (), ()), (UNITS[2], (UNITS[1],), (), ()),
    ]
    assert job.always_execute is True and job.propagate_handoff is False and job.strict_gaps is True
    assert len(job.input_validators) == 1
    assert job.output_validators == () and job.result_transform is None
    assert job.implementation_identity is None and job.validation_identity is None
    result = {"units": {"publication.publish_handoff": {"pin_count": 3}}}
    assert job.finalize_result(SimpleNamespace(), result) is result


def test_input_validation_accepts_the_exact_topology_and_wired_runner():
    job = build_job(runner=matching_runner)
    assert job.input_validators[0](SimpleNamespace(config=config()), None) is None
    assert gate.settings_of(config()).enabled is True


@pytest.mark.parametrize("change", ["step-order", "step-missing", "task"], ids=str)
def test_input_validation_refuses_changed_topology_before_inspecting_images(change):
    cfg = config()
    if change == "step-order":
        cfg.steps = tuple(reversed(cfg.steps))
    elif change == "step-missing":
        cfg.steps = cfg.steps[:-1]
    else:
        cfg.step = lambda key: SimpleNamespace(tasks=("unexpected",))
    runner = Mock(side_effect=AssertionError("inspection must not start"))
    message = "task order mismatch: selection" if change == "task" else "topology does not match configuration"
    with pytest.raises(ValueError, match=message):
        build_job(runner=runner).input_validators[0](SimpleNamespace(config=cfg), None)
    runner.assert_not_called()


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        (None, "must be a table"),
        ({}, "missing settings: enabled"),
        ({"enabled": "yes"}, "enabled must be a boolean"),
        ({"enabled": True, "unexpected": 1}, "unknown settings: unexpected"),
        ({"enabled": True, "parallelism": 2}, "unknown settings: parallelism"),
        ({"enabled": True, "pin_mismatch": "report"}, "unknown settings: pin_mismatch"),
    ],
    ids=["table", "missing", "boolean", "unknown", "parallelism", "mismatch-policy"],
)
def test_input_validation_rejects_bad_settings(settings, message):
    cfg = config()
    cfg.settings = settings
    with pytest.raises(ValueError, match=message):
        build_job(runner=matching_runner).input_validators[0](SimpleNamespace(config=cfg), None)


def test_unwired_job_is_refused_before_any_handler():
    with pytest.raises(ValueError, match="image inspection runner is not wired"):
        build_job().input_validators[0](SimpleNamespace(config=config()), None)


def test_inspection_defends_against_a_bypassed_unwired_claim(tmp_path):
    unit = context(tmp_path, UNITS[1])
    with pytest.raises(AssertionError):
        handler(UNITS[1], runner=None)(unit)
    assert unit.reads == [] and unit.events == []
    assert list(unit.unit_root.iterdir()) == []


def test_resolve_binds_frozen_host_pins_and_hashes_exact_input_bytes(tmp_path):
    unit = context(tmp_path, UNITS[0])
    catalog, frozen, host = write_inputs(unit)
    result = handler(UNITS[0])(unit)
    identity, document = artifact(unit, "image-pin-plan.json")
    expected_pins = [pin("containers/catalog.toml images.tool.image_id")]
    assert result == {"schema": "appsec-review/image-pin-plan/2", "artifact": identity,
                      "pins": expected_pins, "pin_count": 1}
    assert document == {
        "schema": "appsec-review/image-pin-plan/2",
        "catalog": {"path": "containers/catalog.toml",
                    "sha256": hashlib.sha256(catalog.read_bytes()).hexdigest(),
                    "release_id": "platform-fixture"},
        "configuration": {"path": "data/configuration/resolved.json",
                          "sha256": hashlib.sha256(frozen.read_bytes()).hexdigest()},
        "host_pins": {"path": "data/configuration/host-pins.toml",
                      "sha256": hashlib.sha256(host.read_bytes()).hexdigest()},
        "pins": expected_pins,
    }
    assert not (unit.job.repository_root / "containers/build.py").exists()
    assert sorted(path.name for path in catalog.parent.iterdir()) == ["catalog.toml"]


def test_resolve_wires_bound_catalog_and_resolved_document_into_selection(tmp_path, monkeypatch):
    unit = context(tmp_path, UNITS[0])
    _, frozen, _ = write_inputs(unit)
    selection = Mock(return_value=[pin("selected")])
    monkeypatch.setattr(gate, "configured_pins", selection)
    result = handler(UNITS[0])(unit)
    selection.assert_called_once_with(
        [{"id": "tool", "state": "enabled", "tag": "fixture/tool:1", "image_id": PIN_A}],
        json.loads(frozen.read_bytes()),
    )
    assert result["pins"] == [pin("selected")] and result["pin_count"] == 1


@pytest.mark.parametrize("change", ["hash", "document", "missing-record"], ids=str)
def test_resolve_refuses_host_identity_drift_without_publishing_a_plan(tmp_path, change):
    unit = context(tmp_path, UNITS[0])
    _, frozen, _ = write_inputs(unit)
    document = json.loads(frozen.read_bytes())
    if change == "hash":
        document["configuration_host_pins"]["sha256"] = "0" * 64
    elif change == "document":
        document["configuration_host_pins"]["document"]["images"]["fixture/tool:1"] = PIN_B
    else:
        del document["configuration_host_pins"]
    frozen.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="image pin verification host-pins identity mismatch"):
        handler(UNITS[0])(unit)
    assert list(unit.unit_root.iterdir()) == []


@pytest.mark.parametrize("missing", ["catalog", "configuration", "host"], ids=str)
def test_resolve_requires_every_input_file(tmp_path, missing):
    unit = context(tmp_path, UNITS[0])
    paths = dict(zip(("catalog", "configuration", "host"), write_inputs(unit), strict=True))
    paths[missing].unlink()
    with pytest.raises(FileNotFoundError) as failure:
        handler(UNITS[0])(unit)
    assert ("requires containers/catalog.toml" in str(failure.value)
            if missing == "catalog" else failure.value.filename == str(paths[missing]))
    assert list(unit.unit_root.iterdir()) == []


@pytest.mark.parametrize("malformed", ["catalog-toml", "catalog-utf8", "configuration-json", "host-toml"], ids=str)
def test_resolve_does_not_replace_malformed_inputs_with_an_empty_success(tmp_path, malformed):
    unit = context(tmp_path, UNITS[0])
    catalog, frozen, host = write_inputs(unit)
    if malformed == "catalog-toml":
        catalog.write_bytes(b"[[")
    elif malformed == "catalog-utf8":
        catalog.write_bytes(b"\xff")
    elif malformed == "configuration-json":
        frozen.write_bytes(b"{")
    else:
        host.write_bytes(b"[[")
        document = json.loads(frozen.read_bytes())
        document["configuration_host_pins"]["sha256"] = hashlib.sha256(b"[[").hexdigest()
        frozen.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError):
        handler(UNITS[0])(unit)
    assert list(unit.unit_root.iterdir()) == []


def test_resolve_refuses_an_empty_enabled_pin_selection(tmp_path):
    unit = context(tmp_path, UNITS[0])
    write_inputs(unit, catalog=b'images = []\n')
    with pytest.raises(ValueError, match="found no enabled catalog image or configured pin"):
        handler(UNITS[0])(unit)
    assert list(unit.unit_root.iterdir()) == []


def test_inspect_wires_a_copy_of_each_pin_and_projects_only_published_image_fields(tmp_path, monkeypatch):
    pins = [pin(), pin("second", image_id=None)]
    plan = {"artifact": {"path": "plan.json"}, "pins": pins}
    unit = context(tmp_path, UNITS[1], {UNITS[0]: plan})
    runner = object()

    def verify(selected, supplied_runner):
        assert selected == pins and selected is not pins
        assert all(left is not right for left, right in zip(selected, pins, strict=True))
        assert supplied_runner is runner
        return [{**row, "resolved_image_id": PIN_A, "status": status, "detail": "", "private": "omit"}
                for row, status in zip(selected, ("matched", "present"), strict=True)]

    monkeypatch.setattr(gate, "verify_pins", verify)
    result = handler(UNITS[1], runner)(unit)
    identity, document = artifact(unit, "image-pin-verification.json")
    assert result == {
        "schema": "appsec-review/image-pin-verification/1", "artifact": identity, "pin_count": 2,
        "images": [{**row, "resolved_image_id": PIN_A, "status": status}
                   for row, status in zip(pins, ("matched", "present"), strict=True)],
    }
    assert document["plan"] == plan["artifact"] and document["status"] == "PASSED" and document["gaps"] == []
    assert len(document["pins"]) == 2 and document["pins"][0]["private"] == "omit"
    assert unit.events == [
        ("IMAGE_PIN_VERIFICATION_STARTED", {"unit_id": UNITS[1], "pin_count": 2}),
        ("IMAGE_PIN_VERIFICATION_COMPLETED", {"unit_id": UNITS[1], "pin_count": 2}),
    ]
    assert unit.reads == [UNITS[0]]


@pytest.mark.parametrize("status", ["inspect_failed", "mismatched", "missing"], ids=str)
def test_inspect_failure_is_typed_scoped_retryable_and_keeps_evidence_before_raising(
        tmp_path, monkeypatch, caplog, status):
    rows = [
        {**pin("failed-source"), "resolved_image_id": PIN_B if status == "mismatched" else None,
         "status": status, "detail": "daemon unavailable"},
        {**pin("passed-source"), "resolved_image_id": PIN_A, "status": "matched", "detail": ""},
    ]
    unit = context(tmp_path, UNITS[1], {UNITS[0]: {"artifact": {"path": "plan.json"}, "pins": [pin(), pin()]}})
    monkeypatch.setattr(gate, "verify_pins", Mock(return_value=rows))
    with caplog.at_level(logging.ERROR, logger=gate.__name__):
        with pytest.raises(gate.ImagePinVerificationFailed, match="1 of 2 image pins") as failure:
            handler(UNITS[1])(unit)
    identity, document = artifact(unit, "image-pin-verification.json")
    assert document["status"] == "FAILED" and document["pins"] == rows
    [gap] = document["gaps"]
    assert (gap["schema"], gap["code"], gap["scope_id"], gap["unit_id"], gap["retryable"]) == (
        "appsec-review/producer-gap/1", "producer_blocked", "failed-source", UNITS[1], True)
    assert gap["reason"] == gate.describe(rows[0]) and gap["evidence_refs"] == []
    assert gap["reason"] in str(failure.value)
    assert f"verification record: {unit.unit_root / 'image-pin-verification.json'}" in str(failure.value)
    assert str(failure.value) in caplog.text
    assert unit.events == [
        ("IMAGE_PIN_VERIFICATION_STARTED", {"unit_id": UNITS[1], "pin_count": 2}),
        ("IMAGE_PIN_VERIFICATION_FAILED", {"unit_id": UNITS[1], "failures": [rows[0]], "record": identity["path"]}),
    ]
    assert not (unit.unit_root / "image-pin-verification-handoff.json").exists()


def test_inspect_emits_one_gap_for_each_failed_source_not_each_distinct_tag(tmp_path):
    pins = [pin("catalog"), pin("profile"), pin("source")]
    unit = context(tmp_path, UNITS[1], {UNITS[0]: {"artifact": {"path": "plan.json"}, "pins": pins}})
    calls = []

    def missing(argv, timeout):
        calls.append((argv, timeout))
        return 1, b"", b"No such image: fixture/tool:1", False

    with pytest.raises(gate.ImagePinVerificationFailed, match="3 of 3 image pins"):
        handler(UNITS[1], missing)(unit)
    _, document = artifact(unit, "image-pin-verification.json")
    assert len(calls) == 1
    assert [(gap["code"], gap["scope_id"]) for gap in document["gaps"]] == [
        ("producer_blocked", "catalog"), ("producer_blocked", "profile"), ("producer_blocked", "source"),
    ]
    assert len({gap["gap_id"] for gap in document["gaps"]}) == 3


def test_publish_wires_verified_artifact_images_and_pin_count_without_reinspection(tmp_path):
    verified = {
        "artifact": {"path": "verification.json", "sha256": "a" * 64, "size_bytes": 987},
        "images": [{**pin(), "resolved_image_id": PIN_A, "status": "matched"}], "pin_count": 1,
    }
    unit = context(tmp_path, UNITS[2], {UNITS[1]: verified})
    runner = Mock(side_effect=AssertionError("publication must not inspect"))
    result = handler(UNITS[2], runner)(unit)
    identity, document = artifact(unit, "image-pin-verification-handoff.json")
    assert document == {"schema": "appsec-review/image-pin-verification/1",
                        "artifact": verified["artifact"], "images": verified["images"]}
    assert result == {"schema": document["schema"], "artifact": identity, "pin_count": 1,
                      "images": verified["images"], "terminal_status": "SUCCEEDED", "gaps": []}
    assert unit.reads == [UNITS[1]] and unit.events == []
    runner.assert_not_called()


def test_identity_rewrites_only_path_to_run_relative_and_hashes_written_bytes(tmp_path):
    unit = context(tmp_path, UNITS[2])
    document = {"schema": "fixture/1", "unicode": "π", "count": 7}
    identity = gate._identity(unit, unit.unit_root / "fixture.json", document)
    expected_identity, written = artifact(unit, "fixture.json")
    assert identity == expected_identity and written == document
