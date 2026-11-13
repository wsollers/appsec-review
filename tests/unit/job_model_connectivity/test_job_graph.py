"""Graph metadata, claim-time validation and wiring, without executing a job graph."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_model_connectivity import job as connectivity
from appsec_review.jobs.job_model_connectivity.job import build_job
from appsec_review.runtime import UnitExecutor

from .support import PUBLISH, RESOLVE, SCHEMA, VERIFY, configuration, context, handler, model


ROOT = Path(__file__).resolve().parents[3]


def test_graph_ids_dependencies_validators_and_schema_are_explicit() -> None:
    job = build_job()
    assert (job.job_id, job.name, job.schema_identity) == (
        "job_model_connectivity", "model_connectivity", "appsec-review/model-connectivity-job/2",
    )
    assert connectivity.TOPOLOGY == {
        "connectivity": ("resolve_models", "verify_models"),
        "publication": ("publish_handoff",),
    }
    assert [(unit.unit_id, unit.dependencies, unit.input_validators, unit.output_validators)
            for unit in job.units] == [
        (RESOLVE, (), (), ()),
        (VERIFY, (RESOLVE,), (), ()),
        (PUBLISH, (VERIFY,), (), ()),
    ]
    assert [unit.handler.__name__ for unit in job.units] == [
        "resolve_models", "verify_models", "publish_handoff",
    ]
    assert isinstance(job.handler.__self__, UnitExecutor)
    assert job.handler.__func__ is UnitExecutor.execute
    assert job.handler.__self__.units is job.units
    assert job.strict_gaps is True and job.always_execute is True and job.propagate_handoff is False
    assert len(job.input_validators) == 1
    assert job.input_validators[0].__name__ == "validate"
    assert job.implementation_identity is None and job.validation_identity is None


def test_no_job_output_validator_or_result_transform_is_installed() -> None:
    job = build_job()
    assert job.output_validators == ()
    assert job.result_transform is None
    result = {
        "schema": "appsec-review/unit-execution/1", "status": "SUCCEEDED",
        "outputs": {PUBLISH: {"schema": SCHEMA}}, "units": {},
    }
    assert job.finalize_result(SimpleNamespace(), result) is result


def test_shipped_dev_configuration_matches_the_topology_and_passes_validation() -> None:
    config = load_config(ROOT / "appsec-review.toml", profile="dev").job("job_model_connectivity")
    assert [(step, tuple(config.step(step).tasks)) for step in config.steps] == [
        ("connectivity", ("resolve_models", "verify_models")), ("publication", ("publish_handoff",)),
    ]
    assert config.settings["timeout_seconds"] == 120
    check = lambda *args, **kwargs: pytest.fail("validation must not call a provider")
    assert build_job(check_models=check).input_validators[0](SimpleNamespace(config=config), None) is None


@pytest.mark.parametrize("steps", [
    (), ("publication", "connectivity"), ("connectivity",), ("connectivity", "publication", "extra"),
], ids=["empty", "reordered", "missing", "extra"])
def test_validation_rejects_changed_step_topology_before_reading_settings(steps) -> None:
    config = SimpleNamespace(steps=dict.fromkeys(steps))
    with pytest.raises(ValueError, match="^model connectivity topology does not match configuration$"):
        build_job(check_models=object()).input_validators[0](SimpleNamespace(config=config), None)


@pytest.mark.parametrize(("step", "tasks"), [
    ("connectivity", ()),
    ("connectivity", ("verify_models", "resolve_models")),
    ("publication", ("publish_handoff", "extra")),
], ids=["missing-task", "reordered-tasks", "extra-task"])
def test_validation_rejects_changed_task_topology_and_names_the_step(step, tasks) -> None:
    config = configuration()
    config.steps[step] = SimpleNamespace(tasks=tasks)
    with pytest.raises(ValueError, match=f"^model connectivity task order mismatch: {step}$"):
        build_job(check_models=object()).input_validators[0](SimpleNamespace(config=config), None)


@pytest.mark.parametrize("timeout", [None, False, True, "120", 1.0, -1, 0, 601],
                         ids=["none", "false", "true", "string", "float", "negative", "zero", "too-large"])
def test_validation_rejects_non_integer_or_out_of_range_timeout(timeout) -> None:
    with pytest.raises(ValueError, match="^model connectivity timeout is invalid$"):
        build_job(check_models=object()).input_validators[0](
            SimpleNamespace(config=configuration(timeout=timeout)), None,
        )


def test_validation_rejects_a_missing_timeout_setting() -> None:
    config = configuration()
    config.settings.clear()
    with pytest.raises(ValueError, match="^model connectivity timeout is invalid$"):
        build_job(check_models=object()).input_validators[0](SimpleNamespace(config=config), None)


@pytest.mark.parametrize("timeout", [1, 120, 600], ids=["minimum", "default", "maximum"])
def test_validation_accepts_inclusive_timeout_bounds_without_checking_a_provider(timeout) -> None:
    check = lambda *args, **kwargs: pytest.fail("claim-time validation must not call the provider")
    assert build_job(check_models=check).input_validators[0](
        SimpleNamespace(config=configuration(timeout=timeout)), None,
    ) is None


def test_validation_rejects_an_unwired_check_before_any_unit_runs() -> None:
    with pytest.raises(ValueError, match="^model connectivity check is not wired into this job instance$"):
        build_job().input_validators[0](SimpleNamespace(config=configuration()), None)


def test_resolve_wires_run_configuration_into_model_selection_and_counts_unique_pairs(
    tmp_path: Path, monkeypatch,
) -> None:
    unit = context(tmp_path, RESOLVE)
    document = object()
    required = [model("job_a", "p", "a"), model("job_b", "p", "a"), model("job_c", "q", "a")]
    optional = [model("job_d", "p", "a"), model("job_e", "p", "b"), model("job_f", "p", "b")]
    calls = []
    monkeypatch.setattr(connectivity, "resolved_configuration",
                        lambda root: calls.append(("read", root)) or document)
    monkeypatch.setattr(connectivity, "required_models",
                        lambda value: calls.append(("split", value)) or (required, optional))
    result = handler(RESOLVE)(unit)
    assert calls == [("read", unit.job.run_root), ("split", document)]
    assert result == {
        "required": required, "not_required": optional, "model_count": 2, "not_required_count": 1,
    }
    assert result["required"] is required and result["not_required"] is optional
    assert not unit.job.run_root.exists()


def test_verify_wires_the_callback_timeout_unit_and_output_to_the_report_writer(
    tmp_path: Path, monkeypatch,
) -> None:
    check = object()
    resolved = {
        "required": [model("job_a", "a", "m")],
        "not_required": [model("job_z", "z", "off"), model("job_b", "a", "off")],
    }
    unit = context(tmp_path, VERIFY, {RESOLVE: resolved}, timeout="49")
    document = {
        "providers": {
            "z": {"models": {"z": {"available": True}, "a": {"available": True}}},
            "a": {"models": {"m": {"available": True}, "off": {"available": False}}},
        },
        "unavailable": [],
        "unavailable_not_required": [{"provider": "z", "model": "off"}, {"provider": "a", "model": "off"}],
        "gaps": [],
    }
    calls = []

    def verify(callback, required, optional, **kwargs):
        calls.append(("verify", callback, required, optional, kwargs))
        return document

    def write(path, value):
        calls.append(("write", path, value))
        return {"path": str(path), "sha256": "a" * 64, "size_bytes": 17}

    monkeypatch.setattr(connectivity, "verify_configured_models", verify)
    monkeypatch.setattr(connectivity, "write_json", write)
    result = handler(VERIFY, check_models=check)(unit)
    assert calls == [
        ("verify", check, resolved["required"], resolved["not_required"],
         {"timeout_seconds": 49, "unit_id": VERIFY}),
        ("write", unit.unit_root / "model-connectivity.json", document),
    ]
    assert result == {
        "schema": SCHEMA, "artifact": {
            "path": "data/jobs/job_model_connectivity/attempts/attempt_0001/steps/"
                    "connectivity/tasks/verify_models/model-connectivity.json",
            "sha256": "a" * 64, "size_bytes": 17,
        },
        "providers": ["a", "z"], "verified": ["a/m", "z/a", "z/z"], "not_required": ["a/off", "z/off"],
        "unavailable_not_required": ["a/off", "z/off"], "gaps": [], "terminal_status": "SUCCEEDED",
    }
    assert unit.job.events.records == [("MODEL_CONNECTIVITY_COMPLETED", {
        "unit_id": VERIFY, "provider_count": 2, "model_count": 4,
        "unavailable_count": 0, "unavailable_not_required_count": 2,
    })]


def test_publish_wires_only_the_verified_summary_and_keeps_gaps_on_the_observing_unit(
    tmp_path: Path, monkeypatch,
) -> None:
    verified = {
        "artifact": {"path": "verification.json", "sha256": "a" * 64, "size_bytes": 17},
        "providers": ["p"], "verified": ["p/m"], "not_required": ["p/off"],
        "unavailable_not_required": ["p/off"],
        "gaps": [{"code": "producer_blocked", "scope_id": "p/off"}],
        "terminal_status": "COMPLETED_WITH_GAPS",
    }
    unit = context(tmp_path, PUBLISH, {VERIFY: verified})
    writes = []
    monkeypatch.setattr(connectivity, "write_json",
                        lambda path, value: writes.append((path, value)) or {
                            "path": str(path), "sha256": "b" * 64, "size_bytes": 29,
                        })
    result = handler(PUBLISH)(unit)
    assert writes == [(unit.unit_root / "model-connectivity-handoff.json", {
        "schema": SCHEMA, "artifact": verified["artifact"], "providers": ["p"], "verified": ["p/m"],
        "not_required": ["p/off"], "unavailable_not_required": ["p/off"],
    })]
    assert result == {
        "schema": SCHEMA, "artifact": {
            "path": "data/jobs/job_model_connectivity/attempts/attempt_0001/steps/"
                    "publication/tasks/publish_handoff/model-connectivity-handoff.json",
            "sha256": "b" * 64, "size_bytes": 29,
        },
        "verified": ["p/m"], "not_required": ["p/off"], "unavailable_not_required": ["p/off"],
        "terminal_status": "SUCCEEDED", "gaps": [],
    }
    assert verified["gaps"] == [{"code": "producer_blocked", "scope_id": "p/off"}]
    assert unit.job.events.records == []
