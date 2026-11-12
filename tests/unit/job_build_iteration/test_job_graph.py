"""job_build_iteration: the one-unit graph and the wiring of job.py, with the controller, the
production iteration, the launch and the Dagster definition faked at the module boundary.

No Dagster execution, no runner, no container: each function is called with a context over a run
root the test writes, and the values a regression would change are asserted (which reference is
re-read, which request is observed, which configuration the language-build context is given,
which run id the worker receives).
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs import build_iterations
from appsec_review.jobs.build_iterations import REQUEST_SCHEMA, retain
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_build_iteration import job as job_module
from appsec_review.jobs.job_build_iteration.job import (
    _invoke, build_job, invoke_registered_iteration, iteration_inputs, load_iteration_configuration,
    registered_definition,
)
from appsec_review.jobs.job_language_build import job as language_job
from appsec_review.runtime import inputs as runtime_inputs
from appsec_review.runtime import launch as runtime_launch
from appsec_review.runtime.contracts import InputChannel
from appsec_review.runtime.job import JobContext
from appsec_review.runtime.launch import LaunchInputs
from appsec_review.runtime.units import UnitContext

ROOT = Path(__file__).resolve().parents[3]
RUN_ID = "2026-11-12-0001"
DAGSTER_RUN = "dagster-run-" + "1" * 8


# --- graph shape -----------------------------------------------------------------------------------

def test_graph_is_one_execute_unit_without_validators_and_the_job_is_an_always_executed_transaction() -> None:
    job = build_job()
    (unit,) = job.units
    assert (unit.unit_id, unit.dependencies, unit.input_validators, unit.output_validators) == (
        "execute.node", (), (), ())
    assert job.input_validators == () and job.output_validators == ()
    assert (job.job_id, job.name, job.schema_identity) == (
        "job_build_iteration", "build_iteration", "appsec-review/job-result/1")
    assert job.always_execute is True and job.propagate_handoff is False and job.strict_gaps is True


# --- the Dagster invocation boundary ------------------------------------------------------------------

class _Definition:
    """A stand-in for the Dagster job definition: records the invocation, answers like a result."""

    def __init__(self, success: bool = True) -> None:
        self.success = success
        self.calls: list[dict] = []

    def execute_in_process(self, **kwargs):
        self.calls.append(kwargs)
        definition = self

        class Result:
            success = definition.success
            run_id = DAGSTER_RUN

            @staticmethod
            def output_for_node(node):
                return {"node": node, "terminal_status": "SUCCEEDED"}
        return Result()


def test_invoke_passes_the_request_as_op_config_tags_the_internal_iteration_and_returns_the_node_output() -> None:
    definition = _Definition()
    request = {"path": "artifacts/build/iterations/requests/a.json", "sha256": "a" * 64, "size_bytes": 3, "run_id": RUN_ID}
    assert _invoke(definition, request, "build_cpp") == {"node": "execute_build_node", "terminal_status": "SUCCEEDED"}
    (call,) = definition.calls
    assert call == {
        "run_config": {"ops": {"execute_build_node": {"config": {"request": request}}}},
        "tags": {"appsec/build_iteration_label": "build_cpp", "appsec/internal_build_iteration": "true"},
        "raise_on_error": False,
    }
    assert call["run_config"]["ops"]["execute_build_node"]["config"]["request"] is not request, "a copy, not the mapping"


def test_a_failed_dagster_run_is_an_error_naming_its_run_id_not_a_result() -> None:
    with pytest.raises(RuntimeError, match=f"build iteration invocation failed: {DAGSTER_RUN}"):
        _invoke(_Definition(success=False), {"path": "x"}, "label")


def test_invoke_registered_iteration_resolves_the_frozen_configuration_and_launches_with_the_job_runner(
        tmp_path: Path, monkeypatch) -> None:
    from appsec_review.runtime import JobRunner
    seen: dict = {}
    monkeypatch.setattr(job_module, "load_iteration_configuration", lambda run_root: seen.setdefault("root", run_root))
    monkeypatch.setattr(job_module, "registered_definition",
                        lambda config, factory: seen.update(config=config, factory=factory) or "definition")
    monkeypatch.setattr(job_module, "_invoke", lambda definition, request, label: (definition, request, label))
    result = invoke_registered_iteration(tmp_path, {"path": "r"}, "build_cpp2")
    assert result == ("definition", {"path": "r"}, "build_cpp2")
    assert seen["root"] == tmp_path and seen["config"] == tmp_path and seen["factory"] is JobRunner


# --- the frozen run configuration ---------------------------------------------------------------------

def _write_manifest(run_root: Path, config, *, resolved_sha256: str | None = None) -> None:
    configuration = run_root / "data/configuration"
    configuration.mkdir(parents=True, exist_ok=True)
    (configuration / "manifest.json").write_text(json.dumps({
        "schema": "appsec-review/run-configuration/2",
        "resolved_sha256": resolved_sha256 or config.resolved_sha256,
        "sources": [{"path": str(ROOT / "appsec-review.toml"), "sha256": config.source_sha256}],
        "selection": {"profile": config.profile, "overlay": None, "compiler_target": config.compiler_target.value},
    }), encoding="utf-8")


def test_the_worker_reloads_the_run_manifest_selection_and_refuses_a_drifted_resolved_identity(tmp_path: Path) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    run_root = tmp_path / RUN_ID
    _write_manifest(run_root, config)
    loaded = load_iteration_configuration(run_root)
    assert loaded.resolved_sha256 == config.resolved_sha256
    assert loaded.profile == config.profile and loaded.compiler_target is config.compiler_target
    assert loaded.job("job_language_build").name == "language_build"
    _write_manifest(run_root, config, resolved_sha256="0" * 64)
    with pytest.raises(ValueError, match="iteration worker configuration differs from its frozen run"):
        load_iteration_configuration(run_root)


# --- iteration_inputs: the request binds the target by its immutable source identity ------------------

def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src/main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    return target


def _request(run_root: Path, target: Path, fingerprinted: Path | None = None) -> dict:
    """A retained iteration request for ``target``, bound to the source identity of ``fingerprinted``."""
    value = {"schema": REQUEST_SCHEMA, "run_id": run_root.name, "node_id": "build-unit-" + "a" * 20,
             "target": str(target), "binding": {"source_identity": source_fingerprint(fingerprinted or target)}}
    return {**retain(run_root, "requests", value), "run_id": run_root.name}


def test_iteration_inputs_resolve_the_retained_target_its_fingerprint_and_the_selected_upstream_handoffs(
        tmp_path: Path, monkeypatch) -> None:
    run_root = tmp_path / RUN_ID
    run_root.mkdir()
    target = _target(tmp_path)
    reference = _request(run_root, target)
    seen: dict = {}

    def fake_selected(job, root, supplied):
        seen.update(job=job.job_id, root=root, supplied=supplied)
        return {"job_project_build": "6" * 64}
    monkeypatch.setattr(runtime_inputs, "selected_handoffs", fake_selected)
    inputs = iteration_inputs(run_root, reference)
    assert inputs == LaunchInputs(target.resolve(), source_fingerprint(target), {"job_project_build": "6" * 64})
    assert seen == {"job": "job_build_iteration", "root": run_root, "supplied": None}


def test_iteration_inputs_refuse_a_target_that_no_longer_matches_its_source_identity(tmp_path: Path, monkeypatch) -> None:
    run_root = tmp_path / RUN_ID
    run_root.mkdir()
    target = _target(tmp_path)
    reference = _request(run_root, target)
    monkeypatch.setattr(runtime_inputs, "selected_handoffs", lambda *a: {})
    (target / "src/main.c").write_text("int main(void) { return 1; }\n", encoding="utf-8")
    with pytest.raises(ValueError, match="iteration target differs from its immutable source identity"):
        iteration_inputs(run_root, reference)
    missing = _request(run_root, tmp_path / "gone", target)
    with pytest.raises(FileNotFoundError):
        iteration_inputs(run_root, missing)


# --- registered_definition: the Dagster op body launches the job over the resolved run ----------------

def test_the_registered_op_body_launches_the_job_in_the_referenced_run_with_the_dagster_orchestration(
        tmp_path: Path, monkeypatch) -> None:
    runs = tmp_path / "runs"
    run_root = runs / RUN_ID
    run_root.mkdir(parents=True)
    config = SimpleNamespace(runtime=SimpleNamespace(runs_dir=runs))
    reference = {"path": "artifacts/build/iterations/requests/a.json", "sha256": "a" * 64, "size_bytes": 1,
                 "run_id": RUN_ID}
    launch_inputs = LaunchInputs(tmp_path, "f" * 64, {})
    seen: dict = {}
    monkeypatch.setattr(job_module, "iteration_definition", lambda worker: worker)
    monkeypatch.setattr(job_module, "iteration_inputs",
                        lambda root, ref: seen.update(inputs_root=root, inputs_ref=ref) or launch_inputs)

    def fake_launch(runner, job, inputs, *, run_id, orchestration):
        seen.update(runner=runner, job=job.job_id, inputs=inputs, run_id=run_id, orchestration=orchestration)
        return {"result": {"outputs": {"execute.node": {"completion": {"path": "c"}, "terminal_status": "SUCCEEDED"}}}}
    monkeypatch.setattr(runtime_launch, "launch", fake_launch)
    execute = registered_definition(config, lambda cfg: ("runner-for", cfg))
    assert execute(reference, DAGSTER_RUN) == {"completion": {"path": "c"}, "terminal_status": "SUCCEEDED"}
    assert seen["inputs_root"] == run_root.resolve() and seen["inputs_ref"] == reference
    assert seen["runner"] == ("runner-for", config) and seen["job"] == "job_build_iteration"
    assert seen["inputs"] is launch_inputs and seen["run_id"] == RUN_ID
    assert seen["orchestration"] == {"system": "dagster", "run_id": DAGSTER_RUN,
                                     "iteration_request": json.dumps(reference, sort_keys=True)}
    with pytest.raises(FileNotFoundError, match="run does not exist"):
        execute({**reference, "run_id": "2026-11-12-0002"}, DAGSTER_RUN)


# --- the execute.node handler -------------------------------------------------------------------------

def _unit(run_root: Path, orchestration: dict) -> UnitContext:
    job = JobContext(run_id=run_root.name, attempt_id="attempt_0001", trigger="dagster", repository_root=ROOT,
                     run_root=run_root, attempt_root=run_root / "data/jobs/job_build_iteration/attempts/attempt_0001",
                     metadata_root=run_root / "metadata", orchestration=orchestration,
                     config=SimpleNamespace(job_id="job_build_iteration"), events=SimpleNamespace(),
                     target_root=run_root.parent / "target", source_fingerprint="f" * 64)
    return UnitContext(job=job, unit_id="execute.node", step_id="execute", task_id="node",
                       unit_root=run_root / "unit", outputs={})


def _handler():
    return build_job().units[0].handler


def _claim(run_root: Path, reference: dict) -> None:
    pending = run_root / "data/build/iterations/pending.json"
    pending.parent.mkdir(parents=True, exist_ok=True)
    pending.write_text(json.dumps({"request": reference, "before_generation": "g0"}), encoding="utf-8")


def test_the_handler_requires_an_iteration_request_and_an_active_controller_claim_for_that_request(
        tmp_path: Path) -> None:
    run_root = tmp_path / RUN_ID
    run_root.mkdir()
    with pytest.raises(ValueError, match="requires an immutable iteration_request reference"):
        _handler()(_unit(run_root, {"run_id": DAGSTER_RUN}))
    reference = _request(run_root, _target(tmp_path))
    unit = _unit(run_root, {"run_id": DAGSTER_RUN, "iteration_request": json.dumps(reference, sort_keys=True)})
    with pytest.raises(ValueError, match="standalone iteration has no active controller claim"):
        _handler()(unit)
    _claim(run_root, {**reference, "sha256": "b" * 64})
    with pytest.raises(ValueError, match="not the controller's claimed request"):
        _handler()(unit)
    tampered = {**reference, "size_bytes": reference["size_bytes"] + 1}
    with pytest.raises(ValueError, match="integrity mismatch"):
        _handler()(_unit(run_root, {"run_id": DAGSTER_RUN, "iteration_request": json.dumps(tampered)}))


def test_the_handler_observes_the_request_swaps_in_the_language_build_configuration_and_executes_the_claim(
        tmp_path: Path, monkeypatch) -> None:
    run_root = tmp_path / RUN_ID
    run_root.mkdir()
    reference = _request(run_root, _target(tmp_path))
    _claim(run_root, reference)
    seen: dict = {}
    observed: list = []
    monkeypatch.setattr(runtime_inputs, "observe_external",
                        lambda root, *args, **kwargs: observed.append((root, args, kwargs)))
    language_config = SimpleNamespace(job_id="job_language_build")
    monkeypatch.setattr(job_module, "load_iteration_configuration",
                        lambda root: SimpleNamespace(job=lambda name: seen.setdefault("job", name) and language_config))
    accepted = {"execution_mode": "iterative"}
    outcome = build_iterations.IterationOutcome({"terminal_status": "SUCCEEDED"}, (), True)

    class Controller:
        def _execute(self, ref, dagster_run_id, worker):
            seen.update(ref=ref, dagster_run_id=dagster_run_id)
            seen["outcome"] = worker({"node_id": "n"}, dagster_run_id)
            return {"completion": {"path": "completed"}, "terminal_status": "SUCCEEDED"}

    def fake_controller(unit):
        seen["controller_unit"] = unit
        return Controller(), accepted, [{"terminal_status": "GAP"}]

    def fake_production(unit, value, run_id, acc):
        seen.update(production_unit=unit, value=value, production_run_id=run_id, accepted=acc)
        return outcome
    monkeypatch.setattr(language_job, "iteration_controller", fake_controller)
    monkeypatch.setattr(language_job, "_production_iteration", fake_production)
    unit = _unit(run_root, {"run_id": DAGSTER_RUN, "iteration_request": json.dumps(reference, sort_keys=True)})
    result = _handler()(unit)
    assert result == {"completion": {"path": "completed"}, "terminal_status": "SUCCEEDED"}
    assert observed == [(run_root, ("build_controller", "iteration_request", REQUEST_SCHEMA, reference),
                         {"channel": InputChannel.TRANSACTION})]
    assert seen["job"] == "job_language_build"
    language_unit = seen["controller_unit"]
    assert language_unit is seen["production_unit"] and language_unit is not unit
    assert language_unit.job.config is language_config and language_unit.job.run_root == run_root
    assert language_unit.job.orchestration == unit.job.orchestration and language_unit.unit_id == "execute.node"
    assert unit.job.config.job_id == "job_build_iteration", "the original context is not mutated"
    assert seen["ref"] == reference and seen["dagster_run_id"] == DAGSTER_RUN
    assert seen["value"] == {"node_id": "n"} and seen["production_run_id"] == DAGSTER_RUN
    assert seen["accepted"] is accepted and seen["outcome"] is outcome
