"""One bounded production node transaction, not an unconditional review-graph job."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from appsec_review.runtime import Job, Unit, UnitExecutor

from .datasets import CONTRACT, DATASETS


def iteration_definition(worker: Callable[[Mapping[str, Any], str], Mapping[str, Any]]):
    from dagster import In, Out, graph, op

    @op(name="execute_build_node", ins={}, out=Out(dict),
        config_schema={"request": dict}, tags={"appsec/pool": "cpp_build"})
    def execute(context):
        return dict(worker(context.op_config["request"], context.run_id))

    @graph(name="build_iteration")
    def iteration():
        return execute()

    return iteration.to_job(description="Configure, build, capture and commit one selected build node.")


def invoke_iteration(request: Mapping[str, Any], label: str,
                     worker: Callable[[Mapping[str, Any], str], Mapping[str, Any]]) -> Mapping[str, Any]:
    return _invoke(iteration_definition(worker), request, label)


def _invoke(definition, request: Mapping[str, Any], label: str) -> Mapping[str, Any]:
    result = definition.execute_in_process(
        run_config={"ops": {"execute_build_node": {"config": {"request": dict(request)}}}},
        tags={"appsec/build_iteration_label": label, "appsec/internal_build_iteration": "true"},
        raise_on_error=False,
    )
    if not result.success:
        raise RuntimeError(f"build iteration invocation failed: {result.run_id}")
    return result.output_for_node("execute_build_node")


def load_iteration_configuration(run_root: Path):
    from appsec_review.config import load_config
    manifest = json.loads((run_root / "data/configuration/manifest.json").read_bytes())
    selection = manifest["selection"]
    config = load_config(Path(manifest["sources"][0]["path"]), profile=selection["profile"],
                         overlay=selection.get("overlay"), compiler_target=selection["compiler_target"])
    if config.resolved_sha256 != manifest["resolved_sha256"]:
        raise ValueError("iteration worker configuration differs from its frozen run")
    return config


def invoke_registered_iteration(run_root: Path, request: Mapping[str, Any], label: str):
    from appsec_review.runtime import JobRunner
    return _invoke(registered_definition(load_iteration_configuration(run_root), JobRunner), request, label)


def iteration_inputs(run_root: Path, reference: Mapping[str, Any]):
    from appsec_review.jobs.build_iterations import read_reference
    from appsec_review.jobs.cataloging import source_fingerprint
    from appsec_review.runtime.launch import LaunchInputs
    request = read_reference(run_root, reference)
    target = Path(request["target"]).resolve(strict=True)
    source = request["binding"]["source_identity"]
    if source_fingerprint(target) != source:
        raise ValueError("iteration target differs from its immutable source identity")
    from appsec_review.runtime.inputs import selected_handoffs
    return LaunchInputs(target, source, selected_handoffs(build_job(), run_root, None))


def registered_definition(config, runner_factory):
    from appsec_review.runtime.launch import launch
    from appsec_review.storage import RunStore

    def execute(reference, dagster_run_id):
        run_root = RunStore(config.runtime.runs_dir).resolve(reference["run_id"])
        inputs = iteration_inputs(run_root, reference)
        outcome = launch(
            runner_factory(config), build_job(), inputs, run_id=run_root.name,
            orchestration={"system": "dagster", "run_id": dagster_run_id,
                           "iteration_request": json.dumps(reference, sort_keys=True)})
        return outcome["result"]["outputs"]["execute.node"]

    return iteration_definition(execute)


def build_job() -> Job:
    def execute(unit):
        raw = unit.job.orchestration.get("iteration_request")
        if not raw:
            raise ValueError("job_build_iteration requires an immutable iteration_request reference")
        from appsec_review.jobs.build_iterations import read_reference
        from appsec_review.jobs.job_language_build.job import (
            iteration_controller, _production_iteration,
        )
        reference = json.loads(raw)
        request = read_reference(unit.job.run_root, reference)
        from appsec_review.runtime.contracts import InputChannel
        from appsec_review.runtime.inputs import observe_external
        observe_external(unit.job.run_root, "build_controller", "iteration_request",
                         "appsec-review/build-iteration-request/1", reference,
                         channel=InputChannel.TRANSACTION)
        pending_path = unit.job.run_root / "data/build/iterations/pending.json"
        if not pending_path.is_file():
            raise ValueError("standalone iteration has no active controller claim")
        pending = json.loads(pending_path.read_bytes())
        if pending["request"] != reference:
            raise ValueError("standalone iteration is not the controller's claimed request")
        config = load_iteration_configuration(unit.job.run_root)
        language = replace(unit, job=replace(unit.job, config=config.job("job_language_build")))
        controller, accepted, _skipped = iteration_controller(language)
        return controller._execute(reference, unit.job.orchestration["run_id"],
                                   lambda value, run_id: _production_iteration(language, value, run_id, accepted))

    units = (Unit("execute.node", execute),)
    return Job("job_build_iteration", "build_iteration", UnitExecutor(units).execute,
               units=units, datasets=DATASETS, contract=CONTRACT,
               always_execute=True, propagate_handoff=False, run_input_identity=iteration_input_identity)


def iteration_input_identity(target: Path | None, run_root: Path) -> str:
    from appsec_review.storage.atomic import canonical_json_sha256
    from appsec_review.jobs.build_iterations import read_reference
    from appsec_review.storage.shared import safe_path
    path = safe_path(run_root, "data/build/iterations/pending.json")
    if not path.is_file():
        return canonical_json_sha256({"iteration_request": None})
    request = json.loads(path.read_bytes())["request"]
    read_reference(run_root, request)
    return canonical_json_sha256({"iteration_request": request})
