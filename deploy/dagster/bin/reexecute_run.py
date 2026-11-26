"""Guarded native Dagster parent re-execution; never a whole-graph fallback."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import pickle
import re
import sys


from appsec_review.runtime.inputs import PARENT_REEXECUTION_SCHEMA as SCHEMA


def selected_steps(dependencies: dict[str, set[str]], job_id: str, *,
                   additional_jobs: list[str] | tuple[str, ...] = ()) -> list[str]:
    if not isinstance(additional_jobs, (list, tuple)):
        raise ValueError("additional restart boundaries must be a list of jobs")
    roots = [job_id, *additional_jobs]
    if (any(not isinstance(root, str) or not re.fullmatch(r"job_[a-z][a-z0-9_]*", root)
            for root in roots) or len(set(roots)) != len(roots)):
        raise ValueError("restart boundary must name a distinct registered job")
    selected = set()
    for root in roots:
        prefix = root.removeprefix("job_") + "__"
        steps = {key for key in dependencies if key.startswith(prefix)}
        if prefix + "begin" not in steps or prefix + "finalize" not in steps:
            raise ValueError("restart boundary is absent from the parent execution plan")
        selected.update(steps)
    if any(not parents <= dependencies.keys() for parents in dependencies.values()):
        raise ValueError("execution plan contains unknown dependencies")
    while True:
        added = {key for key, parents in dependencies.items() if parents & selected} - selected
        if not added:
            return sorted(selected)
        selected.update(added)


def snapshot_shape(snapshot) -> dict:
    return {
        step.key: {
            "inputs": sorted(
                (item.name, item.dagster_type_key,
                 sorted((handle.step_key, handle.output_name, handle.mapping_key)
                        for handle in item.upstream_output_handles))
                for item in step.inputs),
            "outputs": sorted((item.name, item.dagster_type_key, item.properties.is_dynamic)
                              for item in step.outputs),
        }
        for step in snapshot.steps
    }


def retained_outputs(instance, snapshot, selected: set[str], known_state) -> list[dict]:
    handles = {
        handle for step in snapshot.steps if step.key in selected
        for item in step.inputs if item.dagster_type_key != "Nothing"
        for handle in item.upstream_output_handles if handle.step_key not in selected
    }
    storage = Path(instance.storage_directory())
    outputs = []
    for handle in sorted(handles, key=lambda item: (item.step_key, item.output_name)):
        if handle.mapping_key is not None:
            raise ValueError("mapped parent outputs require a separate re-execution plan")
        state = known_state.parent_state
        while state is not None and handle not in state.produced_outputs:
            state = state.parent_state
        if state is None:
            raise ValueError(f"parent has no committed output for {handle.step_key}/{handle.output_name}")
        path = storage / state.run_id / handle.step_key / handle.output_name
        if (not path.is_file() or path.is_symlink()
                or not path.resolve().is_relative_to(storage.resolve())):
            raise ValueError(f"retained parent output is unavailable: {handle.step_key}/{handle.output_name}")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        outputs.append({
            "run_id": state.run_id, "step_key": handle.step_key, "output_name": handle.output_name,
            "sha256": digest, "size_bytes": path.stat().st_size,
        })
    return outputs


def canonical(value) -> bytes:
    from appsec_review.storage import canonical_json
    return canonical_json(value)


class ParentContextReader(pickle.Unpickler):
    def find_class(self, module, name):
        raise ValueError("retained parent context must contain primitive data, not Python objects")


def retained_handoff_pins(instance, outputs: list[dict], run_root: Path) -> dict[str, str]:
    from appsec_review.retrieval.core import _accepted_handoff
    from appsec_review.runtime.repair import verify_publication

    pins = {}
    for output in outputs:
        path = Path(instance.storage_directory()) / output["run_id"] / output["step_key"] / output["output_name"]
        with path.open("rb") as stream:
            payload = stream.read(1024 * 1024 + 1)
        if len(payload) > 1024 * 1024 or hashlib.sha256(payload).hexdigest() != output["sha256"]:
            raise ValueError("retained parent context changed or exceeds its metadata bound")
        value = ParentContextReader(io.BytesIO(payload)).load()
        if not isinstance(value, dict) or value.get("run_id") != run_root.name:
            raise ValueError("retained parent context belongs to another application run")
        supplied = value.get("completed_handoffs", value.get("handoffs", {}))
        if not isinstance(supplied, dict):
            raise ValueError("retained parent handoffs are not a mapping")
        for producer, digest in supplied.items():
            if (not isinstance(producer, str) or not re.fullmatch(r"job_[a-z0-9_]+", producer)
                    or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                raise ValueError("retained parent handoff identity is invalid")
            if producer in pins and pins[producer] != digest:
                raise ValueError(f"retained parent contexts disagree about {producer}")
            pins[producer] = digest
    for producer, digest in sorted(pins.items()):
        handoff, _ = _accepted_handoff(run_root, producer, digest)
        verify_publication(run_root, handoff, digest)
    return dict(sorted(pins.items()))


def scoped_source_repair(config, root, selected, release, binding):
    from appsec_review.jobs.cataloging import source_fingerprint
    from appsec_review.orchestration.topology import wave1_dependencies
    from appsec_review.runtime.dependencies import graph_dependencies
    from appsec_review.runtime.launch import configured_target
    from appsec_review.runtime.registry import builtin_registry
    from appsec_review.runtime.repair import deployment_identity, plan_repair
    from appsec_review.runtime.configuration import admitted_configuration_sha256

    if (binding["release_sha256"] == release["sha256"]
            and binding["deployment"] == deployment_identity(config.runtime.repository_root)
            and admitted_configuration_sha256(root, binding) == config.resolved_sha256):
        return None, (), None, None
    registry = builtin_registry()
    order = wave1_dependencies(set(registry.job_ids()))
    if order is None:
        raise ValueError("registered wave1 topology is unavailable")
    jobs = tuple(registry.build(job_id) for job_id in order
                 if job_id.removeprefix("job_") + "__begin" in selected)
    if not jobs:
        raise ValueError("parent re-execution selects no registered application jobs")
    dependencies = graph_dependencies(jobs)
    target = configured_target(config.runtime.repository_root, config.target_acquisition.targets_dir)
    if target is None:
        raise ValueError("parent re-execution requires the original target")
    plan = plan_repair(config, root, jobs, source_fingerprint(target),
                       target_root=target, dependencies=dependencies)
    if not plan["admissible"] or plan["refusals"]:
        raise ValueError("selected-job source repair refused: " + "; ".join(plan["refusals"]))
    return plan, jobs, dependencies, target


def container_command(container_id: str, request: dict) -> list[str]:
    return ["exec", container_id, "python", "-c", Path(__file__).read_text(encoding="utf-8"),
            json.dumps(request, sort_keys=True)]


def execute_request(request: dict) -> dict:
    from dagster import DagsterInstance, DagsterRunStatus, RunsFilter
    from dagster._core.execution.plan.state import KnownExecutionState
    from dagster._core.storage.tags import PARENT_RUN_ID_TAG, ROOT_RUN_ID_TAG
    from dagster._core.workspace.context import WorkspaceProcessContext
    from dagster._core.workspace.load_target import WorkspaceFileTarget
    from appsec_review.config import load_config
    from appsec_review.config.run_selection import RunConfigurations
    from appsec_review.runtime.release import load_release, read_document
    from appsec_review.runtime.repair import code_server_worker_status, current_binding, stopped_reasons
    from appsec_review.storage import RunStore
    import os

    if request["action"] not in {"preview", "launch"}:
        raise ValueError("unsupported re-execution action")
    config = load_config(os.environ.get("APPSEC_REVIEW_CONFIG", "appsec-review.toml"))
    config = RunConfigurations(config).for_tags(request["tags"])
    root = RunStore(config.runtime.runs_dir).resolve(request["application_run_id"])
    if (root / "data/configuration/execution-safety.json").exists():
        raise ValueError("first-error recovery requires the existing successor-run procedure")
    from appsec_review.runtime.configuration import candidate_configuration_changes
    candidate_configuration_changes(config, root)
    release = load_release(config.runtime.repository_root)
    binding = current_binding(root)
    if release is None or binding is None:
        raise ValueError("parent re-execution requires measured current and original source bindings")
    reasons = stopped_reasons(config, root)
    if reasons:
        raise ValueError("re-execution requires verified stopped workers: " + "; ".join(reasons))

    from appsec_review.storage.validation import validation_scope
    with validation_scope(root), DagsterInstance.get() as instance, WorkspaceProcessContext(
            instance, WorkspaceFileTarget(paths=["/opt/dagster/home/workspace.yaml"])) as workspace:
        verified_dispatches = []
        for prior in instance.get_runs(filters=RunsFilter(tags={"appsec/application_run_id": root.name})):
            if not prior.is_finished:
                raise ValueError(f"application dispatch is still active: {prior.run_id}")
            launcher = instance.run_launcher
            if launcher.supports_check_run_worker_health:
                worker_status = launcher.check_run_worker_health(prior).status.value
            elif type(launcher).__name__ == "DefaultRunLauncher":
                worker_status = code_server_worker_status(prior)
            else:
                raise ValueError("launcher cannot verify stopped parent workers")
            if worker_status not in {"SUCCESS", "NOT_FOUND"}:
                raise ValueError(f"dispatch worker stop is uncertain: {prior.run_id}: {worker_status}")
            verified_dispatches.append(prior.run_id)
        parent = instance.get_run_by_id(request["parent_run_id"])
        if (parent is None or not parent.is_finished or parent.job_name != "wave1_review"
                or parent.tags.get("appsec/application_run_id") != root.name):
            raise ValueError("parent must be a terminal wave1 dispatch of this application run")
        for name in ("appsec/profile", "appsec/overlay", "appsec/compiler_target"):
            if parent.tags.get(name) != request["tags"].get(name):
                raise ValueError(f"parent re-execution cannot change {name}")
        if parent.run_config.get("resources", {}).get("io_manager"):
            raise ValueError("custom parent I/O configuration is not supported by this recovery path")
        request_context = workspace.create_request_context()
        origin = parent.remote_job_origin.repository_origin
        location = request_context.get_code_location(origin.code_location_origin.location_name)
        remote_job = location.get_repository(origin.repository_name).get_full_job(parent.job_name)
        old = instance.get_execution_plan_snapshot(parent.execution_plan_snapshot_id)
        full = location.get_execution_plan(
            remote_job, parent.run_config, step_keys_to_execute=None, known_state=None, instance=instance)
        shape = snapshot_shape(old)
        if shape != snapshot_shape(full.execution_plan_snapshot):
            raise ValueError("execution graph or I/O types changed; inspect a new dependency plan")
        dependencies = {
            step.key: {handle.step_key for item in step.inputs for handle in item.upstream_output_handles}
            for step in old.steps
        }
        selected = selected_steps(dependencies, request["from_job"],
                                  additional_jobs=request.get("additional_jobs", ()))
        stats = instance.get_run_step_stats(parent.run_id)
        outside_failures = [step.step_key for step in stats
                            if step.status.value == "FAILURE" and step.step_key not in selected]
        if outside_failures:
            raise ValueError("other failed steps are outside the requested boundary: " + ", ".join(outside_failures))
        known = KnownExecutionState.build_for_reexecution(instance, parent)
        outputs = retained_outputs(instance, old, set(selected), known)
        if not outputs:
            raise ValueError("targeted recovery requires retained upstream outputs")
        known = known.update_for_step_selection(selected)
        subset = location.get_execution_plan(
            remote_job, parent.run_config, step_keys_to_execute=selected, known_state=known, instance=instance)
        pins = retained_handoff_pins(instance, outputs, root)
        source_repair, jobs, source_dependencies, target = scoped_source_repair(config, root, selected, release, binding)
        plan = {
            "schema": SCHEMA, "application_run_id": root.name, "parent_run_id": parent.run_id,
            "root_run_id": parent.root_run_id or parent.run_id, "from_job": request["from_job"],
            "release_sha256": release["sha256"], "resolved_config_sha256": config.resolved_sha256,
            "binding_sha256": hashlib.sha256(canonical(binding)).hexdigest(),
            "graph_sha256": hashlib.sha256(canonical(shape)).hexdigest(),
            "step_keys": selected, "retained_outputs": outputs,
            "retained_handoffs": pins, "source_repair": source_repair,
            "retained_step_count": len(dependencies) - len(selected),
            "verified_dispatches": sorted(verified_dispatches),
        }
        if request.get("additional_jobs"):
            plan["additional_jobs"] = request["additional_jobs"]
        plan["sha256"] = hashlib.sha256(canonical(plan)).hexdigest()
        if request["action"] == "preview":
            return plan
        if request["plan"] != plan:
            raise ValueError("parent re-execution plan changed; inspect it again before submission")
        if source_repair is not None:
            from appsec_review.runtime.repair import admit_repair
            admit_repair(config, root, jobs, source_repair, target_root=target, dependencies=source_dependencies)
        tags = {**remote_job.tags, **request["tags"],
                PARENT_RUN_ID_TAG: plan["parent_run_id"], ROOT_RUN_ID_TAG: plan["root_run_id"]}
        run = instance.create_run(
            job_name=parent.job_name, run_id=request["dagster_run_id"], run_config=parent.run_config,
            resolved_op_selection=parent.resolved_op_selection, step_keys_to_execute=selected,
            status=DagsterRunStatus.NOT_STARTED, tags=tags,
            root_run_id=plan["root_run_id"], parent_run_id=parent.run_id,
            job_snapshot=remote_job.job_snapshot, execution_plan_snapshot=subset.execution_plan_snapshot,
            parent_job_snapshot=remote_job.parent_job_snapshot, op_selection=parent.op_selection,
            asset_selection=remote_job.asset_selection, asset_check_selection=remote_job.asset_check_selection,
            remote_job_origin=remote_job.get_remote_origin(), job_code_origin=remote_job.get_python_origin(),
            asset_graph=request_context.asset_graph,
        )
        instance.submit_run(run.run_id, request_context)
        return {"dagster_run_id": run.run_id, "plan_sha256": plan["sha256"]}


if __name__ == "__main__":
    print(json.dumps(execute_request(json.loads(sys.argv[1])), sort_keys=True))
