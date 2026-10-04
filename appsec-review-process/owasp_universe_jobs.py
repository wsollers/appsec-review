#!/usr/bin/env python3
"""Graph-node wiring of the ADR-0034 OWASP universe chain.

``04-owasp-candidate-search`` keeps its logic in ``owasp_candidate_search`` (a CLI over plain files);
this module owns what the graph node needs around it: it binds each graph dependency of the node by
accepted pointer, envelope and attempt-tree hashes (dependencies come from ``job-graph.json``, so the
graph stays the one source of wiring), allocates an immutable attempt, calls ``main(argv)`` with the
accepted artifact paths (``--index`` code-index.sqlite, ``--treesitter-ast``, ``--source-sast``,
``--evidence-run-id`` for the accepted 02-evidence-index of this run, ``--component-map`` for the tag
cloud, ``--source-root``, ``--output``; a dependency that is not accepted, or was skipped, has no flag and
the module records the gap), wraps the bare ``search`` result with its input bindings
(``owasp_candidate_search.document``), validates it and publishes it through ``publish_job_output``.

``04-owasp-participation`` (``owasp_participation.run``) and ``04-owasp-universe``
(``owasp_universe.run``: BLOCKED over budget, never accepted) publish themselves. After an accepted
universe, ``project`` admits the T03 lane-in and runs the ``04-owasp-component-routing`` projection, so
the projected universe request exists for ``04-owasp-validation-worklist`` and is reused unchanged by
the join's T03-T06 chain. Job modules are imported only when a job runs.
"""
from __future__ import annotations

import argparse
import importlib
from pathlib import Path
import sys
from typing import Any

from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, identifier, now, read_json, run_path, tree_hashes
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current
import registry_paths
from schema_validate import validate_document

REPO = ROOT.parent
RULES = "data/owasp-asvs/category-rules-v1.json"
CANDIDATES, PARTICIPATION, UNIVERSE = "04-owasp-candidate-search", "04-owasp-participation", "04-owasp-universe"
# job -> (module, result artifact, result schema, worker kind, consumer whose edge authorizes a skip)
JOBS = {
    CANDIDATES: ("owasp_candidate_search", "owasp-candidate-search.json", "owasp-candidate-search.schema.json",
                 "deterministic_python", PARTICIPATION),
}
# dependency job -> the accepted artifact the module reads
ARTIFACTS = {
    "02-code-index": "code-index.sqlite",
    "02-code-property-graph": "code-property-graph.json",
    "02-treesitter-ast": "treesitter-ast.json",
    "02-source-sast": "source-sast.json",
    "02-evidence-index": "index.sqlite",
    "01-component-characterization": "component-purpose-map.json",
    "02-language-census": "language-census.json",
}
CANDIDATE_FLAGS = {"02-treesitter-ast": "--treesitter-ast", "02-source-sast": "--source-sast",
                   "01-component-characterization": "--component-map", "02-language-census": "--language-census"}
# the inputs owasp-candidate-search.schema.json binds (evidence index and tag cloud are in inputs.json)
CANDIDATE_INPUTS = ("02-code-index", "02-code-property-graph", "02-treesitter-ast", "02-source-sast",
                    "02-language-census")
SOURCES = {CANDIDATES: [RULES]}


def _job(job_id: str) -> tuple[str, str, str, str, str]:
    if job_id not in JOBS:
        raise Blocked(f"OWASP universe jobs: unsupported job {job_id}")
    return JOBS[job_id]


def root(run_id: str, job_id: str) -> Path:
    return data_path(run_id, "jobs", job_id)


def _contract(job_id: str) -> str:
    return read_json(registry_paths.template(job_id))["composition"]["output_contract_id"]


def _dependencies(job_id: str) -> list[dict[str, Any]]:
    from job_graph import load_graph
    return [dep for dep in load_graph()["jobs"][job_id]["dependencies"] if dep.get("enabled", True)]


def _pointer_base(run_id: str, job: str) -> Path:
    direct = data_path(run_id, "jobs", job)
    for value in (direct, direct / "whole"):
        if (value / "accepted.json").is_file():
            return value
    return direct


def accepted(run_id: str, job: str) -> dict[str, Any] | None:
    """The accepted common-envelope publication of ``job`` verified by pointer, envelope and attempt-tree
    hashes, or None when there is none. A changed tree is refused, never treated as absent."""
    base = _pointer_base(run_id, job)
    pointer_path = base / "accepted.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        return None
    pointer = read_json(pointer_path)
    if pointer.get("status") not in ("OK", "OK_WITH_GAPS", "SKIPPED"):
        return None
    attempt = base / "attempts" / str(pointer.get("attempt_id"))
    if (pointer.get("run_id") != run_id or pointer.get("job") != job or attempt.is_symlink() or not attempt.is_dir() or
            tree_hashes(attempt) != pointer.get("hashes") or
            file_hash(attempt / pointer.get("envelope_path", "result.json")) != pointer.get("envelope_sha256")):
        raise Blocked(f"OWASP universe jobs: accepted {job} is not current")
    envelope = read_json(attempt / pointer.get("envelope_path", "result.json"))
    binding = {"job_id": job, "attempt_id": pointer["attempt_id"], "status": pointer["status"],
               "skip_reason": envelope.get("skip_reason") if pointer["status"] == "SKIPPED" else None,
               "accepted_pointer_sha256": file_hash(pointer_path), "artifact_path": None, "artifact_sha256": None}
    artifact = ARTIFACTS.get(job)
    if pointer["status"] != "SKIPPED" and artifact:
        path = attempt / artifact
        if path.is_symlink() or not path.is_file():
            raise Blocked(f"OWASP universe jobs: accepted {job} has no {artifact}")
        binding.update(artifact_path=path.relative_to(data_path(run_id)).as_posix(), artifact_sha256=file_hash(path))
    return binding


def _source_root(run_id: str) -> tuple[Path, str]:
    manifest = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not manifest.is_file() or manifest.is_symlink():
        raise Blocked("OWASP universe jobs: staged artifact-manifest.json is required")
    value = (read_json(manifest).get("target") or {}).get("repo_path")
    path = Path(value) if isinstance(value, str) and value else None
    if path is None or not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise Blocked("OWASP universe jobs: target.repo_path must be an absolute real checkout directory")
    return path.resolve(), "sha256:" + file_hash(manifest)


def _code(job_id: str) -> dict[str, str | None]:
    module = _job(job_id)[0]
    paths = [f"{module}.py", "owasp_universe_jobs.py", registry_paths.template_rel(job_id),
             registry_paths.contract_rel(_contract(job_id))]
    values = {name: (file_hash(ROOT / name) if (ROOT / name).is_file() else None) for name in paths}
    values.update({name: file_hash(REPO / name) for name in SOURCES[job_id]})
    values["schemas/" + _job(job_id)[2]] = file_hash(REPO / "schemas" / _job(job_id)[2])
    return values


def current_inputs(run_id: str, job_id: str) -> dict[str, Any]:
    """Every graph dependency bound, or Blocked for a required one that is not accepted or skipped
    for a reason its edge does not allow."""
    run_id = identifier(run_id)
    source_root, generation = _source_root(run_id)
    bindings, absent = {}, []
    for dep in _dependencies(job_id):
        binding = accepted(run_id, dep["job"])
        if binding is None:
            if dep["kind"] == "required":
                raise Blocked(f"{job_id}: required dependency {dep['job']} is not accepted")
            absent.append(dep["job"])
            continue
        if binding["status"] == "SKIPPED" and binding["skip_reason"] not in dep["allowed_skip_reasons"]:
            raise Blocked(f"{job_id}: {dep['job']} was skipped for a reason its edge does not allow")
        bindings[dep["job"]] = binding
    return {"run_id": run_id, "job": job_id, "source_generation": generation, "source_root": str(source_root),
            "bindings": bindings, "absent_optional": sorted(absent), "code": _code(job_id)}


def _read(inputs: dict[str, Any], job: str) -> str | None:
    binding = inputs["bindings"].get(job)
    if binding is None or binding["status"] == "SKIPPED":
        return None
    return str(data_path(inputs["run_id"]) / binding["artifact_path"])


def argv(inputs: dict[str, Any], attempt: Path) -> list[str]:
    """The module CLI for one attempt: accepted, non-skipped dependencies only."""
    _, result, *_ = _job(inputs["job"])
    values = ["--index", _read(inputs, "02-code-index"), "--source-root", inputs["source_root"]]
    if _read(inputs, "02-evidence-index"):
        values += ["--evidence-run-id", inputs["run_id"]]
    for job, flag in CANDIDATE_FLAGS.items():
        if _read(inputs, job):
            values += [flag, _read(inputs, job)]
    return values + ["--output", str(attempt / result)]


def _candidate_document(module: Any, inputs: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Wrap the bare ``search`` result into the published document with its input bindings."""
    rows = []
    for job in CANDIDATE_INPUTS:
        binding = inputs["bindings"].get(job)
        live = binding is not None and binding["status"] != "SKIPPED"
        rows.append({"job_id": job, "required": job != "02-source-sast", "accepted": live,
                     "attempt_id": binding["attempt_id"] if live else None,
                     "artifact_path": binding["artifact_path"] if live else None,
                     "artifact_sha256": binding["artifact_sha256"] if live else None})
    return module.document(result, run_id=inputs["run_id"], source_snapshot_sha256=inputs["source_generation"],
                           rules=read_json(REPO / RULES), rules_sha256=file_hash(REPO / RULES), inputs=rows)


def _gap_lines(document: dict[str, Any]) -> list[str]:
    lines = []
    for gap in document.get("gaps") or []:
        if isinstance(gap, dict):
            lines.append(f"{gap.get('kind', 'gap')}: {gap.get('statement') or gap.get('detail') or gap.get('reason') or ''}".strip())
        else:
            lines.append(str(gap))
    return lines


def _published_files(attempt: Path) -> list[str]:
    return sorted(path.name for path in attempt.iterdir()
                  if path.is_file() and not path.is_symlink() and path.name not in {"inputs.json", "result.json"})


def run(job_id: str, run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    module_name, result, schema, worker_kind, consumer = _job(job_id)
    run_id = identifier(run_id)
    base, contract = root(run_id, job_id), _contract(job_id)
    resume = f"python -B appsec-review-process/owasp_universe_jobs.py --job {job_id} --run-id {run_id}"

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        if inputs["code"] != _code(job_id):
            raise Blocked(f"{job_id}: implementation changed before execution")
        module = importlib.import_module(module_name)
        code = module.main(argv(inputs, attempt))
        if code not in (0, None):
            raise Blocked(f"{job_id}: {module_name}.main exited {code}")
        document = _candidate_document(module, inputs, read_json(attempt / result))
        atomic_json(attempt / result, document)
        errors = validate_document(document, schema)
        if errors:
            raise Blocked(f"{job_id}: result fails schema validation: {'; '.join(errors[:5])}")
        gaps = _gap_lines(document) + [f"optional input absent: {job}" for job in inputs["absent_optional"]]
        status = "OK_WITH_GAPS" if gaps else document["status"]
        record = {"process": job_id, "status": status, "run_id": run_id, "dagster_run_id": dagster_id,
                  "attempt_id": allocation["attempt_id"], "network": "none", "qualification": "implemented_not_qualified",
                  "candidates": len(document["candidates"]), "chapters": len(document["chapters"]),
                  "gaps": len(gaps), "ended_at": now()}
        return record_terminal_current(base, attempt, run_id=run_id, job_id=job_id, dagster_run_id=dagster_id,
            worker_kind=worker_kind, output_contract=contract, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=status,
            summary=f"{job_id}: {status}, {len(document['candidates'])} candidate(s)", status_record=record,
            artifact_paths=_published_files(attempt), gaps=gaps or None, consumer_job_id=consumer)

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=job_id, dagster_run_id=dagster_id,
        worker_kind=worker_kind, output_contract=contract, resume_command=resume,
        derive_inputs=lambda: current_inputs(run_id, job_id), fingerprint_inputs=lambda value: "sha256:" + digest(value),
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": job_id,
            "preflight_error": f"{type(exc).__name__}: {exc}"}, force=force, consumer_job_id=consumer,
        blocked_summary=f"{job_id}: accepted inputs were not current.",
        failed_summary=f"{job_id} did not publish; no older success may be used.")


def run_participation(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    """04-owasp-participation publishes itself (pool coordinator; Blocked over its participation budget)."""
    import owasp_participation
    return owasp_participation.run(run_id, dagster_id, force)


def run_universe(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    """04-owasp-universe (``owasp_universe.run``; Blocked over budget), then its projection."""
    import owasp_universe
    result = owasp_universe.run(run_id, dagster_id, force=force)
    return {**result, "projection": project(run_id, dagster_id, force)}


def project(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    """Project the accepted, within-budget universe into the OWASP applicability request (T03 lane-in,
    then the ``04-owasp-component-routing`` projection); both reuse their publication on unchanged inputs."""
    import owasp_component_routing
    import owasp_lane_in
    import owasp_universe
    import owasp_workbench_lifecycle as workbench
    run_id = identifier(run_id)
    owasp_universe.accepted(run_id)
    owasp_lane_in.admit(run_id, workbench._write_request(run_id, "owasp-lane-in-request.json",
                                                         workbench.lane_in_request(run_id)), force=force)
    return owasp_component_routing.run(run_id, dagster_id, force=force)


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--job", required=True, choices=sorted([*JOBS, PARTICIPATION, UNIVERSE]))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-id", default="manual")
    parser.add_argument("--force", action="store_true")
    parsed = parser.parse_args(args)
    if parsed.job == UNIVERSE:
        print(run_universe(parsed.run_id, parsed.dagster_id, parsed.force))
    elif parsed.job == PARTICIPATION:
        print(run_participation(parsed.run_id, parsed.dagster_id, parsed.force))
    else:
        print(run(parsed.job, parsed.run_id, parsed.dagster_id, parsed.force))
    return 0


if __name__ == "__main__":
    sys.exit(main())
