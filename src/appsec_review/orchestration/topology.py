"""Composite review-graph topology, independent of the Dagster import.

The Dagster definitions build ``wave1_review`` from :func:`wave1_dependencies`, and the operator's
stepwise acceptance tool reads the same topology from the packaged code location through
``python -m appsec_review.orchestration.topology``. There is one copy of the wave order.

A job launched on its own (its single-job Dagster job) has no in-graph upstream. To execute it
exactly as the composite graph would, the launcher names the accepted upstream handoffs the graph
would have propagated in the :data:`UPSTREAM_HANDOFFS_TAG` run tag; :func:`tagged_upstream_handoffs`
verifies every reference against the application run's accepted pointers before the job binds them.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Mapping, Set
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

UPSTREAM_HANDOFFS_TAG = "appsec/upstream_handoffs"
WAVE1_GRAPH = "wave1_review"
WAVE1_REQUIRED = frozenset({"job_model_connectivity", "job_review_intake", "job_target_catalog",
                            "job_target_analysis_plan"})
_JOB_ID = re.compile(r"job_[a-z0-9_]+")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def gate_ids(registered: Set[str]) -> tuple[str, ...]:
    from appsec_review.runtime.contracts import TargetAccess
    from appsec_review.runtime.registry import builtin_contracts
    contracts = builtin_contracts()
    order = wave1_dependencies(registered | WAVE1_REQUIRED) or {}
    return tuple(name for name in order if name in registered
                 and contracts[name].target_access is TargetAccess.NONE)


def gate_dependencies(registered: Set[str]) -> dict[str, tuple[str, ...]]:
    gates = gate_ids(registered)
    return {job_id: ((gates[position - 1],) if position else ()) for position, job_id in enumerate(gates)}


def wave1_dependencies(registered: Set[str]) -> dict[str, tuple[str, ...]] | None:
    """Project enabled graph jobs from their authoritative input and schedule contracts."""
    from appsec_review.runtime.contracts import DispatchClass
    from appsec_review.runtime.registry import builtin_contracts
    if not WAVE1_REQUIRED <= registered:
        return None
    contracts = builtin_contracts()
    graph = {name: contract for name, contract in contracts.items()
             if contract.dispatch is DispatchClass.REVIEW_GRAPH}
    if "job_remediation_validation" in registered and "job_remediation_planning" not in registered:
        raise ValueError("job_remediation_validation requires enabled job_remediation_planning")
    edges = {name: tuple(dict.fromkeys((*contract.schedule_after, *contract.consumes)))
             for name, contract in graph.items()}
    for name, parents in edges.items():
        if set(parents) - graph.keys():
            raise ValueError(f"graph contract names a non-graph producer: {name}")
    result: dict[str, tuple[str, ...]] = {}
    visiting: set[str] = set()
    def visit(name: str) -> tuple[str, ...]:
        if name in visiting:
            raise ValueError(f"job contract dependency cycle: {name}")
        if name in result:
            return (name,)
        visiting.add(name)
        parents = tuple(dict.fromkeys(parent for dep in edges[name] for parent in visit(dep)))
        visiting.remove(name)
        if name in registered:
            result[name] = parents
            return (name,)
        return parents
    for name in graph:
        visit(name)
    return {name: tuple(parent for parent in parents if not any(
        parent in upstream_closure(other, result, set(result)) for other in parents if other != parent))
        for name, parents in result.items()}


def enabled_wave1_dependencies(registered: Set[str], all_registered: Set[str]) -> dict[str, tuple[str, ...]] | None:
    if not registered <= all_registered:
        raise ValueError("enabled selection names unregistered jobs")
    return wave1_dependencies(registered)


def upstream_closure(job_id: str, dependencies: Mapping[str, Iterable[str]],
                     propagating: Set[str]) -> tuple[str, ...]:
    """Jobs whose handoffs the composite graph hands to ``job_id``.

    Every finalized job passes on the handoffs it received and adds its own when it propagates, so a
    job receives every transitive ancestor that propagates its handoff.
    """

    seen: set[str] = set()
    pending = list(dependencies.get(job_id, ()))
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        pending.extend(dependencies.get(current, ()))
    return tuple(sorted(seen & set(propagating)))


def tagged_upstream_handoffs(run_root: Path, raw: str) -> dict[str, str]:
    """Verify a launcher-supplied upstream handoff set against the run's accepted pointers."""

    from appsec_review.storage import file_sha256

    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{UPSTREAM_HANDOFFS_TAG} is not JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{UPSTREAM_HANDOFFS_TAG} must be a JSON object of job id to handoff sha256")
    run_root = Path(run_root).resolve()
    verified: dict[str, str] = {}
    for job_id, digest in sorted(value.items()):
        if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
            raise ValueError(f"invalid upstream job id in {UPSTREAM_HANDOFFS_TAG}: {job_id!r}")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError(f"invalid upstream handoff digest for {job_id}")
        pointer_path = run_root / "data" / "jobs" / job_id / "latest.json"
        if not pointer_path.is_file():
            raise ValueError(f"tagged upstream {job_id} has no accepted handoff in this run")
        try:
            pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
            handoff_path = (run_root / str(pointer["handoff_path"])).resolve()
        except (KeyError, ValueError) as exc:
            raise ValueError(f"accepted pointer for {job_id} is corrupt") from exc
        if pointer.get("handoff_sha256") != digest:
            raise ValueError(f"tagged upstream {job_id} is not the run's accepted handoff")
        if run_root not in handoff_path.parents or not handoff_path.is_file():
            raise ValueError(f"accepted handoff for {job_id} escapes the run or is missing")
        if file_sha256(handoff_path) != digest:
            raise ValueError(f"accepted handoff for {job_id} does not match its digest")
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        if handoff.get("job_id") != job_id or handoff.get("status") != "ACCEPTED":
            raise ValueError(f"tagged upstream {job_id} is not an accepted handoff of that job")
        verified[job_id] = digest
    return verified


def accepted_upstream_handoffs(run_root: Path, job_ids: Iterable[str]) -> dict[str, str]:
    """The run's accepted handoff of every job in ``job_ids``, verified like a tagged set."""

    digests = {}
    for job_id in job_ids:
        pointer = Path(run_root) / "data" / "jobs" / job_id / "latest.json"
        if not pointer.is_file():
            raise ValueError(f"upstream {job_id} has no accepted handoff in this run")
        try:
            digests[job_id] = json.loads(pointer.read_text(encoding="utf-8"))["handoff_sha256"]
        except (KeyError, ValueError) as exc:
            raise ValueError(f"accepted pointer for {job_id} is corrupt") from exc
    return tagged_upstream_handoffs(run_root, json.dumps(digests))


def launch_upstream_handoffs(runs_dir: Path, tags: Mapping[str, str], *,
                             in_graph: bool) -> dict[str, str] | None:
    """Return the verified tagged upstream handoffs of a standalone launch, or ``None`` untagged.

    Only a job with no in-graph upstream may take tagged handoffs, and only inside an existing
    application run named by ``appsec/application_run_id``.
    """

    raw = tags.get(UPSTREAM_HANDOFFS_TAG)
    if raw is None:
        return None
    if in_graph:
        raise ValueError(f"{UPSTREAM_HANDOFFS_TAG} is only valid for a job without in-graph upstream")
    run_id = tags.get("appsec/application_run_id")
    if not run_id:
        raise ValueError(f"{UPSTREAM_HANDOFFS_TAG} requires appsec/application_run_id")
    from appsec_review.storage import RunStore

    return tagged_upstream_handoffs(RunStore(Path(runs_dir)).resolve(run_id), raw)


def describe_wave1(config: Any, registry: Any, include: Iterable[str] = ()) -> dict[str, Any]:
    """Describe ``wave1_review`` as the packaged code location builds it.

    ``include`` names registered jobs to treat as enabled, so a manually invoked job that is disabled in the
    graph (``job_poc_generation``) can be given the upstream handoffs it would have in the graph.
    """

    from appsec_review.runtime import job_is_enabled
    from appsec_review.runtime.dependencies import input_projection

    registered = {job_id for job_id in registry.job_ids() if job_is_enabled(config, job_id)}
    registered |= {job_id for job_id in include if job_id in set(registry.job_ids())}
    dependencies = enabled_wave1_dependencies(registered, set(registry.job_ids()))
    if dependencies is None:
        raise ValueError("wave1_review is not defined by this configuration")
    propagating = {job_id for job_id in dependencies if registry.build(job_id).propagate_handoff}
    return {
        "schema": "appsec-review/graph-topology/1",
        "graph": WAVE1_GRAPH,
        "upstream_handoffs_tag": UPSTREAM_HANDOFFS_TAG,
        "jobs": [{
            "job_id": job_id,
            "name": config.job(job_id).name,
            "dependencies": list(dependencies[job_id]),
            "propagate_handoff": job_id in propagating,
            "upstream_handoffs": list(input_projection(
                registry.build(job_id), {name: "" for name in propagating}, dependencies, propagating)),
            "contract": registry.build(job_id).contract.document(),
        } for job_id in dependencies],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print the wave1_review topology as JSON.")
    parser.add_argument("--config", default=os.environ.get("APPSEC_REVIEW_CONFIG", "appsec-review.toml"))
    args = parser.parse_args(argv)
    from appsec_review.config import load_config
    from appsec_review.runtime.registry import builtin_registry

    json.dump(describe_wave1(load_config(args.config), builtin_registry()), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
