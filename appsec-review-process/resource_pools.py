#!/usr/bin/env python3
"""Dedicated Dagster resource pools (backlog batch B15): the single source of truth.

Pool ids, limits, the explicit ``unassigned`` state, the derivation of a pool from a worker kind
and its granted permission kinds, the ADR-0008 Decision 6 persona budget classes, and the
functions that apply and verify the limits on a Dagster instance all live here. Nothing else in
the repository may hold a pool id or a pool limit as a local constant: ``dagster_workflow.py``
and ``orchestrator/dagster/definitions.py`` take their ``pool=`` values from this module, and
``docs/resource-pools.md`` is tied to these constants by a test.

What Dagster 1.13.21 does (confirmed against the installed package, see the operator doc):

* a pool is a name on an op (``@op(pool=...)``); an op without one never claims a slot, whatever
  ``default_limit`` says, so "no pool" is unlimited by pools. That is why the explicit
  ``unassigned`` state is a recorded tag here and an op with neither is an error;
* per-pool limits live in the event-log storage (tables ``concurrency_limits`` /
  ``concurrency_slots`` / ``pending_steps``), not in ``dagster.yaml``. Only the default for a named
  pool without a stored limit is YAML (``concurrency.default_op_concurrency_limit``);
* slots are claimed and freed by the run's own executor; a run worker that dies leaves its slots
  claimed until the daemon frees them (``run_monitoring.free_slots_after_run_end_seconds``).

The module imports Dagster lazily so the pure parts run on a host without it.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parent

STATE_SCHEMA_ID = "appsec-review/resource-pool-state/1.0"
STATE_SCHEMA_FILE = "resource-pool-state.schema.json"

CPU = "cpu"
MEMORY = "memory"
DOCKER = "docker"
NETWORK = "network"
PERSONA_LLM = "persona_llm"
DYNAMIC_ANALYSIS = "dynamic_analysis"

# The explicit "no pool has been decided" state. It is a recorded value (an op tag, a manifest
# value), never the absence of one, and every report lists it as a gap.
UNASSIGNED = "unassigned"
UNASSIGNED_REASONS = ("coordination_only", "worker_not_implemented", "bootstrap_diagnostic")
TAG_POOL = "appsec_resource_pool"
TAG_REASON = "appsec_resource_pool_reason"


@dataclass(frozen=True)
class Pool:
    pool_id: str
    limit: int
    work: str
    justification: str


# Outer limits that already exist in dagster.yaml / dagster_workflow.py. B15 does not change
# them; they are recorded here so that verification can prove pools only ever add constraints.
OUTER_LIMITS = {"max_concurrent_runs": 2, "per_engagement_limit": 1, "nvd_feed_limit": 1}
ENGAGEMENT_TAG = "engagement_run_id"
NVD_TAG = "nvd_feed_id"
EXECUTOR_STEP_CEILING = 3  # the largest multiprocess `max_concurrent` of any job
AGGREGATE_STEP_CEILING = OUTER_LIMITS["max_concurrent_runs"] * EXECUTOR_STEP_CEILING

POOLS = (
    Pool(CPU, 3, "deterministic Python work: intake, preparation branches, build discovery, gates",
         "equals workflow-plan.json max_concurrent_steps, the fan-out one run is already allowed; "
         "1 would serialize the qualified parallel preparation branches; today two runs may use 6"),
    Pool(MEMORY, 1, "memory-heavy deterministic work: the evidence index",
         "no memory measurement exists; today two engagements may index at once, so 1 is tighter"),
    Pool(DOCKER, 1, "pinned-container and target-execution work: the sandboxed configure",
         "no Docker load measurement exists; today two engagements may configure at once"),
    Pool(NETWORK, 1, "fixed-destination network work: Scorecard ingestion, the NVD feed sync",
         "no provider rate measurement exists; today a Scorecard step and the NVD sync may overlap"),
    Pool(PERSONA_LLM, 3, "persona / model invocations",
         "ADR-0008 Decision 6 deep class needs 3 concurrent cells; 3 does not exceed the executor "
         "cap of 3 steps per run and is half of today's aggregate of 6; no persona op exists yet"),
    Pool(DYNAMIC_ANALYSIS, 1, "dynamic testing and debugger/ptrace work",
         "no dynamic worker exists and nothing is measured; 1"),
)
POOL_IDS = tuple(pool.pool_id for pool in POOLS)
LIMITS = {pool.pool_id: pool.limit for pool in POOLS}

# A named pool that has no stored limit gets this many slots (dagster.yaml
# `concurrency.default_op_concurrency_limit`). It is the fail-closed floor for a fresh or wiped
# storage and for a mistyped pool name; `apply_limits` then writes the explicit limits.
DEFAULT_POOL_LIMIT = 1
# dagster.yaml `run_monitoring.free_slots_after_run_end_seconds`: how long after a run ends the
# daemon returns slots that the run's executor did not free (run worker killed or lost).
FREE_SLOTS_AFTER_RUN_END_SECONDS = 120
GUARD_SENSOR_NAME = "resource_pool_guard"
GUARD_INTERVAL_SECONDS = 30

# Most restrictive / most specific first. A Dagster op holds exactly one pool, so a worker whose
# kind and grants point at several pools gets the first of these that applies.
PRECEDENCE = (DYNAMIC_ANALYSIS, DOCKER, PERSONA_LLM, NETWORK, MEMORY, CPU)

WORKER_KIND_POOLS = {
    "deterministic_python": CPU,
    "supplied_human_decision": CPU,
    "pinned_container": DOCKER,
    "persona": PERSONA_LLM,
}
# docs/permission-capabilities.md integration follow-up 8. `None` means the kind says nothing
# about which resource the work consumes. Every registered kind must appear here.
PERMISSION_KIND_POOLS = {
    "fixed-network-destination": NETWORK,
    "package-restore": NETWORK,
    "dynamic-testing": DYNAMIC_ANALYSIS,
    "debugger-ptrace": DYNAMIC_ANALYSIS,
    "target-execution": DOCKER,
    "credential-use": None,
    "target-mutation": None,
}

# ADR-0008 Decision 6: concurrent persona cells per budget class, expressed as the number of
# persona-pool slots one run may request at once.
PERSONA_BUDGET_CELLS = {"probe": 1, "standard": 2, "deep": 3}


class PoolAssignmentError(ValueError):
    """A pool could not be derived, or an op has no explicit pool state."""


class PoolStateError(RuntimeError):
    """The Dagster instance does not hold the declared pool limits."""


def constant_errors() -> list[str]:
    """Invariants between the constants above. Empty for a consistent module."""
    errors = []
    if len(set(POOL_IDS)) != len(POOL_IDS) or UNASSIGNED in POOL_IDS:
        errors.append("pool ids must be unique and must not include the unassigned state")
    if sorted(PRECEDENCE) != sorted(POOL_IDS):
        errors.append("precedence must list every pool exactly once")
    for pool in POOLS:
        if not re.fullmatch(r"[a-z][a-z_]{1,31}", pool.pool_id):
            errors.append(f"{pool.pool_id}: not a valid pool id")
        if type(pool.limit) is not int or not 1 <= pool.limit <= AGGREGATE_STEP_CEILING:
            errors.append(f"{pool.pool_id}: limit must be between 1 and the aggregate step ceiling")
        if not pool.justification or not pool.work:
            errors.append(f"{pool.pool_id}: limit needs a recorded justification")
    for table in (WORKER_KIND_POOLS, PERMISSION_KIND_POOLS):
        for key, value in table.items():
            if value is not None and value not in POOL_IDS:
                errors.append(f"{key}: maps to an unknown pool")
    if not 1 <= DEFAULT_POOL_LIMIT <= min(LIMITS.values()):
        errors.append("the default pool limit must not be looser than any declared limit")
    if max(PERSONA_BUDGET_CELLS.values()) > LIMITS[PERSONA_LLM]:
        errors.append("a persona budget class asks for more cells than the persona pool holds")
    if max(PERSONA_BUDGET_CELLS.values()) > EXECUTOR_STEP_CEILING:
        errors.append("a persona budget class asks for more cells than one run may execute")
    return errors


def derive_pool(worker_kind: str, granted_kinds: Iterable[str], *, memory_heavy: bool) -> str:
    """(worker kind, granted permission kinds) -> pool id. Pure, total over the known vocabulary,
    and closed: an unknown worker kind or permission kind raises instead of guessing."""
    if not isinstance(worker_kind, str) or worker_kind not in WORKER_KIND_POOLS:
        raise PoolAssignmentError(f"unknown worker kind: {worker_kind!r}")
    if isinstance(granted_kinds, (str, bytes, Mapping)) or not isinstance(
            granted_kinds, (list, tuple, set, frozenset)):
        raise PoolAssignmentError("granted permission kinds must be a list, tuple or set of kind ids")
    if type(memory_heavy) is not bool:
        raise PoolAssignmentError("memory_heavy must be a bool")
    candidates = {WORKER_KIND_POOLS[worker_kind]}
    for kind in granted_kinds:
        if not isinstance(kind, str) or kind not in PERMISSION_KIND_POOLS:
            raise PoolAssignmentError(f"unknown permission kind: {kind!r}")
        if PERMISSION_KIND_POOLS[kind] is not None:
            candidates.add(PERMISSION_KIND_POOLS[kind])
    if memory_heavy:
        candidates.add(MEMORY)
    return next(pool for pool in PRECEDENCE if pool in candidates)


def persona_slot_request(budget_class: str) -> int:
    """Persona-pool slots one run may hold at once for an ADR-0008 budget class."""
    if not isinstance(budget_class, str) or budget_class not in PERSONA_BUDGET_CELLS:
        raise PoolAssignmentError(f"unknown persona budget class: {budget_class!r}")
    cells = PERSONA_BUDGET_CELLS[budget_class]
    if cells > LIMITS[PERSONA_LLM]:
        raise PoolAssignmentError("budget class exceeds the persona pool limit; the limit is not raised")
    return cells


def unassigned(reason: str) -> dict[str, str]:
    """Op tags that record the explicit unassigned state. Use as `@op(tags=unassigned(...))`."""
    if reason not in UNASSIGNED_REASONS:
        raise PoolAssignmentError(f"unknown unassigned reason: {reason!r}")
    return {TAG_POOL: UNASSIGNED, TAG_REASON: reason}


# ---------------------------------------------------------------------------------------------
# Op assignments in a loaded Dagster repository
# ---------------------------------------------------------------------------------------------

def _jobs_of(definitions: Any) -> list[Any]:
    if hasattr(definitions, "get_repository_def"):
        return list(definitions.get_repository_def().get_all_jobs())
    if hasattr(definitions, "get_all_jobs"):
        return list(definitions.get_all_jobs())
    return list(definitions)


def inspect_assignments(definitions: Any) -> dict[str, list]:
    """Every op of every job as pooled, explicitly unassigned, or an error. Read-only."""
    from dagster import OpDefinition
    pooled, open_ops, errors = [], [], []
    for job in sorted(_jobs_of(definitions), key=lambda item: item.name):
        ops = [node for node in job.all_node_defs if isinstance(node, OpDefinition)]
        for op_def in sorted(ops, key=lambda item: item.name):
            tags = dict(op_def.tags or {})
            label = f"{job.name}.{op_def.name}"
            pool, state, reason = op_def.pool, tags.get(TAG_POOL), tags.get(TAG_REASON)
            if pool is not None:
                if pool not in POOL_IDS:
                    errors.append(f"{label}: unknown pool")
                elif state is not None or reason is not None:
                    errors.append(f"{label}: has a pool and an unassigned record")
                else:
                    pooled.append({"job": job.name, "op": op_def.name, "pool_id": pool})
            elif state is None and reason is None:
                errors.append(f"{label}: no pool and no explicit unassigned record")
            elif state != UNASSIGNED or reason not in UNASSIGNED_REASONS:
                errors.append(f"{label}: invalid unassigned record")
            else:
                open_ops.append({"job": job.name, "op": op_def.name, "reason": reason})
    return {"pooled": pooled, "unassigned": open_ops, "errors": errors}


def require_explicit_assignments(definitions: Any) -> dict[str, list]:
    """Fail the code location load when any op is silently without a pool state."""
    report = inspect_assignments(definitions)
    if report["errors"]:
        raise PoolAssignmentError("resource pool assignment errors: " + "; ".join(report["errors"]))
    return report


# ---------------------------------------------------------------------------------------------
# Limits on a Dagster instance
# ---------------------------------------------------------------------------------------------

def _storage(instance: Any) -> Any:
    storage = instance.event_log_storage
    if not storage.supports_global_concurrency_limits:
        raise PoolStateError("the instance event-log storage does not support pool limits")
    return storage


def observed_limits(instance: Any) -> dict[str, dict[str, Any]]:
    return {item.name: {"limit": item.limit, "from_default": bool(item.from_default)}
            for item in _storage(instance).get_pool_limits()}


def limit_drift(instance: Any) -> list[dict[str, Any]]:
    """Declared pools whose stored limit is absent, defaulted or different. Read-only."""
    observed = observed_limits(instance)
    drift = []
    for pool in POOLS:
        seen = observed.get(pool.pool_id)
        if seen is None:
            state = "MISSING"
        elif seen["from_default"]:
            state = "DEFAULTED"
        elif seen["limit"] != pool.limit:
            state = "DRIFT"
        else:
            continue
        drift.append({"pool_id": pool.pool_id, "expected": pool.limit, "state": state,
                      "observed": None if seen is None else seen["limit"]})
    return drift


def apply_limits(instance: Any) -> list[dict[str, Any]]:
    """Write the declared limit of every pool that drifted. Idempotent: a second call on the same
    storage writes nothing and returns []. It sets exact values; it never deletes a pool."""
    errors = constant_errors()
    if errors:
        raise PoolStateError("resource pool constants are inconsistent: " + "; ".join(errors))
    storage = _storage(instance)
    corrections = limit_drift(instance)
    for item in corrections:
        storage.set_concurrency_slots(item["pool_id"], LIMITS[item["pool_id"]])
    return corrections


def _outer_limits(instance: Any) -> dict[str, Any]:
    queue = instance.get_concurrency_config().run_queue_config
    observed: dict[str, Any] = {name: None for name in OUTER_LIMITS}
    if queue is None:
        return observed
    observed["max_concurrent_runs"] = queue.max_concurrent_runs
    for entry in queue.tag_concurrency_limits or []:
        value = entry.get("value")
        if entry.get("key") == ENGAGEMENT_TAG and isinstance(value, Mapping) and \
                value.get("applyLimitPerUniqueValue") is True:
            observed["per_engagement_limit"] = entry.get("limit")
        if entry.get("key") == NVD_TAG and value is None:
            observed["nvd_feed_limit"] = entry.get("limit")
    return observed


def instance_settings(instance: Any) -> dict[str, Any]:
    pool_config = instance.get_concurrency_config().pool_config
    granularity = pool_config.pool_granularity
    monitoring = instance.run_monitoring_settings if instance.run_monitoring_enabled else {}
    return {"default_pool_limit": pool_config.default_pool_limit,
            "granularity": "op" if granularity is None else granularity.value,
            "free_slots_after_run_end_seconds": (monitoring or {}).get("free_slots_after_run_end_seconds"),
            "outer_limits": _outer_limits(instance)}


def verify_instance(instance: Any) -> list[str]:
    """Read-only. Empty when the instance holds exactly the declared pool state."""
    errors = list(constant_errors())
    for item in limit_drift(instance):
        errors.append(f"pool {item['pool_id']}: {item['state']} expected={item['expected']} "
                      f"observed={item['observed']}")
    for name in sorted(set(observed_limits(instance)) - set(POOL_IDS)):
        errors.append(f"pool {name}: not a declared pool")
    settings = instance_settings(instance)
    if settings["default_pool_limit"] != DEFAULT_POOL_LIMIT:
        errors.append(f"default pool limit: expected={DEFAULT_POOL_LIMIT} "
                      f"observed={settings['default_pool_limit']}")
    if settings["granularity"] != "op":
        errors.append("pool granularity must be op")
    if settings["free_slots_after_run_end_seconds"] != FREE_SLOTS_AFTER_RUN_END_SECONDS:
        errors.append(f"free_slots_after_run_end_seconds: expected={FREE_SLOTS_AFTER_RUN_END_SECONDS} "
                      f"observed={settings['free_slots_after_run_end_seconds']}")
    for name, expected in OUTER_LIMITS.items():
        if settings["outer_limits"][name] != expected:
            errors.append(f"outer limit {name}: expected={expected} "
                          f"observed={settings['outer_limits'][name]}")
    return errors


def build_guard_sensor() -> Any:
    """The `resource_pool_guard` sensor: at daemon start and every interval it re-applies the
    declared limits and fails its tick, visibly, while the instance disagrees with this module."""
    from dagster import DefaultSensorStatus, SkipReason, sensor

    @sensor(name=GUARD_SENSOR_NAME, minimum_interval_seconds=GUARD_INTERVAL_SECONDS,
            default_status=DefaultSensorStatus.RUNNING,
            description="Applies and verifies the resource pool limits declared in resource_pools.py.")
    def resource_pool_guard(context):
        corrections = apply_limits(context.instance)
        errors = verify_instance(context.instance)
        if errors:
            raise PoolStateError("resource pools are not in the declared state: " + "; ".join(errors))
        if corrections:
            context.log.warning("resource pool limits corrected: %s", json.dumps(corrections, sort_keys=True))
        return SkipReason("resource pools verified; corrected=" + str(len(corrections)))

    return resource_pool_guard


# ---------------------------------------------------------------------------------------------
# Pool-state document (qualification evidence) and its on-disk verifier
# ---------------------------------------------------------------------------------------------

def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _state_digest(document: Mapping[str, Any]) -> str:
    body = {key: value for key, value in document.items() if key != "state_sha256"}
    return "sha256:" + hashlib.sha256(_canonical(body)).hexdigest()


def max_overlap(intervals: Sequence[tuple[float, float | None]]) -> int:
    """Largest number of intervals open at one instant; an interval with no end never closes."""
    points = []
    for start, end in intervals:
        points.append((start, 1))
        points.append((float("inf") if end is None else end, -1))
    best = current = 0
    for _, delta in sorted(points, key=lambda item: (item[0], item[1])):
        current += delta
        best = max(best, current)
    return best


def overlap_by_pool(runs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for pool in POOLS:
        intervals = [(step["started"], step["ended"]) for run in runs for step in run["steps"]
                     if step["pool_id"] == pool.pool_id]
        result.append({"pool_id": pool.pool_id, "limit": pool.limit,
                       "max_concurrent_steps": max_overlap(intervals)})
    return result


def _run_record(instance: Any, run_id: str) -> dict[str, Any]:
    run = instance.get_run_by_id(run_id)
    if run is None:
        raise PoolStateError("unknown Dagster run id")
    plan = instance.get_execution_plan_snapshot(run.execution_plan_snapshot_id)
    pools = {step.key: step.pool for step in plan.steps}
    started: dict[str, float] = {}
    ended: dict[str, float] = {}
    for entry in instance.all_logs(run_id):
        event = entry.dagster_event
        if event is None or event.step_key is None:
            continue
        if event.event_type_value == "STEP_START":
            started[event.step_key] = entry.timestamp
        elif event.event_type_value in ("STEP_SUCCESS", "STEP_FAILURE"):
            ended[event.step_key] = entry.timestamp
    finished = run.is_finished
    steps = []
    for key in sorted(started):
        if pools.get(key) is None:
            continue
        end = ended.get(key)
        if end is None and finished:
            # The step never reported an end but its run is over: close it at the last event.
            end = max([started[key], *ended.values()])
        steps.append({"step_key": key, "pool_id": pools[key], "started": started[key], "ended": end})
    return {"dagster_run_id": run.run_id, "job": run.job_name, "status": run.status.value,
            "engagement_run_id": run.tags.get(ENGAGEMENT_TAG), "steps": steps}


def _state_errors(document: Mapping[str, Any]) -> list[str]:
    errors = list(document["assignments"]["errors"])
    for pool in document["pools"]:
        if pool["state"] != "OK":
            errors.append(f"pool {pool['pool_id']}: {pool['state']}")
    for name in document["foreign_pools"]:
        errors.append(f"pool {name}: not a declared pool")
    for key in ("default_pool_limit", "free_slots_after_run_end_seconds"):
        if document[key]["observed"] != document[key]["expected"]:
            errors.append(f"{key}: not the declared value")
    if document["outer_limits"]["observed"] != document["outer_limits"]["expected"]:
        errors.append("outer limits: not the declared values")
    for item in document["observed_overlap"]:
        if item["max_concurrent_steps"] > item["limit"]:
            errors.append(f"pool {item['pool_id']}: observed overlap exceeds the limit")
    by_engagement: dict[str, list] = {}
    for run in document["runs"]:
        if run["engagement_run_id"] is not None and run["steps"]:
            by_engagement.setdefault(run["engagement_run_id"], []).append(
                (min(step["started"] for step in run["steps"]),
                 None if any(step["ended"] is None for step in run["steps"])
                 else max(step["ended"] for step in run["steps"])))
    for engagement in sorted(by_engagement):
        if max_overlap(by_engagement[engagement]) > OUTER_LIMITS["per_engagement_limit"]:
            errors.append("engagement serialization: pooled steps of two runs of one engagement overlap")
    return errors


def build_state(instance: Any, definitions: Any, run_ids: Sequence[str], generated_at: str) -> dict[str, Any]:
    import dagster
    storage = _storage(instance)
    observed = observed_limits(instance)
    drift = {item["pool_id"]: item["state"] for item in limit_drift(instance)}
    pools = []
    for pool in POOLS:
        info = storage.get_concurrency_info(pool.pool_id)
        seen = observed.get(pool.pool_id)
        pools.append({"pool_id": pool.pool_id, "expected_limit": pool.limit,
                      "observed_limit": None if seen is None else seen["limit"],
                      "from_default": None if seen is None else seen["from_default"],
                      "claimed_slots": len(info.claimed_slots), "pending_steps": len(info.pending_steps),
                      "state": drift.get(pool.pool_id, "OK")})
    settings = instance_settings(instance)
    runs = [_run_record(instance, run_id) for run_id in run_ids]
    document: dict[str, Any] = {
        "schema": STATE_SCHEMA_ID, "generated_at": generated_at, "dagster_version": dagster.__version__,
        "declaration_sha256": "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "default_pool_limit": {"expected": DEFAULT_POOL_LIMIT, "observed": settings["default_pool_limit"]},
        "free_slots_after_run_end_seconds": {"expected": FREE_SLOTS_AFTER_RUN_END_SECONDS,
                                             "observed": settings["free_slots_after_run_end_seconds"]},
        "outer_limits": {"expected": dict(OUTER_LIMITS), "observed": settings["outer_limits"]},
        "pools": pools, "foreign_pools": sorted(set(observed) - set(POOL_IDS)),
        "assignments": inspect_assignments(definitions), "runs": runs,
        "observed_overlap": overlap_by_pool(runs)}
    document["errors"] = _state_errors(document)
    document["result"] = "FAIL" if document["errors"] else "PASS"
    document["state_sha256"] = _state_digest(document)
    return document


def verify_state_file(path: Path) -> list[str]:
    """Re-derive a pool-state document from the bytes on disk. Read-only."""
    from schema_validate import validate_document
    def refuse_constant(name: str) -> None:
        raise ValueError(f"non-finite number: {name}")  # NaN / Infinity are not JSON

    try:
        document = json.loads(Path(path).read_bytes().decode("utf-8"), parse_constant=refuse_constant)
    except (OSError, UnicodeDecodeError, ValueError):
        return ["state document is not readable JSON"]
    errors = validate_document(document, STATE_SCHEMA_FILE)
    if errors:
        return [f"state document fails its schema ({len(errors)} errors)"]
    problems = []
    if document["state_sha256"] != _state_digest(document):
        problems.append("state_sha256 does not match the document")
    if [pool["pool_id"] for pool in document["pools"]] != list(POOL_IDS):
        problems.append("pools are not the declared pools in declared order")
    for pool in document["pools"]:
        if pool["expected_limit"] != LIMITS.get(pool["pool_id"]):
            problems.append(f"pool {pool['pool_id']}: expected limit is not the declared limit")
        state = ("MISSING" if pool["observed_limit"] is None else "DEFAULTED" if pool["from_default"]
                 else "OK" if pool["observed_limit"] == pool["expected_limit"] else "DRIFT")
        if pool["state"] != state:
            problems.append(f"pool {pool['pool_id']}: state does not follow from the observed limit")
    if document["default_pool_limit"]["expected"] != DEFAULT_POOL_LIMIT or \
            document["free_slots_after_run_end_seconds"]["expected"] != FREE_SLOTS_AFTER_RUN_END_SECONDS or \
            document["outer_limits"]["expected"] != OUTER_LIMITS:
        problems.append("expected settings are not the declared settings")
    for run in document["runs"]:
        for step in run["steps"]:
            if step["ended"] is not None and step["ended"] < step["started"]:
                problems.append("a step ends before it starts")
    if document["observed_overlap"] != overlap_by_pool(document["runs"]):
        problems.append("observed overlap does not follow from the recorded steps")
    if document["errors"] != _state_errors(document):
        problems.append("errors do not follow from the document")
    if document["result"] != ("FAIL" if document["errors"] else "PASS"):
        problems.append("result does not follow from the errors")
    return problems


def _load_definitions() -> Any:
    sys.path.insert(0, os.environ.get("APPSEC_DEFINITIONS_DIR", "/opt/app"))
    from definitions import defs
    return defs


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("table", help="print the declared pools (no Dagster needed)")
    commands.add_parser("verify", help="read-only check of the DAGSTER_HOME instance; exit 2 on drift")
    commands.add_parser("apply", help="idempotently write the declared limits, then verify")
    state = commands.add_parser("state", help="write a pool-state document for the given Dagster runs")
    state.add_argument("--out", required=True, type=Path)
    state.add_argument("--run-id", action="append", default=[], help="Dagster run id; repeatable")
    check = commands.add_parser("verify-state", help="re-derive a pool-state document from disk")
    check.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    if args.command == "table":
        print(json.dumps({"pools": [vars(pool) for pool in POOLS], "unassigned": UNASSIGNED,
                          "default_pool_limit": DEFAULT_POOL_LIMIT, "outer_limits": OUTER_LIMITS,
                          "errors": constant_errors()}, indent=2))
        return 2 if constant_errors() else 0
    if args.command == "verify-state":
        problems = verify_state_file(args.path)
        digest = hashlib.sha256(args.path.read_bytes()).hexdigest() if args.path.is_file() else None
        print(json.dumps({"path": str(args.path), "file_sha256": digest, "problems": problems}, indent=2))
        return 2 if problems else 0
    from dagster import DagsterInstance
    with DagsterInstance.get() as instance:
        if args.command == "state":
            from execution_state import now
            if args.out.exists():
                raise SystemExit("refusing to overwrite an existing state document")
            document = build_state(instance, _load_definitions(), args.run_id, now())
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_bytes(json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n")
            problems = verify_state_file(args.out)
            print(json.dumps({"path": str(args.out), "result": document["result"], "errors": document["errors"],
                              "file_sha256": hashlib.sha256(args.out.read_bytes()).hexdigest(),
                              "problems": problems}, indent=2))
            return 0 if document["result"] == "PASS" and not problems else 2
        corrections = apply_limits(instance) if args.command == "apply" else []
        errors = verify_instance(instance)
        print(json.dumps({"corrections": corrections, "errors": errors,
                          "limits": observed_limits(instance)}, indent=2, sort_keys=True))
        return 2 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
