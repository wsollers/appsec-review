#!/usr/bin/env python3
"""Wait-all rendezvous and terminal-instance manifest (backlog batch C02).

Given one verified C01 expansion and a trusted runtime, :func:`run_rendezvous` launches every
expected instance through its real adapter (``worker_adapters``: B13 pinned container, B14 persona
invocation), waits without busy polling until every instance is terminal or the wait ends, and then
publishes exactly one immutable ``appsec-review/pool-rendezvous-manifest/1.0``: LAST, atomically,
created exclusively. :func:`verify_manifest` is the read-only counterpart.

Readers need the launch's :class:`ContainerHostFacts` as well as the ``PoolContext``: B13's verifier
requires the docker executable and container user, and the context does not carry them.

What this module guarantees to T10 and C03:

* :func:`classify_instance` is THE rule for "what state is this instance in". The coordinator and
  the verifier both call it and nothing else decides, so they cannot drift. An adapter outcome is
  read from DISK through the adapter's own verifier (``load_verified_result``), never from a value
  an adapter returned and never from a worker thread's say-so.
* The manifest lists every instance of the expansion, in the expansion's order. A worker that was
  not observed is ``missing``, ``crashed``, ``rendezvous_timed_out`` or ``not_launched_*``; it is
  never an empty success. An ``EMPTY`` expansion publishes ``EMPTY`` with its reason.
* The manifest carries no timestamp, no host path and no free text: one set of on-disk facts and
  coordinator observations derives one byte sequence, in one run or across a restart.
* No value read from a specification, from disk or from an adapter is echoed into a message.
* Threads are in-process and bounded. The caps here (persona slots, ``resource_pools.LIMITS``, the
  runtime's ``max_parallel``) can only be narrower than B15's; they do not replace Dagster pools.
  The op that calls this is ``resource_pools.unassigned('coordination_only')``.

See ``docs/pool-rendezvous.md``.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import sys
import threading
import time
from typing import Any, Mapping
import uuid

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import container_execution as ce  # noqa: E402
from execution_state import Blocked, Lock  # noqa: E402
import permission_capabilities as pc  # noqa: E402
import persona_invocation as pi  # noqa: E402
import pool_specification as ps  # noqa: E402
import resource_pools as rp  # noqa: E402
from schema_validate import validate_document  # noqa: E402
import worker_adapters  # noqa: E402

MANIFEST_ID = "appsec-review/pool-rendezvous-manifest/1.0"
CLASSIFICATION_ID = "appsec-review/pool-instance-classification/1.0"
MANIFEST_SCHEMA = "pool-rendezvous-manifest.schema.json"
INSTANCE_SCHEMA = "pool-rendezvous-instance.schema.json"
MANIFEST_FILE = "terminal-instances.json"
LOCK_SUFFIX = ".lock"

# ---- terminal states (closed) --------------------------------------------------------------------
SUCCEEDED = "succeeded"                  # verified adapter result, OK
FAILED = "failed"                        # verified adapter result, FAILED (any cause but TIMEOUT)
BLOCKED = "blocked"                      # verified adapter result, BLOCKED
CANCELED = "canceled"                    # verified adapter result, CANCELED
INSTANCE_TIMED_OUT = "instance_timed_out"        # verified adapter result, FAILED with cause TIMEOUT
RENDEZVOUS_TIMED_OUT = "rendezvous_timed_out"    # launched; the wait ended before it reported
CRASHED = "crashed"                      # attempt evidence on disk, but no adapter result file
INVALID = "invalid"                      # evidence that cannot be adopted (see classify_instance)
NOT_LAUNCHED_CANCELED = "not_launched_canceled"
NOT_LAUNCHED_RENDEZVOUS_TIMEOUT = "not_launched_rendezvous_timeout"
MISSING = "missing"                      # no attempt evidence at all
STATES = (SUCCEEDED, FAILED, BLOCKED, CANCELED, INSTANCE_TIMED_OUT, RENDEZVOUS_TIMED_OUT, CRASHED, INVALID,
          NOT_LAUNCHED_CANCELED, NOT_LAUNCHED_RENDEZVOUS_TIMEOUT, MISSING)
RESULT_STATES = (SUCCEEDED, FAILED, BLOCKED, CANCELED, INSTANCE_TIMED_OUT)   # the only states with a result_file

# ---- pool outcomes (closed) ----------------------------------------------------------------------
EMPTY = "EMPTY"
COMPLETE = "COMPLETE"
DEGRADED = "DEGRADED"
POOL_FAILED = "FAILED"
POOL_CANCELED = "CANCELED"
OUTCOMES = (EMPTY, COMPLETE, DEGRADED, POOL_FAILED, POOL_CANCELED)

# ---- what the coordinator saw (never published as such; it selects the state) ---------------------
REPORTED = "reported"                    # the attempt ended, or its evidence pre-existed, before the wait ended
UNREPORTED_STOPPED = "unreported_stopped"        # launched, not back in time, worker thread gone after the drain
UNREPORTED_RUNNING = "unreported_running"        # launched, not back in time, worker thread still alive
UNLAUNCHED_CANCELED = "unlaunched_canceled"
UNLAUNCHED_RENDEZVOUS_TIMEOUT = "unlaunched_rendezvous_timeout"
OBSERVATIONS = (REPORTED, UNREPORTED_STOPPED, UNREPORTED_RUNNING, UNLAUNCHED_CANCELED,
                UNLAUNCHED_RENDEZVOUS_TIMEOUT)

# Overall in-process bound. B15's aggregate step ceiling is the most work one host is allowed to
# run at once under the merged limits; a rendezvous may ask for less and never for more.
MAX_PARALLEL = rp.AGGREGATE_STEP_CEILING
# The wait is event driven: a worker's end, a pool cancel and the deadline each wake the waiter.
# This interval is NOT how state is observed. It only bounds how long a lost wake-up could go
# unnoticed (a worker thread that the interpreter failed to run to its ``finally``): at most 12
# idle wake-ups a minute, each a constant-time check of thread liveness.
LIVENESS_BACKSTOP_SECONDS = 5.0
# After the wait ends the coordinator sets the cancel event and gives launched workers this long
# to wind down before it records them as still running. B14's own stop grace is at most 60 s and
# B13 removes its container with at most two 60 s control calls, so nothing useful is gained above.
DRAIN_BOUNDS = (0, 180)

_TEMP_RE = re.compile(r"\.terminal-instances\.[0-9a-f]{12}\.tmp\Z")
_NUMBER = (int, float)

freeze = pi.freeze
thaw = pi.thaw
canonical_bytes = ps.canonical_bytes


class RendezvousError(RuntimeError):
    """The rendezvous cannot run, or cannot publish. Never a success; nothing was published by the
    caller that sees it. Messages are fixed text."""


class RendezvousBusyError(RendezvousError):
    """Another coordinator holds this pool's rendezvous lock."""


class RendezvousPublishedError(RendezvousError):
    """A terminal-instance manifest already exists for this pool. It is never replaced."""


class PoolCancel(threading.Event):
    """The pool's one cancel event. It IS a ``threading.Event`` (the adapters require one and poll
    it), and setting it also wakes every subscribed waiter, so a cancel is observed without a poll."""

    def __init__(self) -> None:
        super().__init__()
        self._listeners: list = []
        self._guard = threading.Lock()

    def subscribe(self, listener: Any) -> None:
        with self._guard:
            self._listeners.append(listener)

    def unsubscribe(self, listener: Any) -> None:
        with self._guard:
            if listener in self._listeners:
                self._listeners.remove(listener)

    def set(self) -> None:
        super().set()
        with self._guard:
            listeners = list(self._listeners)
        for listener in listeners:
            listener()


@dataclass(frozen=True)
class RendezvousRuntime:
    """Trusted, integrator-supplied side of one rendezvous. Every field is required; there is no
    default anywhere.

    ``rendezvous_parent`` is a run-owned directory for terminal-instance manifests. It may not be,
    contain or lie beneath ``context.pool_parent``. ``container_runtime`` and ``persona_runtime``
    are the B13 and B14 runtimes; one may be ``None`` only when the expansion has no instance of
    that kind. Both must carry ``cancel`` itself (the same object) and the facts the context
    records, so what runs is what is later verified. ``wait_limit_seconds`` can only narrow the
    specification's ``rendezvous_timeout_seconds``.
    """
    rendezvous_parent: Path
    container_runtime: Any
    persona_runtime: Any
    cancel: PoolCancel
    max_parallel: int
    wait_limit_seconds: float
    drain_seconds: int


@dataclass(frozen=True)
class ContainerHostFacts:
    """The two B13 host facts a ``PoolContext`` does not carry and B13's verifier requires: the
    docker executable and the container user the launch used (``ContainerRuntime`` fields of the
    same names). With the context's ``host_flavor`` and ``docker_host`` they let B13's verifier
    build the one docker argv a run can have. Required wherever an attempt is classified; ``None``
    only for an expansion without pinned-container instances. Never defaulted, never read from an
    attempt."""
    docker_executable: Path
    container_user: str


def host_facts_of(runtime: Any) -> ContainerHostFacts | None:
    """The facts a launch through this ``ContainerRuntime`` uses; what its verifier must be given."""
    if runtime is None:
        return None
    return ContainerHostFacts(docker_executable=runtime.docker_executable, container_user=runtime.container_user)


def _host_facts_errors(plan: ps.ExpansionPlan, host_facts: Any) -> list:
    tools = any(entry["worker_kind"] == ps.PINNED_CONTAINER for entry in plan.manifest["instances"])
    if host_facts is None:
        return (["the expansion has pinned-container instances and no container host facts were supplied"]
                if tools else [])
    if (not isinstance(host_facts, ContainerHostFacts) or not isinstance(host_facts.docker_executable, Path)
            or not host_facts.docker_executable.is_absolute() or not isinstance(host_facts.container_user, str)):
        return ["host_facts must be ContainerHostFacts with an absolute docker_executable path and a "
                "container_user string"]
    return []


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _bytes_sha(data: bytes) -> str:
    return pi._bytes_sha(data)


def validate_runtime(runtime: Any) -> None:
    if not isinstance(runtime, RendezvousRuntime):
        raise TypeError("a rendezvous requires a RendezvousRuntime")
    if type(runtime.cancel) is not PoolCancel:
        raise RendezvousError("runtime.cancel must be a PoolCancel")
    if runtime.container_runtime is not None:
        ce.validate_runtime(runtime.container_runtime)
    if runtime.persona_runtime is not None:
        pi.validate_runtime(runtime.persona_runtime)
    if not _is_int(runtime.max_parallel) or not 1 <= runtime.max_parallel <= MAX_PARALLEL:
        raise RendezvousError(f"runtime.max_parallel must be an integer within 1..{MAX_PARALLEL}")
    limit = runtime.wait_limit_seconds
    if (isinstance(limit, bool) or not isinstance(limit, _NUMBER)
            or not 0 < limit <= ps.MAX_TOTAL_TIMEOUT_SECONDS):       # NaN fails the comparison too
        raise RendezvousError("runtime.wait_limit_seconds must be a number greater than 0 and at most "
                              f"{ps.MAX_TOTAL_TIMEOUT_SECONDS}")
    low, high = DRAIN_BOUNDS
    if not _is_int(runtime.drain_seconds) or not low <= runtime.drain_seconds <= high:
        raise RendezvousError(f"runtime.drain_seconds must be an integer within {low}..{high}")


def _same_roots(left: Any, right: Any) -> bool:
    return (isinstance(left, Mapping) and isinstance(right, Mapping) and sorted(left) == sorted(right)
            and all(left[key] == right[key] for key in left))


def _binding_errors(plan: ps.ExpansionPlan, context: ps.PoolContext, runtime: RendezvousRuntime) -> list:
    """Every adapter-runtime fact the verifier will later take from the context must BE the
    context's, and every cancel event must be the pool's. Otherwise an instance could run under
    one registry, image directory or snapshot and be verified under another."""
    errors: list = []
    kinds = {entry["worker_kind"] for entry in plan.manifest["instances"]}
    tool, persona = runtime.container_runtime, runtime.persona_runtime
    if ps.PINNED_CONTAINER in kinds and tool is None:
        errors.append("the expansion has pinned-container instances and runtime.container_runtime is null")
    if ps.PERSONA in kinds and persona is None:
        errors.append("the expansion has persona instances and runtime.persona_runtime is null")
    if tool is not None:
        if tool.cancel is not runtime.cancel:
            errors.append("runtime.container_runtime.cancel is not the pool's cancel event")
        for name in ("images_dir", "host_flavor", "docker_host", "source_snapshot_sha256", "registry_ceiling"):
            if getattr(tool, name) != getattr(context, name):
                errors.append(f"runtime.container_runtime.{name} is not context.{name}")
    if persona is not None:
        if persona.cancel is not runtime.cancel:
            errors.append("runtime.persona_runtime.cancel is not the pool's cancel event")
        for name in ("registry_dir", "prompt_root", "allowed_models", "source_snapshot_sha256",
                     "registry_ceiling"):
            if getattr(persona, name) != getattr(context, name):
                errors.append(f"runtime.persona_runtime.{name} is not context.{name}")
        if not _same_roots(persona.readable_roots, context.readable_roots):
            errors.append("runtime.persona_runtime.readable_roots is not context.readable_roots")
        if persona.invoker.invoker_id != context.invoker_id:
            errors.append("runtime.persona_runtime.invoker is not the invoker context.invoker_id names")
    return errors


def _location_errors(context: ps.PoolContext, rendezvous_parent: Any) -> list:
    if (not isinstance(rendezvous_parent, Path) or not ps._real_directory(rendezvous_parent)
            or os.path.realpath(rendezvous_parent) != str(rendezvous_parent)):
        return ["rendezvous_parent must be an absolute, existing, non-link directory in its one real spelling"]
    mine, pools = ps._identity(rendezvous_parent), ps._identity(context.pool_parent)
    if mine in ps._chain(context.pool_parent) or pools in ps._chain(rendezvous_parent):
        return ["rendezvous_parent is, contains or lies beneath context.pool_parent: a manifest may not live "
                "where an instance or an expansion lives"]
    return []


# ---- THE classification rule: shared by the coordinator and the verifier -------------------------

_ROOT_ABSENT, _ROOT_NOT_PRIVATE, _NO_EVIDENCE, _NO_RESULT, _RESULT_REFUSED, _VERIFIED = range(6)


def _load_result(item: ps.InstanceRequest, entry: Mapping[str, Any], attempt_root: Path,
                 context: ps.PoolContext, host_facts: Any) -> Mapping[str, Any] | None:
    """The adapter's own verifier, for this instance's ids and request. None means refused.

    ANY exception is a refusal, a ``TypeError`` from a changed adapter signature included: an
    adapter verifier that cannot be called has verified nothing. It never propagates, never
    passes, and its text is never kept."""
    ids = {"run_id": entry["run_id"], "job_id": entry["job_id"], "attempt_id": entry["attempt_id"]}
    try:
        if item.worker_kind == ps.PERSONA:
            return pi.load_verified_result(
                attempt_root, **ids, request=item.request, registry_dir=context.registry_dir,
                prompt_root=context.prompt_root, readable_roots=context.readable_roots,
                allowed_models=context.allowed_models,
                source_snapshot_sha256=context.source_snapshot_sha256,
                registry_ceiling=context.registry_ceiling)
        return ce.load_verified_result(
            attempt_root, **ids, request=item.request, images_dir=context.images_dir,
            host_flavor=context.host_flavor, docker_host=context.docker_host,
            docker_executable=host_facts.docker_executable, container_user=host_facts.container_user)
    except Exception:      # noqa: BLE001 - a refusal of any kind is a refusal; its text is never kept
        return None


def _disk_facts(plan: ps.ExpansionPlan, index: int, pool_root: Path, context: ps.PoolContext,
                host_facts: Any) -> tuple:
    entry, item = plan.manifest["instances"][index], plan.requests[index]
    attempt_root = pool_root.joinpath(*entry["attempt_root"].split("/"))
    if not os.path.lexists(attempt_root):
        return _ROOT_ABSENT, None
    listing = ps._listing(attempt_root) if ps._real_directory(attempt_root) else None
    if listing is None:
        return _ROOT_NOT_PRIVATE, None
    if not listing:
        return _NO_EVIDENCE, None
    file_name = pi.RESULT_FILE if item.worker_kind == ps.PERSONA else ce.RESULT_FILE
    if not os.path.lexists(attempt_root.joinpath(*entry["log_path"].split("/"), file_name)):
        return _NO_RESULT, None
    result = _load_result(item, entry, attempt_root, context, host_facts)
    return (_VERIFIED, result) if result is not None else (_RESULT_REFUSED, None)


def _result_state(status: Any, cause: Any) -> str | None:
    if status == "OK":
        return SUCCEEDED
    if status == "BLOCKED":
        return BLOCKED
    if status == "CANCELED":
        return CANCELED
    if status == "FAILED":
        return INSTANCE_TIMED_OUT if cause == "TIMEOUT" else FAILED
    return None


def classify_instance(plan: ps.ExpansionPlan, index: int, *, pool_root: Path, context: ps.PoolContext,
                      host_facts: Any, observation: str) -> dict:
    """The manifest entry of one instance: :func:`_disk_facts` now, then :func:`_entry`."""
    errors = _host_facts_errors(plan, host_facts)
    if errors:
        raise RendezvousError("; ".join(errors))
    return _entry(plan, index, _disk_facts(plan, index, pool_root, context, host_facts), observation)


def _entry(plan: ps.ExpansionPlan, index: int, facts: tuple, observation: str) -> dict:
    """``appsec-review/pool-instance-classification/1.0``: the manifest entry of one instance.

    A pure function of the expansion, what is on disk now, and what the coordinator observed.

    ================================  =====================================================
    observation                       state
    ================================  =====================================================
    any, instance root absent         ``missing``
    unreported (either)               ``rendezvous_timed_out``, whatever is on disk: a
                                      result that appears late is never adopted
    unlaunched, root empty            ``not_launched_canceled`` / ``..._rendezvous_timeout``
    unlaunched, root not empty        ``invalid``: evidence nobody here launched
    reported, root not a private dir  ``invalid``
    reported, root empty              ``missing``: a worker's say-so is not evidence
    reported, no adapter result file  ``crashed``
    reported, verifier refuses        ``invalid``
    reported, verified result         by execution status and cause
    ================================  =====================================================
    """
    if observation not in OBSERVATIONS:
        raise RendezvousError("unknown coordinator observation")
    entry, item = plan.manifest["instances"][index], plan.requests[index]
    record = {
        **{name: entry[name] for name in ("instance_id", "group_id", "ordinal", "worker_kind", "attempt_root",
                                          "resource_pool", "request_sha256", "input_fingerprint")},
        "state": None, "adapter_status": None, "adapter_cause": None, "result_file": None,
        "invoker_stopped": None, "container_removed": None, "worker_stopped": None,
    }
    kind, result = facts
    if kind == _ROOT_ABSENT:
        record["state"] = MISSING
    elif observation in (UNREPORTED_STOPPED, UNREPORTED_RUNNING):
        record["state"] = RENDEZVOUS_TIMED_OUT
        record["worker_stopped"] = observation == UNREPORTED_STOPPED
    else:
        if observation != REPORTED:
            record["state"] = INVALID if kind != _NO_EVIDENCE else (
                NOT_LAUNCHED_CANCELED if observation == UNLAUNCHED_CANCELED else NOT_LAUNCHED_RENDEZVOUS_TIMEOUT)
        elif kind == _NO_EVIDENCE:
            record["state"] = MISSING
        elif kind == _NO_RESULT:
            record["state"] = CRASHED
        elif kind != _VERIFIED:
            record["state"] = INVALID
        else:
            persona = item.worker_kind == ps.PERSONA
            state = _result_state(result["execution_status"], result["cause"])
            stopped = result["invoker_stopped"] if persona else result["container_removed"]
            if state is None or (state == SUCCEEDED and stopped is not True):
                record["state"] = INVALID        # nothing that may still be written to is a success
            else:
                data = pi.canonical_bytes(thaw(result)) if persona else ce.canonical_request_bytes(thaw(result))
                file_name = pi.RESULT_FILE if persona else ce.RESULT_FILE
                record.update({
                    "state": state, "adapter_status": result["execution_status"], "adapter_cause": result["cause"],
                    "result_file": {"path": f"{entry['attempt_root']}/{entry['log_path']}/{file_name}",
                                    "sha256": _bytes_sha(data), "bytes": len(data)},
                    "invoker_stopped" if persona else "container_removed": stopped})
    return record


def pool_outcome(states: Any) -> str:
    """The pool-level outcome: a pure function of the instance states, in this precedence.

    ``EMPTY`` no instance; ``COMPLETE`` every instance succeeded; ``CANCELED`` any instance was
    canceled or not launched because of a cancel; ``FAILED`` no instance succeeded; ``DEGRADED``
    some succeeded and some did not. Only ``COMPLETE`` is a whole result set."""
    states = list(states)
    if any(state not in STATES for state in states):
        raise RendezvousError("unknown instance state")
    if not states:
        return EMPTY
    if all(state == SUCCEEDED for state in states):
        return COMPLETE
    if any(state in (CANCELED, NOT_LAUNCHED_CANCELED) for state in states):
        return POOL_CANCELED
    if SUCCEEDED not in states:
        return POOL_FAILED
    return DEGRADED


def manifest_sha256(manifest: Mapping[str, Any]) -> str:
    """Integrity hash over every other field. Not an authenticator: the verifier re-derives."""
    return "sha256:" + pc.digest({key: value for key, value in thaw(manifest).items()
                                  if key != "manifest_sha256"})


def derive_manifest(plan: ps.ExpansionPlan, *, pool_root: Path, context: ps.PoolContext,
                    host_facts: Any, observations: Any) -> dict:
    """The whole manifest from the expansion, the disk and one observation per instance, in the
    expansion's order. No clock, no host path, no free text."""
    errors = _host_facts_errors(plan, host_facts)
    if errors:
        raise RendezvousError("; ".join(errors))
    facts = [_disk_facts(plan, index, pool_root, context, host_facts)
             for index in range(len(plan.manifest["instances"]))]
    return _derive(plan, facts, observations)


def _derive(plan: ps.ExpansionPlan, facts: list, observations: Any) -> dict:
    observations = list(observations)
    if len(observations) != len(plan.manifest["instances"]):
        raise RendezvousError("there must be exactly one observation per expected instance, in order")
    instances = [_entry(plan, index, facts[index], observation) for index, observation in enumerate(observations)]
    states = [record["state"] for record in instances]
    manifest = {
        "schema": MANIFEST_ID, "classification": CLASSIFICATION_ID, "expansion": ps.EXPANSION_ID,
        "expansion_sha256": plan.manifest["expansion_sha256"], "spec_sha256": plan.spec_sha256,
        **{name: plan.manifest[name] for name in ("pool_directory", "pool_id", "lane", "run_id", "job_id",
                                                  "attempt_id", "wait_all", "rendezvous_timeout_seconds",
                                                  "empty_pool_reason")},
        "expansion_state": plan.manifest["state"],
        "outcome": pool_outcome(states),
        "counts": {"instances": len(states), **{state: states.count(state) for state in STATES}},
        "instances": instances,
    }
    manifest["manifest_sha256"] = manifest_sha256(manifest)
    return manifest


# ---- the terminal ledger: who may report, and how often -------------------------------------------

class TerminalLedger:
    """Which expected instances have reported that their attempt ended. A report carries no state
    (the state is read from disk); it only says "look now". An unknown instance id, a second report
    for one instance and a report after the wait ended are refused and change nothing."""

    def __init__(self, instance_ids: Any) -> None:
        self._expected = tuple(instance_ids)
        if len(set(self._expected)) != len(self._expected):
            raise RendezvousError("an expansion lists one instance id twice")
        self._reported: set = set()
        self._closed = False

    def report(self, instance_id: Any) -> None:
        if self._closed:
            raise RendezvousError("the wait has ended: a late terminal report is not adopted")
        if instance_id not in self._expected:
            raise RendezvousError("a terminal report names an instance the expansion does not expect")
        if instance_id in self._reported:
            raise RendezvousError("a second terminal report for one instance is refused: the first one stands")
        self._reported.add(instance_id)

    def close(self) -> frozenset:
        self._closed = True
        return frozenset(self._reported)

    @property
    def reported(self) -> frozenset:
        return frozenset(self._reported)


# ---- the wait -------------------------------------------------------------------------------------

def _limits(plan: ps.ExpansionPlan, runtime: RendezvousRuntime) -> tuple:
    """(overall, persona slots, per resource pool). Each can only be at or below B15's."""
    totals = plan.manifest["totals"]
    personas = min(totals["persona_slot_request"], rp.LIMITS[rp.PERSONA_LLM])
    pools = {record["resource_pool"]: rp.LIMITS[record["resource_pool"]] for record in totals["resource_pools"]}
    return runtime.max_parallel, personas, pools


def _start_worker(work: Any, index: int) -> threading.Thread:
    """One daemon thread per launched instance; at most ``max_parallel`` are in flight."""
    thread = threading.Thread(target=work, args=(index,), daemon=True, name="pool-instance-" + str(index))
    thread.start()
    return thread


def _wait(plan: ps.ExpansionPlan, pool_root: Path, context: ps.PoolContext,
          runtime: RendezvousRuntime) -> tuple:
    """Launches, waits, drains. Returns one observation per instance, in order, and any interrupt
    (KeyboardInterrupt / SystemExit) to re-raise after publication."""
    entries = plan.manifest["instances"]
    ids = [entry["instance_id"] for entry in entries]
    ledger = TerminalLedger(ids)
    condition = threading.Condition()
    exited: set = set()
    threads: dict = {}
    unlaunched: dict = {}
    adapters = {
        ps.PINNED_CONTAINER: (None if runtime.container_runtime is None
                              else worker_adapters.PinnedContainerAdapter(runtime.container_runtime)),
        ps.PERSONA: (None if runtime.persona_runtime is None
                     else worker_adapters.PersonaInvocationAdapter(runtime.persona_runtime)),
    }

    # Restart: an instance root that already holds anything is an attempt that ended or was lost
    # with an earlier coordinator. It is classified from disk and NEVER launched into.
    pending = []
    for index, entry in enumerate(entries):
        kind, _ = _disk_facts(plan, index, pool_root, context, host_facts_of(runtime.container_runtime))
        if kind == _NO_EVIDENCE:
            pending.append(index)
            continue
        ledger.report(entry["instance_id"])
        if kind == _NO_RESULT and entry["worker_kind"] == ps.PINNED_CONTAINER:
            # Best effort, never recorded: a lost coordinator may have left the run-owned container.
            ce.remove_container(runtime.container_runtime,
                                ce.container_name(entry["run_id"], entry["job_id"], entry["attempt_id"]))

    def work(index: int) -> None:
        entry, item = entries[index], plan.requests[index]
        key = "persona_request" if item.worker_kind == ps.PERSONA else "container_request"
        attempt_root = pool_root.joinpath(*entry["attempt_root"].split("/"))
        try:
            # Only ever into the private, still empty directory the expansion created: not into a
            # root that was deleted or replaced, and not on top of anything that is already there.
            if ps._real_directory(attempt_root) and ps._listing(attempt_root) == []:
                adapters[item.worker_kind].execute(worker_adapters.WorkerRequest(
                    run_id=entry["run_id"], job_id=entry["job_id"], attempt_id=entry["attempt_id"],
                    attempt_root=attempt_root, inputs={key: item.request}))
        except BaseException:      # noqa: BLE001 - the outcome is read from disk, never from here
            pass
        finally:
            with condition:
                exited.add(entry["instance_id"])
                try:
                    ledger.report(entry["instance_id"])
                except RendezvousError:
                    pass               # late: the wait has ended and this attempt is not adopted
                condition.notify_all()

    def wake() -> None:
        with condition:
            condition.notify_all()

    def in_flight() -> list:
        return [index for index in threads if entries[index]["instance_id"] not in ledger.reported]

    def launchable(index: int) -> bool:
        overall, personas, pools = _limits(plan, runtime)
        running = [entries[other] for other in in_flight()]
        entry = entries[index]
        if len(running) >= overall:
            return False
        if entry["worker_kind"] == ps.PERSONA and sum(
                1 for other in running if other["worker_kind"] == ps.PERSONA) >= personas:
            return False
        return sum(1 for other in running
                   if other["resource_pool"] == entry["resource_pool"]) < pools[entry["resource_pool"]]

    deadline = time.monotonic() + min(plan.manifest["rendezvous_timeout_seconds"], runtime.wait_limit_seconds)
    interrupt: BaseException | None = None
    runtime.cancel.subscribe(wake)
    try:
        with condition:
            while True:
                try:
                    timed_out = time.monotonic() >= deadline
                    if runtime.cancel.is_set() or timed_out:
                        reason = UNLAUNCHED_CANCELED if runtime.cancel.is_set() else UNLAUNCHED_RENDEZVOUS_TIMEOUT
                        for index in pending:
                            unlaunched[index] = reason
                        pending = []
                    for index in list(pending):
                        if launchable(index):
                            pending.remove(index)
                            try:
                                threads[index] = _start_worker(work, index)
                            except RuntimeError:        # no thread: nothing ran, and the disk will say so
                                threads[index] = None
                                exited.add(entries[index]["instance_id"])
                                ledger.report(entries[index]["instance_id"])
                    if timed_out or (not pending and not in_flight()):
                        break
                    lost = [index for index in in_flight() if not threads[index].is_alive()
                            and entries[index]["instance_id"] not in exited]
                    for index in lost:              # liveness backstop: a thread that died unreported
                        exited.add(entries[index]["instance_id"])
                        ledger.report(entries[index]["instance_id"])
                    if lost:
                        continue                    # its slot is free: launch before waiting again
                    condition.wait(max(0.0, min(deadline - time.monotonic(), LIVENESS_BACKSTOP_SECONDS)))
                except (KeyboardInterrupt, SystemExit) as exc:
                    interrupt = interrupt or exc
                    runtime.cancel.set()
            reported = ledger.close()       # from here on no report is adopted
            late = [index for index in threads if entries[index]["instance_id"] not in reported]
            if late:
                runtime.cancel.set()        # stop what is still running; its output is not adopted
                drained = time.monotonic() + runtime.drain_seconds
                while any(entries[index]["instance_id"] not in exited for index in late):
                    remaining = drained - time.monotonic()
                    if remaining <= 0:
                        break
                    condition.wait(min(remaining, LIVENESS_BACKSTOP_SECONDS))
            observations = []
            for index, entry in enumerate(entries):
                if entry["instance_id"] in reported:
                    observations.append(REPORTED)
                elif index in unlaunched:
                    observations.append(unlaunched[index])
                else:
                    observations.append(UNREPORTED_STOPPED if entry["instance_id"] in exited
                                        else UNREPORTED_RUNNING)
    finally:
        runtime.cancel.unsubscribe(wake)
    return observations, interrupt


# ---- publication ----------------------------------------------------------------------------------

def rendezvous_root(plan: ps.ExpansionPlan, rendezvous_parent: Path) -> Path:
    return rendezvous_parent / plan.pool_directory


def _prepare_root(root: Path) -> None:
    """Under the lock. Creates the rendezvous root, finishes or clears what a dead coordinator's
    publication left, and refuses anything foreign."""
    if not os.path.lexists(root):
        os.mkdir(root, 0o700)
    listing = ps._listing(root) if ps._real_directory(root) else None
    if listing is None:
        raise RendezvousError("the rendezvous root is a link, is not a directory or cannot be listed")
    for name in listing:
        if _TEMP_RE.match(name):
            os.unlink(root / name)      # this coordinator's own unpublished or already-linked bytes
        elif name != MANIFEST_FILE:
            raise RendezvousError("the rendezvous root holds something a coordinator never writes")
    if MANIFEST_FILE in listing:
        raise RendezvousPublishedError("a terminal-instance manifest is already published for this pool; "
                                       "it is never replaced")


def _publish(root: Path, data: bytes) -> None:
    """All of the bytes or none, and never over an existing manifest: the complete temporary file
    is hard-linked to the final name, which fails if that name exists."""
    temporary = root / f".terminal-instances.{uuid.uuid4().hex[:12]}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, root / MANIFEST_FILE)
        except FileExistsError:
            raise RendezvousPublishedError("a terminal-instance manifest is already published for this pool; "
                                           "it is never replaced") from None
    finally:
        os.unlink(temporary)
    if os.name != "nt":
        directory = os.open(root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def run_rendezvous(pool_root: Path, *, expected_spec: Any, context: ps.PoolContext,
                   runtime: RendezvousRuntime) -> Mapping[str, Any]:
    """Verify the expansion, launch and wait for every instance, publish the manifest once.

    Every argument is required. Returns the published manifest, deeply immutable. Raises
    ``PoolSpecError`` (the expansion does not verify), ``RendezvousBusyError`` (another coordinator
    holds the lock), ``RendezvousPublishedError`` (a manifest exists; it is left alone) or
    ``RendezvousError``; in each case this call published nothing."""
    validate_runtime(runtime)
    plan = ps.load_verified_expansion(pool_root, expected_spec=expected_spec, context=context)
    errors = _location_errors(context, runtime.rendezvous_parent) + _binding_errors(plan, context, runtime)
    if errors:
        raise RendezvousError("rendezvous runtime rejected: " + "; ".join(errors))
    root = rendezvous_root(plan, runtime.rendezvous_parent)
    lock = Lock(runtime.rendezvous_parent / (plan.pool_directory + LOCK_SUFFIX))
    try:
        lock.__enter__()
    except Blocked:
        raise RendezvousBusyError("another coordinator holds this pool's rendezvous lock; this call launched "
                                  "nothing and published nothing") from None
    try:
        _prepare_root(root)
        observations, interrupt = _wait(plan, pool_root, context, runtime)
        # The facts the launch used ARE the runtime's; the verifier must later be given the same.
        host_facts = host_facts_of(runtime.container_runtime)
        manifest = derive_manifest(plan, pool_root=pool_root, context=context, host_facts=host_facts,
                                   observations=observations)
        data = canonical_bytes(manifest)
        errors = manifest_errors(data, plan, pool_root=pool_root, context=context, host_facts=host_facts)
        if errors:
            raise RendezvousError("the derived manifest does not verify, so it is not published: "
                                  + "; ".join(errors))
        _publish(root, data)
    finally:
        lock.__exit__(None, None, None)
    if interrupt is not None:
        raise interrupt
    return freeze(manifest)


# ---- verification: a published manifest is a cache, never an authority ----------------------------

# The two things pool_specification.verify_expansion says about a pool whose instance roots are no
# longer all there. A manifest that records such an instance as `missing` must stay verifiable.
_ROOTS_LISTING = "the instances directory does not hold exactly one private root per expected instance"
_ROOTS_IDENTITY = "an instance root is a link, is not a directory, or two roots are one directory"


def expansion_errors(pool_root: Path, *, expected_spec: Any, context: ps.PoolContext) -> list:
    """C01's verifier, except that a damaged ``instances/`` directory is left to the classification
    rule (``missing``, ``invalid``): every other finding stands."""
    return [error for error in ps.verify_expansion(pool_root, expected_spec=expected_spec, context=context)
            if error not in (_ROOTS_LISTING, _ROOTS_IDENTITY)]


def manifest_errors(raw: Any, plan: ps.ExpansionPlan, *, pool_root: Path, context: ps.PoolContext,
                    host_facts: Any) -> list:
    """THE acceptance rule for manifest bytes, used before publication and by the verifier.

    Per instance, the recorded entry must be exactly what :func:`classify_instance` derives NOW for
    one of the observations a coordinator can make; then the whole document must be the bytes
    :func:`derive_manifest` derives for those observations. No hash in the manifest is an input."""
    errors = _host_facts_errors(plan, host_facts)
    if errors:
        return errors
    try:
        found = ps.parse_document(raw)
    except ps.PoolSpecError:
        return ["the manifest is not bounded UTF-8 JSON with exactly one reading"]
    schema_errors = validate_document(found, MANIFEST_SCHEMA)
    if schema_errors:
        return [f"the manifest fails its closed schema ({len(schema_errors)} errors)"]
    if found["wait_all"] is not True:
        return ["wait_all must be the JSON value true"]
    expected = plan.manifest["instances"]
    if [record["instance_id"] for record in found["instances"]] != [entry["instance_id"] for entry in expected]:
        return ["the manifest's instances are not the expansion's instances, each once and in order: a "
                "duplicate, unknown, reordered or absent instance is refused"]
    errors: list = []
    observations = []
    facts = [_disk_facts(plan, index, pool_root, context, host_facts) for index in range(len(expected))]
    for index, record in enumerate(found["instances"]):
        for observation in OBSERVATIONS:
            if _entry(plan, index, facts[index], observation) == record:
                observations.append(observation)
                break
        else:
            errors.append(f"instances[{index}] is not what the expansion, the attempt on disk and any "
                          "coordinator observation derive")
    if errors:
        return errors
    states = [record["state"] for record in found["instances"]]
    if NOT_LAUNCHED_CANCELED in states and NOT_LAUNCHED_RENDEZVOUS_TIMEOUT in states:
        errors.append("one wait cannot end both by cancel and by timeout for instances it never launched")
    if bytes(raw) != canonical_bytes(_derive(plan, facts, observations)):
        if found["manifest_sha256"] != manifest_sha256(found):
            errors.append("manifest_sha256 does not match the manifest record")
        if bytes(raw) != canonical_bytes(found):
            errors.append("the manifest is not in the canonical byte form")
        errors.append("the manifest is not the byte sequence the expansion and the attempts on disk derive")
    return errors


def _verify(pool_root: Path, expected_spec: Any, context: ps.PoolContext, rendezvous_parent: Path,
            host_facts: Any) -> tuple:
    """(errors, the bytes those errors are about)."""
    errors = expansion_errors(pool_root, expected_spec=expected_spec, context=context)
    if errors:
        return ["the pool expansion does not verify: " + "; ".join(errors)], None
    plan = ps.plan_expansion(expected_spec, context=context)
    errors = _location_errors(context, rendezvous_parent)
    if errors:
        return errors, None
    root = rendezvous_root(plan, rendezvous_parent)
    if not ps._real_directory(root):
        return ["the rendezvous root is missing, is a link or is not a directory: no manifest was published"], None
    if ps._listing(root) != [MANIFEST_FILE]:
        return ["the rendezvous root does not hold exactly the terminal-instance manifest"], None
    raw = ps._read_regular(root, root / MANIFEST_FILE)
    if raw is None:
        return ["the manifest is missing, linked, hard-linked, oversized or unreadable"], None
    return manifest_errors(raw, plan, pool_root=pool_root, context=context, host_facts=host_facts), raw


def verify_manifest(pool_root: Path, *, expected_spec: Any, context: ps.PoolContext,
                    rendezvous_parent: Path, host_facts: Any) -> list:
    """Re-derives the published manifest from the expected specification, the expansion and the
    instance attempts on disk. Read-only. Every argument is required. Messages are fixed text."""
    return _verify(pool_root, expected_spec, context, rendezvous_parent, host_facts)[0]


def load_verified_manifest(pool_root: Path, *, expected_spec: Any, context: ps.PoolContext,
                           rendezvous_parent: Path, host_facts: Any) -> Mapping[str, Any]:
    """The manifest T10 and C03 may rely on: verified against disk, deeply immutable."""
    errors, raw = _verify(pool_root, expected_spec, context, rendezvous_parent, host_facts)
    if errors:
        raise RendezvousError("terminal-instance manifest rejected: " + "; ".join(errors))
    return freeze(ps.parse_document(raw))       # the very bytes that were verified
