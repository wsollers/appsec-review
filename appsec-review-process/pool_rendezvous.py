#!/usr/bin/env python3
"""Wait-all rendezvous and terminal-instance manifest (backlog batch C02).

Given one verified C01 expansion and a trusted runtime, :func:`run_rendezvous` launches every
expected instance through its real adapter (``worker_adapters``: B13 pinned container, B14 persona
invocation), waits without busy polling until every instance is terminal or the wait ends, and then
publishes exactly one immutable ``appsec-review/pool-rendezvous-manifest/1.0``: LAST, atomically,
created exclusively. :func:`verify_manifest` is the read-only counterpart.

The ``PoolContext`` is the single carrier of host facts (C01): the coordinator builds the adapter
runtimes from it and the launch-only objects of :class:`RendezvousRuntime`, and every reader hands the
adapters' verifiers the context's own keyword arguments, so what ran is what is verified.

What this module guarantees to T10 and C03:

* :func:`classify_instance` is THE rule for "what state is this instance in". The coordinator and
  the verifier both call it and nothing else decides, so they cannot drift. An adapter outcome is
  read from DISK through the adapter's own verifier (``load_verified_result``), never from a value
  an adapter returned and never from a worker thread's say-so.
* The manifest lists every instance of the expansion, in the expansion's order. A worker that was
  not observed is ``missing``, ``crashed``, ``rendezvous_timed_out`` or ``not_launched_*``; it is
  never an empty success. An ``EMPTY`` expansion publishes ``EMPTY`` with its reason. Every entry
  carries a closed ``state_reason`` saying which of a state's causes applied.
* Once anything may have been launched, ``KeyboardInterrupt`` and ``SystemExit`` are held until the
  manifest is published and re-raised afterwards; they are a cancel, never a way out without one.
* The manifest carries no timestamp, no host path and no free text: one set of on-disk facts and
  coordinator observations derives one byte sequence, in one run or across a restart.
* No value read from a specification, from disk or from an adapter is echoed into a message.
* Threads are in-process and bounded. The caps here (persona slots, ``resource_pools.LIMITS``, the
  runtime's ``max_parallel``) can only be narrower than B15's WITHIN ONE RENDEZVOUS; they do not see
  other runs and do not replace Dagster pools, so at most one rendezvous may run on a host at a
  time (``docs/rendezvous/pool-rendezvous.md``, "Constraint: one rendezvous at a time").
  The op that calls this is ``resource_pools.unassigned('coordination_only')``.

See ``docs/rendezvous/pool-rendezvous.md``.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
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

# ---- why an instance is in its state (closed; one per entry) --------------------------------------
REASON_VERIFIED_RESULT = "verified_adapter_result"
REASON_WORKER_STOPPED_LATE = "worker_stopped_after_the_wait_ended"
REASON_WORKER_STILL_RUNNING = "worker_still_running_after_the_drain"
REASON_NO_RESULT_FILE = "attempt_evidence_without_adapter_result"
REASON_RESULT_REFUSED = "adapter_verifier_refused_the_result"
REASON_ROOT_NOT_PRIVATE = "instance_root_not_a_private_directory"
REASON_EVIDENCE_NOT_LAUNCHED = "evidence_nobody_launched"
REASON_WRITER_NOT_STOPPED = "ok_result_whose_writer_has_not_stopped"
REASON_STATUS_UNKNOWN = "adapter_status_not_classifiable"
REASON_CANCELED_BEFORE_LAUNCH = "pool_canceled_before_launch"
REASON_WAIT_ENDED_BEFORE_LAUNCH = "wait_ended_before_launch"
REASON_ROOT_ABSENT = "instance_root_absent"
REASON_NO_EVIDENCE = "adapter_left_no_evidence"
REASON_THREAD_NOT_STARTED = "worker_thread_not_started"
# THE table of which reasons a state can have. ``_entry`` can produce nothing else (a test walks
# every disk fact and observation), and the instance schema's enum is this table's values.
REASONS_BY_STATE = {
    **{state: (REASON_VERIFIED_RESULT,) for state in RESULT_STATES},
    RENDEZVOUS_TIMED_OUT: (REASON_WORKER_STOPPED_LATE, REASON_WORKER_STILL_RUNNING),
    CRASHED: (REASON_NO_RESULT_FILE,),
    INVALID: (REASON_RESULT_REFUSED, REASON_ROOT_NOT_PRIVATE, REASON_EVIDENCE_NOT_LAUNCHED,
              REASON_WRITER_NOT_STOPPED, REASON_STATUS_UNKNOWN),
    NOT_LAUNCHED_CANCELED: (REASON_CANCELED_BEFORE_LAUNCH,),
    NOT_LAUNCHED_RENDEZVOUS_TIMEOUT: (REASON_WAIT_ENDED_BEFORE_LAUNCH,),
    MISSING: (REASON_ROOT_ABSENT, REASON_NO_EVIDENCE, REASON_THREAD_NOT_STARTED),
}
STATE_REASONS = tuple(dict.fromkeys(reason for state in STATES for reason in REASONS_BY_STATE[state]))

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
UNLAUNCHED_CANCELED = "unlaunched_canceled"      # never began: the pool was canceled (or interrupted) first
UNLAUNCHED_RENDEZVOUS_TIMEOUT = "unlaunched_rendezvous_timeout"
UNSTARTABLE = "unstartable"              # the interpreter refused to start the worker thread
OBSERVATIONS = (REPORTED, UNREPORTED_STOPPED, UNREPORTED_RUNNING, UNLAUNCHED_CANCELED,
                UNLAUNCHED_RENDEZVOUS_TIMEOUT, UNSTARTABLE)

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
            if listener not in self._listeners:
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
    """Trusted, integrator-supplied LAUNCH side of one rendezvous. Every field is required; there is
    no default anywhere.

    It holds no host fact: those are the ``PoolContext``'s, and the coordinator builds the B13 and
    B14 runtimes itself with ``context.container_runtime`` / ``context.persona_runtime`` from the
    launch-only objects here (``pool_specification.CONTAINER_LAUNCH_ONLY_FIELDS`` /
    ``PERSONA_LAUNCH_ONLY_FIELDS``), so a ready-made adapter runtime that disagrees with the context
    cannot be handed in. ``invoker`` may be ``None`` only when the expansion has no persona
    instance; with one it must be the invoker ``context.invoker_id`` names. ``cancel`` is the pool's
    one cancel event and is the event both adapters get.

    ``rendezvous_parent`` is a run-owned directory for terminal-instance manifests. It may not be,
    contain or lie beneath ``context.pool_parent``. ``wait_limit_seconds`` can only narrow the
    specification's ``rendezvous_timeout_seconds``.
    """
    rendezvous_parent: Path
    invoker: Any
    clock: Any
    stop_grace_seconds: int
    cancel: PoolCancel
    max_parallel: int
    wait_limit_seconds: float
    drain_seconds: int


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _bytes_sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def validate_runtime(runtime: Any) -> None:
    """What can be checked without a context. ``invoker``, ``clock`` and ``stop_grace_seconds`` are
    validated by the adapters themselves when :func:`adapter_runtimes` builds their runtimes."""
    if not isinstance(runtime, RendezvousRuntime):
        raise TypeError("a rendezvous requires a RendezvousRuntime")
    if type(runtime.cancel) is not PoolCancel:
        raise RendezvousError("runtime.cancel must be a PoolCancel")
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


def adapter_runtimes(plan: ps.ExpansionPlan, context: ps.PoolContext, runtime: RendezvousRuntime) -> dict:
    """``{worker kind: adapter runtime}`` for exactly the kinds the expansion has, built by the
    context from its own facts and the launch-only objects. Raises ``PoolSpecError`` (C01's and the
    adapters' fixed text): a missing container fact, an invoker that is not the one the context
    names, a clock or stop grace the adapter refuses."""
    kinds = {instance.worker_kind for instance in plan.instances}
    built: dict = {}
    if ps.PINNED_CONTAINER in kinds:
        built[ps.PINNED_CONTAINER] = context.container_runtime(clock=runtime.clock, cancel=runtime.cancel)
    if ps.PERSONA in kinds:
        built[ps.PERSONA] = context.persona_runtime(
            invoker=runtime.invoker, clock=runtime.clock, cancel=runtime.cancel,
            stop_grace_seconds=runtime.stop_grace_seconds)
    return built


def _location_errors(context: ps.PoolContext, rendezvous_parent: Any) -> list:
    if (not isinstance(rendezvous_parent, Path) or not ps.real_directory(rendezvous_parent)
            or os.path.realpath(rendezvous_parent) != str(rendezvous_parent)):
        return ["rendezvous_parent must be an absolute, existing, non-link directory in its one real spelling"]
    mine, pools = ps.path_identity(rendezvous_parent), ps.path_identity(context.pool_parent)
    if mine in ps.identity_chain(context.pool_parent) or pools in ps.identity_chain(rendezvous_parent):
        return ["rendezvous_parent is, contains or lies beneath context.pool_parent: a manifest may not live "
                "where an instance or an expansion lives"]
    return []


# ---- THE classification rule: shared by the coordinator and the verifier -------------------------

_ROOT_ABSENT, _ROOT_NOT_PRIVATE, _NO_EVIDENCE, _NO_RESULT, _RESULT_REFUSED, _VERIFIED = range(6)


def _load_result(instance: ps.PlannedInstance, attempt_root: Path,
                 context: ps.PoolContext) -> Mapping[str, Any] | None:
    """The adapter's own verifier, for this instance's ids and request and the CONTEXT's facts.
    None means refused.

    ANY exception is a refusal, a ``TypeError`` from a changed adapter signature and a context
    without container facts included: an adapter verifier that cannot be called has verified
    nothing. It never propagates, never passes, and its text is never kept."""
    try:
        if instance.worker_kind == ps.PERSONA:
            return pi.load_verified_result(attempt_root, **instance.ids, request=instance.request.request,
                                           **context.persona_verification_arguments())
        return ce.load_verified_result(attempt_root, **instance.ids, request=instance.request.request,
                                       **context.container_verification_arguments())
    except Exception:      # noqa: BLE001 - a refusal of any kind is a refusal; its text is never kept
        return None


def _result_file_name(instance: ps.PlannedInstance) -> str:
    return pi.RESULT_FILE if instance.worker_kind == ps.PERSONA else ce.RESULT_FILE


def _disk_facts(instance: ps.PlannedInstance, pool_root: Path, context: ps.PoolContext) -> tuple:
    attempt_root = instance.attempt_root_path(pool_root)
    if not os.path.lexists(attempt_root):
        return _ROOT_ABSENT, None
    listing = ps.directory_listing(attempt_root) if ps.real_directory(attempt_root) else None
    if listing is None:
        return _ROOT_NOT_PRIVATE, None
    if not listing:
        return _NO_EVIDENCE, None
    if not os.path.lexists(attempt_root.joinpath(*instance.entry["log_path"].split("/"),
                                                 _result_file_name(instance))):
        return _NO_RESULT, None
    result = _load_result(instance, attempt_root, context)
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


def _context_errors(plan: ps.ExpansionPlan, context: Any) -> list:
    """A reader of a pool with pinned-container instances must hold the container facts; without
    them B13's verifier cannot be called and every such instance would silently read ``invalid``."""
    if not isinstance(context, ps.PoolContext):
        return ["context must be a PoolContext"]
    if any(instance.worker_kind == ps.PINNED_CONTAINER for instance in plan.instances):
        try:
            context.require_container_facts()
        except ps.PoolSpecError:
            return ["the expansion has pinned-container instances and the context carries no "
                    "docker_executable and container_user"]
    return []


def classify_instance(plan: ps.ExpansionPlan, index: int, *, pool_root: Path, context: ps.PoolContext,
                      observation: str) -> dict:
    """The manifest entry of one instance: :func:`_disk_facts` now, then :func:`_entry`."""
    errors = _context_errors(plan, context)
    if errors:
        raise RendezvousError("; ".join(errors))
    instance = plan.instances[index]
    return _entry(instance, _disk_facts(instance, pool_root, context), observation)


def _entry(instance: ps.PlannedInstance, facts: tuple, observation: str) -> dict:
    """``appsec-review/pool-instance-classification/1.0``: the manifest entry of one instance.

    A pure function of the expansion, what is on disk now, and what the coordinator observed.

    ================================  ==============================  =================================
    observation, disk                 state                           state_reason
    ================================  ==============================  =================================
    any, instance root absent         ``missing``                     ``instance_root_absent``
    unreported, worker gone           ``rendezvous_timed_out``        ``worker_stopped_after_the_...``
    unreported, worker alive          ``rendezvous_timed_out``        ``worker_still_running_after...``
                                      (whatever is on disk: a result that appears late is never adopted)
    unlaunched, root empty            ``not_launched_canceled`` /     ``pool_canceled_before_launch`` /
                                      ``..._rendezvous_timeout``      ``wait_ended_before_launch``
    unstartable, root empty           ``missing``                     ``worker_thread_not_started``
    unlaunched or unstartable, root   ``invalid``                     ``evidence_nobody_launched``
    not empty (or not private)
    reported, root not a private dir  ``invalid``                     ``instance_root_not_a_private...``
    reported, root empty              ``missing``                     ``adapter_left_no_evidence``
                                      (a worker's say-so is not evidence)
    reported, no adapter result file  ``crashed``                     ``attempt_evidence_without_...``
    reported, verifier refuses        ``invalid``                     ``adapter_verifier_refused_...``
    reported, OK but writer running   ``invalid``                     ``ok_result_whose_writer_has...``
    reported, verified result         by execution status and cause   ``verified_adapter_result``
    ================================  ==============================  =================================
    """
    if observation not in OBSERVATIONS:
        raise RendezvousError("unknown coordinator observation")
    entry = instance.entry
    record = {
        **{name: entry[name] for name in ("instance_id", "group_id", "ordinal", "worker_kind", "attempt_root",
                                          "resource_pool", "request_sha256", "input_fingerprint")},
        "state": None, "state_reason": None, "adapter_status": None, "adapter_cause": None, "result_file": None,
        "invoker_stopped": None, "container_removed": None, "worker_stopped": None,
    }

    def end(state: str, reason: str) -> dict:
        if reason not in REASONS_BY_STATE[state]:
            raise RendezvousError("the classification rule derived a reason its state does not have")
        record.update(state=state, state_reason=reason)
        return record

    kind, result = facts
    if kind == _ROOT_ABSENT:
        return end(MISSING, REASON_ROOT_ABSENT)
    if observation in (UNREPORTED_STOPPED, UNREPORTED_RUNNING):
        record["worker_stopped"] = observation == UNREPORTED_STOPPED
        return end(RENDEZVOUS_TIMED_OUT, REASON_WORKER_STOPPED_LATE if record["worker_stopped"]
                   else REASON_WORKER_STILL_RUNNING)
    if observation != REPORTED:
        if kind != _NO_EVIDENCE:
            return end(INVALID, REASON_EVIDENCE_NOT_LAUNCHED)
        if observation == UNSTARTABLE:
            return end(MISSING, REASON_THREAD_NOT_STARTED)
        if observation == UNLAUNCHED_CANCELED:
            return end(NOT_LAUNCHED_CANCELED, REASON_CANCELED_BEFORE_LAUNCH)
        return end(NOT_LAUNCHED_RENDEZVOUS_TIMEOUT, REASON_WAIT_ENDED_BEFORE_LAUNCH)
    if kind == _ROOT_NOT_PRIVATE:
        return end(INVALID, REASON_ROOT_NOT_PRIVATE)
    if kind == _NO_EVIDENCE:
        return end(MISSING, REASON_NO_EVIDENCE)
    if kind == _NO_RESULT:
        return end(CRASHED, REASON_NO_RESULT_FILE)
    if kind != _VERIFIED:
        return end(INVALID, REASON_RESULT_REFUSED)
    persona = instance.worker_kind == ps.PERSONA
    state = _result_state(result["execution_status"], result["cause"])
    stopped = result["invoker_stopped"] if persona else result["container_removed"]
    if state is None:
        return end(INVALID, REASON_STATUS_UNKNOWN)
    if state == SUCCEEDED and stopped is not True:
        return end(INVALID, REASON_WRITER_NOT_STOPPED)      # nothing that may still be written to is a success
    data = pi.canonical_bytes(thaw(result)) if persona else ce.canonical_request_bytes(thaw(result))
    record.update({
        "adapter_status": result["execution_status"], "adapter_cause": result["cause"],
        "result_file": {"path": f"{entry['attempt_root']}/{entry['log_path']}/{_result_file_name(instance)}",
                        "sha256": _bytes_sha(data), "bytes": len(data)},
        "invoker_stopped" if persona else "container_removed": stopped})
    return end(state, REASON_VERIFIED_RESULT)


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
                    observations: Any) -> dict:
    """The whole manifest from the expansion, the disk and one observation per instance, in the
    expansion's order. No clock, no host path, no free text."""
    errors = _context_errors(plan, context)
    if errors:
        raise RendezvousError("; ".join(errors))
    facts = [_disk_facts(instance, pool_root, context) for instance in plan.instances]
    return _derive(plan, facts, observations)


def _derive(plan: ps.ExpansionPlan, facts: list, observations: Any) -> dict:
    observations = list(observations)
    if len(observations) != len(plan.instances):
        raise RendezvousError("there must be exactly one observation per expected instance, in order")
    instances = [_entry(instance, facts[instance.index], observations[instance.index])
                 for instance in plan.instances]
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


def _start_worker(thread: threading.Thread) -> None:
    """The one place a worker thread is started (a seam for tests). ``RuntimeError`` means the
    interpreter could not start it."""
    thread.start()


# An interrupt is held, never swallowed for good: a caller that keeps interrupting one step more
# often than this gets its interrupt back although nothing was published.
MAX_HELD_INTERRUPTS = 32


class _Interrupts:
    """``KeyboardInterrupt`` / ``SystemExit`` from the first possible launch until publication.
    Each is a cancel: it is recorded, the pool's cancel event is set, and the RESUMABLE step it
    landed in is entered again. The first one is re-raised by ``run_rendezvous`` after publication."""

    def __init__(self, cancel: PoolCancel) -> None:
        self.caught: list = []
        self._cancel = cancel

    def hold(self, step: Any) -> Any:
        while True:
            try:
                if self.caught:
                    self._cancel.set()
                return step()
            except (KeyboardInterrupt, SystemExit) as exc:
                self.caught.append(exc)
                if len(self.caught) > MAX_HELD_INTERRUPTS:
                    raise


class _Wait:
    """Launches, waits, drains. :meth:`run` returns one observation per instance, in order, and is
    RESUMABLE: every piece of state lives here, so entering it again after an interrupt at any
    point continues the same wait (nothing is launched twice, the ledger closes once, the drain
    keeps its one deadline)."""

    def __init__(self, plan: ps.ExpansionPlan, pool_root: Path, context: ps.PoolContext,
                 runtime: RendezvousRuntime, runtimes: Mapping[str, Any], interrupts: _Interrupts) -> None:
        self.plan, self.pool_root, self.context, self.runtime = plan, pool_root, context, runtime
        self.instances = plan.instances
        self.runtimes, self.interrupts = runtimes, interrupts
        self.adapters = {
            ps.PINNED_CONTAINER: worker_adapters.PinnedContainerAdapter,
            ps.PERSONA: worker_adapters.PersonaInvocationAdapter,
        }
        self.ledger = TerminalLedger([instance.instance_id for instance in self.instances])
        self.condition = threading.Condition()
        self.pending: list = []
        self.threads: dict = {}          # index -> Thread, registered BEFORE it is started
        self.begun: set = set()          # workers that passed the launch gate (under the condition)
        self.exited: set = set()         # instance ids whose worker left its ``finally``
        self.unlaunched: dict = {}       # index -> why nothing was ever launched for it
        self.unstartable: set = set()
        self.ended: str | None = None    # why the wait ended for what was never launched
        self.deadline: float | None = None
        self.reported: frozenset | None = None
        self.drain_until: float | None = None

    def scan(self) -> None:
        """Restart, before anything is launched (not held: an interrupt here leaves nothing behind
        that a later coordinator cannot classify). An instance root that already holds anything is
        an attempt that ended or was lost with an earlier coordinator. It is classified from disk
        and NEVER launched into."""
        for instance in self.instances:
            kind, _ = _disk_facts(instance, self.pool_root, self.context)
            if kind == _NO_EVIDENCE:
                self.pending.append(instance.index)
                continue
            self.ledger.report(instance.instance_id)
            if kind == _NO_RESULT and instance.worker_kind == ps.PINNED_CONTAINER:
                # Best effort, never recorded: a lost coordinator may have left the run-owned container.
                ce.remove_container(self.runtimes[ps.PINNED_CONTAINER], ce.container_name(**instance.ids))

    # -- worker side ------------------------------------------------------------------------------
    def _work(self, index: int) -> None:
        instance = self.instances[index]
        with self.condition:
            # THE launch gate. The coordinator decides "never launched" under this same lock, so a
            # worker that has not passed the gate by then launches nothing, ever.
            if index in self.unlaunched:
                return
            if self.runtime.cancel.is_set():
                self.unlaunched[index] = UNLAUNCHED_CANCELED
                self.condition.notify_all()
                return
            self.begun.add(index)
        key = "persona_request" if instance.worker_kind == ps.PERSONA else "container_request"
        attempt_root = instance.attempt_root_path(self.pool_root)
        try:
            # Only ever into the private, still empty directory the expansion created: not into a
            # root that was deleted or replaced, and not on top of anything that is already there.
            if ps.real_directory(attempt_root) and ps.directory_listing(attempt_root) == []:
                adapter = self.adapters[instance.worker_kind](self.runtimes[instance.worker_kind])
                adapter.execute(worker_adapters.WorkerRequest(
                    **instance.ids, attempt_root=attempt_root, inputs={key: instance.request.request}))
        except BaseException:      # noqa: BLE001 - the outcome is read from disk, never from here
            pass
        finally:
            with self.condition:
                self.exited.add(instance.instance_id)
                try:
                    self.ledger.report(instance.instance_id)
                except RendezvousError:
                    pass               # late: the wait has ended and this attempt is not adopted
                self.condition.notify_all()

    def wake(self) -> None:
        with self.condition:
            self.condition.notify_all()

    # -- coordinator side (all under the condition) -------------------------------------------------
    def _in_flight(self) -> list:
        return [index for index in self.threads
                if index not in self.unlaunched and index not in self.unstartable
                and self.instances[index].instance_id not in self.ledger.reported]

    def _launchable(self, index: int) -> bool:
        overall, personas, pools = _limits(self.plan, self.runtime)
        running = [self.instances[other].entry for other in self._in_flight()]
        entry = self.instances[index].entry
        if len(running) >= overall:
            return False
        if entry["worker_kind"] == ps.PERSONA and sum(
                1 for other in running if other["worker_kind"] == ps.PERSONA) >= personas:
            return False
        return sum(1 for other in running
                   if other["resource_pool"] == entry["resource_pool"]) < pools[entry["resource_pool"]]

    def _never_began(self, index: int) -> None:
        """A registered worker that has not passed the gate and now never will."""
        if self.ended is None and not self.runtime.cancel.is_set():
            self.unstartable.add(index)         # nothing ended the wait: the thread simply never ran
        else:
            self.unlaunched[index] = self.ended or UNLAUNCHED_CANCELED

    def _loop(self) -> None:
        if self.deadline is None:
            self.deadline = time.monotonic() + min(self.plan.manifest["rendezvous_timeout_seconds"],
                                                   self.runtime.wait_limit_seconds)
        while True:
            timed_out = time.monotonic() >= self.deadline
            if self.runtime.cancel.is_set() or timed_out:
                if self.ended is None:
                    self.ended = (UNLAUNCHED_CANCELED if self.runtime.cancel.is_set()
                                  else UNLAUNCHED_RENDEZVOUS_TIMEOUT)
                for index in self.pending:
                    self.unlaunched[index] = self.ended
                self.pending = []
            for index in list(self.pending):
                if self._launchable(index):
                    thread = threading.Thread(target=self._work, args=(index,), daemon=True,
                                              name="pool-instance-" + str(index))
                    self.threads[index] = thread        # registered first: an interrupt cannot lose it
                    self.pending.remove(index)
                    try:
                        _start_worker(thread)
                    except RuntimeError:                # no thread: nothing ran, and the manifest says so
                        self.unstartable.add(index)
            if timed_out or (not self.pending and not self._in_flight()):
                return
            lost = [index for index in self._in_flight() if not self.threads[index].is_alive()
                    and self.instances[index].instance_id not in self.exited]
            for index in lost:                  # liveness backstop
                if index in self.begun:         # a thread that died unreported: the disk says what it left
                    self.exited.add(self.instances[index].instance_id)
                    self.ledger.report(self.instances[index].instance_id)
                else:                           # a thread that never ran (an interrupt landed in its start)
                    self._never_began(index)
            if lost:
                continue                        # its slot is free: launch before waiting again
            self.condition.wait(max(0.0, min(self.deadline - time.monotonic(), LIVENESS_BACKSTOP_SECONDS)))

    def _drain(self) -> None:
        late = [index for index in self._in_flight()
                if self.instances[index].instance_id not in self.reported]
        if not late:
            return
        self.runtime.cancel.set()               # stop what is still running; its output is not adopted
        if self.drain_until is None:
            self.drain_until = time.monotonic() + self.runtime.drain_seconds
        while any(self.instances[index].instance_id not in self.exited for index in late):
            if len(self.interrupts.caught) > 1:
                return                          # a second interrupt cuts the drain short; publication follows
            remaining = self.drain_until - time.monotonic()
            if remaining <= 0:
                return
            self.condition.wait(min(remaining, LIVENESS_BACKSTOP_SECONDS))

    def run(self) -> list:
        with self.condition:
            if self.reported is None:
                self._loop()
                for index in self.threads:      # under the gate's lock: what has not begun never will
                    if (index not in self.begun and index not in self.unlaunched
                            and index not in self.unstartable):
                        self._never_began(index)
                self.reported = self.ledger.close()     # from here on no report is adopted
            self._drain()
            observations = []
            for instance in self.instances:
                if instance.index in self.unstartable:
                    observations.append(UNSTARTABLE)
                elif instance.index in self.unlaunched:
                    observations.append(self.unlaunched[instance.index])
                elif instance.instance_id in self.reported:
                    observations.append(REPORTED)
                else:
                    observations.append(UNREPORTED_STOPPED if instance.instance_id in self.exited
                                        else UNREPORTED_RUNNING)
            return observations


def _wait(plan: ps.ExpansionPlan, pool_root: Path, context: ps.PoolContext, runtime: RendezvousRuntime,
          runtimes: Mapping[str, Any], interrupts: _Interrupts) -> _Wait:
    """The wait of one rendezvous, restart scan done, nothing launched yet."""
    wait = _Wait(plan, pool_root, context, runtime, runtimes, interrupts)
    wait.scan()
    return wait


# ---- publication ----------------------------------------------------------------------------------

def rendezvous_root(plan: ps.ExpansionPlan, rendezvous_parent: Path) -> Path:
    return rendezvous_parent / plan.pool_directory


def _prepare_root(root: Path) -> None:
    """Under the lock. Creates the rendezvous root, finishes or clears what a dead coordinator's
    publication left, and refuses anything foreign."""
    if not os.path.lexists(root):
        os.mkdir(root, 0o700)
    listing = ps.directory_listing(root) if ps.real_directory(root) else None
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


def _publish_once(root: Path, data: bytes) -> None:
    """:func:`_publish`, RESUMABLE: entered again after an interrupt it links nothing twice, clears
    a temporary file the interrupted attempt left, and still refuses a manifest that is not these
    bytes. Under the pool's lock, after :func:`_prepare_root` found no manifest."""
    if not os.path.lexists(root / MANIFEST_FILE):
        _publish(root, data)
    for name in ps.directory_listing(root) or []:
        if _TEMP_RE.match(name):
            os.unlink(root / name)
    if ps.read_regular_file(root, root / MANIFEST_FILE) != data:
        raise RendezvousPublishedError("a terminal-instance manifest is already published for this pool; "
                                       "it is never replaced")


def run_rendezvous(pool_root: Path, *, expected_spec: Any, context: ps.PoolContext,
                   runtime: RendezvousRuntime) -> Mapping[str, Any]:
    """Verify the expansion, launch and wait for every instance, publish the manifest once.

    Every argument is required. Returns the published manifest, deeply immutable. Raises
    ``PoolSpecError`` (the expansion does not verify, or the context and the launch-only objects do
    not make the adapter runtimes), ``RendezvousBusyError`` (another coordinator holds the lock),
    ``RendezvousPublishedError`` (a manifest exists; it is left alone) or ``RendezvousError``; in
    each case this call published nothing.

    From the moment anything may be launched until the manifest is published, ``KeyboardInterrupt``
    and ``SystemExit`` are HELD: each is a pool cancel, a second one also cuts the drain short, and
    the first is re-raised after publication. So an interrupted rendezvous still publishes, a
    late instance stays ``rendezvous_timed_out``, and no later run can adopt its result."""
    validate_runtime(runtime)
    plan = ps.load_verified_expansion(pool_root, expected_spec=expected_spec, context=context)
    errors = _location_errors(context, runtime.rendezvous_parent)
    if errors:
        raise RendezvousError("rendezvous runtime rejected: " + "; ".join(errors))
    runtimes = adapter_runtimes(plan, context, runtime)
    root = rendezvous_root(plan, runtime.rendezvous_parent)
    lock = Lock(runtime.rendezvous_parent / (plan.pool_directory + LOCK_SUFFIX))
    try:
        lock.__enter__()
    except Blocked:
        raise RendezvousBusyError("another coordinator holds this pool's rendezvous lock; this call launched "
                                  "nothing and published nothing") from None
    interrupts = _Interrupts(runtime.cancel)
    done: dict = {}
    try:
        _prepare_root(root)
        wait = _wait(plan, pool_root, context, runtime, runtimes, interrupts)

        def finish() -> None:       # RESUMABLE as a whole: wait -> close -> drain -> derive -> validate -> publish
            runtime.cancel.subscribe(wait.wake)
            if "observations" not in done:
                done["observations"] = wait.run()
            if "data" not in done:
                manifest = derive_manifest(plan, pool_root=pool_root, context=context,
                                           observations=done["observations"])
                data = canonical_bytes(manifest)
                errors = manifest_errors(data, plan, pool_root=pool_root, context=context)
                if errors:
                    raise RendezvousError("the derived manifest does not verify, so it is not published: "
                                          + "; ".join(errors))
                done["manifest"] = manifest
                done["data"] = data
            _publish_once(root, done["data"])
            runtime.cancel.unsubscribe(wait.wake)

        try:
            interrupts.hold(finish)
        finally:
            runtime.cancel.unsubscribe(wait.wake)
    finally:
        lock.__exit__(None, None, None)
    if interrupts.caught:
        raise interrupts.caught[0]
    return freeze(done["manifest"])


# ---- verification: a published manifest is a cache, never an authority ----------------------------

def _checked_expansion(pool_root: Path, expected_spec: Any, context: ps.PoolContext) -> tuple:
    """(errors, plan): C01's ONE check of the pool root, with exactly one tolerance."""
    check = ps.check_expansion(pool_root, expected_spec=expected_spec, context=context)
    return [finding.message for finding in check.findings
            if finding.code not in ps.INSTANCE_ROOT_DAMAGE_CODES], check.plan


def expansion_errors(pool_root: Path, *, expected_spec: Any, context: ps.PoolContext) -> list:
    """C01's verifier (``check_expansion``), except that damage to ONE EXPECTED instance root --
    the codes in ``pool_specification.INSTANCE_ROOT_DAMAGE_CODES``: the root was deleted, or it was
    replaced by a link or a non-directory -- is left to the classification rule, which records
    that instance as ``missing`` or ``invalid``. Findings are selected by code, never by message
    text. Every other finding stands, exactly as it does for ``run_rendezvous``: an unexpected
    extra entry under ``instances/``, an ``instances`` that is not a real directory and two roots
    that are one directory are no instance's outcome, and refuse the pool."""
    return _checked_expansion(pool_root, expected_spec, context)[0]


def _check_manifest(raw: Any, plan: ps.ExpansionPlan, pool_root: Path, context: ps.PoolContext) -> tuple:
    """(errors, the disk facts they were derived from, one per instance)."""
    errors = _context_errors(plan, context)
    if errors:
        return errors, None
    try:
        found = ps.parse_document(raw)
    except ps.PoolSpecError:
        return ["the manifest is not bounded UTF-8 JSON with exactly one reading"], None
    schema_errors = validate_document(found, MANIFEST_SCHEMA)
    if schema_errors:
        return [f"the manifest fails its closed schema ({len(schema_errors)} errors)"], None
    if found["wait_all"] is not True:
        return ["wait_all must be the JSON value true"], None
    if [record["instance_id"] for record in found["instances"]] != [item.instance_id for item in plan.instances]:
        return ["the manifest's instances are not the expansion's instances, each once and in order: a "
                "duplicate, unknown, reordered or absent instance is refused"], None
    errors = []
    observations = []
    facts = [_disk_facts(instance, pool_root, context) for instance in plan.instances]
    for instance, record in zip(plan.instances, found["instances"]):
        for observation in OBSERVATIONS:
            if _entry(instance, facts[instance.index], observation) == record:
                observations.append(observation)
                break
        else:
            errors.append(f"instances[{instance.index}] is not what the expansion, the attempt on disk and "
                          "any coordinator observation derive")
    if errors:
        return errors, None
    states = [record["state"] for record in found["instances"]]
    if NOT_LAUNCHED_CANCELED in states and NOT_LAUNCHED_RENDEZVOUS_TIMEOUT in states:
        errors.append("one wait cannot end both by cancel and by timeout for instances it never launched")
    if bytes(raw) != canonical_bytes(_derive(plan, facts, observations)):
        if found["manifest_sha256"] != manifest_sha256(found):
            errors.append("manifest_sha256 does not match the manifest record")
        if bytes(raw) != canonical_bytes(found):
            errors.append("the manifest is not in the canonical byte form")
        errors.append("the manifest is not the byte sequence the expansion and the attempts on disk derive")
    return errors, facts


def manifest_errors(raw: Any, plan: ps.ExpansionPlan, *, pool_root: Path, context: ps.PoolContext) -> list:
    """THE acceptance rule for manifest bytes, used before publication and by the verifier.

    Per instance, the recorded entry -- ``state_reason`` included -- must be exactly what
    :func:`classify_instance` derives NOW for one of the observations a coordinator can make; then
    the whole document must be the bytes :func:`derive_manifest` derives for those observations. No
    hash in the manifest is an input. A reason the disk decides is thereby re-derived; the ones only
    the coordinator saw (which of the two ``rendezvous_timed_out`` reasons; for an empty root,
    ``adapter_left_no_evidence`` or ``worker_thread_not_started``) are bounded to that closed set."""
    return _check_manifest(raw, plan, pool_root, context)[0]


def _verify(pool_root: Path, expected_spec: Any, context: ps.PoolContext, rendezvous_parent: Path) -> tuple:
    """(errors, the bytes those errors are about, the plan, the disk facts)."""
    errors, plan = _checked_expansion(pool_root, expected_spec, context)
    if errors:
        return ["the pool expansion does not verify: " + "; ".join(errors)], None, None, None
    errors = _location_errors(context, rendezvous_parent)
    if errors:
        return errors, None, None, None
    root = rendezvous_root(plan, rendezvous_parent)
    if not ps.real_directory(root):
        return (["the rendezvous root is missing, is a link or is not a directory: no manifest was published"],
                None, None, None)
    if ps.directory_listing(root) != [MANIFEST_FILE]:
        return ["the rendezvous root does not hold exactly the terminal-instance manifest"], None, None, None
    raw = ps.read_regular_file(root, root / MANIFEST_FILE)
    if raw is None:
        return ["the manifest is missing, linked, hard-linked, oversized or unreadable"], None, None, None
    errors, facts = _check_manifest(raw, plan, pool_root, context)
    return errors, raw, plan, facts


def verify_manifest(pool_root: Path, *, expected_spec: Any, context: ps.PoolContext,
                    rendezvous_parent: Path) -> list:
    """Re-derives the published manifest from the expected specification, the expansion and the
    instance attempts on disk. Read-only. Every argument is required. Messages are fixed text."""
    return _verify(pool_root, expected_spec, context, rendezvous_parent)[0]


@dataclass(frozen=True)
class VerifiedInstance:
    """One instance as a consumer needs it: C01's planned instance (ids, request, paths), its
    manifest ``record``, and -- exactly for the ``RESULT_STATES`` -- the adapter ``result`` that the
    adapter's own verifier returned during THIS verification and whose canonical bytes the record's
    ``result_file`` pins. ``result`` is ``None`` for every other state. Deeply immutable."""
    instance: ps.PlannedInstance
    record: Mapping[str, Any]
    result: Mapping[str, Any] | None

    @property
    def state(self) -> str:
        return self.record["state"]


@dataclass(frozen=True)
class VerifiedManifest:
    """What :func:`load_verified_manifest` hands a consumer: the manifest (the very bytes that were
    verified), the plan they were verified against, and one :class:`VerifiedInstance` per expected
    instance, in the expansion's order. Deeply immutable; a cache of one verification, never an
    authority -- a consumer that needs the facts later verifies again."""
    manifest: Mapping[str, Any]
    plan: ps.ExpansionPlan
    instances: tuple

    @property
    def outcome(self) -> str:
        return self.manifest["outcome"]

    def in_state(self, state: str) -> tuple:
        if state not in STATES:
            raise RendezvousError("unknown instance state")
        return tuple(item for item in self.instances if item.state == state)


def load_verified_manifest(pool_root: Path, *, expected_spec: Any, context: ps.PoolContext,
                           rendezvous_parent: Path) -> VerifiedManifest:
    """The rendezvous T10 and C03 may rely on: verified against disk, deeply immutable, with the
    adapter results the verification itself obtained -- a consumer does not call an adapter
    verifier again, and does not need ``pool_specification.load_verified_expansion`` (which refuses
    a pool whose manifest honestly records a ``missing`` instance)."""
    errors, raw, plan, facts = _verify(pool_root, expected_spec, context, rendezvous_parent)
    if errors:
        raise RendezvousError("terminal-instance manifest rejected: " + "; ".join(errors))
    manifest = freeze(ps.parse_document(raw))       # the very bytes that were verified
    instances = tuple(
        VerifiedInstance(instance=instance, record=record,
                         result=facts[instance.index][1] if record["state"] in RESULT_STATES else None)
        for instance, record in zip(plan.instances, manifest["instances"]))
    return VerifiedManifest(manifest=manifest, plan=plan, instances=instances)
