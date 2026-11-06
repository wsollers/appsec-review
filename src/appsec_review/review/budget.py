"""Persistent launch admission, usage receipts, and versioned execution timing.

``reserve_call`` atomically admits one turn and the requested input/output maxima, counting
known spend, live reservations, and liabilities for missing reports. Admission is nonblocking:
reservation pressure can disappear after settlement; actual exhaustion remains sticky.
This is a soft *launch* bound, never a hard billed-cost guarantee. Provider overruns are retained,
cache tokens are reported separately (not subtracted), and replay never adds new billed tokens.
The original token snapshot fields are known partial sums; ``actual_*`` totals are None when
incomplete. Missing reports retain the corresponding reservation as an admission liability.

The legacy ``charge`` interface remains available but cannot provide atomic call admission.
V1 documents keep their schema, counters and wall-clock timing; their historical token totals
cannot be certified complete (``historical_usage_quality="legacy_unverified"``). New documents
use accounting v2. Default timing is still
``wall_clock_v1`` for existing callers. New runs explicitly opt into ``active_v2``: register an
immutable run/attempt owner with ``resume_execution`` and close it with ``pause_execution``.
Time is the union of active owners, not their sum. Reopening never resets spend or timing.
An owner cannot restart after cessation; a resumed runtime attempt needs a new immutable ID.

``cessation_evidence`` is a trusted caller's reference to existing run/attempt evidence proving
that the named owner and its dispatches stopped. This module does not infer runtime lifecycle,
verify worker liveness, reclaim by age, or backdate pauses. ``reconcile_owner`` closes abandoned
owners, retaining unknown dispatch liability unless the caller positively proves no dispatch.
Settlements and owner closures are append-only receipts within the atomic budget document.

``for_run`` imports the old runtime layout, ``attempts/attempt_NNNN/budget/budget.json``,
once under the destination and source locks. Only original v1 ledgers with matching terminal
attempt claim/status evidence are unambiguous imports. Distinct attempts' counters are summed,
the earliest wall-clock start is retained, and exact source/claim/status hashes are pinned.
Source changes, newly appearing ledgers, missing evidence, nonterminal attempts, different
limits, or preexisting unlinked destination spend fail explicitly rather than resetting or
guessing. Import never modifies the attempt ledgers or silently opts history into active time.
``for_run(..., new_timing_mode="active_v2")`` opts only genuinely new runs into active timing,
preserving existing/imported timing. In contrast, ``timing_mode`` is an exact-mode assertion.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from contextlib import ExitStack
from dataclasses import asdict, dataclass, field
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import threading
import time
from typing import Any, Literal, Mapping
from uuid import uuid4

from appsec_review.config.inference_review import BudgetSettings
from appsec_review.inference.errors import ExecutionContractError
from appsec_review.inference.usage import Usage, token_count
from appsec_review.review.models import Lane
from appsec_review.storage import atomic_json, bounded_file_lock


BUDGET_SCHEMA_V1 = "appsec-review/inference-review-budget/1"
BUDGET_SCHEMA = "appsec-review/inference-review-budget/2"
TimingMode = Literal["wall_clock_v1", "active_v2"]
BUDGET_DIRECTORY = Path("data") / "jobs" / "job_inference_security_review" / "budget"
USAGE_COUNTERS = ("model_turns", "input_tokens", "output_tokens", "retrieval_queries")
# Usage counter -> the job ceiling that bounds it, in the order exhaustion is reported.
_CEILINGS = (("model_turns", "max_model_turns"), ("input_tokens", "max_input_tokens"),
             ("output_tokens", "max_output_tokens"), ("retrieval_queries", "max_retrieval_queries"))
_TOKENS = ("input_tokens", "output_tokens", "cache_tokens")
_KNOWN = (*USAGE_COUNTERS, "cache_tokens")
_EXHAUSTION = {ceiling for _, ceiling in _CEILINGS} | {"budget_team_packages", "timeout_seconds"}
_LEGACY_FIELDS = {"schema", "limits", "started_at", "team_packages", "exhausted", *USAGE_COUNTERS}
_LEGACY_PATH = re.compile(
    r"data/jobs/job_inference_security_review/attempts/attempt_[0-9]{4}/budget/budget\.json")


def _identity(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 1024:
        raise ExecutionContractError(f"{name} must be a nonempty bounded evidence identity")
    return value


def _number(value: object) -> bool:
    try:
        return type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def _counts(value: object, keys: Iterable[str]) -> bool:
    return (isinstance(value, dict) and set(value) == set(keys)
            and all(type(v) is int and v >= 0 for v in value.values()))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExecutionContractError("duplicate job budget field")
        result[key] = value
    return result


def _instant(value: object) -> datetime:
    if not isinstance(value, str):
        raise ExecutionContractError("invalid attempt evidence timestamp")
    try:
        instant = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ExecutionContractError("invalid attempt evidence timestamp") from exc
    if instant.tzinfo is None:
        raise ExecutionContractError("attempt evidence timestamp needs a timezone")
    return instant


@dataclass(frozen=True, slots=True)
class BudgetSnapshot:
    team_packages: Mapping[str, int]     # per lane value
    model_turns: int
    input_tokens: int
    output_tokens: int
    retrieval_queries: int
    started_at: float
    exhausted: str | None                # the first ceiling reached, or None
    accounting_version: int = 2
    timing_mode: str = "wall_clock_v1"
    elapsed_seconds: float = 0.0
    active_execution_seconds: float = 0.0
    active_owners: tuple[str, ...] = ()
    cache_tokens: int = 0
    actual_input_tokens: int | None = None
    actual_output_tokens: int | None = None
    actual_cache_tokens: int | None = None
    unknown_usage: Mapping[str, int] = field(default_factory=dict)
    historical_usage_complete: bool = True
    historical_usage_quality: str = "versioned"
    reserved_model_turns: int = 0
    reserved_input_tokens: int = 0
    reserved_output_tokens: int = 0
    liability_input_tokens: int = 0
    liability_output_tokens: int = 0
    replayed_model_turns: int = 0
    replayed_input_tokens: int = 0
    replayed_output_tokens: int = 0
    replayed_cache_tokens: int = 0
    replayed_unknown_usage: Mapping[str, int] = field(default_factory=dict)
    live_reservations: int = 0
    imported_ledgers: Mapping[str, str] = field(default_factory=dict)


class JobBudget:
    """One file lock serializes every check/reserve/settle across instances and processes.

    Active timing uses the supplied shared, durable wall clock only between explicit owner
    transitions. Clock regression fails explicitly rather than erasing elapsed execution.
    ``timing_mode=None`` adopts the persisted mode, or wall-clock for a newly created budget;
    passing a different mode for an existing budget is an error, not a timing migration.
    """

    def __init__(self, root: Path, limits: BudgetSettings, *, lock_timeout_seconds: int = 60,
                 clock: Callable[[], float] = time.time,
                 timing_mode: TimingMode | None = None, _run_root: Path | None = None,
                 _new_timing_mode: TimingMode = "wall_clock_v1") -> None:
        self.root = Path(root)
        self.limits = limits
        self.state_path = self.root / "budget.json"
        self.lock_path = self.root / "budget.lock"
        self.lock_timeout_seconds = lock_timeout_seconds
        self.clock = clock
        if (timing_mode not in (None, "wall_clock_v1", "active_v2")
                or _new_timing_mode not in ("wall_clock_v1", "active_v2")):
            raise ExecutionContractError("unsupported budget timing mode")
        self.timing_mode = timing_mode
        self._new_timing_mode = _new_timing_mode
        self._run_root = Path(_run_root).resolve() if _run_root is not None else None
        self._thread_lock = threading.Lock()
        self._transact(lambda state, now: None)

    @classmethod
    def for_run(cls, run_root: Path, limits: BudgetSettings, *,
                new_timing_mode: TimingMode = "wall_clock_v1", **kwargs: Any) -> "JobBudget":
        """Open a cumulative run ledger, including identity-pinned original attempt budgets.

        Keywords are the constructor's lock timeout, clock and optional timing_mode. Existing
        wall-clock history cannot opt into active_v2; an omitted mode adopts the persisted mode.
        new_timing_mode applies only with no existing run/attempt ledger, so callers can enable
        active timing for new runs without probing paths or reinterpreting resumed history.
        Repeated/concurrent opens verify imports but never sum a source a second time.
        """
        root = Path(run_root).resolve()
        return cls(root / BUDGET_DIRECTORY, limits, _run_root=root, _new_timing_mode=new_timing_mode, **kwargs)

    def _initialize_accounting(self, state: dict[str, Any], *, legacy: bool) -> None:
        state.update(
            accounting_version=2,
            direct_usage={**{name: state[name] for name in USAGE_COUNTERS}, "cache_tokens": 0},
            direct_unknown={name: 0 for name in _TOKENS},
            historical_usage_complete=not legacy,
            reservations={}, settlements={}, ceased_owners={}, legacy_imports={},
            timing={"mode": "wall_clock_v1" if legacy else self.timing_mode or self._new_timing_mode,
                    "active_seconds": 0.0, "active_since": None, "owners": {},
                    "last_observed_at": state["started_at"]},
        )

    def _legacy_ledger(self, value: Any) -> None:
        self._validate_base(value)
        if value["schema"] != BUDGET_SCHEMA_V1 or set(value) != _LEGACY_FIELDS:
            raise ExecutionContractError("only original v1 attempt ledgers can be imported unambiguously")

    def _import_attempts(self, state: dict[str, Any], now: float, *, fresh: bool, locks: ExitStack) -> None:
        if self._run_root is None:
            return
        attempts = self._run_root / BUDGET_DIRECTORY.parent / "attempts"
        if attempts.resolve() != attempts:
            raise ExecutionContractError("legacy attempt directory is not run-owned")
        if any(not directory.is_dir() or not (directory / "budget.json").is_file()
               for directory in attempts.glob("*/budget")):
            raise ExecutionContractError("legacy budget directory changed: missing its ledger")
        sources = sorted(attempts.glob("*/budget/budget.json"))
        expected = state.get("legacy_imports")
        if not isinstance(expected, dict):
            raise ExecutionContractError("missing legacy import identity registry")
        paths = {source.relative_to(self._run_root).as_posix(): source for source in sources}
        if not fresh and set(paths) != set(expected):
            raise ExecutionContractError("legacy attempt ledger set changed; explicit reconciliation required")
        if not sources:
            return
        if fresh and self.timing_mode is None:
            state["timing"]["mode"] = "wall_clock_v1"
        if state["timing"]["mode"] != "wall_clock_v1":
            raise ExecutionContractError("legacy attempt wall-clock history cannot be reinterpreted")
        imports: dict[str, Any] = {}
        inodes: set[tuple[int, int]] = set()
        if sources:
            for relative, source in paths.items():
                if not _LEGACY_PATH.fullmatch(relative) or source.resolve() != source or not source.is_file():
                    raise ExecutionContractError("invalid run-owned legacy budget path")
                stat = source.stat()
                inode = (stat.st_dev, stat.st_ino)
                if inode in inodes:
                    raise ExecutionContractError("aliased legacy ledgers cannot be counted as separate attempts")
                inodes.add(inode)
                if (source.parent / "budget.lock").is_symlink():
                    raise ExecutionContractError("legacy budget lock must be run-owned")
                locks.enter_context(bounded_file_lock(source.parent / "budget.lock", self.lock_timeout_seconds))
            for relative, source in paths.items():
                attempt = source.parent.parent
                documents: dict[str, Any] = {}
                hashes: dict[str, str] = {}
                for label, path in (("ledger", source), ("claim", attempt / "claim.json"),
                                    ("status", attempt / "status.json")):
                    if path.resolve() != path or not path.is_file():
                        raise ExecutionContractError("legacy budget requires run-owned claim/status evidence")
                    try:
                        content = path.read_bytes()
                        documents[label] = json.loads(content, object_pairs_hook=_unique_object)
                    except (ValueError, UnicodeError) as exc:
                        raise ExecutionContractError("malformed legacy attempt evidence") from exc
                    hashes[f"{label}_sha256"] = hashlib.sha256(content).hexdigest()
                ledger, claim, status = (documents[key] for key in ("ledger", "claim", "status"))
                self._legacy_ledger(ledger)
                if ledger["started_at"] > now:
                    raise ExecutionContractError("legacy budget starts after the current clock")
                identity = {"run_id": self._run_root.name, "job_id": BUDGET_DIRECTORY.parent.name,
                            "attempt_id": attempt.name}
                if (not isinstance(claim, dict) or not isinstance(status, dict)
                        or any(claim.get(key) != value or status.get(key) != value for key, value in identity.items())
                        or claim.get("schema") != "appsec-review/attempt-claim/1"
                        or claim.get("attempt_path") != attempt.relative_to(self._run_root).as_posix()
                        or status.get("status") not in ("SUCCEEDED", "COMPLETED_WITH_GAPS", "FAILED", "DEGRADED")
                        or status.get("started_at") != claim.get("started_at")):
                    raise ExecutionContractError("legacy budget has no matching terminal attempt evidence")
                if _instant(status.get("completed_at")) < _instant(claim.get("started_at")):
                    raise ExecutionContractError("legacy attempt evidence timestamps conflict")
                imported = {**hashes, "ledger": ledger}
                if not fresh and expected[relative] != imported:
                    raise ExecutionContractError("immutable legacy import identity changed")
                imports[relative] = imported
            if fresh:
                state["legacy_imports"] = imports
                state["started_at"] = min(item["ledger"]["started_at"] for item in imports.values())
                state["historical_usage_complete"] = False
                for lane in state["team_packages"]:
                    state["team_packages"][lane] = sum(item["ledger"]["team_packages"][lane]
                                                       for item in imports.values())
                state["exhausted"] = next((item["ledger"]["exhausted"] for item in imports.values()
                                           if item["ledger"]["exhausted"] is not None), None)
                known, _, _, _, _, _ = self._totals(state)
                state.update({name: known[name] for name in USAGE_COUNTERS})

    def _validate_base(self, state: Any) -> None:
        if not isinstance(state, dict) or state.get("schema") not in (BUDGET_SCHEMA, BUDGET_SCHEMA_V1):
            raise ExecutionContractError("unsupported job budget schema")
        if json.dumps(state.get("limits"), sort_keys=True) != json.dumps(asdict(self.limits), sort_keys=True):
            raise ValueError("job budget was opened with different limits")
        if (not _counts({k: state.get(k) for k in USAGE_COUNTERS}, USAGE_COUNTERS)
                or not _counts(state.get("team_packages"), (lane.value for lane in Lane))
                or not _number(state.get("started_at"))
                or not (state.get("exhausted") is None or isinstance(state.get("exhausted"), str)
                        and state["exhausted"] in _EXHAUSTION)
                or "exhausted" not in state):
            raise ExecutionContractError("malformed job budget counters")

    @staticmethod
    def _validate_reservation(value: Any) -> None:
        if (not isinstance(value, dict)
                or set(value) != {"owner_id", "input_tokens", "output_tokens", "replay"}
                or not _counts({k: value.get(k) for k in _TOKENS[:2]}, _TOKENS[:2])
                or type(value.get("replay")) is not bool):
            raise ExecutionContractError("malformed job budget reservation")
        _identity(value["owner_id"], "owner_id")

    def _validate(self, state: dict[str, Any]) -> None:
        self._validate_base(state)
        if (type(state.get("accounting_version")) is not int or state["accounting_version"] != 2
                or not _counts(state.get("direct_usage"), _KNOWN)
                or not _counts(state.get("direct_unknown"), _TOKENS)
                or type(state.get("historical_usage_complete")) is not bool
                or any(not isinstance(state.get(name), dict)
                       for name in ("reservations", "settlements", "ceased_owners", "timing", "legacy_imports"))):
            raise ExecutionContractError("malformed job budget accounting")
        for path, imported in state["legacy_imports"].items():
            if (not _LEGACY_PATH.fullmatch(path) or not isinstance(imported, dict)
                    or set(imported) != {"ledger_sha256", "claim_sha256", "status_sha256", "ledger"}
                    or any(not isinstance(imported[key], str) or not re.fullmatch("[0-9a-f]{64}", imported[key])
                           for key in ("ledger_sha256", "claim_sha256", "status_sha256"))):
                raise ExecutionContractError("malformed legacy budget import identity")
            self._legacy_ledger(imported["ledger"])
        if state["legacy_imports"] and (
                state["historical_usage_complete"] or state["timing"].get("mode") != "wall_clock_v1"
                or state["started_at"] != min(v["ledger"]["started_at"] for v in state["legacy_imports"].values())):
            raise ExecutionContractError("legacy imported timing/history cannot be reinterpreted")
        reservations, settlements = state["reservations"], state["settlements"]
        if reservations.keys() & settlements.keys():
            raise ExecutionContractError("reservation is both live and settled")
        for owner, closure in state["ceased_owners"].items():
            _identity(owner, "owner_id")
            if (not isinstance(closure, dict) or set(closure) != {"evidence", "dispatched"}
                    or closure["dispatched"] is not None and type(closure["dispatched"]) is not bool):
                raise ExecutionContractError("malformed owner cessation")
            _identity(closure["evidence"], "cessation_evidence")
        for identifier, reservation in reservations.items():
            _identity(identifier, "reservation_id")
            self._validate_reservation(reservation)
            if reservation["owner_id"] in state["ceased_owners"]:
                raise ExecutionContractError("ceased owner still has live reservations")
        for identifier, receipt in settlements.items():
            _identity(identifier, "reservation_id")
            if (not isinstance(receipt, dict)
                    or set(receipt) != {"reservation", "usage", "dispatched", "cessation_evidence"}
                    or type(receipt["dispatched"]) is not bool):
                raise ExecutionContractError("malformed job budget settlement")
            self._validate_reservation(receipt["reservation"])
            usage = receipt["usage"]
            if (not isinstance(usage, dict) or set(usage) != {*_TOKENS, "source", "unavailable_reason"}
                    or usage["source"] not in ("provider", "replay")
                    or any(v is not None and token_count(v) is None
                           for v in (usage[name] for name in _TOKENS))
                    or usage["unavailable_reason"] is not None
                    and not isinstance(usage["unavailable_reason"], str)):
                raise ExecutionContractError("malformed settled usage")
            if (receipt["reservation"]["replay"] and usage["source"] != "replay"
                    or not receipt["dispatched"] and any(usage[name] is not None for name in _TOKENS)):
                raise ExecutionContractError("inconsistent settlement provenance")
            if receipt["cessation_evidence"] is not None:
                _identity(receipt["cessation_evidence"], "cessation_evidence")
                closure = state["ceased_owners"].get(receipt["reservation"]["owner_id"])
                if closure != {"evidence": receipt["cessation_evidence"],
                               "dispatched": receipt["dispatched"]}:
                    raise ExecutionContractError("settlement has no matching cessation evidence")
        timing = state["timing"]
        if (set(timing) != {"mode", "active_seconds", "active_since", "owners", "last_observed_at"}
                or timing["mode"] not in ("wall_clock_v1", "active_v2")
                or not _number(timing["active_seconds"]) or not _number(timing["last_observed_at"])
                or not isinstance(timing["owners"], dict)
                or timing["active_since"] is not None and not _number(timing["active_since"])):
            raise ExecutionContractError("malformed budget timing")
        if (self.timing_mode is not None and timing["mode"] != self.timing_mode
                or state["schema"] == BUDGET_SCHEMA_V1
                and (timing["mode"] != "wall_clock_v1" or state["historical_usage_complete"])):
            raise ExecutionContractError("existing budget timing/history cannot be reinterpreted")
        for owner, interval in timing["owners"].items():
            _identity(owner, "owner_id")
            if (not isinstance(interval, dict) or set(interval) != {"started_at", "stopped_at"}
                    or not _number(interval["started_at"])
                    or interval["stopped_at"] is not None and
                    (not _number(interval["stopped_at"]) or interval["stopped_at"] < interval["started_at"])
                    or (interval["stopped_at"] is not None) != (owner in state["ceased_owners"])
                    or interval["started_at"] < state["started_at"]
                    or max(interval["started_at"], interval["stopped_at"] or 0) > timing["last_observed_at"]):
                raise ExecutionContractError("malformed execution owner interval")
        active = [v["started_at"] for v in timing["owners"].values() if v["stopped_at"] is None]
        if (bool(active) != (timing["active_since"] is not None)
                or active and not (state["started_at"] <= timing["active_since"] <= min(active))
                or timing["last_observed_at"] < state["started_at"]
                or timing["mode"] == "wall_clock_v1"
                and (timing["owners"] or timing["active_seconds"] != 0 or active)):
            raise ExecutionContractError("inconsistent active execution timing")
        intervals: list[list[float]] = []
        for interval in sorted(timing["owners"].values(), key=lambda v: v["started_at"]):
            start = interval["started_at"]
            stop = interval["stopped_at"] if interval["stopped_at"] is not None else timing["last_observed_at"]
            if intervals and start <= intervals[-1][1]:
                intervals[-1][1] = max(intervals[-1][1], stop)
            else:
                intervals.append([start, stop])
        union = sum(stop - start for start, stop in intervals)
        if not math.isclose(union, self._active_seconds(state, timing["last_observed_at"]), abs_tol=1e-6):
            raise ExecutionContractError("active execution total disagrees with owner receipts")
        if timing["mode"] == "active_v2" and any(
                r["owner_id"] not in timing["owners"] for r in reservations.values()):
            raise ExecutionContractError("reservation has no active execution owner")
        known, _, _, _, _, _ = self._totals(state)
        if any(state[name] != known[name] for name in USAGE_COUNTERS):
            raise ExecutionContractError("budget counters disagree with settlement receipts")

    def _transact(self, mutate: Callable[[dict[str, Any], float], Any]) -> tuple[Any, dict[str, Any], float]:
        with self._thread_lock, bounded_file_lock(self.lock_path, self.lock_timeout_seconds), ExitStack() as locks:
            now = self.clock()
            if not _number(now):
                raise ExecutionContractError("invalid budget clock")
            if self.state_path.exists():
                try:
                    state = json.loads(self.state_path.read_text(encoding="utf-8"),
                                       object_pairs_hook=_unique_object)
                except (ValueError, UnicodeError) as exc:
                    raise ExecutionContractError("invalid job budget JSON") from exc
                self._validate_base(state)
                before = json.dumps(state, sort_keys=True)
                if state["schema"] == BUDGET_SCHEMA_V1 and "accounting_version" not in state:
                    if set(state) != _LEGACY_FIELDS:
                        raise ExecutionContractError("malformed legacy job budget")
                    self._initialize_accounting(state, legacy=True)
            else:
                state = {"schema": BUDGET_SCHEMA, "limits": asdict(self.limits), "started_at": now,
                         "team_packages": {lane.value: 0 for lane in Lane},
                         **{name: 0 for name in USAGE_COUNTERS}, "exhausted": None}
                self._initialize_accounting(state, legacy=False)
                before = None
            self._validate(state)
            self._import_attempts(state, now, fresh=before is None, locks=locks)
            self._validate(state)
            if now < state["timing"]["last_observed_at"]:
                raise ExecutionContractError("budget clock regressed")
            state["timing"]["last_observed_at"] = now
            self._update_exhaustion(state, now)
            result = mutate(state, now)
            known, _, _, _, _, _ = self._totals(state)
            state.update({name: known[name] for name in USAGE_COUNTERS})
            self._update_exhaustion(state, now)
            self._validate(state)
            if json.dumps(state, sort_keys=True) != before:
                atomic_json(self.state_path, state)
            return result, state, now

    def _totals(self, state: dict[str, Any]) -> tuple[dict[str, int], ...]:
        known = dict(state["direct_usage"])
        for imported in state["legacy_imports"].values():
            for name in USAGE_COUNTERS:
                known[name] += imported["ledger"][name]
        unknown = dict(state["direct_unknown"])
        reserved = {"model_turns": len(state["reservations"]), "input_tokens": 0, "output_tokens": 0}
        liability = {name: getattr(self.limits, f"max_{name}") if state["direct_unknown"][name] else 0
                     for name in _TOKENS[:2]}
        replayed = {"model_turns": 0, **{name: 0 for name in _TOKENS}}
        replay_unknown = {name: 0 for name in _TOKENS}
        for reservation in state["reservations"].values():
            if not reservation["replay"]:
                for name in _TOKENS[:2]:
                    reserved[name] += reservation[name]
        for receipt in state["settlements"].values():
            if not receipt["dispatched"]:
                continue
            known["model_turns"] += 1
            usage = receipt["usage"]
            replay = usage["source"] == "replay"
            if replay:
                replayed["model_turns"] += 1
            for name in _TOKENS:
                if usage[name] is None:
                    (replay_unknown if replay else unknown)[name] += 1
                    if not replay and name in liability:
                        liability[name] += receipt["reservation"][name]
                else:
                    (replayed if replay else known)[name] += usage[name]
        return known, unknown, reserved, liability, replayed, replay_unknown

    @staticmethod
    def _active_seconds(state: dict[str, Any], now: float) -> float:
        timing = state["timing"]
        return timing["active_seconds"] + (
            now - timing["active_since"] if timing["active_since"] is not None else 0)

    def _elapsed(self, state: dict[str, Any], now: float) -> float:
        return (self._active_seconds(state, now) if state["timing"]["mode"] == "active_v2"
                else now - state["started_at"])

    def _update_exhaustion(self, state: dict[str, Any], now: float) -> None:
        if state["exhausted"] is not None:
            return                      # sticky: once stopped, launches never resume
        for counter, ceiling in _CEILINGS:
            if state[counter] >= getattr(self.limits, ceiling):
                state["exhausted"] = ceiling
                return
        if (self.limits.budget_team_packages != "all" and
                sum(state["team_packages"].values()) >= self.limits.budget_team_packages):
            state["exhausted"] = "budget_team_packages"
        elif self._elapsed(state, now) >= self.limits.timeout_seconds:
            state["exhausted"] = "timeout_seconds"

    def _usage_exhaustion(self, state: dict[str, Any], now: float) -> str | None:
        known, _, reserved, liability, _, _ = self._totals(state)
        for counter, ceiling in _CEILINGS:
            if known[counter] + reserved.get(counter, 0) + liability.get(counter, 0) >= getattr(self.limits, ceiling):
                return ceiling
        if self._elapsed(state, now) >= self.limits.timeout_seconds:
            return "timeout_seconds"
        return None

    def _exhaustion(self, state: dict[str, Any], now: float) -> str | None:
        return state["exhausted"] or self._usage_exhaustion(state, now)

    def reserve(self, lane: Lane | str) -> bool:
        """Count one team-package launch for ``lane``; False (launch nothing) when exhausted."""
        selected = Lane(lane)

        def mutate(state: dict[str, Any], now: float) -> bool:
            if self._exhaustion(state, now) is not None:
                return False
            state["team_packages"][selected.value] += 1
            return True

        return self._transact(mutate)[0]

    def can_launch(self) -> bool:
        """Whether a new team may start; checked before every team launch."""
        return self.snapshot().exhausted is None

    def usage_exhausted(self) -> str | None:
        """The first usage/admission or timing ceiling, ignoring ``budget_team_packages``.

        A team already launched keeps launching its own cells after the team-package ceiling is
        reached; any turn, token, query, or wall-clock ceiling stops new cell launches.
        """
        _, state, now = self._transact(lambda state, now: None)
        return self._usage_exhaustion(state, now)

    def cell_launch_allowed(self) -> bool:
        """Whether a new cell inside a launched team may start; checked before every cell launch."""
        return self.usage_exhausted() is None

    def charge(self, *, model_turns: int = 0, input_tokens: int | None = None, output_tokens: int | None = None,
               retrieval_queries: int = 0) -> str | None:
        """Legacy direct reporting; not a replacement for reserving/settling model calls.

        Omitting usage for positive model_turns records unknown totals. Without a reservation
        there is no trustworthy missing-usage estimate, so admission fails closed at that token
        ceiling. Explicit integer zero is known zero. Charges always retain actual overruns.
        """
        usage = {"model_turns": model_turns, "input_tokens": input_tokens, "output_tokens": output_tokens,
                 "retrieval_queries": retrieval_queries}
        if (any(type(usage[name]) is not int or usage[name] < 0 for name in ("model_turns", "retrieval_queries"))
                or any(usage[name] is not None and token_count(usage[name]) is None for name in _TOKENS[:2])):
            raise ValueError("budget charges must be non-negative integers")

        def mutate(state: dict[str, Any], now: float) -> None:
            for name, value in usage.items():
                if value is not None:
                    state["direct_usage"][name] += value
            if model_turns:
                for name in _TOKENS:
                    if usage.get(name) is None:
                        state["direct_unknown"][name] += model_turns

        _, state, now = self._transact(mutate)
        return self._exhaustion(state, now)

    def reserve_call(self, *, owner_id: str, input_tokens: int, output_tokens: int,
                     replay: bool = False) -> str | None:
        """Reserve one turn and token maxima, or return None without consuming anything.

        Replays still consume the execution-turn allowance, but reserve no billable tokens.
        In active mode, owner_id must be an active immutable attempt ID. A live reservation
        is not spend. Call settle_call exactly once logically, including on BaseException.
        """
        _identity(owner_id, "owner_id")
        if token_count(input_tokens) is None or token_count(output_tokens) is None or type(replay) is not bool:
            raise ExecutionContractError("invalid call reservation")

        def mutate(state: dict[str, Any], now: float) -> str | None:
            if owner_id in state["ceased_owners"]:
                raise ExecutionContractError("ceased budget owner cannot dispatch")
            if state["timing"]["mode"] == "active_v2" and owner_id not in state["timing"]["owners"]:
                raise ExecutionContractError("call owner has no active execution")
            known, _, reserved, liability, _, _ = self._totals(state)
            if not replay and any(state["direct_unknown"][name] for name in _TOKENS[:2]):
                return None
            if self._elapsed(state, now) >= self.limits.timeout_seconds:
                return None
            requested = {"model_turns": 1, "input_tokens": 0 if replay else input_tokens,
                         "output_tokens": 0 if replay else output_tokens, "retrieval_queries": 0}
            for counter, ceiling in _CEILINGS:
                limit = getattr(self.limits, ceiling)
                if known[counter] >= limit or (
                        known[counter] + reserved.get(counter, 0) + liability.get(counter, 0)
                        + requested[counter] > limit):
                    return None
            identifier = uuid4().hex
            if identifier in state["reservations"] or identifier in state["settlements"]:
                raise ExecutionContractError("call reservation identity collision")
            state["reservations"][identifier] = {"owner_id": owner_id, "input_tokens": input_tokens,
                                                  "output_tokens": output_tokens, "replay": replay}
            return identifier

        return self._transact(mutate)[0]

    @staticmethod
    def _reported_usage(usage: Usage | None, *, replay: bool, dispatched: bool) -> dict[str, Any]:
        if usage is not None and not isinstance(usage, Usage):
            raise ExecutionContractError("settlement requires Usage or None")
        if not dispatched and usage is not None:
            raise ExecutionContractError("undispatched call cannot report provider usage")
        if usage is None:
            usage = Usage(source="replay" if replay else "provider",
                          unavailable_reason="no_provider_response" if dispatched else "not_dispatched")
        if usage.source not in ("provider", "replay") or replay and usage.source != "replay":
            raise ExecutionContractError("inconsistent settlement usage source")
        if usage.unavailable_reason is not None and not isinstance(usage.unavailable_reason, str):
            raise ExecutionContractError("invalid usage unavailable reason")
        normalized = {name: token_count(getattr(usage, name)) for name in _TOKENS}
        invalid = any(getattr(usage, name) is not None and normalized[name] is None for name in _TOKENS)
        reason = ("invalid_provider_usage" if invalid else usage.unavailable_reason
                  or ("provider_usage_missing" if any(normalized[name] is None for name in _TOKENS[:2]) else None))
        return {**normalized, "source": usage.source, "unavailable_reason": reason}

    def settle_call(self, reservation_id: str, *, usage: Usage | None = None,
                    dispatched: bool = True) -> str | None:
        """Release a reservation and append a receipt, preserving every known reported token.

        ``dispatched=False`` asserts the transport was never invoked; only then can a failed or
        cancelled call release all liability. After possible dispatch, missing dimensions retain
        their reserved maxima as liabilities, not actual usage. Identical retries are no-ops;
        conflicting retries/unknown IDs are contract errors, never duplicate charges.
        """
        _identity(reservation_id, "reservation_id")
        if type(dispatched) is not bool:
            raise ExecutionContractError("dispatched must be boolean")

        def mutate(state: dict[str, Any], now: float) -> None:
            existing = state["settlements"].get(reservation_id)
            reservation = existing["reservation"] if existing else state["reservations"].get(reservation_id)
            if reservation is None:
                raise ExecutionContractError("unknown call reservation")
            reported = self._reported_usage(usage, replay=reservation["replay"], dispatched=dispatched)
            if existing:
                if existing["usage"] != reported or existing["dispatched"] != dispatched:
                    raise ExecutionContractError("conflicting call settlement")
                return
            state["settlements"][reservation_id] = {
                "reservation": reservation, "usage": reported, "dispatched": dispatched,
                "cessation_evidence": None}
            del state["reservations"][reservation_id]

        _, state, now = self._transact(mutate)
        return self._exhaustion(state, now)

    def resume_execution(self, owner_id: str) -> None:
        """Start/join active-v2 union time using a new immutable run/attempt owner identity."""
        _identity(owner_id, "owner_id")

        def mutate(state: dict[str, Any], now: float) -> None:
            timing = state["timing"]
            if timing["mode"] != "active_v2":
                raise ExecutionContractError("wall-clock budgets cannot opt into active timing")
            if owner_id in state["ceased_owners"]:
                raise ExecutionContractError("ceased execution requires a new immutable owner_id")
            if owner_id in timing["owners"]:
                return
            if timing["active_since"] is None:
                timing["active_since"] = now
            timing["owners"][owner_id] = {"started_at": now, "stopped_at": None}

        self._transact(mutate)

    @staticmethod
    def _close_execution(state: dict[str, Any], owner_id: str, now: float) -> None:
        timing = state["timing"]
        interval = timing["owners"].get(owner_id)
        if interval is not None and interval["stopped_at"] is None:
            interval["stopped_at"] = now
            if not any(v["stopped_at"] is None for v in timing["owners"].values()):
                timing["active_seconds"] += now - timing["active_since"]
                timing["active_since"] = None

    def pause_execution(self, owner_id: str, *, cessation_evidence: str) -> None:
        """Close one stopped owner; callers must settle its dispatches before pausing.

        Evidence identifies a run-owned cessation receipt, not an age/liveness guess. Repeated
        closure with identical evidence is idempotent. Other owners keep the union clock running.
        """
        _identity(owner_id, "owner_id")
        _identity(cessation_evidence, "cessation_evidence")

        def mutate(state: dict[str, Any], now: float) -> None:
            if state["timing"]["mode"] != "active_v2":
                raise ExecutionContractError("wall-clock budgets cannot pause")
            if owner_id not in state["timing"]["owners"]:
                raise ExecutionContractError("unknown execution owner")
            if any(r["owner_id"] == owner_id for r in state["reservations"].values()):
                raise ExecutionContractError("settle or reconcile live reservations before pausing")
            existing = state["ceased_owners"].get(owner_id)
            if existing:
                if existing["evidence"] != cessation_evidence:
                    raise ExecutionContractError("conflicting owner cessation evidence")
                return
            state["ceased_owners"][owner_id] = {"evidence": cessation_evidence, "dispatched": None}
            self._close_execution(state, owner_id, now)

        self._transact(mutate)

    def reconcile_owner(self, owner_id: str, *, cessation_evidence: str,
                        dispatched: bool = True) -> tuple[str, ...]:
        """Close a positively stopped owner, atomically settling its abandoned reservations.

        Default: all remaining calls may have dispatched, so keep turn spend and unknown token
        liabilities. ``dispatched=False`` requires positive evidence that *none* dispatched.
        No timestamp can reclaim an owner. Active time is charged until this observation.
        Returns the same reconciled IDs on an identical retry; never rewrites earlier receipts.
        """
        _identity(owner_id, "owner_id")
        _identity(cessation_evidence, "cessation_evidence")
        if type(dispatched) is not bool:
            raise ExecutionContractError("dispatched must be boolean")

        def mutate(state: dict[str, Any], now: float) -> tuple[str, ...]:
            closure = {"evidence": cessation_evidence, "dispatched": dispatched}
            existing = state["ceased_owners"].get(owner_id)
            if existing:
                if existing != closure:
                    raise ExecutionContractError("conflicting owner reconciliation")
                return tuple(sorted(key for key, receipt in state["settlements"].items()
                                    if receipt["reservation"]["owner_id"] == owner_id
                                    and receipt["cessation_evidence"] == cessation_evidence))
            selected = sorted(key for key, r in state["reservations"].items() if r["owner_id"] == owner_id)
            if (not selected and owner_id not in state["timing"]["owners"]
                    and not any(r["reservation"]["owner_id"] == owner_id for r in state["settlements"].values())):
                raise ExecutionContractError("unknown budget owner")
            state["ceased_owners"][owner_id] = closure
            for identifier in selected:
                reservation = state["reservations"].pop(identifier)
                state["settlements"][identifier] = {
                    "reservation": reservation, "dispatched": dispatched,
                    "usage": self._reported_usage(None, replay=reservation["replay"], dispatched=dispatched),
                    "cessation_evidence": cessation_evidence}
            self._close_execution(state, owner_id, now)
            return tuple(selected)

        return self._transact(mutate)[0]

    def snapshot(self) -> BudgetSnapshot:
        _, state, now = self._transact(lambda state, now: None)
        known, unknown, reserved, liability, replayed, replay_unknown = self._totals(state)
        return BudgetSnapshot(team_packages=dict(state["team_packages"]),
                              **{name: state[name] for name in USAGE_COUNTERS},
                              started_at=state["started_at"], exhausted=self._exhaustion(state, now),
                              timing_mode=state["timing"]["mode"], elapsed_seconds=self._elapsed(state, now),
                              active_execution_seconds=self._active_seconds(state, now),
                              active_owners=tuple(sorted(k for k, v in state["timing"]["owners"].items()
                                                         if v["stopped_at"] is None)),
                              cache_tokens=known["cache_tokens"],
                              **{f"actual_{name}": known[name] if not unknown[name]
                                 and state["historical_usage_complete"]
                                 and not any(not r["replay"] for r in state["reservations"].values())
                                 else None for name in _TOKENS},
                              unknown_usage=unknown, historical_usage_complete=state["historical_usage_complete"],
                              historical_usage_quality=("versioned" if state["historical_usage_complete"]
                                                        else "legacy_unverified"),
                              **{f"reserved_{name}": value for name, value in reserved.items()},
                              **{f"liability_{name}": value for name, value in liability.items()},
                              **{f"replayed_{name}": value for name, value in replayed.items()},
                              replayed_unknown_usage=replay_unknown,
                              live_reservations=len(state["reservations"]),
                              imported_ledgers={path: value["ledger_sha256"]
                                                for path, value in state["legacy_imports"].items()})

    def team_packages(self) -> dict[Lane, int]:
        """Per-lane launched team-packages, the consumed counts for ``FairShareScheduler.next``."""
        counts = self.snapshot().team_packages
        return {lane: int(counts[lane.value]) for lane in Lane}

    def not_launched(self, queued: Iterable[str]) -> list[tuple[str, str]]:
        """``(subject_id, reason)`` for every still-queued item, in the given canonical order.

        Each becomes a ``not_launched`` cell with a ``budget_gap``; the caller mints the gap ids.
        """
        exhausted = self.snapshot().exhausted
        if exhausted is None:
            raise ValueError("job budget is not exhausted; queued work must still be launched")
        reason = f"not launched: job budget exhausted ({exhausted})"
        return [(str(subject_id), reason) for subject_id in queued]
