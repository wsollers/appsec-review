"""Review-team handler for one intake lane (design "Two-lane intake and review teams", R1, R2, R6).

A lane unit takes its packages in canonical order (rank, then ``package_id``) and launches one
review team per package under the run-wide :class:`ReviewTeamSemaphore`, the deterministic
fair-share allocation, and the attempt's :class:`JobBudget`. A team runs:

1. three red cells (lane A: ``red_team_analyst`` with the stack, preconditions and failure-mode
   lenses; lane B: the ``hunt-panel/1`` (strategy, persona) pairs as ``hypothesis_hunter``), each
   returning one admitted ``red-discovery-result/1`` (``review.red_discovery``);
2. package-local normalization of the red proposals (``review.claims``), their evidence references
   and observed taint hops, evidence requests, named gaps, lead accounting and chain seeds, then the
   lane B triage gate or the lane A cap;
3. for every admitted claim, ``blue_control`` and ``blue_reachability`` refuters and one blind
   ``independent_verifier`` whose request carries only the claim's identity fields;
4. for the claims ``roles.adjudication_judge.when`` selects, ``judges_per_claim`` ``adjudication_judge`` cells that see
   the package and the red and blue positions as sides A and B in a deterministic shuffled order
   (docs/architecture/review-judge-and-poc.md). A judge records a ``judge_verdict`` and relations with provenance
   ``adjudication_judge``; it sets no state, and R5 and R6 do not read it.

Every cell runs through ``review.cells.reuse_or_run``; every cited relation is re-resolved through
``review.evidence.resolve_relation``; every failure is a typed gap with exactly one terminal cell
record. Only :class:`IntegrityError` propagates. The lane's events are sealed into one ledger shard.
"""
from __future__ import annotations

from collections import defaultdict
from appsec_review.storage.shared import PublicationThreadPoolExecutor as ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, replace
import json
from pathlib import Path
import threading
import time
from typing import Any, Callable, Iterable, Mapping, Sequence

from appsec_review.config.inference_review import InferenceSecurityReviewSettings, ModelProfileSettings
from appsec_review.guidance import compose_bundle, hunt_panel, pin_bundle, render_prompt, route_persona, route_stack
from appsec_review.guidance.routing import unit_sources
from appsec_review.inference import ModelResult, ReviewModelRequest
from appsec_review.retrieval.index import INDEX_NAMES
from appsec_review.review.budget import JobBudget
from appsec_review.review.capability import EXPAND_TOOL, IN_PROCESS_TOOLS, CellCapability
from appsec_review.review.cells import CellBudgetExceeded, CellOutcome, CellSpec, cell_fingerprint, reuse_or_run
from appsec_review.review.claims import normalize_claim
from appsec_review.review.compact import Expander, expand_blue, expand_judge, expand_red, expand_verifier
from appsec_review.review.fact_summary import summarize_fact
from appsec_review.review.evidence import resolve_relation, satisfies
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.independence import ActorRecord, model_distinct, provider_distinct, verify_independence
from appsec_review.review.judge import (
    JUDGE_PERSONA, JUDGE_TASK, PROVENANCE, blue_side, present, red_affirms, red_side, selected,
    side_assignment,
)
from appsec_review.review.ledger import EvidenceRequestOutcome, LedgerWriter, gap_json
from appsec_review.review.models import (
    BlueTask, CellRecord, CellStatus, Claim, EvidenceRelation, Gap, GapClass, HuntStrategy, IntegrityError,
    JudgePredicateVerdict, JudgeVerdict, JudgeVerdictValue, Lane, Predicate, RelationKind, Role, make_gap,
)
from appsec_review.review.obligations import required_predicates_for
from appsec_review.review.package_view import PackageView, ViewLimits, build_view
from appsec_review.review import red_discovery
from appsec_review.review.red_discovery import RED_ROLES, Citation, RedInvocation
from appsec_review.review.teams import FairShareScheduler, QueuedPackage, ReviewTeamSemaphore, TeamUnavailable
from appsec_review.storage import atomic_json, file_sha256

from .schemas import SchemaSet

LANE_SCHEMA = "appsec-review/inference-review-lane/1"
VALIDATOR_VERSION = "inference-review-results/3"
CHAIN_SEEDS_SCHEMA = "appsec-review/red-chain-seeds/1"
POC_BASIS_SCHEMA = "appsec-review/red-poc-basis/1"
RESULT_SCHEMAS = {Role.RED_TEAM_ANALYST: red_discovery.SCHEMA_NAME, Role.HYPOTHESIS_HUNTER: red_discovery.SCHEMA_NAME,
                  Role.BLUE_TEAM_REFUTER: "blue-result", Role.INDEPENDENT_VERIFIER: "verifier-result",
                  Role.ADJUDICATION_JUDGE: "judge-result"}
# The schema a model is told to answer in is the compact one (review-protocol/2); the application expands it
# into RESULT_SCHEMAS[role] (``review.compact``) before any validator runs.
OUTPUT_SCHEMAS = {red_discovery.SCHEMA_NAME: "appsec-review/red-compact/1",
                  "blue-result": "appsec-review/blue-compact/1",
                  "verifier-result": "appsec-review/verifier-compact/1",
                  "judge-result": "appsec-review/judge-result-compact/1"}
LEAD_LENSES = ("lead_red_stack", "lead_red_preconditions", "lead_red_failure_modes")
VERIFIER_TASK = "blind_verifier"
# Relation kinds each role may author (the registry ``outputs`` of each role; red evidence travels
# with its proposed claim). Anything else is a schema error and never reaches the ledger.
ROLE_RELATION_KINDS = {
    Role.RED_TEAM_ANALYST: frozenset({RelationKind.SUPPORTS, RelationKind.QUALIFIES}),
    Role.HYPOTHESIS_HUNTER: frozenset({RelationKind.SUPPORTS, RelationKind.QUALIFIES}),
    Role.BLUE_TEAM_REFUTER: frozenset({RelationKind.CONTRADICTS, RelationKind.QUALIFIES}),
    Role.INDEPENDENT_VERIFIER: frozenset({RelationKind.SUPPORTS, RelationKind.CONTRADICTS, RelationKind.QUALIFIES}),
    # A judge's relations are derived from its verdict (supports / contradicts, qualifies when not direct); they carry
    # provenance and are never counted by R5.
    Role.ADJUDICATION_JUDGE: frozenset({RelationKind.SUPPORTS, RelationKind.CONTRADICTS, RelationKind.QUALIFIES}),
}
GRAPH_FACT_KINDS = frozenset({"sink_site", "range_fact", "guard_fact", "call_site", "entry_point", "dataflow_path",
                              "flow_summary", "symbol"})
MIN_MARKER_CHARACTERS = 16
MAX_RESULT_BYTES = 64 * 1024


# ------------------------------------------------------------------------------------------------
# Context and package records


@dataclass(frozen=True, slots=True)
class PackageWork:
    package_id: str
    lane: Lane
    sha256: str
    document: Mapping[str, Any]
    rank: tuple[int, str]
    basis: str                          # dependency fingerprint used as the cell reuse basis
    entities: tuple[str, ...]           # capability entity scope (guidance/evaluator files removed)
    unit_key: str | None



@dataclass
class ReviewContext:
    run_root: Path
    run_id: str
    repository_root: Path
    settings: InferenceSecurityReviewSettings
    core: Any
    infer: Callable[..., ModelResult]
    receipts_root: Path
    budget: JobBudget
    semaphore: ReviewTeamSemaphore
    vocabulary: Any
    crosswalk: Any
    covers: Mapping[str, Sequence[str]]
    role_tools: Mapping[str, tuple[str, ...]]
    schemas: SchemaSet
    accepted_cwe_ids: frozenset[str]
    rule_predicates: Mapping[str, tuple[Predicate, ...]]
    source_languages: Mapping[str, str]
    build_unit_languages: Mapping[str, tuple[str, ...]]
    index_names: tuple[str, ...]
    available_sources: tuple[str, ...]
    max_page_size: int = 20
    max_depth: int = 4
    _bundles: dict[str, dict[str, Any]] = field(default_factory=dict)
    _pinned: set[str] = field(default_factory=set)
    _views: dict[str, PackageView] = field(default_factory=dict)
    _resolves: dict[str, bool] = field(default_factory=dict)
    _names: dict[str, str | None] = field(default_factory=dict)
    _locations: dict[str, Mapping[str, Any] | None] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def profile(self, role: Role) -> ModelProfileSettings:
        return self.settings.profile_for(role)

    def bundle(self, *, role: Role, persona: str, stack: str, task: str, lane: Lane,
               capability: CellCapability) -> dict[str, Any]:
        """Compose (once) and pin a hash-pinned guidance bundle; conflicting guidance raises."""
        # ``expand`` is application navigation, not a registry tool: the role allowlist and the receipt omit it.
        receipt = {"granted_tools": [name for name in capability.tools if name != EXPAND_TOOL],
                   "max_queries": capability.max_queries,
                   "max_turns": capability.max_turns, "page_size": capability.page_size}
        key = sha256_hex({"role": role.value, "persona": persona, "stack": stack, "task": task,
                          "lane": lane.value, "receipt": receipt})
        with self._lock:
            cached = self._bundles.get(key)
        if cached is None:
            cached = compose_bundle(self.repository_root, role=role.value, persona=persona, stack=stack, task=task,
                                    task_input={"lane": lane.value}, capability=receipt,
                                    vocabulary=self.vocabulary, crosswalk=self.crosswalk)
            cached = {"bundle": cached, "text": render_prompt(cached)}
            with self._lock:
                self._bundles[key] = cached
        identity = cached["bundle"]["sha256"]
        with self._lock:
            if identity not in self._pinned:
                pin_bundle(self.run_root, cached["bundle"])
                self._pinned.add(identity)
        return cached

    def package_view(self, work: PackageWork) -> PackageView:
        """The labelled, budgeted model-facing view of a package (built once per package; ``package-view/1``)."""
        with self._lock:
            cached = self._views.get(work.package_id)
        if cached is None:
            cached = build_view(work.document, self.core, ViewLimits.from_settings(self.settings.packages))
            with self._lock:
                cached = self._views.setdefault(work.package_id, cached)
        return cached

    def resolves(self, identity: str) -> bool:
        with self._lock:
            if identity in self._resolves:
                return self._resolves[identity]
        try:
            found = bool(self.core.find(identity=identity, limit=1)["results"])
        except (ValueError, LookupError):
            found = False
        with self._lock:
            self._resolves[identity] = found
        return found

    def entity_name(self, identity: str) -> str | None:
        with self._lock:
            if identity in self._names:
                return self._names[identity]
        try:
            results = self.core.find(identity=identity, limit=1)["results"]
            name = str(results[0].get("name")) if results else None
        except (ValueError, LookupError):
            name = None
        with self._lock:
            self._names[identity] = name
        return name

    def location(self, identity: str) -> Mapping[str, Any] | None:
        """The accepted source location of ``identity`` (``None`` when it has none)."""
        with self._lock:
            if identity in self._locations:
                return self._locations[identity]
        try:
            results = self.core.find(identity=identity, limit=1)["results"]
            location = results[0].get("location") if results else None
        except (ValueError, LookupError):
            location = None
        location = location if isinstance(location, Mapping) else None
        with self._lock:
            self._locations[identity] = location
        return location

    def describe(self, identity: str, limit: int) -> str:
        """Bounded resolved content of one accepted identity, for a row re-presented to a judge (``J`` label)."""
        try:
            results = self.core.find(identity=identity, limit=1)["results"]
        except (ValueError, LookupError):
            results = []
        if not results:
            return "not resolvable in the accepted index"[:limit]
        row = results[0]
        kind, location = str(row.get("kind")), row.get("location") if isinstance(row.get("location"), Mapping) else {}
        payload = row.get("payload")
        parts = [kind]
        if kind in GRAPH_FACT_KINDS and isinstance(payload, Mapping):
            parts.append(summarize_fact(kind, payload, line=location.get("start_line")))
        elif row.get("name"):
            parts.append(str(row["name"]))
        if location:
            parts.append(f"{location.get('path')}:{location.get('start_line')}-{location.get('end_line')}")
            try:
                excerpt = self.core.read_excerpt(identity=identity, context_lines=0)["results"]
            except (ValueError, LookupError, OSError):
                excerpt = []
            if excerpt:
                parts.append("| " + " / ".join(str(excerpt[0]["excerpt"]).splitlines()[:3]))
        return " ".join(" ".join(parts).split())[:limit]

    def shard_sha256(self, label: str) -> str | None:
        """The accepted manifest's hash of shard ``<index>/<shard_id>``."""
        for item in self.core.manifest["indexes"]:
            if f"{item['name']}/{item.get('shard_id', 'default')}" == label:
                return str(item["sha256"])
        return None

    def red_validator_version(self) -> str:
        """Red cells' validator version: the admission rules and the resolved closed limits."""
        return (f"{VALIDATOR_VERSION};{red_discovery.ADMISSION_RULES_VERSION};"
                f"limits={sha256_hex(self.settings.red_output.record())[:16]}")


@dataclass
class TeamResult:
    package_id: str
    lane: Lane
    unit_key: str | None
    routing: dict[str, Any] = field(default_factory=dict)
    cells: list[CellRecord] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    relations: list[EvidenceRelation] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    requests: list[dict[str, Any]] = field(default_factory=list)
    independence: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    verifier_gaps: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    coverage: list[dict[str, Any]] = field(default_factory=list)
    capabilities: list[dict[str, Any]] = field(default_factory=list)
    security_events: list[Mapping[str, Any]] = field(default_factory=list)
    triage: list[dict[str, Any]] = field(default_factory=list)
    leads: tuple[str, ...] = ()                                   # the package's lead menu
    lead_entries: list[tuple[str, str, str]] = field(default_factory=list)   # (cell, lead, outcome)
    chain_seeds: list[dict[str, Any]] = field(default_factory=list)
    poc_basis: list[dict[str, Any]] = field(default_factory=list)
    judge_verdicts: list[JudgeVerdict] = field(default_factory=list)
    judging: dict[str, Any] = field(default_factory=dict)         # claim id -> judge cells / why none was selected
    launched: bool = False
    counts: dict[str, int] = field(default_factory=lambda: {"cells_run": 0, "cells_reused": 0,
                                                            "cells_not_launched": 0})


@dataclass
class _Cell:
    spec: CellSpec
    capability: CellCapability
    kind: str                            # red | blue | verifier | judge
    strategy: str | None = None
    invocation: RedInvocation | None = None   # red cells: what the result must echo and account for
    outcome: CellOutcome | None = None
    record: CellRecord | None = None
    requests: list[bytes] = field(default_factory=list)

    @property
    def cell_id(self) -> str:
        return cell_fingerprint(self.spec, self.capability)


# ------------------------------------------------------------------------------------------------
# Allocation (deterministic, work-conserving)


def lane_allocation(lead_count: int, hunt_count: int, lead_share: float, budget_team_packages: int) -> dict[Lane, int]:
    """Team-packages each lane may launch: the fair-share scheduler run over both declared queues.

    Shares split ``budget_team_packages``; a lane whose queue empties releases its unused share to the
    other lane. The result depends only on the queue lengths and configuration, never on timing.
    """
    scheduler = FairShareScheduler(lead_share, budget_team_packages)
    queues = {Lane.LEAD: [QueuedPackage(0, f"lead-{index:06d}") for index in range(lead_count)],
              Lane.HUNT: [QueuedPackage(0, f"hunt-{index:06d}") for index in range(hunt_count)]}
    consumed = {Lane.LEAD: 0, Lane.HUNT: 0}
    while (decision := scheduler.choose(queues, consumed)) is not None:
        lane, package_id = decision
        queues[lane] = [item for item in queues[lane] if item.package_id != package_id]
        consumed[lane] += 1
    return consumed


# ------------------------------------------------------------------------------------------------
# Cell construction


def _claim_view(claim: Claim, *, statement: bool, labels: Mapping[str, str] | None = None,
                names: Callable[[str], str | None] = lambda _ref: None) -> dict[str, Any]:
    """The claim as a blue or verifier cell sees it: affected entities by label, never by raw identity."""
    view = {"claim_id": claim.claim_id,
            "affected": [{"label": (labels or {}).get(ref, "?"), "name": names(ref)}
                         for ref in claim.affected_entities],
            "weakness_cwe": claim.weakness_cwe, "security_predicate": str(claim.security_predicate),
            "preconditions": list(claim.preconditions),
            "required_predicates": sorted(item.value for item in required_predicates_for(claim))}
    if statement:
        view["statement"] = claim.statement
    return view


def _routed(view: PackageView, routing: Mapping[str, Any], persona: str) -> dict[str, Any]:
    """The view document of one cell: the package view plus the cell\'s persona and stack profile."""
    return {**view.document, "persona": persona, "stack_profile": routing.get("stack")}


def _cell(ctx: ReviewContext, work: PackageWork, routing: Mapping[str, Any], *, role: Role, persona: str,
          task: str, kind: str, task_input: Mapping[str, Any], claim: Claim | None = None,
          strategy: str | None = None, view: PackageView | None = None,
          side_map: Mapping[str, str] | None = None, extra_entities: Sequence[str] = ()) -> _Cell:
    invocation = None
    expand: Expander
    schema_errors = ctx.schemas.errors
    if role in RED_ROLES:
        invocation = RedInvocation(role, 0, work.basis, _lead_ids(work))
        expand = lambda compact, labels: expand_red(  # noqa: E731
            compact, labels, invocation=invocation, schema_errors=schema_errors)
    elif role is Role.BLUE_TEAM_REFUTER:
        expand = lambda compact, labels: expand_blue(  # noqa: E731
            compact, labels, claim_id=claim.claim_id, task=task, schema_errors=schema_errors)
    elif role is Role.ADJUDICATION_JUDGE:
        expand = lambda compact, labels: expand_judge(  # noqa: E731
            compact, labels, claim_id=claim.claim_id, side_map=dict(side_map or {}), schema_errors=schema_errors)
    else:
        expand = lambda compact, labels: expand_verifier(  # noqa: E731
            compact, labels, claim_id=claim.claim_id, schema_errors=schema_errors)
    profile = ctx.profile(role)
    tools = tuple(sorted((set(ctx.role_tools.get(role.value, ())) & IN_PROCESS_TOOLS) | {EXPAND_TOOL}))
    capability = CellCapability.issue(
        run_id=ctx.run_id, manifest_sha256=ctx.core.manifest_sha256, package_id=work.package_id,
        package_sha256=work.sha256, role=role, round=0, tools=tools,
        indexes=tuple(name for name in ctx.index_names if name in INDEX_NAMES),
        entities=(*work.entities, *extra_entities),
        graph_scopes=tuple((work.document.get("retrieval") or {}).get("graph_scopes", ())),
        max_queries=max(1, profile.max_queries), max_turns=profile.max_turns,
        page_size=min(100, ctx.max_page_size), max_depth=min(8, ctx.max_depth), max_result_bytes=MAX_RESULT_BYTES)
    stack = str(routing["stack"])
    guidance = ctx.bundle(role=role, persona=persona, stack=stack, task=task, lane=work.lane, capability=capability)
    schema = RESULT_SCHEMAS[role]
    spec = CellSpec(
        manifest_sha256=ctx.core.manifest_sha256, lane=work.lane, package_id=work.package_id,
        package_sha256=work.sha256, claim_id=claim.claim_id if claim else None, role=role, persona=persona,
        stack_profile=stack, strategy=strategy, task=task, task_input=dict(task_input), round=0,
        round_delta_sha256=None, evidence_set=tuple(sorted({*work.entities, *extra_entities})),
        guidance_bundle_sha256=guidance["bundle"]["sha256"], guidance_text=guidance["text"],
        provider=profile.provider, model=profile.model, reasoning=profile.reasoning,
        max_input_tokens=profile.max_input_tokens, max_output_tokens=profile.max_output_tokens,
        timeout_seconds=profile.timeout_seconds, output_schema=OUTPUT_SCHEMAS[schema],
        validator_version=ctx.red_validator_version() if invocation else VALIDATOR_VERSION, reuse_basis=work.basis,
        view=view if view is not None else ctx.package_view(work), expand=expand)
    return _Cell(spec, capability, kind, strategy, invocation)


def _lead_ids(work: PackageWork) -> tuple[str, ...]:
    return tuple(str(lead["observation_id"]) for lead in work.document.get("lead_menu", ()))


def _validator(ctx: ReviewContext, role: Role, *, claim_id: str | None = None, task: str | None = None,
               invocation: RedInvocation | None = None) -> Callable[[Mapping[str, Any]], list[str]]:
    schema = RESULT_SCHEMAS[role]

    def validate(result: Mapping[str, Any]) -> list[str]:
        errors = ctx.schemas.errors(schema, result)
        if invocation is not None and not errors and isinstance(result, Mapping):
            errors.extend(red_discovery.admission_errors(result, invocation, ctx.settings.red_output))
        if claim_id is not None and isinstance(result, Mapping) and result.get("claim_id") != claim_id:
            errors.append("result names a different claim")
        if task is not None and isinstance(result, Mapping) and result.get("task") != task:
            errors.append("result names a different blue task")
        return errors

    return validate


class _Guard:
    """Per-cell infer wrapper: wall-clock deadline, token caps, job budget charges, request capture."""

    def __init__(self, ctx: ReviewContext, cell: _Cell, profile: ModelProfileSettings, *, capture: bool,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.ctx, self.cell, self.profile, self.capture, self.clock = ctx, cell, profile, capture, clock
        self.deadline: float | None = None

    def __call__(self, request: ReviewModelRequest, *, timeout_seconds: int) -> ModelResult:
        now = self.clock()
        if self.deadline is None:
            self.deadline = now + self.profile.timeout_seconds
        remaining = self.deadline - now
        if remaining <= 0:
            raise CellBudgetExceeded("cell_deadline")
        if self.capture:
            self.cell.requests.append(json.dumps(asdict(request), sort_keys=True, default=str).encode("utf-8"))
        try:
            result = self.ctx.infer(request, timeout_seconds=max(1, min(int(timeout_seconds), int(remaining) or 1)))
        except BaseException:
            self.ctx.budget.charge(model_turns=1)
            raise
        input_tokens, output_tokens = int(result.input_tokens or 0), int(result.output_tokens or 0)
        self.ctx.budget.charge(model_turns=1, input_tokens=input_tokens, output_tokens=output_tokens)
        if input_tokens > self.profile.max_input_tokens or output_tokens > self.profile.max_output_tokens:
            raise CellBudgetExceeded("cell_token_cap")
        if self.clock() > self.deadline:
            raise CellBudgetExceeded("cell_deadline")
        return result


def _not_launched(cell: _Cell, reason: str, gap_class: GapClass = GapClass.BUDGET_GAP) -> tuple[CellRecord, Gap]:
    gap = make_gap(gap_class, cell.cell_id, f"not_launched: {reason}")
    record = CellRecord(cell_id=cell.cell_id, lane=cell.spec.lane, package_id=cell.spec.package_id,
                        role=cell.spec.role, persona=cell.spec.persona, stack_profile=cell.spec.stack_profile,
                        task=cell.spec.task, claim_id=cell.spec.claim_id, status=CellStatus.NOT_LAUNCHED,
                        attempts=0, gap_ids=(gap.gap_id,), receipt_sha256=None)
    return record, gap


def _run(ctx: ReviewContext, cell: _Cell, validate: Callable[[Mapping[str, Any]], list[str]], *,
         capture: bool = False) -> None:
    """Run or reuse one cell; ordinary failures end in a terminal record, never an exception."""
    if not ctx.budget.cell_launch_allowed():
        cell.record, gap = _not_launched(cell, f"job budget exhausted ({ctx.budget.usage_exhausted()})")
        cell.outcome = CellOutcome(cell.record, None, (gap,), (), (), False, {})
        return
    retry = ctx.settings.retry
    guard = _Guard(ctx, cell, ctx.profile(cell.spec.role), capture=capture)
    outcome = reuse_or_run(cell.spec, infer=guard, core=ctx.core, capability=cell.capability,
                           receipts_root=ctx.receipts_root, validate_final=validate,
                           max_attempts=retry.max_attempts, retry_on_timeout=retry.retry_on_timeout,
                           retry_on_provider_error=retry.retry_on_provider_error,
                           retry_on_invalid_output=retry.retry_on_invalid_output)
    if not outcome.reused and outcome.counts.get("queries"):
        ctx.budget.charge(retrieval_queries=int(outcome.counts["queries"]))
    cell.outcome, cell.record = outcome, outcome.record


def _seen(cell: _Cell) -> set[str]:
    if cell.outcome is None or not cell.outcome.receipt_paths:
        return set()
    receipt = json.loads(Path(cell.outcome.receipt_paths[-1]).read_text(encoding="utf-8"))
    return set(receipt.get("seen_identities", ()))


def _relations(ctx: ReviewContext, cell: _Cell, claim_id: str, items: Iterable[Mapping[str, Any]],
               seen: set[str]) -> tuple[list[EvidenceRelation], list[Gap]]:
    relations: list[EvidenceRelation] = []
    gaps: list[Gap] = []
    allowed = ROLE_RELATION_KINDS[cell.spec.role]
    receipt = cell.record.receipt_sha256 if cell.record else None
    for item in items:
        kind = RelationKind(item["kind"])
        predicate = Predicate(item["predicate"])
        if kind not in allowed:
            gaps.append(make_gap(GapClass.SCHEMA_ERROR, cell.cell_id,
                                 f"relation kind {kind.value} is outside the {cell.spec.role.value} authority",
                                 predicate=predicate))
            continue
        entity = str(item["entity_id"])
        resolved = resolve_relation(ctx.core, claim_id=claim_id, predicate=predicate, kind=kind, entity_id=entity,
                                    producing_cell_id=cell.cell_id,
                                    retrieval_receipt_sha256=receipt if entity in seen else None,
                                    rule_predicates=ctx.rule_predicates.get(entity, ()),
                                    role=cell.spec.role.value)
        (relations if isinstance(resolved, EvidenceRelation) else gaps).append(resolved)
    return relations, gaps


def _requests(cell: _Cell, claim_id: str, items: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    found = []
    for item in items:
        body = {"claim_id": claim_id, "predicate": item["predicate"], "requested_kind": item["requested_kind"],
                "anchors": sorted(item.get("anchors", ())), "origin_cell_id": cell.cell_id}
        found.append({**body, "request_id": make_id("evidence_request", 1, body)})
    return found


def _narratives(result: Mapping[str, Any]) -> list[str]:
    """Blue prose (rationales) that must never reach the blind verifier (R6 markers)."""
    texts = [str(result.get("rationale", ""))]
    texts.extend(str(item.get("rationale", "")) for item in result.get("proposed_relations", ()))
    return _markers(texts)


def _markers(texts: Iterable[str]) -> list[str]:
    return [text for text in texts if len(text.strip()) >= MIN_MARKER_CHARACTERS]


def _red_relations(ctx: ReviewContext, cell: _Cell, claim_id: str, red: Mapping[str, Any],
                   proposal: Mapping[str, Any], seen: set[str]) -> tuple[list[EvidenceRelation], list[Gap]]:
    """Relations for one red proposal: its cited references and its observed taint hops.

    ``nominates`` references and hops whose basis is ``analyst_hypothesis`` never become relations.
    Every other citation is re-resolved through ``resolve_relation`` (accepted graph facts included);
    a cited shard or source locator that disagrees with the re-resolved entity is an ``evidence_gap``.
    """
    relations: list[EvidenceRelation] = []
    gaps: list[Gap] = []
    for citation in red_discovery.proposal_citations(red, proposal):
        if citation.kind is None:
            continue
        found, failed = _relations(ctx, cell, claim_id, [{"kind": citation.kind.value, "entity_id": citation.entity_id,
                                                          "predicate": citation.predicate.value}], seen)
        gaps.extend(failed)
        for relation in found:
            mismatch = _citation_mismatch(ctx, relation, citation)
            if mismatch is None:
                relations.append(relation)
            else:
                gaps.append(make_gap(GapClass.EVIDENCE_GAP, claim_id, mismatch, predicate=relation.predicate))
    return relations, gaps


def _citation_mismatch(ctx: ReviewContext, relation: EvidenceRelation, citation: Citation) -> str | None:
    if citation.shard_id is not None and citation.shard_id != relation.shard_id:
        return "cited shard is not the accepted shard the entity re-resolves to"
    if citation.shard_sha256 is not None and citation.shard_sha256 != ctx.shard_sha256(relation.shard_id):
        return "cited shard hash does not match the accepted manifest"
    if citation.locator.get("kind") == "source_line":
        location = ctx.location(relation.entity_id)
        if location is None:
            return "source-line locator cites an entity without an accepted source location"
        if (citation.locator["path"], citation.locator["file_sha256"]) != (location.get("path"),
                                                                           location.get("file_sha256")):
            return "source-line locator names a different file than the re-resolved entity"
        if (int(citation.locator["end_line"]) < int(location.get("start_line", 0)) or
                int(citation.locator["start_line"]) > int(location.get("end_line", 0))):
            return "source-line locator lies outside the re-resolved entity's lines"
    return None


def _worker_gap(cell: _Cell, item: Mapping[str, Any]) -> Gap:
    """A gap the red worker named: missing or partial coverage, never evidence of a clean target."""
    gap_class = GapClass.EVIDENCE_GAP if item["kind"] in ("unresolved", "ambiguous") else GapClass.COVERAGE_GAP
    return make_gap(gap_class, cell.cell_id, f"worker_named_gap:{item['kind']}:{item['local_id']}: {item['scope']}")


# ------------------------------------------------------------------------------------------------
# Routing


_LANGUAGE_TAGS = {"c": "lang:c", "c++": "lang:cpp", "cpp": "lang:cpp", "c#": "lang:csharp", "csharp": "lang:csharp",
                  "python": "lang:python", "java": "lang:java", "kotlin": "lang:kotlin", "go": "lang:go",
                  "rust": "lang:rust", "javascript": "lang:javascript", "typescript": "lang:typescript",
                  "php": "lang:php"}


def route(ctx: ReviewContext, work: PackageWork) -> dict[str, Any]:
    """persona-routing/1 and stack-routing/1 for one package, with every basis recorded."""
    document = work.document
    scope = document["scope"]
    languages: dict[str, float] = {}
    for identity in scope.get("source_ids", ()):
        language = ctx.source_languages.get(identity)
        if language and (tag := _LANGUAGE_TAGS.get(language.lower())):
            languages[tag] = languages.get(tag, 0.0) + 1.0
    for language in ctx.build_unit_languages.get(str(scope.get("build_unit_id")), ()):
        if tag := _LANGUAGE_TAGS.get(language.lower()):
            languages[tag] = languages.get(tag, 0.0) + 1.0
    tags: dict[str, float] = {}
    for entry in document.get("context", ()):
        if entry.get("kind") == "tag_assignment" and (name := ctx.entity_name(entry["id"])):
            tags[name] = tags.get(name, 0.0) + 1.0
    lead_cwes = sorted({cwe for lead in document.get("lead_menu", ()) for cwe in lead.get("rule_cwe", ())})
    for cwe in lead_cwes:
        tag = "cwe:" + cwe.split("-", 1)[-1].lstrip("0")
        tags[tag] = tags.get(tag, 0.0) + 1.0
    subject = sorted(tag for tag in tags if tag.startswith(("infra:", "func:")))
    stack = route_stack(languages=languages, subject_tags=subject)
    gaps: list[Gap] = []
    if stack.get("routing_gap"):
        gaps.append(make_gap(GapClass.ROUTING_GAP, f"{work.package_id}:routing:stack", stack.get("reason", "")))
    routing: dict[str, Any] = {"stack": stack["stack"], "stack_basis": stack["basis"], "tags": sorted(tags)}
    if work.lane is Lane.LEAD:
        persona = route_persona(ctx.covers, lead_cwe=lead_cwes[0] if lead_cwes else None,
                                location_tags=sorted(tag for tag in tags if not tag.startswith("cwe:")))
        routing.update(persona=persona["persona"], persona_basis=persona["basis"],
                       matched_tags=persona["matched_tags"])
        if persona.get("routing_gap"):
            gaps.append(make_gap(GapClass.ROUTING_GAP, f"{work.package_id}:routing:persona",
                                 persona.get("reason", "")))
    else:
        # Graph-backed strategies unlock per unit, from the families accepted for the package scope.
        sources = unit_sources(ctx.available_sources, (document.get("retrieval") or {}).get("graph_families", ()))
        panel = hunt_panel(ctx.covers, unit_tags=tags, available_sources=sources)
        routing.update(persona=panel["cells"][0]["persona"], panel=panel["cells"], panel_rule=panel["rule"])
        for item in panel["gaps"]:
            gaps.append(make_gap(GapClass.COVERAGE_GAP, f"{work.package_id}:strategy:{item['strategy']}",
                                 item["reason"]))
        if panel.get("routing_gap"):
            gaps.append(make_gap(GapClass.ROUTING_GAP, f"{work.package_id}:routing:panel",
                                 "panel_includes_generalist"))
        routing["strategy_gaps"] = list(panel["gaps"])
    routing["gaps"] = gaps
    return routing


def _red_cells(ctx: ReviewContext, work: PackageWork, routing: Mapping[str, Any]) -> list[_Cell]:
    view = ctx.package_view(work)
    if work.lane is Lane.LEAD:
        document = _routed(view, routing, routing["persona"])
        return [_cell(ctx, work, routing, role=Role.RED_TEAM_ANALYST, persona=routing["persona"], task=lens,
                      kind="red", task_input={"package": document, "lens": lens})
                for lens in LEAD_LENSES[:ctx.settings.teams.red_per_team]]
    return [_cell(ctx, work, routing, role=Role.HYPOTHESIS_HUNTER, persona=item["persona"], task=item["strategy"],
                  kind="red", strategy=item["strategy"],
                  task_input={"package": _routed(view, routing, item["persona"]), "strategy": item["strategy"],
                              "known_claims": []})
            for item in routing["panel"][:ctx.settings.teams.red_per_team]]


# ------------------------------------------------------------------------------------------------
# One team


def _record(result: TeamResult, cell: _Cell) -> None:
    assert cell.record is not None and cell.outcome is not None
    result.cells.append(cell.record)
    result.gaps.extend(cell.outcome.gaps)
    result.security_events.extend(cell.outcome.security_events)
    result.capabilities.append({"cell_id": cell.record.cell_id, "role": cell.spec.role.value,
                                "package_id": cell.spec.package_id, **cell.capability.body(),
                                "capability_sha256": cell.capability.capability_sha256})
    key = ("cells_not_launched" if cell.record.status is CellStatus.NOT_LAUNCHED
           else "cells_reused" if cell.outcome.reused else "cells_run")
    result.counts[key] += 1


def _coverage_row(work: PackageWork, cell: _Cell) -> dict[str, Any]:
    status = cell.record.status if cell.record else CellStatus.NOT_LAUNCHED
    state = ("reviewed" if status is CellStatus.SUCCEEDED else
             "not_launched" if status is CellStatus.NOT_LAUNCHED else "gap")
    return {"unit_key": work.unit_key, "package_id": work.package_id, "strategy": cell.strategy,
            "persona": cell.spec.persona, "status": state, "cell_id": cell.cell_id, "reason": None}


def run_team(ctx: ReviewContext, work: PackageWork, *, launch: bool, not_launched_reason: str = "") -> TeamResult:
    """Run one package's team to terminal records. Only an :class:`IntegrityError` escapes."""
    result = TeamResult(work.package_id, work.lane, work.unit_key, leads=_lead_ids(work))
    routing = route(ctx, work)
    result.routing = {key: value for key, value in routing.items() if key != "gaps"}
    result.gaps.extend(routing["gaps"])
    reds = _red_cells(ctx, work, routing)
    if launch and not ctx.budget.reserve(work.lane):
        launch, not_launched_reason = False, f"job budget exhausted ({ctx.budget.snapshot().exhausted})"
    if not launch:
        _skip(result, work, reds, not_launched_reason or "not launched", GapClass.BUDGET_GAP)
        return result
    try:
        with ctx.semaphore.acquire(work.lane):
            result.launched = True
            _team_body(ctx, work, routing, reds, result)
    except TeamUnavailable:
        _skip(result, work, reds, "no review team became free within the wait bound", GapClass.WORKER_GAP)
    except IntegrityError:
        raise
    except Exception as exc:  # a team failure is a package gap; partial team output is discarded
        failed = TeamResult(work.package_id, work.lane, work.unit_key, routing=result.routing, launched=True,
                            leads=result.leads)
        failed.gaps.extend(routing["gaps"])
        failed.gaps.append(make_gap(GapClass.WORKER_GAP, work.package_id, f"team failure: {type(exc).__name__}"))
        for cell in reds:
            gap = make_gap(GapClass.WORKER_GAP, cell.cell_id, f"team failure: {type(exc).__name__}")
            cell.record = CellRecord(cell_id=cell.cell_id, lane=work.lane, package_id=work.package_id,
                                     role=cell.spec.role, persona=cell.spec.persona,
                                     stack_profile=cell.spec.stack_profile, task=cell.spec.task, claim_id=None,
                                     status=CellStatus.FAILED, attempts=0, gap_ids=(gap.gap_id,))
            cell.outcome = CellOutcome(cell.record, None, (gap,), (), (), False, {})
            _record(failed, cell)
            if work.lane is Lane.HUNT:
                failed.coverage.append(_coverage_row(work, cell))
        return failed
    return result


def _skip(result: TeamResult, work: PackageWork, reds: list[_Cell], reason: str, gap_class: GapClass) -> None:
    result.gaps.append(make_gap(gap_class, work.package_id, f"package not launched: {reason}"))
    for cell in reds:
        cell.record, gap = _not_launched(cell, reason, gap_class)
        cell.outcome = CellOutcome(cell.record, None, (gap,), (), (), False, {})
        _record(result, cell)
        if work.lane is Lane.HUNT:
            result.coverage.append(_coverage_row(work, cell))


def _team_body(ctx: ReviewContext, work: PackageWork, routing: Mapping[str, Any], reds: list[_Cell],
               result: TeamResult) -> None:
    teams = ctx.settings.teams
    with ThreadPoolExecutor(max_workers=max(1, teams.red_per_team), thread_name_prefix="red") as pool:
        futures = [pool.submit(_run, ctx, cell, _validator(ctx, cell.spec.role, invocation=cell.invocation))
                   for cell in reds]
        for future in futures:
            future.result()
    for cell in reds:
        _record(result, cell)
        if work.lane is Lane.HUNT:
            result.coverage.append(_coverage_row(work, cell))
    if work.lane is Lane.HUNT:
        for item in routing.get("strategy_gaps", ()):
            result.coverage.append({"unit_key": work.unit_key, "package_id": work.package_id,
                                    "strategy": item["strategy"], "persona": None, "status": "gap",
                                    "cell_id": None, "reason": item["reason"]})

    groups = _normalize(ctx, work, reds, result)
    admitted = _triage(ctx, work, groups, result)
    reviews: list[tuple[dict[str, Any], _Cell, _Cell, _Cell]] = []
    for group in admitted:
        claim: Claim = group["claim"]
        claim_view, added = ctx.package_view(work).with_extra(claim.affected_entities)
        document = _routed(claim_view, routing, group["persona"])
        blue_input = {"claim": _claim_view(claim, statement=True, labels=added, names=ctx.entity_name),
                      "package": document}
        # The blind verifier\'s request is built here and only here: the claim\'s identity fields and the package.
        verifier_input = {"claim": _claim_view(claim, statement=False, labels=added, names=ctx.entity_name),
                          "package": document}
        control = _cell(ctx, work, routing, role=Role.BLUE_TEAM_REFUTER, persona=group["persona"],
                        task=BlueTask.CONTROL.value, kind="blue", claim=claim, view=claim_view,
                        task_input={**blue_input, "task": BlueTask.CONTROL.value})
        reach = _cell(ctx, work, routing, role=Role.BLUE_TEAM_REFUTER, persona=group["persona"],
                      task=BlueTask.REACHABILITY.value, kind="blue", claim=claim, view=claim_view,
                      task_input={**blue_input, "task": BlueTask.REACHABILITY.value})
        verifier = _cell(ctx, work, routing, role=Role.INDEPENDENT_VERIFIER, persona=group["persona"],
                         task=VERIFIER_TASK, kind="verifier", claim=claim, view=claim_view,
                         task_input=verifier_input)
        reviews.append((group, control, reach, verifier))
    workers = max(1, teams.blue_per_team + teams.verifier_per_team)
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="review") as pool:
        futures = []
        for group, control, reach, verifier in reviews:
            claim_id = group["claim"].claim_id
            futures.append(pool.submit(_run, ctx, control, _validator(
                ctx, Role.BLUE_TEAM_REFUTER, claim_id=claim_id, task=BlueTask.CONTROL.value)))
            futures.append(pool.submit(_run, ctx, reach, _validator(
                ctx, Role.BLUE_TEAM_REFUTER, claim_id=claim_id, task=BlueTask.REACHABILITY.value)))
            futures.append(pool.submit(_run, ctx, verifier, _validator(
                ctx, Role.INDEPENDENT_VERIFIER, claim_id=claim_id), capture=True))
        for future in futures:
            future.result()
    judges = _plan_judges(ctx, work, routing, reviews, result)
    _run_judges(ctx, judges)
    for group, control, reach, verifier in reviews:
        _review(ctx, group, (control, reach), verifier, result)
    for plan in judges:
        _judged(ctx, plan, result)


@dataclass
class _JudgePlan:
    """One planned judge cell: the claim it judges, the side-to-role map and the cells behind the two sides."""

    group: Mapping[str, Any]
    cell: _Cell
    assignment: dict[str, str]
    blues: tuple[_Cell, _Cell]
    markers: tuple[str, ...]
    index: int


def _blindness_markers(ctx: ReviewContext, actors: Sequence[_Cell], judge: ModelProfileSettings) -> tuple[str, ...]:
    """Identifiers of the red and blue side that must not reach a judge: their role names, and for the cells behind
    the two sides their task, strategy and persona names, cell and actor identities, and a model name the judge does
    not itself run on. (Only identifiers: a generic word such as ``variant`` is not an identity.)"""
    found = {role.value for role in (*RED_ROLES, Role.BLUE_TEAM_REFUTER)}
    for cell in actors:
        found |= {cell.cell_id, _actor(cell).actor_id}
        for name in (cell.spec.task, cell.spec.strategy, cell.spec.persona):
            if name and "_" in name and name != JUDGE_PERSONA:
                found.add(name)
        if cell.spec.model != judge.model:
            found.add(cell.spec.model)
    return tuple(sorted(item for item in found if item))


def _plan_judges(ctx: ReviewContext, work: PackageWork, routing: Mapping[str, Any],
                 reviews: Sequence[tuple[dict[str, Any], _Cell, _Cell, _Cell]], result: TeamResult
                 ) -> list[_JudgePlan]:
    """Judge cells for the admitted claims ``roles.adjudication_judge.when`` selects; the rest are accounted."""
    settings = ctx.settings.judge
    if settings is None:
        return []
    plans: list[_JudgePlan] = []
    profile = ctx.profile(Role.ADJUDICATION_JUDGE)
    for group, control, reach, _verifier in reviews:
        claim: Claim = group["claim"]
        red = red_side((proposal, red_result) for _cell_, proposal, red_result, _seen_ in group["items"])
        blue, dispositions = blue_side(
            cell.outcome.result if cell.record is not None and cell.record.status is CellStatus.SUCCEEDED else None
            for cell in (control, reach))
        if not selected(settings.when, red_affirmed=red_affirms(red), blue_dispositions=dispositions):
            result.judging[claim.claim_id] = {
                "selected": False,
                "reason": "red_not_affirmed" if not red_affirms(red) else "no_disagreement"}
            continue
        claim_view, added = ctx.package_view(work).with_extra(claim.affected_entities)
        actors = (*group["cells"], control, reach)
        markers = _blindness_markers(ctx, actors, profile)
        entries = []
        for index in range(settings.judges_per_claim):
            assignment = side_assignment(ctx.core.manifest_sha256, claim.claim_id, index)
            shown = present({"red": red, "blue": blue}, assignment, claim_view, max_why=settings.max_why_chars,
                            max_rows=settings.max_cited_rows_per_side, markers=markers,
                            describe=lambda ref: ctx.describe(ref, settings.max_cited_row_chars))
            task_input = {"task": JUDGE_TASK,
                          "claim": _claim_view(claim, statement=True, labels=added, names=ctx.entity_name),
                          "package": _routed(shown.view, routing, JUDGE_PERSONA),
                          "sides": shown.sides, "cited_rows": shown.cited_rows}
            cell = _cell(ctx, work, routing, role=Role.ADJUDICATION_JUDGE, persona=JUDGE_PERSONA, task=JUDGE_TASK,
                         kind="judge", claim=claim, strategy=f"judge-{index + 1}", view=shown.view,
                         task_input=task_input, side_map=assignment, extra_entities=shown.rows)
            plans.append(_JudgePlan(group, cell, assignment, (control, reach), markers, index))
            entries.append(cell.cell_id)
        result.judging[claim.claim_id] = {"selected": True, "cells": entries}
    return plans


def _run_judges(ctx: ReviewContext, plans: Sequence[_JudgePlan]) -> None:
    if not plans:
        return
    settings = ctx.settings.judge
    workers = max(1, min(settings.workers if settings else 1, len(plans)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="judge") as pool:
        futures = [pool.submit(_run, ctx, plan.cell, _validator(ctx, Role.ADJUDICATION_JUDGE,
                                                                claim_id=plan.group["claim"].claim_id),
                               capture=True) for plan in plans]
        for future in futures:
            future.result()
    for plan in plans:
        # The side-to-role map is part of the terminal record and of nothing the model sees.
        plan.cell.record = replace(plan.cell.record, side_map=tuple(sorted(plan.assignment.items())))


def _judge_request_blind(plan: _JudgePlan) -> tuple[bool, str]:
    """Whether the stored judge request holds none of the red or blue identifiers, and why not (fails closed).

    A fresh run checks the exact request bytes and records the result beside the receipt (hashes and the offending
    identifier). A reused cell sent no request; its recorded check is used when the markers are unchanged, and
    otherwise the check fails closed.
    """
    cell = plan.cell
    digest = sha256_hex(list(plan.markers))
    sidecar = Path(cell.outcome.receipt_paths[-1]).with_name(f"judge-request-check-{cell.record.attempts}.json") \
        if cell.outcome.receipt_paths else None
    if cell.requests:
        joined = b"\n".join(cell.requests)
        leaked = sorted(marker for marker in plan.markers if marker.encode("utf-8") in joined)
        if sidecar is not None:
            _publish_check(sidecar, {"schema": "appsec-review/judge-request-check/1", "cell_id": cell.cell_id,
                                  "attempt": cell.record.attempts, "markers_sha256": digest,
                                  "request_sha256s": [sha256_hex(item.decode("utf-8")) for item in cell.requests],
                                  "contains_forbidden_marker": bool(leaked), "leaked": leaked[:8]})
        return not leaked, (f"judge_request_contains_identifier:{leaked[0]}" if leaked else "")
    try:
        check = json.loads(sidecar.read_text(encoding="utf-8")) if sidecar is not None else None
    except (OSError, ValueError):
        check = None
    if not check or check.get("markers_sha256") != digest:
        return False, "judge_request_unverified"
    _consume_check(sidecar)
    if check.get("contains_forbidden_marker"):
        return False, f"judge_request_contains_identifier:{(check.get('leaked') or ['?'])[0]}"
    return True, ""


def _judge_relations(ctx: ReviewContext, cell: _Cell, claim_id: str, per_predicate: Mapping[str, Any],
                     seen: set[str]) -> tuple[list[EvidenceRelation], list[Gap]]:
    """Evidence relations from a judge\'s citations, with provenance ``adjudication_judge``.

    Siding with red on a predicate records ``supports`` for each direct citation, siding with blue ``contradicts``;
    a citation that is not a direct, complete row records ``qualifies``. ``both``, ``neither`` and ``unresolved``
    record none. Admissibility is the ordinary re-resolution; a judge cannot make a row direct.
    """
    relations: list[EvidenceRelation] = []
    gaps: list[Gap] = []
    receipt = cell.record.receipt_sha256 if cell.record else None
    for name, entry in sorted(per_predicate.items()):        # receipts store keys sorted; so does a fresh run
        verdict = entry["verdict"]
        if verdict not in (JudgeVerdictValue.RED_CORRECT.value, JudgeVerdictValue.BLUE_CORRECT.value):
            continue
        decided = RelationKind.SUPPORTS if verdict == JudgeVerdictValue.RED_CORRECT.value else RelationKind.CONTRADICTS
        for ref in entry["cites"]:
            resolved: EvidenceRelation | Gap | None = None
            for kind in (decided, RelationKind.QUALIFIES):
                resolved = resolve_relation(
                    ctx.core, claim_id=claim_id, predicate=Predicate(name), kind=kind, entity_id=ref,
                    producing_cell_id=cell.cell_id, retrieval_receipt_sha256=receipt if ref in seen else None,
                    rule_predicates=ctx.rule_predicates.get(ref, ()))
                if not isinstance(resolved, EvidenceRelation) or satisfies(resolved):
                    break                      # a gap, or a direct complete row, stands as decided
            if isinstance(resolved, EvidenceRelation):
                relations.append(replace(resolved, provenance=PROVENANCE))
            elif resolved is not None:
                gaps.append(resolved)
    return relations, gaps


def _judged(ctx: ReviewContext, plan: _JudgePlan, result: TeamResult) -> None:
    """Record one judge cell: its terminal record, and (when it answered and stayed blind) verdict and relations."""
    cell, claim = plan.cell, plan.group["claim"]
    _record(result, cell)
    entry: dict[str, Any] = {"cell_id": cell.cell_id, "status": cell.record.status.value, "verdict": None,
                             "judge_model_distinct": None}
    result.judging.setdefault(claim.claim_id, {}).setdefault("results", []).append(entry)
    if cell.record.status is not CellStatus.SUCCEEDED or cell.outcome.result is None:
        return
    blind, why = _judge_request_blind(plan)
    if not blind:
        # Fail closed: a verdict whose request could carry a side\'s identity is dropped, never trusted.
        result.gaps.append(make_gap(GapClass.AUTHORITY_ERROR, claim.claim_id, why))
        return
    document = cell.outcome.result
    settings = ctx.settings.judge
    named = {role.value for role in (settings.require_distinct_from_roles if settings else ())}
    compared = [_actor(other) for other in (*plan.group["cells"], *plan.blues) if other.spec.role.value in named]
    distinct = model_distinct(_actor(cell), compared)
    verdict = JudgeVerdict(
        verdict_id=make_id("judge_verdict", 1, {"claim_id": claim.claim_id, "cell_id": cell.cell_id}),
        claim_id=claim.claim_id, verdict=JudgeVerdictValue(document["verdict"]),
        per_predicate=tuple(JudgePredicateVerdict(Predicate(name), JudgeVerdictValue(item["verdict"]),
                                                  tuple(sorted(item["cites"])))
                            for name, item in sorted(document["per_predicate"].items())),
        reason=str(document["reason"]), cell_id=cell.cell_id, judge_model_distinct=distinct)
    found, failed = _judge_relations(ctx, cell, claim.claim_id, document["per_predicate"], _seen(cell))
    result.judge_verdicts.append(verdict)
    result.relations.extend(found)
    result.gaps.extend(failed)
    entry.update(verdict=verdict.verdict.value, judge_model_distinct=distinct, verdict_id=verdict.verdict_id)


def _normalize(ctx: ReviewContext, work: PackageWork, reds: list[_Cell], result: TeamResult) -> list[dict[str, Any]]:
    """Package-local normalization of admitted red results: one group per claim identity.

    Every succeeded red cell contributes its lead accounting, its named gaps and its chain seeds
    (a run-owned artifact, never claims); every proposal becomes a claim through
    ``normalize_claim``, merging exact duplicates across the package's red cells.
    """
    groups: dict[str, dict[str, Any]] = {}
    for cell in reds:
        if cell.record is None or cell.record.status is not CellStatus.SUCCEEDED or cell.outcome.result is None:
            continue
        red = cell.outcome.result
        seen = _seen(cell)
        result.lead_entries.extend((cell.cell_id, lead, outcome)
                                   for lead, outcome in sorted(red_discovery.lead_outcomes(red).items()))
        result.gaps.extend(_worker_gap(cell, item) for item in red_discovery.named_gaps(red))
        local_claims: dict[str, str] = {}
        for proposal in red["proposals"]:
            reference = str(proposal["local_id"])
            weakness = proposal["weakness"]
            try:
                normalized = normalize_claim(
                    lane=work.lane, package_id=work.package_id, affected_entities=proposal["affected_entities"],
                    weakness_cwe=weakness["id"] if weakness else None,
                    security_predicate=proposal["security_predicate"],
                    preconditions=proposal["attacker_entry"]["preconditions"], statement=proposal["statement"],
                    accepted_cwe_ids=ctx.accepted_cwe_ids, origin_cell_ids=(cell.cell_id,))
            except (ValueError, KeyError, TypeError) as exc:
                result.gaps.append(make_gap(GapClass.EVIDENCE_GAP, f"hypothesis:{cell.cell_id}:{reference}",
                                            f"gate:closed_vocabulary: {exc}"))
                result.triage.append({"cell_id": cell.cell_id, "claim_ref": reference, "claim_id": None,
                                      "decision": "rejected", "reason": "closed_vocabulary"})
                continue
            claim = normalized.claim
            local_claims[reference] = claim.claim_id
            if proposal.get("poc_basis") is not None:
                result.poc_basis.append({"claim_id": claim.claim_id, "package_id": work.package_id,
                                         "lane": work.lane.value, "cell_id": cell.cell_id,
                                         "poc_basis": dict(proposal["poc_basis"])})
            group = groups.setdefault(claim.claim_id, {"claim": claim, "cells": [], "items": [],
                                                       "gaps": [], "persona": cell.spec.persona})
            group["cells"].append(cell)
            group["items"].append((cell, proposal, red, seen))
            group["gaps"].extend(normalized.gaps)
        for seed in red_discovery.chain_seeds(red):
            steps = sorted({str(step["proposal_id"]) for step in seed["steps"] if step["proposal_id"]})
            result.chain_seeds.append({"package_id": work.package_id, "lane": work.lane.value,
                                       "cell_id": cell.cell_id, "seed_local_id": seed["local_id"],
                                       "proposal_claims": {local: local_claims.get(local) for local in steps},
                                       "seed": dict(seed)})
    ordered = []
    for claim_id in sorted(groups):
        group = groups[claim_id]
        cells = sorted({cell.cell_id for cell in group["cells"]})
        group["claim"] = replace(group["claim"], origin_cell_ids=tuple(cells))
        relations: dict[str, EvidenceRelation] = {}
        gaps = list({gap.gap_id: gap for gap in group["gaps"]}.values())
        requests: list[dict[str, Any]] = []
        for cell, proposal, red, seen in group["items"]:
            found, failed = _red_relations(ctx, cell, claim_id, red, proposal, seen)
            relations.update((relation.relation_id, relation) for relation in found)
            gaps.extend(failed)
            requests.extend(_requests(cell, claim_id, red_discovery.proposal_requests(red, proposal["local_id"])))
        group["relations"] = [relations[key] for key in sorted(relations)]
        group["relation_gaps"] = gaps
        group["requests"] = requests
        group["support"] = len({relation.predicate for relation in relations.values()
                                if relation.kind is RelationKind.SUPPORTS and satisfies(relation)})
        group["narratives"] = [text for _cell_, proposal, _red, _seen in group["items"]
                               for text in _markers(red_discovery.narratives(proposal))]
        ordered.append(group)
    return ordered


def _triage(ctx: ReviewContext, work: PackageWork, groups: list[dict[str, Any]],
            result: TeamResult) -> list[dict[str, Any]]:
    """Lane B gate then the deterministic cap; lane A only the cap. Every claim is proposed."""
    lanes = ctx.settings.lanes
    cap = lanes.hunt_max_claims_per_package if work.lane is Lane.HUNT else lanes.lead_max_claims_per_package
    candidates = []
    for group in groups:
        claim = group["claim"]
        result.claims.append(claim)
        result.gaps.extend(group["relation_gaps"])
        if work.lane is Lane.HUNT:
            unresolved = sorted(identity for _cell_, proposal, red, _seen in group["items"]
                                for identity in red_discovery.cited_entities(red, proposal)
                                if not ctx.resolves(identity))
            if unresolved:
                result.gaps.append(make_gap(GapClass.EVIDENCE_GAP, claim.claim_id,
                                            f"gate:unresolvable_citation ({len(unresolved)} identities)"))
                result.triage.append({"claim_id": claim.claim_id, "decision": "rejected",
                                      "reason": "unresolvable_citation", "support": group["support"]})
                continue
        candidates.append(group)
    candidates.sort(key=lambda group: (-group["support"], group["claim"].claim_id))
    admitted = candidates[:cap]
    for group in candidates[cap:]:
        claim_id = group["claim"].claim_id
        result.gaps.append(make_gap(GapClass.BUDGET_GAP, claim_id,
                                    f"triage: over the {work.lane.value} cap of {cap} claims per package"))
        result.triage.append({"claim_id": claim_id, "decision": "over_cap", "reason": "claims_per_package_cap",
                              "support": group["support"]})
    for group in admitted:
        result.triage.append({"claim_id": group["claim"].claim_id, "decision": "admitted", "reason": None,
                              "support": group["support"]})
        result.relations.extend(group["relations"])
        result.requests.extend(group["requests"])
    return admitted


def _actor(cell: _Cell) -> ActorRecord:
    return ActorRecord(actor_id=make_id("actor", 1, {"cell_id": cell.cell_id}), provider=cell.spec.provider,
                       model=cell.spec.model, conversation_id=cell.cell_id)


def _review(ctx: ReviewContext, group: Mapping[str, Any], blues: tuple[_Cell, _Cell], verifier: _Cell,
            result: TeamResult) -> None:
    claim: Claim = group["claim"]
    markers = list(group["narratives"])
    for cell in (*blues, verifier):
        _record(result, cell)
    # Decision 2: recorded from the cells' configured model profiles whatever the verifier's outcome.
    verifier_model_distinct = model_distinct(_actor(verifier), [_actor(cell) for cell in group["cells"]])
    for cell in blues:
        if cell.record.status is CellStatus.SUCCEEDED and cell.outcome.result is not None:
            found, failed = _relations(ctx, cell, claim.claim_id, cell.outcome.result.get("proposed_relations", ()),
                                       _seen(cell))
            result.relations.extend(found)
            result.gaps.extend(failed)
            result.requests.extend(_requests(cell, claim.claim_id, cell.outcome.result.get("evidence_requests", ())))
            markers.extend(_narratives(cell.outcome.result))
    if verifier.record.status is not CellStatus.SUCCEEDED or verifier.outcome.result is None:
        terminal = [gap for gap in verifier.outcome.gaps if gap.gap_class is not GapClass.AUTHORITY_ERROR]
        result.verifier_gaps[claim.claim_id] = [gap_json(gap) for gap in terminal]
        result.independence.setdefault(claim.claim_id, []).append({
            "verifier_cell_id": verifier.cell_id, "independent": False, "provider_distinct": False,
            "verifier_model_distinct": verifier_model_distinct, "review_id": None, "gap_ids": sorted(gap.gap_id for gap in terminal), "status": verifier.record.status.value})
        return
    seen = _seen(verifier)
    found, failed = _relations(ctx, verifier, claim.claim_id, verifier.outcome.result.get("proposed_relations", ()),
                               seen)
    result.relations.extend(found)
    result.gaps.extend(failed)
    result.requests.extend(_requests(verifier, claim.claim_id, verifier.outcome.result.get("evidence_requests", ())))
    others = [_actor(cell) for cell in (*group["cells"], *blues)]
    marker_digest = sha256_hex(sorted(set(markers)))
    request_bytes = _verifier_request_bytes(ctx, verifier, markers, marker_digest)
    independent, gaps = verify_independence(
        _actor(verifier), others, request_bytes, markers, found, required_predicates_for(claim),
        {verifier.record.receipt_sha256} if verifier.record.receipt_sha256 else set(), claim_id=claim.claim_id)
    result.gaps.extend(gaps)
    result.independence.setdefault(claim.claim_id, []).append({
        "verifier_cell_id": verifier.cell_id, "independent": independent,
        "provider_distinct": provider_distinct(_actor(verifier), others),
        "verifier_model_distinct": verifier_model_distinct,
        "review_id": make_id("review", 1, {"cell_id": verifier.cell_id, "claim_id": claim.claim_id}),
        "gap_ids": sorted(gap.gap_id for gap in gaps), "status": verifier.record.status.value})


def _verifier_request_bytes(ctx: ReviewContext, verifier: _Cell, markers: Sequence[str], digest: str) -> bytes:
    """The verifier's stored request bytes for the R6 check.

    A fresh run checks the exact request bytes and records the result next to the cell receipt
    (hashes only). A reused cell sent no request; its recorded check is used when the forbidden
    markers are unchanged, and otherwise the check fails closed.
    """
    sidecar = ctx.receipts_root / verifier.cell_id / f"independence-attempt-{verifier.record.attempts}.json"
    if verifier.requests:
        joined = b"\n".join(verifier.requests)
        encoded = [marker.encode("utf-8") for marker in markers]
        _publish_check(sidecar, {"schema": "appsec-review/verifier-request-check/1", "cell_id": verifier.cell_id,
                              "attempt": verifier.record.attempts, "markers_sha256": digest,
                              "request_sha256s": [sha256_hex(item.decode("utf-8")) for item in verifier.requests],
                              "contains_forbidden_marker": any(marker in joined for marker in encoded)})
        return joined
    try:
        check = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        check = None
    if not check or check.get("markers_sha256") != digest or check.get("contains_forbidden_marker"):
        # Fail closed: the forbidden marker itself stands in for unverifiable request bytes.
        return markers[0].encode("utf-8") if markers else b"\x00unverified-verifier-request"
    _consume_check(sidecar)
    return b""


def _publish_check(path: Path, document: Mapping[str, Any]) -> None:
    from appsec_review.storage import canonical_json
    from appsec_review.storage.shared import current, publish_named
    owner = current()
    publish_named(owner.run_root if owner is not None else path.parent, path,
                  canonical_json(document), namespace="cell-check",
                  computation={"cell_id": document["cell_id"],
                               "markers_sha256": document["markers_sha256"]})


def _consume_check(path: Path) -> None:
    from appsec_review.storage.shared import current, consume_named
    owner = current()
    if owner is not None:
        consume_named(owner.run_root, path, namespace="cell-check")


# ------------------------------------------------------------------------------------------------
# One lane


def run_lane(ctx: ReviewContext, lane: Lane, packages: Sequence[PackageWork], *, other_lane_count: int,
             ledger_path: Path, stream: str, signal_dir: Path) -> dict[str, Any]:
    """Run every package of ``lane`` and seal the lane's ledger shard; returns the lane document."""
    ordered = sorted(packages, key=lambda item: (item.rank, item.package_id))
    counts = {Lane.LEAD: len(ordered), Lane.HUNT: other_lane_count} if lane is Lane.LEAD else {
        Lane.LEAD: other_lane_count, Lane.HUNT: len(ordered)}
    allocation = lane_allocation(counts[Lane.LEAD], counts[Lane.HUNT], ctx.settings.lanes.lead_budget_share,
                                 ctx.settings.budgets.budget_team_packages)
    _signal(signal_dir, lane, ordered, allocation, queue_empty=False)
    other = Lane.HUNT if lane is Lane.LEAD else Lane.LEAD
    declared = _read_signal(signal_dir, other)
    if declared is not None and int(declared["declared"]) != counts[other]:
        raise IntegrityError(f"lane {other.value} declared a different package queue than the accepted manifest")
    launches = allocation[lane]
    with ThreadPoolExecutor(max_workers=max(1, ctx.settings.teams.review_teams), thread_name_prefix=lane.value) as pool:
        futures = [pool.submit(run_team, ctx, work, launch=index < launches,
                               not_launched_reason=(f"lane {lane.value} team-package allocation of {launches} "
                                                    f"exhausted (budget_team_packages)"))
                   for index, work in enumerate(ordered)]
        teams = [future.result() for future in futures]
    _signal(signal_dir, lane, ordered, allocation, queue_empty=True)
    return _seal(ctx, lane, teams, allocation, ledger_path, stream)


def lane_failure(lane: Lane, packages: Sequence[PackageWork], reason: str, ledger_path: Path, stream: str) -> dict[str, Any]:
    """A lane that could not start: every package is a gapped package and the shard records it."""
    teams = []
    for work in sorted(packages, key=lambda item: (item.rank, item.package_id)):
        team = TeamResult(work.package_id, lane, work.unit_key, leads=_lead_ids(work))
        team.gaps.append(make_gap(GapClass.WORKER_GAP, work.package_id, f"lane failure: {reason}"))
        teams.append(team)
    return _seal(None, lane, teams, {Lane.LEAD: 0, Lane.HUNT: 0}, ledger_path, stream)


def _signal(signal_dir: Path, lane: Lane, ordered: Sequence[PackageWork], allocation: Mapping[Lane, int], *,
            queue_empty: bool) -> None:
    atomic_json(Path(signal_dir) / f"{lane.value}.json", {
        "schema": "appsec-review/inference-review-lane-queue/1", "lane": lane.value, "declared": len(ordered),
        "package_ids": [work.package_id for work in ordered],
        "allocation": {key.value: value for key, value in allocation.items()}, "queue_empty": queue_empty})


def _read_signal(signal_dir: Path, lane: Lane) -> Mapping[str, Any] | None:
    try:
        return json.loads((Path(signal_dir) / f"{lane.value}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _seal(ctx: ReviewContext | None, lane: Lane, teams: Sequence[TeamResult], allocation: Mapping[Lane, int],
          ledger_path: Path, stream: str) -> dict[str, Any]:
    writer = LedgerWriter(ledger_path, stream)
    gaps: dict[str, Gap] = {}
    for team in teams:
        for claim in team.claims:
            writer.propose_claim(claim)
        for relation in sorted({item.relation_id: item for item in team.relations}.values(),
                               key=lambda item: item.relation_id):
            writer.add_relation(relation)
        for verdict in sorted(team.judge_verdicts, key=lambda item: item.verdict_id):
            writer.judge_verdict(verdict)
        for request in sorted({item["request_id"]: item for item in team.requests}.values(),
                              key=lambda item: item["request_id"]):
            writer.open_request(request["request_id"], request["claim_id"], Predicate(request["predicate"]),
                                request["requested_kind"], origin_cell_id=request["origin_cell_id"])
            writer.close_request(request["request_id"], request["claim_id"], EvidenceRequestOutcome.UNSATISFIED,
                                 reason="slice 1 runs round 0 only; no evidence-resolution round follows")
        for gap in team.gaps:
            gaps.setdefault(gap.gap_id, gap)
    for gap_id in sorted(gaps):
        writer.record_gap(gaps[gap_id])
    for team in teams:
        for record in team.cells:
            writer.cell_terminal(record)
    receipt = writer.seal()
    seeds_path = Path(ledger_path).with_name("chain-seeds.json")
    seeds = _chain_seed_artifact(lane, teams, seeds_path, ctx.settings.red_output.max_chain_seeds if ctx else 0)
    expected_cells = {record.cell_id: lane.value for team in teams for record in team.cells}
    document = {
        "schema": LANE_SCHEMA, "lane": lane.value,
        "allocation": {key.value: value for key, value in allocation.items()},
        "packages": {team.package_id: lane.value for team in teams},
        "launched": sorted(team.package_id for team in teams if team.launched),
        "expected_cells": dict(sorted(expected_cells.items())),
        "proposals": {claim.claim_id: sorted({team.package_id for team in teams for item in team.claims
                                              if item.claim_id == claim.claim_id})
                      for team in teams for claim in team.claims},
        "independence": _merge_lists(team.independence for team in teams),
        "verifier_gaps": _merge_lists(team.verifier_gaps for team in teams),
        "judging": {claim_id: value for team in teams for claim_id, value in sorted(team.judging.items())},
        "routing": {team.package_id: team.routing for team in teams},
        "triage": {team.package_id: team.triage for team in teams},
        "lead_accounting": {team.package_id: _lead_summary(team) for team in teams},
        "chain_seeds": seeds,
        "poc_basis": _poc_basis_artifact(lane, teams, Path(ledger_path).with_name("poc-basis.json")),
        "coverage": [row for team in teams for row in team.coverage],
        "capabilities": [row for team in teams for row in team.capabilities],
        "security_events": [dict(event) for team in teams for event in team.security_events],
        "counts": {key: sum(team.counts[key] for team in teams)
                   for key in ("cells_run", "cells_reused", "cells_not_launched")},
        "ledger_shard": {"path": str(ledger_path), "stream": stream, "events": receipt.event_count,
                         "sha256": file_sha256(ledger_path)},
    }
    document["counts"].update(claims=len({claim.claim_id for team in teams for claim in team.claims}),
                              cells=len(expected_cells), gaps=len(gaps))
    return document


def _lead_summary(team: TeamResult) -> dict[str, dict[str, Any]]:
    """Each package lead across the package's succeeded red cells (``red_discovery.summarize_lead``).

    ``no_proposal`` is never clean coverage; ``unaccounted`` means no red cell of the package
    succeeded (its cells already carry the terminal gaps).
    """
    entries: dict[str, dict[str, str]] = {lead: {} for lead in team.leads}
    for cell_id, lead, outcome in team.lead_entries:
        entries.setdefault(lead, {})[cell_id] = outcome
    return {lead: {"outcome": red_discovery.summarize_lead(list(cells.values())), "cells": dict(sorted(cells.items()))}
            for lead, cells in sorted(entries.items())}


def _chain_seed_artifact(lane: Lane, teams: Sequence[TeamResult], path: Path, per_cell: int) -> dict[str, Any]:
    """Persist the lane's red chain seeds for the later chain-composition slice; they are not claims.

    The artifact is bounded: each red cell contributes at most ``settings.red_output.max_chain_seeds``
    admitted seeds, so it holds at most that many per red cell of the lane.
    """
    seeds = sorted((seed for team in teams for seed in team.chain_seeds),
                   key=lambda item: (item["package_id"], item["cell_id"], item["seed_local_id"]))
    cells = {record.cell_id for team in teams for record in team.cells}
    if len(seeds) > per_cell * max(1, len(cells)):
        raise IntegrityError("admitted chain seeds exceed the configured per-cell bound")
    atomic_json(path, {"schema": CHAIN_SEEDS_SCHEMA, "lane": lane.value,
                       "statement": "red chain seeds are hypotheses for later chain composition; they are "
                                    "not claims, findings or confirmed chains",
                       "seeds": seeds})
    return {"path": str(path), "schema": CHAIN_SEEDS_SCHEMA, "count": len(seeds), "sha256": file_sha256(path)}


def _poc_basis_artifact(lane: Lane, teams: Sequence[TeamResult], path: Path) -> dict[str, Any]:
    """Persist the red cells\' proof-of-concept briefs beside the claims, for a later PoC-generation job.

    A brief is neither a claim, nor evidence, nor executable: nothing in adjudication, scoring or the report reads
    it.
    """
    entries = sorted((item for team in teams for item in team.poc_basis),
                     key=lambda item: (item["claim_id"], item["cell_id"]))
    atomic_json(path, {"schema": POC_BASIS_SCHEMA, "lane": lane.value,
                       "statement": "proof-of-concept briefs are inputs to a later job; they are not claims, evidence "
                                    "or executable code, and no claim state depends on them",
                       "briefs": entries})
    return {"path": str(path), "schema": POC_BASIS_SCHEMA, "count": len(entries), "sha256": file_sha256(path)}


def _merge_lists(items: Iterable[Mapping[str, list[Any]]]) -> dict[str, list[Any]]:
    merged: dict[str, list[Any]] = defaultdict(list)
    for item in items:
        for key, values in item.items():
            merged[key].extend(values)
    return {key: merged[key] for key in sorted(merged)}
