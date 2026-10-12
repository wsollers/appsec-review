"""Review-team handler for one intake lane (design "Two-lane intake and review teams", R1, R2, R6).

A lane unit takes its packages in canonical order (rank, then ``package_id``) and launches one
review team per package under the run-wide :class:`ReviewTeamSemaphore`, the deterministic
fair-share allocation, and the attempt's :class:`JobBudget`. A team runs:

1. three red cells (lane A: ``red_team_analyst`` with the stack, preconditions and failure-mode
   lenses; lane B: the ``hunt-panel/1`` (strategy, persona) pairs as ``hypothesis_hunter``);
2. package-local normalization (``review.claims``), then the lane B triage gate or the lane A cap;
3. for every admitted claim, ``blue_control`` and ``blue_reachability`` refuters and one blind
   ``independent_verifier`` whose request carries only the claim's identity fields.

Every cell runs through ``review.cells.reuse_or_run``; every cited relation is re-resolved through
``review.evidence.resolve_relation``; every failure is a typed gap with exactly one terminal cell
record. Only :class:`IntegrityError` propagates. The lane's events are sealed into one ledger shard.
"""
from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
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
from appsec_review.review.capability import IN_PROCESS_TOOLS, CellCapability
from appsec_review.review.cells import CellBudgetExceeded, CellOutcome, CellSpec, cell_fingerprint, reuse_or_run
from appsec_review.review.claims import normalize_claim
from appsec_review.review.evidence import resolve_relation, satisfies
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.independence import ActorRecord, provider_distinct, verify_independence
from appsec_review.review.ledger import EvidenceRequestOutcome, LedgerWriter, gap_json
from appsec_review.review.models import (
    BlueTask, CellRecord, CellStatus, Claim, EvidenceRelation, Gap, GapClass, IntegrityError, Lane, Predicate,
    RelationKind, Role, make_gap,
)
from appsec_review.review.obligations import required_predicates
from appsec_review.review.teams import FairShareScheduler, QueuedPackage, ReviewTeamSemaphore, TeamUnavailable
from appsec_review.storage import atomic_json, file_sha256

from .schemas import SchemaSet

LANE_SCHEMA = "appsec-review/inference-review-lane/1"
VALIDATOR_VERSION = "inference-review-results/1"
RESULT_SCHEMAS = {Role.RED_TEAM_ANALYST: "red-result", Role.HYPOTHESIS_HUNTER: "red-result",
                  Role.BLUE_TEAM_REFUTER: "blue-result", Role.INDEPENDENT_VERIFIER: "verifier-result"}
OUTPUT_SCHEMAS = {name: f"appsec-review/{name}/1" for name in ("red-result", "blue-result", "verifier-result")}
LEAD_LENSES = ("lead_red_stack", "lead_red_preconditions", "lead_red_failure_modes")
VERIFIER_TASK = "blind_verifier"
# Relation kinds each role may author (the registry ``outputs`` of each role; red evidence travels
# with its proposed claim). Anything else is a schema error and never reaches the ledger.
ROLE_RELATION_KINDS = {
    Role.RED_TEAM_ANALYST: frozenset({RelationKind.SUPPORTS, RelationKind.QUALIFIES}),
    Role.HYPOTHESIS_HUNTER: frozenset({RelationKind.SUPPORTS, RelationKind.QUALIFIES}),
    Role.BLUE_TEAM_REFUTER: frozenset({RelationKind.CONTRADICTS, RelationKind.QUALIFIES}),
    Role.INDEPENDENT_VERIFIER: frozenset({RelationKind.SUPPORTS, RelationKind.CONTRADICTS, RelationKind.QUALIFIES}),
}
MIN_MARKER_CHARACTERS = 16
MAX_RESULT_BYTES = 64 * 1024
SANITIZED_PACKAGE_KEYS = frozenset({"package_id", "manifest_sha256", "input_fingerprint", "run_id"})


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

    def view(self, routing: Mapping[str, Any]) -> dict[str, Any]:
        """The package as a worker sees it: run/manifest identities removed, routing set."""
        body = {key: value for key, value in self.document.items() if key not in SANITIZED_PACKAGE_KEYS}
        body["persona"] = routing.get("persona")
        body["stack_profile"] = routing.get("stack")
        return body


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
    _resolves: dict[str, bool] = field(default_factory=dict)
    _names: dict[str, str | None] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def profile(self, role: Role) -> ModelProfileSettings:
        return self.settings.profile_for(role)

    def bundle(self, *, role: Role, persona: str, stack: str, task: str, lane: Lane,
               capability: CellCapability) -> dict[str, Any]:
        """Compose (once) and pin a hash-pinned guidance bundle; conflicting guidance raises."""
        receipt = {"granted_tools": list(capability.tools), "max_queries": capability.max_queries,
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
            pin = identity not in self._pinned
            self._pinned.add(identity)
        if pin:
            pin_bundle(self.run_root, cached["bundle"])
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
    launched: bool = False
    counts: dict[str, int] = field(default_factory=lambda: {"cells_run": 0, "cells_reused": 0,
                                                            "cells_not_launched": 0})


@dataclass
class _Cell:
    spec: CellSpec
    capability: CellCapability
    kind: str                            # red | blue | verifier
    strategy: str | None = None
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


def _claim_view(claim: Claim, *, statement: bool) -> dict[str, Any]:
    view = {"claim_id": claim.claim_id, "affected_entities": list(claim.affected_entities),
            "weakness_cwe": claim.weakness_cwe, "security_predicate": claim.security_predicate,
            "preconditions": list(claim.preconditions),
            "required_predicates": sorted(item.value for item in required_predicates(claim.preconditions))}
    if statement:
        view["statement"] = claim.statement
    return view


def _cell(ctx: ReviewContext, work: PackageWork, routing: Mapping[str, Any], *, role: Role, persona: str,
          task: str, kind: str, task_input: Mapping[str, Any], claim: Claim | None = None,
          strategy: str | None = None) -> _Cell:
    profile = ctx.profile(role)
    tools = tuple(sorted(set(ctx.role_tools.get(role.value, ())) & IN_PROCESS_TOOLS))
    capability = CellCapability.issue(
        run_id=ctx.run_id, manifest_sha256=ctx.core.manifest_sha256, package_id=work.package_id,
        package_sha256=work.sha256, role=role, round=0, tools=tools,
        indexes=tuple(name for name in ctx.index_names if name in INDEX_NAMES), entities=work.entities,
        max_queries=max(1, profile.max_queries), max_turns=profile.max_turns,
        page_size=min(100, ctx.max_page_size), max_depth=min(8, ctx.max_depth), max_result_bytes=MAX_RESULT_BYTES)
    stack = str(routing["stack"])
    guidance = ctx.bundle(role=role, persona=persona, stack=stack, task=task, lane=work.lane, capability=capability)
    schema = RESULT_SCHEMAS[role]
    spec = CellSpec(
        manifest_sha256=ctx.core.manifest_sha256, lane=work.lane, package_id=work.package_id,
        package_sha256=work.sha256, claim_id=claim.claim_id if claim else None, role=role, persona=persona,
        stack_profile=stack, strategy=strategy, task=task, task_input=dict(task_input), round=0,
        round_delta_sha256=None, evidence_set=tuple(sorted(set(work.entities))),
        guidance_bundle_sha256=guidance["bundle"]["sha256"], guidance_text=guidance["text"],
        provider=profile.provider, model=profile.model, reasoning=profile.reasoning,
        max_input_tokens=profile.max_input_tokens, max_output_tokens=profile.max_output_tokens,
        timeout_seconds=profile.timeout_seconds, output_schema=OUTPUT_SCHEMAS[schema],
        validator_version=VALIDATOR_VERSION, reuse_basis=work.basis)
    return _Cell(spec, capability, kind, strategy)


def _validator(ctx: ReviewContext, role: Role, *, claim_id: str | None = None,
               task: str | None = None) -> Callable[[Mapping[str, Any]], list[str]]:
    schema = RESULT_SCHEMAS[role]

    def validate(result: Mapping[str, Any]) -> list[str]:
        errors = ctx.schemas.errors(schema, result)
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
                                    rule_predicates=ctx.rule_predicates.get(entity, ()))
        (relations if isinstance(resolved, EvidenceRelation) else gaps).append(resolved)
    return relations, gaps


def _requests(cell: _Cell, claim_id: str, items: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    found = []
    for item in items:
        body = {"claim_id": claim_id, "predicate": item["predicate"], "requested_kind": item["requested_kind"],
                "anchors": sorted(item.get("anchors", ())), "origin_cell_id": cell.cell_id}
        found.append({**body, "request_id": make_id("evidence_request", 1, body)})
    return found


def _narratives(result: Mapping[str, Any] | None, claim_ref: Mapping[str, Any] | None = None) -> list[str]:
    texts: list[str] = []
    if claim_ref is not None:
        texts.append(str(claim_ref.get("statement", "")))
        texts.extend(str(item.get("rationale", "")) for item in claim_ref.get("proposed_relations", ()))
    elif result is not None:
        texts.append(str(result.get("rationale", "")))
        texts.extend(str(item.get("rationale", "")) for item in result.get("proposed_relations", ()))
    return [text for text in texts if len(text.strip()) >= MIN_MARKER_CHARACTERS]


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
    view = work.view(routing)
    if work.lane is Lane.LEAD:
        return [_cell(ctx, work, routing, role=Role.RED_TEAM_ANALYST, persona=routing["persona"], task=lens,
                      kind="red", task_input={"package": view, "lens": lens})
                for lens in LEAD_LENSES[:ctx.settings.teams.red_per_team]]
    return [_cell(ctx, work, routing, role=Role.HYPOTHESIS_HUNTER, persona=item["persona"], task=item["strategy"],
                  kind="red", strategy=item["strategy"],
                  task_input={"package": view, "strategy": item["strategy"], "known_claims": []})
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
    result = TeamResult(work.package_id, work.lane, work.unit_key)
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
        failed = TeamResult(work.package_id, work.lane, work.unit_key, routing=result.routing, launched=True)
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
        futures = [pool.submit(_run, ctx, cell, _validator(ctx, cell.spec.role)) for cell in reds]
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
        blue_input = {"claim": _claim_view(claim, statement=True), "package_entities": list(work.entities)}
        verifier_input = {"claim": _claim_view(claim, statement=False), "package_entities": list(work.entities)}
        control = _cell(ctx, work, routing, role=Role.BLUE_TEAM_REFUTER, persona=group["persona"],
                        task=BlueTask.CONTROL.value, kind="blue", claim=claim,
                        task_input={**blue_input, "task": BlueTask.CONTROL.value})
        reach = _cell(ctx, work, routing, role=Role.BLUE_TEAM_REFUTER, persona=group["persona"],
                      task=BlueTask.REACHABILITY.value, kind="blue", claim=claim,
                      task_input={**blue_input, "task": BlueTask.REACHABILITY.value})
        verifier = _cell(ctx, work, routing, role=Role.INDEPENDENT_VERIFIER, persona=group["persona"],
                         task=VERIFIER_TASK, kind="verifier", claim=claim, task_input=verifier_input)
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
    for group, control, reach, verifier in reviews:
        _review(ctx, group, (control, reach), verifier, result)


def _normalize(ctx: ReviewContext, work: PackageWork, reds: list[_Cell], result: TeamResult) -> list[dict[str, Any]]:
    """Package-local normalization: one group per claim identity, merging every red proposal."""
    groups: dict[str, dict[str, Any]] = {}
    for cell in reds:
        if cell.record is None or cell.record.status is not CellStatus.SUCCEEDED or cell.outcome.result is None:
            continue
        seen = _seen(cell)
        for index, item in enumerate(cell.outcome.result.get("claims", ())):
            reference = str(item.get("claim_ref", index))
            try:
                normalized = normalize_claim(
                    lane=work.lane, package_id=work.package_id, affected_entities=item["affected_entities"],
                    weakness_cwe=item["weakness_cwe"], security_predicate=item["security_predicate"],
                    preconditions=item["preconditions"], statement=item["statement"],
                    accepted_cwe_ids=ctx.accepted_cwe_ids, origin_cell_ids=(cell.cell_id,))
            except (ValueError, KeyError, TypeError) as exc:
                result.gaps.append(make_gap(GapClass.EVIDENCE_GAP, f"hypothesis:{cell.cell_id}:{reference}",
                                            f"gate:closed_vocabulary: {exc}"))
                result.triage.append({"cell_id": cell.cell_id, "claim_ref": reference, "claim_id": None,
                                      "decision": "rejected", "reason": "closed_vocabulary"})
                continue
            claim = normalized.claim
            group = groups.setdefault(claim.claim_id, {"claim": claim, "cells": [], "items": [],
                                                       "gaps": [], "persona": cell.spec.persona})
            group["cells"].append(cell)
            group["items"].append((cell, item, seen))
            group["gaps"].extend(normalized.gaps)
    ordered = []
    for claim_id in sorted(groups):
        group = groups[claim_id]
        cells = sorted({cell.cell_id for cell in group["cells"]})
        group["claim"] = replace(group["claim"], origin_cell_ids=tuple(cells))
        relations: dict[str, EvidenceRelation] = {}
        gaps = list({gap.gap_id: gap for gap in group["gaps"]}.values())
        requests: list[dict[str, Any]] = []
        for cell, item, seen in group["items"]:
            found, failed = _relations(ctx, cell, claim_id, item.get("proposed_relations", ()), seen)
            relations.update((relation.relation_id, relation) for relation in found)
            gaps.extend(failed)
            requests.extend(_requests(cell, claim_id, item.get("evidence_requests", ())))
        group["relations"] = [relations[key] for key in sorted(relations)]
        group["relation_gaps"] = gaps
        group["requests"] = requests
        group["support"] = len({relation.predicate for relation in relations.values()
                                if relation.kind is RelationKind.SUPPORTS and satisfies(relation)})
        group["narratives"] = [text for _cell_, item, _seen in group["items"] for text in _narratives(None, item)]
        ordered.append(group)
    return ordered


def _cited(item: Mapping[str, Any]) -> set[str]:
    cited = set(item.get("affected_entities", ()))
    for values in (item.get("citations") or {}).values():
        cited.update(values)
    cited.update(relation["entity_id"] for relation in item.get("proposed_relations", ()))
    return cited


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
            unresolved = sorted(identity for _cell_, item, _seen in group["items"] for identity in _cited(item)
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
            "review_id": None, "gap_ids": sorted(gap.gap_id for gap in terminal), "status": verifier.record.status.value})
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
        _actor(verifier), others, request_bytes, markers, found, required_predicates(claim.preconditions),
        {verifier.record.receipt_sha256} if verifier.record.receipt_sha256 else set(), claim_id=claim.claim_id)
    result.gaps.extend(gaps)
    result.independence.setdefault(claim.claim_id, []).append({
        "verifier_cell_id": verifier.cell_id, "independent": independent,
        "provider_distinct": provider_distinct(_actor(verifier), others),
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
        atomic_json(sidecar, {"schema": "appsec-review/verifier-request-check/1", "cell_id": verifier.cell_id,
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
    return b""


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
        team = TeamResult(work.package_id, lane, work.unit_key)
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
        "routing": {team.package_id: team.routing for team in teams},
        "triage": {team.package_id: team.triage for team in teams},
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


def _merge_lists(items: Iterable[Mapping[str, list[Any]]]) -> dict[str, list[Any]]:
    merged: dict[str, list[Any]] = defaultdict(list)
    for item in items:
        for key, values in item.items():
            merged[key].extend(values)
    return {key: merged[key] for key in sorted(merged)}
