"""Canonical evidence-obligation lifecycle and warranted reconciliation (``evidence-obligation/1``, TRI-C / T-153).

Follow-up investigation cells (red, blue, independent verifier) emit bounded ``evidence_requests``.
This module provides the single canonical semantic lifecycle for those requests:

1. **Canonical obligation identity (``obligation_id``)**: hashes ``claim_id``, ``predicate``,
   normalized ``subject_binding``, sorted ``anchors``, ``scope_ceiling``, ``requested_kind``,
   canonicalized ``question``, and ``OBLIGATION_POLICY_VERSION`` — excluding originating cell and
   round. Repeated equivalent requests across cells or rounds coalesce into one canonical obligation
   while preserving all ``origin_request_ids``, ``origin_cell_ids``, and ``round_opened``.
   ``obligation_id`` is the canonical request ID shared directly with ``HUNT-C`` (``T-156``).
2. **Deterministic warranted reconciliation**: evaluates admitted ``EvidenceRelation`` records and
   proposition-bound ``PredicateWarrant`` verdicts (``review/warrants.py``) against the obligation's
   claim, predicate, anchors/subject binding, ``requested_kind``, ``completeness_required``,
   ``scope_ceiling``, and ``admissible_producer_ids``.
   - Warranted ``ESTABLISHED_SUPPORT`` or ``ESTABLISHED_CONTRADICTION`` satisfies the obligation
     (an answered question may either support or refute the claim).
   - Matching both warranted support and warranted contradiction on the same obligation remains
     ``unsatisfied`` with ``reason_code = "unresolved_contradiction"`` rather than picking a side.
   - Matching only a predicate string on an unrelated anchor, subject, or incompatible evidence kind
     never resolves a different obligation.
3. **Transport vs. semantic resolution (``HUNT-C`` join contract)**: transport/delivery receipts
   (``coverage_receipt_refs``) prove bytes were served or denied, never that the question was
   answered. Legacy delivery-only receipts without a bound ``TRI-C`` resolution retain explicit
   ``legacy_resolution_unknown`` semantic status rather than becoming ``satisfied``.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
import re
from typing import AbstractSet, Any

from appsec_review.retrieval.core import RetrievalCore, RetrievalGap, RetrievalIntegrityError
from appsec_review.retrieval.model import EntityKind, LogicalIdentity, RelationKind as IndexRelation
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import (
    Admissibility, CellRecord, CellStatus, Claim, EvidenceRelation, Gap, GapClass,
    IntegrityError, Predicate, RelationKind, SecurityPredicate,
)
from appsec_review.review.numeric_reasoning import is_numeric_weakness
from appsec_review.review.warrants import (
    PredicateWarrant, SubjectBinding, UNCOMMISSIONED_GUARD_SECURITY_PREDICATES, WarrantCoverage,
    WarrantReasonCode, WarrantResult, WarrantScope, bind_claim_subject, evaluate_warrant,
)

OBLIGATION_SCHEMA = "appsec-review/evidence-obligation/1"
LANE_OBLIGATIONS_SCHEMA = "appsec-review/lane-evidence-obligations/1"
OBLIGATION_POLICY_VERSION = "evidence-obligation/1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_OBLIGATION_ID_RE = re.compile(r"^evob-[0-9a-f]{64}$")
_REQUEST_ID_RE = re.compile(r"^evreq-[0-9a-f]{64}$")
_CLAIM_ID_RE = re.compile(r"^claim-[0-9a-f]{64}$")
_CELL_ID_RE = re.compile(r"^cell-[0-9a-f]{64}$")
_RELATION_ID_RE = re.compile(r"^evrel-[0-9a-f]{64}$")
_WARRANT_ID_RE = re.compile(r"^warrant-[0-9a-f]{64}$")
_GAP_ID_RE = re.compile(r"^gap-[0-9a-f]{64}$")
_WHITESPACE_RE = re.compile(r"\s+")
_TRAILING_PUNCT_RE = re.compile(r"[?.!;:]+$")

_ABSTRACT_REQUESTED_KINDS: frozenset[str] = frozenset({
    "source_line", "compiled_view", "dataflow", "configuration",
    "build_provenance", "deployment", "run_artifact", "other",
})
_ENTITY_KIND_VALUES: frozenset[str] = frozenset(item.value for item in EntityKind)
VALID_REQUESTED_KINDS: frozenset[str] = _ABSTRACT_REQUESTED_KINDS | _ENTITY_KIND_VALUES

_CONSTRUCT_ENTITY_KINDS: frozenset[EntityKind] = frozenset({
    EntityKind.SOURCE_SPAN, EntityKind.AST_NODE, EntityKind.SYMBOL,
    EntityKind.CALL_SITE, EntityKind.SINK_SITE,
    EntityKind.BINARY_FUNCTION, EntityKind.BINARY_CALL_SITE,
})

_KIND_COMPATIBILITY: Mapping[str, frozenset[EntityKind]] = {
    "source_line": frozenset({
        EntityKind.SOURCE_SPAN, EntityKind.AST_NODE, EntityKind.SYMBOL,
        EntityKind.CALL_SITE, EntityKind.SINK_SITE,
    }),
    "compiled_view": frozenset({
        EntityKind.IR_ENTITY, EntityKind.OBJECT_FILE, EntityKind.LIBRARY,
        EntityKind.EXECUTABLE, EntityKind.BINARY_FUNCTION, EntityKind.BINARY_CALL_SITE,
        EntityKind.BYTECODE_MODULE, EntityKind.MANAGED_ASSEMBLY, EntityKind.WASM_MODULE,
    }),
    "dataflow": frozenset({
        EntityKind.DATAFLOW_PATH, EntityKind.ENTRY_POINT,
        EntityKind.GUARD_FACT, EntityKind.RANGE_FACT,
    }),
    "configuration": frozenset({
        EntityKind.BUILD_ACTION, EntityKind.COMPILE_UNIT,
        EntityKind.EVIDENCE_ARTIFACT, EntityKind.PACKAGE,
    }),
    "build_provenance": frozenset({
        EntityKind.BUILD_ACTION, EntityKind.COMPILE_UNIT, EntityKind.BUILD_ARTIFACT,
        EntityKind.OBJECT_FILE, EntityKind.LIBRARY, EntityKind.EXECUTABLE,
        EntityKind.PACKAGE, EntityKind.ARCHIVE_MEMBER,
    }),
    "deployment": frozenset({
        EntityKind.BUILD_ARTIFACT, EntityKind.EVIDENCE_ARTIFACT,
        EntityKind.PACKAGE, EntityKind.ARCHIVE_MEMBER, EntityKind.EXECUTABLE,
    }),
    "run_artifact": frozenset({
        EntityKind.EVIDENCE_ARTIFACT, EntityKind.BUILD_ARTIFACT,
    }),
    "other": frozenset(EntityKind),
}

_TRACE_RELATIONS: tuple[str, ...] = tuple(item.value for item in IndexRelation)


class ObligationState(StrEnum):
    OPEN = "open"
    SATISFIED = "satisfied"
    UNSATISFIED = "unsatisfied"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"


class ObligationReasonCode(StrEnum):
    OPEN_PENDING = "open_pending"
    SATISFIED_BY_WARRANTED_EVIDENCE = "satisfied_by_warranted_evidence"
    UNRESOLVED_CONTRADICTION = "unresolved_contradiction"
    OUTSIDE_PACKAGE = "outside_package"
    PRODUCER_UNCOMMISSIONED = "producer_uncommissioned"
    EVIDENCE_UNAVAILABLE = "evidence_unavailable"
    INCOMPLETE_MAPPING = "incomplete_mapping"
    RETRIEVAL_CAP = "retrieval_cap"
    MODEL_BUDGET = "model_budget"
    TIMED_OUT = "timed_out"
    INVALID_RESPONSE = "invalid_response"
    NO_DECISIVE_EVIDENCE = "no_decisive_evidence"
    SUPERSEDED_BY_OBLIGATION = "superseded_by_obligation"
    WITHDRAWN_CLAIM_CAPPED = "withdrawn_claim_capped"


class RequiredEvidenceClass(StrEnum):
    GUARD_OR_RANGE_FACT = "guard_or_range_fact"
    STRUCTURED_FLOW = "structured_flow"
    BUILD_CONFIGURATION = "build_configuration"
    COMPILED_OR_IR_ENTITY = "compiled_or_ir_entity"
    CONSTRUCT_PRESENCE = "construct_presence"
    DEPLOYMENT_OR_ARTIFACT = "deployment_or_artifact"
    UNCOMMISSIONED_SEMANTICS = "uncommissioned_semantics"
    SCOPED_DIRECT_EVIDENCE = "scoped_direct_evidence"


class BudgetDisposition(StrEnum):
    WITHIN_BUDGET = "within_budget"
    FOLLOW_UP_REQUEST_CUTOFF = "follow_up_request_cutoff"
    MAX_ROUNDS_CUTOFF = "max_rounds_cutoff"
    CELL_BUDGET_EXHAUSTED = "cell_budget_exhausted"
    CLAIMS_PER_PACKAGE_CAP = "claims_per_package_cap"
    MAX_ACTIVE_CLAIMS = "max_active_claims"
    PACKAGE_NOT_LAUNCHED = "package_not_launched"


class ResolutionPolarity(StrEnum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    CONFLICTED = "conflicted"


@dataclass(frozen=True, slots=True)
class RequestSubmission:
    """One per-cell ``evidence_request`` submission prior to canonical deduplication."""

    request_id: str
    claim_id: str
    predicate: Predicate
    requested_kind: str
    anchors: tuple[str, ...]
    question: str
    specialist: str | None = None
    origin_cell_id: str | None = None
    round: int = 0
    budget_disposition: BudgetDisposition = BudgetDisposition.WITHIN_BUDGET


@dataclass(frozen=True, slots=True)
class CoverageReceiptRef:
    """Transport/delivery receipt reference bound from ``HUNT-C`` (``T-156``).

    Transport receipts prove bytes were served, empty, or denied; they never establish semantic
    satisfaction on their own.
    """

    receipt_id: str
    artifact_sha256: str
    canonical_request_id: str | None = None
    delivery_state: str = "served"
    semantic_resolution: str = "pending_tri_c_reconciliation"

    def __post_init__(self) -> None:
        if not isinstance(self.receipt_id, str) or not self.receipt_id.strip():
            raise IntegrityError("coverage receipt reference requires non-empty receipt_id")
        if not isinstance(self.artifact_sha256, str) or not _SHA256_RE.match(self.artifact_sha256):
            raise IntegrityError("coverage receipt reference requires 64-hex artifact_sha256")
        if self.canonical_request_id is not None and not _OBLIGATION_ID_RE.match(self.canonical_request_id):
            raise IntegrityError("coverage receipt canonical_request_id must match evob-<sha256>")
        if self.delivery_state not in {
            "served", "delivered", "empty", "denied", "budget_exhausted", "legacy_delivery_only",
        }:
            raise IntegrityError(f"unsupported coverage receipt delivery_state: {self.delivery_state!r}")
        if self.semantic_resolution not in {
            "pending_tri_c_reconciliation", "legacy_resolution_unknown",
            "satisfied", "unsatisfied", "superseded", "withdrawn",
        }:
            raise IntegrityError(f"unsupported coverage receipt semantic_resolution: {self.semantic_resolution!r}")


@dataclass(frozen=True, slots=True)
class TransportResolutionView:
    """Explicit join view for ``HUNT-C`` transport receipts vs. ``TRI-C`` semantic outcomes."""

    receipt_id: str
    artifact_sha256: str
    delivery_state: str
    canonical_request_id: str | None
    canonical_resolution_ref: str | None
    resolution_basis: str
    semantic_state: str
    reason_code: str | None


@dataclass(frozen=True, slots=True)
class ObligationResolution:
    """Deterministic resolution payload for an :class:`EvidenceObligation`."""

    relation_ids: tuple[str, ...]
    warrant_ids: tuple[str, ...]
    read_receipt_refs: tuple[str, ...]
    evaluated_round: int
    resolution_rule: str
    reason_code: ObligationReasonCode
    polarity: ResolutionPolarity | None = None
    superseded_by: str | None = None

    def __post_init__(self) -> None:
        if type(self.evaluated_round) is not int or self.evaluated_round < 0:
            raise IntegrityError("obligation resolution evaluated_round must be a non-negative int")
        if self.resolution_rule != OBLIGATION_POLICY_VERSION:
            raise IntegrityError(f"unsupported obligation resolution_rule: {self.resolution_rule!r}")
        if any(not _RELATION_ID_RE.match(item) for item in self.relation_ids):
            raise IntegrityError("obligation resolution relation_ids must match evrel-<sha256>")
        if len(set(self.relation_ids)) != len(self.relation_ids):
            raise IntegrityError("obligation resolution relation_ids must be unique")
        if any(not _WARRANT_ID_RE.match(item) for item in self.warrant_ids):
            raise IntegrityError("obligation resolution warrant_ids must match warrant-<sha256>")
        if len(set(self.warrant_ids)) != len(self.warrant_ids):
            raise IntegrityError("obligation resolution warrant_ids must be unique")
        if any(not _SHA256_RE.match(item) for item in self.read_receipt_refs):
            raise IntegrityError("obligation resolution read_receipt_refs must be 64-hex sha256 digests")
        if len(set(self.read_receipt_refs)) != len(self.read_receipt_refs):
            raise IntegrityError("obligation resolution read_receipt_refs must be unique")
        if self.superseded_by is not None and not _OBLIGATION_ID_RE.match(self.superseded_by):
            raise IntegrityError("obligation resolution superseded_by must match evob-<sha256>")


@dataclass(frozen=True, slots=True)
class EvidenceObligation:
    """Canonical ``evidence-obligation/1`` record."""

    obligation_id: str
    origin_request_ids: tuple[str, ...]
    claim_id: str
    predicate: Predicate
    subject_binding: SubjectBinding
    anchors: tuple[str, ...]
    question: str
    canonical_question: str
    requested_kind: str
    requested_specialist: str | None
    origin_cell_ids: tuple[str, ...]
    round_opened: int
    required_evidence_class: RequiredEvidenceClass
    admissible_producer_ids: tuple[str, ...]
    scope_ceiling: str
    completeness_required: bool
    state: ObligationState
    resolution: ObligationResolution
    coverage_receipt_refs: tuple[CoverageReceiptRef, ...] = ()
    remaining_gap_ids: tuple[str, ...] = ()
    attempted_retrieval_ids: tuple[str, ...] = ()
    budget_disposition: BudgetDisposition = BudgetDisposition.WITHIN_BUDGET
    policy_version: str = OBLIGATION_POLICY_VERSION

    def __post_init__(self) -> None:
        if not _OBLIGATION_ID_RE.match(self.obligation_id):
            raise IntegrityError(f"malformed obligation_id: {self.obligation_id!r}")
        if self.policy_version != OBLIGATION_POLICY_VERSION:
            raise IntegrityError(f"unsupported obligation policy_version: {self.policy_version!r}")
        if not self.origin_request_ids or any(not _REQUEST_ID_RE.match(r) for r in self.origin_request_ids):
            raise IntegrityError("obligation requires non-empty valid origin_request_ids")
        if len(set(self.origin_request_ids)) != len(self.origin_request_ids):
            raise IntegrityError("obligation origin_request_ids must be unique")
        if not _CLAIM_ID_RE.match(self.claim_id):
            raise IntegrityError(f"malformed obligation claim_id: {self.claim_id!r}")
        if self.requested_kind not in VALID_REQUESTED_KINDS:
            raise IntegrityError(f"unsupported obligation requested_kind: {self.requested_kind!r}")
        if any(not _CELL_ID_RE.match(c) for c in self.origin_cell_ids):
            raise IntegrityError("obligation origin_cell_ids must match cell-<sha256>")
        if len(set(self.origin_cell_ids)) != len(self.origin_cell_ids):
            raise IntegrityError("obligation origin_cell_ids must be unique")
        if type(self.round_opened) is not int or self.round_opened < 0:
            raise IntegrityError("obligation round_opened must be a non-negative int")
        if not isinstance(self.scope_ceiling, str) or not self.scope_ceiling.strip():
            raise IntegrityError("obligation requires non-empty scope_ceiling")
        if type(self.completeness_required) is not bool:
            raise IntegrityError("obligation completeness_required must be bool")
        if tuple(sorted(set(self.anchors))) != self.anchors:
            raise IntegrityError("obligation anchors must be sorted and unique")
        if tuple(sorted(set(self.admissible_producer_ids))) != self.admissible_producer_ids:
            raise IntegrityError("obligation admissible_producer_ids must be sorted and unique")
        if any(not _GAP_ID_RE.match(g) for g in self.remaining_gap_ids):
            raise IntegrityError("obligation remaining_gap_ids must match gap-<sha256>")
        if len(set(self.remaining_gap_ids)) != len(self.remaining_gap_ids):
            raise IntegrityError("obligation remaining_gap_ids must be unique")
        if len(set(self.attempted_retrieval_ids)) != len(self.attempted_retrieval_ids):
            raise IntegrityError("obligation attempted_retrieval_ids must be unique")
        if canonicalize_question(self.question) != self.canonical_question:
            raise IntegrityError("obligation canonical_question does not match question")

        expected_id = compute_obligation_id(
            claim_id=self.claim_id,
            predicate=self.predicate,
            subject_binding=self.subject_binding,
            anchors=self.anchors,
            scope_ceiling=self.scope_ceiling,
            requested_kind=self.requested_kind,
            canonical_question=self.canonical_question,
            policy_version=self.policy_version,
        )
        if self.obligation_id != expected_id:
            raise IntegrityError(
                f"obligation_id {self.obligation_id} does not match canonical digest {expected_id}"
            )

        for ref in self.coverage_receipt_refs:
            if ref.canonical_request_id is not None and ref.canonical_request_id != self.obligation_id:
                raise IntegrityError(
                    f"coverage receipt {ref.receipt_id} canonical_request_id {ref.canonical_request_id} "
                    f"does not match obligation {self.obligation_id}"
                )

        res = self.resolution
        if self.state is ObligationState.OPEN:
            if (res.reason_code is not ObligationReasonCode.OPEN_PENDING
                    or res.superseded_by is not None
                    or res.polarity is not None
                    or res.relation_ids
                    or res.warrant_ids):
                raise IntegrityError("open obligation must carry open_pending resolution without deciding refs")
        elif self.state is ObligationState.SATISFIED:
            if (res.reason_code is not ObligationReasonCode.SATISFIED_BY_WARRANTED_EVIDENCE
                    or not res.relation_ids
                    or not res.warrant_ids
                    or not res.read_receipt_refs
                    or res.polarity not in {ResolutionPolarity.SUPPORTS, ResolutionPolarity.CONTRADICTS}
                    or res.superseded_by is not None):
                raise IntegrityError(
                    "satisfied obligation requires warranted relation_ids, warrant_ids, "
                    "read_receipt_refs, and non-conflicted polarity"
                )
        elif self.state is ObligationState.SUPERSEDED:
            if (res.reason_code is not ObligationReasonCode.SUPERSEDED_BY_OBLIGATION
                    or res.superseded_by is None
                    or res.superseded_by == self.obligation_id
                    or res.polarity is not None):
                raise IntegrityError("superseded obligation requires distinct superseded_by obligation_id")
        elif self.state in {ObligationState.UNSATISFIED, ObligationState.WITHDRAWN}:
            if res.reason_code in {
                ObligationReasonCode.OPEN_PENDING,
                ObligationReasonCode.SATISFIED_BY_WARRANTED_EVIDENCE,
                ObligationReasonCode.SUPERSEDED_BY_OBLIGATION,
            }:
                raise IntegrityError(f"invalid reason_code {res.reason_code} for {self.state} obligation")
            if res.superseded_by is not None:
                raise IntegrityError(f"{self.state} obligation must not set superseded_by")
            if res.reason_code is ObligationReasonCode.UNRESOLVED_CONTRADICTION:
                if (res.polarity is not ResolutionPolarity.CONFLICTED
                        or len(res.relation_ids) < 2
                        or len(res.warrant_ids) < 2):
                    raise IntegrityError(
                        "unresolved_contradiction requires conflicted polarity and >=2 relation/warrant refs"
                    )
            elif res.polarity is not None:
                raise IntegrityError("non-contradiction unsatisfied/withdrawn obligation must have null polarity")

    @property
    def primary_request_id(self) -> str:
        """Deterministic representative ``evreq-*`` submission ID."""
        return self.origin_request_ids[0]


def canonicalize_question(question: str) -> str:
    """Normalize whitespace, trailing punctuation, and ASCII case for obligation identity."""
    if not isinstance(question, str):
        raise ValueError("obligation question must be a string")
    collapsed = _WHITESPACE_RE.sub(" ", question.strip())
    stripped = _TRAILING_PUNCT_RE.sub("", collapsed).strip()
    lowered = stripped.casefold()
    if not lowered:
        raise ValueError("obligation question must not be empty")
    return lowered


def _subject_binding_json(binding: SubjectBinding) -> dict[str, Any]:
    return {
        "affected_entity_ids": list(binding.affected_entity_ids),
        "operation_id": binding.operation_id,
        "sink_id": binding.sink_id,
        "build_scope_id": binding.build_scope_id,
    }


def compute_obligation_id(
    *,
    claim_id: str,
    predicate: Predicate,
    subject_binding: SubjectBinding,
    anchors: Sequence[str],
    scope_ceiling: str,
    requested_kind: str,
    canonical_question: str,
    policy_version: str = OBLIGATION_POLICY_VERSION,
) -> str:
    """Compute canonical ``evob-<sha256>`` (shared directly as ``HUNT-C`` ``canonical_request_id``)."""
    body = {
        "policy_version": policy_version,
        "claim_id": claim_id,
        "predicate": Predicate(predicate).value,
        "subject_binding": _subject_binding_json(subject_binding),
        "anchors": sorted(set(anchors)),
        "scope_ceiling": scope_ceiling,
        "requested_kind": requested_kind,
        "canonical_question": canonical_question,
    }
    return f"evob-{sha256_hex({'kind': 'evidence_obligation', 'version': 1, 'body': body})}"


def infer_required_evidence_class(
    claim: Claim,
    predicate: Predicate,
    requested_kind: str,
) -> RequiredEvidenceClass:
    """Derive the machine evidence class required to satisfy ``(claim, predicate, requested_kind)``."""
    predicate = Predicate(predicate)
    if predicate is Predicate.SECURITY_IMPACT or (
        predicate is Predicate.MISSING_OR_INEFFECTIVE_GUARD
        and SecurityPredicate(claim.security_predicate) in UNCOMMISSIONED_GUARD_SECURITY_PREDICATES
    ):
        return RequiredEvidenceClass.UNCOMMISSIONED_SEMANTICS
    if predicate is Predicate.MISSING_OR_INEFFECTIVE_GUARD and is_numeric_weakness(claim.weakness_cwe):
        return RequiredEvidenceClass.GUARD_OR_RANGE_FACT
    if requested_kind in {EntityKind.GUARD_FACT.value, EntityKind.RANGE_FACT.value}:
        return RequiredEvidenceClass.GUARD_OR_RANGE_FACT
    if requested_kind in {"dataflow", EntityKind.DATAFLOW_PATH.value, EntityKind.ENTRY_POINT.value}:
        return RequiredEvidenceClass.STRUCTURED_FLOW
    if predicate in {Predicate.ATTACKER_INPUT_CONTROL, Predicate.SOURCE_TO_SINK_REACHABILITY} and requested_kind == "other":
        return RequiredEvidenceClass.STRUCTURED_FLOW
    if (predicate is Predicate.CONFIGURATION_ENABLES
            or requested_kind in {"configuration", "build_provenance",
                                  EntityKind.BUILD_ACTION.value, EntityKind.COMPILE_UNIT.value}):
        return RequiredEvidenceClass.BUILD_CONFIGURATION
    if requested_kind in {
        "compiled_view", EntityKind.IR_ENTITY.value, EntityKind.OBJECT_FILE.value,
        EntityKind.LIBRARY.value, EntityKind.EXECUTABLE.value, EntityKind.BINARY_FUNCTION.value,
        EntityKind.BINARY_CALL_SITE.value, EntityKind.BYTECODE_MODULE.value,
        EntityKind.MANAGED_ASSEMBLY.value, EntityKind.WASM_MODULE.value,
    }:
        return RequiredEvidenceClass.COMPILED_OR_IR_ENTITY
    if requested_kind in {
        "source_line", EntityKind.SOURCE_SPAN.value, EntityKind.AST_NODE.value,
        EntityKind.SYMBOL.value, EntityKind.CALL_SITE.value, EntityKind.SINK_SITE.value,
    }:
        return RequiredEvidenceClass.CONSTRUCT_PRESENCE
    if requested_kind in {
        "deployment", "run_artifact", EntityKind.EVIDENCE_ARTIFACT.value,
        EntityKind.BUILD_ARTIFACT.value, EntityKind.PACKAGE.value, EntityKind.ARCHIVE_MEMBER.value,
    }:
        return RequiredEvidenceClass.DEPLOYMENT_OR_ARTIFACT
    return RequiredEvidenceClass.SCOPED_DIRECT_EVIDENCE


def _kind_matches_requested(requested_kind: str, entity_kind: EntityKind) -> bool:
    if requested_kind in _KIND_COMPATIBILITY:
        return entity_kind in _KIND_COMPATIBILITY[requested_kind]
    return entity_kind.value == requested_kind


def coalesce_obligations(
    submissions: Iterable[RequestSubmission],
    *,
    claims_by_id: Mapping[str, Claim],
    core: RetrievalCore | None = None,
    scope: WarrantScope | None = None,
    scope_ceiling: str,
    admissible_producer_ids: Iterable[str] = (),
    completeness_required: bool = True,
) -> tuple[EvidenceObligation, ...]:
    """Deduplicate per-cell ``RequestSubmission`` items into canonical ``EvidenceObligation`` records."""
    producers = tuple(sorted(set(admissible_producer_ids)))
    subject_cache: dict[str, SubjectBinding] = {}
    grouped: dict[str, list[RequestSubmission]] = defaultdict(list)
    meta: dict[str, tuple[Claim, Predicate, SubjectBinding, tuple[str, ...], str]] = {}

    for sub in submissions:
        if sub.claim_id not in claims_by_id:
            raise IntegrityError(f"request submission {sub.request_id} references unknown claim {sub.claim_id}")
        claim = claims_by_id[sub.claim_id]
        predicate = Predicate(sub.predicate)
        if sub.claim_id not in subject_cache:
            subject_cache[sub.claim_id] = bind_claim_subject(core, claim, scope)
        binding = subject_cache[sub.claim_id]
        anchors = tuple(sorted(set(sub.anchors)))
        canon_q = canonicalize_question(sub.question)
        ob_id = compute_obligation_id(
            claim_id=sub.claim_id,
            predicate=predicate,
            subject_binding=binding,
            anchors=anchors,
            scope_ceiling=scope_ceiling,
            requested_kind=sub.requested_kind,
            canonical_question=canon_q,
        )
        grouped[ob_id].append(sub)
        meta.setdefault(ob_id, (claim, predicate, binding, anchors, canon_q))

    obligations: list[EvidenceObligation] = []
    for ob_id in sorted(grouped):
        claim, predicate, binding, anchors, canon_q = meta[ob_id]
        ordered = sorted(
            grouped[ob_id],
            key=lambda item: (item.round, item.origin_cell_id or "", item.request_id),
        )
        seen_req: dict[str, RequestSubmission] = {}
        for item in ordered:
            seen_req.setdefault(item.request_id, item)
        unique_subs = tuple(seen_req.values())
        origin_request_ids = tuple(item.request_id for item in unique_subs)
        origin_cell_ids = tuple(dict.fromkeys(
            item.origin_cell_id for item in unique_subs if item.origin_cell_id is not None
        ))
        round_opened = min(item.round for item in unique_subs)
        specialist = next((item.specialist for item in unique_subs if item.specialist is not None), None)
        disposition = unique_subs[0].budget_disposition
        for item in unique_subs:
            if item.budget_disposition is not BudgetDisposition.WITHIN_BUDGET:
                disposition = item.budget_disposition
                break
        req_class = infer_required_evidence_class(claim, predicate, unique_subs[0].requested_kind)
        obligations.append(
            EvidenceObligation(
                obligation_id=ob_id,
                origin_request_ids=origin_request_ids,
                claim_id=claim.claim_id,
                predicate=predicate,
                subject_binding=binding,
                anchors=anchors,
                question=unique_subs[0].question,
                canonical_question=canon_q,
                requested_kind=unique_subs[0].requested_kind,
                requested_specialist=specialist,
                origin_cell_ids=origin_cell_ids,
                round_opened=round_opened,
                required_evidence_class=req_class,
                admissible_producer_ids=producers,
                scope_ceiling=scope_ceiling,
                completeness_required=completeness_required,
                state=ObligationState.OPEN,
                resolution=ObligationResolution(
                    relation_ids=(),
                    warrant_ids=(),
                    read_receipt_refs=(),
                    evaluated_round=round_opened,
                    resolution_rule=OBLIGATION_POLICY_VERSION,
                    reason_code=ObligationReasonCode.OPEN_PENDING,
                ),
                budget_disposition=disposition,
            )
        )
    return tuple(obligations)


def _safe_find_one(core: RetrievalCore, entity_id: str) -> tuple[Mapping[str, Any] | None, bool]:
    """Return ``(entity_or_none, retrieval_unavailable)``."""
    try:
        found = core.find(identity=entity_id, limit=1)["results"]
        return (found[0] if found else None), False
    except RetrievalIntegrityError:
        raise
    except RetrievalGap:
        return None, True
    except (LookupError, ValueError):
        return None, False


def _covered_entities_for_fact(
    core: RetrievalCore | None,
    entity_id: str,
    entity: Mapping[str, Any] | None,
    warrant: PredicateWarrant,
    candidate_anchors: AbstractSet[str],
) -> set[str]:
    """Return all target entity IDs structurally covered by ``(entity_id, warrant)``."""
    covered: set[str] = {entity_id}
    for ref in warrant.evidence_refs:
        covered.add(ref.entity_id)
    if warrant.subject_binding.sink_id:
        covered.add(warrant.subject_binding.sink_id)
    if entity is not None:
        payload = entity.get("payload")
        if isinstance(payload, Mapping):
            result = payload.get("result")
            if isinstance(result, Mapping):
                for key in ("sink", "source", "enclosing_function", "caller", "function"):
                    holder = result.get(key)
                    if isinstance(holder, Mapping):
                        for subkey in ("sink_site", "entry_point", "entity_id", "symbol", "call_site", "id"):
                            val = holder.get(subkey)
                            if isinstance(val, str) and val.startswith("asr:"):
                                covered.add(val)
                for direct_key in ("sink_site", "guarded_sink", "target_id", "source_id"):
                    val = result.get(direct_key)
                    if isinstance(val, str) and val.startswith("asr:"):
                        covered.add(val)
        build_id = (
            entity.get("build_scope_id")
            or (payload.get("build_scope_id") if isinstance(payload, Mapping) else None)
            or (entity_id if entity.get("kind") in {EntityKind.BUILD_ACTION.value, EntityKind.COMPILE_UNIT.value} else None)
        )
        if isinstance(build_id, str) and core is not None and candidate_anchors:
            for anchor_id in candidate_anchors:
                anchor_ent, _ = _safe_find_one(core, anchor_id)
                if anchor_ent is None:
                    continue
                anchor_payload = anchor_ent.get("payload") if isinstance(anchor_ent.get("payload"), Mapping) else {}
                anchor_build = anchor_ent.get("build_scope_id") or anchor_payload.get("build_scope_id")
                if anchor_build == build_id:
                    covered.add(anchor_id)
                    continue
                e_loc = entity.get("location") if isinstance(entity.get("location"), Mapping) else None
                a_loc = anchor_ent.get("location") if isinstance(anchor_ent.get("location"), Mapping) else None
                if (e_loc and a_loc
                        and isinstance(e_loc.get("path"), str)
                        and e_loc.get("path") == a_loc.get("path")):
                    covered.add(anchor_id)
    if core is not None:
        try:
            limit = min(100, core.limits.max_results)
            traced = core.trace(identity=entity_id, relations=_TRACE_RELATIONS, depth=1, limit=limit)["results"]
        except RetrievalIntegrityError:
            raise
        except (RetrievalGap, LookupError, ValueError):
            traced = ()
        for rel in traced:
            if not rel.get("exact", True):
                continue
            src = rel.get("source_id")
            dst = rel.get("target_id")
            if isinstance(src, str):
                covered.add(src)
            if isinstance(dst, str):
                covered.add(dst)
    return covered


def _entity_kind_for_warrant(relation: EvidenceRelation, warrant: PredicateWarrant,
                             entity: Mapping[str, Any] | None) -> EntityKind | None:
    if entity is not None and isinstance(entity.get("kind"), str):
        try:
            return EntityKind(entity["kind"])
        except ValueError:
            pass
    for ref in warrant.evidence_refs:
        try:
            return EntityKind(ref.entity_kind)
        except ValueError:
            continue
    try:
        return LogicalIdentity.parse(relation.entity_id).kind
    except ValueError:
        return None


def _relation_within_package(
    relation: EvidenceRelation,
    entity_kind: EntityKind | None,
    covered: AbstractSet[str],
    package_entities: AbstractSet[str] | None,
) -> bool:
    if package_entities is None:
        return True
    if relation.entity_id in package_entities:
        return True
    if entity_kind in _CONSTRUCT_ENTITY_KINDS:
        return False
    return bool(covered & package_entities)


def _bind_coverage_receipts(
    obligation_id: str,
    raw_refs: Sequence[CoverageReceiptRef],
    semantic_state: ObligationState,
) -> tuple[CoverageReceiptRef, ...]:
    bound: list[CoverageReceiptRef] = []
    seen: set[tuple[str, str]] = set()
    for ref in sorted(raw_refs, key=lambda item: (item.receipt_id, item.artifact_sha256)):
        if ref.canonical_request_id is not None and ref.canonical_request_id != obligation_id:
            raise IntegrityError(
                f"coverage receipt {ref.receipt_id} canonical_request_id {ref.canonical_request_id} "
                f"mismatches obligation {obligation_id}"
            )
        key = (ref.receipt_id, ref.artifact_sha256)
        if key in seen:
            continue
        seen.add(key)
        resolved_label = (
            "legacy_resolution_unknown"
            if ref.delivery_state == "legacy_delivery_only"
            else "pending_tri_c_reconciliation"
            if semantic_state is ObligationState.OPEN
            else semantic_state.value
        )
        bound.append(
            CoverageReceiptRef(
                receipt_id=ref.receipt_id,
                artifact_sha256=ref.artifact_sha256,
                canonical_request_id=obligation_id,
                delivery_state=ref.delivery_state,
                semantic_resolution=resolved_label,
            )
        )
    return tuple(bound)


def reconcile_obligations(
    obligations: Sequence[EvidenceObligation],
    *,
    claims_by_id: Mapping[str, Claim],
    relations: Sequence[EvidenceRelation] = (),
    warrants_by_relation_id: Mapping[str, PredicateWarrant] | None = None,
    core: RetrievalCore | None = None,
    scope: WarrantScope | None = None,
    package_entities: Collection[str] | None = None,
    commissioned_producers: Collection[str] | None = None,
    shard_producers: Mapping[str, str] | None = None,
    cell_roles: Mapping[str, str] | None = None,
    cells: Sequence[CellRecord] = (),
    gaps: Sequence[Gap] = (),
    coverage_receipts: Mapping[str, Sequence[CoverageReceiptRef]] | None = None,
    cutoff_obligation_ids: Collection[str] = (),
    superseded_by_map: Mapping[str, str] | None = None,
    withdrawn_claims: Mapping[str, BudgetDisposition] | None = None,
    round_stop_reason: str | None = None,
    evaluated_round: int = 0,
    terminal: bool = False,
) -> tuple[EvidenceObligation, ...]:
    """Deterministically reconcile ``obligations`` at a round boundary or terminal seal."""
    pkg_set = frozenset(package_entities) if package_entities is not None else None
    commissioned = frozenset(commissioned_producers) if commissioned_producers is not None else None
    warrant_map = dict(warrants_by_relation_id or {})
    superseded_map = dict(superseded_by_map or {})
    withdrawn_map = dict(withdrawn_claims or {})
    receipt_map = coverage_receipts or {}
    cutoff_ids = frozenset(cutoff_obligation_ids)
    roles = dict(cell_roles or {})

    known_ids = {ob.obligation_id for ob in obligations}
    for src_id, dst_id in superseded_map.items():
        if src_id == dst_id or dst_id not in known_ids:
            raise IntegrityError(f"invalid obligation supersession {src_id!r} -> {dst_id!r}")
        cursor = dst_id
        visited = {src_id}
        while cursor in superseded_map:
            if cursor in visited:
                raise IntegrityError(f"cyclic obligation supersession involving {src_id}")
            visited.add(cursor)
            cursor = superseded_map[cursor]

    relations_by_claim_pred: dict[tuple[str, Predicate], list[EvidenceRelation]] = defaultdict(list)
    for rel in sorted(relations, key=lambda item: item.relation_id):
        relations_by_claim_pred[(rel.claim_id, rel.predicate)].append(rel)

    gaps_by_subject: dict[str, list[Gap]] = defaultdict(list)
    for gap in gaps:
        gaps_by_subject[gap.subject_id].append(gap)

    reconciled: list[EvidenceObligation] = []
    for ob in sorted(obligations, key=lambda item: item.obligation_id):
        if ob.claim_id not in claims_by_id:
            raise IntegrityError(f"obligation {ob.obligation_id} references unknown claim {ob.claim_id}")
        claim = claims_by_id[ob.claim_id]
        budget = ob.budget_disposition
        if ob.obligation_id in cutoff_ids and budget is BudgetDisposition.WITHIN_BUDGET:
            budget = BudgetDisposition.FOLLOW_UP_REQUEST_CUTOFF

        linked_gaps: set[str] = set(ob.remaining_gap_ids)
        for req_id in ob.origin_request_ids:
            for gap in gaps_by_subject.get(req_id, ()):
                linked_gaps.add(gap.gap_id)
        for gap in gaps_by_subject.get(ob.obligation_id, ()):
            linked_gaps.add(gap.gap_id)
        for gap in gaps_by_subject.get(ob.claim_id, ()):
            linked_gaps.add(gap.gap_id)

        # 1. Explicit supersession wins deterministically.
        if ob.obligation_id in superseded_map:
            target_id = superseded_map[ob.obligation_id]
            state = ObligationState.SUPERSEDED
            reconciled.append(
                replace(
                    ob,
                    state=state,
                    resolution=ObligationResolution(
                        relation_ids=(),
                        warrant_ids=(),
                        read_receipt_refs=(),
                        evaluated_round=evaluated_round,
                        resolution_rule=OBLIGATION_POLICY_VERSION,
                        reason_code=ObligationReasonCode.SUPERSEDED_BY_OBLIGATION,
                        superseded_by=target_id,
                    ),
                    coverage_receipt_refs=_bind_coverage_receipts(
                        ob.obligation_id, receipt_map.get(ob.obligation_id, ob.coverage_receipt_refs), state,
                    ),
                    remaining_gap_ids=tuple(sorted(linked_gaps)),
                    budget_disposition=budget,
                )
            )
            continue

        # 2. Triage-withdrawn / capped claims close deterministically as WITHDRAWN.
        if ob.claim_id in withdrawn_map:
            w_budget = withdrawn_map[ob.claim_id]
            state = ObligationState.WITHDRAWN
            reconciled.append(
                replace(
                    ob,
                    state=state,
                    resolution=ObligationResolution(
                        relation_ids=(),
                        warrant_ids=(),
                        read_receipt_refs=(),
                        evaluated_round=evaluated_round,
                        resolution_rule=OBLIGATION_POLICY_VERSION,
                        reason_code=ObligationReasonCode.WITHDRAWN_CLAIM_CAPPED,
                    ),
                    coverage_receipt_refs=_bind_coverage_receipts(
                        ob.obligation_id, receipt_map.get(ob.obligation_id, ob.coverage_receipt_refs), state,
                    ),
                    remaining_gap_ids=tuple(sorted(linked_gaps)),
                    budget_disposition=w_budget,
                )
            )
            continue

        # 3. Scope ceiling check: anchors or claim wholly outside package_entities fail closed immediately.
        if pkg_set is not None and (
            not set(ob.anchors).issubset(pkg_set)
            or all(ent not in pkg_set for ent in claim.affected_entities)
        ):
            state = ObligationState.UNSATISFIED
            reconciled.append(
                replace(
                    ob,
                    state=state,
                    resolution=ObligationResolution(
                        relation_ids=(),
                        warrant_ids=(),
                        read_receipt_refs=(),
                        evaluated_round=evaluated_round,
                        resolution_rule=OBLIGATION_POLICY_VERSION,
                        reason_code=ObligationReasonCode.OUTSIDE_PACKAGE,
                    ),
                    coverage_receipt_refs=_bind_coverage_receipts(
                        ob.obligation_id, receipt_map.get(ob.obligation_id, ob.coverage_receipt_refs), state,
                    ),
                    remaining_gap_ids=tuple(sorted(linked_gaps)),
                    budget_disposition=budget,
                )
            )
            continue

        # 4. Uncommissioned semantics or uncommissioned required producer check.
        producer_blocked = (
            commissioned is not None
            and bool(ob.admissible_producer_ids)
            and not (set(ob.admissible_producer_ids) & commissioned)
        )
        uncommissioned_class = ob.required_evidence_class is RequiredEvidenceClass.UNCOMMISSIONED_SEMANTICS

        # 5. Evaluate candidate relations on (claim_id, predicate).
        support_matches: list[tuple[EvidenceRelation, PredicateWarrant, set[str]]] = []
        contra_matches: list[tuple[EvidenceRelation, PredicateWarrant, set[str]]] = []
        attempted: set[str] = set(ob.attempted_retrieval_ids)
        saw_incomplete = False
        saw_uncommissioned = uncommissioned_class or producer_blocked
        saw_unavailable = False

        if core is not None:
            for anchor_id in ob.anchors:
                found_anchor, gap_unavail = _safe_find_one(core, anchor_id)
                if found_anchor is None or gap_unavail:
                    saw_unavailable = True

        anchor_set = frozenset(ob.anchors)
        subject_targets = frozenset(
            item for item in (
                *ob.subject_binding.affected_entity_ids,
                ob.subject_binding.operation_id,
                ob.subject_binding.sink_id,
            )
            if item is not None
        )

        for rel in relations_by_claim_pred.get((ob.claim_id, ob.predicate), ()):
            attempted.add(rel.entity_id)
            if rel.provenance is not None:
                continue
            if shard_producers is not None and ob.admissible_producer_ids:
                prod = shard_producers.get(rel.shard_id)
                if prod is not None and prod not in ob.admissible_producer_ids:
                    continue

            entity_doc: Mapping[str, Any] | None = None
            if core is not None:
                entity_doc, rel_unavail = _safe_find_one(core, rel.entity_id)
                if rel_unavail:
                    saw_unavailable = True

            warrant = warrant_map.get(rel.relation_id)
            if warrant is None and core is not None and entity_doc is not None:
                role = roles.get(rel.producing_cell_id or "")
                warrant = evaluate_warrant(
                    core,
                    claim=claim,
                    predicate=rel.predicate,
                    requested_relation=rel.kind,
                    entity=entity_doc,
                    admissibility=rel.admissibility,
                    complete=rel.complete,
                    shard_id=rel.shard_id,
                    content_sha256=str(entity_doc.get("content_sha256") or sha256_hex(entity_doc)),
                    locator=str(rel.locator),
                    retrieval_receipt_sha256=rel.retrieval_receipt_sha256,
                    relation_id=rel.relation_id,
                    role=role,
                    scope=scope,
                )
            if warrant is None:
                continue
            if warrant.claim_id != ob.claim_id or warrant.predicate is not ob.predicate:
                continue

            ent_kind = _entity_kind_for_warrant(rel, warrant, entity_doc)
            if ent_kind is None or not _kind_matches_requested(ob.requested_kind, ent_kind):
                continue

            covered = _covered_entities_for_fact(core, rel.entity_id, entity_doc, warrant, anchor_set or subject_targets)
            if not _relation_within_package(rel, ent_kind, covered, pkg_set):
                continue

            if anchor_set:
                matched_anchors = covered & anchor_set
                if not matched_anchors:
                    continue
            else:
                if subject_targets and not (covered & subject_targets):
                    continue
                matched_anchors = set()

            if warrant.result is WarrantResult.UNCOMMISSIONED:
                saw_uncommissioned = True
                continue

            if ob.completeness_required and (
                not rel.complete or warrant.coverage is WarrantCoverage.INCOMPLETE_FACTS
            ):
                saw_incomplete = True
                continue

            if warrant.reason_code in {
                WarrantReasonCode.INCOMPLETE_FACT_RECORD,
                WarrantReasonCode.OPERAND_OR_WIDTH_MISSING,
                WarrantReasonCode.DESTINATION_BOUND_UNPROVED,
                WarrantReasonCode.CONFIGURATION_FACT_INCONCLUSIVE,
                WarrantReasonCode.NUMERIC_MACHINE_FACT_REQUIRED,
            }:
                saw_incomplete = True
                continue

            if producer_blocked:
                continue

            if rel.admissibility not in {Admissibility.DIRECT, Admissibility.DIRECT_FOR_MAPPED_PREDICATE}:
                saw_incomplete = True
                continue

            if (warrant.result is WarrantResult.ESTABLISHED_SUPPORT
                    and warrant.effective_relation is RelationKind.SUPPORTS
                    and rel.kind is RelationKind.SUPPORTS):
                support_matches.append((rel, warrant, matched_anchors))
            elif (warrant.result is WarrantResult.ESTABLISHED_CONTRADICTION
                  and warrant.effective_relation is RelationKind.CONTRADICTS
                  and rel.kind is RelationKind.CONTRADICTS):
                contra_matches.append((rel, warrant, matched_anchors))

        support_covers_all = bool(support_matches) and (
            not anchor_set
            or anchor_set.issubset(set().union(*(m[2] for m in support_matches)))
        )
        contra_covers_all = bool(contra_matches) and (
            not anchor_set
            or anchor_set.issubset(set().union(*(m[2] for m in contra_matches)))
        )
        if (support_matches and not support_covers_all) or (contra_matches and not contra_covers_all):
            saw_incomplete = True
        if anchor_set and support_covers_all:
            support_matches = [
                m for m in support_matches
                if not any(m[2] < other[2] for other in support_matches)
            ]
        if anchor_set and contra_covers_all:
            contra_matches = [
                m for m in contra_matches
                if not any(m[2] < other[2] for other in contra_matches)
            ]

        # 6. Contradictory warranted answers never resolve silently to one side.
        if support_covers_all and contra_covers_all:
            if not terminal:
                state = ObligationState.OPEN
                resolution = ObligationResolution(
                    relation_ids=(),
                    warrant_ids=(),
                    read_receipt_refs=(),
                    evaluated_round=evaluated_round,
                    resolution_rule=OBLIGATION_POLICY_VERSION,
                    reason_code=ObligationReasonCode.OPEN_PENDING,
                )
            else:
                combined = [*support_matches, *contra_matches]
                rel_ids = tuple(dict.fromkeys(m[0].relation_id for m in combined))
                war_ids = tuple(dict.fromkeys(m[1].warrant_id for m in combined))
                rcpt_refs = tuple(dict.fromkeys(
                    ref_hash
                    for m in combined
                    for ref_hash in (
                        m[0].retrieval_receipt_sha256,
                        *(er.retrieval_receipt_sha256 for er in m[1].evidence_refs),
                    )
                    if isinstance(ref_hash, str) and _SHA256_RE.match(ref_hash)
                ))
                state = ObligationState.UNSATISFIED
                resolution = ObligationResolution(
                    relation_ids=rel_ids,
                    warrant_ids=war_ids,
                    read_receipt_refs=rcpt_refs,
                    evaluated_round=evaluated_round,
                    resolution_rule=OBLIGATION_POLICY_VERSION,
                    reason_code=ObligationReasonCode.UNRESOLVED_CONTRADICTION,
                    polarity=ResolutionPolarity.CONFLICTED,
                )
            reconciled.append(
                replace(
                    ob,
                    state=state,
                    resolution=resolution,
                    coverage_receipt_refs=_bind_coverage_receipts(
                        ob.obligation_id, receipt_map.get(ob.obligation_id, ob.coverage_receipt_refs), state,
                    ),
                    remaining_gap_ids=tuple(sorted(linked_gaps)),
                    attempted_retrieval_ids=tuple(sorted(attempted)),
                    budget_disposition=budget,
                )
            )
            continue

        # 7. Unambiguous warranted support OR warranted contradiction satisfies the obligation.
        chosen = support_matches if support_covers_all else contra_matches if contra_covers_all else ()
        if chosen:
            polarity = ResolutionPolarity.SUPPORTS if support_covers_all else ResolutionPolarity.CONTRADICTS
            rel_ids = tuple(dict.fromkeys(m[0].relation_id for m in chosen))
            war_ids = tuple(dict.fromkeys(m[1].warrant_id for m in chosen))
            rcpt_refs = tuple(dict.fromkeys(
                ref_hash
                for m in chosen
                for ref_hash in (
                    m[0].retrieval_receipt_sha256,
                    *(er.retrieval_receipt_sha256 for er in m[1].evidence_refs),
                )
                if isinstance(ref_hash, str) and _SHA256_RE.match(ref_hash)
            ))
            if rcpt_refs:
                state = ObligationState.SATISFIED
                reconciled.append(
                    replace(
                        ob,
                        state=state,
                        resolution=ObligationResolution(
                            relation_ids=rel_ids,
                            warrant_ids=war_ids,
                            read_receipt_refs=rcpt_refs,
                            evaluated_round=evaluated_round,
                            resolution_rule=OBLIGATION_POLICY_VERSION,
                            reason_code=ObligationReasonCode.SATISFIED_BY_WARRANTED_EVIDENCE,
                            polarity=polarity,
                        ),
                        coverage_receipt_refs=_bind_coverage_receipts(
                            ob.obligation_id, receipt_map.get(ob.obligation_id, ob.coverage_receipt_refs), state,
                        ),
                        remaining_gap_ids=(),
                        attempted_retrieval_ids=tuple(sorted(attempted)),
                        budget_disposition=budget,
                    )
                )
                continue

        # 8. Not yet resolved: remain OPEN at intermediate round boundaries (unless uncommissioned),
        #    or classify specific terminal UNSATISFIED reason at lane/package seal.
        if not terminal:
            state = ObligationState.OPEN
            reconciled.append(
                replace(
                    ob,
                    state=state,
                    resolution=ObligationResolution(
                        relation_ids=(),
                        warrant_ids=(),
                        read_receipt_refs=(),
                        evaluated_round=evaluated_round,
                        resolution_rule=OBLIGATION_POLICY_VERSION,
                        reason_code=ObligationReasonCode.OPEN_PENDING,
                    ),
                    coverage_receipt_refs=_bind_coverage_receipts(
                        ob.obligation_id, receipt_map.get(ob.obligation_id, ob.coverage_receipt_refs), state,
                    ),
                    remaining_gap_ids=tuple(sorted(linked_gaps)),
                    attempted_retrieval_ids=tuple(sorted(attempted)),
                    budget_disposition=budget,
                )
            )
            continue

        reason_code, final_budget = _classify_unsatisfied_reason(
            ob=ob,
            budget=budget,
            saw_uncommissioned=saw_uncommissioned,
            saw_unavailable=saw_unavailable,
            saw_incomplete=saw_incomplete,
            cells=cells,
            gaps=gaps,
            receipts=receipt_map.get(ob.obligation_id, ob.coverage_receipt_refs),
            round_stop_reason=round_stop_reason,
        )
        state = ObligationState.UNSATISFIED
        reconciled.append(
            replace(
                ob,
                state=state,
                resolution=ObligationResolution(
                    relation_ids=(),
                    warrant_ids=(),
                    read_receipt_refs=(),
                    evaluated_round=evaluated_round,
                    resolution_rule=OBLIGATION_POLICY_VERSION,
                    reason_code=reason_code,
                ),
                coverage_receipt_refs=_bind_coverage_receipts(
                    ob.obligation_id, receipt_map.get(ob.obligation_id, ob.coverage_receipt_refs), state,
                ),
                remaining_gap_ids=tuple(sorted(linked_gaps)),
                attempted_retrieval_ids=tuple(sorted(attempted)),
                budget_disposition=final_budget,
            )
        )

    return tuple(reconciled)


def _classify_unsatisfied_reason(
    *,
    ob: EvidenceObligation,
    budget: BudgetDisposition,
    saw_uncommissioned: bool,
    saw_unavailable: bool,
    saw_incomplete: bool,
    cells: Sequence[CellRecord],
    gaps: Sequence[Gap],
    receipts: Sequence[CoverageReceiptRef],
    round_stop_reason: str | None,
) -> tuple[ObligationReasonCode, BudgetDisposition]:
    if saw_uncommissioned:
        return ObligationReasonCode.PRODUCER_UNCOMMISSIONED, budget

    if budget is BudgetDisposition.FOLLOW_UP_REQUEST_CUTOFF:
        return ObligationReasonCode.RETRIEVAL_CAP, budget

    if any(ref.delivery_state == "denied" for ref in receipts):
        return ObligationReasonCode.OUTSIDE_PACKAGE, budget
    if any(ref.delivery_state == "budget_exhausted" for ref in receipts):
        return ObligationReasonCode.RETRIEVAL_CAP, BudgetDisposition.FOLLOW_UP_REQUEST_CUTOFF

    relevant_gaps = [
        gap for gap in gaps
        if gap.subject_id in {ob.obligation_id, ob.claim_id, *ob.origin_request_ids}
    ]
    if any("retrieval_cap" in gap.reason or "max_results" in gap.reason or "request_cutoff" in gap.reason
           for gap in relevant_gaps):
        return ObligationReasonCode.RETRIEVAL_CAP, budget

    if saw_unavailable or any(
        gap.gap_class is GapClass.EVIDENCE_GAP
        and ("unavailable" in gap.reason or "missing_shard" in gap.reason or "unresolved" in gap.reason)
        and not gap.reason.startswith("unresolved_specialist_referral:")
        for gap in relevant_gaps
    ):
        return ObligationReasonCode.EVIDENCE_UNAVAILABLE, budget

    if saw_incomplete:
        return ObligationReasonCode.INCOMPLETE_MAPPING, budget

    failed_cells = [cell for cell in cells if cell.status is not CellStatus.SUCCEEDED]
    if any(cell.status is CellStatus.TIMED_OUT for cell in failed_cells):
        return ObligationReasonCode.TIMED_OUT, budget
    if any(cell.status in {CellStatus.INVALID, CellStatus.FAILED}
           for cell in failed_cells) or any(gap.gap_class is GapClass.AUTHORITY_ERROR for gap in gaps):
        return ObligationReasonCode.INVALID_RESPONSE, budget
    if any(cell.status in {CellStatus.NOT_LAUNCHED, CellStatus.BLOCKED, CellStatus.CANCELED}
           for cell in failed_cells):
        return ObligationReasonCode.MODEL_BUDGET, BudgetDisposition.CELL_BUDGET_EXHAUSTED

    if budget in {
        BudgetDisposition.CLAIMS_PER_PACKAGE_CAP,
        BudgetDisposition.MAX_ACTIVE_CLAIMS,
        BudgetDisposition.CELL_BUDGET_EXHAUSTED,
        BudgetDisposition.PACKAGE_NOT_LAUNCHED,
    }:
        return ObligationReasonCode.MODEL_BUDGET, budget

    if round_stop_reason is not None and round_stop_reason != "stable":
        if round_stop_reason == "max_rounds":
            return ObligationReasonCode.MODEL_BUDGET, BudgetDisposition.MAX_ROUNDS_CUTOFF
        return ObligationReasonCode.MODEL_BUDGET, BudgetDisposition.CELL_BUDGET_EXHAUSTED

    if any(gap.gap_class is GapClass.BUDGET_GAP for gap in relevant_gaps):
        return ObligationReasonCode.MODEL_BUDGET, budget

    return ObligationReasonCode.NO_DECISIVE_EVIDENCE, budget


def semantic_round_fingerprint(obligations: Iterable[EvidenceObligation]) -> list[tuple[str, str]]:
    """Return canonical ``(obligation_id, state)`` pairs for round-convergence hashing.

    Repeating an already-open obligation across cells or rounds keeps ``(obligation_id, "open")``
    unchanged so actor/round repetition cannot defeat convergence, while opening a new obligation or
    transitioning an obligation to ``satisfied`` / ``superseded`` / ``withdrawn`` changes state once.
    """
    return sorted((ob.obligation_id, ob.state.value) for ob in obligations)


def pending_followup_requests(
    obligations: Iterable[EvidenceObligation],
    *,
    max_requests: int,
) -> tuple[tuple[dict[str, Any], ...], tuple[str, ...]]:
    """Return ``(pending_request_dicts, cutoff_obligation_ids)`` for the next bounded round.

    Only ``OPEN`` canonical obligations are eligible for follow-up; already ``SATISFIED``,
    ``UNSATISFIED`` (such as ``outside_package``), ``SUPERSEDED``, and ``WITHDRAWN`` obligations are
    never re-forwarded.
    """
    if max_requests < 0:
        raise ValueError("max_requests must be non-negative")
    open_obs = sorted(
        (ob for ob in obligations if ob.state is ObligationState.OPEN),
        key=lambda item: (item.round_opened, item.obligation_id),
    )
    selected = open_obs[:max_requests]
    cutoff = tuple(item.obligation_id for item in open_obs[max_requests:])
    payloads: list[dict[str, Any]] = []
    for ob in selected:
        row: dict[str, Any] = {
            "obligation_id": ob.obligation_id,
            "claim_id": ob.claim_id,
            "predicate": ob.predicate.value,
            "requested_kind": ob.requested_kind,
            "anchors": list(ob.anchors),
            "question": ob.question,
        }
        if ob.requested_specialist is not None:
            row["specialist"] = ob.requested_specialist
        payloads.append(row)
    return tuple(payloads), cutoff


def resolve_transport_receipt(
    receipt: CoverageReceiptRef,
    obligations_by_id: Mapping[str, EvidenceObligation] | None = None,
) -> TransportResolutionView:
    """Join a ``HUNT-C`` transport receipt against ``TRI-C`` canonical obligations.

    - Legacy delivery-only receipts without ``canonical_request_id`` or without a bound ``TRI-C``
      obligation explicitly retain ``resolution_basis = "legacy_resolution_unknown"`` and
      ``semantic_state = "unknown"`` — never ``"satisfied"``.
    - A receipt with ``delivery_state == "served"`` or ``"delivered"`` bound to an ``OPEN`` or
      ``UNSATISFIED`` obligation reports ``TRI-C``'s semantic state, proving transport never implies
      resolution.
    """
    lookup = obligations_by_id or {}
    if receipt.canonical_request_id is None or receipt.delivery_state == "legacy_delivery_only":
        return TransportResolutionView(
            receipt_id=receipt.receipt_id,
            artifact_sha256=receipt.artifact_sha256,
            delivery_state=receipt.delivery_state,
            canonical_request_id=receipt.canonical_request_id,
            canonical_resolution_ref=None,
            resolution_basis="legacy_resolution_unknown",
            semantic_state="unknown",
            reason_code=None,
        )
    ob = lookup.get(receipt.canonical_request_id)
    if ob is None:
        return TransportResolutionView(
            receipt_id=receipt.receipt_id,
            artifact_sha256=receipt.artifact_sha256,
            delivery_state=receipt.delivery_state,
            canonical_request_id=receipt.canonical_request_id,
            canonical_resolution_ref=None,
            resolution_basis="legacy_resolution_unknown",
            semantic_state="unknown",
            reason_code=None,
        )
    resolution_digest = sha256_hex(obligation_json(ob))
    return TransportResolutionView(
        receipt_id=receipt.receipt_id,
        artifact_sha256=receipt.artifact_sha256,
        delivery_state=receipt.delivery_state,
        canonical_request_id=ob.obligation_id,
        canonical_resolution_ref=f"{ob.obligation_id}:{resolution_digest}",
        resolution_basis="tri_c_verified_resolution",
        semantic_state=ob.state.value,
        reason_code=ob.resolution.reason_code.value,
    )


def obligation_json(obligation: EvidenceObligation) -> dict[str, Any]:
    """Serialize ``obligation`` to a closed ``evidence-obligation/1`` JSON dictionary."""
    return {
        "schema": OBLIGATION_SCHEMA,
        "obligation_id": obligation.obligation_id,
        "policy_version": obligation.policy_version,
        "origin_request_ids": list(obligation.origin_request_ids),
        "claim_id": obligation.claim_id,
        "predicate": obligation.predicate.value,
        "subject_binding": _subject_binding_json(obligation.subject_binding),
        "anchors": list(obligation.anchors),
        "question": obligation.question,
        "canonical_question": obligation.canonical_question,
        "requested_kind": obligation.requested_kind,
        "requested_specialist": obligation.requested_specialist,
        "origin_cell_ids": list(obligation.origin_cell_ids),
        "round_opened": obligation.round_opened,
        "required_evidence_class": obligation.required_evidence_class.value,
        "admissible_producer_ids": list(obligation.admissible_producer_ids),
        "scope_ceiling": obligation.scope_ceiling,
        "completeness_required": obligation.completeness_required,
        "state": obligation.state.value,
        "resolution": {
            "relation_ids": list(obligation.resolution.relation_ids),
            "warrant_ids": list(obligation.resolution.warrant_ids),
            "read_receipt_refs": list(obligation.resolution.read_receipt_refs),
            "evaluated_round": obligation.resolution.evaluated_round,
            "resolution_rule": obligation.resolution.resolution_rule,
            "reason_code": obligation.resolution.reason_code.value,
            "polarity": obligation.resolution.polarity.value if obligation.resolution.polarity else None,
            "superseded_by": obligation.resolution.superseded_by,
        },
        "coverage_receipt_refs": [
            {
                "receipt_id": ref.receipt_id,
                "artifact_sha256": ref.artifact_sha256,
                "canonical_request_id": ref.canonical_request_id,
                "delivery_state": ref.delivery_state,
                "semantic_resolution": ref.semantic_resolution,
            }
            for ref in obligation.coverage_receipt_refs
        ],
        "remaining_gap_ids": list(obligation.remaining_gap_ids),
        "attempted_retrieval_ids": list(obligation.attempted_retrieval_ids),
        "budget_disposition": obligation.budget_disposition.value,
    }


_REQUIRED_TOP_KEYS: frozenset[str] = frozenset({
    "schema", "obligation_id", "policy_version", "origin_request_ids", "claim_id", "predicate",
    "subject_binding", "anchors", "question", "canonical_question", "requested_kind",
    "requested_specialist", "origin_cell_ids", "round_opened", "required_evidence_class",
    "admissible_producer_ids", "scope_ceiling", "completeness_required", "state", "resolution",
    "coverage_receipt_refs", "remaining_gap_ids", "attempted_retrieval_ids", "budget_disposition",
})

_REQUIRED_BINDING_KEYS: frozenset[str] = frozenset({
    "affected_entity_ids", "operation_id", "sink_id", "build_scope_id",
})

_REQUIRED_RESOLUTION_KEYS: frozenset[str] = frozenset({
    "relation_ids", "warrant_ids", "read_receipt_refs", "evaluated_round",
    "resolution_rule", "reason_code", "polarity", "superseded_by",
})

_REQUIRED_COVERAGE_KEYS: frozenset[str] = frozenset({
    "receipt_id", "artifact_sha256", "canonical_request_id", "delivery_state", "semantic_resolution",
})


def _require_str_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise IntegrityError(f"obligation {label} must be a list of strings")
    return tuple(value)


def obligation_from_json(raw: Mapping[str, Any]) -> EvidenceObligation:
    """Parse and cryptographically validate a closed ``evidence-obligation/1`` JSON dictionary."""
    if not isinstance(raw, Mapping) or set(raw) != _REQUIRED_TOP_KEYS:
        raise IntegrityError("malformed evidence-obligation/1 top-level keys")
    if raw.get("schema") != OBLIGATION_SCHEMA:
        raise IntegrityError(f"unexpected evidence obligation schema: {raw.get('schema')!r}")

    raw_binding = raw.get("subject_binding")
    if not isinstance(raw_binding, Mapping) or set(raw_binding) != _REQUIRED_BINDING_KEYS:
        raise IntegrityError("malformed evidence obligation subject_binding")
    affected_ids = _require_str_list(raw_binding["affected_entity_ids"], "subject_binding.affected_entity_ids")
    for opt_key in ("operation_id", "sink_id", "build_scope_id"):
        if raw_binding[opt_key] is not None and not isinstance(raw_binding[opt_key], str):
            raise IntegrityError(f"malformed obligation subject_binding.{opt_key}")
    binding = SubjectBinding(
        affected_entity_ids=affected_ids,
        operation_id=raw_binding["operation_id"],
        sink_id=raw_binding["sink_id"],
        build_scope_id=raw_binding["build_scope_id"],
    )

    raw_res = raw.get("resolution")
    if not isinstance(raw_res, Mapping) or set(raw_res) != _REQUIRED_RESOLUTION_KEYS:
        raise IntegrityError("malformed evidence obligation resolution")
    try:
        reason_code = ObligationReasonCode(raw_res["reason_code"])
        polarity = ResolutionPolarity(raw_res["polarity"]) if raw_res["polarity"] is not None else None
        predicate = Predicate(raw["predicate"])
        req_class = RequiredEvidenceClass(raw["required_evidence_class"])
        state = ObligationState(raw["state"])
        budget = BudgetDisposition(raw["budget_disposition"])
    except (ValueError, KeyError) as exc:
        raise IntegrityError(f"invalid enum value in evidence obligation: {exc}") from exc

    if raw_res["superseded_by"] is not None and not isinstance(raw_res["superseded_by"], str):
        raise IntegrityError("malformed obligation resolution.superseded_by")
    if not isinstance(raw_res["resolution_rule"], str):
        raise IntegrityError("malformed obligation resolution.resolution_rule")
    resolution = ObligationResolution(
        relation_ids=_require_str_list(raw_res["relation_ids"], "resolution.relation_ids"),
        warrant_ids=_require_str_list(raw_res["warrant_ids"], "resolution.warrant_ids"),
        read_receipt_refs=_require_str_list(raw_res["read_receipt_refs"], "resolution.read_receipt_refs"),
        evaluated_round=raw_res["evaluated_round"],
        resolution_rule=raw_res["resolution_rule"],
        reason_code=reason_code,
        polarity=polarity,
        superseded_by=raw_res["superseded_by"],
    )

    raw_cov = raw.get("coverage_receipt_refs")
    if not isinstance(raw_cov, list):
        raise IntegrityError("obligation coverage_receipt_refs must be a list")
    cov_refs: list[CoverageReceiptRef] = []
    for item in raw_cov:
        if not isinstance(item, Mapping) or set(item) != _REQUIRED_COVERAGE_KEYS:
            raise IntegrityError("malformed obligation coverage_receipt_ref")
        cov_refs.append(
            CoverageReceiptRef(
                receipt_id=item["receipt_id"],
                artifact_sha256=item["artifact_sha256"],
                canonical_request_id=item["canonical_request_id"],
                delivery_state=item["delivery_state"],
                semantic_resolution=item["semantic_resolution"],
            )
        )

    if raw["requested_specialist"] is not None and not isinstance(raw["requested_specialist"], str):
        raise IntegrityError("malformed obligation requested_specialist")
    for str_key in ("obligation_id", "policy_version", "claim_id", "question",
                    "canonical_question", "requested_kind", "scope_ceiling"):
        if not isinstance(raw[str_key], str):
            raise IntegrityError(f"obligation {str_key} must be a string")

    try:
        return EvidenceObligation(
            obligation_id=raw["obligation_id"],
            policy_version=raw["policy_version"],
            origin_request_ids=_require_str_list(raw["origin_request_ids"], "origin_request_ids"),
            claim_id=raw["claim_id"],
            predicate=predicate,
            subject_binding=binding,
            anchors=_require_str_list(raw["anchors"], "anchors"),
            question=raw["question"],
            canonical_question=raw["canonical_question"],
            requested_kind=raw["requested_kind"],
            requested_specialist=raw["requested_specialist"],
            origin_cell_ids=_require_str_list(raw["origin_cell_ids"], "origin_cell_ids"),
            round_opened=raw["round_opened"],
            required_evidence_class=req_class,
            admissible_producer_ids=_require_str_list(raw["admissible_producer_ids"], "admissible_producer_ids"),
            scope_ceiling=raw["scope_ceiling"],
            completeness_required=raw["completeness_required"],
            state=state,
            resolution=resolution,
            coverage_receipt_refs=tuple(cov_refs),
            remaining_gap_ids=_require_str_list(raw["remaining_gap_ids"], "remaining_gap_ids"),
            attempted_retrieval_ids=_require_str_list(raw["attempted_retrieval_ids"], "attempted_retrieval_ids"),
            budget_disposition=budget,
        )
    except ValueError as exc:
        raise IntegrityError(f"invalid evidence obligation content: {exc}") from exc
