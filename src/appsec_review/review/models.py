"""Shared closed vocabularies and core records for the inference security review.

This module is the contract between review components. Enum values are serialized exactly as
written; adding or renaming a member is a schema version change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from appsec_review.review.identity import make_id

MAX_GAP_REASON = 256


class Lane(StrEnum):
    LEAD = "lead"      # lane A: admitted reported critical/high/unknown leads
    HUNT = "hunt"      # lane B: ranked open discovery


class Role(StrEnum):
    HYPOTHESIS_HUNTER = "hypothesis_hunter"
    RED_TEAM_ANALYST = "red_team_analyst"
    BLUE_TEAM_REFUTER = "blue_team_refuter"
    INDEPENDENT_VERIFIER = "independent_verifier"
    INDEPENDENT_SCORER = "independent_scorer"
    POC_DESIGNER = "poc_designer"
    POC_VERIFIER = "poc_verifier"
    ATTACK_CHAIN_ANALYST = "attack_chain_analyst"
    FINDING_ADJUDICATOR = "finding_adjudicator"
    COMPLETENESS_REVIEWER = "completeness_reviewer"
    LEAD_TRIAGER = "lead_triager"                # review.lead_triage: assigns a lead's priority severity only
    ADJUDICATION_JUDGE = "adjudication_judge"   # decides which side of a claim is correct; never sets a state


class BlueTask(StrEnum):
    CONTROL = "blue_control"            # seek an effective guard or control
    REACHABILITY = "blue_reachability"  # seek a reachability or configuration break


class HuntStrategy(StrEnum):
    VARIANT = "variant"
    SINK_UP = "sink_up"
    ENTRY_DOWN = "entry_down"
    CONTROL_GAP = "control_gap"
    PERSONA_SWEEP = "persona_sweep"


class ClaimState(StrEnum):
    PROPOSED = "proposed"
    SUPPORTED = "supported"
    CONFIRMED = "confirmed"
    CONTRADICTED = "contradicted"
    NOT_REACHABLE = "not_reachable"
    NOT_EXPLOITABLE_IN_OBSERVED_CONFIGURATION = "not_exploitable_in_observed_configuration"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    DUPLICATE = "duplicate"
    OUT_OF_SCOPE = "out_of_scope"
    COVERAGE_GAP = "coverage_gap"


class Predicate(StrEnum):
    """Closed obligation predicates (obligation-rules/1, design R4)."""

    AFFECTED_CONSTRUCT = "affected_construct"
    ATTACKER_INPUT_CONTROL = "attacker_input_control"
    SOURCE_TO_SINK_REACHABILITY = "source_to_sink_reachability"
    MISSING_OR_INEFFECTIVE_GUARD = "missing_or_ineffective_guard"
    CONFIGURATION_ENABLES = "configuration_enables"
    SECURITY_IMPACT = "security_impact"


SECURITY_PREDICATES_VERSION = "security-predicates/1"


class SecurityPredicate(StrEnum):
    """Closed security-consequence vocabulary of a claim (``security-predicates/1``, design R7).

    Rolled up from the weakness classes of the security tag taxonomy; see
    :data:`SECURITY_PREDICATE_CWE_ROLLUP` and the design's R7 table. It is part of claim identity,
    so adding, renaming, or remapping a member is a vocabulary version change. Anything that fits
    no member is ``OTHER``, which normalization records with a gap.
    """

    MEMORY_CORRUPTION = "memory_corruption"
    OUT_OF_BOUNDS_READ = "out_of_bounds_read"
    USE_AFTER_FREE = "use_after_free"
    INTEGER_ERROR = "integer_error"
    INJECTION = "injection"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    CODE_INJECTION = "code_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    DESERIALIZATION = "deserialization"
    AUTHN_BYPASS = "authn_bypass"
    AUTHZ_BYPASS = "authz_bypass"
    INFO_DISCLOSURE = "info_disclosure"
    CRYPTO_WEAKNESS = "crypto_weakness"
    RACE_CONDITION = "race_condition"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    INSECURE_CONFIGURATION = "insecure_configuration"
    SUPPLY_CHAIN_COMPROMISE = "supply_chain_compromise"
    OTHER = "other"


_SP = SecurityPredicate
# security-predicates/1 roll-up of the taxonomy's weakness tables (docs/architecture/
# security-tag-taxonomy.md sections 3 and 5) and the CERT categories they cite. It documents which
# member a weakness normally implies; it never rewrites a worker's predicate (identity uses the
# predicate the claim states). CWE-20 (Improper Input Validation) is deliberately absent: it names
# no consequence, so the claim states the consequence the missing validation enables.
SECURITY_PREDICATE_CWE_ROLLUP: dict[str, SecurityPredicate] = {
    **dict.fromkeys(("CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-787", "CWE-788", "CWE-805", "CWE-134",
                     "CWE-457", "CWE-908"), _SP.MEMORY_CORRUPTION),
    **dict.fromkeys(("CWE-125", "CWE-126", "CWE-127"), _SP.OUT_OF_BOUNDS_READ),
    **dict.fromkeys(("CWE-416", "CWE-415", "CWE-825"), _SP.USE_AFTER_FREE),
    **dict.fromkeys(("CWE-190", "CWE-191", "CWE-681", "CWE-682", "CWE-369"), _SP.INTEGER_ERROR),
    **dict.fromkeys(("CWE-74", "CWE-79", "CWE-90", "CWE-91", "CWE-611", "CWE-643", "CWE-943"), _SP.INJECTION),
    **dict.fromkeys(("CWE-77", "CWE-78"), _SP.COMMAND_INJECTION),
    **dict.fromkeys(("CWE-89", "CWE-564"), _SP.SQL_INJECTION),
    **dict.fromkeys(("CWE-94", "CWE-95", "CWE-96", "CWE-917"), _SP.CODE_INJECTION),
    **dict.fromkeys(("CWE-22", "CWE-23", "CWE-36", "CWE-59"), _SP.PATH_TRAVERSAL),
    **dict.fromkeys(("CWE-918",), _SP.SSRF),
    **dict.fromkeys(("CWE-502",), _SP.DESERIALIZATION),
    **dict.fromkeys(("CWE-287", "CWE-306", "CWE-798", "CWE-290", "CWE-384"), _SP.AUTHN_BYPASS),
    **dict.fromkeys(("CWE-284", "CWE-285", "CWE-269", "CWE-352", "CWE-639", "CWE-862", "CWE-863"),
                    _SP.AUTHZ_BYPASS),
    **dict.fromkeys(("CWE-200", "CWE-209", "CWE-532", "CWE-668"), _SP.INFO_DISCLOSURE),
    **dict.fromkeys(("CWE-311", "CWE-319", "CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-338", "CWE-347"),
                    _SP.CRYPTO_WEAKNESS),
    **dict.fromkeys(("CWE-362", "CWE-366", "CWE-367"), _SP.RACE_CONDITION),
    **dict.fromkeys(("CWE-400", "CWE-674", "CWE-770", "CWE-789", "CWE-1333"), _SP.RESOURCE_EXHAUSTION),
    **dict.fromkeys(("CWE-16", "CWE-250", "CWE-276", "CWE-732", "CWE-778"), _SP.INSECURE_CONFIGURATION),
    **dict.fromkeys(("CWE-494", "CWE-829", "CWE-1104", "CWE-1357", "CWE-1395"), _SP.SUPPLY_CHAIN_COMPROMISE),
}
# CERT C categories the taxonomy cites, rolled up the same way (by rule).
SECURITY_PREDICATE_CERT_ROLLUP: dict[str, SecurityPredicate] = {
    "cert-c:mem30-c": _SP.USE_AFTER_FREE, "cert-c:int32-c": _SP.INTEGER_ERROR,
    "cert-c:arr30-c": _SP.MEMORY_CORRUPTION, "cert-c:arr36-c": _SP.MEMORY_CORRUPTION,
    "cert-c:con43-c": _SP.RACE_CONDITION, "cert-c:fio30-c": _SP.MEMORY_CORRUPTION,
    "cert-c:env33-c": _SP.COMMAND_INJECTION, "cert-c:exp33-c": _SP.MEMORY_CORRUPTION,
}
del _SP


class RelationKind(StrEnum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    DUPLICATES = "duplicates"
    POSSIBLE_DUPLICATE = "possible_duplicate"
    DERIVES_FROM = "derives_from"
    SUPERSEDES = "supersedes"
    QUALIFIES = "qualifies"
    COMPONENT_OF_CHAIN = "component_of_chain"
    REQUESTS_EVIDENCE = "requests_evidence"


class Admissibility(StrEnum):
    DIRECT = "direct"
    DIRECT_FOR_MAPPED_PREDICATE = "direct_for_mapped_predicate"
    # Authentic and relevant, but supporting the proposition needs human-style judgment of the cited
    # text (``predicate-admission/1``). Recorded and shown; never satisfies an obligation.
    ANALYST_ASSESSED = "analyst_assessed"
    INDIRECT = "indirect"


class CellStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    TIMED_OUT = "timed_out"
    CANCELED = "canceled"
    INVALID = "invalid"
    NOT_LAUNCHED = "not_launched"


class GapClass(StrEnum):
    """Design "Error and gap taxonomy". Only INTEGRITY and PUBLICATION block publication."""

    INTEGRITY_ERROR = "integrity_error"
    AUTHORITY_ERROR = "authority_error"
    SCHEMA_ERROR = "schema_error"
    WORKER_GAP = "worker_gap"
    COVERAGE_GAP = "coverage_gap"
    EVIDENCE_GAP = "evidence_gap"
    INDEPENDENCE_GAP = "independence_gap"
    SCORE_GAP = "score_gap"
    POC_POLICY_GAP = "poc_policy_gap"
    POC_EXECUTION_GAP = "poc_execution_gap"
    CHAIN_GAP = "chain_gap"
    BUDGET_GAP = "budget_gap"
    ROUTING_GAP = "routing_gap"
    PUBLICATION_ERROR = "publication_error"


BLOCKING_GAP_CLASSES = frozenset({GapClass.INTEGRITY_ERROR, GapClass.PUBLICATION_ERROR})


class IntegrityError(RuntimeError):
    """A framework-integrity failure. It blocks publication; never convert it into a gap."""


@dataclass(frozen=True, slots=True)
class EvidenceRelation:
    relation_id: str                 # evrel-<sha256>, design R3
    claim_id: str
    predicate: Predicate
    kind: RelationKind               # SUPPORTS, CONTRADICTS or QUALIFIES for evidence
    entity_id: str                   # accepted retrieval LogicalIdentity
    entity_kind: str                 # retrieval EntityKind value
    admissibility: Admissibility
    shard_id: str
    content_sha256: str
    locator: str
    complete: bool
    producing_cell_id: str
    retrieval_receipt_sha256: str | None
    reason: str | None = None        # why the application recorded a weaker kind than the cell asked for
    # ``adjudication_judge`` for a relation derived from a judge's citations; ``None`` for the relations the
    # producing role itself authored. R5 and scoring count only the latter (review-judge-and-poc.md section 3.4).
    provenance: str | None = None


class JudgeVerdictValue(StrEnum):
    """A judge's de-shuffled verdict on one claim (``judge-result/1``)."""

    RED_CORRECT = "red_correct"
    BLUE_CORRECT = "blue_correct"
    PARTLY = "partly"
    NEITHER = "neither"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class JudgePredicateVerdict:
    predicate: Predicate
    verdict: JudgeVerdictValue
    cites: tuple[str, ...]           # resolved logical identities, sorted


@dataclass(frozen=True, slots=True)
class JudgeVerdict:
    """The ledger record of one judge cell's verdict (``judge_verdict`` event). It sets no claim state."""

    verdict_id: str                  # judge-<sha256> over (claim, cell)
    claim_id: str
    verdict: JudgeVerdictValue
    per_predicate: tuple[JudgePredicateVerdict, ...]
    reason: str
    cell_id: str
    judge_model_distinct: bool


@dataclass(frozen=True, slots=True)
class Gap:
    gap_id: str
    gap_class: GapClass
    subject_id: str                  # claim, package, cell, shard, unit or request identity
    reason: str                      # bounded, redacted; machines use gap_class only
    predicate: Predicate | None = None
    round: int = 0


def make_gap(gap_class: GapClass, subject_id: str, reason: str, *, predicate: Predicate | None = None,
             round: int = 0) -> Gap:
    """Return a gap whose identity covers its class, subject, predicate, round, and bounded reason."""
    bounded = " ".join(str(reason).split())[:MAX_GAP_REASON]
    body = {"gap_class": GapClass(gap_class).value, "subject_id": subject_id, "reason": bounded,
            "predicate": predicate.value if predicate is not None else None, "round": round}
    return Gap(make_id("gap", 1, body), GapClass(gap_class), subject_id, bounded, predicate, round)


@dataclass(frozen=True, slots=True)
class Claim:
    claim_id: str
    lane: Lane
    package_id: str
    affected_entities: tuple[str, ...]   # sorted accepted logical identities (R7)
    weakness_cwe: str | None             # e.g. "CWE-120"
    security_predicate: SecurityPredicate  # security-predicates/1 member
    preconditions: tuple[str, ...]       # sorted members of preconditions/1
    statement: str                       # prose; excluded from identity
    state: ClaimState = ClaimState.PROPOSED
    duplicate_of: str | None = None
    origin_cell_ids: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class CellRecord:
    """Exactly one terminal record per expected cell (design rule 6)."""

    cell_id: str                     # cell/v1 fingerprint identity
    lane: Lane
    package_id: str
    role: Role
    persona: str
    stack_profile: str
    task: str                        # strategy, blue task, or stage task id
    claim_id: str | None
    status: CellStatus
    attempts: int
    gap_ids: tuple[str, ...] = field(default_factory=tuple)
    receipt_sha256: str | None = None
    # Judge cells only: the (side, role) pairs behind sides A and B of the cell's request
    # (review-judge-and-poc.md section 3.2). It is kept here and appears nowhere in the model-facing request.
    side_map: tuple[tuple[str, str], ...] | None = None
