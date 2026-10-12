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
    security_predicate: str
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
