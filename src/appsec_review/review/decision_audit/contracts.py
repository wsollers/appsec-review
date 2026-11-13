"""Closed, immutable contracts for the model-free decision-audit sidecar.

All constructors and readers validate the same schemas. Content identities exclude only
their own ``record_id``. The existing inner review handoff is an input: it must never
reference this sidecar. References describe provenance, not permission or source proof.

Paths are lexically run-relative here. Publication/readers must additionally verify
accepted pins, filesystem custody and bytes through the existing bound-artifact APIs.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from enum import StrEnum
from functools import lru_cache
import hashlib
import json
from typing import ClassVar, TypeAlias

from appsec_review.application_paths import application_asset
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.review.adjudication import DecidingRow
from appsec_review.review.models import Admissibility, CellStatus, IntegrityError, Predicate, RelationKind, Role
from appsec_review.storage.atomic import canonical_json

MAX_EXPLANATION = 2000
MAX_INLINE_REFERENCES = 256
MAX_SHARD_RECORDS = 5000
MAX_SHARD_BYTES = 8 * 1024 * 1024
SCHEMA_FILE = "review-decision-audit.schema.json"
DECISION_SCHEMA = "appsec-review/review-decision/1"
VERIFICATION_SCHEMA = "appsec-review/verification-coverage/1"
BASIS_SCHEMA = "appsec-review/decision-basis/1"
MANIFEST_SCHEMA = "appsec-review/review-audit-manifest/1"
JSON: TypeAlias = None | bool | int | str | list["JSON"] | dict[str, "JSON"]


class AbsenceReason(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    PRE_CLAIM = "pre_claim"
    NOT_PRODUCED = "not_produced"
    NOT_COMMISSIONED = "not_commissioned"
    LEGACY_UNRECORDED = "legacy_unrecorded"
    UNAVAILABLE = "unavailable"
    REDACTED = "redacted"
    UNKNOWN_MODEL_REVISION = "unknown_model_revision"


class Stage(StrEnum):
    COLLECTION = "collection"
    SEVERITY_TRIAGE = "severity_triage"
    ADMISSION = "admission"
    PACKAGE_ASSEMBLY = "package_assembly"
    RED_DISCOVERY = "red_discovery"
    PROPOSAL_NORMALIZATION = "proposal_normalization"
    CLAIM_CAP = "claim_cap"
    BLUE_REVIEW = "blue_review"
    INDEPENDENT_VERIFICATION = "independent_verification"
    JUDGE_REVIEW = "judge_review"
    ADJUDICATION = "adjudication"
    SCORING = "scoring"
    PUBLICATION = "publication"


class ReasonCode(StrEnum):
    RECORDED_DECISION = "recorded_decision"
    UNSTATED = "unstated"
    SEVERITY_BELOW_ADMISSION = "severity_below_admission"
    ADMISSION_POLICY = "admission_policy"
    INVALID_OUTPUT = "invalid_output"
    TIMED_OUT = "timed_out"
    NOT_LAUNCHED = "not_launched"
    BUDGET_LIMIT = "budget_limit"
    OUTSIDE_SCOPE = "outside_scope"
    EXACT_DUPLICATE = "exact_duplicate"
    DIRECT_SUPPORT = "direct_support"
    DIRECT_CONTRADICTION = "direct_contradiction"
    UNRESOLVED_CONTRADICTION = "unresolved_contradiction"
    MISSING_EVIDENCE = "missing_evidence"
    PUBLICATION_POLICY = "publication_policy"
    INPUT_UNAVAILABLE = "input_unavailable"


class BasisStatus(StrEnum):
    UNSTATED = "unstated"
    NARRATIVE_ONLY = "narrative_only"
    CITED_NONDECIDING = "cited_nondeciding"
    EXISTING_POLICY = "existing_policy"


class EvidenceUse(StrEnum):
    AVAILABLE = "available"
    SUPPLIED = "supplied"
    READ = "read"
    CITED = "cited"


class NoncountedReason(StrEnum):
    ANALYST_ASSESSED = "analyst_assessed"
    INDIRECT = "indirect"
    INCOMPLETE = "incomplete"
    JUDGE_NONDECIDING = "judge_nondeciding"
    QUALIFYING = "qualifying"
    NOT_REQUIRED = "not_required"
    NOT_EVALUATED = "not_evaluated"


class CoverageReason(StrEnum):
    LEGACY_UNAVAILABLE = "legacy_unavailable"
    INPUT_UNAVAILABLE = "input_unavailable"
    NOT_COMMISSIONED = "not_commissioned"
    BOUNDED_OMISSION = "bounded_omission"
    FAILED_INPUT = "failed_input"
    PARTIAL_INPUT = "partial_input"


class ProductKind(StrEnum):
    DECISION = "decision"
    VERIFICATION = "verification_coverage"
    BASIS = "decision_basis"


class Population(StrEnum):
    DECISIONS = "decision"
    VERIFICATIONS = "verification_coverage"
    BASES = "decision_basis"
    LEADS = "collected_leads"
    CELLS = "expected_cells"
    PROPOSALS = "emitted_proposals"


class ReferenceField(StrEnum):
    SOURCES = "sources"
    RELATIONS = "relations"
    ORIGIN_PROPOSALS = "origin_proposals"
    WARRANTS = "warrants"
    REQUEST_RESOLUTIONS = "request_resolutions"
    HUNT_RECEIPTS = "hunt_receipts"


class SupportCoverage(StrEnum):
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    CONFLICTED = "conflicted"
    MISSING = "missing"
    UNKNOWN = "unknown"


@lru_cache(maxsize=1)
def _schemas() -> SchemaSet:
    path = application_asset(f"docs/schemas/{SCHEMA_FILE}")
    schemas = SchemaSet(path.parents[2] / SCHEMA_DIRECTORY)
    document = json.loads(path.read_text(encoding="utf-8"))
    schemas.documents[SCHEMA_FILE] = document
    for name in document["$defs"]:
        schemas.documents[f"audit-{name}.schema.json"] = {
            "$ref": f"{SCHEMA_FILE}#/$defs/{name}"}
    return schemas


def _validate(name: str, value: object) -> None:
    try:
        _schemas().validate(f"audit-{name}", value)
    except ValueError as exc:
        raise IntegrityError(f"decision audit {name}: {exc}") from exc


def _json(value: object) -> JSON:
    if isinstance(value, _Contract):
        return value.to_dict()
    if isinstance(value, tuple):
        return [_json(item) for item in value]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    raise IntegrityError("decision audit values must be typed immutable contract values")


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise IntegrityError("decision audit requires a JSON object")
    return dict(value)


def _array(value: object) -> list[object]:
    if not isinstance(value, list):
        raise IntegrityError("decision audit requires a JSON array")
    return value


def _unique(values: Sequence[object], label: str) -> None:
    if len(set(values)) != len(values):
        raise IntegrityError(f"duplicate or colliding {label}")


def _sort(record: _Contract, *names: str) -> None:
    for name in names:
        items = getattr(record, name)
        if not isinstance(items, tuple):
            raise IntegrityError(f"{name} must be an immutable tuple")
        encoded = [canonical_json(_json(item)) for item in items]
        _unique(encoded, name)
        object.__setattr__(record, name, tuple(item for _, item in sorted(zip(encoded, items))))


class _Contract:
    DEF: ClassVar[str]

    def to_dict(self) -> dict[str, JSON]:
        return {field.name: _json(getattr(self, field.name)) for field in fields(self)}

    def __post_init__(self) -> None:
        _validate(self.DEF, self.to_dict())


@dataclass(frozen=True, slots=True)
class Link(_Contract):
    """An original identity, or an explicit reason that no such identity exists."""
    DEF = "link"
    value: str | None
    absence_reason: AbsenceReason | None


@dataclass(frozen=True, slots=True)
class Round(_Contract):
    DEF = "round"
    value: int | None
    absence_reason: AbsenceReason | None


@dataclass(frozen=True, slots=True)
class HashLink(_Contract):
    DEF = "hash_link"
    value: str | None
    absence_reason: AbsenceReason | None


@dataclass(frozen=True, slots=True)
class Check(_Contract):
    """An observed check; unknown is not a successful or failed check."""
    DEF = "check"
    value: bool | None
    absence_reason: AbsenceReason | None


@dataclass(frozen=True, slots=True)
class Origin(_Contract):
    DEF = "origin"
    run_id: str
    review_attempt_id: str
    target_snapshot: str
    accepted_manifest_sha256: str
    review_handoff_sha256: str
    ledger_head_sha256: str
    projection_sha256: str
    package_manifest_sha256: str
    lead_package_manifest_sha256: HashLink
    configuration_sha256: str
    guidance_sha256: HashLink
    implementation_sha256: HashLink
    projection_policy_version: str
    projection_policy_sha256: str


@dataclass(frozen=True, slots=True)
class Subject(_Contract):
    DEF = "subject"
    lead_id: Link
    proposal_ref: Link
    claim_id: Link
    adjudication_id: Link
    finding_package_id: Link
    package_id: Link
    operation_id: Link
    component_id: Link
    build_scope_id: Link
    cell_id: Link
    round: Round

    def __post_init__(self) -> None:
        super(Subject, self).__post_init__()
        if not any(item.value is not None for item in
                   (self.lead_id, self.proposal_ref, self.claim_id, self.package_id, self.cell_id)):
            raise IntegrityError("decision subject has no original identity")
        if self.claim_id.value is None and (self.adjudication_id.value or self.finding_package_id.value):
            raise IntegrityError("pre-claim subject cannot name an adjudication or finding")


@dataclass(frozen=True, slots=True)
class SourceRef(_Contract):
    """Hash of actual artifact bytes; use labels never imply one another."""
    DEF = "source_ref"
    run_id: str
    path: str
    sha256: str
    record_id: Link
    uses: tuple[EvidenceUse, ...]

    def __post_init__(self) -> None:
        _sort(self, "uses")
        super(SourceRef, self).__post_init__()


@dataclass(frozen=True, slots=True)
class OptionalSource(_Contract):
    DEF = "optional_source"
    value: SourceRef | None
    absence_reason: AbsenceReason | None


@dataclass(frozen=True, slots=True)
class Explanation(_Contract):
    DEF = "explanation"
    text: str | None
    absence_reason: AbsenceReason | None
    redaction_reason: Link
    authority: str = "non_evidentiary"


@dataclass(frozen=True, slots=True)
class RelationRef(_Contract):
    DEF = "relation_ref"
    relation_id: str
    claim_id: str
    predicate: Predicate
    kind: RelationKind
    producing_cell_id: str
    actor_role: Role
    admissibility: Admissibility
    counted: bool
    noncounted_reason: NoncountedReason | None
    source: SourceRef

    def __post_init__(self) -> None:
        super(RelationRef, self).__post_init__()
        if self.source.record_id.value != self.relation_id:
            raise IntegrityError("relation source does not identify the original relation")
        if self.counted and (self.kind == RelationKind.QUALIFIES
                             or self.actor_role == Role.ADJUDICATION_JUDGE
                             or (self.kind == RelationKind.CONTRADICTS and self.actor_role in
                                 (Role.RED_TEAM_ANALYST, Role.HYPOTHESIS_HUNTER))
                             or self.admissibility not in
                             (Admissibility.DIRECT, Admissibility.DIRECT_FOR_MAPPED_PREDICATE)):
            raise IntegrityError("nondeciding relation cannot be counted")


@dataclass(frozen=True, slots=True)
class ContinuationRef(_Contract):
    """A hash-bound continuation of one named inline reference field, not evidence."""
    DEF = "continuation_ref"
    field: ReferenceField
    path: str
    sha256: str
    record_count: int
    byte_count: int


@dataclass(frozen=True, slots=True)
class OptionalSources(_Contract):
    DEF = "optional_sources"
    values: tuple[SourceRef, ...]
    absence_reason: AbsenceReason | None

    def __post_init__(self) -> None:
        _sort(self, "values")
        super(OptionalSources, self).__post_init__()
        _source_identities(self.values)


@dataclass(frozen=True, slots=True)
class FutureReferences(_Contract):
    """Only links: no future warrant or semantic request-resolution assertions."""
    DEF = "future_references"
    warrants: OptionalSources
    request_resolutions: OptionalSources
    hunt_receipts: OptionalSources
    authority: str = "non_authoritative_reference"


@dataclass(frozen=True, slots=True)
class CoverageCount(_Contract):
    DEF = "coverage_count"
    population: Population
    expected: int | None
    emitted: int
    omitted: int
    unavailable: int | None
    reason: CoverageReason | None

    def __post_init__(self) -> None:
        super(CoverageCount, self).__post_init__()
        if self.expected is not None:
            if self.unavailable is None or self.expected != self.emitted + self.omitted + self.unavailable:
                raise IntegrityError("coverage counts do not account for the expected population")
        elif self.unavailable is not None:
            raise IntegrityError("unknown expected population requires unknown unavailable count")
        incomplete = self.expected is None or self.omitted > 0 or self.unavailable != 0
        if incomplete != (self.reason is not None):
            raise IntegrityError("coverage absence/omission requires a reason; complete coverage does not")


@dataclass(frozen=True, slots=True)
class Context(_Contract):
    DEF = "context"
    origin: Origin
    subject: Subject
    sources: tuple[SourceRef, ...]
    relations: tuple[RelationRef, ...]
    origin_proposals: tuple[SourceRef, ...]
    continuations: tuple[ContinuationRef, ...]
    future: FutureReferences
    explanation: Explanation
    gap_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _sort(self, "sources", "relations", "origin_proposals", "continuations", "gap_ids")
        super(Context, self).__post_init__()
        _unique([item.relation_id for item in self.relations], "relation identities")
        _unique([item.path for item in self.continuations], "continuation paths")
        _source_identities(self.sources)
        if any(item.claim_id != self.subject.claim_id.value for item in self.relations):
            raise IntegrityError("relation belongs to a foreign claim")
        refs = (*self.sources, *self.origin_proposals,
                *self.future.warrants.values, *self.future.request_resolutions.values,
                *self.future.hunt_receipts.values)
        if len(refs) + len(self.relations) > MAX_INLINE_REFERENCES:
            raise IntegrityError("inline reference limit exceeded; use continuation shards")
        sources = _source_bindings(self)
        _check_sources(self.origin, sources)
        _check_paths((*sources, *self.continuations))
        future_fields = {ReferenceField.WARRANTS: self.future.warrants,
                         ReferenceField.REQUEST_RESOLUTIONS: self.future.request_resolutions,
                         ReferenceField.HUNT_RECEIPTS: self.future.hunt_receipts}
        if any(ref.field in future_fields and future_fields[ref.field].absence_reason is not None
               for ref in self.continuations):
            raise IntegrityError("absent future references cannot have a continuation")
        proposal_ids = [item.record_id.value for item in self.origin_proposals]
        if any(value is None for value in proposal_ids):
            raise IntegrityError("origin proposals require original proposal identities")
        _unique(proposal_ids, "origin proposal identities")


def _source_bindings(value: object) -> tuple[SourceRef, ...]:
    """Enumerate sources in the closed immutable record tree, including future nested fields."""
    if isinstance(value, SourceRef):
        return (value,)
    if isinstance(value, _Contract):
        return tuple(source for field in fields(value)
                     for source in _source_bindings(getattr(value, field.name)))
    if isinstance(value, tuple):
        return tuple(source for item in value for source in _source_bindings(item))
    return ()


def _source_identities(sources: Sequence[SourceRef]) -> None:
    _unique([(item.path, item.record_id.value) for item in sources], "source record references")


def _check_paths(sources: Sequence[SourceRef | ContinuationRef | ShardRef | ManifestRef]) -> None:
    paths: dict[str, str] = {}
    for source in sources:
        if source.path in paths and paths[source.path] != source.sha256:
            raise IntegrityError("source path has conflicting hash bindings")
        paths[source.path] = source.sha256


def _check_sources(origin: Origin, sources: Sequence[SourceRef]) -> None:
    _check_paths(sources)
    for source in sources:
        if source.run_id != origin.run_id:
            raise IntegrityError("source belongs to a foreign run")


class _Product(_Contract):
    SCHEMA: ClassVar[str]
    PREFIX: ClassVar[str]

    @property
    def record_id(self) -> str:
        return f"{self.PREFIX}-{hashlib.sha256(canonical_json(self._body())).hexdigest()}"

    def _body(self) -> dict[str, JSON]:
        return {"schema": self.SCHEMA, "visibility": "protected_audit",
                "authority": "projection_only", **super().to_dict()}

    def to_dict(self) -> dict[str, JSON]:
        return {**self._body(), "record_id": self.record_id}

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.to_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class DecisionRecord(_Product):
    DEF = "decision"
    SCHEMA = DECISION_SCHEMA
    PREFIX = "decision"
    context: Context
    stage: Stage
    outcome: str
    original_outcome: Link
    cell_receipt: OptionalSource
    reason_code: ReasonCode
    basis_status: BasisStatus
    deciding_row: DecidingRow | None
    deciding_row_absence_reason: AbsenceReason | None
    deciding_actor_roles: tuple[Role, ...]
    required_predicates: tuple[Predicate, ...]
    missing_predicates: tuple[Predicate, ...]

    def __post_init__(self) -> None:
        _sort(self, "deciding_actor_roles", "required_predicates", "missing_predicates")
        super(DecisionRecord, self).__post_init__()
        if not set(self.missing_predicates) <= set(self.required_predicates):
            raise IntegrityError("missing predicates must be required predicates")
        if self.stage == Stage.ADJUDICATION and self.context.subject.claim_id.value is None:
            raise IntegrityError("adjudication requires an original claim identity")
        roles = {item.actor_role for item in self.context.relations if item.counted}
        if not roles <= set(self.deciding_actor_roles):
            raise IntegrityError("deciding roles omit counted relation provenance")
        if Role.ADJUDICATION_JUDGE in self.deciding_actor_roles:
            raise IntegrityError("judge is not a deciding actor")
        if self.cell_receipt.value is not None:
            if self.context.subject.cell_id.value is None:
                raise IntegrityError("cell receipt requires an original cell identity")
        sources = _source_bindings(self)
        _check_sources(self.context.origin, sources)
        _check_paths((*sources, *self.context.continuations))


@dataclass(frozen=True, slots=True)
class Blindness(_Contract):
    DEF = "blindness"
    actor_distinct: Check
    conversation_fresh: Check
    prior_response_absent: Check
    shared_actor_cache_absent: Check
    request_check: OptionalSource
    passed: Check

    def __post_init__(self) -> None:
        super(Blindness, self).__post_init__()
        if self.passed.value is True and (self.request_check.value is None or
                any(check.value is not True for check in (self.actor_distinct, self.conversation_fresh,
                                                         self.prior_response_absent, self.shared_actor_cache_absent))):
            raise IntegrityError("passed blindness requires all observed checks and the request-check reference")


@dataclass(frozen=True, slots=True)
class Diversity(_Contract):
    DEF = "diversity"
    provider_distinct: Check
    model_profile_distinct: Check
    resolved_model_revision: Link


@dataclass(frozen=True, slots=True)
class PredicateCoverage(_Contract):
    DEF = "predicate_coverage"
    predicate: Predicate
    required: bool
    own_read_refs: tuple[SourceRef, ...]
    supporting_relation_ids: tuple[str, ...]
    contradicting_relation_ids: tuple[str, ...]
    qualifying_relation_ids: tuple[str, ...]
    coverage: SupportCoverage
    unknown_reason: AbsenceReason | None

    def __post_init__(self) -> None:
        _sort(self, "own_read_refs", "supporting_relation_ids", "contradicting_relation_ids",
              "qualifying_relation_ids")
        super(PredicateCoverage, self).__post_init__()
        _source_identities(self.own_read_refs)
        _unique((*self.supporting_relation_ids, *self.contradicting_relation_ids,
                 *self.qualifying_relation_ids), "predicate relation identities")
        if any(EvidenceUse.READ not in item.uses for item in self.own_read_refs):
            raise IntegrityError("own reads must be observed reads, not supplied or available references")
        support, contra = bool(self.supporting_relation_ids), bool(self.contradicting_relation_ids)
        expected = (SupportCoverage.CONFLICTED if support and contra else
                    SupportCoverage.SUPPORTED if support else
                    SupportCoverage.CONTRADICTED if contra else SupportCoverage.MISSING)
        if self.coverage != SupportCoverage.UNKNOWN and self.coverage != expected:
            raise IntegrityError("predicate support coverage disagrees with relation references")
        if (support or contra) and not self.own_read_refs:
            raise IntegrityError("verifier support or contradiction requires observed own reads")


@dataclass(frozen=True, slots=True)
class EvidenceOverlap(_Contract):
    DEF = "evidence_overlap"
    same_upstream_artifact_ids: tuple[str, ...]
    distinct_upstream_producer_ids: tuple[str, ...]
    comparison_available: Check

    def __post_init__(self) -> None:
        _sort(self, "same_upstream_artifact_ids", "distinct_upstream_producer_ids")
        super(EvidenceOverlap, self).__post_init__()
        if self.comparison_available.value is not True and (
                self.same_upstream_artifact_ids or self.distinct_upstream_producer_ids):
            raise IntegrityError("unavailable overlap comparison cannot assert artifact/producer differences")


@dataclass(frozen=True, slots=True)
class VerificationRecord(_Product):
    DEF = "verification"
    SCHEMA = VERIFICATION_SCHEMA
    PREFIX = "verification"
    context: Context
    status: CellStatus
    receipt: OptionalSource
    blindness: Blindness
    diversity: Diversity
    predicates: tuple[PredicateCoverage, ...]
    evidence_overlap: EvidenceOverlap
    confirmation_eligible: Check
    existing_r6_passed: Check

    def __post_init__(self) -> None:
        _sort(self, "predicates")
        super(VerificationRecord, self).__post_init__()
        subject = self.context.subject
        if subject.claim_id.value is None or subject.cell_id.value is None:
            raise IntegrityError("verification requires original claim and expected cell identities")
        _unique([item.predicate for item in self.predicates], "coverage predicates")
        sources = _source_bindings(self)
        _check_sources(self.context.origin, sources)
        _check_paths((*sources, *self.context.continuations))
        _verify_verifier_relations(
            self, self.context.relations,
            defer_missing=any(ref.field == ReferenceField.RELATIONS for ref in self.context.continuations))


def _verify_verifier_relations(record: VerificationRecord, population: Sequence[RelationRef], *,
                               defer_missing: bool) -> None:
    """Only declared, not-yet-loaded relation continuations can defer reference-dependent checks."""
    subject = record.context.subject
    relations = {item.relation_id: item for item in population}
    for item in record.predicates:
        for kind, ids in ((RelationKind.SUPPORTS, item.supporting_relation_ids),
                          (RelationKind.CONTRADICTS, item.contradicting_relation_ids),
                          (RelationKind.QUALIFIES, item.qualifying_relation_ids)):
            for identity in ids:
                relation = relations.get(identity)
                if relation is None:
                    if defer_missing:
                        continue
                    raise IntegrityError("verifier coverage names a foreign or mismatched relation")
                if (relation.claim_id, relation.predicate, relation.kind, relation.producing_cell_id,
                    relation.actor_role) != (subject.claim_id.value, item.predicate, kind,
                                             subject.cell_id.value, Role.INDEPENDENT_VERIFIER):
                    raise IntegrityError("verifier coverage names a foreign or mismatched relation")
    if record.confirmation_eligible.value is not True:
        return
    if (record.status != CellStatus.SUCCEEDED or record.blindness.passed.value is not True
            or not any(item.required for item in record.predicates)):
        raise IntegrityError("confirmation eligibility requires observed blindness and required own support")
    for item in record.predicates:
        if not item.required:
            continue
        counted_support = any(relations[ref].counted for ref in item.supporting_relation_ids if ref in relations)
        pending_support = defer_missing and any(ref not in relations for ref in item.supporting_relation_ids)
        own_contradiction = any(
            relation.counted and relation.kind == RelationKind.CONTRADICTS
            and (relation.predicate, relation.producing_cell_id, relation.actor_role) ==
            (item.predicate, subject.cell_id.value, Role.INDEPENDENT_VERIFIER)
            for relation in population)
        if (item.coverage != SupportCoverage.SUPPORTED or own_contradiction
                or not (counted_support or pending_support)):
            raise IntegrityError("confirmation eligibility requires observed blindness and required own support")


@dataclass(frozen=True, slots=True)
class RecordRef(_Contract):
    DEF = "record_ref"
    kind: ProductKind
    record_id: str
    sha256: str

    @classmethod
    def of(cls, record: DecisionRecord | VerificationRecord | DecisionBasisRecord) -> RecordRef:
        return cls(_kind(record), record.record_id, record.sha256)


@dataclass(frozen=True, slots=True)
class OptionalRecord(_Contract):
    DEF = "optional_record"
    value: RecordRef | None
    absence_reason: AbsenceReason | None


@dataclass(frozen=True, slots=True)
class DecisionBasisRecord(_Product):
    DEF = "basis"
    SCHEMA = BASIS_SCHEMA
    PREFIX = "decision-basis"
    context: Context
    claim: SourceRef
    finding: SourceRef
    adjudication: SourceRef
    decisions: tuple[RecordRef, ...]
    verification: OptionalRecord
    required_predicates: tuple[Predicate, ...]
    missing_predicates: tuple[Predicate, ...]
    judge_verdicts: tuple[SourceRef, ...]
    score_refs: tuple[SourceRef, ...]

    def __post_init__(self) -> None:
        _sort(self, "decisions", "required_predicates", "missing_predicates", "judge_verdicts", "score_refs")
        super(DecisionBasisRecord, self).__post_init__()
        subject = self.context.subject
        for source, link in ((self.claim, subject.claim_id), (self.finding, subject.finding_package_id),
                             (self.adjudication, subject.adjudication_id)):
            if link.value is None or source.record_id.value != link.value:
                raise IntegrityError("decision basis requires exact accepted claim/finding/adjudication bindings")
        sources = _source_bindings(self)
        _check_sources(self.context.origin, sources)
        _check_paths((*sources, *self.context.continuations))
        _source_identities(self.judge_verdicts)
        _source_identities(self.score_refs)
        _unique([item.record_id for item in self.decisions], "decision basis record identities")
        if not set(self.missing_predicates) <= set(self.required_predicates):
            raise IntegrityError("missing predicates must be required predicates")


Product: TypeAlias = DecisionRecord | VerificationRecord | DecisionBasisRecord


def _kind(record: Product) -> ProductKind:
    if isinstance(record, DecisionRecord):
        return ProductKind.DECISION
    if isinstance(record, VerificationRecord):
        return ProductKind.VERIFICATION
    if isinstance(record, DecisionBasisRecord):
        return ProductKind.BASIS
    raise IntegrityError("not a decision-audit product")


@dataclass(frozen=True, slots=True)
class ShardRef(_Contract):
    """Record order is significant: hashes bind exact canonical JSONL byte order."""
    DEF = "shard_ref"
    kind: ProductKind
    path: str
    sha256: str
    byte_count: int
    record_count: int
    records: tuple[RecordRef, ...]

    def __post_init__(self) -> None:
        super(ShardRef, self).__post_init__()
        if len(self.records) != self.record_count or any(item.kind != self.kind for item in self.records):
            raise IntegrityError("shard count or record kind disagrees with membership")
        _unique([item.record_id for item in self.records], "shard record identities")


@dataclass(frozen=True, slots=True)
class AuditManifest(_Product):
    DEF = "manifest"
    SCHEMA = MANIFEST_SCHEMA
    PREFIX = "audit-manifest"
    origin: Origin
    shards: tuple[ShardRef, ...]
    coverage: tuple[CoverageCount, ...]

    def __post_init__(self) -> None:
        _sort(self, "shards", "coverage")
        super(AuditManifest, self).__post_init__()
        _unique([item.path for item in self.shards], "manifest shard paths")
        _unique([ref.record_id for shard in self.shards for ref in shard.records], "manifest record identities")
        _unique([item.population for item in self.coverage], "coverage populations")
        for kind in ProductKind:
            count = sum(item.record_count for item in self.shards if item.kind == kind)
            if next(item.emitted for item in self.coverage if item.population == kind) != count:
                raise IntegrityError("manifest emitted coverage does not equal exact record membership")


@dataclass(frozen=True, slots=True)
class ManifestRef(_Contract):
    """External accepted-output reference; never embedded in the manifest it hashes."""
    DEF = "manifest_ref"
    origin: Origin
    path: str
    sha256: str
    record_id: str

    @classmethod
    def of(cls, path: str, manifest: AuditManifest) -> ManifestRef:
        return cls(manifest.origin, path, manifest.sha256, manifest.record_id)

    @classmethod
    def from_document(cls, value: object, *, expected_origin: Origin) -> ManifestRef:
        _validate(cls.DEF, value)
        data = _object(value)
        result = cls(**{**data, "origin": _origin(data["origin"])})
        if result.origin != expected_origin:
            raise IntegrityError("manifest reference differs from the accepted origin")
        return result

    def verify(self, manifest: AuditManifest, *, expected_origin: Origin) -> None:
        if self.origin != expected_origin or manifest.origin != expected_origin:
            raise IntegrityError("manifest reference differs from the accepted origin")
        if (self.record_id, self.sha256) != (manifest.record_id, manifest.sha256):
            raise IntegrityError("manifest reference has a changed identity or hash")


def canonical_bytes(record: Product | AuditManifest) -> bytes:
    """Repository canonical JSON (including its final LF); shared by producer and reader."""
    if not isinstance(record, (DecisionRecord, VerificationRecord, DecisionBasisRecord, AuditManifest)):
        raise IntegrityError("canonical bytes require a decision-audit product or manifest")
    return canonical_json(record.to_dict())


def make_shard(path: str, records: Sequence[Product]) -> ShardRef:
    """Describe canonical JSONL without writing it. Caller chooses the semantic row order."""
    if not records:
        raise IntegrityError("empty shards are not publications; record zero/unknown coverage instead")
    data = b"".join(canonical_bytes(item) for item in records)
    return ShardRef(_kind(records[0]), path, hashlib.sha256(data).hexdigest(),
                    len(data), len(records), tuple(RecordRef.of(item) for item in records))


def reference_bytes(field: ReferenceField, records: Sequence[SourceRef | RelationRef], *,
                    origin: Origin, claim_id: Link) -> bytes:
    """Canonical JSONL for an unordered reference continuation, without storage access."""
    if not isinstance(field, ReferenceField):
        raise IntegrityError("continuation field must be a closed ReferenceField")
    if not 1 <= len(records) <= MAX_SHARD_RECORDS:
        raise IntegrityError("reference continuation requires 1..5000 records")
    sources: list[SourceRef] = []
    identities: list[object] = []
    for record in records:
        if field == ReferenceField.RELATIONS:
            if not isinstance(record, RelationRef) or record.claim_id != claim_id.value:
                raise IntegrityError("relation continuation has a wrong kind or foreign claim")
            sources.append(record.source)
            identities.append(record.relation_id)
        else:
            if not isinstance(record, SourceRef):
                raise IntegrityError("source continuation has the wrong record kind")
            if field == ReferenceField.ORIGIN_PROPOSALS and record.record_id.value is None:
                raise IntegrityError("proposal continuation requires original identities")
            sources.append(record)
            identities.append((record.path, record.record_id.value))
    _unique(identities, "continuation reference identities")
    _check_sources(origin, sources)
    result = b"".join(sorted(canonical_json(item.to_dict()) for item in records))
    if len(result) > MAX_SHARD_BYTES:
        raise IntegrityError("reference continuation exceeds the byte limit")
    return result


def make_continuation(field: ReferenceField, path: str, records: Sequence[SourceRef | RelationRef], *,
                      origin: Origin, claim_id: Link) -> ContinuationRef:
    data = reference_bytes(field, records, origin=origin, claim_id=claim_id)
    return ContinuationRef(field, path, hashlib.sha256(data).hexdigest(), len(records), len(data))


def reference_from_document(value: object, *, field: ReferenceField, origin: Origin,
                            claim_id: Link) -> SourceRef | RelationRef:
    """Decode one closed continuation row, retaining source use and role provenance."""
    _validate("relation_ref" if field == ReferenceField.RELATIONS else "source_ref", value)
    result = _relation(value) if field == ReferenceField.RELATIONS else _source(value)
    reference_bytes(field, (result,), origin=origin, claim_id=claim_id)
    return result


def validate_bundle(manifest: AuditManifest, shards: Mapping[str, Sequence[Product]], *,
                    expected_origin: Origin, manifest_reference: ManifestRef,
                    continuations: Mapping[str, Sequence[SourceRef | RelationRef]] | None = None) -> None:
    """Verify exact membership and cross-product links in already read, validated shards.

    The external manifest reference supplies its path without a self-hash cycle.
    This does not resolve a path or establish that a publication was accepted. A
    standalone record with declared continuations is not fully validated until this succeeds.
    """
    if manifest.origin != expected_origin:
        raise IntegrityError("audit origin differs from the accepted origin")
    manifest_reference.verify(manifest, expected_origin=expected_origin)
    if set(shards) != {item.path for item in manifest.shards}:
        raise IntegrityError("supplied shards differ from the manifest")
    records: dict[str, Product] = {}
    for shard in manifest.shards:
        items = shards[shard.path]
        if make_shard(shard.path, items) != shard:
            raise IntegrityError("shard bytes, count, kind or ordered membership changed")
        for item in items:
            if item.context.origin != expected_origin:
                raise IntegrityError("record belongs to a foreign audit origin")
            records[item.record_id] = item
    continued = {} if continuations is None else continuations
    if set(continued) != {ref.path for record in records.values() for ref in record.context.continuations}:
        raise IntegrityError("supplied reference continuations differ from the declared references")
    if set(shards) & set(continued) or manifest_reference.path in set(shards) | set(continued):
        raise IntegrityError("manifest, product and reference shards must have distinct paths")
    for record in records.values():
        _verify_continuations(record, continued)
        if isinstance(record, DecisionBasisRecord):
            refs = (*record.decisions, *((record.verification.value,) if record.verification.value else ()))
            for ref in refs:
                linked = records.get(ref.record_id)
                if linked is None or RecordRef.of(linked) != ref:
                    raise IntegrityError("decision basis references an absent or changed record")
                if linked.context.subject.claim_id != record.context.subject.claim_id:
                    raise IntegrityError("decision basis references a foreign claim")
    _check_paths((
        manifest_reference, *manifest.shards,
        *(ref for record in records.values() for ref in record.context.continuations),
        *_source_bindings(tuple(records.values())),
        *_source_bindings(tuple(row for rows in continued.values() for row in rows))))


def _verify_continuations(record: Product, continued: Mapping[str, Sequence[SourceRef | RelationRef]]) -> None:
    context = record.context
    grouped: dict[ReferenceField, list[SourceRef | RelationRef]] = {
        ReferenceField.SOURCES: list(context.sources), ReferenceField.RELATIONS: list(context.relations),
        ReferenceField.ORIGIN_PROPOSALS: list(context.origin_proposals),
        ReferenceField.WARRANTS: list(context.future.warrants.values),
        ReferenceField.REQUEST_RESOLUTIONS: list(context.future.request_resolutions.values),
        ReferenceField.HUNT_RECEIPTS: list(context.future.hunt_receipts.values),
    }
    all_sources = list(_source_bindings(record))
    for ref in context.continuations:
        rows = continued[ref.path]
        if make_continuation(ref.field, ref.path, rows, origin=context.origin,
                             claim_id=context.subject.claim_id) != ref:
            raise IntegrityError("reference continuation bytes, count or kind changed")
        grouped[ref.field].extend(rows)
        all_sources.extend(_source_bindings(tuple(rows)))
    _check_sources(context.origin, all_sources)
    _check_paths((*all_sources, *context.continuations))
    for name, rows in grouped.items():
        if name == ReferenceField.RELATIONS:
            relations = [item for item in rows if isinstance(item, RelationRef)]
            _unique([item.relation_id for item in relations], "continued relation identities")
            if isinstance(record, DecisionRecord) and not {
                    item.actor_role for item in relations if item.counted} <= set(record.deciding_actor_roles):
                raise IntegrityError("deciding roles omit continued relation provenance")
            if isinstance(record, VerificationRecord):
                _verify_verifier_relations(record, relations, defer_missing=False)
        else:
            sources = [item for item in rows if isinstance(item, SourceRef)]
            _source_identities(sources)
            if name == ReferenceField.ORIGIN_PROPOSALS:
                _unique([item.record_id.value for item in sources], "continued origin proposal identities")


def _link(value: object) -> Link:
    data = _object(value)
    return Link(**{**data, "absence_reason": _absence(data["absence_reason"])})


def _absence(value: object) -> AbsenceReason | None:
    return None if value is None else AbsenceReason(value)


def _check(value: object) -> Check:
    data = _object(value)
    return Check(**{**data, "absence_reason": _absence(data["absence_reason"])})


def _hash_link(value: object) -> HashLink:
    data = _object(value)
    return HashLink(**{**data, "absence_reason": _absence(data["absence_reason"])})


def _record_ref(value: object) -> RecordRef:
    data = _object(value)
    return RecordRef(**{**data, "kind": ProductKind(data["kind"])})


def _source(value: object) -> SourceRef:
    data = _object(value)
    return SourceRef(**{**data, "record_id": _link(data["record_id"]),
                        "uses": tuple(EvidenceUse(item) for item in _array(data["uses"]))})


def _relation(value: object) -> RelationRef:
    data = _object(value)
    return RelationRef(**{**data, "source": _source(data["source"]),
        "predicate": Predicate(data["predicate"]), "kind": RelationKind(data["kind"]),
        "actor_role": Role(data["actor_role"]), "admissibility": Admissibility(data["admissibility"]),
        "noncounted_reason": None if data["noncounted_reason"] is None
        else NoncountedReason(data["noncounted_reason"])})


def _optional_source(value: object) -> OptionalSource:
    data = _object(value)
    return OptionalSource(**{**data, "value": None if data["value"] is None else _source(data["value"]),
                             "absence_reason": _absence(data["absence_reason"])})


def _origin(value: object) -> Origin:
    data = _object(value)
    return Origin(**{**data, **{name: _hash_link(data[name]) for name in
                               ("lead_package_manifest_sha256", "guidance_sha256", "implementation_sha256")}})


def _context(value: object) -> Context:
    data = _object(value)
    subject = _object(data["subject"])
    explanation = _object(data["explanation"])
    future = _object(data["future"])
    return Context(
        origin=_origin(data["origin"]),
        subject=Subject(**{key: Round(**{**_object(item),
            "absence_reason": _absence(_object(item)["absence_reason"])}) if key == "round" else _link(item)
                           for key, item in subject.items()}),
        sources=tuple(_source(item) for item in _array(data["sources"])),
        relations=tuple(_relation(item) for item in _array(data["relations"])),
        origin_proposals=tuple(_source(item) for item in _array(data["origin_proposals"])),
        continuations=tuple(ContinuationRef(**{**_object(item), "field": ReferenceField(_object(item)["field"])})
                            for item in _array(data["continuations"])),
        future=FutureReferences(**{**future, **{
            name: OptionalSources(tuple(_source(item) for item in _array(_object(future[name])["values"])),
                                  _absence(_object(future[name])["absence_reason"]))
            for name in ("warrants", "request_resolutions", "hunt_receipts")}}),
        explanation=Explanation(**{**explanation, "redaction_reason": _link(explanation["redaction_reason"]),
                                    "absence_reason": _absence(explanation["absence_reason"])}),
        gap_ids=tuple(_array(data["gap_ids"])))


def from_document(value: object, *, expected_origin: Origin) -> Product | AuditManifest:
    """Read a closed document, revalidate identity and require the caller's accepted origin.

    Historical absence is represented by coverage/optional references, never accepted as
    a missing schema, identity, field, or silently successful empty product.
    Declared continuations defer only reference-dependent checks. Before publication or
    consumption, validate_bundle must resolve them against the complete accepted population.
    """
    data = _object(value)
    schemas = {DECISION_SCHEMA: "decision", VERIFICATION_SCHEMA: "verification",
               BASIS_SCHEMA: "basis", MANIFEST_SCHEMA: "manifest"}
    schema = data.get("schema")
    if not isinstance(schema, str) or schema not in schemas:
        raise IntegrityError("unknown or missing decision audit schema")
    _validate(schemas[schema], data)
    body = {key: item for key, item in data.items() if key not in
            ("schema", "record_id", "visibility", "authority")}
    record: Product | AuditManifest
    if schema == MANIFEST_SCHEMA:
        record = AuditManifest(
            _origin(body["origin"]),
            tuple(ShardRef(**{**_object(item), "kind": ProductKind(_object(item)["kind"]),
                "records": tuple(_record_ref(ref)
                  for ref in _array(_object(item)["records"]))}) for item in _array(body["shards"])),
            tuple(CoverageCount(**{**_object(item), "population": Population(_object(item)["population"]),
                "reason": None if _object(item)["reason"] is None else CoverageReason(_object(item)["reason"])})
                for item in _array(body["coverage"])))
        origin = record.origin
    else:
        context = _context(body.pop("context"))
        origin = context.origin
        if schema == DECISION_SCHEMA:
            record = DecisionRecord(context=context, **{**body, **{
                name: tuple(Predicate(item) for item in _array(body[name])) for name in
                ("required_predicates", "missing_predicates")},
                "stage": Stage(body["stage"]), "reason_code": ReasonCode(body["reason_code"]),
                "basis_status": BasisStatus(body["basis_status"]),
                "deciding_row": None if body["deciding_row"] is None else DecidingRow(body["deciding_row"]),
                "deciding_row_absence_reason": _absence(body["deciding_row_absence_reason"]),
                "deciding_actor_roles": tuple(Role(item) for item in _array(body["deciding_actor_roles"])),
                "original_outcome": _link(body["original_outcome"]),
                "cell_receipt": _optional_source(body["cell_receipt"])})
        elif schema == VERIFICATION_SCHEMA:
            blind = _object(body["blindness"])
            diversity = _object(body["diversity"])
            overlap = _object(body["evidence_overlap"])
            record = VerificationRecord(
                context=context, status=CellStatus(body["status"]), receipt=_optional_source(body["receipt"]),
                blindness=Blindness(**{key: _optional_source(item) if key == "request_check"
                                      else _check(item) for key, item in blind.items()}),
                diversity=Diversity(_check(diversity["provider_distinct"]),
                                    _check(diversity["model_profile_distinct"]),
                                    _link(diversity["resolved_model_revision"])),
                predicates=tuple(PredicateCoverage(**{**_object(item),
                    "predicate": Predicate(_object(item)["predicate"]),
                    "coverage": SupportCoverage(_object(item)["coverage"]),
                    "unknown_reason": _absence(_object(item)["unknown_reason"]),
                    "own_read_refs": tuple(_source(ref) for ref in _array(_object(item)["own_read_refs"])),
                    **{name: tuple(_array(_object(item)[name])) for name in
                       ("supporting_relation_ids", "contradicting_relation_ids", "qualifying_relation_ids")}})
                    for item in _array(body["predicates"])),
                evidence_overlap=EvidenceOverlap(
                    tuple(_array(overlap["same_upstream_artifact_ids"])),
                    tuple(_array(overlap["distinct_upstream_producer_ids"])),
                    _check(overlap["comparison_available"])),
                confirmation_eligible=_check(body["confirmation_eligible"]),
                existing_r6_passed=_check(body["existing_r6_passed"]))
        else:
            verification = _object(body["verification"])
            record = DecisionBasisRecord(
                context=context, claim=_source(body["claim"]), finding=_source(body["finding"]),
                adjudication=_source(body["adjudication"]),
                decisions=tuple(_record_ref(item) for item in _array(body["decisions"])),
                verification=OptionalRecord(
                    None if verification["value"] is None else _record_ref(verification["value"]),
                    _absence(verification["absence_reason"])),
                required_predicates=tuple(Predicate(item) for item in _array(body["required_predicates"])),
                missing_predicates=tuple(Predicate(item) for item in _array(body["missing_predicates"])),
                judge_verdicts=tuple(_source(item) for item in _array(body["judge_verdicts"])),
                score_refs=tuple(_source(item) for item in _array(body["score_refs"])))
    if origin != expected_origin:
        raise IntegrityError("audit origin differs from the accepted origin")
    if record.record_id != data["record_id"]:
        raise IntegrityError("decision audit content identity mismatch")
    return record


__all__ = [
    "AbsenceReason", "AuditManifest", "BASIS_SCHEMA", "BasisStatus", "Blindness", "Check",
    "Context", "ContinuationRef", "CoverageCount", "CoverageReason", "DECISION_SCHEMA",
    "DecisionBasisRecord", "DecisionRecord", "Diversity", "EvidenceOverlap", "EvidenceUse",
    "Explanation", "FutureReferences", "HashLink", "Link", "MANIFEST_SCHEMA", "ManifestRef", "MAX_EXPLANATION",
    "MAX_INLINE_REFERENCES", "MAX_SHARD_BYTES", "MAX_SHARD_RECORDS", "NoncountedReason",
    "OptionalRecord", "OptionalSource", "OptionalSources", "Origin", "Population",
    "PredicateCoverage", "Product", "ProductKind", "ReasonCode", "RecordRef", "ReferenceField",
    "RelationRef", "Round", "SCHEMA_FILE", "ShardRef", "SourceRef", "Stage", "Subject",
    "SupportCoverage", "VERIFICATION_SCHEMA", "VerificationRecord", "canonical_bytes",
    "from_document", "make_continuation", "make_shard", "reference_bytes",
    "reference_from_document", "validate_bundle",
]
