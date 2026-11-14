"""Proposition-bound predicate warrants and polarity checks (``predicate-warrants/1``, TRI-B / T-152).

An admissible retrieval record is an authentic citation, not proof of an arbitrary proposition.
This module evaluates whether re-resolved machine evidence actually warrants a ``supports`` or
``contradicts`` relation on a specific :class:`~appsec_review.review.models.Claim` and
:class:`~appsec_review.review.models.Predicate` without reading model prose or claim statements.

Covered evidence methods in ``predicate-warrants/1``:
1. Structured construct presence (``affected_construct``): bound to the claim's subject and build
   scope; existence alone never contradicts ``affected_construct``.
2. Structured build configuration (``configuration_enables``): bound to the claim's build scope and
   source/target inputs, requiring recorded flags/settings rather than discovery stubs.
3. Structured graph flow (``entry_point``, ``dataflow_path``): bound to the claim's sink/function
   and build scope; positive flow/entry existence never contradicts reachability or input control.
4. Structured guard and range checks (``guard_fact``, ``range_fact`` on
   ``missing_or_ineffective_guard``): checked in both polarities against the claim's bound sink,
   operand, destination byte capacity, and signedness. An effective guard cannot support
   ``missing_or_ineffective_guard`` (including via cherry-picked sibling guards on an already
   effectively guarded sink), and an inconclusive fact qualifies rather than proving absence.
5. Numeric weakness guardrail: numeric CWEs require machine ``guard_fact``/``range_fact`` records on
   ``missing_or_ineffective_guard``; ``tool_observation`` (O1) or source spans remain unresolved.
6. Uncommissioned semantics (general authorization, authentication, race conditions, resource
   exhaustion on ``missing_or_ineffective_guard``, ``security_impact``, and ``analyst_assessed``
   narrative citations) remain ``qualifies`` with ``uncommissioned`` result rather than deciding.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
import re
from typing import Any, Iterable, Mapping

from appsec_review.graph.bounds import (
    destination_bytes, fact_bounds_destination, guard_bounds_destination, sink_destination_bytes,
)
from appsec_review.graph.contract import (
    ADMISSIBILITY_RULE as GRAPH_FACT_ADMISSIBILITY_RULE, GRAPH_FACT_SCHEMA, ineligibility_reasons,
)
from appsec_review.retrieval.core import RetrievalCore, RetrievalGap, RetrievalIntegrityError
from appsec_review.retrieval.model import EntityKind, LogicalIdentity, RelationKind as IndexRelation
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.models import (
    Admissibility, Claim, Predicate, RelationKind, SecurityPredicate,
)
from appsec_review.review.numeric_reasoning import is_numeric_weakness

WARRANT_SCHEMA = "appsec-review/predicate-warrant/1"
WARRANT_RULE_VERSION = "predicate-warrants/1"

GUARD_CONTRADICTION_ROLES: frozenset[str] = frozenset({"blue_team_refuter", "independent_verifier", "judge"})
REFUTATION_ROLES: frozenset[str] = frozenset({"blue_team_refuter", "independent_verifier", "judge"})

UNCOMMISSIONED_GUARD_SECURITY_PREDICATES: frozenset[SecurityPredicate] = frozenset({
    SecurityPredicate.AUTHN_BYPASS,
    SecurityPredicate.AUTHZ_BYPASS,
    SecurityPredicate.RACE_CONDITION,
    SecurityPredicate.RESOURCE_EXHAUSTION,
})

SIGNEDNESS_SENSITIVE_CWES: frozenset[str] = frozenset({
    "CWE-129", "CWE-191", "CWE-195", "CWE-196", "CWE-197",
})

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_WARRANT_ID_RE = re.compile(r"^warrant-[0-9a-f]{64}$")
_RELATION_ID_RE = re.compile(r"^evrel-[0-9a-f]{64}$")
_CLAIM_ID_RE = re.compile(r"^claim-[0-9a-f]{64}$")

_UPPER_RELATIONS = frozenset({"<", "<=", "=="})
_FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}
_NEGATE = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}
_CONSTANT_KINDS = frozenset({"constant", "sizeof"})

_PRESENCE_DIRECT_KINDS: frozenset[EntityKind] = frozenset({
    EntityKind.SOURCE_SPAN, EntityKind.AST_NODE, EntityKind.IR_ENTITY, EntityKind.SYMBOL,
    EntityKind.BUILD_ACTION, EntityKind.COMPILE_UNIT, EntityKind.OBJECT_FILE, EntityKind.LIBRARY,
    EntityKind.EXECUTABLE, EntityKind.BUILD_ARTIFACT, EntityKind.PACKAGE, EntityKind.ARCHIVE_MEMBER,
    EntityKind.BYTECODE_MODULE, EntityKind.MANAGED_ASSEMBLY, EntityKind.WASM_MODULE,
    EntityKind.EVIDENCE_ARTIFACT, EntityKind.BINARY_FUNCTION, EntityKind.BINARY_CALL_SITE,
    EntityKind.CALL_SITE, EntityKind.SINK_SITE,
})
_BUILD_CONFIG_KINDS: frozenset[EntityKind] = frozenset({EntityKind.BUILD_ACTION, EntityKind.COMPILE_UNIT})
_GUARD_FACT_KINDS: frozenset[EntityKind] = frozenset({EntityKind.GUARD_FACT, EntityKind.RANGE_FACT})
_FLOW_FACT_KINDS: frozenset[EntityKind] = frozenset({EntityKind.ENTRY_POINT, EntityKind.DATAFLOW_PATH})
_SUBJECT_RELATIONS: tuple[str, ...] = (
    IndexRelation.CONTAINS.value,
    IndexRelation.SAME_AS.value,
    IndexRelation.GENERATED_FROM.value,
    IndexRelation.DERIVED_FROM.value,
    IndexRelation.DEFINES.value,
    IndexRelation.DECLARES.value,
    IndexRelation.COMPILES_TO.value,
    IndexRelation.OBSERVED_AT.value,
)
_MISSING_OPERAND_SUBSTRINGS: tuple[str, ...] = (
    "destination object size is unknown",
    "operands are not both recorded",
    "both operands are constants",
    "not a compile-time constant",
    "no interval was computed",
    "no known upper bound",
    "not a recorded comparison",
    "missing or not recognized",
)


class WarrantBasis(StrEnum):
    STRUCTURED_PRESENCE = "structured_presence"
    STRUCTURED_BUILD_FACT = "structured_build_fact"
    STRUCTURED_FLOW_FACT = "structured_flow_fact"
    STRUCTURED_GUARD_CHECK = "structured_guard_check"
    NUMERIC_BOUND_CHECK = "numeric_bound_check"
    MAPPED_TOOL_OBSERVATION = "mapped_tool_observation"
    UNCOMMISSIONED_SEMANTICS = "uncommissioned_semantics"


class WarrantResult(StrEnum):
    ESTABLISHED_SUPPORT = "established_support"
    ESTABLISHED_CONTRADICTION = "established_contradiction"
    QUALIFIED = "qualified"
    NOT_ESTABLISHED = "not_established"
    UNCOMMISSIONED = "uncommissioned"


class WarrantCoverage(StrEnum):
    COMPLETE_FOR_SUPPLIED_FACTS = "complete_for_supplied_facts"
    INCOMPLETE_FACTS = "incomplete_facts"
    AMBIGUOUS_BINDING = "ambiguous_binding"
    OUT_OF_SCOPE = "out_of_scope"
    UNCOMMISSIONED_METHOD = "uncommissioned_method"


class WarrantReasonCode(StrEnum):
    BOUND_PRESENCE_SUPPORTS_CONSTRUCT = "bound_presence_supports_construct"
    PRESENCE_CANNOT_CONTRADICT_CONSTRUCT = "presence_cannot_contradict_construct"
    BOUND_FLOW_SUPPORTS_PREDICATE = "bound_flow_supports_predicate"
    POSITIVE_FACT_CANNOT_CONTRADICT = "positive_fact_cannot_contradict"
    BOUND_CONFIGURATION_FACT = "bound_configuration_fact"
    CONFIGURATION_FACT_INCONCLUSIVE = "configuration_fact_inconclusive"
    EFFECTIVE_GUARD_BOUNDS_DESTINATION = "effective_guard_bounds_destination"
    EFFECTIVE_GUARD_CANNOT_SUPPORT_MISSING_GUARD = "effective_guard_cannot_support_missing_guard"
    GUARD_ABSENT_AT_BOUND_SINK = "guard_absent_at_bound_sink"
    GUARD_INEFFECTIVE_FOR_DESTINATION = "guard_ineffective_for_destination"
    DESTINATION_BOUND_UNPROVED = "destination_bound_unproved"
    OPERAND_OR_WIDTH_MISSING = "operand_or_width_missing"
    OPERAND_MISMATCH = "operand_mismatch"
    NUMERIC_MACHINE_FACT_REQUIRED = "numeric_machine_fact_required"
    BOUND_MAPPED_EVIDENCE = "bound_mapped_evidence"
    SUBJECT_NOT_BOUND_TO_CLAIM = "subject_not_bound_to_claim"
    AMBIGUOUS_SUBJECT_BINDING = "ambiguous_subject_binding"
    SINK_MISMATCH = "sink_mismatch"
    BUILD_SCOPE_MISMATCH = "build_scope_mismatch"
    CONTRADICTION_ROLE_NOT_PERMITTED = "contradiction_role_not_permitted"
    INCOMPLETE_FACT_RECORD = "incomplete_fact_record"
    INDIRECT_OR_ANALYST_ASSESSED = "indirect_or_analyst_assessed"
    UNCOMMISSIONED_SEMANTIC_PREDICATE = "uncommissioned_semantic_predicate"
    QUALIFYING_OBSERVATION = "qualifying_observation"


@dataclass(frozen=True, slots=True)
class WarrantScope:
    """Optional caller-supplied snapshot and build-scope pins for warrant checks."""

    target_snapshot: str | None = None
    build_scope_id: str | None = None


@dataclass(frozen=True, slots=True)
class SubjectBinding:
    """Canonical claim-subject and scope binding recorded in ``predicate-warrant/1``."""

    affected_entity_ids: tuple[str, ...]
    operation_id: str | None = None
    sink_id: str | None = None
    build_scope_id: str | None = None


@dataclass(frozen=True, slots=True)
class WarrantEvidenceRef:
    """Accepted retrieval record bound to a predicate warrant."""

    entity_id: str
    entity_kind: str
    shard_id: str
    content_sha256: str
    locator: str
    retrieval_receipt_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class PredicateWarrant:
    """Closed ``appsec-review/predicate-warrant/1`` decision record."""

    warrant_id: str
    claim_id: str
    relation_id: str
    predicate: Predicate
    requested_relation: RelationKind
    effective_relation: RelationKind
    subject_binding: SubjectBinding
    basis: WarrantBasis
    evidence_refs: tuple[WarrantEvidenceRef, ...]
    rule: str
    result: WarrantResult
    reason_code: WarrantReasonCode
    coverage: WarrantCoverage


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _warrant_body(*, claim_id: str, relation_id: str, predicate: Predicate, requested_relation: RelationKind,
                  effective_relation: RelationKind, subject_binding: SubjectBinding, basis: WarrantBasis,
                  evidence_refs: tuple[WarrantEvidenceRef, ...], rule: str, result: WarrantResult,
                  reason_code: WarrantReasonCode, coverage: WarrantCoverage) -> dict[str, Any]:
    return {
        "claim_id": claim_id,
        "relation_id": relation_id,
        "predicate": predicate.value,
        "requested_relation": requested_relation.value,
        "effective_relation": effective_relation.value,
        "subject_binding": {
            "affected_entity_ids": list(subject_binding.affected_entity_ids),
            "operation_id": subject_binding.operation_id,
            "sink_id": subject_binding.sink_id,
            "build_scope_id": subject_binding.build_scope_id,
        },
        "basis": basis.value,
        "evidence_refs": [
            {
                "entity_id": ref.entity_id,
                "entity_kind": ref.entity_kind,
                "shard_id": ref.shard_id,
                "content_sha256": ref.content_sha256,
                "locator": ref.locator,
                "retrieval_receipt_sha256": ref.retrieval_receipt_sha256,
            }
            for ref in evidence_refs
        ],
        "rule": rule,
        "result": result.value,
        "reason_code": reason_code.value,
        "coverage": coverage.value,
    }


def compute_warrant_id(body: Mapping[str, Any]) -> str:
    return f"warrant-{sha256_hex({'kind': 'predicate_warrant', 'version': 1, 'body': dict(body)})}"


def bind_warrant_relation_id(warrant: PredicateWarrant, relation_id: str) -> PredicateWarrant:
    """Recompute ``warrant_id`` after binding the canonical ``EvidenceRelation.relation_id``."""
    body = _warrant_body(
        claim_id=warrant.claim_id,
        relation_id=relation_id,
        predicate=warrant.predicate,
        requested_relation=warrant.requested_relation,
        effective_relation=warrant.effective_relation,
        subject_binding=warrant.subject_binding,
        basis=warrant.basis,
        evidence_refs=warrant.evidence_refs,
        rule=warrant.rule,
        result=warrant.result,
        reason_code=warrant.reason_code,
        coverage=warrant.coverage,
    )
    return replace(warrant, warrant_id=compute_warrant_id(body), relation_id=relation_id)


def warrant_json(warrant: PredicateWarrant) -> dict[str, Any]:
    body = _warrant_body(
        claim_id=warrant.claim_id,
        relation_id=warrant.relation_id,
        predicate=warrant.predicate,
        requested_relation=warrant.requested_relation,
        effective_relation=warrant.effective_relation,
        subject_binding=warrant.subject_binding,
        basis=warrant.basis,
        evidence_refs=warrant.evidence_refs,
        rule=warrant.rule,
        result=warrant.result,
        reason_code=warrant.reason_code,
        coverage=warrant.coverage,
    )
    return {"schema": WARRANT_SCHEMA, "warrant_id": warrant.warrant_id, **body}


def validate_warrant_json(value: Mapping[str, Any]) -> None:
    """Fail-closed structural validation for ``appsec-review/predicate-warrant/1``."""
    if not isinstance(value, Mapping):
        raise ValueError("predicate warrant must be a JSON object")
    expected_keys = {
        "schema", "warrant_id", "claim_id", "relation_id", "predicate", "requested_relation",
        "effective_relation", "subject_binding", "basis", "evidence_refs", "rule", "result",
        "reason_code", "coverage",
    }
    if set(value.keys()) != expected_keys:
        raise ValueError(f"predicate warrant keys mismatch: {sorted(set(value.keys()) ^ expected_keys)}")
    if value["schema"] != WARRANT_SCHEMA:
        raise ValueError(f"unsupported predicate warrant schema: {value['schema']!r}")
    if not isinstance(value["warrant_id"], str) or not _WARRANT_ID_RE.fullmatch(value["warrant_id"]):
        raise ValueError("invalid warrant_id")
    if not isinstance(value["claim_id"], str) or not _CLAIM_ID_RE.fullmatch(value["claim_id"]):
        raise ValueError("invalid claim_id")
    if not isinstance(value["relation_id"], str) or not _RELATION_ID_RE.fullmatch(value["relation_id"]):
        raise ValueError("invalid relation_id")
    Predicate(value["predicate"])
    requested = RelationKind(value["requested_relation"])
    effective = RelationKind(value["effective_relation"])
    allowed_relations = {RelationKind.SUPPORTS, RelationKind.CONTRADICTS, RelationKind.QUALIFIES}
    if requested not in allowed_relations or effective not in allowed_relations:
        raise ValueError("warrant relation must be supports, contradicts, or qualifies")
    binding = value["subject_binding"]
    if not isinstance(binding, Mapping) or set(binding.keys()) != {
        "affected_entity_ids", "operation_id", "sink_id", "build_scope_id",
    }:
        raise ValueError("invalid subject_binding object")
    affected = binding["affected_entity_ids"]
    if not isinstance(affected, list) or not affected:
        raise ValueError("subject_binding.affected_entity_ids must be a non-empty list")
    for item in affected:
        LogicalIdentity.parse(str(item))
    for opt_key in ("operation_id", "sink_id", "build_scope_id"):
        opt_val = binding[opt_key]
        if opt_val is not None and (not isinstance(opt_val, str) or not opt_val):
            raise ValueError(f"invalid subject_binding.{opt_key}")
    if binding["sink_id"] is not None:
        parsed_sink = LogicalIdentity.parse(binding["sink_id"])
        if parsed_sink.kind is not EntityKind.SINK_SITE:
            raise ValueError("subject_binding.sink_id must be a sink_site identity")
    WarrantBasis(value["basis"])
    WarrantResult(value["result"])
    WarrantReasonCode(value["reason_code"])
    WarrantCoverage(value["coverage"])
    if value["rule"] != WARRANT_RULE_VERSION:
        raise ValueError(f"unsupported warrant rule: {value['rule']!r}")
    refs = value["evidence_refs"]
    if not isinstance(refs, list) or not refs:
        raise ValueError("evidence_refs must be a non-empty list")
    ref_keys = {"entity_id", "entity_kind", "shard_id", "content_sha256", "locator", "retrieval_receipt_sha256"}
    for ref in refs:
        if not isinstance(ref, Mapping) or set(ref.keys()) != ref_keys:
            raise ValueError("invalid evidence_ref object")
        parsed_ref = LogicalIdentity.parse(str(ref["entity_id"]))
        if EntityKind(ref["entity_kind"]) is not parsed_ref.kind:
            raise ValueError("evidence_ref entity_kind does not match entity_id")
        if not isinstance(ref["shard_id"], str) or not ref["shard_id"]:
            raise ValueError("invalid evidence_ref.shard_id")
        if not isinstance(ref["content_sha256"], str) or not _SHA256_RE.fullmatch(ref["content_sha256"]):
            raise ValueError("invalid evidence_ref.content_sha256")
        if not isinstance(ref["locator"], str) or not ref["locator"]:
            raise ValueError("invalid evidence_ref.locator")
        receipt = ref["retrieval_receipt_sha256"]
        if receipt is not None and (not isinstance(receipt, str) or not _SHA256_RE.fullmatch(receipt)):
            raise ValueError("invalid evidence_ref.retrieval_receipt_sha256")


def warrant_from_json(value: Mapping[str, Any]) -> PredicateWarrant:
    validate_warrant_json(value)
    binding = value["subject_binding"]
    subject = SubjectBinding(
        affected_entity_ids=tuple(str(item) for item in binding["affected_entity_ids"]),
        operation_id=binding["operation_id"],
        sink_id=binding["sink_id"],
        build_scope_id=binding["build_scope_id"],
    )
    refs = tuple(
        WarrantEvidenceRef(
            entity_id=str(ref["entity_id"]),
            entity_kind=str(ref["entity_kind"]),
            shard_id=str(ref["shard_id"]),
            content_sha256=str(ref["content_sha256"]),
            locator=str(ref["locator"]),
            retrieval_receipt_sha256=ref["retrieval_receipt_sha256"],
        )
        for ref in value["evidence_refs"]
    )
    warrant = PredicateWarrant(
        warrant_id=str(value["warrant_id"]),
        claim_id=str(value["claim_id"]),
        relation_id=str(value["relation_id"]),
        predicate=Predicate(value["predicate"]),
        requested_relation=RelationKind(value["requested_relation"]),
        effective_relation=RelationKind(value["effective_relation"]),
        subject_binding=subject,
        basis=WarrantBasis(value["basis"]),
        evidence_refs=refs,
        rule=str(value["rule"]),
        result=WarrantResult(value["result"]),
        reason_code=WarrantReasonCode(value["reason_code"]),
        coverage=WarrantCoverage(value["coverage"]),
    )
    expected_id = compute_warrant_id(_warrant_body(
        claim_id=warrant.claim_id,
        relation_id=warrant.relation_id,
        predicate=warrant.predicate,
        requested_relation=warrant.requested_relation,
        effective_relation=warrant.effective_relation,
        subject_binding=warrant.subject_binding,
        basis=warrant.basis,
        evidence_refs=warrant.evidence_refs,
        rule=warrant.rule,
        result=warrant.result,
        reason_code=warrant.reason_code,
        coverage=warrant.coverage,
    ))
    if warrant.warrant_id != expected_id:
        raise ValueError("warrant_id does not match canonical warrant content")
    return warrant


def warrant_satisfies_support(warrant: PredicateWarrant) -> bool:
    return (
        warrant.effective_relation is RelationKind.SUPPORTS
        and warrant.result is WarrantResult.ESTABLISHED_SUPPORT
    )


def warrant_satisfies_contradiction(warrant: PredicateWarrant) -> bool:
    return (
        warrant.effective_relation is RelationKind.CONTRADICTS
        and warrant.result is WarrantResult.ESTABLISHED_CONTRADICTION
    )


# ---------------------------------------------------------------------------
# Retrieval inspection helpers (fail-closed, deterministic, bounded)
# ---------------------------------------------------------------------------

def _safe_find_one(core: RetrievalCore, identity: str) -> Mapping[str, Any] | None:
    try:
        found = core.find(identity=identity, limit=1)["results"]
        return found[0] if found else None
    except RetrievalIntegrityError:
        raise
    except (RetrievalGap, LookupError, ValueError):
        return None


def _safe_trace(core: RetrievalCore, identity: str, relations: Iterable[str], *, depth: int = 1) -> list[Mapping[str, Any]]:
    try:
        limit = min(100, core.limits.max_results)
        return list(core.trace(identity=identity, relations=tuple(relations), depth=depth, limit=limit)["results"])
    except RetrievalIntegrityError:
        raise
    except (RetrievalGap, LookupError, ValueError):
        return []


def _entity_build_scope_id(entity: Mapping[str, Any] | None) -> str | None:
    if not isinstance(entity, Mapping):
        return None
    payload = entity.get("payload")
    if not isinstance(payload, Mapping):
        return None
    scope = payload.get("scope")
    if isinstance(scope, Mapping) and isinstance(scope.get("build_unit_id"), str) and scope["build_unit_id"]:
        return str(scope["build_unit_id"])
    for key in ("build_unit_id", "project_id", "case"):
        val = payload.get(key)
        if isinstance(val, str) and val:
            return val
    return None


def _locations_overlap_exact(first: Mapping[str, Any] | None, second: Mapping[str, Any] | None) -> tuple[bool, bool]:
    """Return ``(overlaps_unambiguously, overlaps_ambiguously)`` for two accepted locations."""
    if not isinstance(first, Mapping) or not isinstance(second, Mapping):
        return False, False
    if first.get("path") != second.get("path") or first.get("file_sha256") != second.get("file_sha256"):
        return False, False
    start_a, end_a = first.get("start_byte"), first.get("end_byte")
    start_b, end_b = second.get("start_byte"), second.get("end_byte")
    if not all(_is_int(v) for v in (start_a, end_a, start_b, end_b)):
        return False, False
    if int(end_a) < int(start_b) or int(end_b) < int(start_a):
        return False, False
    if bool(first.get("ambiguous")) or bool(second.get("ambiguous")):
        return False, True
    return True, False


def _location_contains_exact(outer: Mapping[str, Any] | None, inner: Mapping[str, Any] | None) -> tuple[bool, bool]:
    """Return ``(contains_unambiguously, contains_ambiguously)``."""
    if not isinstance(outer, Mapping) or not isinstance(inner, Mapping):
        return False, False
    if outer.get("path") != inner.get("path") or outer.get("file_sha256") != inner.get("file_sha256"):
        return False, False
    start_o, end_o = outer.get("start_byte"), outer.get("end_byte")
    start_i, end_i = inner.get("start_byte"), inner.get("end_byte")
    if not all(_is_int(v) for v in (start_o, end_o, start_i, end_i)):
        return False, False
    if not (int(start_o) <= int(start_i) and int(end_i) <= int(end_o)):
        return False, False
    if bool(outer.get("ambiguous")) or bool(inner.get("ambiguous")):
        return False, True
    return True, False


def _resolve_claim_entities(core: RetrievalCore, claim: Claim) -> dict[str, Mapping[str, Any]]:
    resolved: dict[str, Mapping[str, Any]] = {}
    for entity_id in sorted(set(claim.affected_entities)):
        found = _safe_find_one(core, entity_id)
        if found is not None:
            resolved[entity_id] = found
    return resolved


def _infer_expected_build_scope(claim_entities: Mapping[str, Mapping[str, Any]],
                                scope: WarrantScope | None) -> str | None:
    if scope is not None and scope.build_scope_id:
        return scope.build_scope_id
    found_scopes = {
        build_id
        for entity in claim_entities.values()
        if (build_id := _entity_build_scope_id(entity)) is not None
    }
    return next(iter(found_scopes)) if len(found_scopes) == 1 else None


def _claim_operation_id(claim_entities: Mapping[str, Mapping[str, Any]]) -> str | None:
    symbols = sorted(
        entity_id for entity_id, entity in claim_entities.items()
        if entity.get("kind") in {EntityKind.SYMBOL.value, EntityKind.BINARY_FUNCTION.value}
    )
    if len(symbols) == 1:
        return symbols[0]
    calls = sorted(
        entity_id for entity_id, entity in claim_entities.items()
        if entity.get("kind") in {EntityKind.CALL_SITE.value, EntityKind.BINARY_CALL_SITE.value}
    )
    return calls[0] if len(calls) == 1 else None


def _candidate_sinks_for_claim(core: RetrievalCore, claim: Claim,
                               claim_entities: Mapping[str, Mapping[str, Any]]) -> tuple[frozenset[str], bool]:
    """Return ``(candidate_sink_ids, has_ambiguous_link)`` for a claim's affected entities."""
    explicit_sinks: set[str] = set()
    for entity_id in claim.affected_entities:
        try:
            if LogicalIdentity.parse(entity_id).kind is EntityKind.SINK_SITE:
                explicit_sinks.add(entity_id)
        except ValueError:
            continue
    if explicit_sinks:
        return frozenset(explicit_sinks), False

    ambiguous = False
    narrow_sinks: set[str] = set()
    for entity_id, entity in sorted(claim_entities.items()):
        kind = entity.get("kind")
        if kind not in {EntityKind.CALL_SITE.value, EntityKind.SOURCE_SPAN.value, EntityKind.TOOL_OBSERVATION.value}:
            continue
        loc = entity.get("location")
        if isinstance(loc, Mapping) and isinstance(loc.get("path"), str):
            try:
                limit = min(100, core.limits.max_results)
                sinks_in_file = core.find(kind=EntityKind.SINK_SITE.value, path=str(loc["path"]), limit=limit)["results"]
            except RetrievalIntegrityError:
                raise
            except (RetrievalGap, LookupError, ValueError):
                sinks_in_file = []
            for candidate in sinks_in_file:
                exact_ov, amb_ov = _locations_overlap_exact(loc, candidate.get("location"))
                if exact_ov:
                    narrow_sinks.add(str(candidate["identity"]))
                elif amb_ov:
                    ambiguous = True
    if narrow_sinks:
        return frozenset(narrow_sinks), ambiguous

    symbol_sinks: set[str] = set()
    for entity_id, entity in sorted(claim_entities.items()):
        if entity.get("kind") not in {EntityKind.SYMBOL.value, EntityKind.BINARY_FUNCTION.value}:
            continue
        for rel in _safe_trace(core, entity_id, (IndexRelation.CONTAINS.value,), depth=1):
            other_id = rel.get("target_id") if rel.get("source_id") == entity_id else rel.get("source_id")
            if not isinstance(other_id, str):
                continue
            try:
                if LogicalIdentity.parse(other_id).kind is not EntityKind.SINK_SITE:
                    continue
            except ValueError:
                continue
            if rel.get("exact"):
                symbol_sinks.add(other_id)
            else:
                ambiguous = True
        loc = entity.get("location")
        if isinstance(loc, Mapping) and isinstance(loc.get("path"), str):
            try:
                limit = min(100, core.limits.max_results)
                sinks_in_file = core.find(kind=EntityKind.SINK_SITE.value, path=str(loc["path"]), limit=limit)["results"]
            except RetrievalIntegrityError:
                raise
            except (RetrievalGap, LookupError, ValueError):
                sinks_in_file = []
            for candidate in sinks_in_file:
                res = (candidate.get("payload") or {}).get("result")
                enclosing = (res.get("enclosing_function") or {}).get("symbol") if isinstance(res, Mapping) else None
                if enclosing == entity_id:
                    symbol_sinks.add(str(candidate["identity"]))
                    continue
                exact_ct, amb_ct = _location_contains_exact(loc, candidate.get("location"))
                if exact_ct:
                    symbol_sinks.add(str(candidate["identity"]))
                elif amb_ct:
                    ambiguous = True
    return frozenset(symbol_sinks), ambiguous


def _check_subject_binding(core: RetrievalCore, claim: Claim, claim_entities: Mapping[str, Mapping[str, Any]],
                           entity: Mapping[str, Any]) -> tuple[bool, bool]:
    """Return ``(bound_exact, bound_ambiguous)`` between ``entity`` and ``claim.affected_entities``."""
    entity_id = str(entity.get("identity", ""))
    affected_set = set(claim.affected_entities)
    loc = entity.get("location") if isinstance(entity.get("location"), Mapping) else None

    if entity_id in affected_set:
        if loc is not None and bool(loc.get("ambiguous")):
            return False, True
        return True, False

    payload = entity.get("payload") if isinstance(entity.get("payload"), Mapping) else {}
    result = payload.get("result") if isinstance(payload.get("result"), Mapping) else {}
    for sym_holder in (
        result.get("enclosing_function"),
        result.get("caller"),
        result.get("function"),
    ):
        if isinstance(sym_holder, Mapping) and sym_holder.get("symbol") in affected_set:
            if loc is not None and bool(loc.get("ambiguous")):
                return False, True
            return True, False

    ambiguous = False
    for rel in _safe_trace(core, entity_id, _SUBJECT_RELATIONS, depth=1):
        other = rel.get("target_id") if rel.get("source_id") == entity_id else rel.get("source_id")
        if other in affected_set:
            if rel.get("exact") and not (loc is not None and bool(loc.get("ambiguous"))):
                return True, False
            ambiguous = True

    if loc is not None:
        for claim_entity in claim_entities.values():
            c_loc = claim_entity.get("location") if isinstance(claim_entity.get("location"), Mapping) else None
            exact_ov, amb_ov = _locations_overlap_exact(loc, c_loc)
            if exact_ov:
                return True, False
            if amb_ov:
                ambiguous = True

    return False, ambiguous


# ---------------------------------------------------------------------------
# Guard, range, and signedness checks (Safeguards 2, 3, 4)
# ---------------------------------------------------------------------------

def _is_direct_eligible_graph_fact(entity: Mapping[str, Any], expected_family: EntityKind) -> bool:
    payload = entity.get("payload")
    if not isinstance(payload, Mapping):
        return False
    if payload.get("schema") != GRAPH_FACT_SCHEMA or payload.get("family") != expected_family.value:
        return False
    block = payload.get("admissibility")
    if not isinstance(block, Mapping) or block.get("rule") != GRAPH_FACT_ADMISSIBILITY_RULE:
        return False
    if block.get("direct_eligible") is not True or list(block.get("ineligibility_reasons") or ()) != []:
        return False
    return not ineligibility_reasons(payload)


def _sink_guard_and_range_entities(core: RetrievalCore, sink_id: str
                                   ) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]:
    """Return ``(guard_entities, range_entities)`` linked to ``sink_id`` in the accepted index."""
    guards: dict[str, Mapping[str, Any]] = {}
    ranges: dict[str, Mapping[str, Any]] = {}
    for rel in _safe_trace(core, sink_id, (IndexRelation.GUARDS.value, IndexRelation.DERIVED_FROM.value), depth=1):
        if rel.get("target_id") != sink_id or not isinstance(rel.get("source_id"), str):
            continue
        source_id = str(rel["source_id"])
        found = _safe_find_one(core, source_id)
        if found is None:
            continue
        if found.get("kind") == EntityKind.GUARD_FACT.value:
            guards[source_id] = found
        elif found.get("kind") == EntityKind.RANGE_FACT.value:
            ranges[source_id] = found
    return [guards[k] for k in sorted(guards)], [ranges[k] for k in sorted(ranges)]


def _range_non_negative_safe(result: Mapping[str, Any]) -> tuple[bool, WarrantReasonCode | None]:
    """Check whether a ``range_fact`` has complete type/width info and a non-negative lower bound if signed."""
    type_info = result.get("type")
    if not isinstance(type_info, Mapping):
        return False, WarrantReasonCode.OPERAND_OR_WIDTH_MISSING
    bits = type_info.get("bits")
    signed = type_info.get("signed")
    if not _is_int(bits) or int(bits) <= 0 or not isinstance(signed, bool):
        return False, WarrantReasonCode.OPERAND_OR_WIDTH_MISSING
    if result.get("sign_change"):
        return False, WarrantReasonCode.DESTINATION_BOUND_UNPROVED
    interval = result.get("interval")
    if not isinstance(interval, Mapping):
        return False, WarrantReasonCode.OPERAND_OR_WIDTH_MISSING
    if signed is True:
        lower = interval.get("lower")
        if not _is_int(lower):
            return False, WarrantReasonCode.OPERAND_OR_WIDTH_MISSING
        if int(lower) < 0:
            return False, WarrantReasonCode.DESTINATION_BOUND_UNPROVED
    return True, None


def _sink_has_unbounded_signed_operand(range_entities: Iterable[Mapping[str, Any]]) -> bool:
    """True when an eligible ``range_fact`` on the sink shows a signed operand that may be negative or sign-changed."""
    for entity in range_entities:
        if not _is_direct_eligible_graph_fact(entity, EntityKind.RANGE_FACT):
            continue
        result = (entity.get("payload") or {}).get("result")
        if not isinstance(result, Mapping):
            continue
        if result.get("sign_change"):
            return True
        type_info = result.get("type")
        interval = result.get("interval")
        if isinstance(type_info, Mapping) and type_info.get("signed") is True:
            lower = interval.get("lower") if isinstance(interval, Mapping) else None
            if not _is_int(lower) or int(lower) < 0:
                return True
    return False


def _fact_effectively_bounds_sink(*, kind: EntityKind, result: Mapping[str, Any], destination: int | None,
                                  weakness_cwe: str | None,
                                  range_entities: Sequence_or_List) -> tuple[bool, WarrantReasonCode, WarrantCoverage]:
    """Determine whether ``result`` establishes an effective destination bound (including signedness)."""
    if kind is EntityKind.RANGE_FACT:
        signed_ok, fail_code = _range_non_negative_safe(result)
        if not signed_ok and fail_code is not None:
            cov = (WarrantCoverage.INCOMPLETE_FACTS if fail_code is WarrantReasonCode.OPERAND_OR_WIDTH_MISSING
                   else WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS)
            return False, fail_code, cov
    bound = fact_bounds_destination(kind.value, result, destination)
    if not bound.bounds:
        if any(token in bound.reason for token in _MISSING_OPERAND_SUBSTRINGS):
            return False, WarrantReasonCode.OPERAND_OR_WIDTH_MISSING, WarrantCoverage.INCOMPLETE_FACTS
        cov = (WarrantCoverage.INCOMPLETE_FACTS if "constrains_sink_operand=unknown" in bound.reason
               else WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS)
        return False, WarrantReasonCode.DESTINATION_BOUND_UNPROVED, cov

    if kind is EntityKind.GUARD_FACT:
        if weakness_cwe in SIGNEDNESS_SENSITIVE_CWES or _sink_has_unbounded_signed_operand(range_entities):
            return False, WarrantReasonCode.DESTINATION_BOUND_UNPROVED, WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS
    return True, WarrantReasonCode.EFFECTIVE_GUARD_BOUNDS_DESTINATION, WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS


Sequence_or_List = list[Mapping[str, Any]]


def _fact_affirmatively_shows_missing_or_ineffective_guard(
    *, kind: EntityKind, result: Mapping[str, Any], destination: int | None
) -> tuple[bool, WarrantReasonCode, WarrantCoverage]:
    """Return whether a single ``guard_fact`` or ``range_fact`` affirmatively demonstrates guard failure.

    Lack of a proven bound (unknown capacity, dynamic comparison, unknown ``constrains_sink_operand``,
    or over-approximated upper range when ``lower <= capacity``) is inconclusive and returns ``False``.
    """
    if kind is EntityKind.GUARD_FACT:
        state = result.get("guard_state")
        if state == "none":
            return True, WarrantReasonCode.GUARD_ABSENT_AT_BOUND_SINK, WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS
        if state in {"non_dominating", "post_dominating_only"}:
            return True, WarrantReasonCode.GUARD_INEFFECTIVE_FOR_DESTINATION, WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS
        if state != "dominating":
            return False, WarrantReasonCode.OPERAND_OR_WIDTH_MISSING, WarrantCoverage.INCOMPLETE_FACTS

        constrains = result.get("constrains_sink_operand")
        if constrains is False:
            return True, WarrantReasonCode.GUARD_INEFFECTIVE_FOR_DESTINATION, WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS
        if constrains is not True:
            return False, WarrantReasonCode.DESTINATION_BOUND_UNPROVED, WarrantCoverage.INCOMPLETE_FACTS

        capacity = destination_bytes(result)
        if capacity is None:
            return False, WarrantReasonCode.OPERAND_OR_WIDTH_MISSING, WarrantCoverage.INCOMPLETE_FACTS
        comparison = result.get("comparison")
        if not isinstance(comparison, Mapping):
            return False, WarrantReasonCode.OPERAND_OR_WIDTH_MISSING, WarrantCoverage.INCOMPLETE_FACTS
        operator = comparison.get("operator")
        operands = comparison.get("operands")
        polarity = result.get("polarity")
        by_role = {
            item.get("role"): item for item in operands if isinstance(item, Mapping)
        } if isinstance(operands, list) else {}
        if operator not in _FLIP or set(by_role) != {"lhs", "rhs"} or polarity not in {"true_branch", "false_branch"}:
            return False, WarrantReasonCode.OPERAND_OR_WIDTH_MISSING, WarrantCoverage.INCOMPLETE_FACTS
        constants = {
            r: int(op["value"])
            for r, op in by_role.items()
            if isinstance(op, Mapping) and op.get("kind") in _CONSTANT_KINDS and _is_int(op.get("value"))
        }
        if len(constants) != 1:
            return False, WarrantReasonCode.OPERAND_OR_WIDTH_MISSING, WarrantCoverage.INCOMPLETE_FACTS
        bound_role, limit = next(iter(constants.items()))
        relation = operator if bound_role == "rhs" else _FLIP[operator]
        if polarity == "false_branch":
            relation = _NEGATE[relation]
        allowed = capacity + 1 if relation == "<" else capacity
        if relation not in _UPPER_RELATIONS or limit > allowed:
            return True, WarrantReasonCode.GUARD_INEFFECTIVE_FOR_DESTINATION, WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS
        # Upper bound holds within capacity; signed/lower-bound safety is unproved rather than disproved by this guard.
        return False, WarrantReasonCode.DESTINATION_BOUND_UNPROVED, WarrantCoverage.INCOMPLETE_FACTS

    if kind is EntityKind.RANGE_FACT:
        type_info = result.get("type")
        interval = result.get("interval")
        if not isinstance(type_info, Mapping) or not _is_int(type_info.get("bits")) or not isinstance(
            type_info.get("signed"), bool
        ):
            return False, WarrantReasonCode.OPERAND_OR_WIDTH_MISSING, WarrantCoverage.INCOMPLETE_FACTS
        if not isinstance(interval, Mapping):
            return False, WarrantReasonCode.OPERAND_OR_WIDTH_MISSING, WarrantCoverage.INCOMPLETE_FACTS
        lower = interval.get("lower")
        upper = interval.get("upper")
        if _is_int(destination) and int(destination) > 0 and _is_int(lower) and int(lower) > int(destination):
            return True, WarrantReasonCode.GUARD_INEFFECTIVE_FOR_DESTINATION, WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS
        if type_info.get("signed") is True and _is_int(upper) and int(upper) < 0:
            return True, WarrantReasonCode.GUARD_INEFFECTIVE_FOR_DESTINATION, WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS
        if not _is_int(destination) or int(destination) <= 0 or not _is_int(upper):
            return False, WarrantReasonCode.OPERAND_OR_WIDTH_MISSING, WarrantCoverage.INCOMPLETE_FACTS
        return False, WarrantReasonCode.DESTINATION_BOUND_UNPROVED, WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS

    return False, WarrantReasonCode.DESTINATION_BOUND_UNPROVED, WarrantCoverage.INCOMPLETE_FACTS


# ---------------------------------------------------------------------------
# Build configuration checks (Safeguard 3)
# ---------------------------------------------------------------------------

def _check_build_configuration_fact(
    *, core: RetrievalCore, claim: Claim, claim_entities: Mapping[str, Mapping[str, Any]],
    entity: Mapping[str, Any], requested_relation: RelationKind, role: str | None
) -> tuple[RelationKind, WarrantResult, WarrantReasonCode, WarrantCoverage]:
    payload = entity.get("payload") if isinstance(entity.get("payload"), Mapping) else {}
    native_id = str(entity.get("native_id", ""))

    if native_id.startswith("planned-build:"):
        return (RelationKind.QUALIFIES, WarrantResult.NOT_ESTABLISHED,
                WarrantReasonCode.CONFIGURATION_FACT_INCONCLUSIVE, WarrantCoverage.INCOMPLETE_FACTS)
    if set(payload.keys()) <= {"compile_database_sha256", "shard_id"}:
        return (RelationKind.QUALIFIES, WarrantResult.NOT_ESTABLISHED,
                WarrantReasonCode.CONFIGURATION_FACT_INCONCLUSIVE, WarrantCoverage.INCOMPLETE_FACTS)

    config_keys = {
        "arguments", "flags", "security_flags", "defines", "configuration",
        "environment_facts", "declared_settings", "command_facts", "argv_sha256",
        "command_fingerprint", "ordered_tokens",
    }
    if not (set(payload.keys()) & config_keys):
        return (RelationKind.QUALIFIES, WarrantResult.NOT_ESTABLISHED,
                WarrantReasonCode.CONFIGURATION_FACT_INCONCLUSIVE, WarrantCoverage.INCOMPLETE_FACTS)

    bound_exact, bound_ambiguous = _check_subject_binding(core, claim, claim_entities, entity)
    claim_paths = {
        str(loc["path"])
        for item in claim_entities.values()
        if isinstance((loc := item.get("location")), Mapping) and isinstance(loc.get("path"), str)
    }
    if not bound_exact and claim_paths:
        target_path = payload.get("target_path")
        if isinstance(target_path, str) and target_path in claim_paths:
            bound_exact = True
        files_field = payload.get("files") or payload.get("declared_inputs") or payload.get("inputs")
        if isinstance(files_field, list) and files_field:
            recorded_paths: set[str] = set()
            for entry in files_field:
                if isinstance(entry, str):
                    recorded_paths.add(entry)
                elif isinstance(entry, Mapping) and isinstance(entry.get("path"), str):
                    recorded_paths.add(str(entry["path"]))
            if recorded_paths:
                if recorded_paths & claim_paths:
                    bound_exact = True
                else:
                    return (RelationKind.QUALIFIES, WarrantResult.NOT_ESTABLISHED,
                            WarrantReasonCode.SUBJECT_NOT_BOUND_TO_CLAIM, WarrantCoverage.OUT_OF_SCOPE)

    if not bound_exact:
        if bound_ambiguous:
            return (RelationKind.QUALIFIES, WarrantResult.NOT_ESTABLISHED,
                    WarrantReasonCode.AMBIGUOUS_SUBJECT_BINDING, WarrantCoverage.AMBIGUOUS_BINDING)
        return (RelationKind.QUALIFIES, WarrantResult.NOT_ESTABLISHED,
                WarrantReasonCode.SUBJECT_NOT_BOUND_TO_CLAIM, WarrantCoverage.OUT_OF_SCOPE)

    if payload.get("timed_out") is True or (payload.get("exit_code") not in (None, 0)):
        return (RelationKind.QUALIFIES, WarrantResult.NOT_ESTABLISHED,
                WarrantReasonCode.CONFIGURATION_FACT_INCONCLUSIVE, WarrantCoverage.INCOMPLETE_FACTS)

    if requested_relation is RelationKind.CONTRADICTS:
        if role not in REFUTATION_ROLES:
            return (RelationKind.QUALIFIES, WarrantResult.NOT_ESTABLISHED,
                    WarrantReasonCode.CONTRADICTION_ROLE_NOT_PERMITTED,
                    WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS)
        capture = payload.get("execution_capture")
        if isinstance(capture, Mapping) and (capture.get("truncated") is True or capture.get("argv_truncated") is True):
            return (RelationKind.QUALIFIES, WarrantResult.NOT_ESTABLISHED,
                    WarrantReasonCode.CONFIGURATION_FACT_INCONCLUSIVE, WarrantCoverage.INCOMPLETE_FACTS)
        if payload.get("evidence_kind") == "declared" and payload.get("did_work") is False:
            return (RelationKind.QUALIFIES, WarrantResult.NOT_ESTABLISHED,
                    WarrantReasonCode.CONFIGURATION_FACT_INCONCLUSIVE, WarrantCoverage.INCOMPLETE_FACTS)
        return (RelationKind.CONTRADICTS, WarrantResult.ESTABLISHED_CONTRADICTION,
                WarrantReasonCode.BOUND_CONFIGURATION_FACT, WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS)

    return (RelationKind.SUPPORTS, WarrantResult.ESTABLISHED_SUPPORT,
            WarrantReasonCode.BOUND_CONFIGURATION_FACT, WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS)


# ---------------------------------------------------------------------------
# Public warrant evaluator
# ---------------------------------------------------------------------------

def evaluate_warrant(
    core: RetrievalCore,
    *,
    claim: Claim,
    predicate: Predicate,
    requested_relation: RelationKind,
    entity: Mapping[str, Any],
    admissibility: Admissibility,
    complete: bool,
    shard_id: str,
    content_sha256: str,
    locator: str,
    retrieval_receipt_sha256: str | None,
    relation_id: str | None = None,
    role: str | None = None,
    scope: WarrantScope | None = None,
) -> PredicateWarrant:
    """Evaluate a proposition-bound ``predicate-warrant/1`` record for one re-resolved citation."""
    predicate = Predicate(predicate)
    requested_relation = RelationKind(requested_relation)
    entity_id = str(entity["identity"])
    entity_kind = EntityKind(entity["kind"])
    affected_ids = tuple(sorted(set(claim.affected_entities)))

    claim_entities = _resolve_claim_entities(core, claim)
    expected_build_scope = _infer_expected_build_scope(claim_entities, scope)
    entity_build_scope = _entity_build_scope_id(entity)
    operation_id = _claim_operation_id(claim_entities)
    candidate_sinks, sinks_ambiguous = _candidate_sinks_for_claim(core, claim, claim_entities)
    bound_sink_id = next(iter(candidate_sinks)) if len(candidate_sinks) == 1 else None

    placeholder_rel_id = relation_id or make_id("evidence_relation", 1, {
        "claim_id": claim.claim_id, "predicate": predicate.value,
        "kind": requested_relation.value, "entity_id": entity_id,
    })
    evidence_ref = WarrantEvidenceRef(
        entity_id=entity_id,
        entity_kind=entity_kind.value,
        shard_id=shard_id,
        content_sha256=content_sha256,
        locator=locator,
        retrieval_receipt_sha256=retrieval_receipt_sha256,
    )

    def build(
        *,
        effective_relation: RelationKind,
        basis: WarrantBasis,
        result: WarrantResult,
        reason_code: WarrantReasonCode,
        coverage: WarrantCoverage,
        sink_override: str | None = bound_sink_id,
        build_scope_override: str | None = expected_build_scope or entity_build_scope,
    ) -> PredicateWarrant:
        binding = SubjectBinding(
            affected_entity_ids=affected_ids,
            operation_id=operation_id,
            sink_id=sink_override,
            build_scope_id=build_scope_override,
        )
        body = _warrant_body(
            claim_id=claim.claim_id,
            relation_id=placeholder_rel_id,
            predicate=predicate,
            requested_relation=requested_relation,
            effective_relation=effective_relation,
            subject_binding=binding,
            basis=basis,
            evidence_refs=(evidence_ref,),
            rule=WARRANT_RULE_VERSION,
            result=result,
            reason_code=reason_code,
            coverage=coverage,
        )
        return PredicateWarrant(
            warrant_id=compute_warrant_id(body),
            claim_id=claim.claim_id,
            relation_id=placeholder_rel_id,
            predicate=predicate,
            requested_relation=requested_relation,
            effective_relation=effective_relation,
            subject_binding=binding,
            basis=basis,
            evidence_refs=(evidence_ref,),
            rule=WARRANT_RULE_VERSION,
            result=result,
            reason_code=reason_code,
            coverage=coverage,
        )

    # Basis classification for early exits (qualifies, incomplete, uncommissioned, indirect).
    numeric_guard = (
        predicate is Predicate.MISSING_OR_INEFFECTIVE_GUARD
        and is_numeric_weakness(claim.weakness_cwe)
    )
    default_basis = (
        WarrantBasis.UNCOMMISSIONED_SEMANTICS
        if (predicate is Predicate.SECURITY_IMPACT
            or (predicate is Predicate.MISSING_OR_INEFFECTIVE_GUARD
                and SecurityPredicate(claim.security_predicate) in UNCOMMISSIONED_GUARD_SECURITY_PREDICATES))
        else WarrantBasis.NUMERIC_BOUND_CHECK if numeric_guard
        else WarrantBasis.STRUCTURED_GUARD_CHECK if entity_kind in _GUARD_FACT_KINDS
        else WarrantBasis.STRUCTURED_BUILD_FACT if (
            predicate is Predicate.CONFIGURATION_ENABLES and entity_kind in _BUILD_CONFIG_KINDS
        )
        else WarrantBasis.STRUCTURED_FLOW_FACT if entity_kind in _FLOW_FACT_KINDS
        else WarrantBasis.MAPPED_TOOL_OBSERVATION if entity_kind is EntityKind.TOOL_OBSERVATION
        else WarrantBasis.STRUCTURED_PRESENCE if predicate is Predicate.AFFECTED_CONSTRUCT
        else WarrantBasis.UNCOMMISSIONED_SEMANTICS
    )

    if requested_relation is RelationKind.QUALIFIES:
        return build(
            effective_relation=RelationKind.QUALIFIES,
            basis=default_basis,
            result=WarrantResult.QUALIFIED,
            reason_code=WarrantReasonCode.QUALIFYING_OBSERVATION,
            coverage=WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS if complete else WarrantCoverage.INCOMPLETE_FACTS,
        )

    # Safeguard 5a: uncommissioned semantic predicates never decide.
    if predicate is Predicate.SECURITY_IMPACT or (
        predicate is Predicate.MISSING_OR_INEFFECTIVE_GUARD
        and SecurityPredicate(claim.security_predicate) in UNCOMMISSIONED_GUARD_SECURITY_PREDICATES
    ):
        return build(
            effective_relation=RelationKind.QUALIFIES,
            basis=WarrantBasis.UNCOMMISSIONED_SEMANTICS,
            result=WarrantResult.UNCOMMISSIONED,
            reason_code=WarrantReasonCode.UNCOMMISSIONED_SEMANTIC_PREDICATE,
            coverage=WarrantCoverage.UNCOMMISSIONED_METHOD,
        )

    # Safeguard 4: numeric CWEs require machine guard/range facts on missing_or_ineffective_guard
    # before considering report citations or prose-bearing spans.
    if numeric_guard and entity_kind not in _GUARD_FACT_KINDS:
        return build(
            effective_relation=RelationKind.QUALIFIES,
            basis=WarrantBasis.NUMERIC_BOUND_CHECK,
            result=WarrantResult.NOT_ESTABLISHED,
            reason_code=WarrantReasonCode.NUMERIC_MACHINE_FACT_REQUIRED,
            coverage=WarrantCoverage.INCOMPLETE_FACTS,
        )

    # Non-direct citations (analyst-assessed narrative or indirect context) remain qualified.
    if admissibility not in {Admissibility.DIRECT, Admissibility.DIRECT_FOR_MAPPED_PREDICATE}:
        basis = (WarrantBasis.UNCOMMISSIONED_SEMANTICS if admissibility is Admissibility.ANALYST_ASSESSED
                 else default_basis)
        res = (WarrantResult.UNCOMMISSIONED if admissibility is Admissibility.ANALYST_ASSESSED
               else WarrantResult.NOT_ESTABLISHED)
        cov = (WarrantCoverage.UNCOMMISSIONED_METHOD if admissibility is Admissibility.ANALYST_ASSESSED
               else WarrantCoverage.INCOMPLETE_FACTS)
        return build(
            effective_relation=RelationKind.QUALIFIES,
            basis=basis,
            result=res,
            reason_code=WarrantReasonCode.INDIRECT_OR_ANALYST_ASSESSED,
            coverage=cov,
        )

    if not complete:
        return build(
            effective_relation=RelationKind.QUALIFIES,
            basis=default_basis,
            result=WarrantResult.NOT_ESTABLISHED,
            reason_code=WarrantReasonCode.INCOMPLETE_FACT_RECORD,
            coverage=WarrantCoverage.INCOMPLETE_FACTS,
        )

    # Safeguard 3a: snapshot and build-scope matching.
    if scope is not None and scope.target_snapshot:
        manifest_snapshot = str(core.manifest.get("target_snapshot", ""))
        if manifest_snapshot and manifest_snapshot != scope.target_snapshot:
            return build(
                effective_relation=RelationKind.QUALIFIES,
                basis=default_basis,
                result=WarrantResult.NOT_ESTABLISHED,
                reason_code=WarrantReasonCode.BUILD_SCOPE_MISMATCH,
                coverage=WarrantCoverage.OUT_OF_SCOPE,
            )
    if expected_build_scope and entity_build_scope and entity_build_scope != expected_build_scope:
        return build(
            effective_relation=RelationKind.QUALIFIES,
            basis=default_basis,
            result=WarrantResult.NOT_ESTABLISHED,
            reason_code=WarrantReasonCode.BUILD_SCOPE_MISMATCH,
            coverage=WarrantCoverage.OUT_OF_SCOPE,
            build_scope_override=expected_build_scope,
        )

    # 1. affected_construct: structured presence / mapped observation.
    if predicate is Predicate.AFFECTED_CONSTRUCT:
        basis = (WarrantBasis.MAPPED_TOOL_OBSERVATION if entity_kind is EntityKind.TOOL_OBSERVATION
                 else WarrantBasis.STRUCTURED_PRESENCE)
        if requested_relation is RelationKind.CONTRADICTS:
            return build(
                effective_relation=RelationKind.QUALIFIES,
                basis=basis,
                result=WarrantResult.NOT_ESTABLISHED,
                reason_code=WarrantReasonCode.PRESENCE_CANNOT_CONTRADICT_CONSTRUCT,
                coverage=WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS,
            )
        bound_exact, bound_ambiguous = _check_subject_binding(core, claim, claim_entities, entity)
        if not bound_exact:
            if bound_ambiguous:
                return build(
                    effective_relation=RelationKind.QUALIFIES,
                    basis=basis,
                    result=WarrantResult.NOT_ESTABLISHED,
                    reason_code=WarrantReasonCode.AMBIGUOUS_SUBJECT_BINDING,
                    coverage=WarrantCoverage.AMBIGUOUS_BINDING,
                )
            return build(
                effective_relation=RelationKind.QUALIFIES,
                basis=basis,
                result=WarrantResult.NOT_ESTABLISHED,
                reason_code=WarrantReasonCode.SUBJECT_NOT_BOUND_TO_CLAIM,
                coverage=WarrantCoverage.OUT_OF_SCOPE,
            )
        code = (WarrantReasonCode.BOUND_MAPPED_EVIDENCE if entity_kind is EntityKind.TOOL_OBSERVATION
                else WarrantReasonCode.BOUND_PRESENCE_SUPPORTS_CONSTRUCT)
        return build(
            effective_relation=RelationKind.SUPPORTS,
            basis=basis,
            result=WarrantResult.ESTABLISHED_SUPPORT,
            reason_code=code,
            coverage=WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS,
        )

    # 2. configuration_enables: structured build facts or mapped config observations.
    if predicate is Predicate.CONFIGURATION_ENABLES:
        if entity_kind in _BUILD_CONFIG_KINDS:
            eff_rel, res, code, cov = _check_build_configuration_fact(
                core=core, claim=claim, claim_entities=claim_entities,
                entity=entity, requested_relation=requested_relation, role=role,
            )
            return build(
                effective_relation=eff_rel,
                basis=WarrantBasis.STRUCTURED_BUILD_FACT,
                result=res,
                reason_code=code,
                coverage=cov,
            )
        if entity_kind is EntityKind.TOOL_OBSERVATION:
            if requested_relation is RelationKind.CONTRADICTS:
                return build(
                    effective_relation=RelationKind.QUALIFIES,
                    basis=WarrantBasis.MAPPED_TOOL_OBSERVATION,
                    result=WarrantResult.NOT_ESTABLISHED,
                    reason_code=WarrantReasonCode.POSITIVE_FACT_CANNOT_CONTRADICT,
                    coverage=WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS,
                )
            bound_exact, bound_ambiguous = _check_subject_binding(core, claim, claim_entities, entity)
            if not bound_exact:
                return build(
                    effective_relation=RelationKind.QUALIFIES,
                    basis=WarrantBasis.MAPPED_TOOL_OBSERVATION,
                    result=WarrantResult.NOT_ESTABLISHED,
                    reason_code=(WarrantReasonCode.AMBIGUOUS_SUBJECT_BINDING if bound_ambiguous
                                 else WarrantReasonCode.SUBJECT_NOT_BOUND_TO_CLAIM),
                    coverage=(WarrantCoverage.AMBIGUOUS_BINDING if bound_ambiguous
                              else WarrantCoverage.OUT_OF_SCOPE),
                )
            return build(
                effective_relation=RelationKind.SUPPORTS,
                basis=WarrantBasis.MAPPED_TOOL_OBSERVATION,
                result=WarrantResult.ESTABLISHED_SUPPORT,
                reason_code=WarrantReasonCode.BOUND_MAPPED_EVIDENCE,
                coverage=WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS,
            )

    # 3. attacker_input_control / source_to_sink_reachability.
    if predicate in {Predicate.ATTACKER_INPUT_CONTROL, Predicate.SOURCE_TO_SINK_REACHABILITY}:
        basis = (WarrantBasis.MAPPED_TOOL_OBSERVATION if entity_kind is EntityKind.TOOL_OBSERVATION
                 else WarrantBasis.STRUCTURED_FLOW_FACT)
        if requested_relation is RelationKind.CONTRADICTS:
            return build(
                effective_relation=RelationKind.QUALIFIES,
                basis=basis,
                result=WarrantResult.NOT_ESTABLISHED,
                reason_code=WarrantReasonCode.POSITIVE_FACT_CANNOT_CONTRADICT,
                coverage=WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS,
            )
        if entity_kind is EntityKind.DATAFLOW_PATH:
            result = ((entity.get("payload") or {}).get("result") or {})
            fact_sink = (result.get("sink") or {}).get("sink_site") if isinstance(result, Mapping) else None
            if not isinstance(fact_sink, str) or not fact_sink:
                return build(
                    effective_relation=RelationKind.QUALIFIES,
                    basis=basis,
                    result=WarrantResult.NOT_ESTABLISHED,
                    reason_code=WarrantReasonCode.INCOMPLETE_FACT_RECORD,
                    coverage=WarrantCoverage.INCOMPLETE_FACTS,
                )
            if not candidate_sinks or fact_sink not in candidate_sinks:
                return build(
                    effective_relation=RelationKind.QUALIFIES,
                    basis=basis,
                    result=WarrantResult.NOT_ESTABLISHED,
                    reason_code=(WarrantReasonCode.AMBIGUOUS_SUBJECT_BINDING if (not candidate_sinks and sinks_ambiguous)
                                 else WarrantReasonCode.SINK_MISMATCH),
                    coverage=(WarrantCoverage.AMBIGUOUS_BINDING if (not candidate_sinks and sinks_ambiguous)
                              else WarrantCoverage.OUT_OF_SCOPE),
                )
            if len(candidate_sinks) > 1:
                return build(
                    effective_relation=RelationKind.QUALIFIES,
                    basis=basis,
                    result=WarrantResult.NOT_ESTABLISHED,
                    reason_code=WarrantReasonCode.AMBIGUOUS_SUBJECT_BINDING,
                    coverage=WarrantCoverage.AMBIGUOUS_BINDING,
                )
            return build(
                effective_relation=RelationKind.SUPPORTS,
                basis=basis,
                result=WarrantResult.ESTABLISHED_SUPPORT,
                reason_code=WarrantReasonCode.BOUND_FLOW_SUPPORTS_PREDICATE,
                coverage=WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS,
                sink_override=fact_sink,
            )

        if entity_kind is EntityKind.ENTRY_POINT:
            bound_exact, bound_ambiguous = _check_subject_binding(core, claim, claim_entities, entity)
            if not bound_exact and candidate_sinks:
                for rel in _safe_trace(core, entity_id, (IndexRelation.FLOWS_TO.value,), depth=2):
                    other = rel.get("target_id") if rel.get("source_id") == entity_id else None
                    if other in candidate_sinks:
                        if rel.get("exact"):
                            bound_exact = True
                            break
                        bound_ambiguous = True
            if not bound_exact:
                return build(
                    effective_relation=RelationKind.QUALIFIES,
                    basis=basis,
                    result=WarrantResult.NOT_ESTABLISHED,
                    reason_code=(WarrantReasonCode.AMBIGUOUS_SUBJECT_BINDING if bound_ambiguous
                                 else WarrantReasonCode.SUBJECT_NOT_BOUND_TO_CLAIM),
                    coverage=(WarrantCoverage.AMBIGUOUS_BINDING if bound_ambiguous
                              else WarrantCoverage.OUT_OF_SCOPE),
                )
            return build(
                effective_relation=RelationKind.SUPPORTS,
                basis=basis,
                result=WarrantResult.ESTABLISHED_SUPPORT,
                reason_code=WarrantReasonCode.BOUND_FLOW_SUPPORTS_PREDICATE,
                coverage=WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS,
            )

        if entity_kind is EntityKind.TOOL_OBSERVATION:
            bound_exact, bound_ambiguous = _check_subject_binding(core, claim, claim_entities, entity)
            if not bound_exact:
                return build(
                    effective_relation=RelationKind.QUALIFIES,
                    basis=basis,
                    result=WarrantResult.NOT_ESTABLISHED,
                    reason_code=(WarrantReasonCode.AMBIGUOUS_SUBJECT_BINDING if bound_ambiguous
                                 else WarrantReasonCode.SUBJECT_NOT_BOUND_TO_CLAIM),
                    coverage=(WarrantCoverage.AMBIGUOUS_BINDING if bound_ambiguous
                              else WarrantCoverage.OUT_OF_SCOPE),
                )
            return build(
                effective_relation=RelationKind.SUPPORTS,
                basis=basis,
                result=WarrantResult.ESTABLISHED_SUPPORT,
                reason_code=WarrantReasonCode.BOUND_MAPPED_EVIDENCE,
                coverage=WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS,
            )

    # 4. missing_or_ineffective_guard (Safeguards 2, 3, 4, 5).
    if predicate is Predicate.MISSING_OR_INEFFECTIVE_GUARD:
        if entity_kind in _GUARD_FACT_KINDS:
            basis = WarrantBasis.NUMERIC_BOUND_CHECK if numeric_guard else WarrantBasis.STRUCTURED_GUARD_CHECK
            payload = entity.get("payload") if isinstance(entity.get("payload"), Mapping) else {}
            result = payload.get("result") if isinstance(payload.get("result"), Mapping) else {}
            fact_sink = (result.get("sink") or {}).get("sink_site") if isinstance(result.get("sink"), Mapping) else None
            if not isinstance(fact_sink, str) or not fact_sink:
                return build(
                    effective_relation=RelationKind.QUALIFIES,
                    basis=basis,
                    result=WarrantResult.NOT_ESTABLISHED,
                    reason_code=WarrantReasonCode.INCOMPLETE_FACT_RECORD,
                    coverage=WarrantCoverage.INCOMPLETE_FACTS,
                )
            if not candidate_sinks or fact_sink not in candidate_sinks:
                return build(
                    effective_relation=RelationKind.QUALIFIES,
                    basis=basis,
                    result=WarrantResult.NOT_ESTABLISHED,
                    reason_code=(WarrantReasonCode.AMBIGUOUS_SUBJECT_BINDING if (not candidate_sinks and sinks_ambiguous)
                                 else WarrantReasonCode.SINK_MISMATCH),
                    coverage=(WarrantCoverage.AMBIGUOUS_BINDING if (not candidate_sinks and sinks_ambiguous)
                              else WarrantCoverage.OUT_OF_SCOPE),
                )
            if len(candidate_sinks) > 1:
                return build(
                    effective_relation=RelationKind.QUALIFIES,
                    basis=basis,
                    result=WarrantResult.NOT_ESTABLISHED,
                    reason_code=WarrantReasonCode.AMBIGUOUS_SUBJECT_BINDING,
                    coverage=WarrantCoverage.AMBIGUOUS_BINDING,
                )

            sink_entity = _safe_find_one(core, fact_sink)
            if entity_kind is EntityKind.RANGE_FACT:
                op_idx = result.get("operand_index")
                if not _is_int(op_idx) or int(op_idx) < 0:
                    return build(
                        effective_relation=RelationKind.QUALIFIES,
                        basis=basis,
                        result=WarrantResult.NOT_ESTABLISHED,
                        reason_code=WarrantReasonCode.OPERAND_OR_WIDTH_MISSING,
                        coverage=WarrantCoverage.INCOMPLETE_FACTS,
                        sink_override=fact_sink,
                    )
                sink_res = ((sink_entity.get("payload") or {}).get("result")
                            if isinstance(sink_entity, Mapping) else None)
                sink_arg = sink_res.get("argument_index") if isinstance(sink_res, Mapping) else None
                if _is_int(sink_arg) and int(sink_arg) >= 0 and int(op_idx) != int(sink_arg):
                    return build(
                        effective_relation=RelationKind.QUALIFIES,
                        basis=basis,
                        result=WarrantResult.NOT_ESTABLISHED,
                        reason_code=WarrantReasonCode.OPERAND_MISMATCH,
                        coverage=WarrantCoverage.OUT_OF_SCOPE,
                        sink_override=fact_sink,
                    )

            guard_entities, range_entities = _sink_guard_and_range_entities(core, fact_sink)
            guard_results = [
                res for item in guard_entities
                if isinstance((res := (item.get("payload") or {}).get("result")), Mapping)
            ]
            if entity_kind is EntityKind.GUARD_FACT and result not in guard_results:
                guard_results.append(result)
            destination = sink_destination_bytes(guard_results)

            this_bounds, bound_code, bound_cov = _fact_effectively_bounds_sink(
                kind=entity_kind,
                result=result,
                destination=destination,
                weakness_cwe=claim.weakness_cwe,
                range_entities=range_entities,
            )

            if requested_relation is RelationKind.CONTRADICTS:
                if not this_bounds:
                    return build(
                        effective_relation=RelationKind.QUALIFIES,
                        basis=basis,
                        result=WarrantResult.NOT_ESTABLISHED,
                        reason_code=bound_code,
                        coverage=bound_cov,
                        sink_override=fact_sink,
                    )
                if role not in GUARD_CONTRADICTION_ROLES:
                    return build(
                        effective_relation=RelationKind.QUALIFIES,
                        basis=basis,
                        result=WarrantResult.NOT_ESTABLISHED,
                        reason_code=WarrantReasonCode.CONTRADICTION_ROLE_NOT_PERMITTED,
                        coverage=WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS,
                        sink_override=fact_sink,
                    )
                return build(
                    effective_relation=RelationKind.CONTRADICTS,
                    basis=basis,
                    result=WarrantResult.ESTABLISHED_CONTRADICTION,
                    reason_code=WarrantReasonCode.EFFECTIVE_GUARD_BOUNDS_DESTINATION,
                    coverage=WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS,
                    sink_override=fact_sink,
                )

            # requested_relation is SUPPORTS: check this fact AND sibling guards/ranges on the same sink.
            sibling_bounds = False
            if not this_bounds:
                for sib in guard_entities:
                    if not _is_direct_eligible_graph_fact(sib, EntityKind.GUARD_FACT):
                        continue
                    sib_res = (sib.get("payload") or {}).get("result")
                    if isinstance(sib_res, Mapping) and _fact_effectively_bounds_sink(
                        kind=EntityKind.GUARD_FACT, result=sib_res, destination=destination,
                        weakness_cwe=claim.weakness_cwe, range_entities=range_entities,
                    )[0]:
                        sibling_bounds = True
                        break
                if not sibling_bounds:
                    sink_arg = (((sink_entity.get("payload") or {}).get("result") or {}).get("argument_index")
                                if isinstance(sink_entity, Mapping) else None)
                    for sib in range_entities:
                        if not _is_direct_eligible_graph_fact(sib, EntityKind.RANGE_FACT):
                            continue
                        sib_res = (sib.get("payload") or {}).get("result")
                        if not isinstance(sib_res, Mapping):
                            continue
                        sib_op = sib_res.get("operand_index")
                        if _is_int(sink_arg) and int(sink_arg) >= 0 and _is_int(sib_op) and int(sib_op) != int(sink_arg):
                            continue
                        if _fact_effectively_bounds_sink(
                            kind=EntityKind.RANGE_FACT, result=sib_res, destination=destination,
                            weakness_cwe=claim.weakness_cwe, range_entities=range_entities,
                        )[0]:
                            sibling_bounds = True
                            break

            if this_bounds or sibling_bounds:
                return build(
                    effective_relation=RelationKind.QUALIFIES,
                    basis=basis,
                    result=WarrantResult.NOT_ESTABLISHED,
                    reason_code=WarrantReasonCode.EFFECTIVE_GUARD_CANNOT_SUPPORT_MISSING_GUARD,
                    coverage=WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS,
                    sink_override=fact_sink,
                )

            affirmative, aff_code, aff_cov = _fact_affirmatively_shows_missing_or_ineffective_guard(
                kind=entity_kind,
                result=result,
                destination=destination,
            )
            if affirmative:
                return build(
                    effective_relation=RelationKind.SUPPORTS,
                    basis=basis,
                    result=WarrantResult.ESTABLISHED_SUPPORT,
                    reason_code=aff_code,
                    coverage=aff_cov,
                    sink_override=fact_sink,
                )
            return build(
                effective_relation=RelationKind.QUALIFIES,
                basis=basis,
                result=WarrantResult.NOT_ESTABLISHED,
                reason_code=aff_code,
                coverage=aff_cov,
                sink_override=fact_sink,
            )

        if entity_kind is EntityKind.TOOL_OBSERVATION:
            if requested_relation is RelationKind.CONTRADICTS:
                return build(
                    effective_relation=RelationKind.QUALIFIES,
                    basis=WarrantBasis.MAPPED_TOOL_OBSERVATION,
                    result=WarrantResult.NOT_ESTABLISHED,
                    reason_code=WarrantReasonCode.POSITIVE_FACT_CANNOT_CONTRADICT,
                    coverage=WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS,
                )
            bound_exact, bound_ambiguous = _check_subject_binding(core, claim, claim_entities, entity)
            if not bound_exact:
                return build(
                    effective_relation=RelationKind.QUALIFIES,
                    basis=WarrantBasis.MAPPED_TOOL_OBSERVATION,
                    result=WarrantResult.NOT_ESTABLISHED,
                    reason_code=(WarrantReasonCode.AMBIGUOUS_SUBJECT_BINDING if bound_ambiguous
                                 else WarrantReasonCode.SUBJECT_NOT_BOUND_TO_CLAIM),
                    coverage=(WarrantCoverage.AMBIGUOUS_BINDING if bound_ambiguous
                              else WarrantCoverage.OUT_OF_SCOPE),
                )
            return build(
                effective_relation=RelationKind.SUPPORTS,
                basis=WarrantBasis.MAPPED_TOOL_OBSERVATION,
                result=WarrantResult.ESTABLISHED_SUPPORT,
                reason_code=WarrantReasonCode.BOUND_MAPPED_EVIDENCE,
                coverage=WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS,
            )

    return build(
        effective_relation=RelationKind.QUALIFIES,
        basis=WarrantBasis.UNCOMMISSIONED_SEMANTICS,
        result=WarrantResult.UNCOMMISSIONED,
        reason_code=WarrantReasonCode.UNCOMMISSIONED_SEMANTIC_PREDICATE,
        coverage=WarrantCoverage.UNCOMMISSIONED_METHOD,
    )


__all__ = [
    "GUARD_CONTRADICTION_ROLES",
    "PredicateWarrant",
    "REFUTATION_ROLES",
    "SIGNEDNESS_SENSITIVE_CWES",
    "SubjectBinding",
    "UNCOMMISSIONED_GUARD_SECURITY_PREDICATES",
    "WARRANT_RULE_VERSION",
    "WARRANT_SCHEMA",
    "WarrantBasis",
    "WarrantCoverage",
    "WarrantEvidenceRef",
    "WarrantReasonCode",
    "WarrantResult",
    "WarrantScope",
    "bind_warrant_relation_id",
    "compute_warrant_id",
    "evaluate_warrant",
    "validate_warrant_json",
    "warrant_from_json",
    "warrant_json",
    "warrant_satisfies_contradiction",
    "warrant_satisfies_support",
]
