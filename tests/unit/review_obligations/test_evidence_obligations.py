"""Unit tests for ``evidence-obligation/1`` reconciliation, deduplication, and HUNT-C join (TRI-C / T-153)."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
import pytest

from appsec_review.graph.contract import (
    AUTHORITY,
    CATALOG_SCHEMA,
    CROSS_CHECK_RULE,
    GRAPH_FACT_SCHEMA,
    NORMALIZE_RULE,
    Family,
    GraphFact,
    admissibility as graph_admissibility,
    fact_identity,
)
from appsec_review.retrieval import (
    EntityKind,
    EntityRecord,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    RelationKind as IndexRelation,
    RelationRecord,
    RetrievalCore,
    SourceLocation,
    index_fingerprint,
    write_manifest,
)
from appsec_review.review.evidence_obligations import (
    LANE_OBLIGATIONS_SCHEMA,
    OBLIGATION_POLICY_VERSION,
    OBLIGATION_SCHEMA,
    BudgetDisposition,
    CoverageReceiptRef,
    EvidenceObligation,
    ObligationReasonCode,
    ObligationState,
    RequestSubmission,
    ResolutionPolarity,
    canonicalize_question,
    coalesce_obligations,
    obligation_from_json,
    obligation_json,
    pending_followup_requests,
    reconcile_obligations,
    resolve_transport_receipt,
    semantic_round_fingerprint,
)
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.review.models import (
    Admissibility,
    CellRecord,
    CellStatus,
    Claim,
    ClaimState,
    EvidenceRelation,
    GapClass,
    IntegrityError,
    Lane,
    Predicate,
    RelationKind,
    Role,
    SecurityPredicate,
    make_gap,
)
from appsec_review.review.warrants import (
    PredicateWarrant,
    SubjectBinding,
    WARRANT_RULE_VERSION,
    WarrantBasis,
    WarrantCoverage,
    WarrantEvidenceRef,
    WarrantReasonCode,
    WarrantResult,
    compute_warrant_id,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA = json.loads((REPO_ROOT / "docs/schemas/evidence-obligation.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)
SNAPSHOT = "target-sha256:" + "7" * 64
RECEIPT_A = "a" * 64
RECEIPT_B = "b" * 64


def _eid(kind: EntityKind, name: str) -> str:
    return LogicalIdentity.derive(kind, SNAPSHOT, {"native": name}).value


def _cell_id(tag: str) -> str:
    return make_id("cell", 1, {"tag": tag})


def _req_id(claim_id: str, cell_id: str, round_idx: int, question: str, anchor: str) -> str:
    return make_id(
        "evidence_request",
        1,
        {
            "claim_id": claim_id,
            "cell_id": cell_id,
            "round": round_idx,
            "question": question,
            "anchor": anchor,
        },
    )


def _make_claim(
    tag: str,
    entities: tuple[str, ...],
    *,
    sec_pred: SecurityPredicate = SecurityPredicate.SQL_INJECTION,
    cwe: str = "CWE-89",
) -> Claim:
    claim_id = make_id("claim", 1, {"tag": tag, "entities": list(entities)})
    return Claim(
        claim_id=claim_id,
        lane=Lane.LEAD,
        package_id="pkg-test",
        security_predicate=sec_pred,
        affected_entities=tuple(sorted(set(entities))),
        preconditions=("untrusted_input",),
        weakness_cwe=cwe,
        state=ClaimState.PROPOSED,
        origin_cell_ids=(_cell_id("origin"),),
        statement=f"claim {tag}",
    )


def _make_relation_and_warrant(
    claim: Claim,
    *,
    predicate: Predicate,
    kind: RelationKind,
    entity_id: str,
    entity_kind: EntityKind,
    warrant_result: WarrantResult,
    effective_kind: RelationKind | None = None,
    reason_code: WarrantReasonCode = WarrantReasonCode.BOUND_FLOW_SUPPORTS_PREDICATE,
    coverage: WarrantCoverage = WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS,
    admissibility: Admissibility = Admissibility.DIRECT,
    complete: bool = True,
    receipt_sha256: str = RECEIPT_A,
    shard_id: str = "graph/main",
    sink_id: str | None = None,
) -> tuple[EvidenceRelation, PredicateWarrant]:
    eff = effective_kind or kind
    cell = _cell_id(f"prod-{entity_id}-{kind.value}")
    rel_id = make_id(
        "evidence_relation",
        1,
        {
            "claim_id": claim.claim_id,
            "predicate": predicate.value,
            "kind": kind.value,
            "entity_id": entity_id,
            "receipt": receipt_sha256,
        },
    )
    content_digest = sha256_hex({"entity": entity_id})
    rel = EvidenceRelation(
        relation_id=rel_id,
        claim_id=claim.claim_id,
        predicate=predicate,
        kind=kind,
        entity_id=entity_id,
        entity_kind=entity_kind.value,
        admissibility=admissibility,
        shard_id=shard_id,
        content_sha256=content_digest,
        locator=f"src/app.c:10:{entity_kind.value}",
        complete=complete,
        producing_cell_id=cell,
        retrieval_receipt_sha256=receipt_sha256,
    )
    binding = SubjectBinding(
        affected_entity_ids=tuple(sorted(set(claim.affected_entities))),
        sink_id=sink_id,
    )
    ev_ref = WarrantEvidenceRef(
        entity_id=entity_id,
        entity_kind=entity_kind.value,
        shard_id=shard_id,
        content_sha256=content_digest,
        locator=rel.locator,
        retrieval_receipt_sha256=receipt_sha256,
    )
    basis = WarrantBasis.STRUCTURED_FLOW_FACT
    body = {
        "claim_id": claim.claim_id,
        "relation_id": rel_id,
        "predicate": predicate.value,
        "requested_relation": kind.value,
        "effective_relation": eff.value,
        "subject_binding": {
            "affected_entity_ids": list(binding.affected_entity_ids),
            "operation_id": None,
            "sink_id": sink_id,
            "build_scope_id": None,
        },
        "basis": basis.value,
        "evidence_refs": [
            {
                "entity_id": ev_ref.entity_id,
                "entity_kind": ev_ref.entity_kind,
                "shard_id": ev_ref.shard_id,
                "content_sha256": ev_ref.content_sha256,
                "locator": ev_ref.locator,
                "retrieval_receipt_sha256": ev_ref.retrieval_receipt_sha256,
            }
        ],
        "rule": WARRANT_RULE_VERSION,
        "result": warrant_result.value,
        "reason_code": reason_code.value,
        "coverage": coverage.value,
    }
    warrant = PredicateWarrant(
        warrant_id=compute_warrant_id(body),
        claim_id=claim.claim_id,
        relation_id=rel_id,
        predicate=predicate,
        requested_relation=kind,
        effective_relation=eff,
        subject_binding=binding,
        basis=basis,
        evidence_refs=(ev_ref,),
        rule=WARRANT_RULE_VERSION,
        result=warrant_result,
        reason_code=reason_code,
        coverage=coverage,
    )
    return rel, warrant


def _assert_schema_and_roundtrip(obligations: tuple[EvidenceObligation, ...]) -> None:
    items = [obligation_json(ob) for ob in obligations]
    for doc in items:
        VALIDATOR.validate(doc)
        parsed = obligation_from_json(doc)
        assert parsed == obligation_from_json(obligation_json(parsed))
    lane_doc: dict[str, Any] = {
        "schema": LANE_OBLIGATIONS_SCHEMA,
        "lane": "lead",
        "policy_version": OBLIGATION_POLICY_VERSION,
        "count": len(items),
        "items": items,
    }
    VALIDATOR.validate(lane_doc)


def test_deduplication_preserves_origins_and_excludes_actor_and_round() -> None:
    anchor = _eid(EntityKind.COMPILE_UNIT, "cu_debug")
    claim = _make_claim("cfg", (anchor,))
    c1, c2, c3 = _cell_id("red-1"), _cell_id("red-2"), _cell_id("blue-1")
    r1 = _req_id(claim.claim_id, c1, 0, "Is -DFORTIFY_SOURCE=2 enabled?", anchor)
    r2 = _req_id(claim.claim_id, c2, 0, "  is -dfortify_source=2   enabled?? ", anchor)
    r3 = _req_id(claim.claim_id, c3, 1, "Is -DFORTIFY_SOURCE=2 enabled.", anchor)
    r_other = _req_id(claim.claim_id, c1, 0, "Is -fstack-protector-strong enabled?", anchor)

    obligations = coalesce_obligations(
        [
            RequestSubmission(r3, claim.claim_id, Predicate.CONFIGURATION_ENABLES, "configuration",
                              (anchor,), "Is -DFORTIFY_SOURCE=2 enabled.", None, c3, 1),
            RequestSubmission(r2, claim.claim_id, Predicate.CONFIGURATION_ENABLES, "configuration",
                              (anchor,), "  is -dfortify_source=2   enabled?? ", "build_supply_chain", c2, 0),
            RequestSubmission(r1, claim.claim_id, Predicate.CONFIGURATION_ENABLES, "configuration",
                              (anchor,), "Is -DFORTIFY_SOURCE=2 enabled?", None, c1, 0),
            RequestSubmission(r_other, claim.claim_id, Predicate.CONFIGURATION_ENABLES, "configuration",
                              (anchor,), "Is -fstack-protector-strong enabled?", None, c1, 0),
        ],
        claims_by_id={claim.claim_id: claim},
        scope_ceiling="package:pkg-1",
    )
    assert len(obligations) == 2
    fortify = next(ob for ob in obligations if "fortify" in ob.canonical_question)
    assert set(fortify.origin_request_ids) == {r1, r2, r3}
    assert len(fortify.origin_request_ids) == 3
    assert set(fortify.origin_cell_ids) == {c1, c2, c3}
    assert fortify.round_opened == 0
    assert fortify.requested_specialist == "build_supply_chain"
    assert fortify.state is ObligationState.OPEN
    assert fortify.resolution.reason_code is ObligationReasonCode.OPEN_PENDING
    _assert_schema_and_roundtrip(obligations)


def test_scoped_warranted_resolution_ignores_unrelated_same_predicate_evidence() -> None:
    anchor_a = _eid(EntityKind.COMPILE_UNIT, "cu_a")
    anchor_b = _eid(EntityKind.COMPILE_UNIT, "cu_b")
    wrong_kind_span = _eid(EntityKind.SOURCE_SPAN, "span_a")
    claim = _make_claim("cfg-two", (anchor_a, anchor_b))
    cell = _cell_id("red-1")

    sub_a = RequestSubmission(
        _req_id(claim.claim_id, cell, 0, "Does cu_a enable unsafe macro?", anchor_a),
        claim.claim_id, Predicate.CONFIGURATION_ENABLES, "configuration",
        (anchor_a,), "Does cu_a enable unsafe macro?", None, cell, 0,
    )
    sub_b = RequestSubmission(
        _req_id(claim.claim_id, cell, 0, "Does cu_b enable unsafe macro?", anchor_b),
        claim.claim_id, Predicate.CONFIGURATION_ENABLES, "configuration",
        (anchor_b,), "Does cu_b enable unsafe macro?", None, cell, 0,
    )
    obs = coalesce_obligations(
        [sub_a, sub_b],
        claims_by_id={claim.claim_id: claim},
        scope_ceiling="package:pkg-1",
    )
    ob_a = next(ob for ob in obs if ob.anchors == (anchor_a,))
    ob_b = next(ob for ob in obs if ob.anchors == (anchor_b,))

    # Same predicate on anchor_a, plus a source_span (wrong requested_kind for "configuration") on anchor_b.
    rel_a, war_a = _make_relation_and_warrant(
        claim,
        predicate=Predicate.CONFIGURATION_ENABLES,
        kind=RelationKind.SUPPORTS,
        entity_id=anchor_a,
        entity_kind=EntityKind.COMPILE_UNIT,
        warrant_result=WarrantResult.ESTABLISHED_SUPPORT,
        reason_code=WarrantReasonCode.BOUND_CONFIGURATION_FACT,
    )
    rel_wrong_kind, war_wrong_kind = _make_relation_and_warrant(
        claim,
        predicate=Predicate.CONFIGURATION_ENABLES,
        kind=RelationKind.SUPPORTS,
        entity_id=wrong_kind_span,
        entity_kind=EntityKind.SOURCE_SPAN,
        warrant_result=WarrantResult.ESTABLISHED_SUPPORT,
        reason_code=WarrantReasonCode.BOUND_PRESENCE_SUPPORTS_CONSTRUCT,
    )

    reconciled = reconcile_obligations(
        obs,
        claims_by_id={claim.claim_id: claim},
        relations=(rel_a, rel_wrong_kind),
        warrants_by_relation_id={rel_a.relation_id: war_a, rel_wrong_kind.relation_id: war_wrong_kind},
        package_entities={anchor_a, anchor_b, wrong_kind_span},
        evaluated_round=1,
        terminal=True,
    )
    by_id = {ob.obligation_id: ob for ob in reconciled}
    assert by_id[ob_a.obligation_id].state is ObligationState.SATISFIED
    assert by_id[ob_a.obligation_id].resolution.reason_code is ObligationReasonCode.SATISFIED_BY_WARRANTED_EVIDENCE
    assert by_id[ob_a.obligation_id].resolution.polarity is ResolutionPolarity.SUPPORTS
    assert by_id[ob_a.obligation_id].resolution.relation_ids == (rel_a.relation_id,)
    assert by_id[ob_a.obligation_id].resolution.warrant_ids == (war_a.warrant_id,)
    assert by_id[ob_a.obligation_id].resolution.read_receipt_refs == (RECEIPT_A,)

    # ob_b must NOT be resolved by anchor_a's same-predicate evidence or wrong-kind evidence!
    assert by_id[ob_b.obligation_id].state is ObligationState.UNSATISFIED
    assert by_id[ob_b.obligation_id].resolution.reason_code is ObligationReasonCode.NO_DECISIVE_EVIDENCE
    assert by_id[ob_b.obligation_id].resolution.relation_ids == ()
    _assert_schema_and_roundtrip(reconciled)


def test_warranted_contradiction_satisfies_obligation_while_conflict_remains_unsatisfied() -> None:
    sink = _eid(EntityKind.SINK_SITE, "memcpy_sink")
    guard_ok = _eid(EntityKind.GUARD_FACT, "guard_bounds_dst")
    guard_bad = _eid(EntityKind.GUARD_FACT, "guard_ineffective")
    claim = _make_claim("buf", (sink,), sec_pred=SecurityPredicate.MEMORY_CORRUPTION, cwe="CWE-120")
    cell = _cell_id("blue-1")

    obs = coalesce_obligations(
        [
            RequestSubmission(
                _req_id(claim.claim_id, cell, 0, "Does a guard bound memcpy_sink?", sink),
                claim.claim_id, Predicate.MISSING_OR_INEFFECTIVE_GUARD, "guard_fact",
                (sink,), "Does a guard bound memcpy_sink?", "memory_safety_native", cell, 0,
            )
        ],
        claims_by_id={claim.claim_id: claim},
        scope_ceiling="package:pkg-buf",
    )

    rel_contra, war_contra = _make_relation_and_warrant(
        claim,
        predicate=Predicate.MISSING_OR_INEFFECTIVE_GUARD,
        kind=RelationKind.CONTRADICTS,
        entity_id=guard_ok,
        entity_kind=EntityKind.GUARD_FACT,
        warrant_result=WarrantResult.ESTABLISHED_CONTRADICTION,
        reason_code=WarrantReasonCode.EFFECTIVE_GUARD_BOUNDS_DESTINATION,
        receipt_sha256=RECEIPT_A,
        sink_id=sink,
    )

    # 1. Refuting warranted evidence alone satisfies the obligation (the question was answered!).
    refuted = reconcile_obligations(
        obs,
        claims_by_id={claim.claim_id: claim},
        relations=(rel_contra,),
        warrants_by_relation_id={rel_contra.relation_id: war_contra},
        package_entities={sink},
        evaluated_round=1,
        terminal=True,
    )
    assert refuted[0].state is ObligationState.SATISFIED
    assert refuted[0].resolution.polarity is ResolutionPolarity.CONTRADICTS
    assert refuted[0].resolution.warrant_ids == (war_contra.warrant_id,)
    _assert_schema_and_roundtrip(refuted)

    # 2. Both warranted support AND warranted contradiction on the same obligation stay OPEN mid-run
    #    and close UNSATISFIED with unresolved_contradiction at terminal seal.
    rel_sup, war_sup = _make_relation_and_warrant(
        claim,
        predicate=Predicate.MISSING_OR_INEFFECTIVE_GUARD,
        kind=RelationKind.SUPPORTS,
        entity_id=guard_bad,
        entity_kind=EntityKind.GUARD_FACT,
        warrant_result=WarrantResult.ESTABLISHED_SUPPORT,
        reason_code=WarrantReasonCode.GUARD_INEFFECTIVE_FOR_DESTINATION,
        receipt_sha256=RECEIPT_B,
        sink_id=sink,
    )
    mid_round = reconcile_obligations(
        obs,
        claims_by_id={claim.claim_id: claim},
        relations=(rel_contra, rel_sup),
        warrants_by_relation_id={rel_contra.relation_id: war_contra, rel_sup.relation_id: war_sup},
        package_entities={sink},
        evaluated_round=0,
        terminal=False,
    )
    assert mid_round[0].state is ObligationState.OPEN

    sealed_conflict = reconcile_obligations(
        obs,
        claims_by_id={claim.claim_id: claim},
        relations=(rel_contra, rel_sup),
        warrants_by_relation_id={rel_contra.relation_id: war_contra, rel_sup.relation_id: war_sup},
        package_entities={sink},
        evaluated_round=1,
        terminal=True,
    )
    assert sealed_conflict[0].state is ObligationState.UNSATISFIED
    assert sealed_conflict[0].resolution.reason_code is ObligationReasonCode.UNRESOLVED_CONTRADICTION
    assert sealed_conflict[0].resolution.polarity is ResolutionPolarity.CONFLICTED
    assert set(sealed_conflict[0].resolution.relation_ids) == {rel_contra.relation_id, rel_sup.relation_id}
    assert set(sealed_conflict[0].resolution.warrant_ids) == {war_contra.warrant_id, war_sup.warrant_id}
    _assert_schema_and_roundtrip(sealed_conflict)


def test_specific_terminal_reasons_for_scope_producers_caps_timeouts_and_incomplete_evidence() -> None:
    in_pkg = _eid(EntityKind.SYMBOL, "sym_in")
    foreign = _eid(EntityKind.SYMBOL, "sym_foreign")
    claim = _make_claim("reasons", (in_pkg,))
    capped_claim = _make_claim("capped", (in_pkg,))
    cell = _cell_id("red-1")
    claims = {claim.claim_id: claim, capped_claim.claim_id: capped_claim}

    obs = coalesce_obligations(
        [
            RequestSubmission(
                _req_id(claim.claim_id, cell, 0, "Foreign symbol check?", foreign),
                claim.claim_id, Predicate.AFFECTED_CONSTRUCT, "symbol", (foreign,),
                "Foreign symbol check?", None, cell, 0,
            ),
            RequestSubmission(
                _req_id(claim.claim_id, cell, 0, "What is business impact?", in_pkg),
                claim.claim_id, Predicate.SECURITY_IMPACT, "other", (in_pkg,),
                "What is business impact?", "business_logic_abuse", cell, 0,
            ),
            RequestSubmission(
                _req_id(capped_claim.claim_id, cell, 0, "Capped claim check?", in_pkg),
                capped_claim.claim_id, Predicate.AFFECTED_CONSTRUCT, "symbol", (in_pkg,),
                "Capped claim check?", None, cell, 0,
            ),
        ],
        claims_by_id=claims,
        scope_ceiling="package:pkg-reasons",
    )
    # Non-terminal pass already fails closed on outside_package and withdrawn claims.
    mid = reconcile_obligations(
        obs,
        claims_by_id=claims,
        package_entities={in_pkg},
        withdrawn_claims={capped_claim.claim_id: BudgetDisposition.CLAIMS_PER_PACKAGE_CAP},
        evaluated_round=0,
        terminal=False,
    )
    by_q_mid = {ob.canonical_question: ob for ob in mid}
    assert by_q_mid["foreign symbol check"].state is ObligationState.UNSATISFIED
    assert by_q_mid["foreign symbol check"].resolution.reason_code is ObligationReasonCode.OUTSIDE_PACKAGE
    assert by_q_mid["capped claim check"].state is ObligationState.WITHDRAWN
    assert by_q_mid["capped claim check"].resolution.reason_code is ObligationReasonCode.WITHDRAWN_CLAIM_CAPPED

    sealed = reconcile_obligations(
        obs,
        claims_by_id=claims,
        package_entities={in_pkg},
        withdrawn_claims={capped_claim.claim_id: BudgetDisposition.CLAIMS_PER_PACKAGE_CAP},
        evaluated_round=1,
        terminal=True,
    )
    by_q = {ob.canonical_question: ob for ob in sealed}
    assert by_q["what is business impact"].state is ObligationState.UNSATISFIED
    assert by_q["what is business impact"].resolution.reason_code is ObligationReasonCode.PRODUCER_UNCOMMISSIONED
    _assert_schema_and_roundtrip(sealed)

    # Incomplete mapping vs timeout vs invalid response vs retrieval cap vs model budget vs unavailable.
    single_ob = coalesce_obligations(
        [
            RequestSubmission(
                _req_id(claim.claim_id, cell, 0, "Is sym_in reachable?", in_pkg),
                claim.claim_id, Predicate.AFFECTED_CONSTRUCT, "symbol", (in_pkg,),
                "Is sym_in reachable?", None, cell, 0,
            )
        ],
        claims_by_id={claim.claim_id: claim},
        scope_ceiling="package:pkg-reasons",
    )
    rel_inc, war_inc = _make_relation_and_warrant(
        claim,
        predicate=Predicate.AFFECTED_CONSTRUCT,
        kind=RelationKind.SUPPORTS,
        entity_id=in_pkg,
        entity_kind=EntityKind.SYMBOL,
        warrant_result=WarrantResult.NOT_ESTABLISHED,
        effective_kind=RelationKind.QUALIFIES,
        reason_code=WarrantReasonCode.INCOMPLETE_FACT_RECORD,
        coverage=WarrantCoverage.INCOMPLETE_FACTS,
        complete=False,
    )
    inc_res = reconcile_obligations(
        single_ob,
        claims_by_id={claim.claim_id: claim},
        relations=(rel_inc,),
        warrants_by_relation_id={rel_inc.relation_id: war_inc},
        package_entities={in_pkg},
        evaluated_round=1,
        terminal=True,
    )
    assert inc_res[0].resolution.reason_code is ObligationReasonCode.INCOMPLETE_MAPPING

    cutoff_res = reconcile_obligations(
        single_ob,
        claims_by_id={claim.claim_id: claim},
        package_entities={in_pkg},
        cutoff_obligation_ids={single_ob[0].obligation_id},
        evaluated_round=1,
        terminal=True,
    )
    assert cutoff_res[0].resolution.reason_code is ObligationReasonCode.RETRIEVAL_CAP
    assert cutoff_res[0].budget_disposition is BudgetDisposition.FOLLOW_UP_REQUEST_CUTOFF

    timed_out_cell = CellRecord(
        cell_id=_cell_id("timeout"), lane=Lane.LEAD, package_id="pkg-reasons",
        role=Role.RED_TEAM_ANALYST, persona="default", stack_profile="c_cpp", task="red_follow_up",
        claim_id=claim.claim_id, status=CellStatus.TIMED_OUT, attempts=1, receipt_sha256=RECEIPT_A,
    )
    to_res = reconcile_obligations(
        single_ob,
        claims_by_id={claim.claim_id: claim},
        package_entities={in_pkg},
        cells=(timed_out_cell,),
        evaluated_round=1,
        terminal=True,
    )
    assert to_res[0].resolution.reason_code is ObligationReasonCode.TIMED_OUT

    invalid_cell = CellRecord(
        cell_id=_cell_id("invalid"), lane=Lane.LEAD, package_id="pkg-reasons",
        role=Role.RED_TEAM_ANALYST, persona="default", stack_profile="c_cpp", task="red_follow_up",
        claim_id=claim.claim_id, status=CellStatus.INVALID, attempts=1, receipt_sha256=RECEIPT_A,
    )
    inv_res = reconcile_obligations(
        single_ob,
        claims_by_id={claim.claim_id: claim},
        package_entities={in_pkg},
        cells=(invalid_cell,),
        evaluated_round=1,
        terminal=True,
    )
    assert inv_res[0].resolution.reason_code is ObligationReasonCode.INVALID_RESPONSE

    budget_res = reconcile_obligations(
        single_ob,
        claims_by_id={claim.claim_id: claim},
        package_entities={in_pkg},
        round_stop_reason="max_rounds",
        evaluated_round=2,
        terminal=True,
    )
    assert budget_res[0].resolution.reason_code is ObligationReasonCode.MODEL_BUDGET
    assert budget_res[0].budget_disposition is BudgetDisposition.MAX_ROUNDS_CUTOFF

    unavail_gap = make_gap(GapClass.EVIDENCE_GAP, single_ob[0].primary_request_id, "missing_shard_unavailable")
    unavail_res = reconcile_obligations(
        single_ob,
        claims_by_id={claim.claim_id: claim},
        package_entities={in_pkg},
        gaps=(unavail_gap,),
        evaluated_round=1,
        terminal=True,
    )
    assert unavail_res[0].resolution.reason_code is ObligationReasonCode.EVIDENCE_UNAVAILABLE
    assert unavail_res[0].remaining_gap_ids == (unavail_gap.gap_id,)
    _assert_schema_and_roundtrip((*inc_res, *cutoff_res, *to_res, *inv_res, *budget_res, *unavail_res))


def test_transport_served_never_implies_resolved_and_legacy_receipts_stay_unknown() -> None:
    anchor = _eid(EntityKind.COMPILE_UNIT, "cu_prod")
    claim = _make_claim("hunt-join", (anchor,))
    cell = _cell_id("hunt-1")
    obs = coalesce_obligations(
        [
            RequestSubmission(
                _req_id(claim.claim_id, cell, 0, "What flags compile cu_prod?", anchor),
                claim.claim_id, Predicate.CONFIGURATION_ENABLES, "configuration",
                (anchor,), "What flags compile cu_prod?", None, cell, 0,
            )
        ],
        claims_by_id={claim.claim_id: claim},
        scope_ceiling="package:pkg-hunt",
    )
    ob_id = obs[0].obligation_id
    served_receipt = CoverageReceiptRef(
        receipt_id="hunt-rcpt-001",
        artifact_sha256="c" * 64,
        canonical_request_id=ob_id,
        delivery_state="served",
    )

    # Served transport receipt WITHOUT warranted evidence NEVER marks the obligation satisfied!
    reconciled = reconcile_obligations(
        obs,
        claims_by_id={claim.claim_id: claim},
        package_entities={anchor},
        coverage_receipts={ob_id: (served_receipt,)},
        evaluated_round=1,
        terminal=True,
    )
    assert reconciled[0].state is ObligationState.UNSATISFIED
    assert reconciled[0].resolution.reason_code is ObligationReasonCode.NO_DECISIVE_EVIDENCE
    assert reconciled[0].coverage_receipt_refs[0].semantic_resolution == "unsatisfied"

    joined_served = resolve_transport_receipt(served_receipt, {ob_id: reconciled[0]})
    assert joined_served.canonical_request_id == ob_id
    assert joined_served.resolution_basis == "tri_c_verified_resolution"
    assert joined_served.semantic_state == "unsatisfied"

    # Legacy delivery-only receipt retains explicit unknown semantic resolution, never satisfied.
    legacy = CoverageReceiptRef(
        receipt_id="legacy-rcpt-000",
        artifact_sha256="d" * 64,
        canonical_request_id=None,
        delivery_state="legacy_delivery_only",
        semantic_resolution="legacy_resolution_unknown",
    )
    legacy_view = resolve_transport_receipt(legacy, {ob_id: reconciled[0]})
    assert legacy_view.resolution_basis == "legacy_resolution_unknown"
    assert legacy_view.semantic_state == "unknown"
    assert legacy_view.canonical_resolution_ref is None

    # Mismatched canonical_request_id fails closed.
    wrong_id = "evob-" + "e" * 64
    bad_receipt = CoverageReceiptRef(
        receipt_id="hunt-rcpt-bad",
        artifact_sha256="c" * 64,
        canonical_request_id=wrong_id,
        delivery_state="served",
    )
    with pytest.raises(IntegrityError, match="mismatches obligation"):
        reconcile_obligations(
            obs,
            claims_by_id={claim.claim_id: claim},
            coverage_receipts={ob_id: (bad_receipt,)},
            terminal=True,
        )


def test_round_convergence_and_pending_followup_filtering_and_supersession() -> None:
    a1 = _eid(EntityKind.COMPILE_UNIT, "cu_1")
    a2 = _eid(EntityKind.COMPILE_UNIT, "cu_2")
    claim = _make_claim("conv", (a1, a2))
    c1, c2 = _cell_id("r0"), _cell_id("r1")

    sub_r0_a1 = RequestSubmission(
        _req_id(claim.claim_id, c1, 0, "Check cu_1?", a1),
        claim.claim_id, Predicate.CONFIGURATION_ENABLES, "configuration", (a1,), "Check cu_1?", None, c1, 0,
    )
    sub_r0_a2 = RequestSubmission(
        _req_id(claim.claim_id, c1, 0, "Check cu_2?", a2),
        claim.claim_id, Predicate.CONFIGURATION_ENABLES, "configuration", (a2,), "Check cu_2?", None, c1, 0,
    )
    r0_obs = reconcile_obligations(
        coalesce_obligations([sub_r0_a1, sub_r0_a2], claims_by_id={claim.claim_id: claim}, scope_ceiling="pkg:1"),
        claims_by_id={claim.claim_id: claim},
        package_entities={a1, a2},
        evaluated_round=0,
        terminal=False,
    )
    fp0 = semantic_round_fingerprint(r0_obs)

    # Repeating the exact same request from a new cell in round 1 produces the IDENTICAL semantic fingerprint.
    sub_r1_repeat = RequestSubmission(
        _req_id(claim.claim_id, c2, 1, "Check cu_1?", a1),
        claim.claim_id, Predicate.CONFIGURATION_ENABLES, "configuration", (a1,), "Check cu_1?", None, c2, 1,
    )
    r1_repeated = reconcile_obligations(
        coalesce_obligations(
            [sub_r0_a1, sub_r0_a2, sub_r1_repeat], claims_by_id={claim.claim_id: claim}, scope_ceiling="pkg:1",
        ),
        claims_by_id={claim.claim_id: claim},
        package_entities={a1, a2},
        evaluated_round=1,
        terminal=False,
    )
    assert semantic_round_fingerprint(r1_repeated) == fp0

    # Satisfying cu_1 changes the fingerprint once and drops cu_1 from pending_followup_requests.
    rel_a1, war_a1 = _make_relation_and_warrant(
        claim,
        predicate=Predicate.CONFIGURATION_ENABLES,
        kind=RelationKind.SUPPORTS,
        entity_id=a1,
        entity_kind=EntityKind.COMPILE_UNIT,
        warrant_result=WarrantResult.ESTABLISHED_SUPPORT,
        reason_code=WarrantReasonCode.BOUND_CONFIGURATION_FACT,
    )
    r1_answered = reconcile_obligations(
        r1_repeated,
        claims_by_id={claim.claim_id: claim},
        relations=(rel_a1,),
        warrants_by_relation_id={rel_a1.relation_id: war_a1},
        package_entities={a1, a2},
        evaluated_round=1,
        terminal=False,
    )
    assert semantic_round_fingerprint(r1_answered) != fp0
    pending, cutoff = pending_followup_requests(r1_answered, max_requests=10)
    assert len(pending) == 1 and pending[0]["anchors"] == [a2]
    assert cutoff == ()

    # Explicit supersession closes one obligation in favor of another and rejects cycles.
    ob_ids = [ob.obligation_id for ob in r0_obs]
    superseded = reconcile_obligations(
        r0_obs,
        claims_by_id={claim.claim_id: claim},
        superseded_by_map={ob_ids[0]: ob_ids[1]},
        evaluated_round=1,
        terminal=True,
    )
    sup_map = {ob.obligation_id: ob for ob in superseded}
    assert sup_map[ob_ids[0]].state is ObligationState.SUPERSEDED
    assert sup_map[ob_ids[0]].resolution.superseded_by == ob_ids[1]
    _assert_schema_and_roundtrip(superseded)

    with pytest.raises(IntegrityError, match="cyclic obligation supersession"):
        reconcile_obligations(
            r0_obs,
            claims_by_id={claim.claim_id: claim},
            superseded_by_map={ob_ids[0]: ob_ids[1], ob_ids[1]: ob_ids[0]},
            terminal=True,
        )


def test_tampered_obligation_json_fails_closed() -> None:
    anchor = _eid(EntityKind.COMPILE_UNIT, "cu_tamper")
    claim = _make_claim("tamper", (anchor,))
    cell = _cell_id("r0")
    obs = coalesce_obligations(
        [
            RequestSubmission(
                _req_id(claim.claim_id, cell, 0, "Tamper check?", anchor),
                claim.claim_id, Predicate.CONFIGURATION_ENABLES, "configuration",
                (anchor,), "Tamper check?", None, cell, 0,
            )
        ],
        claims_by_id={claim.claim_id: claim},
        scope_ceiling="package:pkg-t",
    )
    doc = obligation_json(obs[0])
    assert doc["schema"] == OBLIGATION_SCHEMA

    # Changing question without recomputing obligation_id fails digest check.
    forged_q = copy.deepcopy(doc)
    forged_q["question"] = "Different question?"
    forged_q["canonical_question"] = canonicalize_question("Different question?")
    with pytest.raises(IntegrityError, match="does not match canonical digest"):
        obligation_from_json(forged_q)

    # Forging state="satisfied" without warrant/relation/receipt refs fails both parser and JSON schema.
    forged_sat = copy.deepcopy(doc)
    forged_sat["state"] = "satisfied"
    forged_sat["resolution"]["reason_code"] = "satisfied_by_warranted_evidence"
    with pytest.raises(IntegrityError, match="satisfied obligation requires"):
        obligation_from_json(forged_sat)
    assert not VALIDATOR.is_valid(forged_sat)


def test_on_demand_retrieval_core_warrant_reconciliation_and_multi_anchor_flow(tmp_path: Path) -> None:
    """When warrant_policy.enabled is false (no precomputed warrant map), TRI-C evaluates warrants via RetrievalCore."""
    from tests.handoff_fixture import write_fixture_handoff

    run_id = "2026-11-14-0153"
    scope_id = "codeql:c/c++:debug:" + "1" * 16
    runs = tmp_path / "runs"
    run_root = runs / run_id
    target = tmp_path / "target"
    src_file = target / "src" / "query.c"
    src_file.parent.mkdir(parents=True, exist_ok=True)
    src_text = "int run(const char *a, const char *b) { return exec_sql(a); }\n"
    src_file.write_text(src_text, encoding="utf-8")
    src_digest = file_sha256(src_file)
    loc = SourceLocation(
        SNAPSHOT, "src/query.c", src_digest, 0, len(src_text) - 1, 1, 1, 1, len(src_text),
        {}, "fixture-exact", 1.0, False,
    )

    def _gf(family: Family, native: dict[str, Any], result: dict[str, Any]) -> EntityRecord:
        payload: dict[str, Any] = {
            "schema": GRAPH_FACT_SCHEMA,
            "family": family.value,
            "producer": {
                "name": "codeql-export", "tool_version": "2.27.0", "export_pack_sha256": "a" * 64,
                "catalog_version": CATALOG_SCHEMA, "rule_version": NORMALIZE_RULE,
            },
            "scope": {
                "scope_id": scope_id, "language": "c/c++",
                "build_unit_id": "debug", "component_id": "component:0001",
            },
            "exact": True,
            "coverage_status": "complete",
            "gaps": [],
            "cross_check": {"rule": CROSS_CHECK_RULE, "state": "not_covered", "producers": []},
            "result": result,
            "upstream": [],
            "authority": AUTHORITY,
        }
        payload["admissibility"] = graph_admissibility(payload)
        identity = fact_identity(family, SNAPSHOT, {"scope_id": scope_id, **native})
        return GraphFact(identity, f"{family.value}:{identity.value[-8:]}", payload, loc).to_entity()

    ent_src_a = _gf(
        Family.ENTRY_POINT,
        {"path": "src/query.c", "start_byte": 8, "end_byte": 21, "source_class": "remote"},
        {"source_class": "remote", "api_or_parameter": {"display": "a"}},
    )
    ent_src_b = _gf(
        Family.ENTRY_POINT,
        {"path": "src/query.c", "start_byte": 23, "end_byte": 36, "source_class": "remote"},
        {"source_class": "remote", "api_or_parameter": {"display": "b"}},
    )
    ent_sink = _gf(
        Family.SINK_SITE,
        {"path": "src/query.c", "start_byte": 47, "end_byte": 58, "sink_class": "sql_execution", "argument_index": 0},
        {"sink_class": "sql_execution", "cwe_family": "CWE-89", "api": {"display": "exec_sql"}},
    )
    src_a_id = ent_src_a.identity.value
    src_b_id = ent_src_b.identity.value
    sink_id = ent_sink.identity.value
    ent_flow_ab = _gf(
        Family.DATAFLOW_PATH,
        {"source_identity": src_b_id, "sink_identity": sink_id, "step_locations_sha256": "7" * 64},
        {"source": {"entry_point": src_b_id, "source_class": "remote"},
         "sink": {"sink_site": sink_id, "sink_class": "sql_execution", "cwe_family": "CWE-89"},
         "steps": [], "hop_count": 1, "truncated_steps": False},
    )
    ent_flow_ok = _gf(
        Family.DATAFLOW_PATH,
        {"source_identity": src_a_id, "sink_identity": sink_id, "step_locations_sha256": "8" * 64},
        {"source": {"entry_point": src_a_id, "source_class": "remote"},
         "sink": {"sink_site": sink_id, "sink_class": "sql_execution", "cwe_family": "CWE-89"},
         "steps": [], "hop_count": 1, "truncated_steps": False},
    )
    flow_ab_id = ent_flow_ab.identity.value
    flow_ok_id = ent_flow_ok.identity.value

    fp = index_fingerprint(
        name="graph", target_snapshot=SNAPSHOT, producer_artifacts=[{"sha256": "a" * 64}],
        tool_identity={"tool": "fixture"}, parser_identity="p/1",
        normalizer_identity="n/1", mapping_identity="m/1",
    )
    db_path = run_root / "data" / "indices" / "graph" / "cpp-debug" / f"{fp}.sqlite"
    builder = IndexBuilder(db_path, name="graph", fingerprint=fp, target_snapshot=SNAPSHOT, shard_id="cpp-debug")
    for ent in (ent_src_a, ent_src_b, ent_sink, ent_flow_ab, ent_flow_ok):
        builder.add_entity(ent)
    builder.add_relation(RelationRecord(IndexRelation.FLOWS_TO, src_b_id, sink_id, True, 1.0))
    builder.add_relation(RelationRecord(IndexRelation.FLOWS_TO, src_a_id, sink_id, True, 1.0))
    builder.add_coverage("graph:cpp-debug", "complete", None)
    digest = builder.build()
    ident = IndexIdentity(
        "graph", "appsec-review/retrieval-index/2", digest, fp,
        db_path.relative_to(run_root).as_posix(), {"fixture": "graph"}, (), "cpp-debug",
    )
    manifest = run_root / "data" / "indices" / "manifests" / "fixture.json"
    write_manifest(manifest, run_id=run_id, target_snapshot=SNAPSHOT, target_root=target, indexes=[ident])
    attempt = run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001"
    attempt.mkdir(parents=True)
    art = {"path": manifest.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest), "size_bytes": manifest.stat().st_size}
    handoff = attempt / "handoff.json"
    write_fixture_handoff(run_root, handoff, {
        "source_fingerprint": SNAPSHOT, "status": "ACCEPTED", "job_id": "fixture",
        "attempt_id": "attempt_0001", "artifacts": [art], "outputs": {},
    })
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": run_id,
        "handoff_path": handoff.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff),
        "manifest_path": art["path"], "manifest_sha256": art["sha256"],
    })
    core = RetrievalCore(runs, run_id)

    claim = _make_claim("multi-anchor-flow", (sink_id,))
    cell = _cell_id("red-flow")
    # Obligation specifically asks whether dataflow connects BOTH src_a AND sink.
    obs = coalesce_obligations(
        [
            RequestSubmission(
                _req_id(claim.claim_id, cell, 0, "Does param_a flow to exec_sql_sink?", src_a_id),
                claim.claim_id, Predicate.SOURCE_TO_SINK_REACHABILITY, "dataflow",
                (src_a_id, sink_id), "Does param_a flow to exec_sql_sink?", None, cell, 0,
            )
        ],
        claims_by_id={claim.claim_id: claim},
        core=core,
        scope_ceiling="package:pkg-flow",
    )
    assert obs[0].subject_binding.sink_id == sink_id

    rel_wrong_src = EvidenceRelation(
        relation_id=make_id("evidence_relation", 1, {"e": flow_ab_id}),
        claim_id=claim.claim_id,
        predicate=Predicate.SOURCE_TO_SINK_REACHABILITY,
        kind=RelationKind.SUPPORTS,
        entity_id=flow_ab_id,
        entity_kind=EntityKind.DATAFLOW_PATH.value,
        admissibility=Admissibility.DIRECT,
        shard_id="cpp-debug",
        content_sha256=src_digest,
        locator="src/query.c:1:flow_b",
        complete=True,
        producing_cell_id=cell,
        retrieval_receipt_sha256=RECEIPT_A,
    )
    # Wrong-source flow touches sink, NOT src_a -> must NOT satisfy the multi-anchor obligation!
    wrong_only = reconcile_obligations(
        obs,
        claims_by_id={claim.claim_id: claim},
        relations=(rel_wrong_src,),
        core=core,
        package_entities={src_a_id, src_b_id, sink_id},
        evaluated_round=1,
        terminal=True,
    )
    assert wrong_only[0].state is ObligationState.UNSATISFIED
    assert wrong_only[0].resolution.reason_code is ObligationReasonCode.INCOMPLETE_MAPPING

    rel_right_src = EvidenceRelation(
        relation_id=make_id("evidence_relation", 1, {"e": flow_ok_id}),
        claim_id=claim.claim_id,
        predicate=Predicate.SOURCE_TO_SINK_REACHABILITY,
        kind=RelationKind.SUPPORTS,
        entity_id=flow_ok_id,
        entity_kind=EntityKind.DATAFLOW_PATH.value,
        admissibility=Admissibility.DIRECT,
        shard_id="cpp-debug",
        content_sha256=src_digest,
        locator="src/query.c:1:flow_a",
        complete=True,
        producing_cell_id=cell,
        retrieval_receipt_sha256=RECEIPT_B,
    )
    both = reconcile_obligations(
        obs,
        claims_by_id={claim.claim_id: claim},
        relations=(rel_wrong_src, rel_right_src),
        core=core,
        package_entities={src_a_id, src_b_id, sink_id},
        evaluated_round=1,
        terminal=True,
    )
    assert both[0].state is ObligationState.SATISFIED
    assert both[0].resolution.relation_ids == (rel_right_src.relation_id,)
    assert len(both[0].resolution.warrant_ids) == 1
    assert both[0].resolution.read_receipt_refs == (RECEIPT_B,)
    _assert_schema_and_roundtrip(both)
