from __future__ import annotations

import pytest

from appsec_review.retrieval.model import EntityKind, LogicalIdentity
from appsec_review.review.adjudication import POLICY_SHA256, DecidingRow, PredicateOutcome, adjudicate
from appsec_review.review.claims import normalize_claim
from appsec_review.review.evidence import make_gap
from appsec_review.review.identity import make_id
from appsec_review.review.models import (
    Admissibility, ClaimState, EvidenceRelation, GapClass, Lane, Predicate, RelationKind,
)
from appsec_review.review.obligations import ALWAYS_REQUIRED

ENTITY = LogicalIdentity.derive(EntityKind.SYMBOL, "snap", {"n": "copy"}).value
CLAIM = normalize_claim(lane=Lane.LEAD, package_id="p", affected_entities=[ENTITY], weakness_cwe="CWE-120",
                        security_predicate="memory_corruption", preconditions=["attacker_controls_request_field"],
                        statement="s", accepted_cwe_ids={"CWE-120"}).claim
CONFIG_CLAIM = normalize_claim(lane=Lane.LEAD, package_id="p", affected_entities=[ENTITY], weakness_cwe=None,
                               security_predicate="memory_corruption", preconditions=["debug_mode_enabled"],
                               statement="s", accepted_cwe_ids=()).claim
SCOPE = {ENTITY}


def rel(predicate: Predicate, kind: RelationKind = RelationKind.SUPPORTS, *, claim=CLAIM,
        admissibility: Admissibility = Admissibility.DIRECT, complete: bool = True, tag: str = "red",
        entity_kind: str = "source_span") -> EvidenceRelation:
    body = {"p": predicate.value, "k": kind.value, "a": admissibility.value, "c": complete, "t": tag,
            "claim": claim.claim_id}
    return EvidenceRelation(make_id("evidence_relation", 1, body), claim.claim_id, predicate, kind, ENTITY,
                            entity_kind, admissibility, "analysis/default", "0" * 64, "src/a.c:1-1", complete,
                            f"cell-{tag}", "f" * 64)


def all_supported(claim=CLAIM, predicates=ALWAYS_REQUIRED, **kwargs) -> list[EvidenceRelation]:
    return [rel(p, claim=claim, **kwargs) for p in predicates]


def run(relations, independent=True, claim=CLAIM, existing=(), scope=SCOPE, **kwargs):
    return adjudicate(claim, relations, independent, scope, existing, **kwargs)


def test_full_direct_support_with_independence_confirms() -> None:
    result = run(all_supported())
    assert result.state is ClaimState.CONFIRMED and result.deciding_row is DecidingRow.CONFIRMED
    assert result.policy_sha256 == POLICY_SHA256 and result.adjudication_id.startswith("adjudication-")
    assert result.gaps == ()
    required = {s.predicate for s in result.predicates if s.required}
    assert required == set(ALWAYS_REQUIRED)


def test_ten_identical_unsupported_model_claims_cannot_confirm() -> None:
    prose = [rel(p, admissibility=Admissibility.INDIRECT, tag=f"opinion-{i}", entity_kind="review_signal")
             for i in range(10) for p in ALWAYS_REQUIRED]
    result = run(prose)
    assert result.state is ClaimState.INSUFFICIENT_EVIDENCE
    assert result.counted_relation_ids == ()
    assert {gap.predicate for gap in result.gaps} == set(ALWAYS_REQUIRED)


def test_repeated_opinions_do_not_outweigh_one_contradiction() -> None:
    supports = [rel(Predicate.SECURITY_IMPACT, tag=f"v{i}") for i in range(10)]
    result = run([*all_supported(predicates=[p for p in ALWAYS_REQUIRED if p is not Predicate.SECURITY_IMPACT]),
                  *supports, rel(Predicate.SECURITY_IMPACT, RelationKind.CONTRADICTS, tag="blue")])
    assert result.state is ClaimState.INSUFFICIENT_EVIDENCE
    assert result.deciding_row is DecidingRow.UNRESOLVED_CONTRADICTION


def test_blue_support_alone_cannot_confirm_without_independent_verifier() -> None:
    result = run(all_supported(tag="blue"), independent=False)
    assert result.state is ClaimState.SUPPORTED and result.deciding_row is DecidingRow.SUPPORTED


def test_partial_support_is_supported_with_missing_evidence_gaps() -> None:
    result = run([rel(Predicate.AFFECTED_CONSTRUCT)])
    assert result.state is ClaimState.SUPPORTED
    assert {gap.predicate for gap in result.gaps} == set(ALWAYS_REQUIRED) - {Predicate.AFFECTED_CONSTRUCT}
    assert all(gap.gap_class is GapClass.EVIDENCE_GAP for gap in result.gaps)


def test_contradiction_on_reachability_is_not_reachable() -> None:
    relations = [*all_supported(predicates=[p for p in ALWAYS_REQUIRED
                                            if p is not Predicate.SOURCE_TO_SINK_REACHABILITY]),
                 rel(Predicate.SOURCE_TO_SINK_REACHABILITY, RelationKind.CONTRADICTS, tag="blue")]
    result = run(relations)
    assert result.state is ClaimState.NOT_REACHABLE and result.deciding_row is DecidingRow.DIRECT_CONTRADICTION
    status = {s.predicate: s for s in result.predicates}[Predicate.SOURCE_TO_SINK_REACHABILITY]
    assert status.outcome is PredicateOutcome.CONTRADICTED and status.contradicting


def test_contradiction_on_configuration_is_not_exploitable_in_observed_configuration() -> None:
    relations = [*all_supported(claim=CONFIG_CLAIM),
                 rel(Predicate.CONFIGURATION_ENABLES, RelationKind.CONTRADICTS, claim=CONFIG_CLAIM)]
    result = run(relations, claim=CONFIG_CLAIM)
    assert result.state is ClaimState.NOT_EXPLOITABLE_IN_OBSERVED_CONFIGURATION


def test_configuration_predicate_is_required_only_for_configuration_scoped_claims() -> None:
    assert run(all_supported(claim=CONFIG_CLAIM), claim=CONFIG_CLAIM).state is ClaimState.SUPPORTED
    unrelated = run([*all_supported(), rel(Predicate.CONFIGURATION_ENABLES, RelationKind.CONTRADICTS)])
    assert unrelated.state is ClaimState.CONFIRMED


def test_contradiction_on_other_predicate_is_contradicted() -> None:
    relations = [rel(Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.CONTRADICTS, tag="blue")]
    assert run(relations).state is ClaimState.CONTRADICTED


def test_reachability_precedes_other_contradictions() -> None:
    relations = [rel(Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.CONTRADICTS),
                 rel(Predicate.SOURCE_TO_SINK_REACHABILITY, RelationKind.CONTRADICTS)]
    assert run(relations).state is ClaimState.NOT_REACHABLE


def test_both_direct_conflict_is_insufficient_evidence_with_gap() -> None:
    relations = [*all_supported(), rel(Predicate.SOURCE_TO_SINK_REACHABILITY, RelationKind.CONTRADICTS, tag="blue")]
    result = run(relations)
    assert result.state is ClaimState.INSUFFICIENT_EVIDENCE
    assert result.deciding_row is DecidingRow.UNRESOLVED_CONTRADICTION
    assert [(g.gap_class, g.predicate, g.reason) for g in result.gaps] == [
        (GapClass.EVIDENCE_GAP, Predicate.SOURCE_TO_SINK_REACHABILITY, "unresolved_contradiction")]


def test_incomplete_evidence_never_satisfies() -> None:
    result = run(all_supported(complete=False))
    assert result.state is ClaimState.INSUFFICIENT_EVIDENCE and result.counted_relation_ids == ()
    contra = run([*all_supported(), rel(Predicate.SECURITY_IMPACT, RelationKind.CONTRADICTS, complete=False)])
    assert contra.state is ClaimState.CONFIRMED


def test_tool_observation_mapped_relation_counts_and_qualifies_do_not() -> None:
    mapped = all_supported(admissibility=Admissibility.DIRECT_FOR_MAPPED_PREDICATE, entity_kind="tool_observation")
    assert run(mapped).state is ClaimState.CONFIRMED
    qualifies = all_supported(kind=RelationKind.QUALIFIES)
    assert run(qualifies).state is ClaimState.INSUFFICIENT_EVIDENCE


def test_duplicate_and_scope_rows_win_first() -> None:
    duplicate = run(all_supported(), existing={CLAIM.claim_id})
    assert duplicate.state is ClaimState.DUPLICATE and duplicate.duplicate_of == CLAIM.claim_id
    out = run(all_supported(), scope={"asr:symbol:" + "0" * 64})
    assert out.state is ClaimState.OUT_OF_SCOPE
    in_scope = run(all_supported(), scope={ENTITY, "asr:symbol:" + "0" * 64})
    assert in_scope.state is ClaimState.CONFIRMED


def test_failed_verifier_links_worker_gap() -> None:
    worker_gap = make_gap(GapClass.WORKER_GAP, "cell-verifier", "provider timeout")
    result = run([], independent=False, verifier_gap=worker_gap)
    assert result.state is ClaimState.INSUFFICIENT_EVIDENCE
    assert result.deciding_row is DecidingRow.INSUFFICIENT_EVIDENCE
    assert worker_gap.gap_id in result.gap_ids and result.linked_gap_ids == (worker_gap.gap_id,)


def test_relations_for_other_claims_are_rejected() -> None:
    with pytest.raises(ValueError):
        run([rel(Predicate.SECURITY_IMPACT, claim=CONFIG_CLAIM)])


def test_identity_is_order_independent_and_records_prior_state() -> None:
    relations = [*all_supported(), rel(Predicate.SECURITY_IMPACT, tag="second")]
    first = run(relations)
    second = run(list(reversed(relations)) + relations)
    assert first == second
    prior = run(relations, prior_state=ClaimState.SUPPORTED)
    assert prior.prior_state is ClaimState.SUPPORTED and prior.adjudication_id != first.adjudication_id


def test_adding_indirect_relations_never_changes_state_property() -> None:
    hypothesis = pytest.importorskip("hypothesis")
    st = pytest.importorskip("hypothesis.strategies")

    relation = st.builds(
        lambda predicate, kind, admissibility, complete, tag: rel(
            predicate, kind, admissibility=admissibility, complete=complete, tag=tag),
        st.sampled_from(list(Predicate)), st.sampled_from([RelationKind.SUPPORTS, RelationKind.CONTRADICTS]),
        st.sampled_from(list(Admissibility)), st.booleans(), st.text(max_size=4))
    indirect = st.builds(
        lambda predicate, kind, complete, tag: rel(
            predicate, kind, admissibility=Admissibility.INDIRECT, complete=complete, tag="i" + tag,
            entity_kind="hotspot"),
        st.sampled_from(list(Predicate)), st.sampled_from(list(RelationKind)), st.booleans(), st.text(max_size=4))

    @hypothesis.settings(max_examples=200, deadline=None)
    @hypothesis.given(st.lists(relation, max_size=12), st.lists(indirect, max_size=12), st.booleans())
    def check(base, extra, independent):
        before = run(base, independent=independent)
        after = run([*extra, *base, *extra], independent=independent)
        assert after.state is before.state
        assert after.predicates == before.predicates
        assert after.adjudication_id == before.adjudication_id

    check()
