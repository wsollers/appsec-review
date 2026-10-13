from __future__ import annotations

import pytest

from appsec_review.review.identity import make_id
from appsec_review.review.independence import ActorRecord, model_distinct, provider_distinct, verify_independence
from appsec_review.review.models import Admissibility, EvidenceRelation, GapClass, Predicate, RelationKind
from appsec_review.review.obligations import ALWAYS_REQUIRED

CLAIM = "claim-" + "1" * 64
RECEIPT = "a" * 64
RED = ActorRecord("actor-red", "claude-cli", "opus", "conv-red", cache_key="cache-red")
BLUE = ActorRecord("actor-blue", "claude-cli", "opus", "conv-blue", cache_key="cache-blue")
VERIFIER = ActorRecord("actor-verifier", "claude-cli", "opus", "conv-verifier", cache_key="cache-verifier")
REQUEST = b'{"claim": "normalized claim", "evidence": ["evrel-original"]}'
MARKERS = ["red narrative: the copy overflows", "blue disposition: guarded"]


def rel(predicate: Predicate, *, receipt: str | None = RECEIPT, kind: RelationKind = RelationKind.SUPPORTS,
        admissibility: Admissibility = Admissibility.DIRECT, complete: bool = True,
        claim: str = CLAIM) -> EvidenceRelation:
    rid = make_id("evidence_relation", 1, {"p": predicate.value, "r": receipt, "k": kind.value,
                                           "a": admissibility.value, "c": complete})
    return EvidenceRelation(rid, claim, predicate, kind, "asr:symbol:" + "b" * 64, "symbol", admissibility,
                            "analysis/default", "0" * 64, "src/a.c:1-1", complete, "cell-verifier", receipt)


def check(verifier=VERIFIER, others=(RED, BLUE), request=REQUEST, relations=None, receipts=(RECEIPT,), **kwargs):
    relations = [rel(p) for p in ALWAYS_REQUIRED] if relations is None else relations
    return verify_independence(verifier, others, request, MARKERS, relations, ALWAYS_REQUIRED, receipts,
                               claim_id=CLAIM, **kwargs)


def reasons(result) -> set[str]:
    independent, gaps = result
    assert not independent and gaps
    assert all(gap.gap_class is GapClass.INDEPENDENCE_GAP and gap.subject_id == CLAIM for gap in gaps)
    return {gap.reason for gap in gaps}


def test_blind_fresh_verifier_with_own_evidence_is_independent() -> None:
    assert check() == (True, [])


def test_same_actor_is_not_independent() -> None:
    same = ActorRecord("actor-red", "claude-cli", "opus", "conv-new")
    assert "verifier_actor_not_distinct" in reasons(check(verifier=same))


def test_prior_response_shared_conversation_or_cache_is_not_independent() -> None:
    assert reasons(check(verifier=ActorRecord("actor-v", "p", "m", "conv-v", prior_response_sha256="x"))) == {
        "verifier_conversation_has_prior_response"}
    assert reasons(check(verifier=ActorRecord("actor-v", "p", "m", "conv-red"))) == {
        "verifier_conversation_not_fresh"}
    assert reasons(check(verifier=ActorRecord("actor-v", "p", "m", "conv-v", cache_key="cache-blue"))) == {
        "verifier_shares_cache_entry"}


@pytest.mark.parametrize("leak", [MARKERS[0].encode(), b"actor-blue", MARKERS[1].encode()])
def test_request_bytes_with_narrative_or_actor_ids_are_not_independent(leak: bytes) -> None:
    assert reasons(check(request=REQUEST + leak)) == {"verifier_request_contains_forbidden_marker"}


def test_each_required_predicate_needs_support_from_verifier_receipts() -> None:
    relations = [rel(p) for p in ALWAYS_REQUIRED if p is not Predicate.SECURITY_IMPACT]
    relations += [
        rel(Predicate.SECURITY_IMPACT, receipt="c" * 64),                       # red's receipt
        rel(Predicate.SECURITY_IMPACT, receipt=None),
        rel(Predicate.SECURITY_IMPACT, admissibility=Admissibility.INDIRECT),
        rel(Predicate.SECURITY_IMPACT, complete=False),
        rel(Predicate.SECURITY_IMPACT, kind=RelationKind.CONTRADICTS),
        rel(Predicate.SECURITY_IMPACT, claim="claim-" + "9" * 64),
    ]
    independent, gaps = check(relations=relations)
    assert not independent
    assert [(gap.reason, gap.predicate) for gap in gaps] == [
        ("verifier_lacks_independent_support", Predicate.SECURITY_IMPACT)]


def test_provider_distinctness_recorded_but_not_required_by_default() -> None:
    assert provider_distinct(VERIFIER, [RED, BLUE]) is False
    assert check()[0] is True
    assert reasons(check(require_distinct_provider=True)) == {"verifier_provider_not_distinct"}
    other = ActorRecord("actor-v2", "anthropic-api", "opus", "conv-v2")
    assert provider_distinct(other, [RED, BLUE]) and check(verifier=other, require_distinct_provider=True)[0]


def test_verifier_model_distinctness_is_recorded_and_never_gates_independence() -> None:
    """Decision 2: (provider, model) must differ from every red cell's; R6 independence is unchanged."""
    assert model_distinct(VERIFIER, [RED]) is False and check()[0] is True
    other_model = ActorRecord("actor-v2", "claude-cli", "sonnet", "conv-v2")
    other_provider = ActorRecord("actor-v3", "anthropic-api", "opus", "conv-v3")
    assert model_distinct(other_model, [RED]) and model_distinct(other_provider, [RED])
    # One red cell on the verifier's model is enough to make it not distinct.
    assert not model_distinct(other_model, [RED, ActorRecord("actor-red2", "claude-cli", "sonnet", "conv-r2")])
    assert model_distinct(other_model, [])            # no red cell: nothing to correlate with
    assert check(verifier=other_model)[0] is True


def test_empty_marker_is_rejected() -> None:
    with pytest.raises(ValueError):
        verify_independence(VERIFIER, [], REQUEST, [""], [], [], [], claim_id=CLAIM)
