from __future__ import annotations

import pytest

from appsec_review.retrieval.model import EntityKind, LogicalIdentity
from appsec_review.review.claims import (
    claim_identity, normalize_claim, normalize_cwe, possible_duplicates,
)
from appsec_review.review.models import GapClass, Lane

SNAP = "snapshot"
SPAN = LogicalIdentity.derive(EntityKind.SOURCE_SPAN, SNAP, {"n": "span"}).value
SPAN2 = LogicalIdentity.derive(EntityKind.SOURCE_SPAN, SNAP, {"n": "span2"}).value
SYMBOL = LogicalIdentity.derive(EntityKind.SYMBOL, SNAP, {"n": "copy"}).value
OTHER = LogicalIdentity.derive(EntityKind.SYMBOL, SNAP, {"n": "other"}).value
ACCEPTED = frozenset({"CWE-120", "CWE-787", "CWE-78"})


def _claim(**overrides):
    values = dict(lane=Lane.LEAD, package_id="package-1", affected_entities=[SPAN, OTHER],
                  weakness_cwe="CWE-120", security_predicate="unbounded_copy",
                  preconditions=["attacker_controls_request_field"],
                  statement="A request field reaches strcpy.", accepted_cwe_ids=ACCEPTED)
    values.update(overrides)
    return normalize_claim(**values)


def test_identity_is_stable_under_ordering_whitespace_and_prose() -> None:
    base = _claim().claim
    variant = _claim(
        lane=Lane.HUNT, package_id="package-9", affected_entities=[f" {OTHER} ", SPAN, SPAN],
        weakness_cwe=" cwe-120 ", security_predicate="  Unbounded-Copy ",
        preconditions=[" Attacker_Controls_Request_Field ", "attacker_controls_request_field"],
        statement="  Totally   different\nprose. ", origin_cell_ids=["cell-b", "cell-a"]).claim
    assert variant.claim_id == base.claim_id
    assert variant.affected_entities == tuple(sorted({SPAN, OTHER}))
    assert variant.statement == "Totally different prose."
    assert variant.origin_cell_ids == ("cell-a", "cell-b")
    assert base.claim_id == claim_identity(base.affected_entities, "CWE-120", "unbounded_copy",
                                           ("attacker_controls_request_field",))


@pytest.mark.parametrize("change", [
    {"weakness_cwe": "CWE-787"},
    {"security_predicate": "command_injection"},
    {"preconditions": ["attacker_controls_request_field", "feature_flag_enabled"]},
    {"affected_entities": [SPAN]},
])
def test_identity_changes_on_material_change(change) -> None:
    assert _claim(**change).claim.claim_id != _claim().claim.claim_id


def test_span_normalizes_to_enclosing_symbol_when_covered() -> None:
    lookup = {SPAN: SYMBOL, SPAN2: SYMBOL}.get
    claim = _claim(affected_entities=[SPAN, SPAN2], enclosing_symbol=lookup).claim
    assert claim.affected_entities == (SYMBOL,)
    uncovered = _claim(affected_entities=[SPAN], enclosing_symbol=lambda _: None).claim
    assert uncovered.affected_entities == (SPAN,)
    with pytest.raises(ValueError, match="non-symbol"):
        _claim(affected_entities=[SPAN], enclosing_symbol=lambda _: SPAN2)


def test_unaccepted_cwe_is_dropped_with_gap() -> None:
    result = _claim(weakness_cwe="CWE-999999")
    assert result.claim.weakness_cwe is None
    assert [gap.gap_class for gap in result.gaps] == [GapClass.EVIDENCE_GAP]
    assert result.gaps[0].subject_id == result.claim.claim_id
    assert _claim(weakness_cwe="not a cwe").claim.weakness_cwe is None
    no_cwe = _claim(weakness_cwe=None)
    assert no_cwe.claim.weakness_cwe is None and no_cwe.gaps == ()
    assert no_cwe.claim.claim_id == result.claim.claim_id
    assert normalize_cwe("120") == "CWE-120" and normalize_cwe("CWE-0120") == "CWE-120"


@pytest.mark.parametrize("bad", [
    {"preconditions": ["attacker_is_wizard"]},
    {"affected_entities": []},
    {"affected_entities": ["src/copy.c:3"]},
    {"security_predicate": "!!"},
])
def test_malformed_claims_are_rejected(bad) -> None:
    with pytest.raises(ValueError):
        _claim(**bad)


def test_possible_duplicates_nominate_same_entity_different_cwe() -> None:
    a = _claim(affected_entities=[SYMBOL]).claim
    b = _claim(affected_entities=[SYMBOL], weakness_cwe="CWE-787").claim
    same_cwe = _claim(affected_entities=[SYMBOL], security_predicate="other_condition").claim
    disjoint = _claim(affected_entities=[OTHER], weakness_cwe="CWE-78").claim
    pairs = possible_duplicates([disjoint, b, same_cwe, a, a])
    expected = {tuple(sorted((a.claim_id, b.claim_id))), tuple(sorted((b.claim_id, same_cwe.claim_id)))}
    assert set(pairs) == expected and len(pairs) == 2
    assert all(left < right for left, right in pairs)
    assert pairs == possible_duplicates([a, same_cwe, b, disjoint])
