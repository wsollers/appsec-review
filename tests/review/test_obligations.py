from __future__ import annotations

import pytest

from appsec_review.review import obligations
from appsec_review.review.models import Predicate
from appsec_review.review.obligations import (
    ALWAYS_REQUIRED, CONFIGURATION_SCOPED, Precondition, parse_precondition, required_predicates,
)


def test_every_claim_requires_the_five_base_predicates() -> None:
    assert required_predicates([]) == frozenset(ALWAYS_REQUIRED)
    assert required_predicates([Precondition.ATTACKER_CONTROLS_REQUEST_FIELD]) == frozenset(ALWAYS_REQUIRED)
    assert Predicate.CONFIGURATION_ENABLES not in ALWAYS_REQUIRED
    assert set(ALWAYS_REQUIRED) | {Predicate.CONFIGURATION_ENABLES} == set(Predicate)


@pytest.mark.parametrize("precondition", sorted(CONFIGURATION_SCOPED))
def test_configuration_scoped_preconditions_require_configuration_enables(precondition: Precondition) -> None:
    required = required_predicates(["attacker_is_unauthenticated", precondition.value])
    assert required == frozenset(ALWAYS_REQUIRED) | {Predicate.CONFIGURATION_ENABLES}


def test_precondition_vocabulary_is_closed() -> None:
    assert parse_precondition("  Feature_Flag_Enabled ") is Precondition.FEATURE_FLAG_ENABLED
    with pytest.raises(ValueError, match="preconditions/1"):
        parse_precondition("attacker_is_very_clever")
    with pytest.raises(ValueError):
        required_predicates(["attacker_controls_request_field", "made_up"])
    assert CONFIGURATION_SCOPED < set(Precondition)


def test_policy_hash_is_stable_and_covers_rule_tables(monkeypatch: pytest.MonkeyPatch) -> None:
    assert len(obligations.POLICY_SHA256) == 64
    assert obligations._policy_document() == obligations._policy_document()
    assert obligations.POLICY_SHA256 == obligations.sha256_hex(obligations._policy_document())
    monkeypatch.setattr(obligations, "CONFIGURATION_SCOPED", frozenset())
    assert obligations.sha256_hex(obligations._policy_document()) != obligations.POLICY_SHA256
