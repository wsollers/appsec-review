from __future__ import annotations

from dataclasses import replace

import pytest

from appsec_review.review.models import ClaimState, Gap, GapClass
from appsec_review.review.scoring import (
    INTERFACE_VERSION, ApplicationRiskMatrixProvider, ProviderRegistry, ScoreProviderResult, ScoreRequest,
    ScoringProvider, default_registry,
)
from appsec_review.review.scoring.application_matrix import DEFAULT_MATRIX

TABLE = {"CWE-120": "high", "CWE-78": "critical", "CWE-200": "medium"}
REQUEST = ScoreRequest(
    claim_id="claim-" + "1" * 64, adjudication_id="adjudication-" + "2" * 64, claim_state=ClaimState.CONFIRMED,
    weakness_cwe="CWE-120", evidence_relation_ids=("evrel-b", "evrel-a"), environment_sha256=None,
    policy_sha256="3" * 64, scorer_actor_id="actor-independent-scorer")


def test_provider_conforms_to_protocol_and_registry_is_closed() -> None:
    provider = ApplicationRiskMatrixProvider(TABLE)
    assert isinstance(provider, ScoringProvider)
    assert provider.interface_version == INTERFACE_VERSION
    registry = default_registry(TABLE)
    assert registry.ids() == ("application_risk_matrix",)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(ApplicationRiskMatrixProvider(TABLE))
    with pytest.raises(KeyError):
        registry.get("cvss_v4")
    with pytest.raises(TypeError):
        ProviderRegistry((object(),))  # type: ignore[arg-type]
    assert provider.input_schema() and provider.output_schema()["bands"]


@pytest.mark.parametrize(("state", "cwe", "band", "confidence"), [
    (ClaimState.CONFIRMED, "CWE-120", "high", "high"),
    (ClaimState.SUPPORTED, "CWE-120", "medium", "medium"),
    (ClaimState.CONFIRMED, "CWE-78", "critical", "high"),
    (ClaimState.SUPPORTED, "CWE-78", "high", "medium"),
    (ClaimState.SUPPORTED, "CWE-200", "low", "medium"),
])
def test_matrix_lookup(state, cwe, band, confidence) -> None:
    result = ApplicationRiskMatrixProvider(TABLE).score(replace(REQUEST, claim_state=state, weakness_cwe=cwe))
    assert result.technical_severity.rating == band
    assert result.technical_severity.scale == "application_risk_matrix/1"
    assert result.exploitability_confidence.rating == confidence
    assert result.exploitability_confidence.scale == "evidence_confidence/1"
    assert result.native["cell"] == [TABLE[cwe], confidence] and result.native["band"] == band
    assert result.environmental_business_impact is None and result.remediation_priority is None
    assert "impact_class" not in result.missing_factors


def test_matrix_is_deterministic_and_fingerprints_inputs() -> None:
    first = ApplicationRiskMatrixProvider(TABLE).score(REQUEST)
    again = ApplicationRiskMatrixProvider(dict(reversed(list(TABLE.items())))).score(
        replace(REQUEST, evidence_relation_ids=("evrel-a", "evrel-b", "evrel-a")))
    assert first == again
    assert first.score_id.startswith("score-") and len(first.input_fingerprint) == 64
    assert first.evidence_relations == ("evrel-a", "evrel-b")
    changed_input = ApplicationRiskMatrixProvider(TABLE).score(replace(REQUEST, environment_sha256="4" * 64))
    assert changed_input.input_fingerprint != first.input_fingerprint and changed_input.score_id != first.score_id
    changed_config = ApplicationRiskMatrixProvider({**TABLE, "CWE-787": "high"}).score(REQUEST)
    assert changed_config.provider_config_sha256 != first.provider_config_sha256
    assert changed_config.score_id != first.score_id


def test_unmapped_or_missing_cwe_gives_null_rating_and_missing_factors() -> None:
    provider = ApplicationRiskMatrixProvider(TABLE)
    unmapped = provider.score(replace(REQUEST, weakness_cwe="CWE-787"))
    assert unmapped.technical_severity.rating is None and unmapped.native["cell"] is None
    assert "impact_class" in unmapped.missing_factors
    assert unmapped.exploitability_confidence.rating == "high"
    absent = provider.score(replace(REQUEST, weakness_cwe=None))
    assert absent.technical_severity.rating is None and "weakness_cwe" in absent.missing_factors
    for result in (unmapped, absent):
        assert {"environmental_business_impact", "remediation_priority"} <= set(result.missing_factors)


@pytest.mark.parametrize("state", sorted(set(ClaimState) - {ClaimState.CONFIRMED, ClaimState.SUPPORTED}))
def test_only_confirmed_and_supported_claims_are_scored(state: ClaimState) -> None:
    registry = default_registry(TABLE)
    gap = registry.score("application_risk_matrix", replace(REQUEST, claim_state=state))
    assert isinstance(gap, Gap) and gap.gap_class is GapClass.SCORE_GAP and gap.subject_id == REQUEST.claim_id
    with pytest.raises(ValueError):
        ApplicationRiskMatrixProvider(TABLE).score(replace(REQUEST, claim_state=state))


def test_registry_scores_and_reports_unavailable_provider_as_gap() -> None:
    registry = default_registry(TABLE, implementation="application_risk_matrix/1")
    assert isinstance(registry.score("application_risk_matrix", REQUEST), ScoreProviderResult)
    missing = registry.score("cvss_v4", REQUEST)
    assert isinstance(missing, Gap) and missing.gap_class is GapClass.SCORE_GAP


def test_invalid_configuration_is_rejected() -> None:
    with pytest.raises(ValueError):
        ApplicationRiskMatrixProvider({"CWE-120": "catastrophic"})
    with pytest.raises(ValueError):
        ApplicationRiskMatrixProvider({"buffer overflow": "high"})
    with pytest.raises(ValueError, match="conflicting"):
        ApplicationRiskMatrixProvider({"CWE-120": "high", "cwe-0120": "low"})
    with pytest.raises(ValueError):
        ApplicationRiskMatrixProvider(TABLE, {k: v for k, v in DEFAULT_MATRIX.items() if k != "low"})
