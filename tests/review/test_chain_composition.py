from dataclasses import replace
from pathlib import Path

import pytest

from appsec_review.config.attack_chains import AttackChainSettings
from appsec_review.jobs.job_inference_security_review.chains import effective_max_links
from appsec_review.review.chain_composition import (
    AttackChainCompositionSettings, ChainStepFinding, compose_multi_step_chains,
    evaluate_chain_elevation, load_chain_querying_skill,
)

ROOT = Path(__file__).resolve().parents[2]


def test_medium_cross_boundary_chain_retains_its_elevation():
    steps = [
        ChainStepFinding("ssrf", "ssrf", "medium", unit_key="edge", trust_boundary="public"),
        ChainStepFinding("rce", "command_injection", "medium", "CWE-78",
                         unit_key="worker", trust_boundary="internal"),
    ]
    report = compose_multi_step_chains(steps, [
        {"from_claim_id": "ssrf", "to_claim_id": "rce", "satisfied_dimensions": ["trust_boundary"]}])
    chain, = report.chains
    assert chain.step_claim_ids == ("ssrf", "rce")
    assert chain.composed_severity == "critical"
    assert chain.elevated and chain.chain_boundary_crossings
    assert report.telemetry["medium_to_high_or_critical_chains"] == 1


@pytest.mark.parametrize("severities", [(None, None), ("high", None), (None, "medium")])
def test_missing_component_severity_cannot_be_elevated(severities):
    steps = [
        ChainStepFinding("a", "ssrf", severities[0], unit_key="edge", trust_boundary="public"),
        ChainStepFinding("b", "command_injection", severities[1], unit_key="worker", trust_boundary="internal"),
    ]
    severity, _ = evaluate_chain_elevation(steps)
    assert severity is None
    assert not compose_multi_step_chains(steps, [{"from_claim_id": "a", "to_claim_id": "b"}]).chains


def test_same_boundary_low_noise_is_rejected():
    steps = [ChainStepFinding("a", "info_disclosure", "low", unit_key="u", trust_boundary="t"),
             ChainStepFinding("b", "open_redirect", "medium", unit_key="u", trust_boundary="t")]
    assert not compose_multi_step_chains(steps, [{"from_claim_id": "a", "to_claim_id": "b"}]).chains


def test_explicit_four_step_limit_is_preserved_and_six_steps_are_supported():
    steps = [ChainStepFinding(f"c{i}", "authz_bypass", "medium",
                              unit_key=f"service-{i}", trust_boundary=f"zone-{i}") for i in range(6)]
    edges = [{"from_claim_id": f"c{i}", "to_claim_id": f"c{i + 1}"} for i in range(5)]
    assert effective_max_links(replace(AttackChainSettings(), max_links=4)) == 4
    four = compose_multi_step_chains(steps, edges, settings=AttackChainCompositionSettings(max_steps=4))
    six = compose_multi_step_chains(steps, edges, settings=AttackChainCompositionSettings(max_steps=6))
    assert four.telemetry["max_chain_length_observed"] == 4
    assert six.telemetry["max_chain_length_observed"] == 6
    assert six.chains[0].composed_severity == "critical"


def test_chain_guidance_uses_the_actual_job_authority():
    skill = load_chain_querying_skill(ROOT, job_id="job_inference_security_review")
    assert skill.name == "evidence-and-graph-querying"
    from appsec_review.guidance.fragments import GuidanceError
    with pytest.raises(GuidanceError):
        load_chain_querying_skill(ROOT, job_id="job_attack_chain_composition")
