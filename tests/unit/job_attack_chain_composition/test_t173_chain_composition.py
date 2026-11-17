"""Focused T-173 unit tests for job_attack_chain_composition."""
from __future__ import annotations

from pathlib import Path
from types import MappingProxyType, SimpleNamespace

from appsec_review.jobs.job_attack_chain_composition import (
    AttackChainCompositionSettings,
    ChainStepFinding,
    DEFAULT_MAX_CHAIN_STEPS,
    JOB_ID,
    build_job,
    compose_multi_step_chains,
    load_chain_querying_skill,
)
from appsec_review.observability import EventLog
from appsec_review.runtime.job import JobContext

ROOT = Path(__file__).resolve().parents[3]


def test_attack_chain_settings_contract_and_runtime_skill() -> None:
    settings = AttackChainCompositionSettings.from_mapping({})
    assert settings.max_steps == 6
    assert DEFAULT_MAX_CHAIN_STEPS == 6
    assert settings.admit_medium_cross_boundary is True
    assert settings.admit_medium_cross_unit is True
    assert settings.thinking_min_output_tokens == 4096
    job = build_job()
    assert job.strict_gaps is True
    skill = load_chain_querying_skill(ROOT)
    assert skill.name == "evidence-and-graph-querying"
    assert "codeql_semantic" in skill.body


def test_medium_plus_medium_cross_boundary_elevates_to_critical() -> None:
    findings = [
        ChainStepFinding(
            claim_id="claim-ssrf",
            security_predicate="ssrf",
            standalone_severity="medium",
            unit_key="edge_proxy",
            trust_boundary="internet_edge",
        ),
        ChainStepFinding(
            claim_id="claim-rce",
            security_predicate="command_injection",
            standalone_severity="medium",
            weakness_cwe="CWE-78",
            unit_key="internal_worker",
            trust_boundary="internal_control_plane",
        ),
    ]
    edges = [{"from_claim_id": "claim-ssrf", "to_claim_id": "claim-rce", "satisfied_dimensions": ["trust_boundary"]}]
    report = compose_multi_step_chains(findings, edges)
    assert len(report.chains) == 1
    chain = report.chains[0]
    assert chain.step_claim_ids == ("claim-ssrf", "claim-rce")
    assert chain.composed_severity == "critical"
    assert chain.elevated is True
    assert len(chain.chain_boundary_crossings) >= 1
    assert report.telemetry["medium_to_high_or_critical_chains"] == 1


def test_same_unit_same_boundary_low_noise_rejected_and_six_step_job_executes(tmp_path: Path) -> None:
    # Low + medium without boundary crossing is rejected
    noisy = [
        ChainStepFinding(claim_id="c-low", security_predicate="info_disclosure", standalone_severity="low", unit_key="u1", trust_boundary="tb1"),
        ChainStepFinding(claim_id="c-med", security_predicate="open_redirect", standalone_severity="medium", unit_key="u1", trust_boundary="tb1"),
    ]
    empty_report = compose_multi_step_chains(noisy, [{"from_claim_id": "c-low", "to_claim_id": "c-med"}])
    assert empty_report.chains == ()

    # 6-step medium cross-boundary chain executes through build_job()
    raw_findings = []
    raw_edges = []
    for i in range(6):
        cid = f"claim-{i}"
        raw_findings.append({
            "claim_id": cid,
            "security_predicate": "privilege_escalation" if i == 5 else "authz_bypass",
            "standalone_severity": "medium",
            "unit_key": f"service-{i}",
            "trust_boundary": f"zone-{i}",
        })
        if i > 0:
            raw_edges.append({"from_claim_id": f"claim-{i - 1}", "to_claim_id": cid})

    job = build_job()
    run_root = tmp_path / "run"
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / "att-1"
    metadata_root = run_root / "metadata"
    attempt_root.mkdir(parents=True, exist_ok=True)
    metadata_root.mkdir(parents=True, exist_ok=True)
    ctx = JobContext(
        run_id="run-1",
        attempt_id="att-1",
        trigger="unit-test",
        repository_root=ROOT,
        run_root=run_root,
        attempt_root=attempt_root,
        metadata_root=metadata_root,
        orchestration={},
        config=SimpleNamespace(settings={"max_steps": 6, "findings": raw_findings, "candidate_edges": raw_edges}),
        events=EventLog(attempt_root / "events.jsonl"),
        evidence_target_snapshot="snap-1",
        source_fingerprint="fp-1",
        input_manifest_sha256="scope-1",
        upstream_handoffs=MappingProxyType({}),
    )
    res = job.execute(ctx)
    assert not res["failed_units"], res
    unit_out = res["outputs"]["compose.multi_step_chains"]
    assert unit_out["terminal_status"] == "SUCCEEDED"
    assert unit_out["telemetry"]["max_chain_length_observed"] == 6
    assert unit_out["chains"][0]["composed_severity"] == "critical"
