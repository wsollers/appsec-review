"""Focused T-173 unit tests for job_finding_adjudication."""
from __future__ import annotations

from pathlib import Path
from types import MappingProxyType, SimpleNamespace

from appsec_review.jobs.job_finding_adjudication import (
    FindingAdjudicationSettings,
    JOB_ID,
    build_job,
    load_adjudication_querying_skill,
    resolve_finding_chain_severity,
)
from appsec_review.observability import EventLog
from appsec_review.runtime.job import JobContext

ROOT = Path(__file__).resolve().parents[3]


def test_finding_adjudication_preserves_standalone_and_chain_elevated_severity(tmp_path: Path) -> None:
    job = build_job()
    assert job.strict_gaps is True
    skill = load_adjudication_querying_skill(ROOT)
    assert skill.name == "evidence-and-graph-querying"
    assert "syntactic_fallback" in skill.body

    chains = [
        {
            "chain_id": "chain-alpha",
            "status": "confirmed",
            "step_claim_ids": ["claim-med", "claim-crit"],
            "composed_severity": "high",
            "chain_boundary_crossings": [
                {
                    "edge_index": 0,
                    "from_claim_id": "claim-med",
                    "to_claim_id": "claim-crit",
                    "crossing_kind": "trust_boundary",
                    "from_scope": "edge",
                    "to_scope": "core",
                }
            ],
        }
    ]
    cfg = FindingAdjudicationSettings.from_mapping({})

    med_res = resolve_finding_chain_severity("claim-med", standalone_severity="medium", chain_records=chains, settings=cfg)
    assert med_res.standalone_severity == "medium"
    assert med_res.composed_severity == "high"
    assert med_res.effective_severity == "high"
    assert med_res.chain_elevated is True
    assert med_res.attack_chain_ids == ("chain-alpha",)
    assert len(med_res.chain_boundary_crossings) == 1

    # Standalone critical is NEVER downgraded by a 'high' chain
    crit_res = resolve_finding_chain_severity("claim-crit", standalone_severity="critical", chain_records=chains, settings=cfg)
    assert crit_res.standalone_severity == "critical"
    assert crit_res.composed_severity == "critical"
    assert crit_res.effective_severity == "critical"
    assert crit_res.chain_elevated is False

    # Execute standalone job unit cleanly
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
        config=SimpleNamespace(
            settings={
                "findings": [
                    {"claim_id": "claim-med", "standalone_severity": "medium"},
                    {"claim_id": "claim-crit", "standalone_severity": "critical"},
                ],
                "chains": chains,
            }
        ),
        events=EventLog(attempt_root / "events.jsonl"),
        evidence_target_snapshot="snap-1",
        source_fingerprint="fp-1",
        input_manifest_sha256="scope-1",
        upstream_handoffs=MappingProxyType({}),
    )
    out = job.execute(ctx)
    assert not out["failed_units"], out
    unit_res = out["outputs"]["adjudicate.preserve_chain_severity"]
    assert unit_res["terminal_status"] == "SUCCEEDED"
    assert unit_res["chain_elevated_count"] == 1
