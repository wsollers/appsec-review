"""Manual full-fixture review: requires prepared offline recordings and tool images."""
from dataclasses import replace
import os
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.runtime import GraphRunner, JobRunner, active_job_ids
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.repair import admit_repair, plan_repair


def test_full_offline_fixture_review_preserves_predecessors_and_gaps(monkeypatch):
    from appsec_review.cli import GRAPH_JOB_IDS, POST_INDEX_JOB_IDS
    from appsec_review.inference import recording
    import appsec_review.inference as inference
    required = ("APPSEC_REPAIR_ACCEPTANCE_CONFIG", "APPSEC_REPAIR_ACCEPTANCE_TARGET",
                "APPSEC_REVIEW_MODEL_REPLAY_DIR")
    missing = [name for name in required if not os.environ.get(name)]
    assert not missing, f"manual acceptance prerequisites are missing: {missing}"
    monkeypatch.setenv(recording.MODE_ENVIRONMENT, "replay")
    assert Path(os.environ[recording.REPLAY_ENVIRONMENT]).is_dir(), "offline recording directory is absent"
    def no_live_inference(*args, **kwargs):
        pytest.fail("acceptance must never call a live model")
    def recorded_availability(provider, names, *, timeout_seconds):
        return {"models": {name: {"available": True, "detail": "offline fixture replay"} for name in names}}
    monkeypatch.setattr(inference, "infer", no_live_inference)
    monkeypatch.setattr(inference, "check_models", recorded_availability)
    config = load_config(Path(os.environ[required[0]]))
    target = Path(os.environ[required[1]]).resolve()
    assert config.runtime.runs_dir.resolve() != (config.runtime.repository_root / "runs").resolve(), (
        "manual acceptance requires an isolated runs_dir, never production runs")
    registry = builtin_registry()
    ids = active_job_ids(config, (*GRAPH_JOB_IDS, *POST_INDEX_JOB_IDS))
    jobs = [registry.build(job_id) for job_id in ids]
    assert "job_final_report_publication" in ids
    fingerprint = source_fingerprint(target)
    runner = JobRunner(config)
    from datetime import datetime, timezone
    run_id, run_root = runner.runs.create(datetime.now(timezone.utc))
    selected = next(job for job in jobs if job.job_id == "job_document_issue_analysis")
    def failure(context):
        raise RuntimeError("acceptance injected failure")
    broken = replace(selected, units=(replace(selected.units[0], handler=failure), *selected.units[1:]))
    failing_jobs = [broken if job.job_id == selected.job_id else job for job in jobs]
    with pytest.raises(RuntimeError, match="acceptance injected failure"):
        GraphRunner(config, failing_jobs).run(target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    original = (run_root / "data/configuration/resolved.json").read_bytes()
    # Reset only the test's recording cursor; no live-model fallback is permitted.
    with recording._lock:
        recording._replayed.clear()
    plan = plan_repair(config, run_root, jobs, fingerprint, target_root=target)
    assert plan["admissible"], plan["refusals"]
    assert any(item["action"] == "REUSE" for item in plan["decisions"])
    assert any(item["job_id"] == selected.job_id and item["action"] == "RUN" for item in plan["decisions"])
    admit_repair(config, run_root, jobs, plan, target_root=target)
    result = GraphRunner(config, jobs).run(target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert result["status"] == "COMPLETED_WITH_GAPS", "the fixture must contain a deliberate retained coverage gap"
    assert result["jobs"]["job_review_intake"]["decision"]["action"] == "REUSE"
    assert (run_root / "data/configuration/resolved.json").read_bytes() == original
