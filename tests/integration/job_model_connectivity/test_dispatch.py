"""Pre-walk suite pending replacement: connectivity dispatch and downstream reuse.

Moved verbatim from the mixed model-preflight suite; execute only with explicit integration
authorization. Shared intake/provider fixtures remain owned by that suite.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review import inference
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_model_connectivity import build_job as build_connectivity
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.runtime import GraphRunner
from appsec_review.runtime.registry import builtin_registry
from tests.test_model_preflight import _fixture, _serving


def test_registry_wires_the_real_check_into_the_first_job_of_a_review(monkeypatch, tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    seen: list[str] = []
    monkeypatch.setitem(inference.MODEL_CHECKS, "claude-cli", lambda names, *, timeout_seconds: (
        seen.extend(names) or {"method": "probe", "listed": None, "models": {
            name: {"available": True, "detail": "answered"} for name in names}}))
    gate = builtin_registry().build("job_model_connectivity")
    assert gate.always_execute is True and gate.propagate_handoff is False
    outcome = GraphRunner(config, [gate]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    assert outcome["status"] == "SUCCEEDED" and seen == ["claude-haiku-5-5"]


def test_connectivity_gate_runs_again_without_invalidating_reusable_downstream_work(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    from tests.release_support import write_release
    write_release(tmp_path, ("job_model_connectivity", "job_review_intake"))
    check, calls = _serving("claude-haiku-5-5")
    jobs = [build_connectivity(check_models=check), build_intake()]
    first = GraphRunner(config, jobs).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    second = GraphRunner(config, jobs).run(
        run_id=first["run_id"], target_root=target, source_fingerprint=source_fingerprint(target))
    assert [item["action"] for item in second["decisions"]] == ["RUN", "REUSE"]
    assert len(calls) == 2
    attempts = config.runtime.runs_dir / first["run_id"] / "data/jobs/job_model_connectivity/attempts"
    assert sorted(path.name for path in attempts.iterdir()) == ["attempt_0001", "attempt_0002"]


def test_connectivity_failure_stops_before_review_intake(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    check, _calls = _serving()
    with pytest.raises(RuntimeError, match="connectivity.verify_models"):
        GraphRunner(config, [build_connectivity(check_models=check), build_intake()]).run(
            target_root=target, source_fingerprint=source_fingerprint(target))
    run_id = next(path.name for path in config.runtime.runs_dir.iterdir() if path.name != "metadata")
    assert not (config.runtime.runs_dir / run_id / "data/jobs/job_review_intake").exists()
