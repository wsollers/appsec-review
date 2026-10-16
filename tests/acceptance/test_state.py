from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.acceptance.state import StateError, StepwiseState

TOPOLOGY = {"graph": "wave1_review", "jobs": [
    {"job_id": "job_model_connectivity", "name": "model_connectivity", "dependencies": [],
     "propagate_handoff": False, "upstream_handoffs": []},
    {"job_id": "job_review_intake", "name": "review_intake", "dependencies": ["job_model_connectivity"],
     "propagate_handoff": True, "upstream_handoffs": []},
    {"job_id": "job_target_catalog", "name": "target_catalog", "dependencies": ["job_review_intake"],
     "propagate_handoff": True, "upstream_handoffs": ["job_review_intake"]},
]}


def _state() -> StepwiseState:
    return StepwiseState.create("2026-10-16-0004", target="/opt/app/targets/t", topology=TOPOLOGY)


def test_walk_moves_in_graph_order_through_check_and_accept(tmp_path: Path) -> None:
    state = _state()
    assert state.next_job()["job_id"] == "job_model_connectivity"
    with pytest.raises(StateError, match="not next"):
        state.record_launch("job_review_intake", "d0")
    state.record_launch("job_model_connectivity", "d1")
    with pytest.raises(StateError, match="no passing check"):
        state.record_accept("job_model_connectivity", corpus_tag="v1", handoff_sha256="h1")
    state.record_check("job_model_connectivity", passed=False, summary={})
    assert state.job("model_connectivity")["status"] == "failed"
    state.record_launch("job_model_connectivity", "d2")
    state.record_check("job_model_connectivity", passed=True, summary={"dagster_status": "SUCCESS"})
    with pytest.raises(StateError, match="awaits acceptance"):
        state.record_launch("job_model_connectivity", "d3")
    state.record_accept("job_model_connectivity", corpus_tag="v1", handoff_sha256="h1")
    assert state.next_job()["job_id"] == "job_review_intake"
    assert state.job("job_model_connectivity")["dagster_run_ids"] == ["d1", "d2"]
    path = StepwiseState.path_for(tmp_path, state.app_run_id)
    state.save(path)
    loaded = StepwiseState.load(path)
    assert loaded.as_dict() == state.as_dict()
    assert loaded.upstream_of("job_target_catalog") == ("job_review_intake",)


def test_corpus_tag_is_fixed_and_safe() -> None:
    state = _state()
    state.record_launch("job_model_connectivity", "d1")
    state.record_check("job_model_connectivity", passed=True, summary={})
    with pytest.raises(StateError, match="safe directory"):
        state.record_accept("job_model_connectivity", corpus_tag="../x", handoff_sha256=None)
    state.record_accept("job_model_connectivity", corpus_tag="v1", handoff_sha256=None)
    state.record_launch("job_review_intake", "d2")
    state.record_check("job_review_intake", passed=True, summary={})
    with pytest.raises(StateError, match="corpus tag v1"):
        state.validate_accept("job_review_intake", corpus_tag="v2")


def test_recheck_of_an_accepted_job_does_not_reopen_it() -> None:
    state = _state()
    state.mark_seeded("job_review_intake", corpus_tag="v1", handoffs={"job_review_intake": "h"})
    state.record_check("job_review_intake", passed=False, summary={})
    assert state.job("job_review_intake")["status"] == "accepted"
    assert state.next_job()["job_id"] == "job_target_catalog"
    assert state.accepted_handoffs() == {"job_review_intake": "h"}
