from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.inference import ModelRequest, ModelResult
from appsec_review.inference import recording
from appsec_review.inference.recording import (
    MODE_ENVIRONMENT, REPLAY_ENVIRONMENT, ModelReplayMiss, recorded, unit_scope)


def _request(root: Path, note: str = "plan") -> ModelRequest:
    return ModelRequest(
        schema="appsec-review/plan/1", persona="planner", role="build", guidance="g",
        summary={"target": f"{root}/targets/relay/src/main.cpp", "note": note},
        allowed_scanners=(), allowed_build_systems=("cmake",), allowed_components=(),
        allowed_paths=("src/main.cpp",), allowed_build_units=(), provider="anthropic-api",
        model="model", reasoning="low", max_input_tokens=10, max_output_tokens=10)


def _scope(root: Path, run_root: Path):
    return unit_scope(run_root=run_root, job_id="job_target_analysis_plan", repository_root=root,
                      target_root=root / "targets" / "relay")


@pytest.fixture(autouse=True)
def _fresh_replay_counts():
    recording._replayed.clear()
    yield
    recording._replayed.clear()


def test_a_recorded_response_replays_for_the_same_request_under_other_roots(tmp_path, monkeypatch) -> None:
    container, host = tmp_path / "opt" / "app", tmp_path / "home" / "checkout"
    for root in (container, host):
        (root / "targets" / "relay").mkdir(parents=True)
    calls: list[ModelRequest] = []

    def live(request, *, timeout_seconds):
        calls.append(request)
        return ModelResult({"steps": [len(calls)]}, input_tokens=3, raw_response="{}")

    monkeypatch.setenv(MODE_ENVIRONMENT, "record")
    with _scope(container, container / "runs" / "r1"):
        first = recorded(live)(_request(container), timeout_seconds=5)
        repeated = recorded(live)(_request(container), timeout_seconds=5)

    monkeypatch.setenv(MODE_ENVIRONMENT, "replay")
    monkeypatch.setenv(REPLAY_ENVIRONMENT, str(container / "runs" / "r1" / recording.RECORDINGS))
    replay = recorded(lambda *args, **kwargs: pytest.fail("replay must not reach the model"))
    with _scope(host, host / "runs" / "r1"):
        assert replay(_request(host), timeout_seconds=5) == first
        assert replay(_request(host), timeout_seconds=5) == repeated
        with pytest.raises(ModelReplayMiss) as missed:
            replay(_request(host), timeout_seconds=5)
    assert len(calls) == 2 and first != repeated
    assert missed.value.sequence == 2


def test_a_request_the_recorder_never_made_fails_closed(tmp_path, monkeypatch) -> None:
    root = tmp_path / "app"
    (root / "targets" / "relay").mkdir(parents=True)
    monkeypatch.setenv(MODE_ENVIRONMENT, "replay")
    monkeypatch.setenv(REPLAY_ENVIRONMENT, str(tmp_path / "empty"))
    with _scope(root, root / "runs" / "r1"), pytest.raises(ModelReplayMiss) as missed:
        recorded(lambda *args, **kwargs: None)(_request(root, "other"), timeout_seconds=5)
    assert missed.value.request["summary"]["target"] == "<target>/src/main.cpp"
    kept = tmp_path / "empty" / "job_target_analysis_plan" / "misses" / f"{missed.value.key}.0000.json"
    assert json.loads(kept.read_text(encoding="utf-8"))["request"] == missed.value.request


def test_the_environment_switch_is_validated_and_scoped(tmp_path, monkeypatch) -> None:
    root = tmp_path / "app"
    live = lambda request, *, timeout_seconds: ModelResult({"ok": True})  # noqa: E731
    monkeypatch.delenv(MODE_ENVIRONMENT, raising=False)
    assert recorded(live)(_request(root), timeout_seconds=5).proposal == {"ok": True}
    monkeypatch.setenv(MODE_ENVIRONMENT, "record")
    with pytest.raises(RuntimeError, match="outside a job unit"):
        recorded(live)(_request(root), timeout_seconds=5)
    monkeypatch.setenv(MODE_ENVIRONMENT, "sometimes")
    with pytest.raises(ValueError, match="record or replay"):
        recorded(live)(_request(root), timeout_seconds=5)
