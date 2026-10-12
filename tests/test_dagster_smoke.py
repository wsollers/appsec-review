from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest


BIN = Path(__file__).resolve().parents[1] / "deploy" / "dagster" / "bin"
sys.path.insert(0, str(BIN))
spec = importlib.util.spec_from_file_location("dagster_smoke", BIN / "smoke.py")
assert spec is not None and spec.loader is not None
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def test_compose_uses_host_specific_cli_layout() -> None:
    assert smoke.compose("windows")[-1].endswith("compose.windows.yaml")
    assert smoke.compose("linux")[-1].endswith("compose.claude.yaml")
    assert smoke.compose("wsl")[-1].endswith("compose.claude.yaml")


def test_live_smoke_lock_excludes_parallel_runs_and_cleans_up(tmp_path: Path, monkeypatch) -> None:
    lock = tmp_path / "dagster-smoke.lock"
    monkeypatch.setattr(smoke, "LOCK", lock)
    with smoke.serial_lock():
        assert (lock / "owner.json").is_file()
        with pytest.raises(RuntimeError, match="another smoke run"):
            with smoke.serial_lock():
                pass
    assert not lock.exists()


def test_active_run_gate_includes_queued_runs(monkeypatch) -> None:
    monkeypatch.setattr(smoke, "request_json", lambda *_: {"data": {"runsOrError": {
        "__typename": "Runs", "results": [
            {"runId": "finished", "status": "SUCCESS"},
            {"runId": "queued", "status": "QUEUED"},
            {"runId": "started", "status": "STARTED"},
        ]}}})
    assert smoke.active_runs("http://localhost:3000") == ["queued", "started"]
    with pytest.raises(RuntimeError, match="queued, started"):
        smoke.reject_contention("http://localhost:3000", "windows")


def test_cli_smoke_requires_subscription_auth(monkeypatch) -> None:
    import json

    def fake_run(command, *, capture=False):
        return type("Result", (), {"stdout": json.dumps({"loggedIn": True, "authMethod": "api_key"})})()

    monkeypatch.setattr(smoke, "run", fake_run)
    with pytest.raises(RuntimeError, match="subscription login"):
        smoke.check_cli("windows")


def test_feed_smoke_checks_every_publication(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(smoke, "ROOT", tmp_path)
    monkeypatch.setattr(smoke, "reject_contention", lambda *_: None)
    monkeypatch.setattr(smoke, "request_json", lambda *_: {"data": {"runOrError": {
        "__typename": "Run", "pipelineName": "third_party_data_sync", "status": "SUCCESS"}}})
    commands = []

    def fake_run(command, *, capture=False):
        commands.append(command)
        if "verify.py" in " ".join(command):
            return type("Result", (), {"stdout": __import__("json").dumps({"acceptance_run": {
                "published_snapshots": {feed: {} for feed in smoke.FEEDS}}})})()
        return type("Result", (), {"stdout": ""})()

    monkeypatch.setattr(smoke, "run", fake_run)
    result = smoke.sync_feeds("windows", "http://localhost:3000", 1)
    assert set(result["feeds"]) == smoke.FEEDS
    assert sum("launch" in command for command in commands) == 1
    assert sum("verify.py" in " ".join(command) for command in commands) == 1
