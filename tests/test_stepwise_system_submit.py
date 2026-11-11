"""The stepwise system walk submits its review through the real ``review_run.submit`` signature."""
from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import UUID

from tests.test_stepwise_rewind import stepwise

import ops  # noqa: E402  (tests.test_stepwise_rewind puts deploy/dagster/bin on sys.path)

URL = "http://127.0.0.1:3999/graphql"
TAG = "fixture-corpus-v1"
TARGET = "/opt/app/targets/fixture"


def test_system_submits_through_review_run_with_the_walk_endpoint(tmp_path, monkeypatch, capsys):
    key_root = tmp_path / "test/acceptance" / TAG
    key_root.mkdir(parents=True)
    (key_root / "job_fixture.json").write_text("{}\n", encoding="utf-8")
    (key_root / "job_fixture.provenance.json").write_text(json.dumps({"target": TARGET}), encoding="utf-8")
    monkeypatch.setattr(stepwise, "ACCEPTANCE_ROOT", tmp_path / "test/acceptance")
    monkeypatch.setattr(stepwise, "packaged_topology", lambda: {"graph": "wave1_review", "jobs": []})
    monkeypatch.setattr(stepwise, "compose", lambda *arguments, **options: TARGET + "\n")
    submitted, waited = [], []
    # Only the outermost boundaries are faked: the operator launch behind review_run.submit and the
    # Dagster GraphQL reads. review_run.submit itself is real, so its signature is exercised.
    monkeypatch.setattr(ops, "cmd_review_start", lambda args: submitted.append(args))

    def wait(url, dagster_run_id, interval):
        waited.append((url, dagster_run_id, interval))
        return {"status": "FAILURE", "tag_map": {}}

    monkeypatch.setattr(stepwise, "wait", wait)
    monkeypatch.setattr(stepwise, "failure_messages", lambda url, run_id: [f"step=fixture url={url}"])

    arguments = SimpleNamespace(tag=TAG, app_run=None, url=URL, interval_seconds=1, show=1)
    assert stepwise.command_system(arguments) == 1

    (launch,) = submitted
    assert launch.url == URL
    assert str(UUID(launch.dagster_run_id)) == launch.dagster_run_id
    assert launch.stop_on_first_error is False and launch.no_probe is False
    assert waited == [(URL, launch.dagster_run_id, 1)]
    output = capsys.readouterr().out
    assert f"submitted_dagster_run_id={launch.dagster_run_id}" in output
    assert "system FAILED: the Dagster run ended FAILURE without an application run" in output
