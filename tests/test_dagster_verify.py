from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "dagster_verify", ROOT / "deploy" / "dagster" / "bin" / "verify.py")
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


def test_workspace_expectations_omit_job_level_disabled_jobs(monkeypatch) -> None:
    jobs = ["enabled_job", "wave1_error_state", "wave1_review"]
    responses = iter(({}, {
        "data": {"repositoriesOrError": {
            "__typename": "RepositoryConnection",
            "nodes": [{
                "name": "appsec_review",
                "location": {"name": "appsec_review"},
                "pipelines": [{"name": name} for name in jobs],
                "schedules": [],
                "sensors": [
                    {"name": "wave1_canceled_state", "sensorState": {"status": "RUNNING"}},
                    {"name": "wave1_failure_state", "sensorState": {"status": "RUNNING"}},
                    {"name": "wave1_step_failure_state", "sensorState": {"status": "RUNNING"}},
                ],
            }],
        }},
    }))
    monkeypatch.setattr(verify, "request_json", lambda *_args, **_kwargs: next(responses))
    document = {"jobs": {
        "job_enabled": {"name": "enabled_job", "settings": {}},
        "job_disabled": {"name": "disabled_job", "settings": {"enabled": False}},
    }}

    result = verify._workspace("http://dagster.invalid", document)

    assert result["jobs"] == jobs


def test_workspace_expectations_reject_non_boolean_job_enablement(monkeypatch) -> None:
    responses = iter(({}, {
        "data": {"repositoriesOrError": {
            "__typename": "RepositoryConnection",
            "nodes": [{
                "name": "appsec_review",
                "location": {"name": "appsec_review"},
                "pipelines": [],
                "schedules": [],
                "sensors": [],
            }],
        }},
    }))
    monkeypatch.setattr(verify, "request_json", lambda *_args, **_kwargs: next(responses))
    document = {"jobs": {
        "job_invalid": {"name": "invalid_job", "settings": {"enabled": "false"}},
    }}

    try:
        verify._workspace("http://dagster.invalid", document)
    except SystemExit as exc:
        assert str(exc) == "jobs.job_invalid.settings.enabled must be a boolean"
    else:
        raise AssertionError("non-boolean job enablement was accepted")
