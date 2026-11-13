"""Pre-walk suite pending replacement: intake/model graph and its original provider fixtures.

Graph claims are preserved for explicitly authorized integration execution. Provider-only tests
remain in tests/test_model_preflight.py; code-level intake tests live in tests/unit/job_review_intake.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review import inference
from appsec_review.config import load_config
from appsec_review.inference import check_models
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_review_intake.job import PREFLIGHT_SCHEMA, configured_models
from appsec_review.runtime import GraphRunner


ROOT = Path(__file__).parents[3]


def _fixture(tmp_path: Path, *, extra: str = "", owasp_enabled: bool = True):
    config_path = tmp_path / "appsec-review.toml"
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if not owasp_enabled:
        header = '[jobs.job_owasp_control_assessment.settings]\nenabled = true'
        assert source.count(header) == 1
        source = source.replace(header, '[jobs.job_owasp_control_assessment.settings]\nenabled = false', 1)
    config_path.write_text(source + extra, encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    return load_config(config_path), target


def _repository_document() -> dict:
    import tomllib

    return tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))


def _repository_required_count() -> int:
    return len(configured_models(_repository_document()))


def _serving(*available: str):
    calls: list[tuple[str, tuple[str, ...], int]] = []

    def check(provider: str, names, *, timeout_seconds: int):
        calls.append((provider, tuple(names), timeout_seconds))
        return {"provider": provider, "transport": True, "method": "catalog", "listed": sorted(available),
                "error": None, "models": {name: (
                    {"available": True, "detail": "listed by the provider"} if name in available else
                    {"available": False, "detail": "the provider does not list this model"}) for name in names}}
    return check, calls


def _preflight(config, run_id: str) -> dict:
    root = config.runtime.runs_dir / run_id
    return json.loads(next(root.rglob("model-preflight.json")).read_text(encoding="utf-8"))


def test_intake_confirms_every_configured_model_before_publishing(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    check, calls = _serving("claude-haiku-5-5")
    outcome = GraphRunner(config, [build_intake(check_models=check)]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    assert outcome["status"] == "SUCCEEDED"
    assert calls == [("claude-cli", ("claude-haiku-5-5",), 120)]
    document = _preflight(config, outcome["run_id"])
    assert document["schema"] == PREFLIGHT_SCHEMA and document["unavailable"] == []
    assert document["unavailable_not_required"] == [] and document["gaps"] == []
    assert len(document["required"]) + len(document["not_required"]) == _repository_required_count()
    # The one disabled model setting in the repository configuration is checked but cannot block.
    assert [(item["job_id"], item["reason"]) for item in document["not_required"]] == [
        ("job_post_build_security_assessment", "model setting disabled")]
    assert document["providers"]["claude-cli"]["models"]["claude-haiku-5-5"]["available"] is True
    assert document["providers"]["claude-cli"]["listed"] == ["claude-haiku-5-5"]


DEEP = '\n[jobs.job_owasp_control_assessment.settings.models.deep]\nprovider = "{provider}"\nmodel = "{model}"\n'


def test_a_missing_model_named_only_by_a_disabled_job_is_checked_and_recorded_but_never_blocks(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, extra=DEEP.format(provider="claude-cli", model="claude-sonnet-9-9"),
                              owasp_enabled=False)
    check, calls = _serving("claude-haiku-5-5")
    outcome = GraphRunner(config, [build_intake(check_models=check)]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    assert outcome["status"] == "COMPLETED_WITH_GAPS", outcome
    document = _preflight(config, outcome["run_id"])
    # Every configured model was asked for, in one call per provider.
    assert calls == [("claude-cli", ("claude-haiku-5-5", "claude-sonnet-9-9"), 120)]
    assert document["unavailable"] == []
    assert [f"{item['provider']}/{item['model']}" for item in document["unavailable_not_required"]] == [
        "claude-cli/claude-sonnet-9-9"]
    assert document["unavailable_not_required"][0]["jobs"] == ["job_owasp_control_assessment"]
    [gap] = document["gaps"]
    assert gap["code"] == "producer_blocked" and gap["retryable"] is True and "disabled job_owasp_control_assessment" in gap["reason"]
    # The review starts: the intake handoff is published and carries the gap.
    run_root = config.runtime.runs_dir / outcome["run_id"]
    pointer = json.loads((run_root / "data" / "jobs" / "job_review_intake" / "latest.json").read_text(encoding="utf-8"))
    handoff = json.loads((run_root / pointer["handoff_path"]).read_text(encoding="utf-8"))
    assert [gap["code"] for gap in handoff["outputs"]["model_preflight.verify_models"]["gaps"]] == ["producer_blocked"]


@pytest.mark.parametrize("provider, model", [("claude-cli", "claude-sonnet-9-9"), ("openai", "gpt-missing")],
                         ids=["same-provider", "second-provider"])
def test_one_unavailable_required_model_blocks_the_review_and_keeps_the_evidence(
        tmp_path: Path, provider: str, model: str) -> None:
    expected = f"{provider}/{model}"
    config, target = _fixture(tmp_path, extra=DEEP.format(provider=provider, model=model))
    check, calls = _serving("claude-haiku-5-5")
    with pytest.raises(RuntimeError, match="job reported partial failure: model_preflight.verify_models"):
        GraphRunner(config, [build_intake(check_models=check)]).run(
            target_root=target, source_fingerprint=source_fingerprint(target))
    run_id = next(path.name for path in config.runtime.runs_dir.iterdir() if path.name != "metadata")
    document = _preflight(config, run_id)
    assert [f"{item['provider']}/{item['model']}" for item in document["unavailable"]] == [expected]
    assert document["unavailable"][0]["jobs"] == ["job_owasp_control_assessment"]
    assert document["unavailable_not_required"] == [] and document["gaps"] == []
    assert {provider for provider, _names, _timeout in calls} == {item["provider"] for item in document["required"]}
    # Nothing downstream can start: the intake handoff was never published.
    assert not (config.runtime.runs_dir / run_id / "data" / "jobs" / "job_review_intake" / "latest.json").exists()
    status = json.loads(next((config.runtime.runs_dir / run_id).rglob(
        "steps/model_preflight/tasks/verify_models/status.json")).read_text(encoding="utf-8"))
    assert status["status"] == "FAILED" and expected in status["error"]["message"]


def test_a_provider_that_cannot_be_reached_blocks_the_review_with_its_error(tmp_path: Path, monkeypatch) -> None:
    config, target = _fixture(tmp_path)
    monkeypatch.setitem(inference.MODEL_CHECKS, "claude-cli",
                        lambda names, *, timeout_seconds: (_ for _ in ()).throw(FileNotFoundError("no claude binary")))
    with pytest.raises(RuntimeError, match="model_preflight.verify_models"):
        GraphRunner(config, [build_intake(check_models=check_models)]).run(
            target_root=target, source_fingerprint=source_fingerprint(target))
    run_id = next(path.name for path in config.runtime.runs_dir.iterdir() if path.name != "metadata")
    document = _preflight(config, run_id)
    assert document["providers"]["claude-cli"]["error"] == "FileNotFoundError: no claude binary"
    assert document["unavailable"][0]["detail"] == "FileNotFoundError: no claude binary"


def test_an_unwired_intake_reports_that_no_check_ran(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    outcome = GraphRunner(config, [build_intake()]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    result = json.loads(next((config.runtime.runs_dir / outcome["run_id"]).rglob(
        "attempts/*/result.json")).read_text(encoding="utf-8"))
    verify = result["outputs"]["model_preflight.verify_models"]
    assert verify["terminal_status"] == "NOT_APPLICABLE"
    assert len(verify["required"]) + len(verify["not_required"]) == _repository_required_count()
