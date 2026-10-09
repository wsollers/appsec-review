from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path
import stat
from urllib.error import HTTPError

import pytest

from appsec_review import inference
from appsec_review.config import load_config
from appsec_review.inference import anthropic_api, check_models, claude_cli, openai_api
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_review_intake.job import PREFLIGHT_SCHEMA, configured_models
from appsec_review.runtime import GraphRunner
from appsec_review.runtime.registry import builtin_registry


ROOT = Path(__file__).parents[1]


class _Response:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return json.dumps(self.value).encode()


def _fixture(tmp_path: Path, *, extra: str = ""):
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8") + extra, encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    return load_config(config_path), target


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


# ---------------------------------------------------------------- which models a run must confirm

def test_every_model_the_configuration_names_is_required_including_disabled_and_nested() -> None:
    document = {"jobs": {
        "job_a": {"settings": {"model": {"enabled": True, "provider": "claude-cli", "model": "m-1"}}},
        "job_b": {"settings": {"model": {"enabled": False, "provider": "openai", "model": "m-2"}}},
        "job_c": {"settings": {"models": {"default": {"provider": "anthropic-api", "model": "m-3"},
                                           "deep": {"provider": "anthropic-api", "model": "m-4"}}}},
        "job_d": {"settings": {"limit": 3}},
    }}
    required = configured_models(document)
    assert [(item["job_id"], item["setting"], item["provider"], item["model"], item["enabled"])
            for item in required] == [
        ("job_a", "settings.model", "claude-cli", "m-1", True),
        ("job_b", "settings.model", "openai", "m-2", False),
        ("job_c", "settings.models.default", "anthropic-api", "m-3", True),
        ("job_c", "settings.models.deep", "anthropic-api", "m-4", True),
    ]


def test_repository_configuration_names_only_providers_the_preflight_can_check() -> None:
    import tomllib

    required = configured_models(tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8")))
    assert {item["job_id"] for item in required} == {
        "job_target_analysis_plan", "job_project_build", "job_post_build_security_assessment",
        "job_owasp_control_assessment"}
    assert {item["provider"] for item in required} <= set(inference.MODEL_CHECKS) & set(inference.PROVIDERS)


# ---------------------------------------------------------------- the intake step

def test_intake_confirms_every_configured_model_before_publishing(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    check, calls = _serving("claude-haiku-5-5")
    outcome = GraphRunner(config, [build_intake(check_models=check)]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    assert outcome["status"] == "SUCCEEDED"
    assert calls == [("claude-cli", ("claude-haiku-5-5",), 120)]
    document = _preflight(config, outcome["run_id"])
    assert document["schema"] == PREFLIGHT_SCHEMA and document["unavailable"] == []
    assert len(document["required"]) == 4
    assert document["providers"]["claude-cli"]["models"]["claude-haiku-5-5"]["available"] is True
    assert document["providers"]["claude-cli"]["listed"] == ["claude-haiku-5-5"]


@pytest.mark.parametrize("extra, expected", [
    # A model only a disabled job names still has to exist.
    ('\n[jobs.job_owasp_control_assessment.settings.models.deep]\nprovider = "claude-cli"\n'
     'model = "claude-sonnet-9-9"\n', "claude-cli/claude-sonnet-9-9"),
    # A second provider is asked separately, and its missing model blocks as well.
    ('\n[jobs.job_owasp_control_assessment.settings.models.deep]\nprovider = "openai"\n'
     'model = "gpt-missing"\n', "openai/gpt-missing"),
], ids=["disabled-job-model", "second-provider"])
def test_one_unavailable_model_blocks_the_review_and_keeps_the_evidence(
        tmp_path: Path, extra: str, expected: str) -> None:
    config, target = _fixture(tmp_path, extra=extra)
    check, calls = _serving("claude-haiku-5-5")
    with pytest.raises(RuntimeError, match="job reported partial failure: model_preflight.verify_models"):
        GraphRunner(config, [build_intake(check_models=check)]).run(
            target_root=target, source_fingerprint=source_fingerprint(target))
    run_id = next(path.name for path in config.runtime.runs_dir.iterdir() if path.name != "metadata")
    document = _preflight(config, run_id)
    assert [f"{item['provider']}/{item['model']}" for item in document["unavailable"]] == [expected]
    assert document["unavailable"][0]["jobs"] == ["job_owasp_control_assessment"]
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
    assert verify["terminal_status"] == "NOT_APPLICABLE" and len(verify["required"]) == 4


def test_registry_wires_the_real_check_into_the_first_job_of_a_review(monkeypatch, tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    seen: list[str] = []
    monkeypatch.setitem(inference.MODEL_CHECKS, "claude-cli", lambda names, *, timeout_seconds: (
        seen.extend(names) or {"method": "probe", "listed": None, "models": {
            name: {"available": True, "detail": "answered"} for name in names}}))
    outcome = GraphRunner(config, [builtin_registry().build("job_review_intake")]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    assert outcome["status"] == "SUCCEEDED" and seen == ["claude-haiku-5-5"]


# ---------------------------------------------------------------- provider checks

def test_check_models_reports_provider_failures_instead_of_raising(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    report = check_models("anthropic-api", ["claude-haiku-5-5", "claude-haiku-5-5"], timeout_seconds=5)
    assert report["error"].startswith("RuntimeError: ANTHROPIC_API_KEY is unavailable")
    assert report["models"] == {"claude-haiku-5-5": {"available": False, "detail": report["error"]}}
    unknown = check_models("mystery", ["m"], timeout_seconds=5)
    assert unknown["transport"] is False and unknown["models"]["m"]["available"] is False
    assert "unsupported inference provider" in unknown["error"]


def test_a_listed_model_without_an_inference_transport_is_still_unavailable(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "fixture-key")
    monkeypatch.setattr(openai_api, "urlopen", lambda request, timeout: _Response(
        {"data": [{"id": "gpt-5"}, {"id": "gpt-5-mini"}]}))
    report = check_models("openai", ["gpt-5"], timeout_seconds=5)
    assert report["listed"] == ["gpt-5", "gpt-5-mini"] and report["error"] is None
    assert report["models"]["gpt-5"] == {
        "available": False, "detail": "no inference transport is implemented for provider openai"}


def test_openai_listing_sends_the_key_and_reports_membership(monkeypatch) -> None:
    captured = {}

    def fake_open(request, timeout):
        captured.update(url=request.full_url, authorization=request.get_header("Authorization"), timeout=timeout)
        return _Response({"data": [{"id": "gpt-5"}]})

    monkeypatch.setenv("OPENAI_API_KEY", "fixture-key")
    monkeypatch.setattr(openai_api, "urlopen", fake_open)
    result = openai_api.models(["gpt-5", "gpt-absent"], timeout_seconds=9)
    assert captured == {"url": "https://api.openai.com/v1/models", "authorization": "Bearer fixture-key",
                        "timeout": 9}
    assert result["models"]["gpt-5"]["available"] is True
    assert result["models"]["gpt-absent"]["available"] is False


def test_anthropic_listing_resolves_aliases_and_rejects_unknown_models(monkeypatch) -> None:
    requested: list[str] = []

    def fake_open(request, timeout):
        requested.append(request.full_url)
        assert request.get_header("X-api-key") == "fixture-key"
        if request.full_url.endswith("?limit=1000"):
            return _Response({"data": [{"id": "claude-haiku-5-5-20260101"}, {"id": "claude-sonnet-5-5-20260101"}]})
        if request.full_url.endswith("/claude-haiku-5-5"):
            return _Response({"id": "claude-haiku-5-5-20260101"})
        raise HTTPError(request.full_url, 404, "Not Found", {}, BytesIO(b"{}"))

    monkeypatch.setenv("ANTHROPIC_API_KEY", "fixture-key")
    monkeypatch.setattr(anthropic_api, "urlopen", fake_open)
    result = anthropic_api.models(
        ["claude-sonnet-5-5-20260101", "claude-haiku-5-5", "claude-opus-0-0"], timeout_seconds=5)
    assert result["listed"] == ["claude-haiku-5-5-20260101", "claude-sonnet-5-5-20260101"]
    assert result["models"]["claude-sonnet-5-5-20260101"] == {"available": True, "detail": "listed by the provider"}
    assert result["models"]["claude-haiku-5-5"]["detail"] == "resolved by the provider to claude-haiku-5-5-20260101"
    assert result["models"]["claude-opus-0-0"]["available"] is False
    assert len(requested) == 3


@pytest.mark.skipif(__import__("os").name == "nt", reason="uses a POSIX executable stand-in")
def test_claude_cli_probe_accepts_only_a_model_that_actually_answered(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "claude"
    binary.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "model = sys.argv[sys.argv.index('--model') + 1]\n"
        "assert sys.argv[sys.argv.index('--allowedTools') + 1] == '' and 'ANTHROPIC_API_KEY' not in os.environ\n"
        "if model == 'claude-haiku-5-5':\n"
        "    print(json.dumps({'is_error': False, 'result': 'ok', 'modelUsage': {'claude-haiku-5-5': {}}}))\n"
        "elif model == 'claude-substituted':\n"
        "    print(json.dumps({'is_error': False, 'result': 'ok', 'modelUsage': {'claude-other': {}}}))\n"
        "elif model == 'claude-garbled':\n"
        "    print('not json'); sys.stderr.write('boom'); sys.exit(3)\n"
        "else:\n"
        "    print(json.dumps({'is_error': True, 'terminal_reason': 'api_error', 'modelUsage': {}})); sys.exit(1)\n",
        encoding="utf-8")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{tmp_path}:{__import__('os').environ['PATH']}")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-not-reach-the-subscription-cli")
    result = claude_cli.models(
        ["claude-haiku-5-5", "claude-missing", "claude-substituted", "claude-garbled"], timeout_seconds=20)
    assert result["method"] == "probe" and result["listed"] is None
    assert result["models"]["claude-haiku-5-5"] == {"available": True, "detail": "answered an availability probe"}
    assert result["models"]["claude-missing"] == {
        "available": False, "detail": "probe was not answered by this model: api_error"}
    assert result["models"]["claude-substituted"]["available"] is False
    assert result["models"]["claude-garbled"] == {"available": False, "detail": "Claude CLI exited 3: boom"}
