"""Provider-level preflight checks retained outside the intake job's tier walk."""
from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path
import stat
from urllib.error import HTTPError

import pytest

from appsec_review.inference import anthropic_api, check_models, claude_cli, openai_api


class _Response:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return json.dumps(self.value).encode()


def test_check_models_reports_provider_failures_instead_of_raising(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    report = check_models("anthropic-api", ["claude-haiku-5-5", "claude-haiku-5-5"], timeout_seconds=5)
    assert report["error"].startswith("ProviderError: Anthropic API authentication is unavailable")
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
        "elif model == 'claude-expired':\n"
        "    print(json.dumps({'is_error': True, 'terminal_reason': 'api_error', "
        "'result': 'OAuth access token has expired. Re-authenticate to continue.', 'modelUsage': {}})); sys.exit(1)\n"
        "else:\n"
        "    print(json.dumps({'is_error': True, 'terminal_reason': 'api_error', 'modelUsage': {}})); sys.exit(1)\n",
        encoding="utf-8")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{tmp_path}:{__import__('os').environ['PATH']}")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-not-reach-the-subscription-cli")
    result = claude_cli.models(
        ["claude-haiku-5-5", "claude-missing", "claude-substituted", "claude-garbled",
         "claude-expired"], timeout_seconds=20)
    assert result["method"] == "probe" and result["listed"] is None
    assert result["models"]["claude-haiku-5-5"] == {"available": True, "detail": "answered an availability probe"}
    assert result["models"]["claude-missing"] == {
        "available": False, "detail": "probe was not answered by this model: api_error"}
    assert result["models"]["claude-substituted"]["available"] is False
    assert result["models"]["claude-garbled"] == {"available": False, "detail": "Claude CLI exited 3: boom"}
    assert result["models"]["claude-expired"] == {
        "available": False,
        "detail": "probe was not answered by this model: OAuth access token has expired. "
                  "Re-authenticate to continue.",
    }
