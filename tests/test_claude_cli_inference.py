from __future__ import annotations

import json

import pytest

from appsec_review.inference.claude_cli import ModelOutputError, models, parse_model_payload, send
from appsec_review.inference.request import ModelRequest


SCHEMA = "appsec-review/target-analysis-proposal/2"
VALUE = {"schema": SCHEMA, "component_proposals": [], "build_recipes": []}


@pytest.mark.parametrize("raw", [
    json.dumps(VALUE),
    json.dumps({"result": json.dumps(VALUE), "usage": {"input_tokens": 2}}),
    "```json\n" + json.dumps(VALUE) + "\n```",
    "Here is the bounded result:\n" + json.dumps(VALUE),
])
def test_model_parser_accepts_expected_cli_wrappers(raw: str) -> None:
    assert parse_model_payload(raw, SCHEMA) == VALUE


@pytest.mark.parametrize("raw", ["", "not json", '{"schema":',
    json.dumps(VALUE) + "\n" + json.dumps({**VALUE, "build_recipes": [{"x": 1}]})])
def test_model_parser_rejects_missing_malformed_or_ambiguous_output(raw: str) -> None:
    with pytest.raises(ModelOutputError):
        parse_model_payload(raw, SCHEMA)


def test_cli_transport_disables_tools_for_inference_and_preflight(monkeypatch) -> None:
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        assert argv[argv.index("--tools") + 1] == ""
        assert "--safe-mode" in argv
        assert "--allowedTools" not in argv
        assert "bypassPermissions" not in argv
        class Result:
            returncode = 0
            stderr = ""
            stdout = json.dumps({"result": json.dumps(VALUE), "is_error": False,
                                 "modelUsage": {"example": {}}})
        return Result()

    monkeypatch.setattr("appsec_review.inference.claude_cli.shutil.which", lambda _: "/bin/claude")
    monkeypatch.setattr("appsec_review.inference.claude_cli.subprocess.run", fake_run)
    request = ModelRequest(schema=SCHEMA, persona="p", role="r", guidance="g", summary={},
                           allowed_scanners=(), allowed_build_systems=(), allowed_components=(),
                           allowed_paths=(), allowed_build_units=(), provider="claude-cli",
                           model="example", reasoning="low", max_input_tokens=100,
                           max_output_tokens=100)
    assert send(request, timeout_seconds=5).proposal == VALUE
    assert models(["example"], timeout_seconds=5)["models"]["example"]["available"]
    assert len(calls) == 2
