from __future__ import annotations

import json
from pathlib import Path
import stat

import pytest

from appsec_review import inference
from appsec_review.inference import ModelResult, ReviewModelRequest, infer

TURN_SCHEMA = "appsec-review/worker-turn/1"
TURN = {"schema": TURN_SCHEMA, "action": "final", "result": {"hypotheses": []}}
GUIDANCE = "governing rules / role / task guidance"


def _request(provider: str) -> ReviewModelRequest:
    return ReviewModelRequest(
        schema=TURN_SCHEMA, role="hypothesis_hunter", persona="web_api", stack_profile="python_web",
        guidance_bundle_sha256="a" * 64, guidance_text=GUIDANCE, task_input={"task": "hunt/sink_up"},
        transcript=({"turn": 1, "from": "worker", "content": {"action": "retrieve", "requests": []}},),
        provider=provider, model="claude-opus-5-5", reasoning="high", max_input_tokens=32000,
        max_output_tokens=8000, repair_errors=("cites unseen identities",), cell_id="cell-" + "b" * 64)


def test_infer_dispatches_review_requests_through_the_provider_table(monkeypatch) -> None:
    seen = []

    def send(request, *, timeout_seconds):
        seen.append((type(request).__name__, request.cell_id, timeout_seconds))
        return ModelResult(TURN)

    monkeypatch.setitem(inference.PROVIDERS, "claude-cli", send)
    assert infer(_request("claude-cli"), timeout_seconds=11).proposal == TURN
    assert seen == [("ReviewModelRequest", "cell-" + "b" * 64, 11)]
    with pytest.raises(ValueError, match="unsupported inference provider"):
        infer(_request("openai"), timeout_seconds=5)


def test_review_request_carries_no_build_planning_fields() -> None:
    fields = set(ReviewModelRequest.__dataclass_fields__)
    assert not fields & {"summary", "allowed_paths", "allowed_scanners", "allowed_components",
                         "allowed_build_units", "allowed_build_systems", "prior_response", "guidance"}


@pytest.mark.skipif(__import__("os").name == "nt", reason="uses a POSIX executable stand-in")
def test_claude_cli_sends_review_turns_with_no_tools(tmp_path: Path, monkeypatch) -> None:
    record = tmp_path / "invocation.json"
    binary = tmp_path / "claude"
    binary.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"json.dump({{'argv': sys.argv[1:], 'stdin': json.load(sys.stdin)}}, open({str(record)!r}, 'w'))\n"
        f"print(json.dumps({{'result': json.dumps({TURN!r}), 'usage': {{'input_tokens': 7, 'output_tokens': 2}}}}))\n",
        encoding="utf-8")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{tmp_path}:{__import__('os').environ['PATH']}")
    result = infer(_request("claude-cli"), timeout_seconds=30)
    assert result.proposal == TURN and (result.input_tokens, result.output_tokens) == (7, 2)
    invocation = json.loads(record.read_text(encoding="utf-8"))
    argv = invocation["argv"]
    assert argv[argv.index("--allowedTools") + 1] == ""
    assert argv[argv.index("--model") + 1] == "claude-opus-5-5"
    prompt = invocation["stdin"]
    assert prompt["guidance"] == GUIDANCE and prompt["task_input"] == {"task": "hunt/sink_up"}
    assert prompt["transcript"][0]["turn"] == 1 and prompt["response_schema"] == TURN_SCHEMA
    assert prompt["repair"]["validation_errors"] == ["cites unseen identities"]
    assert "allowlists" not in prompt and "catalog_summary" not in prompt


class _Response:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return json.dumps(self.value).encode()


def test_anthropic_api_sends_guidance_as_system_and_turn_data_as_user(monkeypatch) -> None:
    captured = {}

    def fake_open(request, timeout):
        captured["body"] = json.loads(request.data)
        return _Response({"content": [{"type": "text", "text": json.dumps(TURN)}],
                          "usage": {"input_tokens": 9, "output_tokens": 4}})

    monkeypatch.setenv("ANTHROPIC_API_KEY", "fixture-key")
    monkeypatch.setattr("appsec_review.inference.anthropic_api.urlopen", fake_open)
    result = infer(_request("anthropic-api"), timeout_seconds=30)
    body = captured["body"]
    assert result.proposal == TURN and result.input_tokens == 9
    assert body["system"] == GUIDANCE and "tools" not in body
    user = json.loads(body["messages"][0]["content"])
    assert "guidance" not in user and user["task_input"] == {"task": "hunt/sink_up"}
    assert user["transcript"][0]["from"] == "worker"
