from __future__ import annotations

import json

from appsec_review.inference.anthropic_api import AnthropicApiModelClient
from appsec_review.jobs.job_target_analysis_plan.planning import ModelRequest, PROPOSAL_SCHEMA


class Response:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return json.dumps(self.value).encode()


def test_anthropic_adapter_applies_model_reasoning_and_bounded_json(monkeypatch) -> None:
    captured = {}

    def fake_open(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        value = {"schema": PROPOSAL_SCHEMA, "component_proposals": [], "build_recipes": []}
        return Response({"content": [{"type": "thinking", "thinking": "private"},
                                     {"type": "text", "text": json.dumps(value)}],
                         "usage": {"input_tokens": 12, "output_tokens": 8}})

    monkeypatch.setenv("ANTHROPIC_API_KEY", "fixture-key")
    monkeypatch.setattr("appsec_review.inference.anthropic_api.urlopen", fake_open)
    request = ModelRequest(
        schema=PROPOSAL_SCHEMA, guidance="bounded", summary={"build_units": []},
        allowed_scanners=(), allowed_build_systems=(), allowed_components=(), allowed_paths=(),
        allowed_build_units=(), provider="anthropic-api", model="claude-haiku-4-5-20251001",
        reasoning="medium", max_input_tokens=32000, max_output_tokens=8000,
    )
    result = AnthropicApiModelClient().complete(request, timeout_seconds=30)
    body = json.loads(captured["request"].data)
    assert body["model"] == request.model
    assert body["thinking"] == {"type": "enabled", "budget_tokens": 2048}
    assert captured["request"].headers["X-api-key"] == "fixture-key"
    assert result.proposal["schema"] == PROPOSAL_SCHEMA
    assert result.input_tokens == 12 and result.output_tokens == 8
