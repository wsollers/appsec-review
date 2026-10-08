from __future__ import annotations

import json

import pytest

from appsec_review.inference.claude_cli import ModelOutputError, parse_model_payload


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
