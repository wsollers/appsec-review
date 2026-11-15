from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.inference.claude_cli import (
    ModelOutputError, models, parse_model_payload, retained_reply_bytes, send,
)
from appsec_review.inference.errors import SCHEMA_FAILURE_CLASSES
from appsec_review.inference.request import ModelRequest, ModelResult


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


def test_a_worker_turn_without_its_schema_field_is_accepted_and_one_with_another_schema_is_not() -> None:
    turn = "appsec-review/worker-turn/1"
    retrieve = {"action": "retrieve", "requests": [{"tool": "query_observations", "parameters": {"entity_id": "e"}}]}
    assert parse_model_payload("```json\n" + json.dumps(retrieve) + "\n```", turn) == {"schema": turn, **retrieve}
    assert parse_model_payload(json.dumps({"action": "final", "result": {}}), turn)["schema"] == turn
    # Only a recognised action may stand in for the schema, and a different declared schema stays rejected.
    with pytest.raises(ModelOutputError):
        parse_model_payload(json.dumps({"action": "explore", "requests": []}), turn)
    with pytest.raises(ModelOutputError):
        parse_model_payload(json.dumps({"schema": "appsec-review/other/1", "action": "retrieve"}), turn)
    # A different expected schema is never filled in this way.
    with pytest.raises(ModelOutputError):
        parse_model_payload(json.dumps(retrieve), "appsec-review/red-discovery-result/1")


def test_cli_transport_disables_tools_for_inference_and_preflight(monkeypatch) -> None:
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        assert argv[argv.index("--tools") + 1] == ""
        assert "--safe-mode" in argv
        assert argv[argv.index("--allowedTools") + 1] == ""
        assert "bypassPermissions" not in argv
        if kwargs.get("input", "").startswith("{"):
            prompt = json.loads(kwargs["input"])
            assert prompt["allowlists"]["image_profiles"] == ["android"]
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
                           max_output_tokens=100, allowed_image_profiles=("android",))
    assert send(request, timeout_seconds=5).proposal == VALUE
    assert models(["example"], timeout_seconds=5)["models"]["example"]["available"]
    assert len(calls) == 2


# ----------------------------------------------------------------------------------------- T-5022
FIXTURES = Path(__file__).parent / "fixtures" / "dependency_intelligence" / "t5022"
NATIVE = "appsec-review/native-dependency-resolution-proposal/1"


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def _cli_envelope(fixture: dict) -> str:
    reply = fixture["reply"]
    return json.dumps({"type": "result", "subtype": reply["subtype"], "is_error": reply["is_error"],
                       "stop_reason": reply["stop_reason"], "usage": reply["usage"],
                       "modelUsage": {fixture["request"]["model"]: {}}, "result": reply["result"]})


@pytest.mark.parametrize("name", ["failed-first-attempt", "failed-second-attempt"])
def test_a_recorded_0005_proposal_without_its_schema_field_parses_as_one_proposal(name: str) -> None:
    fixture = _fixture(name)
    proposal = parse_model_payload(_cli_envelope(fixture), NATIVE)
    assert proposal["schema"] == NATIVE
    assert proposal["candidate_id"] == fixture["request"]["summary"]["candidate"]["candidate_id"]
    assert set(proposal) == {"schema", "candidate_id", "repository", "confidence", "evidence_refs", "rationale"}
    # The same text under its recorded failure message used to be rejected: the field set is the contract.
    assert fixture["error_message"] == f"expected exactly one {NATIVE} JSON object, found 0"


def test_a_schema_bearing_0005_reply_still_parses_unchanged() -> None:
    fixture = _fixture("succeeded-after-repair")
    assert parse_model_payload(_cli_envelope(fixture), NATIVE) == fixture["proposal"]


@pytest.mark.parametrize("value", [
    {"candidate_id": "c", "repository": None, "confidence": 0},                    # missing fields
    {"candidate_id": "c", "repository": None, "confidence": 0, "evidence_refs": [], "rationale": "", "x": 1},
    {"schema": "appsec-review/other/1", "candidate_id": "c", "repository": None, "confidence": 0,
     "evidence_refs": [], "rationale": ""},                                          # another schema
])
def test_only_the_exact_native_proposal_field_set_stands_in_for_its_schema(value: dict) -> None:
    with pytest.raises(ModelOutputError) as raised:
        parse_model_payload(json.dumps(value), NATIVE)
    assert raised.value.failure_class == "schema_mismatch"


def test_the_native_field_set_never_fills_in_a_different_schema() -> None:
    fields = {"candidate_id": "c", "repository": None, "confidence": 0, "evidence_refs": ["c"], "rationale": "r"}
    with pytest.raises(ModelOutputError):
        parse_model_payload(json.dumps(fields), SCHEMA)


@pytest.mark.parametrize("raw, failure_class", [
    ("   ", "empty_reply"),
    ("```json\n```", "empty_reply"),
    ("I cannot determine a repository from a bare link flag.", "no_json_object"),
    (json.dumps({"schema": "appsec-review/other/1", "x": 1}), "schema_mismatch"),
    (json.dumps(VALUE) + "\n" + json.dumps({**VALUE, "build_recipes": [{"x": 1}]}), "several_objects"),
])
def test_parser_rejections_carry_a_closed_failure_class(raw: str, failure_class: str) -> None:
    with pytest.raises(ModelOutputError) as raised:
        parse_model_payload(raw, SCHEMA)
    assert raised.value.failure_class == failure_class
    assert failure_class in SCHEMA_FAILURE_CLASSES


def _send_with_stdout(monkeypatch, stdout: str, *, max_output_tokens: int = 4000) -> ModelResult:
    def fake_run(argv, **kwargs):
        class Result:
            returncode = 0
            stderr = ""
        Result.stdout = stdout
        return Result()
    monkeypatch.setattr("appsec_review.inference.claude_cli.shutil.which", lambda _: "/bin/claude")
    monkeypatch.setattr("appsec_review.inference.claude_cli.subprocess.run", fake_run)
    request = ModelRequest(schema=SCHEMA, persona="p", role="r", guidance="g", summary={},
                           allowed_scanners=(), allowed_build_systems=(), allowed_components=(),
                           allowed_paths=(), allowed_build_units=(), provider="claude-cli",
                           model="example", reasoning="low", max_input_tokens=100,
                           max_output_tokens=max_output_tokens)
    return send(request, timeout_seconds=5)


def test_a_failed_reply_keeps_text_stop_reason_usage_and_class_like_a_success(monkeypatch) -> None:
    fixture = _fixture("failed-first-attempt")
    stdout = _cli_envelope(fixture)
    with pytest.raises(ModelOutputError) as raised:
        _send_with_stdout(monkeypatch, stdout)              # SCHEMA is not the native schema: rejected
    error = raised.value
    assert error.failure_class == "schema_mismatch"
    assert error.stop_reason == "end_turn"
    assert error.usage == {"input_tokens": 2, "output_tokens": 910, "cache_tokens": 2234}
    assert error.raw_response == stdout and error.raw_response_truncated is False
    assert error.rejected_output == fixture["reply"]["result"]
    assert error.rejected_output.lstrip().startswith("```json")


def test_a_reply_stopped_at_the_output_budget_is_classified_truncated(monkeypatch) -> None:
    stdout = json.dumps({"type": "result", "subtype": "success", "is_error": False, "stop_reason": "max_tokens",
                         "usage": {"input_tokens": 1, "output_tokens": 4000}, "result": '{"schema": "' + SCHEMA})
    with pytest.raises(ModelOutputError) as raised:
        _send_with_stdout(monkeypatch, stdout)
    assert raised.value.failure_class == "truncated_output" and raised.value.stop_reason == "max_tokens"
    assert raised.value.usage == {"input_tokens": 1, "output_tokens": 4000, "cache_tokens": None}


@pytest.mark.parametrize("envelope", [
    {"stop_reason": "refusal", "is_error": False, "subtype": "success"},
    {"stop_reason": "end_turn", "is_error": True, "subtype": "success"},
    {"stop_reason": "end_turn", "is_error": False, "subtype": "error_during_execution"},
])
def test_a_declined_reply_is_classified_refusal(monkeypatch, envelope: dict) -> None:
    stdout = json.dumps({"type": "result", **envelope, "usage": {}, "result": "I will not answer this."})
    with pytest.raises(ModelOutputError) as raised:
        _send_with_stdout(monkeypatch, stdout)
    assert raised.value.failure_class == "refusal"


def test_retained_failed_reply_is_bounded_by_the_typed_output_budget_and_says_so(monkeypatch) -> None:
    long_reply = "x" * 2000
    stdout = json.dumps({"type": "result", "stop_reason": "end_turn", "usage": {}, "result": long_reply})
    assert retained_reply_bytes(100) == 800 and retained_reply_bytes(10 ** 9) == 2 * 1024 * 1024
    with pytest.raises(ModelOutputError) as raised:
        _send_with_stdout(monkeypatch, stdout, max_output_tokens=100)
    assert raised.value.raw_response_truncated is True
    assert len(raised.value.raw_response.encode("utf-8")) == 800
    assert raised.value.raw_response == stdout[:800]
    assert raised.value.rejected_output == long_reply      # the reply text itself keeps its own bound
    with pytest.raises(ModelOutputError) as whole:
        _send_with_stdout(monkeypatch, stdout, max_output_tokens=4000)
    assert whole.value.raw_response_truncated is False and whole.value.raw_response == stdout
