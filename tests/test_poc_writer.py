"""The poc_writer turn: request, in-process retrieval, repair, declines, receipts and pinned guidance.

The model is a scripted ``Infer`` double (the live transport is not exercised here). The assertions are on
what the application sends (no tools, a closed turn protocol, hash-pinned guidance), what it accepts and what
it records.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess

import pytest

from appsec_review.guidance import GuidanceError
from appsec_review.guidance.skills import load_runtime_skill
from appsec_review.inference import ModelOutputError, ModelResult, ReviewModelRequest
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_poc_generation import writer
from appsec_review.jobs.job_poc_generation.brief import Brief
from appsec_review.jobs.job_poc_generation.buildctx import Headers, declarations
from appsec_review.jobs.job_poc_generation.settings import PocGenerationSettings
from tests import poc_support
from tests.fixtures.poc_generation import relay

ROOT = Path(__file__).parents[1]
SCHEMAS = SchemaSet(ROOT / "docs" / "schemas" / "poc-generation")
SETTINGS = poc_support.settings()
CLAIM = "claim-" + "7" * 64
BRIEF = Brief({"schema": "appsec-review/poc-writer-brief/1", "sink": {"name": relay.SINK}}, {}, (relay.SINK,), ())


class Script:
    """A scripted model: each call pops the next proposal (or raises the next exception)."""

    def __init__(self, *turns) -> None:
        self.turns, self.requests = list(turns), []

    def __call__(self, request, *, timeout_seconds):
        self.requests.append((request, timeout_seconds))
        turn = self.turns.pop(0)
        if isinstance(turn, BaseException):
            raise turn
        return ModelResult(proposal=turn, input_tokens=100, output_tokens=20, raw_response=json.dumps(turn))


def retrieve(*requests) -> dict:
    return {"action": "retrieve", "requests": list(requests)}


@pytest.fixture()
def reader(tmp_path):
    workspace, manifest = poc_support.relay_workspace(tmp_path / "w")
    unit = poc_support.relay_unit(workspace, manifest)
    headers = Headers(unit)
    return writer.WorkspaceReader(
        workspace, manifest, headers.search_directories(),
        lambda name: declarations(unit, headers, [name], source_bytes=65536, max_files=10, max_lines=30))


@pytest.fixture()
def guidance(tmp_path):
    return writer.load_guidance(ROOT, tmp_path / "run", "job_poc_generation", SETTINGS.writer)


def run(script, reader, guidance, settings=SETTINGS):
    return writer.run_writer(BRIEF, guidance=guidance, settings=settings, infer=script, reader=reader,
                             schemas=SCHEMAS, claim_id=CLAIM)


def with_models(**changes) -> PocGenerationSettings:
    table = deepcopy(poc_support.settings_table())
    for key, value in changes.items():
        if key.startswith("retry_"):
            table["retry"][key] = value
        elif key == "max_attempts":
            table["retry"]["max_attempts"] = value
        else:
            table["models"]["default"][key] = value
    return PocGenerationSettings.from_mapping(table)


# --------------------------------------------------------------------------------------------- the request


def test_one_final_turn_is_the_answer_and_the_request_grants_no_tools(reader, guidance) -> None:
    script = Script(relay.answer())
    outcome = run(script, reader, guidance)
    assert outcome.status == "answered" and outcome.result["test_function"]["name"] == relay.TEST_NAME
    (request, timeout), = script.requests
    assert isinstance(request, ReviewModelRequest) and timeout == SETTINGS.writer.timeout_seconds
    assert (request.role, request.persona, request.stack_profile) == ("poc_writer", "", "")
    assert request.schema == writer.TURN_SCHEMA and request.guidance_bundle_sha256 == guidance.sha256
    assert (request.provider, request.model) == ("claude-cli", "claude-haiku-5-5")
    assert request.cell_id == f"poc-writer:{CLAIM}" and request.transcript == ()
    protocol = request.task_input["turn_protocol"]
    assert [tool["name"] for tool in protocol["tool_catalog"]] == ["read_source", "find_declaration"]
    assert protocol["actions"] == ["retrieve", "final"] and request.task_input["protocol"] == "poc-writer/1"
    assert request.task_input["input"]["sink"]["name"] == relay.SINK
    assert not hasattr(request, "tools")


def test_the_guidance_is_the_shared_rules_the_role_and_the_runtime_skill_only(guidance, tmp_path) -> None:
    text = guidance.text
    assert "Review-worker governing rules" in text and "# Role: Proof-of-Concept Writer" in text
    assert "# Writing a proof-of-concept function" in text
    for forbidden in ("AGENTS.md", "Repository Agent Guidance", "multi-session-coordination", "docs-sync"):
        assert forbidden not in text
    pinned = tmp_path / "run" / "data" / "guidance" / guidance.sha256
    assert sorted(path.name for path in pinned.iterdir()) == ["governing-rules.md", "model-identity.json",
                                                              "role.md", "skill.md"]
    again = writer.load_guidance(ROOT, tmp_path / "run", "job_poc_generation", SETTINGS.writer)
    assert again.sha256 == guidance.sha256
    other = writer.load_guidance(ROOT, tmp_path / "run", "job_poc_generation",
                                 with_models(model="claude-opus-9").writer)
    assert other.sha256 != guidance.sha256                                  # the model identity is part of the pin
    (pinned / "skill.md").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="changed after pinning"):
        writer.load_guidance(ROOT, tmp_path / "run", "job_poc_generation", SETTINGS.writer)


def test_the_skill_is_loadable_only_by_this_job() -> None:
    assert load_runtime_skill(ROOT, "poc-writer", job_id="job_poc_generation").name == "poc-writer"
    with pytest.raises(GuidanceError, match="not allowed"):
        load_runtime_skill(ROOT, "poc-writer", job_id="job_inference_security_review")


# ------------------------------------------------------------------------------------------ retrieval turns


def test_the_application_answers_source_and_declaration_requests_in_process(reader, guidance) -> None:
    script = Script(
        retrieve({"tool": "find_declaration", "parameters": {"name": "Header"}},
                 {"tool": "read_source", "parameters": {"path": "src/packet.cpp", "start_line": 7, "end_line": 9}}),
        relay.answer())
    outcome = run(script, reader, guidance)
    assert outcome.status == "answered"
    second, _ = script.requests[1]
    worker, application = second.transcript
    assert worker["from"] == "worker" and worker["content"]["action"] == "retrieve"
    declaration, source = application["responses"]
    assert declaration["status"] == "ok" and any("char name[16];" in line for row in declaration["rows"]
                                                  for line in row["text"])
    assert source["lines"] == "7-9" and source["text"][0].startswith("7| int parse_header(")
    assert application["remaining_queries"] == SETTINGS.writer.max_queries - 2
    attempt = outcome.attempts[0]
    assert attempt.queries == 2 and [t["action"] for t in attempt.turns] == ["retrieve", "final"]


@pytest.mark.parametrize("request_", [
    {"tool": "shell", "parameters": {"command": "id"}},
    {"tool": "read_source", "parameters": {"path": "../../etc/passwd", "start_line": 1, "end_line": 5}},
    {"tool": "read_source", "parameters": {"path": "/etc/passwd", "start_line": 1, "end_line": 5}},
    {"tool": "read_source", "parameters": {"path": "src/missing.cpp", "start_line": 1, "end_line": 5}},
    {"tool": "read_source", "parameters": {"path": "src/packet.cpp", "start_line": 1, "end_line": 5000}},
    {"tool": "read_source", "parameters": {"path": "src/packet.cpp"}},
    {"tool": "find_declaration", "parameters": {"name": ""}},
    {"tool": "find_declaration"},
    "not an object",
])
def test_a_denied_request_is_feedback_with_the_corrected_shape_not_a_failure(reader, guidance, request_) -> None:
    script = Script(retrieve(request_), relay.answer())
    outcome = run(script, reader, guidance)
    assert outcome.status == "answered"
    response = script.requests[1][0].transcript[1]["responses"][0]
    assert response["status"] == "denied" and response["code"] and response["corrected"]["tool"] in writer.TOOLS
    assert outcome.attempts[0].denials == 1


def test_the_second_identical_denial_ends_the_attempt(reader, guidance) -> None:
    bad = {"tool": "shell", "parameters": {"command": "id"}}
    script = Script(retrieve(bad), retrieve(bad), relay.answer())
    outcome = run(script, reader, guidance, with_models(max_attempts=1))
    assert outcome.status == "failed" and "repeated_denial" in outcome.reason and len(script.requests) == 2


def test_the_query_and_turn_caps_force_a_final_answer(reader, guidance) -> None:
    ask = retrieve({"tool": "find_declaration", "parameters": {"name": "Header"}})
    script = Script(ask, ask, ask)
    outcome = run(script, reader, guidance, with_models(max_turns=2, max_attempts=1))
    assert outcome.status == "failed" and "cap_reached_without_final" in outcome.reason
    assert script.requests[-1][0].transcript[-1]["final_required"] is True or len(script.requests) == 2
    spent = Script(retrieve(*[{"tool": "find_declaration", "parameters": {"name": "Header"}}] * 3), relay.answer())
    outcome = run(spent, reader, guidance, with_models(max_queries=2))
    responses = spent.requests[1][0].transcript[1]["responses"]
    assert [item["status"] for item in responses] == ["ok", "ok", "denied"] and responses[2]["code"] == "query_cap_exceeded"
    assert outcome.status == "answered"


def test_the_workspace_reader_is_path_scoped_and_hash_checked(tmp_path) -> None:
    workspace, manifest = poc_support.relay_workspace(tmp_path / "w")
    scoped = writer.WorkspaceReader(workspace, manifest, ["include"], lambda name: [])
    assert scoped.read_source("include/relay/relay.hpp", 9, 10)["text"][0] == "9| struct Header {"
    assert scoped.read_source("src/packet.cpp", 1, 3) is None                    # outside the allowed directories
    assert scoped.read_source("include/relay/missing.hpp", 1, 3) is None        # not in the manifest
    (workspace / "include" / "relay" / "relay.hpp").write_text("changed\n", encoding="utf-8")
    assert scoped.read_source("include/relay/relay.hpp", 1, 1) is None           # no longer the accepted bytes


# ------------------------------------------------------------------------------------------------ outcomes


def test_a_schema_invalid_final_is_repaired_once_and_the_errors_are_sent(reader, guidance) -> None:
    broken = deepcopy(relay.answer())
    del broken["result"]["negative_control"]
    script = Script(broken, relay.answer())
    outcome = run(script, reader, guidance)
    assert outcome.status == "answered" and [a.status for a in outcome.attempts] == ["invalid", "answered"]
    repair = script.requests[1][0].repair_errors
    assert repair and any("negative_control" in item for item in repair)
    assert outcome.attempts[0].reason == "final_result_rejected"


def test_the_name_main_is_not_a_schema_error_so_the_writer_cannot_repair_its_way_past_the_validators(reader, guidance) -> None:
    script = Script(relay.answer(test_name="main"))
    outcome = run(script, reader, guidance)
    assert outcome.status == "answered" and outcome.result["test_function"]["name"] == "main"
    assert len(script.requests) == 1


def test_a_decline_is_a_terminal_outcome_with_its_status(reader, guidance) -> None:
    script = Script({"action": "final", "result": {"decline": {"status": "unsafe_to_attempt", "why": "needs a socket"}}})
    outcome = run(script, reader, guidance)
    assert outcome.status == "declined" and outcome.result["decline"]["status"] == "unsafe_to_attempt"
    refused = Script({"action": "final", "result": {"decline": {"status": "policy_denied", "why": "x"}}},
                     {"action": "final", "result": {"decline": {"status": "not_applicable", "why": "x"}}})
    outcome = run(refused, reader, guidance)
    assert outcome.status == "declined" and len(refused.requests) == 2        # the writer may not pick a status


@pytest.mark.parametrize(("failure", "retried", "reason"), [
    (ModelOutputError("no json"), True, "model_output_unparseable"),
    (TimeoutError("slow"), True, "provider_timeout"),
    (subprocess.TimeoutExpired("claude", 5), True, "provider_timeout"),
    (RuntimeError("boom"), True, "provider_error:RuntimeError"),
])
def test_provider_failures_are_named_and_retried_per_policy(reader, guidance, failure, retried, reason) -> None:
    script = Script(failure, failure)
    outcome = run(script, reader, guidance)
    assert outcome.status == "failed" and reason in outcome.reason and len(script.requests) == 2
    once = Script(failure, relay.answer())
    outcome = run(once, reader, guidance, with_models(max_attempts=1))
    assert outcome.status == "failed" and len(once.requests) == 1
    table = deepcopy(poc_support.settings_table())
    for key in ("retry_on_timeout", "retry_on_provider_error", "retry_on_invalid_output"):
        table["retry"][key] = False
    never = Script(failure, relay.answer())
    outcome = run(never, reader, guidance, PocGenerationSettings.from_mapping(table))
    assert outcome.status == "failed" and len(never.requests) == 1
    assert retried


def test_malformed_turns_are_invalid_and_repairable(reader, guidance) -> None:
    for turn in ({"action": "final"}, {"action": "retrieve", "requests": []}, {"action": "think"},
                 {"schema": "other/1", "action": "final", "result": {}}, ["not", "a", "turn"]):
        script = Script(turn, relay.answer())
        outcome = run(script, reader, guidance)
        assert outcome.status == "answered" and outcome.attempts[0].reason == "malformed_turn", turn
        assert script.requests[1][0].repair_errors


def test_the_receipt_holds_hashes_and_counts_never_prompts_or_source(reader, guidance) -> None:
    outcome = run(Script(relay.answer()), reader, guidance)
    receipt = outcome.receipt(CLAIM, "a" * 64, guidance.sha256, SETTINGS.writer)
    assert receipt["schema"] == writer.RECEIPT_SCHEMA and receipt["guidance_bundle_sha256"] == guidance.sha256
    assert receipt["model"]["model"] == "claude-haiku-5-5" and receipt["result_sha256"]
    (attempt,) = receipt["attempts"]
    assert attempt["status"] == "answered" and attempt["input_tokens"] == 100 and attempt["output_tokens"] == 20
    text = json.dumps(receipt)
    assert "memset" not in text and "parse_header" not in text and "Proof-of-concept" not in text
    assert all(len(turn["request_sha256"]) == 64 and len(turn["response_sha256"]) == 64 for turn in attempt["turns"])
