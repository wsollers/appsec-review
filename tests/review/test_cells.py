from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from appsec_review.inference import ModelOutputError, ModelResult, ReviewModelRequest
from appsec_review.review.capability import CellCapability
from appsec_review.review.cells import (
    TURN_SCHEMA, CellSpec, cell_fingerprint, reuse_or_run, run_cell,
)
from appsec_review.review.models import CellStatus, GapClass, IntegrityError, Lane, Role

MANIFEST = "1" * 64
SPAN = "asr:source_span:" + "a" * 64
SINK = "asr:source_span:" + "b" * 64
OUTSIDE = "asr:source_span:" + "f" * 64
LEAD = "asr:tool_observation:" + "c" * 64
SECRET_EXCERPT = "memcpy(dst, src, attacker_len); /* target text */"
GUIDANCE = "GOVERNING RULES TEXT that must never be copied into a receipt"


class FakeCore:
    """Same method names and response envelope shape as `RetrievalCore`."""

    manifest_sha256 = MANIFEST

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _envelope(self, tool: str, results: list[dict[str, Any]]) -> dict[str, Any]:
        return {"schema": "appsec-review/retrieval-response/1", "tool": tool, "run_id": "2026-10-12-0001",
                "index_manifest": {"schema": "x", "sha256": MANIFEST, "content_sha256": "2" * 64},
                "indexes": [], "results": results, "pagination": {"next_cursor": None},
                "coverage_gaps": [], "truncated": False, "duration_ms": 1}

    def search(self, **parameters):
        self.calls.append(("search", parameters))
        return self._envelope("search", [
            {"identity": SPAN, "kind": "source_span", "name": "copy", "payload": {}, "index": "source",
             "shard_id": "default", "location": {"path": "src/a.c", "start_line": 3, "end_line": 4}},
            {"identity": OUTSIDE, "kind": "source_span", "name": "other", "payload": {}, "index": "source",
             "shard_id": "default"},
        ])

    def read_excerpt(self, **parameters):
        self.calls.append(("read_excerpt", parameters))
        return self._envelope("read_excerpt", [
            {"identity": parameters["identity"], "kind": "source_span", "excerpt": SECRET_EXCERPT,
             "payload": {"calls": SINK}, "index": "source", "shard_id": "default"}])

    def find(self, **parameters):
        self.calls.append(("find", parameters))
        raise ValueError("invalid logical identifier")


class ScriptedInfer:
    def __init__(self, *script: Any) -> None:
        self.script = list(script)
        self.requests: list[ReviewModelRequest] = []

    def __call__(self, request: ReviewModelRequest, *, timeout_seconds: int) -> ModelResult:
        assert isinstance(request, ReviewModelRequest) and timeout_seconds == 60
        self.requests.append(request)
        step = self.script.pop(0)
        if isinstance(step, BaseException):
            raise step
        return ModelResult({"schema": TURN_SCHEMA, **step}, input_tokens=100, output_tokens=10)


def retrieve(*requests: dict[str, Any]) -> dict[str, Any]:
    return {"action": "retrieve", "requests": list(requests)}


def final(*cited: str) -> dict[str, Any]:
    return {"action": "final", "result": {"hypotheses": [{"entities": list(cited), "statement": "x"}]}}


def validate(result) -> list[str]:
    return [] if isinstance(result.get("hypotheses"), list) else ["hypotheses is required"]


def spec(**overrides) -> CellSpec:
    values = dict(
        manifest_sha256=MANIFEST, lane=Lane.HUNT, package_id="package-1", package_sha256="3" * 64,
        claim_id=None, role=Role.HYPOTHESIS_HUNTER, persona="native_memory_safety",
        stack_profile="c_cpp", strategy="sink_up", task="hunt/sink_up", task_input={"lead": LEAD},
        round=0, round_delta_sha256=None, evidence_set=(LEAD,), guidance_bundle_sha256="4" * 64,
        guidance_text=GUIDANCE, provider="claude-cli", model="claude-opus-5-5", reasoning="high",
        max_input_tokens=32000, max_output_tokens=8000, timeout_seconds=60,
        output_schema="appsec-review/red-result/1", validator_version="red-result-validator/1")
    values.update(overrides)
    return CellSpec(**values)


def capability(**overrides) -> CellCapability:
    values = dict(run_id="2026-10-12-0001", manifest_sha256=MANIFEST, package_id="package-1",
                  package_sha256="3" * 64, role=Role.HYPOTHESIS_HUNTER, round=0,
                  tools=("search", "read_excerpt", "find"), indexes=("source",),
                  entities=(SPAN, SINK, LEAD), entity_prefixes=(), max_queries=4, max_turns=4,
                  page_size=10, max_depth=2, max_result_bytes=16384)
    values.update(overrides)
    return CellCapability.issue(**values)


def run(tmp_path: Path, infer, *, cell_spec=None, cap=None, core=None, **retry):
    return run_cell(cell_spec or spec(), infer=infer, core=core or FakeCore(), capability=cap or capability(),
                    receipts_root=tmp_path / "cells", validate_final=validate, **retry)


def test_retrieve_then_final_succeeds_with_bounded_scoped_results(tmp_path: Path) -> None:
    core = FakeCore()
    infer = ScriptedInfer(
        retrieve({"tool": "search", "parameters": {"query": "memcpy"}}),
        retrieve({"tool": "read_excerpt", "parameters": {"identity": SPAN}}),
        final(SPAN, SINK, LEAD))
    outcome = run(tmp_path, infer, core=core)
    assert outcome.record.status is CellStatus.SUCCEEDED and outcome.record.attempts == 1
    assert outcome.result == final(SPAN, SINK, LEAD)["result"] and outcome.gaps == ()
    assert outcome.counts["queries"] == 2 and outcome.counts["turns"] == 3
    assert outcome.counts["input_tokens"] == 300 and outcome.counts["output_tokens"] == 30
    assert core.calls[0] == ("search", {"query": "memcpy", "indexes": ["source"], "limit": 10})
    # The application turn carries identities; the out-of-scope row is withheld, not shown.
    application = infer.requests[1].transcript[1]
    response = application["responses"][0]
    assert [row["identity"] for row in response["results"]] == [SPAN]
    assert response["withheld_out_of_scope"] == 1
    assert infer.requests[0].task_input["capability"]["tools"] == ["find", "read_excerpt", "search"]
    assert outcome.record.cell_id == cell_fingerprint(spec(), capability())
    receipt = json.loads(outcome.receipt_paths[0].read_text(encoding="utf-8"))
    assert receipt["status"] == "succeeded" and receipt["turns"][0]["retrievals"][0]["withheld_count"] == 1
    assert outcome.receipt_paths[0] == tmp_path / "cells" / outcome.record.cell_id / "attempt-1.json"


def test_receipts_hold_hashes_not_prompts_guidance_or_retrieved_text(tmp_path: Path) -> None:
    infer = ScriptedInfer(retrieve({"tool": "read_excerpt", "parameters": {"identity": SPAN}}), final(SPAN))
    outcome = run(tmp_path, infer)
    text = outcome.receipt_paths[0].read_text(encoding="utf-8")
    assert GUIDANCE not in text and SECRET_EXCERPT not in text and "memcpy" not in text
    turn = json.loads(text)["turns"][1]
    assert set(turn) >= {"request_sha256", "transcript_sha256", "response_sha256"}
    assert all(len(turn[key]) == 64 for key in ("request_sha256", "transcript_sha256", "response_sha256"))


def test_denials_become_authority_gaps_and_security_events_and_the_loop_continues(tmp_path: Path) -> None:
    infer = ScriptedInfer(
        retrieve({"tool": "read_excerpt", "parameters": {"identity": OUTSIDE}},
                 {"tool": "shell", "parameters": {"cmd": "cat /etc/passwd"}},
                 {"tool": "search", "parameters": {"query": "strcpy.*buf"}}),
        retrieve({"tool": "read_excerpt", "parameters": {"identity": SPAN}}),
        final(SPAN))
    outcome = run(tmp_path, infer)
    assert outcome.record.status is CellStatus.SUCCEEDED
    assert [gap.gap_class for gap in outcome.gaps] == [GapClass.AUTHORITY_ERROR] * 3
    assert set(outcome.record.gap_ids) == {gap.gap_id for gap in outcome.gaps}
    assert [event["denial_code"] for event in outcome.security_events] == [
        "entity_out_of_scope", "unknown_tool", "regex_like_value"]
    assert all("cat /etc/passwd" not in json.dumps(event) for event in outcome.security_events)
    responses = infer.requests[1].transcript[1]["responses"]
    assert [item["status"] for item in responses] == ["denied"] * 3
    assert outcome.counts["denials"] == 3 and outcome.counts["queries"] == 1


def test_tool_errors_are_coverage_gaps_not_failures(tmp_path: Path) -> None:
    infer = ScriptedInfer(retrieve({"tool": "find", "parameters": {"kind": "not_a_kind"}}), final())
    outcome = run(tmp_path, infer)
    assert outcome.record.status is CellStatus.SUCCEEDED
    assert [gap.gap_class for gap in outcome.gaps] == [GapClass.COVERAGE_GAP]


def test_at_the_turn_cap_the_next_turn_must_be_final(tmp_path: Path) -> None:
    search = {"tool": "search", "parameters": {"query": "copy"}}
    infer = ScriptedInfer(retrieve(search), retrieve(search), retrieve(search))
    outcome = run(tmp_path, infer, cap=capability(max_turns=3))
    assert outcome.record.status is CellStatus.TIMED_OUT
    assert [gap.gap_class for gap in outcome.gaps] == [GapClass.BUDGET_GAP]
    assert infer.requests[-1].transcript[-1]["final_required"] is True
    assert outcome.counts["turns"] == 3 and outcome.result is None


def test_query_cap_denies_extra_requests_and_then_requires_final(tmp_path: Path) -> None:
    search = {"tool": "search", "parameters": {"query": "copy"}}
    infer = ScriptedInfer(retrieve(search, search, search), final(SPAN))
    outcome = run(tmp_path, infer, cap=capability(max_queries=2))
    assert outcome.record.status is CellStatus.SUCCEEDED and outcome.counts["queries"] == 2
    assert [event["denial_code"] for event in outcome.security_events] == ["query_cap_exceeded"]
    assert infer.requests[1].transcript[1]["final_required"] is True


def test_citing_an_identity_not_seen_in_the_cell_is_a_schema_error(tmp_path: Path) -> None:
    infer = ScriptedInfer(final(SINK))      # in entity scope but never retrieved or packaged
    outcome = run(tmp_path, infer)
    assert outcome.record.status is CellStatus.INVALID and outcome.result is None
    assert [gap.gap_class for gap in outcome.gaps] == [GapClass.SCHEMA_ERROR]


@pytest.mark.parametrize("turn", [
    {"action": "final", "result": {"hypotheses": []}, "note": "extra"},
    {"action": "retrieve", "requests": []},
    {"action": "shell", "requests": []},
])
def test_malformed_turns_are_invalid(tmp_path: Path, turn) -> None:
    outcome = run(tmp_path, ScriptedInfer(turn))
    assert outcome.record.status is CellStatus.INVALID


def test_retry_creates_a_new_attempt_under_the_same_fingerprint_and_keeps_the_failed_receipt(tmp_path: Path) -> None:
    cap = capability()
    infer = ScriptedInfer(final(OUTSIDE), final(LEAD))
    outcome = run(tmp_path, infer, cap=cap, max_attempts=2, retry_on_invalid_output=True)
    assert outcome.record.status is CellStatus.SUCCEEDED and outcome.record.attempts == 2
    first, second = outcome.receipt_paths
    assert (first.name, second.name) == ("attempt-1.json", "attempt-2.json") and first.parent == second.parent
    assert json.loads(first.read_text(encoding="utf-8"))["status"] == "invalid"
    assert first.parent.name == outcome.record.cell_id == cell_fingerprint(spec(), cap)
    # The retry repairs; it never widens tools or caps.
    assert infer.requests[1].repair_errors and infer.requests[1].task_input == infer.requests[0].task_input
    assert outcome.gaps == ()


def test_invalid_output_is_not_retried_unless_enabled(tmp_path: Path) -> None:
    infer = ScriptedInfer(final(OUTSIDE), final(LEAD))
    outcome = run(tmp_path, infer, max_attempts=2, retry_on_invalid_output=False)
    assert outcome.record.status is CellStatus.INVALID and len(infer.requests) == 1


@pytest.mark.parametrize(("error", "status"), [
    (RuntimeError("Claude CLI exited 1"), CellStatus.FAILED),
    (TimeoutError("slow"), CellStatus.TIMED_OUT),
])
def test_provider_failures_are_worker_gaps_never_exceptions(tmp_path: Path, error, status) -> None:
    infer = ScriptedInfer(error, error)
    outcome = run(tmp_path, infer, max_attempts=2)
    assert outcome.record.status is status and outcome.record.attempts == 2
    assert [gap.gap_class for gap in outcome.gaps] == [GapClass.WORKER_GAP]
    assert len(outcome.receipt_paths) == 2


def test_unparseable_model_output_is_a_schema_error(tmp_path: Path) -> None:
    outcome = run(tmp_path, ScriptedInfer(ModelOutputError("no object")))
    assert outcome.record.status is CellStatus.INVALID
    assert [gap.gap_class for gap in outcome.gaps] == [GapClass.SCHEMA_ERROR]


def test_reuse_skips_inference_and_a_changed_validator_reruns(tmp_path: Path) -> None:
    first = run(tmp_path, ScriptedInfer(retrieve({"tool": "read_excerpt", "parameters": {"identity": SPAN}}),
                                        final(SPAN)))
    never = ScriptedInfer()
    reused = reuse_or_run(spec(), infer=never, core=FakeCore(), capability=capability(),
                          receipts_root=tmp_path / "cells", validate_final=validate)
    assert reused.reused and never.requests == [] and reused.result == first.result
    assert reused.record == first.record
    # A result the current validator rejects is not reused; the cell runs as a new attempt.
    again = ScriptedInfer(final(LEAD))
    rerun = reuse_or_run(spec(), infer=again, core=FakeCore(), capability=capability(),
                         receipts_root=tmp_path / "cells", validate_final=lambda result: ["stricter"])
    assert not rerun.reused and len(again.requests) == 1 and rerun.record.attempts == 2


def test_tampered_receipt_is_an_integrity_error(tmp_path: Path) -> None:
    outcome = run(tmp_path, ScriptedInfer(final(LEAD)))
    path = outcome.receipt_paths[0]
    receipt = json.loads(path.read_text(encoding="utf-8"))
    receipt["result"]["hypotheses"] = []
    path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(IntegrityError):
        reuse_or_run(spec(), infer=ScriptedInfer(), core=FakeCore(), capability=capability(),
                     receipts_root=tmp_path / "cells", validate_final=validate)


def test_capability_or_core_bound_to_another_cell_is_an_integrity_error(tmp_path: Path) -> None:
    with pytest.raises(IntegrityError):
        run(tmp_path, ScriptedInfer(), cap=capability(package_id="package-2"))
    core = FakeCore()
    core.manifest_sha256 = "9" * 64
    with pytest.raises(IntegrityError):
        run(tmp_path, ScriptedInfer(), core=core)


def test_fingerprint_tracks_semantic_inputs_but_not_capacity() -> None:
    base = cell_fingerprint(spec(), capability())
    for changed in (spec(evidence_set=(LEAD, SPAN)), spec(guidance_bundle_sha256="5" * 64),
                    spec(model="claude-sonnet-5"), spec(provider="anthropic-api"),
                    spec(validator_version="red-result-validator/2"), spec(task_input={"lead": SPAN}),
                    spec(round_delta_sha256="6" * 64), spec(persona="")):
        assert cell_fingerprint(changed, capability()) != base
    assert cell_fingerprint(spec(), capability(max_queries=5)) != base
    assert cell_fingerprint(spec(), capability(tools=("search",))) != base
    # Run identity is not semantic, and neither is evidence ordering; retry and concurrency
    # settings are not fingerprint inputs at all.
    assert cell_fingerprint(spec(), capability(run_id="2026-10-13-0002")) == base
    assert cell_fingerprint(spec(evidence_set=(LEAD, LEAD)), capability()) == base
    assert set(cell_fingerprint.__code__.co_varnames[:cell_fingerprint.__code__.co_argcount]) == {
        "spec", "capability"}
    assert not {"workers", "review_teams", "max_attempts", "pool"} & set(CellSpec.__dataclass_fields__)


def test_retry_settings_do_not_change_the_cell_id(tmp_path: Path) -> None:
    one = run(tmp_path / "a", ScriptedInfer(final(LEAD)), max_attempts=1)
    three = run(tmp_path / "b", ScriptedInfer(final(LEAD)), max_attempts=3, retry_on_invalid_output=True)
    assert one.record.cell_id == three.record.cell_id
