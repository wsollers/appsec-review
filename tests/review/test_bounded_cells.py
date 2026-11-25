from dataclasses import replace
import json
import shutil

import pytest

from appsec_review.inference import ModelResult
from appsec_review.inference.errors import ModelCancelled, ProviderError
from appsec_review.review.models import CellStatus, GapClass, IntegrityError
from tests.review.test_cells import (
    LEAD, FakeCore, ScriptedInfer, capability, final, run, spec,
)
from tests.test_bounded_execution import Clock


def test_alternate_cpg_uses_analysis_and_admits_only_scoped_rows():
    from appsec_review.review.capability import Authorized
    from appsec_review.review.cells import _bound

    tools = ("query_call_paths", "query_cpg_slice")
    cap = capability(tools=tools, indexes=("analysis",))
    for tool, args in ((tools[0], {"source": "parse"}), (tools[1], {"function_name": "parse"})):
        assert isinstance(cap.authorize({"tool": tool, "parameters": args}), Authorized)
        graph_only = capability(tools=tools, indexes=("graph",))
        assert graph_only.authorize({"tool": tool, "parameters": args}).code == "index_not_granted"
    packages = {"io/parse.py"}
    node = {"record_type": "cpg_node", "path": "io/parse.py"}
    path = {"record_type": "cpg_path", "hops": [{"path": "io/parse.py"}]}
    outside = {"record_type": "cpg_path", "hops": [*path["hops"], {"path": "other.py"}]}
    for tool, allowed, denied in ((tools[0], path, outside), (tools[1], node, {**node, "path": "other.py"})):
        result, withheld = _bound(tool, {"results": [allowed, denied]}, cap, locator_paths=packages)
        assert (result["results"], withheld) == ([allowed], 1)


def test_accepted_view_permits_cross_package_evidence_not_citations_from_target_text():
    from appsec_review.review.capability import Authorized
    from appsec_review.review.cells import _bind, _bound
    from tests.review.test_cells import OUTSIDE, SINK

    core = FakeCore()
    core.run_id = "2026-10-12-0001"
    core.read_view_sha256 = "4" * 64
    cap = capability(read_view_sha256=core.read_view_sha256, entities=(LEAD,))
    _bind(spec(), cap, core)
    locator = {"tool": "find", "parameters": {"locator": {"path": "another/pkg.py", "line": 7}}}
    assert isinstance(cap.authorize(locator), Authorized)
    assert capability().authorize(locator).code == "entity_out_of_scope"
    assert isinstance(cap.authorize({"tool": "read_excerpt", "parameters": {"identity": OUTSIDE}}), Authorized)
    row = {"index": "source", "kind": "source_span", "identity": OUTSIDE,
           "payload": {"untrusted_comment": SINK}}
    granted = set()
    result, withheld = _bound("find", {"results": [row]}, cap, granted=granted)
    assert result["results"] == [row] and not withheld
    assert granted == {OUTSIDE}
    assert not cap.entity_in_scope(SINK)
    relation = {"index": "source", "source_id": OUTSIDE, "target_id": SINK}
    foreign = {**relation, "index": "binary"}
    response = {"results": [{"entity": row, "relationships": [relation, foreign]}]}
    resolved, withheld = _bound("resolve_evidence", response, cap)
    assert withheld == 1
    assert resolved["results"] == [{"entity": row, "relationships": [relation]}]
    for field, other in (("read_view_sha256", "5" * 64), ("run_id", "other-run")):
        original = getattr(core, field)
        setattr(core, field, other)
        with pytest.raises(IntegrityError, match="different accepted run or read view"):
            _bind(spec(), cap, core)
        setattr(core, field, original)


def test_oversized_first_scoped_row_is_diagnosed_without_leaking_its_bytes():
    from appsec_review.review.cells import _bound
    row = {"identity": LEAD, "name": "private-row-value" * 500}
    cap = capability(max_result_bytes=640)
    result, withheld = _bound("find", {"results": [row], "pagination": {"next_cursor": "past-row"}}, cap)
    assert not withheld and result["truncated"] and result["results"] == [] and result["next_cursor"] is None
    diagnostic = result["oversized_item"]
    assert diagnostic["item_bytes"] == len(json.dumps(row, sort_keys=True).encode())
    assert diagnostic["limit_bytes"] == 640 and diagnostic["hint"]
    assert "private-row-value" not in json.dumps(result) and len(json.dumps(result).encode()) <= 640


def test_coverage_metadata_alone_does_not_drop_the_row_or_mark_it_truncated():
    from appsec_review.review.cells import _bound
    row = {"identity": LEAD}
    cap = capability(max_result_bytes=640)
    result, _ = _bound("find", {"results": [row], "coverage_gaps": [str(i) * 200 for i in range(25)]}, cap)
    assert result["results"] == [row] and result["gaps_truncated"] and not result["truncated"]
    assert len(json.dumps(result).encode()) <= 640


def test_review_backoff_consumes_deadline_without_resetting_usage_or_receipts(tmp_path):
    clock = Clock()
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append((clock(), timeout_seconds))
        if len(calls) == 1:
            raise ProviderError("temporary", retryable=True)
        return ModelResult({"schema": request.schema, **final(LEAD)}, 100, 10)

    outcome = run(tmp_path, infer, max_attempts=2, backoff_seconds=(3,),
                  clock=clock, sleep=clock.sleep)
    assert calls == [(0, 60), (pytest.approx(3), 57)]
    assert outcome.record.status is CellStatus.SUCCEEDED
    assert len(outcome.receipt_paths) == 2
    first, second = [json.loads(path.read_text()) for path in outcome.receipt_paths]
    assert first["turns"][0]["execution"]["failure_category"] == "provider"
    assert second["turns"][0]["execution"]["retry_reason"] == "provider"
    assert first["counts"]["input_tokens"] is None
    assert second["counts"]["input_tokens"] == 100
    assert outcome.counts["input_tokens"] is None


def test_retry_backoff_cannot_extend_cell_deadline(tmp_path):
    clock = Clock()
    infer = ScriptedInfer(ProviderError("temporary", retryable=True))
    outcome = run(tmp_path, infer, max_attempts=3, backoff_seconds=(61,),
                  clock=clock, sleep=clock.sleep)
    assert len(infer.requests) == 1
    assert outcome.record.status is CellStatus.TIMED_OUT
    assert outcome.gaps[-1].gap_class is GapClass.BUDGET_GAP
    assert json.loads(outcome.receipt_paths[-1].read_text())["turns"] == []


def test_nontransient_provider_failure_never_retries(tmp_path):
    infer = ScriptedInfer(ProviderError("authentication failed"), final(LEAD))
    outcome = run(tmp_path, infer, max_attempts=3)
    assert outcome.record.status is CellStatus.FAILED
    assert len(infer.requests) == 1


@pytest.mark.parametrize("error", [RuntimeError("bug"), TypeError("bad contract"), IntegrityError("bad evidence")])
def test_programming_and_integrity_errors_propagate_with_receipt(tmp_path, error):
    infer = ScriptedInfer(error)
    with pytest.raises(type(error)) as raised:
        run(tmp_path, infer, max_attempts=3)
    assert raised.value is error and len(infer.requests) == 1
    [path] = list((tmp_path / "cells").glob("*/attempt-*.json"))
    receipt = json.loads(path.read_text())
    assert receipt["reason"] == f"execution_contract_error:{type(error).__name__}"
    assert receipt["turns"][0]["execution"]["failure_category"] == "contract"


def test_cancel_during_call_and_backoff_preserves_prior_attempts(tmp_path):
    with pytest.raises(ModelCancelled):
        run(tmp_path, ScriptedInfer(ModelCancelled("stop")), max_attempts=3)
    [path] = list((tmp_path / "cells").glob("*/attempt-*.json"))
    assert json.loads(path.read_text())["reason"] == "run_stopped"
    clock = Clock()

    def cancel_wait(seconds):
        raise ModelCancelled("stop waiting")

    with pytest.raises(ModelCancelled):
        run(tmp_path / "wait", ScriptedInfer(ProviderError("temporary", retryable=True)),
            max_attempts=3, backoff_seconds=(1,), clock=clock, sleep=cancel_wait)
    paths = list((tmp_path / "wait" / "cells").glob("*/attempt-*.json"))
    assert len(paths) == 2
    assert json.loads(paths[-1].read_text())["reason"] == "run_stopped"


@pytest.mark.parametrize("value", [None, -1, True, "100", 3.5])
def test_cell_missing_invalid_usage_is_unknown_not_zero(tmp_path, value):
    outcome = run(tmp_path, lambda request, **kw: ModelResult(
        {"schema": request.schema, **final(LEAD)}, input_tokens=value, output_tokens=7))
    assert outcome.record.status is CellStatus.SUCCEEDED
    assert outcome.counts["input_tokens"] is None and outcome.counts["output_tokens"] == 7
    turn = json.loads(outcome.receipt_paths[0].read_text())["turns"][0]
    assert turn["input_tokens"] is None


def test_cell_replay_and_no_evidence_answer_are_not_new_spend(tmp_path):
    outcome = run(tmp_path, lambda request, **kw: ModelResult(
        {"schema": request.schema, **final()}, 100, 20, usage_source="replay"))
    assert outcome.record.status is CellStatus.SUCCEEDED
    assert outcome.result == final()["result"]
    assert outcome.counts["input_tokens"] == 0 and outcome.counts["output_tokens"] == 0
    turn = json.loads(outcome.receipt_paths[0].read_text())["turns"][0]
    assert turn["replayed_usage"]["input_tokens"] == 100
    assert turn["usage_source"] == "replay"


def test_cell_input_and_output_bounds_prevent_unbounded_transcript(tmp_path):
    infer = ScriptedInfer(final(LEAD))
    outcome = run(tmp_path, infer, cell_spec=replace(spec(), task_input={"text": "x" * 128_000}))
    assert not infer.requests
    assert outcome.record.status is CellStatus.TIMED_OUT
    assert outcome.gaps[-1].gap_class is GapClass.BUDGET_GAP
    result = {"schema": "appsec-review/worker-turn/1", **final(LEAD)}
    result["result"]["text"] = "x" * 64_001
    outcome = run(tmp_path / "output", lambda *a, **kw: ModelResult(result, 10, 10))
    assert outcome.record.status is CellStatus.INVALID
    assert outcome.counts["input_tokens"] == 10


def test_first_error_mode_preserves_one_failed_receipt_and_no_retry(tmp_path, monkeypatch):
    from appsec_review.runtime import execution_safety as safety
    monkeypatch.setattr(safety, "active", lambda: True)
    infer = ScriptedInfer(ProviderError("temporary", retryable=True), final(LEAD))
    with pytest.raises(safety.ReviewStopped):
        run(tmp_path, infer, max_attempts=3)
    assert len(infer.requests) == 1
    assert len(list((tmp_path / "cells").glob("*/attempt-*.json"))) == 1


def test_recorded_timeout_replays_through_real_cell_retries_without_billing(tmp_path, monkeypatch):
    from appsec_review.inference.recording import (
        MODE_ENVIRONMENT, RECORDINGS, REPLAY_ENVIRONMENT, recorded, unit_scope,
    )
    from appsec_review.inference.execution import CallContext
    from appsec_review.observability.events import PipelineLog

    first_root, replay_root = tmp_path / "record", tmp_path / "replay-run"
    provider = ScriptedInfer(TimeoutError("bounded timeout"), final(LEAD))
    monkeypatch.setenv(MODE_ENVIRONMENT, "record")
    with unit_scope(run_root=first_root, job_id="job_inference_security_review",
                    repository_root=None, target_root=None):
        first = run(first_root, recorded(provider), max_attempts=2)
    assert first.record.status is CellStatus.SUCCEEDED and len(provider.requests) == 2
    recordings = first_root / RECORDINGS
    replay_copy = tmp_path / "recording-copy"
    shutil.copytree(recordings, replay_copy)
    monkeypatch.setenv(MODE_ENVIRONMENT, "replay")
    monkeypatch.setenv(REPLAY_ENVIRONMENT, str(replay_copy))

    def never(*args, **kwargs):
        pytest.fail("replay must not call a provider")

    with unit_scope(run_root=replay_root, job_id="job_inference_security_review",
                    repository_root=None, target_root=None):
        replay = run(replay_root, recorded(never), max_attempts=2,
                     execution_context=CallContext(replay_root, "run", "job_inference_security_review", "attempt"))
    assert replay.result == first.result and len(replay.receipt_paths) == 2
    assert replay.counts["input_tokens"] == replay.counts["output_tokens"] == 0
    events, _ = PipelineLog(replay_root).read()
    completed = [row["details"] for row in events if row["event_type"] == "MODEL_CALL_COMPLETED"]
    assert completed[0]["terminal_status"] == "TIMED_OUT"
    assert all(row["execution_mode"] == "replay" and row["input_tokens"] is None for row in completed)


def test_query_receipt_reports_timeout_and_bounds_without_changing_hashes(tmp_path):
    from tests.review.test_cells import retrieve

    class Core(FakeCore):
        duration = 0

        def search(self, *, query, **kw):
            rows = ({"timeout": [], "oversized": [{"text": "x" * 1500}],
                     "narrow": [{"text": "y" * 270}] * 3})[query]
            return {**self._envelope("search", rows), "status": "timeout" if query == "timeout" else "ok",
                    "coverage_gaps": [str(i) for i in range(25)], "duration_ms": self.duration}

    receipts = []
    for ms in (11, 17):
        core = Core()
        core.duration = ms
        infer = ScriptedInfer(retrieve(*({"tool": "search", "parameters": {"query": term}}
                                         for term in ("timeout", "oversized", "narrow"))), final(LEAD))
        outcome = run(tmp_path / str(ms), infer, core=core, cap=capability(max_result_bytes=640))
        assert outcome.record.status is CellStatus.SUCCEEDED
        turns = json.loads(outcome.receipt_paths[0].read_text())["turns"]
        call, oversized, narrow = turns[0]["retrievals"]
        assert (call["status"], call["duration_ms"], call["gaps_truncated"]) == ("timeout", ms, True)
        shown = infer.requests[1].transcript[-1]["responses"]
        assert shown[0]["status"] == "ok" and all("duration_ms" not in item for item in shown)
        assert oversized["status"] == "executed" and oversized["oversized_item"] == shown[1]["oversized_item"]
        assert oversized["oversized_item"]["item_bytes"] > 640 and not oversized["narrowing_hint_emitted"]
        assert narrow["oversized_item"] is None and narrow["narrowing_hint_emitted"] and shown[2]["narrowing_hint"]
        assert not turns[0]["catalog_deduped"] and turns[1]["catalog_deduped"]
        assert 0 < turns[0]["tool_catalog_bytes"] < turns[0]["prompt_bytes"]
        receipts.append(([item["response_sha256"] for item in turns[0]["retrievals"]],
                         turns[1]["request_sha256"], turns[1]["transcript_sha256"], outcome.record.cell_id))
    assert receipts[0] == receipts[1]


def test_query_receipt_counts_only_omissions_on_visible_syntax_results(tmp_path):
    from tests.review.test_cells import OUTSIDE, SPAN, retrieve

    file_id = "asr:source_file:" + "a" * 64

    class Core(FakeCore):
        def query_syntax(self, **kw):
            return self._envelope("query_syntax", [
                {"identity": ref, "payload": {"syntax": {"capture_bytes_omitted": n, "qualifiers_omitted": q}}}
                for ref, n, q in ((SPAN, 12, 0), (SPAN, 4, 2), (OUTSIDE, 8000, 30))])

    infer = ScriptedInfer(retrieve({"tool": "query_syntax", "parameters": {"mode": "calls", "subject": file_id}},
                                   {"tool": "search", "parameters": {"query": "copy"}}), final())
    cap = capability(entities=(file_id, SPAN), tools=("query_syntax", "search"), indexes=("analysis", "source"))
    outcome = run(tmp_path, infer, core=Core(), cap=cap)
    syntax, plain = json.loads(outcome.receipt_paths[0].read_text())["turns"][0]["retrievals"]
    assert (syntax["result_count"], syntax["withheld_count"], syntax["capture_bytes_omitted"],
            syntax["qualifiers_omitted"]) == (2, 1, 16, 2)
    assert "capture_bytes_omitted" not in plain and "qualifiers_omitted" not in plain


def test_admission_summary_uses_real_grant_and_bundle_without_affecting_cell_identity(tmp_path):
    from collections import Counter
    from types import SimpleNamespace
    from appsec_review.guidance.cards import review_query_sources
    from appsec_review.jobs.job_inference_security_review.teams import PackageWork, ReviewContext, _cell
    from appsec_review.review.cells import cell_fingerprint
    from appsec_review.review.models import Lane, Role
    from tests.review.test_cells import view_for

    class Core(FakeCore):
        def dataset_inventory(self, indexes):
            return {"analysis": [{"shard_id": "alternate-cpg", "producer": {"kind": "alternate_cpg"},
                                  "sha256": "3" * 64, "entity_count": 2, "coverage_gaps": []}]}

    core, role = Core(), Role.BLUE_TEAM_REFUTER
    populations = []

    def bundle(*, capability, population, **kw):
        populations.append(population)
        sources = list(review_query_sources(capability.tools, population))
        return {"text": "guidance", "bundle": {"sha256": "4" * 64, "sections": [
            {"name": "procedures", "items": [{"id": "base-skill"}, {"id": "selected-skill"}]},
            {"name": "receipt", "capability": {"query_sources": sources,
                                              "query_procedures": {"selected-skill": sources}}}]}}

    profile = SimpleNamespace(max_queries=4, max_turns=4, provider="provider", model="model", reasoning="high",
                              timeout_seconds=60, max_input_tokens=32000, max_output_tokens=8000)
    ctx = SimpleNamespace(core=core, role_tools={role.value: ("query_syntax", "query_cpg_slice", "unknown")},
                          run_id="run", schemas=SimpleNamespace(errors=lambda *_: []), profile=lambda _: profile,
                          index_names=("analysis", "graph"), max_page_size=10, max_depth=2, bundle=bundle)
    ctx.review_grant = ReviewContext.review_grant.__get__(ctx)
    work = PackageWork("p", Lane.LEAD, "1" * 64, {}, (1, "p"), "2" * 64, (LEAD,), None)
    cell = _cell(ctx, work, {"stack": "generic"}, role=role, persona="generalist", task="review", kind="blue",
                 task_input={}, claim=SimpleNamespace(claim_id="claim"), view=view_for())
    infer = ScriptedInfer(final())
    # Run a schema-neutral final to isolate the admission receipt, rather than a second role-verdict test.
    outcome = run(tmp_path, infer, core=core, cell_spec=replace(cell.spec, expand=None), cap=cell.capability)
    receipt = json.loads(outcome.receipt_paths[0].read_text())
    counts = dict(Counter(row["availability"] for row in populations[0].values()))
    assert set(counts) == {"available", "partial", "not_admitted", "unavailable"}
    assert receipt["admission"] == {"candidate_tool_count": 3, "admitted_tool_count": 2,
                                    "omitted_unavailable_tools": ["query_syntax"], "dataset_availability_counts": counts,
                                    "query_sources": ["alternate_cpg"], "attached_skills": ["base-skill", "selected-skill"],
                                    "query_procedures": {"selected-skill": ["alternate_cpg"]}}
    assert cell.capability.tools == ("expand", "query_cpg_slice")
    assert receipt["cell_id"] == cell_fingerprint(replace(cell.spec, admission=None), cell.capability)
    assert "attached_skills" not in json.dumps(infer.requests[0].task_input)
