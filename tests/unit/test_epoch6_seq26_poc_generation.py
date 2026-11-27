"""Epoch-6 seq=26 regressions for job_poc_generation (Defects 26A and 26B)."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
from typing import Any

from appsec_review.inference import ModelResult
from appsec_review.jobs.bound_artifacts import artifact_ref
from types import SimpleNamespace
from unittest.mock import patch
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_poc_generation import inputs as poc_inputs, job as poc_job, writer
from appsec_review.jobs.job_poc_generation.brief import Brief, build_brief
from appsec_review.jobs.job_poc_generation.buildctx import Headers
from appsec_review.jobs.job_poc_generation.candidates import parse_candidates
from appsec_review.jobs.job_poc_generation.settings import PocGenerationSettings
from appsec_review.jobs.job_poc_generation.source import (
    UNGROUNDED_UNSAFE_DECLINE_GUIDANCE,
    ungrounded_unsafe_decline_error,
)
from appsec_review.runtime import UnitContext
from appsec_review.storage import atomic_json
from appsec_review.storage.validation import current_validation
from tests import poc_support
from tests.fixtures.poc_generation import relay
from tests.unit.job_poc_generation.test_brief_inputs_and_helpers import _cfg
from tests.unit.job_poc_generation.test_job_units import _basis_dict, _candidate_dict, _fast_workspace, _job_context, _verified_inputs, _view_with_resolved_labels

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = SchemaSet(ROOT / "docs" / "schemas" / "poc-generation")
SETTINGS = PocGenerationSettings.from_mapping(poc_support.settings_table())

SINK_ID = "asr:sink_site:" + "8" * 64
ENTRY_ID = "asr:entry_point:" + "1" * 64
FLOW_ID = "asr:dataflow_path:" + "4" * 64
SYM_SERVE = "asr:symbol:" + "a" * 64
SYM_HANDLE = "asr:symbol:" + "b" * 64
SYM_LOG = "asr:symbol:" + "c" * 64


class ScopedFakeCore:
    """Records every ``find`` call with its ``indexes`` argument to verify bounded graph lookup."""

    def __init__(self, rows_by_id: dict[str, dict[str, Any]], *, symbol_rows: list[dict[str, Any]] = (),
                 timeout_ids: set[str] | None = None) -> None:
        self.rows_by_id = rows_by_id
        self.symbol_rows = list(symbol_rows)
        self.timeout_ids = timeout_ids or set()
        self.calls: list[dict[str, Any]] = []

    def find(self, *, identity: str | None = None, path: str | None = None, kind: str | None = None,
             indexes: tuple[str, ...] | None = None, limit: int | None = None,
             max_results: int = 20, **_kwargs: Any) -> dict[str, Any]:
        cap = int(limit if limit is not None else max_results)
        self.calls.append({"identity": identity, "path": path, "kind": kind, "indexes": indexes, "limit": cap})
        if identity is not None:
            if identity in self.timeout_ids:
                return {"status": "timeout", "results": []}
            row = self.rows_by_id.get(identity)
            if row is None:
                return {"status": "ok", "results": []}
            row_index = row.get("_index", "graph")
            if indexes is not None and row_index not in indexes:
                return {"status": "ok", "results": []}
            return {"status": "ok", "results": [row]}
        if path is not None and kind == "symbol":
            matched = [
                r for r in self.symbol_rows
                if (r.get("location", {}).get("path") or r.get("path")) == path
            ]
            return {"status": "ok", "results": matched[:cap]}
        return {"status": "ok", "results": []}


def test_sink_of_resolves_codeql_enclosing_display_symbol_and_start_line_via_graph_index() -> None:
    core = ScopedFakeCore({
        SINK_ID: {
            "_index": "graph",
            "identity": SINK_ID,
            "kind": "sink_site",
            "name": "printf",
            "location": {"path": "src/request.cpp", "start_line": 28, "end_line": 28},
            "payload": {
                "category": "output",
                "subcategory": "format_string",
                "enclosing_function": {"display": "log_message", "symbol": SYM_LOG},
            },
        },
        SYM_LOG: {
            "_index": "graph",
            "identity": SYM_LOG,
            "kind": "symbol",
            "name": "log_message",
            "location": {"path": "src/request.cpp", "start_line": 27, "end_line": 29},
            "payload": {"name": "log_message", "kind": "function"},
        },
    })
    package = {
        "scope": {"operation": {"path": "src/request.cpp", "start_line": 28, "anchor_ids": [SINK_ID]}},
        "neighborhood": {"function": None, "sinks": [{"ref": SINK_ID, "path": "src/request.cpp", "start_line": 28}]},
    }
    diags: list[str] = []
    sink = poc_inputs.sink_of(package, core=core, diagnostics=diags)
    assert sink == {
        "name": "log_message",
        "path": "src/request.cpp",
        "line": 27,
        "symbol": SYM_LOG,
    }
    assert diags == []
    assert [c["indexes"] for c in core.calls] == [("graph",), ("graph",)]


def test_sink_of_parses_cpg_node_json_end_line_and_single_line_declaration_fallback() -> None:
    cpg_core = ScopedFakeCore(
        {},
        symbol_rows=[
            {
                "identity": SYM_LOG,
                "kind": "symbol",
                "name": "log_message",
                "location": {"path": "src/request.cpp", "start_line": 27, "end_line": 27},
                "payload": {
                    "kind": "function",
                    "cpg_node_json": json.dumps({"name": "log_message", "start_line": 27, "end_line": 31}),
                },
            },
        ],
    )
    pkg = {
        "scope": {"operation": {"path": "src/request.cpp", "start_line": 28, "anchor_ids": []}},
        "neighborhood": {"function": None, "sinks": []},
    }
    assert poc_inputs.sink_of(pkg, core=cpg_core) == {
        "name": "log_message",
        "path": "src/request.cpp",
        "line": 27,
        "symbol": SYM_LOG,
    }
    assert cpg_core.calls[-1]["indexes"] == ("graph", "analysis")

    decl_only_core = ScopedFakeCore(
        {},
        symbol_rows=[
            {"identity": SYM_SERVE, "kind": "symbol", "name": "helper_above",
             "location": {"path": "src/request.cpp", "start_line": 10, "end_line": 10},
             "payload": {"kind": "function"}},
            {"identity": SYM_LOG, "kind": "symbol", "name": "log_message",
             "location": {"path": "src/request.cpp", "start_line": 27, "end_line": 27},
             "payload": {"kind": "function"}},
            {"identity": SYM_HANDLE, "kind": "symbol", "name": "handle_request",
             "location": {"path": "src/request.cpp", "start_line": 95, "end_line": 95},
             "payload": {"kind": "function"}},
        ],
    )
    assert poc_inputs.sink_of(pkg, core=decl_only_core) == {
        "name": "log_message",
        "path": "src/request.cpp",
        "line": 27,
        "symbol": SYM_LOG,
    }


def test_sink_of_and_plan_step_surface_retrieval_timeout_and_activate_validation_scope(tmp_path: Path) -> None:
    timeout_core = ScopedFakeCore({}, timeout_ids={SINK_ID})
    pkg = {
        "scope": {"operation": {"path": "src/request.cpp", "start_line": 28, "anchor_ids": [SINK_ID]}},
        "neighborhood": {"function": None, "sinks": [{"ref": SINK_ID, "path": "src/request.cpp", "start_line": 28}]},
    }
    diags: list[str] = []
    assert poc_inputs.sink_of(pkg, core=timeout_core, diagnostics=diags) is None
    assert len(diags) == 1 and "retrieval_timeout" in diags[0]

    ctx = _job_context(tmp_path)
    cand = _candidate_dict(1, basis=_basis_dict(entry=[ENTRY_ID], path=[FLOW_ID, SINK_ID]))
    ver = _verified_inputs(ctx.run_root, [cand], {1: {"package_id": cand["package_id"], **pkg}})
    seen_validation: list[bool] = []

    def core_factory(run_root: Path, _doc: Any) -> Any:
        seen_validation.append(current_validation(Path(run_root).resolve()) is not None)
        return timeout_core

    ws, manifest = _fast_workspace(tmp_path / "ws")
    unit = poc_support.relay_unit(ws, manifest)
    built = poc_job.build_job(
        infer=lambda *_a, **_kw: None,
        executor_factory=lambda *_a, **_kw: poc_support.FakeExecutor(),
        builds_factory=lambda _: poc_support.builds(unit),
        core_factory=core_factory,
        view_factory=lambda *_a, **_kw: _view_with_resolved_labels(),
        repository_root=ROOT,
    )
    accepted_ptr = SimpleNamespace(path="jobs/rev/latest.json", sha256="a" * 64)
    with (
        patch("appsec_review.jobs.job_poc_generation.inputs.verify_inputs", return_value=ver),
        patch("appsec_review.jobs.job_poc_generation.job.accepted_handoff", return_value=accepted_ptr),
    ):
        result = built.handler(ctx)
    assert seen_validation == [True]
    plan_doc = poc_job.read_bound_json(ctx.run_root, result["outputs"]["plan.briefs"]["artifact"])
    entry = plan_doc["entries"][cand["claim_id"]]
    assert entry["terminal"]["status"] == "insufficient_evidence"
    assert "retrieval_timeout" in entry["terminal"]["reason"]


def test_build_brief_resolves_dataflow_step_symbols_into_clean_path_calls(tmp_path: Path) -> None:
    core = ScopedFakeCore({
        ENTRY_ID: {
            "_index": "graph",
            "identity": ENTRY_ID,
            "kind": "entry_point",
            "name": "recv",
            "location": {"path": "src/server.cpp", "start_line": 44, "end_line": 44},
            "payload": {"enclosing_function": {"display": "serve_once", "symbol": SYM_SERVE}},
        },
        FLOW_ID: {
            "_index": "graph",
            "identity": FLOW_ID,
            "kind": "dataflow_path",
            "name": "recv -> output/format_string: printf (argument 0)",
            "location": {"path": "src/request.cpp", "start_line": 44, "end_line": 28},
            "summary": f"flow {SYM_SERVE} -> {SYM_LOG}",
            "payload": {
                "steps": [
                    {"display": "recv_buf", "symbol": SYM_SERVE, "path": "src/server.cpp", "line": 44},
                    {"display": "*line", "symbol": SYM_HANDLE, "path": "src/request.cpp", "line": 108},
                    {"display": "*fmt", "symbol": SYM_LOG, "path": "src/request.cpp", "line": 28},
                ],
            },
        },
        SINK_ID: {
            "_index": "graph",
            "identity": SINK_ID,
            "kind": "sink_site",
            "name": "printf",
            "location": {"path": "src/request.cpp", "start_line": 28, "end_line": 28},
            "summary": "output/format_string: printf (argument 0)",
            "payload": {"enclosing_function": {"display": "log_message", "symbol": SYM_LOG}},
        },
        SYM_SERVE: {"_index": "graph", "identity": SYM_SERVE, "kind": "symbol", "name": "serve_once",
                    "payload": {"name": "serve_once", "kind": "function"}},
        SYM_HANDLE: {"_index": "graph", "identity": SYM_HANDLE, "kind": "symbol", "name": "handle_request",
                     "payload": {"name": "handle_request", "kind": "function"}},
        SYM_LOG: {"_index": "graph", "identity": SYM_LOG, "kind": "symbol", "name": "log_message",
                  "payload": {"name": "log_message", "kind": "function"}},
    })
    cand = parse_candidates([_candidate_dict(1, basis=_basis_dict(entry=[ENTRY_ID], path=[FLOW_ID, SINK_ID]))])[0]
    view = _view_with_resolved_labels()
    view.document["sinks"] = [{
        "label": "S9", "ref": SINK_ID, "summary": "output/format_string: printf (argument 0)",
        "path": "src/request.cpp", "lines": "28-28",
    }]
    ws, manifest = _fast_workspace(tmp_path / "ws")
    unit = poc_support.relay_unit(ws, manifest)
    built = build_brief(
        cand,
        finding={"title": "Uncontrolled format string"},
        package={},
        view=view,
        sink={"name": relay.SINK, "path": "src/packet.cpp", "line": 7},
        unit=unit,
        headers=Headers(unit),
        settings=_cfg(),
        core=core,
    )
    assert built.gaps == ()
    assert set(built.expectation_inputs["path_calls"]) == {"serve_once", "handle_request", "log_message"}
    for noise in ("asr", "symbol", "argument", "format_string", "output", "printf", "recv"):
        assert noise not in built.expectation_inputs["path_calls"]
    assert all(c["indexes"] == ("graph",) for c in core.calls)


def test_guidance_and_writer_reframe_static_ast_fixtures_and_recover_from_ungrounded_unsafe_decline(
    tmp_path: Path,
) -> None:
    guidance = writer.load_guidance(ROOT, tmp_path / "run", "job_poc_generation", SETTINGS.writer)
    normalized = re.sub(r"\s+", " ", guidance.text)
    assert "Because the harness is compile-only and never executed" not in normalized
    assert "static AST-and-typecheck unit-test fixtures" in normalized
    assert "do NOT craft format-string exploit tokens" in normalized

    brief_with_decl = Brief(
        {
            "schema": "appsec-review/poc-writer-brief/1",
            "sink": {"name": relay.SINK, "path": "src/packet.cpp", "line": 7},
            "declarations": [
                {"name": relay.SINK, "path": "src/packet.cpp", "lines": "7-7",
                 "text": "int handle_request(char *line, size_t len, int sock, Session *session);",
                 "predeclared": True},
            ],
        },
        {},
        (relay.SINK,),
        (),
    )
    reader = writer.WorkspaceReader(tmp_path, {}, ("include", "src"), lambda _: [])
    ungrounded_refusal = {
        "action": "final",
        "result": {
            "decline": {
                "status": "unsafe_to_attempt",
                "why": (
                    "A compile-only harness would still provide a target-specific reproducer. "
                    "The format-argument issue can be verified by inspection without provoking undefined behavior."
                ),
            },
        },
    }
    seen_requests: list[Any] = []
    replies = [ungrounded_refusal, relay.answer()]

    def scripted_infer(request: Any, **_kwargs: Any) -> ModelResult:
        seen_requests.append(request)
        return ModelResult(proposal=deepcopy(replies.pop(0)), input_tokens=10, output_tokens=10)

    outcome = writer.run_writer(
        brief_with_decl, guidance=guidance, settings=SETTINGS, infer=scripted_infer,
        reader=reader, schemas=SCHEMAS, claim_id="claim-24cb47d9",
    )
    assert outcome.status == "answered"
    assert len(outcome.attempts) == 2
    assert outcome.attempts[0].status == "invalid"
    assert outcome.attempts[0].reason == "ungrounded_unsafe_decline"
    assert outcome.attempts[0].repair_errors == (UNGROUNDED_UNSAFE_DECLINE_GUIDANCE,)
    assert seen_requests[1].repair_errors == (UNGROUNDED_UNSAFE_DECLINE_GUIDANCE,)
    assert "static AST-and-typecheck unit-test fixtures" in seen_requests[0].task_input["fixture_contract"]


def test_legitimate_and_final_attempt_unsafe_declines_remain_clean_terminal_declines(tmp_path: Path) -> None:
    guidance = writer.load_guidance(ROOT, tmp_path / "run", "job_poc_generation", SETTINGS.writer)
    brief_with_decl = Brief(
        {
            "schema": "appsec-review/poc-writer-brief/1",
            "sink": {"name": relay.SINK},
            "declarations": [{"name": relay.SINK, "text": "void f(void);", "predeclared": True}],
        },
        {},
        (relay.SINK,),
        (),
    )
    reader = writer.WorkspaceReader(tmp_path, {}, ("include", "src"), lambda _: [])

    # 1. Legitimate denylisted C/POSIX primitive named -> accepted on Attempt 1 without wasted retry.
    legit_decline = {
        "action": "final",
        "result": {
            "decline": {
                "status": "unsafe_to_attempt",
                "why": "Calling the signature requires invoking fork() and socket() directly in poc_*.",
            },
        },
    }
    assert ungrounded_unsafe_decline_error(
        legit_decline["result"],
        declarations=brief_with_decl.document["declarations"],
        call_denylist=SETTINGS.policy.call_denylist,
    ) is None
    calls = 0

    def legit_infer(_req: Any, **_kw: Any) -> ModelResult:
        nonlocal calls
        calls += 1
        return ModelResult(proposal=deepcopy(legit_decline), input_tokens=5, output_tokens=5)

    legit_outcome = writer.run_writer(
        brief_with_decl, guidance=guidance, settings=SETTINGS, infer=legit_infer,
        reader=reader, schemas=SCHEMAS, claim_id="claim-legit",
    )
    assert legit_outcome.status == "declined" and calls == 1

    # 2. Final-attempt exhaustion: if Attempt 2 still declines with ungrounded unsafe_to_attempt, record cleanly.
    stubborn = {
        "action": "final",
        "result": {"decline": {"status": "unsafe_to_attempt", "why": "verified by inspection only"}},
    }
    stubborn_calls = 0

    def stubborn_infer(_req: Any, **_kw: Any) -> ModelResult:
        nonlocal stubborn_calls
        stubborn_calls += 1
        return ModelResult(proposal=deepcopy(stubborn), input_tokens=5, output_tokens=5)

    exhausted = writer.run_writer(
        brief_with_decl, guidance=guidance, settings=SETTINGS, infer=stubborn_infer,
        reader=reader, schemas=SCHEMAS, claim_id="claim-exhausted",
    )
    assert exhausted.status == "declined"
    assert stubborn_calls == SETTINGS.max_attempts == 2
    assert exhausted.attempts[0].status == "invalid" and exhausted.attempts[0].reason == "ungrounded_unsafe_decline"
    assert exhausted.attempts[1].status == "declined"
