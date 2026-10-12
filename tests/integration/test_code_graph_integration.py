"""Focused tests for the code-graph integration fixes (code-graph-precomputation.md section 10, C9).

Each test pins one seam between merged chunks: scope-bound graph grants for review cells and the
scoped MCP adapter, run-bound graph settings in ``RetrievalCore``, the CLI graph order, and the
``code_graph`` producer in the review evidence map. The offline end-to-end acceptance is
``test_code_graph_end_to_end.py``.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time
from typing import Any

import pytest

from appsec_review.cli import GRAPH_JOB_IDS, parser
from appsec_review.graph.contract import GraphSettings
from appsec_review.inference import ModelResult
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.mcp.capability import ScopedRetrievalMcpAdapter, issue_capability
from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.core import RetrievalIntegrityError
from appsec_review.review.capability import CellCapability
from appsec_review.review.cells import TURN_SCHEMA, CellSpec, run_cell
from appsec_review.review.models import CellStatus, Lane, Role
from appsec_review.review.scope import accept_manifest
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import atomic_bytes, atomic_json
from tests.test_retrieval_code_graph import RUN_ID, SCOPE, build_graph_run

SECRET = b"k" * 32


@pytest.fixture()
def graph(tmp_path: Path) -> tuple[RetrievalCore, dict[str, str], Path]:
    runs, ids = build_graph_run(tmp_path)
    return RetrievalCore(runs, RUN_ID), ids, runs


class Script:
    def __init__(self, *turns: dict[str, Any]) -> None:
        self.turns = list(turns)
        self.requests: list[Any] = []

    def __call__(self, request, *, timeout_seconds: int) -> ModelResult:
        self.requests.append(request)
        return ModelResult({"schema": TURN_SCHEMA, **self.turns.pop(0)}, input_tokens=10, output_tokens=5)


def _cell(core: RetrievalCore, ids: dict[str, str], tmp_path: Path, graph_scopes: tuple[str, ...]):
    capability = CellCapability.issue(
        run_id=RUN_ID, manifest_sha256=core.manifest_sha256, package_id="package-1", package_sha256="3" * 64,
        role=Role.INDEPENDENT_VERIFIER, round=0, tools=("query_code_graph", "find"), indexes=("graph",),
        entities=(ids["sink_memcpy"],), graph_scopes=graph_scopes, max_queries=4, max_turns=4, page_size=10,
        max_depth=3, max_result_bytes=65536)
    spec = CellSpec(
        manifest_sha256=core.manifest_sha256, lane=Lane.LEAD, package_id="package-1", package_sha256="3" * 64,
        claim_id=None, role=Role.INDEPENDENT_VERIFIER, persona="", stack_profile="c_cpp", strategy=None,
        task="blind_verifier", task_input={}, round=0, round_delta_sha256=None, evidence_set=(ids["sink_memcpy"],),
        guidance_bundle_sha256="4" * 64, guidance_text="rules", provider="fixture", model="fixture",
        reasoning="low", max_input_tokens=1000, max_output_tokens=1000, timeout_seconds=60,
        output_schema="appsec-review/verifier-result/1", validator_version="fixture/1")
    script = Script(
        {"action": "retrieve", "requests": [{"tool": "query_code_graph",
                                             "parameters": {"mode": "guards", "subject": ids["sink_memcpy"]}},
                                            {"tool": "find", "parameters": {"identity": ids["sink_memcpy"]}}]},
        # sym_parse is the sink's enclosing function: only the granted sink row's payload references it.
        {"action": "retrieve", "requests": [{"tool": "query_code_graph",
                                             "parameters": {"mode": "callers", "subject": ids["sym_parse"]}}]},
        {"action": "final", "result": {"cited": [ids["guard_none"], ids["call_handle_parse"]]}})
    outcome = run_cell(spec, infer=script, core=core, capability=capability, receipts_root=tmp_path / "cells",
                       validate_final=lambda result: [])
    return outcome, script


def test_a_review_cell_receives_and_cites_graph_facts_of_its_granted_scope_only(graph, tmp_path: Path) -> None:
    core, ids, _runs = graph
    granted, script = _cell(core, ids, tmp_path / "granted", (SCOPE,))
    assert granted.record.status is CellStatus.SUCCEEDED, granted.gaps
    guards = script.requests[1].transcript[1]["responses"][0]
    assert {row["identity"] for row in guards["results"]} == {ids["guard_none"], ids["guard_dominating"]}
    assert guards["withheld_out_of_scope"] == 0
    callers = script.requests[2].transcript[3]["responses"][0]
    assert callers["status"] == "ok" and ids["call_handle_parse"] in {row["identity"] for row in callers["results"]}

    # The same cell without a scope grant, or with another scope's grant, never sees the rows.
    for scopes in ((), ("cpp-other",)):
        withheld, script = _cell(core, ids, tmp_path / f"withheld-{len(scopes)}", scopes)
        response = script.requests[1].transcript[1]["responses"][0]
        assert response["results"] == [] and response["withheld_out_of_scope"] == 2
        # sym_parse was never received in scope, so the follow-up query is an authority denial.
        assert script.requests[2].transcript[3]["responses"][0]["code"] == "entity_out_of_scope"
        assert withheld.record.status is CellStatus.INVALID
        assert any("authority_error" in gap.gap_class.value for gap in withheld.gaps)


def test_graph_scope_grants_are_bound_into_the_capability_hash(graph) -> None:
    core, ids, _runs = graph
    values = dict(run_id=RUN_ID, manifest_sha256=core.manifest_sha256, package_id="p", package_sha256="3" * 64,
                  role=Role.HYPOTHESIS_HUNTER, round=0, tools=("query_code_graph",), indexes=("graph",),
                  entities=(ids["sink_memcpy"],), max_queries=2, max_turns=2, page_size=5, max_depth=2,
                  max_result_bytes=4096)
    plain, scoped = CellCapability.issue(**values), CellCapability.issue(**values, graph_scopes=(SCOPE,))
    assert plain.capability_sha256 != scoped.capability_sha256
    assert scoped.semantic_body()["graph_scopes"] == [SCOPE]
    with pytest.raises(ValueError, match="requires the graph index"):
        CellCapability.issue(**{**values, "indexes": ("source",)}, graph_scopes=(SCOPE,))
    row = {"identity": ids["guard_none"], "kind": "guard_fact", "index": "graph",
           "payload": {"scope": {"scope_id": SCOPE}}}
    assert scoped.graph_row_in_scope(row) and not plain.graph_row_in_scope(row)
    # A row whose kind, index or identity prefix disagrees is never granted, whatever its payload says.
    assert not scoped.graph_row_in_scope({**row, "index": "observations"})
    assert not scoped.graph_row_in_scope({**row, "kind": "tool_observation"})
    assert not scoped.graph_row_in_scope({**row, "identity": ids["obs_bridged"]})


def _package(core: RetrievalCore, ids: dict[str, str], graph_scopes: list[str]) -> dict[str, Any]:
    return {"run_id": RUN_ID, "manifest_sha256": core.manifest_sha256, "package_id": "package-1",
            "retrieval": {"indexes": ["graph", "source"], "query_sets": [], "entity_ids": [ids["sink_memcpy"]],
                          "graph_scopes": graph_scopes, "max_page_size": 20, "max_pages": 2, "max_depth": 3,
                          "max_response_bytes": 262144}}


def _scoped(core: RetrievalCore, package: dict[str, Any]) -> ScopedRetrievalMcpAdapter:
    token = issue_capability(package, role="verifier", round_id="1", secret=SECRET,
                             expires_at=int(time.time()) + 300)
    return ScopedRetrievalMcpAdapter(RetrievalMcpAdapter(core), package, capability=token, secret=SECRET,
                                     role="verifier", round_id="1")


def test_the_scoped_mcp_adapter_applies_the_same_scope_bound_graph_grant(graph) -> None:
    core, ids, _runs = graph
    scoped = _scoped(core, _package(core, ids, [SCOPE]))
    guards = scoped.call("query_code_graph", {"mode": "guards", "subject": ids["sink_memcpy"]})
    assert {row["identity"] for row in guards["results"]} == {ids["guard_none"], ids["guard_dominating"]}
    assert scoped.call("find", {"identity": ids["guard_none"]})["results"]
    assert scoped.call("find", {"identity": ids["sink_memcpy"]})["results"]   # references sym_parse
    assert scoped.call("query_code_graph", {"mode": "callers", "subject": ids["sym_parse"]})["results"]
    for scopes in ([], ["cpp-other"]):
        other = _scoped(core, _package(core, ids, scopes))
        with pytest.raises(ValueError, match="escaped review package"):
            other.call("query_code_graph", {"mode": "guards", "subject": ids["sink_memcpy"]})
        with pytest.raises(ValueError, match="outside review package"):
            other.call("find", {"identity": ids["guard_none"]})


def _bind(run_root: Path, graph: dict[str, int]) -> Path:
    resolved = json.dumps({"jobs": {"job_code_graph_index": {"settings": {"graph": graph}}}}).encode()
    destination = run_root / "data" / "configuration"
    atomic_bytes(destination / "resolved.json", resolved)
    atomic_json(destination / "manifest.json", {"schema": "appsec-review/run-configuration/2",
                                                "resolved_sha256": hashlib.sha256(resolved).hexdigest()})
    return destination / "resolved.json"


def test_retrieval_core_reads_graph_caps_from_the_run_bound_configuration(graph) -> None:
    core, ids, runs = graph
    assert core.graph_settings == GraphSettings()                  # no bound configuration: defaults
    resolved = _bind(runs / RUN_ID, {"max_call_depth": 1})
    bound = RetrievalCore(runs, RUN_ID)
    assert bound.graph_settings.max_call_depth == 1
    assert core.query_code_graph(mode="callers", subject=ids["sym_helper"], depth=2)["results"]
    with pytest.raises(ValueError, match="depth exceeds bound 1"):
        bound.query_code_graph(mode="callers", subject=ids["sym_helper"], depth=2)
    resolved.write_bytes(resolved.read_bytes() + b" ")
    with pytest.raises(RetrievalIntegrityError, match="hash mismatch"):
        RetrievalCore(runs, RUN_ID)


def test_cli_resume_and_force_from_cover_the_code_graph_job() -> None:
    order = list(GRAPH_JOB_IDS)
    assert order.index("job_codeql_analysis") < order.index("job_review_prioritization") < order.index(
        "job_code_graph_index") < order.index("job_review_data_indexing")
    for command in ("plan-resume", "resume"):
        args = parser().parse_args([command, "--run-id", "r", "--target", ".", "--force-from", "job_code_graph_index"])
        assert args.force_from == "job_code_graph_index"
    registry = builtin_registry()
    assert all(registry.build(job_id).job_id == job_id for job_id in GRAPH_JOB_IDS)


def test_the_review_evidence_map_lists_code_graph_coverage_and_gaps(graph) -> None:
    _core, _ids, runs = graph
    scope = accept_manifest(runs / RUN_ID)
    evidence = scope.evidence_map()
    coverage = scope.producer("code_graph")
    assert "code_graph" in evidence["available"] and coverage.state == "partial"
    assert len(coverage.shards) == 7
    assert [(gap.scope, gap.state) for gap in coverage.gaps] == [
        (f"graph/{SCOPE}.call_site:graph:{SCOPE}:call_site", "partial")]
    record = next(item for item in evidence["producers"] if item["producer"] == "code_graph")
    assert record["gap_ids"] == [coverage.gaps[0].gap_id]


def test_a_run_without_graph_shards_names_code_graph_as_missing(tmp_path: Path) -> None:
    from tests.fixtures.inference_review.builder import build_accepted_index_set

    fixture = build_accepted_index_set(tmp_path)
    evidence = accept_manifest(fixture.run_root).evidence_map()
    assert "code_graph" in evidence["missing"]
    assert any(gap["producer"] == "code_graph" and gap["state"] == "missing" for gap in evidence["gaps"])
