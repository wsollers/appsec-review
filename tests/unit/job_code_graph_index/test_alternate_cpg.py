"""Fast (<2s) unit tests for universal Alternate CPG & inter-procedural CFG synthesis (T-169)."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from appsec_review.jobs.job_code_graph_index import (
    ALTERNATE_CPG_SCHEMA,
    AlternateCpgSettings,
    compute_cpg_slice,
    find_interprocedural_paths,
    synthesize_alternate_cpg,
)
from appsec_review.jobs.job_code_graph_index.alternate_cpg import (
    RESOLUTION_TIERS,
    SUPPORTED_LANGUAGES,
    publish_alternate_cpg,
    _extract_tree_sitter_files,
    build_run_alternate_cpg,
)
from appsec_review.jobs.job_tree_sitter_ast.cfg import synthesize_file_cfg, write_scope_cfg_artifacts
from appsec_review.jobs.job_code_graph_index.datasets import CONTRACT
from appsec_review.jobs.job_tree_sitter_ast.datasets import DATASETS as TS_DATASETS
from appsec_review.retrieval import IndexBuilder, IndexIdentity
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.review.models import IntegrityError
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.retrieval.graph import query_call_paths, query_cpg_slice
from appsec_review.retrieval.index import write_manifest
from tests.handoff_fixture import write_fixture_handoff

SCHEMA_PATH = Path("docs/schemas/code-graph-index/alternate-cpg.schema.json")
SNAPSHOT = "a" * 64


def _accepted_tree_sitter(root, *, gaps=()):
    ast = _make_two_fn_ast(
        fn_type="function_definition", body_type="block", if_type="if_statement",
        ret_type="return_statement", call_type="call", entry_name="handle", helper_name="parse",
        guard_expr="input_val is not None", sink_call="eval",
    )
    cfg = synthesize_file_cfg(ast, language="python", path="app.py")
    refs, _ = write_scope_cfg_artifacts(
        run_root=root, cfg_dir=root / "data/treesitter/cfg" / ("f" * 64),
        scope_id="python-s1", language="python", grammar="python", target_snapshot=SNAPSHOT,
        file_results=[cfg],
    )
    path = root / "data/indices/analysis/tree-sitter.sqlite"
    builder = IndexBuilder(path, name="analysis", fingerprint="f" * 64,
                           target_snapshot=SNAPSHOT, shard_id="python-s1")
    sha = builder.build()
    shard = json.loads(json.dumps(asdict(IndexIdentity(
        "analysis", "appsec-review/retrieval-index/2", sha, "f" * 64,
        path.relative_to(root).as_posix(), {"job": "job_tree_sitter_ast"}, (), "python-s1",
    ))))
    attempt = root / "data/jobs/job_tree_sitter_ast/attempts/attempt_0001"
    atomic_json(attempt / "claim.json", {"dataset_contract": dataset_contract(
        "job_tree_sitter_ast", ("load", "plan", "parse", "acceptance"), TS_DATASETS,
    )})
    handoff = write_fixture_handoff(root, attempt / "handoff.json", {
        "job_id": "job_tree_sitter_ast", "target_snapshot": SNAPSHOT,
        "outputs": {"parse.dynamic_scopes": {"dispositions": [{
            "scope_id": "python-s1", "index_identity": shard, "cfg_artifacts": refs,
        }], "gaps": list(gaps)}}, "artifacts": [*refs.values(), {
            "path": path.relative_to(root).as_posix(), "sha256": sha,
        }],
    })
    digest = file_sha256(handoff)
    atomic_json(root / "data/jobs/job_tree_sitter_ast/latest.json", {
        "handoff_path": handoff.relative_to(root).as_posix(), "handoff_sha256": digest,
    })
    context = SimpleNamespace(run_root=root, config=SimpleNamespace(job_id="job_code_graph_index"),
                              upstream_handoffs={"job_tree_sitter_ast": digest}, contract=CONTRACT)
    return context, shard, refs


def test_cfg_uses_accepted_scope_and_retains_read_receipts(tmp_path):
    context, shard, _ = _accepted_tree_sitter(tmp_path)
    foreign = tmp_path / "data/treesitter/cfg/unaccepted/cfg-nodes.jsonl"
    foreign.parent.mkdir(parents=True)
    foreign.write_text("not JSON", encoding="utf-8")
    gaps = []
    with input_read_scope(context) as reads:
        files = _extract_tree_sitter_files(tmp_path, [shard], target_snapshot=SNAPSHOT, gaps=gaps)
        assert len(files) == 1 and files[0]["path"] == "app.py"
        assert files[0]["functions"] and files[0]["cfg_nodes"] and files[0]["cfg_edges"]
        cpg, _ = build_run_alternate_cpg(
            tmp_path, run_id=tmp_path.name, target_snapshot=SNAPSHOT,
            upstream_shards=[shard], graph_shards=[],
        )
        assert cpg["counts"]["alternate_cpg_nodes"] > 0 and cpg["gaps"] == []
        assert {row["output_kind"] for row in reads.document()["reads"]} >= {"handoff", "tree_sitter_cfg"}
    assert gaps == []


@pytest.mark.parametrize("defect", ["tampered", "symlink", "different-shard", "unpinned"])
def test_cfg_rejects_unaccepted_or_changed_artifacts(tmp_path, defect):
    context, shard, refs = _accepted_tree_sitter(tmp_path)
    if defect == "tampered":
        (tmp_path / refs["nodes"]["path"]).write_text("{}", encoding="utf-8")
    elif defect == "symlink":
        path = tmp_path / refs["nodes"]["path"]
        other = path.with_suffix(".other")
        path.rename(other)
        path.symlink_to(other)
    elif defect == "different-shard":
        shard = {**shard, "fingerprint": "d" * 64}
    else:
        context.upstream_handoffs = {}
    with pytest.raises((ValueError, IntegrityError)), input_read_scope(context):
        _extract_tree_sitter_files(tmp_path, [shard], target_snapshot=SNAPSHOT, gaps=[])


def test_cfg_absence_is_a_gap_not_a_directory_scan(tmp_path, monkeypatch):
    context, _, _ = _accepted_tree_sitter(tmp_path)
    context.upstream_handoffs = {}
    monkeypatch.setattr(Path, "iterdir", lambda *_: pytest.fail("no directory discovery"))
    with input_read_scope(context):
        cpg, _ = build_run_alternate_cpg(
            tmp_path, run_id=tmp_path.name, target_snapshot=SNAPSHOT,
            upstream_shards=[], graph_shards=[],
        )
    assert cpg["nodes"] == []
    assert cpg["gaps"] == ["tree_sitter_cfg_unavailable: no admitted Tree-sitter producer"]


def test_partial_cfg_input_remains_partial_when_other_scope_has_no_shard(tmp_path):
    context, shard, _ = _accepted_tree_sitter(tmp_path, gaps=["python-s2: parser byte limit"])
    with input_read_scope(context):
        cpg, _ = build_run_alternate_cpg(
            tmp_path, run_id=tmp_path.name, target_snapshot=SNAPSHOT,
            upstream_shards=[shard], graph_shards=[],
        )
    assert cpg["counts"]["alternate_cpg_nodes"] > 0
    assert cpg["gaps"] == ["tree_sitter_cfg_partial: python-s2: parser byte limit"]


def _validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))


def _make_two_fn_ast(
    *,
    fn_type: str,
    body_type: str,
    if_type: str,
    ret_type: str,
    call_type: str,
    entry_name: str,
    helper_name: str,
    guard_expr: str,
    sink_call: str,
) -> dict[str, Any]:
    return {
        "type": "program",
        "start_line": 1,
        "end_line": 20,
        "children": [
            {
                "type": fn_type,
                "start_line": 2,
                "end_line": 8,
                "children": [
                    {"type": "identifier", "field": "name", "text": entry_name, "start_line": 2, "end_line": 2},
                    {
                        "type": "parameters",
                        "field": "parameters",
                        "start_line": 2,
                        "end_line": 2,
                        "children": [{"type": "identifier", "text": "input_val", "start_line": 2, "end_line": 2}],
                    },
                    {
                        "type": body_type,
                        "field": "body",
                        "start_line": 3,
                        "end_line": 8,
                        "children": [
                            {
                                "type": if_type,
                                "start_line": 3,
                                "end_line": 5,
                                "children": [
                                    {"type": "binary_expression", "field": "condition", "text": guard_expr, "start_line": 3, "end_line": 3},
                                    {
                                        "type": body_type,
                                        "field": "consequence",
                                        "start_line": 4,
                                        "end_line": 4,
                                        "children": [{"type": ret_type, "text": "return", "start_line": 4, "end_line": 4}],
                                    },
                                ],
                            },
                            {
                                "type": ret_type,
                                "text": f"return {helper_name}(input_val)",
                                "start_line": 7,
                                "end_line": 7,
                                "children": [
                                    {
                                        "type": call_type,
                                        "text": f"{helper_name}(input_val)",
                                        "start_line": 7,
                                        "end_line": 7,
                                        "children": [
                                            {"type": "identifier", "field": "function", "text": helper_name, "start_line": 7, "end_line": 7},
                                            {"type": "identifier", "text": "input_val", "start_line": 7, "end_line": 7},
                                        ],
                                    }
                                ],
                            },
                        ],
                    },
                ],
            },
            {
                "type": fn_type,
                "start_line": 10,
                "end_line": 15,
                "children": [
                    {"type": "identifier", "field": "name", "text": helper_name, "start_line": 10, "end_line": 10},
                    {
                        "type": "parameters",
                        "field": "parameters",
                        "start_line": 10,
                        "end_line": 10,
                        "children": [{"type": "identifier", "text": "payload", "start_line": 10, "end_line": 10}],
                    },
                    {
                        "type": body_type,
                        "field": "body",
                        "start_line": 11,
                        "end_line": 15,
                        "children": [
                            {
                                "type": call_type,
                                "text": f"{sink_call}(payload)",
                                "start_line": 12,
                                "end_line": 12,
                                "children": [
                                    {"type": "identifier", "field": "function", "text": sink_call, "start_line": 12, "end_line": 12},
                                    {"type": "identifier", "text": "payload", "start_line": 12, "end_line": 12},
                                ],
                            }
                        ],
                    },
                ],
            },
        ],
    }


NINE_LANGUAGE_SPECS = [
    ("cpp", "src/cmd_handler.cpp", "function_definition", "compound_statement", "if_statement", "return_statement", "call_expression", "input_val == nullptr", "system", "null_check", "command_injection"),
    ("java", "src/UserController.java", "method_declaration", "block", "if_statement", "return_statement", "method_invocation", "!hasRole(input_val)", "executeQuery", "auth_or_role_check", "sql_injection"),
    ("javascript", "src/routes/exec.js", "function_declaration", "statement_block", "if_statement", "return_statement", "call_expression", "input_val.length > 256", "child_process.exec", "bounds_check", "command_injection"),
    ("python", "app/views.py", "function_definition", "block", "if_statement", "return_statement", "call", "input_val is None", "subprocess.run", "null_check", "command_injection"),
    ("ruby", "app/controllers/users_controller.rb", "method", "body_statement", "if", "return", "call", "input_val.nil?", "Kernel.system", "null_check", "command_injection"),
    ("go", "cmd/server/handlers.go", "function_declaration", "block", "if_statement", "return_statement", "call_expression", "err != nil", "exec.Command", "error_return_guard", "command_injection"),
    ("csharp", "Controllers/AdminController.cs", "method_declaration", "block", "if_statement", "return_statement", "invocation_expression", "!IsAuthorized(input_val)", "Process.Start", "auth_or_role_check", "command_injection"),
    ("rust", "src/handlers.rs", "function_item", "block", "if_expression", "return_expression", "call_expression", "input_val.len() >= 1024", "Command::new", "bounds_check", "command_injection"),
    ("php", "app/Http/Controllers/ExecController.php", "method_declaration", "compound_statement", "if_statement", "return_statement", "function_call_expression", "!isset($input_val)", "shell_exec", "null_check", "command_injection"),
]


@pytest.mark.parametrize(
    ("lang", "rel_path", "fn_type", "body_type", "if_type", "ret_type", "call_type", "guard_expr", "sink_call", "expected_pol", "expected_sink"),
    NINE_LANGUAGE_SPECS,
    ids=[spec[0] for spec in NINE_LANGUAGE_SPECS],
)
def test_syntactic_fallback_across_all_nine_smoke_languages(
    lang: str,
    rel_path: str,
    fn_type: str,
    body_type: str,
    if_type: str,
    ret_type: str,
    call_type: str,
    guard_expr: str,
    sink_call: str,
    expected_pol: str,
    expected_sink: str,
) -> None:
    assert set(SUPPORTED_LANGUAGES) == {"cpp", "java", "javascript", "python", "ruby", "go", "csharp", "rust", "php"}
    validator = _validator()
    ast_tree = _make_two_fn_ast(
        fn_type=fn_type,
        body_type=body_type,
        if_type=if_type,
        ret_type=ret_type,
        call_type=call_type,
        entry_name="handle_request",
        helper_name="run_worker",
        guard_expr=guard_expr,
        sink_call=sink_call,
    )
    ts_cfg = synthesize_file_cfg(ast_tree, language=lang, path=rel_path)
    cpg = synthesize_alternate_cpg(
        tree_sitter_files=[ts_cfg],
        run_id=f"run-{lang}",
        target_snapshot=SNAPSHOT,
    )

    assert cpg["schema"] == ALTERNATE_CPG_SCHEMA
    assert lang in cpg["languages"]
    assert cpg["counts"]["alternate_cpg_nodes"] >= 6
    assert cpg["counts"]["Syntactic" if False else "syntactic_fallback_edges_count"] > 0
    assert cpg["counts"]["semantic_edges_count"] == 0
    assert cpg["counts"]["entrypoints_linked"] >= 1
    assert cpg["counts"]["reachable_sink_paths_precomputed"] >= 1

    edge_kinds = {e["edge_kind"] for e in cpg["edges"]}
    assert {"CALLS", "ARG_TO_PARAM", "DEF_USE", "FLOWS_TO", "GUARDS", "ENTRYPOINT_TO_FN", "FN_TO_SINK"} <= edge_kinds

    for node in cpg["nodes"]:
        validator.validate(node)
    for edge in cpg["edges"]:
        validator.validate(edge)
        assert edge["resolution_tier"] == "syntactic_fallback"
    for path_rec in cpg["paths"]:
        validator.validate(path_rec)

    paths = find_interprocedural_paths(cpg, entrypoint_only=True, sink_class=expected_sink, language=lang, max_hops=10)
    assert len(paths) >= 1
    top = paths[0]
    assert top["source_name"] == "handle_request"
    assert top["hop_count"] == 2
    assert top["entrypoint_linked"] is True
    assert top["resolution_tier"] == "syntactic_fallback"
    assert expected_pol in top["guard_polarities"]
    assert any(d["guard_polarity"] == expected_pol and d["branch"] == "false_branch" for d in top["guard_dominators"])


def test_dual_seeded_fusion_codeql_sarif_clangd_routes_and_resolution_tiers() -> None:
    validator = _validator()
    py_ast = _make_two_fn_ast(
        fn_type="function_definition",
        body_type="block",
        if_type="if_statement",
        ret_type="return_statement",
        call_type="call",
        entry_name="api_exec",
        helper_name="dispatch_cmd",
        guard_expr="not sanitize_cmd(input_val)",
        sink_call="os.system",
    )
    cpp_ast = _make_two_fn_ast(
        fn_type="function_definition",
        body_type="compound_statement",
        if_type="if_statement",
        ret_type="return_statement",
        call_type="call_expression",
        entry_name="cpp_entry",
        helper_name="cpp_exec",
        guard_expr="input_val == nullptr",
        sink_call="popen",
    )
    ts_py = synthesize_file_cfg(py_ast, language="python", path="app/api.py")
    ts_cpp = synthesize_file_cfg(cpp_ast, language="cpp", path="src/native.cpp")

    codeql_facts = [
        {
            "kind": "entry_point",
            "language": "python",
            "path": "app/api.py",
            "start_line": 2,
            "name": "api_exec",
        },
        {
            "kind": "call_site",
            "language": "python",
            "path": "app/api.py",
            "start_line": 7,
            "callee": "dispatch_cmd",
            "target_path": "app/api.py",
            "target_line": 10,
        },
        {
            "kind": "dataflow_path",
            "language": "python",
            "steps": [
                {"path": "app/api.py", "start_line": 2},
                {"path": "app/api.py", "start_line": 12},
            ],
        },
        {
            "kind": "sink_site",
            "language": "python",
            "path": "app/api.py",
            "start_line": 12,
            "name": "os.system",
            "sink_class": "command_injection",
        },
    ]
    sarif_observations = [
        {
            "rule_id": "py/command-line-injection",
            "code_flows": [
                {
                    "steps": [
                        {"path": "app/api.py", "start_line": 2},
                        {"path": "app/api.py", "start_line": 12},
                    ]
                }
            ],
        }
    ]
    clangd_symbols = [
        {"identity": "c:@F@cpp_entry", "name": "cpp_entry", "path": "src/native.cpp", "start_line": 2, "end_line": 8},
        {"identity": "c:@F@cpp_exec", "name": "cpp_exec", "path": "src/native.cpp", "start_line": 10, "end_line": 15},
    ]
    clangd_relations = [
        {
            "kind": "CALLS",
            "source_id": "c:@F@cpp_entry",
            "target_id": "c:@F@cpp_exec",
            "payload": {"line": 7},
        }
    ]
    route_entrypoints = [
        {
            "route_pattern": "/api/exec",
            "http_method": "POST",
            "handler_symbol": "api_exec",
            "path": "app/api.py",
            "line": 2,
            "framework": "fastapi",
            "language": "python",
        }
    ]

    cpg = synthesize_alternate_cpg(
        tree_sitter_files=[ts_py, ts_cpp],
        codeql_facts=codeql_facts,
        sarif_observations=sarif_observations,
        clangd_symbols=clangd_symbols,
        clangd_relations=clangd_relations,
        route_entrypoints=route_entrypoints,
        run_id="2026-11-17-0001",
        target_snapshot=SNAPSHOT,
    )

    tiers_seen = {e["resolution_tier"] for e in cpg["edges"]}
    assert tiers_seen <= set(RESOLUTION_TIERS)
    assert "hybrid_fused" in tiers_seen
    assert "codeql_semantic" in tiers_seen
    assert cpg["counts"]["semantic_edges_count"] >= 3
    assert cpg["counts"]["syntactic_fallback_edges_count"] >= 1
    assert cpg["counts"]["entrypoints_linked"] >= 2

    edge_kinds = {e["edge_kind"] for e in cpg["edges"]}
    assert "TAINT_STEP" in edge_kinds
    assert "ENTRYPOINT_TO_FN" in edge_kinds

    py_call = [
        e for e in cpg["edges"]
        if e["edge_kind"] == "CALLS" and e["path"] == "app/api.py" and e["line"] == 7
    ]
    assert len(py_call) >= 1
    assert any(e["resolution_tier"] in {"hybrid_fused", "codeql_semantic"} for e in py_call)

    cpp_call = [
        e for e in cpg["edges"]
        if e["edge_kind"] == "CALLS" and e["path"] == "src/native.cpp" and e["line"] == 7
    ]
    assert len(cpp_call) >= 1
    assert any(e["resolution_tier"] in {"hybrid_fused", "clangd_semantic"} for e in cpp_call)

    clangd_only_cpg = synthesize_alternate_cpg(
        tree_sitter_files=[],
        clangd_symbols=clangd_symbols,
        clangd_relations=clangd_relations,
        run_id="2026-11-17-0002",
        target_snapshot=SNAPSHOT,
    )
    assert any(e["resolution_tier"] == "clangd_semantic" for e in clangd_only_cpg["edges"])

    for rec in (*cpg["nodes"], *cpg["edges"], *cpg["paths"]):
        validator.validate(rec)


def test_ten_hop_interprocedural_reachability_guard_dominators_and_max_hops_cutoff() -> None:
    functions: list[dict[str, Any]] = []
    guard_by_idx = {
        0: ("!check_auth(req)", "if_statement"),
        3: ("req == None", "if_statement"),
        6: ("len(req) > 512", "if_statement"),
        9: ("not escape_shell(req)", "if_statement"),
    }
    for idx in range(11):
        fn_name = "handle_entry_0" if idx == 0 else f"hop_{idx}"
        callee = f"hop_{idx + 1}" if idx < 10 else "subprocess.Popen"
        base_line = idx * 10 + 1
        stmts: list[dict[str, Any]] = []
        if idx in guard_by_idx:
            g_expr, g_type = guard_by_idx[idx]
            stmts.append(
                {
                    "type": g_type,
                    "start_line": base_line + 1,
                    "end_line": base_line + 3,
                    "children": [
                        {"type": "binary_expression", "field": "condition", "text": g_expr, "start_line": base_line + 1, "end_line": base_line + 1},
                        {
                            "type": "block",
                            "field": "consequence",
                            "start_line": base_line + 2,
                            "end_line": base_line + 2,
                            "children": [{"type": "return_statement", "text": "return None", "start_line": base_line + 2, "end_line": base_line + 2}],
                        },
                    ],
                }
            )
        stmts.append(
            {
                "type": "call",
                "text": f"{callee}(req)",
                "start_line": base_line + 5,
                "end_line": base_line + 5,
                "children": [
                    {"type": "identifier", "field": "function", "text": callee, "start_line": base_line + 5, "end_line": base_line + 5},
                    {"type": "identifier", "text": "req", "start_line": base_line + 5, "end_line": base_line + 5},
                ],
            }
        )
        functions.append(
            {
                "type": "function_definition",
                "start_line": base_line,
                "end_line": base_line + 7,
                "children": [
                    {"type": "identifier", "field": "name", "text": fn_name, "start_line": base_line, "end_line": base_line},
                    {
                        "type": "parameters",
                        "field": "parameters",
                        "start_line": base_line,
                        "end_line": base_line,
                        "children": [{"type": "identifier", "text": "req", "start_line": base_line, "end_line": base_line}],
                    },
                    {"type": "block", "field": "body", "start_line": base_line + 1, "end_line": base_line + 7, "children": stmts},
                ],
            }
        )

    ts_chain = synthesize_file_cfg(
        {"type": "module", "start_line": 1, "end_line": 120, "children": functions},
        language="python",
        path="service/pipeline.py",
    )
    cpg_12 = synthesize_alternate_cpg(
        tree_sitter_files=[ts_chain],
        settings=AlternateCpgSettings(max_hops=12),
        run_id="2026-11-17-0003",
        target_snapshot=SNAPSHOT,
    )

    short_paths = find_interprocedural_paths(
        cpg_12, source="handle_entry_0", entrypoint_only=True, max_hops=8
    )
    assert short_paths == []

    full_paths = find_interprocedural_paths(
        cpg_12, source="handle_entry_0", entrypoint_only=True, max_hops=12
    )
    assert len(full_paths) >= 1
    p = full_paths[0]
    assert p["hop_count"] >= 10
    assert set(p["guard_polarities"]) >= {
        "auth_or_role_check",
        "null_check",
        "bounds_check",
        "sanitization_guard",
    }
    assert len(p["guard_dominators"]) >= 4


def test_cycle_handling_and_deterministic_ordering() -> None:
    def _fn(name: str, line: int, calls: list[str]) -> dict[str, Any]:
        return {
            "type": "function_definition",
            "start_line": line,
            "end_line": line + 5,
            "children": [
                {"type": "identifier", "field": "name", "text": name, "start_line": line, "end_line": line},
                {"type": "parameters", "field": "parameters", "start_line": line, "end_line": line, "children": []},
                {
                    "type": "block",
                    "field": "body",
                    "start_line": line + 1,
                    "end_line": line + 5,
                    "children": [
                        {
                            "type": "call",
                            "text": f"{c}()",
                            "start_line": line + idx + 1,
                            "end_line": line + idx + 1,
                            "children": [{"type": "identifier", "field": "function", "text": c, "start_line": line + idx + 1, "end_line": line + idx + 1}],
                        }
                        for idx, c in enumerate(calls)
                    ],
                },
            ],
        }

    ts_files = [
        synthesize_file_cfg({"type": "module", "start_line": 1, "end_line": 10, "children": [_fn("handle_a", 1, ["cycle_b"])]}, language="python", path="app/handle_a.py"),
        synthesize_file_cfg({"type": "module", "start_line": 1, "end_line": 10, "children": [_fn("cycle_b", 1, ["cycle_c", "eval"])]}, language="python", path="app/cycle_b.py"),
        synthesize_file_cfg({"type": "module", "start_line": 1, "end_line": 10, "children": [_fn("cycle_c", 1, ["handle_a"])]}, language="python", path="app/cycle_c.py"),
    ]

    cpg_1 = synthesize_alternate_cpg(
        tree_sitter_files=ts_files,
        run_id="2026-11-17-0004",
        target_snapshot=SNAPSHOT,
    )
    cpg_2 = synthesize_alternate_cpg(
        tree_sitter_files=list(reversed(ts_files)),
        run_id="2026-11-17-0004",
        target_snapshot=SNAPSHOT,
    )

    assert [n["node_id"] for n in cpg_1["nodes"]] == [n["node_id"] for n in cpg_2["nodes"]]
    assert [e["edge_id"] for e in cpg_1["edges"]] == [e["edge_id"] for e in cpg_2["edges"]]
    assert [p["path_id"] for p in cpg_1["paths"]] == [p["path_id"] for p in cpg_2["paths"]]
    assert len(cpg_1["paths"]) >= 1

    bwd = compute_cpg_slice(cpg_1, function_name="eval", direction="backward", max_depth=10)
    fwd = compute_cpg_slice(cpg_1, function_name="handle_a", direction="forward", max_depth=10)
    assert len(bwd["nodes"]) >= 3
    assert len(fwd["nodes"]) >= 3


def test_sqlite_publication_and_retrieval_queries_cpg_slice_and_call_paths(tmp_path: Path) -> None:
    run_id = "2026-11-17-0010"
    run_root = tmp_path / "runs" / run_id
    target_dir = tmp_path / "target"
    (target_dir / "auth").mkdir(parents=True)
    login_file = target_dir / "auth" / "login.py"
    login_file.write_text("# fixture\n" * 16, encoding="utf-8")

    unit_root = run_root / "data" / "jobs" / "job_code_graph_index" / "attempts" / "attempt-001" / "steps" / "acceptance" / "tasks" / "publish_handoff"
    unit_root.mkdir(parents=True)

    py_ast = _make_two_fn_ast(
        fn_type="function_definition",
        body_type="block",
        if_type="if_statement",
        ret_type="return_statement",
        call_type="call",
        entry_name="handle_login",
        helper_name="exec_sql",
        guard_expr="input_val is None",
        sink_call="cursor.execute",
    )
    ts_py = synthesize_file_cfg(py_ast, language="python", path="auth/login.py")
    cpg = synthesize_alternate_cpg(
        tree_sitter_files=[ts_py],
        route_entrypoints=[
            {
                "route_pattern": "/login",
                "http_method": "POST",
                "handler_symbol": "handle_login",
                "path": "auth/login.py",
                "line": 2,
                "framework": "flask",
                "language": "python",
            }
        ],
        run_id=run_id,
        target_snapshot=SNAPSHOT,
    )

    summary_doc, shard_identity = publish_alternate_cpg(
        run_root,
        unit_root,
        cpg,
        job_id="job_code_graph_index",
        unit_id="acceptance.publish_handoff",
        file_shas={"auth/login.py": file_sha256(login_file)},
    )

    assert summary_doc["counts"]["alternate_cpg_nodes"] >= 6
    assert summary_doc["counts"]["alternate_cpg_edges"] >= 6
    assert summary_doc["counts"]["entrypoints_linked"] >= 1
    assert summary_doc["counts"]["reachable_sink_paths_precomputed"] >= 1
    assert (run_root / "data/code-graph/alternate-cpg/cpg-nodes.jsonl").is_file()
    assert (run_root / "data/code-graph/alternate-cpg/cpg-edges.jsonl").is_file()
    assert (run_root / "data/code-graph/alternate-cpg/cpg-paths.jsonl").is_file()
    assert (unit_root / "alternate-cpg-summary.json").is_file()

    manifest_path = run_root / "data" / "indices" / "manifest.json"
    write_manifest(
        manifest_path,
        run_id=run_id,
        target_snapshot=SNAPSHOT,
        target_root=target_dir,
        indexes=[shard_identity],
    )
    core = RetrievalCore(
        tmp_path / "runs",
        run_id,
        manifest_path=manifest_path,
        manifest_sha256=file_sha256(manifest_path),
    )

    # 1. query_call_paths
    paths_res = query_call_paths(
        core,
        entrypoint_only=True,
        sink_class="sql_injection",
        language="python",
        max_hops=10,
    )
    assert len(paths_res["results"]) >= 1
    first_path = paths_res["results"][0]
    assert first_path["source_name"] == "handle_login"
    assert first_path["sink_class"] == "sql_injection"
    assert "null_check" in first_path["guard_polarities"]

    # 2. Backward query_cpg_slice from sink line
    bwd_res = query_cpg_slice(
        core,
        direction="backward",
        path="auth/login.py",
        line=12,
        max_depth=8,
    )
    slice_names = {item["name"] for item in bwd_res["results"]}
    assert "exec_sql" in slice_names
    assert "handle_login" in slice_names

    # 3. Forward query_cpg_slice with pagination (limit=2)
    fwd_page1 = query_cpg_slice(
        core,
        direction="forward",
        function_name="handle_login",
        max_depth=8,
        limit=2,
    )
    assert len(fwd_page1["results"]) == 2
    assert fwd_page1["truncated"] is True
    assert fwd_page1["pagination"]["next_cursor"] is not None

    fwd_page2 = query_cpg_slice(
        core,
        direction="forward",
        function_name="handle_login",
        max_depth=8,
        limit=2,
        cursor=fwd_page1["pagination"]["next_cursor"],
    )
    assert len(fwd_page2["results"]) >= 1

    # 4. Validation & named gaps
    with pytest.raises(ValueError, match="direction"):
        query_cpg_slice(core, direction="sideways", function_name="handle_login")
    with pytest.raises(ValueError, match="max_hops"):
        query_call_paths(core, max_hops=99)

    missing_res = query_cpg_slice(core, direction="backward", function_name="nonexistent_symbol_xyz")
    assert missing_res["results"] == []
    assert any("no Alternate CPG node matched" in g for g in missing_res["coverage_gaps"])

    # Empty run manifest -> named gap accepted analysis/alternate-cpg shard is unavailable
    empty_run_id = "2026-11-17-0011"
    empty_run_root = tmp_path / "runs" / empty_run_id
    empty_manifest = empty_run_root / "data" / "indices" / "manifest.json"
    write_manifest(
        empty_manifest,
        run_id=empty_run_id,
        target_snapshot=SNAPSHOT,
        target_root=target_dir,
        indexes=[],
    )
    empty_core = RetrievalCore(
        tmp_path / "runs",
        empty_run_id,
        manifest_path=empty_manifest,
        manifest_sha256=file_sha256(empty_manifest),
    )
    unavail = query_call_paths(empty_core)
    assert unavail["results"] == []
    assert any("alternate-cpg shard is unavailable" in g for g in unavail["coverage_gaps"])
