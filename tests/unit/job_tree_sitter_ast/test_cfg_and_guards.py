"""Fast (<2s) unit tests for universal Tree-sitter intra-procedural CFG and guard polarity (T-168)."""

from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from appsec_review.jobs.job_tree_sitter_ast.cfg import (
    CFG_SCHEMA,
    EDGE_KINDS,
    GUARD_POLARITIES,
    classify_guard_polarity,
    flatten_syntax_tree,
    synthesize_file_cfg,
    write_scope_cfg_artifacts,
)
from appsec_review.jobs.job_tree_sitter_ast.model import GrammarLock, Scope
from appsec_review.jobs.job_tree_sitter_ast.normalize import normalize_scope, reusable_shard
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.retrieval.index import write_manifest
from appsec_review.storage import file_sha256
from appsec_review.retrieval.model import EntityKind, LogicalIdentity
from appsec_review.retrieval.syntax import query_cfg_function, query_guard_dominators


SCHEMA_PATH = Path("docs/schemas/tree-sitter-ast/tree-sitter-cfg.schema.json")


@pytest.mark.parametrize(
    ("expr", "expected_polarity"),
    [
        ("ptr == nullptr", "null_check"),
        ("x is not None", "null_check"),
        ("val.nil?", "null_check"),
        ("opt.is_some()", "null_check"),
        ("idx < buf_len && idx >= 0", "bounds_check"),
        ("len(items) <= MAX_SIZE", "bounds_check"),
        ("user.is_admin() && has_permission(ctx, 'write')", "auth_or_role_check"),
        ("verify_jwt(req.headers)", "auth_or_role_check"),
        ("err != nil", "error_return_guard"),
        ("FAILED(hr)", "error_return_guard"),
        ("res.is_err()", "error_return_guard"),
        ("sanitize_html(input_str)", "sanitization_guard"),
        ("filepath.Clean(rawPath)", "sanitization_guard"),
        ("mode == 'fast'", "general_condition"),
    ],
)
def test_guard_polarity_classifier_covers_all_closed_polarities(expr: str, expected_polarity: str) -> None:
    polarity, cleaned, identifiers = classify_guard_polarity(expr)
    assert polarity == expected_polarity
    assert polarity in GUARD_POLARITIES
    assert cleaned
    assert isinstance(identifiers, list)


LANGUAGE_FIXTURES: list[tuple[str, str, str, str, str, str, str, str, str]] = [
    ("cpp", "src/parser.cpp", "function_definition", "compound_statement", "if_statement", "while_statement", "return_statement", "ptr == nullptr", "null_check"),
    ("java", "src/AuthController.java", "method_declaration", "block", "if_statement", "for_statement", "return_statement", "!user.hasRole('ADMIN')", "auth_or_role_check"),
    ("javascript", "src/router.js", "function_declaration", "statement_block", "if_statement", "while_statement", "return_statement", "idx >= items.length", "bounds_check"),
    ("python", "app/views.py", "function_definition", "block", "if_statement", "for_statement", "return_statement", "not user.is_authenticated", "auth_or_role_check"),
    ("ruby", "app/controllers/users_controller.rb", "method", "body_statement", "if", "while", "return", "record.nil?", "null_check"),
    ("go", "pkg/api/handler.go", "function_declaration", "block", "if_statement", "for_statement", "return_statement", "err != nil", "error_return_guard"),
    ("csharp", "Controllers/OrdersController.cs", "method_declaration", "block", "if_statement", "foreach_statement", "return_statement", "!User.IsInRole('Manager')", "auth_or_role_check"),
    ("rust", "src/handler.rs", "function_item", "block", "if_expression", "loop_expression", "return_expression", "payload.is_err()", "error_return_guard"),
    ("php", "src/UserController.php", "method_declaration", "compound_statement", "if_statement", "foreach_statement", "return_statement", "htmlspecialchars($rawInput)", "sanitization_guard"),
]


@pytest.mark.parametrize(
    ("lang", "rel_path", "fn_type", "body_type", "if_type", "loop_type", "ret_type", "guard_expr", "expected_pol"),
    LANGUAGE_FIXTURES,
    ids=[item[0] for item in LANGUAGE_FIXTURES],
)
def test_cfg_synthesis_across_all_nine_target_languages(
    lang: str,
    rel_path: str,
    fn_type: str,
    body_type: str,
    if_type: str,
    loop_type: str,
    ret_type: str,
    guard_expr: str,
    expected_pol: str,
) -> None:
    validator = Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))
    tree = {
        "type": "program",
        "start_line": 1,
        "end_line": 20,
        "children": [
            {
                "type": fn_type,
                "start_line": 2,
                "end_line": 18,
                "children": [
                    {"type": "identifier", "field": "name", "text": "handle_request", "start_line": 2, "end_line": 2},
                    {
                        "type": "parameters",
                        "field": "parameters",
                        "start_line": 2,
                        "end_line": 2,
                        "children": [{"type": "identifier", "text": "req", "start_line": 2, "end_line": 2}],
                    },
                    {
                        "type": body_type,
                        "field": "body",
                        "start_line": 3,
                        "end_line": 18,
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
                                        "end_line": 5,
                                        "children": [{"type": ret_type, "text": "return err", "start_line": 4, "end_line": 4}],
                                    },
                                ],
                            },
                            {
                                "type": loop_type,
                                "start_line": 7,
                                "end_line": 12,
                                "children": [
                                    {"type": "binary_expression", "field": "condition", "text": "i < limit", "start_line": 7, "end_line": 7},
                                    {
                                        "type": body_type,
                                        "field": "body",
                                        "start_line": 8,
                                        "end_line": 12,
                                        "children": [
                                            {
                                                "type": if_type,
                                                "start_line": 8,
                                                "end_line": 9,
                                                "children": [
                                                    {"type": "binary_expression", "field": "condition", "text": "i >= max_len", "start_line": 8, "end_line": 8},
                                                    {
                                                        "type": body_type,
                                                        "field": "consequence",
                                                        "start_line": 8,
                                                        "end_line": 9,
                                                        "children": [{"type": "break_statement", "text": "break", "start_line": 8, "end_line": 8}],
                                                    },
                                                ],
                                            },
                                            {
                                                "type": if_type,
                                                "start_line": 10,
                                                "end_line": 11,
                                                "children": [
                                                    {"type": "call_expression", "field": "condition", "text": "sanitize_sql(item)", "start_line": 10, "end_line": 10},
                                                    {
                                                        "type": body_type,
                                                        "field": "consequence",
                                                        "start_line": 10,
                                                        "end_line": 11,
                                                        "children": [{"type": "continue_statement", "text": "continue", "start_line": 10, "end_line": 10}],
                                                    },
                                                ],
                                            },
                                        ],
                                    },
                                ],
                            },
                            {
                                "type": "expression_statement",
                                "start_line": 14,
                                "end_line": 14,
                                "children": [
                                    {
                                        "type": "call_expression",
                                        "start_line": 14,
                                        "end_line": 14,
                                        "children": [
                                            {"type": "identifier", "field": "function", "text": "exec_query", "start_line": 14, "end_line": 14},
                                            {"type": "identifier", "text": "req", "start_line": 14, "end_line": 14},
                                        ],
                                    }
                                ],
                            },
                            {"type": ret_type, "text": "return ok", "start_line": 16, "end_line": 16},
                        ],
                    },
                ],
            }
        ],
    }

    file_sha = hashlib.sha256(rel_path.encode("utf-8")).hexdigest()
    source_id = f"asr:source_file:{file_sha[:24]}"
    result = synthesize_file_cfg(
        tree,
        language=lang,
        path=rel_path,
        file_sha256=file_sha,
        source_identity=source_id,
    )
    assert len(result.functions) == 1
    fn = result.functions[0]
    assert fn.language == lang
    assert fn.function_name == "handle_request"
    assert fn.guard_count >= 1

    edge_kinds = {e.edge_kind for e in fn.edges}
    assert {"entry", "true_branch", "false_branch", "loop_back", "break_edge", "continue_edge", "return_exit"} <= edge_kinds
    assert edge_kinds <= set(EDGE_KINDS)

    polarities = {n.guard_polarity for n in fn.nodes if n.guard_polarity is not None}
    assert expected_pol in polarities

    sink_nodes = [n for n in fn.nodes if n.start_line == 14]
    assert sink_nodes, "expected sink call statement node at line 14"
    sink_doms = sink_nodes[0].guard_dominators
    assert any(
        d.guard_polarity == expected_pol and d.branch_arm == "false_branch"
        for d in sink_doms
    ), f"expected early-return false_branch guard dominator on sink node, got {sink_doms}"

    for node in fn.nodes:
        validator.validate(node.to_jsonl_record())
    for edge in fn.edges:
        validator.validate(edge.to_jsonl_record())


def test_exception_and_switch_fallthrough_edges_and_manifest_schema(tmp_path: Path) -> None:
    validator = Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))
    nested_tree = {
        "type": "program",
        "start_line": 1,
        "end_line": 22,
        "children": [
            {
                "type": "function_declaration",
                "start_line": 1,
                "end_line": 20,
                "children": [
                    {"type": "identifier", "field": "name", "text": "process", "start_line": 1, "end_line": 1},
                    {
                        "type": "statement_block",
                        "field": "body",
                        "start_line": 2,
                        "end_line": 20,
                        "children": [
                            {
                                "type": "try_statement",
                                "start_line": 2,
                                "end_line": 8,
                                "children": [
                                    {
                                        "type": "statement_block",
                                        "field": "body",
                                        "start_line": 2,
                                        "end_line": 4,
                                        "children": [
                                            {"type": "throw_statement", "text": "throw new Error('bad')", "start_line": 3, "end_line": 3}
                                        ],
                                    },
                                    {
                                        "type": "catch_clause",
                                        "start_line": 5,
                                        "end_line": 7,
                                        "children": [
                                            {
                                                "type": "statement_block",
                                                "field": "body",
                                                "start_line": 5,
                                                "end_line": 7,
                                                "children": [
                                                    {"type": "expression_statement", "text": "log(err)", "start_line": 6, "end_line": 6}
                                                ],
                                            }
                                        ],
                                    },
                                ],
                            },
                            {
                                "type": "switch_statement",
                                "start_line": 10,
                                "end_line": 18,
                                "children": [
                                    {"type": "identifier", "field": "value", "text": "tag", "start_line": 10, "end_line": 10},
                                    {
                                        "type": "switch_body",
                                        "field": "body",
                                        "start_line": 10,
                                        "end_line": 18,
                                        "children": [
                                            {
                                                "type": "switch_case",
                                                "start_line": 11,
                                                "end_line": 13,
                                                "children": [
                                                    {"type": "number", "field": "value", "text": "1", "start_line": 11, "end_line": 11},
                                                    {"type": "expression_statement", "text": "step1()", "start_line": 12, "end_line": 12},
                                                ],
                                            },
                                            {
                                                "type": "switch_case",
                                                "start_line": 14,
                                                "end_line": 17,
                                                "children": [
                                                    {"type": "number", "field": "value", "text": "2", "start_line": 14, "end_line": 14},
                                                    {"type": "break_statement", "text": "break", "start_line": 16, "end_line": 16},
                                                ],
                                            },
                                        ],
                                    },
                                ],
                            },
                        ],
                    },
                ],
            }
        ],
    }

    res = synthesize_file_cfg(
        nested_tree,
        language="javascript",
        path="src/worker.js",
        file_sha256="a" * 64,
        source_identity="asr:source_file:" + ("b" * 24),
    )
    fn = res.functions[0]
    edge_kinds = {e.edge_kind for e in fn.edges}
    assert "exception_edge" in edge_kinds
    assert "fallthrough" in edge_kinds
    assert "unconditional" in edge_kinds

    cfg_dir = tmp_path / "data/treesitter/cfg/fp1"
    written, cfg_counts = write_scope_cfg_artifacts(
        run_root=tmp_path,
        cfg_dir=cfg_dir,
        scope_id="js-scope",
        language="JavaScript",
        grammar="javascript",
        target_snapshot="c" * 64,
        file_results=[res],
    )
    manifest = json.loads((tmp_path / written["manifest"]["path"]).read_text(encoding="utf-8"))
    validator.validate(manifest)
    assert cfg_counts["cfg_functions_built"] == 1


def test_normalize_scope_and_retrieval_cfg_and_guard_dominator_queries(tmp_path: Path) -> None:
    src_text = (
        "def update_account(user, token, sql_cmd):\n"
        "    if not verify_token(token):\n"
        "        return None\n"
        "    if user is None:\n"
        "        return None\n"
        "    if len(sql_cmd) <= 256:\n"
        "        db_execute(sql_cmd)\n"
        "    return True\n"
    )
    src_bytes = src_text.encode("utf-8")
    digest = hashlib.sha256(src_bytes).hexdigest()
    target_snap = "d" * 64

    lines = src_text.splitlines(keepends=True)
    offsets: list[tuple[int, int]] = []
    pos = 0
    for ln in lines:
        b = len(ln.encode("utf-8"))
        offsets.append((pos, pos + b))
        pos += b

    def span_of(sub: str, start_from: int = 0) -> tuple[int, int, list[int], list[int]]:
        idx = src_text.index(sub, start_from)
        end_idx = idx + len(sub)
        sl = src_text.count("\n", 0, idx)
        sc = idx - (src_text.rfind("\n", 0, idx) + 1)
        el = src_text.count("\n", 0, end_idx)
        ec = end_idx - (src_text.rfind("\n", 0, end_idx) + 1)
        return idx, end_idx, [sl, sc], [el, ec]

    def cst(ord_path: list[int], ntype: str, sub: str, *, field: str | None = None, start_from: int = 0) -> dict[str, Any]:
        sb, eb, sp, ep = span_of(sub, start_from)
        return {
            "ordinal_path": ord_path,
            "field": field,
            "type": ntype,
            "named": True,
            "start_byte": sb,
            "end_byte": eb,
            "start_point": sp,
            "end_point": ep,
        }

    if1_str = "if not verify_token(token):\n        return None"
    if2_str = "if user is None:\n        return None"
    if3_str = "if len(sql_cmd) <= 256:\n        db_execute(sql_cmd)"
    body_str = src_text[src_text.index("if not verify_token"):]

    nodes = [
        {"ordinal_path": [], "field": None, "type": "module", "named": True, "start_byte": 0, "end_byte": len(src_bytes), "start_point": [0, 0], "end_point": [8, 0]},
        {"ordinal_path": [0], "field": None, "type": "function_definition", "named": True, "start_byte": 0, "end_byte": len(src_bytes), "start_point": [0, 0], "end_point": [8, 0]},
        cst([0, 0], "identifier", "update_account", field="name"),
        cst([0, 1], "parameters", "(user, token, sql_cmd)", field="parameters"),
        cst([0, 2], "block", body_str, field="body"),
        cst([0, 2, 0], "if_statement", if1_str),
        cst([0, 2, 0, 0], "not_operator", "not verify_token(token)", field="condition"),
        cst([0, 2, 0, 1], "block", "return None", field="consequence", start_from=src_text.index("if not")),
        cst([0, 2, 0, 1, 0], "return_statement", "return None", start_from=src_text.index("if not")),
        cst([0, 2, 1], "if_statement", if2_str),
        cst([0, 2, 1, 0], "comparison_operator", "user is None", field="condition"),
        cst([0, 2, 1, 1], "block", "return None", field="consequence", start_from=src_text.index("if user")),
        cst([0, 2, 1, 1, 0], "return_statement", "return None", start_from=src_text.index("if user")),
        cst([0, 2, 2], "if_statement", if3_str),
        cst([0, 2, 2, 0], "comparison_operator", "len(sql_cmd) <= 256", field="condition"),
        cst([0, 2, 2, 1], "block", "db_execute(sql_cmd)", field="consequence"),
        cst([0, 2, 2, 1, 0], "expression_statement", "db_execute(sql_cmd)"),
        cst([0, 2, 2, 1, 0, 0], "call", "db_execute(sql_cmd)"),
        cst([0, 2, 2, 1, 0, 0, 0], "identifier", "db_execute", field="function"),
        cst([0, 2, 3], "return_statement", "return True"),
    ]

    scope = Scope(
        "python-scope",
        "component",
        ".",
        "source:component",
        ".",
        "Python",
        ({"path": "app/account.py", "sha256": digest, "size_bytes": len(src_bytes), "language": "Python"},),
    )
    grammar = GrammarLock(
        "Python", "python", "https://example.invalid/grammar", "a" * 40, "MIT", "python.so", "b" * 64,
    )
    output = {
        "schema": "appsec-review/tree-sitter-container-output/1",
        "scope_id": scope.scope_id,
        "language": "Python",
        "records": [
            {
                "path": "app/account.py",
                "sha256": digest,
                "status": "SUCCEEDED",
                "bytes": len(src_bytes),
                "nodes": nodes,
            }
        ],
    }
    run_id = "2026-11-17-0001"
    run_root = tmp_path / run_id
    target_dir = tmp_path / "target"
    target_dir.mkdir(parents=True, exist_ok=True)
    fp = "f" * 64
    artifact_path = run_root / "data/treesitter/shards" / f"{fp}.jsonl"
    index_path = run_root / "data/indices/analysis" / f"{fp}.sqlite"
    cfg_dir = run_root / "data/treesitter/cfg" / fp
    metadata_path = run_root / "data/treesitter/shards" / f"{fp}.json"

    artifact, identity, counts = normalize_scope(
        run_root=run_root,
        target_snapshot=target_snap,
        scope=scope,
        grammar=grammar,
        fingerprint=fp,
        container_output=output,
        producer={"job": "job_tree_sitter_ast", "scope_id": scope.scope_id},
        artifact_path=artifact_path,
        index_path=index_path,
        source_bytes={"app/account.py": src_bytes},
        cfg_dir=cfg_dir,
    )
    counts_mut = dict(counts)
    assert counts_mut["cfg_functions_built"] == 1
    assert counts_mut["cfg_nodes_emitted"] >= 6
    assert counts_mut["cfg_edges_emitted"] >= 6
    assert counts_mut["cfg_guards_classified"] == 3
    assert counts_mut["cfg_languages"] == ["python"]
    cfg_artifacts = counts_mut.pop("cfg_artifacts")
    assert (run_root / cfg_artifacts["nodes"]["path"]).is_file()
    assert (run_root / cfg_artifacts["edges"]["path"]).is_file()
    assert (run_root / cfg_artifacts["manifest"]["path"]).is_file()

    meta_record = {
        "fingerprint": fp,
        "artifact": artifact,
        "cfg_artifacts": cfg_artifacts,
        "index_identity": asdict(identity),
        "terminal_status": "completed",
    }
    metadata_path.write_text(json.dumps(meta_record), encoding="utf-8")
    assert reusable_shard(metadata_path, artifact_path, index_path, fp) is not None

    manifest_path = run_root / "data/indices/manifest.json"
    write_manifest(
        manifest_path,
        run_id=run_id,
        target_snapshot=target_snap,
        target_root=target_dir,
        indexes=[identity],
    )
    core = RetrievalCore(tmp_path, run_id, manifest_path=manifest_path, manifest_sha256=file_sha256(manifest_path))

    fn_resp = query_cfg_function(core, function_name="update_account", path="app/account.py")
    assert len(fn_resp["results"]) == 1
    fn_rec = fn_resp["results"][0]
    assert fn_rec["schema"] == CFG_SCHEMA
    assert fn_rec["path"] == "app/account.py"
    assert fn_rec["guard_count"] == 3
    assert fn_rec["start_line"] == 1 and fn_rec["end_line"] == 9

    # Line 7 (db_execute(sql_cmd)) is dominated by all 3 guards:
    # 1) auth_or_role_check (false_branch of early return `if not verify_token(token)`)
    # 2) null_check (false_branch of early return `if user is None`)
    # 3) bounds_check (true_branch of `if len(sql_cmd) <= 256`)
    dom_resp = query_guard_dominators(core, path="app/account.py", line=7)
    assert len(dom_resp["results"]) == 1
    doms = dom_resp["results"][0]["guard_dominators"]
    pol_branches = [(d["guard_polarity"], d["branch_arm"]) for d in doms]
    assert ("auth_or_role_check", "false_branch") in pol_branches
    assert ("null_check", "false_branch") in pol_branches
    assert ("bounds_check", "true_branch") in pol_branches
    assert any("len(sql_cmd) <= 256" in d["guard_expression"] for d in doms)
    assert any("user is None" in d["guard_expression"] for d in doms)

    auth_only = query_guard_dominators(core, path="app/account.py", line=7, polarity="auth_or_role_check")
    assert len(auth_only["results"]) == 1
    assert [d["guard_polarity"] for d in auth_only["results"][0]["guard_dominators"]] == ["auth_or_role_check"]

    src_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, target_snap, {"path": "app/account.py", "sha256": digest}).value
    by_src = query_cfg_function(core, subject=src_id)
    assert len(by_src["results"]) == 1
    assert by_src["results"][0]["function_id"] == fn_rec["function_id"]


def _public_finally_cfg(tmp_path: Path, *, legacy: bool = False, parse_partial: bool = False,
                        unmodeled: bool = False, extra_statements: int = 0):
    source = (
        "function f(flag, user) {\n"
        "  if (!has_role(user)) { return; }\n"
        "  try {\n"
        "    if (flag) { return; }\n"
        "    normal();\n"
        "  } finally {\n"
        "    if (is_valid(user)) {\n"
        "      cleanup();\n"
        "    }\n"
        "  }\n"
        "  after();\n"
        "}\n"
    )
    if unmodeled:
        source = source.replace("  after();", "  done: after();")
    elif extra_statements:
        source = source.replace("  after();", "".join(f"  tail_{i}();\n" for i in range(extra_statements)) + "  after();")

    def n(kind, text, *children, field=None, after=0):
        start = source.index(text, after)
        end = start + len(text)
        return {
            "type": kind, "field": field, "children": list(children),
            "start_byte": start, "end_byte": end,
            "start_line": source.count("\n", 0, start) + 1,
            "end_line": source.count("\n", 0, end) + 1,
        }

    def call(name):
        return n("expression_statement", f"{name}();",
                 n("call_expression", f"{name}()",
                   n("identifier", name, field="function")))

    auth = n("if_statement", "if (!has_role(user)) { return; }",
             n("parenthesized_expression", "(!has_role(user))", field="condition"),
             n("statement_block", "{ return; }", n("return_statement", "return;"), field="consequence"))
    flag_pos = source.index("if (flag)")
    flag = n("if_statement", "if (flag) { return; }",
             n("parenthesized_expression", "(flag)", field="condition"),
             n("statement_block", "{ return; }",
               n("return_statement", "return;", after=flag_pos), field="consequence", after=flag_pos))
    inner = n("if_statement", "if (is_valid(user)) {\n      cleanup();\n    }",
              n("parenthesized_expression", "(is_valid(user))", field="condition"),
              n("statement_block", "{\n      cleanup();\n    }", call("cleanup"), field="consequence"))
    protected = n("try_statement", "try {\n    if (flag) { return; }\n    normal();\n  } finally {\n    if (is_valid(user)) {\n      cleanup();\n    }\n  }",
                  n("statement_block", "{\n    if (flag) { return; }\n    normal();\n  }",
                    flag, call("normal"), field="body"),
                  n("finally_clause", "finally {\n    if (is_valid(user)) {\n      cleanup();\n    }\n  }",
                    n("statement_block", "{\n    if (is_valid(user)) {\n      cleanup();\n    }\n  }",
                      inner, field="body")))
    after_statement = n("labeled_statement", "done: after();", call("after")) if unmodeled else call("after")
    tree = n("program", source, n(
        "function_declaration", source, n("identifier", "f", field="name", after=source.index(" f")),
        n("statement_block", source[source.index("{"):].rstrip(), auth, protected,
          *(call(f"tail_{i}") for i in range(extra_statements)), after_statement, field="body")))
    data = source.encode()
    nodes, _ = flatten_syntax_tree(tree, data)
    digest = hashlib.sha256(data).hexdigest()
    scope = Scope("scope", "component", ".", "source:component", ".", "JavaScript",
                  ({"path": "app.js", "sha256": digest, "size_bytes": len(data), "language": "JavaScript"},))
    grammar = GrammarLock("JavaScript", "javascript", "https://example.invalid/grammar", "a" * 40,
                          "MIT", "grammar.so", "b" * 64)
    run_id = "2026-11-19-0001"
    run_root = tmp_path / run_id
    _, identity, _ = normalize_scope(
        run_root=run_root, target_snapshot="a" * 64, scope=scope, grammar=grammar, fingerprint="f" * 64,
        container_output={"schema": "appsec-review/tree-sitter-container-output/1",
                          "scope_id": scope.scope_id, "language": scope.language, "records": [
                              {"path": "app.js", "sha256": digest, "status": "SUCCEEDED",
                               "bytes": len(data), "nodes": nodes, "truncated": parse_partial},
                          ]},
        producer={"job": "job_tree_sitter_ast"}, artifact_path=run_root / "ast.jsonl",
        index_path=run_root / "ast.sqlite", source_bytes={"app.js": data},
    )
    with sqlite3.connect(run_root / "ast.sqlite") as db:
        rows = list(db.execute("SELECT identity,payload_json FROM entities"))
        raw_cfg = next(json.loads(p) for _, p in rows if "cfg_nodes" in json.loads(p))
        cleanup = [x for x in raw_cfg["cfg_nodes"] if "cleanup" in x["calls"]]
        if legacy:
            for entity_id, payload_json in rows:
                payload = json.loads(payload_json)
                if "cfg" in payload:
                    for key in ("coverage_status", "gaps", "truncated", "unmodeled_constructs"):
                        payload["cfg"].pop(key)
                    db.execute("UPDATE entities SET payload_json=? WHERE identity=?", (json.dumps(payload), entity_id))
    if legacy:
        identity = replace(identity, sha256=file_sha256(run_root / "ast.sqlite"))
    manifest = run_root / "manifest.json"
    write_manifest(manifest, run_id=run_id, target_snapshot="a" * 64, target_root=run_root, indexes=[identity])
    return (RetrievalCore(tmp_path, run_id, manifest_path=manifest, manifest_sha256=file_sha256(manifest)),
            raw_cfg, cleanup)


@pytest.mark.parametrize("reason", ["node_cap", "legacy", "parse_partial", "unmodeled"])
def test_public_cfg_and_guard_queries_surface_incomplete_producer_coverage(tmp_path, monkeypatch, reason):
    if reason == "node_cap":
        from appsec_review.jobs.job_tree_sitter_ast import cfg
        monkeypatch.setattr(cfg, "MAX_CFG_NODES_PER_FUNCTION", 8)
    core, raw, _ = _public_finally_cfg(tmp_path, legacy=reason == "legacy",
                                     parse_partial=reason == "parse_partial", unmodeled=reason == "unmodeled")
    response = core.query_cfg_function(path="app.js")
    assert response["results"]
    expected = {"node_cap": "cfg_node_limit_reached", "legacy": "unknown", "parse_partial": "node limit reached",
                "unmodeled": "cfg_unmodeled_construct:labeled_statement"}[reason]
    assert any(expected in gap for gap in response["coverage_gaps"])
    assert all(not n["guard_dominators"] for n in response["results"][0]["nodes"])
    guarded = next(n for n in raw["cfg_nodes"] if n["kind"] not in {"entry", "exit"})
    guards = core.query_guard_dominators(path="app.js", node_id=guarded["node_id"])
    assert guards["results"]
    assert not guards["results"][0]["guard_dominators"]
    assert any(expected in gap for gap in guards["coverage_gaps"])


@pytest.mark.parametrize("selector", ["line", "ast", "source", "source_all"])
def test_public_source_occurrence_guards_intersect_all_finally_contexts(tmp_path, selector):
    core, raw, cleanup = _public_finally_cfg(tmp_path)
    assert len(cleanup) >= 2
    assert len({n["ast_identity"] for n in cleanup}) == 1
    params = {"path": "app.js", "line": 8}
    if selector == "ast":
        params = {"subject": cleanup[0]["ast_identity"]}
    elif selector == "source":
        params = {"subject": raw["cfg"]["source_identity"], "line": 8}
    elif selector == "source_all":
        params = {"subject": raw["cfg"]["source_identity"]}
    response = core.query_guard_dominators(**params, limit=20 if selector == "source_all" else 1)
    cleanup_rows = [r for r in response["results"] if r["ast_identity"] == cleanup[0]["ast_identity"]]
    assert len(cleanup_rows) == 1
    guards = cleanup_rows[0]["guard_dominators"]
    assert {g["guard_expression"] for g in guards} == {
        "(!has_role(user))", "(is_valid(user))",
    }
    assert {(g["guard_polarity"], g["branch_arm"]) for g in guards} == {
        ("auth_or_role_check", "false_branch"), ("sanitization_guard", "true_branch"),
    }
    assert any("cfg_ast_context_projection" in gap for gap in response["coverage_gaps"])
    assert not any(r["ast_identity"] == cleanup[0]["ast_identity"] for r in
                   core.query_guard_dominators(**params, polarity="general_condition")["results"])


def test_explicit_cfg_node_keeps_its_context_guards_and_function_keeps_context_edges(tmp_path):
    core, raw, cleanup = _public_finally_cfg(tmp_path)
    contextual = next(n for n in cleanup if any(g["guard_expression"] == "(flag)" for g in n["guard_dominators"]))
    response = core.query_guard_dominators(node_id=contextual["node_id"])
    assert response["results"][0]["guard_dominators"] == contextual["guard_dominators"]
    function_response = core.query_cfg_function(subject=raw["cfg"]["source_identity"])
    assert len(function_response["results"]) == 1
    assert len(function_response["results"][0]["nodes"]) == len(raw["cfg_nodes"])
    assert {e["edge_id"] for e in function_response["results"][0]["edges"]} == {e["edge_id"] for e in raw["cfg_edges"]}
    assert any("cfg_ast_context_projection" in gap for gap in function_response["coverage_gaps"])
    assert not {"coverage_status", "gaps", "truncated", "unmodeled_constructs"} & function_response["results"][0].keys()
    assert set(response["results"][0]) == {
        "schema", "function_id", "function_name", "node_id", "ast_identity", "kind", "language",
        "source_identity", "path", "file_sha256", "start_line", "end_line", "statement_text", "guard_dominators",
    }


def test_unresolved_ast_subject_does_not_fall_back_to_other_function_guards(tmp_path):
    core, _, cleanup = _public_finally_cfg(tmp_path)
    response = core.query_guard_dominators(subject="asr:ast_node:" + "0" * 64)
    assert not response["results"]
    assert response["coverage_gaps"]
    assert not core.query_guard_dominators(subject="asr:source_file:" + "0" * 64,
                                          node_id=cleanup[0]["node_id"])["results"]


def test_public_cfg_names_payload_loss_from_real_index_serialization_bounds(tmp_path):
    core, raw, _ = _public_finally_cfg(tmp_path, extra_statements=501)
    assert raw["cfg"]["coverage_status"] == "complete"
    assert raw["cfg"]["node_count"] > len(raw["cfg_nodes"])
    response = core.query_cfg_function(path="app.js")
    assert response["truncated"] and not response["results"]
    assert any("cfg_payload_incomplete" in gap for gap in response["coverage_gaps"])
    guarded = next(n for n in raw["cfg_nodes"] if n["guard_dominators"])
    guards = core.query_guard_dominators(node_id=guarded["node_id"])
    assert guards["results"] and not guards["results"][0]["guard_dominators"]
    assert any("cfg_payload_incomplete" in gap for gap in guards["coverage_gaps"])
