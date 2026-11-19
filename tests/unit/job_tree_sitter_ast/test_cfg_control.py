"""T-5211: real recorded CST and small producer-shaped control-flow regressions."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest
from jsonschema import Draft202012Validator

from appsec_review.jobs.job_tree_sitter_ast import cfg
from appsec_review.jobs.job_tree_sitter_ast.model import GrammarLock, Scope
from appsec_review.jobs.job_tree_sitter_ast.normalize import normalize_scope


def node(kind, *children, text=None, field=None):
    return {"type": kind, "children": list(children), "text": text, "field": field}


def block(*children, field="body"):
    return node("statement_block", *children, field=field)


def call(name):
    return node("expression_statement", node(
        "call_expression", node("identifier", text=name, field="function"),
        node("arguments", text="()", field="arguments"),
    ))


def branch(yes, no=None):
    children = [node("identifier", text="flag", field="condition"),
                block(yes, field="consequence")]
    if no is not None:
        children.append(block(no, field="alternative"))
    return node("if_statement", *children)


def try_finally(body, cleanup=None, catch=None):
    children = [block(body)]
    if catch is not None:
        children.append(node("catch_clause", block(catch)))
    children.append(node("finally_clause", block(cleanup if cleanup is not None else call("cleanup"))))
    return node("try_statement", *children)


def function(*statements):
    return node("program", node(
        "function_declaration", node("identifier", text="f", field="name"), block(*statements),
    ))


def lower(*statements):
    return cfg.synthesize_file_cfg(function(*statements), language="javascript").functions[0]


def reachable(fn, start, blocked=()):
    seen = set()
    todo = [start]
    while todo:
        current = todo.pop()
        if current in seen or current in blocked:
            continue
        seen.add(current)
        todo.extend(e.target_node_id for e in fn.edges if e.source_node_id == current)
    return seen


def calls(fn, name):
    return {n.node_id for n in fn.nodes if name in n.calls and n.kind == "statement"}


def recorded(path):
    base = Path("tests/fixtures/review_prioritization")
    record = json.loads(gzip.decompress((base / "ast-golden.json.gz").read_bytes()))["files"][path]
    data = (base / "target" / path).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record["sha256"]
    assert not record["root_has_error"]
    result = cfg.synthesize_file_cfg(record["nodes"], data, language=record["grammar"],
                                     path=path, file_sha256=record["sha256"])
    return result


def test_recorded_rust_early_return_guard_survives_statement_wrappers():
    fn = next(f for f in recorded("rust/src/wire.rs").functions if f.function_name == "read_header")
    guard = next(n for n in fn.nodes if n.kind == "branch")
    assert guard.guard_expression == "buf.len() < 5"
    assert guard.early_exit
    returned = next(n for n in fn.nodes if n.kind == "return")
    access = next(n for n in fn.nodes if n.statement_text.startswith("let kind"))
    assert access.node_id not in reachable(fn, returned.node_id)
    assert [(g.branch_node_id, g.branch_arm) for g in access.guard_dominators] == [
        (guard.node_id, "false_branch")]
    assert fn.to_summary()["coverage_status"] == "complete"


def test_recorded_rust_loop_and_break_are_executable_not_opaque_statements():
    fn = next(f for f in recorded("rust/src/lib.rs").functions if f.function_name == "walk")
    loop = next(n for n in fn.nodes if n.kind == "loop_header")
    assert loop.guard_expression is None
    jump = next(n for n in fn.nodes if n.ast_type == "break_expression")
    assert any(e.source_node_id == jump.node_id and e.edge_kind == "break_edge" for e in fn.edges)
    assert len([n for n in fn.nodes if n.kind == "branch"]) == 3
    assert not any(e.source_node_id == loop.node_id and e.edge_kind == "false_branch" for e in fn.edges)


@pytest.mark.parametrize("kind", ["return_expression", "break_expression", "continue_expression"])
def test_rust_wrapped_terminator_does_not_fall_through(kind):
    wrapped = node("expression_statement", node(kind, text=kind.split("_")[0]),
                   {"type": ";", "named": False})
    tree = node("source_file", node(
        "function_item", node("identifier", text="f", field="name"),
        node("block", node("expression_statement", node(
            "loop_expression", node("block", wrapped, call("unreachable"), field="body"),
        )), call("after"), field="body"),
    ))
    fn = cfg.synthesize_file_cfg(tree, language="rust").functions[0]
    jump = next(n for n in fn.nodes if n.ast_type == kind)
    assert not calls(fn, "unreachable")
    expected = {"return_expression": "return_exit", "break_expression": "break_edge",
                "continue_expression": "continue_edge"}[kind]
    assert any(e.source_node_id == jump.node_id and e.edge_kind == expected for e in fn.edges)


@pytest.mark.parametrize("kind", ["return_statement", "throw_statement", "break_statement", "continue_statement"])
def test_finally_runs_before_every_pending_abrupt_completion(kind):
    body = try_finally(node(kind, text=kind))
    if kind in {"break_statement", "continue_statement"}:
        body = node("while_statement", node("identifier", text="again", field="condition"), block(body))
    fn = lower(body, call("after"))
    abrupt = next(n for n in fn.nodes if n.ast_type == kind)
    cleanup = calls(fn, "cleanup")
    assert cleanup & reachable(fn, abrupt.node_id)
    destinations = {e.target_node_id for e in fn.edges
                    if e.source_node_id in cleanup and e.edge_kind in {
                        "return_exit", "exception_edge", "break_edge", "continue_edge"}}
    assert destinations
    assert not (destinations & reachable(fn, abrupt.node_id, cleanup))
    if kind in {"return_statement", "throw_statement"}:
        assert not (calls(fn, "after") & reachable(fn, abrupt.node_id))


def test_finally_preserves_distinct_return_and_normal_continuations():
    fn = lower(try_finally(branch(node("return_statement", text="return 1"), call("normal"))), call("after"))
    ret = next(n for n in fn.nodes if n.kind == "return")
    assert calls(fn, "cleanup") & reachable(fn, ret.node_id)
    assert not (calls(fn, "after") & reachable(fn, ret.node_id))
    normal = next(iter(calls(fn, "normal")))
    assert calls(fn, "after") & reachable(fn, normal)
    assert not (calls(fn, "after") & reachable(fn, normal, calls(fn, "cleanup")))


def test_finally_return_overrides_pending_exception_and_break():
    body = branch(node("throw_statement", text="throw error"), node("break_statement", text="break"))
    fn = lower(node("while_statement", node("identifier", text="again", field="condition"),
                    block(try_finally(body, node("return_statement", text="return 2")))), call("after"))
    for abrupt in [n for n in fn.nodes if n.ast_type in {"throw_statement", "break_statement"}]:
        reached = reachable(fn, abrupt.node_id)
        assert any(n.node_id in reached and n.kind == "return" for n in fn.nodes)
        assert not calls(fn, "after") & reached


def test_nested_finally_runs_inner_then_outer_before_return():
    fn = lower(try_finally(try_finally(node("return_statement", text="return 1"), call("inner")),
                          call("outer")))
    ret = next(n for n in fn.nodes if n.kind == "return")
    inner, outer = calls(fn, "inner"), calls(fn, "outer")
    assert inner & reachable(fn, ret.node_id)
    assert outer & reachable(fn, ret.node_id)
    assert not outer & reachable(fn, ret.node_id, inner)
    assert fn.exit_node_id not in reachable(fn, ret.node_id, outer)


def test_local_loop_break_does_not_run_enclosing_finally_early():
    loop = node("while_statement", node("identifier", text="again", field="condition"),
                block(node("break_statement", text="break")))
    fn = lower(try_finally(block(loop, call("still_in_try"))))
    jump = next(n for n in fn.nodes if n.ast_type == "break_statement")
    assert calls(fn, "still_in_try") & reachable(fn, jump.node_id)
    assert not calls(fn, "cleanup") & reachable(fn, jump.node_id, calls(fn, "still_in_try"))


def test_throw_reaches_local_catch_before_finally_and_outer_catch_after_finally():
    inner = try_finally(node("throw_statement", text="throw first"),
                        call("cleanup"), node("throw_statement", text="throw second"))
    outer = node("try_statement", block(inner), node("catch_clause", block(call("outer_catch"))))
    fn = lower(outer)
    first = next(n for n in fn.nodes if n.statement_text == "throw first")
    second = next(n for n in fn.nodes if n.statement_text == "throw second")
    assert second.node_id in reachable(fn, first.node_id, calls(fn, "cleanup"))
    assert not calls(fn, "outer_catch") & reachable(fn, second.node_id, calls(fn, "cleanup"))
    assert calls(fn, "outer_catch") & reachable(fn, second.node_id)


@pytest.mark.parametrize("transfer", [None, "continue_statement", "break_statement"])
def test_do_while_executes_body_before_condition_and_continue_tests_condition(transfer):
    statements = [call("work")]
    if transfer:
        statements.append(node(transfer, text=transfer))
    fn = lower(node("do_statement", block(*statements), node("false", text="false", field="condition")),
               call("after"))
    work = next(n for n in fn.nodes if n.node_id in calls(fn, "work"))
    condition = next(n for n in fn.nodes if n.kind == "loop_header")
    assert fn.exit_node_id not in reachable(fn, fn.entry_node_id, {work.node_id})
    assert not work.guard_dominators
    if transfer == "continue_statement":
        jump = next(n for n in fn.nodes if n.ast_type == transfer)
        assert any(e.source_node_id == jump.node_id and e.target_node_id == condition.node_id
                   and e.edge_kind == "continue_edge" for e in fn.edges)
    elif transfer == "break_statement":
        jump = next(n for n in fn.nodes if n.ast_type == transfer)
        assert condition.node_id not in reachable(fn, jump.node_id)


def test_cfg_cap_reports_partial_without_inventing_exit_or_guard_proofs():
    fn = lower(branch(call("first")), *(call(f"s{i}") for i in range(2050)))
    summary = fn.to_summary()
    assert len(fn.nodes) == cfg.MAX_CFG_NODES_PER_FUNCTION
    assert summary["truncated"] is True
    assert summary["coverage_status"] == "partial"
    assert "cfg_node_limit_reached" in summary["gaps"]
    assert not any(n.guard_dominators for n in fn.nodes)
    assert fn.exit_node_id not in reachable(fn, fn.entry_node_id)


@pytest.mark.parametrize("statements", [5, 6])
def test_cfg_cap_includes_entry_exit_without_marking_exact_fit_partial(monkeypatch, statements):
    monkeypatch.setattr(cfg, "MAX_CFG_NODES_PER_FUNCTION", 7)
    fn = lower(*(call(f"work{i}") for i in range(statements)))
    assert len(fn.nodes) == 7
    assert fn.to_summary()["truncated"] == (statements == 6)
    assert (fn.exit_node_id in reachable(fn, fn.entry_node_id)) == (statements == 5)


@pytest.mark.parametrize("kind", ["if_statement", "try_statement", "do_statement"])
def test_node_cap_also_bounds_recursive_branch_handler_and_finally_allocation(monkeypatch, kind):
    monkeypatch.setattr(cfg, "MAX_CFG_NODES_PER_FUNCTION", 7)
    if kind == "if_statement":
        body = branch(branch(branch(call("yes"), call("no")), call("else")), call("other"))
    elif kind == "try_statement":
        body = try_finally(branch(node("return_statement", text="return 1"), call("normal")))
    else:
        body = node("do_statement", block(branch(call("yes"), call("no"))),
                    node("identifier", text="again", field="condition"))
    fn = lower(body, call("after"))
    assert len(fn.nodes) <= 7
    assert fn.to_summary()["coverage_status"] == "partial"
    assert fn.to_summary()["truncated"]


def test_recorded_goto_and_label_are_explicitly_unmodeled():
    fn = next(f for f in recorded("native/src/codec.c").functions
              if any(n.ast_type == "goto_statement" for n in f.nodes))
    summary = fn.to_summary()
    assert summary["coverage_status"] == "partial"
    assert {"goto_statement", "labeled_statement"} <= set(summary["unmodeled_constructs"])
    assert summary["gaps"]
    assert not any(n.guard_dominators for n in fn.nodes)


@pytest.mark.parametrize("kind", ["if_statement", "while_statement", "do_statement", "switch_statement"])
def test_missing_condition_is_not_invented_from_body(kind):
    fn = lower(node(kind, block(call("work"), field="consequence" if kind == "if_statement" else "body")),
               call("after"))
    control = next(n for n in fn.nodes if n.ast_type == kind)
    assert control.guard_expression is None
    assert control.guard_polarity is None
    assert fn.to_summary()["coverage_status"] == "partial"
    assert f"cfg_missing_condition:{kind}" in fn.to_summary()["gaps"]


def test_partial_manifest_retains_function_gaps_and_validates(tmp_path):
    result = cfg.synthesize_file_cfg(function(node("goto_statement", text="goto done")), language="javascript")
    refs, counts = cfg.write_scope_cfg_artifacts(
        run_root=tmp_path, cfg_dir=tmp_path / "cfg", scope_id="scope", language="JavaScript",
        grammar="javascript", target_snapshot="a" * 64, file_results=[result],
    )
    manifest = json.loads((tmp_path / refs["manifest"]["path"]).read_text())
    assert counts["cfg_partial_functions"] == 1
    assert counts["cfg_unmodeled_constructs"] == 1
    assert manifest["functions"][0]["gaps"] == ["cfg_unmodeled_construct:goto_statement"]
    schema = json.loads(Path("docs/schemas/tree-sitter-ast/tree-sitter-cfg.schema.json").read_text())
    Draft202012Validator(schema).validate(manifest)


def test_missing_parser_token_condition_is_partial_not_a_guard():
    condition = {**node("identifier", field="condition"), "missing": True}
    fn = lower(node("if_statement", condition, block(call("sink"), field="consequence")))
    assert fn.to_summary()["gaps"] == ["cfg_missing_condition:if_statement"]
    assert not fn.guard_count
    assert not any(n.guard_dominators for n in fn.nodes)


def test_rust_match_arm_values_and_outer_loop_break_survive_wrappers():
    # Rust match_arm uses pattern and value fields; value is the executed body.
    match = node("match_expression", node("identifier", text="value", field="value"),
                 node("match_block",
                      node("match_arm", node("match_pattern", text="Some(x)", field="pattern"),
                           node("block", node("expression_statement", node("break_expression", text="break")),
                                field="value")),
                      node("match_arm", node("match_pattern", text="_", field="pattern"),
                           node("call_expression", node("identifier", text="work", field="function"),
                                field="value"), text="_ => work()"), field="body"))
    tree = node("source_file", node(
        "function_item", node("identifier", text="f", field="name"),
        node("block", node("expression_statement", node(
            "loop_expression", node("block", node("expression_statement", match),
                                    call("in_loop"), field="body"))),
             call("after_loop"), field="body")))
    fn = cfg.synthesize_file_cfg(tree, language="rust").functions[0]
    jump = next(n for n in fn.nodes if n.ast_type == "break_expression")
    assert calls(fn, "after_loop") & reachable(fn, jump.node_id)
    assert not calls(fn, "in_loop") & reachable(fn, jump.node_id)
    assert any("work" in n.calls for n in fn.nodes)
    assert fn.to_summary()["coverage_status"] == "complete"


@pytest.mark.parametrize("kind", ["break_expression", "continue_expression"])
def test_unsupported_rust_labeled_transfer_never_guesses_inner_loop_target(kind):
    tree = node("source_file", node(
        "function_item", node("block", node(
            "loop_expression", node("block", node("expression_statement", node(
                kind, node("label", text="'outer"), text=f"{kind} 'outer")),
                call("unreachable"), field="body")), field="body")))
    fn = cfg.synthesize_file_cfg(tree, language="rust").functions[0]
    jump = next(n for n in fn.nodes if n.ast_type == kind)
    assert fn.to_summary()["coverage_status"] == "partial"
    assert not any(e.source_node_id == jump.node_id for e in fn.edges)
    assert not calls(fn, "unreachable")


def test_unlowered_control_in_expression_is_a_named_gap():
    tree = node("source_file", node(
        "function_item", node("block", node("let_declaration",
            node("identifier", text="answer", field="pattern"),
            node("if_expression", node("identifier", text="flag", field="condition"),
                 node("block", node("return_expression", text="return"), field="consequence"),
                 field="value")), call("after"), field="body")))
    fn = cfg.synthesize_file_cfg(tree, language="rust").functions[0]
    assert "if_expression" in fn.to_summary()["unmodeled_constructs"]
    assert fn.to_summary()["coverage_status"] == "partial"
    assert not any(n.guard_dominators for n in fn.nodes)


def normalize_tree(tmp_path, tree, *, language="javascript", data=None):
    nodes, source = cfg.flatten_syntax_tree(tree, data)
    digest = hashlib.sha256(source).hexdigest()
    scope = Scope("scope", "component", ".", "source:component", ".", language,
                  ({"path": "source", "sha256": digest, "size_bytes": len(source), "language": language},))
    lock = GrammarLock(language, language, "https://example.invalid/grammar", "a" * 40,
                       "MIT", "grammar.so", "b" * 64)
    output = {"schema": "appsec-review/tree-sitter-container-output/1",
              "scope_id": scope.scope_id, "language": language, "records": [
                  {"path": "source", "sha256": digest, "status": "SUCCEEDED",
                   "bytes": len(source), "nodes": nodes, "root_has_error": False},
              ]}
    artifact, identity, counts = normalize_scope(
        run_root=tmp_path, target_snapshot="snap", scope=scope, grammar=lock, fingerprint="f" * 64,
        container_output=output, producer={"job": "job_tree_sitter_ast"},
        artifact_path=tmp_path / "nodes.jsonl", index_path=tmp_path / "index.sqlite",
        source_bytes={"source": source}, cfg_dir=tmp_path / "cfg",
    )
    return artifact, identity, counts


@pytest.mark.parametrize("failure", ["node_cap", "unsupported", "none"])
def test_normalized_cfg_coverage_gaps_are_independent_of_complete_raw_ast(tmp_path, monkeypatch, failure):
    if failure == "node_cap":
        monkeypatch.setattr(cfg, "MAX_CFG_NODES_PER_FUNCTION", 4)
    tree = function(*(call(f"work{i}") for i in range(4)),
                    node("goto_statement", text="goto done") if failure == "unsupported" else call("last"))
    _, identity, counts = normalize_tree(tmp_path, tree)
    with sqlite3.connect(tmp_path / "index.sqlite") as db:
        coverage = db.execute("SELECT area,status,gap FROM coverage").fetchall()
        payload = next(json.loads(row[0]) for row in db.execute("SELECT payload_json FROM entities")
                       if "cfg_nodes" in json.loads(row[0]))
    assert ("source", "complete", None) in coverage
    cfg_coverage = next(row for row in coverage if row[0].startswith("cfg:"))
    if failure == "none":
        assert not identity.gaps
        assert counts["cfg_partial_functions"] == 0
        assert cfg_coverage[1:] == ("complete", None)
    else:
        assert identity.gaps
        assert cfg_coverage[1] == "partial"
        assert counts["cfg_partial_functions"] == 1
        assert counts["cfg_truncated_functions"] == (failure == "node_cap")
        assert payload["cfg"]["coverage_status"] == "partial"
        assert all(not n["guard_dominators"] for n in payload["cfg_nodes"])
        manifest = json.loads((tmp_path / counts["cfg_artifacts"]["manifest"]["path"]).read_text())
        assert manifest["functions"][0]["gaps"] == payload["cfg"]["gaps"]


def test_contextual_finally_is_not_collapsed_into_false_ast_flow_edges_or_guards(tmp_path):
    tree = function(try_finally(branch(node("return_statement", text="return 1"), call("normal"))), call("after"))
    _, identity, _ = normalize_tree(tmp_path, tree)
    assert any("cfg_ast_context_projection" in gap for gap in identity.gaps)
    with sqlite3.connect(tmp_path / "index.sqlite") as db:
        payloads = [json.loads(row[0]) for row in db.execute("SELECT payload_json FROM entities")]
        function_payload = next(p for p in payloads if "cfg_nodes" in p)
        cleanups = [n for n in function_payload["cfg_nodes"] if "cleanup" in n["calls"]]
        assert len(cleanups) >= 2
        assert len({n["ast_identity"] for n in cleanups}) == 1
        cleanup_identity = cleanups[0]["ast_identity"]
        rows = db.execute("SELECT source_id, target_id FROM relations WHERE kind='flows_to'").fetchall()
        assert not any(cleanup_identity in row for row in rows)
        cleanup_payload = json.loads(db.execute("SELECT payload_json FROM entities WHERE identity=?",
                                               (cleanup_identity,)).fetchone()[0])
    assert "cfg_block_id" not in cleanup_payload
    assert "cfg_guard_dominators" not in cleanup_payload


def test_absent_function_lowering_does_not_claim_complete_cfg_coverage(tmp_path):
    _, _, counts = normalize_tree(tmp_path, node("program", call("top_level")), language="bash")
    assert counts["cfg_functions_built"] == 0
    with sqlite3.connect(tmp_path / "index.sqlite") as db:
        assert not db.execute("SELECT status FROM coverage WHERE area LIKE 'cfg:%'").fetchall()
