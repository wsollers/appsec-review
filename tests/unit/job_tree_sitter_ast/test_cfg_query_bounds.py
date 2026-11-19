"""CFG paging bounds apply to materialized payloads, not just returned rows (T-5212)."""

from dataclasses import replace
import hashlib
import json
import sqlite3

import pytest

from appsec_review.jobs.job_tree_sitter_ast.cfg import flatten_syntax_tree
from appsec_review.jobs.job_tree_sitter_ast.model import GrammarLock, Scope
from appsec_review.jobs.job_tree_sitter_ast.normalize import normalize_scope
from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.index import write_manifest


def _core(tmp_path, *, count=12, paths=("page.js",), unguarded=0, statements=1):
    run_id = "2026-11-19-0001"
    run_root = tmp_path / run_id
    indexes = []
    for shard, path in enumerate(paths):
        source = ""
        functions = []
        for index in range(count):
            name = f"f{index:02}"
            calls = " ".join(f"sink{i}();" for i in range(statements))
            body = "" if index < unguarded else f"  if (allowed) {{ {calls} }}\n"
            text = f"function {name}() {{\n{body}}}\n"
            start = len(source)
            source += text

            def node(kind, text, *children, field=None):
                begin = source.index(text, start)
                end = begin + len(text)
                return {"type": kind, "field": field, "children": list(children),
                        "start_byte": begin, "end_byte": end,
                        "start_line": source.count("\n", 0, begin) + 1,
                        "end_line": source.count("\n", 0, end) + 1}

            branch = []
            if body:
                branch = [node("if_statement", f"if (allowed) {{ {calls} }}",
                               node("identifier", "allowed", field="condition"),
                               node("statement_block", f"{{ {calls} }}",
                                    *(node("expression_statement", f"sink{i}();") for i in range(statements)),
                                    field="consequence"))]
            functions.append(node("function_declaration", text.rstrip(),
                                  node("identifier", name, field="name"),
                                  node("statement_block", text[text.index("{"):].rstrip(),
                                       *branch, field="body")))
        data = source.encode()
        nodes, _ = flatten_syntax_tree(
            {"type": "program", "start_byte": 0, "end_byte": len(data), "start_line": 1,
             "end_line": source.count("\n") + 1, "children": functions}, data)
        digest = hashlib.sha256(data).hexdigest()
        scope = Scope(f"scope-{shard}", "component", ".", "source:component", ".", "JavaScript",
                      ({"path": path, "sha256": digest, "size_bytes": len(data), "language": "JavaScript"},))
        grammar = GrammarLock("JavaScript", "javascript", "https://example.invalid/grammar",
                              "a" * 40, "MIT", "grammar.so", "b" * 64)
        _, identity, _ = normalize_scope(
            run_root=run_root, target_snapshot="a" * 64, scope=scope, grammar=grammar,
            fingerprint=f"{shard:064x}",
            container_output={"schema": "appsec-review/tree-sitter-container-output/1",
                              "scope_id": scope.scope_id, "language": scope.language, "records": [
                                  {"path": path, "sha256": digest, "status": "SUCCEEDED",
                                   "bytes": len(data), "nodes": nodes}]},
            producer={"job": "job_tree_sitter_ast"},
            artifact_path=run_root / f"ast-{shard}.jsonl",
            index_path=run_root / f"ast-{shard}.sqlite", source_bytes={path: data})
        indexes.append(identity)
    manifest = run_root / "manifest.json"
    write_manifest(manifest, run_id=run_id, target_snapshot="a" * 64, target_root=run_root, indexes=indexes)
    return RetrievalCore(tmp_path, run_id, manifest_path=manifest)


def _observe_payload_reads(monkeypatch, core):
    reads = []
    original = core._database

    def database(*args):
        connection = original(*args)

        def row_factory(cursor, values):
            row = sqlite3.Row(cursor, values)
            if "payload_json" in row.keys():
                reads.append(row["identity"])
            return row

        connection.row_factory = row_factory
        return connection

    monkeypatch.setattr(core, "_database", database)
    return reads


def test_cfg_pages_materialize_only_the_requested_function_and_resume(monkeypatch, tmp_path):
    core = _core(tmp_path)
    reads = _observe_payload_reads(monkeypatch, core)
    cursor, names = None, []
    for index in range(12):
        reads.clear()
        page = core.query_cfg_function(path="page.js", limit=1, cursor=cursor)
        assert len(reads) == 1
        names.append(page["results"][0]["function_name"])
        cursor = page["pagination"]["next_cursor"]
        assert bool(cursor) == (index < 11)
    assert names == [f"f{index:02}" for index in range(12)]


def test_cfg_pages_merge_shards_deduplicate_and_bind_the_cursor(monkeypatch, tmp_path):
    core = _core(tmp_path, count=2, paths=("z.js", "a.js", "a.js"))
    reads = _observe_payload_reads(monkeypatch, core)
    cursor, rows = None, []
    for _ in range(4):
        reads.clear()
        page = core.query_cfg_function(function_name="f00", limit=1, cursor=cursor)
        assert len(reads) == 1
        rows.extend(page["results"])
        next_cursor = page["pagination"]["next_cursor"]
        if not next_cursor:
            break
        with pytest.raises(ValueError, match="cursor"):
            core.query_cfg_function(function_name="f01", limit=1, cursor=next_cursor)
        cursor = next_cursor
    assert [row["path"] for row in rows] == ["a.js", "z.js"]
    assert not next_cursor


def test_node_lookup_does_not_materialize_unrelated_functions(monkeypatch, tmp_path):
    core = _core(tmp_path)
    function = core.query_cfg_function(function_name="f11")["results"][0]
    guarded = next(node for node in function["nodes"] if node["guard_dominators"])
    reads = _observe_payload_reads(monkeypatch, core)
    page = core.query_guard_dominators(node_id=guarded["node_id"], limit=1)
    assert len(reads) == 1
    assert page["results"][0]["guard_dominators"] == guarded["guard_dominators"]
    assert not page["pagination"]["next_cursor"]


def test_guard_candidate_budget_advances_even_through_empty_pages(monkeypatch, tmp_path):
    core = _core(tmp_path, count=7, unguarded=5)
    core.limits = replace(core.limits, max_results=2)
    reads = _observe_payload_reads(monkeypatch, core)
    cursor, pages, rows = None, [], []
    for _ in range(12):
        reads.clear()
        page = core.query_guard_dominators(path="page.js", limit=1, cursor=cursor)
        assert len(reads) <= 2
        pages.append(page)
        rows.extend(page["results"])
        next_cursor = page["pagination"]["next_cursor"]
        if not next_cursor:
            break
        assert next_cursor != cursor
        assert page["coverage_gaps"]
        cursor = next_cursor
    assert not next_cursor
    assert not pages[0]["results"] and not pages[1]["results"]
    assert {row["function_name"] for row in rows} == {"f05", "f06"}
    assert len({row["node_id"] for row in rows}) == len(rows)


def test_cfg_byte_withholding_resumes_at_the_last_returned_function(tmp_path):
    core = _core(tmp_path, count=3)
    first = core.query_cfg_function(path="page.js", limit=2)
    first_size = len(json.dumps(first["results"][0]).encode())
    core.limits = replace(core.limits, max_response_bytes=first_size + 1800)
    bounded = core.query_cfg_function(path="page.js", limit=2)
    assert bounded["truncated"] and len(bounded["results"]) == 1
    resumed = core.query_cfg_function(path="page.js", limit=2, cursor=bounded["pagination"]["next_cursor"])
    assert resumed["results"][0]["function_name"] == "f01"


@pytest.mark.parametrize("statements", [1, 3])
def test_guard_pages_preserve_all_occurrences_and_replay_deterministically(monkeypatch, tmp_path, statements):
    core = _core(tmp_path, count=3, statements=statements)
    expected = core.query_guard_dominators(path="page.js")["results"]
    assert len(expected) == 3 * statements
    reads = _observe_payload_reads(monkeypatch, core)
    cursor, rows = None, []
    for _ in range(len(expected) + 1):
        reads.clear()
        page = core.query_guard_dominators(path="page.js", limit=1, cursor=cursor)
        assert len(reads) == 1
        replay = core.query_guard_dominators(path="page.js", limit=1, cursor=cursor)
        assert replay["results"] == page["results"]
        assert replay["pagination"] == page["pagination"]
        rows.extend(page["results"])
        cursor = page["pagination"]["next_cursor"]
        if cursor is None:
            break
    assert rows == expected
    reads.clear()
    absent = core.query_guard_dominators(node_id="cfg:absent", limit=1)
    assert not reads and not absent["results"] and absent["coverage_gaps"]
