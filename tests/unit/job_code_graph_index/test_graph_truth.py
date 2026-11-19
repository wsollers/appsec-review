"""T-5098/T-5099: producer bytes survive alternate graph projection and publication."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json
import sqlite3

import pytest

from appsec_review.indexing.store import ShardSet
from appsec_review.jobs.job_code_graph_index import alternate_cpg as alt
from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.storage import file_sha256
from tests.graph.test_normalize import SNAPSHOT, SOURCE_BYTES, TARGET_PATH, _normalize


def _shard(root, builder, producer):
    sha = builder.build()
    identity = asdict(IndexIdentity(
        builder.name, "appsec-review/retrieval-index/2", sha, builder.fingerprint,
        builder.path.relative_to(root).as_posix(), {"job": producer}, (), builder.shard_id,
    ))
    return identity, ShardSet(root, [identity])


def _canonical_graph(root, *, disputed=False):
    graph = _normalize()
    builder = IndexBuilder(root / "primary.sqlite", name="graph", fingerprint="a" * 64,
                           target_snapshot=SNAPSHOT, shard_id="primary")
    for symbol in graph.symbols:
        builder.add_entity(symbol)
    for fact in graph.facts:
        if disputed and fact.family.value == "call_site":
            from appsec_review.graph.contract import admissibility
            payload = deepcopy(fact.payload)
            payload["cross_check"]["state"] = "disagree"
            payload["admissibility"] = admissibility(payload)
            fact = replace(fact, payload=payload)
        builder.add_entity(fact.to_entity())
    for relation in graph.relations:
        builder.add_relation(relation)
    identity, rows = _shard(root, builder, "job_code_graph_index")
    return graph, identity, list(rows.entities(rows.shards)), list(rows.relations(rows.shards))


def _publish(root, cpg, **kwargs):
    return alt.publish_alternate_cpg(root, root / "publication", cpg,
                                     job_id="job_code_graph_index", unit_id="publish", **kwargs)


def _functions(*names):
    return [{"identity": f"symbol-{index}", "name": name, "location": {
        "path": "app.py", "start_line": index * 3 + 1, "end_line": index * 3 + 2,
    }, "payload": {"kind": "function", "qualified_name": name}} for index, name in enumerate(names)]


@pytest.mark.parametrize("call_count", [2, 24])
def test_clangd_variable_reference_and_occurrences_survive_real_normalization(tmp_path, call_count):
    from appsec_review.jobs.job_cpp_symbol_index.job import normalize_scope
    from tests.unit.job_cpp_symbol_index.test_handlers import _make_scope_and_unit

    body = " ".join("helper();" for _ in range(call_count))
    text = f"int global;\nint helper() {{ return global; }}\nint main() {{ {body} return 0; }}\n"
    columns = [index for index in range(len(text.splitlines()[2]))
               if text.splitlines()[2].startswith("helper()", index)]
    root, _, scope, unit = _make_scope_and_unit(tmp_path, sources={"native/a.cpp": text})
    documents = []
    for sid, name, kind, line in (
        ("1111111111111111", "global", "Variable", 0),
        ("2222222222222222", "helper", "Function", 1),
        ("3333333333333333", "main", "Function", 2),
    ):
        documents.append(f"""--- !Symbol
ID: {sid}
Name: {name}
SymInfo:
  Kind: {kind}
  Lang: Cpp
Definition:
  FileURI: 'file:///target/source/a.cpp'
  Start:
    Line: {line}
    Column: 4
...
""")
    for target, caller, bits, line, columns in (
        ("1111111111111111", "2222222222222222", 4, 1, [22]),
        ("2222222222222222", "3333333333333333", 28, 2, columns),
    ):
        documents.append(f"--- !Refs\nID: {target}\nReferences:\n")
        for column in columns:
            documents.append(f"""  - Kind: {bits}
    Container:
      ID: {caller}
    Location:
      FileURI: 'file:///target/source/a.cpp'
      Start:
        Line: {line}
        Column: {column}
""")
        documents.append("...\n")
    (root / "stdout").write_text("".join(documents))
    (root / "stderr").write_text("[1/1] Processing file /target/source/a.cpp\n")
    builder = IndexBuilder(root / "clangd.sqlite", name="analysis", fingerprint="c" * 64,
                           target_snapshot=unit.job.source_fingerprint, shard_id="clangd")
    normalize_scope(unit, scope, {
        "timed_out": False, "oom_killed": False, "exit_code": 0, "stdout_truncated": False,
        "stdout_path": "stdout", "stderr_path": "stderr",
    }, {"max_documents_per_scope": 100, "max_symbols_per_scope": 100,
        "max_relations_per_scope": 100, "locations_per_relation": call_count}, builder, "clangd")
    identity, _ = _shard(root, builder, "job_cpp_symbol_index")
    cpg, shas = alt.build_run_alternate_cpg(
        root, run_id="r", target_snapshot=unit.job.source_fingerprint,
        upstream_shards=[identity], graph_shards=[],
    )
    global_node = next(n for n in cpg["nodes"] if n["name"] == "global")
    assert global_node["node_kind"] != "function"
    assert any(e["edge_kind"] == "REFERENCES" and e["target_id"] == global_node["node_id"] for e in cpg["edges"])
    calls = [e for e in cpg["edges"] if e["edge_kind"] == "CALLS"]
    assert len(calls) == call_count and {e["line"] for e in calls} == {3}
    assert {e["location"]["column"] for e in calls} == {column + 1 for column in columns}
    assert all(e["evidence"][0]["identity"] in {relation.relation_id for relation in builder.relations}
               and e["evidence"][0]["accepted_shard"]["sha256"] == identity["sha256"] for e in calls)
    _, published = _publish(root, cpg, file_shas=shas)
    with sqlite3.connect(root / published.relative_path) as db:
        db.row_factory = sqlite3.Row
        loaded = alt.load_cpg_from_sqlite(db)
    assert len([edge for edge in loaded["edges"] if edge["edge_kind"] == "CALLS"]) == call_count


def test_source_identity_without_catalog_is_retrievable(tmp_path, monkeypatch):
    tmp_path = tmp_path / "2026-11-19-0001"
    tmp_path.mkdir()
    graph, shard, _, _ = _canonical_graph(tmp_path)
    monkeypatch.setattr(alt, "_accepted_cfg", lambda *args: [])
    cpg, shas = alt.build_run_alternate_cpg(
        tmp_path, run_id="run", target_snapshot=SNAPSHOT, upstream_shards=[], graph_shards=[shard],
    )
    main = next(node for node in cpg["nodes"] if node["node_kind"] == "function" and node["name"] == "main")
    assert main["evidence"][0]["accepted_shard"]["sha256"] == shard["sha256"]
    _, identity = _publish(tmp_path, cpg, file_shas=shas)
    target = tmp_path / "target"
    (target / TARGET_PATH).parent.mkdir(parents=True)
    (target / TARGET_PATH).write_bytes(SOURCE_BYTES)
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest, run_id=tmp_path.name, target_snapshot=SNAPSHOT, target_root=target, indexes=[identity])
    core = RetrievalCore(tmp_path.parent, tmp_path.name, manifest_path=manifest, manifest_sha256=file_sha256(manifest))
    result = core.find(name="main", kind="symbol", indexes=["analysis"])
    assert result["results"]
    excerpt = core.read_excerpt(identity=result["results"][0]["identity"])
    assert excerpt["results"], excerpt
    with sqlite3.connect(tmp_path / identity.relative_path) as db:
        db.row_factory = sqlite3.Row
        locations = [dict(row) for row in db.execute("SELECT * FROM locations")]
    assert all(loc["file_sha256"] == hashlib.sha256(SOURCE_BYTES).hexdigest() for loc in locations)
    assert any(loc["start_byte"] > 0 and loc["end_byte"] > loc["start_byte"] for loc in locations)
    original = next(symbol.location for symbol in graph.symbols if symbol.name == "main")
    assert dict(original.producer_location) in [json.loads(loc["producer_location_json"]) for loc in locations]


def test_missing_source_identity_is_a_gap_not_an_invented_digest(tmp_path):
    cpg = alt.synthesize_alternate_cpg(symbol_declarations=_functions("handle"))
    _, identity = _publish(tmp_path, cpg)
    with sqlite3.connect(tmp_path / identity.relative_path) as db:
        assert db.execute("SELECT COUNT(*) FROM locations").fetchone()[0] == 0
    assert any("source_identity_unavailable" in gap for gap in identity.gaps)


def test_same_count_publications_are_immutable_and_repeatable(tmp_path):
    cpg = alt.synthesize_alternate_cpg(symbol_declarations=_functions("handle"))
    first, first_id = _publish(tmp_path, cpg)
    paths = [tmp_path / first_id.relative_path, *(tmp_path / p for p in first["artifacts"].values())]
    original = {p: p.read_bytes() for p in paths}
    changed = deepcopy(cpg)
    changed["nodes"][0]["qualified_name"] += "_changed"
    second, second_id = _publish(tmp_path, changed)
    assert first_id.relative_path != second_id.relative_path
    assert first["artifacts"]["nodes"] != second["artifacts"]["nodes"]
    assert all(p.read_bytes() == data for p, data in original.items())
    _, repeated = _publish(tmp_path, cpg)
    assert repeated == first_id


def test_disputed_canonical_call_keeps_qualifiers_through_sqlite(tmp_path):
    _, _, facts, relations = _canonical_graph(tmp_path, disputed=True)
    cpg = alt.synthesize_alternate_cpg(codeql_facts=facts, codeql_relations=relations, target_snapshot=SNAPSHOT)
    _, identity = _publish(tmp_path, cpg)
    with sqlite3.connect(tmp_path / identity.relative_path) as db:
        calls = db.execute("SELECT exact, ambiguity, payload_json FROM relations WHERE kind='CALLS'").fetchall()
    assert calls
    assert all(not exact and ambiguity for exact, ambiguity, _ in calls)
    for _, _, payload in calls:
        for edge in json.loads(json.loads(payload)["cpg_edges_json"]):
            assert edge["evidence"][0]["cross_check"]["state"] == "disagree"
            assert edge["evidence"][0]["admissibility"]["direct_eligible"] is False


def test_canonical_calls_keep_actual_occurrence_spans(tmp_path):
    graph, _, facts, relations = _canonical_graph(tmp_path)
    cpg = alt.synthesize_alternate_cpg(codeql_facts=facts, codeql_relations=relations)
    nodes = {n["node_id"]: n for n in cpg["nodes"]}
    expected = {(f.location.start_line, f.location.start_column, f.payload["result"]["callee"]["display"])
                for f in graph.facts if f.family.value == "call_site"
                and f.payload["result"]["callee"]["symbol"]}
    actual = {(e["line"], e.get("location", {}).get("start_column"), nodes[e["target_id"]]["qualified_name"])
              for e in cpg["edges"] if e["edge_kind"] == "CALLS"}
    assert actual == expected


def test_separate_call_guards_are_not_unioned():
    functions = [{"function_id": name, "name": name, "start_line": start, "end_line": end}
                 for name, start, end in (("handle", 1, 8), ("helper", 10, 12))]
    blocks = [{"node_id": f"call-{line}", "function_id": "handle", "start_line": line,
               "calls": ["helper"], "guard_dominators": [{"node_id": "G", "branch": branch}]}
              for line, branch in ((3, "true_branch"), (5, "false_branch"))]
    cpg = alt.synthesize_alternate_cpg(
        tree_sitter_files=[{"path": "a.py", "functions": functions, "cfg_nodes": blocks}],
        codeql_facts=[{"kind": "call_site", "path": "a.py", "start_line": 3,
                      "callee": "helper", "target_path": "a.py", "target_line": 10}],
    )
    calls = [e for e in cpg["edges"] if e["edge_kind"] == "CALLS"]
    assert {e["line"] for e in calls} == {3, 5}
    assert all(len(e["guard_dominators"]) == 1 for e in calls)
    paths = alt.find_interprocedural_paths(cpg, source="handle", sink="helper")
    assert len({path["path_id"] for path in paths}) == len(paths) >= 2
    assert {tuple(g["branch"] for g in path["guard_dominators"]) for path in paths} == {
        ("true_branch",), ("false_branch",),
    }


@pytest.mark.parametrize("names", [("A::f", "B::f"), ("f(int)", "f(double)")])
def test_distinct_qualified_or_overloaded_functions_do_not_merge(names):
    declarations = _functions(*names)
    for declaration in declarations:
        declaration["location"].update(start_line=1, end_line=1)
    cpg = alt.synthesize_alternate_cpg(symbol_declarations=declarations)
    assert {n["qualified_name"] for n in cpg["nodes"] if n["node_kind"] == "function"} == set(names)


def test_flat_scanner_flows_preserve_order_and_missing_steps():
    cpg = alt.synthesize_alternate_cpg(
        symbol_declarations=_functions("handle", "helper"),
        sarif_observations=[{"identity": "observation", "payload": {"flows": [
            {"code_flow": 0, "thread_flow": 0, "ordinal": 2, "location": {"path": "app.py", "start_line": 4}},
            {"code_flow": 0, "thread_flow": 0, "ordinal": 1, "location": {"path": "app.py", "start_line": 1}},
            {"ordinal": 3, "location": {"path": "missing.py", "start_line": 1}},
        ]}}],
    )
    nodes = {n["node_id"]: n for n in cpg["nodes"]}
    taint = [e for e in cpg["edges"] if e["edge_kind"] == "TAINT_STEP"]
    assert [(nodes[e["source_id"]]["name"], nodes[e["target_id"]]["name"]) for e in taint] == [("handle", "helper")]
    assert any("unindexed" in g for g in cpg["gaps"])


def test_real_sarif_normalizer_flows_reach_alternate_consumer():
    from appsec_review.jobs.job_codeql_analysis.sarif import normalize_sarif

    def location(line):
        return {"physicalLocation": {"artifactLocation": {"uri": "app.py"},
                                     "region": {"startLine": line, "startColumn": 1}}}
    observations, gaps = normalize_sarif({
        "version": "2.1.0", "runs": [{"results": [{
            "ruleId": "py/test", "locations": [location(4)],
            "codeFlows": [{"threadFlows": [{"locations": [
                {"location": location(1)}, {"location": location(4)},
            ]}]}],
        }]}],
    }, files=[{"path": "app.py", "sha256": "a" * 64}], root=".", query_identity="query", result_limit=2)
    assert not gaps
    cpg = alt.synthesize_alternate_cpg(
        symbol_declarations=_functions("handle", "helper"),
        sarif_observations=json.loads(json.dumps(observations)),
    )
    nodes = {n["node_id"]: n for n in cpg["nodes"]}
    [edge] = [e for e in cpg["edges"] if e["edge_kind"] == "TAINT_STEP"]
    assert (nodes[edge["source_id"]]["name"], nodes[edge["target_id"]]["name"]) == ("handle", "helper")
    assert not edge["exact"]


def test_linkage_translation_unit_and_source_qualifiers_do_not_collapse():
    declarations = _functions("ns::helper", "ns::helper")
    for index, declaration in enumerate(declarations):
        declaration["location"].update(start_line=1, end_line=1, file_sha256=str(index) * 64)
        declaration["payload"].update(linkage="internal", translation_unit=f"unit-{index}.cpp",
                                      signature="(int)")
    cpg = alt.synthesize_alternate_cpg(symbol_declarations=declarations)
    functions = [n for n in cpg["nodes"] if n["node_kind"] == "function"]
    assert len(functions) == 2
    assert {n["evidence"][0]["translation_unit"] for n in functions} == {"unit-0.cpp", "unit-1.cpp"}
    assert {n["location"]["file_sha256"] for n in functions} == {"0" * 64, "1" * 64}


def test_secondary_producer_identity_is_not_relabelled_codeql(tmp_path):
    _, _, facts, relations = _canonical_graph(tmp_path, disputed=True)
    calls = [fact for fact in facts if fact["kind"] == "call_site"]
    for fact in calls:
        fact["payload"]["producer"]["name"] = "llvm-ir"
    cpg = alt.synthesize_alternate_cpg(codeql_facts=facts, codeql_relations=relations)
    projected = [edge for edge in cpg["edges"] if edge["edge_kind"] == "CALLS"]
    assert projected
    assert all(edge["producers"] == ["llvm-ir"] and not edge["exact"] for edge in projected)
    assert all(edge["evidence"][0]["producer"]["name"] == "llvm-ir" for edge in projected)


@pytest.mark.parametrize("legacy_ast_only", [False, True], ids=["embedded-cfg", "syntax-only"])
def test_ast_fallback_consumes_real_normalizer_payload(tmp_path, monkeypatch, legacy_ast_only):
    from appsec_review.jobs.job_tree_sitter_ast import GrammarLock, Scope
    from appsec_review.jobs.job_tree_sitter_ast.normalize import normalize_scope

    data = b"def handle():\n    helper()\ndef helper():\n    pass\n"
    sha = hashlib.sha256(data).hexdigest()
    path = "app.py"
    scope = Scope("scope-python", "component", "", "source:component", "python", "Python",
                  ({"path": path, "sha256": sha, "size_bytes": len(data), "language": "Python"},))
    grammar = GrammarLock("Python", "python", "https://example.invalid/parser", "a" * 40,
                          "MIT", "python.so", "b" * 64)
    nodes = []
    for ordinal, kind, field, start, end in (
        ((), "module", None, 0, len(data)),
        ((0,), "function_definition", None, 0, 26),
        ((0, 0), "identifier", "name", 4, 10),
        ((0, 1), "block", "body", 18, 26),
        ((0, 1, 0), "call", None, 18, 26),
        ((0, 1, 0, 0), "identifier", "function", 18, 24),
        ((1,), "function_definition", None, 27, len(data)),
        ((1, 0), "identifier", "name", 31, 37),
    ):
        def point(offset):
            before = data[:offset]
            return [before.count(b"\n"), len(before.rsplit(b"\n", 1)[-1])]
        nodes.append({"ordinal_path": list(ordinal), "type": kind, "field": field, "named": True,
                      "start_byte": start, "end_byte": end, "start_point": point(start), "end_point": point(end)})
    _, identity, _ = normalize_scope(
        run_root=tmp_path, target_snapshot=SNAPSHOT, scope=scope, grammar=grammar, fingerprint="f" * 64,
        container_output={"schema": "appsec-review/tree-sitter-container-output/1", "scope_id": scope.scope_id,
                          "language": scope.language, "records": [{"path": path, "sha256": sha, "bytes": len(data),
                                                                  "status": "SUCCEEDED", "nodes": nodes}]},
        producer={"job": "job_tree_sitter_ast"}, artifact_path=tmp_path / "ast.jsonl",
        index_path=tmp_path / "ast.sqlite", source_bytes={path: data},
    )
    if legacy_ast_only:
        from appsec_review.retrieval import EntityRecord, LogicalIdentity, SourceLocation
        rows = ShardSet(tmp_path, [asdict(identity)])
        legacy = IndexBuilder(tmp_path / "legacy-ast.sqlite", name="analysis", fingerprint="e" * 64,
                              target_snapshot=SNAPSHOT, shard_id=scope.scope_id)
        for row in rows.entities(rows.shards):
            payload = {key: value for key, value in row["payload"].items() if not key.startswith("cfg")}
            legacy.add_entity(EntityRecord(
                LogicalIdentity.parse(row["identity"]), row["native_id"], row["name"], row["text"], payload,
                SourceLocation(target_snapshot=SNAPSHOT, producer_location={},
                               **alt._source_location(row["location"])) if row["location"] else None,
            ))
        raw, _ = _shard(tmp_path, legacy, "job_tree_sitter_ast")
        identity = IndexIdentity(**raw)
    monkeypatch.setattr(alt, "_accepted_cfg", lambda *args: [])
    files = alt._extract_tree_sitter_files(tmp_path, [asdict(identity)], target_snapshot=SNAPSHOT, gaps=[])
    cpg = alt.synthesize_alternate_cpg(tree_sitter_files=files)
    assert {"handle", "helper"} <= {n["name"] for n in cpg["nodes"] if n["node_kind"] == "function"}
    assert any(e["edge_kind"] == "CALLS" for e in cpg["edges"])
    assert all(n.get("location", {}).get("file_sha256") == sha
               for n in cpg["nodes"] if n["node_kind"] == "function")


def test_disabled_alternate_does_not_read_inputs(tmp_path, monkeypatch):
    monkeypatch.setattr(alt, "_extract_tree_sitter_files", lambda *a, **k: pytest.fail("disabled input read"))
    cpg, shas = alt.build_run_alternate_cpg(
        tmp_path, run_id="r", target_snapshot=SNAPSHOT, upstream_shards=[], graph_shards=[],
        settings=alt.AlternateCpgSettings(enabled=False),
    )
    assert not cpg["nodes"] and not cpg["edges"] and not shas
    assert "disabled" in " ".join(cpg["gaps"])


def test_slice_seed_and_depth_cuts_are_explicit():
    cpg = alt.synthesize_alternate_cpg(symbol_declarations=_functions("a", "b", "c"))
    result = alt.compute_cpg_slice(cpg, path="app.py", max_nodes=1)
    assert len(result["nodes"]) == 1 and result["truncated"]
    a, b, c = [n for n in sorted(cpg["nodes"], key=lambda n: n["name"]) if n["node_kind"] == "function"]
    cpg["edges"] = [{"edge_id": str(i), "edge_kind": "CALLS", "source_id": src["node_id"],
                     "target_id": dst["node_id"]} for i, (src, dst) in enumerate(((a, b), (b, c)))]
    result = alt.compute_cpg_slice(cpg, criterion_node_id=a["node_id"], direction="forward", max_depth=1)
    assert result["truncated"]
    assert {n["name"] for n in result["nodes"]} == {"a", "b"}


def test_precomputed_path_limit_is_a_named_coverage_gap():
    cpg = alt.synthesize_alternate_cpg(
        symbol_declarations=_functions("handle", "helper"),
        codeql_facts=[{"kind": "sink_site", "path": "app.py", "start_line": 1, "name": "eval"},
                      {"kind": "sink_site", "path": "app.py", "start_line": 2, "name": "exec"}],
        settings=alt.AlternateCpgSettings(max_precomputed_paths=1),
    )
    assert len(cpg["paths"]) == 1
    assert any("path_limit" in gap for gap in cpg.get("gaps", []))


def test_path_work_is_bounded_even_when_no_sink_is_reached(monkeypatch):
    from collections import deque

    visits = []
    class CountingQueue(deque):
        def popleft(self):
            visits.append(1)
            return super().popleft()
    monkeypatch.setattr(alt, "deque", CountingQueue)
    nodes = [{"node_id": str(i), "node_kind": "function", "name": str(i), "path": "x.py",
              "start_line": i + 1} for i in range(27)]
    nodes[-1]["node_kind"] = "sink"
    layers = [[0], *[list(range(start, start + 5)) for start in range(1, 26, 5)]]
    edges = [{"edge_id": f"{a}:{b}", "edge_kind": "CALLS", "source_id": str(a), "target_id": str(b)}
             for left, right in zip(layers, layers[1:]) for a in left for b in right]
    diagnostics = {}
    result = alt.find_interprocedural_paths({"nodes": nodes, "edges": edges}, source="0", max_paths=1,
                                          diagnostics=diagnostics)
    assert result == []
    assert len(visits) <= 1024
    assert diagnostics["truncated"] and diagnostics["gaps"]
    assert diagnostics["cuts"]["work_limit"] > 0


def test_persisted_slice_depth_and_deadline_are_honored(tmp_path):
    cpg = alt.synthesize_alternate_cpg(symbol_declarations=_functions("a", "b", "c"),
                                     settings=alt.AlternateCpgSettings(max_slice_depth=1))
    a, b, c = sorted(cpg["nodes"], key=lambda n: n["name"])
    cpg["edges"] = [{"edge_id": str(i), "edge_kind": "CALLS", "source_id": src["node_id"],
                     "target_id": dst["node_id"], "resolution_tier": "syntactic_fallback"}
                    for i, (src, dst) in enumerate(((a, b), (b, c)))]
    _, identity = _publish(tmp_path, cpg)
    with sqlite3.connect(tmp_path / identity.relative_path) as db:
        db.row_factory = sqlite3.Row
        loaded = alt.load_cpg_from_sqlite(db)
    result = alt.compute_cpg_slice(loaded, criterion_node_id=a["node_id"], direction="forward", max_depth=8)
    assert {n["name"] for n in result["nodes"]} == {"a", "b"}
    assert result["truncated"] and result["cuts"]["depth_limit"] == 1
    def expired():
        raise TimeoutError("deadline reached")
    with pytest.raises(TimeoutError, match="deadline reached"):
        alt.find_interprocedural_paths(loaded, source="a", sink="c", check_deadline=expired)


def _query_core(tmp_path, cpg, **kwargs):
    root = tmp_path / "2026-11-19-0001"
    root.mkdir()
    _, identity = _publish(root, cpg)
    manifest = root / "manifest.json"
    write_manifest(manifest, run_id=root.name, target_snapshot=cpg["target_snapshot"],
                   target_root=tmp_path, indexes=[identity])
    return RetrievalCore(tmp_path, root.name, manifest_path=manifest,
                         manifest_sha256=file_sha256(manifest), **kwargs)


def _chain():
    cpg = alt.synthesize_alternate_cpg(symbol_declarations=_functions("a", "b", "c"),
                                     settings=alt.AlternateCpgSettings(max_slice_depth=1))
    a, b, c = sorted(cpg["nodes"], key=lambda n: n["name"])
    cpg["edges"] = [{"edge_id": str(i), "edge_kind": "CALLS", "source_id": src["node_id"],
                     "target_id": dst["node_id"], "resolution_tier": "syntactic_fallback"}
                    for i, (src, dst) in enumerate(((a, b), (b, c)))]
    return cpg, a


def test_query_adapter_preserves_saved_slice_depth_and_cut_gaps(tmp_path):
    cpg, a = _chain()
    core = _query_core(tmp_path, cpg)
    response = core.query_cpg_slice(criterion_node_id=a["node_id"], direction="forward", max_depth=8)
    assert {node["name"] for node in response["results"]} == {"a", "b"}
    assert response["truncated"]
    assert any("depth_limit" in gap for gap in response["coverage_gaps"])


@pytest.mark.parametrize("query", ["slice", "paths"])
def test_query_adapter_checks_deadline_inside_python_traversal(tmp_path, query):
    import inspect

    def clock():
        frame = inspect.currentframe()
        try:
            while frame:
                if frame.f_code.co_name in {"find_interprocedural_paths", "compute_cpg_slice"}:
                    return 3.0
                frame = frame.f_back
            return 0.0
        finally:
            del frame

    cpg, a = _chain()
    core = _query_core(tmp_path, cpg, clock=clock)
    response = (core.query_call_paths(source="a", sink="c") if query == "paths"
                else core.query_cpg_slice(criterion_node_id=a["node_id"], direction="forward"))
    assert response["truncated"]
    assert "query execution-time budget exceeded" in response["coverage_gaps"]


def test_query_adapter_reports_work_cut_when_no_path_is_found(tmp_path):
    cpg = alt.synthesize_alternate_cpg(symbol_declarations=_functions(*map(str, range(27))))
    nodes = {n["name"]: n for n in cpg["nodes"]}
    nodes["26"]["node_kind"] = "sink"
    layers = [[0], *[list(range(start, start + 5)) for start in range(1, 26, 5)]]
    cpg["edges"] = [{"edge_id": f"{a}:{b}", "edge_kind": "CALLS",
                     "source_id": nodes[str(a)]["node_id"], "target_id": nodes[str(b)]["node_id"],
                     "resolution_tier": "syntactic_fallback"}
                    for left, right in zip(layers, layers[1:]) for a in left for b in right]
    response = _query_core(tmp_path, cpg).query_call_paths(source="0", sink="26", limit=1)
    assert response["results"] == []
    assert response["truncated"]
    assert any("work_limit" in gap for gap in response["coverage_gaps"])


def test_legacy_alternate_shard_reads_do_not_infer_exactness(tmp_path):
    from appsec_review.retrieval import EntityKind, EntityRecord, LogicalIdentity, RelationKind, RelationRecord

    root = tmp_path / "2026-11-19-0001"
    root.mkdir()
    cpg, _ = _chain()
    builder = IndexBuilder(root / "legacy.sqlite", name="analysis", fingerprint="c" * 64,
                           target_snapshot=cpg["target_snapshot"], shard_id="alternate-cpg")
    identities = {}
    for node in cpg["nodes"]:
        legacy = {key: value for key, value in node.items() if key not in {"location", "evidence"}}
        identity = LogicalIdentity.derive(EntityKind.SYMBOL, cpg["target_snapshot"], {"node": node["node_id"]})
        identities[node["node_id"]] = identity.value
        builder.add_entity(EntityRecord(identity, node["node_id"], node["name"], node["name"],
                                       {"cpg_record": "cpg_node", "cpg_node_json": json.dumps(legacy)}))
    for edge in cpg["edges"]:
        builder.add_relation(RelationRecord(
            RelationKind.CALLS, identities[edge["source_id"]], identities[edge["target_id"]],
            True, 0.95, payload={"cpg_edges_json": json.dumps([edge])},
        ))
    identity, _ = _shard(root, builder, "job_code_graph_index")
    manifest = root / "manifest.json"
    write_manifest(manifest, run_id=root.name, target_snapshot=cpg["target_snapshot"],
                   target_root=tmp_path, indexes=[IndexIdentity(**identity)])
    core = RetrievalCore(tmp_path, root.name, manifest_path=manifest, manifest_sha256=file_sha256(manifest))
    paths = core.query_call_paths(source="a", sink="c")
    assert len(paths["results"]) == 1
    assert not paths["results"][0]["exact"]
    assert all(not hop["exact"] and not hop["evidence"] for hop in paths["results"][0]["hops"])
    sliced = core.query_cpg_slice(function_name="a", direction="forward", max_depth=2)
    assert {node["name"] for node in sliced["results"]} == {"a", "b", "c"}
