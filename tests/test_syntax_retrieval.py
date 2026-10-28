from __future__ import annotations

import hashlib
from dataclasses import asdict, replace
import json
from pathlib import Path
import shutil
import subprocess
import time

import pytest

from appsec_review.jobs.job_tree_sitter_ast.model import GrammarLock, Scope
from appsec_review.jobs.job_tree_sitter_ast.normalize import normalize_scope
from appsec_review.jobs.job_tree_sitter_ast.projection import project
from appsec_review.mcp.adapter import RetrievalMcpAdapter
from appsec_review.mcp.capability import ScopedRetrievalMcpAdapter, issue_capability
from appsec_review.retrieval import EntityKind, LogicalIdentity, RetrievalCore
from appsec_review.retrieval.index import IndexBuilder, IndexIdentity, write_manifest
from appsec_review.retrieval.syntax_contract import SCHEMA
from appsec_review.review.capability import Authorized, CellCapability
from appsec_review.review.cells import _bound

RUN_ID = "2026-10-28-0001"
SOURCE = b'import os\n\ndef dispatch(value):\n    return sink(value)\n\ndef other():\n    return sink("x")\n'


def _node(data: bytes, kind: str, ordinal: tuple[int, ...], start: int, end: int, field=None):
    def point(offset):
        prefix = data[:offset]
        return [prefix.count(b"\n"), offset - prefix.rfind(b"\n") - 1]
    return {"type": kind, "ordinal_path": list(ordinal), "field": field, "named": True,
            "error": False, "missing": False, "extra": False, "has_error": False,
            "start_byte": start, "end_byte": end, "start_point": point(start), "end_point": point(end)}


def _nodes(data: bytes = SOURCE):
    nodes = [_node(data, "module", (), 0, len(data)),
             _node(data, "import_statement", (0,), 0, 9),
             _node(data, "dotted_name", (0, 0), 7, 9, "name")]
    for ordinal, name in ((1, b"dispatch"), (2, b"other")):
        start = data.index(b"def " + name)
        name_start = start + 4
        call = data.index(b"sink", name_start)
        end = data.index(b"\n", call)
        nodes.extend([_node(data, "function_definition", (ordinal,), start, end),
                      _node(data, "identifier", (ordinal, 0), name_start, name_start + len(name), "name"),
                      _node(data, "call", (ordinal, 1), call, end),
                      _node(data, "identifier", (ordinal, 1, 0), call, call + 4, "function")])
    return nodes


def _run(tmp_path: Path, *, error=False, grammar="python", data=SOURCE, projection_bytes=None):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_bytes(data)
    run_root = tmp_path / "runs" / RUN_ID
    digest = hashlib.sha256(data).hexdigest()
    scope = Scope("component-123-build-abc-Python-digest", "component-123", ".", "build-abc", ".",
                  "Python", ({"path": "app.py", "sha256": digest, "size_bytes": len(data),
                              "language": "Python"},))
    lock = GrammarLock("Python", grammar, "https://example.invalid/grammar", "a" * 40, "MIT", "grammar.so", "b" * 64)
    nodes = _nodes(data)
    output = {"schema": "appsec-review/tree-sitter-container-output/1", "scope_id": scope.scope_id,
              "language": scope.language, "records": [{"path": "app.py", "sha256": digest,
              "bytes": len(data), "status": "SUCCEEDED", "root_has_error": error, "nodes": nodes}]}
    _, identity, _ = normalize_scope(run_root=run_root, target_snapshot="snapshot", scope=scope,
        grammar=lock, fingerprint="f" * 64, container_output=output,
        source_bytes={"app.py": data if projection_bytes is None else projection_bytes},
        producer={"job": "job_tree_sitter_ast", "language": "Python", "scope_id": scope.scope_id},
        artifact_path=run_root / "data" / "ast.jsonl", index_path=run_root / "data" / "analysis.sqlite")
    manifest = run_root / "data" / "manifest.json"
    write_manifest(manifest, run_id=RUN_ID, target_snapshot="snapshot", target_root=target, indexes=[identity])
    source_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, "snapshot", {"path": "app.py", "sha256": digest}).value
    return RetrievalCore(tmp_path / "runs", RUN_ID, manifest_path=manifest), source_id, identity, nodes


def _capability(core, source, **overrides):
    values = dict(run_id=core.run_id, manifest_sha256=core.manifest_sha256, package_id="one",
                  package_sha256="p" * 64, role="red_team_analyst", round=0,
                  tools=("query_syntax", "find", "read_excerpt"), indexes=("analysis",), entities=(source,),
                  max_queries=20, max_turns=5, page_size=20, max_depth=2, max_result_bytes=65536)
    return CellCapability.issue(**{**values, **overrides})


def test_source_only_navigation_exact_spans_ast_subjects_and_excerpts(tmp_path):
    core, source, identity, _ = _run(tmp_path)
    assert "graph" not in core.indexes
    definitions = core.query_syntax(mode="definitions", subject=source)["results"]
    assert {row["payload"]["syntax"]["written_name"] for row in definitions} == {"dispatch", "other"}
    dispatch = next(row for row in definitions if row["payload"]["syntax"]["written_name"] == "dispatch")
    span = dispatch["payload"]["syntax"]["name_span"]
    assert SOURCE[span["start_byte"]:span["end_byte"]] == b"dispatch"
    calls = core.query_syntax(mode="calls", subject=dispatch["identity"], name="sink")["results"]
    assert len(calls) == 1
    assert calls[0]["payload"]["syntax"]["syntactic_qualifiers"] == ["dispatch"]
    assert calls[0]["payload"]["syntax"]["resolution"] == "unresolved"
    assert calls[0]["kind"] == "ast_node" and calls[0]["payload"]["syntax_only"]
    excerpt = core.read_excerpt(identity=calls[0]["identity"])
    assert "sink(value)" in json.dumps(excerpt)
    assert len(core.query_syntax(mode="calls", subject=source, name="sink")["results"]) == 2
    assert core.query_syntax(mode="calls", subject=source, name="SINk")["results"] == []
    assert core.query_syntax(mode="imports", subject=source)["results"][0]["payload"]["syntax"]["written_name"] == "os"
    assert core.query_syntax(mode="references", subject=source, name="sink")["results"]
    with core._database(core.indexes["analysis"][0], core.clock() + 10) as database:
        plan = list(database.execute("EXPLAIN QUERY PLAN SELECT * FROM entities WHERE kind='ast_node' "
                                    "AND json_extract(payload_json, '$.syntax.source_identity')=?", (source,)))
        assert any("syntax_lookup" in str(tuple(row)) for row in plan)
    assert identity.producer["syntax_projection"] == SCHEMA


def test_raw_ast_subject_and_response_byte_bound(tmp_path):
    core, source, _, _ = _run(tmp_path)
    root = core.find(kind="ast_node", name="module", indexes=["analysis"])["results"][0]
    assert len(core.query_syntax(mode="definitions", subject=root["identity"])["results"]) == 2
    core.limits = replace(core.limits, max_response_bytes=1800)
    response = core.query_syntax(mode="definitions", subject=source)
    assert len(json.dumps(response, separators=(",", ":"), ensure_ascii=False).encode()) <= 1800
    assert response["truncated"] and response["coverage_gaps"]


def test_projection_rejects_bytes_different_from_the_accepted_source(tmp_path):
    with pytest.raises(ValueError, match="source identity differs"):
        _run(tmp_path, projection_bytes=b"changed")


def test_unrepresentable_and_long_names_are_named_projection_gaps():
    for data, reason in ((b"x" * 513, "512"), (b"caf\xe9", "non-UTF-8")):
        nodes = [_node(data, "module", (), 0, len(data)), _node(data, "identifier", (0,), 0, len(data))]
        limitations = set()
        projected = project(nodes, data, grammar="python", source_identity="asr:source_file:" + "a" * 64,
                            identities={tuple(node["ordinal_path"]): "asr:ast_node:" + "b" * 64 for node in nodes},
                            limitations=limitations)
        assert not projected and any(reason in value for value in limitations)


def test_component_prefixed_syntax_scopes_join_explicit_languages_and_failed_siblings(tmp_path):
    from appsec_review.indexing.matrix import language_matrix
    from appsec_review.indexing.store import ShardSet
    core, _, identity, _ = _run(tmp_path)
    path = core.run_root / "data" / "coverage.sqlite"
    builder = IndexBuilder(path, name="analysis", fingerprint="c" * 64, target_snapshot="snapshot",
                           shard_id="tree-sitter-coverage-fixture")
    builder.add_coverage(identity.shard_id, "complete")
    builder.add_coverage("component-another-unrelated-slug", "unavailable", "parser failed")
    sha = builder.build()
    coverage = IndexIdentity("analysis", "appsec-review/retrieval-index/2", sha, "c" * 64,
        path.relative_to(core.run_root).as_posix(), {"job": "job_tree_sitter_ast",
            "scope_languages": {identity.shard_id: "Python", "component-another-unrelated-slug": "Python"}},
        (), "tree-sitter-coverage-fixture")
    rows = language_matrix(ShardSet(core.run_root, [asdict(identity), asdict(coverage)]), {})
    assert len(rows) == 1 and rows[0]["language"] == "python"
    assert rows[0]["lanes"]["syntax"]["state"] == "partial"


def test_pagination_gaps_and_subject_hash_isolation(tmp_path):
    core, source, _, _ = _run(tmp_path, error=True)
    first = core.query_syntax(mode="calls", subject=source, limit=1)
    assert any("parse diagnostics" in gap for gap in first["coverage_gaps"])
    cursor = first["pagination"]["next_cursor"]
    second = core.query_syntax(mode="calls", subject=source, limit=1, cursor=cursor)
    assert len(first["results"]) == len(second["results"]) == 1
    assert first["results"][0]["identity"] != second["results"][0]["identity"]
    with pytest.raises(ValueError, match="cursor"):
        core.query_syntax(mode="definitions", subject=source, limit=1, cursor=cursor)
    other = LogicalIdentity.derive(EntityKind.SOURCE_FILE, "other-snapshot", {"path": "app.py", "sha256": "a" * 64}).value
    absent = core.query_syntax(mode="calls", subject=other)
    assert not absent["results"] and any("unavailable" in gap for gap in absent["coverage_gaps"])
    (core.target_root / "app.py").write_bytes(b"tampered")
    changed = core.read_excerpt(identity=first["results"][0]["identity"])
    assert not changed["results"] and any("source changed after indexing" in gap for gap in changed["coverage_gaps"])


def test_no_projection_mapping_retains_raw_ast_and_names_the_gap(tmp_path):
    core, source, _, _ = _run(tmp_path, grammar="powershell")
    assert core.find(kind="ast_node", indexes=["analysis"])["results"]
    response = core.query_syntax(mode="definitions", subject=source)
    assert not response["results"] and any("no syntax projection mapping" in gap for gap in response["coverage_gaps"])


def test_cell_grants_only_returned_nodes_of_an_exact_source_not_prefixes_or_siblings(tmp_path):
    core, source, _, _ = _run(tmp_path)
    capability = _capability(core, source)
    request = {"tool": "query_syntax", "parameters": {"mode": "calls", "subject": source}}
    assert isinstance(capability.authorize(request), Authorized)
    response = core.query_syntax(mode="calls", subject=source)
    granted = set()
    bounded, withheld = _bound("query_syntax", response, capability, granted=granted)
    assert not withheld and len(granted) == 2
    returned = bounded["results"][0]["identity"]
    assert isinstance(capability.authorize({"tool": "read_excerpt", "parameters": {"identity": returned}},
                                          granted=granted), Authorized)
    other = LogicalIdentity.derive(EntityKind.SOURCE_FILE, "other", {"path": "sibling.py"}).value
    assert capability.authorize({**request, "parameters": {"mode": "calls", "subject": other}}).code == "entity_out_of_scope"
    prefix = _capability(core, other, entity_prefixes=("asr:source_file:",))
    assert prefix.authorize(request).code == "entity_out_of_scope"
    assert _bound("query_syntax", response, prefix)[1] == 2
    assert _capability(core, source, indexes=()).authorize(request).code == "index_not_granted"
    assert capability.authorize({**request, "parameters": {**request["parameters"], "path": "sibling.py"}}).code == "forbidden_parameter"


def test_scoped_mcp_source_fallback_cursor_and_followup_excerpt(tmp_path):
    core, source, _, _ = _run(tmp_path)
    package = {"run_id": core.run_id, "manifest_sha256": core.manifest_sha256, "package_id": "one",
               "retrieval": {"indexes": ["analysis"], "query_sets": [], "entity_ids": [source],
                             "max_page_size": 2, "max_pages": 2, "max_depth": 2, "max_response_bytes": 65536}}
    secret = b"s" * 32
    def scoped(value):
        token = issue_capability(value, role="red", round_id="1", secret=secret, expires_at=int(time.time()) + 300)
        return ScopedRetrievalMcpAdapter(RetrievalMcpAdapter(core), value, capability=token, secret=secret,
                                         role="red", round_id="1")
    adapter = scoped(package)
    query = {"mode": "calls", "subject": source, "limit": 1}
    result = adapter.call("query_syntax", query)
    identity = result["results"][0]["identity"]
    assert adapter.call("find", {"identity": identity})["results"]
    assert adapter.call("read_excerpt", {"identity": identity})["results"]
    cursor = result["pagination"]["next_cursor"]
    assert adapter.call("query_syntax", {**query, "cursor": cursor})["results"]
    with pytest.raises(ValueError, match="cursor binding"):
        scoped({**package, "package_id": "two"}).call("query_syntax", {**query, "cursor": cursor})
    with pytest.raises(ValueError, match="outside review package"):
        scoped(package).call("find", {"identity": identity})
    with pytest.raises(ValueError, match="page"):
        adapter.call("query_syntax", {**query, "limit": 3})


@pytest.mark.parametrize("arguments", [
    {"mode": "dataflow", "subject": "asr:source_file:" + "a" * 64},
    {"mode": "calls", "subject": "asr:symbol:" + "a" * 64},
    {"mode": "calls", "subject": "asr:source_file:" + "a" * 64, "limit": True},
    {"mode": "calls", "subject": "asr:source_file:" + "a" * 64, "name": "x" * 513},
])
def test_invalid_or_unbounded_syntax_requests_are_rejected(tmp_path, arguments):
    core, _, _, _ = _run(tmp_path)
    with pytest.raises(ValueError):
        core.query_syntax(**arguments)


SAMPLES = [
    ("c", "#include <stdio.h>\nint dispatch(){ return sink(); }", "dispatch", "sink"),
    ("cpp", "#include <string>\nclass C { int dispatch(){ return sink(); } };", "dispatch", "sink"),
    ("csharp", "using System;\nclass C { int Dispatch(){ return Sink(); } }", "Dispatch", "Sink"),
    ("go", 'package p\nimport "os"\nfunc dispatch() { sink() }', "dispatch", "sink"),
    ("java", "import java.util.List;\nclass C { int dispatch(){ return sink(); } }", "dispatch", "sink"),
    ("javascript", 'import lib from "lib";\nexport function dispatch(){ return lib.sink(); }', "dispatch", "lib.sink"),
    ("typescript", 'import lib from "lib";\nfunction dispatch(): number { return sink(); }', "dispatch", "sink"),
    ("tsx", 'import lib from "lib";\nfunction dispatch(){ return sink(); }', "dispatch", "sink"),
    ("kotlin", "import java.io.File\nfun dispatch() { sink() }", "dispatch", "sink"),
    ("python", "import os\ndef dispatch():\n    return sink()\n", "dispatch", "sink"),
    ("ruby", "require 'dep'\ndef dispatch\n  sink()\nend\n", "dispatch", "sink"),
    ("rust", "use std::fs;\nfn dispatch() { sink(); }", "dispatch", "sink"),
    ("php", "<?php use Foo\\Bar;\nfunction dispatch() { return sink(); }", "dispatch", "sink"),
]

# No host mounts or network are needed: feed only repository-owned fixture bytes over stdin to the
# already installed image, using its pinned parser and grammars unchanged.
_PARSE_FIXTURES = """
import json, runpy, sys
p = runpy.run_path('/opt/appsec/parser.py')
p['configure'](p['PackConfig'](cache_dir='/opt/grammars'))
result = {}
for grammar, text, _, _ in json.load(sys.stdin):
    tree = p['get_parser'](grammar).parse(text.encode())
    stack, nodes = [(tree.root_node, (), None)], []
    while stack:
        node, ordinal, field = stack.pop()
        nodes.append(p['_node'](node, ordinal, field))
        stack.extend((child, (*ordinal, i), node.field_name_for_child(i))
                     for i, child in reversed(list(enumerate(node.children))))
    result[grammar] = {'error': tree.root_node.has_error, 'nodes': nodes}
json.dump(result, sys.stdout)
"""


@pytest.fixture(scope="module")
def live_nodes():
    if not shutil.which("docker"):
        pytest.skip("pinned Tree-sitter image unavailable")
    from appsec_review.container_runtime import load_catalog
    root = Path(__file__).resolve().parents[1]
    tool = load_catalog(root).tools["tool-tree-sitter"]
    probe = subprocess.run(["docker", "image", "inspect", tool.tag, "--format", "{{.Id}}"],
                           capture_output=True, text=True, timeout=15)
    if probe.returncode != 0:
        pytest.skip("pinned Tree-sitter image unavailable")
    assert probe.stdout.strip() == tool.expected_image_id
    parsed = subprocess.run(["docker", "run", "--rm", "-i", "--network", "none", "--read-only",
                             "--user", "10001:10001", "--entrypoint", "python", tool.expected_image_id, "-c", _PARSE_FIXTURES],
                            input=json.dumps(SAMPLES), capture_output=True, text=True, timeout=60)
    assert parsed.returncode == 0, parsed.stderr
    return json.loads(parsed.stdout)


@pytest.mark.parametrize(("grammar", "source", "definition", "call"), SAMPLES)
def test_locked_grammar_definition_and_call_shapes(live_nodes, grammar, source, definition, call):
    parsed = live_nodes[grammar]
    assert not parsed["error"]
    nodes = parsed["nodes"]
    identities = {tuple(node["ordinal_path"]): "asr:ast_node:" + hashlib.sha256(
                  json.dumps(node).encode()).hexdigest() for node in nodes}
    data = source.encode()
    projected = project(nodes, data, grammar=grammar, source_identity="asr:source_file:" + "f" * 64,
                        identities=identities)
    assert definition in {value["written_name"] for value in projected.values() if value["category"] == "definition"}
    assert call in {value["written_name"] for value in projected.values() if value["category"] == "call_expression"}
    assert any(value.get("import_expression") for value in projected.values())
    for value in projected.values():
        span = value["name_span"]
        assert data[span["start_byte"]:span["end_byte"]].decode() == value["written_name"]
        assert value["syntax_only"] and value["resolution"] == "unresolved"
