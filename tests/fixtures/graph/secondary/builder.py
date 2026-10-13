"""Build small accepted-style secondary shards and CodeQL graph facts for cross-check and correlation tests.

Shards are written with the real ``IndexBuilder`` in the shapes the producing jobs publish
(``job_cpp_symbol_index`` clangd symbols and aggregated ``CALLS``, ``job_cpp_compiled_analysis`` IR
entities/``CALLS`` and AST ``CallExpr`` nodes, ``job_codeql_analysis`` ``tool_observation`` flows and
``job_review_prioritization`` ``review_signal``/``review_flow_step``), bound into a manifest, verified
with ``load_verified_manifest`` and read back through ``indexing.store.ShardSet``, like
``tests/fixtures/inference_review/builder.py``. Graph facts are built directly from the C0 contract.

Usage::

    fixture = build_secondary(tmp_path, clangd=CLANGD_CALLS)
    fixture.read("clangd")           # SecondaryShard
    fixture.call("helper", "process", "helper(n)")   # GraphFact
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import random
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.graph import contract as c
from appsec_review.graph.crosscheck import SecondaryShard, SourceFile, read_secondary
from appsec_review.indexing.store import ShardSet
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.index import load_verified_manifest

RUN_ID = "2026-10-12-0004"
SNAPSHOT = "target-sha256:" + "4" * 64
SHA = "b" * 64
SCOPE = {"scope_id": "codeql-cpp-native-main", "language": "c/c++", "build_unit_id": "native-main",
         "component_id": "component:0002"}

NET_C = """#include <string.h>
static int helper(int x) { return x + 1; }
static int other(int x) { return x - 1; }
int process(char *dst, const char *src, int n) {
    int a = helper(n);
    int b = other(a);
    memcpy(dst, src, b);
    return helper(b);
}
"""
IO_C = """#include <string.h>
#include <unistd.h>
void handle(char *out) {
    char buf[64];
    int n = read(0, buf, sizeof buf);
    int m = n * 2;
    int k = m + 1;
    memcpy(out, buf, k);
}
"""
FILES = {"src/net.c": NET_C, "src/io.c": IO_C}

# clangd symbol name -> (clangd id, path, needle whose first occurrence is the definition name)
CLANGD_SYMBOLS = {"helper": ("0000000000000001", "src/net.c", "helper"),
                  "other": ("0000000000000002", "src/net.c", "other"),
                  "process": ("0000000000000003", "src/net.c", "process")}
# (caller, callee) -> [(line, column)] of the callee reference token, as clangd-indexer reports it.
CLANGD_CALLS = {("process", "helper"): [(5, 13), (6, 13), (8, 12)]}
IR_FUNCTIONS = ("helper", "other", "process")
IR_CALLS = (("process", "helper"), ("process", "other"))


def _clangd_id(name: str) -> str:
    return LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"project_id": "native", "producer": "clangd",
                                                               "clangd_id": CLANGD_SYMBOLS[name][0]}).value


def _ir_id(name: str) -> str:
    return LogicalIdentity.derive(EntityKind.IR_ENTITY, SNAPSHOT, {"compile_unit_id": "tu-net", "function": name,
                                                                  "definition_line": 1}).value


@dataclass
class SecondaryFixture:
    run_root: Path
    shard_set: ShardSet
    shards: dict[str, Mapping[str, Any]]
    sources: dict[str, SourceFile]
    ids: dict[str, str] = field(default_factory=dict)

    def read(self, key: str) -> SecondaryShard:
        producer = {"clangd": c.Producer.CLANGD, "ir": c.Producer.LLVM_IR, "ast": c.Producer.CLANG_AST}[key]
        return read_secondary(self.shard_set, self.shards[key], producer, tool_version="fixture")

    def rows(self, key: str, kinds: Sequence[str]) -> list[dict[str, Any]]:
        return list(self.shard_set.entities([self.shards[key]], kinds=kinds))

    # -- graph facts ---------------------------------------------------------------------------------
    def location(self, path: str, needle: str, nth: int = 0, *, ambiguous: bool = False) -> SourceLocation:
        return span(self.sources, path, needle, nth, ambiguous=ambiguous)

    def call(self, callee: str, caller: str, needle: str, *, nth: int = 0, path: str = "src/net.c",
             dispatch: str = "direct", callee_symbol: str | None | bool = True,
             caller_symbol: str | None = None, callee_display: str | None = None) -> c.GraphFact:
        location = self.location(path, needle, nth)
        caller_id = caller_symbol or self.ids.get(f"clangd:{caller}") or _clangd_id(caller)
        if callee_symbol is True:
            callee_symbol = self.ids.get(f"clangd:{callee}") or (_clangd_id(callee) if callee in CLANGD_SYMBOLS
                                                                  else None)
        display = callee_display or callee
        identity = c.fact_identity(c.Family.CALL_SITE, SNAPSHOT, {
            "scope_id": SCOPE["scope_id"], "caller_symbol": caller_id, "path": path,
            "start_byte": location.start_byte, "end_byte": location.end_byte, "callee_name": display})
        result = {"caller": {"symbol": caller_id, "display": caller},
                  "callee": {"symbol": callee_symbol or None, "display": display, "dispatch": dispatch,
                             "candidate_count": 1},
                  "argument_count": 1, "in_loop": False}
        return c.GraphFact(identity, f"{caller} -> {display}", payload(c.Family.CALL_SITE, result), location)

    def sink(self, needle: str, nth: int = 0, *, line_of: str | None = None) -> c.GraphFact:
        location = self.location("src/io.c", needle, nth)
        identity = c.fact_identity(c.Family.SINK_SITE, SNAPSHOT, {
            "scope_id": SCOPE["scope_id"], "path": "src/io.c", "start_byte": location.start_byte,
            "end_byte": location.end_byte, "sink_class": "memory_write", "argument_index": 2})
        return c.GraphFact(identity, "memcpy size", payload(c.Family.SINK_SITE, {"sink_class": "memory_write"}),
                           location)

    def entry(self, needle: str, nth: int = 0) -> c.GraphFact:
        location = self.location("src/io.c", needle, nth)
        identity = c.fact_identity(c.Family.ENTRY_POINT, SNAPSHOT, {
            "scope_id": SCOPE["scope_id"], "path": "src/io.c", "start_byte": location.start_byte,
            "end_byte": location.end_byte, "source_class": "file"})
        return c.GraphFact(identity, "read", payload(c.Family.ENTRY_POINT, {"source_class": "file"}), location)

    def path(self, entry: c.GraphFact, sink: c.GraphFact, steps: Sequence[tuple[str, int]]) -> c.GraphFact:
        """A dataflow_path whose steps are ``(needle, nth)`` spans in ``src/io.c``."""
        rendered = []
        for n, (needle, nth) in enumerate(steps):
            location = self.location("src/io.c", needle, nth)
            role = "source" if n == 0 else "sink" if n == len(steps) - 1 else "step"
            rendered.append({"n": n, "location": asdict(location), "role": role, "symbol": None, "display": needle})
        step_hash = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, SNAPSHOT, {"steps": rendered}).value[-64:]
        identity = c.fact_identity(c.Family.DATAFLOW_PATH, SNAPSHOT, {
            "scope_id": SCOPE["scope_id"], "source_identity": entry.identity.value,
            "sink_identity": sink.identity.value, "step_locations_sha256": step_hash})
        result = {"source": {"entry_point": entry.identity.value, "source_class": "file"},
                  "sink": {"sink_site": sink.identity.value, "sink_class": "memory_write", "cwe_family": "CWE-787"},
                  "steps": rendered, "hop_count": len(rendered) - 1, "call_depth": 0, "guards": [], "sanitizers": [],
                  "truncated_steps": False, "selection": "shortest-k"}
        return c.GraphFact(identity, "read -> memcpy", payload(c.Family.DATAFLOW_PATH, result), sink.location)

    def symbol(self, name: str, *, needle: str | None = None, nth: int = 0) -> EntityRecord:
        """A CodeQL-exported graph ``symbol`` at the definition name span (or another needle)."""
        _, path, default = CLANGD_SYMBOLS[name]
        location = self.location(path, needle or default, nth)
        identity = LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"producer": "codeql-export",
                                                                        "scope_id": SCOPE["scope_id"], "name": name})
        return EntityRecord(identity, name, name, f"function {name}", {"producer": "codeql-export"}, location)


def span(sources: Mapping[str, SourceFile], path: str, needle: str, nth: int = 0, *,
         ambiguous: bool = False) -> SourceLocation:
    data = sources[path].data
    start = -1
    for _ in range(nth + 1):
        start = data.index(needle.encode(), start + 1)
    end = start + len(needle.encode())
    line = data.count(b"\n", 0, start) + 1
    line_start = data.rfind(b"\n", 0, start) + 1
    column = start - line_start + 1
    return SourceLocation(SNAPSHOT, path, sources[path].sha256, start, end, line, line, column,
                          column + len(needle), {"fixture": needle}, "codeql-location-exact",
                          0.5 if ambiguous else 1.0, ambiguous)


def sarif_step(sources: Mapping[str, SourceFile], ordinal: int, path: str, needle: str, nth: int = 0, *,
               code_flow: int = 0, thread_flow: int = 0) -> dict[str, Any]:
    """One normalized SARIF flow step as ``sarif.py::normalize_sarif`` stores it (end column exclusive)."""
    location = span(sources, path, needle, nth)
    return {"ordinal": ordinal, "code_flow": code_flow, "thread_flow": thread_flow, "message": needle,
            "location": {"path": path, "file_sha256": location.file_sha256, "start_line": location.start_line,
                         "end_line": location.end_line, "start_column": location.start_column,
                         "end_column": location.end_column, "confidence": 1.0, "ambiguous": False,
                         "candidates": [path], "producer_location": {}},
            "supporting": True}


def payload(family: c.Family, result: Mapping[str, Any], **overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": c.GRAPH_FACT_SCHEMA, "family": family.value,
        "producer": {"name": "codeql-export", "tool_version": "2.27.0", "export_pack_sha256": SHA,
                     "catalog_version": c.CATALOG_SCHEMA, "rule_version": c.NORMALIZE_RULE},
        "scope": dict(SCOPE), "exact": True, "coverage_status": "complete", "gaps": [],
        "cross_check": {"rule": c.CROSS_CHECK_RULE, "state": "not_covered", "producers": []},
        "result": dict(result), "upstream": [{"index": "graph-export", "shard_id": "codeql-cpp", "sha256": SHA}],
        "authority": c.AUTHORITY,
    }
    value.update(overrides)
    value["admissibility"] = c.admissibility(value)
    return value


def build_secondary(base: Path, *, clangd: Mapping[tuple[str, str], list[tuple[int, int]]] | None = CLANGD_CALLS,
                    clangd_occurrence_extra: int = 0,
                    ir_calls: Iterable[tuple[str, str]] | None = IR_CALLS,
                    ast_calls: Iterable[tuple[str | None, int]] | None = (("helper", 5),),
                    observations: Sequence[Mapping[str, Any]] = (),
                    priority: Sequence[Mapping[str, Any]] | None = None,
                    seed: int | None = None) -> SecondaryFixture:
    """Write the requested shards; ``None`` omits a shard. ``priority`` lists semantic-path signals."""
    run_root = Path(base) / "runs" / RUN_ID
    target = Path(base) / "target"
    for path, text in FILES.items():
        (target / path).parent.mkdir(parents=True, exist_ok=True)
        (target / path).write_text(text, encoding="utf-8")
    sources = {path: SourceFile.from_bytes(text.encode()) for path, text in FILES.items()}
    shuffle = random.Random(seed).shuffle if seed is not None else (lambda values: None)
    identities: list[IndexIdentity] = []
    keys: dict[str, str] = {}
    ids: dict[str, str] = {}

    def file_location(path: str, line: int, column: int, *, ambiguous: bool = False,
                      method: str = "exact-path") -> SourceLocation:
        size = sources[path].size
        return SourceLocation(SNAPSHOT, path, sources[path].sha256, 0, size, line, line, column, column,
                              {"path": path, "line": line, "column": column}, method, 0.5 if ambiguous else 1.0,
                              ambiguous)

    def shard(key: str, name: str, shard_id: str, producer: dict[str, Any], entities: list[EntityRecord],
              relations: list[RelationRecord] = ()) -> None:
        fingerprint = index_fingerprint(name=name, target_snapshot=SNAPSHOT, producer_artifacts=[{"shard": shard_id}],
                                        tool_identity=producer, parser_identity="fixture/1",
                                        normalizer_identity="fixture/1", mapping_identity="fixture/1")
        path = run_root / "data" / "indices" / name / shard_id / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name=name, fingerprint=fingerprint, target_snapshot=SNAPSHOT, shard_id=shard_id)
        entities, relations = list(entities), list(relations)
        shuffle(entities)
        shuffle(relations)
        for entity in entities:
            builder.add_entity(entity)
        for relation in relations:
            builder.add_relation(relation)
        builder.add_coverage(shard_id, "complete")
        identities.append(IndexIdentity(name, "appsec-review/retrieval-index/2", builder.build(), fingerprint,
                                        path.relative_to(run_root).as_posix(), producer, (), shard_id))
        keys[key] = shard_id

    if clangd is not None:
        entities = []
        for name, (clangd_id, path, needle) in CLANGD_SYMBOLS.items():
            definition = span(sources, path, needle)
            ids[f"clangd:{name}"] = _clangd_id(name)
            entities.append(EntityRecord(
                LogicalIdentity.parse(_clangd_id(name)), clangd_id, name, f"Function {name}",
                {"producer": "clangd", "clangd_id": clangd_id, "kind": "Function",
                 "definition": {"path": path, "line": definition.start_line, "column": definition.start_column,
                                "end_line": definition.end_line, "end_column": definition.end_column},
                 "declaration": None, "project_id": "native", "shard_id": "clangd-native"},
                file_location(path, definition.start_line, definition.start_column, method="clangd-uri-exact-path")))
        relations = [RelationRecord(RelationKind.CALLS, _clangd_id(caller), _clangd_id(callee), True, 1.0, None,
                                    {"producer": "clangd", "occurrences": len(points) + clangd_occurrence_extra,
                                     "locations": [{"path": "src/net.c", "line": line, "column": column,
                                                    "ref_kind": 28} for line, column in points]})
                     for (caller, callee), points in clangd.items()]
        shard("clangd", "analysis", "clangd-native", {"job": "job_cpp_symbol_index", "scope_id": "native"},
              entities, relations)
    if ir_calls is not None:
        entities = [EntityRecord(LogicalIdentity.parse(_ir_id(name)), f"0:{name}", name, f"define i32 @{name}(",
                                 {"kind": "function", "ir_line": 1, "project_id": "native",
                                  "compile_unit_id": "tu-net", "shard_id": "cpp-native-ir"},
                                 file_location("src/net.c", 1, 1, ambiguous=True, method="debug-or-tu-fallback"))
                    for name in IR_FUNCTIONS]
        for name in IR_FUNCTIONS:
            ids[f"ir:{name}"] = _ir_id(name)
        relations = [RelationRecord(RelationKind.CALLS, _ir_id(caller), _ir_id(callee), True, 1.0,
                                    payload={"mapping": "unique-ir-definition"}) for caller, callee in ir_calls]
        shard("ir", "analysis", "cpp-native-ir", {"job": "job_cpp_compiled_analysis", "branch": "ir"},
              entities, relations)
    if ast_calls is not None:
        entities = []
        for ordinal, (name, line) in enumerate(ast_calls):
            identity = LogicalIdentity.derive(EntityKind.AST_NODE, SNAPSHOT, {"compile_unit_id": "tu-net",
                                                                              "native": f"0x{ordinal}",
                                                                              "kind": "CallExpr", "line": line,
                                                                              "column": 1})
            ids[f"ast:{ordinal}"] = identity.value
            entities.append(EntityRecord(identity, f"0x{ordinal}", name or "CallExpr", f"CallExpr {name}",
                                         {"kind": "CallExpr", "type": {"qualType": "int"},
                                          "referenced_decl": {"name": name} if name else None,
                                          "project_id": "native", "compile_unit_id": "tu-net",
                                          "shard_id": "cpp-native-ast"},
                                         file_location("src/net.c", line, 1)))
        shard("ast", "analysis", "cpp-native-ast", {"job": "job_cpp_compiled_analysis", "branch": "ast"}, entities)
    if observations:
        entities = []
        for item in observations:
            identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAPSHOT, {"key": item["key"]})
            ids[f"obs:{item['key']}"] = identity.value
            entities.append(EntityRecord(identity, item["key"], "cpp/overflow", "overflow",
                                         {"producer": "codeql", "rule_id": "cpp/overflow",
                                          "query_identity": "fixture", "flows": list(item["flows"])},
                                         file_location("src/io.c", 8, 5)))
        shard("observations", "observations", "codeql-cpp-native", {"job": "job_codeql_analysis"}, entities)
    if priority is not None:
        entities, relations = [], []
        for item in priority:
            signal_id = item["path_id"]
            observation = ids[f"obs:{item['observation']}"]
            signal = LogicalIdentity.derive(EntityKind.REVIEW_SIGNAL, SNAPSHOT, {"signal_id": signal_id})
            ids[f"signal:{signal_id}"] = signal.value
            steps = item["flow_steps"]
            entities.append(EntityRecord(signal, signal_id, "cpp/overflow", "semantic_path",
                                         {"category": "semantic_path", "path_id": signal_id,
                                          "observation": observation, "code_flow": item["code_flow"],
                                          "thread_flow": item.get("thread_flow", 0), "steps": len(steps),
                                          "authority": "review lead; not a finding"},
                                         file_location("src/io.c", steps[-1]["location"]["start_line"], 1)))
            for ordinal, step in enumerate(steps):
                point = step["location"]
                step_id = LogicalIdentity.derive(EntityKind.REVIEW_FLOW_STEP, SNAPSHOT, {
                    "path_id": signal_id, "ordinal": ordinal, "source": point})
                ids[f"step:{signal_id}:{ordinal}"] = step_id.value
                data = sources[point["path"]].data
                starts = [0, *(index + 1 for index, byte in enumerate(data) if byte == 10)]
                line = point["start_line"]
                end = starts[line] if line < len(starts) else len(data)
                entities.append(EntityRecord(step_id, f"{signal_id}:{ordinal}", f"flow step {ordinal}", "step",
                                             {"path_id": signal_id, "ordinal": ordinal, "message": step["message"],
                                              "producer": "codeql", "basis": "verified_semantic_path"},
                                             SourceLocation(SNAPSHOT, point["path"], sources[point["path"]].sha256,
                                                            starts[line - 1], end, line, line, 1, 1, {},
                                                            "codeql-sarif-flow-step", 1.0)))
                relations.append(RelationRecord(RelationKind.CONTAINS, signal.value, step_id.value, True, 1.0))
        shard("priority", "priority", "review-priority", {"job": "job_review_prioritization"}, entities, relations)

    manifest_path = run_root / "data" / "indices" / "manifests" / "secondary.json"
    write_manifest(manifest_path, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=target, indexes=identities)
    document, _ = load_verified_manifest(run_root, manifest_path)
    by_id = {str(item["shard_id"]): item for item in document["indexes"]}
    shards = {key: by_id[shard_id] for key, shard_id in keys.items()}
    return SecondaryFixture(run_root, ShardSet(run_root, document["indexes"]), shards, sources, ids)
