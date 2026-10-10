from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from appsec_review.mcp import RetrievalMcpAdapter, TOOLS
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, RetrievalCore, RetrievalLimits, SourceLocation, index_fingerprint,
    sanitize_producer_data, write_manifest,
)
from appsec_review.storage import atomic_json, file_sha256


RUN_ID = "2026-10-08-0001"


def _fixture(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    runs = tmp_path / "runs"
    run_root = runs / RUN_ID
    (run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001").mkdir(parents=True)
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    source = target / "src" / "auth.c"
    source.write_text("int authenticate(char *token) {\n  return token != 0;\n}\n", encoding="utf-8")
    source_sha = file_sha256(source)
    snapshot = "target-sha256:" + "1" * 64

    ids = {
        "file": LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot,
                                       {"path": "src/auth.c", "sha256": source_sha}).value,
        "symbol": LogicalIdentity.derive(EntityKind.SYMBOL, snapshot,
                                         {"path": "src/auth.c", "name": "authenticate"}).value,
        "ast": LogicalIdentity.derive(EntityKind.AST_NODE, snapshot, {"native": "function:1"}).value,
        "compile": LogicalIdentity.derive(EntityKind.COMPILE_UNIT, snapshot, {"native": "cc:1"}).value,
        "object": LogicalIdentity.derive(EntityKind.OBJECT_FILE, snapshot, {"native": "auth.o"}).value,
        "executable": LogicalIdentity.derive(EntityKind.EXECUTABLE, snapshot, {"native": "server"}).value,
        "observation": LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"native": "semgrep:1"}).value,
        "codeql": LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"native": "codeql:1"}).value,
        "artifact": LogicalIdentity.derive(EntityKind.EVIDENCE_ARTIFACT, snapshot, {"native": "sarif:1"}).value,
        "fact": LogicalIdentity.derive(EntityKind.IR_ENTITY, snapshot, {"native": "nonnull:1"}).value,
    }
    location = SourceLocation(snapshot, "src/auth.c", source_sha, 0, source.stat().st_size, 1, 3, 1, 1,
                              {"native": "src/auth.c:1"}, "fixture-exact", 1.0)
    index_values: list[IndexIdentity] = []

    def build(name: str, entities: list[EntityRecord], relations: list[RelationRecord],
              gap: str | None = None, shard_id: str = "default"):
        fingerprint = index_fingerprint(
            name=name, target_snapshot=snapshot, producer_artifacts=[{"sha256": "a" * 64}],
            tool_identity={"tool": "fixture", "name": name}, parser_identity="fixture-parser/1",
            normalizer_identity="fixture-normalizer/1", mapping_identity="fixture-mapping/1",
        )
        path = run_root / "data" / "indices" / name / shard_id / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name=name, fingerprint=fingerprint, target_snapshot=snapshot,
                               shard_id=shard_id)
        for entity in entities:
            builder.add_entity(entity)
        for relation in relations:
            builder.add_relation(relation)
        builder.add_coverage(name, "partial" if gap else "complete", gap)
        sha = builder.build()
        index_values.append(IndexIdentity(name, "appsec-review/retrieval-index/2", sha, fingerprint,
                                          path.relative_to(run_root).as_posix(), {"fixture": name},
                                          (gap,) if gap else (), shard_id))

    build("source", [EntityRecord(LogicalIdentity.parse(ids["file"]), "src/auth.c", "src/auth.c",
                                  source.read_text(encoding="utf-8"), {"language": "C"}, location)], [])
    build("analysis", [
        EntityRecord(LogicalIdentity.parse(ids["symbol"]), "authenticate", "authenticate",
                     "function authenticate validates a token", {"role": "definition"}, location),
        EntityRecord(LogicalIdentity.parse(ids["ast"]), "function:1", "function_definition",
                     "authenticate AST", {"node_type": "function_definition"}, location),
        EntityRecord(LogicalIdentity.parse(ids["fact"]), "nonnull:1", "nonnull data-flow fact",
                     "token checked nonnull", {"fact": "nonnull"}, location),
    ], [
        RelationRecord(RelationKind.DEFINES, ids["ast"], ids["symbol"], True, 1.0),
        RelationRecord(RelationKind.REFERENCES, ids["fact"], ids["symbol"], False, 0.6,
                       "debug mapping yielded two same-name candidates"),
    ])
    build("build", [
        EntityRecord(LogicalIdentity.parse(ids["compile"]), "cc:1", "compile auth.c", "cc -c auth.c", {}),
        EntityRecord(LogicalIdentity.parse(ids["object"]), "auth.o", "auth.o", "object auth", {}),
        EntityRecord(LogicalIdentity.parse(ids["executable"]), "server", "server", "linked server", {}),
    ], [
        RelationRecord(RelationKind.COMPILES_TO, ids["compile"], ids["object"], True, 1.0),
        RelationRecord(RelationKind.LINKS_INTO, ids["object"], ids["executable"], True, 1.0),
    ], "link map was unavailable")
    build("observations", [
        EntityRecord(LogicalIdentity.parse(ids["observation"]), "semgrep:1", "token-check",
                     "verysecretsearch token validation observation", {"rule": "token-check"}, location),
        EntityRecord(LogicalIdentity.parse(ids["artifact"]), "sarif:1", "semgrep SARIF",
                     "semgrep result artifact", {"sha256": "b" * 64}),
    ], [
        RelationRecord(RelationKind.OBSERVED_AT, ids["observation"], ids["file"], True, 1.0),
        RelationRecord(RelationKind.DERIVED_FROM, ids["observation"], ids["artifact"], True, 1.0),
        RelationRecord(RelationKind.SUPPORTS, ids["observation"], ids["fact"], True, 0.95),
    ], shard_id="semgrep")
    build("observations", [], [], "gitleaks scanner was unavailable", shard_id="gitleaks")
    build("observations", [
        EntityRecord(LogicalIdentity.parse(ids["codeql"]), "codeql:1", "cpp/unsafe-strcat",
                     "unsafe string concatenation", {
                         "producer": "codeql", "language": "cpp", "source_languages": ["C", "C++"],
                         "scope_id": "cpp-native-main", "build_unit_id": "native-main",
                         "rule_id": "cpp/unsafe-strcat", "producer_level": "error",
                     }, location),
    ], [], shard_id="codeql-cpp-cpp-native-main")

    manifest_path = run_root / "data" / "indices" / "manifests" / "fixture.json"
    write_manifest(manifest_path, run_id=RUN_ID, target_snapshot=snapshot, target_root=target, indexes=index_values)
    manifest_artifact = {"path": manifest_path.relative_to(run_root).as_posix(),
                         "sha256": file_sha256(manifest_path), "size_bytes": manifest_path.stat().st_size}
    handoff_path = run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001" / "handoff.json"
    atomic_json(handoff_path, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
                               "job_id": "fixture", "attempt_id": "attempt_0001",
                               "artifacts": [manifest_artifact], "outputs": {}})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff_path.relative_to(run_root).as_posix(),
        "handoff_sha256": file_sha256(handoff_path), "manifest_path": manifest_artifact["path"],
        "manifest_sha256": manifest_artifact["sha256"],
    })
    return runs, ids


def test_identity_and_location_contracts_reject_unsafe_or_ambiguous_values() -> None:
    for kind in EntityKind:
        assert LogicalIdentity.parse(LogicalIdentity.derive(kind, "snapshot", {"id": kind.value}).value).kind == kind
    with pytest.raises(ValueError, match="traversal"):
        SourceLocation("snapshot", "../secret", "0" * 64, 0, 1, 1, 1, 1, 1, {}, "x", 1.0)
    with pytest.raises(ValueError, match="ambiguity"):
        RelationRecord(RelationKind.CALLS,
                       LogicalIdentity.derive(EntityKind.SYMBOL, "s", {"id": 1}).value,
                       LogicalIdentity.derive(EntityKind.SYMBOL, "s", {"id": 2}).value,
                       False, 0.5)
    sanitized = sanitize_producer_data({"environment": {"API_TOKEN": "do-not-return"},
                                        "argv": ["cc", "--password", "do-not-return", "auth.c"]})
    assert "do-not-return" not in json.dumps(sanitized) and sanitized["environment"]["API_TOKEN"] == "<redacted>"
    assert set(RelationKind) == {RelationKind(value) for value in (
        "DECLARES", "DEFINES", "REFERENCES", "CALLS", "CONTAINS", "GENERATED_FROM", "COMPILES_TO",
        "LINKS_INTO", "DEPENDS_ON", "OBSERVED_AT", "DERIVED_FROM", "SUPPORTS", "CONTRADICTS")}


def test_search_filters_pagination_tamper_and_explicit_gaps(tmp_path: Path) -> None:
    runs, _ = _fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    page = core.search(query="authenticate", indexes=("analysis",), kinds=("symbol",), limit=1)
    assert page["results"][0]["kind"] == "symbol"
    first = core.search(query="token", limit=1)
    assert first["pagination"]["next_cursor"]
    second = core.search(query="token", limit=1, cursor=first["pagination"]["next_cursor"])
    assert second["results"] != first["results"]
    with pytest.raises(ValueError, match="tampered"):
        core.search(query="token", limit=1, cursor=first["pagination"]["next_cursor"] + "x")
    with pytest.raises(ValueError, match="traversal"):
        core.find(path="../outside")
    missing = core.search(query="anything", indexes=("compiled",))
    assert missing["results"] == [] and "compiled index is unavailable" in missing["coverage_gaps"]
    coverage = core.coverage(indexes=("observations",))
    assert {item["shard_id"] for item in coverage["results"]} == {
        "codeql-cpp-cpp-native-main", "gitleaks", "semgrep"}
    assert any("observations/gitleaks" in gap for gap in coverage["coverage_gaps"])


def test_manifest_rejects_duplicate_composite_shard_identity(tmp_path: Path) -> None:
    runs, _ = _fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    item = next(value for value in core.manifest["indexes"]
                if value["name"] == "observations" and value["shard_id"] == "semgrep")
    identity = IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))})
    with pytest.raises(ValueError, match="duplicate index shard"):
        write_manifest(core.run_root / "data" / "indices" / "manifests" / "duplicate.json",
                       run_id=RUN_ID, target_snapshot=core.manifest["target_snapshot"],
                       target_root=core.target_root, indexes=(identity, identity))


def test_relationships_excerpt_integrity_and_evidence_resolution(tmp_path: Path) -> None:
    runs, ids = _fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    trace = core.trace(identity=ids["observation"], depth=2)
    assert {item["kind"] for item in trace["results"]} >= {"OBSERVED_AT", "DERIVED_FROM", "SUPPORTS"}
    ambiguous = core.trace(identity=ids["fact"], depth=1)
    assert any("ambiguous" in gap for gap in ambiguous["coverage_gaps"])
    assert any(not item["exact"] for item in ambiguous["results"])
    with pytest.raises(ValueError, match="bound"):
        core.trace(identity=ids["fact"], depth=9)
    resolved = core.resolve_evidence(identity=ids["observation"])
    assert resolved["results"][0]["entity"]["identity"] == ids["observation"]
    excerpt = core.read_excerpt(identity=ids["symbol"], context_lines=1)
    assert "authenticate" in excerpt["results"][0]["excerpt"]
    (tmp_path / "target" / "src" / "auth.c").write_text("changed\n", encoding="utf-8")
    stale = core.read_excerpt(identity=ids["symbol"])
    assert stale["results"] == [] and "target source changed after indexing" in stale["coverage_gaps"]


def test_integrity_run_isolation_and_manifest_pin(tmp_path: Path) -> None:
    runs, _ = _fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    with pytest.raises(ValueError, match="pin"):
        RetrievalCore(runs, RUN_ID, manifest_sha256="0" * 64)
    with pytest.raises(ValueError, match="run id"):
        RetrievalCore(runs, "../outside")
    source_path = core.run_root / core.indexes["source"]["relative_path"]
    with source_path.open("ab") as stream:
        stream.write(b"tamper")
    with pytest.raises(ValueError, match="integrity"):
        RetrievalCore(runs, RUN_ID)


def test_limits_timeout_audit_redaction_and_concurrent_reads(tmp_path: Path) -> None:
    runs, _ = _fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID, limits=RetrievalLimits(max_response_bytes=1400))
    response = core.search(query="token", limit=100)
    assert len(json.dumps(response).encode()) <= 1600
    log_text = (runs / RUN_ID / "data" / "logs" / "pipeline.jsonl").read_text(encoding="utf-8")
    assert "verysecretsearch" not in log_text and "query_sha256" in log_text
    concurrent = RetrievalCore(runs, RUN_ID)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: concurrent.find(kind="symbol"), range(24)))
    assert all(item["results"][0]["name"] == "authenticate" for item in results)

    ticks = iter((0.0, 3.0, 3.0, 3.0, 3.0))
    timed = RetrievalCore(runs, RUN_ID, limits=RetrievalLimits(timeout_ms=1),
                          clock=lambda: next(ticks, 3.0))
    timeout = timed.coverage()
    assert timeout["truncated"] and "execution-time budget" in timeout["coverage_gaps"][0]


def test_mcp_core_parity_schema_serialization_and_live_stdio_smoke(tmp_path: Path) -> None:
    runs, ids = _fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    adapter = RetrievalMcpAdapter(core)
    assert {item["name"] for item in TOOLS} == {
        "search", "find", "read_excerpt", "trace", "resolve_evidence", "coverage",
        "query_artifacts", "query_build_security", "query_ci_configuration", "query_codeql",
        "query_design_artifacts", "query_owasp_workbench"}
    codeql = adapter.call("query_codeql", {"language": "cpp", "source_language": "C++",
                                            "build_unit": "native-main", "path": "src/auth.c"})
    assert [item["name"] for item in codeql["results"]] == ["cpp/unsafe-strcat"]
    via_mcp = adapter.call("find", {"identity": ids["symbol"]})
    direct = core.find(identity=ids["symbol"])
    assert {key: value for key, value in via_mcp.items() if key != "duration_ms"} == {
        key: value for key, value in direct.items() if key != "duration_ms"}
    requests = [
        ("search", {"query": "authenticate"}), ("find", {"identity": ids["symbol"]}),
        ("read_excerpt", {"identity": ids["symbol"]}), ("trace", {"identity": ids["observation"]}),
        ("resolve_evidence", {"identity": ids["observation"]}), ("coverage", {}),
        ("query_artifacts", {}), ("query_build_security", {}), ("query_codeql", {"language": "cpp"}),
        ("query_owasp_workbench", {}),
    ]
    process = subprocess.Popen(
        [sys.executable, "-m", "appsec_review.mcp.stdio", "--runs-dir", str(runs), "--run-id", RUN_ID],
        cwd=Path(__file__).parents[1], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
    )
    payload = "".join(json.dumps({"jsonrpc": "2.0", "id": number, "method": "tools/call",
                                   "params": {"name": name, "arguments": arguments}}) + "\n"
                      for number, (name, arguments) in enumerate(requests, 1))
    stdout, stderr = process.communicate(payload, timeout=20)
    assert process.returncode == 0, stderr
    responses = [json.loads(line) for line in stdout.splitlines()]
    assert len(responses) == 10
    assert all(item["result"]["structuredContent"]["run_id"] == RUN_ID for item in responses)
    records = [json.loads(line) for line in (
        runs / RUN_ID / "data" / "logs" / "pipeline.jsonl").read_text(encoding="utf-8").splitlines()]
    completed = [item for item in records if item["event_type"] == "MCP_TOOL_COMPLETED"]
    assert len(completed) == 12  # two direct adapter calls above plus ten transport calls
    assert len({item["details"]["mcp_invocation_id"] for item in completed}) == 12
    children = [item for item in records if item["event_type"] == "RETRIEVAL_SUBOP_COMPLETED"]
    assert children and all(item["details"]["parent_invocation_id"] for item in children)
