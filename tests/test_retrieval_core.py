from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading

import pytest

from appsec_review.mcp import RetrievalMcpAdapter, TOOLS
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, RetrievalCore, RetrievalLimits, SourceLocation, index_fingerprint,
    sanitize_producer_data, write_manifest,
)
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.retrieval.precomputed import FACT_SCHEMA
from appsec_review.retrieval.core import materialize_attempt_input_manifest


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
        "priority": LogicalIdentity.derive(EntityKind.PRIORITY_ITEM, snapshot, {"native": "auth-priority"}).value,
        "precomputed": LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, snapshot,
                                                {"set": "symbol_links", "native": "auth-links"}).value,
    }
    location = SourceLocation(snapshot, "src/auth.c", source_sha, 0, source.stat().st_size, 1, 3, 1, 1,
                              {"native": "src/auth.c:1"}, "fixture-exact", 1.0)
    index_values: list[IndexIdentity] = []

    def build(name: str, entities: list[EntityRecord], relations: list[RelationRecord],
              gap: str | None = None, shard_id: str = "default", query_set: str | None = None):
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
        builder.add_coverage(query_set or name, "partial" if gap else "complete", gap)
        sha = builder.build()
        index_values.append(IndexIdentity(name, "appsec-review/retrieval-index/2", sha, fingerprint,
                                          path.relative_to(run_root).as_posix(),
                                          {"fixture": name, **({"query_set": query_set} if query_set else {})},
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
    build("priority", [
        EntityRecord(LogicalIdentity.parse(ids["priority"]), "file:src/auth.c", "src/auth.c",
                     "review priority auth", {"scope": "file", "path": "src/auth.c", "rank": 1,
                                               "score": 81.5, "features": {"history_hotspot": 70}}, location),
    ], [])
    build("precomputed", [
        EntityRecord(LogicalIdentity.parse(ids["precomputed"]), "symbol_links:authenticate",
                     "authenticate symbol links", "precomputed symbol links for authenticate",
                     {"schema": FACT_SCHEMA, "query_set": "symbol_links", "subject_identity": ids["symbol"],
                      "subject_path": "src/auth.c", "result": {"calls_out": 0}, "basis": "fixture"}, location),
    ], [], shard_id="symbol-links-fixture", query_set="symbol_links")

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
        "LINKS_INTO", "DEPENDS_ON", "OBSERVED_AT", "DERIVED_FROM", "SUPPORTS", "CONTRADICTS",
        "FLOWS_TO", "SAME_AS", "AFFECTED_BY", "GUARDS")}


def test_standalone_managed_retrieval_keeps_admission_through_manifest_loading(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from appsec_review.config.assurance import parse_review_policy
    from appsec_review.storage.admission import create_admission, consume_admission
    from appsec_review.storage import validation
    from appsec_review.retrieval import index

    runs, ids = _fixture(tmp_path)
    root = runs / RUN_ID
    pointer_path = root / "data/indices/accepted.json"
    pointer = json.loads(pointer_path.read_bytes())
    manifest = json.loads((root / pointer["manifest_path"]).read_bytes())
    target = Path(manifest["target_root"])
    policy = parse_review_policy({
        "mode": "first_party_managed", "project_id": "fixture",
        "approved_first_party_projects": ["fixture"],
        "target_root": str(target), "custody": "application_private_v1",
    })
    configuration = root / "data/configuration"
    atomic_json(configuration / "resolved.json", {"review_policy": policy.view()})
    atomic_json(configuration / "manifest.json",
                {"resolved_sha256": file_sha256(configuration / "resolved.json")})
    handoff_path = root / pointer["handoff_path"]
    handoff = json.loads(handoff_path.read_bytes())
    handoff["source_fingerprint"] = manifest["target_snapshot"]
    handoff["resolving_paths"] = {"attempt": handoff_path.parent.relative_to(root).as_posix()}
    handoff["artifacts"].extend({
        "path": shard["relative_path"], "sha256": shard["sha256"],
        "size_bytes": (root / shard["relative_path"]).stat().st_size,
    } for shard in manifest["indexes"])
    context = SimpleNamespace(run_root=root, target_root=target, review_policy=policy,
                              source_fingerprint=manifest["target_snapshot"])
    handoff["validation_record"] = create_admission(context, handoff)
    atomic_json(handoff_path, handoff)
    atomic_json(pointer_path, {**pointer, "handoff_sha256": file_sha256(handoff_path)})
    digest = validation.file_sha256

    def no_payload_hash(path):
        assert path.suffix != ".sqlite", "standalone constructor lost its authenticated admission"
        return digest(path)

    def no_sqlite_scan(*args, **kwargs):
        pytest.fail("standalone managed constructor rescanned admitted SQLite payloads")

    connect = index.sqlite3.connect
    monkeypatch.setattr(validation, "file_sha256", no_payload_hash)
    monkeypatch.setattr(index.sqlite3, "connect", no_sqlite_scan)
    for _ in range(2):
        core = RetrievalCore(runs, RUN_ID)
        assert core.manifest_sha256 == pointer["manifest_sha256"]
        assert len(core.manifest["indexes"]) == len(manifest["indexes"])
        assert validation.current_validation(root) is None
    monkeypatch.setattr(index.sqlite3, "connect", connect)
    with validation.validation_scope(root):
        assert consume_admission(root, handoff)
        assert core.trace(identity=ids["observation"], depth=2)["results"]
        assert core.find(identity=ids["symbol"])["results"]
    assert validation.current_validation(root) is None


def test_trace_hashes_each_shard_once_per_operation_and_rechecks_next_call(tmp_path, monkeypatch):
    from collections import Counter
    from appsec_review.storage import validation

    runs, ids = _fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    digest = validation.file_sha256
    calls = []

    def counted(path):
        if path.suffix == ".sqlite":
            calls.append(path)
        return digest(path)

    monkeypatch.setattr(validation, "file_sha256", counted)
    shards = {core.run_root / item["relative_path"] for item in core.manifest["indexes"]}
    for repetition in (1, 2):
        trace = core.trace(identity=ids["observation"], depth=2)
        assert max(item["depth"] for item in trace["results"]) == 2
        assert Counter(calls) == {path: repetition for path in shards}
        assert validation.current_validation(core.run_root) is None
    path = core.run_root / core.indexes["source"]["relative_path"]
    with path.open("ab") as stream:
        stream.write(b"changed after the previous operation")
    with pytest.raises(ValueError, match="integrity"):
        core.trace(identity=ids["observation"], depth=2)


def test_three_repeat_trace_work_comparison(tmp_path, monkeypatch):
    from statistics import median
    from time import perf_counter_ns
    from appsec_review.observability import EventLog, PipelineLog
    from appsec_review.observability.spans import operation_span
    from appsec_review.storage import validation

    runs, ids = _fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    events = EventLog(core.run_root / "data/logs/trace-comparison.jsonl",
                      PipelineLog(core.run_root), {"run_id": RUN_ID})
    shards = {core.run_root / item["relative_path"] for item in core.manifest["indexes"]}
    unique_bytes = sum(path.stat().st_size for path in shards)

    def prior_per_open_verification(root, path, expected):
        assert path in shards and root == core.run_root
        actual = file_sha256(path)
        if actual != expected:
            raise ValueError("fixture target evidence integrity mismatch")
        return actual

    samples = []
    expected_result = None
    for repetition in range(3):
        order = ("prior_per_open", "operation_scoped")
        if repetition % 2:
            order = tuple(reversed(order))
        for variant in order:
            with monkeypatch.context() as patch:
                if variant == "prior_per_open":
                    patch.setattr(validation, "verified_digest", prior_per_open_verification)
                started = perf_counter_ns()
                with operation_span(events, "fixture.trace_comparison") as span:
                    result = core.trace(identity=ids["observation"], depth=2)
                elapsed_ms = (perf_counter_ns() - started) / 1_000_000
            comparable = {key: result[key] for key in ("results", "coverage_gaps", "pagination")}
            if expected_result is None:
                expected_result = comparable
            assert comparable == expected_result
            multiplier = 2 if variant == "prior_per_open" else 1
            assert span.counters["target_hash_objects"] == multiplier * len(shards)
            assert span.counters["target_hash_bytes"] == multiplier * unique_bytes
            samples.append({"repetition": repetition + 1, "variant": variant,
                            "order": list(order), "wall_ms": elapsed_ms,
                            "work": dict(span.counters)})
    medians = {
        variant: median(item["wall_ms"] for item in samples if item["variant"] == variant)
        for variant in ("prior_per_open", "operation_scoped")}
    hash_bytes = {
        variant: median(item["work"]["target_hash_bytes"] for item in samples if item["variant"] == variant)
        for variant in medians}
    work_reduction = 100 * (1 - hash_bytes["operation_scoped"] / hash_bytes["prior_per_open"])
    assert work_reduction >= 50
    report = {
        "schema": "appsec-review/fixture-trace-comparison/1",
        "assurance_mode": "strict",
        "baseline": "prior per-open target-shard verification, not a historical end-to-end run",
        "cache_state": "constructor-warmed fixture shards; no cold or CodeQL tool-cache trial",
        "manifest_sha256": core.manifest_sha256,
        "target_snapshot": core.manifest["target_snapshot"],
        "samples": samples, "median_wall_ms": medians,
        "hash_work_reduction_percent": work_reduction,
        "component_wall_reduction_percent": 100 * (
            1 - medians["operation_scoped"] / medians["prior_per_open"]),
        "equal_results_and_gaps": True,
        "p7_overhead_gate": "not_established_component_only",
        "p7_codeql_nonregression_gate": "not_measured",
        "limitations": ["small warm fixture", "only three repetitions", "shared-host timing noise",
                        "no managed, package, cold-work or resume comparison",
                        "no production performance claim"],
    }
    atomic_json(tmp_path / "trace-comparison.json", report)
    print(json.dumps(report, sort_keys=True))


def test_precomputed_and_hotspot_queries_are_bounded_and_report_missing_sets(tmp_path: Path) -> None:
    runs, ids = _fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    hotspot = core.query_hotspots(scope="file", path="src/auth.c", min_score=80)
    assert [item["identity"] for item in hotspot["results"]] == [ids["priority"]]
    assert core.query_hotspots(min_score=90)["results"] == []
    facts = core.query_precomputed(query_set="symbol_links", subject=ids["symbol"], path="src/auth.c")
    assert [item["identity"] for item in facts["results"]] == [ids["precomputed"]]
    absent = core.query_precomputed(query_set="history_context", subject=ids["symbol"])
    assert absent["results"] == [] and \
        "accepted precomputed history_context index is unavailable" in absent["coverage_gaps"]
    for retired in ("arbitrary", "call_graph", "dataflow"):
        with pytest.raises(ValueError, match="precomputed query set"):
            core.query_precomputed(query_set=retired)
    with pytest.raises(ValueError, match="traversal"):
        core.query_hotspots(path="../outside")


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
    page = core.coverage(indexes=("observations",), limit=1)
    assert page["pagination"]["next_cursor"]
    next_page = core.coverage(indexes=("observations",), limit=1,
                              cursor=page["pagination"]["next_cursor"])
    assert next_page["results"][0]["shard_id"] != page["results"][0]["shard_id"]
    source_coverage = core.coverage(indexes=("source",))["results"][0]
    assert source_coverage["entity_kinds"] == {"source_file": 1}
    assert source_coverage["entity_count"] == 1 and source_coverage["relation_count"] == 0
    assert source_coverage["producer"]["fixture"] == "source"


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


def test_attempt_input_manifest_is_pinned_to_exact_parallel_handoffs(tmp_path: Path) -> None:
    runs, _ = _fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    run_root = core.run_root
    base_path = run_root / "data" / "indices" / "manifests" / "fixture.json"
    base_sha = file_sha256(base_path)
    identities = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))})
                  for item in core.manifest["indexes"]]

    handoffs = {}
    for job_id, selected in (("branch_a", identities[:1]), ("branch_b", identities[1:2])):
        manifest = run_root / "data" / "indices" / "manifests" / f"{job_id}.json"
        write_manifest(manifest, run_id=RUN_ID, target_snapshot=core.manifest["target_snapshot"],
                       target_root=core.target_root, indexes=selected,
                       upstream_manifests=({"path": base_path.relative_to(run_root).as_posix(),
                                            "sha256": base_sha},))
        artifact = {"path": manifest.relative_to(run_root).as_posix(),
                    "sha256": file_sha256(manifest), "size_bytes": manifest.stat().st_size}
        handoff = run_root / "data" / "jobs" / job_id / "attempts" / "attempt_0001" / "handoff.json"
        atomic_json(handoff, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
                              "job_id": job_id, "attempt_id": "attempt_0001", "artifacts": [artifact],
                              "outputs": {"publication.publish": {"index_manifest": artifact}},
                              "upstream_handoff_sha256": {}})
        handoffs[job_id] = file_sha256(handoff)

    # A later run-wide publication is intentionally irrelevant to the next attempt's exact inputs.
    accepted = run_root / "data" / "indices" / "accepted.json"
    accepted.write_text("{}\n", encoding="utf-8")
    attempt = run_root / "data" / "jobs" / "consumer" / "attempts" / "attempt_0001"
    attempt.mkdir(parents=True)
    path, sha256 = materialize_attempt_input_manifest(
        run_root=run_root, attempt_root=attempt, run_id=RUN_ID,
        target_snapshot=core.manifest["target_snapshot"], target_root=core.target_root,
        upstream_handoffs=handoffs,
    )
    assert path is not None and sha256 == file_sha256(path)
    merged = json.loads(path.read_text(encoding="utf-8"))
    keys = [(item["name"], item["shard_id"]) for item in merged["indexes"]]
    assert len(keys) == len(set(keys)) == len(core.manifest["indexes"])
    assert {item["path"] for item in merged["upstream_manifests"]} == {
        "data/indices/manifests/branch_a.json", "data/indices/manifests/branch_b.json"}


def test_a_job_that_does_not_read_the_target_inherits_the_snapshot_its_upstream_manifests_share(tmp_path: Path) -> None:
    # The launch binds the snapshot "none" to jobs outside the target set (the inference review is one);
    # the composed manifest must carry the real snapshot or every shard fails the loader's snapshot check.
    runs, _ = _fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    run_root = core.run_root
    base_path = run_root / "data" / "indices" / "manifests" / "fixture.json"
    base_sha = file_sha256(base_path)
    identities = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))})
                  for item in core.manifest["indexes"]]
    handoffs = {}
    for job_id, selected in (("branch_a", identities[:1]), ("branch_b", identities[1:2])):
        manifest = run_root / "data" / "indices" / "manifests" / f"{job_id}.json"
        write_manifest(manifest, run_id=RUN_ID, target_snapshot=core.manifest["target_snapshot"],
                       target_root=core.target_root, indexes=selected,
                       upstream_manifests=({"path": base_path.relative_to(run_root).as_posix(),
                                            "sha256": base_sha},))
        artifact = {"path": manifest.relative_to(run_root).as_posix(),
                    "sha256": file_sha256(manifest), "size_bytes": manifest.stat().st_size}
        handoff = run_root / "data" / "jobs" / job_id / "attempts" / "attempt_0001" / "handoff.json"
        atomic_json(handoff, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
                              "job_id": job_id, "attempt_id": "attempt_0001", "artifacts": [artifact],
                              "outputs": {"publication.publish": {"index_manifest": artifact}},
                              "upstream_handoff_sha256": {}})
        handoffs[job_id] = file_sha256(handoff)
    attempt = run_root / "data" / "jobs" / "consumer" / "attempts" / "attempt_0001"
    attempt.mkdir(parents=True)
    path, _sha256 = materialize_attempt_input_manifest(
        run_root=run_root, attempt_root=attempt, run_id=RUN_ID, target_snapshot="none", target_root=None,
        upstream_handoffs=handoffs)
    assert json.loads(path.read_text(encoding="utf-8"))["target_snapshot"] == core.manifest["target_snapshot"]
    assert RetrievalCore(runs, RUN_ID, manifest_path=path).manifest["target_snapshot"] == core.manifest["target_snapshot"]


def test_attempt_input_manifest_verifies_each_shared_ancestor_once(tmp_path: Path, monkeypatch) -> None:
    # Every job inherits the catalog lineage, so upstream manifests share ancestors. Verification
    # must be linear in distinct manifests, not in paths through the lineage graph (2**depth here).
    runs, _ = _fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    run_root = core.run_root
    manifests = run_root / "data" / "indices" / "manifests"
    base = manifests / "fixture.json"
    identities = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))})
                  for item in core.manifest["indexes"]]

    def reference(path: Path) -> dict[str, str]:
        return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path)}

    depth = 8
    layer = [base]
    for level in range(1, depth + 1):
        upstream = tuple(reference(path) for path in layer)
        layer = []
        for side, selected in (("a", identities[:1]), ("b", identities[1:2])):
            path = manifests / f"level-{level}-{side}.json"
            write_manifest(path, run_id=RUN_ID, target_snapshot=core.manifest["target_snapshot"],
                           target_root=core.target_root, indexes=selected if level == depth else (),
                           upstream_manifests=upstream)
            layer.append(path)
    handoffs = {}
    for job_id, path in zip(("branch_a", "branch_b"), layer):
        artifact = {**reference(path), "size_bytes": path.stat().st_size}
        handoff = run_root / "data" / "jobs" / job_id / "attempts" / "attempt_0001" / "handoff.json"
        atomic_json(handoff, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
                              "job_id": job_id, "attempt_id": "attempt_0001", "artifacts": [artifact],
                              "outputs": {"publication.publish": {"index_manifest": artifact}},
                              "upstream_handoff_sha256": {}})
        handoffs[job_id] = file_sha256(handoff)

    from appsec_review.retrieval import index as index_module
    verifications = []
    original = index_module.swift_enabled_from_run  # read once per full manifest verification

    def counting(run_root_arg):
        verifications.append(run_root_arg)
        return original(run_root_arg)

    monkeypatch.setattr(index_module, "swift_enabled_from_run", counting)
    attempt = run_root / "data" / "jobs" / "consumer" / "attempts" / "attempt_0001"
    attempt.mkdir(parents=True)
    path, sha256 = materialize_attempt_input_manifest(
        run_root=run_root, attempt_root=attempt, run_id=RUN_ID,
        target_snapshot=core.manifest["target_snapshot"], target_root=core.target_root,
        upstream_handoffs=handoffs,
    )
    assert path == attempt / "inputs" / "retrieval-manifest.json" and sha256 == file_sha256(path)
    distinct = 1 + 2 * depth + 1  # the base, two per level, and the merged input manifest
    assert len(verifications) == distinct
    merged = json.loads(path.read_text(encoding="utf-8"))
    assert {(item["name"], item["shard_id"]) for item in merged["indexes"]} >= {
        (item.name, item.shard_id) for item in identities[:2]}


def test_specialized_index_manifest_preserves_upstream_retrieval_lineage(tmp_path: Path) -> None:
    runs, _ = _fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    run_root = core.run_root
    retrieval_manifest = run_root / "data" / "indices" / "manifests" / "fixture.json"
    retrieval_artifact = {
        "path": retrieval_manifest.relative_to(run_root).as_posix(),
        "sha256": file_sha256(retrieval_manifest),
        "size_bytes": retrieval_manifest.stat().st_size,
    }
    producer_handoff = (
        run_root / "data" / "jobs" / "retrieval_producer" / "attempts" / "attempt_0001" / "handoff.json"
    )
    atomic_json(producer_handoff, {
        "schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
        "job_id": "retrieval_producer", "attempt_id": "attempt_0001",
        "artifacts": [retrieval_artifact],
        "outputs": {"publication.publish": {"index_manifest": retrieval_artifact}},
        "upstream_handoff_sha256": {},
    })

    specialized = run_root / "data" / "indexes" / "owasp" / "manifest.json"
    specialized.parent.mkdir(parents=True)
    atomic_json(specialized, {"schema": "appsec-review/owasp-index-manifest/1", "shards": []})
    specialized_artifact = {
        "path": specialized.relative_to(run_root).as_posix(),
        "sha256": file_sha256(specialized),
        "size_bytes": specialized.stat().st_size,
    }
    specialized_handoff = (
        run_root / "data" / "jobs" / "specialized_producer" / "attempts" / "attempt_0001" / "handoff.json"
    )
    atomic_json(specialized_handoff, {
        "schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
        "job_id": "specialized_producer", "attempt_id": "attempt_0001",
        "artifacts": [specialized_artifact],
        "outputs": {"publication.publish": {"index_manifest": specialized_artifact}},
        "upstream_handoff_sha256": {"retrieval_producer": file_sha256(producer_handoff)},
    })

    attempt = run_root / "data" / "jobs" / "consumer" / "attempts" / "attempt_0001"
    attempt.mkdir(parents=True)
    path, sha256 = materialize_attempt_input_manifest(
        run_root=run_root, attempt_root=attempt, run_id=RUN_ID,
        target_snapshot=core.manifest["target_snapshot"], target_root=core.target_root,
        upstream_handoffs={"specialized_producer": file_sha256(specialized_handoff)},
    )

    assert path == retrieval_manifest
    assert sha256 == retrieval_artifact["sha256"]


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
        "query_change_context", "query_hotspots", "query_precomputed", "query_observations",
        "query_dataset_inventory", "query_code_graph", "list_codeql_databases", "query_codeql_neighborhood",
        "query_owasp_workbench"}
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
        ("query_hotspots", {"scope": "file"}),
        ("query_precomputed", {"query_set": "symbol_links", "subject": ids["symbol"]}),
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
    assert len(responses) == 12
    assert all(item["result"]["structuredContent"]["run_id"] == RUN_ID for item in responses)
    records = [json.loads(line) for line in (
        runs / RUN_ID / "data" / "logs" / "pipeline.jsonl").read_text(encoding="utf-8").splitlines()]
    completed = [item for item in records if item["event_type"] == "MCP_TOOL_COMPLETED"]
    assert len(completed) == 14  # two direct adapter calls above plus twelve transport calls
    assert len({item["details"]["mcp_invocation_id"] for item in completed}) == 14
    children = [item for item in records if item["event_type"] == "RETRIEVAL_SUBOP_COMPLETED"]
    assert children and all(item["details"]["parent_invocation_id"] for item in children)


def _builder_fixture(tmp_path: Path) -> tuple[IndexBuilder, str, str]:
    snapshot = "s" * 64
    source = LogicalIdentity.derive(EntityKind.EXECUTABLE, snapshot, {"native": "server"}).value
    action = LogicalIdentity.derive(EntityKind.BUILD_ACTION, snapshot, {"native": "link:1"}).value
    builder = IndexBuilder(tmp_path / "shard.sqlite", name="artifacts", fingerprint="f" * 64,
                           target_snapshot=snapshot)
    return builder, source, action


def test_builder_merges_repeated_relations_deterministically(tmp_path: Path) -> None:
    import sqlite3

    builder, source, action = _builder_fixture(tmp_path)
    weak = RelationRecord(RelationKind.GENERATED_FROM, source, action, False, 0.5, "heuristic", {"n": 1})
    strong = RelationRecord(RelationKind.GENERATED_FROM, source, action, False, 0.75, "heuristic", {"n": 2})
    for relation in (weak, strong, weak):
        builder.add_relation(relation)
    builder.build()
    database = sqlite3.connect(builder.path)
    try:
        assert database.execute("SELECT relation_id, confidence, payload_json FROM relations").fetchall() == [
            (strong.relation_id, 0.75, '{"n": 2}')]
        metadata = dict(database.execute("SELECT key, value FROM metadata"))
    finally:
        database.close()
    assert metadata["relation_duplicates_merged"] == "2"
    assert json.loads(metadata["relation_kind_counts"]) == {RelationKind.GENERATED_FROM.value: 1}


def test_builder_collapses_identical_entities_and_rejects_conflicting_ones(tmp_path: Path) -> None:
    builder, source, _ = _builder_fixture(tmp_path)
    entity = EntityRecord(LogicalIdentity.parse(source), "server", "server", "", {"kind": "elf"})
    builder.add_entity(entity)
    builder.add_entity(entity)
    builder.build()
    conflicting, _, _ = _builder_fixture(tmp_path / "conflict")
    conflicting.add_entity(entity)
    conflicting.add_entity(EntityRecord(LogicalIdentity.parse(source), "server", "server", "", {"kind": "pe"}))
    with pytest.raises(ValueError, match="conflicting entities"):
        conflicting.build()
    assert not conflicting.path.exists()


def test_builder_reuses_identical_shard_without_replacing_it(tmp_path: Path) -> None:
    builder, source, _ = _builder_fixture(tmp_path)
    builder.add_entity(EntityRecord(LogicalIdentity.parse(source), "server", "server", "", {"kind": "elf"}))
    builder.add_coverage("artifacts", "partial", "missing symbols")
    digest = builder.build()
    before = builder.path.stat()
    contents = builder.path.read_bytes()

    assert builder.build() == digest
    assert builder.path.read_bytes() == contents
    assert builder.path.stat().st_ino == before.st_ino
    assert builder.path.stat().st_mtime_ns == before.st_mtime_ns
    assert list(tmp_path.iterdir()) == [builder.path]


@pytest.mark.parametrize("change", ["entity", "relation", "coverage", "fingerprint", "snapshot", "corrupt"])
def test_builder_rejects_different_or_corrupt_existing_shard(tmp_path: Path, change: str) -> None:
    builder, source, action = _builder_fixture(tmp_path)
    builder.build()
    if change == "entity":
        builder.add_entity(EntityRecord(LogicalIdentity.parse(source), "server", "server", "", {}))
    elif change == "relation":
        builder.add_relation(RelationRecord(RelationKind.GENERATED_FROM, source, action, True, 1.0))
    elif change == "coverage":
        builder.add_coverage("artifacts", "unavailable", "missing")
    elif change == "fingerprint":
        builder.fingerprint = "e" * 64
    elif change == "snapshot":
        builder.target_snapshot = "t" * 64
    else:
        builder.path.write_bytes(b"corrupt")
    before = builder.path.read_bytes()
    with pytest.raises(ValueError, match="immutable index shard"):
        builder.build()
    assert builder.path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [builder.path]


@pytest.mark.parametrize("dangling", [False, True])
def test_builder_rejects_existing_symlink(tmp_path: Path, dangling: bool) -> None:
    builder, _, _ = _builder_fixture(tmp_path)
    builder.build()
    target = tmp_path / "other.sqlite"
    builder.path.rename(target)
    try:
        builder.path.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    contents = target.read_bytes()
    if dangling:
        target.unlink()
    with pytest.raises(ValueError, match="immutable index shard"):
        builder.build()
    assert builder.path.is_symlink()
    if not dangling:
        assert target.read_bytes() == contents


@pytest.mark.parametrize("conflicting", [False, True])
def test_builder_concurrent_publication_never_overwrites(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, conflicting: bool) -> None:
    builders = [_builder_fixture(tmp_path)[0] for _ in range(2)]
    if conflicting:
        builders[1].add_coverage("artifacts", "partial", "missing symbols")
    barrier = threading.Barrier(2)
    real_link = os.link

    def publish(source, destination):
        barrier.wait(timeout=10)
        return real_link(source, destination)

    monkeypatch.setattr("appsec_review.retrieval.index.os.link", publish)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(builder.build) for builder in builders]
        results, errors = [], []
        for future in futures:
            try:
                results.append(future.result())
            except ValueError as exc:
                errors.append(str(exc))
    assert len(errors) == int(conflicting)
    assert all("immutable index shard" in error for error in errors)
    assert set(results) == {file_sha256(builders[0].path)}
    assert list(tmp_path.iterdir()) == [builders[0].path]
    with sqlite3.connect(builders[0].path) as database:
        assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)


def test_builder_removes_only_its_own_temporary_files_after_failure(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    builder, _, _ = _builder_fixture(tmp_path)
    abandoned = tmp_path / "shard.sqlite.building"
    abandoned.write_bytes(b"another writer")
    real_connect = sqlite3.connect

    def fail_connection(path):
        Path(path).write_bytes(b"incomplete database")
        raise sqlite3.OperationalError("injected connection failure")

    monkeypatch.setattr("appsec_review.retrieval.index.sqlite3.connect", fail_connection)
    with pytest.raises(sqlite3.OperationalError, match="injected"):
        builder.build()
    assert not builder.path.exists()
    assert list(tmp_path.iterdir()) == [abandoned]
    assert abandoned.read_bytes() == b"another writer"
    monkeypatch.setattr("appsec_review.retrieval.index.sqlite3.connect", real_connect)
    assert builder.build() == file_sha256(builder.path)


def test_builder_does_not_publish_after_link_failure(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    builder, _, _ = _builder_fixture(tmp_path)

    def fail_publish(source, destination):
        raise OSError("injected publication failure")

    monkeypatch.setattr("appsec_review.retrieval.index.os.link", fail_publish)
    with pytest.raises(OSError, match="injected publication"):
        builder.build()
    assert not list(tmp_path.iterdir())
