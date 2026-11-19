"""Review follow-up: operation ownership and normalized-coordinate uncertainty."""
from pathlib import Path
import json

import pytest

from appsec_review.graph.contract import Family
from appsec_review.jobs.job_codeql_analysis.sarif import normalize_sarif
from appsec_review.jobs.job_review_prioritization import build_job
from appsec_review.jobs.job_review_prioritization.composite import COMPOSITE_SCORE_IDENTITY, score_normalization
from appsec_review.jobs.job_review_prioritization.dependencies import GraphBuilder
from appsec_review.jobs.job_review_prioritization.inputs import read_json
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation, write_manifest,
)
from appsec_review.review.lead_families import LeadCollection
from appsec_review.review.packages import PackageSettings, rank_hunt_candidates
from appsec_review.review.scope import accept_manifest
from appsec_review.storage import file_sha256
from tests.review.test_graph_admissibility import graph_entity, results_for
from tests.unit.job_review_prioritization.test_contract import (
    BASE_CONFIG, JOB_ID, _artifact_ref, _job_context, _publish_handoff, _seed_upstream_run,
)
from tests.unit.job_review_prioritization.test_signals_and_rewiring import _sources


def _identity(run, shard, name, job, fingerprint):
    return IndexIdentity(name, "appsec-review/retrieval-index/2", file_sha256(shard), fingerprint,
                         shard.relative_to(run).as_posix(), {"job": job}, (), name)


@pytest.mark.parametrize("case", ["containing-function", "same-line-siblings", "nested-owner", "ambiguous-owner"])
def test_operation_rank_reads_only_its_exact_function_route(tmp_path: Path, case: str) -> None:
    run, target = tmp_path / "run", tmp_path / "target"
    target.mkdir()
    data = b"x\n" * 30 if case == "containing-function" else b"x" * 100 + b"\n"
    (target / "source.c").write_bytes(data)
    sha, snapshot = file_sha256(target / "source.c"), "a" * 64
    bounds = [(18, 40, 10, 20)] if case == "containing-function" else [
        (0, 40, 1, 1), (50, 90, 1, 1)]
    if case == "ambiguous-owner":
        bounds = [(0, 90, 1, 1), (0, 90, 1, 1)]
    if case == "nested-owner":
        bounds = [(0, 100, 1, 1), (50, 90, 1, 1)]
    point = (28, 29, 15, 15) if case == "containing-function" else (60, 65, 1, 1)

    def location(span):
        return SourceLocation(snapshot, "source.c", sha, *span, 1, 1, {}, "exact", 1.0)

    source_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot, {"path": "source.c"})
    component_id = LogicalIdentity.derive(EntityKind.COMPONENT, snapshot, {"component": "root"})
    rows = {
        "source": [EntityRecord(source_id, "source.c", "source.c", "", {"language": "C"},
                               location((0, len(data), 1, len(data.splitlines()))))],
        "components": [EntityRecord(component_id, "root", "root", "", {"root": "."}, None)],
        "priority": [], "graph": [],
    }
    normalization = score_normalization(BASE_CONFIG.job(JOB_ID).settings)
    route_ids = []
    for number, span in enumerate(bounds):
        identity = LogicalIdentity.derive(EntityKind.REVIEW_SIGNAL, snapshot, {"function": number})
        route_ids.append(identity.value)
        raw = 1.0 if number == 0 else .5
        rows["priority"].append(EntityRecord(identity, str(number), str(number), "", {
            "routing_kind": "hunt_candidate", "routing_ordinal": number, "scope": "function",
            "function_id": f"fn-{number}", "path": "source.c",
            "start_byte": span[0], "end_byte": span[1], "start_line": span[2], "end_line": span[3],
            "run_id": run.name, "target_snapshot": snapshot, "authority": "provisional_navigation_lead",
            "score_identity": COMPOSITE_SCORE_IDENTITY, "score_normalization": normalization,
            "score": raw / normalization["maximum"], "raw_score": raw, "base_score": raw,
        }, location(span)))
    rows["graph"].append(graph_entity(
        Family.SINK_SITE, {"path": "source.c", "start_byte": point[0], "end_byte": point[1],
                           "sink_class": "memory_write", "argument_index": 0},
        results_for(Family.SINK_SITE), location(point), snapshot=snapshot,
        component_id="root", build_unit_id=None))
    identities = []
    for name, records in rows.items():
        path = run / f"data/indices/{name}/test.sqlite"
        builder = IndexBuilder(path, name=name, fingerprint=sha, target_snapshot=snapshot, shard_id=name)
        for record in records:
            builder.add_entity(record)
        builder.build()
        job = (JOB_ID if name == "priority" else "job_code_graph_index" if name == "graph"
               else "job_target_catalog")
        identities.append(_identity(run, path, name, job, sha))
    manifest = run / "data/indices/manifests/test.json"
    write_manifest(manifest, run_id=run.name, target_snapshot=snapshot, target_root=target, indexes=identities)
    scope = accept_manifest(run, manifest_path=manifest, manifest_sha256=file_sha256(manifest))
    candidates = rank_hunt_candidates(scope, PackageSettings(), LeadCollection((), (), {}, None))
    operation, = [ranked.unit for ranked in candidates.ranked if ranked.unit.operation is not None]
    routes = {entry.id for entry in operation.context if entry.id in route_ids}
    expected = ({route_ids[0]} if case == "containing-function" else {route_ids[1]}
                if case in {"same-line-siblings", "nested-owner"} else set())
    assert routes == expected
    lps = next(signal.value for signal in operation.signals if signal.signal == "lps")
    expected_raw = 1.0 if case == "containing-function" else .5
    assert lps == (round(expected_raw / normalization["maximum"] * 1000) if expected else None)


def _normalized_run(tmp_path: Path, *, include_exact: bool, semgrep: bool = False):
    data = b"void a(){ foo(); } void b(){ bar(); }\n"
    target = tmp_path / "target"
    target.mkdir()
    (target / "same.c").write_bytes(data)
    sha = file_sha256(target / "same.c")
    run = tmp_path / "runs/2026-01-01-0001"
    ast = []

    def node(kind, start, end, ordinal, field=None):
        ast.append({
            "path": "same.c", "file_sha256": sha, "grammar_native_type": kind,
            "named": True, "field": field, "error": False, "missing": False,
            "location": {"producer_location": {"grammar": "c", "ordinal_path": ordinal},
                         "start_byte": start, "end_byte": end, "start_line": 1, "end_line": 1,
                         "start_column": start + 1, "end_column": end + 1}})

    node("translation_unit", 0, len(data), [])
    for number, name in enumerate((b"a", b"b")):
        start = 0 if number == 0 else data.index(b"void b")
        end = data.index(b"}", start) + 1
        node("function_definition", start, end, [number])
        pos = data.index(name + b"()", start)
        node("identifier", pos, pos + 1, [number, 0], "declarator")
        node("compound_statement", data.index(b"{", start), end, [number, 1], "body")
    ast_path = run / "fixture/ast.jsonl"
    ast_path.parent.mkdir(parents=True)
    ast_path.write_text("\n".join(json.dumps(row) for row in ast) + "\n")
    run, target, snapshot, pins = _seed_upstream_run(
        tmp_path, golden_paths=(), extra_catalog_files=[{
            "path": "same.c", "sha256": sha, "size_bytes": len(data), "language": "C", "generated": False,
            "delivery_role": "production", "first_party": True, "vendored": False}],
        extra_dispositions=[{"language": "C", "terminal_status": "SUCCEEDED", "gaps": [],
                             "artifact": _artifact_ref(run, ast_path)}])

    def step(column=None):
        region = {"startLine": 1, "endLine": 1}
        if column is not None:
            region.update(startColumn=column, endColumn=column + 1)
        return {"location": {"physicalLocation": {
            "artifactLocation": {"uri": "same.c"}, "region": region}}}

    flows = [[step(), step()]]
    if include_exact:
        flows.append([step(data.index(b"foo") + 1), step(data.index(b"foo") + 2)])
    sarif = {"version": "2.1.0", "runs": [{"columnKind": "utf16CodeUnits", "results": [
        {"ruleId": f"cpp/flow-{number}", "locations": [steps[0]["location"]],
         "codeFlows": [{"threadFlows": [{"locations": steps}]}]} for number, steps in enumerate(flows)]}]}
    observations, gaps = normalize_sarif(
        sarif, files=[{"path": "same.c", "sha256": sha}], root=".", query_identity="q", result_limit=10)
    assert not gaps
    native_location = observations[0]["payload"]["flows"][0]["location"]
    assert native_location["start_column"] == 1
    assert "startColumn" not in native_location["producer_location"]["region"]
    shard = run / "data/indices/observations/codeql.sqlite"
    builder = IndexBuilder(shard, name="observations", fingerprint=sha, target_snapshot=snapshot,
                           shard_id="observations")
    for row in observations:
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"native": row["native_id"]})
        builder.add_entity(EntityRecord(identity, row["native_id"], row["rule_id"], "", row["payload"], None))
    builder.build()
    manifest = run / "fixture/codeql-manifest.json"
    write_manifest(manifest, run_id=run.name, target_snapshot=snapshot, target_root=target,
                   indexes=[_identity(run, shard, "observations", "job_codeql_analysis", sha)])
    summary = _artifact_ref(run, run / "fixture/codeql-summary.json", {
        "scopes": [{"scope_id": "c", "language": "cpp", "root": ".", "query_profile": "security",
                    "terminal_status": "SUCCEEDED", "gaps": []}]})
    pins["job_codeql_analysis"] = _publish_handoff(run, "job_codeql_analysis", {
        "acceptance.publish_handoff": {"artifact": summary, "index_manifest": _artifact_ref(run, manifest)}})
    if semgrep:
        shard = run / "data/indices/observations/semgrep.sqlite"
        builder = IndexBuilder(shard, name="observations", fingerprint=sha, target_snapshot=snapshot,
                               shard_id="observations")
        for number, columns in enumerate(({}, {"start_column": data.index(b"foo") + 1})):
            identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"semgrep": number})
            builder.add_entity(EntityRecord(identity, str(number), "sink", "", {
                "native_rule_id": "appsec-review.review-signal.sink.exec",
                "location": {"path": "same.c", "source_sha256": sha, "start_line": 1, **columns}}, None))
        builder.build()
        manifest = run / "fixture/semgrep-manifest.json"
        write_manifest(manifest, run_id=run.name, target_snapshot=snapshot, target_root=target, indexes=[
            IndexIdentity("observations", "appsec-review/retrieval-index/2", file_sha256(shard), sha,
                          shard.relative_to(run).as_posix(), {
                              "job": "job_evidence_collection", "producer": "tool-semgrep"}, (), "observations")])
        summary = _artifact_ref(run, run / "fixture/semgrep-summary.json", {
            "schema": "appsec-review/evidence-collection-handoff/1", "target_snapshot": snapshot,
            "target_fingerprint": snapshot,
            "dispositions": [{"tool_id": "tool-semgrep", "terminal_status": "SUCCEEDED", "gaps": []}]})
        pins["job_evidence_collection"] = _publish_handoff(run, "job_evidence_collection", {
            "evidence_publication.publish_handoff": {
                "artifact": summary, "index_manifest": _artifact_ref(run, manifest)}})
    context = _job_context(tmp_path, run, target, snapshot, pins, settings_override={
        "sources": _sources("codeql", *(("semgrep",) if semgrep else ())),
        "index": {**BASE_CONFIG.job(JOB_ID).settings["index"], "file_top_count": 1, "function_top_count": 2}})
    result = build_job().execute(context)
    assert not result["failed_units"]
    return run, result


def test_real_sarif_column_defaults_never_become_exact_function_positions(tmp_path: Path) -> None:
    run, result = _normalized_run(tmp_path, include_exact=False)
    document = read_json(run, result["outputs"]["extract.semantic_evidence"]["artifact"])
    path, = document["semantic_paths"]
    assert path["source_function"] is None and path["sink_function"] is None
    assert path["flow_functions"] == []
    assert path["source"]["start_column"] is None
    assert path["source"]["producer_location"]["region"] == {"startLine": 1, "endLine": 1}
    assert path["source"]["column_encoding"] is None  # the real normalizer did not retain run.columnKind


@pytest.mark.parametrize("include_exact", [False, True], ids=["unobserved", "positive-lower-bound"])
def test_ambiguous_function_coverage_survives_scoring_and_publication(tmp_path: Path, include_exact: bool) -> None:
    run, result = _normalized_run(tmp_path, include_exact=include_exact)
    ranking = read_json(run, result["outputs"]["prioritize.score"]["artifact"])
    functions = {item["name"]: item for item in ranking["functions"]}
    assert functions["a"]["features"]["semantic_path"] == (1 if include_exact else None)
    assert functions["b"]["features"]["semantic_path"] is None
    for item in functions.values():
        assert item["semantic_path_lower_bound"] is True
        assert any("function_attribution_unavailable" in gap for gap in item["gaps"])
    manifest = result["outputs"]["publish.publish_handoff"]["index_manifest"]
    scope = accept_manifest(run, manifest_path=run / manifest["path"], manifest_sha256=manifest["sha256"])
    indexed = [row["payload"] for row in scope.store.entities(
        scope.producer("review_prioritization").shards, kinds=("priority_item",))
        if row["payload"]["scope"] == "function"]
    assert len(indexed) == 2
    for item in indexed:
        assert item["features"]["semantic_path"] == functions[item["name"]]["features"]["semantic_path"]
        assert item["semantic_path_lower_bound"] and item["gaps"] == functions[item["name"]]["gaps"]
    assert ranking["files"][0]["features"]["semantic_path"] == (2 if include_exact else 1)


def test_ambiguous_semgrep_owner_keeps_unknown_and_positive_count_qualifications(tmp_path: Path) -> None:
    run, result = _normalized_run(tmp_path, include_exact=True, semgrep=True)
    ranking = read_json(run, result["outputs"]["prioritize.score"]["artifact"])
    functions = {item["name"]: item for item in ranking["functions"]}
    assert functions["a"]["features"]["sink"] == 1
    assert functions["b"]["features"]["sink"] is None
    assert "sink" in functions["b"]["missing_features"]
    for item in functions.values():
        assert any("function_attribution_unavailable:semgrep:sink" in gap for gap in item["gaps"])
    assert ranking["files"][0]["features"]["sink"] == 2


def test_component_instability_is_unknown_when_import_work_is_omitted() -> None:
    files = {
        "a.c": {"grammar": "c", "imports": [{"kind": "include", "specifier": "b.h", "line": 1}]},
        "b.h": {"grammar": "c", "imports": [{"kind": "include", "specifier": "c.h", "line": 1}]},
        "c.h": {"grammar": "c", "imports": []},
    }
    graph = GraphBuilder(files, files, lambda _: b"", min_confidence=.8, max_records=1).build(
        {path: path for path in files})
    assert graph["components"]["a.c"]["efferent_coupling"] == 1
    assert graph["components"]["b.h"]["afferent_coupling"] == 1
    assert graph["omitted_import_count"] == 1
    for value in graph["components"].values():
        assert value["coupling_lower_bound"]
        assert value["instability"] is None
    complete = GraphBuilder(files, files, lambda _: b"", min_confidence=.8, max_records=5).build(
        {path: path for path in files})
    assert [complete["components"][path]["instability"] for path in sorted(files)] == [1.0, .5, 0.0]
    assert not any(value["coupling_lower_bound"] for value in complete["components"].values())
