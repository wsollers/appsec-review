"""job_code_graph_index (docs/architecture/code-graph-precomputation.md section 10, chunk C5).

A fake accepted run (``tests/fixtures/graph/job/builder.py``) stages C2's accepted CodeQL handoff with
C1's recorded synthetic and native exports, a failed and a not-applicable scope, and accepted clangd,
CodeQL observation and prioritization shards. The real job runs through ``JobRunner``; its output is
read back through the accepted manifest, ``query_code_graph``, C8's matrix lane and the inventory audit.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.graph.catalog import CATALOG_PATH
from appsec_review.graph.contract import GRAPH_INDEX, Family
from appsec_review.indexing import matrix
from appsec_review.indexing.inventory import InventoryInputs, build_inventory
from appsec_review.indexing.store import ShardSet, accepted_handoff
from appsec_review.jobs.job_code_graph_index import JOB_ID, build_job
from appsec_review.jobs.job_code_graph_index.datasets import CONSUMES, DATASETS
from appsec_review.jobs.job_codeql_analysis.datasets import DATASETS as CODEQL_DATASETS
from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import file_sha256
from tests.fixtures.graph.job.builder import (
    FAILED, GO, NATIVE, ROOT, SNAPSHOT, SYNTHETIC, Staged, stage_run,
)

FAMILIES = [family.value for family in Family]
SUCCEEDED_SCOPES = (SYNTHETIC, NATIVE)
UNAVAILABLE_SCOPES = (FAILED, GO)


def _run(staged: Staged, job=None) -> dict[str, Any]:
    outcome = JobRunner(staged.config).run(job or build_job(), run_id=staged.run_id, target_root=staged.target,
                                           source_fingerprint=SNAPSHOT)
    return dict(outcome)


def _outputs(outcome: dict[str, Any]) -> dict[str, Any]:
    return json.loads((Path(outcome["attempt_root"]) / "result.json").read_text(encoding="utf-8"))["outputs"]


def _manifest(staged: Staged) -> dict[str, Any]:
    path, sha = resolve_accepted_manifest(staged.run_root)
    document, _ = load_verified_manifest(staged.run_root, path, sha)
    return document


def _graph(document: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in document["indexes"] if item["name"] == GRAPH_INDEX]


@pytest.fixture()
def staged(tmp_path: Path) -> Staged:
    return stage_run(tmp_path)


@pytest.fixture()
def published(staged: Staged) -> tuple[Staged, dict[str, Any]]:
    outcome = _run(staged)
    assert outcome["status"]["status"] == "COMPLETED_WITH_GAPS"
    return staged, outcome


# --------------------------------------------------------------------------- publication


def test_one_graph_shard_per_scope_and_family_with_producer_keys_and_coverage(published) -> None:
    staged, outcome = published
    document = _manifest(staged)
    graph = _graph(document)
    assert sorted((item["producer"]["scope_id"], item["producer"]["family"]) for item in graph) == sorted(
        (scope, family) for scope in (*SUCCEEDED_SCOPES, *UNAVAILABLE_SCOPES) for family in FAMILIES)
    for item in graph:
        producer = item["producer"]
        assert producer["job"] == JOB_ID and producer["language"] in {"cpp", "go"}
        assert producer["build_unit_id"].startswith("build-unit-")
        assert item["shard_id"] == f"graph-{producer['scope_id']}-{producer['family']}"
    shards = ShardSet(staged.run_root, graph)
    coverage = {(row["shard_id"], row["area"]): row["status"] for row in shards.coverage(shards.shards)}
    assert len(coverage) == len(graph)
    for (shard_id, area), _status in coverage.items():
        scope, family = shard_id.removeprefix("graph-").rsplit("-", 1)
        assert area == f"graph:{scope}:{family}"
    # Every symbol rides in the call_site shard and every fact kind sits in its own family shard.
    for item in graph:
        kinds = {row["kind"] for row in shards.entities([item])}
        family = item["producer"]["family"]
        assert kinds <= ({family, "symbol"} if family == "call_site" else {family})
    # The codeql handoff publishes the graph handoff that store.accepted_handoff accepts.
    handoff = accepted_handoff(staged.run_root, JOB_ID)
    assert handoff is not None and handoff.handoff["outputs"]["acceptance.publish_handoff"]["index_manifest"][
        "path"] == resolve_accepted_manifest(staged.run_root)[0].relative_to(staged.run_root).as_posix()
    assert _outputs(outcome)["acceptance.publish_handoff"]["counts"]["shards"] == 28


def test_upstream_shards_are_composed_never_dropped(published) -> None:
    staged, _ = published
    document = _manifest(staged)
    present = {(item["name"], item["shard_id"], item["sha256"]) for item in document["indexes"]}
    assert {(item["name"], item["shard_id"], item["sha256"]) for item in staged.upstream_shards} <= present
    assert len(document["upstream_manifests"]) == 1


def test_failed_or_inapplicable_scope_publishes_unavailable_rows_for_all_families_and_no_entities(published) -> None:
    staged, _ = published
    graph = _graph(_manifest(staged))
    shards = ShardSet(staged.run_root, graph)
    for scope, reason in ((FAILED, "database creation failed"), (GO, "no hash-pinned CodeQL graph export pack")):
        members = [item for item in graph if item["producer"]["scope_id"] == scope]
        assert sorted(item["producer"]["family"] for item in members) == sorted(FAMILIES)
        assert list(shards.entities(members)) == [] and list(shards.relations(members)) == []
        rows = shards.coverage(members)
        assert {row["status"] for row in rows} == {"unavailable"} and len(rows) == 7
        assert all(reason in row["gap"] and row["gap"].startswith("export_unavailable") for row in rows)


def test_cross_check_disagreement_and_secondary_only_make_call_sites_partial_and_relations_resolve(published) -> None:
    staged, outcome = published
    graph = _graph(_manifest(staged))
    [call_shard] = [item for item in graph if item["producer"]["scope_id"] == SYNTHETIC
                    and item["producer"]["family"] == "call_site"]
    shards = ShardSet(staged.run_root, graph)
    [row] = shards.coverage([call_shard])
    assert row["status"] == "partial" and "cross_check_disagreements: 1" in row["gap"]
    states = _outputs(outcome)["crosscheck.scopes"]["scopes"][0]["states"]
    assert (states["agree"], states["disagree"]) == (1, 1)
    calls = list(shards.entities([call_shard], kinds=("call_site",)))
    secondary = [item for item in calls if item["payload"]["result"]["callee"]["dispatch"] == "secondary_only"]
    assert len(secondary) == 1 and secondary[0]["payload"]["admissibility"]["direct_eligible"] is False
    relations = list(shards.relations([call_shard]))
    contains = [item for item in relations if item["kind"] == "CONTAINS" and item["target_id"] == secondary[0]["identity"]]
    # The clangd caller lives in the composed analysis shard: the manifest closure verified above holds.
    assert contains and contains[0]["source_id"] == staged.ids["clangd:main"]
    assert any(item["kind"] == "CONTRADICTS" and item["target_id"] == staged.ids["clangd:forward"]
               for item in relations)
    assert any(item["kind"] == "SAME_AS" and item["target_id"] == staged.ids["clangd:copy_checked"]
               for item in relations)
    # The native scope had no secondary shard of its own: the synthetic clangd shard is never shared.
    native_calls = [item for item in graph if item["producer"]["scope_id"] == NATIVE
                    and item["producer"]["family"] == "call_site"]
    assert {entity["payload"]["cross_check"]["state"]
            for entity in shards.entities(native_calls, kinds=("call_site",))} == {"not_covered"}


def test_broken_sarif_flows_are_dataflow_path_coverage_gaps(published) -> None:
    staged, outcome = published
    graph = _graph(_manifest(staged))
    [path_shard] = [item for item in graph if item["producer"]["scope_id"] == SYNTHETIC
                    and item["producer"]["family"] == "dataflow_path"]
    [row] = ShardSet(staged.run_root, graph).coverage([path_shard])
    assert row["status"] == "partial"
    assert f"sarif_correlation_broken: observation {staged.ids['obs:broken']} code_flow 0.0: source_unmatched" \
        in row["gap"]
    states = _outputs(outcome)["correlate.scopes"]["scopes"][0]["counts"]["correlation_states"]
    assert states == {"bridged": 1, "partial": 0, "broken": 1}


# --------------------------------------------------------------------------- resume and invalidation


def test_rerun_reuses_every_scope_checkpoint(published) -> None:
    staged, first = published
    before = {item["shard_id"]: item["sha256"] for item in _graph(_manifest(staged))}
    second = _run(staged)
    outputs = _outputs(second)
    assert outputs["load.accepted_inputs"]["reused_count"] == 4
    assert outputs["normalize.scopes"]["scopes"] == [] and outputs["crosscheck.scopes"]["scopes"] == []
    assert outputs["correlate.scopes"]["reused_count"] == 4
    assert all(item["checkpoint_reused"] for item in outputs["correlate.scopes"]["scopes"])
    assert {item["shard_id"]: item["sha256"] for item in _graph(_manifest(staged))} == before
    assert second["status"]["attempt_id"] != first["status"]["attempt_id"]


def _changed_catalog(tmp_path: Path) -> Path:
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    catalog["revision"] = int(catalog["revision"]) + 1
    changed = tmp_path / "catalog.json"
    changed.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
    return changed


def test_catalog_change_rebuilds_only_graph_shards(published, tmp_path: Path, monkeypatch) -> None:
    staged, _ = published
    document = _manifest(staged)
    graph_before = {item["shard_id"]: item["sha256"] for item in _graph(document)}
    others_before = sorted((item["name"], item["shard_id"], item["sha256"]) for item in document["indexes"]
                           if item["name"] != GRAPH_INDEX)
    export_checkpoints = {scope: file_sha256(staged.export_dir(scope).parent / "export-checkpoint.json")
                          for scope in SUCCEEDED_SCOPES}
    export_files = {path: file_sha256(path) for scope in SUCCEEDED_SCOPES
                    for path in staged.export_dir(scope).iterdir()}
    changed = _changed_catalog(tmp_path)
    # A run configured with the revised catalog: its CodeQL export pin names the new catalog hash.
    monkeypatch.setattr("appsec_review.jobs.job_code_graph_index.job.catalog_pins",
                        lambda document: {"cpp": frozenset({file_sha256(changed)})})
    outputs = _outputs(_run(staged, build_job(catalog_path=changed)))
    assert outputs["load.accepted_inputs"]["reused_count"] == 0
    assert len(outputs["normalize.scopes"]["scopes"]) == 2
    after = _manifest(staged)
    graph_after = {item["shard_id"]: item["sha256"] for item in _graph(after)}
    assert graph_after.keys() == graph_before.keys()
    assert all(graph_after[shard_id] != sha for shard_id, sha in graph_before.items())
    assert {item["producer"]["catalog_sha256"] for item in _graph(after)} == {
        outputs["load.accepted_inputs"]["catalog"]["sha256"]}
    assert sorted((item["name"], item["shard_id"], item["sha256"]) for item in after["indexes"]
                  if item["name"] != GRAPH_INDEX) == others_before
    assert {scope: file_sha256(staged.export_dir(scope).parent / "export-checkpoint.json")
            for scope in SUCCEEDED_SCOPES} == export_checkpoints
    assert {path: file_sha256(path) for path in export_files} == export_files


def test_a_catalog_other_than_the_configured_codeql_pin_fails_the_load_unit(staged: Staged, tmp_path: Path) -> None:
    # The run-bound jobs.job_codeql_analysis.settings.languages.cpp.export_queries.catalog_sha256 pins
    # the repository catalog; a different catalog would classify facts under rules the run never pinned.
    with pytest.raises(RuntimeError, match="partial failure"):
        _run(staged, build_job(catalog_path=_changed_catalog(tmp_path)))
    attempt = next((staged.run_root / "data" / "jobs" / JOB_ID / "attempts").iterdir())
    status = json.loads((attempt / "steps" / "load" / "tasks" / "accepted_inputs" / "status.json").read_text())
    assert status["status"] == "FAILED" and status["error"]["type"] == "IntegrityError"
    assert accepted_handoff(staged.run_root, JOB_ID) is None


@pytest.mark.parametrize("victim", ["call_sites.json", "export-manifest.json"])
def test_tampered_export_fails_the_load_unit_with_an_integrity_error(staged: Staged, victim: str) -> None:
    path = staged.export_dir(SYNTHETIC) / victim
    data = bytearray(path.read_bytes())
    data[data.index(b"1")] = ord("2")
    path.write_bytes(bytes(data))
    with pytest.raises(RuntimeError, match="partial failure"):
        _run(staged)
    attempt = next((staged.run_root / "data" / "jobs" / JOB_ID / "attempts").iterdir())
    status = json.loads((attempt / "steps" / "load" / "tasks" / "accepted_inputs" / "status.json").read_text())
    assert status["status"] == "FAILED" and status["error"]["type"] == "IntegrityError"
    assert accepted_handoff(staged.run_root, JOB_ID) is None


def test_a_source_changed_after_acceptance_fails_the_load_unit(staged: Staged) -> None:
    (staged.target / "src" / "synthetic.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="partial failure"):
        _run(staged)


# --------------------------------------------------------------------------- consumers


def test_query_code_graph_answers_every_mode_over_the_job_output(published) -> None:
    staged, _ = published
    core = RetrievalCore(staged.runs, staged.run_id)
    graph = _graph(_manifest(staged))
    shards = ShardSet(staged.run_root, [item for item in graph if item["producer"]["scope_id"] == SYNTHETIC])
    symbols = {row["name"]: row["identity"] for row in shards.entities(shards.shards, kinds=("symbol",))}

    callers = core.query_code_graph(mode="callers", subject=symbols["copy_unchecked"])
    direct = [row for row in callers["results"] if "closure_role" not in row]
    assert len(direct) == 2 and {row["kind"] for row in direct} == {"call_site"}
    callees = core.query_code_graph(mode="callees", subject=symbols["main"])
    assert {row["payload"]["result"]["callee"]["display"] for row in callees["results"]} >= {
        "copy_checked", "copy_unchecked", "dispatch", "forward"}

    sinks = core.query_code_graph(mode="sinks", subject=symbols["copy_unchecked"])
    assert sorted((row["location"]["start_line"], row["payload"]["result"]["sink_class"])
                  for row in sinks["results"]) == [(43, "memory_write"), (45, "memory_write")]
    sink = next(row for row in sinks["results"] if row["location"]["start_line"] == 45)
    paths = core.query_code_graph(mode="paths", subject=sink["identity"])
    assert [row["payload"]["result"]["hop_count"] for row in paths["results"]] == [4, 5]
    guards = core.query_code_graph(mode="guards", subject=sink["identity"])
    assert [row["payload"]["result"]["guard_state"] for row in guards["results"]] == ["non_dominating", "none"]

    bridged = core.query_code_graph(mode="sarif_path", subject=staged.ids["obs:bridged"])
    [row] = bridged["results"]
    assert row["kind"] == "dataflow_path" and row["payload"]["result"]["source"]["source_class"] == "environment"
    correlation = row["correlation"]
    assert (correlation["state"], correlation["code_flow"], correlation["thread_flow"], correlation["exact"]) == (
        "bridged", 0, 0, True)
    assert correlation["rule"] == "graph-sarif-correlation/1" and len(correlation["matched_steps"]) == 5
    assert core.find(identity=row["identity"], limit=1)["results"][0]["identity"] == row["identity"]
    broken = core.query_code_graph(mode="sarif_path", subject=staged.ids["obs:broken"])
    assert broken["results"] == []
    assert any("code_flow 0 is broken" in gap and "source_unmatched" in gap for gap in broken["coverage_gaps"])


def test_priority_flow_steps_are_linked_same_as_onto_the_correlated_path(published) -> None:
    staged, _ = published
    graph = _graph(_manifest(staged))
    shards = ShardSet(staged.run_root, graph)
    same_as = [item for item in shards.relations(graph, kinds=("SAME_AS",))
               if item["source_id"] == staged.ids["step:0"]]
    assert len(same_as) == 1 and same_as[0]["shard_id"] == f"graph-{SYNTHETIC}-dataflow_path"


def test_code_graph_matrix_lane_is_computed_from_the_job_output(published) -> None:
    staged, _ = published
    shards = ShardSet(staged.run_root, _manifest(staged)["indexes"])
    rows = {row["language"]: row["lanes"]["code_graph"] for row in matrix.language_matrix(shards, {})}
    assert rows["c/c++"]["state"] == "partial"
    assert set(rows["c/c++"]["families"].values()) == {"partial"}  # the failed C/C++ scope is unavailable
    assert rows["go"]["state"] == "unavailable" and "every fact family unavailable" in rows["go"]["basis"]
    units = {row["build_unit_id"]: row["lanes"]["code_graph"] for row in matrix.build_unit_matrix(shards)}
    assert units["build-unit-native"]["state"] == "complete"
    assert units["build-unit-synthetic"]["state"] == "partial"
    assert units["build-unit-broken"]["state"] == "unavailable"


def test_dataset_declarations_pass_the_inventory_audit_including_unavailable_shards(published) -> None:
    staged, _ = published
    config = staged.config
    steps = {job_id: tuple(config.job(job_id).steps) for job_id in (JOB_ID, "job_codeql_analysis")}
    graph = _graph(_manifest(staged))
    handoffs = {JOB_ID: accepted_handoff(staged.run_root, JOB_ID),
                "job_codeql_analysis": accepted_handoff(staged.run_root, "job_codeql_analysis")}
    inventory = build_inventory(InventoryInputs(
        run_root=staged.run_root, run_id=staged.run_id, target_snapshot=SNAPSHOT, job_steps=steps,
        declarations={JOB_ID: DATASETS, "job_codeql_analysis": CODEQL_DATASETS},
        consumes={JOB_ID: CONSUMES}, handoffs=handoffs, unit_statuses={}, shards=graph))
    violations = [item for item in inventory["audit"]["violations"]
                  if item["job_id"] == JOB_ID or "code-graph" in item["subject"] or JOB_ID in item["subject"]]
    assert violations == []
    rows = [row for row in inventory["rows"] if row["job_id"] == JOB_ID]
    facts = {row["scope"]: row["disposition"] for row in rows if row["output_kind"] == "code_graph_facts"}
    assert len(facts) == 28
    assert {facts[f"graph-{scope}-{family}"] for scope in UNAVAILABLE_SCOPES for family in FAMILIES} == {"unavailable"}
    assert {facts[f"graph-{NATIVE}-{family}"] for family in FAMILIES} == {"indexed"}
    kinds = {row["output_kind"]: row["disposition"] for row in rows if row["output_kind"].startswith("code_graph_")
             and row["output_kind"] != "code_graph_facts"}
    assert kinds == {"code_graph_stages": "artifact_only", "code_graph_checkpoints": "artifact_only",
                     "code_graph_summary": "artifact_only"}


# --------------------------------------------------------------------------- registration and topology


def test_registry_and_configuration_declare_the_job_and_its_settings() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    job_config = config.job(JOB_ID)
    assert list(job_config.steps) == ["load", "normalize", "crosscheck", "correlate", "acceptance"]
    job = builtin_registry().build(JOB_ID)
    assert [unit.unit_id.split(".")[0] for unit in job.units] == list(job_config.steps)
    assert [tuple(job_config.step(step).tasks) for step in job_config.steps] == [
        (unit.unit_id.split(".")[1],) for unit in job.units]
    from appsec_review.graph.contract import GraphSettings
    assert GraphSettings.from_mapping(job_config.settings["graph"]) == GraphSettings()
    assert set(CONSUMES) >= {"job_codeql_analysis", "job_review_prioritization"}


def test_dagster_ops_and_wave_dependencies_match_the_configured_topology() -> None:
    pytest.importorskip("dagster")
    from appsec_review.orchestration.dagster import build_definitions

    path = ROOT / "appsec-review.toml"
    graph = build_definitions(path).get_job_def("wave1_review").graph
    names = {node.name for node in graph.node_defs}
    config = load_config(path).job(JOB_ID)
    expected = {f"code_graph_index__{step}__{task}" for step in config.steps for task in config.step(step).tasks}
    assert expected | {"code_graph_index__begin", "code_graph_index__finalize"} <= names

    def upstream(node: str) -> set[str]:
        mapping = graph.dependency_structure.input_to_upstream_outputs_for_node(node)
        return {output.node_name for outputs in mapping.values() for output in outputs}

    assert upstream("code_graph_index__begin") >= {
        "codeql_analysis__finalize", "review_prioritization__finalize", "cpp_symbol_index__finalize",
        "cpp_compiled_analysis__finalize"}
    assert "code_graph_index__finalize" in upstream("review_data_indexing__begin")
    assert "code_graph_index__finalize" in upstream("security_tagging__begin")
    assert upstream("code_graph_index__normalize__scopes") >= {"code_graph_index__load__accepted_inputs"}
    assert upstream("code_graph_index__acceptance__publish_handoff") >= {"code_graph_index__correlate__scopes"}


def test_configuration_topology_validation_rejects_a_missing_step(staged: Staged) -> None:
    job = build_job()
    from dataclasses import replace
    from types import MappingProxyType, SimpleNamespace

    config = staged.config.job(JOB_ID)
    steps = dict(config.steps)
    steps.pop("crosscheck")
    context = SimpleNamespace(config=replace(config, steps=MappingProxyType(steps)))
    with pytest.raises(ValueError, match="topology"):
        job.input_validators[0](context, None)
