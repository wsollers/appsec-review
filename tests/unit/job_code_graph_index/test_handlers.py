from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
import json
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest

from appsec_review.config.assurance import ComponentReleases, ReviewPolicy
from appsec_review.graph.catalog import CATALOG_PATH
from appsec_review.graph.contract import GRAPH_INDEX, Family
from appsec_review.indexing import matrix
from appsec_review.indexing.inventory import InventoryInputs, build_inventory
from appsec_review.indexing.store import ShardSet, accepted_handoff
from appsec_review.jobs.job_code_graph_index import JOB_ID, build_job
from appsec_review.jobs.job_code_graph_index.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_codeql_analysis.datasets import DATASETS as CODEQL_DATASETS
from appsec_review.observability import EventLog
from appsec_review.retrieval import (
    EntityKind,
    EntityRecord,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    RetrievalCore,
)
from appsec_review.retrieval.index import INDEX_SCHEMA, load_verified_manifest
from appsec_review.review.models import IntegrityError
from appsec_review.runtime.consume import upstream_scope
from appsec_review.runtime.job import JobContext
from appsec_review.runtime.units import UnitContext
from appsec_review.storage import atomic_json, file_sha256
from tests.fixtures.graph.job.builder import (
    FAILED,
    GO,
    NATIVE,
    ROOT,
    SNAPSHOT,
    SYNTHETIC,
    Staged,
    stage_run,
)

FAMILIES = [family.value for family in Family]
SUCCEEDED_SCOPES = (SYNTHETIC, NATIVE)
UNAVAILABLE_SCOPES = (FAILED, GO)


def _upstream_pins(run_root: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    jobs_dir = run_root / "data" / "jobs"
    if not jobs_dir.is_dir():
        return pins
    for latest in sorted(jobs_dir.glob("*/latest.json")):
        producer_job = latest.parent.name
        if producer_job == JOB_ID:
            continue
        doc = json.loads(latest.read_text(encoding="utf-8"))
        pins[producer_job] = str(doc["handoff_sha256"])
    return pins


def _make_job_context(
    staged: Staged,
    *,
    attempt_id: str = "attempt_unit_01",
    with_releases: bool = True,
) -> JobContext:
    attempt_root = staged.run_root / "data" / "jobs" / JOB_ID / "attempts" / attempt_id
    attempt_root.mkdir(parents=True, exist_ok=True)
    metadata_root = staged.run_root / "metadata"
    metadata_root.mkdir(parents=True, exist_ok=True)
    events = EventLog(metadata_root / f"{attempt_id}.events.jsonl")
    policy = (
        staged.config.review_policy
        if with_releases
        else ReviewPolicy(
            releases=ComponentReleases(
                values=MappingProxyType(
                    {"graph_catalog": staged.config.review_policy.releases.values["graph_catalog"]}
                )
            )
        )
    )
    return JobContext(
        run_id=staged.run_id,
        attempt_id=attempt_id,
        trigger="unit_test",
        repository_root=ROOT,
        run_root=staged.run_root,
        attempt_root=attempt_root,
        metadata_root=metadata_root,
        orchestration=MappingProxyType({"driver": "unit"}),
        config=staged.config.job(JOB_ID),
        events=events,
        target_root=staged.target,
        source_fingerprint=SNAPSHOT,
        review_policy=policy,
        upstream_handoffs=MappingProxyType(_upstream_pins(staged.run_root)),
        contract=CONTRACT,
    )


def _execute_units(
    staged: Staged,
    *,
    job=None,
    attempt_id: str = "attempt_unit_01",
    with_releases: bool = True,
) -> dict[str, Any]:
    active_job = job or build_job()
    ctx = _make_job_context(staged, attempt_id=attempt_id, with_releases=with_releases)
    for validator in active_job.input_validators:
        validator(ctx, None)
    with upstream_scope(staged.run_root, JOB_ID, ctx.upstream_handoffs, contract=CONTRACT):
        return dict(active_job.handler(ctx))


def _publish_unit_handoff(
    staged: Staged, result: dict[str, Any], attempt_id: str = "attempt_unit_01"
) -> dict[str, Any]:
    """Bind unit output index-manifest into an accepted handoff for RetrievalCore/inventory queries."""
    from appsec_review.runtime.datasets import dataset_contract
    from tests.handoff_fixture import write_fixture_handoff

    attempt = staged.run_root / "data" / "jobs" / JOB_ID / "attempts" / attempt_id
    pub = result["outputs"]["acceptance.publish_handoff"]
    manifest_ref = pub["index_manifest"]
    summary_ref = pub["artifact"]
    scorecard_doc_ref = pub["scorecard"]["document"]
    scorecard_txt_ref = pub["scorecard"]["rendering"]
    load_art_ref = result["outputs"]["load.accepted_inputs"]["artifact"]
    manifest_doc = json.loads((staged.run_root / manifest_ref["path"]).read_text(encoding="utf-8"))

    extra_refs = [
        manifest_ref,
        summary_ref,
        scorecard_doc_ref,
        scorecard_txt_ref,
        load_art_ref,
    ]
    for unit_name in ("normalize.scopes", "crosscheck.scopes"):
        for sc in result["outputs"][unit_name]["scopes"]:
            extra_refs.append(sc["stage"])
    for sc in result["outputs"]["correlate.scopes"]["scopes"]:
        if "checkpoint" in sc:
            extra_refs.append(sc["checkpoint"])

    def _sized(rel_path: str, sha: str) -> dict[str, Any]:
        return {"path": rel_path, "sha256": sha, "size_bytes": (staged.run_root / rel_path).stat().st_size}

    artifacts = [
        *[_sized(r["path"], r["sha256"]) for r in extra_refs],
        *[
            _sized(item["relative_path"], item["sha256"])
            for item in manifest_doc["indexes"]
            if (item.get("producer") or {}).get("job") == JOB_ID
        ],
    ]
    atomic_json(attempt / "result.json", result)
    res_rel = (attempt / "result.json").relative_to(staged.run_root).as_posix()
    res_sha = file_sha256(attempt / "result.json")
    artifacts.append(_sized(res_rel, res_sha))
    atomic_json(
        attempt / "claim.json",
        {"dataset_contract": dataset_contract(JOB_ID, list(staged.config.job(JOB_ID).steps), DATASETS)},
    )
    ho_path = attempt / "handoff.json"
    write_fixture_handoff(
        staged.run_root,
        ho_path,
        {
            "job_id": JOB_ID,
            "attempt_id": attempt_id,
            "status": "ACCEPTED",
            "completion_status": result["status"],
            "source_fingerprint": SNAPSHOT,
            "outputs": result["outputs"],
            "artifacts": artifacts,
            "resolving_paths": {
                "attempt": attempt.relative_to(staged.run_root).as_posix(),
                "result": res_rel,
            },
        },
    )
    ho_rel = ho_path.relative_to(staged.run_root).as_posix()
    handoff_sha = file_sha256(ho_path)
    atomic_json(
        staged.run_root / "data" / "jobs" / JOB_ID / "latest.json",
        {
            "schema": "appsec-review/latest-handoff/1",
            "attempt_id": attempt_id,
            "handoff_path": ho_rel,
            "handoff_sha256": handoff_sha,
        },
    )
    atomic_json(
        staged.run_root / "data" / "indices" / "accepted.json",
        {
            "schema": "appsec-review/accepted-index-set/1",
            "run_id": staged.run_id,
            "handoff_path": ho_rel,
            "handoff_sha256": handoff_sha,
            "manifest_path": manifest_ref["path"],
            "manifest_sha256": manifest_ref["sha256"],
        },
    )
    doc, _ = load_verified_manifest(
        staged.run_root, staged.run_root / manifest_ref["path"], manifest_ref["sha256"]
    )
    return doc


def test_full_unit_pipeline_publishes_shards_cards_scorecard_queries_matrix_and_inventory(
    tmp_path: Path,
) -> None:
    staged = stage_run(tmp_path)
    first = _execute_units(staged, attempt_id="attempt_unit_01")
    assert first["status"] == "COMPLETED_WITH_GAPS"
    outputs = first["outputs"]

    states = outputs["crosscheck.scopes"]["scopes"][0]["states"]
    assert (states["agree"], states["disagree"]) == (1, 1)
    corr_states = outputs["correlate.scopes"]["scopes"][0]["counts"]["correlation_states"]
    assert corr_states == {"bridged": 1, "partial": 0, "broken": 1}

    counts = outputs["acceptance.publish_handoff"]["counts"]
    assert counts["shards"] == 36 and counts["databases"] == 4
    for telemetry_key in (
        "alternate_cpg_nodes",
        "alternate_cpg_edges",
        "semantic_edges_count",
        "syntactic_fallback_edges_count",
        "entrypoints_linked",
        "reachable_sink_paths_precomputed",
    ):
        assert telemetry_key in counts
        assert isinstance(counts[telemetry_key], int)
    assert counts["alternate_cpg_nodes"] >= 1
    assert counts["alternate_cpg_edges"] >= 1

    document = _publish_unit_handoff(staged, first, "attempt_unit_01")
    all_graph = [item for item in document["indexes"] if item["name"] == GRAPH_INDEX]
    cards = [item for item in all_graph if item["producer"].get("kind") == "codeql_database"]
    prod_shards = [item for item in all_graph if item["producer"].get("kind") == "producer_neighborhood"]
    family_shards = [
        item
        for item in all_graph
        if item["producer"].get("kind") not in {"codeql_database", "producer_neighborhood"}
    ]
    assert len(family_shards) == 28 and len(cards) == 4 and len(prod_shards) == 4

    alt_shards = [
        item for item in document["indexes"]
        if item["name"] == "analysis" and item["shard_id"] == "alternate-cpg"
    ]
    assert len(alt_shards) == 1

    # Upstream shards are composed, never dropped.
    present = {(item["name"], item["shard_id"], item["sha256"]) for item in document["indexes"]}
    assert {(item["name"], item["shard_id"], item["sha256"]) for item in staged.upstream_shards} <= present

    # Unavailable scopes publish unavailable coverage rows and zero entities.
    shards = ShardSet(staged.run_root, family_shards)
    for scope_id, reason in (
        (FAILED, "database creation failed"),
        (GO, "no hash-pinned CodeQL graph export pack"),
    ):
        members = [item for item in family_shards if item["producer"]["scope_id"] == scope_id]
        assert list(shards.entities(members)) == [] and list(shards.relations(members)) == []
        cov_rows = shards.coverage(members)
        assert {r["status"] for r in cov_rows} == {"unavailable"}
        assert all(reason in r["gap"] for r in cov_rows)

    # Priority flow step is linked SAME_AS onto correlated dataflow_path.
    same_as = [
        rel
        for rel in shards.relations(family_shards, kinds=("SAME_AS",))
        if rel["source_id"] == staged.ids["step:0"]
    ]
    assert len(same_as) == 1 and same_as[0]["shard_id"] == f"graph-{SYNTHETIC}-dataflow_path"

    # RetrievalCore query_code_graph modes + list_codeql_databases.
    core = RetrievalCore(staged.runs, staged.run_id)
    syn_shards = ShardSet(
        staged.run_root, [item for item in family_shards if item["producer"]["scope_id"] == SYNTHETIC]
    )
    symbols = {row["name"]: row["identity"] for row in syn_shards.entities(syn_shards.shards, kinds=("symbol",))}
    assert core.query_code_graph(mode="callers", subject=symbols["copy_unchecked"])["results"]
    assert core.query_code_graph(mode="callees", subject=symbols["main"])["results"]
    sinks = core.query_code_graph(mode="sinks", subject=symbols["copy_unchecked"])["results"]
    sink = next(row for row in sinks if row["location"]["start_line"] == 45)
    assert core.query_code_graph(mode="paths", subject=sink["identity"])["results"]
    assert core.query_code_graph(mode="guards", subject=sink["identity"])["results"]
    assert core.query_code_graph(mode="sarif_path", subject=staged.ids["obs:bridged"])["results"]
    assert {row["payload"]["scope_id"] for row in core.list_codeql_databases()["results"]} == {
        SYNTHETIC,
        NATIVE,
        FAILED,
        GO,
    }

    # Matrix lane and inventory audit (including code_graph_scorecard).
    full_shards = ShardSet(staged.run_root, document["indexes"])
    lang_rows = {row["language"]: row["lanes"]["code_graph"] for row in matrix.language_matrix(full_shards, {})}
    assert lang_rows["c/c++"]["state"] == "partial" and lang_rows["go"]["state"] == "unavailable"
    bu_rows = {row["build_unit_id"]: row["lanes"]["code_graph"] for row in matrix.build_unit_matrix(full_shards)}
    assert bu_rows["build-unit-native"]["state"] == "complete"

    steps = {jid: tuple(staged.config.job(jid).steps) for jid in (JOB_ID, "job_codeql_analysis")}
    handoffs = {
        JOB_ID: accepted_handoff(staged.run_root, JOB_ID),
        "job_codeql_analysis": accepted_handoff(staged.run_root, "job_codeql_analysis"),
    }
    inventory = build_inventory(
        InventoryInputs(
            run_root=staged.run_root,
            run_id=staged.run_id,
            target_snapshot=SNAPSHOT,
            job_steps=steps,
            declarations={JOB_ID: DATASETS, "job_codeql_analysis": CODEQL_DATASETS},
            consumes={JOB_ID: CONSUMES},
            handoffs=handoffs,
            unit_statuses={},
            shards=[*family_shards, *prod_shards],
        )
    )
    violations = [
        v for v in inventory["audit"]["violations"] if v["job_id"] == JOB_ID or JOB_ID in v["subject"]
    ]
    assert violations == []
    kinds = {
        row["output_kind"]: row["disposition"]
        for row in inventory["rows"]
        if row["job_id"] == JOB_ID
        and row["output_kind"].startswith("code_graph_")
        and row["output_kind"] != "code_graph_facts"
    }
    assert kinds == {
        "code_graph_stages": "artifact_only",
        "code_graph_checkpoints": "artifact_only",
        "code_graph_summary": "artifact_only",
        "code_graph_scorecard": "artifact_only",
    }

    # Second run reuses all 4 checkpoints even when catalog JSON revision changes without release bump.
    changed_cat = tmp_path / "changed_catalog.json"
    cat_doc = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    cat_doc["revision"] = int(cat_doc["revision"]) + 1
    changed_cat.write_text(json.dumps(cat_doc), encoding="utf-8")

    second = _execute_units(staged, job=build_job(catalog_path=changed_cat), attempt_id="attempt_unit_02")
    assert second["outputs"]["load.accepted_inputs"]["reused_count"] == 4
    assert second["outputs"]["normalize.scopes"]["scopes"] == []
    assert second["outputs"]["crosscheck.scopes"]["scopes"] == []
    assert second["outputs"]["correlate.scopes"]["reused_count"] == 4

    # Running with incomplete release pins logs CHECKPOINT_MISSED and rebuilds instead of reusing.
    third = _execute_units(staged, attempt_id="attempt_unit_03", with_releases=False)
    assert third["outputs"]["load.accepted_inputs"]["reused_count"] == 0


def test_empty_scopes_analyzer_and_svf_crosscheck_catalog_drift_and_missing_shard_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged = stage_run(tmp_path)

    # 1. Empty scopes -> NOT_APPLICABLE across load/normalize/crosscheck/correlate/publish.
    monkeypatch.setattr(
        "appsec_review.jobs.job_code_graph_index.job.s.load_codeql_inputs",
        lambda _root, _snap: {"handoff": {"path": "h", "sha256": "0" * 64}, "scopes": []},
    )
    empty_res = _execute_units(staged, attempt_id="attempt_empty")
    assert empty_res["outputs"]["load.accepted_inputs"]["terminal_status"] == "NOT_APPLICABLE"
    assert empty_res["outputs"]["acceptance.publish_handoff"]["counts"]["databases"] == 0
    monkeypatch.undo()

    # 2. Stage a dropped clang-static analyzer shard under job_clang_static_analysis so restored_secondary
    #    restores it in load, crosscheck runs apply_analyzer_sinks, svf_cross_check reports svf_disagreements,
    #    correlate_scopes hits > MAX_BROKEN_GAPS, and publish composes restored_secondary!
    cs_path = staged.run_root / "data" / "indices" / "observations" / "cs-syn.sqlite"
    cs_fp = "d" * 64
    builder = IndexBuilder(
        cs_path, name="observations", fingerprint=cs_fp, target_snapshot=SNAPSHOT, shard_id="cs-syn"
    )
    builder.add_entity(
        EntityRecord(
            LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAPSHOT, {"cs": "1"}),
            "cs1",
            "core.NullDereference",
            "null deref",
            {"scanner": "clang-static-analyzer", "native_rule_id": "core.NullDereference"},
            None,
        )
    )
    builder.add_coverage("observations:cs-syn", "complete", None)
    cs_sha = builder.build()
    cs_ident = IndexIdentity(
        "observations",
        INDEX_SCHEMA,
        cs_sha,
        cs_fp,
        cs_path.relative_to(staged.run_root).as_posix(),
        {"job": "job_clang_static_analysis", "project_root": "."},
        (),
        "cs-syn",
    )
    from appsec_review.retrieval import write_manifest
    from tests.handoff_fixture import write_fixture_handoff

    cs_man_path = staged.run_root / "data" / "indices" / "manifests" / "cs-man.json"
    write_manifest(
        cs_man_path,
        run_id=staged.run_id,
        target_snapshot=SNAPSHOT,
        target_root=staged.target,
        indexes=[cs_ident],
    )
    cs_man_rel = cs_man_path.relative_to(staged.run_root).as_posix()
    cs_man_sha = file_sha256(cs_man_path)
    cs_attempt = staged.run_root / "data" / "jobs" / "job_clang_static_analysis" / "attempts" / "attempt_01"
    cs_res = {
        "schema": "appsec-review/unit-execution/2",
        "status": "SUCCEEDED",
        "outputs": {"pub.out": {"index_manifest": {"path": cs_man_rel, "sha256": cs_man_sha}}},
    }
    atomic_json(cs_attempt / "result.json", cs_res)
    cs_res_rel = (cs_attempt / "result.json").relative_to(staged.run_root).as_posix()
    cs_ho_path = cs_attempt / "handoff.json"
    write_fixture_handoff(
        staged.run_root,
        cs_ho_path,
        {
            "job_id": "job_clang_static_analysis",
            "attempt_id": "attempt_01",
            "status": "ACCEPTED",
            "completion_status": "SUCCEEDED",
            "source_fingerprint": SNAPSHOT,
            "outputs": cs_res["outputs"],
            "artifacts": [
                {"path": cs_man_rel, "sha256": cs_man_sha, "size_bytes": cs_man_path.stat().st_size},
                {"path": cs_ident.relative_path, "sha256": cs_sha, "size_bytes": cs_path.stat().st_size},
                {"path": cs_res_rel, "sha256": file_sha256(cs_attempt / "result.json"), "size_bytes": (cs_attempt / "result.json").stat().st_size},
            ],
            "resolving_paths": {
                "attempt": cs_attempt.relative_to(staged.run_root).as_posix(),
                "result": cs_res_rel,
            },
        },
    )
    atomic_json(
        staged.run_root / "data" / "jobs" / "job_clang_static_analysis" / "latest.json",
        {
            "schema": "appsec-review/latest-handoff/1",
            "attempt_id": "attempt_01",
            "handoff_path": cs_ho_path.relative_to(staged.run_root).as_posix(),
            "handoff_sha256": file_sha256(cs_ho_path),
        },
    )

    monkeypatch.setattr("appsec_review.jobs.job_code_graph_index.job.s.MAX_BROKEN_GAPS", 0)
    monkeypatch.setattr(
        "appsec_review.jobs.job_code_graph_index.job.apply_analyzer_sinks",
        lambda facts, *_a, **_kw: SimpleNamespace(
            facts=list(facts),
            summary={"corroborated": 1, "analyzer_only": 1, "gaps": ["analyzer_sink_gap"]},
        ),
    )
    monkeypatch.setattr(
        "appsec_review.jobs.job_code_graph_index.job.svf_cross_check",
        lambda facts, *_a, **_kw: SimpleNamespace(
            facts=list(facts),
            relations=[],
            summary={"states": {"disagree": 1}, "secondary_only": 1},
        ),
    )
    enriched = _execute_units(staged, attempt_id="attempt_enriched")
    assert enriched["status"] == "COMPLETED_WITH_GAPS"
    assert any("svf_cross_check_disagreements" in g for g in enriched["outputs"]["crosscheck.scopes"]["gaps"])
    assert any("further broken code flows" in g for g in enriched["outputs"]["correlate.scopes"]["gaps"])
    monkeypatch.undo()

    # 3. Exercise loaded_catalog mid-attempt release drift guard in normalize unit handler.
    job = build_job()
    norm_unit = next(u for u in job.units if u.unit_id == "normalize.scopes")
    ctx = _make_job_context(staged, attempt_id="attempt_drift")
    drift_outputs = {
        "load.accepted_inputs": {
            **enriched["outputs"]["load.accepted_inputs"],
            "catalog": {"release_id": "different-mid-attempt-release"},
        }
    }
    norm_ctx = UnitContext(
        job=ctx,
        unit_id="normalize.scopes",
        step_id="normalize",
        task_id="scopes",
        unit_root=ctx.attempt_root / "steps" / "normalize" / "tasks" / "scopes",
        outputs=drift_outputs,
    )
    with pytest.raises(IntegrityError, match="catalog declaration changed during this attempt"):
        norm_unit.handler(norm_ctx)

    # 4. Exercise publish missing consumed shard guard.
    pub_unit = next(u for u in job.units if u.unit_id == "acceptance.publish_handoff")
    bad_load = json.loads(json.dumps(enriched["outputs"]["load.accepted_inputs"]))
    bad_load["scopes"][0]["inputs"]["observations"].append(
        {"name": "observations", "shard_id": "vanished-shard", "sha256": "f" * 64}
    )
    pub_ctx = UnitContext(
        job=ctx,
        unit_id="acceptance.publish_handoff",
        step_id="acceptance",
        task_id="publish_handoff",
        unit_root=ctx.attempt_root / "steps" / "acceptance" / "tasks" / "publish_handoff",
        outputs={
            "load.accepted_inputs": bad_load,
            "correlate.scopes": enriched["outputs"]["correlate.scopes"],
        },
    )
    with upstream_scope(staged.run_root, JOB_ID, ctx.upstream_handoffs, contract=CONTRACT):
        with pytest.raises(IntegrityError, match="no longer holds the shards"):
            pub_unit.handler(pub_ctx)
    assert asdict(cs_ident)["shard_id"] == "cs-syn" and SimpleNamespace(ok=True).ok


def _stage_single_scope_for_runner(tmp_path: Path) -> Staged:
    """Stage a single C++ scope with shard-bound CodeQL handoff so JobRunner executes in <5s."""
    from tests.handoff_fixture import write_fixture_handoff

    staged = stage_run(tmp_path, with_priority=False)
    run_root = staged.run_root
    cql_attempt = run_root / "data" / "jobs" / "job_codeql_analysis" / "attempts" / "attempt_0001"
    plan_path = cql_attempt / "artifacts" / "codeql" / "plan.json"
    exports_path = cql_attempt / "artifacts" / "codeql" / "graph-exports.json"
    result_path = cql_attempt / "result.json"
    manifest_path = run_root / "data" / "indices" / "manifests" / "codeql-attempt_0001.json"

    plan_doc = json.loads(plan_path.read_text(encoding="utf-8"))
    plan_doc["scopes"] = [sc for sc in plan_doc["scopes"] if sc["scope_id"] == SYNTHETIC]
    atomic_json(plan_path, plan_doc)

    exports_doc = json.loads(exports_path.read_text(encoding="utf-8"))
    exports_doc["exports"] = [ex for ex in exports_doc["exports"] if ex["scope_id"] == SYNTHETIC]
    atomic_json(exports_path, exports_doc)

    def _ref(path: Path) -> dict[str, Any]:
        return {
            "path": path.relative_to(run_root).as_posix(),
            "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size,
        }

    plan_ref = _ref(plan_path)
    exports_ref = _ref(exports_path)
    manifest_ref = _ref(manifest_path)
    outputs = {
        "plan.inventory": {"plan": plan_ref},
        "execution.scopes": {
            "schema": exports_doc["schema"],
            "graph_export_artifact": exports_ref,
            "exports": exports_doc["exports"],
            "gaps": [],
        },
        "acceptance.publish_handoff": {"index_manifest": manifest_ref, "gaps": []},
    }
    atomic_json(result_path, {"schema": "appsec-review/unit-execution/2", "status": "SUCCEEDED", "outputs": outputs})
    res_ref = _ref(result_path)

    artifacts = [
        res_ref,
        plan_ref,
        exports_ref,
        manifest_ref,
        *[
            _ref(run_root / item["relative_path"])
            for item in staged.upstream_shards
            if (item.get("producer") or {}).get("job") == "job_codeql_analysis"
        ],
    ]
    for record in exports_doc["exports"]:
        artifacts.append(record["export_manifest"])
        artifacts.extend(
            {k: v for k, v in item.items() if k != "query_id"} for item in record["export_files"]
        )

    ho_path = cql_attempt / "handoff.json"
    write_fixture_handoff(
        run_root,
        ho_path,
        {
            "job_id": "job_codeql_analysis",
            "attempt_id": "attempt_0001",
            "status": "ACCEPTED",
            "completion_status": "SUCCEEDED",
            "source_fingerprint": SNAPSHOT,
            "outputs": {
                "execution.scopes": outputs["execution.scopes"],
                "acceptance.publish_handoff": outputs["acceptance.publish_handoff"],
            },
            "artifacts": artifacts,
            "resolving_paths": {
                "attempt": cql_attempt.relative_to(run_root).as_posix(),
                "result": res_ref["path"],
            },
        },
    )
    ho_ref = _ref(ho_path)
    atomic_json(
        run_root / "data" / "jobs" / "job_codeql_analysis" / "latest.json",
        {
            "schema": "appsec-review/latest-handoff/1",
            "attempt_id": "attempt_0001",
            "handoff_path": ho_ref["path"],
            "handoff_sha256": ho_ref["sha256"],
        },
    )
    atomic_json(
        run_root / "data" / "indices" / "accepted.json",
        {
            "schema": "appsec-review/accepted-index-set/1",
            "run_id": staged.run_id,
            "handoff_path": ho_ref["path"],
            "handoff_sha256": ho_ref["sha256"],
            "manifest_path": manifest_ref["path"],
            "manifest_sha256": manifest_ref["sha256"],
        },
    )
    return staged


def _assert_security_tagging_observes_all_code_graph_shards(staged: Staged, handoff: Mapping[str, Any]) -> None:
    """Exercise AcceptedIndexes._open -> observe_shard (runtime/inputs.py:573-575) + index-shard custody."""
    from dataclasses import replace

    from appsec_review.jobs.job_security_tagging.datasets import CONTRACT as TAGGING_CONTRACT
    from appsec_review.jobs.job_security_tagging.producers import AcceptedIndexes
    from appsec_review.runtime.inputs import input_read_scope

    pub_manifest = (
        json.loads((staged.run_root / handoff["resolving_paths"]["result"]).read_text(encoding="utf-8"))
        ["outputs"]["acceptance.publish_handoff"]["index_manifest"]
    )
    consumer_contract = replace(
        TAGGING_CONTRACT,
        inputs=tuple(
            req
            for req in TAGGING_CONTRACT.inputs
            if req.producer in {JOB_ID, "job_codeql_analysis", "job_cpp_symbol_index"}
        ),
    )
    pins = _upstream_pins(staged.run_root)
    pins[JOB_ID] = str(
        json.loads((staged.run_root / "data" / "jobs" / JOB_ID / "latest.json").read_text(encoding="utf-8"))[
            "handoff_sha256"
        ]
    )
    tag_attempt = staged.run_root / "data" / "jobs" / "job_security_tagging" / "attempts" / "attempt_0001"
    metadata_root = staged.run_root / "metadata"
    metadata_root.mkdir(parents=True, exist_ok=True)
    consumer_ctx = JobContext(
        run_id=staged.run_id,
        attempt_id="attempt_0001",
        trigger="pytest",
        repository_root=ROOT,
        run_root=staged.run_root,
        attempt_root=tag_attempt,
        metadata_root=metadata_root,
        orchestration=MappingProxyType({"driver": "unit"}),
        config=staged.config.job("job_security_tagging"),
        events=EventLog(metadata_root / "security_tagging.events.jsonl"),
        target_root=staged.target,
        source_fingerprint=SNAPSHOT,
        upstream_handoffs=MappingProxyType(pins),
        contract=consumer_contract,
        review_policy=staged.config.review_policy,
        input_manifest_path=staged.run_root / pub_manifest["path"],
        input_manifest_sha256=pub_manifest["sha256"],
    )
    with input_read_scope(consumer_ctx):
        accepted_indexes = AcceptedIndexes(
            staged.run_root,
            manifest_path=staged.run_root / pub_manifest["path"],
            manifest_sha256=pub_manifest["sha256"],
        )
        own_shards = [
            shard for shard in accepted_indexes.identities if (shard.get("producer") or {}).get("job") == JOB_ID
        ]
        assert len(own_shards) == 10
        assert {shard["name"] for shard in own_shards} == {"graph", "analysis"}
        for shard in own_shards:
            with accepted_indexes._open(shard) as db:
                db.execute("SELECT COUNT(*) FROM entities").fetchone()


def test_job_runner_binds_code_graph_shards_and_alternate_cpg_across_fresh_and_reused_attempts(
    tmp_path: Path,
) -> None:
    from appsec_review.runtime.runner import JobRunner
    from appsec_review.storage.shared import verify_handoff, verify_receipt

    staged = _stage_single_scope_for_runner(tmp_path)
    runner = JobRunner(staged.config)

    first = runner.run(
        build_job(), run_id=staged.run_id, target_root=staged.target, source_fingerprint=SNAPSHOT
    )
    first_ho = first["handoff"]
    verify_handoff(staged.run_root, first_ho)
    first_result = json.loads((Path(first["attempt_root"]) / "result.json").read_text(encoding="utf-8"))
    pub_out = first_result["outputs"]["acceptance.publish_handoff"]
    manifest_doc, _ = load_verified_manifest(
        staged.run_root,
        staged.run_root / pub_out["index_manifest"]["path"],
        pub_out["index_manifest"]["sha256"],
    )
    own_shards = [item for item in manifest_doc["indexes"] if (item.get("producer") or {}).get("job") == JOB_ID]
    assert len(own_shards) == 10
    assert sum(1 for item in own_shards if item["name"] == "graph") == 9
    assert sum(1 for item in own_shards if item["name"] == "analysis" and item["shard_id"] == "alternate-cpg") == 1
    assert all(
        item["relative_path"].startswith(f"data/indices/{item['name']}/attempts/{JOB_ID}/attempt_0001/")
        for item in own_shards
    )

    bound = {(ref["path"], ref["sha256"]) for ref in first_ho["artifacts"]}
    for item in own_shards:
        assert (item["relative_path"], item["sha256"]) in bound
    first_receipt_objects = {
        (
            verify_receipt(staged.run_root, ref)["object"]["path"],
            verify_receipt(staged.run_root, ref)["object"]["sha256"],
        )
        for ref in first_ho["artifacts"]
        if ref["path"].startswith(f"data/jobs/{JOB_ID}/attempts/attempt_0001/shared/index-shard/")
    }
    assert {(item["relative_path"], item["sha256"]) for item in own_shards}.issubset(first_receipt_objects)

    alt_summary = json.loads((staged.run_root / pub_out["alternate_cpg"]["summary"]["path"]).read_text(encoding="utf-8"))
    for key in ("nodes", "edges", "paths"):
        jsonl_rel = alt_summary["artifacts"][key]
        assert jsonl_rel.endswith(f"cpg-{key}.jsonl")
        assert (jsonl_rel, file_sha256(staged.run_root / jsonl_rel)) in bound

    _assert_security_tagging_observes_all_code_graph_shards(staged, first_ho)

    # Second JobRunner attempt reuses attempt_0001's scope checkpoint and re-attests shard custody.
    second = runner.run(
        build_job(), run_id=staged.run_id, target_root=staged.target, source_fingerprint=SNAPSHOT
    )
    second_ho = second["handoff"]
    verify_handoff(staged.run_root, second_ho)
    second_result = json.loads((Path(second["attempt_root"]) / "result.json").read_text(encoding="utf-8"))
    assert second_result["outputs"]["correlate.scopes"]["reused_count"] == 1

    second_pub = second_result["outputs"]["acceptance.publish_handoff"]
    second_manifest, _ = load_verified_manifest(
        staged.run_root,
        staged.run_root / second_pub["index_manifest"]["path"],
        second_pub["index_manifest"]["sha256"],
    )
    second_own = [item for item in second_manifest["indexes"] if (item.get("producer") or {}).get("job") == JOB_ID]
    assert len(second_own) == 10
    second_bound = {(ref["path"], ref["sha256"]) for ref in second_ho["artifacts"]}
    for item in second_own:
        assert (item["relative_path"], item["sha256"]) in second_bound
    second_receipt_objects = {
        (
            verify_receipt(staged.run_root, ref)["object"]["path"],
            verify_receipt(staged.run_root, ref)["object"]["sha256"],
        )
        for ref in second_ho["artifacts"]
        if ref["path"].startswith(f"data/jobs/{JOB_ID}/attempts/attempt_0002/shared/index-shard/")
    }
    assert {(item["relative_path"], item["sha256"]) for item in second_own}.issubset(second_receipt_objects)

    _assert_security_tagging_observes_all_code_graph_shards(staged, second_ho)


def test_out_of_custody_checkpoint_not_reused_and_unbound_shard_handoff_rejected(tmp_path: Path) -> None:
    from appsec_review.jobs.job_code_graph_index.scopes import (
        CHECKPOINT_SCHEMA,
        reuse_checkpoint,
        scope_root,
    )
    from appsec_review.runtime.handoff import verify_handoff_integrity
    from appsec_review.runtime.runner import JobRunner

    # 1. Pre-fix Epoch-1 checkpoints pointing outside data/indices/ are skipped without deleting files.
    legacy_shard = (
        scope_root(tmp_path, "cpp-s1", "attempt_0001") / "indices" / "graph-cpp-s1-sink_site" / ("a" * 64 + ".sqlite")
    )
    legacy_shard.parent.mkdir(parents=True, exist_ok=True)
    legacy_shard.write_bytes(b"sqlite-placeholder")
    legacy_cp = scope_root(tmp_path, "cpp-s1", "attempt_0001") / "checkpoint.json"
    atomic_json(
        legacy_cp,
        {
            "schema": CHECKPOINT_SCHEMA,
            "identity": "ident-epoch1",
            "result": {
                "scope_id": "cpp-s1",
                "shards": [
                    {
                        "name": "graph",
                        "shard_id": "graph-cpp-s1-sink_site",
                        "relative_path": legacy_shard.relative_to(tmp_path).as_posix(),
                        "sha256": file_sha256(legacy_shard),
                    }
                ],
            },
        },
    )
    assert reuse_checkpoint(tmp_path, "cpp-s1", "ident-epoch1", attempt_id="attempt_0001") is None
    assert reuse_checkpoint(tmp_path, "cpp-s1", "ident-epoch1", attempt_id="attempt_0002") is None
    assert legacy_shard.is_file()

    # 2. verify_handoff_integrity rejects accepted handoffs missing a producer-owned manifest shard,
    #    even when all dataset declarations have required=False and result.json omits direct shard refs.
    run_dir = tmp_path / "runner"
    run_dir.mkdir()
    staged = _stage_single_scope_for_runner(run_dir)
    outcome = JobRunner(staged.config).run(
        build_job(), run_id=staged.run_id, target_root=staged.target, source_fingerprint=SNAPSHOT
    )
    handoff = dict(outcome["handoff"])
    res_path = staged.run_root / handoff["resolving_paths"]["result"]
    res_doc = json.loads(res_path.read_text(encoding="utf-8"))
    res_doc["outputs"]["acceptance.publish_handoff"].pop("shard_artifacts", None)
    res_doc["outputs"]["acceptance.publish_handoff"]["alternate_cpg"].pop("shard_artifact", None)
    res_path.write_bytes(json.dumps(res_doc).encode("utf-8"))
    new_res_ref = {
        "path": handoff["resolving_paths"]["result"],
        "sha256": file_sha256(res_path),
        "size_bytes": res_path.stat().st_size,
    }
    dropped = next(
        ref for ref in handoff["artifacts"]
        if ref["path"].startswith(f"data/indices/analysis/attempts/{JOB_ID}/") and ref["path"].endswith(".sqlite")
    )
    handoff["artifacts"] = [
        new_res_ref if ref["path"] == new_res_ref["path"] else ref
        for ref in handoff["artifacts"]
        if ref["path"] != dropped["path"]
    ]
    with pytest.raises(ValueError, match="published index shard is not bound in handoff artifacts"):
        verify_handoff_integrity(staged.run_root, handoff)
