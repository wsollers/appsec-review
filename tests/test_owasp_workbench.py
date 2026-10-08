from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.observability import PipelineLog
from appsec_review.config import load_config
from appsec_review.jobs.job_owasp_control_assessment import build_job
from appsec_review.owasp_workbench import (
    WorkbenchIndex, assess_batch, build_applicability, build_finding_packages,
    characterize_components, compose, control_records, deterministic_join,
    fingerprint_inputs, load_catalogs, partition_work, publish_manifest, publish_shard,
    select_profiles, standards_manifest, verify_results,
)
from appsec_review.owasp_workbench.standards import SUPPORTED_FAMILIES, digest


ROOT = Path(__file__).resolve().parents[1]
CATALOG_FILES = {
    "ASVS": "asvs-5.0.0.json", "MASVS": "masvs-2.1.0.json",
    "MASTG": "mastg-2.0.0.json", "OWASP_API_TOP_10": "api-top10-2023.json",
    "OWASP_TOP_10": "top10-2025.json",
}


def sources() -> dict:
    result = {}
    for family, name in CATALOG_FILES.items():
        path = ROOT / "data" / "reference" / "owasp" / "fixtures" / name
        document = json.loads(path.read_text(encoding="utf-8"))
        result[family] = {"catalog_path": path.relative_to(ROOT).as_posix(),
                          "catalog_sha256": digest(document), "version": document["version"],
                          **document["upstream"]}
    return result


def citation(name: str) -> dict:
    return {"source_identity": name, "artifact_sha256": hashlib.sha256(name.encode()).hexdigest(),
            "lines": [1, 2]}


def component(component_id: str, tags: list[str], paths: list[str] | None = None) -> dict:
    return {"target_id": "target-1", "project_id": "project-1", "component_id": component_id,
            "paths": paths or [f"{component_id}/main.txt"], "languages": [], "frameworks": [],
            "tags": tags, "evidence": [citation(f"component:{component_id}")]}


def prepared(components: list[dict], *, dynamic: bool = False):
    catalogs = load_catalogs(ROOT, sources())
    classifications = characterize_components(components)
    selection = select_profiles(catalogs, asvs_level=2, masvs_profile="L2")
    rows = build_applicability(catalogs, classifications, selection, dynamic_authorized=dynamic)
    return catalogs, classifications, selection, rows


def test_catalog_integrity_and_stable_control_identities() -> None:
    catalogs = load_catalogs(ROOT, sources())
    assert set(catalogs) == set(SUPPORTED_FAMILIES)
    first = control_records(catalogs, asvs_level=2, masvs_profile="L2")
    second = control_records(load_catalogs(ROOT, sources()), asvs_level=2, masvs_profile="L2")
    assert [item["control_identity"] for item in first] == [item["control_identity"] for item in second]
    assert all(item["control_identity"].startswith(("ASVS:5.0.0:", "MASVS:2.1.0:")) for item in first)
    manifest = standards_manifest(catalogs)
    assert manifest["fingerprint"] and all(source["upstream"]["commit"] for source in manifest["sources"])
    assert all("fixture" in gap for gap in manifest["gaps"])


def test_hash_or_authority_tampering_is_rejected() -> None:
    configured = sources()
    configured["ASVS"] = {**configured["ASVS"], "catalog_sha256": "0" * 64}
    with pytest.raises(ValueError, match="hash mismatch"):
        load_catalogs(ROOT, configured)


def test_central_toml_pins_the_verified_catalogs_and_profiles() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    settings = config.job("job_owasp_control_assessment").settings
    catalogs = load_catalogs(ROOT, settings["standards"])
    assert set(catalogs) == set(SUPPORTED_FAMILIES)
    assert settings["asvs_level"] == 2 and settings["masvs_profile"] == "L2"
    assert config.dagster.pool_limits["owasp_validator"] == 4
    assert config.dagster.pool_limits["owasp_verification"] == 2


def test_job_topology_exposes_independent_validation_cells_and_join_barrier() -> None:
    job = build_job()
    units = {unit.unit_id: unit for unit in job.units}
    cells = {f"validation.cell_0{index}" for index in range(1, 5)}
    assert cells <= set(units)
    assert all(units[cell].dependencies == ("batching.partition_work", "batching.build_packages")
               for cell in cells)
    assert set(units["verification.independent_review"].dependencies) == cells
    assert "verification.independent_review" in units["join.deterministic_join"].dependencies
    assert "join.deterministic_join" in units["publication.publish_indexes"].dependencies


def test_non_mobile_target_receives_no_applicable_masvs_controls() -> None:
    _, _, _, rows = prepared([component("server", ["server", "api"])])
    masvs = [row for row in rows if row["standard"] == "MASVS"]
    assert masvs and {row["outcome"] for row in masvs} == {"not_applicable"}
    assert all(row["evidence"] and row["reason"] for row in masvs)
    assert any(row["outcome"] == "applicable" for row in rows if row["standard"] == "ASVS")


def test_mixed_target_routes_asvs_and_masvs_to_different_components() -> None:
    _, _, _, rows = prepared([
        component("api", ["server", "api"]),
        component("android", ["android"], ["mobile/AndroidManifest.xml", "mobile/Main.kt"]),
    ], dynamic=True)
    applicable = {(row["standard"], row["component_id"]) for row in rows if row["outcome"] == "applicable"}
    assert ("ASVS", "api") in applicable and ("MASVS", "android") in applicable
    assert ("MASVS", "api") not in applicable and ("ASVS", "android") not in applicable


def test_ambiguous_component_routes_cannot_determine_not_na() -> None:
    _, classifications, _, rows = prepared([component("mystery", [], ["src/blob.xyz"])])
    assert classifications[0]["confidence"] == "low"
    assert {row["outcome"] for row in rows} == {"cannot_determine"}


def test_dynamic_obligation_is_explicit_missing_evidence() -> None:
    _, _, _, rows = prepared([component("android", ["android"], ["AndroidManifest.xml"])])
    network = next(row for row in rows if row["control_id"] == "MASVS-NETWORK-1")
    assert network["outcome"] == "unsupported_missing_evidence"
    assert network["gaps"]


def test_batch_limits_assignment_and_exact_dispatch_accounting() -> None:
    _, _, _, rows = prepared([component("api", ["server", "api"])])
    work = partition_work(rows, ROOT, max_batch_size=1, max_components=1)
    assert all(len(batch["row_ids"]) <= 1 and len(batch["component_ids"]) <= 1
               for batch in work["batches"])
    assert all(batch["assignment"]["role"] == "control_assessor" for batch in work["batches"])
    assigned = [row for batch in work["batches"] for row in batch["row_ids"]]
    expected = [row["row_id"] for row in rows if row["outcome"] == "applicable"]
    assert sorted(assigned) == sorted(expected) and len(assigned) == len(set(assigned))


def test_role_persona_composition_and_hash_invalidation() -> None:
    task = {"task_id": "task-1", "question": "Assess one bounded control.",
            "proof_obligations": ["one"], "prohibited_claims": ["uncited finding"]}
    first = compose(ROOT, role="control_assessor", persona="api_web", task=task)
    second = compose(ROOT, role="control_assessor", persona="api_web",
                     task={**task, "question": "Assess the changed bounded control."})
    assert first["sha256"] != second["sha256"]
    with pytest.raises(ValueError, match="bounded question"):
        compose(ROOT, role="control_assessor", persona="api_web", task={**task, "authority": "expand"})


def _packages(catalogs, classifications, selection, rows, *, contradictory=False):
    work = partition_work(rows, ROOT, max_batch_size=12, max_components=5)
    controls = control_records(catalogs, asvs_level=selection["policy"]["asvs_level"],
                               masvs_profile=selection["policy"]["masvs_profile"])
    evidence = []
    for row in rows:
        if row["outcome"] != "applicable":
            continue
        evidence.append({"component_id": row["component_id"], "control_id": row["control_id"],
                         "disposition": "supports", "citation": citation(f"evidence:{row['row_id']}")})
        if contradictory:
            evidence.append({"component_id": row["component_id"], "control_id": row["control_id"],
                             "disposition": "refutes", "citation": citation(f"counter:{row['row_id']}")})
    packages = {batch["batch_id"]: build_finding_packages(batch, rows, controls, classifications,
                evidence, retrieval_manifest={"sha256": "1" * 64}) for batch in work["batches"]}
    return work, packages


def test_worker_failure_becomes_gap_siblings_survive_and_failed_batch_resumes() -> None:
    catalogs, classifications, selection, rows = prepared([component("api", ["server", "api"])])
    work, packages = _packages(catalogs, classifications, selection, rows)
    assert len(work["batches"]) >= 2
    failed = assess_batch(work["batches"][0], packages[work["batches"][0]["batch_id"]], fail=True)
    sibling = assess_batch(work["batches"][1], packages[work["batches"][1]["batch_id"]])
    resumed = assess_batch(work["batches"][0], packages[work["batches"][0]["batch_id"]])
    assert failed["terminal_state"] == "failed" and sibling["terminal_state"] == "succeeded"
    assert resumed["terminal_state"] == "succeeded"
    assert resumed["fingerprint"] == failed["fingerprint"] == work["batches"][0]["fingerprint"]


def test_conflicts_preserved_and_elevated_model_claim_requires_independent_review() -> None:
    catalogs, classifications, selection, rows = prepared([component("api", ["server", "api"])])
    work, packages = _packages(catalogs, classifications, selection, rows, contradictory=True)
    batch = work["batches"][0]
    result = assess_batch(batch, packages[batch["batch_id"]], worker=lambda _package: {
        "observations": [{"observation_id": "obs-1", "severity": "High", "ship_blocking": True,
                          "summary": "untrusted model proposal"}]})
    verified = verify_results([result])
    assert verified[0]["status"] == "cannot_verify" and verified[0]["disagreements"]
    assert verified[0]["observations"][0]["state"] == "awaiting_independent_verification"


def test_join_is_complete_exactly_once_and_rejects_duplicate() -> None:
    catalogs, classifications, selection, rows = prepared([component("api", ["server", "api"])])
    work, packages = _packages(catalogs, classifications, selection, rows)
    batch_results = [assess_batch(batch, packages[batch["batch_id"]]) for batch in work["batches"]]
    verified = verify_results(batch_results)
    joined = deterministic_join(rows, verified)
    assert joined["accounting"] == {"selected": len(rows), "joined": len(rows), "exactly_once": True}
    with pytest.raises(ValueError, match="duplicate"):
        deterministic_join(rows, [*verified, verified[0]])


def test_unresolved_citation_cannot_be_promoted() -> None:
    with pytest.raises(ValueError, match="unresolved evidence citation"):
        verify_results([{"results": [{"row_id": "row", "status": "satisfied",
            "evidence_used": [{"source_identity": "x"}], "observations": [], "gaps": []}]}])


def test_run_isolated_scoped_index_retrieval_and_pagination(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    run_root = runs / "run-1"
    run_root.mkdir(parents=True)
    shard = publish_shard(run_root, family="applicability", shard_id="component-a",
        records=[{"standard": "ASVS", "version": "5.0.0", "profile": "L2",
                  "control_id": f"V{i}", "component_id": "component-a", "project_id": "p",
                  "outcome": "applicable", "evidence_mode": "static_source"} for i in range(3)],
        fingerprint_inputs={"component": "a"})
    publish_manifest(run_root, run_id="run-1", shards=[shard],
                     accepted_upstream_manifest={"sha256": "a" * 64},
                     configuration_sha256="b" * 64)
    query = WorkbenchIndex(runs, "run-1")
    first = query.query(family="applicability", standard="ASVS", component="component-a", limit=2)
    assert len(first["results"]) == 2 and first["pagination"]["truncated"]
    second = query.query(family="applicability", standard="ASVS", component="component-a",
                         limit=2, cursor=first["pagination"]["next_cursor"])
    assert len(second["results"]) == 1 and all(item["run_id"] == "run-1" for item in second["results"])
    with pytest.raises(ValueError, match="unavailable"):
        WorkbenchIndex(runs, "run-2")


def test_selective_invalidation_after_one_component_change() -> None:
    catalogs, classifications, selection, rows = prepared([
        component("api-a", ["server", "api"]), component("api-b", ["server", "api"])])
    work = partition_work(rows, ROOT)
    manifest = standards_manifest(catalogs)
    args = dict(standards=manifest, selection=selection, rows=rows, batches=work["batches"],
                retrieval_manifest={"sha256": "a" * 64}, configuration_sha256="b" * 64,
                guidance_bundle_sha256="c" * 64, model_identity={"model": "fake"},
                parser_versions={"rules": "1"})
    before = fingerprint_inputs(classifications=classifications, **args)
    changed_input = [component("api-a", ["server", "api", "auth"]), component("api-b", ["server", "api"])]
    _, changed_classifications, changed_selection, changed_rows = prepared(changed_input)
    changed_work = partition_work(changed_rows, ROOT)
    after = fingerprint_inputs(classifications=changed_classifications, standards=manifest,
        selection=changed_selection, rows=changed_rows, batches=changed_work["batches"],
        retrieval_manifest={"sha256": "a" * 64}, configuration_sha256="b" * 64,
        guidance_bundle_sha256="c" * 64, model_identity={"model": "fake"},
        parser_versions={"rules": "1"})
    assert before["components"]["api-b"] == after["components"]["api-b"]
    assert before["components"]["api-a"] != after["components"]["api-a"]


def test_central_log_redacts_queries_and_secrets(tmp_path: Path) -> None:
    log = PipelineLog(tmp_path / "run")
    log.write("MCP_TOOL_COMPLETED", run_id="run", details={
        "query_text": "sensitive search", "authorization": "Bearer secret", "tool_id": "find"})
    record = log.read()[0][0]
    assert record["details"]["query_text"] == "<redacted>"
    assert record["details"]["authorization"] == "<redacted>"


def test_finding_packages_are_bounded_and_do_not_embed_target_tree() -> None:
    catalogs, classifications, selection, rows = prepared([component("api", ["server", "api"])])
    work, packages = _packages(catalogs, classifications, selection, rows)
    package = next(iter(packages.values()))[0]
    assert "control" in package and "component" in package and "proof_obligations" in package
    assert "target_tree" not in json.dumps(package)
    assert package["allowed_retrieval_tools"]
