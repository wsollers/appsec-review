"""CodeQL's unchanged Python normalizer must feed build-unit coverage through admitted metadata."""

from copy import deepcopy
from contextlib import nullcontext
from dataclasses import asdict
import json
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_codeql_analysis.datasets import DATASETS as CODEQL_DATASETS
from appsec_review.jobs.job_codeql_analysis.job import _normalize_one
from appsec_review.jobs.job_codeql_analysis.planning import CodeQLScope, SCOPE_SCHEMA
from appsec_review.jobs.job_review_data_indexing.job import JOB_ID, PRODUCT_SETS, build_job
from appsec_review.retrieval import EntityKind
from appsec_review.runtime import UnitContext
from appsec_review.runtime.consume import upstream_scope
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import SharedArtifacts, attempt_artifacts, publication_scope_for_owner, reference
from tests.handoff_fixture import _freeze_configuration, write_fixture_handoff
from tests.unit.job_codeql_analysis.test_handlers import _make_unit
from tests.unit.job_review_data_indexing.test_audit_semantics import SNAPSHOT, _entity, _shard


CODEQL = "job_codeql_analysis"


def _case(tmp_path, *, build_unit="u1", mutation=None, succeeded=False):
    producer = _make_unit(tmp_path, fp=SNAPSHOT)
    producer.unit_id = "execution.scopes"
    run = producer.job.run_root
    path = run / f"data/jobs/{CODEQL}/attempts/attempt_0001/handoff.json"
    resolved_sha, _ = _freeze_configuration(run, CODEQL)
    producer.job.attempt_id = path.parent.name
    producer.job.config.job_id = CODEQL
    producer.job.orchestration = {"system": "unit", "run_id": "codeql-scope-binding"}
    atomic_json(path.with_name("claim.json"), {
        "schema": "appsec-review/attempt-claim/1", "run_id": run.name, "job_id": CODEQL,
        "attempt_id": path.parent.name, "attempt_path": path.parent.relative_to(run).as_posix(),
        "source_fingerprint": SNAPSHOT, "orchestration": producer.job.orchestration,
        "resolved_config_sha256": resolved_sha, "input_identity": None, "upstream_handoffs": {},
        "dataset_contract": dataset_contract(CODEQL, ["plan", "execution", "acceptance"], CODEQL_DATASETS)})
    source = producer.job.target_root / "app.py"
    source.write_text("value = 1\n")
    scope = CodeQLScope(SCOPE_SCHEMA, "opaque-scope-1729", "python", ("Python",), "none", ".",
                        ({"path": "app.py", "sha256": file_sha256(source), "size_bytes": source.stat().st_size},),
                        build_unit, None, "inert-environment", False)
    query = {
        "scope": asdict(scope), "query_profile": {"query_id": "security", "kind": "default"},
        "database_identity": "d" * 64, "query_identity": "e" * 64,
        "terminal_status": "SUCCEEDED" if succeeded else "FAILED", "gaps": [] if succeeded else ["query failed"],
    }
    if succeeded:
        sarif = run / "data/codeql/scopes/opaque-scope-1729/queries/security/results.sarif"
        atomic_json(sarif, {"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "fixture"}}, "results": [{
                "ruleId": "py/fixture", "message": {"text": "inert observation"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 1, "endLine": 1, "startColumn": 1, "endColumn": 6}}}],
            }],
        }]})
        execution = sarif.parent / "executions/query/receipt.json"
        atomic_json(execution, {"status": "SUCCEEDED", "fixture": "no engine was executed"})
        query.update(sarif=reference(run, sarif), query_execution=reference(run, execution))
    owner = SharedArtifacts.for_job(producer.job)
    with publication_scope_for_owner(owner) if succeeded else nullcontext():
        normalized = _normalize_one(producer, query)
    # Do not patch the producer or backfill the fields missing from its actual wire format.
    actual_shard = normalized["index_identity"]
    assert "scope_id" not in actual_shard["producer"]
    assert "build_unit_id" not in actual_shard["producer"]
    admitted = deepcopy(normalized)
    if mutation == "hash":
        admitted["index_identity"]["sha256"] = "0" * 64
    elif mutation == "path":
        admitted["index_identity"]["relative_path"] = "data/indices/observations/foreign.sqlite"
    elif mutation == "scope":
        admitted["scope"]["scope_id"] = "different-scope"
    scopes = [admitted]
    if mutation == "conflict":
        scopes.append({**admitted, "scope": {**admitted["scope"], "build_unit_id": "u2"}})
    write_fixture_handoff(run, path, {
        "job_id": CODEQL, "attempt_id": "attempt_0001",
        "source_fingerprint": "foreign-target" if mutation == "target" else SNAPSHOT,
        "completion_status": "COMPLETED_WITH_GAPS",
        "artifacts": [normalized["index"], *attempt_artifacts(run, path.parent)],
        "outputs": {"execution.scopes": {
            "scopes": scopes, "gaps": normalized["gaps"], "terminal_status": "COMPLETED_WITH_GAPS",
        }},
    })
    atomic_json(path.parent.parent.parent / "latest.json", {
        "handoff_path": path.relative_to(run).as_posix(), "handoff_sha256": file_sha256(path)})
    catalog = _shard(run, "build", "catalog-units", "job_target_catalog",
                     [_entity(EntityKind.BUILD_ACTION, unit, {"build_unit_id": unit}) for unit in ("u1", "u2")])
    document = run / "data/inputs-fixture.json"
    atomic_json(document, {
        "target_snapshot": SNAPSHOT, "shards": [catalog, actual_shard], "restored_shards": [],
        "registry_jobs": [CODEQL, JOB_ID], "registered_jobs": [CODEQL, JOB_ID],
        "handoffs": {CODEQL: {"sha256": file_sha256(path)}}, "consumes": {JOB_ID: [CODEQL]},
    })
    inventory = run / "data/inventory-fixture.json"
    atomic_json(inventory, {"rows": []})
    outputs = {
        "load.accepted_inputs": {"artifact": {"path": document.relative_to(run).as_posix(),
                                             "sha256": file_sha256(document)}},
        "audit.inventory": {"artifact": {"path": inventory.relative_to(run).as_posix(),
                                         "sha256": file_sha256(inventory)}},
        **{f"precompute.{name}": {"status": "unavailable", "gaps": [], "counts": {}} for name in PRODUCT_SETS},
    }
    task_root = run / f"data/jobs/{JOB_ID}/attempts/attempt_0001/steps/matrix/tasks/coverage"
    task_root.mkdir(parents=True)
    context = UnitContext(
        SimpleNamespace(run_root=run, tools=SimpleNamespace(enable_swift=False)), "matrix.coverage",
        "matrix", "coverage", task_root, outputs)
    pins = {CODEQL: file_sha256(path)}
    return context, normalized, pins


def _coverage(context, pins):
    from appsec_review.jobs.job_review_data_indexing.datasets import CONTRACT
    unit = next(unit for unit in build_job().units if unit.unit_id == "matrix.coverage")
    with upstream_scope(context.job.run_root, JOB_ID, pins, contract=CONTRACT):
        output = unit.handler(context)
    return json.loads((context.job.run_root / output["artifact"]["path"]).read_text())


@pytest.mark.parametrize("build_unit", ["u1", "u2"])
def test_real_normalizer_failure_is_bound_to_exact_admitted_build_unit(tmp_path, build_unit):
    context, normalized, pins = _case(tmp_path, build_unit=build_unit)
    result = _coverage(context, pins)
    cells = {row["build_unit_id"]: row["lanes"]["codeql"] for row in result["build_units"]}
    selected = cells[build_unit]
    assert selected["count"] == 1
    assert selected["state"] == "unavailable"
    assert selected["shards"] == [normalized["index_identity"]["shard_id"]]
    assert any("query failed" in gap for gap in selected["gaps"])
    assert cells["u2" if build_unit == "u1" else "u1"]["count"] == 0
    assert "opaque-scope-1729" not in cells


def test_real_successful_normalizer_keeps_complete_unit_coverage(tmp_path):
    context, normalized, pins = _case(tmp_path, succeeded=True)
    assert normalized["observation_count"] == 1 and normalized["gaps"] == []
    result = _coverage(context, pins)
    cells = {row["build_unit_id"]: row["lanes"]["codeql"] for row in result["build_units"]}
    assert cells["u1"]["state"] == "complete" and cells["u1"]["count"] == 1
    assert cells["u1"]["shards"] == [normalized["index_identity"]["shard_id"]]
    assert cells["u1"]["gaps"] == []
    assert cells["u2"]["count"] == 0


@pytest.mark.parametrize("mutation", ["hash", "path", "target", "scope", "conflict"])
def test_foreign_or_conflicting_scope_metadata_cannot_bind_a_build_unit(tmp_path, mutation):
    context, _, pins = _case(tmp_path, mutation=mutation)
    if mutation in {"hash", "path"}:
        result = _coverage(context, pins)
        assert all(row["lanes"]["codeql"]["count"] == 0 for row in result["build_units"])
        assert result["languages"][0]["lanes"]["codeql"]["state"] == "unavailable"
    else:
        with pytest.raises(ValueError, match="CodeQL.*(snapshot|scope|conflict)"):
            _coverage(context, pins)


def test_source_only_scope_does_not_invent_a_build_unit(tmp_path):
    context, normalized, pins = _case(tmp_path, build_unit=None)
    result = _coverage(context, pins)
    assert {row["build_unit_id"] for row in result["build_units"]} == {"u1", "u2"}
    assert all(row["lanes"]["codeql"]["count"] == 0 for row in result["build_units"])
    assert result["languages"][0]["lanes"]["codeql"]["shards"] == [normalized["index_identity"]["shard_id"]]


def test_unsupplied_codeql_handoff_cannot_supply_scope_bindings(tmp_path):
    context, _, _ = _case(tmp_path)
    result = _coverage(context, {})
    assert all(row["lanes"]["codeql"]["count"] == 0 for row in result["build_units"])
