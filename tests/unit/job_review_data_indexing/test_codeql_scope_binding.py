"""CodeQL's unchanged Python normalizer must feed build-unit coverage through admitted metadata."""

from dataclasses import asdict, replace
import json
import hashlib
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_codeql_analysis.datasets import DATASETS as CODEQL_DATASETS
from appsec_review.jobs.job_codeql_analysis import job as codeql
from appsec_review.jobs.job_codeql_analysis.planning import CodeQLPlan, CodeQLScope, PLAN_SCHEMA, SCOPE_SCHEMA
from appsec_review.jobs.job_language_build.datasets import DATASETS as BUILD_DATASETS
from appsec_review.jobs.job_target_catalog.datasets import DATASETS as CATALOG_DATASETS
from appsec_review.jobs.job_review_data_indexing.job import JOB_ID, PRODUCT_SETS, build_job
from appsec_review.jobs.job_review_data_indexing.datasets import CONTRACT
from appsec_review.retrieval import EntityKind
from appsec_review.runtime import UnitContext
from appsec_review.runtime.consume import upstream_scope
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.runtime.runner import JobRunner
from appsec_review.config import load_config
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from appsec_review.storage.shared import SharedArtifacts, attempt_artifacts, publication_scope_for_owner, reference
from tests.handoff_fixture import _freeze_configuration, write_fixture_handoff
from tests.unit.job_codeql_analysis.test_handlers import _make_unit
from tests.unit.job_review_data_indexing.test_audit_semantics import SNAPSHOT, _entity, _shard


CODEQL = "job_codeql_analysis"


def _case(tmp_path, monkeypatch, *, build_unit="u1", mutation=None, succeeded=False):
    producer = _make_unit(tmp_path, fp=SNAPSHOT)
    producer.unit_id = "execution.scopes"
    run = producer.job.run_root
    path = run / f"data/jobs/{CODEQL}/attempts/attempt_0001/handoff.json"
    resolved_sha, _ = _freeze_configuration(run, CODEQL)
    producer.job.attempt_id = path.parent.name
    producer.job.config.job_id = CODEQL
    settings = producer.job.config.typed_settings
    producer.job.config.typed_settings = replace(
        settings, concurrency=1, threads=1, ram_mb=2048, preinstalled_runtimes=(),
        languages={**settings.languages, "python": replace(
            settings.languages["python"], additional_queries=(), custom_queries=())},
        export_queries=replace(settings.export_queries, enabled=False))
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
        "scope": asdict(scope),
        "database_identity": "d" * 64, "query_identity": "e" * 64,
        "terminal_status": "SUCCEEDED" if succeeded else "FAILED", "gaps": [] if succeeded else ["query failed"],
        "argv": ["not-for-the-domain-payload"], "stdout": "private engine output",
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
    plan_path = path.parent / "artifacts/codeql/plan.json"
    atomic_json(plan_path, CodeQLPlan(PLAN_SCHEMA, SNAPSHOT, ("python",), (scope,), (), ()).as_dict())
    producer._stored["plan.inventory"] = {"plan": reference(run, plan_path)}
    build_path = run / "data/jobs/job_language_build/attempts/attempt_0001/artifacts/receipts.json"
    atomic_json(build_path, {"schema": "appsec-review/language-build-handoff/2",
                            "source_fingerprint": SNAPSHOT, "receipts": [{"build_unit_id": build_unit}]})
    build_handoff = build_path.parent.parent / "handoff.json"
    atomic_json(build_handoff.with_name("claim.json"), {"dataset_contract": dataset_contract(
        "job_language_build", sorted({item.step for item in BUILD_DATASETS}), BUILD_DATASETS)})
    write_fixture_handoff(run, build_handoff, {
        "job_id": "job_language_build", "source_fingerprint": SNAPSHOT,
        "outputs": {"acceptance.publish_handoff": {"artifact": reference(run, build_path)}}})
    atomic_json(build_handoff.parent.parent.parent / "latest.json", {
        "handoff_path": build_handoff.relative_to(run).as_posix(), "handoff_sha256": file_sha256(build_handoff)})
    # Only engine execution is fake: use the real scheduler, normalizer, publisher and control projection.
    monkeypatch.setattr(codeql, "_database_isolated", lambda unit, scope, receipts: {
        "scope": asdict(scope), "database_identity": "d" * 64, "terminal_status": "SUCCEEDED", "gaps": []})
    monkeypatch.setattr(codeql, "_query_one", lambda unit, database, profile: {**query, "query_profile": profile})
    execute = next(unit for unit in codeql.build_job().units if unit.unit_id == "execution.scopes")
    owner = SharedArtifacts.for_job(producer.job)
    producer.job.upstream_handoffs = {"job_language_build": file_sha256(build_handoff)}
    with publication_scope_for_owner(owner), upstream_scope(
            run, CODEQL, producer.job.upstream_handoffs, contract=codeql.CONTRACT):
        execution_output = execute.handler(producer)
    normalized, = execution_output["scopes"]
    # Do not patch the producer or backfill the fields missing from its actual wire format.
    actual_shard = normalized["index_identity"]
    assert "scope_id" not in actual_shard["producer"]
    assert "build_unit_id" not in actual_shard["producer"]
    if mutation not in {None, "tamper", "member", "missing"} and "artifact" in execution_output:
        payload_path = run / execution_output["artifact"]["path"]
        payload = json.loads(payload_path.read_text())
        admitted = payload["scopes"][0]
        if mutation == "hash":
            admitted["index_identity"]["sha256"] = "0" * 64
        elif mutation == "path":
            admitted["index_identity"]["relative_path"] = "data/indices/observations/foreign.sqlite"
        elif mutation == "scope":
            admitted["scope"]["scope_id"] = "different-scope"
        elif mutation == "target":
            payload["source_fingerprint"] = "foreign-target"
        elif mutation == "run":
            payload["run_id"] = "foreign-run"
        elif mutation == "attempt":
            payload["attempt_id"] = "attempt_9999"
        elif mutation == "count":
            payload["scope_count"] += 1
        elif mutation == "conflict":
            payload["scopes"].append({**admitted, "scope": {**admitted["scope"], "build_unit_id": "u2"}})
            payload["scope_count"] += 1
            payload["indexed_scope_count"] += 1
        payload_path = payload_path.with_name(
            f"execution-result-{hashlib.sha256(canonical_json(payload)).hexdigest()}.json")
        atomic_json(payload_path, payload)
        execution_output["artifact"] = reference(run, payload_path)
    if mutation == "missing":
        execution_output.pop("artifact", None)
    write_fixture_handoff(run, path, {
        "job_id": CODEQL, "attempt_id": "attempt_0001",
        "source_fingerprint": SNAPSHOT,
        "completion_status": "COMPLETED_WITH_GAPS",
        "artifacts": [normalized["index"], *attempt_artifacts(run, path.parent)],
        "outputs": {"execution.scopes": execution_output},
    })
    prior = json.loads(path.read_text())
    claim = json.loads(path.with_name("claim.json").read_text())
    claim.update(component_identities={"implementation": "unit/1", "schema": "unit/1", "validation": "unit/1"},
                 started_at=prior["started_at"], job_config_sha256=prior["job_config_sha256"])
    projected = JobRunner(load_config(producer.job.repository_root / "appsec-review.toml"))._handoff_document(
        producer.job, claim, {"status": "COMPLETED_WITH_GAPS", "outputs": {"execution.scopes": execution_output}},
        json.loads(path.with_name("outcomes.json").read_text()), prior["outcomes"],
        accepted=True, completed=prior["completed_at"], artifacts=prior["artifacts"])
    assert "scopes" not in projected["outputs"]["execution.scopes"]
    atomic_json(path, projected)
    atomic_json(path.parent.parent.parent / "latest.json", {
        "handoff_path": path.relative_to(run).as_posix(), "handoff_sha256": file_sha256(path)})
    catalog = _shard(run, "build", "catalog-units", "job_target_catalog",
                     [_entity(EntityKind.BUILD_ACTION, unit, {"build_unit_id": unit}) for unit in ("u1", "u2")])
    catalog_handoff = run / "data/jobs/job_target_catalog/attempts/attempt_0001/handoff.json"
    atomic_json(catalog_handoff.with_name("claim.json"), {"dataset_contract": dataset_contract(
        "job_target_catalog", sorted({item.step for item in CATALOG_DATASETS}), CATALOG_DATASETS)})
    write_fixture_handoff(run, catalog_handoff, {
        "job_id": "job_target_catalog", "source_fingerprint": SNAPSHOT,
        "artifacts": [reference(run, run / catalog["relative_path"])]})
    atomic_json(catalog_handoff.parent.parent.parent / "latest.json", {
        "handoff_path": catalog_handoff.relative_to(run).as_posix(), "handoff_sha256": file_sha256(catalog_handoff)})
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
        SimpleNamespace(run_root=run, tools=SimpleNamespace(enable_swift=False),
                        config=SimpleNamespace(job_id=JOB_ID), contract=CONTRACT,
                        producer_fixture=producer, execution_output=execution_output), "matrix.coverage",
        "matrix", "coverage", task_root, outputs)
    pins = {CODEQL: file_sha256(path), "job_target_catalog": file_sha256(catalog_handoff)}
    if mutation == "tamper" and "artifact" in execution_output:
        (run / execution_output["artifact"]["path"]).write_text("{}")
    if mutation == "member":
        (run / actual_shard["relative_path"]).write_bytes(b"changed member")
    return context, normalized, pins


def _coverage(context, pins):
    unit = next(unit for unit in build_job().units if unit.unit_id == "matrix.coverage")
    context.job.upstream_handoffs = pins
    with input_read_scope(context.job) as reads:
        output = unit.handler(context)
    context.job.reads = reads.document()["reads"]
    return json.loads((context.job.run_root / output["artifact"]["path"]).read_text())


@pytest.mark.parametrize("build_unit", ["u1", "u2"])
def test_real_normalizer_failure_is_bound_to_exact_admitted_build_unit(tmp_path, monkeypatch, build_unit):
    context, normalized, pins = _case(tmp_path, monkeypatch, build_unit=build_unit)
    result = _coverage(context, pins)
    cells = {row["build_unit_id"]: row["lanes"]["codeql"] for row in result["build_units"]}
    selected = cells[build_unit]
    assert selected["count"] == 1
    assert selected["state"] == "unavailable"
    assert selected["shards"] == [normalized["index_identity"]["shard_id"]]
    assert any("query failed" in gap for gap in selected["gaps"])
    assert cells["u2" if build_unit == "u1" else "u1"]["count"] == 0
    assert "opaque-scope-1729" not in cells


def test_real_successful_normalizer_keeps_complete_unit_coverage(tmp_path, monkeypatch):
    context, normalized, pins = _case(tmp_path, monkeypatch, succeeded=True)
    assert normalized["observation_count"] == 1 and normalized["gaps"] == []
    result = _coverage(context, pins)
    cells = {row["build_unit_id"]: row["lanes"]["codeql"] for row in result["build_units"]}
    assert cells["u1"]["state"] == "complete" and cells["u1"]["count"] == 1
    assert cells["u1"]["shards"] == [normalized["index_identity"]["shard_id"]]
    assert cells["u1"]["gaps"] == []
    assert cells["u2"]["count"] == 0


@pytest.mark.parametrize("mutation", ["hash", "path", "target", "scope", "conflict", "run", "attempt", "count"])
def test_foreign_or_conflicting_scope_metadata_cannot_bind_a_build_unit(tmp_path, monkeypatch, mutation):
    context, _, pins = _case(tmp_path, monkeypatch, mutation=mutation)
    if mutation in {"hash", "path"}:
        result = _coverage(context, pins)
        assert all(row["lanes"]["codeql"]["count"] == 0 for row in result["build_units"])
        assert result["languages"][0]["lanes"]["codeql"]["state"] == "unavailable"
    else:
        with pytest.raises(ValueError, match="CodeQL.*(snapshot|scope|conflict)"):
            _coverage(context, pins)


def test_source_only_scope_does_not_invent_a_build_unit(tmp_path, monkeypatch):
    context, normalized, pins = _case(tmp_path, monkeypatch, build_unit=None)
    result = _coverage(context, pins)
    assert {row["build_unit_id"] for row in result["build_units"]} == {"u1", "u2"}
    assert all(row["lanes"]["codeql"]["count"] == 0 for row in result["build_units"])
    assert result["languages"][0]["lanes"]["codeql"]["shards"] == [normalized["index_identity"]["shard_id"]]


def test_unsupplied_codeql_handoff_cannot_supply_scope_bindings(tmp_path, monkeypatch):
    context, _, pins = _case(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="unsupplied"):
        _coverage(context, {key: value for key, value in pins.items() if key != CODEQL})


@pytest.mark.parametrize("mutation", ["tamper", "missing", "member"])
def test_domain_payload_must_be_pinned_and_unchanged(tmp_path, monkeypatch, mutation):
    context, _, pins = _case(tmp_path, monkeypatch, mutation=mutation)
    with pytest.raises(ValueError):
        _coverage(context, pins)


def test_domain_payload_and_member_reads_are_recorded_without_private_data(tmp_path, monkeypatch):
    context, normalized, pins = _case(tmp_path, monkeypatch)
    _coverage(context, pins)
    reference = context.job.execution_output["artifact"]
    payload = json.loads((context.job.run_root / reference["path"]).read_text())
    assert payload["scope_count"] == payload["indexed_scope_count"] == 1
    assert set(payload["scopes"][0]) == {"scope", "terminal_status", "index_identity"}
    assert set(payload["scopes"][0]["scope"]) == {"scope_id", "language", "build_unit_id"}
    assert "not-for-the-domain-payload" not in json.dumps(payload)
    assert "private engine output" not in json.dumps(payload)
    assert context.job.execution_output["scopes"][0]["argv"] == ["not-for-the-domain-payload"]
    assert any(row["output_kind"] == "codeql_plan_and_summary" and row["path"] == reference["path"]
               and row["sha256"] == reference["sha256"] and row["handoff_sha256"] == pins[CODEQL]
               for row in context.job.reads)
    assert any(row["output_kind"] == "codeql_observations"
               and row["sha256"] == normalized["index_identity"]["sha256"] for row in context.job.reads)


def test_handoff_permission_does_not_grant_domain_payload_permission(tmp_path, monkeypatch):
    context, _, pins = _case(tmp_path, monkeypatch)
    context.job.contract = replace(CONTRACT, inputs=tuple(
        item for item in CONTRACT.inputs
        if (item.producer, item.output_kind) != (CODEQL, "codeql_plan_and_summary")))
    with pytest.raises(ValueError, match="undeclared consumption.*codeql_plan_and_summary"):
        _coverage(context, pins)


def test_execution_domain_is_immutable_and_attempt_owned(tmp_path, monkeypatch):
    from copy import copy, deepcopy

    context, _, _ = _case(tmp_path, monkeypatch)
    first = context.job.producer_fixture
    run = first.job.run_root
    original = context.job.execution_output["artifact"]
    before = (run / original["path"]).read_bytes()
    execute = next(unit for unit in codeql.build_job().units if unit.unit_id == "execution.scopes")

    def publish(producer):
        with publication_scope_for_owner(SharedArtifacts.for_job(producer.job)), upstream_scope(
                run, CODEQL, producer.job.upstream_handoffs, contract=codeql.CONTRACT):
            return execute.handler(producer)

    assert publish(first)["artifact"] == original
    monkeypatch.setattr(codeql, "_query_one", lambda unit, database, profile: {
        "scope": database["scope"], "database_identity": database["database_identity"],
        "query_identity": "f" * 64, "query_profile": profile,
        "terminal_status": "FAILED", "gaps": ["a different query failure"]})
    changed = publish(first)
    assert changed["artifact"]["path"] != original["path"]
    assert (run / original["path"]).read_bytes() == before
    second = copy(first)
    second.job = copy(first.job)
    second.job.attempt_id = "attempt_0002"
    second.job.attempt_root = first.job.attempt_root.with_name(second.job.attempt_id)
    second._stored = deepcopy(first._stored)
    second.output = lambda name: second._stored[name]
    claim = json.loads((first.job.attempt_root / "claim.json").read_text())
    claim.update(attempt_id=second.job.attempt_id,
                 attempt_path=second.job.attempt_root.relative_to(run).as_posix())
    atomic_json(second.job.attempt_root / "claim.json", claim)
    plan = second.job.attempt_root / "artifacts/codeql/plan.json"
    atomic_json(plan, json.loads((run / first._stored["plan.inventory"]["plan"]["path"]).read_text()))
    second._stored["plan.inventory"]["plan"] = reference(run, plan)
    output = publish(second)
    assert output["artifact"]["path"].startswith(
        "data/jobs/job_codeql_analysis/attempts/attempt_0002/artifacts/codeql/")
    assert (run / original["path"]).read_bytes() == before
    assert output["artifact"]["path"] != original["path"]
    assert output["scopes"][0]["index_identity"] == changed["scopes"][0]["index_identity"]
