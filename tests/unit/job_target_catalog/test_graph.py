from __future__ import annotations

from pathlib import Path
import json
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_target_catalog import job as catalog
from tests.unit.job_target_catalog.support import (
    COMPILE, COMPONENTS, DEPENDENCIES, INDEX_UNITS, PARTITION, PROJECTS, SYSTEMS, TARGETS,
    context,
)


def _catalog_repair_projection(tmp_path, openapi_raw):
    from appsec_review.interchange import validate_unit_output
    from appsec_review.jobs.job_target_analysis_plan import build_job as plan_job
    from appsec_review.jobs.job_target_catalog.reader import load_accepted_catalog
    from appsec_review.retrieval import RetrievalCore
    from appsec_review.runtime.datasets import dataset_contract
    from appsec_review.runtime.inputs import admit_inputs, input_read_scope
    from appsec_review.runtime.runner import JobRunner
    from appsec_review.storage import atomic_json, file_sha256
    from appsec_review.storage.shared import SharedArtifacts, attempt_artifacts, publication_scope_for_owner
    from tests.handoff_fixture import write_fixture_handoff
    from tests.unit.job_target_catalog.support import source

    unit = context(tmp_path, PARTITION)
    unit.job.run_root = tmp_path / "2026-11-20-5196"
    unit.job.attempt_root = unit.job.run_root / "data/jobs/job_target_catalog/attempts/attempt_0001"
    repository = tmp_path / "repository"
    repository.mkdir()
    unit.job.repository_root = repository
    unit.job.config.inventory_max_file_bytes = 80_000
    unit.job.config.job_id = "job_target_catalog"
    unit.job.run_id = unit.job.run_root.name
    unit.job.orchestration = {}
    source(unit, "build.gradle", (
        b"plugins { id 'com.android.application' }\nandroid { compileSdk 35 }\n"
        + b"// padding\n" * 7000), None)
    source(unit, "bad/package.json", b"[]", None)
    source(unit, "good/package.json", b'{"dependencies":{"good":"^1"}}', None)
    raw = "# café\r\ndef present():\r\n    pass\r\n".encode()
    entry = source(unit, "present.py", raw)
    source(unit, "omitted.py", b"def omitted():\n" + b"# padding\n" * 9000)
    api_entry = source(unit, "openapi.json", openapi_raw, None)
    root, attempt = unit.job.run_root, unit.job.attempt_root
    job = catalog.build_job()
    atomic_json(attempt / "claim.json", {
        "dataset_contract": dataset_contract(
            job.job_id, tuple(catalog.TOPOLOGY), job.datasets, job_contract=job.contract.document()),
        "orchestration": {},
    })
    identity = {"job_id": job.job_id, "source_fingerprint": unit.job.source_fingerprint,
                "schema_identity": job.schema_identity}
    write_fixture_handoff(root, attempt / "handoff.json", identity)
    with publication_scope_for_owner(SharedArtifacts.for_job(unit.job)):
        for task in job.units:
            unit.unit_id = task.unit_id
            unit.outputs[task.unit_id] = task.handler(unit)
            validate_unit_output(unit.outputs[task.unit_id], unit_id=task.unit_id, strict_gaps=True)
    (attempt / "result.json").unlink()
    handoff_path = write_fixture_handoff(root, attempt / "handoff.json", {
        **identity, "completion_status": "COMPLETED_WITH_GAPS",
        "outputs": unit.outputs, "artifacts": attempt_artifacts(root, attempt),
    })
    provisional = json.loads(handoff_path.read_bytes())
    claim = json.loads((attempt / "claim.json").read_bytes())
    claim.update(component_identities={"implementation": "unit/1", "schema": job.schema_identity,
                                       "validation": "unit/1"},
                 started_at=provisional["started_at"], job_config_sha256=provisional["job_config_sha256"])
    projected = JobRunner(load_config(Path(__file__).resolve().parents[3] / "appsec-review.toml"))._handoff_document(
        unit.job, claim, {"status": "COMPLETED_WITH_GAPS", "outputs": unit.outputs},
        json.loads((attempt / "outcomes.json").read_bytes()), provisional["outcomes"],
        accepted=True, completed=provisional["completed_at"], artifacts=provisional["artifacts"])
    atomic_json(handoff_path, projected)
    digest = file_sha256(handoff_path)
    atomic_json(root / "data/jobs/job_target_catalog/latest.json", {
        "handoff_path": handoff_path.relative_to(root).as_posix(), "handoff_sha256": digest})
    assert "targets" not in projected["outputs"][TARGETS]
    consumer = SimpleNamespace(
        run_root=root, target_root=unit.job.target_root, repository_root=repository,
        source_fingerprint=unit.job.source_fingerprint,
        evidence_target_snapshot=unit.job.source_fingerprint,
        config=SimpleNamespace(job_id="job_target_analysis_plan"),
        contract=plan_job().contract, upstream_handoffs={job.job_id: digest},
        optional_prior_handoffs={}, external_input_selection=None,
    )
    admit_inputs(consumer, {job.job_id})
    with input_read_scope(consumer) as reads:
        accepted = load_accepted_catalog(root)
    observations = reads.document()["reads"]
    assert len(observations) == 8
    assert {row["output_kind"] for row in observations} == {"handoff", "catalog_documents"}
    assert all(row["handoff_sha256"] == digest and row["read"] and row["cited"] is None
               for row in observations)
    assert accepted["catalog_handoff_sha256"] == digest
    android = next(build for build in accepted["build_units"] if build["build_system"] == "gradle")
    assert android["required_image_profile"] == "android"
    assert android["descriptor_facts"]["compile_sdk"] == "35"
    assert android["descriptor_package"]["documents"] == []
    assert any("omitted.py" in gap["path"] for gap in accepted["gaps"] if isinstance(gap, dict))
    dependencies = unit.outputs[DEPENDENCIES]
    assert [item["name"] for item in dependencies["dependencies"]] == ["good"]
    assert any(gap["code"] == "parser_error" for gap in dependencies["gaps"])
    published = unit.outputs["publish_catalog.publish_handoff"]
    core = RetrievalCore(root.parent, root.name, manifest_path=root / published["index_manifest"]["path"],
                         manifest_sha256=published["index_manifest"]["sha256"])
    [coverage] = core.coverage(indexes=["analysis"])["results"]
    assert coverage["coverage"][0]["status"] == "partial"
    assert coverage["coverage"][0]["gap"] == unit.outputs[INDEX_UNITS[1]]["gaps"][0]["gap_id"]
    [symbol] = core.find(indexes=["analysis"], kind="symbol", name="present")["results"]
    location = symbol["location"]
    assert location["file_sha256"] == entry["sha256"]
    assert raw[location["start_byte"]:location["end_byte"]] == b"def present():\r\n"
    assert len(core.find(indexes=["documents"], kind="document_record")["results"]) == 2
    return core, api_entry


def test_catalog_repairs_reach_admitted_reader_and_retrieval_projection(tmp_path):
    _catalog_repair_projection(tmp_path, b'{"openapi":"3.0.3","paths":{"/x":{"get":{},"post":{}}}}')


@pytest.mark.parametrize("layout", ["tabs", "escaped", "literal", "tabs-crlf-escaped"])
def test_openapi_json_unicode_and_whitespace_reach_admitted_reader(tmp_path, layout):
    route = "/orders" if layout == "tabs" else "/\U0001f600"
    operation = {"operationId": "orders\U0001f600",
                 "parameters": [{"name": "query\U0001f680", "in": "query"}],
                 "responses": {"200": {"description": "ok"}}}
    spec = {"openapi": "3.0.3", "paths": {route: {"get": operation, "post": operation}}}
    indent = "\t" if layout.startswith("tabs") else "  "
    escaped = layout != "literal"
    text = json.dumps(spec, indent=indent, ensure_ascii=escaped)
    newline = "\r\n" if "crlf" in layout else "\n"
    raw = text.replace("\n", newline).encode()
    core, entry = _catalog_repair_projection(tmp_path, raw)
    rows = core.find(indexes=["documents"], kind="document_record")["results"]
    assert {row["payload"]["fields"]["method"] for row in rows} == {"GET", "POST"}
    for row in rows:
        fields, location = row["payload"]["fields"], row["location"]
        assert row["payload"]["authority"] == "declared"
        assert fields["route"] == route
        assert fields["operation_id"] == operation["operationId"]
        assert fields["parameters"] == operation["parameters"]
        assert location["file_sha256"] == entry["sha256"]
        method = fields["method"].lower()
        block = json.dumps(operation, indent=indent, ensure_ascii=escaped).splitlines()
        expected = (indent * 3 + f'"{method}": ' + block[0] + "\n"
                    + "\n".join(indent * 3 + line for line in block[1:])
                    + ("," if method == "get" else "") + "\n").replace("\n", newline).encode()
        assert raw[location["start_byte"]:location["end_byte"]] == expected

EXPECTED = {
    PARTITION: (),
    "repository_discovery.census_languages": (PARTITION,),
    SYSTEMS: (PARTITION,),
    PROJECTS: (PARTITION, SYSTEMS),
    COMPILE: (PARTITION,),
    TARGETS: (SYSTEMS, COMPILE, PARTITION),
    COMPONENTS: (PROJECTS,),
    DEPENDENCIES: (COMPONENTS,),
    INDEX_UNITS[0]: (PARTITION,),
    INDEX_UNITS[1]: (PARTITION,),
    INDEX_UNITS[2]: (COMPONENTS,),
    INDEX_UNITS[3]: (PARTITION,),
    "publish_catalog.validate_catalog": INDEX_UNITS,
    "publish_catalog.publish_handoff": (
        "publish_catalog.validate_catalog", TARGETS, DEPENDENCIES,
        "repository_discovery.census_languages",
    ),
}


def test_graph_ids_dependencies_validators_and_result_identity():
    job = catalog.build_job()
    assert (job.job_id, job.name, job.schema_identity) == (
        "job_target_catalog", "target_catalog", "appsec-review/target-catalog-job/1")
    assert job.strict_gaps is True
    assert {unit.unit_id: unit.dependencies for unit in job.units} == EXPECTED
    assert [unit.handler.__name__ for unit in job.units] == [
        "partition", "census", "build_systems", "projects", "compile_commands", "build_targets",
        "components", "dependencies", "path_index", "symbol_index", "component_index",
        "document_index", "validate_catalog", "publish",
    ]
    assert job.input_validators == (catalog._validate_config,)
    assert job.output_validators == ()
    assert job.result_transform is None
    assert all(unit.output_validators == () for unit in job.units)
    result = {"status": "SUCCEEDED", "outputs": {"example": {"value": 1}}}
    assert job.finalize_result(SimpleNamespace(), result) is result


def test_shipped_configuration_matches_topology():
    config = load_config(Path(__file__).resolve().parents[3] / "appsec-review.toml").job("job_target_catalog")
    catalog._validate_config(SimpleNamespace(config=config), None)
    assert tuple(config.steps) == tuple(catalog.TOPOLOGY)
    for step, tasks in catalog.TOPOLOGY.items():
        assert tuple(config.step(step).tasks) == tasks


@pytest.mark.parametrize("bad_step", ["steps", *sorted(catalog.TOPOLOGY)])
def test_configuration_rejects_missing_steps_and_task_order(bad_step):
    steps = dict(catalog.TOPOLOGY)
    if bad_step == "steps":
        steps.pop("publish_catalog")
    config = SimpleNamespace(steps=steps, step=lambda name: SimpleNamespace(
        tasks=tuple(reversed(catalog.TOPOLOGY[name])) if name == bad_step else catalog.TOPOLOGY[name]))
    message = ("target catalog topology does not match configuration" if bad_step == "steps"
               else f"target catalog task order mismatch: {bad_step}")
    with pytest.raises(catalog.CatalogConfigurationError, match=f"^{message}$"):
        catalog._validate_config(SimpleNamespace(config=config), None)


@pytest.mark.parametrize("unit_id", sorted(EXPECTED))
def test_injected_failure_is_scoped_before_any_handler_read(tmp_path, unit_id):
    job = catalog.build_job(fail_task=unit_id)
    unit = next(unit for unit in job.units if unit.unit_id == unit_id)
    ctx = context(tmp_path, unit_id)
    with pytest.raises(catalog.TargetCatalogFailed, match=f"^injected bounded failure: {unit_id}$"):
        unit.handler(ctx)
    assert ctx.reads == [] and ctx.events == []
