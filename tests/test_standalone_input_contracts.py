"""Direct adapter begin-op admission against a genuinely published synthetic upstream."""
import json
from types import SimpleNamespace
from unittest.mock import Mock

from dagster import DagsterRun
import pytest

from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.orchestration.dagster.adapter import _build_dagster_graph
from appsec_review.orchestration.topology import UPSTREAM_HANDOFFS_TAG
from appsec_review.runtime import Job, JobRunner, Unit, UnitExecutor
from appsec_review.runtime.contracts import JobContract
from appsec_review.runtime.registry import builtin_registry
from tests.downstream_contract_fixture import configuration


@pytest.mark.parametrize("supply", ("unspecified", "tagged", "empty", "composite"))
def test_adapter_existing_run_uses_the_same_contract_selection_as_runner(tmp_path, monkeypatch, supply):
    config = configuration(tmp_path)
    runner = JobRunner(config)
    target = tmp_path / "source"
    target.mkdir()
    (target / "input.txt").write_text("bounded fixture\n")
    monkeypatch.setenv("APPSEC_REVIEW_TARGET", str(target))
    registry = builtin_registry()
    intake = registry.build("job_review_intake")
    units = (Unit("publish_intake.publish_handoff", lambda _: {"terminal_status": "SUCCEEDED"}),)
    producer = Job(intake.job_id, intake.name, UnitExecutor(units).execute, units=units,
                   datasets=intake.datasets, contract=JobContract(), strict_gaps=True)
    snapshot = source_fingerprint(target)
    published = runner.run(producer, target_root=target, source_fingerprint=snapshot)
    assert published["status"]["status"] == "SUCCEEDED"
    run_id = published["status"]["run_id"]
    root = runner.runs.resolve(run_id)
    digest = published["handoff_sha256"]
    accepted = accepted_handoff(root, intake.job_id)
    assert accepted is not None and accepted.sha256 == digest
    catalog = registry.build("job_target_catalog")
    jobs = (catalog,)
    edges = None
    if supply == "composite":
        jobs += (registry.build("job_image_pin_verification"),)
        edges = {catalog.job_id: (), "job_image_pin_verification": (catalog.job_id,)}
    definition = _build_dagster_graph("fixture_catalog", jobs, config, JobRunner, job_dependencies=edges)
    graph = definition.graph
    begin = graph.node_named("target_catalog__begin").definition
    assert not begin.input_defs
    dependencies = graph.dependency_structure
    for job in jobs:
        prefix = job.job_id.removeprefix("job_")
        for suffix in (*[unit.unit_id.replace(".", "__") for unit in job.units], "finalize"):
            inputs = dependencies.input_to_upstream_outputs_for_node(f"{prefix}__{suffix}")
            claim_sources = [output.node_name for item, outputs in inputs.items()
                             if item.input_name == "claim" for output in outputs]
            assert claim_sources == [f"{prefix}__begin"]
    if supply == "composite":
        upstream = dependencies.all_upstream_outputs_from_node("image_pin_verification__begin")
        assert [(output.node_name, output.output_name) for output in upstream] == [
            ("target_catalog__finalize", "result")]
    tags = {"appsec/application_run_id": run_id}
    if supply in {"tagged", "empty"}:
        tags[UPSTREAM_HANDOFFS_TAG] = json.dumps({intake.job_id: digest} if supply == "tagged" else {})
    dagster_run = DagsterRun(job_name=definition.name, tags=tags)
    # Only Dagster's tag/metadata sinks are faked; the built op and its safety wrapper stay real.
    context = SimpleNamespace(
        dagster_run=dagster_run, run_id=dagster_run.run_id, op=begin,
        instance=SimpleNamespace(add_run_tags=Mock()), add_output_metadata=Mock())
    if supply in {"empty", "composite"}:
        with pytest.raises(ValueError, match=r"^required input unavailable: job_review_intake/handoff$"):
            begin.compute_fn.decorated_fn(context)
        context.instance.add_run_tags.assert_not_called()
        context.add_output_metadata.assert_not_called()
        [claim_path] = (root / f"data/jobs/{catalog.job_id}/attempts").glob("*/claim.json")
        claim = json.loads(claim_path.read_bytes())
        assert claim["upstream_handoffs"] == {}
        assert json.loads(claim_path.with_name("status.json").read_bytes())["status"] == "FAILED"
    else:
        claim = begin.compute_fn.decorated_fn(context)
        assert claim["upstream_handoffs"] == {intake.job_id: digest}
        assert claim["input_admission"] == {
            "schema": "appsec-review/input-admission/1",
            "contract_sha256": catalog.contract.document()["sha256"],
            "requirements": [{
                "channel": "handoff", "producer": intake.job_id,
                "output_kind": requirement.output_kind, "schema": requirement.schema,
                "authority": requirement.authority.value,
                "available": requirement.output_kind == "handoff",
                "supplied": requirement.output_kind == "handoff", "read": False, "cited": None,
                "handoff_sha256": digest, "attempt_id": published["status"]["attempt_id"],
                "target_snapshot": snapshot, "coverage": published["handoff"]["coverage"],
                "status": "supplied" if requirement.output_kind == "handoff" else "gap",
            } for requirement in catalog.contract.inputs],
        }
        persisted = json.loads((root / claim["attempt_path"] / "claim.json").read_bytes())
        assert persisted["upstream_handoffs"] == claim["upstream_handoffs"]
        assert persisted["input_admission"] == claim["input_admission"]
        context.instance.add_run_tags.assert_called_once_with(dagster_run.run_id, {
            "appsec/application_run_id": run_id, "appsec/trigger": "manual"})
        context.add_output_metadata.assert_called_once_with({
            "application_run_id": run_id, "application_attempt_id": claim["attempt_id"],
            "job_id": catalog.job_id})
    assert claim["job_id"] == catalog.job_id
    assert claim["run_id"] == run_id
    assert claim["source_fingerprint"] == snapshot
    assert claim["target_root"] == str(target)
    assert claim["orchestration"] == {
        "system": "dagster", "run_id": dagster_run.run_id,
        "workflow": definition.name, "node": begin.name}
    assert not (root / f"data/jobs/{catalog.job_id}/latest.json").exists()
