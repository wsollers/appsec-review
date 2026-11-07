"""Actual Dagster begin-op execution on an existing synthetic run, without live work."""
from datetime import datetime, timezone
import json

from dagster import DagsterInstance
import pytest

from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.orchestration.dagster.adapter import _build_dagster_graph
from appsec_review.orchestration.topology import UPSTREAM_HANDOFFS_TAG
from appsec_review.runtime import JobRunner
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import atomic_json, file_sha256
from tests.downstream_contract_fixture import configuration
from tests.handoff_fixture import write_fixture_handoff


@pytest.mark.parametrize("supply", ("unspecified", "tagged", "empty", "composite"))
def test_adapter_existing_run_uses_the_same_contract_selection_as_runner(tmp_path, monkeypatch, supply):
    config = configuration(tmp_path)
    runner = JobRunner(config)
    run_id, root = runner.runs.create(datetime(2026, 11, 6, tzinfo=timezone.utc))
    runner._bind_configuration(root)
    target = tmp_path / "source"
    target.mkdir()
    (target / "input.txt").write_text("bounded fixture\n")
    monkeypatch.setenv("APPSEC_REVIEW_TARGET", str(target))
    registry = builtin_registry()
    intake = registry.build("job_review_intake")
    attempt = root / "data/jobs/job_review_intake/attempts/attempt_0001"
    atomic_json(attempt / "claim.json", {
        "dataset_contract": dataset_contract(intake.job_id, config.job(intake.job_id).steps, intake.datasets)})
    handoff = attempt / "handoff.json"
    write_fixture_handoff(root, handoff, {"job_id": intake.job_id, "outputs": {},
                                         "source_fingerprint": source_fingerprint(target)})
    digest = file_sha256(handoff)
    atomic_json(attempt.parent.parent / "latest.json", {
        "handoff_path": handoff.relative_to(root).as_posix(), "handoff_sha256": digest})
    catalog = registry.build("job_target_catalog")
    jobs = (catalog,)
    edges = None
    if supply == "composite":
        jobs += (registry.build("job_image_pin_verification"),)
        edges = {catalog.job_id: (), "job_image_pin_verification": (catalog.job_id,)}
    definition = _build_dagster_graph("fixture_catalog", jobs, config, JobRunner, job_dependencies=edges)
    tags = {"appsec/application_run_id": run_id}
    if supply in {"tagged", "empty"}:
        tags[UPSTREAM_HANDOFFS_TAG] = json.dumps({intake.job_id: digest} if supply == "tagged" else {})
    with DagsterInstance.ephemeral() as instance:
        result = definition.execute_in_process(instance=instance, tags=tags,
                                               op_selection=["target_catalog__begin"], raise_on_error=False)
    if supply in {"empty", "composite"}:
        assert not result.success
        assert any("required input unavailable: job_review_intake/handoff" in str(event.event_specific_data)
                   for event in result.all_events if event.is_step_failure)
    else:
        assert result.success
        assert result.output_for_node("target_catalog__begin")["upstream_handoffs"] == {intake.job_id: digest}
