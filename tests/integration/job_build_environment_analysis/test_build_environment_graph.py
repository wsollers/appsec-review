"""Whole-graph and JobRunner environment integration scenarios relocated during T-113.

Pre-walk status: moved without execution from tests/test_build_environment_analysis.py.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_build_environment_analysis.job import (
    JOB_ID,
    build_job,
    environment_contract,
    load_environment,
)
from appsec_review.jobs.job_review_intake import build_job as intake_job
from appsec_review.jobs.job_target_catalog import build_job as catalog_job
from appsec_review.runtime import GraphRunner

from .support import ROOT, _published

pytestmark = pytest.mark.integration


def test_real_static_producer_publication_and_strict_current_reader(tmp_path):
    config, root, fingerprint, contract = _published(tmp_path)
    value = load_environment(root, fingerprint, contract)
    assert config.job(JOB_ID).settings["enabled"] is True
    assert value["availability"] == "AVAILABLE"
    assert value["evidence"]["declarations"][0]["name"] == "SDK_ROOT"
    assert value["expected_producer"] == JOB_ID
    assert value["artifact"]["sha256"] == hashlib.sha256(
        (root / value["artifact"]["path"]).read_bytes()
    ).hexdigest()


@pytest.mark.parametrize("consumer_id", ["job_language_build", "job_evidence_collection"])
def test_plan_consumer_admits_and_records_bound_environment(tmp_path, consumer_id):
    from appsec_review.jobs.job_evidence_collection.datasets import CONTRACT as evidence_contract
    from appsec_review.jobs.job_language_build.datasets import CONTRACT as language_contract
    from appsec_review.jobs.job_project_build.datasets import DATASETS as project_datasets
    from appsec_review.runtime import Job, JobRunner, Unit
    from appsec_review.runtime.contracts import EvidenceAuthority

    config, root, source, environment = _published(tmp_path)
    runner = JobRunner(config)
    target = tmp_path / "target"
    runner.run(
        Job(
            "job_project_build",
            config.job("job_project_build").name,
            lambda _: {},
            units=(Unit("acceptance.publish_handoff", lambda _: {}),),
            datasets=project_datasets,
        ),
        run_id=root.name,
        target_root=target,
        source_fingerprint=source,
    )
    contract = language_contract if consumer_id == "job_language_build" else evidence_contract
    inputs = [item for item in contract.inputs if item.producer == JOB_ID]
    assert {item.output_kind for item in inputs} == {"handoff", "build_environment"}
    assert all(item.authority is EvidenceAuthority.OPERATIONAL for item in inputs)

    def read_environment(unit):
        return {"environment": load_environment(unit.job.run_root, source, environment)}

    unit_id = "iterations.dispatch" if consumer_id == "job_language_build" else "source_sast.semgrep_scan"
    consumer = Job(
        consumer_id,
        config.job(consumer_id).name,
        lambda _: {},
        units=(Unit(unit_id, read_environment),),
        contract=contract,
        input_identity=lambda _: "environment-reader-fixture-no-external-feeds",
    )
    result = runner.run(consumer, run_id=root.name, target_root=target, source_fingerprint=source)
    attempt = Path(result["attempt_root"])
    claim = json.loads((attempt / "claim.json").read_bytes())
    assert claim["upstream_handoffs"][JOB_ID] == environment["reference"]
    step, task = unit_id.split(".")
    unit_path = attempt / "steps" / step / "tasks" / task
    status = json.loads((unit_path / "status.json").read_bytes())
    assert any(
        item["producer"] == JOB_ID
        and item["read"]
        and item["authority"] == "operational"
        and item["handoff_sha256"] == environment["reference"]
        for item in status["input_consumption"]["reads"]
    )
    output = json.loads((unit_path / "result.json").read_bytes())
    assert output["environment"]["reference"] == environment["reference"]
    assert output["environment"]["evidence"]["declarations"][0]["name"] == "SDK_ROOT"


def test_real_environment_publication_uses_registered_build_dataset_contract(tmp_path):
    from appsec_review.jobs.job_build_environment_analysis.datasets import CONSUMES, DATASETS
    from appsec_review.runtime.datasets import FAMILIES, METADATA_ROUTE, read_dataset_contract

    producer = build_job()
    assert producer.datasets == DATASETS and producer.consumes == CONSUMES == ("job_target_catalog",)
    (declaration,) = producer.datasets
    assert declaration.family == "build" and declaration.family in FAMILIES
    assert "build_environment" not in FAMILIES
    assert declaration.output_kind == "build_environment"
    assert declaration.step == "environment_analysis"
    assert declaration.schema == producer.schema_identity == "appsec-review/build-environment-analysis/1"
    assert declaration.sensitivity == "sensitive" and declaration.disposition == "artifact_only"
    assert declaration.query_route == METADATA_ROUTE
    assert declaration.reason == "advisory source declarations; never recipe-enforced target proof"
    assert declaration.artifacts == (
        "data/jobs/job_build_environment_analysis/attempts/*/steps/"
        "environment_analysis/tasks/publish_handoff/build-environment.json",
    )
    with pytest.raises(ValueError, match="unknown dataset family: build_environment"):
        replace(declaration, family="build_environment")

    _, root, source, contract = _published(tmp_path)
    environment = load_environment(root, source, contract)
    pointer = json.loads((root / "data/jobs" / JOB_ID / "latest.json").read_bytes())
    handoff_bytes = (root / pointer["handoff_path"]).read_bytes()
    assert hashlib.sha256(handoff_bytes).hexdigest() == contract["reference"]
    handoff = json.loads(handoff_bytes)
    claim = json.loads((root / handoff["resolving_paths"]["attempt"] / "claim.json").read_bytes())
    steps, published = read_dataset_contract(claim["dataset_contract"], JOB_ID)
    assert steps == ("environment_analysis",) and published == DATASETS
    assert handoff["dataset_contract_sha256"] == claim["dataset_contract"]["sha256"]
    artifact = handoff["outputs"]["environment_analysis.publish_handoff"]["artifact"]
    assert artifact == environment["artifact"] and Path(artifact["path"]).match(declaration.artifacts[0])
    assert artifact in handoff["artifacts"]
    raw = (root / artifact["path"]).read_bytes()
    assert len(raw) == artifact["size_bytes"] and hashlib.sha256(raw).hexdigest() == artifact["sha256"]
    assert environment["availability"] == "AVAILABLE"
    assert environment["evidence"]["declarations"][0]["reason"] == "static_literal_advisory_only"


def test_optional_prior_stale_is_unavailable_but_expected_current_blocks(tmp_path):
    config, root, source, contract = _published(tmp_path)
    optional = environment_contract(
        config,
        {"environment_mode": "OPTIONAL_PRIOR"},
        {JOB_ID: contract["reference"]},
    )
    assert optional["mode"] == "OPTIONAL_PRIOR" and optional["expected_producer"] is None
    assert optional["workflow"] == "standalone" and optional["reference"] == contract["reference"]
    current = load_environment(root, source, optional)
    assert current["availability"] == "AVAILABLE" and current["evidence"]["declarations"]
    value = load_environment(root, "other-source", optional)
    assert value["availability"] == "UNAVAILABLE"
    assert value["evidence"] is None and value["artifact"] is None
    assert value["reason"] == "STALE optional prior source"
    with pytest.raises(ValueError, match="wrong source"):
        load_environment(root, "other-source", contract)
    (root / current["artifact"]["path"]).write_bytes(b"{}")
    with pytest.raises(ValueError, match="identity mismatch"):
        load_environment(root, "other-source", optional)


@pytest.mark.parametrize("stale", [False, True])
@pytest.mark.parametrize("mode", ["strict", "first_party_managed"])
@pytest.mark.parametrize("reference_source", ["upstream", "host"])
def test_optional_prior_host_identity_survives_direct_launch_and_reuse(
    tmp_path, stale, mode, reference_source
):
    from appsec_review.jobs.job_target_analysis_plan import build_job as planner_job, load_accepted_plan
    from appsec_review.runtime import JobRunner
    from appsec_review.runtime.resume import ResumePlanner

    config, root, source, environment = _published(tmp_path, reusable=True, mode=mode)
    prior = load_environment(root, source, environment)
    target = tmp_path / "target"
    if stale:
        (target / "README.md").write_bytes(b"synthetic new source after accepted optional environment\n")
        source = source_fingerprint(target)
        GraphRunner(config, [intake_job(), catalog_job()]).run(
            target_root=target,
            source_fingerprint=source,
            run_id=root.name,
        )
    upstream = {
        name: json.loads((root / "data/jobs" / name / "latest.json").read_bytes())["handoff_sha256"]
        for name in ("job_review_intake", "job_target_catalog", JOB_ID)
    }
    orchestration = {"workflow": "standalone", "environment_mode": "OPTIONAL_PRIOR"}
    if reference_source == "host":
        upstream.pop(JOB_ID)
        orchestration["environment_reference"] = environment["reference"]
    job = planner_job(infer=lambda *_args, **_kwargs: pytest.fail("environment-only fixture cannot call a model"))
    runner = JobRunner(config)
    result = runner.run(
        job,
        run_id=root.name,
        target_root=target,
        source_fingerprint=source,
        upstream_handoffs=upstream,
        orchestration=orchestration,
    )
    plan = load_accepted_plan(root)
    stored = plan["build_environment"]
    assert stored["mode"] == "OPTIONAL_PRIOR" and stored["expected_producer"] is None
    assert stored["reference"] == environment["reference"]
    assert stored["availability"] == ("UNAVAILABLE" if stale else "AVAILABLE")
    assert (stored["evidence"] is None) is stale
    assert (stored["artifact"] is None) is stale
    original = json.loads((Path(result["attempt_root"]) / "claim.json").read_bytes())
    launch = environment_contract(config, orchestration, upstream)
    assert json.loads(original["orchestration"]["build_environment_contract"]) == launch
    required = {key: value for key, value in upstream.items() if key != JOB_ID}
    assert original["upstream_handoffs"] == result["handoff"]["upstream_handoff_sha256"] == required
    assert environment["reference"] not in json.dumps(
        json.loads((root / original["input_manifest_path"]).read_bytes())
    )
    resumed = ResumePlanner(config, root, [job], source, target_root=target, orchestration=orchestration)
    assert resumed.accepted(job, upstream) == ((), result["handoff_sha256"])
    claim = runner.begin_or_reuse_attempt(
        job,
        run_id=root.name,
        target_root=target,
        source_fingerprint=source,
        upstream_handoffs=upstream,
        orchestration=orchestration,
    )
    assert claim["reused"] is True and claim["attempt_id"] == original["attempt_id"]
    assert claim["upstream_handoffs"] == required
    assert json.loads(claim["orchestration"]["build_environment_contract"]) == launch
    assert load_accepted_plan(root) == plan
    if stale and reference_source == "upstream":
        with pytest.raises(ValueError, match="current catalog|wrong source"):
            ResumePlanner(config, root, [job], source, target_root=target).accepted(job, upstream)
    else:
        reasons, _ = ResumePlanner(config, root, [job], source, target_root=target).accepted(job, upstream)
        assert "planning environment availability identity changed" in reasons
    assert not (root / "data/jobs/job_target_analysis_plan/attempts/attempt_0002").exists()
    artifact = root / prior["artifact"]["path"]
    artifact.write_bytes(artifact.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="identity mismatch"):
        runner.begin_or_reuse_attempt(
            job,
            run_id=root.name,
            target_root=target,
            source_fingerprint=source,
            upstream_handoffs=upstream,
            orchestration=orchestration,
        )
    assert not (root / "data/jobs/job_target_analysis_plan/attempts/attempt_0002").exists()


@pytest.mark.parametrize("stale", [False, True])
@pytest.mark.parametrize("mode", ["strict", "first_party_managed"])
def test_unscheduled_optional_host_reference_survives_actual_graph_plan_and_run(tmp_path, stale, mode):
    from appsec_review.jobs.job_target_analysis_plan import build_job as planner_job, load_accepted_plan

    config, root, source, environment = _published(tmp_path, reusable=True, mode=mode)
    target = tmp_path / "target"
    if stale:
        (target / "README.md").write_bytes(b"synthetic new graph source\n")
        source = source_fingerprint(target)
    orchestration = {
        "workflow": "standalone",
        "environment_mode": "OPTIONAL_PRIOR",
        "environment_reference": environment["reference"],
    }
    job = planner_job(infer=lambda *_args, **_kwargs: pytest.fail("environment-only fixture cannot call a model"))
    graph = GraphRunner(config, [intake_job(), catalog_job(), job])
    first = graph.run(
        target_root=target,
        source_fingerprint=source,
        run_id=root.name,
        orchestration=orchestration,
    )
    stored = load_accepted_plan(root)["build_environment"]
    assert stored["reference"] == environment["reference"] and stored["mode"] == "OPTIONAL_PRIOR"
    assert stored["availability"] == ("UNAVAILABLE" if stale else "AVAILABLE")
    assert (stored["evidence"] is None) is stale
    plan_gaps = load_accepted_plan(root)["coverage_gaps"]
    assert ("build environment: STALE optional prior source" in plan_gaps) is stale
    if stale:
        assert first["jobs"]["job_target_analysis_plan"]["status"]["status"] == "COMPLETED_WITH_GAPS"
    planned = graph.plan(root.name, source, target_root=target, orchestration=orchestration)
    assert [decision.action for decision in planned] == ["REUSE", "REUSE", "REUSE"]
    again = graph.run(
        target_root=target,
        source_fingerprint=source,
        run_id=root.name,
        orchestration=orchestration,
    )
    assert [decision["action"] for decision in again["decisions"]] == ["REUSE", "REUSE", "REUSE"]
    assert again["jobs"]["job_target_analysis_plan"]["handoff_sha256"] == (
        first["jobs"]["job_target_analysis_plan"]["handoff_sha256"]
    )
    without_prior = graph.plan(root.name, source, target_root=target)
    assert without_prior[-1].action == "RUN"
    assert "planning environment availability identity changed" in without_prior[-1].reasons
    with pytest.raises(ValueError, match="^environment reference is not the accepted producer$"):
        graph.plan(root.name, source, target_root=target, orchestration={"workflow": "wave1_review"})


def test_expected_current_missing_and_changed_bytes_block(tmp_path):
    config = load_config(ROOT / "appsec-review.toml")
    contract = environment_contract(config, {"workflow": "wave1_review"}, {})
    with pytest.raises(ValueError, match="no accepted handoff"):
        load_environment(tmp_path, "s", contract)
    _, root, source, contract = _published(tmp_path)
    value = load_environment(root, source, contract)
    (root / value["artifact"]["path"]).write_bytes(b"{}")
    with pytest.raises(ValueError, match="identity mismatch"):
        load_environment(root, source, contract)
