"""Whole-job JobRunner integration scenarios for job_inference_security_review."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_inference_security_review import TOPOLOGY, build_job, chains
from appsec_review.observability.events import PipelineLog
from appsec_review.review.ledger import merge_shards, project
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import file_sha256
from tests.fixtures.inference_review.acceptance import ROOT, write_config
from tests.fixtures.inference_review.builder import build_accepted_index_set
from tests.fixtures.inference_review.fake_infer import ScriptedInfer
from tests.review.test_attack_chain_job import ChainInfer
from tests.review.test_team_handler import _prepared_template, prepared  # noqa: F401

pytestmark = pytest.mark.integration


def test_real_inference_job_handoff_publishes_manifest_metrics_and_no_invented_connections(
    tmp_path_factory, monkeypatch,
):
    monkeypatch.delenv("APPSEC_REVIEW_CONFIG_OVERLAY", raising=False)
    directory = tmp_path_factory.mktemp("ac") / "r"
    directory.mkdir()
    config = write_config(directory, directory / "runs")
    fixture = build_accepted_index_set(directory, config=config)
    infer = ChainInfer(inner=ScriptedInfer({"ids": fixture.ids}))
    job = build_job(infer=infer, repository_root=ROOT)
    runner = JobRunner(load_config(config))
    claim = runner.begin_attempt(job, run_id=fixture.run_id, upstream_handoffs=fixture.upstream_handoffs)
    outputs = {}
    for unit in job.units:
        outputs[unit.unit_id] = runner.execute_or_reuse_unit(job, claim, unit.unit_id)
    accepted = runner.finalize_attempt(job, claim)
    assert accepted["handoff"]["status"] == "ACCEPTED"
    handoff = chains.read_artifact(fixture.run_root, {
        key: outputs["publication.publish_handoff"]["artifact"][key] for key in ("path", "sha256")})
    assert handoff["schema"] == "appsec-review/inference-review-handoff/3"
    manifest = chains.read_artifact(fixture.run_root, handoff["attack_chain_manifest"])
    assert manifest["items"] and all(item["status"] == "insufficient_evidence" for item in manifest["items"])
    assert any("no_commissioned_native_continuity_producer" in gap for gap in manifest["gaps"])
    paths = [
        fixture.run_root / output["ledger_shard"]["path"]
        for output in outputs.values()
        if "ledger_shard" in output
    ]
    final = project(merge_shards(paths).events)
    base = project(merge_shards([path for path in paths if "attack_chains" not in path.parts]).events)
    assert final.claims == base.claims and final.relations == base.relations
    assert all(not json.loads(path.read_text())["attack_chains"] for path in (
        fixture.run_root / Path(outputs["publication.publish_handoff"]["artifact"]["path"]).parent / "findings"
    ).glob("*.json"))
    assert manifest["accounting"]["admitted"] == len(final.attack_chains)
    events, errors = PipelineLog(fixture.run_root).read()
    assert not errors
    metrics = [item for item in events if item["event_type"].startswith("INFERENCE_REVIEW_ATTACK_CHAIN")]
    assert [item["event_type"] for item in metrics] == [
        "INFERENCE_REVIEW_ATTACK_CHAIN_COMPOSITION_COMPLETED",
        "INFERENCE_REVIEW_ATTACK_CHAIN_CHALLENGE_COMPLETED",
        "INFERENCE_REVIEW_ATTACK_CHAIN_CHALLENGE_COMPLETED",
        "INFERENCE_REVIEW_ATTACK_CHAINS_PUBLISHED"]
    for metric in metrics:
        details = metric["details"]
        assert details["duration_ms"] >= 0
        assert not any(key in details for key in ("chain_id", "claim_id", "evidence", "prompt"))
    assert (
        file_sha256(fixture.run_root / handoff["attack_chain_manifest"]["path"])
        == handoff["attack_chain_manifest"]["sha256"]
    )


def test_bounded_rounds_publish_end_to_end_without_live_models(prepared):
    job = build_job(infer=prepared.infer, repository_root=ROOT)
    runner = JobRunner(load_config(prepared.fixture.config))
    attempt = runner.begin_attempt(
        job, run_id=prepared.fixture.run_id, upstream_handoffs=prepared.fixture.upstream_handoffs,
    )
    outputs = {}
    for step, tasks in TOPOLOGY.items():
        for task in tasks:
            unit_id = f"{step}.{task}"
            outputs[unit_id] = runner.execute_or_reuse_unit(job, attempt, unit_id)
    assert outputs["publication.publish_claim_ledger"]["ledger_head_sha256"]
    assert outputs["publication.publish_handoff"]["terminal_status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
