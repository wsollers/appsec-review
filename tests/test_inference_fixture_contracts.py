"""Admission/scope checks for the accepted-index fixture, without executing review rounds."""
import json

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_inference_security_review import build_job
from appsec_review.runtime import JobRunner
from tests.fixtures.inference_review.acceptance import write_config
from tests.fixtures.inference_review.builder import FEEDS, SHARDS, build_accepted_index_set
from tests.release_support import write_release


def prepared(tmp_path, *, full=False):
    config_path = write_config(tmp_path, tmp_path / "runs")
    config = load_config(config_path)
    write_release(tmp_path, config.jobs)
    options = {} if full else {"omit": tuple(name for name in SHARDS if name not in {
        "source", "components", "build", "semgrep", "scanner_correlation"}), "omit_feeds": FEEDS}
    fixture = build_accepted_index_set(tmp_path, config=config_path, **options)
    return config, fixture


@pytest.mark.parametrize("full", (False, True), ids=("bounded", "all-producers"))
def test_indexing_fixture_admits_current_review_contract(tmp_path, full):
    config, fixture = prepared(tmp_path, full=full)
    runner = JobRunner(config)
    def forbidden_model(*args, **kwargs):
        pytest.fail("admission and scope must not dispatch a model")
    job = build_job(infer=forbidden_model)
    claim = runner.begin_attempt(job, run_id=fixture.run_id,
                                  upstream_handoffs=fixture.upstream_handoffs)
    summary = next(row for row in claim["input_admission"]["requirements"]
                   if row["producer"] == "job_review_data_indexing" and row["output_kind"] == "accepted_input_summary")
    assert summary["supplied"] and summary["schema"] == "appsec-review/review-data-indexing-inputs/2"
    assert {"job_target_catalog", "job_evidence_collection", "job_review_package_assembly"} <= set(
        claim["upstream_handoffs"])
    accepted = runner.execute_or_reuse_unit(job, claim, "scope.accept_manifest")
    assert accepted["shard_count"] > 0
    result = runner.execute_or_reuse_unit(job, claim, "scope.assemble_scope")
    assert result["source_languages"]
    root = fixture.run_root
    document = json.loads((root / "data/jobs/job_review_data_indexing/attempts/attempt_0001/steps/load"
                          "/tasks/accepted_inputs/accepted-inputs.json").read_bytes())
    assert document["schema"] == summary["schema"]
    assert document["handoffs"]["job_target_catalog"]["sha256"] == claim["upstream_handoffs"]["job_target_catalog"]
    assert document["feeds"] == fixture.feed_pins
    assert document["owasp"]["status"] != "complete"
    assert not (root / "data/jobs/job_inference_security_review/latest.json").exists()


@pytest.mark.parametrize("mutation", ("missing-owner", "corrupt-owner"))
def test_original_fixture_producer_is_required_and_byte_verified(tmp_path, mutation):
    config, fixture = prepared(tmp_path)
    path = fixture.run_root / "data/jobs/job_evidence_collection/attempts/attempt_0001/handoff.json"
    if mutation == "missing-owner":
        path.unlink()
    else:
        path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="accepted handoff|changed|mismatch"):
        JobRunner(config).begin_attempt(build_job(), run_id=fixture.run_id,
                                        upstream_handoffs=fixture.upstream_handoffs)
