"""Manual full indexing/package pipeline; never part of implicit unit collection."""
from pathlib import Path

from appsec_review.jobs.job_review_package_assembly import build_job
from appsec_review.retrieval import RetrievalCore
from appsec_review.review_packages import verify_review_packages
from appsec_review.runtime import JobRunner
from appsec_review.runtime.inputs import read_input_observations
from tests.test_review_data_indexing import (
    LocalSqliteFts, SNAPSHOT, _accepted_run, _catalog_fts_image_id, _configured, _run,
)


def test_declared_fixture_producers_reach_frozen_packages(tmp_path: Path):
    config = _configured(tmp_path)
    run_id, root, target, _ = _accepted_run(tmp_path, config)
    indexing = _run(config, run_id, target, LocalSqliteFts(root, _catalog_fts_image_id()))
    outcome = JobRunner(config).run(
        build_job(), run_id=run_id, target_root=target, source_fingerprint=SNAPSHOT,
        upstream_handoffs={"job_review_data_indexing": indexing["handoff_sha256"]})
    result = outcome["result"]["outputs"]["publication.publish_packages"]
    manifest = verify_review_packages(RetrievalCore(config.runtime.runs_dir, run_id),
                                      root / result["package_directory"])
    assert manifest["packages"]
    observations = read_input_observations(root, outcome["handoff"])
    assert observations["citation_observation"] == "not_observed"
    assert {row["producer"] for row in observations["reads"]} >= {
        "job_target_catalog", "job_review_data_indexing"}
