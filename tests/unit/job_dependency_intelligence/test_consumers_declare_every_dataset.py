"""Every job that consumes dependency intelligence declares every index shard it publishes (run 2026-11-16-0006)."""
from __future__ import annotations

import importlib

import pytest

from appsec_review.jobs.job_dependency_intelligence.datasets import DATASETS

CONSUMERS = sorted(["job_owasp_control_assessment", "job_document_issue_analysis", "job_security_tagging",
                    "job_inference_security_review", "job_review_package_assembly", "job_review_data_indexing"])
PRODUCER = "job_dependency_intelligence"


@pytest.mark.parametrize("job", CONSUMERS)
def test_consumer_contract_names_every_dependency_intelligence_dataset(job: str) -> None:
    """A consumer that reads the producer's shards through the shared index readers trips
    ``undeclared consumption`` for any dataset its typed contract omits; keep the declarations in lockstep."""
    contract = importlib.import_module(f"appsec_review.jobs.{job}.datasets").CONTRACT
    declared = {row.output_kind for row in contract.inputs if row.producer == PRODUCER}
    # Only shards the shared index readers can select trip undeclared consumption; protected files do not.
    published = {dataset.output_kind for dataset in DATASETS if dataset.indexes}
    assert published - declared == set(), f"{job} does not declare {sorted(published - declared)}"
