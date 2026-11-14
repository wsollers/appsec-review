"""Consumption is derived from typed contracts; scheduling never grants evidence permission."""
from __future__ import annotations

import pytest

from appsec_review.orchestration.topology import upstream_closure, wave1_dependencies
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.contracts import DispatchClass


def _graph():
    registry = builtin_registry()
    ids = set(registry.job_ids())
    dependencies = wave1_dependencies(ids)
    assert dependencies is not None
    return registry, ids, dependencies


@pytest.mark.parametrize("job_id", sorted(builtin_registry().job_ids()))
def test_consumes_are_registered_producers(job_id: str) -> None:
    registry, ids, _ = _graph()
    job = registry.build(job_id)
    assert job.contract is not None and job.consumes == job.contract.consumes
    unknown = sorted(set(job.consumes) - ids)
    assert not unknown, f"{job_id} consumes unregistered jobs: {unknown}"


@pytest.mark.parametrize("job_id", sorted(builtin_registry().job_ids()))
def test_consumes_are_scheduled_before_the_consumer(job_id: str) -> None:
    registry, _, dependencies = _graph()
    job = registry.build(job_id)
    if job_id not in dependencies:
        assert job.contract.dispatch is not DispatchClass.REVIEW_GRAPH
        return
    assert job.contract.dispatch is DispatchClass.REVIEW_GRAPH
    closure = set(upstream_closure(job_id, dependencies, set(dependencies)))
    unscheduled = sorted(set(job.consumes) - closure)
    assert not unscheduled, (
        f"{job_id} declares CONSUMES that the topology does not schedule before it: {unscheduled}")


def test_owasp_upstream_allowlist_names_only_registered_jobs() -> None:
    from appsec_review.owasp_workbench.evidence import UPSTREAM_JOBS
    registry, ids, _ = _graph()
    assert set(UPSTREAM_JOBS) <= ids
    assert "job_target_documents" not in UPSTREAM_JOBS


def test_security_tagging_declares_the_manifest_publishers_it_follows() -> None:
    registry, _, dependencies = _graph()
    job = registry.build("job_security_tagging")
    assert job.consumes == job.contract.consumes
    assert {"job_review_prioritization", "job_code_graph_index", "job_codeql_analysis"} <= set(job.consumes)
    assert set(job.consumes) <= set(upstream_closure(job.job_id, dependencies, set(dependencies)))


def test_owasp_declares_every_producer_the_tags_manifest_embeds() -> None:
    """OWASP accepts security_tagging's manifest and opens every embedded shard, so it must declare
    every producer that manifest can carry. Regression for smoke-cpp run 2026-11-13-0001: the target
    produced profile data and test coverage, their shards reached the tags manifest, and
    load_inputs refused with "undeclared or unsupplied shard producer: job_profile_data"."""
    registry, _, _ = _graph()
    owasp = registry.build("job_owasp_control_assessment")
    tagging = registry.build("job_security_tagging")
    missing = sorted(({*tagging.consumes, "job_security_tagging"} - set(owasp.consumes)) - {"job_owasp_control_assessment"})
    assert not missing, f"OWASP cannot read shards from producers it does not declare: {missing}"


def test_owasp_evidence_import_does_not_depend_on_registry_preload() -> None:
    from pathlib import Path
    import subprocess
    import sys
    result = subprocess.run([
        sys.executable, "-c",
        "from appsec_review.owasp_workbench.evidence import EvidenceResolver, UPSTREAM_JOBS; "
        "from appsec_review.jobs.job_owasp_control_assessment import build_job; "
        "assert UPSTREAM_JOBS == build_job().contract.consumes",
    ], cwd=Path(__file__).resolve().parents[1], text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
