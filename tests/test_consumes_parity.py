"""A job's declared CONSUMES names registered producers that the wave1 topology schedules before it."""
from __future__ import annotations

import pytest

from appsec_review.orchestration.topology import upstream_closure, wave1_dependencies
from appsec_review.runtime.registry import builtin_registry


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
    unknown = sorted(set(job.consumes) - ids)
    assert not unknown, f"{job_id} consumes unregistered jobs: {unknown}"


@pytest.mark.parametrize("job_id", sorted(builtin_registry().job_ids()))
def test_consumes_are_scheduled_before_the_consumer(job_id: str) -> None:
    registry, _, dependencies = _graph()
    if job_id not in dependencies:
        pytest.skip(f"{job_id} is not a wave1_review vertex")
    job = registry.build(job_id)
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
    assert set(job.consumes) == {"job_review_prioritization", "job_code_graph_index", "job_codeql_analysis"}
    assert set(job.consumes) <= set(dependencies["job_security_tagging"])
