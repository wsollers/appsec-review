"""Driver contracts without executing a Dagster graph, tools, or models."""
from pathlib import Path

import pytest

from appsec_review.orchestration.topology import enabled_wave1_dependencies, upstream_closure, wave1_dependencies
from appsec_review.runtime.dependencies import force_selected, graph_dependencies, input_projection
from appsec_review.runtime.launch import LaunchInputs, begin
from appsec_review.runtime.registry import builtin_registry


def test_both_drivers_project_disabled_jobs_and_support_every_enabled_job():
    registry = builtin_registry()
    complete = wave1_dependencies(set(registry.job_ids()))
    enabled = set(complete) - {"job_project_build", "job_language_build", "job_review_data_indexing"}
    expected = enabled_wave1_dependencies(enabled, set(registry.job_ids()))
    jobs = tuple(registry.build(job_id) for job_id in expected)
    assert graph_dependencies(jobs) == expected
    assert set(expected) == enabled
    assert set(expected["job_artifact_indexing"]) == {"job_target_analysis_plan"}
    for job_id in expected:
        assert force_selected(job_id, job_id, expected)
        assert all(parent in enabled for parent in expected[job_id])
    with pytest.raises(ValueError, match="disabled"):
        force_selected("job_target_catalog", "job_project_build", expected)


def test_sibling_handoffs_are_not_accumulated_as_inputs():
    edges = {"a": (), "b": ("a",), "c": (), "d": ("b", "c")}
    available = {"a": "a", "b": "b", "c": "c"}
    assert input_projection("b", available, edges, set(edges)) == {"a": "a"}
    assert input_projection("c", available, edges, set(edges)) == {}
    assert upstream_closure("d", edges, {"a", "b", "c"}) == ("a", "b", "c")
    assert not force_selected("c", "b", edges)
    assert force_selected("d", "b", edges)


def test_launch_force_uses_fresh_attempt_without_reuse():
    calls = []
    class Runner:
        def begin_attempt(self, job, **kwargs):
            calls.append("fresh")
            return kwargs
        def begin_or_reuse_attempt(self, job, **kwargs):
            calls.append("reuse-admission")
            return kwargs
    job = builtin_registry().build("job_final_report_publication")
    for force in (False, True):
        begin(Runner(), job, LaunchInputs(None, "none"), run_id="fixture", trigger="manual",
              orchestration={"system": "dagster"}, force=force)
    assert calls == ["reuse-admission", "fresh"]


def test_implicit_collection_excludes_manual_repair_suites():
    from types import SimpleNamespace
    import pytest
    from tests.conftest import pytest_ignore_collect
    root = Path(__file__).parents[1]
    config = SimpleNamespace(args_source=pytest.Config.ArgsSource.TESTPATHS)
    for relative in ("tests/integration/test_repair_workflow.py", "tests/acceptance/test_repair_fixture_review.py"):
        assert pytest_ignore_collect(root / relative, config) is True
