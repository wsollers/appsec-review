"""Plan consumers declare the environment publication that ``load_accepted_plan`` re-reads (T-054).

When ``job_build_environment_analysis`` runs in the graph, the accepted plan is bound to its
publication (``EXPECTED_CURRENT``) and every ``load_accepted_plan`` call re-reads that handoff
through the instrumented reader. A consumer that did not declare the producer was rejected with
``undeclared consumption by <job>: job_build_environment_analysis/handoff``.

Unit tests: the real configuration, the real GraphRunner and runner admission, real producers for
intake, catalog, environment and plan, and the consumers' existing injected executors. No Docker,
no model, no network. The consumption check itself is never replaced.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_build_environment_analysis import build_job as build_environment
from appsec_review.jobs.job_build_environment_analysis.job import JOB_ID as ENVIRONMENT
from appsec_review.jobs.job_evidence_collection import build_job as build_evidence
from appsec_review.jobs.job_language_build import build_job as build_language
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan, load_accepted_plan
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner
from appsec_review.runtime.contracts import Availability, EvidenceAuthority, InputChannel, MissingPolicy
from appsec_review.jobs.build_topology_artifacts import guard_action
from appsec_review.runtime.inputs import input_read_scope, read_input_observations
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.runner import JobRunner
from tests import test_evidence_collection_job as evidence_tests
from tests.integration.job_language_build import test_language_build_graph as language_tests
from tests.capture_fakes import capturing_fake


def _accepted_handoff(run_root: Path, job_id: str) -> tuple[dict, str]:
    pointer = json.loads((run_root / "data/jobs" / job_id / "latest.json").read_bytes())
    return json.loads((run_root / pointer["handoff_path"]).read_bytes()), pointer["handoff_sha256"]


def _assert_declared_environment_read(run_root: Path, consumer: str) -> None:
    """The consumer was supplied the accepted environment handoff and its reader receipt names it."""
    _, environment_sha = _accepted_handoff(run_root, ENVIRONMENT)
    assert load_accepted_plan(run_root)["build_environment"]["mode"] == "EXPECTED_CURRENT"
    handoff, _ = _accepted_handoff(run_root, consumer)
    assert handoff["upstream_handoff_sha256"][ENVIRONMENT] == environment_sha
    reads = read_input_observations(run_root, handoff)["reads"]
    assert any(item["producer"] == ENVIRONMENT and item["output_kind"] == "handoff"
               and item["handoff_sha256"] == environment_sha and item["read"] is True for item in reads), reads


@pytest.mark.parametrize("job_id", ["job_build_iteration", "job_evidence_collection", "job_language_build"])
def test_plan_consumers_declare_the_environment_publication_as_an_optional_input(job_id: str) -> None:
    contract = builtin_registry().build(job_id).contract
    declared = {item.output_kind: item for item in contract.inputs if item.producer == ENVIRONMENT}
    assert set(declared) == {"handoff", "build_environment"}
    for requirement in declared.values():
        # Optional: a disabled or unscheduled environment producer is a plan-recorded mode, not a rejection.
        assert requirement.channel is InputChannel.HANDOFF
        assert requirement.availability is Availability.OPTIONAL and requirement.missing is MissingPolicy.GAP
        assert requirement.authority is EvidenceAuthority.OPERATIONAL
    assert ENVIRONMENT in contract.consumes


def test_evidence_collection_begins_and_publishes_under_an_environment_bound_plan(tmp_path: Path) -> None:
    config, target = evidence_tests.fixture(tmp_path)
    calls: list[str] = []
    outcome = GraphRunner(config, [
        build_intake(), build_catalog(), build_environment(), build_plan(),
        build_evidence(executor_factory=lambda unit: evidence_tests.FakeExecutor(
            unit.job.repository_root, unit.job.run_root, calls)),
    ]).run(target_root=target, source_fingerprint=source_fingerprint(target))
    assert outcome["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}, outcome["status"]
    assert calls
    _assert_declared_environment_read(config.runtime.runs_dir / outcome["run_id"], "job_evidence_collection")


def test_language_build_dispatch_guard_reads_the_environment_bound_plan(tmp_path: Path) -> None:
    """The guard ``iterations.dispatch`` runs for every build action, in a real admitted attempt.

    The offline fixtures cannot make a build unit ready (project build reports it blocked), so the
    dispatch unit itself never reaches its guard here. The guard is therefore called directly inside
    the attempt's own read scope: its first step is the plan (and environment) read that was refused.
    """
    config, target = language_tests._fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    calls: list[tuple[str, ...]] = []
    upstream = GraphRunner(config, [
        build_intake(), build_catalog(), build_environment(),
        build_plan(infer=language_tests.NativeRecipeModel().complete),
        build_projects(
            executor_factory=lambda unit, profile: capturing_fake(profile, language_tests.NativeExecutor(calls)),
            image_resolver_factory=lambda unit: language_tests.ImageResolver(
                target, releases=unit.job.review_policy.releases)),
    ]).run(target_root=target, source_fingerprint=fingerprint)
    run_root = config.runtime.runs_dir / upstream["run_id"]
    _, environment_sha = _accepted_handoff(run_root, ENVIRONMENT)
    job = build_language()
    runner = JobRunner(config)
    claim = runner.begin_attempt(
        job, run_id=upstream["run_id"], target_root=target, source_fingerprint=fingerprint,
        upstream_handoffs={key: upstream["jobs"][key]["handoff_sha256"] for key in job.consumes})
    context = runner._context_from_claim(job, claim)
    with input_read_scope(context) as reads:
        # An action without a recipe is refused only after the accepted plan and its environment
        # publication were read; an undeclared read would raise first and poison the scope.
        with pytest.raises(ValueError, match="exact selected non-null recipe"):
            guard_action(context.run_root, {})
        reads.check()
        observed = reads.document()["reads"]
    assert claim["upstream_handoffs"][ENVIRONMENT] == environment_sha
    assert load_accepted_plan(run_root)["build_environment"]["mode"] == "EXPECTED_CURRENT"
    assert any(item["producer"] == ENVIRONMENT and item["output_kind"] == "handoff"
               and item["handoff_sha256"] == environment_sha and item["read"] is True for item in observed), observed
