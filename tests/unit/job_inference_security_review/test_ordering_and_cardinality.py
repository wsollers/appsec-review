"""Lead attention ordering and configured worker capacity versus logical review tasks."""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import shutil

import pytest

from appsec_review.jobs.job_inference_security_review import teams
from appsec_review.jobs.job_inference_security_review.job import lead_package_rank
from appsec_review.retrieval import RetrievalCore
from appsec_review.review.budget import JobBudget
from appsec_review.review.models import CellStatus, Lane, Role
from appsec_review.review.package_view import PackageView
from appsec_review.review.teams import ReviewTeamSemaphore
from tests.downstream_contract_fixture import fixture as accepted_fixture
from tests.fixtures.inference_review.fake_infer import ScriptedInfer
from tests.unit.job_inference_security_review.test_t173_evidence_and_budgets import (
    evidence_core, review_context,  # noqa: F401
)


@pytest.mark.parametrize("assessed", [False, True], ids=["reported", "triaged-unknown"])
def test_lead_attention_preserves_noncritical_severity_order(assessed):
    severities = ("critical", "high", "medium", "low", "info", "unknown")
    works = []
    for index, severity in enumerate(severities):
        lead = {"reported_severity": "unknown" if assessed else severity}
        if assessed:
            lead["severity_record"] = {"effective": {"value": severity}}
        package_id = f"package-{len(severities) - index}"
        document = {"package_id": package_id, "lead_menu": [lead]}
        works.append(teams.PackageWork(package_id, Lane.LEAD, "a" * 64, document,
                                       lead_package_rank(document), "basis", (), None))
    ordered = teams._ordered_packages(list(reversed(works)))
    assert [work.package_id for work in ordered] == [work.package_id for work in works]
    assert len({work.rank[0] for work in ordered}) == len(severities)
    # Attention ordering does not turn unknown scanner/triage data into a finding severity.
    assert ordered[-1].document["lead_menu"][0]["reported_severity"] == "unknown"


def test_equal_lead_severities_keep_identity_tiebreak():
    documents = [{"package_id": identity, "lead_menu": [{"reported_severity": "high"}]}
                 for identity in ("package-b", "package-a")]
    assert [row["package_id"] for row in sorted(documents, key=lead_package_rank)] == [
        "package-a", "package-b"]


@pytest.mark.parametrize("red,blue,verifier,role_workers,judges", [
    (1, 0, 1, 1, 1),
    (1, 1, 1, 4, 2),
    (3, 2, 2, 1, 2),
    (4, 3, 3, 4, 1),
], ids=["no-blue", "one-blue-slot", "multiple-review-slots", "more-slots-than-lenses"])
def test_team_capacity_does_not_fabricate_logical_tasks(
        review_context, tmp_path, monkeypatch, red, blue, verifier, role_workers, judges):
    ctx = review_context
    repository = tmp_path / "repository"
    shutil.copytree(ctx.repository_root / "pipeline", repository / "pipeline")
    (repository / "docs" / "schemas").mkdir(parents=True)
    shutil.copyfile(ctx.repository_root / "docs" / "schemas" / "retrieval-mcp-tools.json",
                    repository / "docs" / "schemas" / "retrieval-mcp-tools.json")
    ctx.repository_root = repository
    settings = ctx.settings
    ctx.settings = replace(
        settings,
        teams=replace(settings.teams, red_per_team=red, blue_per_team=blue, verifier_per_team=verifier),
        rounds=replace(settings.rounds, max_rounds=1, stable_rounds_required=1),
        roles={**settings.roles,
               Role.INDEPENDENT_VERIFIER: replace(
                   settings.roles[Role.INDEPENDENT_VERIFIER], workers=role_workers),
               Role.ADJUDICATION_JUDGE: replace(
                   settings.roles[Role.ADJUDICATION_JUDGE], enabled=True, when="all",
                   workers=role_workers, judges_per_claim=judges)},
        retry=replace(settings.retry, max_attempts=1),
    )
    (tmp_path / "accepted").mkdir()
    case = accepted_fixture(tmp_path / "accepted")
    ctx.run_root, ctx.run_id = case.root, case.root.name
    ctx.core = RetrievalCore(case.root.parent, case.root.name)
    ctx.receipts_root = case.root / "data" / "cardinality-cells"
    ctx.budget = JobBudget.for_run(case.root, ctx.settings.budgets)
    ctx.semaphore = ReviewTeamSemaphore.for_run(case.root, 1)
    ctx.index_names = tuple(sorted(ctx.core.indexes))
    entity, lead = case.ids["affected"], case.ids["copy"]
    work = teams.PackageWork(case.package["package_id"], Lane.LEAD, "a" * 64, case.package,
                             (1, case.package["package_id"]), "b" * 64, (entity, lead), None)
    ctx._views[work.package_id] = PackageView(
        {"leads": [{"ref": lead}]}, {"K1": entity, "L1": lead}, {}, frozenset(), (lead,),
        frozenset((entity, lead)))
    ctx.covers = {"generalist": ()}
    calls, executors = [], []

    class ObservedExecutor(ThreadPoolExecutor):
        def __init__(self, max_workers, thread_name_prefix):
            executors.append((thread_name_prefix, max_workers))
            super().__init__(max_workers=max_workers, thread_name_prefix=thread_name_prefix)

    monkeypatch.setattr(teams, "ThreadPoolExecutor", ObservedExecutor)

    def infer(request, **kwargs):
        calls.append(request)
        if request.role == Role.RED_TEAM_ANALYST.value:
            return ScriptedInfer._final({
                "claims": [{"id": "p1", "leads": ["L1"], "affected": ["K1"],
                            "security_predicate": "sql_injection",
                            "statement": "Untrusted input reaches a query.",
                            "support": {"affected_construct": ["K1"]}}],
                "no_claim": [], "blocked": [],
            })
        if request.role == Role.BLUE_TEAM_REFUTER.value:
            return ScriptedInfer._final({"stance": "unresolved", "why": "More evidence is needed."})
        if request.role == Role.INDEPENDENT_VERIFIER.value:
            return ScriptedInfer._final({
                "disposition": "insufficient_evidence", "per_predicate": {}, "why": "More evidence is needed."})
        assert request.role == Role.ADJUDICATION_JUDGE.value
        sides = request.task_input["input"]["sides"]
        side = next(letter for letter, value in sides.items() if value["stance"] == "supports")
        return ScriptedInfer._final({"verdict": side, "per_predicate": {},
                                    "reason": "The cited construct supports this side."})

    ctx.infer = infer
    result = teams.run_team(ctx, work, launch=True)
    assert len(result.claims) == 1, (result.triage, result.gaps)
    assert all(cell.status is CellStatus.SUCCEEDED for cell in result.cells)
    assert Counter(request.role for request in calls) == {
        Role.RED_TEAM_ANALYST.value: min(red, 3),
        **({Role.BLUE_TEAM_REFUTER.value: 2} if blue else {}),
        Role.INDEPENDENT_VERIFIER.value: 1,
        Role.ADJUDICATION_JUDGE.value: judges,
    }
    assert {request.task_input["task"] for request in calls
            if request.role == Role.BLUE_TEAM_REFUTER.value} == (
                {"blue_control", "blue_reachability"} if blue else set())
    assert executors == [("red", red), ("review", blue + verifier),
                         ("judge", min(role_workers, judges))]
    assert all(request.model == ctx.profile(Role(request.role)).model for request in calls)
