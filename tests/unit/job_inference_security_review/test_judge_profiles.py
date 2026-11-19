"""ISR-F03/F04: real cell dispatch, ledger publication and PoC admission without providers."""
from dataclasses import replace
import json

import pytest

from appsec_review.config.inference_review import PocCandidateSettings
from appsec_review.inference import ModelResult
from appsec_review.inference.errors import ProviderError
from appsec_review.jobs.accepted_review import load_accepted_review, poc_candidate_agrees
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.jobs.job_inference_security_review import stages, teams
from appsec_review.retrieval import RetrievalCore
from appsec_review.review.accounting import exact_accounting
from appsec_review.review.budget import JobBudget
from appsec_review.review.ledger import LedgerWriter, merge_shards, project
from appsec_review.review.models import (
    Admissibility, CellStatus, Claim, EvidenceRelation, Lane, Predicate, RelationKind, Role,
)
from appsec_review.review.package_view import PackageView
from appsec_review.review.ship_block import SEVERITY_PROVIDER
from appsec_review.review.teams import ReviewTeamSemaphore
from appsec_review.storage import atomic_json, file_sha256
from tests.downstream_contract_fixture import fixture as accepted_fixture
from tests.fixtures.inference_review.fake_infer import ScriptedInfer
from tests.handoff_fixture import write_fixture_handoff
from tests.review.test_inference_review_schemas import validator as schema_validator
from tests.unit.job_inference_security_review.test_t173_evidence_and_budgets import (
    evidence_core, review_context,  # noqa: F401
)


def _claim(ctx):
    entity = ctx.core.find(name="parse_token", limit=1)["results"][0]["identity"]
    return Claim("claim-" + "c" * 64, Lane.LEAD, "package", (entity,), "CWE-89",
                 "sql_injection", (), "Untrusted input reaches a query.",
                 origin_cell_ids=("cell-" + "a" * 64,))


def _work(claim):
    return teams.PackageWork(claim.package_id, Lane.LEAD, "4" * 64, {}, (1, claim.package_id),
                             "basis", claim.affected_entities, None)


def _judge(ctx, claim, *, strategy="judge-1"):
    view = PackageView({}, {"K1": claim.affected_entities[0]}, {}, frozenset(), (),
                       frozenset(claim.affected_entities))
    cell = teams._cell(ctx, _work(claim), {"stack": "generic"}, role=Role.ADJUDICATION_JUDGE,
                       persona="generalist", task=teams.JUDGE_TASK, kind="judge", claim=claim,
                       task_input={"claim": {"claim_id": claim.claim_id}}, view=view,
                       side_map={"A": "red", "B": "blue"}, strategy=strategy)
    return teams._JudgePlan({"claim": claim, "cells": []}, cell, {"A": "red", "B": "blue"},
                            (), ("forbidden-side-identity",), 0)


def _run_judge(ctx, claim, mode, result, *, strategy="judge-1"):
    plan = _judge(ctx, claim, strategy=strategy)
    if mode == "not_launched":
        ctx.allow_new_calls = False

    def infer(request, **kwargs):
        assert mode != "not_launched"
        assert request.task_input["capability"]["max_queries"] == 0
        if mode == "provider":
            raise ProviderError("offline provider outage", retryable=False)
        if mode == "timeout":
            raise TimeoutError("offline timeout")
        if mode == "invalid":
            return ModelResult({"not": "a review turn"})
        return ScriptedInfer._final({
            "verdict": "A", "per_predicate": {"affected_construct": {"verdict": "A", "cites": ["K1"]}},
            "reason": "The cited construct supports this side.",
        })

    ctx.infer = infer
    teams._run(ctx, plan.cell, teams._validator(ctx, Role.ADJUDICATION_JUDGE, claim_id=claim.claim_id),
               capture=True)
    if mode == "untrusted":
        plan = replace(plan, markers=(ctx.profile(Role.ADJUDICATION_JUDGE).model,))
    teams._judged(ctx, plan, result)
    return plan.cell


def _publish(ctx, claim, result, root, *, scores=None):
    ledger_path = root / "team.jsonl"
    writer = LedgerWriter(ledger_path, "lead_review.teams")
    writer.propose_claim(claim)
    writer.add_relation(EvidenceRelation(
        "evrel-" + "a" * 64, claim.claim_id, Predicate.AFFECTED_CONSTRUCT, RelationKind.SUPPORTS,
        claim.affected_entities[0], "symbol", Admissibility.DIRECT, "symbols", "b" * 64,
        "src/auth.py:40", True, claim.origin_cell_ids[0], "c" * 64))
    for cell in result.cells:
        writer.cell_terminal(cell)
    for gap in result.gaps:
        writer.record_gap(gap)
    for verdict in result.judge_verdicts:
        writer.judge_verdict(verdict)
    writer.seal()
    projection = project(merge_shards([ledger_path]).events)
    merged = stages.merge_claims(
        [{"proposals": {claim.claim_id: [claim.package_id]}, "independence": {}, "verifier_gaps": {}}],
        [ledger_path], {claim.package_id: claim.affected_entities}, [])
    adjudication = stages.apply_policy(merged, projection, root / "adjudication.jsonl",
                                       "adjudicate.apply_policy")
    assert adjudication["states"] == {"supported": 1}
    projection = project(merge_shards([ledger_path, root / "adjudication.jsonl"]).events)
    if scores is None:
        scores = [{"claim_id": claim.claim_id, "provider": SEVERITY_PROVIDER, "score_id": "score-" + "d" * 64,
                   "technical_severity": "high"}]
    findings = stages.finding_packages(
        projection, adjudication["adjudications"], merged, scores,
        manifest_sha256=ctx.core.manifest_sha256, out_dir=root / "findings", schemas=ctx.schemas)
    finding, = findings
    package = json.loads((root / "findings" / finding["file"]).read_text())
    brief = {"claim_id": claim.claim_id, "package_id": claim.package_id,
             "cell_id": claim.origin_cell_ids[0],
             "poc_basis": {"entry": list(claim.affected_entities), "path": list(claim.affected_entities),
                           "trigger": [], "input_format": "query", "preconditions": [],
                           "expected_observation": "query reaches sink", "unknowns": []}}
    return finding, package, stages.poc_candidates(findings, [brief], PocCandidateSettings()), projection


@pytest.mark.parametrize("rounds,judges_per_claim", [(1, 1), (2, 4), (2, 5)],
                         ids=["historical-one", "historical-eight", "multi-round-ten"])
def test_all_round_judges_reach_the_accepted_consumer(review_context, tmp_path, rounds, judges_per_claim):
    (tmp_path / "accepted").mkdir()
    case = accepted_fixture(tmp_path / "accepted")
    prior = case.accepted_review.handoff
    old_review = read_bound_json(case.root, prior["outputs"]["publication.publish_handoff"]["artifact"])
    old_package_path = case.root / case.review["packages"][0]["path"]
    old_package_bytes = old_package_path.read_bytes()
    ctx = review_context
    ctx.run_root, ctx.run_id = case.root, case.root.name
    ctx.core = RetrievalCore(case.root.parent, case.root.name)
    ctx.receipts_root = case.root / "data" / "judge-round-cells"
    ctx.covers = {"generalist": ()}
    ctx.index_names = tuple(sorted(ctx.core.indexes))
    settings = ctx.settings
    ctx.settings = replace(
        settings,
        teams=replace(settings.teams, red_per_team=1, blue_per_team=0, verifier_per_team=1),
        roles={**settings.roles, Role.ADJUDICATION_JUDGE: replace(
            settings.judge, judges_per_claim=judges_per_claim, workers=1)},
        rounds=replace(settings.rounds, max_rounds=rounds, stable_rounds_required=1),
        retry=replace(settings.retry, max_attempts=1))
    ctx.budget = JobBudget.for_run(case.root, ctx.settings.budgets)
    ctx.semaphore = ReviewTeamSemaphore.for_run(case.root, 1)
    package_id = case.package["package_id"]
    package_set = read_bound_json(case.root, prior["outputs"]["packages.assemble_lead_packages"]["artifact"])
    package_ref, = package_set["packages"]
    affected, lead = case.ids["affected"], case.ids["copy"]
    work = teams.PackageWork(package_id, Lane.LEAD, package_ref["sha256"], case.package,
                             (1, package_id), "b" * 64, (affected, lead), None)
    ctx._views[package_id] = PackageView(
        {"leads": [{"ref": lead}]}, {"K1": affected, "L1": lead}, {},
        frozenset(), (lead,), frozenset((affected, lead)))

    def infer(request, **kwargs):
        if request.role == Role.RED_TEAM_ANALYST.value:
            return ScriptedInfer._final({
                "claims": [{"id": "p1", "leads": ["L1"], "affected": ["K1"],
                            "security_predicate": "sql_injection",
                            "statement": "Untrusted input reaches a query.",
                            "support": {"affected_construct": ["K1"]}}],
                "no_claim": [], "blocked": [],
            })
        if request.role == Role.INDEPENDENT_VERIFIER.value:
            return ScriptedInfer._final({
                "disposition": "insufficient_evidence", "per_predicate": {}, "why": "More evidence is needed."})
        assert request.role == Role.ADJUDICATION_JUDGE.value
        sides = request.task_input["input"]["sides"]
        side = next(letter for letter, value in sides.items() if value["stance"] == "supports")
        cites = sides[side]["per_predicate"]["affected_construct"]["cites"]
        return ScriptedInfer._final({
            "verdict": side, "per_predicate": {"affected_construct": {"verdict": side, "cites": cites}},
            "reason": "The cited construct supports this side.",
        })

    ctx.infer = infer
    result = teams.run_team(ctx, work, launch=True)
    claim, = result.claims
    assert len(result.rounds) == rounds
    if rounds > 1:
        assert result.rounds[-1]["stop_reason"] == "stable"
    judges = [cell for cell in result.cells if cell.role is Role.ADJUDICATION_JUDGE]
    assert len(judges) == rounds * judges_per_claim
    assert all(cell.status is CellStatus.SUCCEEDED for cell in judges)
    assert len(result.judge_verdicts) == len(judges)

    attempt = case.root / "data" / "jobs" / "job_inference_security_review" / "attempts" / "attempt_0002"
    directory = attempt / "steps" / "publication" / "tasks" / "publish_handoff"
    finding, package, candidates, projection = _publish(ctx, claim, result, directory, scores=())
    assert candidates == []  # This fixture has no severity score; do not fabricate one for acceptance.
    ctx.schemas.validate("finding-package", package)
    schema_validator("finding-package").validate(package)
    shards = [directory / "team.jsonl", directory / "adjudication.jsonl"]
    stages.write_ledger(stages.merge_verified(shards), projection, directory / "ledger")
    accounting = exact_accounting(projection, {cell.cell_id: cell.lane for cell in result.cells},
                                  {package_id: Lane.LEAD}, incomplete_gap_ratio=0.5)
    handoff = stages.build_handoff(
        run_id=case.root.name, manifest_sha256=ctx.core.manifest_sha256,
        configuration_sha256=old_review["configuration_sha256"], projection=projection, accounting=accounting,
        shards=stages.shard_records(case.root, shards), findings=[finding], scores=(),
        package_manifest_sha256=old_review["package_manifest_sha256"],
        lead_package_manifest_sha256=old_review["lead_package_manifest_sha256"],
        coverage=old_review["coverage_matrix"], possible=(), schemas=ctx.schemas,
        ship_block_policy_sha256=package["ship_block"]["policy_sha256"],
        verification=ctx.settings.verifier_distinctness(), attack_chain_manifest=old_review["attack_chain_manifest"])
    atomic_json(directory / "review.json", handoff)
    outputs = {**prior["outputs"],
               "publication.publish_claim_ledger": {
                   "artifact": artifact_ref(case.root, directory / "ledger" / "ledger-head.json")},
               "publication.publish_handoff": {
                   "schema": prior["outputs"]["publication.publish_handoff"]["schema"],
                   "artifact": artifact_ref(case.root, directory / "review.json")}}
    declarations = prior["dataset_contract_sha256"]
    old_claim = json.loads((case.root / prior["resolving_paths"]["attempt"] / "claim.json").read_bytes())
    assert old_claim["dataset_contract"]["sha256"] == declarations
    atomic_json(attempt / "claim.json", {"dataset_contract": old_claim["dataset_contract"]})
    path = write_fixture_handoff(case.root, attempt / "handoff.json", {
        "job_id": "job_inference_security_review", "source_fingerprint": case.snapshot,
        "outputs": outputs, "upstream_handoff_sha256": prior["upstream_handoff_sha256"]})
    atomic_json(attempt.parent.parent / "latest.json",
                {"handoff_path": path.relative_to(case.root).as_posix(), "handoff_sha256": file_sha256(path)})
    accepted = load_accepted_review(case.root, ctx.schemas, max_packages=10)
    accepted_package, = accepted.document["packages"]
    expected_ids = sorted(verdict.verdict_id for verdict in result.judge_verdicts)
    assert accepted_package["judge_verdict"]["verdict_ids"] == expected_ids
    assert [item["verdict_id"] for item in package["judge_verdict"]["judges"]] == expected_ids
    assert old_package_path.read_bytes() == old_package_bytes
    ctx.schemas.validate("finding-package", json.loads(old_package_bytes))


@pytest.mark.parametrize("mode,status", [
    ("provider", CellStatus.FAILED), ("timeout", CellStatus.TIMED_OUT),
    ("invalid", CellStatus.INVALID), ("untrusted", CellStatus.SUCCEEDED),
    ("not_launched", CellStatus.NOT_LAUNCHED),
])
def test_unavailable_judge_never_becomes_not_convened(review_context, tmp_path, mode, status):
    ctx = review_context
    ctx.settings = replace(ctx.settings, retry=replace(ctx.settings.retry, max_attempts=1))
    claim = _claim(ctx)
    result = teams.TeamResult(claim.package_id, Lane.LEAD, None)
    cell = _run_judge(ctx, claim, mode, result)
    assert cell.record.status is status
    assert result.judge_verdicts == [] and result.gaps
    finding, package, candidates, projection = _publish(ctx, claim, result, tmp_path)
    assert candidates == []
    assert package["judge_verdict"] is None
    assert set(package["gaps"]) & {gap.gap_id for gap in result.gaps}
    assert finding["state"] == "supported"
    stale_candidate = {"claim_id": claim.claim_id, "state": finding["state"], "judge_verdict": "not_convened",
                       "finding_package": {"finding_package_id": finding["finding_package_id"],
                                           "sha256": finding["sha256"]}}
    assert not poc_candidate_agrees(stale_candidate, package, finding["sha256"],
                                   judge_cells=stages.judge_cells_by_claim(projection)[claim.claim_id])


@pytest.mark.parametrize("mode", ["not_selected", "successful", "partial_failure"])
def test_poc_admission_distinguishes_selection_and_partial_judging(review_context, tmp_path, mode):
    ctx = review_context
    ctx.settings = replace(ctx.settings, retry=replace(ctx.settings.retry, max_attempts=1))
    claim = _claim(ctx)
    result = teams.TeamResult(claim.package_id, Lane.LEAD, None)
    if mode != "not_selected":
        cell = _run_judge(ctx, claim, "success", result)
        assert len(result.judge_verdicts) == 1
        assert cell.capability.max_queries == 0 and cell.outcome.counts["queries"] == 0
    if mode == "partial_failure":
        _run_judge(ctx, claim, "provider", result, strategy="judge-2")
    finding, package, candidates, projection = _publish(ctx, claim, result, tmp_path)
    if mode == "partial_failure":
        assert candidates == []
    else:
        candidate, = candidates
        assert candidate["judge_verdict"] == ("not_convened" if mode == "not_selected" else "red_correct")
        assert poc_candidate_agrees(candidate, package, finding["sha256"],
                                    judge_cells=stages.judge_cells_by_claim(projection).get(claim.claim_id, ()))
    if mode == "partial_failure":
        stale_candidate = {"claim_id": claim.claim_id, "state": finding["state"], "judge_verdict": "red_correct",
                           "finding_package": {"finding_package_id": finding["finding_package_id"],
                                               "sha256": finding["sha256"]}}
        assert not poc_candidate_agrees(stale_candidate, package, finding["sha256"],
                                       judge_cells=stages.judge_cells_by_claim(projection)[claim.claim_id])
    assert package["state"] == "supported"


@pytest.mark.parametrize("missing", ["all", "one"])
def test_admitted_verdicts_require_matching_terminal_cells(review_context, tmp_path, missing):
    ctx = review_context
    claim = _claim(ctx)
    result = teams.TeamResult(claim.package_id, Lane.LEAD, None)
    _run_judge(ctx, claim, "success", result)
    if missing == "one":
        _run_judge(ctx, claim, "success", result, strategy="judge-2")
    result.cells.pop()
    finding, package, candidates, projection = _publish(ctx, claim, result, tmp_path)
    assert package["judge_verdict"]["verdict"] == "red_correct"
    assert finding["judge_complete"] is False
    assert candidates == []
    stale_candidate = {"claim_id": claim.claim_id, "state": finding["state"], "judge_verdict": "red_correct",
                       "finding_package": {"finding_package_id": finding["finding_package_id"],
                                           "sha256": finding["sha256"]}}
    assert not poc_candidate_agrees(
        stale_candidate, package, finding["sha256"],
        judge_cells=stages.judge_cells_by_claim(projection).get(claim.claim_id, ()))


@pytest.mark.parametrize("disabled", ["profile", "role"])
def test_disabled_judge_is_intentionally_not_selected(review_context, tmp_path, disabled):
    ctx = review_context
    profile_name = ctx.settings.roles[Role.ADJUDICATION_JUDGE].model_profile
    if disabled == "profile":
        ctx.settings = replace(ctx.settings, models={
            **ctx.settings.models, profile_name: replace(ctx.settings.models[profile_name], enabled=False)})
    else:
        ctx.settings = replace(ctx.settings, roles={
            **ctx.settings.roles, Role.ADJUDICATION_JUDGE: replace(ctx.settings.judge, enabled=False)})
    claim = _claim(ctx)
    result = teams.TeamResult(claim.package_id, Lane.LEAD, None)
    proposal = {"statement": claim.statement, "evidence_ids": ["e1"], "counterevidence_ids": []}
    red = {"evidence_refs": [{"local_id": "e1", "predicate": "affected_construct",
                              "entity_id": claim.affected_entities[0]}]}
    group = {"claim": claim, "cells": [], "items": [(None, proposal, red, set())]}
    plans = teams._plan_judges(ctx, _work(claim), {"stack": "generic"},
                              [(group, (), None)], result)
    assert plans == [] and result.cells == []
    if disabled == "profile":
        assert result.judging[claim.claim_id] == {"selected": False, "reason": "model_profile_disabled"}
        assert any("model_profile_disabled" in gap.reason for gap in result.gaps)
    else:
        assert result.judging == {} and result.gaps == []
    _, package, candidates, _ = _publish(ctx, claim, result, tmp_path)
    assert package["judge_verdict"] is None
    assert candidates[0]["judge_verdict"] == "not_convened"


@pytest.mark.parametrize("role,task", [
    (Role.RED_TEAM_ANALYST, "lead_red_stack"),
    (Role.HYPOTHESIS_HUNTER, "sink_up"),
    (Role.BLUE_TEAM_REFUTER, "blue_control"),
    (Role.INDEPENDENT_VERIFIER, "blind_verifier"),
    (Role.ADJUDICATION_JUDGE, "judge"),
])
def test_disabled_profile_does_not_dispatch_team_cells(review_context, role, task):
    ctx = review_context
    ctx.settings = replace(ctx.settings, models={name: replace(profile, enabled=False)
                                                for name, profile in ctx.settings.models.items()},
                           retry=replace(ctx.settings.retry, max_attempts=1))
    claim = _claim(ctx)
    cell = teams._cell(ctx, _work(claim), {"stack": "generic"}, role=role, persona="generalist",
                       task=teams.JUDGE_TASK if role is Role.ADJUDICATION_JUDGE else task,
                       kind="test", task_input={}, claim=claim)
    calls = []

    def infer(request, **kwargs):
        calls.append(request)
        return ModelResult({"not": "a review turn"})

    ctx.infer = infer
    teams._run(ctx, cell, teams._validator(ctx, role, claim_id=claim.claim_id, invocation=cell.invocation))
    assert calls == []
    assert cell.record.status is CellStatus.NOT_LAUNCHED and cell.record.attempts == 0
    assert any("model_profile_disabled" in gap.reason for gap in cell.outcome.gaps)
    assert cell.outcome.receipt_paths == ()
    assert ctx.budget.snapshot().model_turns == 0


def test_disabled_triage_profile_preserves_deterministic_assessments():
    from tests.review import test_lead_triage as fixture
    from appsec_review.review.lead_triage import run_triage
    from appsec_review.review.lead_triage_settings import TriageRule

    calls = []

    def infer(request, **kwargs):
        calls.append(request)
        return ModelResult({"schema": fixture.RESULT_SCHEMA, "items": []})

    outcome = run_triage(
        [fixture.lead("unknown"), fixture.lead("secret", scanner="tool-gitleaks")],
        settings=fixture.settings(TriageRule("gitleaks", "high", "rule_semantics", "Exposed credential.")),
        profile=replace(fixture.PROFILE, enabled=False), infer=infer, read_excerpt=fixture.reader,
        reference=None, guidance=fixture.GUIDANCE, schemas=fixture.SCHEMAS)
    assert calls == [] and outcome.model_calls == 0
    rows = {row["lead_id"]: row for row in outcome.document["leads"]}
    assert rows["secret"]["assessed"]["value"] == "high"
    assert rows["unknown"]["state"] == "unresolved" and rows["unknown"]["assessed"] is None
    assert rows["unknown"]["gap"]["code"] == "triage_failed:model_profile_disabled"
    assert outcome.document["batches"][0]["attempts"] == []


def test_disabled_planner_profile_falls_back_without_dispatch():
    from tests.review import test_hunt_plan as fixture
    from appsec_review.review.hunt_plan import run_planner, selection_from_document

    calls = []

    def infer(request, **kwargs):
        calls.append(request)
        return ModelResult({"schema": fixture.RESULT_SCHEMA, "areas": [], "unassigned": [], "gaps": []})

    outcome = run_planner(
        fixture.brief(), settings=fixture.SETTINGS, profile=replace(fixture.PROFILE, enabled=False),
        infer=infer, guidance=fixture.GUIDANCE, schemas=fixture.SCHEMAS)
    assert calls == [] and outcome.model_calls == 0
    assert outcome.document["status"] == "fallback"
    assert outcome.document["gap"] == "hunt_plan_unavailable:model_profile_disabled"
    assert outcome.document["attempts"] == [] and selection_from_document(outcome.document) is None
