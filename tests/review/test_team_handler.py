"""Review-team handler: lane allocation, triage, isolation, duplicate proposals, and failure gaps."""
from __future__ import annotations

from dataclasses import asdict, replace
import json
from pathlib import Path
import time
from types import MappingProxyType, SimpleNamespace

from jsonschema import Draft202012Validator
import pytest
from referencing import Registry, Resource

from appsec_review.config import load_config
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_inference_security_review import build_job
from appsec_review.jobs.job_inference_security_review import teams as team_handler
from appsec_review.jobs.job_inference_security_review.job import (
    TARGET_GUIDANCE, _excluded, package_works, review_context,
)
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_inference_security_review.teams import lane_allocation, lane_failure, run_lane, run_team
from appsec_review.review.accounting import exact_accounting
from appsec_review.review.budget import JobBudget
from appsec_review.review.ledger import merge_shards, project
from appsec_review.review.models import CellStatus, ClaimState, GapClass, Lane, Role
from appsec_review.review.scope import SourceFile
from appsec_review.runtime.runner import JobRunner
from tests.fixtures.inference_review.acceptance import JOB, ROOT, write_config
from tests.fixtures.inference_review.builder import build_accepted_index_set
from tests.fixtures.inference_review.fake_infer import NARRATIVES, ScriptedInfer

SCHEMAS = ROOT / "docs" / "schemas" / "inference-security-review"


class Recording:
    """Wrap an infer double and keep every request it receives."""

    def __init__(self, inner) -> None:
        self.inner, self.requests = inner, []

    def __call__(self, request, *, timeout_seconds: int) -> ModelResult:
        self.requests.append(request)
        return self.inner(request, timeout_seconds=timeout_seconds)

    def by_role(self, role: str) -> list:
        return [item for item in self.requests if item.role == role]


@pytest.fixture()
def prepared(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("APPSEC_REVIEW_CONFIG_OVERLAY", raising=False)
    fixture = build_accepted_index_set(tmp_path / "review")
    config = write_config(tmp_path / "review", fixture.runs_dir)
    job = build_job(infer=ScriptedInfer({"ids": fixture.ids}), repository_root=ROOT)
    runner = JobRunner(load_config(config))
    claim = runner.begin_attempt(job, run_id=fixture.run_id)
    outputs = {}
    for unit in ("scope.accept_manifest", "scope.assemble_scope", "triage.lead_severity", "packages.assemble_lead_packages",
                 "packages.assemble_hunt_packages"):
        outputs[unit] = runner.execute_or_reuse_unit(job, claim, unit)
    settings = load_config(config).job(JOB).typed_settings

    def documents(lane: str) -> dict:
        return json.loads((fixture.run_root / outputs[f"packages.assemble_{lane}_packages"]["artifact"]["path"])
                          .read_text())

    def context(infer, *, lane: str = "lead", attempt: str = "a", **changes):
        changes.setdefault("rounds", replace(settings.rounds, max_rounds=1, stable_rounds_required=1))
        return review_context(run_root=fixture.run_root, run_id=fixture.run_id,
                              attempt_root=tmp_path / "attempts" / attempt, repository_root=ROOT,
                              settings=replace(settings, **changes) if changes else settings, infer=infer,
                              manifest_sha256=outputs["scope.accept_manifest"]["manifest_sha256"],
                              packages_doc=documents(lane), scope_out=outputs["scope.assemble_scope"])

    def work(lane: str, lead_key: str):
        identity = fixture.ids[lead_key]
        return next(item for item in package_works(fixture.run_root, documents(lane))
                    if identity in [lead["observation_id"] for lead in item.document["lead_menu"]])

    return SimpleNamespace(fixture=fixture, settings=settings, context=context, work=work, documents=documents,
                           tmp=tmp_path, infer=ScriptedInfer({"ids": fixture.ids}))


# ------------------------------------------------------------------------------------------------ allocation


def test_lane_allocation_is_fair_share_work_conserving_and_timing_free() -> None:
    assert lane_allocation(9, 2, 0.9, 10) == {Lane.LEAD: 9, Lane.HUNT: 1}
    assert lane_allocation(9, 2, 0.5, 10) == {Lane.LEAD: 8, Lane.HUNT: 2}      # hunt releases 3 of its 5
    assert lane_allocation(3, 2, 0.5, 10) == {Lane.LEAD: 3, Lane.HUNT: 2}
    assert lane_allocation(0, 5, 0.5, 4) == {Lane.LEAD: 0, Lane.HUNT: 4}
    assert lane_allocation(4, 4, 0.5, 0) == {Lane.LEAD: 0, Lane.HUNT: 0}
    assert lane_allocation(485, 114, 0.5, 200) == {Lane.LEAD: 100, Lane.HUNT: 100}


@pytest.mark.parametrize("lead_count,hunt_count", [(485, 114), (114, 485), (201, 201), (0, 599), (599, 0), (0, 0)])
@pytest.mark.parametrize("share", [0.0, 0.5, 1.0])
def test_all_packages_allocation_has_no_lane_quota(lead_count, hunt_count, share) -> None:
    assert lane_allocation(lead_count, hunt_count, share, "all") == {
        Lane.LEAD: lead_count, Lane.HUNT: hunt_count}


@pytest.mark.parametrize("profile,expected", [
    ("prod", {Lane.LEAD: 485, Lane.HUNT: 114}),
    ("copilot-prod", {Lane.LEAD: 485, Lane.HUNT: 114}),
    ("dev", {Lane.LEAD: 100, Lane.HUNT: 100}),
    ("copilot-dev", {Lane.LEAD: 100, Lane.HUNT: 100}),
])
@pytest.mark.parametrize("lane_order", [(Lane.LEAD, Lane.HUNT), (Lane.HUNT, Lane.LEAD)])
def test_lane_dispatch_and_shared_reservations_follow_profile(tmp_path, monkeypatch, profile, expected,
                                                             lane_order) -> None:
    settings = load_config(ROOT / "appsec-review.toml", profile=profile).job(JOB).typed_settings
    budget = JobBudget(tmp_path / "budget", settings.budgets)
    ctx = SimpleNamespace(settings=settings, budget=budget)
    counts = {Lane.LEAD: 485, Lane.HUNT: 114}

    def reserve_team(ctx, work, *, launch, not_launched_reason):
        return team_handler.TeamResult(work.package_id, work.lane, work.unit_key,
                                       launched=launch and ctx.budget.reserve(work.lane))

    monkeypatch.setattr(team_handler, "run_team", reserve_team)
    for lane in lane_order:
        packages = [team_handler.PackageWork(
            package_id=f"{lane.value}-{index:04d}", lane=lane, sha256="a" * 64,
            document={}, rank=(index, str(index)), basis="fixture", entities=(), unit_key=None)
            for index in reversed(range(counts[lane]))]
        result = run_lane(ctx, lane, packages, other_lane_count=counts[Lane.HUNT if lane is Lane.LEAD else Lane.LEAD],
                          ledger_path=tmp_path / lane.value / "ledger.jsonl", stream=f"{lane.value}_review.teams",
                          signal_dir=tmp_path / "signals")
        assert result["allocation"] == {key.value: value for key, value in expected.items()}
        assert len(result["packages"]) == counts[lane]
        assert result["launched"] == [f"{lane.value}-{index:04d}" for index in range(expected[lane])]
        signal = json.loads((tmp_path / "signals" / f"{lane.value}.json").read_text())
        assert signal["queue_empty"] and signal["declared"] == counts[lane]
    assert budget.team_packages() == expected
    assert budget.snapshot().exhausted == (None if settings.budgets.budget_team_packages == "all"
                                           else "budget_team_packages")


# ------------------------------------------------------------------------------------------------ triage


def test_hunt_triage_orders_by_direct_support_then_claim_id_and_caps(prepared) -> None:
    ctx = prepared.context(prepared.infer, lane="hunt")
    result = run_team(ctx, prepared.work("hunt", "sast_critical"), launch=True)
    decisions = [item for item in result.triage if item["decision"] != "rejected"]
    admitted = [item for item in decisions if item["decision"] == "admitted"]
    over = [item for item in decisions if item["decision"] == "over_cap"]
    assert len(admitted) == prepared.settings.lanes.hunt_max_claims_per_package == 2
    assert [item["claim_id"] for item in admitted] == sorted(item["claim_id"] for item in admitted)
    assert min(item["support"] for item in admitted) >= max(item["support"] for item in over) and len(over) == 1
    rejected = [item for item in result.triage if item["decision"] == "rejected"]
    assert rejected == [{"cell_id": rejected[0]["cell_id"], "claim_ref": "h3", "claim_id": None,
                         "decision": "rejected", "reason": "closed_vocabulary"}]
    gaps = {(gap.gap_class, gap.subject_id) for gap in result.gaps}
    assert (GapClass.BUDGET_GAP, over[0]["claim_id"]) in gaps
    assert any(cls is GapClass.EVIDENCE_GAP and subject.startswith("hypothesis:") for cls, subject in gaps)
    # Over-cap and rejected hypotheses get no review cells and no relations; every claim is proposed.
    assert {claim.claim_id for claim in result.claims} == {item["claim_id"] for item in decisions}
    assert over[0]["claim_id"] not in {relation.claim_id for relation in result.relations}
    reviewed = {record.claim_id for record in result.cells if record.claim_id}
    assert reviewed == {item["claim_id"] for item in admitted}
    roles = sorted(record.role.value for record in result.cells)
    assert roles.count("blue_team_refuter") == 4 and roles.count("independent_verifier") == 2
    assert len({(record.persona, record.task) for record in result.cells if record.role is Role.HYPOTHESIS_HUNTER}) == 3


def test_lead_lane_has_no_gate_but_caps_claims_per_package(prepared) -> None:
    ctx = prepared.context(prepared.infer, lanes=replace(prepared.settings.lanes, lead_max_claims_per_package=1))
    result = run_team(ctx, prepared.work("lead", "sast_critical"), launch=True)
    assert [item["decision"] for item in result.triage] == ["admitted"]          # one claim from two lenses
    assert len(result.claims) == 1 and len(result.claims[0].origin_cell_ids) == 2


# ------------------------------------------------------------------------------------------------ isolation


def test_blue_cells_never_see_each_other_and_the_verifier_is_blind(prepared) -> None:
    recording = Recording(prepared.infer)
    result = run_team(prepared.context(recording), prepared.work("lead", "codeql_high"), launch=True)
    blues = recording.by_role("blue_team_refuter")
    assert {item.task_input["task"] for item in blues} == {"blue_control", "blue_reachability"}
    guard = NARRATIVES["blue-guard"]
    for request in blues:
        text = json.dumps(asdict(request), default=str)
        assert "for the scripted review" not in text                  # no red relation rationale
        assert not request.transcript or all(turn["from"] in {"worker", "application"} for turn in request.transcript)
        if request.task_input["task"] == "blue_control":
            assert guard not in text                                  # never the other blue's output
    verifiers = recording.by_role("independent_verifier")
    assert verifiers
    markers = [NARRATIVES["C3"], guard, "for the scripted review", "blue rationale"]
    for request in verifiers:
        text = json.dumps(asdict(request), default=str)
        assert "statement" not in request.task_input["input"]["claim"]
        assert not any(marker in text for marker in markers)

    recording = Recording(prepared.infer)
    # ci_high: its CI rule observation is direct for exactly the predicates its claim family requires, so the
    # blind verifier can re-retrieve independent support (the sast_critical claim cannot, see the next test).
    result = run_team(prepared.context(recording, attempt="b"), prepared.work("lead", "ci_high"), launch=True)
    [record] = [item for values in result.independence.values() for item in values]
    assert record["independent"] is True and record["review_id"].startswith("review-")
    assert record["provider_distinct"] is False and record["verifier_model_distinct"] is False
    [verifier] = [item for item in result.cells if item.role is Role.INDEPENDENT_VERIFIER]
    supporting = [item for item in result.relations if item.producing_cell_id == verifier.cell_id]
    assert supporting and all(item.retrieval_receipt_sha256 == verifier.receipt_sha256 for item in supporting)


def test_a_distinct_verifier_profile_is_recorded_without_changing_independence(prepared) -> None:
    """Decision 2 via configuration: roles.independent_verifier.model_profile names another model."""
    settings = prepared.settings
    verifier_profile = replace(settings.models["default"], model="claude-verifier-model")
    models = MappingProxyType({**settings.models, "verifier": verifier_profile})
    roles = MappingProxyType({**settings.roles, Role.INDEPENDENT_VERIFIER: replace(
        settings.roles[Role.INDEPENDENT_VERIFIER], model_profile="verifier")})
    changed = replace(settings, models=models, roles=roles)
    assert changed.verifier_distinctness()["distinct"] is True and changed.verifier_distinctness()["warning"] is None
    assert settings.verifier_distinctness()["warning"]                       # the checked-in default
    recording = Recording(prepared.infer)
    result = run_team(prepared.context(recording, models=models, roles=roles), prepared.work("lead", "ci_high"),
                      launch=True)
    [record] = [item for values in result.independence.values() for item in values]
    assert record["independent"] is True and record["verifier_model_distinct"] is True
    assert record["provider_distinct"] is False
    assert {item.model for item in recording.by_role("independent_verifier")} == {"claude-verifier-model"}
    assert {item.model for item in recording.by_role("red_team_analyst")} == {settings.models["default"].model}


def test_a_verifier_citing_irrelevant_but_real_evidence_is_not_independent(prepared) -> None:
    """The sast_critical verifier cites a real build action for attacker control, reachability and guards.

    The citations resolve, but ``predicate-admission/2`` makes them indirect for those predicates, so no
    required predicate besides the construct has independent support and the claim reaches supported at best.
    """
    result = run_team(prepared.context(Recording(prepared.infer), attempt="c"),
                      prepared.work("lead", "sast_critical"), launch=True)
    [record] = [item for values in result.independence.values() for item in values]
    assert record["independent"] is False
    cited = [relation for relation in result.relations if relation.entity_kind == "build_action"]
    assert cited and not any(
        relation.admissibility.value == "direct" and relation.predicate.value in {
            "attacker_input_control", "source_to_sink_reachability", "missing_or_ineffective_guard"}
        for relation in cited)


# ------------------------------------------------------------------------------------------------ duplicates


def test_duplicate_proposal_merges_into_the_lead_claim_and_is_counted(prepared) -> None:
    lead_ctx = prepared.context(prepared.infer, lane="lead")
    hunt_ctx = prepared.context(prepared.infer, lane="hunt")
    shards = prepared.tmp / "shards"
    lead = run_lane(lead_ctx, Lane.LEAD, package_works(prepared.fixture.run_root, prepared.documents("lead")),
                    other_lane_count=2, ledger_path=shards / "lead.jsonl", stream="lead_review.teams",
                    signal_dir=prepared.tmp / "lanes")
    hunt = run_lane(hunt_ctx, Lane.HUNT, package_works(prepared.fixture.run_root, prepared.documents("hunt")),
                    other_lane_count=9, ledger_path=shards / "hunt.jsonl", stream="hunt_review.teams",
                    signal_dir=prepared.tmp / "lanes")
    projection = project(merge_shards([shards / "lead.jsonl", shards / "hunt.jsonl"]).events)
    merged = [view for view in projection.claims.values() if len(view.proposal_lanes) > 1]
    assert len(merged) == 1
    view = merged[0]
    assert view.proposal_lanes == (Lane.LEAD, Lane.HUNT) and view.claim.lane is Lane.LEAD
    assert view.duplicate_proposals == {Lane.LEAD: 0, Lane.HUNT: 1}
    assert view.claim.package_id in lead["packages"] and view.claim.duplicate_of is None
    hunt_cells = set(hunt["expected_cells"])
    assert set(view.claim.origin_cell_ids) & hunt_cells and set(view.claim.origin_cell_ids) - hunt_cells
    attached = {item.producing_cell_id for item in projection.relations[view.claim.claim_id]}
    assert attached & hunt_cells                                       # lane B evidence attached as relations
    expected_cells = {**{key: Lane(value) for key, value in lead["expected_cells"].items()},
                      **{key: Lane(value) for key, value in hunt["expected_cells"].items()}}
    packages = {**{key: Lane(value) for key, value in lead["packages"].items()},
                **{key: Lane(value) for key, value in hunt["packages"].items()}}
    accounting = exact_accounting(projection, expected_cells, packages, incomplete_gap_ratio=0.4)
    # Before adjudication every claim is still proposed; that is the only accounting violation.
    assert {gap.reason for gap in accounting.violations} == {"claim_not_final"}
    assert accounting.duplicate_proposals == 1 and accounting.lane(Lane.HUNT).duplicate_proposals == 1
    assert accounting.claims_by_state[ClaimState.DUPLICATE] == 0
    assert lead["allocation"] == {"lead": 9, "hunt": 1} == hunt["allocation"]
    assert json.loads((prepared.tmp / "lanes" / "hunt.json").read_text())["queue_empty"] is True


# ------------------------------------------------------------------------------------------------ failures


def test_provider_and_schema_failures_are_typed_gaps_with_terminal_records(prepared) -> None:
    result = run_team(prepared.context(prepared.infer), prepared.work("lead", "dep_high"), launch=True)
    [verifier] = [item for item in result.cells if item.role is Role.INDEPENDENT_VERIFIER]
    assert verifier.status is CellStatus.FAILED and verifier.attempts == prepared.settings.retry.max_attempts
    [claim_id] = result.verifier_gaps
    assert result.verifier_gaps[claim_id][0]["gap_class"] == "worker_gap"
    assert result.independence[claim_id][0]["independent"] is False

    def malformed(request, *, timeout_seconds):
        if request.role == "blue_team_refuter":
            return ModelResult(proposal={"action": "final", "result": {"schema": "wrong"}})
        return prepared.infer(request, timeout_seconds=timeout_seconds)

    result = run_team(prepared.context(malformed, attempt="b"), prepared.work("lead", "sast_high"), launch=True)
    blues = [item for item in result.cells if item.role is Role.BLUE_TEAM_REFUTER]
    assert blues and {item.status for item in blues} == {CellStatus.INVALID}
    assert any(gap.gap_class is GapClass.SCHEMA_ERROR and gap.subject_id == blues[0].cell_id for gap in result.gaps)


def test_a_team_failure_preserves_completed_red_records_and_names_the_gap(prepared, monkeypatch) -> None:
    from appsec_review.jobs.job_inference_security_review import teams

    def broken(*args, **kwargs):
        raise RuntimeError("normalization bug")

    monkeypatch.setattr(teams, "_normalize", broken)
    result = run_team(prepared.context(prepared.infer), prepared.work("lead", "sast_critical"), launch=True)
    assert [record.status for record in result.cells] == [CellStatus.SUCCEEDED] * 3
    assert len({record.cell_id for record in result.cells}) == 3
    assert not result.claims and not result.relations
    assert any(gap.subject_id == result.package_id and gap.gap_class is GapClass.WORKER_GAP for gap in result.gaps)


def test_an_entire_lane_failing_never_raises(prepared) -> None:
    def outage(request, *, timeout_seconds):
        raise ConnectionError("provider down")

    ctx = prepared.context(outage, lane="hunt")
    document = run_lane(ctx, Lane.HUNT, package_works(prepared.fixture.run_root, prepared.documents("hunt")),
                        other_lane_count=9, ledger_path=prepared.tmp / "hunt.jsonl", stream="hunt_review.teams",
                        signal_dir=prepared.tmp / "lanes")
    projection = project(merge_shards([prepared.tmp / "hunt.jsonl"]).events)
    statuses = sorted(records[0].status.value for records in projection.cells.values())
    assert statuses == ["failed"] * 3 + ["not_launched"] * 3 and not projection.claims
    assert document["counts"]["cells"] == 6
    failed = lane_failure(Lane.HUNT, package_works(prepared.fixture.run_root, prepared.documents("hunt")),
                          "RuntimeError", prepared.tmp / "failed.jsonl", "hunt_review.teams")
    gaps = project(merge_shards([prepared.tmp / "failed.jsonl"]).events).gaps
    assert {gap.subject_id for gap in gaps} == set(failed["packages"]) and not failed["expected_cells"]


def test_budgets_end_cells_not_launched_or_timed_out_and_are_never_retried(prepared) -> None:
    result = run_team(prepared.context(prepared.infer), prepared.work("lead", "sast_high"), launch=False,
                      not_launched_reason="allocation exhausted")
    assert {item.status for item in result.cells} == {CellStatus.NOT_LAUNCHED} and len(result.cells) == 3
    assert any(gap.gap_class is GapClass.BUDGET_GAP and gap.subject_id == result.package_id for gap in result.gaps)

    tiny = replace(prepared.settings.budgets, max_model_turns=1)
    result = run_team(prepared.context(prepared.infer, attempt="turns", budgets=tiny), prepared.work("lead", "sast_high"),
                      launch=True)
    # Red cells run concurrently, so which of them pass the launch check before the first turn is charged
    # is timing; only the bound and the terminal statuses are deterministic.
    launched = [item for item in result.cells if item.status is not CellStatus.NOT_LAUNCHED]
    assert len(launched) <= 3 and all(item.attempts <= 1 for item in result.cells)
    assert {item.status for item in launched} <= {CellStatus.SUCCEEDED, CellStatus.TIMED_OUT}
    # Exhaustion is sticky for the attempt: every later cell is not launched.
    again = run_team(prepared.context(prepared.infer, attempt="turns", budgets=tiny),
                     prepared.work("lead", "ci_high"), launch=True)
    assert {item.status for item in again.cells} == {CellStatus.NOT_LAUNCHED}
    assert any(gap.gap_class is GapClass.BUDGET_GAP for gap in again.gaps)

    profile = prepared.settings.models["default"]
    capped = MappingProxyType({"default": replace(profile, max_input_tokens=50)})
    result = run_team(prepared.context(prepared.infer, attempt="tokens", models=capped),
                      prepared.work("lead", "sast_high"), launch=True)
    assert {item.status for item in result.cells} == {CellStatus.TIMED_OUT}
    assert all(item.attempts == 1 for item in result.cells)
    assert {gap.reason for gap in result.gaps if gap.gap_class is GapClass.BUDGET_GAP} == {
        "cell_budget_exceeded:cell_token_cap"}

    def slow(request, *, timeout_seconds):
        time.sleep(1.2)
        return prepared.infer(request, timeout_seconds=timeout_seconds)

    short = MappingProxyType({"default": replace(profile, timeout_seconds=1)})
    teams = replace(prepared.settings.teams, red_per_team=1)
    result = run_team(prepared.context(slow, attempt="clock", models=short, teams=teams),
                      prepared.work("lead", "ci_high"), launch=True)
    assert [item.status for item in result.cells] == [CellStatus.TIMED_OUT]
    assert any(gap.reason == "cell_budget_exceeded:cell_deadline" for gap in result.gaps)


def test_rerunning_a_team_reuses_every_succeeded_cell(prepared) -> None:
    first = run_team(prepared.context(prepared.infer), prepared.work("lead", "sast_critical"), launch=True)
    recording = Recording(prepared.infer)
    again = run_team(prepared.context(recording, attempt="b"), prepared.work("lead", "sast_critical"), launch=True)
    assert not recording.requests
    assert again.counts["cells_reused"] == len(first.cells) == 7          # 3 red, 2 blue, verifier, judge
    assert again.cells == first.cells and again.relations == first.relations
    assert again.independence == first.independence


# ------------------------------------------------------------------------------------------------ isolation rules


def test_target_guidance_and_evaluator_files_never_enter_a_capability() -> None:
    for path in ("AGENTS.md", "svc/CLAUDE.md", ".github/copilot-instructions.md", ".cursorrules",
                 ".cursor/rules/style.mdc", ".github/instructions/review.md"):
        assert TARGET_GUIDANCE.search(path), path
    for path in ("svc/api/agents.py", "docs/agents.md.txt", "native/src/parse.c"):
        assert not TARGET_GUIDANCE.search(path), path
    scope = SimpleNamespace(source_files=(
        SourceFile("AGENTS.md", "asr:source_file:" + "1" * 64, None),
        SourceFile("appsec-multi-vuln-guide/answers.json", "asr:source_file:" + "2" * 64, None),
        SourceFile("svc/api/handler.py", "asr:source_file:" + "3" * 64, "Python")))
    assert _excluded(scope) == {"asr:source_file:" + "1" * 64, "asr:source_file:" + "2" * 64}


def test_closed_schema_validator_agrees_with_jsonschema() -> None:
    documents = [json.loads(path.read_text()) for path in SCHEMAS.glob("*.schema.json")]
    registry = Registry().with_resources((item["$id"], Resource.from_contents(item)) for item in documents)
    closed = SchemaSet(SCHEMAS)
    claim = "claim-" + "a" * 64
    red = {"schema": "appsec-review/red-discovery-result/1", "package": {"basis_sha256": "b" * 64},
           "role": "hypothesis_hunter", "round_id": "0", "result_status": "completed", "lead_accounting": [],
           "proposals": [], "proof_obligations": [], "taint_paths": [], "chain_seeds": [], "evidence_refs": [],
           "evidence_requests": [], "gaps": []}
    cases = [
        ("red-discovery-result", red),
        ("red-discovery-result", {**red, "extra": 1}),
        ("red-discovery-result", {**red, "round_id": "first"}),
        ("red-discovery-result", {**red, "evidence_refs": [{
            "local_id": "e1", "entity_id": "asr:symbol:" + "c" * 64, "shard_id": None, "shard_sha256": None,
            "relation": "supports", "predicate": "affected_construct",
            "locator": {"kind": "unresolved", "reason": "not read"}}]}),
        ("red-discovery-result", {**red, "evidence_refs": [{
            "local_id": "e1", "entity_id": "asr:symbol:" + "c" * 64, "shard_id": "graph/x", "shard_sha256": None,
            "relation": "supports", "predicate": "reachability",
            "locator": {"kind": "unresolved", "reason": "not read"}}]}),
        ("blue-result", {"schema": "appsec-review/blue-result/1", "claim_id": claim, "citations": {},
                         "proposed_relations": [], "evidence_requests": [], "rationale": "x",
                         "task": "blue_control", "disposition": "unresolved"}),
        ("blue-result", {"schema": "appsec-review/blue-result/1", "claim_id": claim, "citations": {},
                         "proposed_relations": [], "evidence_requests": [], "rationale": "x",
                         "task": "blue_control", "disposition": "supports_everything"}),
        ("verifier-result", {"schema": "appsec-review/verifier-result/1", "claim_id": "claim-x", "citations": {},
                             "proposed_relations": [], "evidence_requests": [], "rationale": "x",
                             "proposed_disposition": "confirmed"}),
    ]
    for name, document in cases:
        reference = Draft202012Validator(json.loads((SCHEMAS / f"{name}.schema.json").read_text()), registry=registry)
        assert (not closed.errors(name, document)) is reference.is_valid(document), (name, document)


# ------------------------------------------------------------------------------------------------ red-discovery-result/1


def _rewriting(inner, rewrite):
    """Pass every turn through; let ``rewrite(request, result)`` edit red final results in place."""

    def infer(request, *, timeout_seconds):
        response = inner(request, timeout_seconds=timeout_seconds)
        proposal = response.proposal
        if request.role in {"red_team_analyst", "hypothesis_hunter"} and proposal.get("action") == "final":
            result = json.loads(json.dumps(proposal["result"]))
            rewrite(request, result)
            return replace(response, proposal={**proposal, "result": result})
        return response

    return infer


def test_a_lead_the_answer_omits_is_a_blocked_lead_with_a_named_gap(prepared) -> None:
    def drop(request, result):
        result.pop("no_claim", None)
        result.pop("blocked", None)

    result = run_team(prepared.context(_rewriting(prepared.infer, drop)), prepared.work("lead", "sast_high"),
                      launch=True)
    reds = [item for item in result.cells if item.role is Role.RED_TEAM_ANALYST]
    assert reds and {item.status for item in reds} == {CellStatus.SUCCEEDED}
    outcomes = {outcome for _cell, _lead, outcome in result.lead_entries}
    assert "blocked" in outcomes and "proposal" in outcomes                   # an omitted lead is never clean
    assert any(gap.reason.startswith("worker_named_gap:missing:") for gap in result.gaps)


def test_red_citations_that_disagree_with_re_resolution_are_evidence_gaps() -> None:
    from appsec_review.jobs.job_inference_security_review.teams import _citation_mismatch
    from appsec_review.review.red_discovery import Citation

    ctx = SimpleNamespace(shard_sha256=lambda label: "a" * 64,
                          location=lambda identity: {"path": "a.py", "file_sha256": "b" * 64, "start_line": 5, "end_line": 6})
    relation = SimpleNamespace(shard_id="observations/real", entity_id="asr:symbol:" + "1" * 64)

    def citation(**changes):
        base = dict(local_id="e1", entity_id=relation.entity_id, predicate=None, kind=None, shard_id=None,
                    shard_sha256=None, locator={"kind": "unresolved", "reason": "x"}, via="proposal")
        return Citation(**{**base, **changes})

    assert _citation_mismatch(ctx, relation, citation()) is None
    assert _citation_mismatch(ctx, relation, citation(shard_id="observations/other")) == (
        "cited shard is not the accepted shard the entity re-resolves to")
    assert _citation_mismatch(ctx, relation, citation(shard_id="observations/real", shard_sha256="c" * 64)) == (
        "cited shard hash does not match the accepted manifest")
    elsewhere = {"kind": "source_line", "path": "elsewhere.py", "file_sha256": "e" * 64, "start_line": 1, "end_line": 2}
    assert _citation_mismatch(ctx, relation, citation(locator=elsewhere)).startswith("source-line locator")


def test_lead_accounting_and_named_gaps_reach_the_lane(prepared) -> None:
    def enrich(request, result):
        if request.task_input["task"] != "lead_red_stack" or not result["claims"]:
            return
        result["claims"][0]["missing"] = ["no deployment snapshot in the package"]

    ctx = prepared.context(_rewriting(prepared.infer, enrich), lane="lead")
    shards = prepared.tmp / "seeded"
    lane = run_lane(ctx, Lane.LEAD, package_works(prepared.fixture.run_root, prepared.documents("lead")),
                    other_lane_count=2, ledger_path=shards / "ledger.jsonl", stream="lead_review.teams",
                    signal_dir=prepared.tmp / "lanes-seeded")
    outcomes = {lead: summary["outcome"] for leads in lane["lead_accounting"].values() for lead, summary in leads.items()}
    assert outcomes[prepared.fixture.ids["sast_critical"]] == "proposal"
    assert set(outcomes.values()) <= {"proposal", "no_proposal", "blocked", "unaccounted"}
    assert "no_proposal" in outcomes.values()                         # looked, proposed nothing: not clean
    # The compact protocol carries no chain seeds: the artifact stays, empty, and the briefs artifact is empty too.
    artifact = json.loads((shards / "chain-seeds.json").read_text())
    assert artifact["schema"] == "appsec-review/red-chain-seeds/1" and artifact["seeds"] == []
    assert lane["chain_seeds"]["count"] == 0 and lane["poc_basis"]["count"] == 0
    assert json.loads((shards / "poc-basis.json").read_text())["schema"] == "appsec-review/red-poc-basis/1"
    projection = project(merge_shards([shards / "ledger.jsonl"]).events)
    assert any(gap.gap_class is GapClass.EVIDENCE_GAP and
               gap.reason.startswith("worker_named_gap:unresolved:g1: no deployment snapshot in the package")
               for gap in projection.gaps)


def test_poc_basis_briefs_are_stored_beside_the_claims_and_never_as_claim_state(tmp_path) -> None:
    from appsec_review.jobs.job_inference_security_review.teams import TeamResult, _poc_basis_artifact

    team = TeamResult("package-1", Lane.LEAD, None)
    team.poc_basis = [{"claim_id": "claim-" + "b" * 64, "package_id": "package-1", "lane": "lead",
                       "cell_id": "cell-" + "2" * 64, "poc_basis": {"entry": [], "path": []}},
                      {"claim_id": "claim-" + "a" * 64, "package_id": "package-1", "lane": "lead",
                       "cell_id": "cell-" + "1" * 64, "poc_basis": {"entry": [], "path": []}}]
    entry = _poc_basis_artifact(Lane.LEAD, [team], tmp_path / "poc-basis.json")
    document = json.loads((tmp_path / "poc-basis.json").read_text())
    assert entry["count"] == 2 and [item["claim_id"][-1] for item in document["briefs"]] == ["a", "b"]
    assert "not claims, evidence" in document["statement"]
