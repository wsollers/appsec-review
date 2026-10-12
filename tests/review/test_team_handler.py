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
from appsec_review.jobs.job_inference_security_review.job import (
    TARGET_GUIDANCE, _excluded, package_works, review_context,
)
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_inference_security_review.teams import lane_allocation, lane_failure, run_lane, run_team
from appsec_review.review.accounting import exact_accounting
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
    for unit in ("scope.accept_manifest", "scope.assemble_scope", "packages.assemble_lead_packages",
                 "packages.assemble_hunt_packages"):
        outputs[unit] = runner.execute_or_reuse_unit(job, claim, unit)
    settings = load_config(config).job(JOB).typed_settings

    def documents(lane: str) -> dict:
        return json.loads((fixture.run_root / outputs[f"packages.assemble_{lane}_packages"]["artifact"]["path"])
                          .read_text())

    def context(infer, *, lane: str = "lead", attempt: str = "a", **changes):
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
        if request.task_input["task"] == "blue_reachability":
            assert guard not in text                                  # never the other blue's output
    verifiers = recording.by_role("independent_verifier")
    assert verifiers
    markers = [NARRATIVES["C3"], guard, "for the scripted review", "blue rationale"]
    for request in verifiers:
        text = json.dumps(asdict(request), default=str)
        assert "statement" not in request.task_input["input"]["claim"]
        assert not any(marker in text for marker in markers)

    recording = Recording(prepared.infer)
    result = run_team(prepared.context(recording, attempt="b"), prepared.work("lead", "sast_critical"), launch=True)
    [record] = [item for values in result.independence.values() for item in values]
    assert record["independent"] is True and record["review_id"].startswith("review-")
    assert record["provider_distinct"] is False
    [verifier] = [item for item in result.cells if item.role is Role.INDEPENDENT_VERIFIER]
    supporting = [item for item in result.relations if item.producing_cell_id == verifier.cell_id]
    assert supporting and all(item.retrieval_receipt_sha256 == verifier.receipt_sha256 for item in supporting)


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


def test_a_team_failure_is_a_package_gap_with_terminal_red_records(prepared, monkeypatch) -> None:
    from appsec_review.jobs.job_inference_security_review import teams

    def broken(*args, **kwargs):
        raise RuntimeError("normalization bug")

    monkeypatch.setattr(teams, "_normalize", broken)
    result = run_team(prepared.context(prepared.infer), prepared.work("lead", "sast_critical"), launch=True)
    assert [record.status for record in result.cells] == [CellStatus.FAILED] * 3
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
    launched = [item for item in result.cells if item.status is not CellStatus.NOT_LAUNCHED]
    assert len(launched) <= 3 and any(item.status is CellStatus.NOT_LAUNCHED for item in result.cells)

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
    assert again.counts["cells_reused"] == len(first.cells) == 6
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
    cases = [
        ("red-result", {"schema": "appsec-review/red-result/1", "claims": []}),
        ("red-result", {"schema": "appsec-review/red-result/1", "claims": [], "extra": 1}),
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
