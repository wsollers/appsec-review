"""Offline execution contracts for routing, bounded rounds, admission and residual coverage."""
from dataclasses import fields, replace
import json
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.guidance import compose_bundle, load_persona_covers, load_registry
from appsec_review.jobs.job_inference_security_review.job import TOPOLOGY, _taxonomy, build_job
from appsec_review.jobs.job_inference_security_review.stages import apply_policy, completeness_gaps, merge_claims
from appsec_review.jobs.job_inference_security_review.teams import (
    PackageWork, _red_cells, _requests, _round_state, _seal, route, run_lane, run_team,
)
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.review.accounting import exact_accounting
from appsec_review.review.ledger import merge_shards, project
from appsec_review.review.lead_families import collect_leads
from appsec_review.review.models import CellStatus, Lane, Role
from appsec_review.review.packages import PackageSettings, admission_reasons, assemble_packages
from appsec_review.review.scope import accept_manifest
from appsec_review.runtime.runner import JobRunner
from tests.fixtures.inference_review import builder
from tests.fixtures.inference_review.acceptance import JOB, ROOT
from tests.review.test_team_handler import Recording, prepared
from tests.test_inference_review_config import _variant


def test_later_round_failure_keeps_completed_cells_and_accounts_for_current_reds(prepared, monkeypatch):
    from appsec_review.jobs.job_inference_security_review import teams
    from appsec_review.review.models import CellStatus

    original_run = teams._run
    failed = set()
    completed = set()

    def run_with_one_failure(ctx, cell, validate, **kwargs):
        if cell.spec.round == 1 and cell.spec.task == "lead_red_stack":
            failed.add(cell.cell_id)
            raise OSError("fixture receipt write failure")
        original_run(ctx, cell, validate, **kwargs)
        if cell.spec.round == 1:
            completed.add(cell.cell_id)

    monkeypatch.setattr(teams, "_run", run_with_one_failure)
    ctx = prepared.context(prepared.infer, rounds=replace(prepared.settings.rounds, max_rounds=2))
    result = run_team(ctx, prepared.work("lead", "ci_high"), launch=True)
    records = {record.cell_id: record for record in result.cells}
    assert failed and completed
    assert failed <= records.keys() and completed <= records.keys()
    assert all(records[cell].status is CellStatus.FAILED for cell in failed)
    assert all(records[cell].status is CellStatus.SUCCEEDED for cell in completed)
    assert len(records) == len(result.cells)
    assert any(item["round"] == 0 for item in result.capabilities)
    assert {item["cell_id"] for item in result.capabilities if item["round"] == 1} == failed | completed


@pytest.mark.parametrize(("languages", "component", "facts", "interfaces", "expected"), [
    (["Python"], "component:application-api-server", [], [], "python_service"),
    (["Java", "Python"], "component:application-api-server", [], [], "jvm_service"),
    (["Kotlin"], "component:android-mobile", [], [], "android"),
    (["Swift"], "component:ios-mobile", [], [], "ios"),
    (["C"], "component:platform-integration", ["wasm"], [], "wasm"),
    (["C"], "component:platform-integration", ["freestanding"], [], "c_systems_embedded"),
    (["C"], "component:application-api-server", [], ["protobuf"], "cpp_rpc_service"),
])
def test_accepted_facts_select_the_assembled_stack(tmp_path, monkeypatch, languages, component, facts,
                                                 interfaces, expected):
    original = builder.EntityRecord

    def entity(*args, **kwargs):
        record = original(*args, **kwargs)
        if record.native_id == "native-main":
            record = replace(record, payload={**record.payload, "languages": languages,
                                               "build_facts": facts, "interfaces": interfaces})
        if record.native_id == "tag-2":
            record = replace(record, name=component, payload={**record.payload, "tag": component})
        if record.native_id.startswith("native/") and record.identity.kind.value == "source_file":
            record = replace(record, payload={**record.payload, "language": languages[0]})
        return record

    monkeypatch.setattr(builder, "EntityRecord", entity)
    fixture = builder.build_accepted_index_set(tmp_path)
    scope = accept_manifest(fixture.run_root)
    assembly = assemble_packages(scope)
    package = next(item for item in assembly.packages if item.lead_ids == (fixture.ids["sast_critical"],))
    doc = package.document()
    assert fixture.ids["tag:2"] in doc["retrieval"]["entity_ids"]
    core = RetrievalCore(fixture.runs_dir, fixture.run_id, manifest_sha256=scope.manifest_sha256)
    settings = load_config(ROOT / "appsec-review.toml").job(JOB).typed_settings
    vocab, crosswalk = _taxonomy(ROOT)
    ctx = SimpleNamespace(core=core, entity_name=lambda identity: core.find(identity=identity, limit=1)["results"][0]["name"],
                          source_languages={item.identity: item.language for item in scope.source_files},
                          build_unit_languages={item.build_unit_id: item.languages for item in scope.build_units},
                          covers=load_persona_covers(ROOT, load_registry(ROOT)), settings=settings)
    work = PackageWork(package.package_id, Lane.LEAD, package.sha256, doc, (0, package.package_id),
                       doc["input_fingerprint"], tuple(doc["retrieval"]["entity_ids"]), package.unit_key)
    routed = route(ctx, work)
    assert routed["stack"] == expected
    bundle = compose_bundle(ROOT, role="red_team_analyst", persona=routed["persona"], stack=routed["stack"],
                            task="lead_red_stack", task_input={"lane": "lead"},
                            capability={"granted_tools": ["find"]}, vocabulary=vocab, crosswalk=crosswalk)
    stack = next(section for section in bundle["sections"] if section["name"] == "stack")
    assert expected in str(stack)


def test_medium_low_exploration_is_opt_in_and_bounded(tmp_path):
    fixture = builder.build_accepted_index_set(tmp_path)
    scope = accept_manifest(fixture.run_root)
    baseline = assemble_packages(scope)
    enabled = assemble_packages(scope, PackageSettings(exploration_enabled=True, exploration_reserve=2))
    initial = {item.package_id for item in baseline.packages}
    explored = [item for item in enabled.packages if item.kind == "finding_lead"
                and item.document()["lead_menu"][0]["admission_reasons"] == ["exploration_reserve"]]
    assert len(explored) == 2
    assert all(item.document()["lead_menu"][0]["reported_severity"] == "medium" for item in explored)
    assert initial
    excluded = [item for item in enabled.manifest["admission"] if item["status"] == "not_admitted"]
    assert any(item["residual_coverage"] == "exploration_reserve_cutoff" for item in excluded)
    assert all(item["effective_severity"] in {"medium", "low", "info"} for item in excluded)
    low = assemble_packages(scope, PackageSettings(exploration_enabled=True, exploration_reserve=4))
    assert any(item["status"] == "admitted" and item["effective_severity"] == "low"
               for item in low.manifest["admission"])
    informational = replace(collect_leads(scope).leads[0], reported_severity="info", advisory=None)
    assert not admission_reasons(informational, PackageSettings(exploration_enabled=True))
    assert len(completeness_gaps((), (), admission=excluded)) == len(excluded)


@pytest.mark.parametrize("profile", ["dev", "copilot-dev", "prod", "copilot-prod"])
@pytest.mark.parametrize("severity", ["medium", "low"])
def test_resolved_profiles_admit_bounded_exploration(tmp_path, profile, severity):
    config = load_config(ROOT / "appsec-review.toml", profile=profile)
    settings = config.job(JOB).typed_settings
    enabled = profile in {"prod", "copilot-prod"}
    assert settings.lanes.exploration_enabled is enabled
    assert settings.lanes.exploration_reserve == 1
    assert "info" not in settings.lanes.lead_admission
    assert json.loads(config.resolved_json)["jobs"][JOB]["settings"]["lanes"]["exploration_enabled"] is enabled
    scope = accept_manifest(builder.build_accepted_index_set(tmp_path).run_root)
    collection = collect_leads(scope)
    # Keep urgent and informational leads, with only the requested exploratory severity competing.
    collection = replace(collection, leads=tuple(
        lead for lead in collection.leads if lead.effective_severity not in {"medium", "low"}
        or lead.effective_severity == severity))
    assembly = assemble_packages(scope, PackageSettings.from_review_settings(settings), collection=collection)
    explored = [item for item in assembly.manifest["admission"]
                if item["status"] == "admitted" and item["reasons"] == ["exploration_reserve"]]
    assert len(explored) == int(enabled)
    assert all(item["effective_severity"] == severity for item in explored)
    assert all(item["status"] == "not_admitted" for item in assembly.manifest["admission"]
               if item["effective_severity"] == "info")


@pytest.mark.parametrize(("budget", "reserve"), [("all", 4), (1, 1), (2, 2), (200, 4)])
def test_package_settings_bound_exploration_for_all_and_finite_budgets(budget, reserve):
    settings = load_config(ROOT / "appsec-review.toml", profile="prod").job(JOB).typed_settings
    settings = replace(settings, lanes=replace(settings.lanes, exploration_reserve=4),
                       budgets=replace(settings.budgets, budget_team_packages=budget))
    assert PackageSettings.from_review_settings(settings).exploration_reserve == reserve


@pytest.mark.parametrize("profile", ["prod", "copilot-prod"])
def test_production_rounds_use_actual_models_and_confirmed_local_variant_seeds(prepared, profile):
    settings = load_config(ROOT / "appsec-review.toml", profile=profile).job(JOB).typed_settings

    def infer(request, *, timeout_seconds):
        if request.role == "hypothesis_hunter":
            return prepared.infer._lead_red(request, "lead_red_stack", request.task_input["input"])
        return prepared.infer(request, timeout_seconds=timeout_seconds)

    recording = Recording(infer)
    ctx = prepared.context(recording, **{item.name: getattr(settings, item.name) for item in fields(settings)})
    scope = accept_manifest(prepared.fixture.run_root)
    assembly = assemble_packages(scope, PackageSettings.from_review_settings(settings))
    package = next(item for item in assembly.packages
                   if item.kind == "hunt" and prepared.fixture.ids["ci_high"] in item.lead_ids)
    doc = package.document()
    work = PackageWork(package.package_id, Lane.HUNT, package.sha256, doc, (0, package.package_id),
                       doc["input_fingerprint"], tuple(doc["retrieval"]["entity_ids"]), package.unit_key)
    result = run_team(ctx, work, launch=True)
    assert result.launched and all(cell.status is CellStatus.SUCCEEDED for cell in result.cells)
    assert 1 < len(result.rounds) <= settings.rounds.max_rounds == 3
    assert result.rounds[-1]["stop_reason"] == "stable"
    assert result.rounds[0]["variant_seed_ids"]
    variants = [request for request in recording.requests if request.task_input["task"] == "variant"]
    assert variants
    for request in variants:
        assert request.task_input["input"]["round"] >= 1
        seeds = request.task_input["input"]["variant_seeds"]
        assert seeds and all(seed["state"] == "confirmed" for seed in seeds)
        assert {seed["claim_id"] for seed in seeds} <= {claim.claim_id for claim in result.claims}
        assert all(seed["adjudication_id"] and seed["policy_sha256"] and seed["evidence_labels"] for seed in seeds)
    assert {request.role for request in recording.requests} == {
        "hypothesis_hunter", "blue_team_refuter", "independent_verifier", "adjudication_judge"}
    for request in recording.requests:
        model = settings.profile_for(Role(request.role))
        assert (request.provider, request.model, request.reasoning) == (model.provider, model.model, model.reasoning)
        expected_skills = {
            "hypothesis_hunter": ["generative-investigation"],
            "blue_team_refuter": ["effective-control-verification"],
            "independent_verifier": ["predicate-verification"],
            "adjudication_judge": ["conflict-resolution"],
        }[request.role]
        if request.task_input["task"] == "control_gap":
            expected_skills.append("effective-control-verification")
        bundle = next(item["bundle"] for item in ctx._bundles.values()
                      if item["bundle"]["sha256"] == request.guidance_bundle_sha256)
        procedures = next(section for section in bundle["sections"] if section["name"] == "procedures")
        assert [item["id"] for item in procedures["items"]] == expected_skills
        assert all(item["text"] in request.guidance_text for item in procedures["items"])
        assert request.persona in ctx.covers
        assert request.stack_profile == result.routing["stack"]
        if request.role == "adjudication_judge":
            assert request.persona == "generalist"
    known, _ = _round_state(ctx, work, result)
    supported = replace(work, round_index=1, known_claims=tuple({**seed, "state": "supported"} for seed in known))
    assert all(cell.strategy != "variant" for cell in _red_cells(ctx, supported, route(ctx, supported)))
    assert all(request.task_input["input"]["round"] > 0 for request in variants)
    assert ctx.budget.snapshot().team_packages[Lane.HUNT] == 1
    assert any(gap.reason == "cross_package_and_cross_lane_variant_seeds_unavailable" for gap in result.gaps)


@pytest.mark.parametrize("profile", ["prod", "copilot-prod"])
def test_production_exploration_is_scheduled_with_follow_up_rounds(prepared, profile):
    settings = load_config(ROOT / "appsec-review.toml", profile=profile).job(JOB).typed_settings
    ctx = prepared.context(prepared.infer, **{item.name: getattr(settings, item.name) for item in fields(settings)})
    scope = accept_manifest(prepared.fixture.run_root)
    assembly = assemble_packages(scope, PackageSettings.from_review_settings(settings))
    package = next(item for item in assembly.packages if item.kind == "finding_lead"
                   and item.document()["lead_menu"][0]["admission_reasons"] == ["exploration_reserve"])
    doc = package.document()
    work = PackageWork(package.package_id, Lane.LEAD, package.sha256, doc, (0, package.package_id),
                       doc["input_fingerprint"], tuple(doc["retrieval"]["entity_ids"]), package.unit_key)
    lane = run_lane(ctx, Lane.LEAD, [work], other_lane_count=0, ledger_path=prepared.tmp / "prod-lane.jsonl",
                    stream="lead_review.teams", signal_dir=prepared.tmp / "prod-signals")
    assert lane["launched"] == [work.package_id]
    assert lane["exploration"][work.package_id]["status"] == "explored"
    assert ctx.budget.snapshot().team_packages[Lane.LEAD] == 1
    assert {item["round"] for item in lane["capabilities"]} == {0, 1}


def test_production_all_packages_keeps_the_shared_active_claim_bound(tmp_path, monkeypatch):
    from appsec_review.jobs.job_inference_security_review import teams

    settings = load_config(ROOT / "appsec-review.toml", profile="prod").job(JOB).typed_settings
    counts = {Lane.LEAD: 485, Lane.HUNT: 114}
    assigned = {}

    def record_allocation(ctx, work, *, launch, not_launched_reason):
        assert launch
        assigned[work.package_id] = work.active_claim_limit
        return teams.TeamResult(work.package_id, work.lane, work.unit_key, launched=True)

    monkeypatch.setattr(teams, "run_team", record_allocation)
    for lane, count in counts.items():
        packages = [PackageWork(f"{lane.value}-{index:04d}", lane, "a" * 64, {}, (index, str(index)),
                                "fixture", (), None) for index in range(count)]
        result = run_lane(SimpleNamespace(settings=settings), lane, packages,
                          other_lane_count=sum(counts.values()) - count,
                          ledger_path=tmp_path / lane.value / "ledger.jsonl",
                          stream=f"{lane.value}_review.teams", signal_dir=tmp_path / "signals")
        assert len(result["launched"]) == count
    assert sum(assigned.values()) == settings.rounds.max_active_claims == 500
    assert sum(value == 0 for value in assigned.values()) == 99
    assert assigned["hunt-0014"] == 1 and assigned["hunt-0015"] == 0


@pytest.mark.parametrize(("old", "new"), [
    ("exploration_enabled = false", 'exploration_enabled = "true"'),
    ("exploration_reserve = 1", "exploration_reserve = false"),
    ("exploration_reserve = 1", "exploration_reserve = 0"),
])
def test_exploration_configuration_rejects_wrong_types_and_empty_reserve(tmp_path, old, new):
    with pytest.raises(ValueError, match="exploration_"):
        _variant(tmp_path, (old, new))


def test_exploration_opt_in_preserves_all_model_and_budget_limits(tmp_path):
    before = load_config(ROOT / "appsec-review.toml").job(JOB).typed_settings
    after = _variant(tmp_path, ("exploration_enabled = false", "exploration_enabled = true")).job(JOB).typed_settings
    assert after.lanes.exploration_enabled
    assert after.models == before.models
    assert after.budgets == before.budgets


@pytest.mark.parametrize("stable_rounds", [1, 2])
def test_rounds_use_accepted_seeds_deduplicate_and_account(prepared, stable_rounds):
    recording = Recording(prepared.infer)
    ctx = prepared.context(recording, rounds=replace(prepared.settings.rounds, stable_rounds_required=stable_rounds))
    work = prepared.work("lead", "ci_high")
    result = run_team(ctx, work, launch=True)
    assert len(result.rounds) == stable_rounds + 1
    assert result.rounds[-1]["stop_reason"] == "stable"
    assert len(result.claims) == 1
    assert result.rounds[0]["variant_seed_ids"] == [result.claims[0].claim_id]
    assert {item["round"] for item in result.capabilities} == set(range(stable_rounds + 1))
    second = [request.task_input["input"] for request in recording.by_role("red_team_analyst")
              if request.task_input["input"]["round"] == 1]
    assert second and all(item["known_claims"][0]["state"] == "confirmed" for item in second)
    assert all(item["known_claims"][0]["evidence_labels"] for item in second)
    assert ctx.budget.snapshot().team_packages["lead"] == 1
    ledger = prepared.tmp / "rounds.jsonl"
    lane = _seal(ctx, Lane.LEAD, [result], {Lane.LEAD: 1, Lane.HUNT: 0}, ledger, "rounds")
    projection = project(merge_shards([ledger]).events)
    assert len(projection.claims) == 1
    assert not any(sum(view.duplicate_proposals.values()) for view in projection.claims.values())
    merged = merge_claims([lane], [ledger], {work.package_id: work.entities}, ())
    adjudications = prepared.tmp / "adjudications.jsonl"
    decisions = apply_policy(merged, projection, adjudications, "adjudications")
    assert decisions["adjudications"][0]["round"] == stable_rounds
    projection = project(merge_shards([ledger, adjudications]).events)
    accounting = exact_accounting(projection, {key: Lane(value) for key, value in lane["expected_cells"].items()},
                                  {work.package_id: Lane.LEAD}, incomplete_gap_ratio=1)
    assert not accounting.violations
    assert lane["counts"]["cells"] == len(result.cells) == len({cell.cell_id for cell in result.cells})
    for request in recording.by_role("independent_verifier"):
        hypothesis = request.task_input["input"]["claim"]["hypothesis"]
        assert hypothesis["condition"] == str(result.claims[0].security_predicate)
        assert "statement" not in request.task_input["input"]["claim"]


def test_variant_dispatch_requires_r5_r6_confirmed_seed(prepared):
    ctx = prepared.context(prepared.infer)
    work = prepared.work("lead", "ci_high")
    result = run_team(ctx, work, launch=True)
    known, _ = _round_state(ctx, work, result)
    assert known and known[0]["state"] == "confirmed"
    hunt = replace(work, lane=Lane.HUNT, round_index=1, known_claims=tuple(known))
    cells = _red_cells(ctx, hunt, route(ctx, hunt))
    variant = next(cell for cell in cells if cell.strategy == "variant")
    assert variant.spec.round == variant.capability.round == variant.invocation.round == 1
    assert variant.spec.task_input["variant_seeds"]
    evidence_changed = replace(hunt, known_claims=({**known[0], "evidence_relations": ["different-evidence"]},))
    other_variant = next(cell for cell in _red_cells(ctx, evidence_changed, route(ctx, evidence_changed))
                         if cell.strategy == "variant")
    assert other_variant.cell_id != variant.cell_id
    assert any(gap.reason == "panel_size_cutoff" for gap in route(ctx, hunt)["gaps"])
    changed = replace(hunt, known_claims=())
    assert all(cell.strategy != "variant" for cell in _red_cells(ctx, changed, route(ctx, changed)))
    assert any(gap.reason == "required_source_unavailable:confirmed_claims" for gap in route(ctx, changed)["gaps"])
    result.relations.clear()
    result.independence.clear()
    known, _ = _round_state(ctx, work, result)
    assert known == []


def test_round_cutoff_active_claim_limit_and_budget_are_honest(prepared):
    ctx = prepared.context(prepared.infer, rounds=replace(prepared.settings.rounds, max_rounds=1))
    work = replace(prepared.work("hunt", "sast_critical"), active_claim_limit=1)
    result = run_team(ctx, work, launch=True)
    assert len(result.claims) == 1
    assert any(gap.reason == "max_active_claims" for gap in result.gaps)
    assert result.rounds[-1]["stop_reason"] == "max_rounds"
    assert any(gap.reason == "follow_up_cutoff:max_rounds" for gap in result.gaps)
    assert any(gap.reason == "cross_package_and_cross_lane_variant_seeds_unavailable" for gap in result.gaps)


def test_referral_fields_and_round_survive_ledger(prepared):
    ctx = prepared.context(prepared.infer)
    work = prepared.work("lead", "ci_high")
    result = run_team(ctx, work, launch=True)
    cell = _red_cells(ctx, replace(work, round_index=1), route(ctx, work))[0]
    result.requests = _requests(cell, result.claims[0].claim_id, [{
        "predicate": "configuration_enables", "requested_kind": "configuration", "anchors": list(work.entities[:1]),
        "question": "Which accepted configuration enables this operation?", "specialist": "business_logic_abuse",
    }])
    path = prepared.tmp / "referrals.jsonl"
    _seal(ctx, Lane.LEAD, [result], {Lane.LEAD: 1, Lane.HUNT: 0}, path, "referrals")
    projection = project(merge_shards([path]).events)
    request = next(iter(projection.evidence_requests.values()))
    assert request.specialist == "business_logic_abuse"
    assert request.anchors == tuple(work.entities[:1])
    assert request.question.startswith("Which accepted")
    assert any(gap.reason == "unresolved_specialist_referral:business_logic_abuse" for gap in projection.gaps)


def test_expected_specialists_are_not_satisfied_by_one_selected_persona(prepared):
    ctx = prepared.context(prepared.infer)
    work = prepared.work("lead", "sast_critical")
    work = replace(work, document={**work.document, "lead_menu": [
        {**work.document["lead_menu"][0], "rule_cwe": ["CWE-120", "CWE-78"]}]})
    routing = route(ctx, work)
    assert len(routing["expected_personas"]) >= 2
    assert routing["missing_personas"]
    assert any(gap.reason == "expected_specialist_not_scheduled" for gap in routing["gaps"])


def test_scheduler_reserves_exploration_without_expanding_package_budget(prepared):
    work = prepared.work("lead", "sast_critical")
    exploratory = replace(work, package_id="exploratory", document={**work.document, "lead_menu": [
        {**work.document["lead_menu"][0], "admission_reasons": ["exploration_reserve"]}]})
    settings = prepared.settings
    ctx = prepared.context(prepared.infer, budgets=replace(settings.budgets, budget_team_packages=1),
                           rounds=replace(settings.rounds, max_active_claims=1, max_rounds=1))
    lane = run_lane(ctx, Lane.LEAD, [work, exploratory], other_lane_count=0,
                    ledger_path=prepared.tmp / "allocation.jsonl", stream="allocation",
                    signal_dir=prepared.tmp / "allocation-signals")
    assert lane["launched"] == ["exploratory"]
    assert sum(ctx.budget.snapshot().team_packages.values()) == 1
    assert len(lane["proposals"]) <= 1
    assert lane["exploration"]["exploratory"]["status"] == "explored"


def test_bounded_rounds_publish_end_to_end_without_live_models(prepared):
    job = build_job(infer=prepared.infer, repository_root=ROOT)
    runner = JobRunner(load_config(prepared.tmp / "review" / "appsec-review.toml"))
    attempt = runner.begin_attempt(job, run_id=prepared.fixture.run_id)
    outputs = {}
    for step, tasks in TOPOLOGY.items():
        for task in tasks:
            unit_id = f"{step}.{task}"
            outputs[unit_id] = runner.execute_or_reuse_unit(job, attempt, unit_id)
    assert outputs["publication.publish_claim_ledger"]["ledger_head_sha256"]
    assert outputs["publication.publish_handoff"]["terminal_status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
