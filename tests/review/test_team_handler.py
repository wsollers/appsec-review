"""Review-team handler: lane allocation, triage, isolation, duplicate proposals, and failure gaps."""
from __future__ import annotations

from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import shutil
import time
from types import MappingProxyType, SimpleNamespace

from jsonschema import Draft202012Validator
import pytest
from referencing import Registry, Resource

from appsec_review.config import load_config
from appsec_review.inference import ModelResult
from appsec_review.inference.errors import ProviderError
from appsec_review.jobs.job_inference_security_review import teams as team_handler
from appsec_review.jobs.job_inference_security_review.job import (
    TARGET_GUIDANCE, _excluded, lead_package_rank, package_works, review_context,
)
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_inference_security_review.teams import lane_allocation, lane_failure, run_lane, run_team
from appsec_review.review.accounting import exact_accounting
from appsec_review.review.budget import JobBudget
from appsec_review.review.ledger import merge_shards, project
from appsec_review.review.models import CellStatus, ClaimState, GapClass, Lane, Role
from appsec_review.review.scope import SourceFile
from tests.fixtures.inference_review.acceptance import JOB, ROOT, write_config
from tests.fixtures.inference_review.builder import build_accepted_index_set
from tests.fixtures.inference_review.fake_infer import NARRATIVES, ScriptedInfer
from tests.final_report_support import job_tables


def _full_protocol(settings):
    """The behaviour tests exercise the whole team protocol: three red lenses, two blue refuters, the judge,
    three rounds and twelve turns. The repository's defaults are right-sized by review protocol v3 (one red, no
    blue, judge off, one round, four turns; T-5033); the mechanics under test do not depend on that policy."""
    judge = replace(settings.roles[Role.ADJUDICATION_JUDGE], enabled=True)
    roles = MappingProxyType({**settings.roles, Role.ADJUDICATION_JUDGE: judge})
    models = MappingProxyType({**settings.models, "default": replace(settings.models["default"], max_turns=12)})
    return replace(settings, teams=replace(settings.teams, red_per_team=3, blue_per_team=2),
                   rounds=replace(settings.rounds, max_rounds=3), roles=roles, models=models,
                   lanes=replace(settings.lanes, hunt_max_units=50))

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


@pytest.fixture(scope="session")
def _prepared_template(tmp_path_factory):
    import threading
    from appsec_review.guidance.coverage import crosswalk_tags
    from appsec_review.jobs.job_inference_security_review.job import (
        EVIDENCE_RULES, JOB_ID, _artifact, _membership, _taxonomy,
    )
    from appsec_review.retrieval import RetrievalCore
    from appsec_review.review import tool_rules
    from appsec_review.review.claims import normalize_cwe
    from appsec_review.review.identity import sha256_hex
    from appsec_review.review.lead_families import collect_leads
    from appsec_review.review.packages import (
        ASSEMBLY_RULE, PackageSettings, assemble_packages, publish_packages,
    )
    from appsec_review.review.references import load_cwe_reference
    from appsec_review.review.scope import accept_manifest
    from appsec_review.review.slicing.sources import AcceptedSliceSources
    from appsec_review.storage import atomic_json, bounded_file_lock

    basetemp = Path(tmp_path_factory.getbasetemp())
    session_root = basetemp.parent if basetemp.name.startswith("popen-gw") else basetemp
    base = session_root / "team-handler-template"
    ready_path = base / "ready.json"
    # Durability is tested in storage unit/integration suites; unit team handler tests check semantics.
    with pytest.MonkeyPatch.context() as mp:
        mp.delenv("APPSEC_REVIEW_CONFIG_OVERLAY", raising=False)
        mp.setattr(os, "fsync", lambda descriptor: None)
        with bounded_file_lock(session_root / "team-handler-template.lock", 60.0):
            if not ready_path.is_file():
                shutil.rmtree(base, ignore_errors=True)
                base.mkdir(parents=True, exist_ok=True)
                config = write_config(base, base / "runs", overrides={"backoff_seconds": [0]},
                                      extra=job_tables("job_third_party_data_sync"))
                settings = _full_protocol(load_config(config).job(JOB).typed_settings)
                built = build_accepted_index_set(base, config=config, publish_v1_packages=False)
                scope = accept_manifest(built.run_root)
                evidence_map = scope.evidence_map()
                evidence_map_path = built.run_root / "data" / "jobs" / JOB_ID / "evidence-map.json"
                atomic_json(evidence_map_path, evidence_map)
                scope_out = {
                    "artifact": _artifact(built.run_root, evidence_map_path),
                    "source_languages": {item.identity: item.language for item in scope.source_files if item.language},
                    "build_unit_languages": {item.build_unit_id: list(item.languages) for item in scope.build_units},
                }
                core = RetrievalCore(built.runs_dir, built.run_id, manifest_sha256=scope.manifest_sha256)
                reference = load_cwe_reference(built.run_root)
                assembly = assemble_packages(
                    scope, PackageSettings.from_review_settings(settings),
                    collection=collect_leads(scope, filters=settings.lead_filters),
                    cwe_reference=reference,
                    slice_sources=AcceptedSliceSources(scope, core=core),
                    behavior_core=core,
                )
                manifest_path = publish_packages(
                    assembly, built.run_root / "data" / "jobs" / JOB_ID / "assembly", run_root=built.run_root,
                )
                excluded = _excluded(scope)
                positions = {row["unit_key"]: row["position"] for row in assembly.manifest["units"]}
                leads = [lead for package in assembly.packages for lead in package.document()["lead_menu"]]
                fallback = {normalize_cwe(cwe) for lead in leads for cwe in lead.get("rule_cwe", ())}
                _vocabulary, crosswalk = _taxonomy(ROOT)
                fallback |= {normalize_cwe(tag.split(":", 1)[1]) for tag in crosswalk_tags(crosswalk)
                             if tag.startswith("cwe:")}
                reference = reference.with_fallback(frozenset(item for item in fallback if item))
                cwe_ids = sorted(item for item in reference.accepted_ids if item)
                rule_predicates = {
                    lead["observation_id"]: [item.value for item in tool_rules.lead_predicates(lead)]
                    for lead in sorted(leads, key=lambda item: item["observation_id"])
                }
                units = [
                    {"unit_key": row["unit_key"], "position": row["position"], "hunted": row["hunted"],
                     "source_ids": row["source_ids"], "coverage_scope": row["coverage_scope"]}
                    for row in assembly.manifest["units"]
                ]
                lane_counts = {
                    item.value: sum(1 for package in assembly.packages if package.lane == item.value)
                    for item in Lane
                }
                docs = {}
                for lane in (Lane.LEAD, Lane.HUNT):
                    mine = [package for package in assembly.packages if package.lane == lane.value]
                    entities = {
                        package.package_id: tuple(sorted(set(package.resolved()["retrieval"]["entity_ids"]) - excluded))
                        for package in mine
                    }
                    membership = _membership(scope, {item for values in entities.values() for item in values})
                    records = []
                    for package in mine:
                        document = package.document()
                        rank = (
                            lead_package_rank(document)
                            if lane is Lane.LEAD else (int(positions[package.unit_key]), package.package_id)
                        )
                        sanitized = {
                            key: value for key, value in document.items()
                            if key not in {"package_id", "manifest_sha256", "input_fingerprint", "run_id"}
                        }
                        shards = sorted({label for identity in entities[package.package_id]
                                         for label in membership.get(identity, ())})
                        basis = sha256_hex({"package": sanitized, "shards": shards, "assembly": ASSEMBLY_RULE,
                                            **EVIDENCE_RULES})
                        records.append({
                            "package_id": package.package_id, "kind": package.kind, "lane": lane.value,
                            "sha256": package.sha256, "unit_key": package.unit_key, "rank": list(rank),
                            "basis": basis, "dependency_shards": shards,
                            "entities": list(entities[package.package_id]),
                            "path": (manifest_path.parent / "packages" / f"{package.package_id}.json")
                            .resolve().relative_to(built.run_root.resolve()).as_posix(),
                        })
                    docs[lane.value] = {
                        "schema": "appsec-review/inference-review-lane-packages/1", "lane": lane.value,
                        "package_manifest": _artifact(built.run_root, manifest_path),
                        "package_manifest_content_sha256": assembly.manifest["content_sha256"],
                        "lane_counts": lane_counts,
                        "packages": sorted(records, key=lambda item: (item["rank"], item["package_id"])),
                        "admission": assembly.manifest["admission"],
                        "accepted_cwe_ids": cwe_ids,
                        "cwe_reference": reference.record(),
                        "rule_predicates": rule_predicates,
                        "units": units,
                    }
                ready_path.write_text(
                    json.dumps({
                        "run_id": built.run_id,
                        "runs_dir": str(built.runs_dir),
                        "run_root": str(built.run_root),
                        "ids": dict(built.ids),
                        "upstream_handoffs": dict(built.upstream_handoffs),
                        "manifest_sha256": scope.manifest_sha256,
                        "scope_out": scope_out,
                        "docs": docs,
                    }),
                    encoding="utf-8",
                )
        ready = json.loads(ready_path.read_text(encoding="utf-8"))
        config = base / "appsec-review.toml"
        settings = _full_protocol(load_config(config).job(JOB).typed_settings)
        fixture = SimpleNamespace(
            run_id=ready["run_id"],
            runs_dir=Path(ready["runs_dir"]),
            run_root=Path(ready["run_root"]),
            ids=dict(ready["ids"]),
            upstream_handoffs=dict(ready.get("upstream_handoffs", {})),
        )
        docs = ready["docs"]
        manifest_sha256 = ready["manifest_sha256"]
        # Build one base ReviewContext on a throwaway copy so fixture.run_root has no initialized budget ledger.
        ctx_runs = tmp_path_factory.mktemp("ctx-template") / "runs"
        ctx_root = ctx_runs / fixture.run_id
        shutil.copytree(fixture.run_root, ctx_root)
        base_ctx = review_context(
            run_root=ctx_root, run_id=fixture.run_id, attempt_root=ctx_runs / "template-attempt",
            repository_root=ROOT, settings=settings, infer=ScriptedInfer({"ids": fixture.ids}),
            manifest_sha256=manifest_sha256, packages_doc=docs["lead"], scope_out=ready["scope_out"],
        )
        base_contexts = {"lead": base_ctx, "hunt": base_ctx}
    return SimpleNamespace(
        fixture=fixture, settings=settings, docs=docs,
        manifest_sha256=manifest_sha256, base_contexts=base_contexts,
        bundles={}, symbols={}, path_symbols={}, views={}, resolves={}, names={}, locations={},
        cache_lock=threading.Lock(),
    )


@pytest.fixture()
def prepared(tmp_path: Path, monkeypatch, _prepared_template):
    from appsec_review.jobs.job_inference_security_review.job import JOB_ID, ReviewTeamSemaphore
    from appsec_review.retrieval import RetrievalCore
    from appsec_review.review.result_cache import cache_from_settings

    monkeypatch.delenv("APPSEC_REVIEW_CONFIG_OVERLAY", raising=False)
    monkeypatch.setattr(os, "fsync", lambda descriptor: None)
    runs_dir = tmp_path / "review" / "runs"
    run_root = runs_dir / _prepared_template.fixture.run_id
    shutil.copytree(_prepared_template.fixture.run_root, run_root)
    config_path = write_config(
        tmp_path / "review",
        runs_dir,
        overrides={"backoff_seconds": [0]},
        extra=job_tables("job_third_party_data_sync"),
    )
    fixture = SimpleNamespace(
        run_id=_prepared_template.fixture.run_id,
        runs_dir=runs_dir,
        run_root=run_root,
        ids=dict(_prepared_template.fixture.ids),
        upstream_handoffs=dict(_prepared_template.fixture.upstream_handoffs),
        config=config_path,
    )
    settings = _prepared_template.settings

    def documents(lane: str) -> dict:
        return json.loads(json.dumps(_prepared_template.docs[lane]))

    def context(infer, *, lane: str = "lead", attempt: str = "a", **changes):
        changes.setdefault("rounds", replace(settings.rounds, max_rounds=1, stable_rounds_required=1))
        resolved = replace(settings, **changes) if changes else settings
        core = RetrievalCore(fixture.runs_dir, fixture.run_id,
                             manifest_sha256=_prepared_template.manifest_sha256)
        same_packages = resolved.packages == settings.packages
        return replace(
            _prepared_template.base_contexts[lane],
            run_root=fixture.run_root,
            settings=resolved,
            core=core,
            infer=infer,
            attempt_id=Path(tmp_path / "attempts" / attempt).name,
            result_cache=cache_from_settings(resolved.result_cache, fixture.run_id),
            receipts_root=fixture.run_root / "data" / "jobs" / JOB_ID / "cells",
            budget=JobBudget.for_run(fixture.run_root, resolved.budgets, new_timing_mode="active_v2"),
            semaphore=ReviewTeamSemaphore.for_run(fixture.run_root, resolved.teams.review_teams),
            max_page_size=resolved.packages.max_page_size,
            max_depth=resolved.packages.max_depth,
            _bundles=_prepared_template.bundles,
            _symbols=_prepared_template.symbols,
            _path_symbols=_prepared_template.path_symbols,
            _pinned=set(),
            _views=_prepared_template.views if same_packages else {},
            _resolves=_prepared_template.resolves,
            _names=_prepared_template.names,
            _locations=_prepared_template.locations,
            _lock=_prepared_template.cache_lock,
        )

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
    def quick_verifier(request, *, timeout_seconds):
        if request.role == "blue_team_refuter":
            return ScriptedInfer._final({"stance": "unresolved", "why": NARRATIVES["blue-guard"]})
        if request.role == "independent_verifier":
            return ScriptedInfer._final({"disposition": "insufficient_evidence", "per_predicate": {},
                                          "why": NARRATIVES["verifier"]})
        return prepared.infer(request, timeout_seconds=timeout_seconds)

    no_judge = MappingProxyType({**prepared.settings.roles, Role.ADJUDICATION_JUDGE: replace(
        prepared.settings.roles[Role.ADJUDICATION_JUDGE], enabled=False)})
    no_cache = replace(prepared.settings.result_cache, enabled=False)
    no_audit = replace(prepared.settings.decision_audit, enabled=False)
    ctx = prepared.context(
        quick_verifier, lane="hunt", roles=no_judge, result_cache=no_cache,
        decision_audit=no_audit,
    )
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
    # T-5055: the checked-in verifier profile is a second model of the same provider.
    assert record["provider_distinct"] is False and record["verifier_model_distinct"] is True
    [verifier] = [item for item in result.cells if item.role is Role.INDEPENDENT_VERIFIER]
    supporting = [item for item in result.relations if item.producing_cell_id == verifier.cell_id]
    assert supporting and all(item.retrieval_receipt_sha256 == verifier.receipt_sha256 for item in supporting)


def test_a_distinct_verifier_profile_is_recorded_without_changing_independence(prepared) -> None:
    """Decision 2 via configuration: roles.independent_verifier.model_profile names another model, and pointing it
    back at the analysts' profile records the warning without changing independence (T-5055)."""
    settings = prepared.settings
    assert settings.verifier_distinctness()["distinct"] is True              # the checked-in default
    roles = MappingProxyType({**settings.roles, Role.INDEPENDENT_VERIFIER: replace(
        settings.roles[Role.INDEPENDENT_VERIFIER], model_profile="default")})
    shared = replace(settings, roles=roles)
    assert shared.verifier_distinctness()["distinct"] is False and shared.verifier_distinctness()["warning"]
    recording = Recording(prepared.infer)
    result = run_team(prepared.context(recording, roles=roles), prepared.work("lead", "ci_high"), launch=True)
    [record] = [item for values in result.independence.values() for item in values]
    assert record["independent"] is True and record["verifier_model_distinct"] is False
    assert record["provider_distinct"] is False
    assert {item.model for item in recording.by_role("independent_verifier")} == {settings.models["default"].model}
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
    def quick_review(request, *, timeout_seconds):
        if request.role == "independent_verifier":
            return ScriptedInfer._final({"disposition": "insufficient_evidence", "per_predicate": {},
                                         "why": NARRATIVES["verifier"]})
        return prepared.infer(request, timeout_seconds=timeout_seconds)

    def only_duplicate_claim(request, result):
        if request.role == "hypothesis_hunter" and "claims" in result:
            result["claims"] = [item for item in result["claims"] if item.get("id") == "c1"]

    budgets = replace(prepared.settings.budgets, budget_team_packages=3)
    single_red = replace(prepared.settings.teams, red_per_team=1)
    no_judge = MappingProxyType({**prepared.settings.roles, Role.ADJUDICATION_JUDGE: replace(
        prepared.settings.roles[Role.ADJUDICATION_JUDGE], enabled=False)})
    lead_ctx = prepared.context(quick_review, lane="lead", budgets=budgets, teams=single_red, roles=no_judge)
    hunt_ctx = prepared.context(_rewriting(quick_review, only_duplicate_claim), lane="hunt",
                                budgets=budgets, teams=single_red, roles=no_judge)
    lead_works = [prepared.work("lead", "sast_critical"), prepared.work("lead", "sast_suppressed")]
    hunt_works = package_works(prepared.fixture.run_root, prepared.documents("hunt"))
    shards = prepared.tmp / "shards"
    lead = run_lane(lead_ctx, Lane.LEAD, lead_works,
                    other_lane_count=len(hunt_works), ledger_path=shards / "lead.jsonl", stream="lead_review.teams",
                    signal_dir=prepared.tmp / "lanes")
    hunt = run_lane(hunt_ctx, Lane.HUNT, hunt_works,
                    other_lane_count=len(lead_works), ledger_path=shards / "hunt.jsonl", stream="hunt_review.teams",
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
    assert lead["allocation"] == {"lead": 2, "hunt": 1} == hunt["allocation"]
    assert json.loads((prepared.tmp / "lanes" / "hunt.json").read_text())["queue_empty"] is True


# ------------------------------------------------------------------------------------------------ failures


def test_provider_and_schema_failures_are_typed_gaps_with_terminal_records(prepared) -> None:
    single_red = replace(prepared.settings.teams, red_per_team=1)
    result = run_team(prepared.context(prepared.infer, teams=single_red), prepared.work("lead", "dep_high"), launch=True)
    [verifier] = [item for item in result.cells if item.role is Role.INDEPENDENT_VERIFIER]
    assert verifier.status is CellStatus.FAILED and verifier.attempts == prepared.settings.retry.max_attempts
    [claim_id] = result.verifier_gaps
    assert result.verifier_gaps[claim_id][0]["gap_class"] == "worker_gap"
    assert result.independence[claim_id][0]["independent"] is False

    def malformed(request, *, timeout_seconds):
        if request.role == "blue_team_refuter":
            return ModelResult(proposal={"action": "final", "result": {"schema": "wrong"}})
        return prepared.infer(request, timeout_seconds=timeout_seconds)

    result = run_team(prepared.context(malformed, attempt="b", teams=single_red),
                      prepared.work("lead", "sast_high"), launch=True)
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
        raise ProviderError("provider down", retryable=True)

    ctx = prepared.context(outage, lane="hunt")
    works = package_works(prepared.fixture.run_root, prepared.documents("hunt"))
    document = run_lane(ctx, Lane.HUNT, works,
                        other_lane_count=9, ledger_path=prepared.tmp / "hunt.jsonl", stream="hunt_review.teams",
                        signal_dir=prepared.tmp / "lanes")
    projection = project(merge_shards([prepared.tmp / "hunt.jsonl"]).events)
    statuses = sorted(records[0].status.value for records in projection.cells.values())
    # Every launched package's three red cells fail on the outage; the packages beyond the lane's allocation are
    # never launched. The fixture's hunt package count follows the assembler, so the expectation is derived.
    launched = document["allocation"]["hunt"]
    reds = ctx.settings.teams.red_per_team
    assert statuses == ["failed"] * (reds * launched) + ["not_launched"] * (reds * (len(works) - launched))
    assert not projection.claims
    assert document["counts"]["cells"] == reds * len(works)
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
    # A different limit is a separate unit scenario, not a reset of a run's persisted budget.
    limited = prepared.context(prepared.infer, attempt="turns")
    limited.settings = replace(limited.settings, budgets=tiny)
    limited.budget = JobBudget(prepared.tmp / "turn-limit-scenario", tiny)
    result = run_team(limited, prepared.work("lead", "sast_high"), launch=True)
    # Cells can reach admission concurrently, but at most one physical model call is reserved.
    launched = [item for item in result.cells if item.status is not CellStatus.NOT_LAUNCHED]
    assert len(launched) <= 3 and all(item.attempts <= 1 for item in result.cells)
    assert {item.status for item in launched} <= {CellStatus.SUCCEEDED, CellStatus.TIMED_OUT}
    assert limited.budget.snapshot().model_turns == 1
    # Exhaustion is sticky for the attempt: every later cell is not launched.
    again = run_team(limited, prepared.work("lead", "ci_high"), launch=True)
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
    assert again.independence.keys() == first.independence.keys()
    for claim_id, first_records in first.independence.items():
        again_records = again.independence[claim_id]
        assert len(again_records) == len(first_records)
        for first_item, again_item in zip(first_records, again_records, strict=True):
            assert {k: v for k, v in again_item.items() if k != "audit"} == {
                k: v for k, v in first_item.items() if k != "audit"}
            assert first_item["audit"]["request_markers_absent"] is True
            assert again_item["audit"] == {**first_item["audit"], "request_markers_absent": None}


def test_resuming_exhausted_team_reconstructs_prior_claims_without_new_calls(prepared):
    ctx = prepared.context(prepared.infer)
    limits = replace(prepared.settings.budgets, budget_team_packages=1, max_model_turns=1)
    ctx.budget = JobBudget(prepared.tmp / "resume-budget", limits)
    ctx.settings = replace(ctx.settings, budgets=limits, teams=replace(ctx.settings.teams, red_per_team=1))
    work = prepared.work("lead", "sast_high")
    first = run_team(ctx, work, launch=True)
    assert first.claims and ctx.budget.snapshot().model_turns == 1
    recording = Recording(prepared.infer)
    ctx.infer = recording
    ctx.attempt_id = "resumed-attempt"
    second = run_team(ctx, work, launch=True)
    assert not recording.requests and second.claims == first.claims
    assert ctx.budget.snapshot().model_turns == 1
    assert any(item.status is CellStatus.SUCCEEDED for item in second.cells)


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


def test_a_final_over_the_output_cap_reaches_the_lane_with_its_answer_and_a_budget_gap(prepared) -> None:
    """The per-call output cap no longer discards a parsed final: the cell succeeds and the gap reaches the lane."""
    cap = prepared.settings.models["default"].max_output_tokens

    def heavy(request, *, timeout_seconds):
        response = prepared.infer(request, timeout_seconds=timeout_seconds)
        if request.role in {"red_team_analyst", "hypothesis_hunter"} and response.proposal.get("action") == "final":
            return replace(response, output_tokens=cap + 1)
        return response

    result = run_team(prepared.context(heavy, attempt="over-cap"), prepared.work("lead", "sast_high"), launch=True)
    reds = [item for item in result.cells if item.role is Role.RED_TEAM_ANALYST]
    assert reds and {item.status for item in reds} == {CellStatus.SUCCEEDED}
    reasons = {gap.reason for gap in result.gaps if gap.gap_class is GapClass.BUDGET_GAP}
    assert reasons == {f"model_token_cap: final turn used {cap + 1} of {cap} output tokens"}
    assert not any(gap.reason == "cell_budget_exceeded:cell_token_cap" for gap in result.gaps)


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


def test_without_blue_refuters_only_the_verifier_answers_a_claim(prepared) -> None:
    """Review protocol v3 D8: with teams.blue_per_team = 0 no blue cell is built; run 2026-11-16-0003 still ran 38
    blue cells under that setting because the cells were created per claim regardless of the pool size."""
    teams = replace(prepared.settings.teams, red_per_team=1, blue_per_team=0)
    no_judge = MappingProxyType({**prepared.settings.roles, Role.ADJUDICATION_JUDGE: replace(
        prepared.settings.roles[Role.ADJUDICATION_JUDGE], enabled=False)})
    result = run_team(prepared.context(prepared.infer, teams=teams, roles=no_judge),
                      prepared.work("lead", "sast_critical"), launch=True)
    roles = [cell.role for cell in result.cells]
    assert Role.BLUE_TEAM_REFUTER not in roles
    assert Role.RED_TEAM_ANALYST in roles and Role.INDEPENDENT_VERIFIER in roles
    assert result.claims                                        # the claim was proposed and verified without a refuter


def test_lead_accounting_and_named_gaps_reach_the_lane(prepared) -> None:
    def enrich(request, result):
        if request.task_input["task"] != "lead_red_stack" or not result["claims"]:
            return
        result["claims"][0]["missing"] = ["no deployment snapshot in the package"]

    single_red = replace(prepared.settings.teams, red_per_team=1)
    ctx = prepared.context(_rewriting(prepared.infer, enrich), lane="lead", teams=single_red)
    selected_works = [prepared.work("lead", "sast_critical"), prepared.work("lead", "sast_suppressed")]
    shards = prepared.tmp / "seeded"
    lane = run_lane(ctx, Lane.LEAD, selected_works,
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


def _memo_ctx(cache, **settings):
    from appsec_review.config.inference_review import ResultCacheSettings
    return SimpleNamespace(result_cache=cache, run_id="2026-10-12-0001",
                           settings=SimpleNamespace(result_cache=ResultCacheSettings(**{"enabled": True, **settings})))


def _memo_cell(role: Role, task: str, claim_id: str | None = "claim-" + "c" * 64):
    return SimpleNamespace(spec=SimpleNamespace(role=role, task=task, claim_id=claim_id))


@pytest.mark.parametrize(("role", "task", "claim_id", "eligible"), [
    (Role.BLUE_TEAM_REFUTER, "blue_control", "claim-" + "c" * 64, True),
    (Role.BLUE_TEAM_REFUTER, "blue_reachability", "claim-" + "c" * 64, True),
    (Role.BLUE_TEAM_REFUTER, "blue_control", None, False),            # no claim, no (function, value) key
    (Role.BLUE_TEAM_REFUTER, "chain_refuter", "claim-" + "c" * 64, False),
    (Role.INDEPENDENT_VERIFIER, "independent_verifier", "claim-" + "c" * 64, False),   # R6
    (Role.ADJUDICATION_JUDGE, "adjudicate_claim", "claim-" + "c" * 64, False),
    (Role.RED_TEAM_ANALYST, "blue_control", "claim-" + "c" * 64, False),
])
def test_only_claim_bound_blue_cells_use_the_result_memo(role, task, claim_id, eligible) -> None:
    from appsec_review.review.result_cache import InMemoryResultCache, Memo
    cache = InMemoryResultCache()
    memo = team_handler._memo(_memo_ctx(cache), _memo_cell(role, task, claim_id))
    assert memo == (Memo(cache, "2026-10-12-0001") if eligible else None)


def test_a_disabled_absent_or_narrowed_memo_is_never_consulted() -> None:
    from appsec_review.review.result_cache import InMemoryResultCache
    blue = _memo_cell(Role.BLUE_TEAM_REFUTER, "blue_reachability")
    assert team_handler._memo(_memo_ctx(InMemoryResultCache(), enabled=False), blue) is None
    assert team_handler._memo(_memo_ctx(None), blue) is None
    assert team_handler._memo(_memo_ctx(InMemoryResultCache(), roles=("blue_control",)), blue) is None


def test_team_counts_separate_memo_reuse_and_store_unavailability() -> None:
    from appsec_review.jobs.job_inference_security_review.teams import TeamResult, _record
    from appsec_review.review.models import CellRecord

    def cell(index: int, *, reused: bool, source: str | None, memo: str | None):
        record = CellRecord(cell_id=f"cell-{index:064d}", package_id="package-1", lane=Lane.LEAD,
                            role=Role.BLUE_TEAM_REFUTER, persona="p", stack_profile="s", task="blue_control",
                            claim_id="claim-" + "c" * 64, status=CellStatus.SUCCEEDED, attempts=1, gap_ids=(),
                            receipt_sha256="a" * 64)
        outcome = SimpleNamespace(record=record, gaps=(), security_events=(), reused=reused,
                                  reuse_source=source, memo_status=memo)
        return SimpleNamespace(record=record, outcome=outcome,
                               spec=SimpleNamespace(role=Role.BLUE_TEAM_REFUTER, package_id="package-1"),
                               capability=SimpleNamespace(body=dict, capability_sha256="b" * 64))

    team = TeamResult("package-1", Lane.LEAD, None)
    for index, (reused, source, memo) in enumerate([(False, None, "miss"), (True, "memo", "hit"),
                                                     (True, "receipt", None), (False, None, "unavailable")]):
        _record(team, cell(index, reused=reused, source=source, memo=memo))
    assert {key: team.counts[key] for key in ("cells_run", "cells_reused", "cells_memo_reused",
                                              "memo_cache_unavailable")} == {
        "cells_run": 2, "cells_reused": 1, "cells_memo_reused": 1, "memo_cache_unavailable": 1}
