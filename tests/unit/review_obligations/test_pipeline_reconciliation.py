"""Focused pipeline, ledger, accounting, schema, and decision-audit tests for T-153 (TRI-C)."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

from appsec_review.config import WarrantPolicySettings, load_config
from appsec_review.jobs.job_inference_security_review import stages
from appsec_review.jobs.job_inference_security_review.audit import publish_decision_audit
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.jobs.job_inference_security_review.teams import (
    PackageWork,
    ReviewContext,
    TeamResult,
    WARRANTS_SCHEMA,
    _pending_requests,
    _relations,
    _round_state,
    _seal,
    _triage,
)
from appsec_review.retrieval import EntityKind, LogicalIdentity, RetrievalCore
from appsec_review.review.accounting import ViolationCode, exact_accounting
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.projection import Document
from appsec_review.review.evidence_obligations import (
    BudgetDisposition,
    EvidenceObligation,
    LANE_OBLIGATIONS_SCHEMA,
    OBLIGATION_POLICY_VERSION,
    ObligationReasonCode,
    ObligationResolution,
    ObligationState,
    RequiredEvidenceClass,
    ResolutionPolarity,
    compute_obligation_id,
    obligation_from_json,
    obligation_json,
)
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.ledger import (
    EvidenceRequestOutcome,
    LedgerWriter,
    project as ledger_project,
    verify_chain,
    verify_events,
)
from appsec_review.review.models import (
    CellRecord,
    CellStatus,
    Claim,
    ClaimState,
    EvidenceRelation,
    IntegrityError,
    Lane,
    Predicate,
    RelationKind,
    Role,
    SecurityPredicate,
)
from appsec_review.review.teams import ReviewTeamSemaphore
from appsec_review.review.warrants import (
    PredicateWarrant,
    SubjectBinding,
    WARRANT_RULE_VERSION,
    WarrantScope,
    warrant_json,
)
from appsec_review.storage import canonical_json
from tests.fixtures.inference_review.acceptance import JOB, ROOT
from tests.unit.review_decision_audit_consumers import helpers as consumer_helpers
from tests.unit.review_decision_audit_producer import helpers as audit_helpers
from tests.unit.review_warrants.test_optin_wiring import SNAPSHOT, wiring_core  # noqa: F401
from tests.unit.review_warrants.test_pipeline_audit_wiring import _make_warrant

OBLIGATION_SCHEMA_PATH = ROOT / "docs" / "schemas" / "evidence-obligation.schema.json"


def _obligation_schema_validator() -> jsonschema.Draft202012Validator:
    schema = json.loads(OBLIGATION_SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def _eid(kind: EntityKind, name: str) -> str:
    return LogicalIdentity.derive(kind, SNAPSHOT, {"native": name}).value


def _make_context(core: RetrievalCore, root: Path, *, warrants_enabled: bool = True) -> ReviewContext:
    base_settings = load_config(ROOT / "appsec-review.toml", profile="dev").job(JOB).typed_settings
    cfg = replace(
        base_settings,
        warrant_policy=WarrantPolicySettings(enabled=warrants_enabled),
    )
    schemas = SchemaSet(ROOT / SCHEMA_DIRECTORY)
    return ReviewContext(
        run_root=root,
        run_id="run-tric",
        repository_root=ROOT,
        settings=cfg,
        core=core,
        infer=lambda _req, *, timeout_seconds=0: None,  # type: ignore[return-value]
        receipts_root=root / "receipts",
        budget=None,  # type: ignore[arg-type]
        semaphore=ReviewTeamSemaphore.for_run(root, 1),
        vocabulary=None,
        crosswalk=None,
        covers={},
        role_tools={},
        schemas=schemas,
        accepted_cwe_ids=frozenset({"CWE-787", "CWE-89"}),
        rule_predicates={},
        source_languages={},
        build_unit_languages={},
        index_names=("code_graph", "source_sast", "build_inventory"),
        available_sources=("code_graph", "source_sast", "build_inventory"),
        attempt_id="att-tric",
    )


def _req_dict(
    *,
    cell_id: str,
    claim_id: str,
    predicate: Predicate,
    requested_kind: str,
    anchors: list[str],
    question: str,
    round_index: int = 0,
    specialist: str | None = None,
) -> dict[str, object]:
    rid = make_id(
        "evidence_request",
        1,
        {
            "cell_id": cell_id,
            "claim_id": claim_id,
            "predicate": predicate.value,
            "requested_kind": requested_kind,
            "anchors": sorted(anchors),
            "question": question,
            "specialist": specialist,
        },
    )
    row: dict[str, object] = {
        "request_id": rid,
        "origin_cell_id": cell_id,
        "claim_id": claim_id,
        "predicate": predicate.value,
        "requested_kind": requested_kind,
        "anchors": sorted(anchors),
        "question": question,
        "round": round_index,
    }
    if specialist is not None:
        row["specialist"] = specialist
    return row


def test_pipeline_round_coalescing_warranted_resolution_and_ledger_seal(
    wiring_core: tuple[RetrievalCore, dict[str, str]],
    tmp_path: Path,
) -> None:
    core, ids = wiring_core
    ctx = _make_context(core, tmp_path / "run", warrants_enabled=True)
    package_id = "pkg-tric-1"
    pkg_entities = (ids["sym_fn"], ids["sink_vuln"], ids["entry"], ids["path_vuln"], ids["g_vuln_none"])
    work = PackageWork(
        package_id=package_id,
        lane=Lane.LEAD,
        sha256="a" * 64,
        document={"scope": {"entities": list(pkg_entities)}},
        rank=(0, package_id),
        basis="b" * 64,
        entities=pkg_entities,
        unit_key="u-1",
    )
    red_1 = "cell-" + "1" * 64
    red_2 = "cell-" + "2" * 64
    ver_1 = "cell-" + "3" * 64
    claim_id = "claim-" + "a" * 64
    claim = Claim(
        claim_id=claim_id,
        lane=Lane.LEAD,
        package_id=package_id,
        affected_entities=(ids["sink_vuln"],),
        weakness_cwe="CWE-787",
        security_predicate=SecurityPredicate.MEMORY_CORRUPTION,
        preconditions=(),
        statement="unbounded memcpy into dst",
        state=ClaimState.PROPOSED,
        origin_cell_ids=(red_1, red_2),
    )

    # Two distinct cells emit semantically equivalent guard-fact requests (with specialist referral),
    # plus one unresolved reachability specialist request and one outside-package anchor request.
    dup_req_1 = _req_dict(
        cell_id=red_1,
        claim_id=claim_id,
        predicate=Predicate.MISSING_OR_INEFFECTIVE_GUARD,
        requested_kind="guard_fact",
        anchors=[ids["sink_vuln"]],
        question="Verify whether bounds guard dominates copy_vuln!",
        round_index=0,
        specialist="memory_safety_native",
    )
    dup_req_2 = _req_dict(
        cell_id=red_2,
        claim_id=claim_id,
        predicate=Predicate.MISSING_OR_INEFFECTIVE_GUARD,
        requested_kind="guard_fact",
        anchors=[ids["sink_vuln"]],
        question="  verify whether bounds guard dominates copy_vuln?  ",
        round_index=0,
        specialist="memory_safety_native",
    )
    unresolved_reachability_req = _req_dict(
        cell_id=red_1,
        claim_id=claim_id,
        predicate=Predicate.SOURCE_TO_SINK_REACHABILITY,
        requested_kind="flow_summary",
        anchors=[ids["sink_vuln"]],
        question="Confirm source-to-sink flow summary",
        round_index=0,
        specialist="injection_interpreters",
    )
    unresolved_impact_req = _req_dict(
        cell_id=red_1,
        claim_id=claim_id,
        predicate=Predicate.SECURITY_IMPACT,
        requested_kind="other",
        anchors=[ids["sink_vuln"]],
        question="Confirm exploitability impact summary",
        round_index=0,
        specialist="business_logic_abuse",
    )
    outside_req = _req_dict(
        cell_id=red_2,
        claim_id=claim_id,
        predicate=Predicate.AFFECTED_CONSTRUCT,
        requested_kind="sink_site",
        anchors=[ids["sink_safe"]],
        question="Inspect outside-package sink",
        round_index=0,
    )

    team = TeamResult(
        package_id=package_id,
        lane=Lane.LEAD,
        unit_key="u-1",
        launched=True,
        package_entities=frozenset(pkg_entities),
        warrant_scope=WarrantScope(),
        claims=[claim],
        requests=[dup_req_1, dup_req_2, unresolved_reachability_req, unresolved_impact_req, outside_req],
        cells=[
            CellRecord(cell_id=red_1, lane=Lane.LEAD, package_id=package_id,
                       role=Role.RED_TEAM_ANALYST, persona="p1", stack_profile="c",
                       task="lead_red_stack", claim_id=None, status=CellStatus.SUCCEEDED, attempts=1),
            CellRecord(cell_id=red_2, lane=Lane.LEAD, package_id=package_id,
                       role=Role.RED_TEAM_ANALYST, persona="p2", stack_profile="c",
                       task="lead_red_preconditions", claim_id=None, status=CellStatus.SUCCEEDED, attempts=1),
            CellRecord(cell_id=ver_1, lane=Lane.LEAD, package_id=package_id,
                       role=Role.INDEPENDENT_VERIFIER, persona="p3", stack_profile="c",
                       task="blind_verifier", claim_id=claim_id, status=CellStatus.SUCCEEDED, attempts=1),
        ],
        capabilities=[
            {"cell_id": red_1, "round": 0},
            {"cell_id": red_2, "round": 0},
            {"cell_id": ver_1, "round": 1},
        ],
    )

    # Round 0 state: duplicate guard requests coalesce to 1 OPEN obligation; outside-package request is UNSATISFIED.
    _, fp_round0 = _round_state(ctx, work, team)
    pending_r0 = _pending_requests(ctx, work, team)
    assert len(team.obligations) == 4
    assert len(pending_r0) == 3
    assert all("obligation_id" in row for row in pending_r0)
    assert any(gap.reason == "follow_up_request_anchor_outside_package" for gap in team.gaps)

    # Repeating the identical request without new evidence does not change the round convergence fingerprint!
    dup_req_round1 = _req_dict(
        cell_id=ver_1,
        claim_id=claim_id,
        predicate=Predicate.MISSING_OR_INEFFECTIVE_GUARD,
        requested_kind="guard_fact",
        anchors=[ids["sink_vuln"]],
        question="verify whether bounds guard dominates copy_vuln",
        round_index=1,
    )
    team.requests.append(dup_req_round1)
    _, fp_round1_repeat = _round_state(ctx, replace(work, round_index=1), team)
    assert fp_round1_repeat == fp_round0

    # Round 1 resolves warranted guard evidence covering sink_vuln:
    warrant_map: dict[str, PredicateWarrant] = {}
    ver_cell = SimpleNamespace(
        cell_id=ver_1,
        spec=SimpleNamespace(role=Role.INDEPENDENT_VERIFIER),
        record=SimpleNamespace(receipt_sha256="d" * 64),
    )
    ver_rels, ver_gaps = _relations(
        ctx,
        ver_cell,
        claim_id,
        [
            {
                "predicate": Predicate.MISSING_OR_INEFFECTIVE_GUARD.value,
                "kind": RelationKind.SUPPORTS.value,
                "entity_id": ids["g_vuln_none"],
            }
        ],
        set(pkg_entities),
        claim=claim,
        warrants=warrant_map,
    )
    assert not ver_gaps
    team.relations.extend(ver_rels)
    team.warrants.update(warrant_map)

    _, fp_round1_resolved = _round_state(ctx, replace(work, round_index=1), team)
    assert fp_round1_resolved != fp_round0
    pending_after_resolve = _pending_requests(ctx, replace(work, round_index=1), team)
    # Only the still-open reachability and impact obligations remain pending!
    assert len(pending_after_resolve) == 2
    assert {row["predicate"] for row in pending_after_resolve} == {
        Predicate.SOURCE_TO_SINK_REACHABILITY.value,
        Predicate.SECURITY_IMPACT.value,
    }

    team.rounds.append({"round": 1, "stop_reason": "max_rounds"})
    ledger_path = tmp_path / "run" / "lead-ledger.jsonl"
    doc = _seal(ctx, Lane.LEAD, [team], {Lane.LEAD: 1, Lane.HUNT: 0}, ledger_path, "lead_review.teams")

    assert "evidence_obligations" in doc
    ob_file = Path(doc["evidence_obligations"]["path"])
    assert ob_file.exists()
    assert hashlib.sha256(ob_file.read_bytes()).hexdigest() == doc["evidence_obligations"]["sha256"]
    raw_obs = json.loads(ob_file.read_text(encoding="utf-8"))
    _obligation_schema_validator().validate(raw_obs)
    assert raw_obs["count"] == 4

    obs_by_pred = {
        Predicate(item["predicate"]): obligation_from_json(item)
        for item in raw_obs["items"]
    }
    guard_ob = obs_by_pred[Predicate.MISSING_OR_INEFFECTIVE_GUARD]
    assert guard_ob.state is ObligationState.SATISFIED
    assert guard_ob.resolution.reason_code is ObligationReasonCode.SATISFIED_BY_WARRANTED_EVIDENCE
    assert guard_ob.resolution.polarity is ResolutionPolarity.SUPPORTS
    assert len(guard_ob.origin_request_ids) == 3
    assert guard_ob.resolution.relation_ids == (ver_rels[0].relation_id,)
    assert guard_ob.resolution.warrant_ids == (warrant_map[ver_rels[0].relation_id].warrant_id,)
    assert guard_ob.remaining_gap_ids == ()

    reach_ob = obs_by_pred[Predicate.SOURCE_TO_SINK_REACHABILITY]
    assert reach_ob.state is ObligationState.UNSATISFIED
    assert reach_ob.resolution.reason_code is ObligationReasonCode.MODEL_BUDGET
    assert reach_ob.budget_disposition is BudgetDisposition.MAX_ROUNDS_CUTOFF
    assert len(reach_ob.remaining_gap_ids) == 1

    impact_ob = obs_by_pred[Predicate.SECURITY_IMPACT]
    assert impact_ob.state is ObligationState.UNSATISFIED
    assert impact_ob.resolution.reason_code is ObligationReasonCode.PRODUCER_UNCOMMISSIONED
    assert len(impact_ob.remaining_gap_ids) == 1

    outside_ob = obs_by_pred[Predicate.AFFECTED_CONSTRUCT]
    assert outside_ob.state is ObligationState.UNSATISFIED
    assert outside_ob.resolution.reason_code is ObligationReasonCode.OUTSIDE_PACKAGE

    # Specialist gap emitted ONLY for unresolved specialists, NOT for satisfied memory_safety_native!
    events = verify_chain(ledger_path)
    verify_events(events)
    for event in events:
        ctx.schemas.validate("ledger-event", event)
    proj = ledger_project(events)
    gap_reasons = [gap.reason for gap in proj.gaps]
    assert "unresolved_specialist_referral:injection_interpreters" in gap_reasons
    assert "unresolved_specialist_referral:business_logic_abuse" in gap_reasons
    assert "unresolved_specialist_referral:memory_safety_native" not in gap_reasons

    # Adjudicate into final claim state and verify exact accounting passes with 1 satisfied, 3 unsatisfied, and 2 superseded!
    merge_doc = stages.merge_claims([doc], [ledger_path], {package_id: pkg_entities}, ())
    adj_path = tmp_path / "run" / "adjudicate-ledger.jsonl"
    stages.apply_policy(
        merge_doc, proj, adj_path, "adjudicate.apply_policy",
        warrants=list(team.warrants.values()), warrant_policy_enabled=True,
    )
    final_proj = ledger_project(stages.merge_verified([ledger_path, adj_path]).events)
    report = exact_accounting(
        final_proj,
        {c_rec.cell_id: Lane.LEAD for c_rec in team.cells},
        {package_id: Lane.LEAD},
        incomplete_gap_ratio=0.25,
    )
    assert report.exact, report.violations
    assert report.evidence_requests_by_outcome == {
        EvidenceRequestOutcome.SATISFIED: 1,
        EvidenceRequestOutcome.SUPERSEDED: 2,
        EvidenceRequestOutcome.UNSATISFIED: 3,
        EvidenceRequestOutcome.WITHDRAWN: 0,
    }


def test_triage_withdrawn_and_request_cutoff_reconcile_cleanly(
    wiring_core: tuple[RetrievalCore, dict[str, str]],
    tmp_path: Path,
) -> None:
    core, ids = wiring_core
    ctx = _make_context(core, tmp_path / "triage-run", warrants_enabled=False)
    ctx = replace(
        ctx,
        settings=replace(
            ctx.settings,
            lanes=replace(ctx.settings.lanes, hunt_max_claims_per_package=1),
            red_output=replace(ctx.settings.red_output, max_evidence_requests=1),
        ),
    )
    package_id = "pkg-hunt-1"
    pkg_entities = (ids["sym_fn"], ids["sink_vuln"], ids["entry"])
    work = PackageWork(
        package_id=package_id,
        lane=Lane.HUNT,
        sha256="a" * 64,
        document={},
        rank=(0, package_id),
        basis="b" * 64,
        entities=pkg_entities,
        unit_key="u-hunt",
    )
    red_id = "cell-" + "9" * 64
    cell = SimpleNamespace(cell_id=red_id, record=SimpleNamespace(receipt_sha256="e" * 64))

    def mk_claim(tag: str) -> Claim:
        return Claim(
            claim_id=f"claim-{tag * 64}",
            lane=Lane.HUNT,
            package_id=package_id,
            affected_entities=(ids["sink_vuln"],),
            weakness_cwe="CWE-787",
            security_predicate=SecurityPredicate.MEMORY_CORRUPTION,
            preconditions=(),
            statement=f"claim {tag}",
            state=ClaimState.PROPOSED,
            origin_cell_ids=(red_id,),
        )

    c_admitted = mk_claim("1")
    c_capped = mk_claim("2")
    c_unresolvable = mk_claim("3")

    def mk_group(cl: Claim, cited_entity: str, support: int, reqs: list[dict[str, object]]) -> dict[str, object]:
        proposal = {
            "local_id": f"prop-{cl.claim_id[-4:]}",
            "proof_obligation_ids": ["p1"],
            "taint_path_ids": [],
            "affected_entities": [cited_entity],
            "attacker_entry": {"entity_id": None},
            "evidence_ids": [],
            "counterevidence_ids": [],
        }
        red_doc = {
            "proof_obligations": [{"local_id": "p1", "evidence_ids": ["e1"]}],
            "evidence_refs": [{"local_id": "e1", "entity_id": cited_entity}],
            "taint_paths": [],
        }
        return {
            "claim": cl,
            "items": [(cell, proposal, red_doc, set())],
            "support": support,
            "relations": [],
            "relation_gaps": [],
            "requests": reqs,
        }

    req_adm_1 = _req_dict(
        cell_id=red_id, claim_id=c_admitted.claim_id,
        predicate=Predicate.MISSING_OR_INEFFECTIVE_GUARD, requested_kind="guard_fact",
        anchors=[ids["sink_vuln"]], question="Check guard 1",
    )
    req_adm_2 = _req_dict(
        cell_id=red_id, claim_id=c_admitted.claim_id,
        predicate=Predicate.SOURCE_TO_SINK_REACHABILITY, requested_kind="dataflow_path",
        anchors=[ids["sink_vuln"]], question="Check path 2",
    )
    req_capped = _req_dict(
        cell_id=red_id, claim_id=c_capped.claim_id,
        predicate=Predicate.MISSING_OR_INEFFECTIVE_GUARD, requested_kind="guard_fact",
        anchors=[ids["sink_vuln"]], question="Capped claim request",
        specialist="memory_safety_native",
    )
    req_unres = _req_dict(
        cell_id=red_id, claim_id=c_unresolvable.claim_id,
        predicate=Predicate.ATTACKER_INPUT_CONTROL, requested_kind="entry_point",
        anchors=[ids["entry"]], question="Unresolvable claim request",
        specialist="injection_interpreters",
    )

    missing_entity = _eid(EntityKind.SYMBOL, "src/missing.c::gone")
    groups = [
        mk_group(c_admitted, ids["sink_vuln"], 2, [req_adm_1, req_adm_2]),
        mk_group(c_capped, ids["sink_vuln"], 1, [req_capped]),
        mk_group(c_unresolvable, missing_entity, 3, [req_unres]),
    ]
    team = TeamResult(
        package_id=package_id,
        lane=Lane.HUNT,
        unit_key="u-hunt",
        launched=True,
        package_entities=frozenset(pkg_entities),
        cells=[
            CellRecord(cell_id=red_id, lane=Lane.HUNT, package_id=package_id,
                       role=Role.HYPOTHESIS_HUNTER, persona="p1", stack_profile="c",
                       task="hunt", claim_id=None, status=CellStatus.SUCCEEDED, attempts=1)
        ],
        capabilities=[{"cell_id": red_id, "round": 0}],
    )

    admitted = _triage(ctx, work, groups, team)
    assert [g["claim"].claim_id for g in admitted] == [c_admitted.claim_id]
    _, _ = _round_state(ctx, work, team)
    pending = _pending_requests(ctx, work, team)
    # max_evidence_requests=1 selects 1 open obligation and marks the 2nd open obligation cutoff!
    assert len(pending) == 1
    assert len(team.cutoff_obligation_ids) == 1

    ledger_path = tmp_path / "triage-run" / "hunt-ledger.jsonl"
    doc = _seal(ctx, Lane.HUNT, [team], {Lane.LEAD: 0, Lane.HUNT: 1}, ledger_path, "hunt_review.teams")
    raw_obs = json.loads(Path(doc["evidence_obligations"]["path"]).read_text(encoding="utf-8"))
    _obligation_schema_validator().validate(raw_obs)
    parsed = {ob.origin_request_ids[0]: ob for ob in (obligation_from_json(i) for i in raw_obs["items"])}

    assert parsed[str(req_capped["request_id"])].state is ObligationState.WITHDRAWN
    assert parsed[str(req_capped["request_id"])].budget_disposition is BudgetDisposition.CLAIMS_PER_PACKAGE_CAP
    assert parsed[str(req_unres["request_id"])].state is ObligationState.WITHDRAWN

    adm_obs = [parsed[str(req_adm_1["request_id"])], parsed[str(req_adm_2["request_id"])]]
    assert sorted(ob.resolution.reason_code for ob in adm_obs) == sorted([
        ObligationReasonCode.RETRIEVAL_CAP,
        ObligationReasonCode.NO_DECISIVE_EVIDENCE,
    ])

    events = verify_chain(ledger_path)
    proj = ledger_project(events)
    # Withdrawn specialist requests do NOT create spurious unresolved_specialist_referral gaps!
    assert not any(gap.reason.startswith("unresolved_specialist_referral:") for gap in proj.gaps)
    merge_doc = stages.merge_claims([doc], [ledger_path], {package_id: pkg_entities}, ())
    adj_path = tmp_path / "triage-run" / "adjudicate-ledger.jsonl"
    stages.apply_policy(merge_doc, proj, adj_path, "adjudicate.apply_policy")
    final_proj = ledger_project(stages.merge_verified([ledger_path, adj_path]).events)
    report = exact_accounting(
        final_proj,
        {red_id: Lane.HUNT},
        {package_id: Lane.HUNT},
        incomplete_gap_ratio=0.25,
    )
    assert report.exact, report.violations
    assert report.evidence_requests_by_outcome == {
        EvidenceRequestOutcome.SATISFIED: 0,
        EvidenceRequestOutcome.SUPERSEDED: 0,
        EvidenceRequestOutcome.UNSATISFIED: 2,
        EvidenceRequestOutcome.WITHDRAWN: 2,
    }


def test_exact_accounting_rejects_unwarranted_satisfied_duplicate_primary_and_invalid_superseded(
    tmp_path: Path,
) -> None:
    claim_id = "claim-" + "b" * 64
    cell_id = "cell-" + "c" * 64
    ob_1 = "evob-" + "1" * 64
    ob_2 = "evob-" + "2" * 64
    req_bad_sat = "evreq-" + "1" * 64
    req_dup_a = "evreq-" + "2" * 64
    req_dup_b = "evreq-" + "3" * 64
    req_bad_sup = "evreq-" + "4" * 64

    claim = Claim(
        claim_id=claim_id,
        lane=Lane.LEAD,
        package_id="pkg-1",
        affected_entities=(_eid(EntityKind.SINK_SITE, "sink:x"),),
        weakness_cwe="CWE-787",
        security_predicate=SecurityPredicate.MEMORY_CORRUPTION,
        preconditions=(),
        statement="stmt",
        state=ClaimState.PROPOSED,
        origin_cell_ids=(cell_id,),
    )
    ledger_path = tmp_path / "bad-accounting.jsonl"
    writer = LedgerWriter(ledger_path, "lead_review.teams")
    writer.propose_claim(claim)
    writer.cell_terminal(
        CellRecord(
            cell_id=cell_id, lane=Lane.LEAD, package_id="pkg-1",
            role=Role.RED_TEAM_ANALYST, persona="p1", stack_profile="c",
            task="t1", claim_id=None, status=CellStatus.SUCCEEDED, attempts=1,
        )
    )
    # 1. Forged SATISFIED with obligation_id but no relation_ids / warrant_ids:
    writer.open_request(req_bad_sat, claim_id, Predicate.MISSING_OR_INEFFECTIVE_GUARD, "guard_fact",
                        origin_cell_id=cell_id, obligation_id=ob_1)
    writer.close_request(req_bad_sat, claim_id, EvidenceRequestOutcome.SATISFIED,
                         reason="forged satisfied without warrant", obligation_id=ob_1)
    # 2. Two non-superseded primaries for the same obligation_id ob_2:
    writer.open_request(req_dup_a, claim_id, Predicate.AFFECTED_CONSTRUCT, "sink_site",
                        origin_cell_id=cell_id, obligation_id=ob_2)
    writer.close_request(req_dup_a, claim_id, EvidenceRequestOutcome.UNSATISFIED,
                         reason="primary 1", obligation_id=ob_2)
    writer.open_request(req_dup_b, claim_id, Predicate.AFFECTED_CONSTRUCT, "sink_site",
                        origin_cell_id=cell_id, obligation_id=ob_2)
    writer.close_request(req_dup_b, claim_id, EvidenceRequestOutcome.UNSATISFIED,
                         reason="primary 2", obligation_id=ob_2)
    # 3. SUPERSEDED pointing to non-existent obligation:
    writer.open_request(req_bad_sup, claim_id, Predicate.SECURITY_IMPACT, "flow_summary",
                        origin_cell_id=cell_id, obligation_id="evob-" + "9" * 64)
    writer.close_request(req_bad_sup, claim_id, EvidenceRequestOutcome.SUPERSEDED,
                         reason="dangling supersession", obligation_id="evob-" + "9" * 64,
                         superseded_by="evob-" + "f" * 64)
    writer.seal()

    proj = ledger_project(verify_chain(ledger_path))
    report = exact_accounting(proj, {cell_id: Lane.LEAD}, {"pkg-1": Lane.LEAD}, incomplete_gap_ratio=0.25)
    assert not report.exact
    codes = {(v.reason, v.subject_id) for v in report.violations}
    assert (ViolationCode.EVIDENCE_REQUEST_UNWARRANTED_SATISFIED.value, req_bad_sat) in codes
    assert (ViolationCode.EVIDENCE_OBLIGATION_DUPLICATE_PRIMARY.value, req_dup_b) in codes
    assert (ViolationCode.EVIDENCE_REQUEST_INVALID_SUPERSEDED.value, req_bad_sup) in codes


def _build_synthetic_obligation(
    *,
    claim_id: str,
    request_id: str,
    origin_cell_id: str,
    predicate: Predicate,
    question: str,
    state: ObligationState,
    relation_ids: tuple[str, ...] = (),
    warrant_ids: tuple[str, ...] = (),
    receipt_refs: tuple[str, ...] = (),
) -> EvidenceObligation:
    sink_audit = _eid(EntityKind.SINK_SITE, "sink:audit")
    binding = SubjectBinding(
        affected_entity_ids=(sink_audit,),
        operation_id=None,
        sink_id=sink_audit,
        build_scope_id=None,
    )
    oid = compute_obligation_id(
        claim_id=claim_id,
        predicate=predicate,
        subject_binding=binding,
        anchors=(),
        scope_ceiling="package-1",
        requested_kind="guard_fact",
        canonical_question=question,
    )
    res = (
        ObligationResolution(
            relation_ids=relation_ids,
            warrant_ids=warrant_ids,
            read_receipt_refs=receipt_refs,
            evaluated_round=0,
            resolution_rule=OBLIGATION_POLICY_VERSION,
            reason_code=ObligationReasonCode.SATISFIED_BY_WARRANTED_EVIDENCE,
            polarity=ResolutionPolarity.SUPPORTS,
        )
        if state is ObligationState.SATISFIED
        else ObligationResolution(
            relation_ids=(),
            warrant_ids=(),
            read_receipt_refs=(),
            evaluated_round=0,
            resolution_rule=OBLIGATION_POLICY_VERSION,
            reason_code=ObligationReasonCode.NO_DECISIVE_EVIDENCE,
        )
    )
    return EvidenceObligation(
        obligation_id=oid,
        policy_version=OBLIGATION_POLICY_VERSION,
        origin_request_ids=(request_id,),
        claim_id=claim_id,
        predicate=predicate,
        subject_binding=binding,
        anchors=(),
        question=question,
        canonical_question=question,
        requested_kind="guard_fact",
        requested_specialist=None,
        origin_cell_ids=(origin_cell_id,),
        round_opened=0,
        required_evidence_class=RequiredEvidenceClass.GUARD_OR_RANGE_FACT,
        admissible_producer_ids=("code_graph",),
        scope_ceiling="package-1",
        completeness_required=True,
        state=state,
        resolution=res,
        coverage_receipt_refs=(),
        remaining_gap_ids=(),
        attempted_retrieval_ids=(),
        budget_disposition=BudgetDisposition.WITHIN_BUDGET,
    )


def _make_warrant_for_rel(claim_id: str, rel: EvidenceRelation) -> PredicateWarrant:
    return _make_warrant(
        claim_id=claim_id,
        relation_id=rel.relation_id,
        predicate=rel.predicate,
        established=True,
        entity_id=rel.entity_id,
        entity_kind=rel.entity_kind,
        shard_id=rel.shard_id,
        content_sha256=rel.content_sha256,
        locator=rel.locator,
        receipt_sha256=rel.retrieval_receipt_sha256,
    )


def _attach_ledger_requests(fx: audit_helpers.Fixture, obligations: list[EvidenceObligation]) -> None:
    req_shard = fx.attempt / "lead-requests.jsonl"
    writer = LedgerWriter(req_shard, "lead_review.requests")
    for ob in obligations:
        outcome = (
            EvidenceRequestOutcome.SATISFIED
            if ob.state is ObligationState.SATISFIED
            else EvidenceRequestOutcome.UNSATISFIED
        )
        req_id = ob.origin_request_ids[0]
        writer.open_request(
            req_id, ob.claim_id, ob.predicate, ob.requested_kind,
            origin_cell_id=ob.origin_cell_ids[0],
            obligation_id=ob.obligation_id,
            question=ob.question,
        )
        writer.close_request(
            req_id, ob.claim_id, outcome,
            reason=ob.resolution.reason_code.value,
            obligation_id=ob.obligation_id,
            reason_code=ob.resolution.reason_code.value,
            relation_ids=ob.resolution.relation_ids,
            warrant_ids=ob.resolution.warrant_ids,
        )
    writer.seal()
    combined = stages.merge_verified([
        fx.attempt / "lead-ledger.jsonl",
        req_shard,
        fx.attempt / "adjudication-ledger.jsonl",
    ])
    new_proj = ledger_project(combined.events)
    proj_doc = audit_helpers.document(fx.root, fx.inputs.projection_document.source.path, new_proj.to_json())
    ledger_path = fx.root / fx.refs.ledger["path"]
    ledger_bytes = b"".join(canonical_json(event) for event in combined.events)
    ledger_path.write_bytes(ledger_bytes)
    handoff_body = {
        **json.loads((fx.root / fx.refs.handoff["path"]).read_text(encoding="utf-8")),
        "ledger_head_sha256": new_proj.head,
        "projection_sha256": new_proj.sha256(),
    }
    handoff_doc = audit_helpers.document(fx.root, fx.refs.handoff["path"], handoff_body)
    new_origin = replace(
        fx.inputs.origin,
        review_handoff_sha256=handoff_doc.source.sha256,
        ledger_head_sha256=new_proj.head,
        projection_sha256=new_proj.sha256(),
    )
    fx.inputs = replace(
        fx.inputs,
        origin=new_origin,
        projection=new_proj,
        projection_document=proj_doc,
    )
    fx.refs = replace(
        fx.refs,
        handoff=audit_helpers.reference(handoff_doc),
        ledger={"path": fx.refs.ledger["path"], "sha256": hashlib.sha256(ledger_bytes).hexdigest()},
        projection=audit_helpers.reference(proj_doc),
    )


def test_decision_audit_projects_publishes_and_verifies_request_resolutions_and_continuations(
    tmp_path: Path,
) -> None:
    # 1. Default without evidence_obligations preserves NOT_PRODUCED on every record.
    fx_off = audit_helpers.fixture(tmp_path / "audit-off", state="confirmed")
    proj_off = fx_off.project()
    assert all(
        rec.context.future.request_resolutions == c.OptionalSources((), c.AbsenceReason.NOT_PRODUCED)
        for rec in proj_off.records
    )

    # 2. With evidence_obligations produced, claim-bearing records bind FutureReferences.request_resolutions.
    fx = audit_helpers.fixture(tmp_path / "audit-ok", state="confirmed")
    claim_id = next(iter(fx.inputs.projection.claims))
    first_rel = fx.inputs.projection.relations[claim_id][0]
    first_req_id = f"evreq-{0:064x}"
    warrant = _make_warrant_for_rel(claim_id, first_rel)
    ob = _build_synthetic_obligation(
        claim_id=claim_id,
        request_id=first_req_id,
        origin_cell_id=audit_helpers.RED,
        predicate=Predicate.MISSING_OR_INEFFECTIVE_GUARD,
        question="verify guard",
        state=ObligationState.SATISFIED,
        relation_ids=(first_rel.relation_id,),
        warrant_ids=(warrant.warrant_id,),
        receipt_refs=(first_rel.retrieval_receipt_sha256,),
    )
    _attach_ledger_requests(fx, [ob])

    lead_obs = audit_helpers.document(
        fx.root,
        f"{audit_helpers.ATTEMPT}/steps/lead_review/tasks/teams/evidence-obligations.json",
        {
            "schema": LANE_OBLIGATIONS_SCHEMA,
            "lane": "lead",
            "policy_version": OBLIGATION_POLICY_VERSION,
            "count": 1,
            "items": [obligation_json(ob)],
        },
    )
    hunt_obs = audit_helpers.document(
        fx.root,
        f"{audit_helpers.ATTEMPT}/steps/hunt_review/tasks/teams/evidence-obligations.json",
        {
            "schema": LANE_OBLIGATIONS_SCHEMA,
            "lane": "hunt",
            "policy_version": OBLIGATION_POLICY_VERSION,
            "count": 0,
            "items": [],
        },
    )
    updated_lanes = []
    for lane_doc in fx.inputs.lanes:
        odoc = lead_obs if lane_doc.value["lane"] == "lead" else hunt_obs
        updated_lanes.append(
            audit_helpers.document(
                fx.root, lane_doc.source.path,
                {**lane_doc.value, "evidence_obligations": audit_helpers.reference(odoc)},
            )
        )
    if not any(doc.value["lane"] == "hunt" for doc in updated_lanes):
        updated_lanes.append(
            audit_helpers.document(
                fx.root,
                f"{audit_helpers.ATTEMPT}/steps/hunt_review/tasks/teams/hunt-lane.json",
                {
                    "schema": "appsec-review/inference-review-lane/1",
                    "lane": "hunt",
                    "expected_cells": {},
                    "independence": {},
                    "capabilities": [],
                    "proposal_audit": {"schema": "appsec-review/proposal-membership-capture/1", "items": []},
                    "evidence_obligations": audit_helpers.reference(hunt_obs),
                },
            )
        )
    fx.inputs = replace(
        fx.inputs,
        lanes=tuple(updated_lanes),
        request_resolutions={"lead": lead_obs, "hunt": hunt_obs},
    )
    fx.refs = replace(fx.refs, lanes=tuple(audit_helpers.reference(doc) for doc in updated_lanes))

    published = publish_decision_audit(
        run_root=fx.root, attempt_root=fx.attempt, origin=fx.inputs.origin,
        scope=fx.scope, collection=fx.inputs.collection,
        inputs=fx.refs, settings=fx.settings,
    )
    assert published.manifest is not None
    assert any(item["path"] == lead_obs.source.path for item in published.source_artifacts)

    proj_on = fx.project()
    adj_records = [
        r for r in proj_on.records
        if isinstance(r, c.DecisionRecord) and r.stage is c.Stage.ADJUDICATION
    ]
    pre_claim_records = [
        r for r in proj_on.records
        if isinstance(r, c.DecisionRecord) and r.context.subject.claim_id.value is None
    ]
    assert len(adj_records) == 1
    res_refs = adj_records[0].context.future.request_resolutions
    assert res_refs.absence_reason is None
    assert len(res_refs.values) == 1
    assert res_refs.values[0].record_id.value == ob.obligation_id
    assert c.EvidenceUse.CITED in res_refs.values[0].uses
    assert all(
        r.context.future.request_resolutions == c.OptionalSources((), c.AbsenceReason.NOT_APPLICABLE)
        for r in pre_claim_records
    )

    # 3. Consumer reader accepts inline + continued ReferenceField.REQUEST_RESOLUTIONS under review_cells.
    cfx = consumer_helpers.Fixture(tmp_path / "consumer")
    ob2 = _build_synthetic_obligation(
        claim_id=claim_id,
        request_id=f"evreq-{1:064x}",
        origin_cell_id=audit_helpers.RED,
        predicate=Predicate.MISSING_OR_INEFFECTIVE_GUARD,
        question="verify second guard",
        state=ObligationState.UNSATISFIED,
    )
    obs_ref = cfx.write(
        cfx.attempt + "/steps/lead_review/tasks/teams/evidence-obligations.json",
        {
            "schema": LANE_OBLIGATIONS_SCHEMA,
            "lane": "lead",
            "policy_version": OBLIGATION_POLICY_VERSION,
            "count": 2,
            "items": [obligation_json(ob), obligation_json(ob2)],
        },
    )
    inline_res = c.SourceRef(
        cfx.root.name, obs_ref["path"], obs_ref["sha256"],
        consumer_helpers.link(ob.obligation_id), (c.EvidenceUse.READ, c.EvidenceUse.CITED),
    )
    continued_res = c.SourceRef(
        cfx.root.name, obs_ref["path"], obs_ref["sha256"],
        consumer_helpers.link(ob2.obligation_id), (c.EvidenceUse.READ,),
    )
    cont_path = cfx.audit_root + "/continuations/request_resolutions/0001.jsonl"
    cont_ref = c.make_continuation(
        c.ReferenceField.REQUEST_RESOLUTIONS, cont_path, (continued_res,),
        origin=cfx.origin, claim_id=consumer_helpers.link("claim-1"),
    )
    cont_bytes = c.reference_bytes(
        c.ReferenceField.REQUEST_RESOLUTIONS, (continued_res,),
        origin=cfx.origin, claim_id=consumer_helpers.link("claim-1"),
    )
    res_future = replace(
        cfx.verification.context.future,
        request_resolutions=c.OptionalSources((inline_res,), None),
    )
    res_verifier = replace(
        cfx.verification,
        context=replace(cfx.verification.context, future=res_future, continuations=(cont_ref,)),
    )
    res_basis = replace(
        cfx.basis,
        context=replace(cfx.basis.context, future=res_future, continuations=(cont_ref,)),
        verification=c.OptionalRecord(c.RecordRef.of(res_verifier), None),
    )
    cfx.publish((cfx.decision, res_verifier, res_basis), continuations={cont_path: cont_bytes})
    loaded = cfx.load()
    loaded_verifiers = [rec for rec in loaded.records if isinstance(rec, c.VerificationRecord)]
    assert len(loaded_verifiers) == 1
    assert len(loaded_verifiers[0].context.future.request_resolutions.values) == 1
    assert len(dict(loaded.continuations)[cont_path]) == 1

    # 4. Overflow >260 obligations + warrants simultaneously stay within MAX_INLINE_REFERENCES (256)
    #    and spill excess request_resolutions into continuations/request_resolutions/*.jsonl.
    fx_many = audit_helpers.fixture(tmp_path / "audit-many", state="confirmed")
    many_obs: list[EvidenceObligation] = []
    many_obs_json = []
    for idx in range(265):
        req_id = f"evreq-{idx:064x}"
        q = f"verify obligation {idx}"
        syn_ob = _build_synthetic_obligation(
            claim_id=claim_id,
            request_id=req_id,
            origin_cell_id=audit_helpers.RED,
            predicate=Predicate.MISSING_OR_INEFFECTIVE_GUARD,
            question=q,
            state=ObligationState.UNSATISFIED,
        )
        many_obs.append(syn_ob)
        many_obs_json.append(obligation_json(syn_ob))
    _attach_ledger_requests(fx_many, many_obs)

    lead_warrants = audit_helpers.document(
        fx_many.root,
        f"{audit_helpers.ATTEMPT}/steps/lead_review/tasks/teams/warrants.json",
        {"schema": WARRANTS_SCHEMA, "lane": "lead", "rule": WARRANT_RULE_VERSION,
         "count": 1, "items": [warrant_json(warrant)]},
    )
    hunt_warrants = audit_helpers.document(
        fx_many.root,
        f"{audit_helpers.ATTEMPT}/steps/hunt_review/tasks/teams/warrants.json",
        {"schema": WARRANTS_SCHEMA, "lane": "hunt", "rule": WARRANT_RULE_VERSION,
         "count": 0, "items": []},
    )
    many_lead_obs = audit_helpers.document(
        fx_many.root,
        f"{audit_helpers.ATTEMPT}/steps/lead_review/tasks/teams/evidence-obligations.json",
        {"schema": LANE_OBLIGATIONS_SCHEMA, "lane": "lead", "policy_version": OBLIGATION_POLICY_VERSION,
         "count": len(many_obs_json), "items": many_obs_json},
    )
    many_hunt_obs = audit_helpers.document(
        fx_many.root,
        f"{audit_helpers.ATTEMPT}/steps/hunt_review/tasks/teams/evidence-obligations.json",
        {"schema": LANE_OBLIGATIONS_SCHEMA, "lane": "hunt", "policy_version": OBLIGATION_POLICY_VERSION,
         "count": 0, "items": []},
    )
    many_lanes: list[Document] = []
    for lane_doc in fx_many.inputs.lanes:
        is_lead = lane_doc.value["lane"] == "lead"
        many_lanes.append(
            audit_helpers.document(
                fx_many.root,
                lane_doc.source.path,
                {
                    **lane_doc.value,
                    "warrants": audit_helpers.reference(lead_warrants if is_lead else hunt_warrants),
                    "evidence_obligations": audit_helpers.reference(many_lead_obs if is_lead else many_hunt_obs),
                },
            )
        )
    if not any(doc.value["lane"] == "hunt" for doc in many_lanes):
        many_lanes.append(
            audit_helpers.document(
                fx_many.root,
                f"{audit_helpers.ATTEMPT}/steps/hunt_review/tasks/teams/hunt-lane.json",
                {
                    "schema": "appsec-review/inference-review-lane/1",
                    "lane": "hunt",
                    "expected_cells": {},
                    "independence": {},
                    "capabilities": [],
                    "proposal_audit": {"schema": "appsec-review/proposal-membership-capture/1", "items": []},
                    "warrants": audit_helpers.reference(hunt_warrants),
                    "evidence_obligations": audit_helpers.reference(many_hunt_obs),
                },
            )
        )
    fx_many.inputs = replace(
        fx_many.inputs,
        lanes=tuple(many_lanes),
        warrants={"lead": lead_warrants, "hunt": hunt_warrants},
        request_resolutions={"lead": many_lead_obs, "hunt": many_hunt_obs},
    )
    fx_many.refs = replace(
        fx_many.refs,
        lanes=tuple(audit_helpers.reference(doc) for doc in many_lanes),
    )

    pub_many = publish_decision_audit(
        run_root=fx_many.root, attempt_root=fx_many.attempt, origin=fx_many.inputs.origin,
        scope=fx_many.scope, collection=fx_many.inputs.collection,
        inputs=fx_many.refs, settings=fx_many.settings,
    )
    assert pub_many.manifest is not None
    proj_many = fx_many.project()
    basis = [r for r in proj_many.records if isinstance(r, c.DecisionBasisRecord)][0]
    assert basis.context.future.warrants.absence_reason is None
    assert basis.context.future.request_resolutions.absence_reason is None
    cont_fields = {ref.field for ref in basis.context.continuations}
    assert c.ReferenceField.REQUEST_RESOLUTIONS in cont_fields
    assert len(proj_many.continuations) >= 1

    # 5. Lane disagreement on evidence_obligations fails closed!
    bad_lanes = [
        many_lanes[0],
        audit_helpers.document(
            fx_many.root,
            many_lanes[1].source.path,
            {k: v for k, v in many_lanes[1].value.items() if k != "evidence_obligations"},
        ),
    ]
    bad_refs = replace(fx_many.refs, lanes=tuple(audit_helpers.reference(doc) for doc in bad_lanes))
    with pytest.raises(IntegrityError, match="disagree on evidence obligation production"):
        publish_decision_audit(
            run_root=fx_many.root, attempt_root=fx_many.attempt, origin=fx_many.inputs.origin,
            scope=fx_many.scope, collection=fx_many.inputs.collection,
            inputs=bad_refs, settings=fx_many.settings,
        )
