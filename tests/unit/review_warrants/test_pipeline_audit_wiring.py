"""Pipeline, stage, schema, and decision-audit wiring tests for TRI-B (T-152)."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from jsonschema import Draft202012Validator
import pytest

from appsec_review.config import WarrantPolicySettings, load_config
from appsec_review.jobs.job_inference_security_review import stages
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.jobs.job_inference_security_review.teams import (
    TeamResult, WARRANTS_SCHEMA, _relations, _seal, lane_failure,
)
from appsec_review.review.adjudication import POLICY_SHA256, WARRANT_POLICY_SHA256
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.projection import Document
from appsec_review.review.ledger import project as ledger_project
from appsec_review.review.models import (
    CellRecord, CellStatus, Claim, ClaimState, IntegrityError, Lane, Predicate,
    RelationKind, Role, SecurityPredicate,
)
from appsec_review.review.warrants import (
    WARRANT_RULE_VERSION, WARRANT_SCHEMA, PredicateWarrant, SubjectBinding, WarrantBasis,
    WarrantCoverage, WarrantEvidenceRef, WarrantReasonCode, WarrantResult,
    bind_warrant_relation_id, warrant_from_json, warrant_json,
)
from tests.fixtures.inference_review.acceptance import JOB, ROOT
from tests.unit.review_decision_audit_consumers import helpers as consumer_helpers
from tests.unit.review_decision_audit_producer import helpers as audit_helpers
from tests.unit.review_warrants.test_optin_wiring import wiring_core  # noqa: F401


PREDICATE_WARRANT_SCHEMA = ROOT / "docs" / "schemas" / "predicate-warrant.schema.json"


def _schema_validator() -> Draft202012Validator:
    schema = json.loads(PREDICATE_WARRANT_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _closed_subset_validator(tmp_path: Path) -> SchemaSet:
    schema_dir = tmp_path / "schemas"
    schema_dir.mkdir(exist_ok=True)
    common = ROOT / SCHEMA_DIRECTORY / "common.schema.json"
    (schema_dir / "common.schema.json").write_text(common.read_text(encoding="utf-8"), encoding="utf-8")
    (schema_dir / "predicate-warrant.schema.json").write_text(
        PREDICATE_WARRANT_SCHEMA.read_text(encoding="utf-8"), encoding="utf-8",
    )
    return SchemaSet(schema_dir)


def _make_warrant(
    *,
    claim_id: str,
    relation_id: str,
    predicate: Predicate = Predicate.AFFECTED_CONSTRUCT,
    established: bool = True,
    entity_id: str = "asr:source_span:" + "a" * 64,
    entity_kind: str = "source_span",
    shard_id: str = "observations/scanner",
    content_sha256: str = "1" * 64,
    locator: str = "src/auth.c:10-20",
    receipt_sha256: str | None = "c" * 64,
) -> PredicateWarrant:
    draft = PredicateWarrant(
        warrant_id="warrant-" + "0" * 64,
        claim_id=claim_id,
        relation_id=relation_id,
        predicate=predicate,
        requested_relation=RelationKind.SUPPORTS if established else RelationKind.CONTRADICTS,
        effective_relation=RelationKind.SUPPORTS if established else RelationKind.QUALIFIES,
        subject_binding=SubjectBinding(
            affected_entity_ids=(entity_id,),
            operation_id="op-auth",
            sink_id=None,
            build_scope_id="codeql:c/c++:debug:1111111111111111",
        ),
        basis=WarrantBasis.STRUCTURED_PRESENCE,
        evidence_refs=(
            WarrantEvidenceRef(
                entity_id=entity_id,
                entity_kind=entity_kind,
                shard_id=shard_id,
                content_sha256=content_sha256,
                locator=locator,
                retrieval_receipt_sha256=receipt_sha256,
            ),
        ),
        rule=WARRANT_RULE_VERSION,
        result=WarrantResult.ESTABLISHED_SUPPORT if established else WarrantResult.NOT_ESTABLISHED,
        reason_code=(
            WarrantReasonCode.BOUND_PRESENCE_SUPPORTS_CONSTRUCT
            if established else WarrantReasonCode.PRESENCE_CANNOT_CONTRADICT_CONSTRUCT
        ),
        coverage=WarrantCoverage.COMPLETE_FOR_SUPPLIED_FACTS,
    )
    return bind_warrant_relation_id(draft, relation_id)


def _sample_warrant(*, valid: bool = True) -> dict:
    return warrant_json(_make_warrant(
        claim_id="claim-" + ("a" * 64 if valid else "b" * 64),
        relation_id="evrel-" + ("1" * 64 if valid else "2" * 64),
        established=valid,
    ))


def test_predicate_warrant_schema_validates_valid_downgraded_and_lane_documents(tmp_path: Path) -> None:
    validator = _schema_validator()
    subset = _closed_subset_validator(tmp_path)

    valid_doc = _sample_warrant(valid=True)
    invalid_doc = _sample_warrant(valid=False)
    lane_doc = {
        "schema": WARRANTS_SCHEMA,
        "lane": "lead",
        "rule": WARRANT_RULE_VERSION,
        "count": 2,
        "items": [valid_doc, invalid_doc],
    }

    for payload in (valid_doc, invalid_doc, lane_doc):
        validator.validate(payload)
        subset.validate("predicate-warrant", payload)

    assert valid_doc["schema"] == WARRANT_SCHEMA
    assert invalid_doc["result"] == WarrantResult.NOT_ESTABLISHED.value
    assert invalid_doc["reason_code"] == WarrantReasonCode.PRESENCE_CANNOT_CONTRADICT_CONSTRUCT.value

    bad_warrant_id = {**valid_doc, "warrant_id": "bad-id"}
    bad_sink_id = {
        **valid_doc,
        "subject_binding": {**valid_doc["subject_binding"], "sink_id": "asr:source_span:" + "9" * 64},
    }
    bad_extra = {**valid_doc, "unexpected": True}
    for bad in (bad_warrant_id, bad_sink_id, bad_extra):
        assert list(validator.iter_errors(bad))
        assert subset.errors("predicate-warrant", bad)


def _run_synthetic_lane(wiring_core, attempt_root: Path, *, enabled: bool) -> SimpleNamespace:
    core, ids = wiring_core
    attempt_root.mkdir(parents=True, exist_ok=True)
    base_settings = load_config(ROOT / "appsec-review.toml", profile="dev").job(JOB).typed_settings
    cfg = replace(base_settings, warrant_policy=WarrantPolicySettings(enabled=enabled))
    ctx = SimpleNamespace(core=core, settings=cfg, rule_predicates={})

    package_id = "package-" + "b" * 64
    red_cell_id = "cell-" + "1" * 64
    ver_cell_id = "cell-" + "2" * 64
    blue_cell_id = "cell-" + "3" * 64
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
        origin_cell_ids=(red_cell_id,),
    )
    seen = set(ids.values())
    warrant_map: dict[str, PredicateWarrant] = {}

    def make_cell(cid: str, role: Role) -> SimpleNamespace:
        return SimpleNamespace(
            cell_id=cid,
            spec=SimpleNamespace(role=role),
            record=SimpleNamespace(receipt_sha256="c" * 64),
        )

    red_rels, red_gaps = _relations(
        ctx, make_cell(red_cell_id, Role.HYPOTHESIS_HUNTER), claim_id,
        [
            {"predicate": Predicate.AFFECTED_CONSTRUCT.value,
             "kind": RelationKind.SUPPORTS.value, "entity_id": ids["sink_vuln"]},
            {"predicate": Predicate.ATTACKER_INPUT_CONTROL.value,
             "kind": RelationKind.SUPPORTS.value, "entity_id": ids["entry"]},
        ],
        seen, claim=claim, warrants=warrant_map,
    )
    ver_rels, ver_gaps = _relations(
        ctx, make_cell(ver_cell_id, Role.INDEPENDENT_VERIFIER), claim_id,
        [
            {"predicate": Predicate.SOURCE_TO_SINK_REACHABILITY.value,
             "kind": RelationKind.SUPPORTS.value, "entity_id": ids["path_vuln"]},
            {"predicate": Predicate.MISSING_OR_INEFFECTIVE_GUARD.value,
             "kind": RelationKind.SUPPORTS.value, "entity_id": ids["g_vuln_none"]},
        ],
        seen, claim=claim, warrants=warrant_map,
    )
    blue_rels, blue_gaps = _relations(
        ctx, make_cell(blue_cell_id, Role.BLUE_TEAM_REFUTER), claim_id,
        [
            {"predicate": Predicate.MISSING_OR_INEFFECTIVE_GUARD.value,
             "kind": RelationKind.CONTRADICTS.value, "entity_id": ids["g_safe_effective"]},
        ],
        seen, claim=claim, warrants=warrant_map,
    )
    team = TeamResult(
        package_id=package_id,
        lane=Lane.LEAD,
        unit_key="unit-1",
        launched=True,
        claims=[claim],
        relations=[*red_rels, *ver_rels, *blue_rels],
        warrants=dict(warrant_map),
        independence={claim_id: [{"claim_id": claim_id, "independent": True,
                                  "verifier_cell_id": ver_cell_id, "shared_factors": []}]},
        cells=[
            CellRecord(cell_id=red_cell_id, lane=Lane.LEAD, package_id=package_id,
                       role=Role.HYPOTHESIS_HUNTER, persona="p1", stack_profile="c",
                       task="variant", claim_id=None, status=CellStatus.SUCCEEDED, attempts=1),
            CellRecord(cell_id=ver_cell_id, lane=Lane.LEAD, package_id=package_id,
                       role=Role.INDEPENDENT_VERIFIER, persona="p2", stack_profile="c",
                       task="verify", claim_id=claim_id, status=CellStatus.SUCCEEDED, attempts=1),
            CellRecord(cell_id=blue_cell_id, lane=Lane.LEAD, package_id=package_id,
                       role=Role.BLUE_TEAM_REFUTER, persona="p3", stack_profile="c",
                       task="blue_control", claim_id=claim_id, status=CellStatus.SUCCEEDED, attempts=1),
        ],
        capabilities=[
            {"cell_id": red_cell_id, "round": 0},
            {"cell_id": ver_cell_id, "round": 0},
            {"cell_id": blue_cell_id, "round": 0},
        ],
        gaps=[*red_gaps, *ver_gaps, *blue_gaps],
        counts={"cells_run": 3, "cells_reused": 0, "cells_memo_reused": 0,
                "cells_not_launched": 0, "memo_cache_unavailable": 0},
    )
    ledger_path = attempt_root / "lead-ledger.jsonl"
    doc = _seal(ctx, Lane.LEAD, [team], {Lane.LEAD: 1, Lane.HUNT: 0}, ledger_path, "lead_review.teams")
    pkg_entities = {package_id: tuple(ids.values())}
    return SimpleNamespace(
        doc=doc, ledger_path=ledger_path, attempt_root=attempt_root,
        cfg=cfg, pkg_entities=pkg_entities,
    )


def test_run_lane_default_off_omits_warrants_and_preserves_default_policy(
    wiring_core, tmp_path: Path,
) -> None:
    off = _run_synthetic_lane(wiring_core, tmp_path / "off", enabled=False)
    assert "warrants" not in off.doc
    fail_off = lane_failure(Lane.HUNT, [], "unavailable", tmp_path / "off-fail" / "ledger.jsonl", "hunt_review.teams")
    assert "warrants" not in fail_off
    off_merged = stages.merge_claims([off.doc], [off.ledger_path], off.pkg_entities, ())
    off_proj = ledger_project(stages.merge_verified([off.ledger_path]).events)
    off_adj = stages.apply_policy(off_merged, off_proj, tmp_path / "off-adj.jsonl", "adjudicate.apply_policy")
    assert off_adj["policy_sha256"] == POLICY_SHA256
    # Under default-off policy, the unrelated guard contradiction contested guard absence -> INSUFFICIENT_EVIDENCE.
    assert off_adj["adjudications"][0]["state"] == ClaimState.INSUFFICIENT_EVIDENCE.value


def test_run_lane_and_stages_emit_verified_warrants_when_enabled(
    wiring_core, tmp_path: Path,
) -> None:
    on = _run_synthetic_lane(wiring_core, tmp_path / "on", enabled=True)
    assert "warrants" in on.doc
    fail_on = lane_failure(
        Lane.HUNT, [], "unavailable", tmp_path / "on-fail" / "ledger.jsonl", "hunt_review.teams",
        warrants_enabled=True,
    )
    assert "warrants" in fail_on and fail_on["warrants"]["count"] == 0
    warrants_file = Path(on.doc["warrants"]["path"])
    assert warrants_file.exists()
    assert hashlib.sha256(warrants_file.read_bytes()).hexdigest() == on.doc["warrants"]["sha256"]
    raw_warrants = json.loads(warrants_file.read_text(encoding="utf-8"))
    _schema_validator().validate(raw_warrants)
    assert raw_warrants["count"] == len(raw_warrants["items"]) == 5

    parsed = tuple(warrant_from_json(item) for item in raw_warrants["items"])
    on_merged = stages.merge_claims([on.doc], [on.ledger_path], on.pkg_entities, ())
    on_proj = ledger_project(stages.merge_verified([on.ledger_path]).events)
    on_adj = stages.apply_policy(
        on_merged, on_proj, tmp_path / "on-adj.jsonl", "adjudicate.apply_policy",
        warrants=parsed, warrant_policy_enabled=True,
    )
    assert on_adj["policy_sha256"] == WARRANT_POLICY_SHA256
    # Under warrant policy, unrelated guard contradiction was downgraded to QUALIFIES -> claim CONFIRMED!
    assert on_adj["adjudications"][0]["state"] == ClaimState.CONFIRMED.value

    schemas = SchemaSet(ROOT / SCHEMA_DIRECTORY)
    scores_doc = stages.score_claims(
        on_adj["adjudications"], on_proj, on.cfg.scoring.cwe_impact_overrides,
        tmp_path / "scores", tmp_path / "score-ledger.jsonl", "scoring.score_claims",
        schemas, warrants=parsed,
    )
    assert scores_doc["schema"] == "appsec-review/inference-review-scores/3"
    assert len(scores_doc["scores"]) == 1
    score_pkg = json.loads((tmp_path / "scores" / scores_doc["scores"][0]["file"]).read_text(encoding="utf-8"))
    assert score_pkg["policy_sha256"] == WARRANT_POLICY_SHA256

    # Tampered warrant for the scored claim fails closed inside score_claims -> factor_input.
    tampered_score_warrant = replace(parsed[0], predicate=Predicate.SECURITY_IMPACT)
    with pytest.raises(ValueError, match="does not match evidence relation"):
        stages.score_claims(
            on_adj["adjudications"], on_proj, on.cfg.scoring.cwe_impact_overrides,
            tmp_path / "bad-scores", tmp_path / "bad-score-ledger.jsonl", "scoring.score_claims",
            schemas, warrants=(tampered_score_warrant, *parsed[1:]),
        )

    # Tampered warrant pointing to an unknown relation fails closed in apply_policy.
    foreign = replace(parsed[0], relation_id="evrel-" + "f" * 64)
    with pytest.raises(IntegrityError, match="absent from the accepted projection"):
        stages.apply_policy(
            on_merged, on_proj, tmp_path / "bad-adj.jsonl", "adjudicate.apply_policy",
            warrants=(*parsed, foreign), warrant_policy_enabled=True,
        )


def _attach_audit_warrants(fx: audit_helpers.Fixture) -> tuple[Document, Document]:
    projection = fx.inputs.projection
    claim_id = next(iter(projection.claims))
    items = []
    for rel in projection.relations[claim_id]:
        established = rel.kind in (RelationKind.SUPPORTS, RelationKind.CONTRADICTS)
        warrant = _make_warrant(
            claim_id=claim_id,
            relation_id=rel.relation_id,
            predicate=rel.predicate,
            established=established,
            entity_id=rel.entity_id,
            entity_kind=rel.entity_kind,
            shard_id=rel.shard_id,
            content_sha256=rel.content_sha256,
            locator=rel.locator,
            receipt_sha256=rel.retrieval_receipt_sha256,
        )
        items.append(warrant_json(warrant))

    lead_warrants = audit_helpers.document(
        fx.root, f"{audit_helpers.ATTEMPT}/steps/lead_review/tasks/teams/warrants.json",
        {"schema": WARRANTS_SCHEMA, "lane": "lead", "rule": WARRANT_RULE_VERSION,
         "count": len(items), "items": items},
    )
    hunt_warrants = audit_helpers.document(
        fx.root, f"{audit_helpers.ATTEMPT}/steps/hunt_review/tasks/teams/warrants.json",
        {"schema": WARRANTS_SCHEMA, "lane": "hunt", "rule": WARRANT_RULE_VERSION,
         "count": 0, "items": []},
    )
    updated_lanes = []
    for lane_doc in fx.inputs.lanes:
        wdoc = lead_warrants if lane_doc.value["lane"] == "lead" else hunt_warrants
        body = {**lane_doc.value, "warrants": audit_helpers.reference(wdoc)}
        rewritten = audit_helpers.document(fx.root, lane_doc.source.path, body)
        updated_lanes.append(rewritten)
    if not any(doc.value["lane"] == "hunt" for doc in updated_lanes):
        hunt_body = {
            "schema": "appsec-review/inference-review-lane/1",
            "lane": "hunt",
            "expected_cells": {},
            "independence": {},
            "capabilities": [],
            "proposal_audit": {"schema": "appsec-review/proposal-membership-capture/1", "items": []},
            "warrants": audit_helpers.reference(hunt_warrants),
        }
        updated_lanes.append(audit_helpers.document(
            fx.root, f"{audit_helpers.ATTEMPT}/steps/hunt_review/tasks/teams/hunt-lane.json", hunt_body,
        ))
    fx.inputs = replace(fx.inputs, lanes=tuple(updated_lanes),
                        warrants={"lead": lead_warrants, "hunt": hunt_warrants})
    fx.refs = replace(fx.refs, lanes=tuple(audit_helpers.reference(doc) for doc in updated_lanes))
    return lead_warrants, hunt_warrants


def test_decision_audit_projects_publishes_and_verifies_warrants_including_continuations(tmp_path: Path) -> None:
    from appsec_review.jobs.job_inference_security_review.audit import publish_decision_audit

    # 1. Default without warrants preserves NOT_PRODUCED on every record.
    fx_off = audit_helpers.fixture(tmp_path / "off", state="confirmed")
    proj_off = fx_off.project()
    assert all(
        rec.context.future.warrants == c.OptionalSources((), c.AbsenceReason.NOT_PRODUCED)
        for rec in proj_off.records
    )

    # 2. With warrants enabled, claim-bearing decision/verification/basis records bind FutureReferences.warrants.
    fx_on = audit_helpers.fixture(tmp_path / "on", state="confirmed")
    lead_warrants, _ = _attach_audit_warrants(fx_on)
    published = publish_decision_audit(
        run_root=fx_on.root, attempt_root=fx_on.attempt, origin=fx_on.inputs.origin,
        scope=fx_on.scope, collection=fx_on.inputs.collection,
        inputs=fx_on.refs, settings=fx_on.settings,
    )
    assert published.manifest is not None
    assert any(item["path"] == lead_warrants.source.path for item in published.source_artifacts)

    proj_on = fx_on.project()
    adj_records = [
        rec for rec in proj_on.records
        if isinstance(rec, c.DecisionRecord) and rec.stage is c.Stage.ADJUDICATION
    ]
    ver_records = [rec for rec in proj_on.records if isinstance(rec, c.VerificationRecord)]
    basis_records = [rec for rec in proj_on.records if isinstance(rec, c.DecisionBasisRecord)]
    pre_claim_records = [
        rec for rec in proj_on.records
        if isinstance(rec, c.DecisionRecord) and rec.context.subject.claim_id.value is None
    ]
    assert len(adj_records) == 1 and adj_records[0].context.future.warrants.values
    assert adj_records[0].context.future.warrants.absence_reason is None
    assert any(c.EvidenceUse.CITED in ref.uses for ref in adj_records[0].context.future.warrants.values)
    assert len(ver_records) == 1 and ver_records[0].context.future.warrants.values
    assert len(basis_records) == 1 and basis_records[0].context.future.warrants.values
    assert all(
        rec.context.future.warrants == c.OptionalSources((), c.AbsenceReason.NOT_APPLICABLE)
        for rec in pre_claim_records
    )

    # 3. Verify consumer reader (verify_decision_audit) accepts inline + continued FutureReferences.warrants
    #    pinned under review_cells steps/lead_review/tasks/teams/warrants.json and rejects tampered digests.
    cfx = consumer_helpers.Fixture(tmp_path / "consumer")
    warrant_payload = _sample_warrant(valid=True)
    warrant_payload_2 = _sample_warrant(valid=False)
    warrants_ref = cfx.write(
        cfx.attempt + "/steps/lead_review/tasks/teams/warrants.json",
        {"schema": WARRANTS_SCHEMA, "lane": "lead", "rule": WARRANT_RULE_VERSION,
         "count": 2, "items": [warrant_payload, warrant_payload_2]},
    )
    inline_warrant = c.SourceRef(
        cfx.root.name, warrants_ref["path"], warrants_ref["sha256"],
        consumer_helpers.link(warrant_payload["warrant_id"]), (c.EvidenceUse.READ, c.EvidenceUse.CITED),
    )
    continued_warrant = c.SourceRef(
        cfx.root.name, warrants_ref["path"], warrants_ref["sha256"],
        consumer_helpers.link(warrant_payload_2["warrant_id"]), (c.EvidenceUse.READ,),
    )
    cont_path = cfx.audit_root + "/continuations/warrants/0001.jsonl"
    cont_ref = c.make_continuation(
        c.ReferenceField.WARRANTS, cont_path, (continued_warrant,),
        origin=cfx.origin, claim_id=consumer_helpers.link("claim-1"),
    )
    cont_bytes = c.reference_bytes(
        c.ReferenceField.WARRANTS, (continued_warrant,),
        origin=cfx.origin, claim_id=consumer_helpers.link("claim-1"),
    )
    warranted_future = replace(
        cfx.verification.context.future,
        warrants=c.OptionalSources((inline_warrant,), None),
    )
    warranted_verifier = replace(
        cfx.verification,
        context=replace(cfx.verification.context, future=warranted_future, continuations=(cont_ref,)),
    )
    warranted_basis = replace(
        cfx.basis,
        context=replace(cfx.basis.context, future=warranted_future, continuations=(cont_ref,)),
        verification=c.OptionalRecord(c.RecordRef.of(warranted_verifier), None),
    )
    cfx.publish((cfx.decision, warranted_verifier, warranted_basis), continuations={cont_path: cont_bytes})
    loaded = cfx.load()
    loaded_verifiers = [rec for rec in loaded.records if isinstance(rec, c.VerificationRecord)]
    assert len(loaded_verifiers) == 1
    assert len(loaded_verifiers[0].context.future.warrants.values) == 1
    assert len(dict(loaded.continuations)[cont_path]) == 1

    # 4. Overflow >256 inline references spills warrants into continuations/warrants/ cleanly.
    fx_big = audit_helpers.fixture(tmp_path / "big", state="confirmed", relation_count=260)
    _attach_audit_warrants(fx_big)
    proj_big = fx_big.project()
    big_adj = next(
        rec for rec in proj_big.records
        if isinstance(rec, c.DecisionRecord) and rec.stage is c.Stage.ADJUDICATION
    )
    assert len(big_adj.context.future.warrants.values) >= 1
    assert big_adj.context.future.warrants.absence_reason is None
    assert any(ref.field is c.ReferenceField.WARRANTS for ref in big_adj.context.continuations)

    # 5. Asymmetric lane warrants fail closed during audit publication.
    fx_asym = audit_helpers.fixture(tmp_path / "asym", state="confirmed")
    _attach_audit_warrants(fx_asym)
    bad_hunt = audit_helpers.document(
        fx_asym.root, fx_asym.inputs.lanes[1].source.path,
        {k: v for k, v in fx_asym.inputs.lanes[1].value.items() if k != "warrants"},
    )
    fx_asym.refs = replace(fx_asym.refs, lanes=(fx_asym.refs.lanes[0], audit_helpers.reference(bad_hunt)))
    with pytest.raises(IntegrityError, match="disagree on predicate warrant production"):
        publish_decision_audit(
            run_root=fx_asym.root, attempt_root=fx_asym.attempt, origin=fx_asym.inputs.origin,
            scope=fx_asym.scope, collection=fx_asym.inputs.collection,
            inputs=fx_asym.refs, settings=fx_asym.settings,
        )
