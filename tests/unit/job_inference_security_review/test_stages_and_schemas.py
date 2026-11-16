"""Focused unit tests for schemas.py and stages.py edge cases."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.config.inference_review import PocCandidateSettings
from appsec_review.jobs.job_inference_security_review import stages
from appsec_review.jobs.job_inference_security_review.job import JOB_ID
from appsec_review.jobs.job_inference_security_review.schemas import (
    SCHEMA_DIRECTORY,
    SchemaSet,
    _equal,
    _is_type,
    schema_set,
)
from appsec_review.review.accounting import PoolOutcome
from appsec_review.review.identity import make_id
from appsec_review.review.ledger import LedgerWriter, gap_json, merge_shards, project
from appsec_review.review.models import (
    Admissibility,
    CellRecord,
    CellStatus,
    Claim,
    ClaimState,
    EvidenceRelation,
    IntegrityError,
    JudgeVerdict,
    JudgeVerdictValue,
    Lane,
    Predicate,
    RelationKind,
    Role,
    make_gap,
    GapClass,
)
from appsec_review.review.warrants import PredicateWarrant, WarrantScope
from appsec_review.storage import file_sha256

ROOT = Path(__file__).resolve().parents[3]


def _sample_claim(claim_id: str | None = None, *, lane: Lane = Lane.LEAD, pkg: str = "pkg-1") -> Claim:
    cid = claim_id or ("claim-" + "a" * 64)
    return Claim(
        claim_id=cid,
        lane=lane,
        package_id=pkg,
        affected_entities=("sym-1",),
        weakness_cwe="CWE-89",
        security_predicate="sql_injection",
        preconditions=(),
        statement="SQL injection in query builder.",
        origin_cell_ids=("cell-" + "1" * 64,),
    )


def test_schema_set_closed_subset_edge_cases(tmp_path: Path) -> None:
    empty_dir = tmp_path / "empty_schemas"
    empty_dir.mkdir()
    with pytest.raises(ValueError, match="schema set is incomplete"):
        SchemaSet(empty_dir)

    sdir = tmp_path / "schemas"
    sdir.mkdir()
    (sdir / "common.schema.json").write_text(
        json.dumps(
            {
                "$defs": {
                    "color": {"type": "string", "enum": ["red", "blue"]},
                    "num": {"type": "number", "minimum": 1, "maximum": 10},
                }
            }
        ),
        encoding="utf-8",
    )
    (sdir / "custom.schema.json").write_text(
        json.dumps(
            {
                "type": "object",
                "required": ["kind", "tags", "meta", "choice"],
                "additionalProperties": False,
                "properties": {
                    "kind": {"const": "demo"},
                    "tags": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 2,
                        "uniqueItems": True,
                        "items": {"type": "string", "minLength": 2, "maxLength": 5, "pattern": "^[a-z]+$"},
                    },
                    "meta": {"type": "object", "additionalProperties": {"$ref": "common.schema.json#$defs/num"}},
                    "choice": {
                        "oneOf": [
                            {"$ref": "common.schema.json#$defs/color"},
                            {"type": "string", "enum": ["green"]},
                        ]
                    },
                    "flag": {"type": ["boolean", "null"]},
                },
                "allOf": [{"not": {"properties": {"kind": {"const": "forbidden"}}, "required": ["kind"]}}],
                "if": {"properties": {"flag": {"const": True}}, "required": ["flag"]},
                "then": {"properties": {"meta": {"required": ["must"]}}},
                "else": {"properties": {"meta": {"not": {"required": ["forbid_else"]}}}},
            }
        ),
        encoding="utf-8",
    )
    ss = SchemaSet(sdir)
    valid = {
        "kind": "demo",
        "tags": ["ab", "cd"],
        "meta": {"must": 5},
        "choice": "green",
        "flag": True,
    }
    ss.validate("custom", valid)

    invalid = {
        "kind": "wrong",
        "tags": ["a", "a", "TOOLONG"],
        "meta": {"low": 0, "high": 99},
        "choice": "yellow",
        "flag": True,
        "extra": 1,
    }
    errs = ss.errors("custom", invalid)
    assert any("does not equal the constant" in e for e in errs)
    assert any("array length out of bounds" in e for e in errs)
    assert any("array items are not unique" in e for e in errs)
    assert any("below minimum" in e for e in errs)
    assert any("above maximum" in e for e in errs)
    assert any("allowed values: red, blue, green" in e for e in errs)
    assert any("unexpected property extra" in e for e in errs)
    assert any("missing required property must" in e for e in errs)
    limited = ss.errors("custom", invalid, limit=2)
    assert 0 < len(limited) < len(errs)

    with pytest.raises(ValueError, match="does not satisfy its schema"):
        ss.validate("custom", invalid)

    else_bad = {**valid, "flag": False, "meta": {"forbid_else": 3}}
    assert any("matches a forbidden schema" in e for e in ss.errors("custom", else_bad))

    (sdir / "bad_kw.schema.json").write_text(json.dumps({"patternProperties": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="schema keyword is not supported"):
        SchemaSet(sdir).errors("bad_kw", {})

    (sdir / "bad_type.schema.json").write_text(json.dumps({"type": "tuple"}), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported schema type"):
        SchemaSet(sdir).errors("bad_type", 1)

    assert _equal(True, 1) is False
    assert _equal(False, 0) is False
    assert _is_type(True, "integer") is False
    assert _is_type(float("nan"), "number") is False
    assert schema_set(str(ROOT)) is schema_set(str(ROOT))


def test_stages_merge_adjudicate_and_receipt_guards(tmp_path: Path) -> None:
    s1 = tmp_path / "s1.jsonl"
    w1 = LedgerWriter(s1, "lead_review.teams")
    claim = _sample_claim()
    w1.propose_claim(claim)
    cell_no_receipt = CellRecord(
        cell_id="cell-" + "2" * 64,
        lane=Lane.LEAD,
        package_id="pkg-1",
        role=Role.RED_TEAM_ANALYST,
        persona="injection_interpreters",
        stack_profile="python_service",
        task="lead_red_stack",
        claim_id=None,
        status=CellStatus.FAILED,
        attempts=1,
        gap_ids=(),
        receipt_sha256=None,
    )
    w1.cell_terminal(cell_no_receipt)
    w1.seal()

    merged_ledger = stages.merge_verified([s1])
    proj = project(merged_ledger.events)
    assert claim.claim_id in proj.claims

    with pytest.raises(IntegrityError, match="cell record without a receipt"):
        stages.verify_receipts(proj, tmp_path / "cells")

    s2 = tmp_path / "s2.jsonl"
    w2 = LedgerWriter(s2, "lead_review.teams")
    cell_with_receipt = replace(cell_no_receipt, receipt_sha256="a" * 64)
    w2.cell_terminal(cell_with_receipt)
    w2.seal()
    proj2 = project(stages.merge_verified([s2]).events)
    with pytest.raises(IntegrityError, match="cell receipt cannot be verified"):
        stages.verify_receipts(proj2, tmp_path / "cells")

    receipt_file = tmp_path / "cells" / cell_with_receipt.cell_id / "attempt-1.json"
    receipt_file.parent.mkdir(parents=True, exist_ok=True)
    receipt_file.write_bytes(b'{"ok":true}')
    s3 = tmp_path / "s3.jsonl"
    w3 = LedgerWriter(s3, "lead_review.teams")
    w3.cell_terminal(replace(cell_no_receipt, receipt_sha256=file_sha256(receipt_file)))
    w3.seal()
    proj3 = project(stages.merge_verified([s3]).events)
    assert stages.verify_receipts(proj3, tmp_path / "cells") == 1

    with pytest.raises(IntegrityError, match="lane documents and ledger shards disagree"):
        stages.merge_claims(
            [{"proposals": {"claim-" + "f" * 64: ["pkg-1"]}, "independence": {}, "verifier_gaps": {}}],
            [s1],
            {"pkg-1": ["sym-1"]},
            [],
        )

    merged_doc = stages.merge_claims(
        [{"proposals": {claim.claim_id: ["pkg-1"]}, "independence": {}, "verifier_gaps": {}}],
        [s1],
        {"pkg-1": ["sym-1"]},
        ["comp-1"],
    )

    bad_warrant = SimpleNamespace(
        claim_id="claim-" + "9" * 64,
        relation_id="rel-" + "9" * 64,
    )
    with pytest.raises(IntegrityError, match="absent from the accepted projection"):
        stages.apply_policy(
            merged_doc,
            proj,
            tmp_path / "adj1.jsonl",
            "adjudicate.apply_policy",
            warrants=[bad_warrant],
            warrant_policy_enabled=True,
        )

    bad_rel_warrant = SimpleNamespace(
        claim_id=claim.claim_id,
        relation_id="rel-" + "9" * 64,
    )
    with pytest.raises(IntegrityError, match="relation absent from the accepted projection"):
        stages.apply_policy(
            merged_doc,
            proj,
            tmp_path / "adj2.jsonl",
            "adjudicate.apply_policy",
            warrants=[bad_rel_warrant],
            warrant_policy_enabled=True,
        )


def test_stages_scoring_findings_poc_candidates_and_completeness_helpers(tmp_path: Path) -> None:
    settings = load_config(ROOT / "appsec-review.toml").job(JOB_ID).typed_settings
    schemas = SchemaSet(ROOT / SCHEMA_DIRECTORY)
    claim = _sample_claim()
    s1 = tmp_path / "s1.jsonl"
    w1 = LedgerWriter(s1, "lead_review.teams")
    w1.propose_claim(claim)
    rel = EvidenceRelation(
        relation_id="evrel-" + "3" * 64,
        claim_id=claim.claim_id,
        predicate=Predicate.AFFECTED_CONSTRUCT,
        kind=RelationKind.SUPPORTS,
        entity_id="sym-1",
        entity_kind="symbol",
        admissibility=Admissibility.DIRECT,
        shard_id="shard-1",
        content_sha256="4" * 64,
        locator="src/a.py:1",
        complete=True,
        producing_cell_id="cell-" + "1" * 64,
        retrieval_receipt_sha256="5" * 64,
    )
    w1.add_relation(rel)
    w1.seal()

    vgap = make_gap(GapClass.INDEPENDENCE_GAP, claim.claim_id, "verifier unavailable")
    merged_doc = stages.merge_claims(
        [
            {
                "proposals": {claim.claim_id: ["pkg-1"]},
                "independence": {
                    claim.claim_id: [
                        {
                            "verifier_cell_id": "cell-v1",
                            "independent": False,
                            "provider_distinct": False,
                            "verifier_model_distinct": False,
                            "review_id": "rev-1",
                        }
                    ]
                },
                "verifier_gaps": {claim.claim_id: [gap_json(vgap)]},
            }
        ],
        [s1],
        {"pkg-1": ["sym-1"]},
        [],
    )
    adj_shard = tmp_path / "adj.jsonl"
    adj_doc = stages.apply_policy(
        merged_doc, project(merge_shards([s1]).events), adj_shard, "adjudicate.apply_policy"
    )
    assert adj_doc["states"] == {"supported": 1}

    lead_pkg = {
        "kind": "finding_lead",
        "lead_menu": [
            {
                "observation_id": "obs-1",
                "lead_family": "dependency_vulnerability",
                "severity_record": {"effective_severity": "critical", "source": "scanner"},
                "advisory_context": {
                    "summary": {"kev_listed": True, "epss_percentile": 0.9},
                    "advisories": [
                        {
                            "nvd": [
                                {
                                    "cve_id": "CVE-2025-0001",
                                    "cwes": ["CWE-89"],
                                    "cvss": [
                                        {
                                            "version": "3.1",
                                            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                            "base_score": 9.8,
                                        }
                                    ],
                                }
                            ],
                            "epss": [
                                {
                                    "cve_id": "CVE-2025-0001",
                                    "epss": 0.5,
                                    "percentile": 0.9,
                                    "score_date": "2025-10-01",
                                }
                            ],
                        }
                    ],
                },
            }
        ],
    }
    docs = {"pkg-1": lead_pkg, "pkg-hunt": {"kind": "hunt", "lead_menu": []}}
    refs = stages.claim_references(merged_doc, docs)
    assert refs[claim.claim_id]["kev_listed"] is True
    fams = stages.claim_lead_families(merged_doc, docs)
    assert fams[claim.claim_id] == ("dependency_vulnerability",)
    sevs = stages.claim_lead_severities(merged_doc, docs)
    assert sevs[claim.claim_id][0]["observation_id"] == "obs-1"

    proj = project(merge_shards([s1, adj_shard]).events)
    score_shard = tmp_path / "score.jsonl"
    score_doc = stages.score_claims(
        adj_doc["adjudications"],
        proj,
        settings.scoring.cwe_impact_overrides,
        tmp_path / "scores",
        score_shard,
        "scoring.score_claims",
        schemas,
        references=refs,
    )
    assert len(score_doc["scores"]) >= 1

    # finding_judge unanimous vs conflicting verdicts
    jv1 = JudgeVerdict("judge-" + "1" * 64, claim.claim_id, JudgeVerdictValue.BLUE_CORRECT, (), "blue wins", "cell-j1", True)
    jv2 = JudgeVerdict("judge-" + "2" * 64, claim.claim_id, JudgeVerdictValue.RED_CORRECT, (), "red wins", "cell-j2", True)
    assert stages.finding_judge([]) is None
    j_blue = stages.finding_judge([jv1])
    assert j_blue["verdict"] == "blue_correct" and j_blue["disagrees_with_state"] is True
    j_split = stages.finding_judge([jv1, jv2])
    assert j_split["verdict"] == "unresolved" and j_split["disagrees_with_state"] is False

    # handoff_status
    assert stages.handoff_status(SimpleNamespace(outcome=PoolOutcome.COMPLETE)) == "COMPLETE"
    assert stages.handoff_status(SimpleNamespace(outcome=PoolOutcome.EMPTY)) == "EMPTY"
    assert stages.handoff_status(SimpleNamespace(outcome=PoolOutcome.DEGRADED)) == "DEGRADED"

    # remediation_partition rejects unpublishable state
    with pytest.raises(IntegrityError, match="unpublishable state"):
        stages.remediation_partition(
            [
                {
                    "finding_package_id": "fp-1",
                    "sha256": "1" * 64,
                    "claim_id": claim.claim_id,
                    "lane": "lead",
                    "ship_block_status": "advisory",
                    "state": "refuted",
                }
            ]
        )

    # poc_candidates filtering on accept_partly, entry/path, and risk_ratings
    finding = {
        "claim_id": claim.claim_id,
        "state": "supported",
        "judge_verdict": "partly",
        "technical_severity": "high",
        "finding_package_id": "fp-1",
        "sha256": "2" * 64,
        "direct_evidence": [rel.relation_id],
    }
    brief = {
        "claim_id": claim.claim_id,
        "package_id": "pkg-1",
        "cell_id": "cell-1",
        "poc_basis": {"entry": "POST /login", "path": "src/app.py"},
    }
    assert stages.poc_candidates([finding], [brief], PocCandidateSettings(accept_partly=False)) == []
    cands = stages.poc_candidates([finding], [brief], PocCandidateSettings(accept_partly=True))
    assert len(cands) == 1 and cands[0]["judge_verdict"] == "partly"
    # Run 2026-11-16-0003: the judge was disabled, so every confirmed claim had judge_verdict None and no candidate
    # was listed. A claim no judge saw is eligible on the verifier's confirmation and says so.
    unjudged = stages.poc_candidates([{**finding, "state": "confirmed", "judge_verdict": None}], [brief],
                                     PocCandidateSettings(accept_partly=False))
    assert len(unjudged) == 1 and unjudged[0]["judge_verdict"] == "not_convened"
    assert stages.poc_candidates([{**finding, "judge_verdict": "blue_correct"}], [brief],
                                 PocCandidateSettings(accept_partly=True)) == []

    # coverage_matrix and completeness_gaps
    cov = stages.coverage_matrix({"coverage": []}, [{"unit_key": "u1", "hunted": False}, {"unit_key": "u2", "hunted": True}])
    assert cov["summary"] == {"gap": 1}
    cgaps = stages.completeness_gaps(
        [{"unit_key": "u1", "hunted": False}],
        [{"producer": "job_sast", "scope": "repo", "state": "degraded", "reason": "timeout"}],
        cwe_reference={"gap": "stale_catalog", "accepted_count": 42},
        admission=[{"lead_id": "obs-9", "status": "not_admitted", "residual_coverage": "below_cutoff"}],
    )
    assert len(cgaps) == 4

    # base_review_projection rejects missing/mismatched chain cells
    with pytest.raises(IntegrityError, match="chain cell accounting is not exact"):
        stages.base_review_projection(proj, {"missing-cell": "hunt"})

    # build_handoff rejects inexact accounting
    bad_acc = SimpleNamespace(exact=False, violations=[make_gap(GapClass.COVERAGE_GAP, "run", "missing_cell")])
    with pytest.raises(IntegrityError, match="claim accounting is not exact"):
        stages.build_handoff(
            run_id="r1",
            manifest_sha256="1" * 64,
            configuration_sha256="2" * 64,
            projection=proj,
            accounting=bad_acc,
            shards=[],
            findings=[],
            scores=[],
            package_manifest_sha256="3" * 64,
            lead_package_manifest_sha256="4" * 64,
            coverage={"path": "c.json", "sha256": "5" * 64, "rows": 0},
            possible=[],
            schemas=schemas,
            ship_block_policy_sha256="6" * 64,
            verification={},
        )


def _scope_claim(entity: str, lane: Lane = Lane.HUNT, pkg: str = "hunt-1", cwe: str = "CWE-134") -> Claim:
    from appsec_review.review.claims import normalize_claim
    return normalize_claim(lane=lane, package_id=pkg, affected_entities=[entity], weakness_cwe=cwe,
                           security_predicate="memory_corruption", preconditions=["attacker_controls_request_field"],
                           statement="s", accepted_cwe_ids={cwe}).claim


SYMBOL = "asr:symbol:" + "a" * 64
FILE = "asr:source_file:" + "b" * 64
OTHER_FILE = "asr:source_file:" + "c" * 64
STRAY = "asr:symbol:" + "d" * 64


def test_claim_scope_resolution_locates_folded_symbols_rehomes_to_the_owner_or_keeps_out_of_scope() -> None:
    """claim-scope-resolution/1. Run 2026-11-16-0004: nine hunt claims folded to enclosing symbols of
    src/request.cpp were discarded as out of scope although their own hunt packages list that file."""
    own = _scope_claim(SYMBOL, pkg="hunt-1")                                   # symbol in the proposer's own file
    foreign = _scope_claim(SYMBOL, pkg="hunt-2", cwe="CWE-120")                # proposer covers no file of it
    stray = _scope_claim(STRAY, pkg="hunt-2", cwe="CWE-78")                    # nowhere in the review scope
    listed = _scope_claim(OTHER_FILE, pkg="hunt-2", cwe="CWE-22")              # a listed entity, in place
    claims = [own, foreign, stray, listed]
    proposals = {own.claim_id: ["hunt-1"], foreign.claim_id: ["hunt-2"], stray.claim_id: ["hunt-2"],
                 listed.claim_id: ["hunt-2"]}
    entities = {"hunt-1": [FILE], "hunt-2": [OTHER_FILE], "finding_lead-1": [FILE, "asr:tool_observation:" + "e" * 64]}
    paths = {"hunt-1": ["src/request.cpp"], "hunt-2": ["src/other.cpp"], "finding_lead-1": ["src/request.cpp"]}
    located = {SYMBOL: "src/request.cpp", STRAY: None}
    scope, resolution = stages.resolve_claim_scopes(claims, proposals, entities, ["comp-1"],
                                                    entity_paths=located, package_paths=paths)
    assert resolution[own.claim_id]["status"] == "in_scope" and resolution[own.claim_id]["basis"] == "located"
    assert SYMBOL in scope[own.claim_id] and resolution[own.claim_id]["rehomed_to"] is None
    # The foreign claim lands in the owning package: two hold the file, the lowest package id wins the tie.
    assert resolution[foreign.claim_id]["status"] == "rehomed"
    assert (resolution[foreign.claim_id]["rehomed_from"], resolution[foreign.claim_id]["rehomed_to"]) == (
        ["hunt-2"], "finding_lead-1")
    assert resolution[foreign.claim_id]["candidates"] == {"finding_lead-1": 1, "hunt-1": 1}
    assert set(scope[foreign.claim_id]) == {"comp-1", FILE, "asr:tool_observation:" + "e" * 64, SYMBOL}
    assert resolution[stray.claim_id]["status"] == "outside_review_scope" and scope[stray.claim_id] == sorted(["comp-1", OTHER_FILE])
    assert resolution[listed.claim_id] == {**resolution[listed.claim_id], "status": "in_scope", "basis": "listed",
                                           "rehomed_to": None, "located_entities": []}
    # Without locations (the earlier inputs) only listed entities count: nothing is located or re-homed.
    plain_scope, plain = stages.resolve_claim_scopes(claims, proposals, entities, ["comp-1"])
    assert {key: value["status"] for key, value in plain.items()} == {
        own.claim_id: "outside_review_scope", foreign.claim_id: "outside_review_scope",
        stray.claim_id: "outside_review_scope", listed.claim_id: "in_scope"}
    assert plain_scope[own.claim_id] == sorted(["comp-1", FILE])


def test_merge_and_adjudication_rehome_a_claim_instead_of_discarding_it(tmp_path: Path) -> None:
    """End to end over the ledger: a hunt claim on a symbol of a lead package's file is adjudicated in that
    package with its own verifier evidence (confirmed), recorded on the adjudication and the merge document;
    a claim outside every package stays out_of_scope; a claim a lead package also proposed is one claim in
    the lead lane, adjudicated in place (the lead-lane claim wins the duplicate proposal)."""
    from appsec_review.review.obligations import ALWAYS_REQUIRED
    shard = tmp_path / "hunt.jsonl"
    writer = LedgerWriter(shard, "hunt_review.teams")
    foreign = _scope_claim(SYMBOL, pkg="hunt-2")
    stray = _scope_claim(STRAY, pkg="hunt-2", cwe="CWE-78")
    shared_hunt = _scope_claim(OTHER_FILE, pkg="hunt-2", cwe="CWE-22")
    shared_lead = _scope_claim(OTHER_FILE, lane=Lane.LEAD, pkg="finding_lead-2", cwe="CWE-22")
    assert shared_hunt.claim_id == shared_lead.claim_id               # one site, one CWE, one predicate: one claim
    for claim in (foreign, stray, shared_hunt, shared_lead):
        writer.propose_claim(claim)
    for predicate in ALWAYS_REQUIRED:
        body = {"p": predicate.value, "claim": foreign.claim_id}
        writer.add_relation(EvidenceRelation(
            make_id("evidence_relation", 1, body), foreign.claim_id, predicate, RelationKind.SUPPORTS, SYMBOL,
            "source_span", Admissibility.DIRECT, "analysis/default", "0" * 64, "src/request.cpp:28-28", True,
            "cell-" + "7" * 64, "f" * 64))
    writer.seal()
    lanes = [{"proposals": {foreign.claim_id: ["hunt-2"], stray.claim_id: ["hunt-2"],
                            shared_hunt.claim_id: ["finding_lead-2", "hunt-2"]},
              "independence": {foreign.claim_id: [{"verifier_cell_id": "cell-" + "8" * 64, "independent": True,
                                                   "provider_distinct": True, "verifier_model_distinct": False,
                                                   "review_id": "review-1", "gap_ids": []}]},
              "verifier_gaps": {}}]
    entities = {"hunt-2": [OTHER_FILE], "finding_lead-1": [FILE], "finding_lead-2": [OTHER_FILE]}
    merged = stages.merge_claims(lanes, [shard], entities, ["comp-1"],
                                 entity_paths={SYMBOL: "src/request.cpp", STRAY: None},
                                 package_paths={"hunt-2": ["src/other.cpp"], "finding_lead-1": ["src/request.cpp"],
                                                "finding_lead-2": ["src/other.cpp"]})
    assert merged["rehoming"] == {foreign.claim_id: {"from": ["hunt-2"], "to": "finding_lead-1", "entities": [SYMBOL]}}
    assert merged["scope_resolution"][stray.claim_id]["status"] == "outside_review_scope"
    assert merged["scope_resolution"][shared_hunt.claim_id]["status"] == "in_scope"
    projection = project(merge_shards([shard]).events)
    assert projection.claims[shared_hunt.claim_id].claim.lane is Lane.LEAD
    assert projection.claims[shared_hunt.claim_id].duplicate_proposals[Lane.HUNT] == 1
    document = stages.apply_policy(merged, projection, tmp_path / "adj.jsonl", "adjudicate.apply_policy")
    by_claim = {row["claim_id"]: row for row in document["adjudications"]}
    assert by_claim[foreign.claim_id]["state"] == "confirmed" and by_claim[foreign.claim_id]["deciding_row"] == "r5_confirmed"
    assert (by_claim[foreign.claim_id]["rehomed_from"], by_claim[foreign.claim_id]["rehomed_to"]) == (["hunt-2"], "finding_lead-1")
    assert document["rehomed"] == {foreign.claim_id: {"from": ["hunt-2"], "to": "finding_lead-1"}}
    assert by_claim[stray.claim_id]["state"] == "out_of_scope" and by_claim[stray.claim_id]["rehomed_to"] is None
    assert by_claim[shared_hunt.claim_id]["state"] == "insufficient_evidence"      # in place, no evidence
    assert by_claim[shared_hunt.claim_id]["rehomed_to"] is None
    assert document["states"] == {"confirmed": 1, "insufficient_evidence": 1, "out_of_scope": 1}
    assert stages.locate_entity_path(SimpleNamespace(find=lambda **_: {"results": [{"location": {"path": "src/a.c"}}]}),
                                     SYMBOL) == "src/a.c"
    assert stages.locate_entity_path(SimpleNamespace(find=lambda **_: {"results": []}), SYMBOL) is None
