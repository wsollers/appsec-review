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
