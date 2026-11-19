"""Focused T-174 unit tests for risk-first remediation ordering, priority-ranking schema, and 9-language source paths."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

from jsonschema import Draft202012Validator
import pytest
from referencing import Registry, Resource

from appsec_review.jobs.accepted_review import project_finding, project_score
from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.jobs.job_poc_generation import detect_poc_language
from appsec_review.jobs.job_remediation_planning import (
    PRIORITY_RANKING_SCHEMA,
    build_job,
    build_priority_ranking_record,
    rank_findings_risk_first,
)
from appsec_review.jobs.job_remediation_planning.inputs import confirmed_findings
from appsec_review.jobs.job_remediation_planning.patches import unsafe_build_changes
from appsec_review.review.models import ClaimState
from appsec_review.review.ship_block import ShipBlockInputs, decide
from tests import remediation_support as support
from tests.unit.job_remediation_planning.test_coverage_edges import _ctx, _seed_planning

ROOT = Path(__file__).resolve().parents[3]


def _priority_schema_validator() -> Draft202012Validator:
    schema_dir = ROOT / "docs" / "schemas" / "remediation-planning"
    docs = {p.name: json.loads(p.read_text(encoding="utf-8")) for p in sorted(schema_dir.glob("*.schema.json"))}
    registry = Registry().with_resources((doc["$id"], Resource.from_contents(doc)) for doc in docs.values())
    return Draft202012Validator(docs["priority-ranking.schema.json"], registry=registry)


def _accepted_finding(finding_id: str, severity: str | None, *, seed: dict | None = None,
                      chains: tuple[str, ...] = (), scores: tuple[dict, ...] = ()) -> dict:
    seed = seed or {"finding_package_id": finding_id, "claim_id": f"claim-{finding_id}",
                    "adjudication_id": f"adj-{finding_id}", "state": "confirmed",
                    "title": finding_id, "direct_evidence": []}
    inputs = ShipBlockInputs(
        claim_state=ClaimState.CONFIRMED, technical_severity=severity, severity_score_id="score-matrix",
        lead_families=(), kev_listed=None, verifier_model_distinct=True,
        severity_missing_factors=("impact_class",) if severity is None else (),
        severity_floor="low" if severity is None else severity,
        severity_ceiling="critical" if severity is None else severity,
    )
    block = decide(inputs).record(inputs, adjudication_id=seed["adjudication_id"],
                                  verification_review_id="verification-1", displayed_context={})
    package = {**seed, "lane": "lead", "label": "confirmed", "ship_block": block,
               "independence": {}, "judge_verdict": None, "verification_review_id": "verification-1",
               "analyst_assessed_evidence": [], "missing_predicates": [], "gaps": [], "poc": None,
               "attack_chains": list(chains)}
    return project_finding({"path": f"data/{finding_id}.json", "sha256": seed.get("sha256", "a" * 64)},
                           package, scores)


def _confirmed_review(findings: list[dict]) -> dict:
    return {"partition": {"confirmed": [item["finding_package_id"] for item in findings]},
            "packages": findings}


@pytest.mark.parametrize("reverse", [False, True], ids=["low-first", "critical-first"])
def test_accepted_critical_gets_only_proposal_slot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                 reverse: bool) -> None:
    """RMP-01: exercise the real accepted projection through all three planning units."""
    env = _seed_planning(tmp_path, monkeypatch, candidate_count=2)
    findings = [_accepted_finding(seed["finding_package_id"], severity, seed=seed)
                for seed, severity in zip(env.review_doc["packages"], ("low", "critical"), strict=True)]
    env.review_doc["packages"] = list(reversed(findings)) if reverse else findings
    writer = support.Writer()
    job = build_job(infer=writer, builds_factory=lambda _: env.builds,
                    core_factory=lambda *_: env.core, repository_root=support.ROOT)
    result = job.execute(_ctx(env.root, support.planning_settings(max_candidates=1)))
    assert not result["failed_units"], result
    summary = read_bound_json(env.root, result["outputs"]["acceptance.publish_handoff"]["artifact"])
    assert [(row["finding"]["finding_package_id"], row["status"]) for row in summary["items"]] == [
        ("finding-2", "proposal_generated"), ("finding-1", "capped")]
    assert len(writer.requests) == 1
    loaded = read_bound_json(env.root, result["outputs"]["load.verify_inputs"]["artifact"])
    assert loaded["candidates"] == [findings[1], findings[0]]
    ranking = read_bound_json(env.root, loaded["priority_ranking"])
    assert [(item["severity"], item["selected"]) for item in ranking["items"]] == [
        ("critical", True), ("low", False)]
    assert all(item["reachable"] is None for item in ranking["items"])
    _priority_schema_validator().validate(ranking)


def test_accepted_chain_membership_is_priority_context_not_composed_severity_or_reachability() -> None:
    findings = [
        _accepted_finding("finding-a", "low"),
        _accepted_finding("finding-b", "medium"),
        _accepted_finding("finding-c", "low", chains=("chain-1",)),
        _accepted_finding("finding-d", "medium", chains=("chain-1",)),
        _accepted_finding("finding-y", "high"),
        _accepted_finding("finding-z", "critical"),
    ]
    ranked = confirmed_findings(_confirmed_review(findings))
    assert [item["finding_package_id"] for item in ranked] == [
        "finding-z", "finding-y", "finding-c", "finding-d", "finding-b", "finding-a"]
    ranking = build_priority_ranking_record(ranked, max_candidates=4)
    assert [item["severity"] for item in ranking["items"]] == ["critical", "high", "low", "medium",
                                                              "medium", "low"]
    assert [item["chain_elevated"] for item in ranking["items"]] == [False, False, True, True, False, False]
    assert all(item["composed_severity"] is None and item["reachable"] is None for item in ranking["items"])
    _priority_schema_validator().validate(ranking)


def test_accepted_ties_do_not_combine_independent_score_dimensions() -> None:
    score = project_score({"sha256": "b" * 64}, {
        "score_id": "score-matrix",
        "provider": {"id": "application_risk_matrix", "interface": "appsec-review/scoring-provider/1",
                     "implementation": "application_risk_matrix/3"},
        "technical_severity": {"scale": "application_risk_matrix/3", "rating": "medium", "value": None},
        "exploitability_confidence": {"scale": "exploitability_evidence/1", "rating": "high", "value": 150},
        "environmental_business_impact": {"scale": "environmental_exposure/1", "rating": "high", "value": 85},
        "remediation_priority": None,
        "severity_assessment": {"assessment": "complete", "severity_floor": "medium",
                                "severity_ceiling": "medium", "unresolved_factors": []},
    })
    findings = [_accepted_finding("finding-z", "medium", scores=(score,)),
                _accepted_finding("finding-a", "medium"), _accepted_finding("finding-m", "medium")]
    before = deepcopy(findings)
    for ordered in (findings, list(reversed(findings)), findings[1:] + findings[:1]):
        ranked = confirmed_findings(_confirmed_review(ordered))
        assert [item["finding_package_id"] for item in ranked] == ["finding-a", "finding-m", "finding-z"]
        record = build_priority_ranking_record(ranked, max_candidates=1)
        assert [item["selected"] for item in record["items"]] == [True, False, False]
        assert all(item["score"] == 0.0 and item["reachable"] is None for item in record["items"])
        _priority_schema_validator().validate(record)
    assert findings == before


@pytest.mark.parametrize("rating", [None, "", "unrated", "unrecognized"])
def test_accepted_unrated_severity_keeps_bounds_without_inventing_a_rating(rating: str | None) -> None:
    finding = _accepted_finding("finding-a", None)
    finding["ship_block"]["technical_severity"] = rating
    known = _accepted_finding("finding-z", "low")
    ranked = confirmed_findings(_confirmed_review([finding, known]))
    assert ranked == [known, finding]
    record = build_priority_ranking_record(ranked, max_candidates=1)
    item = record["items"][1]
    assert item["severity"] == "unknown"
    assert item["reachable"] is None
    assert item["gaps"] == ["severity_missing_or_unrated", "reachability_not_established"]
    assert finding["ship_block"]["technical_severity_floor"] == "low"
    assert finding["ship_block"]["technical_severity_ceiling"] == "critical"
    assert finding["ship_block"]["missing_factors"] == ["impact_class"]
    _priority_schema_validator().validate(record)


def test_risk_first_ordering_beats_alphabetical_finding_id_truncation() -> None:
    f_low = "finding-" + "1" * 64
    f_med_unreach = "finding-" + "2" * 64
    f_crit = "finding-" + "9" * 64
    f_chain = "finding-" + "8" * 64
    f_high = "finding-" + "7" * 64
    f_med_reach = "finding-" + "6" * 64

    findings = [
        {
            "finding_package_id": f_low,
            "claim_id": "claim-" + "1" * 64,
            "severity": "low",
            "composed_severity": None,
            "reachable": True,
            "score": 2.5,
        },
        {
            "finding_package_id": f_med_unreach,
            "claim_id": "claim-" + "2" * 64,
            "severity": "medium",
            "composed_severity": None,
            "reachable": False,
            "score": 5.5,
        },
        {
            "finding_package_id": f_crit,
            "claim_id": "claim-" + "9" * 64,
            "severity": "critical",
            "composed_severity": None,
            "reachable": True,
            "score": 9.8,
        },
        {
            "finding_package_id": f_chain,
            "claim_id": "claim-" + "8" * 64,
            "severity": "medium",
            "composed_severity": "high",
            "attack_chain_ids": ["chain-" + "a" * 64],
            "reachable": True,
            "score": 6.4,
        },
        {
            "finding_package_id": f_high,
            "claim_id": "claim-" + "7" * 64,
            "severity": "high",
            "composed_severity": None,
            "reachable": True,
            "score": 8.1,
        },
        {
            "finding_package_id": f_med_reach,
            "claim_id": "claim-" + "6" * 64,
            "severity": "medium",
            "composed_severity": None,
            "reachable": True,
            "score": 6.0,
        },
    ]

    ranked = rank_findings_risk_first(findings)
    ordered_ids = [item["finding_package_id"] for item in ranked]
    assert ordered_ids == [f_crit, f_high, f_chain, f_med_reach, f_med_unreach, f_low]

    record = build_priority_ranking_record(ranked, max_candidates=3)
    assert record["schema"] == PRIORITY_RANKING_SCHEMA
    assert record["total_confirmed"] == 6
    assert record["selected_count"] == 3
    assert record["capped_count"] == 3
    selected_ids = [entry["finding_package_id"] for entry in record["items"] if entry["selected"]]
    assert selected_ids == [f_crit, f_high, f_chain]
    _priority_schema_validator().validate(record)


def test_nine_language_source_paths_accepted_and_build_scripts_blocked() -> None:
    expected_langs = {
        "src/parser.cpp": "cpp",
        "include/parser.hpp": "cpp",
        "src/main/java/App.java": "java",
        "src/handler.ts": "javascript",
        "app/auth.py": "python",
        "app/controllers/users_controller.rb": "ruby",
        "internal/http/router.go": "go",
        "Controllers/AuthController.cs": "csharp",
        "src/lib.rs": "rust",
        "src/Controller/LoginController.php": "php",
    }
    for valid_src, lang in expected_langs.items():
        assert detect_poc_language(valid_src) == lang
    assert unsafe_build_changes(SimpleNamespace(paths=list(expected_langs))) == []

    for blocked in (
        "CMakeLists.txt",
        "Makefile",
        "pom.xml",
        "build.gradle.kts",
        "Cargo.toml",
        "package.json",
        "Gemfile",
        "composer.json",
        "App.csproj",
        "Directory.Build.props",
    ):
        assert unsafe_build_changes(SimpleNamespace(paths=[blocked])) == [blocked]


@pytest.mark.parametrize("extra", [
    {"entry_points": ["route-1"]},
    {"poc": {"status": "compile_verified"}},
    {"direct_evidence": ["source-line-1"]},
    {"reachability": "unknown"},
    {"exploitability": "none"},
])
def test_context_and_poc_presence_do_not_confirm_reachability(extra: dict) -> None:
    unknown = {"finding_package_id": "finding-a", "claim_id": "claim-a", "severity": "medium", **extra}
    reachable = {"finding_package_id": "finding-z", "claim_id": "claim-z",
                 "severity": "medium", "reachable": True}
    ranked = rank_findings_risk_first([unknown, reachable])
    assert ranked == [reachable, unknown]
    record = build_priority_ranking_record(ranked, max_candidates=1)
    assert record["items"][0]["reachable"] is True
    assert record["items"][1]["reachable"] is None
    assert record["items"][1]["gaps"] == ["reachability_not_established"]
    _priority_schema_validator().validate(record)


@pytest.mark.parametrize("severity", [None, "", "not-rated", 7])
def test_missing_or_unrated_severity_is_not_informational(severity) -> None:
    finding = {"finding_package_id": "finding-a", "claim_id": "claim-a", "severity": severity}
    informational = {"finding_package_id": "finding-z", "claim_id": "claim-z", "severity": "informational"}
    ranked = rank_findings_risk_first([finding, informational])
    assert ranked == [informational, finding]
    record = build_priority_ranking_record(ranked, max_candidates=2)
    assert record["items"][1]["severity"] == "unknown"
    assert "severity_missing_or_unrated" in record["items"][1]["gaps"]
    _priority_schema_validator().validate(record)


def test_explicit_negative_reachability_and_absent_identity_are_preserved() -> None:
    record = build_priority_ranking_record([{"reachable": False, "poc": {"status": "compile_verified"}}],
                                         max_candidates=1)
    item = record["items"][0]
    assert item["reachable"] is False
    assert item["finding_package_id"] is None
    assert item["claim_id"] is None
    assert item["gaps"] == ["severity_missing_or_unrated", "finding_identity_missing", "claim_identity_missing"]
    _priority_schema_validator().validate(record)
