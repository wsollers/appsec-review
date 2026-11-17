"""Focused T-174 unit tests for risk-first remediation ordering, priority-ranking schema, and 9-language source paths."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from appsec_review.jobs.job_poc_generation import detect_poc_language
from appsec_review.jobs.job_remediation_planning import (
    PRIORITY_RANKING_SCHEMA,
    build_priority_ranking_record,
    rank_findings_risk_first,
)
from appsec_review.jobs.job_remediation_planning.patches import unsafe_build_changes

ROOT = Path(__file__).resolve().parents[3]


def _priority_schema_validator() -> Draft202012Validator:
    schema_dir = ROOT / "docs" / "schemas" / "remediation-planning"
    docs = {p.name: json.loads(p.read_text(encoding="utf-8")) for p in sorted(schema_dir.glob("*.schema.json"))}
    registry = Registry().with_resources((doc["$id"], Resource.from_contents(doc)) for doc in docs.values())
    return Draft202012Validator(docs["priority-ranking.schema.json"], registry=registry)


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
