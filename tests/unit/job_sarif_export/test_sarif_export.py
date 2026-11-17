"""Focused unit tests for deterministic SARIF 2.1.0 export (codeFlows, fixes, taxa, radar tags)."""
from __future__ import annotations

from pathlib import Path
import pytest

from appsec_review.jobs.job_sarif_export import (
    JOB_ID,
    SARIF_DOCUMENT_NAME,
    SARIF_RESULT_NAME,
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    build_job,
    export_sarif_bundle,
    validate_sarif_log,
)


def _sample_findings() -> list[dict]:
    return [
        {
            "finding_id": "F-SQLI-001",
            "title": "SQL Injection via Unvalidated Order Filter",
            "description": "User-supplied sort key flows into raw SQL ORDER BY clause.",
            "severity": "critical",
            "cwe": ["CWE-89"],
            "path": "src/orders/repository.py",
            "line": 77,
            "end_line": 79,
            "symbol": "query_orders",
            "taint_path_timeline": [
                {
                    "path": "src/orders/routes.py",
                    "line": 21,
                    "symbol": "get_orders",
                    "role": "source",
                    "taint_transform": "request.args['sort']",
                },
                {
                    "path": "src/orders/validator.py",
                    "line": 39,
                    "symbol": "check_sort",
                    "role": "guard",
                    "guard_status": "bypassed_case_folding",
                },
                {
                    "path": "src/orders/repository.py",
                    "line": 77,
                    "symbol": "query_orders",
                    "role": "sink",
                    "taint_transform": "string concatenation into SQL",
                },
            ],
            "remediation": {
                "validation_status": "in_memory_patch_and_syntax_verified",
                "description": "Map sort parameter through closed column allowlist",
                "unified_diff": (
                    "--- a/src/orders/repository.py\n"
                    "+++ b/src/orders/repository.py\n"
                    "@@ -76,3 +76,4 @@\n"
                    " def query_orders(conn, sort_key):\n"
                    "-    sql = f'SELECT id, total FROM orders ORDER BY {sort_key}'\n"
                    "+    col = ALLOWED_COLUMNS[sort_key]\n"
                    "+    sql = f'SELECT id, total FROM orders ORDER BY {col}'\n"
                    "     return conn.execute(sql)\n"
                ),
            },
        },
        {
            "finding_id": "F-HARD-002",
            "title": "Container Runs as Root UID 0",
            "severity": "medium",
            "cwe": 250,
            "radar_domain": "container_deployment_hardening",
            "path": "Dockerfile",
            "line": 14,
            "remediation": {
                "validation_status": "manual_design_required",
                "unified_diff": "--- a/Dockerfile\n+++ b/Dockerfile\n@@ -14,1 +14,2 @@\n+USER 10001\n CMD [\"app\"]\n",
            },
        },
    ]


def test_sarif_export_codeflows_validated_fixes_taxa_and_determinism(tmp_path: Path) -> None:
    job = build_job()
    assert job.job_id == JOB_ID == "job_sarif_export"
    assert job.strict_gaps is True
    assert job.consumes == ("job_final_publication_gate",)

    findings = _sample_findings()
    first = export_sarif_bundle(findings, run_id="run-001", output_dir=tmp_path / "out1")
    second = export_sarif_bundle(list(reversed(findings)), run_id="run-001", output_dir=tmp_path / "out2")
    assert first.sarif_bytes == second.sarif_bytes
    assert first.sarif_sha256 == second.sarif_sha256
    assert (tmp_path / "out1" / SARIF_DOCUMENT_NAME).read_bytes() == first.sarif_bytes
    assert (tmp_path / "out1" / SARIF_RESULT_NAME).is_file()

    log = first.sarif_log
    assert log["$schema"] == SARIF_SCHEMA_URI
    assert log["version"] == SARIF_VERSION == "2.1.0"
    assert first.result["terminal_status"] == "SUCCEEDED"
    assert first.telemetry["reporting.sarif_results_total"] == 2
    assert first.telemetry["reporting.sarif_codeflows_emitted"] == 1
    assert first.telemetry["reporting.sarif_fixes_emitted"] == 1

    run = log["runs"][0]
    by_id = {r["properties"]["finding_id"]: r for r in run["results"]}

    sqli = by_id["F-SQLI-001"]
    assert sqli["level"] == "error"
    assert sqli["properties"]["radar_domain"]["domain_id"] == "injection_interpreters"
    assert "CWE-89" in sqli["properties"]["cwe"]
    assert any(o.startswith("A05:2025") for o in sqli["properties"]["owasp_2025"])
    assert len(sqli["taxa"]) >= 2

    # Verify codeFlows -> threadFlows
    tfls = sqli["codeFlows"][0]["threadFlows"][0]["locations"]
    assert len(tfls) == 3
    assert [t["kinds"] for t in tfls] == [["acquire"], ["branch"], ["danger"]]
    assert [t["executionOrder"] for t in tfls] == [1, 2, 3]
    assert tfls[0]["location"]["physicalLocation"]["artifactLocation"]["uri"] == "src/orders/routes.py"
    assert tfls[2]["location"]["physicalLocation"]["region"]["startLine"] == 77

    # Verify validated fix emitted on F-SQLI-001, unvalidated fix withheld on F-HARD-002
    assert len(sqli["fixes"]) == 1
    fix_change = sqli["fixes"][0]["artifactChanges"][0]
    assert fix_change["artifactLocation"]["uri"] == "src/orders/repository.py"
    assert fix_change["replacements"][0]["deletedRegion"] == {"startLine": 76, "endLine": 78}
    assert "ALLOWED_COLUMNS" in fix_change["replacements"][0]["insertedContent"]["text"]

    hard = by_id["F-HARD-002"]
    assert "fixes" not in hard
    assert hard["properties"]["radar_domain"]["domain_id"] == "container_deployment_hardening"


def test_sarif_export_records_strict_producer_gaps_and_rejects_invalid_log() -> None:
    bundle = export_sarif_bundle(
        _sample_findings(),
        run_id="run-gaps",
        upstream_gaps=["cpp_compile_db_missing"],
    )
    assert bundle.result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert len(bundle.gaps) == 1
    assert bundle.gaps[0]["schema"] == "appsec-review/producer-gap/1"

    tampered = dict(bundle.sarif_log)
    tampered["version"] = "2.0.0"
    with pytest.raises(ValueError, match="2.1.0"):
        validate_sarif_log(tampered)
