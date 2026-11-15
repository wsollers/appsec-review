"""Unit tests for findings.py: splitters, summary observation drops, and scan_records."""

from __future__ import annotations

import pytest

from appsec_review.interchange import ArtifactReference, NativeResultReference, ResultSelector
from appsec_review.jobs.job_artifact_security_analysis import findings as findings_module
from appsec_review.jobs.job_artifact_security_analysis.findings import (
    CATEGORY_BINARY_HARDENING,
    CATEGORY_BYTECODE,
    CATEGORY_DIAGNOSTIC,
    CATEGORY_INVENTORY,
    CATEGORY_VULNERABILITY,
    RECORD_SCHEMA,
    _list,
    _mapping,
    _summary_observation,
    _text,
    scan_outcome,
    scan_records,
    summary_category,
)
from appsec_review.retrieval.observations import RECORD_KIND_FINDING, RECORD_KIND_SUMMARY


def test_primitive_helpers_outcome_and_summary_category() -> None:
    assert _text(None) is None
    assert _text({"a": 1}) is None
    assert _text(["a"]) is None
    assert _text("   ") is None
    assert _text("  hello world  ", bound=5) == "hello"
    assert _mapping({"k": 1}) == {"k": 1}
    assert _mapping("not-map") == {}
    assert _list([1, 2]) == [1, 2]
    assert _list(("not", "list")) == []

    assert scan_outcome({"gaps": [], "observation": {}}) == "completed"
    assert scan_outcome({"gaps": ["g"], "observation": {"ok": 1}}) == "completed_with_gaps"
    assert scan_outcome({"gaps": ["g"], "observation": {}}) == "not_completed"

    for inv in ("inventory", "syft", "packages"):
        assert summary_category(inv) == CATEGORY_INVENTORY
    for diag in ("native", "blint", "grype", "osv", "spotbugs"):
        assert summary_category(diag) == CATEGORY_DIAGNOSTIC

    syft_summary = _summary_observation("syft", {"artifacts": [{"name": "a"}], "extra": 1}, 0, 0)
    assert syft_summary == {"extra": 1, "artifact_count_reported": 1}
    syft_native = _summary_observation(
        "syft", {"artifacts": [{"name": "a"}], "_native_result_count": 9}, 0, 0
    )
    assert syft_native["artifact_count_reported"] == 9
    blint_fallback = _summary_observation("blint", {"findings": [1], "reviews": [1, 2]}, 1, 1)
    assert blint_fallback == {
        "finding_count_reported": 1,
        "finding_records": 1,
        "review_count_reported": 2,
    }


def test_scan_records_splits_blint_spotbugs_grype_osv_and_builtin_summaries(monkeypatch) -> None:
    native_ref = NativeResultReference(
        ArtifactReference("a", "1" * 64, 10),
        ResultSelector("document"),
        "p/1",
        ArtifactReference("e", "3" * 64, 10),
        ArtifactReference("r", "2" * 64, 10),
        True,
    ).as_dict()
    base_scan = {
        "artifact": {"path": "data/build/app", "canonical_identity": "asr:artifact:app"},
        "classification": {"format": "elf"},
        "fingerprint": "f" * 64,
        "scanner_identity": "s/1",
        "tool_identity": {"scanner": "tool-blint"},
        "gaps": [],
        "raw_artifacts": [],
        "attempt_identity": "a" * 64,
        "exit_code": 0,
        "timed_out": False,
        "duration_ms": 12,
        "result_artifact": {"path": "res.json", "sha256": "4" * 64, "size_bytes": 20},
        "native_output": native_ref,
        "native_reports": {"findings.json": native_ref},
    }

    # Built-in inspector: finding_capable=False, no findings
    inv_summary, inv_findings = scan_records(
        {**base_scan, "capability": "inventory", "observation": {"size_bytes": 42}, "native_output": None}
    )
    assert inv_findings == ()
    assert inv_summary.kind == RECORD_KIND_SUMMARY
    assert inv_summary.payload["schema"] == RECORD_SCHEMA
    assert inv_summary.payload["finding_capable"] is False
    assert inv_summary.payload["finding_count"] is None
    assert inv_summary.payload["findings_complete"] is None
    assert len(inv_summary.payload["common"]["gap_ids"]) == 1

    # Blint: skips missing id, handles duplicate check+subject occurrence, uses _native_report
    blint_summary, blint_findings = scan_records(
        {
            **base_scan,
            "capability": "blint",
            "observation": {
                "findings": [
                    "not-a-dict",
                    {"title": "missing id"},
                    {
                        "id": "CHECK_NX",
                        "severity": "critical",
                        "title": "NX disabled",
                        "filename": "/usr/bin/app",
                        "exe_type": "ELF",
                        "_native_report": "findings.json",
                    },
                    {"id": "CHECK_NX", "exe_name": "app"},
                    {"id": "CHECK_PIE"},
                ],
                "reported_counts": {"reviews": 4},
                "reviews": [{"id": "r"}],
            },
        }
    )
    assert blint_summary.payload["finding_count"] == 3
    assert blint_summary.payload["findings_complete"] is True
    assert blint_summary.payload["observation"]["review_count_reported"] == 4
    assert [f.payload["occurrence"] for f in blint_findings] == [1, 2, 1]
    assert blint_findings[0].payload["category"] == CATEGORY_BINARY_HARDENING
    assert blint_findings[0].payload["subject"] == "app"
    assert blint_findings[2].payload["subject"] == "unknown"

    # SpotBugs: priority 1 mapped, unknown priority -> None, source location vs None
    _, sb_findings = scan_records(
        {
            **base_scan,
            "capability": "spotbugs",
            "tool_identity": {"scanner": "tool-spotbugs"},
            "observation": {
                "findings": [
                    {"class": "SkipNoType"},
                    {
                        "type": "SQL_INJECTION",
                        "category": "SECURITY",
                        "priority": "1",
                        "class": "com.example.Dao",
                        "source": "Dao.java",
                        "start": "10",
                        "end": "14",
                    },
                    {"type": "WEAK_HASH", "priority": "99"},
                ]
            },
        }
    )
    assert len(sb_findings) == 2
    assert sb_findings[0].kind == RECORD_KIND_FINDING
    assert sb_findings[0].payload["category"] == CATEGORY_BYTECODE
    assert sb_findings[0].payload["severity"] == "HIGH"
    assert sb_findings[0].payload["native_location"] == {
        "source": "Dao.java",
        "start": "10",
        "end": "14",
    }
    assert sb_findings[1].payload["severity"] is None
    assert "native_location" not in sb_findings[1].payload

    # Grype: skips missing vuln id, formats name@version, name-only, and unknown
    _, grype_findings = scan_records(
        {
            **base_scan,
            "capability": "grype",
            "tool_identity": {"scanner": "tool-grype"},
            "observation": {
                "matches": [
                    {"vulnerability": {}, "artifact": {"name": "skip"}},
                    {
                        "vulnerability": {"id": "CVE-2026-1", "severity": "High"},
                        "artifact": {"name": "openssl", "version": "3.0.0", "purl": "pkg:generic/openssl@3.0.0"},
                    },
                    {"vulnerability": {"id": "CVE-2026-2"}, "artifact": {"name": "zlib"}},
                    {"vulnerability": {"id": "CVE-2026-3"}, "artifact": {}},
                ]
            },
        }
    )
    assert [f.payload["subject"] for f in grype_findings] == ["openssl@3.0.0", "zlib", "unknown"]
    assert grype_findings[0].payload["category"] == CATEGORY_VULNERABILITY
    assert grype_findings[0].payload["observation"]["matches"][0]["vulnerability"]["id"] == "CVE-2026-1"

    # OSV: nested results/packages/vulnerabilities, aliases + cvss_vectors caps, FINDING_BOUND truncation
    monkeypatch.setattr(findings_module, "FINDING_BOUND", 2)
    osv_summary, osv_findings = scan_records(
        {
            **base_scan,
            "capability": "osv",
            "tool_identity": {"scanner": "tool-osv-scanner"},
            "observation": {
                "results": [
                    {
                        "packages": [
                            {
                                "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
                                "vulnerabilities": [
                                    {"summary": "missing id"},
                                    {
                                        "id": "GHSA-1",
                                        "summary": "Prototype pollution",
                                        "database_specific": {"severity": "HIGH"},
                                        "aliases": [f"CVE-2026-{i}" for i in range(20)],
                                        "severity": [{"score": f"CVSS:3.1/{i}"} for i in range(6)],
                                    },
                                    {"id": "GHSA-2"},
                                ],
                            },
                            {
                                "package": {},
                                "vulnerabilities": [{"id": "GHSA-3"}],
                            },
                        ]
                    }
                ]
            },
        }
    )
    assert len(osv_findings) == 2
    assert len(osv_findings[0].payload["aliases"]) == 16
    assert len(osv_findings[0].payload["cvss_vectors"]) == 4
    assert osv_findings[1].payload["message"] == "GHSA-2 affects lodash@4.17.20"
    assert osv_summary.payload["scan_outcome"] == "completed_with_gaps"
    assert osv_summary.payload["findings_complete"] is False
    assert any("reported 3 findings; only the first 2 are recorded" in g for g in osv_summary.payload["gaps"])
