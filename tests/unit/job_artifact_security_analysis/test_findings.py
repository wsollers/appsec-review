"""Unit tests for findings.py: splitters, summary observation drops, and scan_records."""

from __future__ import annotations

import hashlib
import json

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


def _native_scan(tmp_path, capability, payload):
    from appsec_review.jobs.job_artifact_security_analysis import job
    from appsec_review.provenance import validate_observation_provenance
    from appsec_review.storage import atomic_json, file_sha256
    from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner
    from .test_job_graph import _seed_artifact, _unit_context

    ctx, _ = _unit_context(tmp_path / "run", unit_id=f"analyze.{capability}")
    artifact = _seed_artifact(ctx.job.run_root)
    receipt = ctx.job.attempt_root / "artifacts" / "asa" / "execution.json"
    atomic_json(receipt, {"schema": "appsec-review/container-execution/1", "exit_code": 0})

    def execute(*args):
        return {"stdout": b"", "stderr": b"", "exit_code": 0, "payload": payload,
                "execution_receipt": {"path": receipt.relative_to(ctx.job.run_root).as_posix(),
                                      "sha256": file_sha256(receipt)}}

    with publication_scope_for_owner(SharedArtifacts.for_job(ctx.job)):
        scan = job._scan_one(ctx, artifact, capability, execute)
        summary, findings = scan_records(scan)
        validate_observation_provenance(
            ctx.job.run_root, [record.payload for record in (summary, *findings)],
            parser_identity=job.PARSER_IDENTITY)
    retained = ctx.job.run_root / scan["native_output"]["artifact"]["path"]
    assert retained.read_bytes() == payload
    assert scan["native_output"]["artifact"]["sha256"] == hashlib.sha256(payload).hexdigest()
    return scan, summary, findings


def test_native_cve_array_findings_resolve_original_bytes(tmp_path) -> None:
    payload = b'[\n {"cve_number":"CVE-2018-25032","product":"zlib","version":"1.2.11","severity":"HIGH"}\n]'
    scan, summary, findings = _native_scan(tmp_path, "cve_bin_tool", payload)
    assert scan["gaps"] == [] and summary.payload["findings_complete"] is True
    assert len(findings) == 1
    reference = findings[0].payload["common"]["evidence_refs"][0]
    assert reference["selector"] == {"kind": "json_pointer", "value": "/0"}
    assert json.loads(payload)[0]["cve_number"] == findings[0].payload["rule_id"]


@pytest.mark.parametrize(("capability", "payload", "selector"), [
    ("grype", b'{"matches":[{"vulnerability":{"id":"CVE-2018-25032","severity":"High"},'
              b'"artifact":{"name":"zlib","version":"1.2.11"}}]}', "/matches/0"),
    ("osv", b'{"results":[{"packages":[{"package":{"name":"zlib","version":"1.2.11"},'
            b'"vulnerabilities":[{"id":"CVE-2018-25032","database_specific":{"severity":"HIGH"}}]}]}]}',
     "/results/0/packages/0/vulnerabilities/0"),
    ("spotbugs", b'<BugCollection><BugInstance type="SQL_INJECTION" priority="1">'
                 b'<SourceLine classname="pkg.A"/></BugInstance></BugCollection>', None),
], ids=["grype", "osv", "spotbugs"])
def test_native_positive_reports_keep_resolving_finding_selectors(tmp_path, capability, payload, selector):
    scan, summary, findings = _native_scan(tmp_path, capability, payload)
    assert scan["gaps"] == [] and summary.payload["findings_complete"] is True
    assert len(findings) == 1
    actual = findings[0].payload["common"]["evidence_refs"][0]["selector"]
    if selector is not None:
        assert actual == {"kind": "json_pointer", "value": selector}
    else:
        assert actual == {"kind": "xml_ordinal", "value": {"element": "BugInstance", "ordinal": 0}}


@pytest.mark.parametrize(("capability", "payload"), [
    ("cve_bin_tool", b"[]"),
    ("grype", b'{"matches":[], "descriptor":{"name":"grype"}}'),
    ("syft", b'{"artifacts":[], "schema":{"version":"16.0.16"}}'),
    ("osv", b'{"results":[]}'),
    ("spotbugs", b'<BugCollection><Errors errors="0" missingClasses="0"/></BugCollection>'),
    ("blint", b'{"schema":"appsec-review/blint-report/1","findings":[],"reviews":[],'
              b'"analyzed":[{"report":"app-metadata.json","file_path":"/target/app"}]}'),
], ids=["cve", "grype", "syft", "osv", "spotbugs", "blint"])
def test_native_empty_reports_remain_completed(tmp_path, capability, payload) -> None:
    scan, summary, findings = _native_scan(tmp_path, capability, payload)
    assert scan["gaps"] == [] and findings == ()
    assert summary.payload["scan_outcome"] == "completed"
    assert summary.payload["findings_complete"] is (None if capability == "syft" else True)


@pytest.mark.parametrize(("capability", "payload"), [
    ("grype", b'{"matches":"wrong-type","error":"database failed"}'),
    ("grype", b'{"error":"database failed"}'),
    ("grype", b'{"matches":[{"artifact":{"name":"zlib"},"vulnerability":{}}]}'),
    ("grype", b'{"matches":[], "error":"database failed"}'),
    ("syft", b'{"artifacts":{}}'),
    ("syft", b'{"artifacts":[null]}'),
    ("osv", b'{"results":[{"packages":"invalid"}]}'),
    ("osv", b'{"results":[{"packages":[{"vulnerabilities":[{}]}]}]}'),
    ("cve_bin_tool", b'{"error":"database failed"}'),
    ("cve_bin_tool", b'[{"error":"database failed"}]'),
    ("blint", b'{"findings":"invalid","analyzed":[{"report":"app-metadata.json"}]}'),
    ("spotbugs", b'<Error>analysis failed</Error>'),
    ("spotbugs", b'<BugCollection><Errors errors="1"><Error/></Errors></BugCollection>'),
    ("spotbugs", b'<BugCollection><BugInstance/></BugCollection>'),
], ids=["grype-shape", "grype-error", "grype-record", "grype-empty-error",
        "syft-shape", "syft-record", "osv-shape", "osv-record", "cve-root",
        "cve-record", "blint-shape", "xml-root", "xml-errors", "xml-record"])
def test_parseable_invalid_reports_are_not_complete_empty_results(tmp_path, capability, payload) -> None:
    scan, summary, findings = _native_scan(tmp_path, capability, payload)
    assert scan["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("could not be parsed" in gap for gap in scan["gaps"])
    assert findings == ()
    assert summary.payload["scan_outcome"] == "not_completed"
    assert summary.payload["findings_complete"] is not True


@pytest.mark.parametrize(("capability", "payload"), [
    ("grype", b'{"matches":['), ("spotbugs", b"<BugCollection>"),
], ids=["json", "xml"])
def test_malformed_report_bytes_are_retained_as_parse_gaps(tmp_path, capability, payload) -> None:
    scan, summary, findings = _native_scan(tmp_path, capability, payload)
    assert any("could not be parsed" in gap for gap in scan["gaps"])
    assert summary.payload["scan_outcome"] == "not_completed" and findings == ()


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
    for diag in ("native", "blint", "grype", "osv", "spotbugs", "cve_bin_tool"):
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


@pytest.mark.parametrize("capability,observation", [
    ("native", {"security_risks": [{"check_id": "CONTAINER_ROOT", "message": "root user"}]}),
    ("blint", {"findings": [{"id": "CHECK_NX", "title": "NX disabled"}]}),
    ("grype", {"matches": [{"vulnerability": {"id": "CVE-2026-0001"}}]}),
    ("spotbugs", {"findings": [{"type": "SQL_INJECTION"}]}),
])
def test_missing_finding_metadata_remains_visible_with_explicit_gaps(capability, observation) -> None:
    summary, findings = scan_records({
        "capability": capability, "observation": observation,
        "artifact": {"path": "app", "canonical_identity": "asr:artifact:app"},
        "fingerprint": "f" * 64, "tool_identity": {"scanner": capability}, "gaps": [],
    })
    assert len(findings) == 1
    payload = findings[0].payload
    assert payload["severity"] is None
    assert payload["subject"] is None
    assert payload["severity_hint"] == "unknown"
    assert set(payload["gaps"]) == {"severity_missing_or_unrated", "subject_identity_missing"}
    assert payload["common"]["reported_severity"]["value"] == "unknown"
    assert payload["common"]["gap_ids"]
    assert summary.payload["scan_outcome"] == "completed_with_gaps"
    assert summary.payload["finding_count"] == 1
    assert summary.payload["findings_complete"] is False


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
    assert blint_summary.payload["findings_complete"] is False
    assert set(blint_summary.payload["gaps"]) == {"severity_missing_or_unrated", "subject_identity_missing"}
    assert blint_summary.payload["observation"]["review_count_reported"] == 4
    assert [f.payload["occurrence"] for f in blint_findings] == [1, 2, 1]
    assert blint_findings[0].payload["category"] == CATEGORY_BINARY_HARDENING
    assert blint_findings[0].payload["subject"] == "app"
    assert blint_findings[2].payload["subject"] is None

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

    # Grype: skips missing vuln id, formats name@version, and retains absent subjects.
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
    assert [f.payload["subject"] for f in grype_findings] == ["openssl@3.0.0", "zlib", None]
    assert "subject_identity_missing" in grype_findings[2].payload["gaps"]
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


def test_scan_records_turns_cve_bin_tool_version_string_matches_into_advisory_leads() -> None:
    from appsec_review.indexing.links import advisory_pairs

    records = [
        {"vendor": "zlib", "product": "zlib", "version": "1.2.11", "cve_number": "CVE-2018-25032",
         "severity": "HIGH", "score": "7.5", "cvss_version": "3", "cvss_vector": "CVSS:31/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
         "source": "NVD", "paths": "/target/inftrees.c.o, /target/deflate.c.o", "remarks": "NewFound"},
        {"vendor": "zlib", "product": "zlib", "version": "1.2.11", "cve_number": "CVE-2022-37434",
         "severity": "CRITICAL", "paths": "/target/deflate.c.o"},
        {"vendor": "bzip", "product": "bzip2", "cve_number": "CVE-2019-12900", "severity": "CRITICAL"},
        {"vendor": "lz4_project", "product": "lz4", "version": "1.9.1"},
    ]
    summary, found = scan_records({
        "artifact": {"path": "data/build/deflate.c.o", "canonical_identity": "asr:artifact:deflate"},
        "classification": {"format": "elf"}, "fingerprint": "f" * 64, "capability": "cve_bin_tool",
        "scanner_identity": "tool-cve-bin-tool:3.4:adapter-1",
        "tool_identity": {"scanner": "tool-cve-bin-tool", "rules": {"feed": "cve-bin-tool", "snapshot_id": "s"}},
        "gaps": [], "raw_artifacts": [], "attempt_identity": "a" * 64, "exit_code": 1, "timed_out": False,
        "duration_ms": 12, "result_artifact": {"path": "res.json", "sha256": "4" * 64, "size_bytes": 20},
        "native_output": None, "observation": {"records": records, "_native_result_count": 4},
    })
    # The record without a CVE id is not a finding; the version-less bzip2 match keeps its product.
    assert [finding.payload["subject"] for finding in found] == ["zlib@1.2.11", "zlib@1.2.11", "bzip2"]
    first = found[0].payload
    assert first["record_kind"] == RECORD_KIND_FINDING and first["tool_id"] == "tool-cve-bin-tool"
    assert first["category"] == CATEGORY_VULNERABILITY and first["rule_id"] == "CVE-2018-25032"
    assert (first["package_name"], first["package_version"], first["advisory_id"]) == ("zlib", "1.2.11", "CVE-2018-25032")
    assert first["vendor"] == "zlib" and first["checker"] == "zlib" and first["match_basis"] == "version-string"
    assert first["matched_paths"] == ["/target/inftrees.c.o", "/target/deflate.c.o"]
    assert first["severity"] == "HIGH" and first["cvss_score"] == "7.5" and first["data_source"] == "NVD"
    assert "version string matched in inftrees.c.o" in first["message"]
    # The projection dependency_advisories reads (indexing.links.advisory_pairs) names product, version and CVE.
    assert advisory_pairs({"payload": first}) == [{
        "package": "zlib", "version": "1.2.11", "purl": None, "advisory": "CVE-2018-25032",
        "severity": "HIGH", "scanner": "tool-cve-bin-tool:3.4:adapter-1"}]
    assert advisory_pairs({"payload": found[2].payload}) == [{
        "package": "bzip2", "version": None, "purl": None, "advisory": "CVE-2019-12900",
        "severity": "CRITICAL", "scanner": "tool-cve-bin-tool:3.4:adapter-1"}]
    # Distinct identities for the two zlib CVEs; the summary drops the records and keeps the counts.
    assert len({finding.native_id for finding in found}) == 3
    assert summary.payload["category"] == CATEGORY_DIAGNOSTIC and summary.payload["finding_count"] == 3
    assert "records" not in summary.payload["observation"]
    assert summary.payload["observation"]["finding_count_reported"] == 3
    assert summary.payload["observation"]["_native_result_count"] == 4
