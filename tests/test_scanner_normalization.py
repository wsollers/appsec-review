"""Scanner observations normalize per finding, at their true severity and under their true category.

Covers the two defects of docs/reviews/lead-coverage-audit.md: artifact-scanner records were per-scan-run records
admitted as leads at ``unknown`` (blint's nested CHECK_NX/CHECK_PIE severities collapsed, syft inventories were
leads), and the shellcheck, psalm, hadolint, zizmor and gitleaks parsers emitted the generic ``static_analysis``
category, which classifies as ``other`` and fell out of scanner correlation.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import json
from typing import Any

import pytest

from appsec_review.indexing.products_base import Row
from appsec_review.indexing.sast import SUPPRESSION_TRACKED_SCANNERS, build_scanner_correlation
from appsec_review.jobs.job_artifact_security_analysis import findings as artifact_findings
from appsec_review.jobs.job_artifact_security_analysis.findings import (
    FINDING_BOUND, MESSAGE_BOUND, scan_records,
)
from appsec_review.jobs.job_evidence_collection.adapters import adapter_registry
from appsec_review.retrieval.model import EntityKind, LogicalIdentity
from appsec_review.retrieval.observations import (
    OBSERVATION_CLASSES, RECORD_KIND_FINDING, RECORD_KIND_SUMMARY, classify, scanner_of,
)
from appsec_review.review.lead_families import (
    FAMILY_RULES, NOT_A_LEAD_CLASSES, non_lead_key, observation_family, severity_for,
)
from appsec_review.review.scope import PRODUCERS

ARTIFACT = {"path": "build/diag.cpp.o", "workspace_path": "build/diag.cpp.o", "sha256": "a" * 64, "size_bytes": 10,
            "kind": "object", "build_unit_id": "unit-1",
            "canonical_identity": "asr:object_file:" + "1" * 64}
OTHER_ARTIFACT = {**ARTIFACT, "sha256": "b" * 64, "canonical_identity": "asr:object_file:" + "2" * 64}
ARTIFACT_SHARD = {"name": "observations", "shard_id": "artifact-security",
                  "producer": {"job": "job_artifact_security_analysis"}}


def _blint(*checks: tuple[str, str], filename: str = "/target/diag.cpp.o") -> dict[str, Any]:
    return {"schema": "appsec-review/blint-report/1", "finding_count": len(checks), "reviews": [],
            "analyzed": [{"report": "diag.cpp.o-metadata.json", "has_nx": False}], "analyzed_count": 1,
            "findings": [{"id": check, "severity": severity, "title": f"{check} title", "filename": filename,
                          "exe_name": filename, "exe_type": ""} for check, severity in checks]}


def _scan(capability: str, observation: Mapping[str, Any], *, artifact=ARTIFACT, gaps=(), fingerprint="f" * 64
          ) -> dict[str, Any]:
    return {"capability": capability, "artifact": dict(artifact), "classification": {"format": "elf"},
            "scanner_identity": f"tool-{capability}:1:adapter-2:abc", "tool_identity": {"scanner": capability},
            "observation": dict(observation), "gaps": list(gaps), "raw_artifacts": [], "attempt_identity": "x",
            "exit_code": 0, "timed_out": False, "duration_ms": 1, "fingerprint": fingerprint}


def _row(record, identity: str | None = None) -> dict[str, Any]:
    derived = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, "snapshot", record.identity_key).value
    return {"identity": identity or derived, "name": record.name, "payload": dict(record.payload), "location": None}


# ------------------------------------------------------------------------------ per-finding artifact records


def test_a_blint_scan_splits_into_one_summary_and_one_finding_per_check_at_its_own_severity() -> None:
    scan = _scan("blint", _blint(("CHECK_NX", "critical"), ("CHECK_PIE", "high"), ("CHECK_PAC", "info")))
    summary, found = scan_records(scan)
    assert summary.kind == RECORD_KIND_SUMMARY and [item.kind for item in found] == [RECORD_KIND_FINDING] * 3
    reported = {}
    for record in found:
        row = _row(record)
        assert observation_family(row, ARTIFACT_SHARD) == "artifact_scanner"
        reported[record.payload["native_rule_id"]] = severity_for("artifact_scanner", record.payload)
    assert reported == {"CHECK_NX": ("critical", "critical", "native-label"),
                        "CHECK_PIE": ("high", "high", "native-label"),
                        "CHECK_PAC": ("info", "info", "native-label")}
    first = found[0].payload
    assert (first["category"], first["tool_id"], first["subject"], first["message"]) == (
        "binary_hardening", "tool-blint", "diag.cpp.o", "CHECK_NX title")
    assert first["subject_artifact"] == ARTIFACT["canonical_identity"] and first["artifact"]["sha256"] == "a" * 64
    assert "location" not in first and "observation" not in first       # a finding has no source line of its own


def test_finding_identities_are_stable_unique_and_bind_scan_artifact_and_check() -> None:
    def identities(scan):
        _, found = scan_records(scan)
        return [LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, "snapshot", item.identity_key).value
                for item in found]
    scan = _scan("blint", _blint(("CHECK_NX", "critical"), ("CHECK_PIE", "high"), ("CHECK_NX", "critical")))
    ids = identities(scan)
    assert ids == identities(scan) and len(set(ids)) == 3          # stable; a repeated check gets its own ordinal
    assert [item.payload["occurrence"] for item in scan_records(scan)[1]] == [1, 1, 2]
    assert not set(ids) & set(identities(_scan("blint", scan["observation"], fingerprint="e" * 64)))
    assert not set(ids) & set(identities(_scan("blint", scan["observation"], artifact=OTHER_ARTIFACT)))
    summary, _ = scan_records(scan)
    assert LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, "snapshot", summary.identity_key).value not in ids


def test_a_zero_finding_scan_is_accounted_and_differs_from_a_scan_that_did_not_complete() -> None:
    clean, found = scan_records(_scan("blint", _blint()))
    assert found == () and clean.payload["scan_outcome"] == "completed"
    assert (clean.payload["finding_count"], clean.payload["findings_complete"]) == (0, True)
    failed, none = scan_records(_scan("blint", {}, gaps=["blint scanner exited 2"]))
    assert none == () and failed.payload["scan_outcome"] == "not_completed"
    assert (failed.payload["finding_count"], failed.payload["findings_complete"]) == (0, False)
    unanalyzed, _ = scan_records(_scan("blint", {**_blint(), "analyzed": []},
                                       gaps=["blint produced no per-binary analysis report for this artifact"]))
    assert unanalyzed.payload["scan_outcome"] == "completed_with_gaps" and not unanalyzed.payload["findings_complete"]
    assert "blint produced no per-binary analysis report" in unanalyzed.payload["gaps"][0]


def test_summaries_are_non_leads_of_class_inventory_or_diagnostic_and_are_counted() -> None:
    expected = {"syft": "inventory", "inventory": "inventory", "packages": "inventory", "blint": "diagnostic",
                "native": "diagnostic", "jvm": "diagnostic", "wasm": "diagnostic", "grype": "diagnostic",
                "osv": "diagnostic", "spotbugs": "diagnostic"}
    for capability, observation_class in expected.items():
        summary, found = scan_records(_scan(capability, {"packages": [{"name": "x"}]} if capability == "syft" else {}))
        row = _row(summary)
        assert found == () and classify(row["payload"]) == observation_class
        assert observation_family(row, ARTIFACT_SHARD) is None
        assert non_lead_key(row, ARTIFACT_SHARD) == f"class:{observation_class}"
    assert {"inventory", "diagnostic"} <= set(NOT_A_LEAD_CLASSES)


def test_the_builtin_inspectors_and_inventory_report_no_findings_only_a_summary() -> None:
    summary, found = scan_records(_scan("native", {"binary_format": "ELF", "hardening": "requires-pinned-scanner"},
                                        gaps=["native symbols/imports/exports/loader and hardening require a "
                                              "pinned scanner"]))
    assert found == () and summary.payload["finding_capable"] is False and summary.payload["finding_count"] is None
    assert summary.payload["observation"]["binary_format"] == "ELF"      # the facts stay queryable on the summary
    assert summary.payload["scan_outcome"] == "completed_with_gaps"


def test_a_legacy_or_unknown_artifact_record_is_an_unmapped_gap_never_a_lead() -> None:
    legacy = {"identity": "x", "name": "blint", "location": None,
              "payload": {"capability": "blint", "scanner_identity": "tool-blint:3.4.0:adapter-2:e28",
                          "observation": _blint(("CHECK_NX", "critical"))}}
    assert observation_family(legacy, ARTIFACT_SHARD) is None
    assert non_lead_key(legacy, ARTIFACT_SHARD) is None                  # collect_leads reports unmapped_observations
    assert PRODUCERS["artifact_scanner"](ARTIFACT_SHARD)


def test_spotbugs_priority_maps_through_the_existing_scanner_label_rule() -> None:
    scan = _scan("spotbugs", {"findings": [
        {"type": "SQL_INJECTION", "category": "SECURITY", "priority": "1", "class": "a.B", "source": "B.java",
         "start": "9", "end": "9"},
        {"type": "DM_DEFAULT_ENCODING", "category": "I18N", "priority": "3", "class": "a.C"}]})
    _, found = scan_records(scan)
    assert [severity_for("artifact_scanner", item.payload)[0] for item in found] == ["high", "low"]
    assert found[0].payload["native_priority"] == "1" and found[0].payload["category"] == "bytecode_analysis"
    assert found[0].payload["native_location"] == {"source": "B.java", "start": "9", "end": "9"}
    assert "native_location" not in found[1].payload and "location" not in found[0].payload


def test_grype_and_osv_findings_are_dependency_advisory_leads_per_match() -> None:
    match = {"vulnerability": {"id": "CVE-2024-1", "severity": "High"},
             "artifact": {"name": "openssl", "version": "3.0.1", "purl": "pkg:deb/openssl@3.0.1"}}
    other = {"vulnerability": {"id": "CVE-2024-2", "severity": "Negligible"}, "artifact": {"name": "zlib"}}
    summary, found = scan_records(_scan("grype", {"matches": [match, other]}))
    assert len(found) == 2 and "matches" not in summary.payload["observation"]
    assert summary.payload["observation"]["finding_records"] == 2
    row = _row(found[0])
    assert observation_family(row, ARTIFACT_SHARD) == "dependency_advisory"
    assert severity_for("dependency_advisory", row["payload"])[0] == "high"
    assert severity_for("dependency_advisory", found[1].payload)[0] == "unknown"      # not in the severity vocabulary
    assert row["payload"]["observation"] == {"matches": [match]}     # indexing.links.advisory_pairs reads this match
    osv = {"results": [{"packages": [{"package": {"name": "lodash", "version": "4.0.0", "ecosystem": "npm"},
                                      "vulnerabilities": [{"id": "GHSA-x", "summary": "Prototype pollution",
                                                           "database_specific": {"severity": "MODERATE"},
                                                           "aliases": ["CVE-2020-1"]}]}]}]}
    _, [advisory] = scan_records(_scan("osv", osv))
    assert severity_for("dependency_advisory", advisory.payload)[0] == "medium"
    assert advisory.payload["package_name"] == "lodash" and "package" not in advisory.payload    # no name-only pair
    assert observation_family(_row(advisory), ARTIFACT_SHARD) == "dependency_advisory"


def test_finding_messages_and_counts_are_bounded() -> None:
    long = {**_blint(("CHECK_NX", "critical"))}
    long["findings"][0]["title"] = "x" * 5_000
    [record] = scan_records(_scan("blint", long))[1]
    assert len(record.payload["message"]) == MESSAGE_BOUND
    many = _blint(*[(f"CHECK_{index}", "info") for index in range(FINDING_BOUND + 3)])
    summary, found = scan_records(_scan("blint", many))
    assert len(found) == FINDING_BOUND and summary.payload["findings_complete"] is False
    assert any(str(FINDING_BOUND) in gap for gap in summary.payload["gaps"])
    assert artifact_findings.RECORD_SCHEMA == "appsec-review/artifact-security-record/2"


def test_the_lead_rule_versions_record_the_change() -> None:
    assert FAMILY_RULES["artifact_scanner"] == "appsec-review/lead-family/artifact_scanner/3"
    assert FAMILY_RULES["source_sast"] == "appsec-review/lead-family/source_sast/3"


# ------------------------------------------------------------------------------------------ true categories

PARSER_SAMPLES = {
    "tool-gitleaks": (b'[{"RuleID":"generic-api-key","Description":"d","File":"src/a.cpp","StartLine":2,'
                      b'"EndLine":2}]', "secret_detection", "secret", "secret"),
    "tool-shellcheck": (b'{"comments":[{"file":"a.sh","line":3,"level":"warning","code":2086,"message":"q"}]}',
                        "shell_lint", "source_sast", "source_sast"),
    "tool-psalm": (b'[{"severity":"error","type":"TaintedSql","message":"m","file_name":"a.php","line_from":4}]',
                   "source_sast", "source_sast", "source_sast"),
    "tool-hadolint": (b'[{"file":"Dockerfile","line":2,"code":"DL3008","level":"warning","message":"pin"}]',
                      "config_lint", "configuration", "config_scanner"),
    "tool-zizmor": (b'[{"id":"template-injection","path":".github/workflows/a.yml","line":9,"severity":"high",'
                    b'"message":"m"}]', "ci_security", "configuration", None),
}


@pytest.mark.parametrize("tool", sorted(PARSER_SAMPLES))
def test_parsers_emit_their_true_category_and_it_decides_class_and_family(tool) -> None:
    payload, category, observation_class, family = PARSER_SAMPLES[tool]
    [record] = adapter_registry()[tool].parse(payload)
    assert record["category"] == category != "static_analysis"
    row = {"identity": "asr:tool_observation:" + "0" * 64, "name": "n", "payload": {"tool_id": tool, **record},
           "location": None}
    assert classify(row["payload"]) == observation_class
    shard = {"name": "observations", "shard_id": tool, "producer": {"job": "job_evidence_collection", "producer": tool}}
    assert observation_family(row, shard) == family
    assert scanner_of(row["payload"]) == tool


def test_a_scanner_cannot_choose_its_own_category() -> None:
    [record] = adapter_registry()["tool-gitleaks"].parse(
        b'[{"RuleID":"r","File":"a","StartLine":1,"category":"tool_diagnostic"}]')
    assert record["category"] == "secret_detection"
    [record] = adapter_registry()["tool-shellcheck"].parse(
        b'{"comments":[{"file":"a.sh","line":1,"code":1,"category":"software_inventory"}]}')
    assert record["category"] == "shell_lint"


def test_no_parser_emits_the_retired_generic_category() -> None:
    for tool, (payload, *_rest) in PARSER_SAMPLES.items():
        assert all(item["category"] != "static_analysis" for item in adapter_registry()[tool].parse(payload))


# Parser identities that the category change retires (sha256 of the parser source before this change). A reused
# evidence-collection scan keyed on one of these would carry the generic category.
RETIRED_PARSER_IDENTITIES = {
    "84685e6bb998b66a145c08c4cf3437275842fb7c18da51751f7eea4bf2047aa5",    # _list_parser: gitleaks, psalm, hadolint, zizmor
    "3a45f8132e35e5bb2288b85ca47bc6985577ac023f7ea6695c378369bcbc50c0",    # _shellcheck_parser
}


def test_parser_identities_are_bumped_and_distinct_per_scanner() -> None:
    registry = adapter_registry()
    changed = {tool: registry[tool].parser_identity for tool in PARSER_SAMPLES}
    assert not set(changed.values()) & RETIRED_PARSER_IDENTITIES
    assert len(set(changed.values())) == len(changed), "each scanner has its own parser identity"
    adapters = {tool: registry[tool].adapter_identity for tool in PARSER_SAMPLES}
    assert len(set(adapters.values())) == len(adapters)


# ------------------------------------------------------ correlation keyed by the new categories (indexing/sast)


@dataclass
class _Shards:
    rows: list[Row]
    snapshot: str = "snapshot"
    shard: Mapping[str, Any] = field(default_factory=lambda: {"name": "observations", "shard_id": "s", "sha256": "c" * 64})

    def select(self, index: str, **_: Any):
        return (self.shard,) if index == "observations" else ()

    def coverage(self, _shards):
        return []

    def entities(self, shards, kinds=()):
        return iter(self.rows if tuple(kinds) == ("tool_observation",) and self.shard in tuple(shards) else ())


def _obs(number: int, tool: str, category: str, rule: str, line: int, severity: str = "WARNING") -> Row:
    location = {"path": "src/a.sh", "file_sha256": "d" * 64, "start_byte": 0, "end_byte": 1, "start_line": line,
                "end_line": line, "start_column": 1, "end_column": 2, "mapping_method": "exact", "confidence": 1.0,
                "ambiguous": False}
    return Row("observations", "s", "c" * 64, f"asr:tool_observation:{number:064d}", "tool_observation", str(number),
               rule, {"tool_id": tool, "category": category, "native_rule_id": rule, "severity": severity},
               location)


def test_scanner_correlation_includes_scanners_by_class_and_reports_untracked_suppression_as_unknown() -> None:
    rows = [_obs(1, "tool-shellcheck", "shell_lint", "SC2086", 3), _obs(2, "tool-shellcheck", "shell_lint", "SC2086", 3),
            _obs(3, "tool-psalm", "source_sast", "TaintedSql", 4, "ERROR"),
            _obs(4, "tool-semgrep", "source_sast", "r.x", 5, "HIGH"),
            _obs(5, "tool-hadolint", "config_lint", "DL3008", 2), _obs(6, "tool-gitleaks", "secret_detection", "k", 1),
            _obs(7, "tool-zizmor", "ci_security", "z", 1),
            _obs(8, "tool-shellcheck", "static_analysis", "SC1", 9)]       # the retired generic category
    syntax = {"files": {"src/a.sh": {"component_id": "c1", "language": "sh", "suppression_count": 1,
                                       "suppressions": [{"tool": "psalm", "scope": "declaration", "start_line": 4,
                                                         "signal_id": "s1"}]}}}
    product = build_scanner_correlation(_Shards(rows), syntax, [], {"menu_partition_size": 50})
    leads = {fact.key: fact.result for fact in product.facts if fact.fact_type == "lead"}
    ident = lambda number: f"asr:tool_observation:{number:064d}"
    assert set(leads) == {ident(1), ident(2), ident(3), ident(4)}, "shellcheck and psalm are in; others are not"
    assert leads[ident(1)]["category"] == "shell_lint" and leads[ident(1)]["scanner"] == "tool-shellcheck"
    # shellcheck directives are not tracked: unknown, never a founded "not_suppressed"
    assert leads[ident(1)]["suppression_status"] == leads[ident(2)]["suppression_status"] == "unknown"
    assert "tool-shellcheck" not in SUPPRESSION_TRACKED_SCANNERS
    assert leads[ident(3)]["suppression_status"] == "possibly_suppressed"        # @psalm-suppress, declaration scope
    assert leads[ident(4)]["suppression_status"] == "not_suppressed"
    # same location + same rule: the lower observation id is canonical, the other a duplicate
    assert leads[ident(1)]["duplicate_of"] is None and leads[ident(2)]["duplicate_of"] == ident(1)
    counts = product.counts
    assert counts["source_sast_observations"] == 4
    assert (counts["other_configuration"], counts["other_secret"], counts["other_other"]) == (2, 1, 1)
    assert counts["high_critical"] == 2 and counts["unknown_severity"] == 0


def test_the_observation_vocabulary_is_unchanged_and_every_category_maps_into_it() -> None:
    from appsec_review.retrieval import observations
    assert set(observations._CLASS_BY_CATEGORY.values()) <= set(OBSERVATION_CLASSES)
    assert "secret" in OBSERVATION_CLASSES
    for category in ("secret_detection", "shell_lint", "config_lint", "ci_security", "source_sast"):
        assert category in observations._CLASS_BY_CATEGORY
    assert json.dumps(sorted(OBSERVATION_CLASSES))
