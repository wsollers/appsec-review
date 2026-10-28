"""Per-finding records of artifact-security scans (schema ``appsec-review/artifact-security-record/2``).

A scan result (one scanner run over one produced artifact) used to be indexed as ONE observation holding the
scanner's whole document, so a blint report with a critical ``CHECK_NX`` and a high ``CHECK_PIE`` was one record
whose severity collapsed to ``unknown``, and every syft package inventory was a lead. This module splits a scan
result into

* exactly one **scan summary** per scan (``record_kind: scan_summary``): the account that the scan ran, its outcome,
  its gaps and ``finding_count``, so a scan with zero findings is distinguishable from a scan that never completed.
  It is class ``inventory`` (inventory scans) or ``diagnostic`` (every other scan), never a lead; and
* one **finding** per scanner finding (``record_kind: finding``): a blint check result, a SpotBugs bug instance, an
  OSV vulnerability or a Grype match, each at its own native severity with a stable identity (scan identity,
  artifact identity, check id, subject and an occurrence ordinal for repeats). These are the artifact leads.

The built-in inspectors (``inventory``, ``native``, ``jvm``, ``packages``, ``wasm``) record format facts and the
named gap that a pinned scanner is required; they produce no findings, only their summary. Scanner output is data:
every string is bounded and nothing here executes or follows it.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
import os
from typing import Any

from appsec_review.retrieval.observations import (
    RECORD_KIND_FINDING, RECORD_KIND_SUMMARY, normalize_reported_severity,
)
from appsec_review.provenance import common_metadata, json_selector, select_native

RECORD_SCHEMA = "appsec-review/artifact-security-record/2"
# Version of the scan-result -> record splitting below. It is part of the observations shard fingerprint, not of
# the scan checkpoint fingerprint: scanner receipts stay reusable when only this normalization changes.
FINDING_NORMALIZER = "appsec-review/artifact-security-findings/2"
MESSAGE_BOUND = 512
FIELD_BOUND = 128
FINDING_BOUND = 5_000          # findings kept per scan; a scan above it reports the truncation as a gap

CATEGORY_BINARY_HARDENING = "binary_hardening"
CATEGORY_VULNERABILITY = "vulnerability_matching"
CATEGORY_BYTECODE = "bytecode_analysis"
CATEGORY_INVENTORY = "software_inventory"
CATEGORY_DIAGNOSTIC = "tool_diagnostic"
INVENTORY_CAPABILITIES = frozenset({"inventory", "syft", "packages"})


def _text(value: Any, bound: int = FIELD_BOUND) -> str | None:
    if value is None or isinstance(value, (Mapping, list, tuple)):
        return None
    text = str(value).strip()
    return text[:bound] if text else None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


@dataclass(frozen=True, slots=True)
class Finding:
    """One scanner finding before it becomes an observation."""

    check_id: str
    severity: str | None              # the scanner's own label, mapped later by the family severity rule
    message: str
    category: str
    tool_id: str
    subject: str                      # what the finding is about inside the artifact (binary, package, class)
    fields: Mapping[str, Any]         # bounded scanner-specific facts kept on the observation
    selector: Mapping[str, Any]
    native_report: str | None = None


def _blint(observation: Mapping[str, Any]) -> Iterator[Finding]:
    for index, item in enumerate(_list(observation.get("findings"))):
        item = _mapping(item)
        check = _text(item.get("id"))
        if check is None:
            continue
        binary = _text(item.get("filename") or item.get("exe_name")) or "unknown"
        yield Finding(check, _text(item.get("severity")), _text(item.get("title"), MESSAGE_BOUND) or check,
                      CATEGORY_BINARY_HARDENING, "tool-blint", os.path.basename(binary) or binary,
                      {"binary": binary, "exe_type": _text(item.get("exe_type"))},
                      item.get("_native_selector", json_selector("findings", index).as_dict()),
                      item.get("_native_report"))


def _spotbugs(observation: Mapping[str, Any]) -> Iterator[Finding]:
    for index, item in enumerate(_list(observation.get("findings"))):
        item = _mapping(item)
        check = _text(item.get("type"))
        if check is None:
            continue
        cls = _text(item.get("class")) or "unknown"
        priority = _text(item.get("priority"))
        # SpotBugs ranks 1 (high), 2 (normal), 3 (low); the label comes from the same scanner rule the
        # evidence-collection SpotBugs rows use, so the mapping exists once.
        label = normalize_reported_severity({"tool_id": "tool-spotbugs", "native_severity": priority})
        severity = label["value"].upper() if label["value"] != "unknown" else None
        location = {key: _text(item.get(key)) for key in ("source", "start", "end") if _text(item.get(key))}
        yield Finding(check, severity, f"{check} in {cls}"[:MESSAGE_BOUND], CATEGORY_BYTECODE, "tool-spotbugs", cls,
                      {"native_priority": priority, "bug_category": _text(item.get("category")),
                       "native_location": location or None},
                      item.get("_native_selector", json_selector("findings", index).as_dict()))


def _grype(observation: Mapping[str, Any]) -> Iterator[Finding]:
    for index, match in enumerate(_list(observation.get("matches"))):
        match = _mapping(match)
        vulnerability, package = _mapping(match.get("vulnerability")), _mapping(match.get("artifact"))
        check = _text(vulnerability.get("id"))
        if check is None:
            continue
        name, version = _text(package.get("name")), _text(package.get("version"))
        subject = f"{name}@{version}" if name and version else name or "unknown"
        yield Finding(check, _text(vulnerability.get("severity")),
                      f"{check} affects {subject}"[:MESSAGE_BOUND], CATEGORY_VULNERABILITY, "tool-grype", subject,
                      {"package_name": name, "package_version": version, "advisory_id": check,
                       # Keep the legacy advisory-pair projection; the full match is retained natively.
                       "observation": {"matches": [{
                           "artifact": {key: _text(package.get(key), 512)
                                        for key in ("name", "version", "purl")},
                           "vulnerability": {key: _text(vulnerability.get(key), 512)
                                             for key in ("id", "severity")},
                       }]}}, json_selector("matches", index).as_dict())


def _osv(observation: Mapping[str, Any]) -> Iterator[Finding]:
    for result_index, result in enumerate(_list(observation.get("results"))):
        for package_index, entry in enumerate(_list(_mapping(result).get("packages"))):
            entry = _mapping(entry)
            package = _mapping(entry.get("package"))
            name, version = _text(package.get("name")), _text(package.get("version"))
            subject = f"{name}@{version}" if name and version else name or "unknown"
            for index, vulnerability in enumerate(_list(entry.get("vulnerabilities"))):
                vulnerability = _mapping(vulnerability)
                check = _text(vulnerability.get("id"))
                if check is None:
                    continue
                specific = _mapping(vulnerability.get("database_specific"))
                vectors = [_text(_mapping(item).get("score")) for item in _list(vulnerability.get("severity"))]
                yield Finding(check, _text(specific.get("severity")),
                              (_text(vulnerability.get("summary"), MESSAGE_BOUND) or f"{check} affects {subject}"),
                              CATEGORY_VULNERABILITY, "tool-osv-scanner", subject,
                              {"package_name": name, "package_version": version, "advisory_id": check,
                               "ecosystem": _text(package.get("ecosystem")),
                               "aliases": [_text(item) for item in _list(vulnerability.get("aliases"))[:16]
                                           if _text(item)],
                               "cvss_vectors": [item for item in vectors if item][:4]},
                              json_selector("results", result_index, "packages", package_index,
                                            "vulnerabilities", index).as_dict())


SPLITTERS: Mapping[str, Callable[[Mapping[str, Any]], Iterator[Finding]]] = {
    "blint": _blint, "spotbugs": _spotbugs, "grype": _grype, "osv": _osv,
}
# Nested scanner bodies the summary drops because the findings carry them (the counts remain).
_SUMMARY_DROPS = {"blint": ("findings",), "spotbugs": ("findings",), "grype": ("matches",), "osv": ("results",)}


@dataclass(frozen=True, slots=True)
class Record:
    """One observation to index: ``identity_key`` feeds ``LogicalIdentity.derive`` with the shard's snapshot."""

    kind: str
    identity_key: Mapping[str, Any]
    native_id: str
    name: str
    text: str
    payload: Mapping[str, Any]


def scan_outcome(scan: Mapping[str, Any]) -> str:
    """``completed`` (no gap), ``completed_with_gaps`` (parsed, with named gaps) or ``not_completed`` (no result)."""
    if not scan.get("gaps"):
        return "completed"
    return "completed_with_gaps" if scan.get("observation") else "not_completed"


def summary_category(capability: str) -> str:
    return CATEGORY_INVENTORY if capability in INVENTORY_CAPABILITIES else CATEGORY_DIAGNOSTIC


def _summary_observation(capability: str, observation: Mapping[str, Any], kept: int, total: int) -> dict[str, Any]:
    drops = _SUMMARY_DROPS.get(capability, ())
    body = {key: value for key, value in observation.items() if key not in drops}
    if drops:
        body["finding_count_reported"] = total
        body["finding_records"] = kept
    if capability == "syft":
        body.pop("artifacts", None)
        body["artifact_count_reported"] = observation.get(
            "_native_result_count", len(_list(observation.get("artifacts"))))
    if capability == "blint":
        body.pop("reviews", None)
        body["review_count_reported"] = _mapping(observation.get("reported_counts")).get(
            "reviews", len(_list(observation.get("reviews"))))
    return body


def scan_records(scan: Mapping[str, Any]) -> tuple[Record, tuple[Record, ...]]:
    """Split one scan result into its summary record and its finding records, deterministically."""
    capability, observation = str(scan["capability"]), _mapping(scan.get("observation"))
    artifact, fingerprint = _mapping(scan["artifact"]), str(scan["fingerprint"])
    canonical = str(artifact.get("canonical_identity") or "")
    outcome = scan_outcome(scan)
    splitter = SPLITTERS.get(capability)
    found = list(splitter(observation)) if splitter is not None and observation else []
    gaps = [str(gap)[:MESSAGE_BOUND] for gap in scan.get("gaps") or ()]
    kept = found[:FINDING_BOUND]
    if len(found) > FINDING_BOUND:
        gaps.append(f"{capability} reported {len(found)} findings; only the first {FINDING_BOUND} are recorded")
        outcome = "completed_with_gaps"
    base = {key: scan.get(key) for key in ("artifact", "classification", "capability", "scanner_identity",
                                           "tool_identity", "gaps", "raw_artifacts", "attempt_identity", "exit_code",
                                           "timed_out", "duration_ms", "result_artifact")}
    summary_payload = {
        **base, "gaps": gaps, "schema": RECORD_SCHEMA, "record_kind": RECORD_KIND_SUMMARY,
        "category": summary_category(capability), "scan_fingerprint": fingerprint,
        "scan_outcome": outcome, "finding_capable": splitter is not None,
        "finding_count": len(kept) if splitter is not None else None,
        "findings_complete": (outcome == "completed" and len(found) <= FINDING_BOUND) if splitter is not None else None,
        "observation": _summary_observation(capability, observation, len(kept), len(found)),
    }
    summary_ref = scan.get("native_output")
    summary_payload["common"] = common_metadata(
        {**summary_payload, "tool_id": scan.get("tool_identity", {}).get("scanner") or capability,
         "native_rule_id": capability},
        evidence_refs=(summary_ref,) if summary_ref else (), payload_schema=RECORD_SCHEMA,
        record_kind=RECORD_KIND_SUMMARY,
        gaps=("provenance_unavailable",) if not summary_ref or any(
            gap.startswith("provenance_unavailable") for gap in gaps) else ())
    summary = Record(RECORD_KIND_SUMMARY, {"fingerprint": fingerprint}, fingerprint, capability,
                     f"{capability} scan of {artifact.get('path')}: {outcome}, "
                     f"{len(kept) if splitter is not None else 'no'} finding(s)", summary_payload)
    seen: dict[tuple[str, str], int] = {}
    records: list[Record] = []
    for finding in kept:
        key = (finding.check_id, finding.subject)
        occurrence = seen[key] = seen.get(key, 0) + 1
        identity_key = {"fingerprint": fingerprint, "artifact": canonical, "check": finding.check_id,
                        "subject": finding.subject, "occurrence": occurrence}
        payload = {
            **base, "gaps": [], "schema": RECORD_SCHEMA, "record_kind": RECORD_KIND_FINDING,
            "category": finding.category, "tool_id": finding.tool_id, "scan_fingerprint": fingerprint,
            "native_rule_id": finding.check_id, "rule_id": finding.check_id, "severity": finding.severity,
            "native_severity": finding.severity, "message": finding.message[:MESSAGE_BOUND],
            "subject": finding.subject, "subject_artifact": canonical, "occurrence": occurrence,
            **{key: value for key, value in finding.fields.items() if value not in (None, [], {})},
        }
        native = (scan.get("native_reports", {}).get(finding.native_report)
                  if finding.native_report else summary_ref)
        references = (select_native(native, finding.selector).as_dict(),) if native else ()
        payload["common"] = common_metadata(
            {**payload, **({"native_severity": finding.fields["native_priority"]}
                           if "native_priority" in finding.fields else {})},
            evidence_refs=references, payload_schema=RECORD_SCHEMA,
            gaps=("provenance_unavailable",) if not references or any(
                gap.startswith("provenance_unavailable") for gap in gaps) else ())
        native_id = f"{fingerprint}:{finding.check_id}:{finding.subject}:{occurrence}"
        records.append(Record(RECORD_KIND_FINDING, identity_key, native_id[:512], finding.check_id,
                              f"{capability} {finding.check_id} {finding.subject}: {finding.message}"[:1024],
                              payload))
    return summary, tuple(records)
