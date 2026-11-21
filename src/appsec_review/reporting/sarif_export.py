"""Pure SARIF 2.1.0 assembly and structural validation."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path
from typing import Any

from appsec_review.interchange import GapCode, ProducerStatus, producer_gap
from appsec_review.reporting.sarif import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    build_sarif_log,
    canonical_sarif_bytes,
)

from .sarif_contracts import (
    SARIF_DOCUMENT_NAME,
    SARIF_EXPORT_RESULT_SCHEMA,
    SARIF_RESULT_NAME,
    SarifExportBundle,
)


def _validate_replacement_region(region: Any) -> None:
    if not isinstance(region, Mapping):
        raise ValueError(f"Invalid SARIF replacement deletedRegion: {region}")
    line_fields = {"startLine", "endLine", "startColumn", "endColumn"}
    byte_fields = {"byteOffset", "byteLength"}
    has_lines, has_bytes = bool(line_fields & region.keys()), bool(byte_fields & region.keys())
    valid = has_lines or has_bytes
    if has_lines:
        start = region.get("startLine")
        end = region.get("endLine", start)
        valid = valid and type(start) is int and start >= 1 and type(end) is int and end >= start
        for field in ("startColumn", "endColumn"):
            if field in region:
                valid = valid and type(region[field]) is int and region[field] >= 1
        if valid and end == start:
            valid = region.get("endColumn", region.get("startColumn", 1)) >= region.get("startColumn", 1)
    if has_bytes:
        valid = valid and all(type(region.get(field)) is int and region[field] >= 0 for field in byte_fields)
    if not valid:
        raise ValueError(f"Invalid SARIF replacement deletedRegion: {region}")


def validate_sarif_log(sarif_log: Mapping[str, Any]) -> None:
    """Validate critical OASIS SARIF 2.1.0 structural and referential invariants."""
    if sarif_log.get("$schema") != SARIF_SCHEMA_URI:
        raise ValueError("SARIF log $schema must match OASIS SARIF 2.1.0 schema URI")
    if sarif_log.get("version") != SARIF_VERSION:
        raise ValueError("SARIF log version must equal '2.1.0'")
    runs = sarif_log.get("runs")
    if not isinstance(runs, Sequence) or len(runs) != 1:
        raise ValueError("SARIF log must contain exactly one run")
    run = runs[0]
    driver = run.get("tool", {}).get("driver", {})
    if not isinstance(driver.get("name"), str) or not driver["name"]:
        raise ValueError("SARIF tool.driver.name must be non-empty")
    rules = driver.get("rules", [])
    taxonomies = run.get("taxonomies", [])

    for result in run.get("results", []):
        r_idx = result.get("ruleIndex")
        if not isinstance(r_idx, int) or r_idx < 0 or r_idx >= len(rules):
            raise ValueError(f"SARIF result ruleIndex {r_idx} out of bounds")
        if rules[r_idx].get("id") != result.get("ruleId"):
            raise ValueError("SARIF result ruleId disagrees with rules[ruleIndex].id")
        if result.get("level") not in {"error", "warning", "note", "none"}:
            raise ValueError(f"Invalid SARIF result level: {result.get('level')}")
        if not result.get("locations"):
            raise ValueError("SARIF result must have at least one primary location")
        for location in result["locations"]:
            physical = location.get("physicalLocation", {})
            uri = physical.get("artifactLocation", {}).get("uri")
            region = physical.get("region", {})
            start, end = region.get("startLine"), region.get("endLine")
            if (not isinstance(uri, str) or not uri or uri == "unknown" or uri.startswith("/")
                    or ":" in uri or ".." in uri.split("/") or type(start) is not int or start < 1
                    or end is not None and (type(end) is not int or end < start)):
                raise ValueError("Invalid SARIF primary physicalLocation")
        for taxon_ref in result.get("taxa", []):
            tc_idx = taxon_ref.get("toolComponent", {}).get("index")
            t_idx = taxon_ref.get("index")
            if (
                not isinstance(tc_idx, int)
                or tc_idx < 0
                or tc_idx >= len(taxonomies)
                or not isinstance(t_idx, int)
                or t_idx < 0
                or t_idx >= len(taxonomies[tc_idx].get("taxa", []))
                or taxonomies[tc_idx]["taxa"][t_idx].get("id") != taxon_ref.get("id")
            ):
                raise ValueError(f"Invalid SARIF result taxa reference: {taxon_ref}")
        for cf in result.get("codeFlows", []):
            tfs = cf.get("threadFlows")
            if not isinstance(tfs, Sequence) or not tfs:
                raise ValueError("SARIF codeFlow must contain non-empty threadFlows")
            for tf in tfs:
                locs = tf.get("locations")
                if not isinstance(locs, Sequence) or not locs:
                    raise ValueError("SARIF threadFlow must contain non-empty locations")
                for tfl in locs:
                    phys = tfl.get("location", {}).get("physicalLocation", {})
                    uri = phys.get("artifactLocation", {}).get("uri", "")
                    start_line = phys.get("region", {}).get("startLine", 0)
                    if not uri or uri.startswith("/") or start_line < 1:
                        raise ValueError(f"Invalid SARIF threadFlowLocation physicalLocation: {phys}")
        for fix in result.get("fixes", []):
            changes = fix.get("artifactChanges")
            if not isinstance(changes, Sequence) or not changes:
                raise ValueError("SARIF fix must contain non-empty artifactChanges")
            for ac in changes:
                uri = ac.get("artifactLocation", {}).get("uri", "")
                repls = ac.get("replacements")
                if not uri or not isinstance(repls, Sequence) or not repls:
                    raise ValueError(f"Invalid SARIF artifactChange: {ac}")
                for rep in repls:
                    _validate_replacement_region(rep.get("deletedRegion"))


def _optional_capabilities(
    findings: Sequence[Mapping[str, Any]], limitations: Sequence[Mapping[str, str]],
) -> list[dict[str, str]]:
    if not limitations:
        return []
    identities = {
        identity.strip() for finding in findings
        if isinstance(identity := finding.get("finding_id") or finding.get("finding_package_id")
                      or finding.get("claim_id"), str)
    }
    rows: dict[tuple[str, str], dict[str, str]] = {}
    for limitation in limitations:
        if (not isinstance(limitation, Mapping)
                or set(limitation) != {"finding_id", "capability", "reason"}
                or any(not isinstance(value, str) or not value.strip() or "\x00" in value
                       for value in limitation.values())
                or limitation["finding_id"] not in identities
                or limitation["capability"] not in {"codeFlows", "fixes"}
                or len(limitation["reason"]) > 300):
            raise ValueError("invalid optional SARIF capability limitation")
        key = (limitation["finding_id"], limitation["capability"])
        if key in rows and rows[key] != limitation:
            raise ValueError("conflicting optional SARIF capability limitations")
        rows[key] = dict(limitation)
    return [rows[key] for key in sorted(rows)]


def export_sarif_bundle(
    findings: Sequence[Mapping[str, Any]],
    *,
    run_id: str = "run-local",
    exporter_release: str = "1",
    upstream_gaps: Sequence[Mapping[str, Any] | str] = (),
    optional_capability_limitations: Sequence[Mapping[str, str]] = (),
    output_dir: Path | None = None,
) -> SarifExportBundle:
    """Export required records; optional capability metadata never reclassifies declared gaps."""
    limitations = _optional_capabilities(findings, optional_capability_limitations)
    valid = []
    export_gaps = []
    for finding in findings:
        try:
            candidate, _ = build_sarif_log([finding], exporter_release=exporter_release, run_id=run_id)
            validate_sarif_log(candidate)
        except ValueError as exc:
            identity = finding.get("finding_package_id") or finding.get("finding_id") or finding.get("claim_id")
            export_gaps.append(producer_gap(
                GapCode.PRODUCER_REPORTED_GAP, f"sarif_record_omitted:{identity or 'unidentified'}: {exc}"))
        else:
            valid.append(finding)
    sarif_log, telemetry = build_sarif_log(valid, exporter_release=exporter_release, run_id=run_id)
    if limitations:
        sarif_log["runs"][0]["properties"]["optional_capability_limitations"] = limitations
    validate_sarif_log(sarif_log)
    sarif_bytes = canonical_sarif_bytes(sarif_log)
    sarif_sha256 = hashlib.sha256(sarif_bytes).hexdigest()

    gap_records: list[dict[str, Any]] = sorted(export_gaps, key=lambda row: json.dumps(row, sort_keys=True))
    for raw_gap in upstream_gaps:
        if isinstance(raw_gap, Mapping) and raw_gap.get("schema") == "appsec-review/producer-gap/1":
            gap_records.append(dict(raw_gap))
        elif isinstance(raw_gap, Mapping):
            reason = str(raw_gap.get("reason") or raw_gap.get("limitation_id") or "upstream_coverage_gap")
            gap_records.append(producer_gap(GapCode.PRODUCER_REPORTED_GAP, reason))
        elif isinstance(raw_gap, str) and raw_gap.strip():
            gap_records.append(producer_gap(GapCode.PRODUCER_REPORTED_GAP, raw_gap.strip()))

    terminal_status = (
        ProducerStatus.COMPLETED_WITH_GAPS.value
        if gap_records
        else ProducerStatus.SUCCEEDED.value
    )
    result = {
        "schema": SARIF_EXPORT_RESULT_SCHEMA,
        "run_id": run_id,
        "terminal_status": terminal_status,
        "sarif_document": {
            "filename": SARIF_DOCUMENT_NAME,
            "sha256": sarif_sha256,
            "size_bytes": len(sarif_bytes),
        },
        "telemetry": telemetry,
        "gaps": gap_records,
    }

    if output_dir is not None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / SARIF_DOCUMENT_NAME).write_bytes(sarif_bytes)
        result_bytes = (json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        (out / SARIF_RESULT_NAME).write_bytes(result_bytes)

    return SarifExportBundle(
        sarif_log=sarif_log,
        sarif_bytes=sarif_bytes,
        sarif_sha256=sarif_sha256,
        result=result,
        telemetry=telemetry,
        gaps=tuple(gap_records),
    )
