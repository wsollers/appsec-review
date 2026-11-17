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

from .contracts import (
    SARIF_DOCUMENT_NAME,
    SARIF_EXPORT_RESULT_SCHEMA,
    SARIF_RESULT_NAME,
    SarifExportBundle,
)


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
                    del_reg = rep.get("deletedRegion", {})
                    if del_reg.get("startLine", 0) < 1:
                        raise ValueError(f"Invalid SARIF replacement deletedRegion: {del_reg}")


def export_sarif_bundle(
    findings: Sequence[Mapping[str, Any]],
    *,
    run_id: str = "run-local",
    exporter_release: str = "1",
    upstream_gaps: Sequence[Mapping[str, Any] | str] = (),
    output_dir: Path | None = None,
) -> SarifExportBundle:
    """Assemble, validate, and optionally persist deterministic SARIF 2.1.0 output."""
    sarif_log, telemetry = build_sarif_log(
        findings, exporter_release=exporter_release, run_id=run_id,
    )
    validate_sarif_log(sarif_log)
    sarif_bytes = canonical_sarif_bytes(sarif_log)
    sarif_sha256 = hashlib.sha256(sarif_bytes).hexdigest()

    gap_records: list[dict[str, Any]] = []
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
