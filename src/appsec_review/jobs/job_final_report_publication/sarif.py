"""Project only gate-certified findings and dossier source locations into SARIF."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.reporting.sarif_contracts import SarifExportBundle
from appsec_review.reporting.sarif_export import export_sarif_bundle
from appsec_review.review.models import IntegrityError

from .pdf import bind_dossiers


def chain_manifest_items(run_root: Path, gate: Mapping[str, Any]) -> list[dict[str, Any]]:
    reference = gate["capabilities"]["attack_chains"]["summary"]
    if reference is None:
        return []
    if reference not in gate["bindings"]:
        raise IntegrityError("attack chain manifest is not bound by the accepted gate")
    manifest = read_bound_json(run_root, reference)
    if manifest.get("schema") != "appsec-review/attack-chain-manifest/1" or manifest.get("run_id") != gate["run_id"]:
        raise IntegrityError("attack chain manifest identity differs from the gate")
    by_id = {row["chain_id"]: row for row in manifest["items"]}
    for chain in gate["attachments"]["attack_chains"]:
        row = by_id.get(chain["chain_id"])
        if row is None or any(row[key] != chain[key] for key in ("status", "component_claim_ids", "artifact")):
            raise IntegrityError("attack chain manifest disagrees with the gate")
    return manifest["items"]


def gate_sarif(run_root: Path, gate: Mapping[str, Any], report: Mapping[str, Any]) -> SarifExportBundle:
    dossiers = bind_dossiers(run_root, report, gate["bindings"])
    by_finding = {row.finding["finding_package_id"]: row.document for row in dossiers if row.document}
    findings = []
    for package in report["findings"]:
        dossier = by_finding.get(package["finding_package_id"]) or {}
        sources = dossier.get("sources") or []
        source = sources[0] if sources else {}
        findings.append({
            "finding_package_id": package["finding_package_id"],
            "claim_id": package["claim_id"],
            "title": package["title"],
            "severity": package["ship_block"]["technical_severity"],
            "cwe": dossier.get("weakness_cwe"),
            "security_predicate": dossier.get("security_predicate"),
            "path": source.get("path"),
            "start_line": source.get("start_line"),
            "end_line": source.get("end_line"),
        })
    return export_sarif_bundle(
        findings, run_id=report["run_id"],
        upstream_gaps=[row["statement"] for row in report["limitations"] if row["kind"] == "gap"],
    )
