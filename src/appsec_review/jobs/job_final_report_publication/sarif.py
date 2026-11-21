"""Project only gate-certified findings and exact, qualified protected remediation into SARIF."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from appsec_review.interchange import GapCode, producer_gap
from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.jobs.completion_contracts import REMEDIATION_VALIDATION_SCHEMA, verify_nonexecution_assurance
from appsec_review.reporting.sarif_contracts import SarifExportBundle
from appsec_review.reporting.sarif_export import export_sarif_bundle
from appsec_review.review.models import IntegrityError

from .pdf import bind_dossiers

_CHECK_DIMENSIONS = ("patch_applicability", "policy", "semantic_review", "static_checks", "build",
                     "regression_compile", "runtime_regression")
# Missing certification or unsupported required artifacts are not optional enrichment limits.
_OPTIONAL_FIX_LIMITATIONS = frozenset({
    "qualified_remediation_not_available",
    "validation_checks_do_not_qualify",
    "exact_patch_not_available",
    "patch_projection_is_not_exact",
})


def _qualified_fix(run_root: Path, gate: Mapping[str, Any], dossier: Mapping[str, Any]
                   ) -> tuple[dict[str, Any] | None, str | None]:
    candidates = [row for row in dossier.get("remediation", ()) if row.get("stage") == "Validation"]
    if len(candidates) > 1:
        return None, "ambiguous_remediation_validation"
    if not candidates or candidates[0].get("status") not in {"static_checked", "build_checked"}:
        return None, "qualified_remediation_not_available"
    row = candidates[0]
    bound = {(ref["path"], ref["sha256"]) for ref in gate["bindings"]}
    reference = row.get("artifact")
    if not reference or (reference["path"], reference["sha256"]) not in bound:
        return None, "validation_not_gate_bound"
    validation = read_bound_json(run_root, reference)
    if (validation.get("schema") != REMEDIATION_VALIDATION_SCHEMA
            or validation.get("run_id") != dossier["run_id"]
            or validation.get("finding") != dossier["finding"]
            or validation.get("status") != row["status"]):
        raise IntegrityError("SARIF remediation validation differs from the certified dossier")
    verify_nonexecution_assurance(validation["assurance"])
    if set(validation["checks"]) != set(_CHECK_DIMENSIONS):
        raise IntegrityError("SARIF remediation validation has unsupported check dimensions")
    checks = {name: validation["checks"][name]["status"] for name in _CHECK_DIMENSIONS}
    if checks != {check["dimension"]: check["status"] for check in row.get("checks", ())}:
        raise IntegrityError("SARIF remediation checks differ from the certified dossier")
    required = {"patch_applicability": "passed", "policy": "passed", "static_checks": "passed",
                "semantic_review": "analyst_supported", "runtime_regression": "not_performed_by_policy"}
    if row["status"] == "build_checked":
        required["build"] = "passed"
    if any(checks.get(name) != status for name, status in required.items()):
        return None, "validation_checks_do_not_qualify"
    patch = row.get("patch")
    if not patch:
        return None, "exact_patch_not_available"
    patch_ref = patch["artifact"]
    if validation.get("patch") != patch_ref:
        raise IntegrityError("SARIF remediation patch differs from its certified validation")
    if (patch_ref["path"], patch_ref["sha256"]) not in bound:
        return None, "patch_not_gate_bound"
    original = read_bound_json(run_root, patch_ref)
    if original.get("schema") != "appsec-review/remediation-exact-patch/1":
        return None, "unsupported_patch_format"
    # Dossier code is redacted, whitespace-normalized and bounded. Never apply that altered text.
    if (patch.get("schema") != original["schema"]
            or sorted(patch["files"], key=lambda file: file["path"])
            != sorted(original["files"], key=lambda file: file["path"])):
        return None, "patch_projection_is_not_exact"
    return {"validation_status": row["status"], "files": patch["files"], "patch": dict(patch_ref),
            "validation": dict(reference), "checks": checks}, None


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
    by_finding = {row.finding["finding_package_id"]: row.document for row in dossiers
                  if row.document and row.kind == "confirmed_finding"}
    findings = []
    limitations = []
    gaps = [
        producer_gap(GapCode.PRODUCER_REPORTED_GAP, row["statement"], scope_id=row["limitation_id"])
        for row in report["limitations"] if row["kind"] == "gap"
    ]
    for package in sorted(report["findings"], key=lambda row: row["finding_package_id"]):
        dossier = by_finding.get(package["finding_package_id"]) or {}
        sources = dossier.get("sources") or []
        source = sources[0] if sources else {}
        finding = {
            "finding_package_id": package["finding_package_id"],
            "claim_id": package["claim_id"],
            "title": package["title"],
            "severity": package["ship_block"]["technical_severity"],
            "cwe": dossier.get("weakness_cwe"),
            "security_predicate": dossier.get("security_predicate"),
            "path": source.get("path"),
            "start_line": source.get("start_line"),
            "end_line": source.get("end_line"),
        }
        if dossier:
            identity = package["finding_package_id"]
            # DP-01 deliberately removed invented timelines. No admitted producer supplies ordered paths.
            limitations.append({
                "finding_id": identity, "capability": "codeFlows",
                "reason": f"sarif_codeflow_omitted:{identity}:ordered_trace_not_in_accepted_dossier_contract",
            })
            fix, reason = _qualified_fix(run_root, gate, dossier)
            if fix is not None:
                finding["exact_remediation"] = fix
            else:
                message = f"sarif_fix_omitted:{identity}:{reason}"
                if reason in _OPTIONAL_FIX_LIMITATIONS:
                    limitations.append({"finding_id": identity, "capability": "fixes", "reason": message})
                else:
                    gaps.append(producer_gap(GapCode.PRODUCER_REPORTED_GAP, message))
        findings.append(finding)
    return export_sarif_bundle(
        findings, run_id=report["run_id"],
        upstream_gaps=sorted(gaps, key=lambda row: (row["reason"], row["scope_id"] or "")),
        optional_capability_limitations=limitations,
    )
