"""Optional dependency OpenVEX companion, confined to admitted producer bytes."""
from __future__ import annotations

from pathlib import Path
import json
from typing import Any

from jsonschema import Draft202012Validator

from appsec_review.indexing.store import AcceptedHandoff
from appsec_review.interchange import GapCode, producer_gap

from .contracts import (
    ArtifactRef, ExportFailureReason as Reason, VerifiedInputs, canonical_bytes, source_product_id,
)
from .cve_reachability import project_dependency_advisories_to_openvex
from .inputs import BoundedInputReader, _accepted, _ref, _require
from .settings import OpenVexExportSettings

DEPENDENCY_JOB = "job_dependency_intelligence"
DOCUMENT_NAME = "openvex-dependencies.json"
RESULT_NAME = "openvex-dependencies-result.json"
RESULT_SCHEMA = "appsec-review/openvex-dependencies/1"


def read_dependency_inputs(
    reader: BoundedInputReader, repository_root: Path, *,
    resolved_config_sha256: str, target_snapshot: str,
) -> tuple[AcceptedHandoff, ArtifactRef, dict[str, Any]] | None:
    """Measure optional admitted dependency bytes in the export's shared input budget."""
    accepted = _accepted(reader, DEPENDENCY_JOB, optional=True)
    if accepted is None:
        return None
    _require(accepted.handoff["resolved_config_sha256"] == resolved_config_sha256,
             "dependency export configuration differs from the certified gate", Reason.IDENTITY_CONFLICT)
    output = accepted.handoff["outputs"]["acceptance.publish_handoff"]
    published_ref = output.get("artifact")
    _require(published_ref is not None, "accepted dependency output omits its domain artifact",
             Reason.INPUT_MISSING)
    published = reader.json(_ref(published_ref))
    raw_ref = published.get("sca_reachability")
    _require(raw_ref is not None, "accepted dependency output omits SCA reachability", Reason.INPUT_MISSING)
    reference = _ref(raw_ref)
    document = reader.json(reference)
    schema_path = repository_root / "docs" / "schemas" / "dependency-intelligence" / "sca-reachability.schema.json"
    Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8"))).validate(document)
    _require(document["source_fingerprint"] == target_snapshot,
             "dependency reachability belongs to another target snapshot", Reason.IDENTITY_CONFLICT)
    _require(len(document["advisories"]) <= reader.settings.max_packages,
             "dependency advisory count exceeds the export bound", Reason.BOUND_EXCEEDED)
    return accepted, reference, document


def dependency_projection(
    run_root: Path, verified: VerifiedInputs, settings: OpenVexExportSettings,
    repository_root: Path, release: str,
) -> tuple[dict[str, Any] | None, bytes | None]:
    reader = BoundedInputReader(run_root, settings)
    for reference in verified.input_inventory:
        reader.read(reference)
    loaded = read_dependency_inputs(
        reader, repository_root, resolved_config_sha256=verified.provenance.resolved_config_sha256,
        target_snapshot=verified.source.target_snapshot,
    )
    if loaded is None:
        return None, None
    accepted, reference, document = loaded
    output = accepted.handoff["outputs"]["acceptance.publish_handoff"]
    evidence = next(item.to_json() for item in reader.inventory if item.path == reference.path)
    upstream_evidence = [item.to_json() for item in reader.inventory
                         if item.path in {reference.path, accepted.path}]
    gaps = []
    for gap in [*document.get("gaps", ()), *output.get("gaps", ())]:
        if isinstance(gap, dict) and gap.get("schema") == "appsec-review/producer-gap/1":
            gaps.append(gap)
        else:
            # Legacy producer records remain lossless data in a typed gap, not invented statuses.
            reason = gap if isinstance(gap, str) else canonical_bytes(gap).decode("utf-8").rstrip("\n")
            gaps.append(producer_gap(
                GapCode.PRODUCER_REPORTED_GAP, reason, scope_id=DEPENDENCY_JOB,
                evidence_refs=upstream_evidence,
            ))
    if document.get("coverage") == "partial" and not gaps:
        gaps.append(producer_gap(
            GapCode.PRODUCER_REPORTED_GAP, "dependency reachability coverage is partial",
            scope_id=DEPENDENCY_JOB, evidence_refs=[evidence],
        ))
    # Static import/call matching has no complete executable-path coverage certificate.
    # Do not forward arbitrary coverage flags as authority for a negative VEX statement.
    advisories = []
    source_reasons = sorted({gap["reason"] for gap in gaps})
    for row in document["advisories"]:
        if not isinstance(row["purl"], str) or not row["purl"].startswith("pkg:"):
            gaps.append(producer_gap(
                GapCode.PROVENANCE_UNAVAILABLE,
                f"OpenVEX dependency coordinate unavailable for advisory {row['advisory_id']} "
                f"({row['package_name']}, version={row['package_version']!r}, "
                f"purl={row['purl']!r}, ecosystem={row['ecosystem']!r}); no statement emitted",
                scope_id=row["advisory_id"], evidence_refs=[evidence],
            ))
            continue
        advisory = {key: row.get(key) for key in (
            "advisory_id", "cve_ids", "package_name", "package_version", "purl", "ecosystem")}
        advisory["reachability"] = (
            "symbol_reachable" if row["reachability"] == "symbol_reachable" and row["call_sites"] else "unknown")
        advisory["coverage_complete"] = False
        advisory["gaps"] = source_reasons
        advisories.append(advisory)
    bundle = project_dependency_advisories_to_openvex(
        advisories, author=settings.author, role=settings.role, timestamp=verified.gate_completed_at,
        product_id=source_product_id(
            verified.source.repository_iri, verified.source.target_snapshot,
            verified.provenance.resolved_config_sha256,
        ), exporter_release=release,
        default_action_statement=settings.action_statement,
        run_has_coverage_gaps=any(row["kind"] == "gap" for row in verified.gate["limitations"])
        or bool(document.get("gaps")) or bool(output.get("gaps")),
    )
    reader.reprove()
    _require(bundle.document_bytes is None or len(bundle.document_bytes) <= settings.max_document_bytes,
             "dependency OpenVEX document exceeds its byte bound", Reason.BOUND_EXCEEDED)
    unique_gaps = {canonical_bytes(gap): gap for gap in (*gaps, *bundle.gaps)}
    gaps = [unique_gaps[key] for key in sorted(unique_gaps)]
    result = {
        "schema": RESULT_SCHEMA, "run_id": verified.run_id,
        "source": {"handoff": {"path": accepted.path, "sha256": accepted.sha256},
                   "artifact": reference.to_json(), "gate": verified.provenance.gate.to_json()},
        "statements_by_status": bundle.statements_by_status,
        "gaps": gaps,
        "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED",
    }
    return result, bundle.document_bytes


def telemetry(result: dict[str, Any] | None) -> dict[str, Any]:
    if result is None:
        return {}
    counts = result["statements_by_status"]
    return {
        "openvex.cve_statements_by_status": dict(counts),
        "openvex.cve_total_statements": sum(counts.values()),
        "openvex.cve_coverage_gap_statements": counts["under_investigation"],
    }
