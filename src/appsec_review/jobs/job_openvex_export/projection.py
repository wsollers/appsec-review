"""Pure projection of the accepted gate; no filesystem, clock or publication effects."""
from __future__ import annotations

from collections import Counter
from typing import Any, NoReturn

from . import contracts as c
from .settings import OpenVexExportSettings

_REVIEW_CONTEXT_KEYS = (
    "review", "accounting", "ship_block", "verification", "coverage", "limitations",
    "gap_ids", "capabilities", "attachments", "status",
)


def _fail(message: str, reason: c.ExportFailureReason = c.ExportFailureReason.SEMANTIC_INVALID) -> NoReturn:
    raise c.ExportError(message, reason=reason, phase=c.ExportPhase.ASSEMBLE)


def _check_inputs(inputs: c.VerifiedInputs, settings: OpenVexExportSettings) -> None:
    try:
        settings.require_enabled()
    except ValueError as exc:
        raise c.ExportError(str(exc), reason=c.ExportFailureReason.CONFIGURATION_INVALID,
                            phase=c.ExportPhase.ASSEMBLE) from exc
    if inputs.settings_sha256 != settings.settings_sha256():
        _fail("export settings differ from verified frozen settings", c.ExportFailureReason.INPUT_STALE)
    if settings.repository_iri and inputs.source.repository_iri != settings.repository_iri:
        _fail("reviewed source and operator repository identities disagree", c.ExportFailureReason.IDENTITY_CONFLICT)
    if not settings.repository_iri and (
            inputs.source.repository_identity_basis != c.RepositoryIdentityBasis.SOURCE_SNAPSHOT
            or inputs.source.repository_iri != c.snapshot_repository_iri(inputs.source.target_snapshot)):
        _fail("automatic repository identity does not match the accepted source snapshot",
              c.ExportFailureReason.IDENTITY_CONFLICT)
    if (len(inputs.findings) > settings.max_packages or len(inputs.input_inventory) > settings.max_bindings
            or any(ref.size_bytes > settings.max_artifact_bytes for ref in inputs.input_inventory)
            or inputs.total_input_bytes > settings.max_total_input_bytes):
        _fail("verified input inventory exceeds configured export bounds", c.ExportFailureReason.BOUND_EXCEEDED)
    gate = inputs.gate
    counts = Counter(finding.bucket.value for finding in inputs.findings)
    expected_counts = {"total": len(inputs.findings), **{bucket.value: counts[bucket.value] for bucket in c.GateBucket},
                       "exact": True}
    if c.canonical_bytes(gate["package_counts"]) != c.canonical_bytes(expected_counts):
        _fail("gate package accounting does not exactly match verified findings")
    expected_buckets = {
        bucket.value: [finding.finding_package_id for finding in inputs.findings if finding.bucket == bucket]
        for bucket in c.GateBucket
    }
    if set(gate["buckets"]) != set(expected_buckets):
        _fail("gate bucket identities are not closed")
    for bucket, identities in expected_buckets.items():
        actual = gate["buckets"][bucket]
        if len(actual) != len(set(actual)) or set(actual) != set(identities):
            _fail("gate bucket membership does not exactly match verified findings")
    provenance, review = inputs.provenance, gate["review"]
    expected_review = {
        "accepted_manifest_sha256": provenance.accepted_manifest.sha256,
        "configuration_sha256": provenance.review_settings_sha256,
        "lead_package_manifest_sha256": provenance.lead_package_manifest_sha256,
        "package_manifest_sha256": provenance.hunt_package_manifest_sha256,
        "ledger_head_sha256": provenance.ledger_head_sha256,
        "projection_sha256": provenance.projection_sha256,
        "ship_block_policy_sha256": provenance.ship_block_policy_sha256,
    }
    if any(review[key] != value for key, value in expected_review.items()):
        _fail("gate review provenance disagrees with verified export provenance",
              c.ExportFailureReason.IDENTITY_CONFLICT)
    if (c.canonical_bytes(gate["inputs"]["job_handoff"]) != c.canonical_bytes(provenance.review_handoff.to_json())
            or c.canonical_bytes(gate["inputs"]["review_handoff"]) != c.canonical_bytes(provenance.review.to_json())):
        _fail("gate review references disagree with verified export provenance",
              c.ExportFailureReason.IDENTITY_CONFLICT)


def _output(prefix: str, filename: str, body: c.JsonObject, limit: int) -> tuple[bytes, c.SizedArtifactRef]:
    payload = c.canonical_bytes(body)
    if len(payload) > limit:
        _fail(f"{filename} exceeds its configured byte bound", c.ExportFailureReason.BOUND_EXCEEDED)
    return payload, c.output_reference(prefix, filename, payload)


def assemble_export(
    verified_inputs: c.VerifiedInputs, settings: OpenVexExportSettings, exporter_release: str, *,
    output_prefix: str,
) -> c.ExportBundle:
    """Build document -> companion -> result, preserving accepted review dimensions verbatim."""
    _check_inputs(verified_inputs, settings)
    try:
        for filename in (c.DOCUMENT_NAME, c.MANIFEST_NAME, c.RESULT_NAME):
            c.require_run_path(f"{c.require_run_path(output_prefix)}/{filename}")
        tooling = c.exporter_tooling(exporter_release)
    except ValueError as exc:
        raise c.ExportError(str(exc), reason=c.ExportFailureReason.CONFIGURATION_INVALID,
                            phase=c.ExportPhase.ASSEMBLE) from exc
    if any(ref.path in {f"{output_prefix}/{name}" for name in
                       (c.DOCUMENT_NAME, c.MANIFEST_NAME, c.RESULT_NAME)}
           for ref in verified_inputs.input_inventory):
        _fail("export outputs would overwrite verified inputs", c.ExportFailureReason.IDENTITY_CONFLICT)

    inputs = verified_inputs
    provenance, gate = inputs.provenance, inputs.gate
    timestamp = c.normalize_timestamp(inputs.gate_completed_at)
    product = c.source_product_id(inputs.source.repository_iri, inputs.source.target_snapshot,
                                  provenance.resolved_config_sha256)
    statements: list[dict[str, Any]] = []
    mappings: list[dict[str, Any]] = []
    packages: list[dict[str, Any]] = []
    for finding in inputs.findings:
        identity = None
        if finding.bucket == c.GateBucket.PUBLISHABLE:
            vulnerability = c.vulnerability_id(inputs.source.repository_iri, inputs.source.target_snapshot,
                                               finding.claim_id)
            statement = {
                "version": 1, "vulnerability": {"@id": vulnerability, "name": vulnerability},
                "timestamp": timestamp, "products": [{"@id": product}], "status": c.VexStatus.AFFECTED.value,
                "status_notes": c.STATUS_NOTES, "action_statement": settings.action_statement,
            }
            identity = c.statement_id(settings.author, statement)
            mappings.append({
                "statement_id": identity, "statement_index": len(statements), "vulnerability_id": vulnerability,
                "product_id": product, "finding_package_id": finding.finding_package_id,
                "finding_package": finding.reference.to_json(), "claim_id": finding.claim_id,
                "claim_ledger": c.json_body(gate["inputs"]["claim_ledger"]),
                "projection": c.json_body(gate["inputs"]["projection"]), "settings_sha256": inputs.settings_sha256,
                "evidence_refs": [ref.to_json() for ref in finding.evidence_refs],
            })
            statements.append({"@id": identity, **statement})
        packages.append({
            "finding": c.json_body(finding.projection), "score_refs": [ref.to_json() for ref in finding.score_refs],
            "evidence_refs": [ref.to_json() for ref in finding.evidence_refs],
            "disposition": c.Disposition.INCLUDED.value if identity else c.Disposition.EXCLUDED.value,
            "reason": c.DispositionReason.INCLUDED.value if identity else f"gate_{finding.bucket.value}",
            "statement_id": identity,
        })

    document = None
    document_bytes = None
    document_ref = None
    if statements:
        document = {
            "@context": c.OPENVEX_CONTEXT, "author": settings.author, "timestamp": timestamp,
            "version": 1, "tooling": tooling, "statements": statements,
            **({"role": settings.role} if settings.role else {}),
        }
        document = {"@id": c.document_id(document), **document}
        document_bytes, document_ref = _output(output_prefix, c.DOCUMENT_NAME, document, settings.max_document_bytes)

    gaps = sorted({item["limitation_id"] for item in gate["limitations"] if item["kind"] == "gap"})
    outcome = c.ExportOutcome.EXPORTED_WITH_GAPS if gaps else c.ExportOutcome.EXPORTED
    if not statements:
        outcome = c.ExportOutcome.NO_STATEMENTS
        gaps = sorted({*gaps, c.NO_STATEMENTS_GAP})
    counts = gate["package_counts"]
    included = len(statements)
    excluded = len(inputs.findings) - included
    manifest = {
        "schema": c.OPENVEX_EXPORT_MANIFEST_SCHEMA, "run_id": inputs.run_id, "outcome": outcome.value,
        "disclosure": c.DISCLOSURE,
        "provenance": {
            **provenance.to_json(), "settings_sha256": inputs.settings_sha256,
            "gate_completed_at": timestamp, "timestamp_source": c.TIMESTAMP_SOURCE,
            "exporter_component": c.EXPORTER_COMPONENT, "exporter_release": exporter_release,
            "schema_sha256": c.UPSTREAM_SCHEMA_SHA256, "validation_profile": c.VALIDATION_PROFILE,
            "validation_profile_sha256": c.VALIDATION_PROFILE_SHA256,
        },
        "review_context": {key: c.json_body(gate[key]) for key in _REVIEW_CONTEXT_KEYS},
        "products": [{
            **inputs.source.to_json(), "product_id": product,
            "accepted_manifest": provenance.accepted_manifest.to_json(),
            "resolved_config_sha256": provenance.resolved_config_sha256, "scope_statement": c.STATUS_NOTES,
        }],
        "packages": packages, "statement_mappings": mappings,
        "document": None if document_ref is None else document_ref.to_json(),
        "accounting": {
            "gate_total": counts["total"], "gate_publishable": counts["publishable"],
            "gate_verification_backlog": counts["verification_backlog"], "gate_withheld": counts["withheld"],
            "included_findings": included, "excluded_findings": excluded, "statement_count": included,
            "product_count": 1, "exclusion_counts": {
                "gate_verification_backlog": counts["verification_backlog"], "gate_withheld": counts["withheld"],
            },
        },
        "bindings": [ref.reference.to_json() for ref in inputs.input_inventory],
    }
    manifest_bytes, manifest_ref = _output(output_prefix, c.MANIFEST_NAME, manifest, settings.max_manifest_bytes)
    result = {
        "schema": c.OPENVEX_EXPORT_RESULT_SCHEMA, "run_id": inputs.run_id, "outcome": outcome.value,
        "gate": provenance.gate.to_json(), "manifest": manifest_ref.to_json(),
        "document": None if document_ref is None else document_ref.to_json(), "statement_count": included,
        "included_findings": included, "excluded_findings": excluded, "gaps": gaps,
    }
    result_bytes, result_ref = _output(output_prefix, c.RESULT_NAME, result, c.MAX_RESULT_BYTES)
    return c.ExportBundle(document, manifest, result, document_bytes, manifest_bytes, result_bytes,
                          document_ref, manifest_ref, result_ref)
