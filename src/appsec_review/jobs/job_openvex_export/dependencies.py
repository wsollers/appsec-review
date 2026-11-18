"""Optional dependency OpenVEX companion, confined to admitted producer bytes."""
from __future__ import annotations

from pathlib import Path
import json
from typing import Any

from jsonschema import Draft202012Validator

from .contracts import ExportFailureReason as Reason, VerifiedInputs
from .cve_reachability import project_dependency_advisories_to_openvex
from .inputs import BoundedInputReader, _accepted, _ref, _require
from .settings import OpenVexExportSettings

DEPENDENCY_JOB = "job_dependency_intelligence"
DOCUMENT_NAME = "openvex-dependencies.json"
RESULT_NAME = "openvex-dependencies-result.json"
RESULT_SCHEMA = "appsec-review/openvex-dependencies/1"


def dependency_projection(
    run_root: Path, verified: VerifiedInputs, settings: OpenVexExportSettings,
    repository_root: Path, release: str,
) -> tuple[dict[str, Any] | None, bytes | None]:
    reader = BoundedInputReader(run_root, settings)
    accepted = _accepted(reader, DEPENDENCY_JOB, optional=True)
    if accepted is None:
        return None, None
    _require(accepted.handoff["resolved_config_sha256"] == verified.provenance.resolved_config_sha256,
             "dependency export configuration differs from the certified gate", Reason.IDENTITY_CONFLICT)
    output = accepted.handoff["outputs"]["publication.publish_handoff"]
    raw_ref = output.get("sca_reachability")
    _require(raw_ref is not None, "accepted dependency output omits SCA reachability", Reason.INPUT_MISSING)
    reference = _ref(raw_ref)
    document = reader.json(reference)
    schema_path = repository_root / "docs" / "schemas" / "dependency-intelligence" / "sca-reachability.schema.json"
    Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8"))).validate(document)
    _require(document["source_fingerprint"] == verified.source.target_snapshot,
             "dependency reachability belongs to another target snapshot", Reason.IDENTITY_CONFLICT)
    _require(len(document["advisories"]) <= settings.max_packages,
             "dependency advisory count exceeds the export bound", Reason.BOUND_EXCEEDED)
    # Static import/call matching has no complete executable-path coverage certificate.
    # Do not forward arbitrary coverage flags as authority for a negative VEX statement.
    advisories = []
    for row in document["advisories"]:
        advisory = {key: row.get(key) for key in (
            "advisory_id", "cve_ids", "package_name", "package_version", "purl", "ecosystem")}
        advisory["reachability"] = (
            "symbol_reachable" if row["reachability"] == "symbol_reachable" and row["call_sites"] else "unknown")
        advisory["coverage_complete"] = False
        advisories.append(advisory)
    bundle = project_dependency_advisories_to_openvex(
        advisories, author=settings.author, role=settings.role, timestamp=verified.gate_completed_at,
        product_id=verified.source.repository_iri, exporter_release=release,
        default_action_statement=settings.action_statement,
        run_has_coverage_gaps=any(row["kind"] == "gap" for row in verified.gate["limitations"])
        or bool(document.get("gaps")) or bool(output.get("gaps")),
    )
    reader.reprove()
    _require(bundle.document_bytes is None or len(bundle.document_bytes) <= settings.max_document_bytes,
             "dependency OpenVEX document exceeds its byte bound", Reason.BOUND_EXCEEDED)
    result = {
        "schema": RESULT_SCHEMA, "run_id": verified.run_id,
        "source": {"handoff": {"path": accepted.path, "sha256": accepted.sha256},
                   "artifact": reference.to_json(), "gate": verified.provenance.gate.to_json()},
        "statements_by_status": bundle.statements_by_status,
        "gaps": list(bundle.gaps),
        "terminal_status": "COMPLETED_WITH_GAPS" if bundle.gaps else "SUCCEEDED",
    }
    return result, bundle.document_bytes
