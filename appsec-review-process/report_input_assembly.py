#!/usr/bin/env python3
"""Assemble a hash-bound, prose-free input manifest for draft report synthesis."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from execution_state import Blocked, atomic_json, digest, file_hash, read_json, tree_hashes
from publish_job_output import ACCEPTED_SCHEMA
from schema_validate import validate_document
from worker_result import validate_worker_result
import tool_evidence

JOB = "10-report-input-assembly"
CONTRACT = "report-synthesis-input"
RESULT = "synthesis-input.json"
HASH = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
PROHIBITED = frozenset({"finding", "findings", "runtime_state", "observed_runtime",
                        "compliance", "certification", "remediation_status"})

SPECS = {
    "component": ("01-component-characterization", "component-map", "component-purpose-map.json",
                  "component-purpose-map.schema.json", ()),
    "threat": ("03-threat-model-dfd-stride", "threat-model-core", "integrated-threat-model.json",
               "integrated-threat-model.schema.json", ()),
    "owasp": ("04-owasp-join-report", "owasp-join-report", "owasp-control-status-matrix.json",
              "owasp-control-status-matrix.schema.json",
              (("owasp-coverage-gaps.json", "owasp-coverage-gaps-report.schema.json"),
               ("owasp-candidate-promotion-routes.json", "owasp-candidate-promotion-routes.schema.json"))),
    # The final ledger: L01 admissions plus the accepted 07/08/09 decisions (claim_ledger_final.py).
    "ledger": ("claim-ledger-final", "claim-ledger-final", "claim-decision-ledger.json",
               "claim-decision-ledger.schema.json", ()),
    "verification": ("09-independent-verification", "09-independent-verification",
                     "independent-verification.json", "09-independent-verification.schema.json", ()),
    "scoring": ("12-scoring-prioritization", "12-scoring-prioritization",
                "scoring-prioritization.json", "scoring-prioritization.schema.json", ()),
}
RECEIPTS = ("permission.json", "lineage.json")
# 04 publishes its matrix paginated behind a manifest (owasp_join_publisher._partition_matrix); a
# legacy single-file matrix is still accepted. Pages are reassembled into the same logical document.
MATRIX_MANIFEST = "owasp-control-status-matrix-manifest.json"
PAGE_DIRECTORY = "owasp-control-status-matrix-pages"
PAGINATED = {"owasp": (MATRIX_MANIFEST, "owasp-control-status-matrix-manifest.schema.json",
                       "owasp-control-status-matrix-page.schema.json")}
# Producers that emit no permission/lineage receipts (01's contract has none). Their generation is
# bound from the primary artifact's own source/lineage fields against the attempt's hash-bound
# inputs.json; the absent permission record reaches the report as a named gap.
RECEIPTLESS = frozenset({"component"})
RECEIPT_GAP = ("REPORT-GAP component-receipts-absent: 01-component-characterization publishes no "
               "permission or lineage receipt; its source generation is bound from "
               "component-purpose-map.json (source_snapshot_sha256, evidence_manifest_lineage) and the "
               "attempt's inputs.json, and no producer permission record exists for it.")

CANONICAL_PERMISSIONS = {
    "01-component-characterization": ["read-source", "read-run-data", "write-run-data"],
    "03-threat-model-dfd-stride": ["read-source", "read-run-data", "write-run-data"],
    "04-owasp-join-report": ["read-run-data", "write-run-data"],
    "claim-ledger-routing": ["read-run-data", "write-run-data"],
    "claim-ledger-final": ["read-run-data", "write-run-data"],
    "07-red-team-adversarial": ["read-run-data", "write-run-data"],
    "08-blue-team-refutation": ["read-run-data", "write-run-data"],
    "09-independent-verification": ["read-run-data", "write-run-data"],
    "12-scoring-prioritization": ["read-run-data", "write-run-data"],
}

DECISION_PRODUCERS = {
    "07-red-team-adversarial": ("07-red-team-adversarial", "red-team-adversarial.json",
        "07-red-team-adversarial.schema.json", "hypotheses", "reviewer", "red-team-adversary"),
    "08-blue-team-refutation": ("08-blue-team-refutation", "blue-team-refutation.json",
        "08-blue-team-refutation.schema.json", "reviews", "blue_reviewer", "blue-team-refuter"),
    "09-independent-verification": ("09-independent-verification", "independent-verification.json",
        "09-independent-verification.schema.json", "verifications", "verifier", "independent-verifier"),
}
# The decision's own citations, which claim_ledger.build_ledger merges into the entry it appends.
DECISION_CITATIONS = {"07-red-team-adversarial": "review_citations",
                      "08-blue-team-refutation": "refutation_citations",
                      "09-independent-verification": "verification_citations"}

DECISION_OUTCOMES = {
    "07-red-team-adversarial": {"HYPOTHESIS": "under_review"},
    "08-blue-team-refutation": {"SURVIVING": "narrowed", "REFUTED": "refuted",
                                 "UNRESOLVED": "unresolved"},
    "09-independent-verification": {"VERIFIED": "verified", "REFUTED": "refuted",
                                      "UNRESOLVED": "unresolved", "BLOCKED": "unresolved"},
}


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def _relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str):
        raise Blocked(f"{JOB}: artifact path is not a string")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise Blocked(f"{JOB}: artifact path is not canonical and relative")
    return path


def _plain_directory(owner: Path, path: Path) -> Path:
    try:
        relative = path.relative_to(owner)
        path.resolve(strict=True).relative_to(owner.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise Blocked(f"{JOB}: immutable attempt escapes its canonical root") from exc
    cursor = owner
    if cursor.is_symlink() or not cursor.is_dir():
        raise Blocked(f"{JOB}: producer root is not a real directory")
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink() or not cursor.is_dir():
            raise Blocked(f"{JOB}: immutable attempt traverses a linked directory")
    return path


def _owned(attempt: Path, relative: str) -> Path:
    rel = _relative(relative)
    path = attempt.joinpath(*rel.parts)
    try:
        path.resolve(strict=True).relative_to(attempt.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise Blocked(f"{JOB}: artifact escapes its immutable attempt") from exc
    cursor = attempt
    for part in rel.parts:
        cursor /= part
        if cursor.is_symlink():
            raise Blocked(f"{JOB}: artifact traverses a symbolic link")
    if not path.is_file():
        raise Blocked(f"{JOB}: required artifact is missing")
    return path


def _receipt(value: Any, *, schema: str, run_id: str, job_id: str) -> None:
    required = {"schema", "run_id", "job_id", "source_snapshot_sha256"}
    if (not isinstance(value, dict) or not required <= set(value) or value.get("schema") != schema or
            value.get("run_id") != run_id or value.get("job_id") != job_id or
            not HASH.fullmatch(str(value.get("source_snapshot_sha256", "")))):
        raise Blocked(f"{JOB}: producer receipt identity is invalid")
    if schema.endswith("permission-receipt/1.0"):
        if (set(value) != required | {"permissions"} or
                value.get("permissions") != CANONICAL_PERMISSIONS.get(job_id)):
            raise Blocked(f"{JOB}: permission receipt shape is invalid")
    elif set(value) != required | {"build_lineage_sha256"} or not HASH.fullmatch(
            str(value.get("build_lineage_sha256", ""))):
        raise Blocked(f"{JOB}: lineage receipt shape is invalid")


def load_accepted(pointer_path: Path, *, run_id: str, name: str) -> dict[str, Any]:
    """Revalidate one exact common accepted result, its receipts, and required artifacts."""
    job_id, contract, primary, primary_schema, supporting = SPECS[name]
    pointer_path = Path(pointer_path)
    base = pointer_path.parent
    if base.is_symlink() or not base.is_dir() or pointer_path.is_symlink() or not pointer_path.is_file():
        raise Blocked(f"{JOB}: accepted pointer root is unsafe")
    pointer = read_json(pointer_path)
    pointer_keys = {"schema", "status", "run_id", "job", "attempt_id", "fingerprint",
                    "envelope_path", "envelope_sha256", "hashes", "accepted_at"}
    if (not isinstance(pointer, dict) or set(pointer) != pointer_keys or
            pointer.get("schema") != ACCEPTED_SCHEMA or pointer.get("status") not in {"OK", "OK_WITH_GAPS"} or
            pointer.get("run_id") != run_id or pointer.get("job") != job_id or
            pointer.get("envelope_path") != "result.json"):
        raise Blocked(f"{JOB}: accepted pointer identity or closed shape is invalid")
    latest_path = base / "latest.json"
    if latest_path.is_symlink() or not latest_path.is_file() or read_json(latest_path).get("attempt_id") != pointer["attempt_id"]:
        raise Blocked(f"{JOB}: accepted pointer is stale")
    attempts = _plain_directory(base, base / "attempts")
    attempt = _plain_directory(attempts, attempts / pointer["attempt_id"])
    try:
        hashes = tree_hashes(attempt)
    except (OSError, ValueError) as exc:
        raise Blocked(f"{JOB}: immutable attempt tree is unsafe") from exc
    if hashes != pointer["hashes"]:
        raise Blocked(f"{JOB}: immutable attempt tree changed")
    envelope_path = _owned(attempt, "result.json")
    envelope = read_json(envelope_path)
    if (file_hash(envelope_path) != pointer["envelope_sha256"] or validate_worker_result(envelope) or
            envelope.get("run_id") != run_id or envelope.get("job_id") != job_id or
            envelope.get("attempt_id") != pointer["attempt_id"] or
            envelope.get("input_fingerprint") != pointer["fingerprint"] or
            envelope.get("execution_status") != pointer["status"] or
            envelope.get("acceptance_status") != "CURRENT" or envelope.get("output_contract") != contract):
        raise Blocked(f"{JOB}: accepted result envelope is invalid")
    artifacts = {item.get("path"): item for item in envelope.get("artifacts", [])}
    if len(artifacts) != len(envelope.get("artifacts", [])):
        raise Blocked(f"{JOB}: result envelope has duplicate artifact paths")
    for relative, item in artifacts.items():
        if not isinstance(relative, str) or file_hash(_owned(attempt, relative)) != item.get("sha256"):
            raise Blocked(f"{JOB}: accepted artifact hash is invalid")
    published = PAGINATED[name][0] if name in PAGINATED and primary not in artifacts else primary
    receiptless = name in RECEIPTLESS and not any(item in artifacts for item in RECEIPTS)
    required = [published, *(() if receiptless else RECEIPTS), *(item[0] for item in supporting)]
    if any(item not in artifacts for item in required):
        raise Blocked(f"{JOB}: required report input or receipt is absent")
    documents = {}
    for relative, schema in ((primary, primary_schema), *supporting):
        document = (reassemble_matrix(attempt, artifacts, run_id) if relative == primary != published
                    else read_json(_owned(attempt, relative)))
        try:
            schema_errors = validate_document(document, schema) if schema else []
        except (FileNotFoundError, ValueError) as exc:
            raise Blocked(f"{JOB}: authoritative {name} schema is unavailable") from exc
        if schema_errors:
            raise Blocked(f"{JOB}: accepted {name} artifact fails its closed schema")
        documents[relative] = document
    if receiptless:
        receipt_hashes = (None, None)
        source = _receiptless_generation(attempt, envelope, documents[primary], run_id=run_id, job_id=job_id)
    else:
        permission_path, lineage_path = _owned(attempt, "permission.json"), _owned(attempt, "lineage.json")
        permission, lineage = read_json(permission_path), read_json(lineage_path)
        _receipt(permission, schema="appsec-review/producer-permission-receipt/1.0", run_id=run_id, job_id=job_id)
        _receipt(lineage, schema="appsec-review/producer-lineage-receipt/1.0", run_id=run_id, job_id=job_id)
        if permission["source_snapshot_sha256"] != lineage["source_snapshot_sha256"]:
            raise Blocked(f"{JOB}: producer receipts bind different source generations")
        receipt_hashes = ("sha256:" + file_hash(permission_path), "sha256:" + file_hash(lineage_path))
        source = permission["source_snapshot_sha256"]
    reference = {"job_id": job_id, "attempt_id": pointer["attempt_id"], "contract_id": contract,
        "artifact_path": published, "artifact_sha256": "sha256:" + file_hash(attempt / published),
        "accepted_pointer_sha256": "sha256:" + file_hash(pointer_path),
        "permission_receipt_sha256": receipt_hashes[0], "lineage_receipt_sha256": receipt_hashes[1],
        "supporting_artifacts": [{"artifact_path": relative,
            "artifact_sha256": "sha256:" + file_hash(attempt / relative), "schema": schema}
            for relative, schema in supporting]}
    return {"reference": reference, "documents": documents, "source_generation": source}


def reassemble_matrix(attempt: Path, artifacts: dict[str, Any], run_id: str) -> dict[str, Any]:
    """Rebuild 04's logical matrix from its manifest and envelope-bound pages, exactly as split."""
    manifest_name, manifest_schema, page_schema = PAGINATED["owasp"]
    manifest = read_json(_owned(attempt, manifest_name))
    if validate_document(manifest, manifest_schema) or manifest.get("run_id") != run_id:
        raise Blocked(f"{JOB}: OWASP matrix manifest fails its closed schema or run identity")
    rows, listed = [], set()
    for index, record in enumerate(manifest["pages"]):
        path = record["path"]; listed.add(path)
        if (record["page_index"] != index or path != f"{PAGE_DIRECTORY}/page-{index:04d}.json" or
                path not in artifacts or record["first_row_index"] != len(rows) or
                record["last_row_index"] != len(rows) + record["row_count"] - 1):
            raise Blocked(f"{JOB}: OWASP matrix page is absent or out of order")
        data = _owned(attempt, path).read_bytes()
        if (len(data) != record["byte_size"] or hashlib.sha256(data).hexdigest() != record["sha256"] or
                artifacts[path].get("sha256") != record["sha256"]):
            raise Blocked(f"{JOB}: OWASP matrix page hash or size differs from its manifest")
        page = json.loads(data)
        if (validate_document(page, page_schema) or page.get("run_id") != run_id or
                page.get("selection_id") != manifest["selection_id"] or page.get("page_index") != index or
                page.get("first_row_index") != record["first_row_index"] or
                page.get("last_row_index") != record["last_row_index"] or
                page.get("row_count") != record["row_count"] or len(page.get("rows", [])) != record["row_count"]):
            raise Blocked(f"{JOB}: OWASP matrix page fails its schema or manifest identity")
        rows.extend(page["rows"])
    if any(path.startswith(PAGE_DIRECTORY + "/") and path not in listed for path in artifacts):
        raise Blocked(f"{JOB}: OWASP matrix publishes a page its manifest does not list")
    matrix = {**manifest["matrix_header"], "rows": rows}
    if (len(rows) != manifest["row_count"] or digest(rows) != manifest["rows_sha256"] or
            digest(matrix) != manifest["logical_matrix_sha256"] or
            matrix.get("schema") != manifest["logical_matrix_schema"] or
            matrix.get("run_id") != run_id or matrix.get("selection_id") != manifest["selection_id"]):
        raise Blocked(f"{JOB}: OWASP matrix pages do not reconstruct the published logical matrix")
    return matrix


def _receiptless_generation(attempt: Path, envelope: dict[str, Any], document: dict[str, Any], *,
                            run_id: str, job_id: str) -> str:
    """Source generation of a receipt-less producer: the artifact's own source and lineage fields must
    match the attempt's inputs.json, bound by the pointer's tree hashes and the envelope fingerprint."""
    inputs = read_json(_owned(attempt, "inputs.json"))
    evidence = inputs.get("evidence") if isinstance(inputs, dict) else None
    lineage = document.get("evidence_manifest_lineage")
    source = document.get("source_snapshot_sha256")
    if (not isinstance(evidence, dict) or not isinstance(lineage, dict) or
            _sha(inputs) != envelope.get("input_fingerprint") or
            inputs.get("run_id") != run_id or inputs.get("job") != job_id or
            not HASH.fullmatch(str(source)) or inputs.get("source_snapshot_sha256") != source or
            lineage.get("producer_attempt_id") != evidence.get("attempt_id") or
            lineage.get("accepted_pointer_sha256") != "sha256:" + str(evidence.get("pointer_sha256"))):
        raise Blocked(f"{JOB}: receipt-less {job_id} artifact does not bind its attempt's source generation")
    return source


def _reject_promotions(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower().replace("-", "_") in PROHIBITED and item not in (False, None, [], {}):
                raise Blocked(f"{JOB}: unsupported promotion at {path}.{key}")
            _reject_promotions(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_promotions(item, f"{path}[{index}]")


def _validate_ledger(ledger: dict[str, Any]) -> dict[str, dict[str, Any]]:
    keys = {"schema", "run_id", "job_id", "attempt_id", "source_generation", "component_generation",
            "entries", "head_hash", "claim_states", "claim_limits"}
    limits = {"candidate_only": True, "finding_created": False, "severity_assigned": False,
              "runtime_claimed": False, "compliance_claimed": False}
    if (not isinstance(ledger, dict) or set(ledger) != keys or
            ledger.get("schema") != "appsec-review/claim-decision-ledger/1.0" or
            ledger.get("job_id") != "claim-ledger-routing" or ledger.get("claim_limits") != limits or
            not isinstance(ledger.get("entries"), list) or not ledger["entries"]):
        raise Blocked(f"{JOB}: claim ledger shape or claim ceiling is invalid")
    transitions = {"candidate": {"under_review", "unresolved", "superseded"},
        "under_review": {"narrowed", "verified", "refuted", "unresolved", "superseded"},
        "narrowed": {"under_review", "verified", "refuted", "unresolved", "superseded"},
        "unresolved": {"under_review", "verified", "refuted", "narrowed", "superseded"},
        "verified": {"superseded"}, "refuted": {"superseded"}, "superseded": set()}
    previous, latest, events = None, {}, set()
    for sequence, entry in enumerate(ledger["entries"]):
        if (not isinstance(entry, dict) or entry.get("sequence") != sequence or
                entry.get("event_id") in events or entry.get("previous_entry_hash") != previous or
                entry.get("entry_hash") != _sha({key: value for key, value in entry.items() if key != "entry_hash"}) or
                entry.get("source_generation") != ledger["source_generation"] or
                entry.get("component_generation") != ledger["component_generation"]):
            raise Blocked(f"{JOB}: claim ledger chain or generation is invalid")
        prior = latest.get(entry.get("claim_id"))
        if entry.get("event_type") == "candidate_admitted":
            if prior is not None or entry.get("from_status") is not None or entry.get("status") != "candidate":
                raise Blocked(f"{JOB}: invalid or duplicate candidate admission")
        elif (entry.get("event_type") != "status_decision" or prior is None or
              entry.get("from_status") != prior.get("status") or
              entry.get("status") not in transitions.get(prior.get("status"), set()) or
              entry.get("route_id") != prior.get("route_id")):
            raise Blocked(f"{JOB}: unsupported claim status transition")
        authority = entry.get("decision_authority")
        if entry.get("status") == "verified" and (not isinstance(authority, dict) or
                authority.get("job_id") != "09-independent-verification" or
                (authority.get("job_id"), authority.get("attempt_id")) ==
                (entry.get("producer", {}).get("job_id"), entry.get("producer", {}).get("attempt_id"))):
            raise Blocked(f"{JOB}: verified ledger state lacks independent authority")
        events.add(entry["event_id"]); previous = entry["entry_hash"]; latest[entry["claim_id"]] = entry
    states = [{"claim_id": key, "latest_event_id": latest[key]["event_id"], "status": latest[key]["status"]}
              for key in sorted(latest)]
    if ledger["head_hash"] != previous or ledger["claim_states"] != states:
        raise Blocked(f"{JOB}: claim ledger head or state projection is invalid")
    graph = {key: set(value.get("causal_claim_ids", [])) for key, value in latest.items()}
    if any(not children <= set(graph) for children in graph.values()):
        raise Blocked(f"{JOB}: ledger causal identity does not resolve")
    def visit(node: str, trail: set[str]) -> None:
        if node in trail: raise Blocked(f"{JOB}: circular claim lineage")
        for child in graph[node]: visit(child, trail | {node})
    for claim_id in graph: visit(claim_id, set())
    return latest


def _lifecycle_origin(ledger: dict[str, Any]) -> tuple[str, str]:
    """Return the immutable L01 head consumed by lifecycle stages, before decisions append."""
    first_decision = next((index for index, entry in enumerate(ledger["entries"])
                           if entry["event_type"] == "status_decision"), None)
    if first_decision is None or first_decision == 0:
        raise Blocked(f"{JOB}: final ledger has no lifecycle decision chain")
    if any(entry["event_type"] != "status_decision" for entry in ledger["entries"][first_decision:]):
        raise Blocked(f"{JOB}: candidate admission appears after lifecycle decisions")
    origin = ledger["entries"][first_decision - 1]
    return origin["event_id"], origin["entry_hash"]


def _verify_decision_authority(jobs_root: Path, run_id: str, entry: dict[str, Any],
                               source_generation: str, component_generation: str,
                               prior: dict[str, Any]) -> None:
    """Re-derive one appended decision from its producer's exact accepted attempt; ``prior`` is the
    claim's previous ledger entry."""
    authority = entry.get("decision_authority")
    expected_keys = {"contract_id", "job_id", "attempt_id", "role_id", "source_generation",
        "component_generation", "accepted_pointer_sha256", "envelope_sha256", "artifact_path",
        "artifact_sha256", "permission_receipt_path", "permission_receipt_sha256", "reason"}
    if not isinstance(authority, dict) or set(authority) != expected_keys:
        raise Blocked(f"{JOB}: lifecycle decision authority shape is invalid")
    job_id = authority.get("job_id")
    if job_id not in DECISION_PRODUCERS:
        raise Blocked(f"{JOB}: lifecycle decision authority job is unsupported")
    contract, artifact, schema, collection, actor_field, role = DECISION_PRODUCERS[job_id]
    if (authority.get("contract_id") != contract or authority.get("artifact_path") != artifact or
            authority.get("permission_receipt_path") != "permission.json" or
            authority.get("role_id") != role or authority.get("source_generation") != source_generation or
            authority.get("component_generation") != component_generation):
        raise Blocked(f"{JOB}: lifecycle decision authority identity is invalid")
    producer_root = _plain_directory(jobs_root, jobs_root / job_id)
    pointer_path = _owned(producer_root, "accepted.json")
    pointer = read_json(pointer_path)
    pointer_keys = {"schema", "status", "run_id", "job", "attempt_id", "fingerprint",
                    "envelope_path", "envelope_sha256", "hashes", "accepted_at"}
    if (not isinstance(pointer, dict) or set(pointer) != pointer_keys or
            pointer.get("schema") != ACCEPTED_SCHEMA or pointer.get("status") not in {"OK", "OK_WITH_GAPS"} or
            pointer.get("run_id") != run_id or pointer.get("job") != job_id or
            pointer.get("attempt_id") != authority.get("attempt_id") or
            pointer.get("envelope_path") != "result.json" or
            "sha256:" + file_hash(pointer_path) != authority.get("accepted_pointer_sha256")):
        raise Blocked(f"{JOB}: lifecycle decision accepted pointer is invalid")
    latest = _owned(producer_root, "latest.json")
    if read_json(latest).get("attempt_id") != pointer["attempt_id"]:
        raise Blocked(f"{JOB}: lifecycle decision accepted pointer is stale")
    attempts = _plain_directory(producer_root, producer_root / "attempts")
    attempt = _plain_directory(attempts, attempts / pointer["attempt_id"])
    if tree_hashes(attempt) != pointer["hashes"]:
        raise Blocked(f"{JOB}: lifecycle decision immutable attempt changed")
    envelope_path = _owned(attempt, "result.json")
    envelope = read_json(envelope_path)
    if (file_hash(envelope_path) != pointer["envelope_sha256"] or
            "sha256:" + file_hash(envelope_path) != authority.get("envelope_sha256") or
            validate_worker_result(envelope) or envelope.get("run_id") != run_id or
            envelope.get("job_id") != job_id or envelope.get("attempt_id") != pointer["attempt_id"] or
            envelope.get("input_fingerprint") != pointer["fingerprint"] or
            envelope.get("execution_status") != pointer["status"] or
            envelope.get("acceptance_status") != "CURRENT" or envelope.get("output_contract") != contract):
        raise Blocked(f"{JOB}: lifecycle decision envelope is invalid")
    artifacts = {item.get("path"): item for item in envelope.get("artifacts", [])}
    if len(artifacts) != len(envelope.get("artifacts", [])) or artifact not in artifacts or "permission.json" not in artifacts:
        raise Blocked(f"{JOB}: lifecycle decision artifacts are incomplete")
    artifact_path, permission_path = _owned(attempt, artifact), _owned(attempt, "permission.json")
    if (file_hash(artifact_path) != artifacts[artifact].get("sha256") or
            "sha256:" + file_hash(artifact_path) != authority.get("artifact_sha256") or
            file_hash(permission_path) != artifacts["permission.json"].get("sha256") or
            "sha256:" + file_hash(permission_path) != authority.get("permission_receipt_sha256")):
        raise Blocked(f"{JOB}: lifecycle decision authority hash binding is invalid")
    _receipt(read_json(permission_path), schema="appsec-review/producer-permission-receipt/1.0",
             run_id=run_id, job_id=job_id)
    document = read_json(artifact_path)
    try:
        errors = validate_document(document, schema)
    except (FileNotFoundError, ValueError) as exc:
        raise Blocked(f"{JOB}: lifecycle decision schema is unavailable") from exc
    rows = [row for row in document.get(collection, []) if row.get("claim_id") == entry.get("claim_id")]
    actor = rows[0].get(actor_field) if len(rows) == 1 else None
    row = rows[0] if len(rows) == 1 else {}
    inherited = ("route_id", "claim_class", "hypothesis", "confidence", "component_ids",
        "source_generation", "component_generation", "producer", "causal_claim_ids", "supersedes_claim_id")
    expected_status = DECISION_OUTCOMES[job_id].get(row.get("status"))
    # claim_ledger.build_ledger appends the claim's prior citations merged with this decision's own
    # (first occurrence kept, identical ids coalesced) and the sorted union of prior and row dissent.
    citations, seen = [], {}
    for citation in [*prior.get("citations", []), *(row.get(DECISION_CITATIONS[job_id]) or [])]:
        key = citation.get("citation_id") if isinstance(citation, dict) else None
        if key in seen:
            if seen[key] != citation: citations = None; break
            continue
        seen[key] = citation; citations.append(citation)
    row_citations = row.get("citations") if isinstance(row.get("citations"), list) else None
    dissent = row.get("dissent_ids") if isinstance(row.get("dissent_ids"), list) else None
    if (errors or not isinstance(actor, dict) or actor.get("job_id") != job_id or
            actor.get("attempt_id") != pointer["attempt_id"] or actor.get("role_id") != role or
            actor.get("source_generation") != source_generation or
            actor.get("component_generation") != component_generation or
            expected_status != entry.get("status") or
            any(row.get(field) != entry.get(field) for field in inherited) or
            citations is None or entry.get("citations") != citations or row_citations is None or
            entry["citations"][:len(row_citations)] != row_citations or dissent is None or
            entry.get("dissent_ids") != sorted(set(prior.get("dissent_ids", [])) | set(dissent))):
        raise Blocked(f"{JOB}: lifecycle decision artifact does not support its authority")


# Reviewer judgment carried on 09/12 records (ADR-0020/0026; the closed record schemas allow them).
JUDGMENT_KEYS = frozenset({"cwe_judgments", "mitre_refs", "cvss_v4", "remediation_proposal"})


def _records(document: dict[str, Any], key: str, stage: str, record_keys: set[str],
             optional: frozenset[str] = frozenset()) -> dict[str, dict[str, Any]]:
    top_keys = {"schema", "run_id", "stage", "ledger_head_id", "ledger_head_sha256",
                "upstream", "claim_boundary", key}
    if (set(document) != top_keys or document.get("stage") != stage or
            document.get("claim_boundary") != "DECISION_RECORD_NOT_RUNTIME_OR_COMPLIANCE_PROOF" or
            not isinstance(document.get(key), list)):
        raise Blocked(f"{JOB}: {stage} result shape is invalid")
    result = {}
    for row in document[key]:
        claim_id = row.get("claim_id") if isinstance(row, dict) else None
        if not isinstance(claim_id, str) or claim_id in result or not record_keys <= set(row) <= record_keys | optional:
            raise Blocked(f"{JOB}: duplicate or invalid downstream claim identity")
        result[claim_id] = row
    return result


def _artifact_identity(citation: dict[str, Any]) -> tuple[str, str, str, str]:
    fields = (citation.get("producer_job_id"), citation.get("producer_attempt_id"),
              citation.get("artifact_path"), citation.get("artifact_sha256"))
    if not all(isinstance(item, str) and item for item in fields[:3]) or not HASH.fullmatch(str(fields[3])):
        raise Blocked(f"{JOB}: cited evidence identity is incomplete")
    return fields  # type: ignore[return-value]


def _verify_tool_evidence(jobs_root: Path, run_id: str, identity: tuple[str, str, str, str],
                          citation: dict[str, Any] | None) -> dict[str, str]:
    """A structural record (ADR-0035) under the run's ``data/tool-evidence/``: the cited object must be the
    canonical citation of an untampered record whose query still re-runs to the recorded answer."""
    if citation is None:
        raise Blocked(f"{JOB}: tool-evidence citation has no citation object")
    try:
        canonical = tool_evidence.verify_citation(run_id, citation, data_root=jobs_root.resolve(strict=True).parent)
    except (ValueError, OSError) as exc:
        raise Blocked(f"{JOB}: cited tool evidence is invalid ({str(exc)[:300]})") from None
    if (canonical["producer_job_id"], canonical["producer_attempt_id"], canonical["artifact_path"],
            canonical["artifact_sha256"]) != identity:
        raise Blocked(f"{JOB}: cited tool evidence contradicts its producer identity")
    return {"producer_job_id": identity[0], "producer_attempt_id": identity[1],
            "artifact_path": identity[2], "artifact_sha256": identity[3]}


def _verify_citation(jobs_root: Path, identity: tuple[str, str, str, str], *, run_id: str | None = None,
                     citation: dict[str, Any] | None = None) -> dict[str, str]:
    job, attempt_id, relative, expected = identity
    if relative.startswith(tool_evidence.FOLDER + "/"):
        return _verify_tool_evidence(Path(jobs_root), str(run_id), identity, citation)
    path = PurePosixPath(relative)
    parts = path.parts
    if len(parts) >= 6 and parts[:2] == ("data", "jobs") and parts[3] == "attempts":
        if parts[2] != job or parts[4] != attempt_id:
            raise Blocked(f"{JOB}: citation path contradicts its producer identity")
        relative = "/".join(parts[5:])
    jobs_root = jobs_root.resolve(strict=True)
    producer_root = _plain_directory(jobs_root, jobs_root / job)
    if not (producer_root / "attempts").is_dir() and (producer_root / "whole" / "attempts").is_dir():
        # Scope-partitioned producers (e.g. 02-secrets-inventory) publish under <job>/whole.
        producer_root = _plain_directory(jobs_root, producer_root / "whole")
    attempts_root = _plain_directory(producer_root, producer_root / "attempts")
    attempt_root = _plain_directory(attempts_root, attempts_root / attempt_id)
    actual = "sha256:" + file_hash(_owned(attempt_root, relative))
    if actual.removeprefix("sha256:") != expected.removeprefix("sha256:"):
        raise Blocked(f"{JOB}: cited evidence bytes changed")
    return {"producer_job_id": job, "producer_attempt_id": attempt_id,
            "artifact_path": relative, "artifact_sha256": actual}


def assemble(run_id: str, loaded: dict[str, dict[str, Any]], jobs_root: Path) -> dict[str, Any]:
    if set(loaded) != set(SPECS):
        raise Blocked(f"{JOB}: exact producer set is required")
    component = loaded["component"]["documents"][SPECS["component"][2]]
    threat = loaded["threat"]["documents"][SPECS["threat"][2]]
    matrix = loaded["owasp"]["documents"][SPECS["owasp"][2]]
    gaps = loaded["owasp"]["documents"][SPECS["owasp"][4][0][0]]
    routes = loaded["owasp"]["documents"][SPECS["owasp"][4][1][0]]
    ledger = loaded["ledger"]["documents"][SPECS["ledger"][2]]
    verification = loaded["verification"]["documents"][SPECS["verification"][2]]
    scoring = loaded["scoring"]["documents"][SPECS["scoring"][2]]
    for document in (component, threat, matrix, gaps, routes, ledger, verification, scoring):
        if document.get("run_id", run_id) != run_id:
            raise Blocked(f"{JOB}: producer run identity is mixed")
    latest = _validate_ledger(ledger)
    source_generation, component_generation = ledger["source_generation"], ledger["component_generation"]
    origin_head_id, origin_head_sha256 = _lifecycle_origin(ledger)
    previous: dict[str, dict[str, Any]] = {}
    for entry in ledger["entries"]:
        if entry["event_type"] == "status_decision":
            _verify_decision_authority(Path(jobs_root), run_id, entry, source_generation, component_generation,
                                       previous[entry["claim_id"]])
        previous[entry["claim_id"]] = entry
    if (component.get("source_snapshot_sha256") != source_generation or
            loaded["component"]["reference"]["attempt_id"] != component_generation or
            threat.get("source_snapshot") != source_generation or
            threat.get("component_map_attempt_id") != component_generation or
            any(value["source_generation"] != source_generation for value in loaded.values())):
        raise Blocked(f"{JOB}: stale or mixed source/component generation")
    if not (matrix.get("selection_id") == gaps.get("selection_id") == routes.get("selection_id")):
        raise Blocked(f"{JOB}: OWASP report artifacts have mixed selections")
    if matrix.get("claim_limits") != {"finding_created": False, "severity_assigned": False,
            "runtime_state_claimed": False, "compliance_certified": False,
            "status_upgrade_permitted": False} or routes.get("finding_promotion") != "not_performed":
        raise Blocked(f"{JOB}: OWASP candidate ceiling is invalid")
    matrix_rows = matrix.get("rows", [])
    denominators = matrix.get("denominators", {})
    assessed_statuses = {"satisfied", "partially_satisfied", "not_satisfied", "cannot_verify",
                         "dynamic_test_required", "human_decision_required"}
    expected_denominators = {"selected": len(matrix_rows),
        "applicable": sum(row.get("applicability_status") in {"applicable", "conditional"}
                          for row in matrix_rows),
        "assessed": sum(row.get("applicability_status") in {"applicable", "conditional"} and
                        row.get("joined_status") in assessed_statuses for row in matrix_rows),
        "satisfied": sum(row.get("joined_status") == "satisfied" for row in matrix_rows)}
    row_ids = [row.get("row_index") for row in matrix_rows]
    gap_ids = [row.get("gap_id") for row in gaps.get("gaps", [])]
    route_ids = [row.get("route_id") for row in routes.get("routes", [])]
    if (denominators != expected_denominators or len(row_ids) != len(set(row_ids)) or
            len(gap_ids) != len(set(gap_ids)) or len(route_ids) != len(set(route_ids))):
        raise Blocked(f"{JOB}: OWASP denominators or record identities are invalid")
    verification_keys = {"claim_id", "route_id", "claim_class", "hypothesis", "confidence",
        "component_ids", "component_generation", "source_generation", "producer", "citations",
        "proof_obligations", "dissent_ids", "causal_claim_ids", "supersedes_claim_id",
        "hypothesis_id", "status", "red_reviewer", "blue_reviewer", "verifier",
        "verification_method", "verification_citations"}
    scoring_keys = {"claim_id", "route_id", "claim_class", "hypothesis", "confidence",
        "component_ids", "component_generation", "source_generation", "producer", "citations",
        "proof_obligations", "dissent_ids", "causal_claim_ids", "supersedes_claim_id",
        "verification_status", "verifier", "verification_citations", "score", "severity",
        "priority", "factors", "scoring_rationale"}
    verifications = _records(verification, "verifications", "09-independent-verification", verification_keys,
                             JUDGMENT_KEYS & {"cwe_judgments", "mitre_refs"})
    priorities = _records(scoring, "priorities", "12-scoring-prioritization", scoring_keys, JUDGMENT_KEYS)
    if (verification.get("ledger_head_id") != origin_head_id or
            verification.get("ledger_head_sha256") != origin_head_sha256 or
            scoring.get("ledger_head_id") != origin_head_id or
            scoring.get("ledger_head_sha256") != origin_head_sha256 or
            set(verifications) != set(priorities) or set(verifications) != set(latest)):
        raise Blocked(f"{JOB}: decision results do not bind the exact ledger head")
    citations, structural = {}, {}   # structural: every distinct tev: citation object -> its identity (ADR-0035)
    for entry in ledger["entries"]:
        for citation in entry.get("citations", []):
            identity = _artifact_identity(citation)
            if tool_evidence.is_citation(citation):
                structural[json.dumps(citation, sort_keys=True)] = identity
            prior = citations.setdefault(citation.get("citation_id"), identity)
            if not citation.get("citation_id") or prior != identity:
                raise Blocked(f"{JOB}: duplicate citation id is contradictory")
    for claim_id, record in verifications.items():
        if (record.get("source_generation") != source_generation or
                record.get("component_generation") != component_generation):
            raise Blocked(f"{JOB}: verification generation is stale")
        ledger_status = latest[claim_id]["status"]
        # 09 BLOCKED appends `unresolved` (DECISION_OUTCOMES), or concurs with an 08 `unresolved`.
        expected_status = {"verified": {"VERIFIED"}, "refuted": {"REFUTED"},
                           "unresolved": {"UNRESOLVED", "BLOCKED"}, "narrowed": {"BLOCKED"},
                           "under_review": {"BLOCKED"}, "candidate": {"BLOCKED"}}.get(ledger_status, set())
        if record.get("status") not in expected_status:
            raise Blocked(f"{JOB}: verification status contradicts the ledger")
        for citation in record.get("verification_citations", []):
            identity = _artifact_identity(citation)
            if tool_evidence.is_citation(citation):
                structural[json.dumps(citation, sort_keys=True)] = identity
            prior = citations.setdefault(citation.get("citation_id"), identity)
            if not citation.get("citation_id") or prior != identity:
                raise Blocked(f"{JOB}: verification citation identity is contradictory")
        producer = record.get("producer", {})
        verifier = record.get("verifier", {})
        if record.get("status") == "VERIFIED" and (verifier.get("job_id"), verifier.get("attempt_id")) == (
                producer.get("job_id"), producer.get("attempt_id")):
            raise Blocked(f"{JOB}: self-verified claim is forbidden")
    for claim_id, record in priorities.items():
        verified = verifications[claim_id]
        if (record.get("source_generation") != source_generation or
                record.get("component_generation") != component_generation or
                record.get("verification_status") != verified.get("status")):
            raise Blocked(f"{JOB}: scoring record contradicts verification")
        if record.get("verification_status") != "VERIFIED" and any(
                record.get(key) is not None for key in ("score", "severity")):
            raise Blocked(f"{JOB}: unverified claim has a score or severity")
        if record.get("severity") in {"HIGH", "CRITICAL"} and record.get("verification_status") != "VERIFIED":
            raise Blocked(f"{JOB}: high severity lacks independent verification")
        if record.get("verification_status") == "VERIFIED":
            factors = record.get("factors")
            if not isinstance(factors, dict) or set(factors) != {"impact", "exploitability", "exposure", "confidence"}:
                raise Blocked(f"{JOB}: verified score factors are incomplete")
            score = sum(factors.values())
            expected = ("CRITICAL", "P0") if score >= 15 else (("HIGH", "P1") if score >= 12 else
                       (("MEDIUM", "P2") if score >= 8 else ("LOW", "P3")))
            if (record.get("score"), record.get("severity"), record.get("priority")) != (score, *expected):
                raise Blocked(f"{JOB}: scoring result is inflated or non-deterministic")
    _reject_promotions({"component": component, "threat": threat, "owasp": [matrix, gaps, routes],
                        "ledger": ledger})
    for text, identity in sorted(structural.items()):   # each copy of a structural citation, not only the first
        _verify_tool_evidence(Path(jobs_root), run_id, identity, json.loads(text))
    by_identity = {identity: json.loads(text) for text, identity in structural.items()}
    evidence = [_verify_citation(Path(jobs_root), identity, run_id=run_id, citation=by_identity.get(identity))
                for identity in sorted(set(citations.values()))]
    unresolved = [{"claim_id": claim_id, "status": latest[claim_id]["status"]}
                  for claim_id in sorted(latest) if latest[claim_id]["status"] not in {"verified", "refuted", "superseded"}]
    dissent_ids = sorted({item for entry in ledger["entries"] for item in entry.get("dissent_ids", [])} |
                         {item for record in verifications.values() for item in record.get("dissent_ids", [])})
    statuses = Counter(item.get("status") for item in verifications.values())
    inputs = {name: loaded[name]["reference"] for name in sorted(loaded)}
    coverage = {"component_classification_gaps": sorted(item.get("gap_id", digest(item))
                    for item in component.get("classification_gaps", [])),
        "component_unknowns": sorted(item.get("unknown_id", digest(item)) for item in component.get("unknowns", [])),
        "threat_gaps": sorted(item.get("gap_id", digest(item)) for item in threat.get("gaps", [])),
        "threat_unmodeled_components": sorted(item["component_id"] for item in
                                               threat.get("coverage", {}).get("unmodeled_components", [])),
        "owasp_gap_ids": sorted(item["gap_id"] for item in gaps.get("gaps", []))}
    counts = {"components": len(component.get("functional_components", [])),
        "threat_hypotheses": len(threat.get("stride_hypotheses", [])),
        "owasp_rows": len(matrix.get("rows", [])), "ledger_claims": len(latest),
        "verified_claims": statuses.get("VERIFIED", 0), "refuted_claims": statuses.get("REFUTED", 0),
        "unresolved_claims": len(unresolved),
        "scored_claims": sum(item.get("score") is not None for item in priorities.values())}
    result = {"schema": "appsec-review/synthesis-input/1.0", "run_id": run_id,
        "source_generation": source_generation, "component_generation": component_generation,
        "ledger_head_id": ledger["entries"][-1]["event_id"], "ledger_head_sha256": ledger["head_hash"],
        "lifecycle_origin_head_id": origin_head_id,
        "lifecycle_origin_head_sha256": origin_head_sha256,
        "inputs": inputs, "evidence_artifacts": evidence, "counts": counts, "coverage": coverage,
        "unresolved_claims": unresolved, "dissent_ids": dissent_ids,
        "owasp_denominators": matrix["denominators"], "integrity": {"inputs_sha256": _sha(inputs),
            "evidence_artifacts_sha256": _sha(evidence), "manifest_sha256": ""}}
    result["integrity"]["manifest_sha256"] = _sha({**result, "integrity": {
        **result["integrity"], "manifest_sha256": ""}})
    errors = validate_document(result, "synthesis-input.schema.json")
    if errors: raise Blocked(f"{JOB}: synthesis input fails its closed schema ({errors[0]})")
    return result


def run(run_id: str, pointers: dict[str, Path], jobs_root: Path, output: Path) -> dict[str, Any]:
    loaded = {name: load_accepted(pointers[name], run_id=run_id, name=name) for name in sorted(SPECS)}
    result = assemble(run_id, loaded, jobs_root)
    atomic_json(output, result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--jobs-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    for source in SPECS: parser.add_argument(f"--{source}-accepted", type=Path, required=True)
    args = parser.parse_args()
    run(args.run_id, {name: getattr(args, name + "_accepted") for name in SPECS}, args.jobs_root, args.output)
