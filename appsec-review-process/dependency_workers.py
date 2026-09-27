#!/usr/bin/env python3
"""Deterministic dependency evidence and CVE reachability workers.

These workers consume hash-bound, offline tool exports.  The container adapter is the only
authority allowed to create a ``pinned-tool-evidence`` receipt; this module verifies that receipt
and never invokes a target, a package manager, or the network.  Every successful invocation writes
an immutable attempt and a common worker envelope.  Results are evidence leads, not findings.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
from typing import Any, Callable

from schema_validate import validate_document
from worker_result import artifact_records, terminal_envelope, validate_worker_result
import evidence_redaction
from sbom_family_contracts import (
    canonical_advisory_id, databases_digest, declaration_kind, lifecycle_row_for,
    required_gap_reason, spdx_expression_shape_ok, version_scheme_for,
)

JOBS = {
    "sbom": ("02-sbom-inventory", "sbom-inventory", "outputs/sbom-manifest.json"),
    "sca": ("02-sca-vulnerability-match", "sca-vulnerability-match", "outputs/sca-vulnerability-match.json"),
    "license": ("02-license-scan", "license-inventory", "outputs/license-inventory.json"),
    "lifecycle": ("02-dependency-lifecycle", "dependency-lifecycle", "outputs/dependency-lifecycle.json"),
    "reachability": ("06-cve-reachability", "cve-reachability", "outputs/cve-reachability.json"),
}
PINNED_RECEIPT_SCHEMA = "appsec-review/pinned-tool-evidence/1.0"
REDACTOR = {
    "name": "appsec-review-process/evidence_redaction",
    "module_version": evidence_redaction.MODULE_VERSION,
    "ruleset_sha256": evidence_redaction.RULESET_SHA256,
}
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENT = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,95}\Z")
REACHABILITY = {"reachable", "unreachable", "unknown", "dev-only", "vendored", "generated"}
EVIDENCE_KINDS = {"build", "import", "call", "config", "scope", "vendor", "generator"}
REQUIRED_EVIDENCE = {
    "reachable": {"build", "import", "call", "config"},
    "unreachable": {"build", "import", "call", "config"},
    "dev-only": {"scope"}, "vendored": {"vendor"}, "generated": {"generator"},
}


class WorkerBlocked(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise WorkerBlocked(f"required regular file is absent: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise WorkerBlocked(f"required JSON is unreadable: {path.name}: {type(exc).__name__}") from None
    if not isinstance(value, dict):
        raise WorkerBlocked(f"required JSON is not an object: {path.name}")
    return value


def _path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise WorkerBlocked(f"{label} is required")
    result = Path(value)
    if not result.is_absolute() or not result.is_file() or result.is_symlink():
        raise WorkerBlocked(f"{label} must name an absolute regular file")
    return result


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        raise WorkerBlocked(f"{label} must be a UTC second timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _base(request: dict[str, Any], job: str) -> dict[str, Any]:
    required = ("run_id", "source_snapshot_sha256", "generated_at", "output_root")
    if any(key not in request for key in required):
        raise WorkerBlocked(f"{job}: request is incomplete")
    if not IDENT.fullmatch(str(request["run_id"])) or not SHA.fullmatch(str(request["source_snapshot_sha256"])):
        raise WorkerBlocked(f"{job}: run or source identity is invalid")
    _timestamp(request["generated_at"], "generated_at")
    configured_root = Path(request["output_root"])
    root = configured_root.resolve()
    if not configured_root.is_absolute() or root == Path(root.anchor) or len(root.parts) < 3:
        raise WorkerBlocked(f"{job}: output_root must be a safe absolute directory")
    for parent in (configured_root, *configured_root.parents):
        if parent.exists() and parent.is_symlink():
            raise WorkerBlocked(f"{job}: output_root cannot traverse a symbolic link")
    return {"run_id": request["run_id"], "job_id": job,
            "source_snapshot_sha256": request["source_snapshot_sha256"]}


def _tool(request: dict[str, Any], job: str) -> tuple[dict[str, Any], dict[str, Any], Path]:
    output = _path(request.get("tool_output"), "tool_output")
    receipt_path = _path(request.get("tool_receipt"), "tool_receipt")
    receipt = _json(receipt_path)
    required = {"schema", "run_id", "job_id", "attempt_id", "tool_id", "image_id",
                "image_digest", "result_sha256", "source_snapshot_sha256", "completed_at"}
    if set(receipt) != required or receipt.get("schema") != PINNED_RECEIPT_SCHEMA:
        raise WorkerBlocked(f"{job}: pinned tool receipt is not closed v1.0 evidence")
    expected = request.get("expected_tool")
    if not isinstance(expected, dict) or set(expected) != {"tool_id", "image_id", "image_digest"}:
        raise WorkerBlocked(f"{job}: expected_tool is required")
    if (receipt["run_id"] != request["run_id"] or receipt["job_id"] != job or
            receipt["source_snapshot_sha256"] != request["source_snapshot_sha256"] or
            any(receipt[key] != expected[key] for key in expected)):
        raise WorkerBlocked(f"{job}: pinned tool receipt identity differs from the requested execution")
    if not SHA.fullmatch(str(receipt["image_digest"])) or not SHA.fullmatch(str(receipt["result_sha256"])):
        raise WorkerBlocked(f"{job}: pinned tool receipt hashes are invalid")
    if _hash_file(output) != receipt["result_sha256"]:
        raise WorkerBlocked(f"{job}: pinned tool output hash differs from its external receipt")
    _timestamp(receipt["completed_at"], "tool completed_at")
    return _json(output), receipt, output


def _upstream(request: dict[str, Any], key: str, job: str, result_path: str) -> tuple[dict[str, Any], dict[str, str], Path]:
    block = request.get(key)
    if not isinstance(block, dict) or set(block) != {"attempt_id", "path", "sha256", "accepted_path"}:
        raise WorkerBlocked(f"{job}: exact {key} binding is required")
    path = _path(block["path"], key + ".path")
    if not SHA.fullmatch(str(block["sha256"])) or _hash_file(path) != block["sha256"]:
        raise WorkerBlocked(f"{job}: {key} bytes differ from the accepted binding")
    value = _json(path)
    if value.get("attempt_id") != block["attempt_id"] or value.get("job_id") != job:
        raise WorkerBlocked(f"{job}: {key} identity differs from the accepted binding")
    accepted_path = _path(block["accepted_path"], key + ".accepted_path")
    accepted = _json(accepted_path)
    if (accepted.get("schema") != "appsec-review/accepted-worker-result/1.0" or
            accepted.get("job") != job or accepted.get("run_id") != request["run_id"] or
            accepted.get("attempt_id") != block["attempt_id"] or
            accepted.get("status") not in {"OK", "OK_WITH_GAPS"}):
        raise WorkerBlocked(f"{job}: {key} is not the exact accepted upstream generation")
    attempt = accepted_path.parent / "attempts" / block["attempt_id"]
    expected_path = attempt.joinpath(*PurePosixPath(result_path).parts)
    envelope_path = attempt / accepted.get("envelope_path", "")
    if (path.resolve() != expected_path.resolve() or not envelope_path.is_file() or envelope_path.is_symlink() or
            _hash_file(envelope_path).split(":", 1)[1] != accepted.get("envelope_sha256")):
        raise WorkerBlocked(f"{job}: {key} accepted pointer does not resolve to immutable evidence")
    envelope = _json(envelope_path)
    if (validate_worker_result(envelope) or envelope.get("attempt_id") != block["attempt_id"] or
            envelope.get("job_id") != job or envelope.get("acceptance_status") != "CURRENT" or
            not any(item.get("path") == result_path and "sha256:" + item.get("sha256", "") == block["sha256"]
                    for item in envelope.get("artifacts", []) if isinstance(item, dict))):
        raise WorkerBlocked(f"{job}: {key} accepted common envelope is invalid")
    return value, {"job_id": job, "attempt_id": block["attempt_id"], "path": result_path,
                   "sha256": block["sha256"]}, path


def _citation(receipt: dict[str, Any], output: Path) -> dict[str, Any]:
    return {"source_class": "raw", "producer": receipt["job_id"], "attempt_id": receipt["attempt_id"],
            "path": output.name, "sha256": _hash_file(output).split(":", 1)[1]}


def _component_id(value: dict[str, Any]) -> str:
    return "SC-" + str(int(hashlib.sha256(_canonical(value)).hexdigest()[:12], 16) % 1000000).zfill(6)


def build_sbom(request: dict[str, Any], attempt_id: str) -> tuple[dict[str, bytes], list[str]]:
    job = JOBS["sbom"][0]; base = _base(request, job)
    tool, receipt, output = _tool(request, job)
    rows = tool.get("components")
    if not isinstance(rows, list):
        raise WorkerBlocked(f"{job}: tool export has no components array")
    components = []
    for raw in rows:
        if not isinstance(raw, dict) or not isinstance(raw.get("source"), dict):
            raise WorkerBlocked(f"{job}: component record is malformed")
        source = raw["source"]
        if set(source) != {"path", "sha256"} or not SHA.fullmatch(str(source["sha256"])):
            raise WorkerBlocked(f"{job}: component source evidence is incomplete")
        evidence_kind = declaration_kind(str(raw.get("ecosystem")), str(source["path"]))
        declaration = raw.get("declaration")
        if declaration == "declared" and evidence_kind == "vendored-file-evidence":
            raise WorkerBlocked(f"{job}: vendored evidence cannot be promoted to a declared component")
        if declaration not in {"declared", "inferred-vendored"}:
            raise WorkerBlocked(f"{job}: component declaration is invalid")
        identity = {key: raw.get(key) for key in ("name", "version", "purl", "cpe", "ecosystem")}
        component = {"component_id": _component_id({**identity, "source": source}),
                     "assertion": "component-version-unknown" if raw.get("version") is None else "declared-component-present",
                     "declaration": declaration, **identity,
                     "source": {"evidence_kind": evidence_kind, **source},
                     "tool_id": receipt["tool_id"], "citation": _citation(receipt, output)}
        components.append(component)
    components.sort(key=lambda row: row["component_id"])
    if len({row["component_id"] for row in components}) != len(components):
        raise WorkerBlocked(f"{job}: component identities collide")
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "components": [{"bom-ref": row["component_id"], "name": row["name"],
                           **({"version": row["version"]} if row["version"] else {}),
                           **({"purl": row["purl"]} if row["purl"] else {})} for row in components]}
    cdx_bytes = _canonical(cdx)
    result = {"schema": "appsec-review/sbom-inventory/1.0", **base, "attempt_id": attempt_id,
              "redactor": REDACTOR, "generated_at": request["generated_at"],
              "sbom_document": {"path": "outputs/sbom.cdx.json", "sha256": _hash_bytes(cdx_bytes),
                                "bytes": len(cdx_bytes), "bom_format": "CycloneDX", "spec_version": "1.6"},
              "components": components}
    errors = validate_document(result, "sbom-inventory.schema.json")
    if errors: raise WorkerBlocked(f"{job}: normalized result violates schema ({len(errors)} errors)")
    return {"outputs/sbom.cdx.json": cdx_bytes, "outputs/sbom-manifest.json": _canonical(result),
            "outputs/pinned-tool-evidence.json": _canonical(receipt)}, []


def _database_block(raw: dict[str, Any], evaluated: str, max_age: int) -> dict[str, Any]:
    required = {"database_kind", "vendor_build", "schema_version", "snapshot_id", "sha256", "data_timestamp"}
    if set(raw) != required or raw["database_kind"] not in {"grype-db", "osv"} or not SHA.fullmatch(str(raw["sha256"])):
        raise WorkerBlocked("sca: vulnerability database identity is invalid")
    age = int((_timestamp(evaluated, "generated_at") - _timestamp(raw["data_timestamp"], "database data_timestamp")).total_seconds())
    if age < 0 or age > max_age:
        raise WorkerBlocked("sca: vulnerability database snapshot is stale or from the future")
    database = {key: raw[key] for key in ("database_kind", "vendor_build", "schema_version", "snapshot_id", "sha256")}
    return {"assertion": "database-snapshot-identity", "database": database,
            "data_timestamp": raw["data_timestamp"], "evaluated_at": evaluated, "age_seconds": age,
            "max_age_seconds": max_age, "age_policy": "within-limit"}


def build_sca(request: dict[str, Any], attempt_id: str) -> tuple[dict[str, bytes], list[str]]:
    job = JOBS["sca"][0]; base = _base(request, job)
    sbom, binding, _ = _upstream(request, "sbom", JOBS["sbom"][0], JOBS["sbom"][2])
    if sbom.get("source_snapshot_sha256") != request["source_snapshot_sha256"]:
        raise WorkerBlocked(f"{job}: SBOM has mixed source lineage")
    tool, receipt, output = _tool(request, job)
    max_age = request.get("max_database_age_seconds")
    if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age < 0:
        raise WorkerBlocked(f"{job}: explicit non-negative database age ceiling is required")
    raw_databases = request.get("databases")
    if not isinstance(raw_databases, list) or {item.get("database_kind") for item in raw_databases if isinstance(item, dict)} != {"grype-db", "osv"}:
        raise WorkerBlocked(f"{job}: exact Grype and OSV snapshot identities are required")
    identities = [_database_block(item, request["generated_at"], max_age) for item in raw_databases]
    identities.sort(key=lambda item: item["database"]["database_kind"])
    digest_value = databases_digest({item["database"]["database_kind"]: {
        **{key: value for key, value in item["database"].items() if key != "database_kind"},
        "data_timestamp": item["data_timestamp"]} for item in identities})
    by_id = {row["component_id"]: row for row in sbom["components"]}
    gaps, evaluated = [], []
    for component in sbom["components"]:
        reason = required_gap_reason(component)
        if reason:
            gaps.append({"gap_id": "VG-" + component["component_id"][3:], "assertion": "match-coverage-gap",
                         "component_ref": component["component_id"], "ecosystem": component["ecosystem"], "reason": reason})
        else:
            evaluated_by = ["grype-db"] + (["osv"] if component.get("purl") else [])
            evaluated.append({"component_ref": component["component_id"], "outcome": "no-advisory-matched",
                              "version_scheme": version_scheme_for(component), "evaluated_by": evaluated_by})
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in tool.get("matches", []):
        if not isinstance(raw, dict) or raw.get("component_ref") not in by_id:
            raise WorkerBlocked(f"{job}: matcher cited a component outside the exact SBOM")
        component = by_id[raw["component_ref"]]
        if required_gap_reason(component):
            raise WorkerBlocked(f"{job}: matcher promoted an unevaluable component")
        aliases = raw.get("aliases")
        database = raw.get("database")
        if not isinstance(aliases, list) or not aliases or database not in {"grype-db", "osv"}:
            raise WorkerBlocked(f"{job}: matcher advisory evidence is malformed")
        advisory = canonical_advisory_id(aliases)
        basis = raw.get("match_basis")
        if basis not in {"purl", "cpe"} or component.get(basis) is None or (database == "osv" and basis != "purl"):
            raise WorkerBlocked(f"{job}: matcher basis is unsupported by the exact component and database")
        database_identity = next(item["database"] for item in identities if item["database"]["database_kind"] == database)
        key = (raw["component_ref"], advisory)
        group = grouped.setdefault(key, {"aliases": set(), "citations": []})
        group["aliases"].update(aliases)
        citation = {"database": database_identity, "advisory_id": raw.get("advisory_id", advisory), "match_basis": basis}
        if citation not in group["citations"]: group["citations"].append(citation)
        for row in evaluated:
            if row["component_ref"] == raw["component_ref"]: row["outcome"] = "advisory-matched"
    matches = []
    for index, ((component_ref, advisory), group) in enumerate(sorted(grouped.items()), 1):
        matches.append({"match_id": "VM-" + str(index).zfill(6), "assertion": "advisory-matches-declared-version",
                        "component_ref": component_ref, "advisory_id": advisory, "aliases": sorted(group["aliases"]),
                        "version_scheme": version_scheme_for(by_id[component_ref]),
                        "citations": sorted(group["citations"], key=lambda item: (item["database"]["database_kind"], item["advisory_id"])),
                        "tool_id": receipt["tool_id"], "citation": _citation(receipt, output)})
    header = {**base, "attempt_id": attempt_id}
    result = {"schema": "appsec-review/sca-vulnerability-match/1.0", **header, "redactor": REDACTOR,
              "sbom_binding": binding, "databases_digest": digest_value,
              "evaluated": sorted(evaluated, key=lambda row: row["component_ref"]), "matches": matches}
    gap_doc = {"schema": "appsec-review/sca-vulnerability-match-coverage-gaps/1.0", **header,
               "redactor": REDACTOR, "sbom_binding": binding, "gaps": gaps}
    gap_bytes = _canonical(gap_doc)
    counts = []
    for ecosystem, reason in sorted({(g["ecosystem"], g["reason"]) for g in gaps}):
        counts.append({"ecosystem": ecosystem, "reason": reason,
                       "count": sum(g["ecosystem"] == ecosystem and g["reason"] == reason for g in gaps)})
    summary = {"schema": "appsec-review/sca-vulnerability-match-gap-summary/1.0", **header,
               "sbom_binding": binding, "component_count": len(by_id), "evaluated_count": len(evaluated),
               "gap_count": len(gaps), "counts": counts,
               "gap_list": {"path": "outputs/sca-coverage-gaps.json", "sha256": _hash_bytes(gap_bytes)}}
    identities_doc = {"schema": "appsec-review/sca-vulnerability-match-database-identities/1.0", **header,
                      "databases_digest": digest_value, "databases": identities}
    docs = [(result, "sca-vulnerability-match.schema.json"), (gap_doc, "sca-vulnerability-match-coverage-gaps.schema.json"),
            (summary, "sca-vulnerability-match-gap-summary.schema.json"),
            (identities_doc, "sca-vulnerability-match-database-identities.schema.json")]
    if any(validate_document(doc, schema) for doc, schema in docs):
        raise WorkerBlocked(f"{job}: normalized result violates a closed schema")
    return {"outputs/sca-vulnerability-match.json": _canonical(result), "outputs/sca-coverage-gaps.json": gap_bytes,
            "outputs/coverage-gap-summary.json": _canonical(summary),
            "outputs/vulnerability-database-identities.json": _canonical(identities_doc),
            "outputs/pinned-tool-evidence.json": _canonical(receipt)}, (["SCA_COMPONENT_GAPS"] if gaps else [])


def build_license(request: dict[str, Any], attempt_id: str) -> tuple[dict[str, bytes], list[str]]:
    job = JOBS["license"][0]; base = _base(request, job)
    sbom, binding, _ = _upstream(request, "sbom", JOBS["sbom"][0], JOBS["sbom"][2])
    if sbom.get("source_snapshot_sha256") != request["source_snapshot_sha256"]:
        raise WorkerBlocked(f"{job}: SBOM has mixed source lineage")
    tool, receipt, output = _tool(request, job); component_ids = {row["component_id"] for row in sbom["components"]}
    records = []
    for index, raw in enumerate(tool.get("records", []), 1):
        if not isinstance(raw, dict) or raw.get("component_ref") not in component_ids | {None}:
            raise WorkerBlocked(f"{job}: license record cites an unknown component")
        claim = raw.get("claim_source")
        if not isinstance(claim, dict) or set(claim) != {"kind", "path", "sha256", "start_line", "end_line"} or not SHA.fullmatch(str(claim["sha256"])):
            raise WorkerBlocked(f"{job}: license record has incomplete source evidence")
        expression, state = raw.get("license_expression"), raw.get("expression_state")
        if state == "spdx-expression" and (not isinstance(expression, str) or not spdx_expression_shape_ok(expression)):
            raise WorkerBlocked(f"{job}: claimed SPDX expression has invalid expression shape")
        if state in {"unknown", "no-assertion"} and expression is not None:
            raise WorkerBlocked(f"{job}: non-SPDX state cannot carry a license expression")
        records.append({"record_id": "LI-" + str(index).zfill(6), "assertion": raw.get("assertion"),
                        "component_ref": raw.get("component_ref"), "license_expression": expression,
                        "expression_state": state, "claim_source": claim,
                        "tool_id": receipt["tool_id"], "citation": _citation(receipt, output)})
    result = {"schema": "appsec-review/license-inventory/1.0", **base, "attempt_id": attempt_id,
              "redactor": REDACTOR, "sbom_binding": binding, "records": records}
    if validate_document(result, "license-inventory.schema.json"):
        raise WorkerBlocked(f"{job}: normalized result violates schema")
    return {"outputs/license-inventory.json": _canonical(result),
            "outputs/pinned-tool-evidence.json": _canonical(receipt)}, []


def build_lifecycle(request: dict[str, Any], attempt_id: str) -> tuple[dict[str, bytes], list[str]]:
    job = JOBS["lifecycle"][0]; base = _base(request, job)
    sbom, sbom_binding, _ = _upstream(request, "sbom", JOBS["sbom"][0], JOBS["sbom"][2])
    licenses, license_binding, _ = _upstream(request, "license", JOBS["license"][0], JOBS["license"][2])
    if {sbom.get("source_snapshot_sha256"), licenses.get("source_snapshot_sha256")} != {request["source_snapshot_sha256"]}:
        raise WorkerBlocked(f"{job}: upstream source lineage differs")
    table_path = _path(request.get("reference_table"), "reference_table")
    expected_hash = request.get("reference_table_sha256")
    if not SHA.fullmatch(str(expected_hash)) or _hash_file(table_path) != expected_hash:
        raise WorkerBlocked(f"{job}: lifecycle table differs from its configured identity")
    table = _json(table_path)
    if validate_document(table, "dependency-lifecycle-reference-table.schema.json"):
        raise WorkerBlocked(f"{job}: lifecycle table schema is invalid")
    max_days = request.get("max_reference_age_days")
    if isinstance(max_days, bool) or not isinstance(max_days, int) or max_days < 0:
        raise WorkerBlocked(f"{job}: explicit reference-table age ceiling is required")
    age = (_timestamp(request["generated_at"], "generated_at").date() - datetime.fromisoformat(table["as_of"]).date()).days
    if age < 0 or age > max_days:
        raise WorkerBlocked(f"{job}: lifecycle reference table is stale or from the future")
    license_by_component: dict[str, list[dict[str, Any]]] = {}
    for row in licenses["records"]:
        if row["component_ref"] is not None: license_by_component.setdefault(row["component_ref"], []).append(row)
    entries, gaps = [], []
    for index, component in enumerate(sbom["components"], 1):
        table_row = lifecycle_row_for(component, table["rows"])
        status = table_row["status"] if table_row else "unknown"
        if not table_row: gaps.append("LIFECYCLE_UNKNOWN:" + component["component_id"])
        entries.append({"entry_id": "DL-" + str(index).zfill(6), "component_ref": component["component_id"],
                        "assertion": "reference-table-eol-match" if table_row else "lifecycle-unknown", "status": status,
                        "table_row": ({key: table_row[key] for key in ("row_id", "cycle", "status", "eol_date")} if table_row else None),
                        "resurfaced_licenses": [{"assertion": "license-field-resurfaced", "record_ref": row["record_id"],
                                                  "license_expression": row["license_expression"]}
                                                 for row in license_by_component.get(component["component_id"], [])]})
    identity = {key: table[key] for key in ("table_id", "version", "as_of")}; identity["sha256"] = expected_hash
    result = {"schema": "appsec-review/dependency-lifecycle/1.0", **base, "attempt_id": attempt_id,
              "redactor": REDACTOR, "sbom_binding": sbom_binding, "license_binding": license_binding,
              "reference_table": identity, "entries": entries}
    if validate_document(result, "dependency-lifecycle.schema.json"):
        raise WorkerBlocked(f"{job}: normalized result violates schema")
    return {"outputs/dependency-lifecycle.json": _canonical(result),
            "outputs/reference-table-identity.json": _canonical(identity)}, gaps


def build_reachability(request: dict[str, Any], attempt_id: str) -> tuple[dict[str, bytes], list[str]]:
    job = JOBS["reachability"][0]; base = _base(request, job)
    sca, binding, _ = _upstream(request, "sca", JOBS["sca"][0], JOBS["sca"][2])
    if sca.get("source_snapshot_sha256") != request["source_snapshot_sha256"]:
        raise WorkerBlocked(f"{job}: SCA has mixed source lineage")
    evidence_path = _path(request.get("reachability_evidence"), "reachability_evidence")
    expected = request.get("reachability_evidence_sha256")
    if not SHA.fullmatch(str(expected)) or _hash_file(evidence_path) != expected:
        raise WorkerBlocked(f"{job}: reachability evidence differs from its external binding")
    evidence = _json(evidence_path); rows = evidence.get("assessments")
    if not isinstance(rows, list): raise WorkerBlocked(f"{job}: evidence has no assessments array")
    by_match = {row["match_id"]: row for row in sca["matches"]}; supplied = {}
    for raw in rows:
        if not isinstance(raw, dict) or raw.get("match_ref") not in by_match or raw["match_ref"] in supplied:
            raise WorkerBlocked(f"{job}: evidence cites an unknown or duplicate SCA match")
        supplied[raw["match_ref"]] = raw
    assessments, gaps = [], []
    for match_id, match in sorted(by_match.items()):
        raw = supplied.get(match_id, {"classification": "unknown", "evidence": []})
        classification = raw.get("classification")
        proof = raw.get("evidence")
        if classification not in REACHABILITY or not isinstance(proof, list):
            raise WorkerBlocked(f"{job}: reachability classification is invalid")
        normalized = []
        for item in proof:
            if (not isinstance(item, dict) or set(item) != {"kind", "path", "sha256", "locator"} or
                    item["kind"] not in EVIDENCE_KINDS or not SHA.fullmatch(str(item["sha256"])) or
                    not isinstance(item["locator"], str) or not item["locator"]):
                raise WorkerBlocked(f"{job}: reachability proof is incomplete")
            normalized.append(item)
        kinds = {item["kind"] for item in normalized}
        if classification != "unknown" and not (kinds & REQUIRED_EVIDENCE[classification]):
            raise WorkerBlocked(f"{job}: {classification} cannot be inferred from version match alone")
        if classification == "unknown": gaps.append("REACHABILITY_UNKNOWN:" + match_id)
        assessments.append({"assessment_id": "RA-" + str(len(assessments) + 1).zfill(6),
                            "assertion": "cve-reachability-evidence-lead", "match_ref": match_id,
                            "component_ref": match["component_ref"], "advisory_id": match["advisory_id"],
                            "classification": classification, "evidence": normalized,
                            "claim_ceiling": "EVIDENCE_LEAD_NOT_FINDING"})
    result = {"schema": "appsec-review/cve-reachability/1.0", **base, "attempt_id": attempt_id,
              "sca_binding": binding, "assessments": assessments, "coverage_gaps": gaps,
              "claim_ceiling": "EVIDENCE_LEADS_ONLY"}
    if validate_document(result, "cve-reachability.schema.json"):
        raise WorkerBlocked(f"{job}: normalized result violates schema")
    return {"outputs/cve-reachability.json": _canonical(result),
            "outputs/reachability-evidence-identity.json": _canonical({"path": evidence_path.name, "sha256": expected})}, gaps


BUILDERS: dict[str, Callable[[dict[str, Any], str], tuple[dict[str, bytes], list[str]]]] = {
    "sbom": build_sbom, "sca": build_sca, "license": build_license,
    "lifecycle": build_lifecycle, "reachability": build_reachability,
}


def run(kind: str, request_path: Path) -> dict[str, Any]:
    request = _json(request_path); job, contract, _ = JOBS[kind]
    _base(request, job)
    fingerprint = _hash_bytes(_canonical({"kind": kind, "request": request, "implementation": "dependency-workers-v1"}))
    attempt_id = job + "-" + fingerprint[7:27]
    artifacts, gaps = BUILDERS[kind](request, attempt_id)
    root = Path(request["output_root"]).resolve() / job
    attempt = root / "attempts" / attempt_id
    pointer = root / "accepted.json"
    if attempt.exists():
        envelope = _json(attempt / "result.json")
        if envelope.get("input_fingerprint") != fingerprint or validate_worker_result(envelope):
            raise WorkerBlocked(f"{job}: immutable attempt collision")
        for record in envelope.get("artifacts", []):
            relative = record.get("path") if isinstance(record, dict) else None
            pure = PurePosixPath(relative) if isinstance(relative, str) else None
            if pure is None or pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
                raise WorkerBlocked(f"{job}: immutable attempt has an unsafe artifact path")
            artifact = attempt.joinpath(*pure.parts)
            if (not artifact.is_file() or artifact.is_symlink() or
                    _hash_file(artifact).split(":", 1)[1] != record.get("sha256")):
                raise WorkerBlocked(f"{job}: immutable attempt artifact changed")
        accepted = _json(pointer)
        if (accepted.get("attempt_id") != attempt_id or
                _hash_file(attempt / "result.json").split(":", 1)[1] != accepted.get("envelope_sha256")):
            raise WorkerBlocked(f"{job}: accepted pointer changed")
        return envelope
    if pointer.exists():
        existing = _json(pointer)
        if existing.get("attempt_id") != attempt_id:
            raise WorkerBlocked(f"{job}: another accepted input generation already exists")
    root.mkdir(parents=True, exist_ok=True)
    staging = root / (".attempt." + attempt_id)
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=False, exist_ok=False)
    try:
        for relative, payload in artifacts.items():
            path = staging.joinpath(*PurePosixPath(relative).parts); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        (staging / "inputs.json").write_bytes(_canonical(request))
        paths = sorted(artifacts) + ["inputs.json"]
        status = "OK_WITH_GAPS" if gaps else "OK"
        stamp = request["generated_at"]
        envelope = terminal_envelope(run_id=request["run_id"], job_id=job, attempt_id=attempt_id,
            worker_kind="deterministic_python", execution_status=status, acceptance_status="CURRENT",
            input_fingerprint=fingerprint, output_contract=contract, started_at=stamp, finished_at=stamp,
            summary=f"{job} emitted deterministic evidence leads", artifacts=artifact_records(staging, paths), gaps=gaps)
        errors = validate_worker_result(envelope)
        if errors: raise WorkerBlocked(f"{job}: common envelope is invalid ({len(errors)} errors)")
        (staging / "result.json").write_bytes(_canonical(envelope))
        attempts = root / "attempts"; attempts.mkdir(exist_ok=True)
        os.replace(staging, attempt)
    except BaseException:
        if staging.exists(): shutil.rmtree(staging)
        raise
    temporary = root / (".accepted." + attempt_id)
    temporary.write_bytes(_canonical({"schema": "appsec-review/accepted-worker-result/1.0", "run_id": request["run_id"],
        "job": job, "attempt_id": attempt_id, "status": status, "fingerprint": fingerprint,
        "envelope_path": "result.json", "envelope_sha256": _hash_file(attempt / "result.json").split(":", 1)[1]}))
    os.replace(temporary, pointer)
    return envelope


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=sorted(BUILDERS)); parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.kind, args.request), sort_keys=True))
        return 0
    except WorkerBlocked as exc:
        print(json.dumps({"status": "BLOCKED", "cause": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
