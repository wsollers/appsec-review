#!/usr/bin/env python3
"""Deterministic dependency evidence and CVE reachability workers.

These workers consume hash-bound, offline tool exports.  The container adapter is the only
authority allowed to create a ``pinned-tool-evidence`` receipt; this module verifies that receipt
and never invokes a target, a package manager, or the network.  Every successful invocation writes
an immutable attempt and a common worker envelope.  Results are evidence leads, not findings.
"""
from __future__ import annotations

import argparse
import tunables
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
import container_execution as ce
import dependency_b13_adapters as dependency_adapters
from sbom_family_contracts import (
    build_index_enrichment_errors, canonical_advisory_id, databases_digest, declaration_kind, lifecycle_row_for,
    required_gap_reason, spdx_expression_shape_ok, version_scheme_for,
)
import registry_paths

JOBS = {
    "sbom": ("02-sbom-inventory", "sbom-inventory", "outputs/sbom-manifest.json"),
    "sca": ("02-sca-vulnerability-match", "sca-vulnerability-match", "outputs/sca-vulnerability-match.json"),
    "license": ("02-license-scan", "license-inventory", "outputs/license-inventory.json"),
    "lifecycle": ("02-dependency-lifecycle", "dependency-lifecycle", "outputs/dependency-lifecycle.json"),
    "reachability": ("06-cve-reachability", "cve-reachability", "outputs/cve-reachability.json"),
}
REGISTRY = registry_paths.JOB_TEMPLATES_DIR
PERMISSION_SCHEMA = "appsec-review/producer-permission-receipt/1.0"
LINEAGE_SCHEMA = "appsec-review/producer-lineage-receipt/1.0"
IMPLEMENTATION = "dependency-workers-v2-producer-receipts"
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


class ToolGap(Exception):
    """A re-verified B13 terminal that is a tool-level failure (ADR-0013): carries the gap text
    and the gap record derived from the verified attempt. Raised by ``_tool`` only for callers
    that allow it; everyone else still sees WorkerBlocked."""

    def __init__(self, gap: str, record: dict[str, Any]):
        super().__init__(gap)
        self.gap, self.record = gap, record


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


def _producer_receipts(request: dict[str, Any], job: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Derive assembly receipts from tracked policy and the exact worker request.

    The template, rather than caller input, is the permission authority.  The lineage digest binds
    the complete closed request except for its publication destination; upstream accepted pointers,
    tool-result hashes, snapshot identities, and source generation therefore all affect it.
    """
    template = _json(REGISTRY / f"{job}.json")
    permissions = template.get("permissions")
    if (template.get("job_template_id") != job or not isinstance(permissions, list) or not all(
            isinstance(item, str) and item for item in permissions) or
            len(set(permissions)) != len(permissions)):
        raise WorkerBlocked(f"{job}: registry template permissions are invalid")
    generation = request["source_snapshot_sha256"]
    lineage_request = {key: value for key, value in request.items() if key != "output_root"}
    return (
        {"schema": PERMISSION_SCHEMA, "run_id": request["run_id"], "job_id": job,
         "source_snapshot_sha256": generation, "permissions": permissions},
        {"schema": LINEAGE_SCHEMA, "run_id": request["run_id"], "job_id": job,
         "source_snapshot_sha256": generation,
         "build_lineage_sha256": _hash_bytes(_canonical({"request": lineage_request}))},
    )


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


def _tool(request: dict[str, Any], job: str, kind: str, prefix: str = "", *,
          allow_gap: bool = False) -> tuple[dict[str, Any], dict[str, Any], Path]:
    """Consume a verified immutable B13 attempt, never a caller-authored receipt bundle.

    With ``allow_gap`` a verified tool-level failure (``dependency_b13_adapters.tool_gap``) raises
    :class:`ToolGap` instead of blocking; the binding must then carry no output hash."""
    spec = dependency_adapters.SPECS.get(kind)
    if spec is None or spec["job"] != job:
        raise WorkerBlocked(f"{job}: dependency adapter kind is not valid for this worker")
    binding = request.get(prefix + "b13_attempt")
    fields = {"attempt_root", "expected_result_sha256", "expected_output_sha256", "request", "images_dir", "host_flavor",
              "docker_host", "docker_executable", "container_user"}
    if not isinstance(binding, dict) or set(binding) != fields:
        raise WorkerBlocked(f"{job}: exact immutable B13 attempt binding is required")
    attempt_root = Path(binding["attempt_root"]); images_dir = Path(binding["images_dir"])
    docker_executable = Path(binding["docker_executable"])
    if (not attempt_root.is_absolute() or not attempt_root.is_dir() or attempt_root.is_symlink() or
            not images_dir.is_absolute() or not images_dir.is_dir() or images_dir.is_symlink() or
            not docker_executable.is_absolute() or not SHA.fullmatch(str(binding["expected_result_sha256"])) or
            not (SHA.fullmatch(str(binding["expected_output_sha256"])) or
                 (allow_gap and binding["expected_output_sha256"] is None))):
        raise WorkerBlocked(f"{job}: immutable B13 attempt binding is invalid")
    expected_request = binding["request"]
    if not isinstance(expected_request, dict):
        raise WorkerBlocked(f"{job}: canonical B13 request is required")
    attempt_id = expected_request.get("attempt_id")
    static = {"schema": ce.REQUEST_ID, "run_id": request["run_id"], "job_id": job,
              "argv": dependency_adapters.argv_for(kind), "scratch_path": "scratch", "log_path": "logs/container",
              "network": {"mode": "none", "destinations": []}, "limits": tunables.container_limits(spec["job"])}
    if any(expected_request.get(key) != value for key, value in static.items()):
        raise WorkerBlocked(f"{job}: B13 request differs from the fixed dependency adapter")
    if not isinstance(attempt_id, str) or not IDENT.fullmatch(attempt_id):
        raise WorkerBlocked(f"{job}: B13 attempt identity is invalid")
    environment = [{"name": "LANG", "value": "C"}, {"name": "LC_ALL", "value": "C"},
                   {"name": "NO_COLOR", "value": "1"}]
    if kind == "grype": environment.append({"name": "XDG_CACHE_HOME", "value": "/inputs/grype-db"})
    if kind == "osv": environment.append({"name": "XDG_CACHE_HOME", "value": "/inputs/osv-db"})
    if expected_request.get("environment") != environment:
        raise WorkerBlocked(f"{job}: B13 environment differs from the fixed dependency adapter")
    container_paths = (["/workspace"] if kind in {"syft", "scancode"} else
                       ["/inputs/sbom", "/inputs/" + ("grype-db" if kind == "grype" else "osv-db")])
    mounts = expected_request.get("target_mounts")
    if (not isinstance(mounts, list) or len(mounts) != len(container_paths) or
            any(not isinstance(item, dict) or set(item) != {"host_path", "container_path"}
                for item in mounts) or [item["container_path"] for item in mounts] != container_paths):
        raise WorkerBlocked(f"{job}: B13 mounts differ from the fixed dependency adapter")
    permission = expected_request.get("permission")
    evaluated_at = permission.get("decision", {}).get("evaluated_at") if isinstance(permission, dict) else None
    try:
        canonical_permission = dependency_adapters._permission(
            request["run_id"], job, request["source_snapshot_sha256"], evaluated_at)
    except (TypeError, ValueError, RuntimeError):
        raise WorkerBlocked(f"{job}: B13 permission decision is invalid") from None
    if permission != canonical_permission:
        raise WorkerBlocked(f"{job}: B13 permission decision is not the exact offline decision")
    try:
        image = ce.load_image_registry(images_dir)[spec["image"]]
    except (ce.ContainerRequestError, KeyError):
        raise WorkerBlocked(f"{job}: exact pinned B16 image record is unavailable") from None
    if expected_request.get("image") != {"image_id": image["image_id"], "digest": image["digest"]}:
        raise WorkerBlocked(f"{job}: B13 request does not name the exact pinned B16 image")
    try:
        verified = ce.load_verified_result(
            attempt_root, run_id=request["run_id"], job_id=job, attempt_id=attempt_id,
            request=expected_request, images_dir=images_dir, host_flavor=binding["host_flavor"],
            docker_host=binding["docker_host"], docker_executable=docker_executable,
            container_user=binding["container_user"], expected_result_sha256=binding["expected_result_sha256"])
    except (ce.ContainerRequestError, TypeError, ValueError):
        raise WorkerBlocked(f"{job}: immutable B13 attempt failed independent re-verification") from None
    from dependency_b13_adapters import exit_accepted
    finding_exit = exit_accepted(kind, verified, attempt_root)
    if verified["execution_status"] != "OK" and not finding_exit:
        gap = dependency_adapters.tool_gap(kind, verified, attempt_root) if allow_gap else None
        if gap is None or binding["expected_output_sha256"] is not None:
            raise WorkerBlocked(f"{job}: immutable B13 attempt did not complete successfully")
        raise ToolGap(gap, {"schema": dependency_adapters.TOOL_GAP_SCHEMA, "run_id": request["run_id"],
            "job_id": job, "attempt_id": attempt_id, "tool_id": spec["tool"], "image_id": image["image_id"],
            "image_digest": image["digest"], "execution_status": verified["execution_status"],
            "cause": verified["cause"], "exit_code": verified.get("exit_code"),
            "b13_result_sha256": binding["expected_result_sha256"],
            "source_snapshot_sha256": request["source_snapshot_sha256"], "completed_at": verified["finished_at"],
            "boundary_sha256": ce.boundary_sha256(), "network_mode": "none", "gap": gap})
    if binding["expected_output_sha256"] is None:
        raise WorkerBlocked(f"{job}: completed B13 attempt has no retained output hash")
    output = attempt_root / "scratch" / spec["output"]
    if not output.is_file() or output.is_symlink():
        raise WorkerBlocked(f"{job}: verified B13 attempt lacks its fixed tool output")
    if _hash_file(output) != binding["expected_output_sha256"]:
        raise WorkerBlocked(f"{job}: fixed tool output differs from the externally retained hash")
    receipt = _json(attempt_root / "pinned-tool-evidence.json")
    expected_receipt = {"schema": PINNED_RECEIPT_SCHEMA, "run_id": request["run_id"], "job_id": job,
        "attempt_id": attempt_id, "tool_id": spec["tool"], "image_id": image["image_id"],
        "image_digest": image["digest"], "result_sha256": _hash_file(output),
        "source_snapshot_sha256": request["source_snapshot_sha256"], "completed_at": verified["finished_at"],
        "boundary_sha256": ce.boundary_sha256(), "network_mode": "none",
        "target_read_only": True, "scratch_writable": True}
    if receipt != expected_receipt:
        raise WorkerBlocked(f"{job}: pinned tool receipt was not derived from the verified B13 attempt")
    return _json(output), receipt, output


def _source_files(request: dict[str, Any], job: str) -> dict[str, str]:
    value = request.get("source_files")
    if not isinstance(value, dict) or not all(isinstance(path, str) and SHA.fullmatch(str(sha))
                                               for path, sha in value.items()):
        raise WorkerBlocked(f"{job}: exact accepted source-file hash map is required for raw tool normalization")
    return value


def _location(properties: Any, source_files: dict[str, str], job: str) -> str:
    candidates = []
    if isinstance(properties, list):
        for item in properties:
            if (isinstance(item, dict) and isinstance(item.get("name"), str) and
                    item["name"].startswith("syft:location:") and item["name"].endswith(":path") and
                    isinstance(item.get("value"), str)):
                # Syft's directory source reports paths relative to the scan root with a leading
                # slash (``/package-lock.json``).  Older fixtures and some catalogers report the
                # bind target prefix (``/workspace/package-lock.json``).  Both name the same
                # accepted source file; the exact source-file map below remains authoritative.
                value = item["value"]
                candidates.append(value.removeprefix("/workspace/").removeprefix("/"))
    exact = sorted({path for path in candidates if path in source_files})
    if len(exact) == 1: return exact[0]
    expanded = sorted({path for candidate in candidates for path in source_files
                       if path == candidate or path.startswith(candidate.rstrip("/") + "/")})
    if len(expanded) == 1: return expanded[0]
    raise WorkerBlocked(f"{job}: raw tool component has no unambiguous accepted source location")


def _ecosystem(purl: Any) -> str:
    if isinstance(purl, str) and purl.startswith("pkg:"):
        value = purl[4:].split("/", 1)[0]
        aliases = {"go": "golang", "golang": "golang", "python": "pypi", "generic": "generic"}
        value = aliases.get(value, value)
        if value in {"npm", "pypi", "maven", "golang", "nuget", "cargo", "gem", "composer", "conan", "deb", "rpm", "apk", "generic"}:
            return value
    return "generic"


def _sbom_rows(tool: dict[str, Any], request: dict[str, Any], job: str) -> list[dict[str, Any]]:
    rows = tool.get("components")
    if tool.get("bomFormat") != "CycloneDX":
        if not isinstance(rows, list): raise WorkerBlocked(f"{job}: tool export has no components array")
        return rows
    # CycloneDX permits an omitted components member when a scan discovers no
    # dependency components.  Preserve that as an empty, evidence-backed
    # inventory; malformed non-list values still fail closed.
    if rows is None: rows = []
    if not isinstance(rows, list): raise WorkerBlocked(f"{job}: CycloneDX components is not an array")
    if not rows: return []
    source_files = _source_files(request, job); normalized = []
    for raw in rows:
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
            raise WorkerBlocked(f"{job}: CycloneDX component is malformed")
        # The fixed Syft invocation enables file metadata so package locations can be bound to
        # accepted source bytes.  CycloneDX emits those files alongside dependency packages;
        # they are evidence locators, not dependency inventory components.
        if raw.get("type") == "file":
            continue
        path = _location(raw.get("properties"), source_files, job)
        purl = raw.get("purl"); ecosystem = _ecosystem(purl)
        kind = declaration_kind(ecosystem, path)
        normalized.append({"name": raw["name"], "version": raw.get("version"), "purl": purl,
            "cpe": raw.get("cpe"), "ecosystem": ecosystem,
            "declaration": "declared" if kind != "vendored-file-evidence" else "inferred-vendored",
            "source": {"path": path, "sha256": source_files[path]}})
    return normalized


def _upstream(request: dict[str, Any], key: str, job: str, result_path: str, *,
              embedded_identity: bool = True) -> tuple[dict[str, Any], dict[str, str], Path]:
    block = request.get(key)
    if not isinstance(block, dict) or set(block) != {"attempt_id", "path", "sha256", "accepted_path"}:
        raise WorkerBlocked(f"{job}: exact {key} binding is required")
    path = _path(block["path"], key + ".path")
    if not SHA.fullmatch(str(block["sha256"])) or _hash_file(path) != block["sha256"]:
        raise WorkerBlocked(f"{job}: {key} bytes differ from the accepted binding")
    value = _json(path)
    if embedded_identity and (value.get("attempt_id") != block["attempt_id"] or value.get("job_id") != job):
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
            envelope.get("job_id") != job or envelope.get("run_id") != request["run_id"] or
            envelope.get("acceptance_status") != "CURRENT" or envelope.get("execution_status") != accepted.get("status") or
            envelope.get("input_fingerprint") != accepted.get("fingerprint") or accepted.get("envelope_path") != "result.json" or
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


_CJSON_MEMBER = re.compile(r"(?:[A-Za-z0-9._+@%~,-]+/)*cJSON-([0-9]+\.[0-9]+\.[0-9]+)\Z")
_BUILD_INDEX_ENRICHMENT = "outputs/build-index-vendored-members.json"
_BUILD_INDEX_TOOL_ID = "build-index-vendored-member"


def _build_index_rows(request: dict[str, Any], attempt_id: str,
                      syft_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bytes, list[str]]:
    """Project only unambiguous, build-referenced cJSON members into dependency evidence.

    The accepted build index establishes that the target build names the vendored tree.  The
    directory spelling establishes only the component name and version; it does not establish a
    package URL, CPE, supplier, license, advisory status, or reachability.  Both canonical source
    files must be present in the accepted source snapshot before a row is emitted.
    """
    job = JOBS["sbom"][0]
    index, binding, _path = _upstream(request, "build_index", "02-build-index", "build-index.json",
                                     embedded_identity=False)
    if index.get("schema") != "appsec-review/build-index/1" or not isinstance(index.get("units"), list):
        raise WorkerBlocked(f"{job}: accepted build index has an unsupported shape")
    source_files = _source_files(request, job)
    candidates: list[dict[str, Any]] = []
    for unit in index["units"]:
        if not isinstance(unit, dict) or not isinstance(unit.get("members"), list):
            raise WorkerBlocked(f"{job}: accepted build index member records are malformed")
        for member in unit["members"]:
            if not isinstance(member, dict):
                raise WorkerBlocked(f"{job}: accepted build index member record is malformed")
            path = member.get("path")
            match = _CJSON_MEMBER.fullmatch(path) if isinstance(path, str) else None
            if match is None:
                continue
            if member.get("reason") not in {"referenced-by-parent-build", "autotools-subdirectory"}:
                continue
            source_path, header_path = path + "/cJSON.c", path + "/cJSON.h"
            if source_path not in source_files or header_path not in source_files:
                continue
            candidates.append({"name": "cJSON", "version": match.group(1), "purl": None,
                "cpe": None, "ecosystem": "generic", "declaration": "inferred-vendored",
                "source": {"path": source_path, "sha256": source_files[source_path]},
                "member": {"path": path, "reason": member["reason"],
                           "signal_ids": member.get("signal_ids", [])},
                "header": {"path": header_path, "sha256": source_files[header_path]}})
    candidates.sort(key=lambda row: (row["member"]["path"], row["version"]))
    if len({row["member"]["path"] for row in candidates}) != len(candidates):
        raise WorkerBlocked(f"{job}: accepted build index repeats a cJSON vendored member")

    evidence = {"schema": "appsec-review/build-index-sbom-enrichment/1.0",
        "run_id": request["run_id"], "job_id": job, "attempt_id": attempt_id,
        "producer_id": _BUILD_INDEX_TOOL_ID, "build_index_binding": binding,
        "members": [{"name": row["name"], "version": row["version"],
                     "member": row["member"], "source": row["source"], "header": row["header"],
                     "purl": None, "cpe": None} for row in candidates],
        "coverage_gaps": (["Vendored-member inference supplies no purl or CPE; vulnerability matching remains uncovered."]
                          if candidates else [])}
    evidence_bytes = _canonical(evidence)
    existing = {(str(row.get("name", "")).lower(), row.get("version"), row.get("source", {}).get("path"))
                for row in syft_rows if isinstance(row, dict) and isinstance(row.get("source"), dict)}
    rows, gaps = [], []
    for row in candidates:
        identity = ("cjson", row["version"], row["source"]["path"])
        if identity in existing:
            continue
        rows.append({key: row[key] for key in
                     ("name", "version", "purl", "cpe", "ecosystem", "declaration", "source")})
        gaps.append("vendored-component-inferred-without-package-identifier:" + row["member"]["path"])
    citation = {"source_class": "raw", "producer": job, "attempt_id": attempt_id,
                "path": _BUILD_INDEX_ENRICHMENT,
                "sha256": _hash_bytes(evidence_bytes).split(":", 1)[1]}
    for row in rows:
        row["tool_id"] = _BUILD_INDEX_TOOL_ID
        row["citation"] = citation
    return rows, evidence_bytes, gaps


def build_sbom(request: dict[str, Any], attempt_id: str) -> tuple[dict[str, bytes], list[str]]:
    job = JOBS["sbom"][0]; base = _base(request, job)
    tool, receipt, output = _tool(request, job, "syft")
    syft_rows = _sbom_rows(tool, request, job)
    enriched_rows, enrichment_bytes, enrichment_gaps = _build_index_rows(request, attempt_id, syft_rows)
    rows = syft_rows + enriched_rows
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
        assertion = ("inventory-coverage-gap" if declaration == "inferred-vendored" else
                     "component-version-unknown" if raw.get("version") is None else "declared-component-present")
        component = {"component_id": _component_id({**identity, "source": source}), "assertion": assertion,
                     "declaration": declaration, **identity,
                     "source": {"evidence_kind": evidence_kind, **source},
                     "tool_id": raw.get("tool_id", receipt["tool_id"]),
                     "citation": raw.get("citation", _citation(receipt, output))}
        components.append(component)
    components.sort(key=lambda row: row["component_id"])
    if len({row["component_id"] for row in components}) != len(components):
        raise WorkerBlocked(f"{job}: component identities collide")
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "components": [{"bom-ref": row["component_id"], "name": row["name"],
                           **({"version": row["version"]} if row["version"] else {}),
                           **({"purl": row["purl"]} if row["purl"] else {})} for row in components]}
    cdx_bytes = _canonical(cdx)
    result = {"schema": "appsec-review/sbom-inventory/1.0", **base, "attempt_id": attempt_id,
              "redactor": REDACTOR, "generated_at": request["generated_at"],
              "sbom_document": {"path": "outputs/sbom.cdx.json", "sha256": _hash_bytes(cdx_bytes),
                                "bytes": len(cdx_bytes), "bom_format": "CycloneDX", "spec_version": "1.5"},
              "enrichment_document": {"path": _BUILD_INDEX_ENRICHMENT,
                                      "sha256": _hash_bytes(enrichment_bytes),
                                      "producer_id": _BUILD_INDEX_TOOL_ID},
              "components": components}
    errors = validate_document(result, "sbom-inventory.schema.json")
    errors += build_index_enrichment_errors(result, enrichment_bytes)
    if errors: raise WorkerBlocked(f"{job}: normalized result violates schema ({len(errors)} errors; first: {'; '.join(str(e)[:200] for e in errors[:3])})")
    gaps = enrichment_gaps or ([] if components else ["no-dependency-components-detected"])
    return {"outputs/sbom.cdx.json": cdx_bytes, "outputs/sbom-manifest.json": _canonical(result),
            _BUILD_INDEX_ENRICHMENT: enrichment_bytes,
            "outputs/pinned-tool-evidence.json": _canonical(receipt)}, gaps


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


def _component_for(component_by_id: dict[str, dict[str, Any]], *, purl: Any = None,
                   cpes: Any = None, name: Any = None, version: Any = None,
                   ecosystem: Any = None) -> tuple[str, str] | None:
    if isinstance(purl, str):
        for identifier, component in component_by_id.items():
            if component.get("purl") == purl: return identifier, "purl"
    if isinstance(cpes, list):
        for cpe in cpes:
            for identifier, component in component_by_id.items():
                if component.get("cpe") == cpe: return identifier, "cpe"
    # osv-scanner 1.x omits purl from its result package identity even when the
    # input CycloneDX component carried one.  Bind its exact name, version and
    # ecosystem tuple back to one and only one purl-bearing SBOM component.
    aliases = {"RubyGems": "gem", "Go": "golang", "PyPI": "pypi", "Maven": "maven",
               "npm": "npm", "NuGet": "nuget", "crates.io": "cargo", "Packagist": "composer"}
    normalized_ecosystem = aliases.get(ecosystem, str(ecosystem).lower() if isinstance(ecosystem, str) else None)
    if isinstance(name, str) and isinstance(version, str) and normalized_ecosystem:
        candidates = [(identifier, component) for identifier, component in component_by_id.items()
                      if component.get("name") == name and component.get("version") == version and
                      component.get("ecosystem") == normalized_ecosystem and component.get("purl")]
        if len(candidates) == 1:
            return candidates[0][0], "purl"
    return None


def _sca_rows(tool: dict[str, Any], component_by_id: dict[str, dict[str, Any]], database: str,
              job: str) -> list[dict[str, Any]]:
    if isinstance(tool.get("matches"), list) and all(isinstance(row, dict) and "component_ref" in row
                                                     for row in tool["matches"]):
        return tool["matches"]
    rows = []
    if database == "grype" and isinstance(tool.get("matches"), list):
        for item in tool["matches"]:
            artifact = item.get("artifact") if isinstance(item, dict) else None
            vulnerability = item.get("vulnerability") if isinstance(item, dict) else None
            if not isinstance(artifact, dict) or not isinstance(vulnerability, dict):
                raise WorkerBlocked(f"{job}: Grype match is malformed")
            located = _component_for(component_by_id, purl=artifact.get("purl"), cpes=artifact.get("cpes"))
            if located is None: raise WorkerBlocked(f"{job}: Grype match does not resolve into the exact SBOM")
            aliases = [vulnerability.get("id")]
            aliases.extend(row.get("id") for row in vulnerability.get("relatedVulnerabilities", []) if isinstance(row, dict))
            rows.append({"component_ref": located[0], "aliases": [value for value in aliases if isinstance(value, str)],
                         "database": "grype-db", "advisory_id": vulnerability.get("id"),
                         "match_basis": located[1]})
    elif database == "osv" and isinstance(tool.get("results"), list):
        for result in tool["results"]:
            for package in result.get("packages", []) if isinstance(result, dict) else []:
                package_id = package.get("package") if isinstance(package, dict) else None
                located = _component_for(component_by_id,
                    purl=package_id.get("purl") if isinstance(package_id, dict) else None,
                    name=package_id.get("name") if isinstance(package_id, dict) else None,
                    version=package_id.get("version") if isinstance(package_id, dict) else None,
                    ecosystem=package_id.get("ecosystem") if isinstance(package_id, dict) else None)
                if located is None: raise WorkerBlocked(f"{job}: OSV match does not resolve into the exact SBOM")
                for vulnerability in package.get("vulnerabilities", []):
                    if not isinstance(vulnerability, dict): raise WorkerBlocked(f"{job}: OSV advisory is malformed")
                    aliases = [vulnerability.get("id"), *vulnerability.get("aliases", [])]
                    rows.append({"component_ref": located[0], "aliases": [v for v in aliases if isinstance(v, str)],
                                 "database": "osv", "advisory_id": vulnerability.get("id"), "match_basis": "purl"})
    else:
        raise WorkerBlocked(f"{job}: raw matcher export has an unsupported shape")
    return rows


def build_sca(request: dict[str, Any], attempt_id: str) -> tuple[dict[str, bytes], list[str]]:
    job = JOBS["sca"][0]; base = _base(request, job)
    sbom, binding, _ = _upstream(request, "sbom", JOBS["sbom"][0], JOBS["sbom"][2])
    if sbom.get("source_snapshot_sha256") != request["source_snapshot_sha256"]:
        raise WorkerBlocked(f"{job}: SBOM has mixed source lineage")
    tool, receipt, output = _tool(request, job, "grype")
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
    purl_refs = sorted(row["component_id"] for row in sbom["components"]
                       if isinstance(row.get("purl"), str) and row["purl"])
    supplied_applicability = request.get("osv_applicability")
    expected_applicability = {
        "decision": "EXECUTE" if purl_refs else "SKIPPED_NA",
        "reason": None if purl_refs else "no-purl-bearing-components",
        "examined_component_count": len(sbom["components"]),
        "purl_component_count": len(purl_refs),
        "purl_component_refs": purl_refs,
    }
    if supplied_applicability != expected_applicability:
        raise WorkerBlocked(f"{job}: OSV applicability decision differs from the accepted SBOM")
    osv_executes = expected_applicability["decision"] == "EXECUTE"
    if osv_executes:
        if "osv_b13_attempt" not in request:
            raise WorkerBlocked(f"{job}: applicable OSV scan requires verified offline execution evidence")
        supplemental = _tool(request, job, "osv", "osv_")
    else:
        if "osv_b13_attempt" in request:
            raise WorkerBlocked(f"{job}: non-applicable OSV scan must not carry execution evidence")
        supplemental = None
    gaps, evaluated = [], []
    for component in sbom["components"]:
        reason = required_gap_reason(component)
        if reason:
            gaps.append({"gap_id": "VG-" + component["component_id"][3:], "assertion": "match-coverage-gap",
                         "component_ref": component["component_id"], "ecosystem": component["ecosystem"], "reason": reason})
        else:
            evaluated_by = ["grype-db"] + (["osv"] if osv_executes and component.get("purl") else [])
            evaluated.append({"component_ref": component["component_id"], "outcome": "no-advisory-matched",
                              "version_scheme": version_scheme_for(component), "evaluated_by": evaluated_by})
    raw_matches = _sca_rows(tool, by_id, "grype", job)
    if supplemental is not None:
        raw_matches.extend(_sca_rows(supplemental[0], by_id, "osv", job))
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in raw_matches:
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
    osv_database = next(item["database"] for item in identities if item["database"]["database_kind"] == "osv")
    applicability_doc = {
        "schema": "appsec-review/osv-applicability-receipt/1.0", **header,
        "tool_id": "osv-scanner", "sbom_binding": binding,
        **expected_applicability, "database_identity": osv_database,
    }
    docs = [(result, "sca-vulnerability-match.schema.json"), (gap_doc, "sca-vulnerability-match-coverage-gaps.schema.json"),
            (summary, "sca-vulnerability-match-gap-summary.schema.json"),
            (identities_doc, "sca-vulnerability-match-database-identities.schema.json"),
            (applicability_doc, "osv-applicability-receipt.schema.json")]
    if any(validate_document(doc, schema) for doc, schema in docs):
        raise WorkerBlocked(f"{job}: normalized result violates a closed schema")
    return ({"outputs/sca-vulnerability-match.json": _canonical(result), "outputs/sca-coverage-gaps.json": gap_bytes,
            "outputs/coverage-gap-summary.json": _canonical(summary),
            "outputs/vulnerability-database-identities.json": _canonical(identities_doc),
            "outputs/osv-applicability-receipt.json": _canonical(applicability_doc),
            "outputs/pinned-tool-evidence.json": _canonical(receipt)},
            (["SCA_COMPONENT_GAPS"] if gaps else []) +
            (["OSV_SKIPPED_NA_NO_PURL_COMPONENTS"] if not osv_executes else []))


def build_license(request: dict[str, Any], attempt_id: str) -> tuple[dict[str, bytes], list[str]]:
    job = JOBS["license"][0]; base = _base(request, job)
    sbom, binding, _ = _upstream(request, "sbom", JOBS["sbom"][0], JOBS["sbom"][2])
    if sbom.get("source_snapshot_sha256") != request["source_snapshot_sha256"]:
        raise WorkerBlocked(f"{job}: SBOM has mixed source lineage")
    try:
        tool, receipt, output = _tool(request, job, "scancode", allow_gap=True)
    except ToolGap as gap:
        # ADR-0013: scancode TIMEOUT/OOM/failed exit -> no license records, one recorded gap; the
        # gap record is derived from the re-verified B13 attempt (doom3-bfg, freeciv21).
        result = {"schema": "appsec-review/license-inventory/1.0", **base, "attempt_id": attempt_id,
                  "redactor": REDACTOR, "sbom_binding": binding, "records": []}
        if validate_document(result, "license-inventory.schema.json"):
            raise WorkerBlocked(f"{job}: normalized result violates schema")
        return {"outputs/license-inventory.json": _canonical(result),
                "outputs/pinned-tool-gap.json": _canonical(gap.record)}, [gap.gap]
    component_ids = {row["component_id"] for row in sbom["components"]}
    raw_records = tool.get("records")
    if not isinstance(raw_records, list) and isinstance(tool.get("files"), list):
        source_files = _source_files(request, job); raw_records = []
        for file_record in tool["files"]:
            path = file_record.get("path") if isinstance(file_record, dict) else None
            if isinstance(path, str): path = path.removeprefix("/workspace/")
            if path not in source_files: continue
            detections = file_record.get("license_detections")
            if not isinstance(detections, list): detections = file_record.get("licenses", [])
            for detection in detections:
                if not isinstance(detection, dict): continue
                expression = (detection.get("license_expression_spdx") or detection.get("spdx_license_key") or
                              detection.get("key"))
                if not isinstance(expression, str) or not expression: continue
                component_ref = None
                owners = [row for row in sbom["components"]
                          if path == row["source"]["path"] or path.startswith(str(PurePosixPath(row["source"]["path"]).parent) + "/")]
                if len(owners) == 1: component_ref = owners[0]["component_id"]
                raw_records.append({"assertion": "license-text-detected", "component_ref": component_ref,
                    "license_expression": expression, "expression_state": "spdx-expression",
                    "claim_source": {"kind": "found-in-file", "path": path, "sha256": source_files[path],
                                     "start_line": detection.get("start_line"), "end_line": detection.get("end_line")}})
    if not isinstance(raw_records, list):
        raise WorkerBlocked(f"{job}: ScanCode export has no files or normalized records")
    records = []
    for index, raw in enumerate(raw_records, 1):
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
    fingerprint = _hash_bytes(_canonical({"kind": kind, "request": request, "implementation": IMPLEMENTATION}))
    attempt_id = job + "-" + fingerprint[7:27]
    artifacts, gaps = BUILDERS[kind](request, attempt_id)
    permission, lineage = _producer_receipts(request, job)
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
        if (_json(attempt / "permission.json") != permission or
                _json(attempt / "lineage.json") != lineage):
            raise WorkerBlocked(f"{job}: immutable attempt producer receipts changed")
        accepted = _json(pointer)
        if (accepted.get("attempt_id") != attempt_id or
                _hash_file(attempt / "result.json").split(":", 1)[1] != accepted.get("envelope_sha256")):
            raise WorkerBlocked(f"{job}: accepted pointer changed")
        if "hashes" not in accepted or not (root / "latest.json").is_file():
            _publish_pointer(root, attempt, request["run_id"], job, attempt_id, envelope["execution_status"], fingerprint)
        return envelope
    # A later, independently verified orchestration attempt may supersede the current pointer.
    # The new immutable attempt is completely materialized and validated before the atomic pointer
    # replacement below, so failures cannot fall back silently or corrupt the accepted generation.
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
        (staging / "permission.json").write_bytes(_canonical(permission))
        (staging / "lineage.json").write_bytes(_canonical(lineage))
        paths = sorted(artifacts) + ["inputs.json", "permission.json", "lineage.json"]
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
    _publish_pointer(root, attempt, request["run_id"], job, attempt_id, status, fingerprint)
    return envelope


def _publish_pointer(root: Path, attempt: Path, run_id: str, job: str, attempt_id: str,
                     status: str, fingerprint: str) -> None:
    """Write the full common accepted pointer (with tree hashes) and latest.json, so envelope
    consumers such as 02-evidence-assembly bind this producer like any other worker."""
    from execution_state import tree_hashes
    latest = root / (".latest." + attempt_id)
    latest.write_bytes(_canonical({"attempt_id": attempt_id,
                                   "updated_at": datetime.now(timezone.utc).isoformat()}))
    os.replace(latest, root / "latest.json")
    temporary = root / (".accepted." + attempt_id)
    temporary.write_bytes(_canonical({"schema": "appsec-review/accepted-worker-result/1.0", "run_id": run_id,
        "job": job, "attempt_id": attempt_id, "status": status, "fingerprint": fingerprint,
        "envelope_path": "result.json", "envelope_sha256": _hash_file(attempt / "result.json").split(":", 1)[1],
        "hashes": tree_hashes(attempt), "accepted_at": datetime.now(timezone.utc).isoformat()}))
    os.replace(temporary, root / "accepted.json")


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
