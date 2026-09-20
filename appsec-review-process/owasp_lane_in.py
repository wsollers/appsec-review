#!/usr/bin/env python3
"""Admit explicit, hash-pinned intelligence into an OWASP workbench run.

This is the bounded T03 foundation. It is offline and is not registered in the lifecycle graph.
It never discovers legacy scratch, launches validators, performs dynamic work, or contacts a
target. Every admitted artifact must already be run-owned or an explicit run-owned import.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re
import sys
import uuid
from typing import Any

from execution_state import (
    ROOT, Blocked, Lock, atomic_bytes, atomic_json, beneath, data_path, digest, emergency, event,
    file_hash, identifier, now, read_json, run_path,
)
import reference_snapshots
from schema_validate import validate_document


JOB_ID = "04-owasp-intel-lane-in"
REQUEST_SCHEMA = "appsec-review/owasp-intel-lane-in-request/1.0"
OUTPUT_SCHEMA = "appsec-review/owasp-input-manifest/1.0"
REPO_ROOT = ROOT.parent
DEFAULT_REFERENCE_ROOT = REPO_ROOT / "data" / "reference"
DEFAULT_NVD_ROOT = REPO_ROOT / "data" / "feeds" / "nvd"
REFERENCE_FAMILIES = {
    "owasp_asvs", "owasp_masvs", "owasp_mastg", "owasp_top_10",
    "owasp_api_security_top_10", "owasp_llm_top_10", "opencre",
}


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a nonempty string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp must include timezone: {value!r}")
    return parsed.astimezone(timezone.utc)


def _relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"run-owned path must use nonempty POSIX syntax: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"unsafe run-owned path: {value!r}")
    return path


def _artifact(data_root: Path, record: dict[str, Any]) -> Path:
    relative = _relative(record["path"])
    path = beneath(data_root, data_root.joinpath(*relative.parts))
    if not path.is_file():
        raise Blocked(f"run-owned artifact is missing: {record['path']}")
    if file_hash(path) != record["sha256"]:
        raise Blocked(f"run-owned artifact hash mismatch: {record['path']}")
    return path


def _accepted_producer(data_root: Path, entry: dict[str, Any], artifact: Path) -> None:
    producer = entry.get("producer")
    if not isinstance(producer, dict):
        raise ValueError(f"{entry['input_id']}: accepted output requires producer lineage")
    job_id, attempt_id = identifier(producer["job_id"]), identifier(producer["attempt_id"])
    pointer_ref = {"path": producer["accepted_pointer_path"],
                   "sha256": producer["accepted_pointer_sha256"]}
    pointer_path = _artifact(data_root, pointer_ref)
    if pointer_path.name != "accepted.json":
        raise ValueError(f"{entry['input_id']}: producer pointer must be accepted.json")
    pointer_parts = pointer_path.relative_to(data_root).parts
    if (len(pointer_parts) < 3 or pointer_parts[0] != "jobs" or pointer_parts[1] != job_id or
            "attempts" in pointer_parts):
        raise ValueError(f"{entry['input_id']}: accepted pointer does not belong to the producer job")
    pointer = read_json(pointer_path)
    if pointer.get("status") not in {"OK", "OK_WITH_GAPS"}:
        raise Blocked(f"{entry['input_id']}: producer is not accepted")
    if pointer.get("attempt_id") != attempt_id:
        raise Blocked(f"{entry['input_id']}: accepted pointer attempt mismatch")
    if pointer.get("run_id") not in (None, data_root.parent.name):
        raise Blocked(f"{entry['input_id']}: accepted pointer run mismatch")
    if pointer.get("job_id") not in (None, job_id):
        raise Blocked(f"{entry['input_id']}: accepted pointer job mismatch")
    parts = artifact.relative_to(data_root).parts
    try:
        attempts_at = parts.index("attempts")
    except ValueError:
        raise ValueError(f"{entry['input_id']}: accepted artifact is not beneath an attempt") from None
    if len(parts) <= attempts_at + 1 or parts[0] != "jobs" or parts[1] != job_id or parts[attempts_at + 1] != attempt_id:
        raise ValueError(f"{entry['input_id']}: artifact does not belong to its producer attempt")


def _explicit_import(data_root: Path, entry: dict[str, Any], artifact: Path) -> None:
    parts = artifact.relative_to(data_root).parts
    if len(parts) < 3 or parts[0] != "imports":
        raise ValueError(f"{entry['input_id']}: explicit import must live beneath data/imports/<import_id>")
    import_id = identifier(parts[1])
    receipt_path = beneath(data_root, data_root / "imports" / f"{import_id}.json")
    if not receipt_path.is_file():
        raise Blocked(f"{entry['input_id']}: explicit import receipt is missing")
    receipt = read_json(receipt_path)
    expected_root = f"imports/{import_id}"
    relative = PurePosixPath(*parts[2:]).as_posix()
    if receipt.get("path") != expected_root or receipt.get("hashes", {}).get(relative) != entry["artifact"]["sha256"]:
        raise Blocked(f"{entry['input_id']}: explicit import receipt/hash mismatch")


def _validate_entry(data_root: Path, entry: dict[str, Any]) -> dict[str, Any]:
    artifact = _artifact(data_root, entry["artifact"])
    admission = entry["admission"]
    relative = artifact.relative_to(data_root).as_posix()
    if admission == "accepted_run_output":
        _accepted_producer(data_root, entry, artifact)
    elif admission == "explicit_import":
        if entry.get("producer") is not None:
            raise ValueError(f"{entry['input_id']}: explicit import cannot claim an accepted producer")
        _explicit_import(data_root, entry, artifact)
    else:
        raise ValueError(f"{entry['input_id']}: unsupported admission mode")

    sources = entry["source_artifacts"]
    for source in sources:
        source_path = _artifact(data_root, source)
        if source_path.relative_to(data_root).parts[0] == "imports":
            _explicit_import(data_root, {"input_id": entry["input_id"], "artifact": source}, source_path)
    if entry["evidence_class"] == "derived_intelligence":
        if admission != "accepted_run_output" or not sources:
            raise ValueError(f"{entry['input_id']}: derived intelligence needs an accepted producer and source artifacts")
        if entry.get("derivation_status") not in {"complete", "partial"}:
            raise ValueError(f"{entry['input_id']}: derived intelligence needs derivation status")
        if not entry["caveats"]:
            raise ValueError(f"{entry['input_id']}: derived intelligence needs explicit caveats")
    elif entry.get("derivation_status") is not None:
        raise ValueError(f"{entry['input_id']}: raw evidence cannot claim derivation status")

    index_like = "index" in entry["kind"].lower() or "search" in entry["kind"].lower()
    if index_like:
        if entry["use"] != "locator_only":
            raise ValueError(f"{entry['input_id']}: indexes and search results are locator-only")
        if entry["freshness"]["status"] != "current":
            raise Blocked(f"{entry['input_id']}: stale index is not admissible")
    if entry["use"] == "canonical_evidence" and entry["evidence_class"] == "derived_intelligence":
        raise ValueError(f"{entry['input_id']}: derived intelligence cannot be canonical evidence")
    if entry["freshness"]["status"] == "stale_accepted" and not entry["caveats"]:
        raise ValueError(f"{entry['input_id']}: accepted staleness requires a caveat")

    return {**entry, "artifact": {**entry["artifact"], "path": relative},
            "admission_validated": True,
            "may_support_control_status": entry["use"] == "canonical_evidence"}


def _reference_path(root: Path, selected: dict[str, Any]) -> Path:
    if selected["family"] not in REFERENCE_FAMILIES:
        raise ValueError(f"unsupported reference family: {selected['family']!r}")
    if not re.fullmatch(r"sha256-[0-9a-f]{16}", selected["snapshot_id"]):
        raise ValueError(f"invalid reference snapshot ID: {selected['snapshot_id']!r}")
    if (not selected["edition"] or "/" in selected["edition"] or "\\" in selected["edition"] or
            selected["edition"] in {".", ".."}):
        raise ValueError(f"invalid reference edition: {selected['edition']!r}")
    if selected["family"] == "opencre":
        return root / "opencre" / selected["snapshot_id"]
    return root / "owasp" / selected["family"] / selected["edition"] / selected["snapshot_id"]


def _pin_references(selection: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    pins, identities = [], set()
    for selected in selection["selections"]:
        identity = (selected["family"], selected["edition"], selected["snapshot_id"])
        if identity in identities:
            raise ValueError(f"duplicate standards selection: {identity}")
        identities.add(identity)
        if selected["family"] == "owasp_asvs" and selected["profile_or_level"] != "L2":
            raise Blocked("ASVS 5.0.0 selection must use approved baseline L2")
        snapshot_root = _reference_path(root, selected)
        manifest = reference_snapshots.verify_snapshot(snapshot_root)
        manifest_path = snapshot_root / "manifest.json"
        manifest_hash = file_hash(manifest_path)
        if manifest_hash != selected["manifest_sha256"]:
            raise Blocked(f"selected manifest hash mismatch: {selected['family']}")
        if (manifest["family"] != selected["family"] or manifest["edition"] != selected["edition"] or
                manifest["snapshot_id"] != selected["snapshot_id"]):
            raise Blocked(f"selected reference identity mismatch: {selected['family']}")
        pins.append({
            "family": selected["family"], "edition": selected["edition"],
            "profile_or_level": selected["profile_or_level"], "snapshot_id": selected["snapshot_id"],
            "manifest_path": manifest_path.relative_to(REPO_ROOT).as_posix()
            if manifest_path.is_relative_to(REPO_ROOT) else str(manifest_path),
            "manifest_sha256": manifest_hash,
            "manifest": manifest,
        })
    return pins


def _nvd_identity(value: dict[str, Any]) -> str:
    unsigned = {key: item for key, item in value.items() if key != "snapshot_id"}
    payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    import hashlib
    return "sha256-" + hashlib.sha256(payload).hexdigest()[:16]


def _verify_nvd(root: Path, requested: dict[str, Any], instant: datetime) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    if not requested["requested"]:
        if requested["snapshot_id"] is not None or requested["manifest_sha256"] is not None:
            raise ValueError("unrequested NVD input cannot name a snapshot")
        return None, []
    snapshot_id = requested.get("snapshot_id")
    manifest_hash = requested.get("manifest_sha256")
    if not isinstance(snapshot_id, str) or not isinstance(manifest_hash, str):
        raise Blocked("requested NVD enrichment needs a snapshot ID and manifest hash")
    seen, current = set(), snapshot_id
    selected = None
    while current:
        if current in seen:
            raise ValueError("NVD snapshot parent cycle")
        seen.add(current)
        path = root / "snapshots" / current / "manifest.json"
        if not path.is_file():
            raise Blocked(f"NVD snapshot is missing: {current}")
        manifest = read_json(path)
        errors = validate_document(manifest, "nvd-snapshot-manifest.schema.json")
        if errors:
            raise ValueError("invalid NVD manifest: " + "; ".join(errors))
        if manifest.get("snapshot_id") != current or _nvd_identity(manifest) != current:
            raise ValueError(f"NVD snapshot identity mismatch: {current}")
        if current == snapshot_id:
            if file_hash(path) != manifest_hash:
                raise Blocked("NVD manifest hash mismatch")
            selected = (path, manifest)
        for layer in manifest["layers"]:
            blobs = [layer.get("blob")] if layer.get("blob") else [page.get("blob") for page in layer.get("pages", [])]
            for blob in blobs:
                if not isinstance(blob, dict):
                    raise ValueError("NVD layer has invalid blob record")
                blob_path = beneath(root, root / _relative(blob["path"]))
                if (not blob_path.is_file() or file_hash(blob_path) != blob["sha256"] or
                        blob_path.stat().st_size != blob["size_bytes"]):
                    raise ValueError(f"NVD blob integrity mismatch: {blob['path']}")
        current = manifest.get("parent_snapshot_id")
    if selected is None:
        raise Blocked("requested NVD snapshot could not be verified")
    path, manifest = selected
    captured = _parse_time(manifest["captured_at"])
    age = max(0.0, (instant - captured).total_seconds())
    target = requested.get("advisory_freshness_seconds")
    if target is not None and target < 0:
        raise ValueError("NVD advisory freshness seconds cannot be negative")
    if captured > instant:
        raise ValueError("NVD capture time is in the future")
    stale = target is not None and age > target
    gaps = []
    if stale:
        gaps.append({"gap_id": "nvd-stale-accepted", "kind": "reference_freshness",
                     "summary": f"Pinned NVD snapshot age {int(age)}s exceeds advisory target {target}s; accepted as stale enrichment.",
                     "affected_scope": ["nvd_enrichment"]})
    return {
        "snapshot_id": snapshot_id,
        "manifest_path": path.relative_to(REPO_ROOT).as_posix() if path.is_relative_to(REPO_ROOT) else str(path),
        "manifest_sha256": manifest_hash, "feed_schema": manifest["feed_schema"],
        "manifest": manifest,
        "captured_at": manifest["captured_at"], "cursor": manifest["cursor"],
        "age_seconds": age,
        "freshness_status": "stale_accepted" if stale else "within_advisory_target",
        "limitations": [*manifest["limitations"],
                        "NVD is enrichment only and does not establish product match, reachability, exploitability, severity, or a finding."],
    }, gaps


def _validate_request(run_id: str, request: dict[str, Any], reference_root: Path,
                      nvd_root: Path, clock) -> tuple[dict[str, Any], str]:
    errors = validate_document(request, "owasp-intel-lane-in-request.schema.json")
    if errors:
        raise ValueError("invalid OWASP lane-in request:\n" + "\n".join(errors))
    if request["schema"] != REQUEST_SCHEMA or request["run_id"] != run_id:
        raise ValueError("lane-in request run/schema identity mismatch")
    selection = request["selection"]
    if selection["engagement_id"] != run_id:
        raise ValueError("standards selection engagement does not match run")
    if not selection["selection_id"].strip() or not selection["approver"].strip():
        raise ValueError("standards selection needs nonempty identity and approver")
    _parse_time(selection["approved_at"])
    for selected in selection["selections"]:
        if not selected["enabled_scope"] or any(not scope.strip() for scope in selected["enabled_scope"]):
            raise ValueError(f"{selected['family']}: enabled scope must be explicit and nonempty")
    pins = _pin_references(selection, reference_root)
    data_root = data_path(run_id)
    ids, entries = set(), []
    for entry in request["entries"]:
        if entry["input_id"] in ids:
            raise ValueError(f"duplicate input_id: {entry['input_id']}")
        ids.add(entry["input_id"])
        _parse_time(entry["freshness"]["assessed_at"])
        if entry["source_snapshot"] is not None:
            _parse_time(entry["source_snapshot"]["captured_at"])
        entries.append(_validate_entry(data_root, entry))
    instant = clock()
    if instant.tzinfo is None:
        raise ValueError("lane-in clock must be timezone-aware")
    nvd, nvd_gaps = _verify_nvd(nvd_root, request["nvd"], instant.astimezone(timezone.utc))
    gaps = [*request["completeness_gaps"], *nvd_gaps]
    for gap in gaps:
        if (not gap["gap_id"].strip() or not gap["kind"].strip() or not gap["summary"].strip() or
                any(not scope.strip() for scope in gap["affected_scope"])):
            raise ValueError("lane-in gaps require nonempty identity, kind, summary, and scope values")
    if any(entry["redaction_status"] == "contains_restricted_data" for entry in entries):
        gaps.append({"gap_id": "restricted-input-present", "kind": "redaction",
                     "summary": "One or more admitted inputs contain restricted data; downstream handling must preserve that boundary.",
                     "affected_scope": [entry["input_id"] for entry in entries
                                        if entry["redaction_status"] == "contains_restricted_data"]})
    gap_ids = [gap["gap_id"] for gap in gaps]
    if len(gap_ids) != len(set(gap_ids)):
        raise ValueError("duplicate OWASP lane-in gap_id")
    basis = {"request": request, "reference_snapshots": pins, "entries": entries}
    fingerprint = digest(basis)
    output = {
        "schema": OUTPUT_SCHEMA, "run_id": run_id, "selection_id": selection["selection_id"],
        "selection": selection,
        "input_fingerprint": fingerprint, "admitted_at": instant.astimezone(timezone.utc).isoformat(),
        "permissions": request["permissions"], "reference_snapshots": pins, "entries": entries,
        "nvd": nvd, "gaps": gaps,
        "claim_limits": [
            "Search/index entries are locators and must be dereferenced to canonical evidence before supporting a status.",
            "Derived intelligence is routing context, not canonical target evidence.",
            "Static evidence cannot satisfy dynamic, deployed, runtime, live-state, or manual-observation obligations.",
            "No admitted input by itself establishes a finding, severity, exploitability, compliance, or certification.",
        ],
    }
    errors = validate_document(output, "owasp-input-manifest.schema.json")
    if errors:
        raise ValueError("generated OWASP input manifest is invalid:\n" + "\n".join(errors))
    return output, fingerprint


def _base(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB_ID, "whole")


def _reusable(base: Path, fingerprint: str) -> dict[str, Any] | None:
    accepted_path = base / "accepted.json"
    latest_path = base / "latest.json"
    if not accepted_path.is_file() or not latest_path.is_file():
        return None
    pointer = read_json(accepted_path)
    if pointer.get("status") not in {"OK", "OK_WITH_GAPS"} or pointer.get("input_fingerprint") != fingerprint:
        return None
    attempt_id = identifier(pointer["attempt_id"])
    if read_json(latest_path).get("attempt_id") != attempt_id:
        raise Blocked("OWASP lane-in accepted/latest attempt mismatch")
    attempt = beneath(base, base / "attempts" / attempt_id)
    output = attempt / "outputs" / "owasp-input-manifest.json"
    gaps = attempt / "outputs" / "input-gaps.json"
    expected = pointer.get("artifacts", {})
    for path in (output, gaps):
        relative = path.relative_to(attempt).as_posix()
        if not path.is_file() or expected.get(relative) != file_hash(path):
            raise Blocked("OWASP lane-in accepted artifact is missing or corrupt")
    errors = validate_document(read_json(output), "owasp-input-manifest.schema.json")
    if errors:
        raise Blocked("OWASP lane-in accepted manifest no longer validates")
    if read_json(output).get("input_fingerprint") != fingerprint:
        raise Blocked("OWASP lane-in accepted manifest fingerprint mismatch")
    if validate_document(read_json(gaps), "owasp-input-gaps.schema.json"):
        raise Blocked("OWASP lane-in accepted gaps no longer validate")
    return pointer


def admit(run_id: str, request_path: Path | None = None, *, reference_root: Path | None = None,
          nvd_root: Path | None = None, force: bool = False,
          clock=lambda: datetime.now(timezone.utc)) -> dict[str, Any]:
    run_id = identifier(run_id)
    root = run_path(run_id)
    if not (root / "run-status.json").is_file():
        raise Blocked("create the run through run_process.py --start first")
    request_path = beneath(root, Path(request_path or (root / "inputs" / "owasp-lane-in-request.json")))
    request = read_json(request_path)
    instant = clock()
    if instant.tzinfo is None:
        raise ValueError("lane-in clock must be timezone-aware")
    fixed_clock = lambda: instant
    output, fingerprint = _validate_request(
        run_id, request, Path(reference_root or DEFAULT_REFERENCE_ROOT),
        Path(nvd_root or DEFAULT_NVD_ROOT), fixed_clock,
    )
    base = _base(run_id)
    with Lock(base / "job.lock"):
        if not force:
            reused = _reusable(base, fingerprint)
            if reused:
                return {**reused, "reused": True}
        attempt_id = uuid.uuid4().hex
        attempt = beneath(base, base / "attempts" / attempt_id)
        attempt.mkdir(parents=True, exist_ok=False)
        started = {"status": "RUNNING", "run_id": run_id, "job_id": JOB_ID,
                   "attempt_id": attempt_id, "input_fingerprint": fingerprint,
                   "started_at": now()}
        atomic_json(base / "latest.json", {"attempt_id": attempt_id, "updated_at": now()})
        atomic_json(base / "accepted.json", {"status": "PENDING", "attempt_id": attempt_id,
                                               "input_fingerprint": fingerprint})
        try:
            atomic_json(attempt / "status.json", started)
            atomic_bytes(attempt / "logs" / "stdout.log", b"")
            atomic_bytes(attempt / "logs" / "stderr.log", b"")
            event(attempt / "logs" / "events.jsonl", "START", run_id=run_id,
                  job_id=JOB_ID, attempt_id=attempt_id, input_fingerprint=fingerprint)
            atomic_json(attempt / "inputs.json", request)
            atomic_json(attempt / "validation" / "pre.json",
                        {"status": "OK", "input_fingerprint": fingerprint,
                         "checks": ["request schema", "reference hashes", "run-owned lineage", "permissions"]})
            output_path = attempt / "outputs" / "owasp-input-manifest.json"
            gaps_path = attempt / "outputs" / "input-gaps.json"
            atomic_json(output_path, output)
            atomic_json(gaps_path, {"schema": "appsec-review/owasp-input-gaps/1.0",
                                    "run_id": run_id, "selection_id": output["selection_id"],
                                    "gaps": output["gaps"]})
            rechecked, rechecked_fingerprint = _validate_request(
                run_id, request, Path(reference_root or DEFAULT_REFERENCE_ROOT),
                Path(nvd_root or DEFAULT_NVD_ROOT), fixed_clock,
            )
            if rechecked_fingerprint != fingerprint or rechecked != output:
                raise Blocked("OWASP lane-in inputs changed during admission")
            artifacts = {path.relative_to(attempt).as_posix(): file_hash(path)
                         for path in (output_path, gaps_path)}
            atomic_json(attempt / "validation" / "post.json",
                        {"status": "OK", "schema_validation": "PASS", "artifacts": artifacts})
            status = "OK_WITH_GAPS" if output["gaps"] else "OK"
            terminal = {**started, "status": status, "ended_at": now(), "artifacts": artifacts}
            atomic_json(attempt / "status.json", terminal)
            event(attempt / "logs" / "events.jsonl", "END", status=status,
                  run_id=run_id, job_id=JOB_ID, attempt_id=attempt_id)
            pointer = {"status": status, "run_id": run_id, "job_id": JOB_ID,
                       "attempt_id": attempt_id, "input_fingerprint": fingerprint,
                       "selection_id": output["selection_id"], "artifacts": artifacts,
                       "accepted_at": now()}
            atomic_json(base / "accepted.json", pointer)
            return {**pointer, "reused": False}
        except BaseException as exc:
            failure = {**started, "status": "FAILED", "ended_at": now(),
                       "error_type": type(exc).__name__, "error": str(exc)}
            atomic_json(attempt / "status.json", failure)
            try:
                event(attempt / "logs" / "events.jsonl", "FAILURE", status="FAILED",
                      error_type=type(exc).__name__, run_id=run_id, job_id=JOB_ID,
                      attempt_id=attempt_id)
            except BaseException as diagnostic_error:
                emergency(diagnostic_error)
            atomic_json(base / "accepted.json", {"status": "FAILED", "attempt_id": attempt_id,
                                                   "input_fingerprint": fingerprint})
            raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--reference-root", type=Path)
    parser.add_argument("--nvd-root", type=Path)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = admit(args.run_id, args.request, reference_root=args.reference_root,
                       nvd_root=args.nvd_root, force=args.force)
    except (Blocked, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"OWASP_LANE_IN_BLOCKED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
