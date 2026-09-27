#!/usr/bin/env python3
"""Human-signoff ledger and immutable final publication package.

Draft synthesis remains non-final.  This module can only publish bytes already named and hashed by
the draft publication manifest, after an append-only human decision binds the exact report hash.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any

from execution_state import Blocked, atomic_json, digest, file_hash, read_json
from schema_validate import validate_document

SIGNOFF_SCHEMA = "appsec-review/human-signoff-ledger/1.0"
FINAL_SCHEMA = "appsec-review/final-publication/1.0"


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def append_signoff(ledger: dict[str, Any] | None, *, run_id: str, reviewer_id: str,
                   report_sha256: str, decision: str, signed_at: str, rationale: str) -> dict[str, Any]:
    if decision not in {"APPROVED", "REJECTED"}:
        raise Blocked("final publication: signoff decision is invalid")
    if not reviewer_id or not signed_at or not rationale or not report_sha256.startswith("sha256:"):
        raise Blocked("final publication: signoff identity or binding is incomplete")
    current = deepcopy(ledger) if ledger is not None else {
        "schema": SIGNOFF_SCHEMA, "run_id": run_id, "entries": [], "head_hash": None}
    if (set(current) != {"schema", "run_id", "entries", "head_hash"} or
            current["schema"] != SIGNOFF_SCHEMA or current["run_id"] != run_id):
        raise Blocked("final publication: signoff ledger identity is invalid")
    previous = None
    for sequence, entry in enumerate(current["entries"]):
        if (entry.get("sequence") != sequence or entry.get("previous_entry_hash") != previous or
                entry.get("entry_hash") != _sha({key: value for key, value in entry.items()
                                                 if key != "entry_hash"})):
            raise Blocked("final publication: signoff ledger chain is invalid")
        previous = entry["entry_hash"]
    if current["head_hash"] != previous:
        raise Blocked("final publication: signoff ledger head is invalid")
    entry = {"sequence": len(current["entries"]), "signoff_id": "signoff-" + digest({
        "run_id": run_id, "reviewer_id": reviewer_id, "report_sha256": report_sha256,
        "decision": decision, "signed_at": signed_at})[:24], "reviewer_id": reviewer_id,
        "report_sha256": report_sha256, "decision": decision, "signed_at": signed_at,
        "rationale": rationale, "previous_entry_hash": previous, "entry_hash": ""}
    entry["entry_hash"] = _sha({key: value for key, value in entry.items() if key != "entry_hash"})
    current["entries"].append(entry); current["head_hash"] = entry["entry_hash"]
    errors = validate_document(current, "human-signoff-ledger.schema.json")
    if errors: raise Blocked(f"final publication: generated signoff ledger is invalid ({errors[0]})")
    return current


def validate_signoff(ledger: dict[str, Any], *, run_id: str, report_sha256: str) -> dict[str, Any]:
    # Reuse append validation without mutating the caller by walking the chain directly.
    if ledger.get("schema") != SIGNOFF_SCHEMA or ledger.get("run_id") != run_id:
        raise Blocked("final publication: signoff ledger identity is invalid")
    errors = validate_document(ledger, "human-signoff-ledger.schema.json")
    if errors: raise Blocked(f"final publication: signoff ledger schema is invalid ({errors[0]})")
    previous = None
    for sequence, entry in enumerate(ledger.get("entries", [])):
        if (entry.get("sequence") != sequence or entry.get("previous_entry_hash") != previous or
                entry.get("entry_hash") != _sha({key: value for key, value in entry.items()
                                                 if key != "entry_hash"})):
            raise Blocked("final publication: signoff ledger chain is invalid")
        previous = entry["entry_hash"]
    if ledger.get("head_hash") != previous or not ledger.get("entries"):
        raise Blocked("final publication: signoff ledger is empty or has an invalid head")
    latest = ledger["entries"][-1]
    if latest.get("report_sha256") != report_sha256 or latest.get("decision") != "APPROVED":
        raise Blocked("final publication: latest human signoff does not approve the exact report")
    return latest


def _safe_artifact(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise Blocked("final publication: draft artifact path is unsafe")
    cursor = root
    for part in path.parts:
        cursor /= part
        if cursor.is_symlink():
            raise Blocked("final publication: draft artifact traverses a symlink")
    if not cursor.is_file():
        raise Blocked("final publication: draft artifact is missing")
    try: cursor.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc: raise Blocked("final publication: draft artifact escapes") from exc
    return cursor


def publish(draft_attempt: Path, signoff_ledger: dict[str, Any], final_root: Path) -> dict[str, Any]:
    draft_attempt, final_root = Path(draft_attempt), Path(final_root)
    if final_root.exists():
        raise Blocked("final publication: immutable final package already exists")
    if draft_attempt.is_symlink() or not draft_attempt.is_dir():
        raise Blocked("final publication: draft attempt is unsafe")
    publication_path = _safe_artifact(draft_attempt, "publication-manifest.json")
    publication = read_json(publication_path)
    if (publication.get("status") != "DRAFT_EVIDENCE_BACKED" or publication.get("final") is not False or
            publication.get("human_signoff") is not False):
        raise Blocked("final publication: source package is not a non-final evidence-backed draft")
    artifacts = publication.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise Blocked("final publication: draft publication has no artifacts")
    seen, verified = set(), []
    for record in artifacts:
        if not isinstance(record, dict) or set(record) != {"path", "sha256"} or record["path"] in seen:
            raise Blocked("final publication: draft artifact record is invalid")
        seen.add(record["path"]); path = _safe_artifact(draft_attempt, record["path"])
        actual = "sha256:" + file_hash(path)
        if actual != record["sha256"]:
            raise Blocked("final publication: draft artifact changed")
        verified.append((record["path"], path, actual))
    report_record = next((item for item in verified if item[0] == "report.json"), None)
    if report_record is None:
        raise Blocked("final publication: draft report.json is absent")
    signoff = validate_signoff(signoff_ledger, run_id=publication["run_id"],
                               report_sha256=report_record[2])
    parent = final_root.parent; parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".final-publication-", dir=parent))
    try:
        for relative, source, _hash in verified:
            destination = staging.joinpath(*Path(relative).parts); destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        atomic_json(staging / "human-signoff-ledger.json", signoff_ledger)
        manifest = {"schema": FINAL_SCHEMA, "run_id": publication["run_id"],
            "status": "FINAL_APPROVED", "draft_publication_sha256": "sha256:" + file_hash(publication_path),
            "signoff_head_sha256": signoff_ledger["head_hash"], "signoff_id": signoff["signoff_id"],
            "artifacts": [{"path": relative, "sha256": value} for relative, _source, value in verified],
            "final": True, "human_signoff": True}
        errors = validate_document(manifest, "final-publication.schema.json")
        if errors: raise Blocked(f"final publication: final manifest is invalid ({errors[0]})")
        atomic_json(staging / "final-publication.json", manifest)
        try: os.replace(staging, final_root)
        except OSError as exc: raise Blocked("final publication: atomic package publication failed") from exc
        return manifest
    finally:
        if staging.exists(): shutil.rmtree(staging)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--draft-attempt", type=Path, required=True)
    parser.add_argument("--signoff-ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(publish(args.draft_attempt, read_json(args.signoff_ledger), args.output), indent=2))
