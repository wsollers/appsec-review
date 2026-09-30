#!/usr/bin/env python3
"""Human-signoff ledger and immutable final publication package.

Draft synthesis remains non-final.  This module can only publish bytes already named and hashed by
the draft publication manifest, after an append-only human decision binds the exact report hash.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any

import dev_restart
from execution_state import Blocked, atomic_json, digest, file_hash, read_json, run_path
from schema_validate import validate_document
import synthesis_sarif

SIGNOFF_SCHEMA = "appsec-review/human-signoff-ledger/1.0"
FINAL_SCHEMA = "appsec-review/final-publication/1.0"
PUBLISHER_OWNED = frozenset({
    "critical-findings.sarif", "human-signoff-ledger.json", "final-publication.json"})

def prepare(run_id: str, dagster_run_id: str, force: bool = False):
    """Retain the exact draft's honest pending-approval state; never create human authority."""
    from control_feature_lifecycle import run as lifecycle_run
    return lifecycle_run(run_id, dagster_run_id, "final-publication-preparation", force)


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def sign_authorization(*, run_id: str, reviewer_id: str, report_sha256: str, decision: str,
                       issued_at: str, authorization_id: str, key: bytes) -> dict[str, str]:
    """Create a keyed operator authorization receipt; the key remains outside the ledger."""
    receipt = {"authorization_id": authorization_id, "run_id": run_id,
        "reviewer_id": reviewer_id, "report_sha256": report_sha256, "decision": decision,
        "permission": "approve-final-publication", "issued_at": issued_at}
    payload = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    return {**receipt, "hmac_sha256": "sha256:" + hmac.new(key, payload, hashlib.sha256).hexdigest()}


def _verify_authorization(value: dict[str, Any], *, key: bytes, run_id: str, reviewer_id: str,
                          report_sha256: str, decision: str) -> None:
    if not isinstance(key, bytes) or len(key) < 32 or not isinstance(value, dict):
        raise Blocked("final publication: trusted authorization verifier is unavailable")
    expected_fields = {"authorization_id", "run_id", "reviewer_id", "report_sha256", "decision",
                       "permission", "issued_at", "hmac_sha256"}
    if (set(value) != expected_fields or value.get("run_id") != run_id or
            value.get("reviewer_id") != reviewer_id or value.get("report_sha256") != report_sha256 or
            value.get("decision") != decision or value.get("permission") != "approve-final-publication"):
        raise Blocked("final publication: authorization identity or scope is invalid")
    unsigned = {name: value[name] for name in expected_fields if name != "hmac_sha256"}
    payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    expected = "sha256:" + hmac.new(key, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(value.get("hmac_sha256", ""), expected):
        raise Blocked("final publication: authorization signature is invalid")


def append_signoff(ledger: dict[str, Any] | None, *, run_id: str, reviewer_id: str,
                   report_sha256: str, decision: str, signed_at: str, rationale: str,
                   authorization: dict[str, Any], authorization_key: bytes,
                   expected_prior_head: str) -> dict[str, Any]:
    if decision not in {"APPROVED", "REJECTED"}:
        raise Blocked("final publication: signoff decision is invalid")
    if not reviewer_id or not signed_at or not rationale or not report_sha256.startswith("sha256:"):
        raise Blocked("final publication: signoff identity or binding is incomplete")
    _verify_authorization(authorization, key=authorization_key, run_id=run_id,
                          reviewer_id=reviewer_id, report_sha256=report_sha256, decision=decision)
    current = deepcopy(ledger) if ledger is not None else {
        "schema": SIGNOFF_SCHEMA, "run_id": run_id, "anchor_hash": expected_prior_head,
        "entries": [], "head_hash": expected_prior_head}
    if (set(current) != {"schema", "run_id", "anchor_hash", "entries", "head_hash"} or
            current["schema"] != SIGNOFF_SCHEMA or current["run_id"] != run_id):
        raise Blocked("final publication: signoff ledger identity is invalid")
    if current["head_hash"] != expected_prior_head:
        raise Blocked("final publication: external ledger head does not match")
    previous = current["anchor_hash"]
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
        "rationale": rationale, "authorization": deepcopy(authorization),
        "previous_entry_hash": previous, "entry_hash": ""}
    entry["entry_hash"] = _sha({key: value for key, value in entry.items() if key != "entry_hash"})
    current["entries"].append(entry); current["head_hash"] = entry["entry_hash"]
    errors = validate_document(current, "human-signoff-ledger.schema.json")
    if errors: raise Blocked(f"final publication: generated signoff ledger is invalid ({errors[0]})")
    return current


def validate_signoff(ledger: dict[str, Any], *, run_id: str, report_sha256: str,
                     authorization_key: bytes, expected_anchor: str, expected_current_head: str) -> dict[str, Any]:
    # Reuse append validation without mutating the caller by walking the chain directly.
    if ledger.get("schema") != SIGNOFF_SCHEMA or ledger.get("run_id") != run_id:
        raise Blocked("final publication: signoff ledger identity is invalid")
    errors = validate_document(ledger, "human-signoff-ledger.schema.json")
    if errors: raise Blocked(f"final publication: signoff ledger schema is invalid ({errors[0]})")
    if ledger.get("anchor_hash") != expected_anchor:
        raise Blocked("final publication: signoff ledger anchor is not trusted")
    if ledger.get("head_hash") != expected_current_head:
        raise Blocked("final publication: signoff ledger is not the externally trusted current head")
    previous = expected_anchor
    for sequence, entry in enumerate(ledger.get("entries", [])):
        if (entry.get("sequence") != sequence or entry.get("previous_entry_hash") != previous or
                entry.get("entry_hash") != _sha({key: value for key, value in entry.items()
                                                 if key != "entry_hash"})):
            raise Blocked("final publication: signoff ledger chain is invalid")
        _verify_authorization(entry.get("authorization"), key=authorization_key, run_id=run_id,
                              reviewer_id=entry.get("reviewer_id"),
                              report_sha256=entry.get("report_sha256"), decision=entry.get("decision"))
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


def _publish_documents(draft_attempt: Path, signoff_ledger: dict[str, Any], final_root: Path, *,
            authorization_key: bytes, expected_ledger_anchor: str,
            expected_ledger_head: str,
            completeness_audit: dict[str, Any], terminal_feedback: dict[str, Any],
            completion_bindings: dict[str, Any], publication_preparation: dict[str, Any]) -> dict[str, Any]:
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
    audit_errors=validate_document(completeness_audit,"completeness-audit.schema.json")
    feedback_errors=validate_document(terminal_feedback,"synthetic-hypothesis-resynthesis.schema.json")
    preparation_errors=validate_document(publication_preparation,"final-publication-preparation.schema.json")
    if audit_errors or feedback_errors or preparation_errors:
        raise Blocked("final publication: completion evidence schema is invalid")
    if (completeness_audit.get("run_id")!=publication.get("run_id") or
            terminal_feedback.get("run_id")!=publication.get("run_id") or
            terminal_feedback.get("audit_sha256")!=_sha(completeness_audit) or
            completeness_audit.get("complete") is not True or
            terminal_feedback.get("terminal_state")!="COMPLETE" or
            terminal_feedback.get("unresolved_obligation_ids")!=[]):
        raise Blocked("final publication: completion validator did not reach a publishable terminal state")
    artifacts = publication.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise Blocked("final publication: draft publication has no artifacts")
    seen, verified = set(), []
    for record in artifacts:
        if not isinstance(record, dict) or set(record) != {"path", "sha256"} or record["path"] in seen:
            raise Blocked("final publication: draft artifact record is invalid")
        if record["path"] in PUBLISHER_OWNED:
            raise Blocked("final publication: draft claims a publisher-owned artifact path")
        seen.add(record["path"]); path = _safe_artifact(draft_attempt, record["path"])
        actual = "sha256:" + file_hash(path)
        if actual != record["sha256"]:
            raise Blocked("final publication: draft artifact changed")
        verified.append((record["path"], path, actual))
    report_record = next((item for item in verified if item[0] == "report.json"), None)
    if report_record is None:
        raise Blocked("final publication: draft report.json is absent")
    if completeness_audit.get("subject_sha256") != report_record[2]:
        raise Blocked("final publication: completeness audit is not bound to the exact report")
    if (publication_preparation.get("draft_report_sha256") != report_record[2] or
            publication_preparation.get("draft_publication_manifest_sha256") !=
            "sha256:" + file_hash(publication_path) or
            publication_preparation.get("completion_gate", {}).get("blockers") != ["human_signoff_missing"]):
        raise Blocked("final publication: preparation is not bound to the exact publishable draft")
    signoff = validate_signoff(signoff_ledger, run_id=publication["run_id"],
                               report_sha256=report_record[2], authorization_key=authorization_key,
                               expected_anchor=expected_ledger_anchor,
                               expected_current_head=expected_ledger_head)
    parent = final_root.parent; parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".final-publication-", dir=parent))
    try:
        for relative, source, _hash in verified:
            destination = staging.joinpath(*Path(relative).parts); destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        sarif_path = staging / "critical-findings.sarif"
        synthesis_sarif.convert(staging / "report.json", staging / "evidence-trace-index.json", sarif_path)
        verified.append(("critical-findings.sarif", sarif_path, "sha256:" + file_hash(sarif_path)))
        atomic_json(staging / "human-signoff-ledger.json", signoff_ledger)
        verified.append(("human-signoff-ledger.json", staging / "human-signoff-ledger.json",
                         "sha256:" + file_hash(staging / "human-signoff-ledger.json")))
        for name,value in (("completion/completeness-audit.json",completeness_audit),
                           ("completion/synthetic-hypothesis-resynthesis.json",terminal_feedback),
                           ("completion/publication-preparation.json",publication_preparation),
                           ("completion/accepted-bindings.json",completion_bindings)):
            atomic_json(staging/name,value)
            verified.append((name,staging/name,"sha256:"+file_hash(staging/name)))
        if len({relative for relative, _source, _hash in verified}) != len(verified):
            raise Blocked("final publication: final artifact path collision")
        manifest = {"schema": FINAL_SCHEMA, "run_id": publication["run_id"],
            "status": "FINAL_APPROVED", "draft_publication_sha256": "sha256:" + file_hash(publication_path),
            "signoff_head_sha256": signoff_ledger["head_hash"], "signoff_id": signoff["signoff_id"],
            "completeness_audit_sha256": _sha(completeness_audit),
            "terminal_feedback_sha256": _sha(terminal_feedback),
            "artifacts": [{"path": relative, "sha256": value} for relative, _source, value in verified],
            "final": True, "human_signoff": True}
        errors = validate_document(manifest, "final-publication.schema.json")
        if errors: raise Blocked(f"final publication: final manifest is invalid ({errors[0]})")
        atomic_json(staging / "final-publication.json", manifest)
        expected_files = {relative for relative, _source, _hash in verified} | {"final-publication.json"}
        actual_files = set()
        for path in staging.rglob("*"):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise Blocked("final publication: final tree contains an unsafe entry")
            if path.is_file():
                actual_files.add(path.relative_to(staging).as_posix())
        if actual_files != expected_files:
            raise Blocked("final publication: final tree is not closed")
        for relative, _source, expected_hash in verified:
            if "sha256:" + file_hash(staging.joinpath(*Path(relative).parts)) != expected_hash:
                raise Blocked("final publication: generated artifact changed before publication")
        try: os.replace(staging, final_root)
        except OSError as exc: raise Blocked("final publication: atomic package publication failed") from exc
        return manifest
    finally:
        if staging.exists(): shutil.rmtree(staging)


def publish(draft_attempt: Path, signoff_ledger: dict[str, Any], final_root: Path, *,
            run_root: Path, completeness_ref: dict[str, Any], feedback_ref: dict[str, Any],
            authorization_key: bytes, expected_ledger_anchor: str,
            expected_ledger_head: str) -> dict[str, Any]:
    """Publish only from exact current accepted completeness and feedback attempts."""
    # ADR-0025: a dev process, or a run with any accepted dev-mode result, is never a deliverable.
    dev_restart.assert_deliverable(Path(run_root))
    publication=read_json(_safe_artifact(Path(draft_attempt),"publication-manifest.json"))
    run_id=publication.get("run_id")
    expected=((completeness_ref,"completeness-audit","completeness-audit","completeness-audit.json"),
              (feedback_ref,"synthetic-hypothesis-resynthesis","synthetic-hypothesis-resynthesis",
               "synthetic-hypothesis-resynthesis.json"))
    for ref,job,contract,artifact in expected:
        if (ref.get("job_id")!=job or ref.get("contract_id")!=contract or
                Path(ref.get("artifact_path","")).name!=artifact):
            raise Blocked("final publication: completion reference names the wrong producer")
    # Import here avoids coupling SARIF conversion to lifecycle pointer loading.
    import synthesis_report
    audit,audit_binding=synthesis_report.load_reference(Path(run_root),run_id,completeness_ref)
    feedback,feedback_binding=synthesis_report.load_reference(Path(run_root),run_id,feedback_ref)
    preparation=_current_preparation(Path(run_root),run_id,Path(draft_attempt))
    return _publish_documents(draft_attempt,signoff_ledger,final_root,
        authorization_key=authorization_key,expected_ledger_anchor=expected_ledger_anchor,
        expected_ledger_head=expected_ledger_head,completeness_audit=audit,
        terminal_feedback=feedback,publication_preparation=preparation,
        completion_bindings={"audit":audit_binding,"feedback":feedback_binding})


def _current_preparation(run_root: Path, run_id: str, draft_attempt: Path) -> dict[str, Any]:
    """Re-derive the publication preparation so human approval cannot bypass newer blockers."""
    import control_feature_lifecycle
    if Path(run_root).absolute()!=run_path(run_id).absolute():
        raise Blocked("final publication: run root is not the canonical engagement root")
    inputs=control_feature_lifecycle.current_inputs(run_id,"final-publication-preparation")
    try:
        if Path(inputs["draft_attempt"]).resolve(strict=True)!=Path(draft_attempt).resolve(strict=True):
            raise Blocked("final publication: preparation names a different draft attempt")
    except OSError as exc:
        raise Blocked("final publication: preparation draft attempt is unavailable") from exc
    result,status,gaps,skip=control_feature_lifecycle._produce(
        run_id,"final-publication-preparation",inputs)
    if (status!="OK_WITH_GAPS" or gaps!=["human-signoff-required"] or skip is not None or
            validate_document(result,"final-publication-preparation.schema.json")):
        raise Blocked("final publication: current preparation is not approval-ready")
    return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--draft-attempt", type=Path, required=True)
    parser.add_argument("--signoff-ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--authorization-key", type=Path, required=True)
    parser.add_argument("--expected-ledger-anchor", required=True)
    parser.add_argument("--expected-ledger-head", required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--completeness-ref", type=Path, required=True)
    parser.add_argument("--feedback-ref", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(publish(args.draft_attempt, read_json(args.signoff_ledger), args.output,
        authorization_key=args.authorization_key.read_bytes(),
        expected_ledger_anchor=args.expected_ledger_anchor,
        expected_ledger_head=args.expected_ledger_head,
        run_root=args.run_root,completeness_ref=read_json(args.completeness_ref),
        feedback_ref=read_json(args.feedback_ref)), indent=2))
