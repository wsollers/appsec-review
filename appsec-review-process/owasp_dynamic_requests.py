#!/usr/bin/env python3
"""Validate and publish offline OWASP dynamic/manual request lifecycle records (T09).

This worker is a request ledger, not a launcher.  It validates exact upstream lineage and
explicitly supplied candidate files, but never authorizes or performs dynamic or manual work.
Execute/launch operations publish a deterministic disabled receipt without target contact.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re
import sys
import uuid
from typing import Any

from execution_state import (Blocked, Lock, atomic_bytes, atomic_json, beneath, data_path, digest,
                             emergency, event, file_hash, identifier, now, read_json, run_path)
import owasp_intercom
import owasp_validator_handoff
import owasp_validator_result
from schema_validate import validate_document


JOB_ID = "04-owasp-dynamic-manual-requests"
REQUEST_SCHEMA = "appsec-review/owasp-dynamic-request-publication/1.0"
CANDIDATE_SCHEMA = "appsec-review/owasp-dynamic-manual-request/1.0"
LEDGER_SCHEMA = "appsec-review/owasp-dynamic-request-ledger/1.0"
SUCCESS = {"OK", "OK_WITH_GAPS"}
STATES = {"proposed", "authorized", "executed", "ingested", "reassessed", "canceled", "blocked"}
TRANSITIONS = {
    None: {"proposed", "blocked"},
    "proposed": {"authorized", "canceled", "blocked"},
    "authorized": {"executed", "canceled", "blocked"},
    "executed": {"ingested", "canceled", "blocked"},
    "ingested": {"reassessed", "blocked"},
    "blocked": {"proposed", "canceled"},
    "reassessed": set(), "canceled": set(),
}
EXTERNAL_STATES = {"authorized", "executed", "ingested", "reassessed"}
STATE_ARTIFACT_KINDS = {
    "authorized": "authorization", "executed": "execution_result",
    "ingested": "ingestion_receipt", "reassessed": "reassessment_result",
}
SECRET = re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|password|secret)\b\s*[:=]\s*[^\s,;]{8,}")
PERSONAL_DATA = re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
                           re.IGNORECASE)
INJECTION = re.compile(r"(?i)\b(ignore (?:all |any )?(?:prior|previous) (?:rules|instructions)|"
                       r"override (?:policy|authority)|expand (?:scope|permission)|bypass (?:policy|authorization))\b")
PROMOTION = re.compile(r"(?i)\b(finding|severity|exploitability|compliance certification|"
                       r"remediation complete|verified vulnerability|production is (?:safe|unsafe))\b")


class CandidateRejected(ValueError):
    """The supplied T09 candidate does not satisfy the offline boundary."""


def _relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise CandidateRejected(f"path must use nonempty POSIX syntax: {value!r}")
    result = PurePosixPath(value)
    if result.is_absolute() or any(part in ("", ".", "..") for part in result.parts):
        raise CandidateRejected(f"unsafe relative path: {value!r}")
    return result


def _file(root: Path, reference: dict[str, Any], label: str) -> Path:
    path = beneath(root, root.joinpath(*_relative(reference["path"]).parts))
    if not path.is_file():
        raise CandidateRejected(f"{label} is missing: {reference['path']}")
    if file_hash(path) != reference["sha256"]:
        raise CandidateRejected(f"{label} hash mismatch: {reference['path']}")
    return path


def _parse_time(value: str, label: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise CandidateRejected(f"{label} must be an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise CandidateRejected(f"{label} must include a timezone")


def _narrative_strings(candidate: dict[str, Any]):
    fields = ("static_insufficiency", "test_plan", "authorization_requirements", "criteria",
              "capture_requirements", "owner", "limitations", "contradictions",
              "unresolved_conditions", "dissent", "crosswalks", "transition")
    def walk(value: Any):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for item in value.values():
                yield from walk(item)
        elif isinstance(value, list):
            for item in value:
                yield from walk(item)
    for field in fields:
        yield from walk(candidate.get(field))


def _all_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _all_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _all_strings(item)


def expected_request_id(candidate: dict[str, Any]) -> str:
    """Identity includes every dimension that T09 is forbidden to merge implicitly."""
    def ordered(values: list[Any] | None) -> list[Any] | None:
        if values is None:
            return None
        return sorted(values, key=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")))
    identity = {
        "run_id": candidate.get("run_id"), "selection_id": candidate.get("selection_id"),
        "subject": ordered(candidate.get("subject")),
        "test_type": candidate.get("test_plan", {}).get("test_type"),
        "target_environment": candidate.get("test_plan", {}).get("target_environment"),
        "prerequisites": ordered(candidate.get("test_plan", {}).get("prerequisites")),
        "identity_requirements": ordered(candidate.get("test_plan", {}).get("identity_requirements")),
        "data_requirements": ordered(candidate.get("test_plan", {}).get("data_requirements")),
        "requested_actions": ordered(candidate.get("test_plan", {}).get("requested_actions")),
        "least_privilege": ordered(candidate.get("authorization_requirements", {}).get("least_privilege")),
        "safety_constraints": ordered(candidate.get("authorization_requirements", {}).get("safety_constraints")),
        "required_authority": candidate.get("authorization_requirements", {}).get("required_authority"),
        "criteria": candidate.get("criteria"), "capture_requirements": candidate.get("capture_requirements"),
        "owner": candidate.get("owner"),
    }
    return "dynamic-request-" + digest(identity)[:20]


def _load_source(run_id: str, source: dict[str, Any]):
    wrapper = {"handoff": source["handoff"], "handoff_id": source["handoff_id"],
               "batch_id": source["batch_id"]}
    handoff, handoff_set, pointer = owasp_validator_result._load_handoff(run_id, wrapper)
    assessment = None
    if source["assessment"] is not None:
        assessment = owasp_intercom._load_t07(run_id, source["batch_id"], source["assessment"])
    intercom = None
    if source["intercom"] is not None:
        ref = source["intercom"]
        required = {"attempt_id", "accepted_pointer_path", "accepted_pointer_sha256",
                    "ledger_path", "ledger_sha256", "message_ids"}
        if set(ref) != required:
            raise CandidateRejected("T08 reference must contain exact pointer/ledger/message identity")
        data = data_path(run_id)
        pointer_path = _file(data, {"path": ref["accepted_pointer_path"],
                                    "sha256": ref["accepted_pointer_sha256"]}, "T08 pointer")
        expected_pointer = data / "jobs" / owasp_intercom.JOB_ID / source["batch_id"] / "accepted.json"
        if pointer_path.absolute() != expected_pointer.absolute():
            raise CandidateRejected("T08 reference is not the exact batch accepted pointer")
        intercom_pointer = read_json(pointer_path)
        if (intercom_pointer.get("status") not in SUCCESS or intercom_pointer.get("run_id") != run_id or
                intercom_pointer.get("scope_id") != source["batch_id"] or
                intercom_pointer.get("attempt_id") != ref["attempt_id"]):
            raise Blocked("T08 accepted pointer identity/status mismatch")
        if read_json(pointer_path.with_name("latest.json")).get("attempt_id") != ref["attempt_id"]:
            raise Blocked("T08 ledger is not the newest accepted attempt")
        ledger_path = _file(data, {"path": ref["ledger_path"], "sha256": ref["ledger_sha256"]},
                            "T08 ledger")
        expected_ledger = (data / "jobs" / owasp_intercom.JOB_ID / source["batch_id"] / "attempts" /
                           identifier(ref["attempt_id"]) / "outputs" / "intercom-ledger.json")
        if ledger_path.absolute() != expected_ledger.absolute():
            raise CandidateRejected("T08 ledger path does not belong to the accepted attempt")
        if intercom_pointer.get("artifacts", {}).get("outputs/intercom-ledger.json") != ref["ledger_sha256"]:
            raise Blocked("T08 pointer does not publish the referenced ledger/hash")
        intercom = read_json(ledger_path)
        if validate_document(intercom, "owasp-intercom-ledger.schema.json"):
            raise Blocked("referenced T08 ledger no longer validates")
        owasp_intercom._validate_chain(intercom)
        by_id = {message["message_id"]: message for message in intercom["messages"]}
        if not ref["message_ids"] or any(message_id not in by_id for message_id in ref["message_ids"]):
            raise CandidateRejected("T08 message identity is missing from the exact accepted ledger")
        if any(by_id[message_id]["batch_identity"]["batch_id"] != source["batch_id"]
               for message_id in ref["message_ids"]):
            raise CandidateRejected("T08 message lineage crosses an independent batch boundary")
    return handoff, handoff_set, pointer, assessment, intercom


def _validate_lineage(candidate: dict[str, Any]):
    loaded = []
    seen_batches: set[str] = set()
    for source in candidate["lineage"]["sources"]:
        if source["batch_id"] in seen_batches:
            raise CandidateRejected("duplicate batch lineage would merge independent result authority")
        seen_batches.add(source["batch_id"])
        values = _load_source(candidate["run_id"], source)
        handoff = values[0]
        if (handoff["selection_identity"]["selection_id"] != candidate["selection_id"] or
                handoff["applicability_identity"] != candidate["lineage"]["applicability_identity"] or
                handoff["worklist_identity"] != candidate["lineage"]["worklist_identity"]):
            raise CandidateRejected("run/selection/applicability/worklist lineage mismatch")
        loaded.append((source, *values))
    return loaded


def _validate_subject(candidate: dict[str, Any], loaded) -> None:
    sources = {item[0]["batch_id"]: item for item in loaded}
    seen: set[tuple[str, str, str, str]] = set()
    for subject in candidate["subject"]:
        key = (subject["control_id"], subject["component_id"], subject["fragment_id"],
               subject["proof_obligation_id"])
        if key in seen:
            raise CandidateRejected("duplicate control/component/fragment/proof-obligation identity")
        seen.add(key)
        item = sources.get(subject["batch_id"])
        if item is None or subject["handoff_id"] != item[0]["handoff_id"]:
            raise CandidateRejected("subject lacks exact independent batch/handoff lineage")
        handoff = item[1]
        fragments = {fragment["fragment_id"]: fragment for fragment in handoff["assigned_fragments"]}
        fragment = fragments.get(subject["fragment_id"])
        obligations = ({obligation["obligation_id"]: obligation for obligation in
                        fragment["proof_obligations"]} if fragment is not None else {})
        obligation = obligations.get(subject["proof_obligation_id"])
        if (fragment is None or fragment["control_id"] != subject["control_id"] or
                fragment["component_id"] != subject["component_id"] or obligation is None or
                obligation["primary_evidence_mode"] != subject["evidence_mode"]):
            raise CandidateRejected("subject identity is nonexistent, cross-batch, or out of scope")
        assessment = item[4]
        if assessment is not None and assessment["batch_identity"]["batch_id"] != subject["batch_id"]:
            raise CandidateRejected("cross-batch assessment authority is prohibited")
    if not seen:
        raise CandidateRejected("at least one exact proof-obligation subject is required")
    for source, _handoff, _set, _pointer, _assessment, intercom in loaded:
        if intercom is None:
            continue
        batch_subject = [item for item in candidate["subject"] if item["batch_id"] == source["batch_id"]]
        allowed = {
            "control_ids": {item["control_id"] for item in batch_subject},
            "component_ids": {item["component_id"] for item in batch_subject},
            "fragment_ids": {item["fragment_id"] for item in batch_subject},
            "proof_obligation_ids": {item["proof_obligation_id"] for item in batch_subject},
        }
        by_id = {message["message_id"]: message for message in intercom["messages"]}
        for message_id in source["intercom"]["message_ids"]:
            message_subject = by_id[message_id]["subject"]
            if (not message_subject["proof_obligation_ids"] or any(
                    not set(message_subject[field]) <= allowed[field] for field in allowed)):
                raise CandidateRejected("T08 message subject is unrelated or broader than this request")


def _validate_state_artifact(candidate: dict[str, Any], transition: dict[str, Any]) -> None:
    state = candidate["state"]
    authority = transition["authority"]
    if state not in EXTERNAL_STATES:
        if authority["kind"] == "external_state_artifact":
            raise CandidateRejected("external state artifacts are reserved for externally established states")
        return
    if authority["kind"] != "external_state_artifact" or authority["artifact"] is None:
        raise CandidateRejected(f"{state} requires a separately supplied exact authoritative artifact")
    root = run_path(candidate["run_id"])
    reference = authority["artifact"]
    required = {"path", "sha256", "job_id", "attempt_id", "accepted_pointer_path",
                "accepted_pointer_sha256"}
    if set(reference) != required:
        raise CandidateRejected("state artifact reference must pin its exact accepted producer")
    job_id, attempt_id = identifier(reference["job_id"]), identifier(reference["attempt_id"])
    artifact_path = _file(root, reference, "transition authority artifact")
    relative = artifact_path.relative_to(root).as_posix()
    if job_id in {owasp_validator_handoff.JOB_ID, owasp_validator_result.JOB_ID,
                  owasp_intercom.JOB_ID, JOB_ID}:
        raise CandidateRejected("T06/T07/T08/T09 artifacts cannot authorize lifecycle transitions")
    data = data_path(candidate["run_id"])
    pointer_path = _file(data, {"path": reference["accepted_pointer_path"],
                                "sha256": reference["accepted_pointer_sha256"]},
                         "state producer accepted pointer")
    pointer_relative = pointer_path.relative_to(data).as_posix()
    if not pointer_relative.startswith(f"jobs/{job_id}/") or pointer_path.name != "accepted.json":
        raise CandidateRejected("state artifact pointer does not belong to its named producer job")
    pointer = read_json(pointer_path)
    if (pointer.get("status") not in SUCCESS or pointer.get("run_id") != candidate["run_id"] or
            pointer.get("job_id") != job_id or pointer.get("attempt_id") != attempt_id):
        raise Blocked("state producer accepted pointer identity/status mismatch")
    if read_json(pointer_path.with_name("latest.json")).get("attempt_id") != attempt_id:
        raise Blocked("state authority artifact is not from the newest accepted producer attempt")
    attempt = pointer_path.parent / "attempts" / attempt_id
    try:
        artifact_relative = artifact_path.relative_to(attempt).as_posix()
    except ValueError as exc:
        raise CandidateRejected("state authority artifact is outside its accepted producer attempt") from exc
    if pointer.get("artifacts", {}).get(artifact_relative) != reference["sha256"]:
        raise Blocked("state producer pointer does not publish the authority artifact/hash")
    document = read_json(artifact_path)
    errors = validate_document(document, "owasp-dynamic-request-transition.schema.json")
    if errors:
        raise CandidateRejected("transition authority artifact is invalid: " + "; ".join(errors))
    if (document["request_id"] != candidate["request_id"] or document["run_id"] != candidate["run_id"] or
            document["from_state"] != transition["from_state"] or document["to_state"] != state or
            document["artifact_kind"] != STATE_ARTIFACT_KINDS[state] or
            document["authority_id"] != authority["authority_id"] or
            document["producer_job_id"] != job_id or document["producer_attempt_id"] != attempt_id):
        raise CandidateRejected("transition authority artifact does not establish this exact state transition")
    expected_scope = {"target_environment": candidate["test_plan"]["target_environment"],
                      "subject": candidate["subject"]}
    if document["scope"] != expected_scope:
        raise CandidateRejected("transition authority artifact scope does not exactly match the request")
    if (state == "authorized" and document["authority_id"] !=
            candidate["authorization_requirements"]["required_authority"].get("authority_id")):
        raise CandidateRejected("authorization artifact was not issued by the required authority")
    if document["t09_authorized_or_performed"] or not document["external_claim_requires_reverification"]:
        raise CandidateRejected("state artifact improperly assigns authorization/execution to T09")
    _parse_time(document["issued_at"], "transition authority issued_at")
    for text in _all_strings(document):
        if SECRET.search(text):
            raise CandidateRejected("transition authority artifact contains a secret")
        if PERSONAL_DATA.search(text):
            raise CandidateRejected("transition authority artifact contains unnecessary personal data")
        if INJECTION.search(text):
            raise CandidateRejected("prompt-injected authority artifact cannot widen scope or permission")


def _validate_candidate(candidate: dict[str, Any], envelope: dict[str, Any], current: dict[str, Any] | None,
                        loaded) -> dict[str, Any]:
    probe = copy.deepcopy(candidate)
    probe["publication"] = {"version": envelope["expected_head"]["next_version"],
        "candidate_path": envelope["candidate"]["path"], "candidate_sha256": envelope["candidate"]["sha256"],
        "previous_version_hash": envelope["expected_head"]["version_hash"], "published_at": now()}
    errors = validate_document(probe, "owasp-dynamic-manual-request.schema.json")
    if errors:
        raise CandidateRejected("candidate request schema validation failed: " + "; ".join(errors))
    if "publication" in candidate:
        raise CandidateRejected("candidate may not supply publication authority")
    if candidate["request_id"] != expected_request_id(candidate):
        raise CandidateRejected("request ID is not deterministic across protected deduplication dimensions")
    if candidate["version"] != envelope["expected_head"]["next_version"]:
        raise CandidateRejected("candidate version is stale or skipped")
    if candidate["state"] not in STATES:
        raise CandidateRejected("unsupported lifecycle state")
    prior_state = None if current is None else current["state"]
    transition = candidate["transition"]
    if transition["from_state"] != prior_state or transition["to_state"] != candidate["state"]:
        raise CandidateRejected("transition does not match the exact accepted prior state")
    if candidate["state"] not in TRANSITIONS[prior_state]:
        raise CandidateRejected("skipped, reversed, or terminal lifecycle transition")
    _parse_time(transition["occurred_at"], "transition occurred_at")
    expected_prior = None if current is None else {"request_id": current["request_id"],
        "version": current["version"], "state": current["state"],
        "path": current["publication"]["candidate_path"],
        "sha256": current["publication"]["candidate_sha256"],
        "version_hash": digest(current)}
    if candidate["prior_version"] != expected_prior:
        raise CandidateRejected("prior accepted request/version identity or hash mismatch")
    if candidate["test_plan"]["test_type"] == "manual_observation":
        if candidate["state"] != "blocked" or transition["authority"]["kind"] != "baseline_policy":
            raise CandidateRejected("manual-observation requests remain blocked under current policy")
    elif current is None and candidate["state"] != "proposed":
        raise CandidateRejected("a dynamic request begins as an inert proposed request")
    if candidate["state"] == "proposed" and transition["authority"]["kind"] != "proposal_author":
        raise CandidateRejected("proposed requests require explicit proposal-author identity")
    if candidate["state"] == "blocked" and transition["authority"]["kind"] != "baseline_policy":
        raise CandidateRejected("blocked publication must cite the fail-closed baseline policy")
    if candidate["state"] == "canceled":
        if (transition["authority"]["kind"] != "request_owner" or
                transition["authority"]["authority_id"] != candidate["owner"]["owner_id"]):
            raise CandidateRejected("cancellation requires the exact request owner authority")
    _validate_state_artifact(candidate, transition)
    _validate_subject(candidate, loaded)
    if not candidate["static_insufficiency"]["reasons"]:
        raise CandidateRejected("why static and supplied evidence are insufficient is required")
    if candidate["test_plan"]["test_type"] == "dynamic_runtime" and not any(
            item["evidence_mode"] == "dynamic_runtime" for item in candidate["subject"]):
        raise CandidateRejected("dynamic request must link a dynamic-runtime proof obligation")
    for text in _narrative_strings(candidate):
        if SECRET.search(text):
            raise CandidateRejected("secret-bearing request content is prohibited")
        if PERSONAL_DATA.search(text):
            raise CandidateRejected("unnecessary personal data is prohibited")
        if INJECTION.search(text):
            raise CandidateRejected("prompt-injected content cannot widen scope, tools, permissions, or authority")
        if PROMOTION.search(text):
            raise CandidateRejected("finding, severity, exploitability, compliance, or remediation promotion is prohibited")
    accepted = copy.deepcopy(candidate)
    accepted["publication"] = probe["publication"]
    return accepted


def _base(run_id: str, request_id: str) -> Path:
    return data_path(run_id, "jobs", JOB_ID, request_id)


def _validate_chain(ledger: dict[str, Any]) -> None:
    versions = ledger["versions"]
    if ledger["version"] != len(versions) or not versions:
        raise Blocked("request ledger version/history length mismatch")
    previous_hash = None
    for number, version in enumerate(versions, 1):
        if version["version"] != number or version["publication"]["version"] != number:
            raise Blocked("request ledger has a skipped or reordered version")
        if version["publication"]["previous_version_hash"] != previous_hash:
            raise Blocked("request ledger version hash-chain discontinuity")
        previous_hash = digest(version)
    if ledger["head_version_hash"] != previous_hash or ledger["state"] != versions[-1]["state"]:
        raise Blocked("request ledger head state/hash mismatch")


def _accepted_state(base: Path, run_id: str, request_id: str, prior_latest: dict[str, Any] | None):
    pointer_path = base / "accepted.json"
    if not pointer_path.is_file():
        return None, None, None
    pointer = read_json(pointer_path)
    if pointer.get("status") not in SUCCESS:
        raise Blocked("T09 accepted pointer is not successful")
    expected_identity = {"run_id": run_id, "job_id": JOB_ID, "scope_id": request_id,
                         "request_id": request_id}
    if any(pointer.get(field) != value for field, value in expected_identity.items()):
        raise Blocked("T09 accepted pointer identity does not match this request")
    accepted_attempt_id = identifier(pointer["attempt_id"])
    if not isinstance(prior_latest, dict) or not isinstance(prior_latest.get("attempt_id"), str):
        raise Blocked("T09 accepted pointer is not backed by a newest attempt")
    latest_attempt_id = identifier(prior_latest["attempt_id"])
    if latest_attempt_id != accepted_attempt_id:
        latest_status_path = base / "attempts" / latest_attempt_id / "status.json"
        latest_status = read_json(latest_status_path) if latest_status_path.is_file() else None
        replay_identity = {"run_id": run_id, "job_id": JOB_ID, "scope_id": request_id,
                           "attempt_id": latest_attempt_id, "reused_attempt_id": accepted_attempt_id}
        if (not isinstance(latest_status, dict) or latest_status.get("status") != "REUSED" or
                any(latest_status.get(field) != value for field, value in replay_identity.items())):
            raise Blocked("T09 accepted pointer does not identify the newest accepted request head")
    attempt = base / "attempts" / accepted_attempt_id
    artifacts = pointer.get("artifacts")
    if not isinstance(artifacts, dict):
        raise Blocked("T09 accepted pointer does not publish an artifact map")
    for relative, expected_hash in artifacts.items():
        artifact = beneath(attempt, attempt.joinpath(*_relative(relative).parts))
        if not artifact.is_file() or file_hash(artifact) != expected_hash:
            raise Blocked(f"T09 accepted artifact is missing or corrupt: {relative}")
    ledger_path = attempt / "outputs" / "dynamic-request-ledger.json"
    data = base.parents[2]
    expected_ledger_path = ledger_path.relative_to(data).as_posix()
    published_ledger_hash = artifacts.get("outputs/dynamic-request-ledger.json")
    if (pointer.get("ledger_path") != expected_ledger_path or
            published_ledger_hash != pointer.get("ledger_sha256") or
            file_hash(ledger_path) != published_ledger_hash):
        raise Blocked("T09 accepted ledger is missing or corrupt")
    ledger = read_json(ledger_path)
    if validate_document(ledger, "owasp-dynamic-request-ledger.schema.json"):
        raise Blocked("T09 accepted ledger no longer validates")
    _validate_chain(ledger)
    pointer_projection = {"selection_id": ledger["selection_id"], "request_id": ledger["request_id"],
                          "version": ledger["version"], "state": ledger["state"],
                          "version_hash": ledger["head_version_hash"]}
    if ledger["run_id"] != run_id or any(pointer.get(field) != value for field, value in pointer_projection.items()):
        raise Blocked("T09 accepted pointer and ledger identity do not match")
    if ledger["version"] == 1:
        if any(ledger[key] is not None for key in
               ("previous_attempt_id", "previous_ledger_path", "previous_ledger_sha256")):
            raise Blocked("first request ledger has an unexpected prior-attempt link")
    else:
        previous_path = beneath(data, data.joinpath(*_relative(ledger["previous_ledger_path"]).parts))
        expected_path = (base / "attempts" / identifier(ledger["previous_attempt_id"]) /
                         "outputs" / "dynamic-request-ledger.json")
        if (previous_path.absolute() != expected_path.absolute() or
                file_hash(previous_path) != ledger["previous_ledger_sha256"]):
            raise Blocked("request ledger attempt hash-chain discontinuity")
        previous = read_json(previous_path)
        if (previous.get("version") != ledger["version"] - 1 or
                previous.get("head_version_hash") != digest(ledger["versions"][-2])):
            raise Blocked("prior request ledger no longer matches accepted history")
    return pointer, ledger, ledger_path


def _actual_head(pointer, ledger, ledger_path, data: Path) -> dict[str, Any]:
    if pointer is None:
        return {"previous_attempt_id": None, "ledger_path": None, "ledger_sha256": None,
                "version": None, "state": None, "version_hash": None, "next_version": 1}
    return {"previous_attempt_id": pointer["attempt_id"],
            "ledger_path": ledger_path.relative_to(data).as_posix(),
            "ledger_sha256": file_hash(ledger_path), "version": ledger["version"],
            "state": ledger["state"], "version_hash": ledger["head_version_hash"],
            "next_version": ledger["version"] + 1}


def _disabled_receipt(run_id: str, envelope: dict[str, Any]) -> dict[str, Any]:
    candidate_ref = envelope["candidate"]
    receipt = {"schema": "appsec-review/owasp-dynamic-execution-disabled-receipt/1.0",
        "receipt_id": "dynamic-disabled-" + digest({"run_id": run_id, "operation": envelope["operation"],
            "candidate": candidate_ref})[:20], "run_id": run_id, "operation": envelope["operation"],
        "candidate_path": candidate_ref["path"], "candidate_sha256": candidate_ref["sha256"],
        "result": "dynamic_execution_disabled", "target_contacted": False, "target_mutated": False,
        "manual_observation_performed": False, "dynamic_execution_performed": False,
        "reason": "T09 is an offline request ledger and cannot launch, execute, or observe a target."}
    errors = validate_document(receipt, "owasp-dynamic-execution-disabled-receipt.schema.json")
    if errors:
        raise RuntimeError("generated disabled receipt is invalid: " + "; ".join(errors))
    base = data_path(run_id, "jobs", JOB_ID, "disabled-receipts")
    path = base / f"{receipt['receipt_id']}.json"
    with Lock(data_path(run_id, "jobs", JOB_ID, "job.lock")):
        if path.is_file() and read_json(path) != receipt:
            raise Blocked("immutable dynamic disabled receipt collision")
        if not path.is_file():
            atomic_json(path, receipt)
    return {**receipt, "receipt_path": path.relative_to(data_path(run_id)).as_posix()}


def _summary(ledger: dict[str, Any]) -> bytes:
    request = ledger["versions"][-1]
    lines = ["# OWASP Dynamic/Manual Request", "", f"- Request: `{ledger['request_id']}`",
             f"- Version: {ledger['version']}", f"- State: `{ledger['state']}`",
             f"- Test type: `{request['test_plan']['test_type']}`",
             "- T09 authorization/execution effect: none",
             "- Control assessment effect: none; reassessment and re-verification remain separate",
             "- Findings, severity, exploitability, compliance, remediation, and runtime claims: not promoted", ""]
    return ("\n".join(lines) + "\n").encode()


def publish(run_id: str, request_path: Path | None = None, *, clock=lambda: datetime.now(timezone.utc)) -> dict[str, Any]:
    run_id = identifier(run_id)
    root = run_path(run_id)
    if not (root / "run-status.json").is_file():
        raise Blocked("create the run through run_process.py --start first")
    request_path = beneath(root, Path(request_path or root / "inputs" / "owasp-dynamic-request-publication.json"))
    envelope = read_json(request_path)
    errors = validate_document(envelope, "owasp-dynamic-request-publication.schema.json")
    if errors or envelope.get("schema") != REQUEST_SCHEMA or envelope.get("run_id") != run_id:
        raise ValueError("invalid OWASP dynamic request publication: " + "; ".join(errors))
    if envelope["operation"] in {"execute", "launch"}:
        return _disabled_receipt(run_id, envelope)
    candidate_path = _file(root, envelope["candidate"], "request candidate")
    candidate_bytes = candidate_path.read_bytes()
    candidate = json.loads(candidate_bytes)
    schema_errors = validate_document({**candidate, "publication": {"version": 1,
        "candidate_path": envelope["candidate"]["path"], "candidate_sha256": envelope["candidate"]["sha256"],
        "previous_version_hash": None, "published_at": now()}}, "owasp-dynamic-manual-request.schema.json")
    if schema_errors:
        raise CandidateRejected("candidate request schema validation failed: " + "; ".join(schema_errors))
    request_id = identifier(candidate["request_id"])
    base, data = _base(run_id, request_id), data_path(run_id)
    fingerprint = digest(envelope)
    with Lock(base / "job.lock"):
        latest_path = base / "latest.json"
        prior_latest = read_json(latest_path) if latest_path.is_file() else None
        attempt_id = uuid.uuid4().hex
        attempt = beneath(base, base / "attempts" / attempt_id)
        attempt.mkdir(parents=True, exist_ok=False)
        started = {"status": "RUNNING", "run_id": run_id, "job_id": JOB_ID, "scope_id": request_id,
                   "attempt_id": attempt_id, "input_fingerprint": fingerprint, "started_at": now()}
        atomic_json(base / "latest.json", {"attempt_id": attempt_id, "updated_at": now()})
        atomic_json(attempt / "inputs.json", envelope); atomic_json(attempt / "status.json", started)
        atomic_bytes(attempt / "inputs/candidate.json", candidate_bytes)
        atomic_bytes(attempt / "logs/stdout.log", b""); atomic_bytes(attempt / "logs/stderr.log", b"")
        event(attempt / "logs/events.jsonl", "START", **started)
        try:
            pointer, ledger, ledger_path = _accepted_state(base, run_id, request_id, prior_latest)
            expected_head = _actual_head(pointer, ledger, ledger_path, data)
            current = None if ledger is None else ledger["versions"][-1]
            if (current is not None and current["publication"]["candidate_sha256"] == envelope["candidate"]["sha256"]
                    and current["publication"]["candidate_path"] == envelope["candidate"]["path"]):
                loaded = _validate_lineage(candidate)
                _validate_candidate(candidate, envelope, None if len(ledger["versions"]) == 1 else ledger["versions"][-2], loaded)
                assert pointer is not None
                atomic_json(attempt / "status.json", {**started, "status": "REUSED", "ended_at": now(),
                                                       "reused_attempt_id": pointer["attempt_id"]})
                event(attempt / "logs/events.jsonl", "END", status="REUSED", reused_attempt_id=pointer["attempt_id"])
                return {**pointer, "reused": True}
            if envelope["expected_head"] != expected_head:
                raise CandidateRejected("stale head, skipped transition, rewritten history, or lost update")
            loaded = _validate_lineage(candidate)
            accepted = _validate_candidate(candidate, envelope, current, loaded)
            if read_json(request_path) != envelope or file_hash(candidate_path) != envelope["candidate"]["sha256"]:
                raise Blocked("T09 publication request or candidate changed during validation")
            for source, handoff, handoff_set, t06_pointer, assessment, intercom in loaded:
                if _load_source(run_id, source) != (handoff, handoff_set, t06_pointer, assessment, intercom):
                    raise Blocked("T06/T07/T08 lineage changed during T09 validation")
            versions = [accepted] if ledger is None else [*ledger["versions"], accepted]
            ledger_value = {"schema": LEDGER_SCHEMA, "run_id": run_id, "selection_id": candidate["selection_id"],
                "request_id": request_id, "version": len(versions), "state": accepted["state"],
                "head_version_hash": digest(accepted),
                "previous_attempt_id": None if pointer is None else pointer["attempt_id"],
                "previous_ledger_path": None if ledger_path is None else ledger_path.relative_to(data).as_posix(),
                "previous_ledger_sha256": None if ledger_path is None else file_hash(ledger_path), "versions": versions}
            _validate_chain(ledger_value)
            for value, schema in ((accepted, "owasp-dynamic-manual-request.schema.json"),
                                  (ledger_value, "owasp-dynamic-request-ledger.schema.json")):
                generated_errors = validate_document(value, schema)
                if generated_errors:
                    raise RuntimeError(f"generated {schema} invalid: " + "; ".join(generated_errors))
            validation = {"schema": "appsec-review/owasp-dynamic-request-validation/1.0", "status": "PASS",
                "run_id": run_id, "request_id": request_id, "candidate_path": envelope["candidate"]["path"],
                "candidate_sha256": envelope["candidate"]["sha256"],
                "checks": ["exact independently verified T06/T07/T08 lineage", "deterministic protected deduplication",
                    "append-only authorized lifecycle transition and hash chain", "static evidence cannot close dynamic/manual obligations",
                    "T07/T08 cannot authorize a request", "offline no-contact/no-mutation boundary"], "errors": []}
            output = attempt / "outputs"
            atomic_json(output / "owasp-dynamic-test-request.json", accepted)
            atomic_json(output / "dynamic-request-ledger.json", ledger_value)
            atomic_json(output / "dynamic-request-validation.json", validation)
            atomic_bytes(output / "dynamic-request-summary.md", _summary(ledger_value))
            paths = [attempt / "inputs/candidate.json", *[output / name for name in
                ("owasp-dynamic-test-request.json", "dynamic-request-ledger.json",
                 "dynamic-request-validation.json", "dynamic-request-summary.md")]]
            artifacts = {path.relative_to(attempt).as_posix(): file_hash(path) for path in paths}
            atomic_json(attempt / "validation/post.json", {"status": "OK", "artifacts": artifacts})
            status = "OK_WITH_GAPS" if accepted["state"] in {"proposed", "blocked"} or accepted["limitations"] or accepted["unresolved_conditions"] else "OK"
            atomic_json(attempt / "status.json", {**started, "status": status, "ended_at": now(),
                "request_id": request_id, "version": accepted["version"], "state": accepted["state"], "artifacts": artifacts})
            pointer_value = {"status": status, "run_id": run_id, "job_id": JOB_ID, "scope_id": request_id,
                "attempt_id": attempt_id, "input_fingerprint": fingerprint, "selection_id": accepted["selection_id"],
                "request_id": request_id, "version": accepted["version"], "state": accepted["state"],
                "version_hash": digest(accepted), "ledger_path": (output / "dynamic-request-ledger.json").relative_to(data).as_posix(),
                "ledger_sha256": artifacts["outputs/dynamic-request-ledger.json"], "artifacts": artifacts, "accepted_at": now()}
            atomic_json(base / "accepted.json", pointer_value)
            event(attempt / "logs/events.jsonl", "END", status=status, run_id=run_id, job_id=JOB_ID,
                  scope_id=request_id, attempt_id=attempt_id)
            return {**pointer_value, "reused": False}
        except BaseException as exc:
            terminal = "INVALID" if isinstance(exc, (CandidateRejected, ValueError, json.JSONDecodeError)) else "BLOCKED"
            receipt = {"schema": "appsec-review/owasp-dynamic-request-validation/1.0", "status": terminal,
                "run_id": run_id, "request_id": request_id, "candidate_path": envelope["candidate"]["path"],
                "candidate_sha256": envelope["candidate"]["sha256"], "checks": [],
                "errors": [{"error_type": type(exc).__name__, "message": str(exc)}]}
            if validate_document(receipt, "owasp-dynamic-request-validation.schema.json"):
                emergency(RuntimeError("invalid T09 failure receipt"))
            atomic_json(attempt / "validation/errors.json", receipt)
            atomic_json(attempt / "status.json", {**started, "status": terminal, "ended_at": now(),
                                                   "error_type": type(exc).__name__, "error": str(exc)})
            try:
                event(attempt / "logs/events.jsonl", "FAILURE", status=terminal, error_type=type(exc).__name__)
            except BaseException as diagnostic:
                emergency(diagnostic)
            raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True); parser.add_argument("--request", type=Path)
    args = parser.parse_args(argv)
    try:
        result = publish(args.run_id, args.request)
    except (Blocked, CandidateRejected, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"OWASP_DYNAMIC_REQUEST_BLOCKED: {exc}", file=sys.stderr); return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
