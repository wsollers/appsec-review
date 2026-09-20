#!/usr/bin/env python3
"""Validate and immutably append one offline OWASP structured-intercom message (T08).

Messages are untrusted communication/provenance records.  This worker does not dispatch a
workcell, execute a tool, inspect a target, change an upstream decision, or treat a message as
evidence.  Each accepted append creates a complete immutable ledger snapshot and deterministic
JSONL projection; rejected attempts are retained without moving the last accepted ledger.
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
import owasp_validator_handoff
import owasp_validator_result
from schema_validate import validate_document


JOB_ID = "04-owasp-structured-intercom"
REQUEST_SCHEMA = "appsec-review/owasp-intercom-append-request/1.0"
MESSAGE_SCHEMA = "appsec-review/owasp-intercom-message/1.0"
LEDGER_SCHEMA = "appsec-review/owasp-intercom-ledger/1.0"
SUCCESS = {"OK", "OK_WITH_GAPS"}
MESSAGE_TYPES = {
    "evidence_locator", "applicability_challenge", "component_classification_challenge",
    "assistance_request", "assistance_response", "duplicate_crosswalk_notice", "dissent",
    "dynamic_test_candidate",
}
CLAIM_FOR_TYPE = {
    "evidence_locator": "navigation_hint", "applicability_challenge": "proposal",
    "component_classification_challenge": "proposal", "assistance_request": "assistance",
    "assistance_response": "assistance", "duplicate_crosswalk_notice": "routing_metadata",
    "dissent": "dissent", "dynamic_test_candidate": "proposed_dynamic_request",
}
UPSTREAM_ROLES = {"owasp-applicability-reviewer", "component-classification-owner",
                  "engagement-selection-owner", "owasp-validator", "dynamic-test-request-author"}
PROHIBITED = re.compile(
    r"\b(vulnerab(?:le|ility)|finding|severity|critical|high severity|exploit(?:able|ability)|"
    r"likelihood|impact is|compliant|compliance|certif(?:ied|ication)|remediat(?:ed|ion)|fixed|"
    r"deployed behavior|production behavior|live[- ]state|runtime behavior|manual(?:ly)? observed|"
    r"authorized to execute|permission expanded|scope changed|profile changed|status changed)\b",
    re.IGNORECASE,
)
SECRET = re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|password|secret)\b\s*[:=]\s*[^\s,;]{8,}")
PERSONAL_DATA = re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
                           re.IGNORECASE)
FORBIDDEN_ACTIONS = {"network_access", "endpoint_request", "device_use", "emulator_use", "dast",
                     "fuzzing", "debugger", "instrumentation", "live_infrastructure_query",
                     "target_mutation", "dynamic_execution", "manual_observation"}


class CandidateRejected(ValueError):
    """The untrusted candidate failed the T08 contract."""


def _relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"path must use nonempty POSIX syntax: {value!r}")
    result = PurePosixPath(value)
    if result.is_absolute() or any(part in ("", ".", "..") for part in result.parts):
        raise ValueError(f"unsafe relative path: {value!r}")
    return result


def _run_file(root: Path, relative: str, expected_hash: str) -> Path:
    ref = _relative(relative)
    path = beneath(root, root.joinpath(*ref.parts))
    if not path.is_file():
        raise CandidateRejected(f"candidate artifact is missing: {relative}")
    if file_hash(path) != expected_hash:
        raise CandidateRejected(f"candidate artifact hash mismatch: {relative}")
    return path


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _message_hash(message: dict[str, Any]) -> str:
    return digest(message)


def expected_message_id(candidate: dict[str, Any]) -> str:
    body = {key: value for key, value in candidate.items()
            if key not in {"message_id", "publication"}}
    return "intercom-" + digest(body)[:20]


def _parse_time(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise CandidateRejected("occurred_at must be an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise CandidateRejected("occurred_at must include a timezone")


def _load_handoff(run_id: str, request: dict[str, Any]):
    wrapper = {"handoff": request["handoff"], "handoff_id": request["handoff_id"],
               "batch_id": request["batch_id"]}
    handoff, handoff_set, pointer = owasp_validator_result._load_handoff(run_id, wrapper)
    if (handoff["handoff_id"] != request["handoff_id"] or
            handoff["batch_identity"]["batch_id"] != request["batch_id"]):
        raise Blocked("T06 handoff/batch identity mismatch")
    return handoff, handoff_set, pointer


def _load_t07(run_id: str, batch_id: str, reference: dict[str, Any]) -> dict[str, Any]:
    required = {"attempt_id", "accepted_pointer_path", "accepted_pointer_sha256", "result_path",
                "result_sha256", "result_id"}
    if not isinstance(reference, dict) or set(reference) != required:
        raise CandidateRejected("T07 reference must contain the exact pointer/result identity")
    data = data_path(run_id)
    attempt_id = identifier(reference["attempt_id"])
    pointer_path = _run_file(data, reference["accepted_pointer_path"], reference["accepted_pointer_sha256"])
    expected = data / "jobs" / owasp_validator_result.JOB_ID / batch_id / "accepted.json"
    if pointer_path.absolute() != expected.absolute():
        raise CandidateRejected("T07 reference is not the exact batch accepted pointer")
    pointer = read_json(pointer_path)
    if (pointer.get("status") not in SUCCESS or pointer.get("run_id") != run_id or
            pointer.get("scope_id") != batch_id or pointer.get("attempt_id") != attempt_id):
        raise Blocked("T07 accepted pointer identity/status mismatch")
    if read_json(pointer_path.with_name("latest.json")).get("attempt_id") != attempt_id:
        raise Blocked("T07 result is not the newest accepted attempt")
    result_path = _run_file(data, reference["result_path"], reference["result_sha256"])
    attempt = data / "jobs" / owasp_validator_result.JOB_ID / batch_id / "attempts" / attempt_id
    if result_path.absolute() != (attempt / "outputs" / "control-assessment-result.json").absolute():
        raise CandidateRejected("T07 result path does not belong to the accepted attempt")
    if pointer.get("artifacts", {}).get("outputs/control-assessment-result.json") != reference["result_sha256"]:
        raise Blocked("T07 pointer does not publish the referenced result/hash")
    result = read_json(result_path)
    if validate_document(result, "owasp-control-assessment-result.schema.json"):
        raise Blocked("referenced T07 result no longer validates")
    if result.get("result_id") != reference["result_id"]:
        raise CandidateRejected("T07 result identity mismatch")
    return result


def _accepted_state(base: Path) -> tuple[dict[str, Any] | None, dict[str, Any] | None, Path | None]:
    pointer_path = base / "accepted.json"
    if not pointer_path.is_file():
        return None, None, None
    pointer = read_json(pointer_path)
    if pointer.get("status") not in SUCCESS:
        raise Blocked("T08 accepted pointer is not a successful ledger")
    attempt = base / "attempts" / identifier(pointer["attempt_id"])
    for relative, expected_hash in pointer.get("artifacts", {}).items():
        artifact = beneath(attempt, attempt.joinpath(*_relative(relative).parts))
        if not artifact.is_file() or file_hash(artifact) != expected_hash:
            raise Blocked(f"T08 accepted artifact is missing or corrupt: {relative}")
    ledger_path = attempt / "outputs" / "intercom-ledger.json"
    expected = pointer.get("artifacts", {}).get("outputs/intercom-ledger.json")
    if not ledger_path.is_file() or file_hash(ledger_path) != expected or expected != pointer.get("ledger_sha256"):
        raise Blocked("T08 accepted ledger is missing or corrupt")
    ledger = read_json(ledger_path)
    if validate_document(ledger, "owasp-intercom-ledger.schema.json"):
        raise Blocked("T08 accepted ledger no longer validates")
    _validate_chain(ledger)
    data = base.parents[2]
    if ledger["sequence"] == 1:
        if any(ledger[key] is not None for key in ("previous_attempt_id", "previous_ledger_path",
                                                   "previous_ledger_sha256")):
            raise Blocked("first ledger contains an unexpected prior-attempt link")
    else:
        if not all(ledger[key] is not None for key in ("previous_attempt_id", "previous_ledger_path",
                                                       "previous_ledger_sha256")):
            raise Blocked("ledger attempt hash chain is incomplete")
        previous_ref = _relative(ledger["previous_ledger_path"])
        previous_path = beneath(data, data.joinpath(*previous_ref.parts))
        expected_previous = (base / "attempts" / identifier(ledger["previous_attempt_id"]) /
                             "outputs" / "intercom-ledger.json")
        if (previous_path.absolute() != expected_previous.absolute() or not previous_path.is_file() or
                file_hash(previous_path) != ledger["previous_ledger_sha256"]):
            raise Blocked("ledger attempt hash-chain discontinuity")
        previous = read_json(previous_path)
        if (validate_document(previous, "owasp-intercom-ledger.schema.json") or
                previous.get("sequence") != ledger["sequence"] - 1 or
                previous.get("head_message_id") != ledger["messages"][-2]["message_id"] or
                previous.get("head_message_hash") != _message_hash(ledger["messages"][-2])):
            raise Blocked("previous ledger snapshot no longer matches current history")
    return pointer, ledger, ledger_path


def _validate_chain(ledger: dict[str, Any]) -> None:
    messages = ledger["messages"]
    if ledger["sequence"] != len(messages):
        raise Blocked("ledger sequence/history length mismatch")
    previous_id = previous_hash = None
    seen: set[str] = set()
    for sequence, message in enumerate(messages, 1):
        if message["message_id"] in seen:
            raise Blocked("ledger contains a conflicting message ID")
        seen.add(message["message_id"])
        publication = message["publication"]
        if (publication["sequence"] != sequence or publication["previous_ledger_head_id"] != previous_id or
                publication["previous_ledger_head_hash"] != previous_hash):
            raise Blocked("ledger message hash-chain discontinuity")
        previous_id, previous_hash = message["message_id"], _message_hash(message)
    if ledger["head_message_id"] != previous_id or ledger["head_message_hash"] != previous_hash:
        raise Blocked("ledger head identity/hash mismatch")


def _validate_head(request: dict[str, Any], pointer: dict[str, Any] | None,
                   ledger: dict[str, Any] | None, ledger_path: Path | None, data: Path) -> None:
    expected = request["expected_head"]
    if pointer is None:
        actual = {"previous_attempt_id": None, "ledger_path": None, "ledger_sha256": None,
                  "message_id": None, "message_hash": None, "next_sequence": 1}
    else:
        assert ledger is not None and ledger_path is not None
        actual = {"previous_attempt_id": pointer["attempt_id"],
                  "ledger_path": ledger_path.relative_to(data).as_posix(),
                  "ledger_sha256": file_hash(ledger_path), "message_id": ledger["head_message_id"],
                  "message_hash": ledger["head_message_hash"], "next_sequence": ledger["sequence"] + 1}
    if expected != actual:
        raise CandidateRejected("stale head, skipped sequence, or rewritten-history request")


def _identity_sets(handoff: dict[str, Any]):
    fragments = {f["fragment_id"]: f for f in handoff["assigned_fragments"]}
    controls = {f["control_id"] for f in fragments.values()}
    components = {f["component_id"] for f in fragments.values()}
    obligations = {o["obligation_id"] for f in fragments.values() for o in f["proof_obligations"]}
    return fragments, controls, components, obligations


def _validate_citations(candidate: dict[str, Any], handoff: dict[str, Any]) -> None:
    accepted = {item["input_id"]: item for item in handoff["accepted_inputs"]}
    seen: set[str] = set()
    for collection, canonical in ((candidate["citations"], True), (candidate["evidence_locators"], False)):
        for citation in collection:
            identity = citation["citation_id"] if canonical else citation["locator_id"]
            if identity in seen:
                raise CandidateRejected("duplicate citation/locator identity")
            seen.add(identity)
            entry = accepted.get(citation["input_id"])
            if entry is None or citation["artifact_path"] != entry["artifact"]["path"] or citation["artifact_sha256"] != entry["artifact"]["sha256"]:
                raise CandidateRejected("citation/locator is unrelated to accepted T06 evidence")
    if candidate["assertions"] and not candidate["citations"]:
        raise CandidateRejected("uncited prose conclusion presented as evidence")
    if candidate["message_type"] == "evidence_locator" and not candidate["evidence_locators"]:
        raise CandidateRejected("evidence_locator must identify a locator separately from canonical evidence")


def _validate_roles(candidate: dict[str, Any], handoff: dict[str, Any]) -> None:
    allowed = {handoff["roles"]["primary_validator_role"], *handoff["roles"]["eligible_specialist_roles"],
               *UPSTREAM_ROLES}
    if candidate["sender"]["role"] not in allowed or candidate["recipient"]["role"] not in allowed:
        raise CandidateRejected("sender or recipient role is not valid for this handoff")
    if candidate["sender"]["identity"] == candidate["recipient"]["identity"] and candidate["recipient"]["identity"] is not None:
        raise CandidateRejected("self-addressed messages cannot create corroboration")


def _validate_links(candidate: dict[str, Any], messages: list[dict[str, Any]]) -> None:
    by_id = {message["message_id"]: message for message in messages}
    response = candidate["response_to"]
    if response is not None:
        target = by_id.get(response)
        if target is None:
            raise CandidateRejected("response_to target is missing from the accepted ledger")
        if response == candidate["message_id"]:
            raise CandidateRejected("circular/self response link")
    if candidate["message_type"] == "assistance_response":
        if response is None or by_id[response]["message_type"] != "assistance_request":
            raise CandidateRejected("assistance_response requires a compatible assistance_request")
        request = by_id[response]
        if not ((request["recipient"]["identity"] in (None, candidate["sender"]["identity"]) and
                 request["recipient"]["role"] == candidate["sender"]["role"] and
                 candidate["recipient"]["identity"] in (None, request["sender"]["identity"]) and
                 candidate["recipient"]["role"] == request["sender"]["role"])):
            raise CandidateRejected("assistance response sender/recipient is incompatible with its request")
    elif response is not None and candidate["message_type"] not in {"dissent"}:
        raise CandidateRejected("response_to is only valid for assistance_response or dissent")
    for related in candidate["corroborates_message_ids"]:
        if related == candidate["message_id"] or related not in by_id:
            raise CandidateRejected("repeated, circular, or self-corroborating message reference")


def _validate_specific(candidate: dict[str, Any], handoff: dict[str, Any], messages: list[dict[str, Any]],
                       t07: dict[str, Any] | None) -> None:
    kind = candidate["message_type"]
    if candidate["claim_class"] != CLAIM_FOR_TYPE[kind]:
        raise CandidateRejected("message type/claim class mismatch")
    if kind in {"applicability_challenge", "component_classification_challenge"}:
        if candidate["current_decision"] is None:
            raise CandidateRejected("challenge must retain the current accepted decision")
        expected = handoff["applicability_identity"] if kind == "applicability_challenge" else {
            component["component_id"]: component for component in handoff["components"]}
        if candidate["current_decision"] != expected:
            raise CandidateRejected("challenge attempts to mutate the accepted applicability/component decision")
    elif candidate["current_decision"] is not None:
        raise CandidateRejected("current_decision is only valid on a decision challenge")
    if kind == "duplicate_crosswalk_notice":
        if not candidate["mapping_lineage"]:
            raise CandidateRejected("crosswalk notice must preserve mapping lineage")
    elif candidate["mapping_lineage"]:
        raise CandidateRejected("mapping lineage belongs only to duplicate/crosswalk notices")
    if kind == "dissent":
        disputed = candidate["disputed_identity"]
        if disputed is None or (candidate["response_to"] is None and t07 is None):
            raise CandidateRejected("dissent must identify an exact message or accepted T07 result")
        if t07 is not None and disputed.get("result_id") != t07["result_id"]:
            raise CandidateRejected("dissent disputed result does not match exact accepted T07 result")
    elif candidate["disputed_identity"] is not None:
        raise CandidateRejected("disputed identity belongs only to dissent")
    if kind == "dynamic_test_candidate":
        if candidate["requested_action"] != "propose_inert_dynamic_request":
            raise CandidateRejected("dynamic candidate must remain proposed and inert")
    _validate_links(candidate, messages)


def _validate_tools(candidate: dict[str, Any], handoff: dict[str, Any]) -> None:
    allowed = {item["tool_id"]: set(item["actions"]) for item in handoff["tool_contract"]["allowed_tools"]}
    for use in candidate["tool_activity"]:
        actions = set(use["actions"])
        if use["tool_id"] not in allowed or not actions <= allowed[use["tool_id"]] or actions & FORBIDDEN_ACTIONS:
            raise CandidateRejected("undeclared tool/action or prohibited execution activity")
    if candidate["tool_activity"] and not candidate["derived_outputs"]:
        raise CandidateRejected("derived parser/static-analysis activity requires preserved lineage")
    accepted = {item["input_id"]: item for item in handoff["accepted_inputs"]}
    for output in candidate["derived_outputs"]:
        for source in output["source_lineage"]:
            entry = accepted.get(source["input_id"])
            if entry is None or source["artifact_path"] != entry["artifact"]["path"] or source["artifact_sha256"] != entry["artifact"]["sha256"]:
                raise CandidateRejected("derived output lacks preserved accepted source lineage")


def _validate_candidate(candidate: dict[str, Any], handoff: dict[str, Any], request: dict[str, Any],
                        messages: list[dict[str, Any]], t07: dict[str, Any] | None) -> dict[str, Any]:
    probe = copy.deepcopy(candidate)
    probe["publication"] = {"sequence": request["expected_head"]["next_sequence"],
        "candidate_path": request["candidate"]["path"], "candidate_sha256": request["candidate"]["sha256"],
        "previous_ledger_head_id": request["expected_head"]["message_id"],
        "previous_ledger_head_hash": request["expected_head"]["message_hash"], "published_at": now()}
    errors = validate_document(probe, "owasp-intercom-message.schema.json")
    if errors:
        raise CandidateRejected("candidate message schema validation failed: " + "; ".join(errors))
    if "publication" in candidate:
        raise CandidateRejected("candidate may not supply publication authority")
    if candidate["message_id"] != expected_message_id(candidate):
        raise CandidateRejected("message ID is not deterministic for candidate content")
    if candidate["message_type"] not in MESSAGE_TYPES:
        raise CandidateRejected("unsupported message type")
    expected_identity = (request["run_id"], handoff["selection_identity"]["selection_id"],
                         handoff["applicability_identity"], handoff["worklist_identity"],
                         handoff["batch_identity"], handoff["hashes"])
    actual_identity = (candidate["run_id"], candidate["selection_id"], candidate["applicability_identity"],
                       candidate["worklist_identity"], candidate["batch_identity"], candidate["hashes"])
    expected_handoff = {"handoff_id": handoff["handoff_id"],
        "job_id": owasp_validator_handoff.JOB_ID, "attempt_id": request["handoff"]["attempt_id"],
        "accepted_pointer_path": request["handoff"]["accepted_pointer_path"],
        "accepted_pointer_sha256": request["handoff"]["accepted_pointer_sha256"],
        "handoff_set_path": request["handoff"]["handoff_set_path"],
        "handoff_set_sha256": request["handoff"]["handoff_set_sha256"],
        "member_path": request["handoff"]["member_path"], "member_sha256": request["handoff"]["member_sha256"]}
    if actual_identity != expected_identity or candidate["handoff_identity"] != expected_handoff:
        raise CandidateRejected("run/selection/applicability/worklist/batch/handoff identity mismatch")
    fragments, controls, components, obligations = _identity_sets(handoff)
    subject = candidate["subject"]
    if not set(subject["control_ids"]) <= controls or not set(subject["component_ids"]) <= components or not set(subject["fragment_ids"]) <= set(fragments) or not set(subject["proof_obligation_ids"]) <= obligations:
        raise CandidateRejected("unrelated, nonexistent, cross-batch, or out-of-scope subject identity")
    if candidate["message_type"] not in {"assistance_request", "assistance_response"} and not subject["fragment_ids"]:
        raise CandidateRejected("message requires exact fragment identity")
    _parse_time(candidate["occurred_at"])
    for text in _strings(candidate):
        if SECRET.search(text):
            raise CandidateRejected("secret-bearing output is prohibited")
        if PERSONAL_DATA.search(text):
            raise CandidateRejected("unnecessary personal data is prohibited")
        if PROHIBITED.search(text):
            raise CandidateRejected("message asserts a prohibited finding, authority, compliance, remediation, or runtime claim")
    _validate_roles(candidate, handoff)
    _validate_citations(candidate, handoff)
    _validate_tools(candidate, handoff)
    _validate_specific(candidate, handoff, messages, t07)
    accepted = copy.deepcopy(candidate)
    accepted["publication"] = probe["publication"]
    return accepted


def _base(run_id: str, batch_id: str) -> Path:
    return data_path(run_id, "jobs", JOB_ID, batch_id)


def _projection(messages: list[dict[str, Any]]) -> bytes:
    return b"".join((json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    for item in messages)


def _summary(ledger: dict[str, Any]) -> bytes:
    counts: dict[str, int] = {}
    for message in ledger["messages"]:
        counts[message["message_type"]] = counts.get(message["message_type"], 0) + 1
    lines = ["# OWASP Structured Intercom", "", f"- Sequence: {ledger['sequence']}",
             f"- Head: `{ledger['head_message_id']}`", "- Authority/evidence effect: none",
             "- Dynamic/manual execution: not authorized and not performed", "", "## Message types", ""]
    lines.extend(f"- {key}: {counts[key]}" for key in sorted(counts))
    return ("\n".join(lines) + "\n").encode()


def append(run_id: str, request_path: Path | None = None, *, clock=lambda: datetime.now(timezone.utc)) -> dict[str, Any]:
    run_id = identifier(run_id)
    root = run_path(run_id)
    if not (root / "run-status.json").is_file():
        raise Blocked("create the run through run_process.py --start first")
    request_path = beneath(root, Path(request_path or (root / "inputs" / "owasp-intercom-append-request.json")))
    request = read_json(request_path)
    errors = validate_document(request, "owasp-intercom-append-request.schema.json")
    if errors or request.get("schema") != REQUEST_SCHEMA or request.get("run_id") != run_id:
        raise ValueError("invalid OWASP intercom append request: " + "; ".join(errors))
    batch_id, handoff_id = identifier(request["batch_id"]), identifier(request["handoff_id"])
    base, data = _base(run_id, batch_id), data_path(run_id)
    fingerprint = digest(request)
    with Lock(base / "job.lock"):
        attempt_id = uuid.uuid4().hex
        attempt = beneath(base, base / "attempts" / attempt_id)
        attempt.mkdir(parents=True, exist_ok=False)
        started = {"status": "RUNNING", "run_id": run_id, "job_id": JOB_ID, "scope_id": batch_id,
                   "attempt_id": attempt_id, "input_fingerprint": fingerprint, "started_at": now()}
        atomic_json(base / "latest.json", {"attempt_id": attempt_id, "updated_at": now()})
        atomic_json(attempt / "inputs.json", request)
        atomic_json(attempt / "status.json", started)
        atomic_bytes(attempt / "logs/stdout.log", b""); atomic_bytes(attempt / "logs/stderr.log", b"")
        event(attempt / "logs/events.jsonl", "START", **started)
        try:
            candidate_path = _run_file(root, request["candidate"]["path"], request["candidate"]["sha256"])
            candidate = read_json(candidate_path)
            handoff, handoff_set, t06_pointer = _load_handoff(run_id, request)
            pointer, ledger, ledger_path = _accepted_state(base)
            existing = [] if ledger is None else ledger["messages"]
            # Exact replay is admitted only for the current head and only after every artifact and
            # upstream input has just been revalidated.
            if existing and existing[-1]["message_id"] == candidate.get("message_id") and existing[-1]["publication"]["candidate_sha256"] == request["candidate"]["sha256"]:
                if existing[-1]["publication"]["candidate_path"] != request["candidate"]["path"]:
                    raise CandidateRejected("replay candidate path differs from accepted publication")
                replay_t07_ref = candidate.get("t07_reference")
                replay_t07 = None if replay_t07_ref is None else _load_t07(run_id, batch_id, replay_t07_ref)
                _validate_candidate(candidate, handoff, request, existing[:-1], replay_t07)
                assert pointer is not None
                return {**pointer, "reused": True}
            _validate_head(request, pointer, ledger, ledger_path, data)
            if any(item["message_id"] == candidate.get("message_id") for item in existing):
                raise CandidateRejected("conflicting or repeated message ID")
            t07_ref = candidate.get("t07_reference")
            t07 = None if t07_ref is None else _load_t07(run_id, batch_id, t07_ref)
            accepted = _validate_candidate(candidate, handoff, request, existing, t07)
            if read_json(request_path) != request or file_hash(candidate_path) != request["candidate"]["sha256"]:
                raise Blocked("T08 request or candidate changed during validation")
            re_handoff, re_set, re_pointer = _load_handoff(run_id, request)
            if (re_handoff, re_set, re_pointer) != (handoff, handoff_set, t06_pointer):
                raise Blocked("T06 lineage changed during T08 validation")
            messages = [*existing, accepted]
            ledger_value = {"schema": LEDGER_SCHEMA, "run_id": run_id,
                "selection_id": accepted["selection_id"], "batch_id": batch_id, "handoff_id": handoff_id,
                "sequence": len(messages), "head_message_id": accepted["message_id"],
                "head_message_hash": _message_hash(accepted),
                "previous_attempt_id": None if pointer is None else pointer["attempt_id"],
                "previous_ledger_path": None if ledger_path is None else ledger_path.relative_to(data).as_posix(),
                "previous_ledger_sha256": None if ledger_path is None else file_hash(ledger_path),
                "messages": messages}
            _validate_chain(ledger_value)
            for value, schema in ((accepted, "owasp-intercom-message.schema.json"),
                                  (ledger_value, "owasp-intercom-ledger.schema.json")):
                schema_errors = validate_document(value, schema)
                if schema_errors:
                    raise RuntimeError(f"generated {schema} invalid: " + "; ".join(schema_errors))
            validation = {"schema": "appsec-review/owasp-intercom-validation/1.0", "status": "PASS",
                "run_id": run_id, "batch_id": batch_id, "handoff_id": handoff_id,
                "candidate_path": request["candidate"]["path"], "candidate_sha256": request["candidate"]["sha256"],
                "checks": ["exact newest T06 pointer/set/member/hash", "optional exact newest T07 pointer/result/hash",
                    "exact batch identities and closed roles", "append-only sequence and hash chain",
                    "messages are neither evidence nor authority", "closed tool and execution boundary"], "errors": []}
            output = attempt / "outputs"
            atomic_json(output / "intercom-message.json", accepted)
            atomic_json(output / "intercom-validation.json", validation)
            atomic_json(output / "intercom-ledger.json", ledger_value)
            atomic_bytes(output / "intercom-messages.jsonl", _projection(messages))
            atomic_bytes(output / "intercom-summary.md", _summary(ledger_value))
            paths = [output / name for name in ("intercom-message.json", "intercom-validation.json",
                "intercom-ledger.json", "intercom-messages.jsonl", "intercom-summary.md")]
            artifacts = {path.relative_to(attempt).as_posix(): file_hash(path) for path in paths}
            atomic_json(attempt / "validation/post.json", {"status": "OK", "artifacts": artifacts})
            status = "OK_WITH_GAPS" if accepted["limitations"] or accepted["contradictions"] or accepted["unresolved_conditions"] else "OK"
            atomic_json(attempt / "status.json", {**started, "status": status, "ended_at": now(),
                "message_id": accepted["message_id"], "sequence": len(messages), "artifacts": artifacts})
            pointer_value = {"status": status, "run_id": run_id, "job_id": JOB_ID, "scope_id": batch_id,
                "attempt_id": attempt_id, "input_fingerprint": fingerprint, "selection_id": accepted["selection_id"],
                "handoff_id": handoff_id, "message_id": accepted["message_id"], "message_hash": _message_hash(accepted),
                "sequence": len(messages), "ledger_path": (output / "intercom-ledger.json").relative_to(data).as_posix(),
                "ledger_sha256": artifacts["outputs/intercom-ledger.json"], "artifacts": artifacts, "accepted_at": now()}
            atomic_json(base / "accepted.json", pointer_value)
            event(attempt / "logs/events.jsonl", "END", status=status, run_id=run_id, job_id=JOB_ID,
                  scope_id=batch_id, attempt_id=attempt_id)
            return {**pointer_value, "reused": False}
        except BaseException as exc:
            terminal = "INVALID" if isinstance(exc, (CandidateRejected, ValueError, json.JSONDecodeError)) else "BLOCKED"
            receipt = {"schema": "appsec-review/owasp-intercom-validation/1.0", "status": terminal,
                "run_id": run_id, "batch_id": batch_id, "handoff_id": handoff_id,
                "candidate_path": request["candidate"]["path"], "candidate_sha256": request["candidate"]["sha256"],
                "checks": [], "errors": [{"error_type": type(exc).__name__, "message": str(exc)}]}
            if validate_document(receipt, "owasp-intercom-validation.schema.json"):
                emergency(RuntimeError("invalid T08 failure receipt"))
            atomic_json(attempt / "validation/errors.json", receipt)
            atomic_json(attempt / "status.json", {**started, "status": terminal, "ended_at": now(),
                                                   "error_type": type(exc).__name__, "error": str(exc)})
            try:
                event(attempt / "logs/events.jsonl", "FAILURE", status=terminal, error_type=type(exc).__name__)
            except BaseException as diagnostic:
                emergency(diagnostic)
            # Crucial T08 rule: never replace accepted.json on a rejected/blocked append.
            raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True); parser.add_argument("--request", type=Path)
    args = parser.parse_args(argv)
    try:
        result = append(args.run_id, args.request)
    except (Blocked, CandidateRejected, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"OWASP_INTERCOM_BLOCKED: {exc}", file=sys.stderr); return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
