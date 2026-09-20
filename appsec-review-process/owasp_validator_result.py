#!/usr/bin/env python3
"""Validate and immutably publish one supplied OWASP validator result.

This bounded T07 foundation is offline. It consumes one exact accepted T06 handoff and an
explicitly supplied candidate result. It never executes a validator, inspects the target beyond
the supplied hash-pinned artifacts, joins batches, promotes findings, or performs dynamic/manual
work.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import uuid
from typing import Any

from execution_state import (
    Blocked, Lock, atomic_bytes, atomic_json, beneath, data_path, digest, emergency, event,
    file_hash, identifier, now, read_json, run_path,
)
import owasp_validator_handoff
from schema_validate import validate_document


JOB_ID = "04-owasp-validator-result"
UPSTREAM_JOB = owasp_validator_handoff.JOB_ID
REQUEST_SCHEMA = "appsec-review/owasp-control-assessment-request/1.0"
RESULT_SCHEMA = "appsec-review/owasp-control-assessment-result/1.0"
SUCCESS_TERMINALS = {"OK", "OK_WITH_GAPS"}
FAILURE_TERMINALS = {"BLOCKED", "FAILED", "CANCELED", "TIMED_OUT", "INVALID"}
ASSESSMENTS = {
    "satisfied", "partially_satisfied", "not_satisfied", "cannot_verify",
    "dynamic_test_required", "human_decision_required", "not_assessed",
}
STATIC_MODES = {"document_or_process", "static_source", "static_config", "built_artifact", "test_evidence"}
DERIVED_TOOLS = {"bounded-local-parser", "bounded-static-analysis"}
DERIVED_ACTIONS = {"parse_declared_files", "analyze_declared_files", "preserve_derived_output"}
ALLOWED_CLAIMS = {"control_assessment", "evidence_gap", "proposed_followup", "observed_fact"}


class CandidateRejected(ValueError):
    """The untrusted candidate failed the T07 contract."""


def _relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"path must use nonempty POSIX syntax: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"unsafe relative path: {value!r}")
    return path


def _run_data_file(data_root: Path, relative: str, expected_hash: str) -> Path:
    ref = _relative(relative)
    path = beneath(data_root, data_root.joinpath(*ref.parts))
    if not path.is_file():
        raise Blocked(f"run-owned artifact is missing: {relative}")
    if file_hash(path) != expected_hash:
        raise Blocked(f"run-owned artifact hash mismatch: {relative}")
    return path


def _run_file(run_root: Path, relative: str, expected_hash: str) -> Path:
    ref = _relative(relative)
    path = beneath(run_root, run_root.joinpath(*ref.parts))
    if not path.is_file():
        raise CandidateRejected(f"supplied candidate artifact is missing: {relative}")
    if file_hash(path) != expected_hash:
        raise CandidateRejected(f"supplied candidate artifact hash mismatch: {relative}")
    return path


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise CandidateRejected("timestamp must be a nonempty string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CandidateRejected(f"invalid timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise CandidateRejected(f"timestamp must include timezone: {value!r}")
    return parsed.astimezone(timezone.utc)


def _load_handoff(run_id: str, request: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    data_root = data_path(run_id)
    ref = request["handoff"]
    attempt_id = identifier(ref["attempt_id"])
    pointer_path = _run_data_file(data_root, ref["accepted_pointer_path"], ref["accepted_pointer_sha256"])
    if pointer_path.relative_to(data_root).parts != ("jobs", UPSTREAM_JOB, "whole", "accepted.json"):
        raise ValueError("T07 requires the T06 whole-scope accepted pointer")
    pointer = read_json(pointer_path)
    if (pointer.get("status") not in SUCCESS_TERMINALS or pointer.get("run_id") != run_id or
            pointer.get("job_id") != UPSTREAM_JOB or pointer.get("attempt_id") != attempt_id):
        raise Blocked("T06 accepted pointer identity/status mismatch")
    latest = read_json(pointer_path.with_name("latest.json"))
    if latest.get("attempt_id") != attempt_id:
        raise Blocked("T06 accepted handoff is not the newest attempt")
    attempt = data_root / "jobs" / UPSTREAM_JOB / "whole" / "attempts" / attempt_id
    for relative, expected_hash in pointer.get("artifacts", {}).items():
        path = beneath(attempt, attempt.joinpath(*_relative(relative).parts))
        if not path.is_file() or file_hash(path) != expected_hash:
            raise Blocked(f"T06 accepted artifact is missing or corrupt: {relative}")

    set_path = _run_data_file(data_root, ref["handoff_set_path"], ref["handoff_set_sha256"])
    member_path = _run_data_file(data_root, ref["member_path"], ref["member_sha256"])
    expected_set = attempt / "outputs" / "owasp-validator-handoff-set.json"
    if set_path.absolute() != expected_set.absolute():
        raise ValueError("handoff set does not belong to the accepted T06 attempt")
    set_key = set_path.relative_to(attempt).as_posix()
    member_key = member_path.relative_to(attempt).as_posix()
    if (pointer.get("artifacts", {}).get(set_key) != ref["handoff_set_sha256"] or
            pointer.get("artifacts", {}).get(member_key) != ref["member_sha256"]):
        raise Blocked("T06 pointer does not publish the requested handoff set/member")
    handoff_set = read_json(set_path)
    errors = validate_document(handoff_set, "owasp-validator-handoff-set.schema.json")
    if errors:
        raise Blocked("T06 handoff set is invalid: " + "; ".join(errors))
    members = [item for item in handoff_set["handoffs"] if item["handoff_id"] == request["handoff_id"]]
    if len(members) != 1:
        raise Blocked("requested handoff is not an exact T06 handoff-set member")
    member = members[0]
    if (member["batch_id"] != request["batch_id"] or member["path"] != member_key or
            member["sha256"] != ref["member_sha256"]):
        raise Blocked("T06 handoff-set member identity/hash mismatch")
    handoff = read_json(member_path)
    errors = validate_document(handoff, "owasp-validator-handoff.schema.json")
    if errors:
        raise Blocked("T06 handoff member is invalid: " + "; ".join(errors))
    if (handoff["handoff_id"] != request["handoff_id"] or
            handoff["batch_identity"]["batch_id"] != request["batch_id"] or
            handoff["run_identity"]["run_id"] != run_id or
            handoff_set["run_id"] != run_id or handoff_set["selection_id"] != handoff["selection_identity"]["selection_id"]):
        raise Blocked("T06 handoff run/selection/batch identity mismatch")
    body = {key: value for key, value in handoff.items() if key not in {"schema", "handoff_id", "hashes"}}
    if (digest(body) != handoff["hashes"]["composition_sha256"] or
            digest(handoff["source_identities"]) != handoff["hashes"]["source_sha256"] or
            hashlib.sha256(handoff["prompt_contract"]["text"].encode()).hexdigest() != handoff["hashes"]["prompt_sha256"]):
        raise Blocked("T06 handoff composition/source/prompt hash mismatch")
    return handoff, handoff_set, pointer


def _secret_scan(value: Any, location: str = "$") -> None:
    try:
        owasp_validator_handoff._secret_scan(value, location)
    except Blocked as exc:
        raise CandidateRejected(str(exc).replace("handoff output", "candidate result")) from exc


def _exact_keys(value: dict[str, Any], required: set[str], location: str) -> None:
    if not isinstance(value, dict) or set(value) != required:
        raise CandidateRejected(f"{location} must contain exactly: {', '.join(sorted(required))}")


def _validate_identity(candidate: dict[str, Any], handoff: dict[str, Any], request: dict[str, Any],
                       pointer: dict[str, Any]) -> None:
    if candidate["run_id"] != request["run_id"] or candidate["selection_id"] != handoff["selection_identity"]["selection_id"]:
        raise CandidateRejected("candidate run/selection identity mismatch")
    expected_handoff = {
        "handoff_id": handoff["handoff_id"], "job_id": UPSTREAM_JOB,
        "attempt_id": pointer["attempt_id"],
        "accepted_pointer_path": request["handoff"]["accepted_pointer_path"],
        "accepted_pointer_sha256": request["handoff"]["accepted_pointer_sha256"],
        "handoff_set_path": request["handoff"]["handoff_set_path"],
        "handoff_set_sha256": request["handoff"]["handoff_set_sha256"],
        "member_path": request["handoff"]["member_path"],
        "member_sha256": request["handoff"]["member_sha256"],
    }
    if candidate["handoff_identity"] != expected_handoff:
        raise CandidateRejected("candidate does not preserve the exact T06 handoff identity")
    if candidate["applicability_identity"] != handoff["applicability_identity"]:
        raise CandidateRejected("candidate applicability identity differs from the handoff")
    if candidate["worklist_identity"] != handoff["worklist_identity"]:
        raise CandidateRejected("candidate worklist identity differs from the handoff")
    if candidate["batch_identity"] != handoff["batch_identity"]:
        raise CandidateRejected("candidate batch identity differs from the handoff")
    if candidate["hashes"] != handoff["hashes"]:
        raise CandidateRejected("candidate source/config/prompt/composition hashes differ from the handoff")
    expected_intercom = {
        "path": handoff["expected_outputs"]["structured_intercom"],
        "contract_state": "declared_for_future_T08_only", "implemented": False,
        "messages_consumed": 0, "messages_emitted": 0,
    }
    if candidate["intercom"] != expected_intercom:
        raise CandidateRejected("candidate must preserve only the declared future intercom path")


def _validate_producer_terminal(candidate: dict[str, Any], handoff: dict[str, Any]) -> str:
    _exact_keys(candidate["producer"], {"producer_id", "producer_kind", "produced_at"}, "producer")
    if candidate["producer"]["producer_kind"] not in {"validator", "external_validator"}:
        raise CandidateRejected("candidate producer kind is not a validator")
    if not candidate["producer"]["producer_id"].strip():
        raise CandidateRejected("candidate producer identity is empty")
    _parse_time(candidate["producer"]["produced_at"])
    _exact_keys(candidate["validator"], {"primary_role", "specialist_participants"}, "validator")
    if candidate["validator"]["primary_role"] != handoff["roles"]["primary_validator_role"]:
        raise CandidateRejected("candidate primary validator role differs from the handoff")
    eligible = set(handoff["roles"]["eligible_specialist_roles"])
    participants = candidate["validator"]["specialist_participants"]
    seen = set()
    for participant in participants:
        _exact_keys(participant, {"participant_id", "role"}, "specialist participant")
        if participant["role"] not in eligible or participant["participant_id"] in seen:
            raise CandidateRejected("candidate has an ineligible or duplicate specialist participant")
        seen.add(participant["participant_id"])

    _exact_keys(candidate["terminal"], {"state", "started_at", "ended_at", "failure"}, "terminal")
    state = candidate["terminal"]["state"]
    if state not in SUCCESS_TERMINALS | FAILURE_TERMINALS:
        raise CandidateRejected("candidate terminal state is not allowed by T06")
    started, ended = _parse_time(candidate["terminal"]["started_at"]), _parse_time(candidate["terminal"]["ended_at"])
    if ended < started:
        raise CandidateRejected("candidate terminal time precedes its start")
    failure = candidate["terminal"]["failure"]
    if state in SUCCESS_TERMINALS:
        if failure is not None:
            raise CandidateRejected("successful candidate cannot carry failure provenance")
    else:
        _exact_keys(failure, {"code", "message", "stage"}, "terminal failure")
        if not all(failure[key].strip() for key in failure):
            raise CandidateRejected("terminal failure provenance must be nonempty")
    _exact_keys(candidate["budget"], {"name", "max_output_lines", "timeout_seconds", "output_lines", "elapsed_seconds", "timed_out"}, "budget")
    for key in ("name", "max_output_lines", "timeout_seconds"):
        if candidate["budget"][key] != handoff["budget"][key]:
            raise CandidateRejected("candidate budget differs from the T06 handoff")
    if candidate["budget"]["output_lines"] < 0 or candidate["budget"]["output_lines"] > handoff["budget"]["max_output_lines"]:
        raise CandidateRejected("candidate exceeds its output-line budget")
    if candidate["budget"]["elapsed_seconds"] < 0 or candidate["budget"]["elapsed_seconds"] > handoff["budget"]["timeout_seconds"]:
        raise CandidateRejected("candidate exceeds its timeout without a TIMED_OUT terminal")
    if candidate["budget"]["timed_out"] != (state == "TIMED_OUT"):
        raise CandidateRejected("candidate timeout flag and terminal state disagree")
    return state


def _validate_tools(candidate: dict[str, Any], handoff: dict[str, Any], run_root: Path) -> dict[str, dict[str, Any]]:
    if candidate["tool_profile_id"] != handoff["tool_contract"]["profile_id"]:
        raise CandidateRejected("candidate tool profile differs from the handoff")
    allowed = {tool["tool_id"]: set(tool["actions"]) for tool in handoff["tool_contract"]["allowed_tools"]}
    derived: dict[str, dict[str, Any]] = {}
    accepted = {item["input_id"]: item for item in handoff["accepted_inputs"]}
    for output in candidate["derived_outputs"]:
        _exact_keys(output, {"output_id", "artifact", "producer_tool_id", "producer_action", "source_lineage", "limitations"}, "derived output")
        output_id = output["output_id"]
        if not output_id.strip() or output_id in derived:
            raise CandidateRejected("derived output IDs must be nonempty and unique")
        if (output["producer_tool_id"] not in DERIVED_TOOLS or output["producer_action"] not in DERIVED_ACTIONS or
                output["producer_action"] not in allowed.get(output["producer_tool_id"], set())):
            raise CandidateRejected("derived output producer tool/action is undeclared")
        _exact_keys(output["artifact"], {"path", "sha256"}, "derived output artifact")
        _run_file(run_root, output["artifact"]["path"], output["artifact"]["sha256"])
        if not output["source_lineage"]:
            raise CandidateRejected("derived parser/static-analysis output requires source lineage")
        for source in output["source_lineage"]:
            _exact_keys(source, {"input_id", "artifact_path", "artifact_sha256"}, "derived source lineage")
            entry = accepted.get(source["input_id"])
            if not entry or source["artifact_path"] != entry["artifact"]["path"] or source["artifact_sha256"] != entry["artifact"]["sha256"]:
                raise CandidateRejected("derived output lineage does not match an accepted handoff input")
            _run_data_file(data_path(candidate["run_id"]), source["artifact_path"], source["artifact_sha256"])
        derived[output_id] = output

    used_outputs = set()
    usage_keys = set()
    for usage in candidate["tool_usage"]:
        _exact_keys(usage, {"tool_id", "actions", "purpose", "derived_output_ids"}, "tool usage")
        tool_id = usage["tool_id"]
        actions = usage["actions"]
        key = (tool_id, tuple(actions))
        if key in usage_keys or tool_id not in allowed or not actions or not set(actions).issubset(allowed[tool_id]):
            raise CandidateRejected("candidate reports an undeclared or duplicate tool/action")
        usage_keys.add(key)
        if any(action in DERIVED_ACTIONS for action in actions) and not usage["derived_output_ids"]:
            raise CandidateRejected("bounded parser/static-analysis use requires preserved derived output")
        for output_id in usage["derived_output_ids"]:
            output = derived.get(output_id)
            if not output or output["producer_tool_id"] != tool_id or output["producer_action"] not in actions:
                raise CandidateRejected("tool usage does not match preserved derived-output lineage")
            used_outputs.add(output_id)
    if set(derived) != used_outputs:
        raise CandidateRejected("every derived output must be linked to exact reported tool usage")
    return derived


def _citation_admissible(citation: dict[str, Any], obligation: dict[str, Any], handoff: dict[str, Any],
                         derived: dict[str, dict[str, Any]], run_root: Path) -> bool:
    accepted = {item["input_id"]: item for item in handoff["accepted_inputs"]}
    source_kind = citation["source_kind"]
    if source_kind == "crosswalk":
        raise CandidateRejected("crosswalk records cannot support a proof-obligation outcome")
    if citation["evidence_mode"] == "manual_inspection":
        raise CandidateRejected("manual-observation evidence remains unauthorized")
    if source_kind == "derived_output":
        output = derived.get(citation["derived_output_id"] or "")
        if not output or citation["artifact_path"] != output["artifact"]["path"] or citation["artifact_sha256"] != output["artifact"]["sha256"]:
            raise CandidateRejected("derived citation does not match preserved derived output")
        _run_file(run_root, citation["artifact_path"], citation["artifact_sha256"])
    else:
        if citation["derived_output_id"] is not None:
            raise CandidateRejected("non-derived citation cannot name a derived output")
        entry = accepted.get(citation["input_id"])
        if not entry or citation["artifact_path"] != entry["artifact"]["path"] or citation["artifact_sha256"] != entry["artifact"]["sha256"]:
            raise CandidateRejected("citation does not match an accepted T06 input")
        _run_data_file(data_path(handoff["run_identity"]["run_id"]), citation["artifact_path"], citation["artifact_sha256"])
        producer = entry.get("producer")
        expected_pointer = None if producer is None else {
            "path": producer["accepted_pointer_path"], "sha256": producer["accepted_pointer_sha256"],
            "job_id": producer["job_id"], "attempt_id": producer["attempt_id"],
        }
        if citation["accepted_pointer"] != expected_pointer:
            raise CandidateRejected("citation accepted-producer pointer differs from the handoff")
        if expected_pointer is not None:
            producer_pointer_path = _run_data_file(
                data_path(handoff["run_identity"]["run_id"]),
                expected_pointer["path"], expected_pointer["sha256"],
            )
            producer_pointer = read_json(producer_pointer_path)
            if (producer_pointer.get("status") not in SUCCESS_TERMINALS or
                    producer_pointer.get("attempt_id") != expected_pointer["attempt_id"] or
                    producer_pointer.get("job_id") not in {None, expected_pointer["job_id"]}):
                raise CandidateRejected("citation accepted-producer pointer is no longer accepted")
        if citation["freshness"] != entry["freshness"]:
            raise CandidateRejected("citation freshness differs from its accepted input")
        if source_kind not in {"locator", "nvd_enrichment"} and entry["use"] != "canonical_evidence":
            raise CandidateRejected("locator-only or derived intelligence was presented as canonical evidence")
    if not citation["locator"].strip() or not citation["observed_fact"].strip() or not all(v.strip() for v in citation["covered_scope"]):
        raise CandidateRejected("citation locator, observed fact, and covered scope must be nonempty")
    if citation["freshness"]["status"] == "stale_accepted":
        if not citation["limitations"]:
            raise CandidateRejected("stale evidence must retain an explicit freshness limitation")
        return False
    if source_kind in {"locator", "scanner", "nvd_enrichment"}:
        return False
    if source_kind == "document" and obligation["primary_evidence_mode"] != "document_or_process":
        return False
    if citation["evidence_mode"] not in set(obligation["catalog_minimum_evidence_modes"]) | {obligation["primary_evidence_mode"]}:
        return False
    if obligation["primary_evidence_mode"] in {"dynamic_runtime", "manual_inspection"} and citation["evidence_mode"] in STATIC_MODES:
        return False
    if source_kind == "test_evidence":
        context = citation["test_context"]
        if not context or not all(context[key].strip() for key in ("test_definition", "test_result", "environment_identity")):
            raise CandidateRejected("test evidence requires definition, result, and environment identity")
        deployed_terms = re.compile(r"\b(?:dynamic|runtime|deployed|live[- ]state|production|device)\b", re.IGNORECASE)
        claims_deployed_scope = bool(deployed_terms.search(obligation["text"]) or
                                     any(deployed_terms.search(scope) for scope in citation["covered_scope"]))
        if (context["production_equivalence"] != "equivalent" or context["mocks_used"]) and claims_deployed_scope:
            return False
        if context["production_equivalence"] != "equivalent" and not context["production_equivalence_limitations"]:
            raise CandidateRejected("non-equivalent test evidence requires production-equivalence limitations")
    elif citation["test_context"] is not None:
        raise CandidateRejected("only test evidence may carry test context")
    return True


def _expected_fragment_status(results: list[dict[str, Any]], terminal: str) -> str:
    outcomes = [item["outcome"] for item in results]
    if terminal in FAILURE_TERMINALS:
        return "not_assessed"
    if all(value == "satisfied" for value in outcomes):
        return "satisfied"
    if "partially_satisfied" in outcomes or ("satisfied" in outcomes and any(value != "satisfied" for value in outcomes)):
        return "partially_satisfied"
    if "not_satisfied" in outcomes:
        return "not_satisfied"
    if "dynamic_test_required" in outcomes:
        return "dynamic_test_required"
    if "human_decision_required" in outcomes:
        return "human_decision_required"
    return "cannot_verify"


def _validate_results(candidate: dict[str, Any], handoff: dict[str, Any], terminal: str,
                      derived: dict[str, dict[str, Any]], run_root: Path) -> tuple[set[str], set[str]]:
    expected_fragments = handoff["assigned_fragments"]
    actual = candidate["fragment_results"]
    if [item["fragment_id"] for item in actual] != [item["fragment_id"] for item in expected_fragments]:
        raise CandidateRejected("candidate fragment coverage/order is missing, duplicate, extra, or reordered")
    all_citations, all_obligations = set(), set()
    dynamic_ids = {item["candidate_id"] for item in candidate["dynamic_test_candidates"]}
    route_ids = {item["route_id"] for item in candidate["candidate_verification_routes"]}
    if len(dynamic_ids) != len(candidate["dynamic_test_candidates"]) or len(route_ids) != len(candidate["candidate_verification_routes"]):
        raise CandidateRejected("candidate dynamic/verification route IDs must be unique")

    for fragment, expected in zip(actual, expected_fragments):
        for key in ("fragment_id", "assignment_id", "target_id", "control_id", "component_id", "final_control_status_authority"):
            if fragment[key] != expected[key]:
                raise CandidateRejected(f"fragment {fragment['fragment_id']} changes assigned {key}")
        expected_obligations = expected["proof_obligations"]
        results = fragment["proof_obligation_results"]
        if [item["obligation_id"] for item in results] != [item["obligation_id"] for item in expected_obligations]:
            raise CandidateRejected("candidate proof-obligation coverage/order is missing, duplicate, extra, or reordered")
        for result, obligation in zip(results, expected_obligations):
            all_obligations.add((fragment["fragment_id"], result["obligation_id"]))
            if not result["rationale"].strip():
                raise CandidateRejected("proof-obligation rationale must be nonempty")
            citations = result["evidence_citations"] + result["counterevidence_citations"]
            citation_map = {}
            admissible_evidence, admissible_counter = [], []
            for citation in citations:
                cid = citation["citation_id"]
                if not cid.strip() or cid in citation_map or cid in all_citations:
                    raise CandidateRejected("evidence citation IDs must be globally unique")
                citation_map[cid] = citation
                all_citations.add(cid)
                admissible = _citation_admissible(citation, obligation, handoff, derived, run_root)
                if citation in result["evidence_citations"] and admissible:
                    admissible_evidence.append(citation)
                if citation in result["counterevidence_citations"] and admissible:
                    admissible_counter.append(citation)
            for citation in citations:
                if citation["source_kind"] == "locator":
                    deref = citation_map.get(citation["canonical_dereference_id"] or "")
                    if not deref or deref["source_kind"] in {"locator", "crosswalk", "scanner", "nvd_enrichment"}:
                        raise CandidateRejected("locator-only citation lacks a canonical dereference")
                elif citation["canonical_dereference_id"] is not None:
                    raise CandidateRejected("only locator citations may name a canonical dereference")
            material_unresolved = False
            for contradiction in result["contradictions"]:
                if any(cid not in citation_map for cid in contradiction["citation_ids"]):
                    raise CandidateRejected("contradiction cites evidence outside its obligation")
                if contradiction["resolved"] != (contradiction["resolution"] is not None):
                    raise CandidateRejected("contradiction resolution fields disagree")
                material_unresolved |= contradiction["material"] and not contradiction["resolved"]
            outcome = result["outcome"]
            if terminal in FAILURE_TERMINALS:
                if outcome != "not_assessed":
                    raise CandidateRejected("failed/canceled/timed-out/invalid validator work must map to not_assessed")
                continue
            if outcome == "not_assessed":
                raise CandidateRejected("not_assessed is reserved for unusable terminal validator work")
            if outcome == "satisfied" and (not admissible_evidence or material_unresolved):
                raise CandidateRejected("satisfied requires admissible evidence and no unresolved material contradiction")
            if outcome == "partially_satisfied" and (not admissible_evidence or
                    not (result["evidence_gaps"] or result["unresolved_conditions"] or result["contradictions"] or admissible_counter)):
                raise CandidateRejected("partially_satisfied requires supported and missing/narrow/contradicted scope")
            if outcome == "not_satisfied":
                affirmative = [item for item in admissible_counter if item["affirmative_contrary_evidence"]]
                if not affirmative:
                    raise CandidateRejected("not_satisfied requires admissible affirmative contrary evidence; missing evidence or scanner absence is insufficient")
            if outcome == "cannot_verify" and not (result["evidence_gaps"] or result["unresolved_conditions"] or
                                                     material_unresolved or not admissible_evidence):
                raise CandidateRejected("cannot_verify requires an explicit evidence/capability limitation")
            if outcome == "dynamic_test_required":
                if not result["dynamic_candidate_ids"] or not set(result["dynamic_candidate_ids"]).issubset(dynamic_ids):
                    raise CandidateRejected("dynamic_test_required needs a linked bounded proposed request")
            elif result["dynamic_candidate_ids"]:
                raise CandidateRejected("dynamic candidates may only be linked from dynamic_test_required")
            if outcome == "human_decision_required" and not result["unresolved_conditions"]:
                raise CandidateRejected("human_decision_required needs a policy/risk/legal/scope condition")
            if not set(result["verification_route_ids"]).issubset(route_ids):
                raise CandidateRejected("obligation names an unknown candidate verification route")

        expected_status = _expected_fragment_status(results, terminal)
        if fragment["assessment_status"] != expected_status:
            raise CandidateRejected("fragment assessment status is incompatible with its obligation outcomes")
        if expected["final_control_status_authority"] == "obligation_fragment_only":
            if fragment["final_control_status"] is not None:
                raise CandidateRejected("obligation_fragment_only must not issue a final joined control status")
        elif fragment["final_control_status"] != expected_status:
            raise CandidateRejected("control-result fragment final status must equal its validated fragment status")
    return all_citations, {f"{f}:{o}" for f, o in all_obligations}


def _validate_candidates_and_routes(candidate: dict[str, Any], handoff: dict[str, Any], citation_ids: set[str]) -> None:
    fragments = {item["fragment_id"]: item for item in handoff["assigned_fragments"]}
    obligations = {(fragment["fragment_id"], item["obligation_id"])
                   for fragment in handoff["assigned_fragments"] for item in fragment["proof_obligations"]}
    for item in candidate["dynamic_test_candidates"]:
        fragment = fragments.get(item["fragment_id"])
        if (not fragment or (item["fragment_id"], item["obligation_id"]) not in obligations or
                item["target_id"] != fragment["target_id"] or item["control_id"] != fragment["control_id"] or
                item["component_id"] != fragment["component_id"]):
            raise CandidateRejected("dynamic candidate changes or escapes its assigned identity")
        for field in ("reason_static_is_insufficient", "test_type", "target_environment", "owner", "reentry_path"):
            if not item[field].strip():
                raise CandidateRejected("dynamic candidate must be bounded and complete")
    for route in candidate["candidate_verification_routes"]:
        fragment = fragments.get(route["fragment_id"])
        if (not fragment or route["target_id"] != fragment["target_id"] or
                route["control_id"] != fragment["control_id"] or route["component_id"] != fragment["component_id"] or
                any((route["fragment_id"], obligation_id) not in obligations for obligation_id in route["obligation_ids"]) or
                not set(route["evidence_citation_ids"]).issubset(citation_ids)):
            raise CandidateRejected("candidate verification route lacks exact assignment/evidence lineage")


def _validate_boundaries(candidate: dict[str, Any], handoff: dict[str, Any], citation_ids: set[str]) -> None:
    expected = {
        "trust_boundary_acknowledged": True, "prohibited_claims_acknowledged": True,
        "dynamic_execution_authorized": False, "dynamic_execution_performed": False,
        "manual_observation_performed": False, "target_contacted": False,
        "target_mutated": False, "secrets_included": False, "personal_data_minimized": True,
    }
    if candidate["boundary_acknowledgements"] != expected:
        raise CandidateRejected("candidate trust/authorization boundary acknowledgements are incomplete or widened")
    _secret_scan(candidate)
    for dissent in candidate["dissent"]:
        _exact_keys(dissent, {"dissent_id", "participant_id", "role", "summary", "citation_ids", "resolved"}, "dissent")
        if not dissent["dissent_id"].strip() or not dissent["participant_id"].strip() or not dissent["summary"].strip():
            raise CandidateRejected("dissent identity, participant, and summary must be nonempty")
        if not set(dissent["citation_ids"]).issubset(citation_ids):
            raise CandidateRejected("dissent cites evidence outside the candidate result")
    for claim in candidate["reported_claims"]:
        _exact_keys(claim, {"claim_class", "summary", "evidence_citation_ids"}, "reported claim")
        if claim["claim_class"] not in ALLOWED_CLAIMS or not set(claim["evidence_citation_ids"]).issubset(citation_ids):
            raise CandidateRejected("candidate asserts a prohibited or ungrounded claim class")
        text = claim["summary"].lower()
        prohibited = (
            r"\b(?:is|are|was|were)\s+(?:a\s+)?vulnerab", r"\bseverity\s*(?:is|=|:)",
            r"\bexploitable\b", r"\b(?:is|are)\s+(?:fully\s+)?compliant\b", r"\bcertified\b",
            r"\b(?:is|was|has been)\s+(?:fixed|remediated)\b", r"\bobserved\s+(?:in|on)\s+(?:production|runtime|a live)",
        )
        if any(re.search(pattern, text) for pattern in prohibited):
            raise CandidateRejected("candidate text asserts a prohibited finding/severity/exploitability/compliance/remediation/runtime claim")
    assertive_patterns = (
        r"\b(?:finding|vulnerability)\s+(?:exists|confirmed|established|verified)\b",
        r"\b(?:critical|high|medium|low)\s+severity\b",
        r"\b(?:severity|exploitability|likelihood|impact)\s*(?:is|=|:)\s*\w+",
        r"\b(?:is|are)\s+(?:fully\s+)?(?:compliant|certified)\b",
        r"\b(?:is|was|has been)\s+(?:fixed|remediated)\b",
        r"\b(?:runtime|deployed|live[- ]state|production|device|manual)\s+behavior\s+(?:is|was|has been)\b",
        r"\bobserved\s+(?:in|on)\s+(?:production|runtime|a live|a device)\b",
    )

    def scan_assertions(value: Any) -> None:
        if isinstance(value, dict):
            for item in value.values():
                scan_assertions(item)
        elif isinstance(value, list):
            for item in value:
                scan_assertions(item)
        elif isinstance(value, str) and any(re.search(pattern, value, re.IGNORECASE) for pattern in assertive_patterns):
            raise CandidateRejected("candidate encodes a prohibited finding/severity/exploitability/compliance/remediation/runtime claim")

    scan_assertions(candidate)
    if handoff["handoff_mode"] == "request_authoring_only":
        if any(item["assessment_status"] not in {"dynamic_test_required", "cannot_verify", "not_assessed"}
               for item in candidate["fragment_results"]):
            raise CandidateRejected("dynamic request-authoring handoff cannot assert an observed control status")


def _validate_candidate(candidate: dict[str, Any], handoff: dict[str, Any], request: dict[str, Any],
                        pointer: dict[str, Any], run_root: Path) -> dict[str, Any]:
    errors = validate_document(candidate, "owasp-control-assessment-result.schema.json")
    if errors:
        raise CandidateRejected("candidate result schema validation failed: " + "; ".join(errors))
    if candidate["schema"] != RESULT_SCHEMA:
        raise CandidateRejected("candidate result schema identity mismatch")
    _validate_identity(candidate, handoff, request, pointer)
    terminal = _validate_producer_terminal(candidate, handoff)
    derived = _validate_tools(candidate, handoff, run_root)
    citation_ids, _ = _validate_results(candidate, handoff, terminal, derived, run_root)
    _validate_candidates_and_routes(candidate, handoff, citation_ids)
    _validate_boundaries(candidate, handoff, citation_ids)
    expected_id = "assessment-" + digest({key: value for key, value in candidate.items() if key != "result_id"})[:20]
    if candidate["result_id"] != expected_id:
        raise CandidateRejected("candidate result identity is not deterministic")
    return candidate


def _base(run_id: str, batch_id: str) -> Path:
    return data_path(run_id, "jobs", JOB_ID, batch_id)


def _reusable(base: Path, fingerprint: str) -> dict[str, Any] | None:
    if not (base / "accepted.json").is_file() or not (base / "latest.json").is_file():
        return None
    pointer = read_json(base / "accepted.json")
    if pointer.get("status") not in SUCCESS_TERMINALS or pointer.get("input_fingerprint") != fingerprint:
        return None
    attempt_id = identifier(pointer["attempt_id"])
    if read_json(base / "latest.json").get("attempt_id") != attempt_id:
        raise Blocked("T07 accepted/latest attempt mismatch")
    attempt = beneath(base, base / "attempts" / attempt_id)
    expected = {
        "outputs/control-assessment-result.json", "outputs/result-validation.json",
        "outputs/result-summary.md", "outputs/proposed-dynamic-test-candidates.json",
        "outputs/candidate-verification-routes.json",
    }
    if set(pointer.get("artifacts", {})) != expected:
        raise Blocked("T07 accepted pointer has an incomplete artifact set")
    for relative, expected_hash in pointer["artifacts"].items():
        path = beneath(attempt, attempt.joinpath(*_relative(relative).parts))
        if not path.is_file() or file_hash(path) != expected_hash:
            raise Blocked("T07 accepted artifact is missing or corrupt")
    result = read_json(attempt / "outputs" / "control-assessment-result.json")
    if validate_document(result, "owasp-control-assessment-result.schema.json"):
        raise Blocked("T07 accepted result no longer validates")
    return pointer


def _summary(result: dict[str, Any]) -> bytes:
    counts = {status: 0 for status in sorted(ASSESSMENTS)}
    for fragment in result["fragment_results"]:
        counts[fragment["assessment_status"]] += 1
    lines = [
        "# OWASP validator-result validation summary", "",
        f"- Result: `{result['result_id']}`", f"- Handoff: `{result['handoff_identity']['handoff_id']}`",
        f"- Batch: `{result['batch_identity']['batch_id']}`", f"- Validator terminal state: `{result['terminal']['state']}`",
        f"- Assigned fragments accepted: {len(result['fragment_results'])}",
    ]
    lines.extend(f"- {status}: {count}" for status, count in counts.items() if count)
    lines.extend([
        f"- Proposed dynamic-test candidates: {len(result['dynamic_test_candidates'])}",
        f"- Candidate verification routes: {len(result['candidate_verification_routes'])}",
        "- This result is a control assessment, not a finding, severity, exploitability, compliance, certification, remediation, or runtime authorization claim.",
    ])
    return ("\n".join(lines) + "\n").encode()


def publish(run_id: str, request_path: Path | None = None, *, force: bool = False,
            clock=lambda: datetime.now(timezone.utc)) -> dict[str, Any]:
    run_id = identifier(run_id)
    root = run_path(run_id)
    if not (root / "run-status.json").is_file():
        raise Blocked("create the run through run_process.py --start first")
    request_path = beneath(root, Path(request_path or (root / "inputs" / "owasp-control-assessment-request.json")))
    request = read_json(request_path)
    errors = validate_document(request, "owasp-control-assessment-request.schema.json")
    if errors:
        raise ValueError("invalid OWASP control-assessment request:\n" + "\n".join(errors))
    if request["schema"] != REQUEST_SCHEMA or request["run_id"] != run_id:
        raise ValueError("control-assessment request run/schema mismatch")
    batch_id, handoff_id = identifier(request["batch_id"]), identifier(request["handoff_id"])
    instant = clock()
    if instant.tzinfo is None:
        raise ValueError("T07 clock must be timezone-aware")
    fingerprint = digest({"request": request, "candidate_sha256": request["candidate"]["sha256"]})
    base = _base(run_id, batch_id)
    with Lock(base / "job.lock"):
        candidate_path = None
        candidate = handoff = handoff_set = upstream_pointer = validated = None
        pre_error: BaseException | None = None
        try:
            candidate_path = _run_file(root, request["candidate"]["path"], request["candidate"]["sha256"])
            candidate = read_json(candidate_path)
            handoff, handoff_set, upstream_pointer = _load_handoff(run_id, request)
            validated = _validate_candidate(candidate, handoff, request, upstream_pointer, root)
        except BaseException as exc:
            pre_error = exc
        if pre_error is None and not force:
            reused = _reusable(base, fingerprint)
            if reused:
                return {**reused, "reused": True}
        attempt_id = uuid.uuid4().hex
        attempt = beneath(base, base / "attempts" / attempt_id)
        attempt.mkdir(parents=True, exist_ok=False)
        started = {"status": "RUNNING", "run_id": run_id, "job_id": JOB_ID, "scope_id": batch_id,
                   "attempt_id": attempt_id, "input_fingerprint": fingerprint, "started_at": now()}
        atomic_json(base / "latest.json", {"attempt_id": attempt_id, "updated_at": now()})
        atomic_json(base / "accepted.json", {"status": "PENDING", "attempt_id": attempt_id,
                                               "input_fingerprint": fingerprint, "handoff_id": handoff_id})
        atomic_json(attempt / "status.json", started)
        atomic_bytes(attempt / "logs" / "stdout.log", b"")
        atomic_bytes(attempt / "logs" / "stderr.log", b"")
        event(attempt / "logs" / "events.jsonl", "START", run_id=run_id, job_id=JOB_ID,
              scope_id=batch_id, attempt_id=attempt_id, input_fingerprint=fingerprint)
        atomic_json(attempt / "inputs.json", request)
        try:
            if pre_error is not None:
                raise pre_error
            assert candidate_path is not None and handoff is not None and handoff_set is not None
            assert upstream_pointer is not None and validated is not None
            if read_json(request_path) != request or file_hash(candidate_path) != request["candidate"]["sha256"]:
                raise Blocked("T07 request or candidate changed during validation")
            re_handoff, re_set, re_pointer = _load_handoff(run_id, request)
            if re_handoff != handoff or re_set != handoff_set or re_pointer != upstream_pointer:
                raise Blocked("T06 handoff lineage changed during T07 validation")
            output_dir = attempt / "outputs"
            atomic_json(output_dir / "control-assessment-result.json", validated)
            validation = {
                "schema": "appsec-review/owasp-control-assessment-validation/1.0", "status": "PASS",
                "run_id": run_id, "batch_id": batch_id, "handoff_id": handoff_id,
                "candidate_path": request["candidate"]["path"], "candidate_sha256": request["candidate"]["sha256"],
                "result_id": validated["result_id"], "checks": [
                    "exact accepted T06 pointer, set member, member hash, and newest attempt",
                    "exact fragment and proof-obligation coverage", "evidence sufficiency and freshness",
                    "closed tool/action and derived-output lineage", "claim and trust boundaries",
                    "dynamic/manual execution remains unauthorized",
                ],
            }
            dynamic_set = {
                "schema": "appsec-review/owasp-dynamic-test-candidate-set/1.0", "run_id": run_id,
                "batch_id": batch_id, "authorization": "not_authorized", "execution": "not_executed",
                "candidates": validated["dynamic_test_candidates"],
            }
            route_set = {
                "schema": "appsec-review/owasp-candidate-verification-route-set/1.0", "run_id": run_id,
                "batch_id": batch_id, "finding_promotion": "not_performed",
                "routes": validated["candidate_verification_routes"],
            }
            for value, schema in (
                    (validation, "owasp-control-assessment-validation.schema.json"),
                    (dynamic_set, "owasp-dynamic-test-candidate-set.schema.json"),
                    (route_set, "owasp-candidate-verification-route-set.schema.json")):
                errors = validate_document(value, schema)
                if errors:
                    raise RuntimeError(f"generated {schema} is invalid: " + "; ".join(errors))
            atomic_json(output_dir / "result-validation.json", validation)
            atomic_bytes(output_dir / "result-summary.md", _summary(validated))
            atomic_json(output_dir / "proposed-dynamic-test-candidates.json", dynamic_set)
            atomic_json(output_dir / "candidate-verification-routes.json", route_set)
            paths = [output_dir / name for name in (
                "control-assessment-result.json", "result-validation.json", "result-summary.md",
                "proposed-dynamic-test-candidates.json", "candidate-verification-routes.json")]
            artifacts = {path.relative_to(attempt).as_posix(): file_hash(path) for path in paths}
            atomic_json(attempt / "validation" / "post.json", {"status": "OK", "artifacts": artifacts,
                "schema_validation": "PASS", "coverage": "EXACT", "evidence_sufficiency": "PASS",
                "tool_policy": "PASS", "claim_boundary": "PASS"})
            status = "OK" if validated["terminal"]["state"] == "OK" and not validated["evidence_gaps"] else "OK_WITH_GAPS"
            atomic_json(attempt / "status.json", {**started, "status": status, "ended_at": now(),
                                                   "result_id": validated["result_id"], "artifacts": artifacts})
            event(attempt / "logs" / "events.jsonl", "END", status=status, run_id=run_id,
                  job_id=JOB_ID, scope_id=batch_id, attempt_id=attempt_id)
            pointer = {"status": status, "run_id": run_id, "job_id": JOB_ID, "scope_id": batch_id,
                       "attempt_id": attempt_id, "input_fingerprint": fingerprint,
                       "selection_id": validated["selection_id"], "handoff_id": handoff_id,
                       "result_id": validated["result_id"], "artifacts": artifacts, "accepted_at": now()}
            atomic_json(base / "accepted.json", pointer)
            return {**pointer, "reused": False}
        except BaseException as exc:
            terminal_status = "INVALID" if isinstance(exc, (CandidateRejected, ValueError, json.JSONDecodeError)) else "BLOCKED"
            failure = {**started, "status": terminal_status, "ended_at": now(),
                       "error_type": type(exc).__name__, "error": str(exc)}
            error_receipt = {
                "schema": "appsec-review/owasp-control-assessment-validation/1.0", "status": terminal_status,
                "run_id": run_id, "batch_id": batch_id, "handoff_id": handoff_id,
                "errors": [{"error_type": type(exc).__name__, "message": str(exc)}],
            }
            receipt_errors = validate_document(error_receipt, "owasp-control-assessment-validation.schema.json")
            if receipt_errors:
                emergency(RuntimeError("invalid T07 failure receipt: " + "; ".join(receipt_errors)))
            atomic_json(attempt / "validation" / "errors.json", error_receipt)
            atomic_json(attempt / "status.json", failure)
            try:
                event(attempt / "logs" / "events.jsonl", "FAILURE", status=terminal_status,
                      error_type=type(exc).__name__, run_id=run_id, job_id=JOB_ID,
                      scope_id=batch_id, attempt_id=attempt_id)
            except BaseException as diagnostic_error:
                emergency(diagnostic_error)
            atomic_json(base / "accepted.json", {"status": terminal_status, "run_id": run_id,
                "job_id": JOB_ID, "scope_id": batch_id, "attempt_id": attempt_id,
                "input_fingerprint": fingerprint, "handoff_id": handoff_id,
                "validation_error_path": "validation/errors.json"})
            raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = publish(args.run_id, args.request, force=args.force)
    except (Blocked, CandidateRejected, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"OWASP_VALIDATOR_RESULT_BLOCKED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
