#!/usr/bin/env python3
"""Nominal deterministic append-only claim and decision ledger core (L01)."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
from typing import Any, Iterable

from execution_state import Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest, file_hash, read_json
from publish_job_output import ACCEPTED_SCHEMA, coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document
from worker_result import validate_worker_result
import threat_model_core

JOB = "claim-ledger-routing"
CONTRACT = "claim-ledger-core"
LEDGER = "claim-decision-ledger.json"
ROUTING = "claim-ledger-work-routing.json"
SUMMARY = "claim-ledger-summary.md"
PERMISSIONS = ["read-run-data", "write-run-data"]
STATUSES = frozenset({"candidate", "under_review", "narrowed", "verified", "refuted", "unresolved", "superseded"})
TRANSITIONS = {
    "candidate": frozenset({"under_review", "unresolved", "superseded"}),
    "under_review": frozenset({"narrowed", "verified", "refuted", "unresolved", "superseded"}),
    "narrowed": frozenset({"under_review", "verified", "refuted", "unresolved", "superseded"}),
    "unresolved": frozenset({"under_review", "verified", "refuted", "narrowed", "superseded"}),
    "verified": frozenset({"superseded"}), "refuted": frozenset({"superseded"}), "superseded": frozenset(),
}
AUTHORITY = {
    "07-red-team-adversarial": frozenset({"under_review", "unresolved"}),
    "08-blue-team-refutation": frozenset({"narrowed", "refuted", "unresolved"}),
    "09-independent-verification": frozenset({"narrowed", "verified", "refuted", "unresolved"}),
    JOB: frozenset({"superseded"}),
}
AUTHORITY_ROLES = {"07-red-team-adversarial": "red-team-adversary", "08-blue-team-refutation": "blue-team-refuter",
                   "09-independent-verification": "independent-verifier", JOB: "claim-ledger-custodian"}
DECISION_PRODUCERS = {
    "07-red-team-adversarial": ("07-red-team-adversarial", "red-team-adversarial.json", "hypotheses",
                                "reviewer", "review_citations", {"HYPOTHESIS": "under_review"}),
    "08-blue-team-refutation": ("08-blue-team-refutation", "blue-team-refutation.json", "reviews",
                                "blue_reviewer", "refutation_citations", {"SURVIVING": "narrowed", "REFUTED": "refuted",
                                                   "UNRESOLVED": "unresolved"}),
    "09-independent-verification": ("09-independent-verification", "independent-verification.json",
                                    "verifications", "verifier", "verification_citations", {"VERIFIED": "verified",
                                    "REFUTED": "refuted", "UNRESOLVED": "unresolved",
                                    "BLOCKED": "unresolved"}),
}
DECISION_SCHEMAS = {job: job + ".schema.json" for job in DECISION_PRODUCERS}
DECISION_PERMISSIONS = ["read-run-data", "write-run-data"]
PROHIBITED_KEYS = frozenset({"finding", "findings", "severity", "cvss", "runtime_state",
    "observed_runtime", "compliance", "certification", "remediation_status"})
PROHIBITED_TEXT = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    r"\bverified\s+finding\b", r"\bconfirmed\s+(?:finding|vulnerability)\b",
    r"\bseverity\s*(?::|is)\s*(?:critical|high|medium|low)\b", r"\bobserved\s+runtime\b",
    r"\b(?:is|are)\s+(?:compliant|certified)\b", r"\b(?:is|has been)\s+(?:fixed|remediated)\b"))
CODE_FILES = (
    "claim_ledger.py", "threat_model_core.py", "publish_job_output.py", "validate_job_output.py",
    "registry/job-templates/claim-ledger-routing.json", "registry/roles/claim-ledger-custodian.json",
    "registry/domains/claim-ledger-lifecycle.json", "registry/tooling-profiles/hash-linked-claim-ledger.json",
    "registry/output-contracts/claim-ledger-core.json", "claim-ledger-routing/task-claim-ledger-core.md",
)


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _code_hashes() -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    for name in ("claim-ledger-citation.schema.json", "claim-ledger-entry.schema.json",
                 "claim-decision-ledger.schema.json", "claim-ledger-work-routing.schema.json"):
        values[f"schemas/{name}"] = file_hash(ROOT.parent / "schemas" / name)
    return values


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def _canonical_locator(value: Any) -> str | None:
    return None if value is None else json.dumps(value, sort_keys=True, separators=(",", ":"))


def _citation(source: dict[str, Any], value: dict[str, Any], citation_id: str) -> dict[str, Any]:
    path = value.get("artifact_path", value.get("path", source["artifact_path"]))
    sha = value.get("artifact_sha256", value.get("sha256", source["artifact_sha256"]))
    pointer = value.get("accepted_pointer") or {}
    return {"citation_id": citation_id,
        "producer_job_id": pointer.get("job_id", value.get("producer", source["producer_job_id"])),
        "producer_attempt_id": pointer.get("attempt_id", value.get("attempt_id", source["producer_attempt_id"])),
        "artifact_path": path, "artifact_sha256": sha, "locator_json": _canonical_locator(
            value.get("locator", value.get("line_range"))),
        "observed_fact": value.get("observed_fact", value.get("note", "candidate source citation"))}


def threat_candidates(source: dict[str, Any]) -> list[dict[str, Any]]:
    value = source["artifact"]
    _reject_promotions(value)
    errors = validate_document(value, "integrated-threat-model.schema.json")
    if errors:
        raise Blocked(f"{JOB}: invalid threat-model source ({errors[0]})")
    elements = {item["element_id"]: item for item in value["elements"]}
    flows = {item["flow_id"]: item for item in value["flows"]}
    dissent = {subject: item for item in value["dissent"] for subject in item["subject_record_ids"]}
    candidates = []
    for item in sorted(value["stride_hypotheses"], key=lambda row: row["threat_id"]):
        if item["target_kind"] == "element":
            component_ids = [elements[item["target_id"]]["component_id"]]
        else:
            flow = flows[item["target_id"]]
            component_ids = [elements[key]["component_id"] for key in
                             (flow["source_element_id"], flow["destination_element_id"])]
        citations = [_citation(source, citation, "citation-" + digest(citation)[:24])
                     for citation in item["citations"]]
        obligations = [{"obligation_id": "obligation-" + digest({"route": item["threat_id"], "text": text})[:24],
                        "statement": text} for text in item["proof_obligations"]]
        candidates.append({"route_id": item["threat_id"], "hypothesis": item["statement"],
            "confidence": item["confidence"], "component_ids": sorted(set(component_ids)),
            "citations": citations, "proof_obligations": obligations,
            "dissent_ids": sorted({dissent[item["threat_id"]]["challenge_record_id"]}
                                  if item["threat_id"] in dissent else set()),
            "causal_route_ids": [], "source": source})
    return candidates


def owasp_candidates(source: dict[str, Any]) -> list[dict[str, Any]]:
    value = source["artifact"]
    _reject_promotions(value)
    schema = ROOT.parent / "schemas" / "owasp-candidate-promotion-routes.schema.json"
    if schema.is_file():
        errors = validate_document(value, schema.name)
        if errors: raise Blocked(f"{JOB}: invalid OWASP route source ({errors[0]})")
    if set(value) != {"schema", "run_id", "selection_id", "finding_promotion", "routes"} or value.get("finding_promotion") != "not_performed":
        raise Blocked(f"{JOB}: OWASP source is not the candidate-only T12 contract")
    candidates = []
    for route in sorted(value["routes"], key=lambda row: row["route_id"]):
        if not route.get("candidate_only") or any(route.get(key) for key in
                ("finding_created", "severity_assigned", "runtime_claimed")):
            raise Blocked(f"{JOB}: OWASP route promotes a candidate")
        citations = [_citation(source, item, item["citation_id"]) for item in route["evidence_citations"]]
        candidates.append({"route_id": route["route_id"], "hypothesis": route["mechanism_or_impact_hypothesis"],
            "confidence": "unknown", "component_ids": [route["component_id"]], "citations": citations,
            "proof_obligations": [{"obligation_id": oid, "statement": oid}
                                  for oid in route["proof_obligation_ids"]],
            "dissent_ids": [], "causal_route_ids": [], "source": source})
    return candidates


def _entry_hash(entry: dict[str, Any]) -> str:
    copy = {key: value for key, value in entry.items() if key != "entry_hash"}
    return _sha(copy)


def _admission_claim_id(entry: dict[str, Any]) -> str:
    return "claim-" + digest({"route_id": entry["route_id"],
        "producer": entry["producer"]["job_id"], "attempt": entry["producer"]["attempt_id"],
        "artifact": entry["producer"]["artifact_sha256"],
        "source_generation": entry["source_generation"],
        "component_generation": entry["component_generation"]})[:24]


def _event_id(entry: dict[str, Any]) -> str:
    return "event-" + digest({key: value for key, value in entry.items()
        if key not in {"event_id", "entry_hash"}})[:24]


def _merge_citations(existing: Iterable[dict[str, Any]], added: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Preserve first occurrence order, coalesce identical IDs, reject contradictory reuse."""
    merged: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for citation in [*existing, *added]:
        citation_id = citation.get("citation_id") if isinstance(citation, dict) else None
        if not isinstance(citation_id, str) or not citation_id:
            raise Blocked(f"{JOB}: decision citation identity is absent")
        prior = by_id.get(citation_id)
        if prior is not None:
            if prior != citation:
                raise Blocked(f"{JOB}: contradictory decision citation reuses {citation_id}")
            continue
        copied = deepcopy(citation); by_id[citation_id] = copied; merged.append(copied)
    return merged


def _reject_promotions(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = key.lower().replace("-", "_")
            if normalized in PROHIBITED_KEYS and item not in (False, None, [], {}):
                raise Blocked(f"{JOB}: prohibited promoted claim at {path}.{key}")
            _reject_promotions(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value): _reject_promotions(item, f"{path}[{index}]")
    elif isinstance(value, str) and any(pattern.search(value) for pattern in PROHIBITED_TEXT):
        raise Blocked(f"{JOB}: prohibited promoted claim text at {path}")


def _regular_owned(owner: Path, relative: str) -> Path:
    """Resolve a plain relative file without following a symlink at any path segment."""
    candidate = Path(relative)
    if candidate.is_absolute() or not candidate.parts or any(part in {"", ".", ".."} for part in candidate.parts):
        raise Blocked(f"{JOB}: decision artifact path is not canonical and relative")
    cursor = owner
    if owner.is_symlink() or not owner.is_dir():
        raise Blocked(f"{JOB}: decision producer root is not a plain directory")
    for index, part in enumerate(candidate.parts):
        cursor /= part
        if cursor.is_symlink():
            raise Blocked(f"{JOB}: decision artifact traverses a symbolic link")
        if index < len(candidate.parts) - 1 and not cursor.is_dir():
            raise Blocked(f"{JOB}: decision artifact parent is not a directory")
    if not cursor.is_file():
        raise Blocked(f"{JOB}: decision artifact is missing")
    try:
        cursor.resolve(strict=True).relative_to(owner.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise Blocked(f"{JOB}: decision artifact escapes its canonical attempt") from exc
    return cursor


def load_decision(run_id: str, jobs_root: Path, request: dict[str, Any],
                  source_generation: str, component_generation: str) -> dict[str, Any]:
    """Resolve transition authority from one exact current downstream publication.

    The request selects a claim and producer only.  Paths, hashes, actor identity, disposition,
    permission receipt, and generations are all re-derived from the producer's accepted attempt.
    """
    if not isinstance(request, dict) or set(request) != {"claim_id", "producer_job_id"}:
        raise Blocked(f"{JOB}: decision request shape is not closed")
    producer = request["producer_job_id"]
    if producer not in DECISION_PRODUCERS:
        raise Blocked(f"{JOB}: decision producer is not an accepted downstream authority")
    contract, result_name, collection, actor_field, citation_field, statuses = DECISION_PRODUCERS[producer]
    base = Path(jobs_root) / producer
    pointer_path = _regular_owned(base, "accepted.json")
    latest_path = _regular_owned(base, "latest.json")
    pointer, latest = read_json(pointer_path), read_json(latest_path)
    pointer_keys = {"schema", "status", "run_id", "job", "attempt_id", "fingerprint",
                    "envelope_path", "envelope_sha256", "hashes", "accepted_at"}
    if (set(pointer) != pointer_keys or pointer.get("schema") != ACCEPTED_SCHEMA or
            pointer.get("status") not in {"OK", "OK_WITH_GAPS"} or pointer.get("run_id") != run_id or
            pointer.get("job") != producer or pointer.get("envelope_path") != "result.json" or
            latest.get("attempt_id") != pointer.get("attempt_id")):
        raise Blocked(f"{JOB}: decision producer pointer is stale or malformed")
    attempts = base / "attempts"
    attempt = attempts / str(pointer["attempt_id"])
    if attempts.is_symlink() or attempt.is_symlink() or not attempt.is_dir():
        raise Blocked(f"{JOB}: decision attempt is not a canonical plain directory")
    try:
        attempt.resolve(strict=True).relative_to(attempts.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise Blocked(f"{JOB}: decision attempt escapes its canonical producer root") from exc
    from execution_state import tree_hashes
    try:
        current_hashes = tree_hashes(attempt)
    except (OSError, ValueError) as exc:
        raise Blocked(f"{JOB}: decision attempt tree is unsafe") from exc
    if current_hashes != pointer["hashes"]:
        raise Blocked(f"{JOB}: decision attempt tree changed after acceptance")
    envelope_path = _regular_owned(attempt, "result.json")
    envelope = read_json(envelope_path)
    if (file_hash(envelope_path) != pointer["envelope_sha256"] or validate_worker_result(envelope) or
            envelope.get("run_id") != run_id or envelope.get("job_id") != producer or
            envelope.get("attempt_id") != pointer["attempt_id"] or
            envelope.get("input_fingerprint") != pointer["fingerprint"] or
            envelope.get("execution_status") != pointer["status"] or
            envelope.get("acceptance_status") != "CURRENT" or envelope.get("output_contract") != contract):
        raise Blocked(f"{JOB}: decision producer envelope is invalid")
    artifact_records = {item.get("path"): item for item in envelope.get("artifacts", [])}
    if len(artifact_records) != len(envelope.get("artifacts", [])):
        raise Blocked(f"{JOB}: decision producer has duplicate artifact paths")
    for required in (result_name, "permission.json"):
        if required not in artifact_records:
            raise Blocked(f"{JOB}: decision producer omitted {required}")
        if file_hash(_regular_owned(attempt, required)) != artifact_records[required].get("sha256"):
            raise Blocked(f"{JOB}: decision producer {required} hash is invalid")
    result, permission = read_json(attempt / result_name), read_json(attempt / "permission.json")
    try:
        schema_errors = validate_document(result, DECISION_SCHEMAS[producer])
    except (FileNotFoundError, ValueError) as exc:
        raise Blocked(f"{JOB}: authoritative decision result schema is unavailable") from exc
    if schema_errors:
        raise Blocked(f"{JOB}: accepted decision result fails its closed contract schema ({schema_errors[0]})")
    _reject_promotions(result)
    if (result.get("run_id") != run_id or result.get("stage") != producer or
            result.get("claim_boundary") != "DECISION_RECORD_NOT_RUNTIME_OR_COMPLIANCE_PROOF"):
        raise Blocked(f"{JOB}: decision result identity or claim boundary is invalid")
    rows = [row for row in result.get(collection, []) if row.get("claim_id") == request["claim_id"]]
    if len(rows) != 1 or rows[0].get("status") not in statuses:
        raise Blocked(f"{JOB}: decision result has no unique authorized claim disposition")
    row = rows[0]
    if (row.get("source_generation") != source_generation or
            row.get("component_generation") != component_generation):
        raise Blocked(f"{JOB}: decision result has a stale or mixed generation")
    actor = row.get(actor_field)
    if not isinstance(actor, dict) or actor.get("job_id") != producer or actor.get("attempt_id") != attempt.name:
        raise Blocked(f"{JOB}: decision actor is not the accepted producer attempt")
    if (actor.get("source_generation") != source_generation or
            actor.get("component_generation") != component_generation or
            actor.get("role_id") != AUTHORITY_ROLES[producer]):
        raise Blocked(f"{JOB}: decision actor authority or generation is invalid")
    permission_keys = {"schema", "run_id", "job_id", "source_snapshot_sha256", "permissions"}
    if (set(permission) != permission_keys or permission.get("schema") != "appsec-review/producer-permission-receipt/1.0" or
            permission.get("run_id") != run_id or permission.get("job_id") != producer or
            permission.get("source_snapshot_sha256") != source_generation or
            permission.get("permissions") != DECISION_PERMISSIONS):
        raise Blocked(f"{JOB}: decision permission receipt is invalid")
    authority = {"contract_id": contract, "job_id": producer, "attempt_id": attempt.name,
        "role_id": actor["role_id"],
        "source_generation": source_generation, "component_generation": component_generation,
        "accepted_pointer_sha256": "sha256:" + file_hash(pointer_path),
        "envelope_sha256": "sha256:" + file_hash(envelope_path),
        "artifact_path": result_name, "artifact_sha256": "sha256:" + file_hash(attempt / result_name),
        "permission_receipt_path": "permission.json",
        "permission_receipt_sha256": "sha256:" + file_hash(attempt / "permission.json"),
        "reason": f"Accepted {producer} disposition {row['status']} from its exact current result."}
    return {"claim_id": request["claim_id"], "to_status": statuses[row["status"]],
        "authority": authority, "citations": deepcopy(row[citation_field]),
        "dissent_ids": deepcopy(row["dissent_ids"]),
        "causal_claim_ids": deepcopy(row["causal_claim_ids"]),
        "supersedes_claim_id": row["supersedes_claim_id"], "confidence": row["confidence"]}


def validate_ledger(value: dict[str, Any]) -> list[str]:
    errors = list(validate_document(value, "claim-decision-ledger.schema.json"))
    if errors: return errors
    previous, claims, admissions, events, routes = None, {}, {}, set(), {}
    for sequence, entry in enumerate(value["entries"]):
        if entry["sequence"] != sequence: errors.append("ledger sequence is not contiguous")
        if entry["event_id"] in events: errors.append("duplicate event id")
        events.add(entry["event_id"])
        if entry["event_id"] != _event_id(entry): errors.append("event id differs from canonical content")
        citation_ids = [item["citation_id"] for item in entry["citations"]]
        obligation_ids = [item["obligation_id"] for item in entry["proof_obligations"]]
        if len(citation_ids) != len(set(citation_ids)): errors.append("duplicate/conflicting citation id")
        if len(obligation_ids) != len(set(obligation_ids)): errors.append("duplicate/conflicting proof-obligation id")
        if entry["previous_entry_hash"] != previous: errors.append("broken previous-entry hash chain")
        if entry["entry_hash"] != _entry_hash(entry): errors.append("entry hash differs from canonical content")
        if entry["source_generation"] != value["source_generation"] or entry["component_generation"] != value["component_generation"]:
            errors.append("mixed source/component generation")
        prior = claims.get(entry["claim_id"])
        if entry["event_type"] == "candidate_admitted":
            if prior is not None or entry["from_status"] is not None or entry["status"] != "candidate":
                errors.append("duplicate/conflicting candidate admission")
            if entry["claim_id"] != _admission_claim_id(entry):
                errors.append("claim id differs from deterministic route and producer identity")
            if entry["route_id"] in routes:
                errors.append("duplicate/conflicting route id")
            routes[entry["route_id"]] = entry["claim_id"]
            admissions[entry["claim_id"]] = entry
        elif prior is None or entry["from_status"] != prior["status"] or entry["status"] not in TRANSITIONS[prior["status"]]:
            errors.append("unsupported claim status transition")
        elif entry["route_id"] != admissions[entry["claim_id"]]["route_id"]:
            errors.append("claim route identity changed after admission")
        claims[entry["claim_id"]] = entry
        previous = entry["entry_hash"]
    if value["head_hash"] != previous: errors.append("ledger head does not match the chain")
    expected_states = [{"claim_id": key, "latest_event_id": claims[key]["event_id"], "status": claims[key]["status"]}
                       for key in sorted(claims)]
    if value["claim_states"] != expected_states: errors.append("claim state projection differs from ledger")
    claim_ids = set(claims)
    for entry in value["entries"]:
        missing = set(entry["causal_claim_ids"]) - claim_ids
        if missing: errors.append("causal claim id does not resolve to an existing ledger claim")
    causal = {entry["claim_id"]: set(entry["causal_claim_ids"]) for entry in value["entries"]}
    def visit(node: str, trail: set[str]) -> bool:
        if node in trail: return True
        return any(visit(child, trail | {node}) for child in causal.get(node, ()) if child in causal)
    if any(visit(node, set()) for node in causal): errors.append("causal claim graph contains a cycle")
    return errors


def build_ledger(run_id: str, attempt_id: str, candidates: Iterable[dict[str, Any]],
                 prior: dict[str, Any] | None = None, decisions: Iterable[dict[str, Any]] = (),
                 decision_jobs_root: Path | None = None) -> dict[str, Any]:
    candidates, decisions = list(candidates), list(decisions)
    generations = {(item["source"]["source_generation"], item["source"]["component_generation"])
                   for item in candidates}
    if prior is not None:
        errors = validate_ledger(prior)
        if errors: raise Blocked(f"{JOB}: prior ledger is invalid ({errors[0]})")
        generations.add((prior["source_generation"], prior["component_generation"]))
    if len(generations) != 1: raise Blocked(f"{JOB}: stale or mixed source/component generations")
    source_generation, component_generation = next(iter(generations))
    if decisions:
        if decision_jobs_root is None:
            raise Blocked(f"{JOB}: transitions require exact accepted downstream decision producers")
        decisions = [load_decision(run_id, decision_jobs_root, item, source_generation,
                                   component_generation) for item in decisions]
    entries = deepcopy(prior["entries"] if prior else [])
    claims = {entry["claim_id"]: entry for entry in entries}
    route_ids = {entry["route_id"] for entry in entries if entry["event_type"] == "candidate_admitted"}
    previous = entries[-1]["entry_hash"] if entries else None
    candidate_claim_ids = {candidate["route_id"]: "claim-" + digest({"route_id": candidate["route_id"],
        "producer": candidate["source"]["producer_job_id"], "attempt": candidate["source"]["producer_attempt_id"],
        "artifact": candidate["source"]["artifact_sha256"], "source_generation": source_generation,
        "component_generation": component_generation})[:24] for candidate in candidates}
    for candidate in sorted(candidates, key=lambda item: (item["source"]["producer_job_id"], item["route_id"])):
        if candidate["route_id"] in route_ids: raise Blocked(f"{JOB}: duplicate/conflicting route id")
        if not set(candidate["causal_route_ids"]) <= set(candidate_claim_ids):
            raise Blocked(f"{JOB}: candidate causal route does not resolve in this generation")
        source = candidate["source"]
        claim_id = candidate_claim_ids[candidate["route_id"]]
        if claim_id in claims: raise Blocked(f"{JOB}: duplicate/conflicting claim id")
        entry = {"sequence": len(entries), "event_id": "", "event_type": "candidate_admitted",
            "claim_id": claim_id, "route_id": candidate["route_id"], "claim_class": "candidate_only",
            "hypothesis": candidate["hypothesis"], "status": "candidate", "confidence": candidate["confidence"],
            "component_ids": sorted(set(candidate["component_ids"])), "source_generation": source_generation,
            "component_generation": component_generation, "producer": {"contract_id": source["contract_id"],
                "job_id": source["producer_job_id"], "attempt_id": source["producer_attempt_id"],
                "artifact_path": source["artifact_path"], "artifact_sha256": source["artifact_sha256"],
                "accepted_pointer_sha256": source["accepted_pointer_sha256"]},
            "citations": candidate["citations"], "proof_obligations": candidate["proof_obligations"],
            "dissent_ids": sorted(set(candidate["dissent_ids"])),
            "causal_claim_ids": sorted({candidate_claim_ids[route] for route in candidate["causal_route_ids"]
                                        if route in candidate_claim_ids}),
            "supersedes_claim_id": None, "from_status": None, "decision_authority": None,
            "previous_entry_hash": previous, "entry_hash": ""}
        entry["event_id"] = _event_id(entry)
        entry["entry_hash"] = _entry_hash(entry); entries.append(entry); claims[claim_id] = entry
        route_ids.add(candidate["route_id"]); previous = entry["entry_hash"]
    for decision in decisions:
        claim_id, status = decision["claim_id"], decision["to_status"]
        prior_entry = claims.get(claim_id)
        if prior_entry is None or status not in STATUSES or status not in TRANSITIONS[prior_entry["status"]]:
            raise Blocked(f"{JOB}: illegal decision transition")
        authority = decision["authority"]
        if (status not in AUTHORITY.get(authority["job_id"], frozenset()) or
                authority.get("role_id") != AUTHORITY_ROLES.get(authority["job_id"])):
            raise Blocked(f"{JOB}: decision producer is not authorized for transition")
        if (authority.get("source_generation"), authority.get("component_generation")) != (
                source_generation, component_generation):
            raise Blocked(f"{JOB}: decision producer has a stale or mixed generation")
        if status in {"verified", "refuted"} and (authority["job_id"] == prior_entry["producer"]["job_id"] or
                authority["attempt_id"] == prior_entry["producer"]["attempt_id"]):
            raise Blocked(f"{JOB}: candidate producer cannot self-verify or self-refute")
        entry = deepcopy(prior_entry)
        entry.update(sequence=len(entries), event_id="", event_type="status_decision", status=status,
            from_status=prior_entry["status"], decision_authority=authority,
            confidence=decision.get("confidence", prior_entry["confidence"]),
            citations=_merge_citations(prior_entry["citations"], decision.get("citations", [])),
            dissent_ids=sorted(set(prior_entry["dissent_ids"] + decision.get("dissent_ids", []))),
            causal_claim_ids=sorted(set(decision.get("causal_claim_ids", []))),
            supersedes_claim_id=decision.get("supersedes_claim_id"), previous_entry_hash=previous, entry_hash="")
        if claim_id in entry["causal_claim_ids"]: raise Blocked(f"{JOB}: self-causal decision")
        replacement = entry["supersedes_claim_id"]
        if status == "superseded" and (replacement is None or replacement == claim_id or replacement not in claims):
            raise Blocked(f"{JOB}: supersession must name another existing replacement claim")
        if status != "superseded" and replacement is not None:
            raise Blocked(f"{JOB}: supersession link is illegal for this status")
        entry["event_id"] = _event_id(entry)
        entry["entry_hash"] = _entry_hash(entry); entries.append(entry); claims[claim_id] = entry; previous = entry["entry_hash"]
    states = [{"claim_id": key, "latest_event_id": claims[key]["event_id"], "status": claims[key]["status"]}
              for key in sorted(claims)]
    ledger = {"schema": "appsec-review/claim-decision-ledger/1.0", "run_id": run_id, "job_id": JOB,
        "attempt_id": attempt_id, "source_generation": source_generation,
        "component_generation": component_generation, "entries": entries, "head_hash": previous,
        "claim_states": states, "claim_limits": {"candidate_only": True, "finding_created": False,
            "severity_assigned": False, "runtime_claimed": False, "compliance_claimed": False}}
    _reject_promotions(ledger)
    errors = validate_ledger(ledger)
    if errors: raise Blocked(f"{JOB}: generated ledger is invalid ({errors[0]})")
    return ledger


def work_routing(ledger: dict[str, Any]) -> dict[str, Any]:
    routes = [{"claim_id": item["claim_id"], "status": item["status"],
        "stages": ["07-red-team-adversarial", "08-blue-team-refutation", "09-independent-verification"],
        "current_stage": "07-red-team-adversarial", "authorization": "not_authorized", "execution": "not_executed"}
        for item in ledger["claim_states"] if item["status"] in {"candidate", "unresolved", "narrowed"}]
    value = {"schema": "appsec-review/claim-ledger-work-routing/1.0", "run_id": ledger["run_id"],
        "ledger_head_hash": ledger["head_hash"], "routes": routes}
    errors = validate_document(value, "claim-ledger-work-routing.schema.json")
    if errors: raise Blocked(f"{JOB}: generated routing is invalid ({errors[0]})")
    return value


def current_inputs(run_id: str) -> dict[str, Any]:
    attempt = threat_model_core.validate(run_id)
    pointer_path = threat_model_core.root(run_id) / "accepted.json"
    pointer = read_json(pointer_path)
    artifact_path = attempt / threat_model_core.RESULT
    artifact = read_json(artifact_path)
    source = {"contract_id": "threat-model-core", "producer_job_id": threat_model_core.JOB,
        "producer_attempt_id": attempt.name, "artifact_path": artifact_path.relative_to(data_path(run_id)).as_posix(),
        "artifact_sha256": "sha256:" + file_hash(artifact_path),
        "accepted_pointer_sha256": "sha256:" + file_hash(pointer_path),
        "source_generation": artifact["source_snapshot"], "component_generation": artifact["component_map_attempt_id"],
        "artifact": artifact}
    return {"run_id": run_id, "sources": [source], "code": _code_hashes()}


def _receipts(inputs: dict[str, Any], ledger: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0", "run_id": inputs["run_id"],
        "job_id": JOB, "source_snapshot_sha256": ledger["source_generation"], "permissions": PERMISSIONS}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0", "run_id": inputs["run_id"],
        "job_id": JOB, "source_snapshot_sha256": ledger["source_generation"],
        "build_lineage_sha256": _sha(sorted([{"job": item["producer_job_id"], "attempt": item["producer_attempt_id"],
            "artifact": item["artifact_sha256"], "pointer": item["accepted_pointer_sha256"]}
            for item in inputs["sources"]], key=lambda item: (item["job"], item["attempt"], item["artifact"]))) }
    return permission, lineage


def _validate_attempt(attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs: raise Blocked(f"{JOB}: immutable inputs changed")
    candidates = _candidates(inputs)
    ledger = read_json(attempt / LEDGER)
    if ledger != build_ledger(inputs["run_id"], attempt.name, candidates): raise Blocked(f"{JOB}: ledger differs from immutable inputs")
    if read_json(attempt / ROUTING) != work_routing(ledger): raise Blocked(f"{JOB}: routing differs from ledger")
    permission, lineage = _receipts(inputs, ledger)
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{JOB}: permission or lineage receipt differs from canonical inputs")


def _candidates(inputs: dict[str, Any]) -> list[dict[str, Any]]:
    values = []
    for source in inputs["sources"]:
        if source["contract_id"] == "threat-model-core": values.extend(threat_candidates(source))
        elif source["contract_id"] == "owasp-join-report": values.extend(owasp_candidates(source))
        else: raise Blocked(f"{JOB}: unsupported candidate-route contract {source['contract_id']}")
    return values


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)
    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if inputs["code"] != _code_hashes(): raise Blocked(f"{JOB}: implementation changed before execution")
        attempt = allocation["attempt"]
        candidates = _candidates(inputs)
        ledger = build_ledger(run_id, attempt.name, candidates); routing = work_routing(ledger)
        atomic_json(attempt / LEDGER, ledger); atomic_json(attempt / ROUTING, routing)
        atomic_bytes(attempt / SUMMARY, ("# Candidate claim ledger\n\n"
            f"{len(ledger['claim_states'])} candidate claims; head `{ledger['head_hash']}`.\n\n"
            "Ledger admission does not create a finding, severity, runtime, or compliance claim.\n").encode())
        permission, lineage = _receipts(inputs, ledger)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        status = {"process": JOB, "status": "OK", "claims": len(ledger["claim_states"]),
            "ledger_head_hash": ledger["head_hash"], "claim_limit": "candidate-only"}
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
            worker_kind="deterministic_python", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status="OK",
            summary="Hash-linked candidate claim ledger produced.", status_record=status,
            artifact_paths=[LEDGER, ROUTING, SUMMARY, "permission.json", "lineage.json", "status.json"], gaps=[],
            pre_envelope_validate=lambda path, _status: _validate_attempt(path, inputs))
    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="deterministic_python", output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/claim_ledger.py --run-id {run_id}",
        derive_inputs=lambda: current_inputs(run_id), fingerprint_inputs=lambda value: _sha(value),
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()}, force=force,
        post_validate=lambda attempt, _envelope, inputs: _validate_attempt(attempt, inputs),
        blocked_summary="Claim-ledger inputs were not current and exact.", failed_summary="Claim ledger was not published.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-claim-ledger"); parser.add_argument("--force", action="store_true")
    args = parser.parse_args(); print(json.dumps(run(args.run_id, args.dagster_run_id, args.force), indent=2))
