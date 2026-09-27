"""Deterministic nominal L05--L08 claim decision chain.

All supplied claims, assessments, and prose are untrusted data.  This module performs no target
execution and makes no finding, runtime, or compliance claim.  It preserves immutable evidence
identities while enforcing independent, monotonic decision transitions.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from execution_state import Blocked, atomic_json, digest, file_hash, read_json, tree_hashes
from publish_job_output import ACCEPTED_SCHEMA
from schema_validate import validate_document
from worker_result import validate_worker_result

LEDGER_SCHEMA = "claim-ledger-input.schema.json"
PERMISSIONS = ["read-run-data", "write-run-data"]
LEDGER_TRANSITIONS = {
    "candidate": {"under_review", "unresolved", "superseded"},
    "under_review": {"narrowed", "verified", "refuted", "unresolved", "superseded"},
    "narrowed": {"under_review", "verified", "refuted", "unresolved", "superseded"},
    "unresolved": {"under_review", "verified", "refuted", "narrowed", "superseded"},
    "verified": {"superseded"}, "refuted": {"superseded"}, "superseded": set(),
}
STAGES = {
    "07-red-team-adversarial": ("claim-ledger-core", "claim-decision-ledger.json", LEDGER_SCHEMA,
                                "07-red-team-adversarial.schema.json", "red-team-adversarial.json"),
    "08-blue-team-refutation": ("07-red-team-adversarial", "red-team-adversarial.json",
                                "07-red-team-adversarial.schema.json", "08-blue-team-refutation.schema.json",
                                "blue-team-refutation.json"),
    "09-independent-verification": ("08-blue-team-refutation", "blue-team-refutation.json",
                                    "08-blue-team-refutation.schema.json",
                                    "09-independent-verification.schema.json",
                                    "independent-verification.json"),
    "12-scoring-prioritization": ("09-independent-verification", "independent-verification.json",
                                  "09-independent-verification.schema.json",
                                  "scoring-prioritization.schema.json",
                                  "scoring-prioritization.json"),
}


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def _admission_claim_id(entry: dict[str, Any]) -> str:
    return "claim-" + digest({"route_id": entry["route_id"],
        "producer": entry["producer"]["job_id"], "attempt": entry["producer"]["attempt_id"],
        "artifact": entry["producer"]["artifact_sha256"],
        "source_generation": entry["source_generation"],
        "component_generation": entry["component_generation"]})[:24]


def _event_id(entry: dict[str, Any]) -> str:
    return "event-" + digest({key: value for key, value in entry.items()
        if key not in {"event_id", "entry_hash"}})[:24]


def _ledger_view(value: dict[str, Any]) -> dict[str, Any]:
    """Project the stable candidate surface from the accepted L01 ledger without weakening it."""
    required = {"schema", "run_id", "job_id", "attempt_id", "source_generation",
                "component_generation", "entries", "head_hash", "claim_states", "claim_limits"}
    if (not isinstance(value, dict) or set(value) != required or
            value.get("schema") != "appsec-review/claim-decision-ledger/1.0" or
            value.get("job_id") != "claim-ledger-routing" or not isinstance(value.get("entries"), list) or
            not value["entries"]):
        raise Blocked("claim lifecycle: accepted L01 ledger shape is invalid")
    limits = value.get("claim_limits")
    if limits != {"candidate_only": True, "finding_created": False, "severity_assigned": False,
                  "runtime_claimed": False, "compliance_claimed": False}:
        raise Blocked("claim lifecycle: accepted L01 claim ceiling is invalid")
    entry_keys = {"sequence", "event_id", "event_type", "claim_id", "route_id", "claim_class",
        "hypothesis", "status", "confidence", "component_ids", "source_generation",
        "component_generation", "producer", "citations", "proof_obligations", "dissent_ids",
        "causal_claim_ids", "supersedes_claim_id", "from_status", "decision_authority",
        "previous_entry_hash", "entry_hash"}
    producer_keys = {"contract_id", "job_id", "attempt_id", "artifact_path", "artifact_sha256",
                     "accepted_pointer_sha256"}
    citation_keys = {"citation_id", "producer_job_id", "producer_attempt_id", "artifact_path",
                     "artifact_sha256", "locator_json", "observed_fact"}
    authority_keys = {"contract_id", "job_id", "attempt_id", "role_id", "source_generation",
        "component_generation", "accepted_pointer_sha256", "envelope_sha256", "artifact_path",
        "artifact_sha256", "permission_receipt_path", "permission_receipt_sha256", "reason"}
    previous, latest, admissions, events, routes = None, {}, {}, set(), {}
    for sequence, entry in enumerate(value["entries"]):
        if (not isinstance(entry, dict) or set(entry) != entry_keys or entry.get("sequence") != sequence or
                entry.get("event_id") in events or entry.get("previous_entry_hash") != previous or
                entry.get("entry_hash") != _sha({key: item for key, item in entry.items()
                                                 if key != "entry_hash"}) or
                entry.get("source_generation") != value["source_generation"] or
                entry.get("component_generation") != value["component_generation"]):
            raise Blocked("claim lifecycle: accepted L01 ledger chain is invalid")
        if (entry["event_id"] != _event_id(entry) or not isinstance(entry.get("producer"), dict) or
                set(entry["producer"]) != producer_keys or entry.get("claim_class") != "candidate_only" or
                not isinstance(entry.get("component_ids"), list) or not entry["component_ids"] or
                len(entry["component_ids"]) != len(set(entry["component_ids"])) or
                not isinstance(entry.get("citations"), list) or not entry["citations"] or
                any(not isinstance(item, dict) or set(item) != citation_keys for item in entry["citations"]) or
                not isinstance(entry.get("proof_obligations"), list) or not entry["proof_obligations"] or
                any(not isinstance(item, dict) or set(item) != {"obligation_id", "statement"}
                    for item in entry["proof_obligations"]) or
                len({item["citation_id"] for item in entry["citations"]}) != len(entry["citations"]) or
                len({item["obligation_id"] for item in entry["proof_obligations"]}) != len(entry["proof_obligations"]) or
                len(entry["dissent_ids"]) != len(set(entry["dissent_ids"])) or
                len(entry["causal_claim_ids"]) != len(set(entry["causal_claim_ids"])) or
                (entry["decision_authority"] is not None and
                 (not isinstance(entry["decision_authority"], dict) or
                  set(entry["decision_authority"]) != authority_keys))):
            raise Blocked("claim lifecycle: accepted L01 ledger schema invariants are invalid")
        prior = latest.get(entry["claim_id"])
        if entry["event_type"] == "candidate_admitted":
            if (prior is not None or entry["from_status"] is not None or entry["status"] != "candidate" or
                    entry["claim_id"] != _admission_claim_id(entry) or entry["route_id"] in routes):
                raise Blocked("claim lifecycle: accepted L01 admission identity is invalid")
            routes[entry["route_id"]] = entry["claim_id"]
            admissions[entry["claim_id"]] = entry
        elif (entry["event_type"] != "status_decision" or prior is None or
              entry["from_status"] != prior["status"] or
              entry["status"] not in LEDGER_TRANSITIONS.get(prior["status"], set()) or
              entry["route_id"] != admissions[entry["claim_id"]]["route_id"]):
            raise Blocked("claim lifecycle: accepted L01 status transition is invalid")
        events.add(entry["event_id"]); previous = entry["entry_hash"]; latest[entry["claim_id"]] = entry
    states = [{"claim_id": claim_id, "latest_event_id": latest[claim_id]["event_id"],
               "status": latest[claim_id]["status"]} for claim_id in sorted(latest)]
    if value["head_hash"] != previous or value["claim_states"] != states:
        raise Blocked("claim lifecycle: accepted L01 head or state projection is invalid")
    claim_ids = set(latest)
    if any(not set(entry["causal_claim_ids"]) <= claim_ids for entry in value["entries"]):
        raise Blocked("claim lifecycle: accepted L01 causal identity is missing")
    causal = {claim_id: set(entry["causal_claim_ids"]) for claim_id, entry in latest.items()}
    def visit(claim_id: str, trail: set[str]) -> None:
        if claim_id in trail:
            raise Blocked("claim lifecycle: accepted L01 causal graph is circular")
        for predecessor in causal[claim_id]:
            visit(predecessor, trail | {claim_id})
    for claim_id in causal:
        visit(claim_id, set())
    fields = ("claim_id", "route_id", "claim_class", "hypothesis", "status", "confidence",
              "component_ids", "source_generation", "component_generation", "producer", "citations",
              "proof_obligations", "dissent_ids", "causal_claim_ids", "supersedes_claim_id")
    candidates = [{key: latest[claim_id][key] for key in fields} for claim_id in sorted(latest)
                  if latest[claim_id]["status"] == "candidate"]
    return {"schema": "appsec-review/claim-ledger-input/0.1", "run_id": value["run_id"],
            "ledger_head_id": value["entries"][-1]["event_id"],
            "ledger_head_sha256": value["head_hash"], "candidates": candidates}


def _relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str):
        raise Blocked("claim lifecycle: artifact path is not relative")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise Blocked("claim lifecycle: artifact path is not relative")
    return path


def _owned(attempt: Path, relative: str) -> Path:
    rel = _relative(relative)
    path = attempt.joinpath(*rel.parts)
    try:
        path.resolve(strict=True).relative_to(attempt.resolve())
    except (OSError, ValueError) as exc:
        raise Blocked("claim lifecycle: artifact escapes its immutable attempt") from exc
    cursor = attempt
    for part in rel.parts:
        cursor /= part
        if cursor.is_symlink():
            raise Blocked("claim lifecycle: artifact traverses a symbolic link")
    if not path.is_file():
        raise Blocked("claim lifecycle: artifact is missing")
    return path


def _plain_directory(owner: Path, path: Path) -> Path:
    try:
        relative = path.relative_to(owner)
        resolved_owner = owner.resolve(strict=True)
        path.resolve(strict=True).relative_to(resolved_owner)
    except (OSError, ValueError) as exc:
        raise Blocked("claim lifecycle: accepted attempt escapes its canonical root") from exc
    cursor = owner
    if cursor.is_symlink() or not cursor.is_dir():
        raise Blocked("claim lifecycle: accepted root is not a real directory")
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink() or not cursor.is_dir():
            raise Blocked("claim lifecycle: accepted attempt traverses a linked directory")
    return path


def load_accepted(pointer_path: Path, *, run_id: str, job_id: str, contract: str,
                  artifact: str, schema: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load only an exact newest common accepted pointer and immutable result envelope."""
    pointer_path = Path(pointer_path)
    base = pointer_path.parent
    if base.is_symlink() or not base.is_dir() or pointer_path.is_symlink() or not pointer_path.is_file():
        raise Blocked("claim lifecycle: accepted pointer root is unsafe")
    pointer = read_json(pointer_path)
    keys = {"schema", "status", "run_id", "job", "attempt_id", "fingerprint", "envelope_path",
            "envelope_sha256", "hashes", "accepted_at"}
    if (set(pointer) != keys or pointer.get("schema") != ACCEPTED_SCHEMA or
            pointer.get("status") not in {"OK", "OK_WITH_GAPS"} or pointer.get("run_id") != run_id or
            pointer.get("job") != job_id or pointer.get("envelope_path") != "result.json"):
        raise Blocked("claim lifecycle: accepted pointer identity or shape is invalid")
    latest_path = base / "latest.json"
    if latest_path.is_symlink() or not latest_path.is_file():
        raise Blocked("claim lifecycle: latest pointer is not a regular file")
    latest = read_json(latest_path)
    if latest.get("attempt_id") != pointer["attempt_id"]:
        raise Blocked("claim lifecycle: accepted pointer is stale")
    attempts = _plain_directory(base, base / "attempts")
    attempt = _plain_directory(attempts, attempts / pointer["attempt_id"])
    try:
        hashes = tree_hashes(attempt)
    except (OSError, ValueError) as exc:
        raise Blocked("claim lifecycle: accepted attempt tree is unsafe") from exc
    if hashes != pointer["hashes"]:
        raise Blocked("claim lifecycle: accepted attempt tree is corrupt")
    envelope_path = _owned(attempt, "result.json")
    envelope = read_json(envelope_path)
    if (file_hash(envelope_path) != pointer["envelope_sha256"] or validate_worker_result(envelope) or
            envelope.get("run_id") != run_id or envelope.get("job_id") != job_id or
            envelope.get("attempt_id") != pointer["attempt_id"] or
            envelope.get("input_fingerprint") != pointer["fingerprint"] or
            envelope.get("execution_status") != pointer["status"] or
            envelope.get("acceptance_status") != "CURRENT" or envelope.get("output_contract") != contract):
        raise Blocked("claim lifecycle: accepted result envelope is invalid")
    artifacts = {item.get("path"): item for item in envelope.get("artifacts", [])}
    if len(artifacts) != len(envelope.get("artifacts", [])) or artifact not in artifacts:
        raise Blocked("claim lifecycle: result artifact is absent or duplicated")
    for relative, item in artifacts.items():
        if not isinstance(relative, str) or file_hash(_owned(attempt, relative)) != item.get("sha256"):
            raise Blocked("claim lifecycle: accepted artifact hash is invalid")
    result_path = _owned(attempt, artifact)
    result = read_json(result_path)
    if schema == LEDGER_SCHEMA:
        result = _ledger_view(result)
    if validate_document(result, schema):
        raise Blocked("claim lifecycle: accepted result fails its closed schema")
    binding = {"job_id": job_id, "attempt_id": pointer["attempt_id"],
               "pointer_sha256": "sha256:" + file_hash(pointer_path),
               "artifact_path": artifact, "artifact_sha256": "sha256:" + file_hash(result_path)}
    return result, binding


def _index(records: list[dict[str, Any]], field: str = "claim_id") -> dict[str, dict[str, Any]]:
    result = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get(field), str) or not record[field]:
            raise Blocked("claim lifecycle: claim identity is absent or invalid")
        identity = record[field]
        if identity in result:
            raise Blocked("claim lifecycle: duplicate claim identity")
        result[identity] = record
    return result


def _decision_index(decisions: dict[str, Any], expected: set[str]) -> dict[str, dict[str, Any]]:
    rows = decisions.get("decisions")
    if not isinstance(rows, list):
        raise Blocked("claim lifecycle: decisions must be a list")
    indexed = _index(rows)
    if set(indexed) != expected:
        raise Blocked("claim lifecycle: every and only upstream claim must have one decision")
    return indexed


def _closed(record: dict[str, Any], keys: set[str], stage: str) -> None:
    if not isinstance(record, dict) or set(record) != keys:
        raise Blocked(f"{stage}: decision shape is not closed")


def _validate_ledger(ledger: dict[str, Any]) -> None:
    candidates = _index(ledger["candidates"])
    generations = {(row["component_generation"], row["source_generation"])
                   for row in candidates.values()}
    if len(generations) > 1:
        raise Blocked("red team: mixed ledger generations")
    for row in candidates.values():
        dependencies = row["causal_claim_ids"]
        if len(dependencies) != len(set(dependencies)) or any(item not in candidates for item in dependencies):
            raise Blocked("red team: missing or duplicate causal claim")
        supersedes = row["supersedes_claim_id"]
        if supersedes is not None and (supersedes == row["claim_id"] or supersedes not in candidates):
            raise Blocked("red team: invalid supersession link")
        obligations = [item["obligation_id"] for item in row["proof_obligations"]]
        if len(obligations) != len(set(obligations)):
            raise Blocked("red team: duplicate proof obligation")
    visiting, visited = set(), set()
    def visit(claim_id: str) -> None:
        if claim_id in visiting:
            raise Blocked("red team: circular causal evidence")
        if claim_id in visited:
            return
        visiting.add(claim_id)
        for predecessor in candidates[claim_id]["causal_claim_ids"]:
            visit(predecessor)
        visiting.remove(claim_id); visited.add(claim_id)
    for claim_id in candidates:
        visit(claim_id)


def _base(upstream: dict[str, Any], binding: dict[str, Any], schema: str, stage: str) -> dict[str, Any]:
    return {"schema": schema, "run_id": upstream["run_id"], "stage": stage,
            "ledger_head_id": upstream["ledger_head_id"],
            "ledger_head_sha256": upstream["ledger_head_sha256"], "upstream": binding,
            "claim_boundary": "DECISION_RECORD_NOT_RUNTIME_OR_COMPLIANCE_PROOF"}


def _preserved(record: dict[str, Any]) -> dict[str, Any]:
    return {key: record[key] for key in ("claim_id", "route_id", "claim_class", "hypothesis",
            "confidence", "component_ids", "component_generation", "source_generation", "producer",
            "citations", "proof_obligations", "dissent_ids", "causal_claim_ids", "supersedes_claim_id")}


def _independent(actor: dict[str, Any], forbidden: set[tuple[str, str]]) -> None:
    identity = (actor.get("job_id"), actor.get("attempt_id"))
    if not all(isinstance(item, str) and item for item in identity) or identity in forbidden:
        raise Blocked("claim lifecycle: self-review or reused reviewer identity is forbidden")


def _authority(actor: dict[str, Any], record: dict[str, Any], role_id: str) -> None:
    if (actor.get("role_id") != role_id or actor.get("source_generation") != record["source_generation"] or
            actor.get("component_generation") != record["component_generation"]):
        raise Blocked("claim lifecycle: decision authority role or generation is invalid")


def _citation_ids(values: list[dict[str, Any]]) -> set[str]:
    identities = [value.get("citation_id") for value in values]
    if any(not isinstance(value, str) or not value for value in identities) or len(identities) != len(set(identities)):
        raise Blocked("claim lifecycle: citation identity is absent or duplicated")
    return set(identities)


def _merge_ids(existing: list[str], added: list[str]) -> list[str]:
    if len(existing) != len(set(existing)) or len(added) != len(set(added)):
        raise Blocked("claim lifecycle: dissent identity is duplicated")
    return list(existing) + sorted(value for value in added if value not in set(existing))


def _validate(result: dict[str, Any], schema: str) -> dict[str, Any]:
    if validate_document(result, schema):
        raise Blocked("claim lifecycle: normalized decision output fails its closed schema")
    return result


def permission_receipt(stage: str, result: dict[str, Any]) -> dict[str, Any]:
    records = next(value for value in result.values() if isinstance(value, list))
    generations = {record["source_generation"] for record in records}
    if len(generations) != 1:
        raise Blocked("claim lifecycle: permission receipt generation is absent or mixed")
    return {"schema": "appsec-review/producer-permission-receipt/1.0", "run_id": result["run_id"],
            "job_id": stage, "source_snapshot_sha256": next(iter(generations)),
            "permissions": PERMISSIONS}


def red_team(ledger: dict[str, Any], binding: dict[str, Any], decisions: dict[str, Any]) -> dict[str, Any]:
    _validate_ledger(ledger)
    candidates = _index(ledger["candidates"])
    rows = _decision_index(decisions, set(candidates))
    hypotheses = []
    for claim_id in sorted(candidates):
        candidate, decision = candidates[claim_id], rows[claim_id]
        _closed(decision, {"claim_id", "reviewer", "attacker_case", "citations", "dissent_ids"}, "red team")
        if candidate["claim_class"] != "candidate_only" or candidate["status"] != "candidate":
            raise Blocked("red team: ledger record is not a candidate")
        reviewer = decision["reviewer"]
        _independent(reviewer, {(candidate["producer"]["job_id"], candidate["producer"]["attempt_id"])})
        _authority(reviewer, candidate, "red-team-adversary")
        if not decision.get("attacker_case") or not decision.get("citations"):
            raise Blocked("red team: attacker case and citations are required")
        if not _citation_ids(decision["citations"]) <= _citation_ids(candidate["citations"]):
            raise Blocked("red team: cited evidence does not resolve in the accepted candidate")
        hypotheses.append({**_preserved(candidate), "status": "HYPOTHESIS",
            "proof_obligations": [{**item, "status": "OPEN", "citations": []}
                                  for item in candidate["proof_obligations"]],
            "hypothesis_id": "hyp_" + digest((claim_id, decision))[:20],
            "attacker_case": decision["attacker_case"],
            "reviewer": reviewer, "review_citations": decision["citations"],
            "dissent_ids": _merge_ids(candidate["dissent_ids"], decision.get("dissent_ids", []))})
    result = {**_base(ledger, binding, "appsec-review/red-team-adversarial/1.0",
                      "07-red-team-adversarial"), "hypotheses": hypotheses}
    return _validate(result, "07-red-team-adversarial.schema.json")


def blue_team(red: dict[str, Any], binding: dict[str, Any], decisions: dict[str, Any]) -> dict[str, Any]:
    hypotheses = _index(red["hypotheses"])
    rows = _decision_index(decisions, set(hypotheses))
    reviews = []
    for claim_id in sorted(hypotheses):
        hypothesis, decision = hypotheses[claim_id], rows[claim_id]
        _closed(decision, {"claim_id", "reviewer", "disposition", "rationale", "proof_obligations",
                           "citations", "dissent_ids"}, "blue team")
        _independent(decision["reviewer"], {(hypothesis["reviewer"]["job_id"], hypothesis["reviewer"]["attempt_id"])})
        _authority(decision["reviewer"], hypothesis, "blue-team-refuter")
        disposition = decision["disposition"]
        obligations = decision["proof_obligations"]
        if {x["obligation_id"] for x in obligations} != {x["obligation_id"] for x in hypothesis["proof_obligations"]}:
            raise Blocked("blue team: proof obligations are incomplete")
        statuses = {x["status"] for x in obligations}
        allowed_citations = _citation_ids(hypothesis["citations"]) | _citation_ids(hypothesis["review_citations"])
        if not _citation_ids(decision["citations"]) <= allowed_citations:
            raise Blocked("blue team: cited evidence does not resolve in the accepted hypothesis")
        if any(not _citation_ids(item["citations"]) <= _citation_ids(decision["citations"])
               for item in obligations):
            raise Blocked("blue team: proof obligation citation is outside the decision evidence")
        if disposition == "REFUTED" and "FAILED" not in statuses:
            raise Blocked("blue team: refutation requires a failed proof obligation")
        if disposition == "SURVIVING" and statuses != {"SATISFIED"}:
            raise Blocked("blue team: surviving requires all current proof obligations satisfied")
        if disposition == "UNRESOLVED" and "UNRESOLVED" not in statuses:
            raise Blocked("blue team: unresolved must retain an unresolved proof obligation")
        reviews.append({**_preserved(hypothesis), "hypothesis_id": hypothesis["hypothesis_id"],
            "status": disposition, "attacker_case": hypothesis["attacker_case"],
            "red_reviewer": hypothesis["reviewer"], "blue_reviewer": decision["reviewer"],
            "refutation_rationale": decision["rationale"], "proof_obligations": obligations,
            "refutation_citations": decision["citations"],
            "dissent_ids": _merge_ids(hypothesis["dissent_ids"], decision.get("dissent_ids", []))})
    result = {**_base(red, binding, "appsec-review/blue-team-refutation/1.0",
                      "08-blue-team-refutation"), "reviews": reviews}
    return _validate(result, "08-blue-team-refutation.schema.json")


def verify(blue: dict[str, Any], binding: dict[str, Any], decisions: dict[str, Any]) -> dict[str, Any]:
    reviews = _index(blue["reviews"])
    rows = _decision_index(decisions, set(reviews))
    results = []
    for claim_id in sorted(reviews):
        review, decision = reviews[claim_id], rows[claim_id]
        _closed(decision, {"claim_id", "verifier", "disposition", "method", "proof_obligations",
                           "citations", "dissent_ids"}, "verification")
        forbidden = {(review["red_reviewer"]["job_id"], review["red_reviewer"]["attempt_id"]),
                     (review["blue_reviewer"]["job_id"], review["blue_reviewer"]["attempt_id"])}
        _independent(decision["verifier"], forbidden)
        _authority(decision["verifier"], review, "independent-verifier")
        disposition = decision["disposition"]
        obligations = decision["proof_obligations"]
        if {x["obligation_id"] for x in obligations} != {x["obligation_id"] for x in review["proof_obligations"]}:
            raise Blocked("verification: proof obligations are incomplete")
        statuses = {x["status"] for x in obligations}
        if review["status"] == "REFUTED" and disposition == "VERIFIED":
            raise Blocked("verification: a refuted claim cannot be upgraded to verified")
        if disposition == "VERIFIED" and statuses != {"SATISFIED"}:
            raise Blocked("verification: verified requires every proof obligation satisfied")
        if disposition in {"UNRESOLVED", "BLOCKED"} and "UNRESOLVED" not in statuses:
            raise Blocked("verification: unresolved disposition must remain explicit")
        prior_hashes = {item["citation_id"] for item in review["citations"] + review["refutation_citations"]}
        verification_hashes = {item["citation_id"] for item in decision["citations"]}
        if any(not _citation_ids(item["citations"]) <= verification_hashes for item in obligations):
            raise Blocked("verification: proof obligation citation is outside the verification evidence")
        if disposition == "VERIFIED" and not (verification_hashes - prior_hashes):
            raise Blocked("verification: verified requires new independent evidence")
        if disposition == "VERIFIED" and any(
                (item["producer_job_id"], item["producer_attempt_id"]) !=
                (decision["verifier"]["job_id"], decision["verifier"]["attempt_id"])
                for item in decision["citations"]):
            raise Blocked("verification: independent evidence identity does not match the verifier")
        results.append({**_preserved(review), "hypothesis_id": review["hypothesis_id"],
            "status": disposition, "red_reviewer": review["red_reviewer"],
            "blue_reviewer": review["blue_reviewer"], "verifier": decision["verifier"],
            "verification_method": decision["method"], "proof_obligations": obligations,
            "verification_citations": decision["citations"],
            "dissent_ids": _merge_ids(review["dissent_ids"], decision.get("dissent_ids", []))})
    result = {**_base(blue, binding, "appsec-review/independent-verification/1.0",
                      "09-independent-verification"), "verifications": results}
    return _validate(result, "09-independent-verification.schema.json")


def score(verification: dict[str, Any], binding: dict[str, Any], decisions: dict[str, Any]) -> dict[str, Any]:
    verified = _index(verification["verifications"])
    rows = _decision_index(decisions, set(verified))
    priorities = []
    for claim_id in sorted(verified):
        record, decision = verified[claim_id], rows[claim_id]
        _closed(decision, {"claim_id", "factors", "rationale"}, "scoring")
        if record["status"] != "VERIFIED":
            if decision.get("factors") is not None:
                raise Blocked("scoring: unresolved or refuted claims cannot receive score factors")
            score_value = None
            priority = "UNRESOLVED" if record["status"] in {"UNRESOLVED", "BLOCKED"} else "NOT_SCORED"
            severity, rationale = None, decision["rationale"]
        else:
            factors = decision.get("factors")
            if not isinstance(factors, dict) or set(factors) != {"impact", "exploitability", "exposure", "confidence"}:
                raise Blocked("scoring: verified claim has incomplete factors")
            score_value = sum(factors.values())
            if score_value >= 15: priority, severity = "P0", "CRITICAL"
            elif score_value >= 12: priority, severity = "P1", "HIGH"
            elif score_value >= 8: priority, severity = "P2", "MEDIUM"
            else: priority, severity = "P3", "LOW"
            rationale = decision["rationale"]
        priorities.append({**_preserved(record), "verification_status": record["status"],
            "verifier": record["verifier"], "verification_citations": record["verification_citations"],
            "score": score_value, "severity": severity, "priority": priority,
            "factors": decision.get("factors"), "scoring_rationale": rationale})
    priorities.sort(key=lambda x: (x["score"] is None, -(x["score"] or 0), x["claim_id"]))
    result = {**_base(verification, binding, "appsec-review/scoring-prioritization/1.0",
                      "12-scoring-prioritization"), "priorities": priorities}
    return _validate(result, "scoring-prioritization.schema.json")


def run_stage(stage: str, accepted_pointer: Path, decisions_path: Path, output_path: Path,
              run_id: str) -> dict[str, Any]:
    contract, artifact, upstream_schema, _output_schema, _output_artifact = STAGES[stage]
    upstream_job = "claim-ledger-routing" if stage == "07-red-team-adversarial" else contract
    upstream, binding = load_accepted(accepted_pointer, run_id=run_id, job_id=upstream_job,
                                      contract=contract, artifact=artifact, schema=upstream_schema)
    decisions = read_json(decisions_path)
    function = {"07-red-team-adversarial": red_team, "08-blue-team-refutation": blue_team,
                "09-independent-verification": verify, "12-scoring-prioritization": score}[stage]
    result = function(upstream, binding, decisions)
    atomic_json(output_path, result)
    atomic_json(output_path.parent / "permission.json", permission_receipt(stage, result))
    return result
