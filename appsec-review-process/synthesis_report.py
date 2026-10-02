#!/usr/bin/env python3
"""Deterministic nominal ``10-synthesis-report`` draft core.

This worker reads only current accepted, hash-bound upstream artifacts.  It renders an immutable
evidence-backed draft; it cannot finalize, sign off, invent scores, or promote unresolved claims.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from execution_state import Blocked, ROOT, atomic_bytes, atomic_json, digest, file_hash, read_json, tree_hashes
from publish_job_output import ACCEPTED_SCHEMA
from schema_validate import validate_document
from worker_result import validate_worker_result
import registry_paths

JOB = "10-synthesis-report"
CONTRACT = "synthesis-report-draft"
STATUS = "DRAFT_EVIDENCE_BACKED"
REPORT_JSON = "report.json"
REPORT_MD = "report.md"
APPENDIX = "coverage-unresolved-appendix.md"
TRACE = "evidence-trace-index.json"
PUBLICATION = "publication-manifest.json"
PERMISSIONS = ["read-run-data", "write-run-data"]
# Reviewer judgment carried from 07/09/12 into verified findings (ADR-0020); absent stays absent.
JUDGMENT_FIELDS = ("cwe_judgments", "cvss_v4", "remediation_proposal")
INPUT_NAMES = ("component", "threat", "owasp", "ledger", "verification", "scoring")
EXPECTED = {
    "component":("01-component-characterization","component-map","component-purpose-map.json"),
    "threat":("03-threat-model-dfd-stride","threat-model-core","integrated-threat-model.json"),
    "owasp":("04-owasp-join-report","owasp-join-report","owasp-control-status-matrix.json"),
    "ledger":("claim-ledger-decisions","claim-ledger-decisions","claim-decision-ledger.json"),
    "verification":("09-independent-verification","09-independent-verification","independent-verification.json"),
    "scoring":("12-scoring-prioritization","12-scoring-prioritization","scoring-prioritization.json")}
SCHEMAS = {"component": "component-purpose-map.schema.json", "threat": "integrated-threat-model.schema.json",
    "owasp": "owasp-control-status-matrix.schema.json", "ledger": "claim-decision-ledger.schema.json",
    "verification": "09-independent-verification.schema.json", "scoring": "scoring-prioritization.schema.json"}
PROHIBITED_TEXT = tuple(re.compile(value, re.I) for value in (
    r"(?<!not a )\bfinal(?:ized)?\s+report\b", r"\bhuman\s+sign[- ]?off\s+(?:recorded|complete|approved)\b", r"\bcompliance\s+(?:certified|verdict)\b",
    r"\b(?:is|has been)\s+(?:fixed|remediated)\b", r"\bobserved\s+runtime\b"))
CODE_FILES = ("synthesis_report.py","10-synthesis-report/task-synthesis-report-core.md",
    registry_paths.template_rel("10-synthesis-report"),registry_paths.contract_rel("synthesis-report-draft"),
    "personas/personas/synthesis-report-drafter/persona.json","personas/roles/synthesis-report-drafter/role.json",
    registry_paths.rel(registry_paths.DOMAINS, "synthesis-report-core"),registry_paths.rel(registry_paths.TOOLING_PROFILES, "synthesis-report-static"))
SCHEMA_FILES = ("synthesis-artifact-ref.schema.json","synthesis-owasp-ref.schema.json",
    "synthesis-input.schema.json","synthesis-citation.schema.json","synthesis-proof-obligation.schema.json",
    "synthesis-upstream-binding.schema.json","synthesis-l08-record.schema.json","synthesis-l08-adapter.schema.json",
    "synthesis-report.schema.json","evidence-trace-index.schema.json","report-publication-manifest.schema.json",
    "cwe-judgment.schema.json","cvss-v4-assessment.schema.json","remediation-proposal-candidate.schema.json")


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def _generator_sha256() -> str:
    values={name:file_hash(ROOT/name) for name in CODE_FILES}
    values.update({"schemas/"+name:file_hash(ROOT.parent/"schemas"/name) for name in SCHEMA_FILES})
    return _sha(values)


def _relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str): raise Blocked(f"{JOB}: artifact path is not text")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise Blocked(f"{JOB}: artifact path is not canonical and relative")
    return path


def _owned(owner: Path, relative: str) -> Path:
    path = _relative(relative); cursor = owner
    if owner.is_symlink() or not owner.is_dir(): raise Blocked(f"{JOB}: artifact owner is unsafe")
    for index, part in enumerate(path.parts):
        cursor /= part
        if cursor.is_symlink(): raise Blocked(f"{JOB}: artifact traverses a symbolic link")
        if index < len(path.parts) - 1 and not cursor.is_dir(): raise Blocked(f"{JOB}: artifact parent is missing")
    if not cursor.is_file(): raise Blocked(f"{JOB}: artifact is missing")
    try: cursor.resolve(strict=True).relative_to(owner.resolve(strict=True))
    except (OSError, ValueError) as exc: raise Blocked(f"{JOB}: artifact escapes accepted attempt") from exc
    return cursor


def _attempt_relative(ref: dict[str, Any]) -> str:
    path = _relative(ref["artifact_path"])
    marker = ("jobs", ref["job_id"], "attempts", ref["attempt_id"])
    parts = path.parts
    for offset in range(len(parts) - len(marker) + 1):
        if parts[offset:offset + len(marker)] == marker:
            rest = parts[offset + len(marker):]
            if not rest: break
            return PurePosixPath(*rest).as_posix()
    return path.as_posix()


def load_reference(run_root: Path, run_id: str, ref: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load one artifact from its exact newest accepted common publication."""
    base = Path(run_root) / "data" / "jobs" / ref["job_id"]
    pointer_path = _owned(base, "accepted.json"); latest_path = _owned(base, "latest.json")
    pointer, latest = read_json(pointer_path), read_json(latest_path)
    pointer_keys={"schema","status","run_id","job","attempt_id","fingerprint","envelope_path",
                  "envelope_sha256","hashes","accepted_at"}
    if (set(pointer)!=pointer_keys or set(latest)!={"attempt_id","updated_at"} or
            pointer.get("schema") != ACCEPTED_SCHEMA or pointer.get("run_id") != run_id or
            pointer.get("job") != ref["job_id"] or pointer.get("attempt_id") != ref["attempt_id"] or
            latest.get("attempt_id") != ref["attempt_id"] or pointer.get("status") not in {"OK", "OK_WITH_GAPS"} or
            "sha256:" + file_hash(pointer_path) != ref["accepted_pointer_sha256"]):
        raise Blocked(f"{JOB}: {ref['job_id']} accepted pointer is stale or mismatched")
    attempts = base / "attempts"; attempt = attempts / ref["attempt_id"]
    if attempts.is_symlink() or attempt.is_symlink() or not attempt.is_dir():
        raise Blocked(f"{JOB}: accepted attempt is unsafe")
    try: attempt.resolve(strict=True).relative_to(attempts.resolve(strict=True))
    except (OSError, ValueError) as exc: raise Blocked(f"{JOB}: accepted attempt escapes its job") from exc
    try: hashes = tree_hashes(attempt)
    except (OSError, ValueError) as exc: raise Blocked(f"{JOB}: accepted attempt tree is unsafe") from exc
    if hashes != pointer.get("hashes"): raise Blocked(f"{JOB}: accepted attempt tree changed")
    envelope_path = _owned(attempt, "result.json"); envelope = read_json(envelope_path)
    if (file_hash(envelope_path) != pointer.get("envelope_sha256") or validate_worker_result(envelope) or
            envelope.get("output_contract") != ref["contract_id"] or envelope.get("attempt_id") != ref["attempt_id"] or
            envelope.get("input_fingerprint") != pointer.get("fingerprint") or
            envelope.get("acceptance_status") != "CURRENT"):
        raise Blocked(f"{JOB}: accepted envelope is invalid")
    artifacts = {item.get("path"): item for item in envelope.get("artifacts", [])}
    if len(artifacts) != len(envelope.get("artifacts", [])): raise Blocked(f"{JOB}: duplicate artifact paths")
    relative = _attempt_relative(ref)
    artifact_path = _owned(attempt, relative)
    if relative not in artifacts or artifacts[relative].get("sha256") != file_hash(artifact_path) or \
            "sha256:" + file_hash(artifact_path) != ref["artifact_sha256"]:
        raise Blocked(f"{JOB}: accepted artifact hash or envelope binding is invalid")
    for receipt, field in (("permission.json", "permission_receipt_sha256"), ("lineage.json", "lineage_receipt_sha256")):
        path = _owned(attempt, receipt)
        if receipt not in artifacts or artifacts[receipt].get("sha256") != file_hash(path) or \
                "sha256:" + file_hash(path) != ref[field]:
            raise Blocked(f"{JOB}: accepted {receipt} binding is invalid")
    binding = {key: value for key, value in deepcopy(ref).items() if key != "supporting_artifacts"}
    return read_json(artifact_path), {**binding, "envelope_sha256": "sha256:" + file_hash(envelope_path)}


def load_inputs(run_root: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = read_json(manifest_path)
    errors = validate_document(manifest, "synthesis-input.schema.json")
    if errors: raise Blocked(f"{JOB}: input manifest is invalid ({errors[0]})")
    integrity = manifest["integrity"]
    if (integrity["inputs_sha256"] != _sha(manifest["inputs"]) or
            integrity["evidence_artifacts_sha256"] != _sha(manifest["evidence_artifacts"]) or
            integrity["manifest_sha256"] != _sha({**manifest, "integrity": {
                **integrity, "manifest_sha256": ""}})):
        raise Blocked(f"{JOB}: input manifest integrity binding is invalid")
    loaded, bindings = {}, {}
    for name in INPUT_NAMES:
        ref=manifest["inputs"][name]; expected_job,expected_contract,expected_artifact=EXPECTED[name]
        if (ref["job_id"]!=expected_job or ref["contract_id"]!=expected_contract or
                PurePosixPath(ref["artifact_path"]).name!=expected_artifact):
            raise Blocked(f"{JOB}: {name} reference does not name its exact required producer contract")
        value, binding = load_reference(run_root, manifest["run_id"], ref)
        schema = SCHEMAS[name]
        if (ROOT.parent / "schemas" / schema).is_file():
            errors = validate_document(value, schema)
            if errors: raise Blocked(f"{JOB}: {name} artifact fails its authoritative schema ({errors[0]})")
        loaded[name], bindings[name] = value, binding
    owref = manifest["inputs"]["owasp"]
    support_kinds = {"owasp-coverage-gaps-report.schema.json": "owasp_gaps",
                     "owasp-candidate-promotion-routes.schema.json": "owasp_routes"}
    if {item["schema"] for item in owref["supporting_artifacts"]} != set(support_kinds):
        raise Blocked(f"{JOB}: OWASP supporting artifacts must be exactly gaps and routes")
    expected_support={"owasp_gaps":"owasp-coverage-gaps.json",
                      "owasp_routes":"owasp-candidate-promotion-routes.json"}
    for supporting in owref["supporting_artifacts"]:
        kind = support_kinds[supporting["schema"]]
        if PurePosixPath(supporting["artifact_path"]).name!=expected_support[kind]:
            raise Blocked(f"{JOB}: OWASP supporting artifact path is not canonical")
        ref = {**{key: owref[key] for key in owref if key != "supporting_artifacts"},
               "artifact_path":supporting["artifact_path"],"artifact_sha256":supporting["artifact_sha256"]}
        value, binding = load_reference(run_root, manifest["run_id"], ref)
        loaded[kind], bindings[kind] = value, binding
    evidence = []
    for ref in manifest["evidence_artifacts"]:
        normalized = {"job_id": ref["producer_job_id"], "attempt_id": ref["producer_attempt_id"],
                      "artifact_path": ref["artifact_path"], "artifact_sha256": ref["artifact_sha256"]}
        producer = Path(run_root) / "data" / "jobs" / normalized["job_id"]
        if not (producer / "attempts").is_dir() and (producer / "whole" / "attempts").is_dir():
            producer = producer / "whole"  # scope-partitioned tool-lead producer
        attempt = producer / "attempts" / normalized["attempt_id"]
        if attempt.is_symlink() or not attempt.is_dir():
            raise Blocked(f"{JOB}: cited evidence attempt is unsafe")
        path = _owned(attempt, _attempt_relative(normalized))
        if "sha256:" + file_hash(path) != normalized["artifact_sha256"]:
            raise Blocked(f"{JOB}: cited evidence artifact changed after assembly")
        evidence.append(normalized)
    return {**manifest, "input_manifest_sha256":"sha256:"+file_hash(manifest_path),
            "documents": loaded, "bindings": bindings, "evidence_bindings": evidence,
            "limitations": []}


def _latest_ledger(ledger: dict[str, Any]) -> dict[str, dict[str, Any]]:
    previous, claims, routes, admissions = None, {}, set(), {}
    for index, entry in enumerate(ledger.get("entries", [])):
        if entry.get("sequence") != index or entry.get("previous_entry_hash") != previous:
            raise Blocked(f"{JOB}: ledger chain is broken")
        expected = _sha({key: value for key, value in entry.items() if key != "entry_hash"})
        if entry.get("entry_hash") != expected: raise Blocked(f"{JOB}: ledger entry hash is invalid")
        event_id="event-"+digest({key:value for key,value in entry.items() if key not in {"event_id","entry_hash"}})[:24]
        if entry.get("event_id")!=event_id: raise Blocked(f"{JOB}: ledger event identity is invalid")
        if entry.get("event_type") == "candidate_admitted":
            if (entry.get("route_id") in routes or entry.get("claim_id") in claims or
                    entry.get("status")!="candidate" or entry.get("from_status") is not None):
                raise Blocked(f"{JOB}: duplicate ledger route or claim")
            routes.add(entry["route_id"])
            claim_id="claim-"+digest({"route_id":entry["route_id"],"producer":entry["producer"]["job_id"],
                "attempt":entry["producer"]["attempt_id"],"artifact":entry["producer"]["artifact_sha256"],
                "source_generation":entry["source_generation"],"component_generation":entry["component_generation"]})[:24]
            if entry["claim_id"]!=claim_id: raise Blocked(f"{JOB}: ledger claim identity is invalid")
            admissions[entry["claim_id"]]=entry
        elif entry.get("claim_id") not in claims:
            raise Blocked(f"{JOB}: decision lacks an admitted claim")
        elif (entry.get("from_status")!=claims[entry["claim_id"]]["status"] or
              entry.get("route_id")!=admissions[entry["claim_id"]]["route_id"]):
            raise Blocked(f"{JOB}: ledger transition lineage is invalid")
        claims[entry["claim_id"]] = entry; previous = entry["entry_hash"]
    if ledger.get("head_hash") != previous: raise Blocked(f"{JOB}: ledger head is invalid")
    if any(causal not in claims for entry in ledger.get("entries",[]) for causal in entry.get("causal_claim_ids",[])):
        raise Blocked(f"{JOB}: ledger causal claim is dangling")
    states=[{"claim_id":key,"latest_event_id":claims[key]["event_id"],"status":claims[key]["status"]}
            for key in sorted(claims)]
    if ledger.get("claim_states")!=states: raise Blocked(f"{JOB}: ledger state projection is invalid")
    return claims


def _citation_key(value: dict[str, Any]) -> tuple[str, str, str, str]:
    return (value.get("producer_job_id", value.get("job_id")),
            value.get("producer_attempt_id", value.get("attempt_id")),
            value["artifact_path"], value["artifact_sha256"])


def _limitations(documents: dict[str, Any], explicit: list[str]) -> list[str]:
    values = list(explicit)
    component, threat, gaps = documents["component"], documents["threat"], documents["owasp_gaps"]
    values.extend(item["reason"] for item in component["classification_gaps"])
    values.extend(item["question"] for item in component["unknowns"])
    values.extend(item["condition"] for item in component.get("rescope_triggers", []))
    values.extend(item["statement"] for item in threat["gaps"])
    values.extend(item["statement"] for item in threat.get("assumptions", []))
    values.extend(item["statement"] for item in threat.get("rescope_triggers", []))
    values.extend(item["reason"] for item in threat["coverage"]["unmodeled_components"])
    values.extend(item["statement"] for item in gaps["gaps"])
    return sorted(set(values))


def l08_adapter(run_id: str, verification: dict[str, Any], scoring: dict[str, Any]) -> dict[str, Any]:
    """Narrow provisional L08 to only the fields synthesis is authorized to consume."""
    verifications = {item["claim_id"]: item for item in verification.get("verifications", [])}
    priorities = {item["claim_id"]: item for item in scoring.get("priorities", [])}
    if (len(verifications) != len(verification.get("verifications", [])) or
            len(priorities) != len(scoring.get("priorities", [])) or set(verifications) != set(priorities)):
        raise Blocked(f"{JOB}: duplicate or differing L08 claim population")
    records = []
    for claim_id in sorted(verifications):
        verified, scored = verifications[claim_id], priorities[claim_id]
        fields = ("route_id", "hypothesis", "confidence", "component_ids", "source_generation", "component_generation")
        if any(verified.get(field) != scored.get(field) for field in fields):
            raise Blocked(f"{JOB}: L08 verification and scoring claim semantics differ")
        records.append({"claim_id":claim_id, **{field:verified[field] for field in fields},
            "verification_status":verified["status"],
            "verification_citations":verified["verification_citations"],
            "severity":scored["severity"],"priority":scored["priority"],"score":scored["score"],
            **{key: scored[key] for key in JUDGMENT_FIELDS if key in scored}})
    value = {"schema":"appsec-review/synthesis-l08-adapter/0.1","run_id":run_id,
        "ledger_head_id":verification["ledger_head_id"],
        "ledger_head_sha256":verification["ledger_head_sha256"],"records":records}
    if (scoring.get("ledger_head_id") != value["ledger_head_id"] or
            scoring.get("ledger_head_sha256") != value["ledger_head_sha256"]):
        raise Blocked(f"{JOB}: L08 ledger heads differ")
    errors = validate_document(value, "synthesis-l08-adapter.schema.json")
    if errors: raise Blocked(f"{JOB}: narrow L08 adapter is invalid ({errors[0]})")
    return value


def build_report(inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    docs = inputs["documents"]; ledger = docs["ledger"]
    if any(docs[name].get("run_id", inputs["run_id"]) != inputs["run_id"] for name in INPUT_NAMES):
        raise Blocked(f"{JOB}: mixed run identity")
    if (ledger.get("source_generation") != inputs["source_generation"] or
            ledger.get("component_generation") != inputs["component_generation"] or
            ledger.get("head_hash") != inputs["ledger_head_sha256"]):
        raise Blocked(f"{JOB}: ledger generation or head differs from input manifest")
    latest = _latest_ledger(ledger)
    verification, scoring = docs["verification"], docs["scoring"]
    for value in (verification, scoring):
        if (value.get("ledger_head_id") != inputs["lifecycle_origin_head_id"] or
                value.get("ledger_head_sha256") != inputs["lifecycle_origin_head_sha256"]):
            raise Blocked(f"{JOB}: L08 artifact is stale relative to the lifecycle-origin ledger")
    adapter = l08_adapter(inputs["run_id"], verification, scoring)
    l08 = {item["claim_id"]:item for item in adapter["records"]}
    if not set(l08) <= set(latest):
        raise Blocked(f"{JOB}: L08 claim population differs from the ledger")
    admitted_routes = {entry["route_id"] for entry in latest.values()}
    upstream_routes = {item["threat_id"] for item in docs["threat"].get("stride_hypotheses", [])}
    upstream_routes |= {item["route_id"] for item in docs["owasp_routes"].get("routes", [])}
    if not upstream_routes <= admitted_routes:
        raise Blocked(f"{JOB}: an upstream candidate route is absent from the accepted ledger")
    allowed_citations = {_citation_key(ref) for ref in inputs["evidence_bindings"]}
    allowed_citations |= {(ref["job_id"], ref["attempt_id"], ref["artifact_path"], ref["artifact_sha256"])
                          for ref in inputs["bindings"].values()}
    findings, unresolved, trace_rows = [], [], []
    for claim_id in sorted(latest):
        entry = latest[claim_id]
        if (entry["source_generation"] != inputs["source_generation"] or
                entry["component_generation"] != inputs["component_generation"]):
            raise Blocked(f"{JOB}: mixed claim generation")
        for citation in entry["citations"]:
            if _citation_key(citation) not in allowed_citations:
                raise Blocked(f"{JOB}: claim citation does not resolve to a hash-verified input artifact")
            trace_rows.append({"claim_id": claim_id, **citation})
        l08_row = l08.get(claim_id)
        if l08_row is not None:
            for citation in l08_row.get("verification_citations", []):
                if _citation_key(citation) not in allowed_citations:
                    raise Blocked(f"{JOB}: verification citation does not resolve to a hash-verified input artifact")
                trace_rows.append({"claim_id": claim_id, **citation})
        is_verified = entry["status"] == "verified" and l08_row is not None and l08_row["verification_status"] == "VERIFIED"
        if is_verified:
            for field in ("route_id", "hypothesis", "confidence", "component_ids", "source_generation", "component_generation"):
                if l08_row.get(field) != entry.get(field):
                    raise Blocked(f"{JOB}: independently verified claim semantics differ from ledger")
            findings.append({"claim_id": claim_id, "title": entry["hypothesis"],
                "component_ids": entry["component_ids"], "confidence": entry["confidence"],
                "severity": l08_row["severity"], "priority": l08_row["priority"], "score": l08_row["score"],
                "dissent_ids": entry["dissent_ids"], "citations": entry["citations"],
                "verification_citations": l08_row["verification_citations"],
                **{key: l08_row[key] for key in JUDGMENT_FIELDS if key in l08_row}})
        else:
            unresolved.append({"claim_id": claim_id, "status": entry["status"],
                "hypothesis": entry["hypothesis"], "component_ids": entry["component_ids"],
                "proof_obligations": entry["proof_obligations"], "dissent_ids": entry["dissent_ids"]})
    matrix = docs["owasp"]
    report = {"schema": "appsec-review/synthesis-report/1.0", "status": STATUS,
        "run_id": inputs["run_id"], "source_generation": inputs["source_generation"],
        "component_generation": inputs["component_generation"], "ledger_head_id": inputs["ledger_head_id"],
        "ledger_head_sha256": inputs["ledger_head_sha256"],
        "input_manifest_sha256":inputs["input_manifest_sha256"],"generator_sha256":_generator_sha256(),
        "scope": {"target": docs["component"]["target"],
                  "source_revision": docs["component"].get("source_revision"),
                  "source_snapshot_sha256": docs["component"].get("source_snapshot_sha256", inputs["source_generation"]),
                  "components": [{"component_id": item["component_id"], "name": item["name"],
                                  "purpose": item["observed_purpose"]}
                                 for item in docs["component"]["functional_components"]]},
        "component_relationships": [json.dumps(item, sort_keys=True)
                                    for item in docs["component"].get("component_relationships", [])],
        "threat_model": {key: [json.dumps(item, sort_keys=True) for item in docs["threat"].get(key, [])]
                         for key in THREAT_MODEL_KEYS},
        "owasp_coverage": {"denominators": matrix["denominators"],
                           "applicability_counts": matrix["applicability_counts"],
                           "assessment_counts": matrix["assessment_counts"]},
        "verified_findings": findings, "unresolved_candidates": unresolved,
        "dissent_ids": sorted({item for entry in latest.values() for item in entry["dissent_ids"]} |
            {item["challenge_record_id"] for item in docs["threat"].get("dissent", [])}),
        "limitations": _limitations(docs, inputs["limitations"]),
        "decision": {"recommendation": "HUMAN_DECISION_REQUIRED",
                     "basis": "Draft evidence package requires named human review; no final sign-off is claimed."},
        "claim_limits": {"final": False, "human_signoff": False, "scoring_derived": False,
                         "runtime_claimed": False, "compliance_claimed": False,
                         "remediation_claimed": False}}
    errors = validate_document(report, "synthesis-report.schema.json")
    if errors: raise Blocked(f"{JOB}: report fails its closed schema ({errors[0]})")
    unique_trace = {(row["claim_id"], row["citation_id"], row["producer_job_id"],
                     row["producer_attempt_id"], row["artifact_path"], row["artifact_sha256"]): row
                    for row in trace_rows}
    trace = {"schema": "appsec-review/evidence-trace-index/1.0", "run_id": inputs["run_id"],
             "ledger_head_sha256": inputs["ledger_head_sha256"],
             "upstream": [inputs["bindings"][key] for key in sorted(inputs["bindings"])],
             "citations": [unique_trace[key] for key in sorted(unique_trace)]}
    errors = validate_document(trace, "evidence-trace-index.schema.json")
    if errors: raise Blocked(f"{JOB}: trace index fails its closed schema ({errors[0]})")
    return report, trace


# 03 record families carried into the report (JSON strings, closed schema). data_classes,
# privacy_threats and deployment_zones are the ADR-0019 workbench/L13 families.
THREAT_MODEL_KEYS = ("elements", "flows", "trust_boundaries", "data_classes", "deployment_zones",
                     "abuse_scenarios", "privacy_threats", "attack_trees", "stride_hypotheses",
                     "assumptions", "gaps")


TOOL_LEAD_PREFIX = "Tool lead ("  # claim_ledger.LEAD_HYPOTHESIS_PREFIX (deterministic, not model text)
HUNTER_PREFIX = "Code-reading hypothesis ("  # claim_ledger.HUNTER_HYPOTHESIS_PREFIX (deterministic prefix)


def tool_lead_candidates(unresolved: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Unverified ledger claims admitted from static-tool leads or code-reading hunters, P1 first
    (visibility, not promotion). ``source`` is ``tool-lead`` or ``hunter``."""
    rows = []
    for item in unresolved:
        text = item["hypothesis"]
        for prefix, source in ((TOOL_LEAD_PREFIX, "tool-lead"), (HUNTER_PREFIX, "hunter")):
            if text.startswith(prefix) and text[len(prefix):len(prefix) + 2] in {"P1", "P2", "P3"}:
                rows.append({**item, "tier": text[len(prefix):len(prefix) + 2], "source": source})
    return sorted(rows, key=lambda row: (row["tier"], row["source"] != "tool-lead", row["claim_id"]))


def render_markdown(report: dict[str, Any]) -> tuple[str, str]:
    findings = report["verified_findings"]
    ship_posture = [item for item in findings if item["severity"] in {"CRITICAL","HIGH"}]
    lines = ["# Evidence-backed security review draft", "", f"Status: `{STATUS}`", "",
        "This draft is decision support, not a final report or human sign-off.", "", "## Decision posture", "",
        report["decision"]["recommendation"] + ": " + report["decision"]["basis"], "",
        "## Coverage", "", "| Selected | Applicable | Assessed | Satisfied |", "|---:|---:|---:|---:|",
        "| {selected} | {applicable} | {assessed} | {satisfied} |".format(**report["owasp_coverage"]["denominators"]), "",
        "## High/Critical verified findings for ship decision", ""]
    if ship_posture:
        lines += ["| Claim | Severity | Priority | Components |", "|---|---|---|---|"]
        lines += [f"| {item['claim_id']} | {item['severity']} | {item['priority']} | {', '.join(item['component_ids'])} |"
                  for item in ship_posture]
    else: lines.append("No High/Critical claim satisfied the independent-verification and scoring join.")
    lower = len(findings) - len(ship_posture)
    lines += ["", f"{lower} verified Medium/Low finding(s) remain in `report.json` for technical review."]
    tool_leads = tool_lead_candidates(report["unresolved_candidates"])
    lines += ["", "## Unresolved decision items", "",
              f"{len(report['unresolved_candidates'])} candidate(s) remain unresolved or unverified.", ""]
    if tool_leads:
        tiers = {tier: sum(item["tier"] == tier for item in tool_leads) for tier in ("P1", "P2", "P3")}
        hunted = sum(item["source"] == "hunter" for item in tool_leads)
        what = "static-tool leads" + (f" or code-reading hypotheses ({hunted} from hunters)" if hunted else "")
        lines += [f"{len(tool_leads)} of them are {what} not independently verified "
                  f"(P1 {tiers['P1']}, P2 {tiers['P2']}, P3 {tiers['P3']}); see the appendix.", ""]
    workbench = {key: [json.loads(item) for item in report.get("threat_model", {}).get(key, [])]
                 for key in ("data_classes", "privacy_threats", "deployment_zones", "attack_trees")}
    lines += ["## Threat model workbench", "",
              "Candidate records from `03-threat-model-dfd-stride` (hypotheses for review, not findings): "
              + ", ".join(f"{len(rows)} {key.replace('_', ' ')}" for key, rows in workbench.items()) + ".", ""]
    if workbench["privacy_threats"]:
        categories = sorted({item["linddun_category"] for item in workbench["privacy_threats"]})
        lines += ["LINDDUN categories raised: " + ", ".join(categories) + ".", ""]
    lines += ["## Major limitations", ""]
    lines += [f"- {value}" for value in report["limitations"]] or ["- No additional limitation was supplied."]
    appendix = ["# Coverage and unresolved appendix", "", f"Status: `{STATUS}`", "",
        "## OWASP denominators", "", json.dumps(report["owasp_coverage"], sort_keys=True, indent=2), "",
        "## Unresolved candidates", ""]
    appendix += [f"- `{item['claim_id']}` ({item['status']}): {item['hypothesis']}" for item in report["unresolved_candidates"]]
    if tool_leads:
        appendix += ["", "## Tool leads and code-reading hypotheses not independently verified", "",
                     "| Tier | Source | Claim | Status | Lead |", "|---|---|---|---|---|"]
        appendix += [f"| {item['tier']} | {item['source']} | `{item['claim_id']}` | {item['status']} | "
                     f"{item['hypothesis'].replace('|', '/')} |" for item in tool_leads]
    if any(workbench.values()):
        appendix += ["", "## Threat model workbench records", "", "| Family | Id | Kind |", "|---|---|---|"]
        appendix += [f"| data class | `{item['data_class_id']}` | {item['category']} / {item['sensitivity']} |"
                     for item in workbench["data_classes"]]
        appendix += [f"| privacy threat | `{item['privacy_threat_id']}` | {item['linddun_category']} |"
                     for item in workbench["privacy_threats"]]
        appendix += [f"| deployment zone | `{item['zone_id']}` | {item['kind']} ({item['exposure_label']}) |"
                     for item in workbench["deployment_zones"]]
        appendix += [f"| attack tree | `{item['tree_id']}` | {len(item.get('nodes', []))} nodes |"
                     for item in workbench["attack_trees"]]
    appendix += ["", "## Dissent", ""] + ([f"- {item}" for item in report["dissent_ids"]] or ["- None recorded."])
    appendix += ["", "## Limitations", ""] + [f"- {item}" for item in report["limitations"]]
    for text in ("\n".join(lines) + "\n", "\n".join(appendix) + "\n"):
        if any(pattern.search(text) for pattern in PROHIBITED_TEXT):
            raise Blocked(f"{JOB}: rendered report contains a prohibited promotion")
    return "\n".join(lines) + "\n", "\n".join(appendix) + "\n"


def run(run_root: Path, input_manifest: Path, output_root: Path) -> dict[str, Any]:
    inputs = load_inputs(run_root, input_manifest); report, trace = build_report(inputs)
    output_root.mkdir(parents=True, exist_ok=True)
    atomic_json(output_root / REPORT_JSON, report); atomic_json(output_root / TRACE, trace)
    report_md, appendix = render_markdown(report)
    atomic_bytes(output_root / REPORT_MD, report_md.encode()); atomic_bytes(output_root / APPENDIX, appendix.encode())
    artifacts = [{"path": name, "sha256": "sha256:" + file_hash(output_root / name)}
                 for name in (REPORT_JSON, REPORT_MD, APPENDIX, TRACE)]
    publication = {"schema": "appsec-review/report-publication-manifest/1.0", "run_id": inputs["run_id"],
        "status": STATUS, "ledger_head_sha256": inputs["ledger_head_sha256"],
        "input_manifest_sha256":inputs["input_manifest_sha256"],"generator_sha256":_generator_sha256(),
        "artifacts": artifacts,
        "final": False, "human_signoff": False}
    errors = validate_document(publication, "report-publication-manifest.schema.json")
    if errors: raise Blocked(f"{JOB}: publication manifest fails its closed schema ({errors[0]})")
    atomic_json(output_root / PUBLICATION, publication)
    atomic_json(output_root / "permission.json", {"schema":"appsec-review/producer-permission-receipt/1.0",
        "run_id":inputs["run_id"],"job_id":JOB,"source_snapshot_sha256":inputs["source_generation"],
        "permissions":PERMISSIONS})
    atomic_json(output_root / "lineage.json", {"schema":"appsec-review/producer-lineage-receipt/1.0",
        "run_id":inputs["run_id"],"job_id":JOB,"source_snapshot_sha256":inputs["source_generation"],
        "build_lineage_sha256":_sha({key:inputs["bindings"][key] for key in sorted(inputs["bindings"])})})
    atomic_json(output_root / "status.json", {"process":JOB,"status":STATUS,
        "verified_findings":len(report["verified_findings"]),
        "unresolved_candidates":len(report["unresolved_candidates"]),
        "limitations":len(report["limitations"]),"final":False})
    return publication


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-root", type=Path, required=True); parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True); args = parser.parse_args()
    print(json.dumps(run(args.run_root, args.input, args.output), indent=2))
