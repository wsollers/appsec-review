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
import bounded_analysis_workers
import registry_paths

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
    r"\b(?:is|are)\s+(?:compliant|certified)\b(?!-)", r"\b(?:is|has been)\s+(?:fixed|remediated)\b(?!-)"))
CODE_FILES = (
    "claim_ledger.py", "threat_model_core.py", "publish_job_output.py", "validate_job_output.py",
    registry_paths.template_rel("claim-ledger-routing"), "personas/roles/claim-ledger-custodian/role.json",
    registry_paths.rel(registry_paths.DOMAINS, "claim-ledger-lifecycle"), registry_paths.rel(registry_paths.TOOLING_PROFILES, "hash-linked-claim-ledger"),
    registry_paths.contract_rel("claim-ledger-core"), "claim-ledger-routing/task-claim-ledger-core.md",
)


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _code_hashes() -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    for name in ("claim-ledger-citation.schema.json", "claim-ledger-entry.schema.json",
                 "claim-decision-ledger.schema.json", "claim-ledger-work-routing.schema.json",
                 HUNTER_SCHEMA):
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
    candidates.extend(workbench_candidates(source, elements, dissent))
    return candidates


def workbench_candidates(source: dict[str, Any], elements: dict[str, Any],
                         dissent: dict[str, Any]) -> list[dict[str, Any]]:
    """ADR-0019: threat-workbench abuse scenarios and LINDDUN privacy threats are ledger candidates
    like STRIDE hypotheses. Attack trees are not (ADR-0016 chain composition reads them from the
    model by their stable ids); a record that names no modeled component cannot be routed and is
    left to the model's own gaps."""
    value = source["artifact"]
    flows = {item["flow_id"]: item for item in value["flows"]}
    rows = []
    for item in value.get("abuse_scenarios", []):
        obligations = ([f"Establish from source whether this precondition holds: {text}" for text in item["preconditions"]] +
                       [f"Determine whether this control is present: {text}" for text in item["missing_controls"]]) or [
                       f"Determine from source whether {item['actor']} can reach this objective."]
        rows.append((item["scenario_id"], f"{item['actor']} could {item['attacker_objective']}: {item['harm']}",
                     item["target_element_ids"], item, obligations))
    for item in value.get("privacy_threats", []):
        targets = set(item["target_element_ids"]) | {endpoint for flow_id in item["target_flow_ids"]
            for endpoint in (flows[flow_id]["source_element_id"], flows[flow_id]["destination_element_id"])}
        rows.append((item["privacy_threat_id"], f"Privacy ({item['linddun_category'].replace('_', ' ')}): {item['statement']}",
                     sorted(targets), item, item["proof_obligations"]))
    candidates = []
    for route_id, hypothesis, targets, item, statements in sorted(rows, key=lambda row: row[0]):
        component_ids = sorted({elements[key]["component_id"] for key in targets
                                if key in elements and elements[key]["component_id"]})
        if not component_ids:
            continue
        candidates.append({"route_id": route_id, "hypothesis": hypothesis, "confidence": item["confidence"],
            "component_ids": component_ids,
            "citations": [_citation(source, citation, "citation-" + digest(citation)[:24]) for citation in item["citations"]],
            "proof_obligations": [{"obligation_id": "obligation-" + digest({"route": route_id, "text": text})[:24],
                                   "statement": text} for text in statements],
            "dissent_ids": sorted({dissent[route_id]["challenge_record_id"]} if route_id in dissent else set()),
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


# --- Tool leads: the third candidate source (every accepted static-tool lead is a candidate) -------
# (job_id, output contract, attempt-relative artifact, schema). A producer whose accepted pointer is
# absent or SKIPPED contributes no candidates and is recorded as lead coverage, never a failure.
LEAD_PRODUCERS = (
    ("02-source-sast", "source-sast", "source-sast.json", "source-sast.schema.json"),
    # ADR-0023: one producer row per CodeQL language node (replaces 02-codeql-sast).
    *((f"02-codeql-{language}", "codeql-language", "codeql-language.json", "codeql-language.schema.json")
      for language in ("cpp", "csharp", "go", "java", "javascript", "python", "ruby", "rust")),
    ("02-native-sast", "native-sast", "native-sast.json", "native-sast.schema.json"),
    ("02-secrets-inventory", "secrets-inventory", "outputs/secrets-inventory.redacted.json",
     "secrets-inventory.schema.json"),
    ("02-sca-vulnerability-match", "sca-vulnerability-match", "outputs/sca-vulnerability-match.json",
     "sca-vulnerability-match.schema.json"),
    ("02-iac-config-scan", "iac-config-evidence", "outputs/iac-config-evidence.json",
     "iac-config-evidence.schema.json"),
    ("02-mobile-sast", "mobile-sast", "outputs/mobile-sast.json", "mobile-sast.schema.json"),
)
LEAD_CONTRACTS = frozenset(row[1] for row in LEAD_PRODUCERS)
CODEQL_PRODUCERS = frozenset(row[0] for row in LEAD_PRODUCERS if row[1] == "codeql-language")
LEAD_ORDER = {row[0]: index for index, row in enumerate(LEAD_PRODUCERS)}
LEAD_ROUTE_PREFIX = "tool-lead:"
LEAD_HYPOTHESIS_PREFIX = "Tool lead ("
TIERS = ("P1", "P2", "P3")
# P1: security-relevant sink/weakness categories. P3: code-quality/style checks (kept, ordered last).
# Everything unlisted is P2: reviewable, but not a named security sink.
P1_CATEGORIES = frozenset({"codeql-security-query", "unsafe-input", "memory-lifetime",
    "sensitive-memory-clear", "resource-exhaustion", "unsafe-copy", "memory-copy", "command-execution", "buffer-safety",
    "null-dereference", "undefined-behavior", "format-string", "injection", "sql-injection",
    "path-traversal", "deserialization", "weak-crypto", "insecure-random", "api-misuse",
    "network-exposure", "public-access-grant", "access-control", "encryption-at-rest",
    "encryption-in-transit", "privilege-escalation", "workload-isolation", "embedded-credential-material",
    "improper-credential-usage", "insecure-authentication-authorization", "insufficient-input-output-validation",
    "insecure-communication", "insecure-data-storage", "insufficient-cryptography", "inadequate-privacy-controls",
    "security-misconfiguration"})
P1_TOOLS = frozenset({"gosec"})
P1_RULE_PREFIXES = ("security.", "unix.", "core.", "cplusplus.", "alpha.security.", "cert-", "bugprone-",
                    "clang-analyzer-security.", "clang-analyzer-core.", "clang-analyzer-unix.")
P2_RULES = frozenset({"security.insecureAPI.DeprecatedOrUnsafeBufferHandling", "noCopyConstructor",
                      "noOperatorEq", "PossiblyInvalidOperand", "PossiblyInvalidArgument",
                      "PossiblyInvalidCast", "UnresolvableInclude"})
P3_RULES = frozenset({"variableScope", "constVariablePointer", "constParameterPointer", "constVariable",
    "constParameter", "constParameterReference", "funcArgNamesDifferent", "funcArgNamesDifferentUnnamed",
    "unreadVariable", "unusedVariable", "unusedFunction", "knownConditionTrueFalse",
    "preprocessorErrorDirective", "missingInclude", "missingIncludeSystem", "passedByValue",
    "useStlAlgorithm", "shadowVariable", "shadowFunction", "cstyleCast", "MissingPropertyType",
    "unmatchedSuppression", "checkersReport", "normalCheckLevelMaxBranches"})
P3_RULE_PREFIXES = ("PSR1.", "PSR2.", "PSR12.", "Generic.", "Squiz.", "PEAR.", "readability-", "modernize-",
                    "cppcoreguidelines-", "llvm-", "google-", "hicpp-", "performance-", "deadcode.", "style")
P3_CATEGORIES = frozenset({"maintainability", "portability", "style"})


def lead_tier(lead: dict[str, Any]) -> str:
    """Deterministic review priority from a lead's kind, tool, rule and category (no model)."""
    kind, rule, category = lead["kind"], lead["rule_id"], lead["category"]
    if kind in {"secret", "dependency"}:
        return "P1"
    if kind == "config":
        return "P1" if category in P1_CATEGORIES or lead.get("exposure") else "P2"
    if rule in P3_RULES or rule.startswith(P3_RULE_PREFIXES) or category in P3_CATEGORIES:
        return "P3"
    if rule in P2_RULES:
        return "P2"
    if (lead["tool_id"] in P1_TOOLS or rule.startswith(P1_RULE_PREFIXES) or category in P1_CATEGORIES):
        return "P1"
    return "P2"


def _clean(value: Any, limit: int = 160) -> str:
    return " ".join(str(value).split())[:limit]


def normalize_leads(job_id: str, document: dict[str, Any]) -> list[dict[str, Any]]:
    """Project one accepted tool artifact onto the closed lead shape the ledger consumes."""
    rows: list[dict[str, Any]] = []
    def code(item: dict[str, Any], **extra: Any) -> dict[str, Any]:
        return {"kind": "code", "lead_ref": item["lead_id"], "tool_id": item["tool_id"],
            "rule_id": _clean(item["rule_id"]), "category": item["category"], "path": item["path"],
            "start_line": item["start_line"], "end_line": item.get("end_line", item["start_line"]),
            "source_sha256": item.get("source_sha256"), **extra}
    if job_id == "02-source-sast" or job_id in CODEQL_PRODUCERS:
        rows = [code(item, **({k: item[k] for k in ("language", "rule_name", "cwe") if k in item}
                             if job_id in CODEQL_PRODUCERS else {}))
                for item in document.get("leads", [])]
    elif job_id == "02-native-sast":
        rows = [code(item, unit_id=item.get("unit_id"), start_column=item.get("start_column"))
                for unit in document.get("units", []) for item in unit.get("leads", [])]
    elif job_id == "02-secrets-inventory":
        rows = [{"kind": "secret", "lead_ref": item["entry_id"], "tool_id": item["tool_id"],
                 "rule_id": item["rule_id"], "category": item["data_class"],
                 "path": item["location"]["path"], "start_line": item["location"]["start_line"],
                 "end_line": item["location"]["end_line"], "source_sha256": None,
                 "assertion": item["assertion"]} for item in document.get("entries", [])]
    elif job_id == "02-sca-vulnerability-match":
        rows = [{"kind": "dependency", "lead_ref": item["match_id"], "tool_id": item["tool_id"],
                 "rule_id": item["advisory_id"], "category": "known-advisory-match", "path": None,
                 "start_line": None, "end_line": None, "source_sha256": None,
                 "component_ref": item["component_ref"], "aliases": sorted(item.get("aliases", []))}
                for item in document.get("matches", [])]
    elif job_id == "02-iac-config-scan":
        rows = [{"kind": "config", "lead_ref": item["hit_id"], "tool_id": item["tool_id"],
                 "rule_id": item["rule"]["rule_id"], "category": item["category"],
                 "path": item["location"]["path"], "start_line": item["location"]["start_line"],
                 "end_line": item["location"]["end_line"], "source_sha256": None,
                 "exposure": item.get("exposure")} for item in document.get("rule_hits", [])]
    elif job_id == "02-mobile-sast":
        rows = [{"kind": "code", "lead_ref": item["hit_id"], "tool_id": item["tool_id"],
                 "rule_id": item["rule_id"], "category": item["category"], "path": item["file_path"],
                 "start_line": item["line"], "end_line": item["line"], "source_sha256": item["file_sha256"]}
                for item in document.get("rule_hits", [])]
    else:
        raise Blocked(f"{JOB}: unsupported tool-lead producer {job_id}")
    _reject_promotions(rows)
    return sorted(rows, key=lambda row: (str(row["path"]), row["start_line"] or 0, row["tool_id"],
                                         row["rule_id"], row["lead_ref"]))


def _glob_regex(pattern: str) -> re.Pattern[str]:
    out, index = [], 0
    while index < len(pattern):
        if pattern.startswith("**", index):
            out.append(".*"); index += 2
        elif pattern[index] == "*":
            out.append("[^/]*"); index += 1
        elif pattern[index] == "?":
            out.append("[^/]"); index += 1
        else:
            out.append(re.escape(pattern[index])); index += 1
    return re.compile("".join(out) + r"\Z")


def lead_components(component_map: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(({"component_id": item["component_id"],
                    "path_patterns": sorted(item.get("path_patterns", [])),
                    "aliases": sorted(item.get("aliases", []))}
                   for item in component_map.get("functional_components", [])),
                  key=lambda row: row["component_id"])


def _components_for(path: str | None, components: list[dict[str, Any]]) -> list[str]:
    if not path:
        return ["component-unmapped"]
    matched = {row["component_id"] for row in components
               if any(_glob_regex(pattern).match(path) for pattern in row["path_patterns"])}
    if not matched:
        matched = {row["component_id"] for row in components
                   if any(path == alias or path.startswith(alias.rstrip("/") + "/") for alias in row["aliases"])}
    return sorted(matched) or ["component-unmapped"]


def _lead_location(lead: dict[str, Any]) -> tuple[str, int | None]:
    if lead["kind"] == "dependency":
        return "sbom-component:" + lead["component_ref"], None
    if lead["path"] is None:
        return "withheld-path:" + lead["lead_ref"], None
    return lead["path"], lead["start_line"]


def _lead_citation(source: dict[str, Any], lead: dict[str, Any]) -> dict[str, Any]:
    locator = {key: lead[key] for key in ("lead_ref", "tool_id", "rule_id", "category", "path", "start_line",
               "end_line", "start_column", "unit_id", "source_sha256", "component_ref", "aliases", "exposure")
               if lead.get(key) is not None}
    where = (f"{lead['path']}:{lead['start_line']}" if lead["path"] and lead["start_line"] else
             lead["path"] or _lead_location(lead)[0])
    fact = f"{lead['tool_id']} rule {lead['rule_id']} ({lead['category']}) flagged {where}"
    identity = {"job": source["producer_job_id"], "attempt": source["producer_attempt_id"], "lead": locator}
    return _citation(source, {"artifact_path": source["lead_artifact"], "artifact_sha256": source["artifact_sha256"],
        "locator": locator, "observed_fact": fact}, "citation-" + digest(identity)[:24])


OBLIGATIONS = {
    "code": ("Show the flagged construct at {where} is present in the reviewed source revision.",
             "Show attacker-influenced data or an untrusted caller can reach the flagged construct.",
             "Show the construct violates a security property in its calling context, not only a coding rule."),
    "config": ("Show the flagged declaration at {where} is deployed or built by an in-scope path.",
               "Show the declaration weakens an in-scope security control or exposure boundary."),
    "secret": ("Show the location {where} holds credential or key material rather than a placeholder or test fixture.",
               "Show the material grants access to an in-scope asset or trust boundary."),
    "dependency": ("Show {where} is shipped or linked by an in-scope component at the matched version.",
                   "Show the advisory's affected code path is reachable from the component's use."),
}


def _lead_menu(sources: list[dict[str, Any]]) -> dict[tuple, list[tuple[dict[str, Any], dict[str, Any]]]]:
    """(tier, where, line) -> members: leads merged per location, P3-only locations grouped per file."""
    groups: dict[tuple[str, int | None], list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    for source in sorted(sources, key=lambda row: LEAD_ORDER.get(row["producer_job_id"], len(LEAD_ORDER))):
        for lead in source["leads"]:
            groups.setdefault(_lead_location(lead), []).append((source, lead))
    menu: dict[tuple, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    for (where, line), members in groups.items():
        tier = min((lead_tier(lead) for _source, lead in members), key=TIERS.index)
        key = ("P3", where, None) if tier == "P3" else (tier, where, line)
        menu.setdefault(key, []).extend(members)
    return menu


def lead_locations(sources: dict[str, Any] | Iterable[dict[str, Any]]) -> dict[tuple[str, int], str]:
    """(path, line) -> tier of every P1/P2 tool-lead claim location (the hunter attach targets)."""
    sources = [sources] if isinstance(sources, dict) else list(sources)
    return {(where, line): tier for (tier, where, line) in _lead_menu(sources) if tier != "P3" and line}


REACHABILITY_JOB = "06-cve-reachability"
REACHABILITY_SUMMARY = "outputs/dependency-reachability-summary.json"


def reachability_verdicts(run_id: str) -> dict[str, Any] | None:
    """ADR-0023: the accepted 06 correlated verdict per SCA match (hash-verified), or None when absent."""
    pointer = data_path(run_id, "jobs", REACHABILITY_JOB, "accepted.json")
    if not pointer.is_file():
        return None
    summary, binding = bounded_analysis_workers.load_accepted(pointer, run_id=run_id, job_id=REACHABILITY_JOB,
        contract="cve-reachability", artifact=REACHABILITY_SUMMARY, schema="dependency-reachability-summary.schema.json")
    return {"attempt_id": binding["attempt_id"], "artifact_sha256": binding["artifact_sha256"],
            "matches": {row["match_id"]: {"verdict": row["verdict"], "tier": row["tier"],
                                          "deciding_engines": row["deciding_engines"]} for row in summary["matches"]}}


def _reachability_note(members: list[tuple[dict[str, Any], dict[str, Any]]],
                       reachability: dict[str, Any] | None) -> tuple[str, list[str], bool]:
    """(hypothesis suffix, extra obligations, reachable) for the dependency leads of one claim."""
    if not reachability:
        return "", [], False
    rows = {lead["lead_ref"]: reachability["matches"].get(lead["lead_ref"])
            for _source, lead in members if lead["kind"] == "dependency"}
    reachable = sorted(ref for ref, row in rows.items() if row and row["verdict"] == "reachable")
    conflict = sorted(ref for ref, row in rows.items() if row and row["verdict"] == "conflict")
    text, obligations = "", []
    if reachable:
        text += (f" Dependency reachability (06-cve-reachability): reachable for {', '.join(reachable)} "
                 f"[{', '.join(sorted({str(rows[ref]['tier']) for ref in reachable}))}]; a P1 review claim.")
    if conflict:
        text += (f" Reachability CONFLICT for {', '.join(conflict)}: the engines disagree; flagged for review "
                 "(never resolved silently).")
        obligations.append(f"Resolve the conflicting reachability engine verdicts for {', '.join(conflict)} "
                           f"({REACHABILITY_SUMMARY}) before scoring.")
    return text, obligations, bool(reachable)


def lead_candidates(sources: dict[str, Any] | Iterable[dict[str, Any]],
                    components: list[dict[str, Any]] | None = None,
                    corroboration: dict[tuple[str, int], list[dict[str, Any]]] | None = None,
                    reachability: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Admit every accepted tool lead as a candidate claim (no model; deterministic text and ids).

    Leads at the same (path, start_line) are merged across tools into one claim listing every tool
    and rule. A location whose best tier is P3 (code quality) is grouped per file into one claim so
    reviewers get a manageable menu; nothing is ever dropped. ``corroboration`` maps a P1/P2 lead
    location to code-reading hunter hypotheses at that line (see :func:`hunter_candidates`): their
    citations are attached to the lead claim instead of admitting a duplicate claim.
    """
    sources = [sources] if isinstance(sources, dict) else list(sources)
    components = components or []
    corroboration = corroboration or {}
    candidates = []
    for (tier, where, line), members in _lead_menu(sources).items():
        primary = members[0][0]
        lines = sorted({lead["start_line"] for _source, lead in members if lead["start_line"]})
        location = (f"{where}:{line}" if line else
                    (f"{where} lines {', '.join(map(str, lines))}" if lines else where))
        kinds = sorted({lead["kind"] for _source, lead in members})
        tools = sorted({lead["tool_id"] for _source, lead in members})
        rules = sorted({f"{lead['tool_id']} {lead['rule_id']}" for _source, lead in members})
        categories = sorted({lead["category"] for _source, lead in members})
        route_id = LEAD_ROUTE_PREFIX + tier + ":" + digest({"where": where, "line": line, "tier": tier})[:20]
        shown = rules if len(rules) <= 8 else rules[:8] + [f"and {len(rules) - 8} more"]
        hypothesis = (f"{LEAD_HYPOTHESIS_PREFIX}{tier}, {', '.join(categories)}): {len(members)} static "
            f"analysis lead(s) from {len(tools)} tool(s) at {location} [{'; '.join(shown)}]. Candidate: the "
            "flagged code or configuration is reachable from an attacker-influenced input or trust boundary "
            "and weakens a security property; unreviewed until adversarial review and independent verification.")
        note, extra_obligations, reachable = _reachability_note(members, reachability)
        hypothesis += note
        hunted = corroboration.get((where, line), []) if tier != "P3" and line else []
        if hunted:
            classes = sorted({item["label"] for item in hunted})
            hypothesis += (f" Corroborated by {len(hunted)} code-reading hypothesis(es) "
                           f"[{'; '.join(classes[:6])}].")
        citations, seen = [], set()
        for source, lead in members:
            citation = _lead_citation(source, lead)
            if citation["citation_id"] not in seen:
                seen.add(citation["citation_id"]); citations.append(citation)
        for item in hunted:
            if item["citation"]["citation_id"] not in seen:
                seen.add(item["citation"]["citation_id"]); citations.append(item["citation"])
        statements = [text.format(where=location) for kind in kinds for text in OBLIGATIONS[kind]] + extra_obligations
        obligations = [{"obligation_id": "obligation-" + digest({"route": route_id, "text": text})[:24],
                        "statement": text} for text in statements]
        paths = {lead["path"] for _source, lead in members}
        component_ids = sorted({cid for path in paths for cid in _components_for(path, components)})
        candidates.append({"route_id": route_id, "hypothesis": hypothesis,
            "confidence": "medium" if len(tools) > 1 or hunted or reachable else "low", "component_ids": component_ids,
            "citations": citations, "proof_obligations": obligations, "dissent_ids": [],
            "causal_route_ids": [], "source": primary,
            "order": (1, TIERS.index(tier), where, line or 0)})
    _reject_promotions([{key: value for key, value in item.items() if key != "source"} for item in candidates])
    return sorted(candidates, key=lambda item: item["order"])


# --- Code-reading hunter hypotheses: the fourth candidate source (07-hypothesis-discovery) ----------
HUNTER_JOB = "07-hypothesis-discovery"
HUNTER_CONTRACT = "hypothesis-discovery"
HUNTER_ARTIFACT = "hypothesis-discovery.json"
HUNTER_SCHEMA = "hypothesis-discovery.schema.json"
HUNTER_ROUTE_PREFIX = "hunter:"
HUNTER_HYPOTHESIS_PREFIX = "Code-reading hypothesis ("
HUNTER_OBLIGATIONS = (
    "Show the construct at {where} is present in the reviewed source revision and behaves as described.",
    "Show an attacker meeting the stated preconditions can reach {where}.",
    "Show the behavior at {where} violates a security property ({label}) in its calling context.")


def _hunter_label(row: dict[str, Any]) -> str:
    return _clean((row["cwe"] + " " if row["cwe"] else "") + row["vulnerability_class"], 120)


def _hunter_citation(source: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    locator = {"hypothesis_id": row["hypothesis_id"], "path": row["path"], "start_line": row["start_line"],
               "end_line": row["end_line"], "file_sha256": row["file_sha256"], "tier": row["tier"],
               "hunters": sorted({hunter["persona_id"] for hunter in row["hunters"]})}
    where = f"{row['path']}:{row['start_line']}" + (f"-{row['end_line']}" if row["end_line"] != row["start_line"] else "")
    fact = (f"code-reading hunter(s) {', '.join(locator['hunters'])} proposed {_hunter_label(row)} at {where} "
            f"({row['confidence']} confidence)")
    if any(pattern.search(fact) for pattern in PROHIBITED_TEXT):   # model words stay in the artifact
        fact = f"code-reading hunter(s) {', '.join(locator['hunters'])} proposed a hypothesis at {where}"
    identity = {"job": source["producer_job_id"], "attempt": source["producer_attempt_id"], "hypothesis": locator}
    # Attempt-relative artifact path, like tool-lead citations: report assembly re-verifies the bytes
    # under data/jobs/<producer>/attempts/<attempt>/<artifact_path>.
    return _citation(source, {"artifact_path": HUNTER_ARTIFACT, "artifact_sha256": source["artifact_sha256"],
        "locator": locator, "observed_fact": fact}, "citation-" + digest(identity)[:24])


def hunter_candidates(source: dict[str, Any], locations: dict[tuple[str, int], str] | None = None,
                      components: list[dict[str, Any]] | None = None
                      ) -> tuple[list[dict[str, Any]], dict[tuple[str, int], list[dict[str, Any]]]]:
    """Hunter hypotheses as (standalone candidates, corroboration of P1/P2 tool-lead locations).

    A hypothesis whose line range covers a P1/P2 tool-lead location (same path) is attached to that
    lead claim as corroboration (its citation and class), not admitted twice. Everything else is a
    ``hunter:`` candidate ordered with the tool leads by tier. Text is deterministic; the only
    model words are the class and a clipped mechanism, and those are dropped from the text (never
    the claim) if they would trip the ledger's promotion guard.
    """
    value = source["artifact"]
    if validate_document(value, HUNTER_SCHEMA):
        raise Blocked(f"{JOB}: invalid hunter source")
    locations = locations or {}
    candidates, corroboration = [], {}
    for row in value["hypotheses"]:
        citation = _hunter_citation(source, row)
        label = _hunter_label(row)
        if any(pattern.search(label) for pattern in PROHIBITED_TEXT):
            label = "code-reading"
        hits = sorted((path, line) for (path, line) in locations
                      if path == row["path"] and row["start_line"] <= line <= row["end_line"])
        if hits:
            for key in hits:
                corroboration.setdefault(key, []).append({"citation": citation, "label": label,
                                                          "hypothesis_id": row["hypothesis_id"]})
            continue
        where = f"{row['path']}:{row['start_line']}" + (f"-{row['end_line']}" if row["end_line"] != row["start_line"] else "")
        modes = sorted({hunter["mode"] for hunter in row["hunters"]})
        route_id = HUNTER_ROUTE_PREFIX + row["tier"] + ":" + digest({"hypothesis": row["hypothesis_id"]})[:20]
        head = (f"{HUNTER_HYPOTHESIS_PREFIX}{row['tier']}, {label}): proposed by {len(row['hunters'])} "
                f"code-reading hunter(s) [{', '.join(modes)}] at {where}.")
        tail = (" Candidate: attacker-influenced input reaches the construct and weakens a security property; "
                "unreviewed until adversarial review and independent verification.")
        body = f" Mechanism: {_clean(row['mechanism'], 400)} Preconditions: {_clean('; '.join(row['attacker_preconditions']), 300)}."
        hypothesis = head + body + tail
        if any(pattern.search(hypothesis) for pattern in PROHIBITED_TEXT):
            hypothesis = head + tail   # the model's mechanism stays in the hunter artifact
        obligations = [{"obligation_id": "obligation-" + digest({"route": route_id, "text": text})[:24],
                        "statement": text} for text in (template.format(where=where, label=label)
                                                          for template in HUNTER_OBLIGATIONS)]
        component_ids = row["component_ids"] or _components_for(row["path"], components or [])
        candidates.append({"route_id": route_id, "hypothesis": hypothesis, "confidence": row["confidence"],
            "component_ids": component_ids, "citations": [citation], "proof_obligations": obligations,
            "dissent_ids": [], "causal_route_ids": [], "source": source,
            "order": (1, TIERS.index(row["tier"]), row["path"], row["start_line"])})
    return candidates, corroboration


def hunter_source(run_id: str, source_generation: str,
                  component_generation: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """The accepted 07-hypothesis-discovery result, or None with its coverage row (absent/skipped)."""
    pointer_path = _lead_pointer(run_id, HUNTER_JOB)
    if pointer_path is None:
        return None, {"job_id": HUNTER_JOB, "status": "ABSENT", "leads": 0}
    status = read_json(pointer_path).get("status")
    if status not in {"OK", "OK_WITH_GAPS"}:
        return None, {"job_id": HUNTER_JOB, "status": str(status), "leads": 0}
    document, binding = bounded_analysis_workers.load_accepted(pointer_path, run_id=run_id, job_id=HUNTER_JOB,
        contract=HUNTER_CONTRACT, artifact=HUNTER_ARTIFACT, schema=HUNTER_SCHEMA)
    if (document.get("run_id") != run_id or document.get("source_snapshot_sha256") != source_generation or
            document.get("component_generation") != component_generation):
        raise Blocked(f"{JOB}: {HUNTER_JOB} result is stale for this run's source or component generation")
    owner = pointer_path.parent.relative_to(data_path(run_id)).as_posix()
    source = {"contract_id": HUNTER_CONTRACT, "producer_job_id": HUNTER_JOB,
        "producer_attempt_id": binding["attempt_id"],
        "artifact_path": f"{owner}/attempts/{binding['attempt_id']}/{HUNTER_ARTIFACT}",
        "artifact_sha256": binding["artifact_sha256"], "accepted_pointer_sha256": binding["accepted_pointer_sha256"],
        "source_generation": source_generation, "component_generation": component_generation,
        "artifact": document}
    return source, {"job_id": HUNTER_JOB, "status": str(status), "leads": len(document["hypotheses"])}


def _lead_pointer(run_id: str, job_id: str) -> Path | None:
    for parts in ((job_id, "accepted.json"), (job_id, "whole", "accepted.json")):
        path = data_path(run_id, "jobs", *parts)
        if path.is_file():
            return path
    return None


def lead_sources(run_id: str, source_generation: str,
                 component_generation: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Load every accepted lead producer; absent or SKIPPED upstreams become coverage rows."""
    from execution_state import run_path
    manifest = run_path(run_id) / "inputs" / "artifact-manifest.json"
    snapshot = "sha256:" + file_hash(manifest) if manifest.is_file() else None
    sources, coverage = [], []
    for job_id, contract, artifact, schema in LEAD_PRODUCERS:
        pointer_path = _lead_pointer(run_id, job_id)
        if pointer_path is None:
            coverage.append({"job_id": job_id, "status": "ABSENT", "leads": 0}); continue
        status = read_json(pointer_path).get("status")
        if status not in {"OK", "OK_WITH_GAPS"}:
            coverage.append({"job_id": job_id, "status": str(status), "leads": 0}); continue
        document, binding = bounded_analysis_workers.load_accepted(pointer_path, run_id=run_id,
            job_id=job_id, contract=contract, artifact=artifact, schema=schema)
        if document.get("run_id") != run_id or (snapshot is not None and
                document.get("source_snapshot_sha256") != snapshot):
            raise Blocked(f"{JOB}: {job_id} lead artifact is stale for this run's source snapshot")
        leads = normalize_leads(job_id, document)
        owner = pointer_path.parent.relative_to(data_path(run_id)).as_posix()
        sources.append({"contract_id": contract, "producer_job_id": job_id,
            "producer_attempt_id": binding["attempt_id"],
            "artifact_path": f"{owner}/attempts/{binding['attempt_id']}/{artifact}",
            "lead_artifact": artifact, "artifact_sha256": binding["artifact_sha256"],
            "accepted_pointer_sha256": binding["accepted_pointer_sha256"],
            "source_generation": source_generation, "component_generation": component_generation,
            "tool_snapshot_sha256": document.get("source_snapshot_sha256"), "leads": leads})
        coverage.append({"job_id": job_id, "status": str(status), "leads": len(leads)})
    return sources, coverage


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


# The graph lifecycle 04-asvs-masvs publishes T14 (routes included) as owasp_join_publisher.JOB under
# data/jobs/04-owasp-join-report; reading data/jobs/04-asvs-masvs found nothing and silently dropped
# every OWASP route from the ledger.
OWASP_JOB = "04-owasp-join-report"
POOL_JOB = "deterministic-pool-merge"
POOL_CLASSES = {"07-red-team-adversarial": "candidate_only", "08-blue-team-refutation": "refutation",
                "09-independent-verification": "verification_observation"}
POOL_ACTOR_KEYS = {"07-red-team-adversarial": "reviewer", "08-blue-team-refutation": "reviewer",
                   "09-independent-verification": "verifier"}
_POOL_DIRECTORY = re.compile(r"^[0-9a-f]{32}$")


def pool_decision_actor(run_id: str, jobs_root: Path, producer: str, attempt: Path,
                        fingerprint: str, claim_id: str, *, label: str = JOB) -> dict[str, Any]:
    """The reviewer identity that the accepted stage attempt's own pool chain says decided ``claim_id``.

    A 07/08/09 reviewer is a persona instance of the stage's reviewer pool: its actor names the pool
    request (``requests/<instance id>.json``, sha = the request digest), not the stage attempt that
    later published the pool's merged decisions (claim_review_derive.actor). The row is never trusted
    for that link; it is re-derived from hashed files only: the stage attempt's ``inputs.json`` (its
    digest is the accepted fingerprint) and ``lineage.json`` bind one deterministic-pool-merge attempt,
    which must still be the accepted, tree-hash-verified pool for this stage; the claim's merged pool
    candidate carries the actor and lists the instance among its workers; the pool expansion and the
    retained request file of that instance carry the same run, stage, instance id and request digest.
    """
    attempt = Path(attempt)
    inputs_path = _regular_owned(attempt, "inputs.json")
    inputs = read_json(inputs_path)
    if (not isinstance(inputs, dict) or "sha256:" + digest(inputs) != fingerprint or
            inputs.get("run_id") != run_id or inputs.get("stage") != producer or
            inputs.get("applicability") != "APPLICABLE" or not isinstance(inputs.get("pool_binding"), dict)):
        raise Blocked(f"{label}: decision attempt does not bind an accepted reviewer pool")
    lineage = read_json(_regular_owned(attempt, "lineage.json"))
    expected_lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0", "run_id": run_id,
        "job_id": producer, "source_snapshot_sha256": inputs.get("source_generation"),
        "build_lineage_sha256": "sha256:" + digest({"upstream": inputs.get("upstream_binding"),
            "pool": inputs["pool_binding"], "applicability": inputs["applicability"]})}
    if lineage != expected_lineage:
        raise Blocked(f"{label}: decision attempt lineage does not bind its reviewer pool")
    pool_base = Path(jobs_root) / POOL_JOB / producer
    try:
        pool, binding = bounded_analysis_workers.load_accepted(pool_base / "accepted.json", run_id=run_id,
            job_id=POOL_JOB, contract=POOL_JOB, artifact="deterministic-pool-merge.json",
            schema="deterministic-pool-merge.schema.json")
    except Blocked as exc:
        raise Blocked(f"{label}: decision attempt's reviewer pool is not accepted ({exc})") from exc
    if binding != inputs["pool_binding"] or pool != inputs.get("pool") or pool.get("run_id") != run_id:
        raise Blocked(f"{label}: decision attempt's reviewer pool is not the accepted pool")
    candidates = [item for item in pool.get("candidates", []) if item.get("subject_id") == claim_id]
    if len(candidates) != 1 or candidates[0].get("claim_class") != POOL_CLASSES[producer]:
        raise Blocked(f"{label}: reviewer pool has no unique decision for the claim")
    candidate = candidates[0]
    try:
        decision = json.loads(candidate["assertion"])
    except (TypeError, ValueError) as exc:
        raise Blocked(f"{label}: reviewer pool decision is not JSON") from exc
    staged = [row for row in (inputs.get("decisions") or {}).get("decisions", [])
              if isinstance(row, dict) and row.get("claim_id") == claim_id]
    actor = decision.get(POOL_ACTOR_KEYS[producer]) if isinstance(decision, dict) else None
    if (not isinstance(actor, dict) or decision.get("claim_id") != claim_id or staged != [decision] or
            actor.get("attempt_id") not in candidate.get("worker_ids", [])):
        raise Blocked(f"{label}: reviewer pool decision does not name one of its own workers")
    instance = actor["attempt_id"]
    request_rel = f"requests/{instance}.json"
    if actor.get("artifact_path") != request_rel or actor.get("permission_receipt_path") != request_rel:
        raise Blocked(f"{label}: decision actor does not name its pool request")
    pool_attempt = pool_base / "attempts" / binding["attempt_id"]
    receipt = read_json(_regular_owned(pool_attempt, "pool-receipt.json"))
    directory = receipt.get("pool_directory") if isinstance(receipt, dict) else None
    if (not isinstance(directory, str) or not _POOL_DIRECTORY.match(directory) or
            receipt.get("stage") != producer or receipt.get("run_id") != run_id or
            receipt.get("merge_sha256") != pool.get("merge_sha256")):
        raise Blocked(f"{label}: reviewer pool receipt is invalid")
    expansion = read_json(_regular_owned(pool_attempt, f"pools/{directory}/expansion.json"))
    instances = [item for item in (expansion.get("instances") or []) if item.get("instance_id") == instance]
    request = read_json(_regular_owned(pool_attempt, f"pools/{directory}/{request_rel}"))
    request_sha = "sha256:" + digest(request)
    if (expansion.get("run_id") != run_id or expansion.get("job_id") != producer or len(instances) != 1 or
            instances[0].get("run_id") != run_id or instances[0].get("job_id") != producer or
            instances[0].get("attempt_id") != instance or
            (instances[0].get("request_file") or {}).get("path") != request_rel or
            instances[0].get("request_sha256") != request_sha or
            request.get("run_id") != run_id or request.get("job_id") != producer or
            request.get("attempt_id") != instance or
            actor.get("artifact_sha256") != request_sha or actor.get("permission_receipt_sha256") != request_sha):
        raise Blocked(f"{label}: decision actor is not a request of the accepted reviewer pool")
    return actor


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
    if not isinstance(actor, dict) or actor.get("job_id") != producer:
        raise Blocked(f"{JOB}: decision actor is not the accepted producer attempt")
    if (actor.get("source_generation") != source_generation or
            actor.get("component_generation") != component_generation or
            actor.get("role_id") != AUTHORITY_ROLES[producer]):
        raise Blocked(f"{JOB}: decision actor authority or generation is invalid")
    # The actor is the pool reviewer instance whose merged decision this accepted attempt published
    # (claim_review_derive.actor: the pool request's id and digest). That link is re-derived from the
    # attempt's hashed inputs/lineage and its accepted pool, never taken from the row.
    if pool_decision_actor(run_id, jobs_root, producer, attempt, pointer["fingerprint"],
                           request["claim_id"]) != actor:
        raise Blocked(f"{JOB}: decision actor is not the accepted producer attempt's pool reviewer")
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
    for candidate in sorted(candidates, key=lambda item: (item.get("order", ()),
                                                        item["source"]["producer_job_id"], item["route_id"])):
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


def route_kind(route_id: str, contract_id: str) -> tuple[str, str | None]:
    """(source_kind, review_priority) of one admitted route, derived from its admission identity."""
    if route_id.startswith(LEAD_ROUTE_PREFIX):
        tier = route_id[len(LEAD_ROUTE_PREFIX):].split(":", 1)[0]
        return "tool-lead", tier if tier in TIERS else None
    if route_id.startswith(HUNTER_ROUTE_PREFIX):
        tier = route_id[len(HUNTER_ROUTE_PREFIX):].split(":", 1)[0]
        return "hunter", tier if tier in TIERS else None
    return ("owasp-route" if contract_id == "owasp-join-report" else "threat-model"), None


def work_routing(ledger: dict[str, Any]) -> dict[str, Any]:
    admitted = {entry["claim_id"]: entry for entry in ledger["entries"]
                if entry["event_type"] == "candidate_admitted"}
    routes = []
    for item in ledger["claim_states"]:
        if item["status"] not in {"candidate", "unresolved", "narrowed"}:
            continue
        entry = admitted[item["claim_id"]]
        kind, priority = route_kind(entry["route_id"], entry["producer"]["contract_id"])
        routes.append({"claim_id": item["claim_id"], "status": item["status"],
            "stages": ["07-red-team-adversarial", "08-blue-team-refutation", "09-independent-verification"],
            "current_stage": "07-red-team-adversarial", "authorization": "not_authorized",
            "execution": "not_executed", "source_kind": kind, "review_priority": priority})
    rank = {"threat-model": 0, "owasp-route": 0, "tool-lead": 1, "hunter": 1}
    routes.sort(key=lambda row: (rank[row["source_kind"]], TIERS.index(row["review_priority"])
                                 if row["review_priority"] in TIERS else -1))
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
    sources = [source]
    owasp_pointer = data_path(run_id, "jobs", OWASP_JOB, "accepted.json")
    if owasp_pointer.is_file():
        routes, binding = bounded_analysis_workers.load_accepted(
            owasp_pointer, run_id=run_id, job_id=OWASP_JOB, contract="owasp-join-report",
            artifact="owasp-candidate-promotion-routes.json",
            schema="owasp-candidate-promotion-routes.schema.json")
        sources.append({"contract_id": "owasp-join-report", "producer_job_id": binding["job_id"],
            "producer_attempt_id": binding["attempt_id"],
            "artifact_path": f"jobs/{OWASP_JOB}/attempts/{binding['attempt_id']}/{binding['artifact_path']}",
            "artifact_sha256": binding["artifact_sha256"],
            "accepted_pointer_sha256": binding["accepted_pointer_sha256"],
            "source_generation": artifact["source_snapshot"],
            "component_generation": artifact["component_map_attempt_id"], "artifact": routes})
    leads, coverage = lead_sources(run_id, artifact["source_snapshot"], artifact["component_map_attempt_id"])
    components: list[dict[str, Any]] = []
    component_pointer = data_path(run_id, "jobs", "01-component-characterization", "accepted.json")
    if leads and component_pointer.is_file():
        component_map, component_binding = bounded_analysis_workers.load_accepted(component_pointer,
            run_id=run_id, job_id="01-component-characterization", contract="component-map",
            artifact="component-purpose-map.json", schema="component-purpose-map.schema.json")
        if component_binding["attempt_id"] == artifact["component_map_attempt_id"]:
            components = lead_components(component_map)
    sources.extend(leads)
    hunter, hunter_row = hunter_source(run_id, artifact["source_snapshot"], artifact["component_map_attempt_id"])
    coverage.append(hunter_row)
    if hunter is not None:
        sources.append(hunter)
        if not components and component_pointer.is_file():
            component_map, component_binding = bounded_analysis_workers.load_accepted(component_pointer,
                run_id=run_id, job_id="01-component-characterization", contract="component-map",
                artifact="component-purpose-map.json", schema="component-purpose-map.schema.json")
            if component_binding["attempt_id"] == artifact["component_map_attempt_id"]:
                components = lead_components(component_map)
    return {"run_id": run_id, "sources": sources, "lead_components": components,
            "lead_coverage": coverage, "reachability": reachability_verdicts(run_id) if leads else None,
            "code": _code_hashes()}


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
    values, leads, hunters = [], [], []
    for source in inputs["sources"]:
        if source["contract_id"] == "threat-model-core": values.extend(threat_candidates(source))
        elif source["contract_id"] == "owasp-join-report": values.extend(owasp_candidates(source))
        elif source["contract_id"] in LEAD_CONTRACTS: leads.append(source)
        elif source["contract_id"] == HUNTER_CONTRACT: hunters.append(source)
        else: raise Blocked(f"{JOB}: unsupported candidate-route contract {source['contract_id']}")
    corroboration: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for source in hunters:
        standalone, attached = hunter_candidates(source, lead_locations(leads), inputs.get("lead_components", []))
        values.extend(standalone)
        for key, rows in attached.items():
            corroboration.setdefault(key, []).extend(rows)
    if leads: values.extend(lead_candidates(leads, inputs.get("lead_components", []), corroboration,
                                            inputs.get("reachability")))
    return values


def _summary(ledger: dict[str, Any], inputs: dict[str, Any]) -> str:
    admitted = [entry for entry in ledger["entries"] if entry["event_type"] == "candidate_admitted"]
    kinds: dict[str, int] = {}
    for entry in admitted:
        kind, priority = route_kind(entry["route_id"], entry["producer"]["contract_id"])
        label = kind if priority is None else f"{kind} {priority}"
        kinds[label] = kinds.get(label, 0) + 1
    lines = ["# Candidate claim ledger", "",
             f"{len(ledger['claim_states'])} candidate claims; head `{ledger['head_hash']}`.", "",
             "| Source | Claims |", "|---|---:|"] + [f"| {key} | {kinds[key]} |" for key in sorted(kinds)]
    coverage = inputs.get("lead_coverage", [])
    if coverage:
        lines += ["", "## Tool-lead and hunter coverage", "", "| Producer | Accepted status | Leads / hypotheses |",
                  "|---|---|---:|"]
        lines += [f"| {row['job_id']} | {row['status']} | {row['leads']} |" for row in coverage]
    lines += ["", "Every tool lead is a candidate for review (P3 code-quality leads are grouped per file and "
              "ordered last, never dropped); reviewers remain free to look beyond this menu.", "",
              "Ledger admission does not create a finding, severity, runtime, or compliance claim.", ""]
    return "\n".join(lines)


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)
    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if inputs["code"] != _code_hashes(): raise Blocked(f"{JOB}: implementation changed before execution")
        attempt = allocation["attempt"]
        candidates = _candidates(inputs)
        ledger = build_ledger(run_id, attempt.name, candidates); routing = work_routing(ledger)
        atomic_json(attempt / LEDGER, ledger); atomic_json(attempt / ROUTING, routing)
        atomic_bytes(attempt / SUMMARY, _summary(ledger, inputs).encode())
        permission, lineage = _receipts(inputs, ledger)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        status = {"process": JOB, "status": "OK", "claims": len(ledger["claim_states"]),
            "tool_lead_claims": sum(entry["route_id"].startswith(LEAD_ROUTE_PREFIX) for entry in ledger["entries"]
                                    if entry["event_type"] == "candidate_admitted"),
            "hunter_claims": sum(entry["route_id"].startswith(HUNTER_ROUTE_PREFIX) for entry in ledger["entries"]
                                 if entry["event_type"] == "candidate_admitted"),
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


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
