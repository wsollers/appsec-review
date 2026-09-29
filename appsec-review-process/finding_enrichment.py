#!/usr/bin/env python3
"""Deterministic report-finding enrichment for ``10-synthesis-report`` (ADR-0020).

For every independently verified finding this module collects, in Python and from pinned or
accepted inputs only, the report-template fields the draft used to leave blank:

* CWE -- tool rule metadata through the pinned rule->CWE map, plus the reviewers' CWE judgments
  (07/09/12, carried by the lifecycle), all validated against the pinned CWE catalog;
* CVSS v4.0 -- the vector/score the 12 lifecycle computed from the reviewer's base metrics;
* reachability -- the call-graph analyser over the accepted CPG (+ IR facts); code findings get a
  witness path, SCA findings take the accepted 06-cve-reachability classification; with the
  ``reachability_export_entries`` tunable on, a shipped library's exported functions are roots too
  (``entry_exports``, from the accepted 02-binary-triage evidence);
* severity -- the lifecycle severity, capped by reachability: Critical requires REACHABLE,
  UNKNOWN and UNREACHABLE cap at High (and say so);
* EPSS / KEV -- from the dated, hash-pinned offline snapshot for SCA findings, else "not assessed";
* code snippets -- hash-verified, redacted, bounded extracts from the projected checkout;
* remediation -- 11-remediation-proposal objectives, plus any 12 reviewer proposal labelled
  PATCH_PROPOSED_UNVALIDATED.

No model call, no network, no target execution.  Missing inputs become explicit gaps.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import code_snippets
import cvss4
import cwe_catalog
import entry_exports
import epss_kev_snapshot
import reachability

SCHEMA = "appsec-review/finding-enrichment/1.0"
RESULT = "finding-enrichment.json"
ENTRY_POINTS = "inputs/reachability-entry-points.json"
OPTIONAL_JOBS = {"cpg": ("02-code-property-graph", "code-property-graph.json"),
                 "ir": ("02-ir-facts", "ir-facts.json"),
                 "remediation": ("11-remediation-proposal", "remediation-proposal.json"),
                 "cve_reachability": ("06-cve-reachability", "outputs/cve-reachability.json")}
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
STAGE_RANK = {"12-scoring-prioritization": 0, "09-independent-verification": 1, "07-red-team-adversarial": 2}
MAX_SNIPPETS = 3
SCA_STATE = {"reachable": reachability.REACHABLE, "unreachable": reachability.UNREACHABLE}


def _sha_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _accepted_attempt(run_root: Path, job_id: str) -> tuple[Path, dict[str, Any]] | None:
    """The accepted attempt directory of an optional upstream (scope-partitioned layout aware)."""
    for base in (Path(run_root) / "data" / "jobs" / job_id, Path(run_root) / "data" / "jobs" / job_id / "whole"):
        pointer = base / "accepted.json"
        if pointer.is_file() and not pointer.is_symlink():
            value = json.loads(pointer.read_text())
            attempt = base / "attempts" / str(value.get("attempt_id"))
            if value.get("status") in {"OK", "OK_WITH_GAPS"} and attempt.is_dir() and not attempt.is_symlink():
                return attempt, {"job_id": job_id, "attempt_id": value["attempt_id"],
                                 "accepted_pointer_sha256": _sha_file(pointer)}
    return None


def input_bindings(run_root: Path) -> dict[str, Any]:
    """Everything enrichment reads, by hash, for the synthesis worker's input fingerprint."""
    bindings: dict[str, Any] = {}
    for name, (job_id, artifact) in OPTIONAL_JOBS.items():
        found = _accepted_attempt(run_root, job_id)
        if found and (found[0] / artifact).is_file():
            bindings[name] = {**found[1], "artifact": artifact, "artifact_sha256": _sha_file(found[0] / artifact)}
        else:
            bindings[name] = None
    entry = Path(run_root) / ENTRY_POINTS
    bindings["entry_points"] = _sha_file(entry) if entry.is_file() and not entry.is_symlink() else None
    if entry_exports.enabled("reachability_export_entries"):
        # Only when on: with the tunable off the bindings (and so the fingerprint) are unchanged.
        found = _accepted_attempt(run_root, entry_exports.TRIAGE_JOB)
        bindings["export_entries"] = {**found[1], **entry_exports.triage_binding(found[0])} if found else None
    lock = epss_kev_snapshot.SNAPSHOT_DIR / epss_kev_snapshot.LOCK
    bindings["epss_kev_lock"] = _sha_file(lock) if lock.is_file() else None
    bindings["cwe"] = cwe_catalog.Catalog().identity
    bindings["cvss_lookup_sha256"] = cvss4.LOOKUP_SHA256
    bindings["sources"] = [{"tree": str(root.relative_to(run_root)) if root.is_relative_to(run_root) else root.name}
                           for root in code_snippets.source_roots(run_root)]
    return bindings


class Context:
    """Loaded, verified inputs shared by every finding."""

    def __init__(self, run_root: Path, snapshot_dir: Path | None = None):
        self.run_root = Path(run_root)
        self.catalog = cwe_catalog.Catalog()
        self.gaps: list[str] = []
        self.bindings = input_bindings(self.run_root)
        entry = self.run_root / ENTRY_POINTS
        self.entry_points: list[str] = []
        if self.bindings["entry_points"]:
            value = json.loads(entry.read_text())
            self.entry_points = sorted({str(item) for item in value.get("entry_points", [])})
        self.graph = None
        if self.bindings["cpg"]:
            attempt, _ = _accepted_attempt(self.run_root, OPTIONAL_JOBS["cpg"][0])
            ir = None
            if self.bindings["ir"]:
                ir = _accepted_attempt(self.run_root, OPTIONAL_JOBS["ir"][0])[0] / OPTIONAL_JOBS["ir"][1]
            self.graph = reachability.load_cpg(attempt, ir)
        self.extra: reachability.ExtraEntries | None = None
        if self.graph is not None and "export_entries" in self.bindings:
            tables, gaps = [], [f"export-facts-missing:{entry_exports.TRIAGE_JOB}"]
            if self.bindings["export_entries"]:
                tables, gaps = entry_exports.tables_from_triage(
                    _accepted_attempt(self.run_root, entry_exports.TRIAGE_JOB)[0])
            self.extra = entry_exports.join_exports(self.graph, tables, gaps)
        if self.graph is None:
            self.gaps.append("REACHABILITY_UNKNOWN: no accepted 02-code-property-graph; every code finding is UNKNOWN")
        self.remediation: dict[str, dict[str, Any]] = {}
        if self.bindings["remediation"]:
            attempt, _ = _accepted_attempt(self.run_root, OPTIONAL_JOBS["remediation"][0])
            document = json.loads((attempt / OPTIONAL_JOBS["remediation"][1]).read_text())
            self.remediation = {row["claim_id"]: row for row in document.get("proposals", [])}
        self.sca: dict[str, dict[str, Any]] = {}
        if self.bindings["cve_reachability"]:
            attempt, _ = _accepted_attempt(self.run_root, OPTIONAL_JOBS["cve_reachability"][0])
            document = json.loads((attempt / OPTIONAL_JOBS["cve_reachability"][1]).read_text())
            self.sca = {row["match_ref"]: row for row in document.get("assessments", [])}
        self.snapshot = epss_kev_snapshot.load(snapshot_dir)
        if self.snapshot is None:
            self.gaps.append("EPSS/KEV not assessed: no pinned offline snapshot has been imported")
        self.roots = code_snippets.source_roots(self.run_root)


def _locator(citation: dict[str, Any]) -> dict[str, Any]:
    try:
        value = json.loads(citation.get("locator_json") or "null")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def locations(finding: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(code locations, dependency locations) named by the finding's own citations."""
    code, dependency, seen = [], [], set()
    for citation in finding.get("citations", []) + finding.get("verification_citations", []):
        locator = _locator(citation)
        if locator.get("component_ref"):
            key = ("dep", locator["component_ref"], tuple(locator.get("aliases") or []))
            if key not in seen:
                seen.add(key)
                dependency.append({"component_ref": locator["component_ref"],
                                   "aliases": list(locator.get("aliases") or []),
                                   "lead_ref": locator.get("lead_ref"), "tool_id": locator.get("tool_id"),
                                   "rule_id": locator.get("rule_id")})
        elif locator.get("path") and isinstance(locator.get("start_line"), int):
            key = ("code", locator["path"], locator["start_line"], locator.get("tool_id"), locator.get("rule_id"))
            if key not in seen:
                seen.add(key)
                code.append({"path": locator["path"], "line": locator["start_line"],
                             "end_line": locator.get("end_line") or locator["start_line"],
                             "source_sha256": locator.get("source_sha256"), "tool_id": locator.get("tool_id"),
                             "rule_id": locator.get("rule_id"), "tags": list(locator.get("tags") or [])})
    code.sort(key=lambda row: (row["path"], row["line"], row["tool_id"] or "", row["rule_id"] or ""))
    return code, dependency


def _cwe(ctx: Context, finding: dict[str, Any], code: list[dict[str, Any]]) -> dict[str, Any]:
    entries: dict[str, dict[str, Any]] = {}
    gaps: list[str] = []
    for row in code:
        if not row["tool_id"] or not row["rule_id"]:
            continue
        ids, notes = ctx.catalog.for_lead(row["tool_id"], row["rule_id"], row["tags"])
        gaps.extend(notes)
        if not ids:
            gaps.append(f"no pinned CWE mapping for {row['tool_id']} {row['rule_id']}")
        for cwe_id in ids:
            entries.setdefault(cwe_id, {"cwe_id": cwe_id, "name": ctx.catalog.name(cwe_id), "sources": []})
            source = f"tool rule {row['tool_id']} {row['rule_id']}"
            if source not in entries[cwe_id]["sources"]:
                entries[cwe_id]["sources"].append(source)
    judgments = sorted(finding.get("cwe_judgments") or [], key=lambda item: STAGE_RANK.get(item["stage"], 9))
    for item in judgments:
        cwe_id = ctx.catalog.validate(item["cwe_id"])
        entries.setdefault(cwe_id, {"cwe_id": cwe_id, "name": ctx.catalog.name(cwe_id), "sources": []})
        entries[cwe_id]["sources"].append(f"reviewer {item['stage']}: {item['rationale']}"[:300])
    primary = ctx.catalog.validate(judgments[0]["cwe_id"]) if judgments else (next(iter(entries)) if entries else None)
    ordered = ([entries[primary]] if primary else []) + [value for key, value in entries.items() if key != primary]
    return {"primary": primary, "basis": ("reviewer judgment" if judgments else "tool rule metadata") if primary else None,
            "ids": ordered, "gaps": sorted(set(gaps)),
            "display": ", ".join(item["cwe_id"] for item in ordered) or "Not asserted (no mapped rule or reviewer judgment)"}


def _reachability(ctx: Context, code: list[dict[str, Any]], dependency: list[dict[str, Any]]) -> dict[str, Any]:
    if dependency and not code:
        row = next((ctx.sca[item["lead_ref"]] for item in dependency if item.get("lead_ref") in ctx.sca), None)
        if row is None:
            return {"state": reachability.UNKNOWN, "witness": [], "basis": "06-cve-reachability",
                    "reason": "no accepted 06-cve-reachability assessment for this dependency match"}
        return {"state": SCA_STATE.get(row["classification"], reachability.UNKNOWN), "basis": "06-cve-reachability",
                "witness": [{"function": item["locator"], "file": item["path"]} for item in row["evidence"]],
                "reason": f"06 classification {row['classification']} ({row['assessment_id']})"}
    if not code:
        return {"state": reachability.UNKNOWN, "witness": [], "basis": "none",
                "reason": "finding cites no source location"}
    if ctx.graph is None:
        return {"state": reachability.UNKNOWN, "witness": [], "basis": "none",
                "reason": "no accepted code property graph"}
    best = None
    for row in code:
        result = reachability.assess_location(ctx.graph, row["path"], row["line"], ctx.entry_points, extra=ctx.extra)
        if best is None or reachability.STATES.index(result["state"]) < reachability.STATES.index(best["state"]):
            best = result
    best = {key: value for key, value in best.items() if key != "graph"}
    return {**best, "basis": "02-code-property-graph call graph", "graph": ctx.graph.identity}


def cap_severity(severity: str, state: str) -> tuple[str, str | None]:
    """Reachability is the final arbiter: Critical requires REACHABLE; otherwise cap at High."""
    if severity == "CRITICAL" and state != reachability.REACHABLE:
        return "HIGH", f"capped from CRITICAL to HIGH: reachability {state}"
    return severity, None


def _snippets(ctx: Context, code: list[dict[str, Any]], cwe_display: str) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str | None], list[int]] = {}
    for row in code:
        lines = grouped.setdefault((row["path"], row["source_sha256"]), [])
        lines.extend(range(row["line"], min(row["end_line"], row["line"] + 10) + 1))
    result = []
    for (path, sha), lines in sorted(grouped.items(), key=lambda item: item[0][0])[:MAX_SNIPPETS]:
        result.append(code_snippets.extract(ctx.roots, path, sha, lines,
                                            note=f"Flagged line(s) {', '.join(map(str, sorted(set(lines))))}; {cwe_display}"))
    return result


def _remediation(ctx: Context, finding: dict[str, Any]) -> dict[str, Any]:
    items = []
    row = ctx.remediation.get(finding["claim_id"])
    if row:
        items.append({"source": "11-remediation-proposal", "status": row["status"],
                      "objective": row["remediation_objective"], "patch_status": row["patch_status"],
                      "retest": row["retest"]["status"]})
    if finding.get("remediation_proposal"):
        proposal = finding["remediation_proposal"]
        items.append({"source": proposal["source"], "status": proposal["status"],
                      "objective": proposal["objective"], "patch_proposal": proposal.get("patch_proposal")})
    text = " ".join(f"[{item['status']}] {item['objective']}" +
                    (f" Proposed change: {item['patch_proposal']}" if item.get("patch_proposal") else "")
                    for item in items)
    return {"items": items, "display": text or "No remediation objective or proposal is recorded (11 absent, no 12 proposal)."}


def enrich_finding(ctx: Context, finding: dict[str, Any]) -> dict[str, Any]:
    code, dependency = locations(finding)
    cwe = _cwe(ctx, finding, code)
    reach = _reachability(ctx, code, dependency)
    final, cap = cap_severity(finding["severity"], reach["state"])
    cvss = finding.get("cvss_v4")
    identifiers = sorted({alias for item in dependency for alias in item["aliases"]})
    exploit = None
    if dependency:
        exploit = (ctx.snapshot.lookup(identifiers) if ctx.snapshot is not None
                   else epss_kev_snapshot.not_assessed(identifiers))
    return {"claim_id": finding["claim_id"],
            "locations": [{"path": row["path"], "line": row["line"]} for row in code] +
                         [{"component_ref": row["component_ref"], "aliases": row["aliases"]} for row in dependency],
            "cwe": cwe, "cvss_v4": cvss,
            "severity": {"lifecycle": finding["severity"], "basis": "CVSS v4.0" if cvss else "12 factor bucket",
                         "final": final, "reachability_cap": cap},
            "reachability": reach, "epss_kev": exploit,
            "snippets": _snippets(ctx, code, cwe["display"]) if code else [],
            "remediation": _remediation(ctx, finding)}


def build(report: dict[str, Any], run_root: Path, snapshot_dir: Path | None = None) -> dict[str, Any]:
    ctx = Context(run_root, snapshot_dir)
    findings = [enrich_finding(ctx, finding) for finding in report["verified_findings"]]
    return {"schema": SCHEMA, "run_id": report["run_id"], "ledger_head_sha256": report["ledger_head_sha256"],
            "inputs": ctx.bindings,
            "epss_kev": ctx.snapshot.identity if ctx.snapshot is not None else {"status": "not assessed"},
            "severity_rule": "Critical requires REACHABLE; UNKNOWN and UNREACHABLE cap at High (ADR-0020)",
            "findings": findings, "gaps": ctx.gaps}
