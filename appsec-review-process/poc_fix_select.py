#!/usr/bin/env python3
"""Eligibility selector and request workspaces for lane 12b (``12b-poc-and-fix``).

A finding gets a light PoC and proposed fix only when it is **independently verified** (12's record
carries ``verification_status`` VERIFIED), **scored Critical** by 12, and **REACHABLE** by the
ADR-0020 call-graph analyser. The reachability decision and the severity cap are computed by the
same code the report uses (:mod:`finding_enrichment`, over the same accepted CPG, IR facts and
entry-point file), so 12b and ``10-synthesis-report`` agree on who is eligible; 10 re-checks it.

For each eligible finding (at most ``poc_findings_max``, ordered by 12 score then claim id) Python
builds the workspace the persona reads: finding locations, the reachability witness, the files it
may cite with a pinned ``source_sha256`` and line windows (``poc_citation_window_lines`` around each
finding location and witness call site), and hash-verified, redacted snippets. A file whose hash
cannot be pinned (no citation hash, CPG hash or matching projected-checkout file) is not citable;
a finding with no citable finding location is excluded as a gap.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import code_snippets
import finding_enrichment as enrichment
import poc_fix_derive as derive
import reachability
from execution_state import digest

RULE = ("verified (12 verification_status VERIFIED) + scored CRITICAL by 12 + REACHABLE (ADR-0020 call graph); "
        "the report's reachability cap leaves such a finding CRITICAL")
SNIPPET_CONTEXT = 15
WITNESS_CONTEXT = 3
MAX_SNIPPETS = 8
MAX_FACTS = 16


def finding_rows(scoring: dict[str, Any]) -> list[dict[str, Any]]:
    """12 priority records in the shape the report's ``verified_findings`` use (all of them; the
    caller filters)."""
    rows = []
    for record in sorted(scoring.get("priorities", []), key=lambda row: row["claim_id"]):
        rows.append({"claim_id": record["claim_id"], "title": record["hypothesis"],
                     "component_ids": record["component_ids"], "severity": record["severity"],
                     "score": record["score"], "verification_status": record["verification_status"],
                     "citations": record["citations"], "verification_citations": record["verification_citations"],
                     **{key: record[key] for key in ("cwe_judgments", "cvss_v4") if key in record}})
    return rows


def _checkout_sha(roots: list[Path], path: str) -> str | None:
    for root in roots:
        file = code_snippets._safe_file(Path(root), path)
        if file is not None and file.stat().st_size <= code_snippets.MAX_FILE_BYTES:
            return "sha256:" + hashlib.sha256(file.read_bytes()).hexdigest()
    return None


def pin_hash(ctx: enrichment.Context, path: str, cited: str | None) -> tuple[str | None, str | None, str | None]:
    """(sha256, basis, problem) for one file. A cited or CPG hash must match the projected checkout
    when the checkout holds the file; with no checkout the cited/CPG hash stands (snippets are then
    withheld by :mod:`code_snippets`)."""
    checkout = _checkout_sha(ctx.roots, path)
    cpg = reachability._file_sha(ctx.graph, path) if ctx.graph is not None else None
    for value, basis in ((cited, "finding-citation"), (cpg, "cpg")):
        if value:
            if checkout is not None and checkout != value:
                return None, None, f"{path}: projected checkout hash differs from the {basis} hash"
            return value, basis, None
    if checkout is not None:
        return checkout, "projected-checkout", None
    return None, None, f"{path}: no citation hash, CPG hash or projected checkout file to pin"


def _merge(windows: list[tuple[int, int]]) -> list[dict[str, int]]:
    merged: list[list[int]] = []
    for start, end in sorted(windows):
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [{"start": start, "end": end} for start, end in merged]


def _site(value: Any) -> tuple[str, int] | None:
    if isinstance(value, str) and ":" in value:
        path, _, line = value.rpartition(":")
        if line.isdigit() and int(line) > 0 and path:
            return path, int(line)
    return None


def workspace(ctx: enrichment.Context, finding: dict[str, Any], code: list[dict[str, Any]],
              reach: dict[str, Any], cwe: str | None, *, window: int) -> tuple[dict[str, Any] | None, list[str]]:
    """The request workspace of one eligible finding, or (None, problems) when nothing is citable."""
    problems: list[str] = []
    anchors: dict[str, dict[str, Any]] = {}
    for row in code:
        entry = anchors.setdefault(row["path"], {"cited": row["source_sha256"], "windows": [], "finding": True})
        entry["cited"] = entry["cited"] or row["source_sha256"]
        entry["windows"].append((max(1, row["line"] - window), row["end_line"] + window))
    witness = []
    for step in reach.get("witness", []):
        witness.append({"function": str(step.get("function")), "file": step.get("file"),
                        "line": step.get("line") if isinstance(step.get("line"), int) else None,
                        "calls_next_at": step.get("calls_next_at")})
        for site in ((step.get("file"), step.get("line")), _site(step.get("calls_next_at"))):
            if site and isinstance(site[0], str) and isinstance(site[1], int) and site[1] > 0:
                entry = anchors.setdefault(site[0], {"cited": None, "windows": [], "finding": False})
                entry["windows"].append((max(1, site[1] - window), site[1] + window))
    citable = []
    for path in sorted(anchors):
        sha, basis, problem = pin_hash(ctx, path, anchors[path]["cited"])
        if problem:
            problems.append(problem)
            continue
        citable.append({"path": path, "source_sha256": sha, "hash_basis": basis,
                        "windows": _merge(anchors[path]["windows"])[:64]})
    pinned = {row["path"]: row for row in citable}
    located = [row for row in code if row["path"] in pinned]
    if not located:
        return None, problems + ["no finding location is in a file whose hash could be pinned"]
    snippets = []
    for row in located[:MAX_SNIPPETS]:
        cut = code_snippets.extract(ctx.roots, row["path"], pinned[row["path"]]["source_sha256"],
                                    list(range(row["line"], min(row["end_line"], row["line"] + 10) + 1)),
                                    context=SNIPPET_CONTEXT)
        if cut["status"] == "VERIFIED":
            snippets.append({"path": row["path"], "start": cut["start"], "end": cut["end"], "source": cut["source"]})
    for step in witness:
        site = _site(step["calls_next_at"])
        if len(snippets) >= MAX_SNIPPETS or not site or site[0] not in pinned:
            continue
        cut = code_snippets.extract(ctx.roots, site[0], pinned[site[0]]["source_sha256"], [site[1]],
                                    context=WITNESS_CONTEXT)
        if cut["status"] == "VERIFIED":
            snippets.append({"path": site[0], "start": cut["start"], "end": cut["end"], "source": cut["source"]})
    facts = []
    for citation in finding.get("citations", []) + finding.get("verification_citations", []):
        fact = " ".join(str(citation.get("observed_fact") or "").split())
        if fact and fact[:300] not in facts:
            facts.append(fact[:300])
    document = {"schema": derive.WORKSPACE_SCHEMA_ID, "claim_id": finding["claim_id"],
                "title": " ".join(str(finding["title"]).split())[:600], "severity": "CRITICAL", "cwe": cwe,
                "reachability": {"state": reachability.REACHABLE, "reason": str(reach.get("reason", "")),
                                 "witness": witness[:64]},
                "locations": [{"path": row["path"], "line": row["line"], "end_line": max(row["line"], row["end_line"])}
                              for row in located][:32],
                "citable": citable[:32], "snippets": snippets, "observed_facts": facts[:MAX_FACTS],
                "bounds": dict(derive.BOUNDS)}
    document["request_id"] = "pocreq-" + digest(document)[:16]
    return document, problems


def select(scoring: dict[str, Any], run_root: Path, *, findings_max: int, window: int,
           snapshot_dir: Path | None = None) -> dict[str, Any]:
    """Eligibility decision and request workspaces (pure over the accepted inputs it reads)."""
    ctx = enrichment.Context(Path(run_root), snapshot_dir)
    excluded, gaps, eligible = [], [], []
    rows = finding_rows(scoring)
    for finding in rows:
        claim_id = finding["claim_id"]
        if finding["verification_status"] != "VERIFIED":
            excluded.append({"claim_id": claim_id, "reason": "not-verified",
                             "detail": f"verification_status {finding['verification_status']}"})
            continue
        if finding["severity"] != "CRITICAL":
            excluded.append({"claim_id": claim_id, "reason": "not-critical", "detail": f"12 severity {finding['severity']}"})
            continue
        code, dependency = enrichment.locations(finding)
        reach = enrichment._reachability(ctx, code, dependency)
        final, _cap = enrichment.cap_severity(finding["severity"], reach["state"])
        if reach["state"] != reachability.REACHABLE or final != "CRITICAL":
            excluded.append({"claim_id": claim_id, "reason": "not-reachable",
                             "detail": f"reachability {reach['state']}: {reach.get('reason', '')}"[:600]})
            gaps.append({"scope": "finding", "id": claim_id, "reason": "not-reachable",
                         "detail": f"Critical by 12 but reachability {reach['state']}; the report caps it at High "
                                   f"and no PoC is written"})
            continue
        if not code:
            excluded.append({"claim_id": claim_id, "reason": "no-source-location",
                             "detail": "REACHABLE through 06 (dependency) with no application source location"})
            gaps.append({"scope": "finding", "id": claim_id, "reason": "no-source-location",
                         "detail": "eligible dependency finding cites no application source line; no PoC written"})
            continue
        eligible.append((finding, code, reach))
    eligible.sort(key=lambda item: (-float(item[0]["score"]), item[0]["claim_id"]))
    requests = []
    for finding, code, reach in eligible:
        if len(requests) >= findings_max:
            excluded.append({"claim_id": finding["claim_id"], "reason": "cap",
                             "detail": f"beyond poc_findings_max ({findings_max})"})
            gaps.append({"scope": "finding", "id": finding["claim_id"], "reason": "cap",
                         "detail": f"eligible but beyond poc_findings_max ({findings_max}); no PoC written"})
            continue
        cwe = enrichment._cwe(ctx, finding, code)
        document, problems = workspace(ctx, finding, code, reach, cwe["primary"], window=window)
        for problem in problems:
            gaps.append({"scope": "finding", "id": finding["claim_id"], "reason": "citation-unpinned",
                         "detail": problem[:600]})
        if document is None:
            excluded.append({"claim_id": finding["claim_id"], "reason": "no-citable-source",
                             "detail": "; ".join(problems)[:600]})
            continue
        requests.append(document)
    return {"rule": RULE, "considered": len(rows), "eligible": len(eligible), "requests": requests,
            "excluded": excluded, "gaps": gaps, "enrichment_inputs": ctx.bindings}
