#!/usr/bin/env python3
"""Verification evidence for stage 09 and the claim certainty ladder (ADR-0034 V2).

Python, not the model, assembles what may verify a claim: for each claim under review, one
reachability item from the same call-graph analysis the report uses (``finding_enrichment``: the
accepted code property graph, IR facts and entry points; ``06-cve-reachability`` for a dependency
match). The 09 pool pins this document for its reviewers; a reviewer cites items by id; derive turns
them into citations produced by the verifier; the 09 lifecycle publishes the exact bytes in its own
attempt, so report assembly can re-hash them.

VERIFIED needs every proof obligation satisfied (``claim_lifecycle_core.verify``) and at least one
cited REACHABLE item. An item that cannot decide is UNKNOWN with its reason: it never blocks, and the
claim stays UNRESOLVED.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from execution_state import digest, run_path

SCHEMA = "verification-evidence.schema.json"
SCHEMA_ID = "appsec-review/verification-evidence/1.0"
FILE = "verification-evidence.json"
ROOT_ID = "verification-evidence"
STAGE = "09-independent-verification"
REACHABLE, UNREACHABLE, UNKNOWN = "REACHABLE", "UNREACHABLE", "UNKNOWN"
RUNGS = ("finding", "reachable", "reachable_tainted", "inference_validated", "poc", "patch")
_BINDINGS = ("cpg", "ir", "cve_reachability", "entry_points", "export_entries")
_WITNESS_MAX = 32


def build(run_id: str, records: Iterable[dict[str, Any]], ledger_head_id: str, ledger_head_sha256: str,
          context: Any = None) -> dict[str, Any]:
    """The evidence document for these 09 claims (deterministic over the accepted analysis inputs)."""
    import finding_enrichment
    ctx = context if context is not None else finding_enrichment.Context(run_path(run_id))
    claims = []
    for record in sorted(records, key=lambda item: item["claim_id"]):
        code, dependency = finding_enrichment.locations({"citations": record.get("citations", [])})
        result = finding_enrichment._reachability(ctx, code, dependency)
        kind = "dependency_reachability" if dependency and not code else "call_graph_reachability"
        item = {"item_id": "ve-" + digest({"claim_id": record["claim_id"], "kind": kind})[:24], "kind": kind,
                "state": result["state"] if result.get("state") in (REACHABLE, UNREACHABLE) else UNKNOWN,
                "basis": str(result.get("basis") or "none"), "reason": str(result.get("reason") or ""),
                "witness": json.loads(json.dumps(result.get("witness") or [], default=str))[:_WITNESS_MAX]}
        claims.append({"claim_id": record["claim_id"], "items": [item]})
    gaps = sorted({gap for gap in getattr(ctx, "gaps", []) if gap.startswith(("REACHABILITY", "export-facts"))})
    return {"schema": SCHEMA_ID, "run_id": run_id, "stage": STAGE, "ledger_head_id": ledger_head_id,
            "ledger_head_sha256": ledger_head_sha256,
            "bindings": {key: ctx.bindings.get(key) for key in _BINDINGS if key in ctx.bindings},
            "claims": claims, "gaps": gaps}


def to_bytes(document: dict[str, Any]) -> bytes:
    """The one serialization the pool pins and the 09 attempt publishes (their hashes must agree)."""
    return (json.dumps(document, sort_keys=True, indent=1, ensure_ascii=True) + "\n").encode("utf-8")


def sha256(document: dict[str, Any]) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(to_bytes(document)).hexdigest()


def items(document: dict[str, Any] | None, claim_id: str) -> dict[str, dict[str, Any]]:
    if not document:
        return {}
    for row in document.get("claims", []):
        if row["claim_id"] == claim_id:
            return {item["item_id"]: item for item in row["items"]}
    return {}


def citation(item: dict[str, Any], *, evidence_sha256: str, job_id: str, attempt_id: str) -> dict[str, Any]:
    """A claim-lifecycle citation of one evidence item, produced by the verifier."""
    return {"citation_id": "verification-" + item["item_id"], "producer_job_id": job_id,
            "producer_attempt_id": attempt_id, "artifact_path": FILE, "artifact_sha256": evidence_sha256,
            "locator_json": json.dumps({"item_id": item["item_id"]}, sort_keys=True),
            "observed_fact": f"{item['kind']} {item['state']}: {item['reason']}"[:500] or item["kind"]}


def cited_items(decision: dict[str, Any], document: dict[str, Any] | None) -> list[dict[str, Any]]:
    known = items(document, decision.get("claim_id", ""))
    found = []
    for value in decision.get("citations") or []:
        if value.get("artifact_path") != FILE:
            continue
        try:
            item_id = json.loads(value.get("locator_json") or "{}").get("item_id")
        except ValueError:
            continue
        if item_id in known:
            found.append(known[item_id])
    return found


def verified_errors(decision: dict[str, Any], document: dict[str, Any] | None) -> list[str]:
    """ADR-0034 item 3: VERIFIED needs a cited REACHABLE item (code: call path; dependency: 06 path)."""
    if decision.get("disposition") != "VERIFIED":
        return []
    if any(item["state"] == REACHABLE for item in cited_items(decision, document)):
        return []
    return [f"claim {decision.get('claim_id')}: VERIFIED needs a cited REACHABLE verification-evidence item "
            "(evidence_ids); without one the claim is UNRESOLVED"]


def certainty(decision: dict[str, Any], document: dict[str, Any] | None) -> dict[str, Any]:
    """The claim's certainty ladder at stage 09 (ADR-0034 item 1)."""
    claim_items = list(items(document, decision.get("claim_id", "")).values())
    reach = next((item for item in claim_items if item["kind"].endswith("reachability")), None)
    statuses = {item.get("status") for item in decision.get("proof_obligations") or []}
    rungs = [{"rung": "finding", "state": "established", "reason": "a candidate claim exists", "item_ids": []}]
    if reach is None:
        rungs.append({"rung": "reachable", "state": "not_assessed",
                      "reason": "no verification evidence was assembled for this claim", "item_ids": []})
    else:
        state = {REACHABLE: "established", UNREACHABLE: "not_established"}.get(reach["state"], "uncertain")
        rungs.append({"rung": "reachable", "state": state, "reason": reach["reason"], "item_ids": [reach["item_id"]]})
    rungs.append({"rung": "reachable_tainted", "state": "not_assessed",
                  "reason": "no taint-path producer covers stage-09 claims yet", "item_ids": []})
    rungs.append({"rung": "inference_validated",
                  "state": "established" if statuses == {"SATISFIED"} else "not_established",
                  "reason": ("every proof obligation was satisfied at 09" if statuses == {"SATISFIED"} else
                             "not every proof obligation was satisfied at 09"), "item_ids": []})
    rungs.append({"rung": "poc", "state": "not_assessed",
                  "reason": "no PoC is produced before 09 (12b writes unexecuted PoCs after verification)",
                  "item_ids": []})
    rungs.append({"rung": "patch", "state": "not_assessed",
                  "reason": "12b proposes fixes only after verification", "item_ids": []})
    highest = [row["rung"] for row in rungs if row["state"] == "established"][-1]
    return {"highest": highest, "rungs": rungs}
