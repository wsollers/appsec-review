#!/usr/bin/env python3
"""Report projection of lane 14 for ``10-synthesis-report`` (ADR-0016 decision 9).

Lane 14 is an optional input of the report. This module reads the accepted
``14-attack-chain-refutation`` ledger (full envelope and hash-chain re-verification), checks that
every chain's ``causal_claim_ids`` resolve to claims the report carries, ranks the chains
deterministically with 12's severities for verified links (state, impact kind, severity, trust
boundaries crossed, fewer links, chain id) and splits them into the report body
(``chains_reported_max``) and an appendix. A SKIPPED lane renders "no chain composed" with its
reason; an absent or failed lane is a limitation, never a report failure. Refuted chains are
counted, not listed. Chains never enter ``verified_findings``: they are prioritisation context.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import attack_chain_refute as refute
import bounded_analysis_workers
import tunables
from execution_state import Blocked

SCHEMA = "appsec-review/attack-chain-report/1.0"
RESULT = "attack-chains.json"
JOB = "14-attack-chain-refutation"
CONTRACT = "14-attack-chain-refutation"
ARTIFACT = "attack-chain-ledger.json"
NOTE = ("Attack chains are prioritisation context composed from reviewed claims: each is at most "
        "'supported' (composed from verified parts along tool-recorded edges and not broken by an "
        "adversarial reviewer), never a verified finding, and assigns no severity.")
LABEL_CHARS = 160


def _sha_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _pointer(run_root: Path) -> Path:
    return Path(run_root) / "data" / "jobs" / JOB / "accepted.json"


def input_binding(run_root: Path) -> dict[str, Any] | None:
    """What the report reads from lane 14, by hash, for the synthesis input fingerprint."""
    pointer = _pointer(run_root)
    if not pointer.is_file() or pointer.is_symlink():
        return None
    value = json.loads(pointer.read_text(encoding="utf-8"))
    return {"job_id": JOB, "status": value.get("status"), "attempt_id": value.get("attempt_id"),
            "reason": value.get("reason"), "accepted_pointer_sha256": _sha_file(pointer)}


def _clip(text: Any, limit: int = LABEL_CHARS) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _empty(report: dict[str, Any], status: str, reason: str, gaps: list[str]) -> dict[str, Any]:
    return {"schema": SCHEMA, "run_id": report["run_id"], "status": status, "reason": reason, "binding": None,
            "chains": [], "appendix": [], "refuted_count": 0, "coverage": {}, "gaps": gaps, "note": NOTE}


def build(report: dict[str, Any], run_root: Path, *, reported_max: int | None = None) -> dict[str, Any]:
    """The report's attack-chain section (pure function of the report and the accepted ledger)."""
    binding = input_binding(run_root)
    if binding is None:
        return _empty(report, "ABSENT", "14-attack-chain-refutation has no accepted publication in this run",
                      ["attack-chains: lane 14 did not publish; no chain composed (recorded gap, not a failure)"])
    if binding["status"] == "SKIPPED":
        return {**_empty(report, "SKIPPED", binding["reason"] or "skipped", []), "binding": binding}
    if binding["status"] not in {"OK", "OK_WITH_GAPS"}:
        return {**_empty(report, "ABSENT", f"14-attack-chain-refutation ended {binding['status']}",
                         [f"attack-chains: lane 14 ended {binding['status']}; no chain reported"]), "binding": binding}
    ledger, loaded = bounded_analysis_workers.load_accepted(_pointer(run_root), run_id=report["run_id"], job_id=JOB,
        contract=CONTRACT, artifact=ARTIFACT, schema=refute.LEDGER_SCHEMA)
    refute.verify_ledger(ledger)
    if ledger["claim_ledger_head_sha256"] not in {None, report["ledger_head_sha256"]}:
        raise Blocked("10-synthesis-report: the attack-chain ledger is bound to a different claim-ledger head")
    findings = {row["claim_id"]: row for row in report["verified_findings"]}
    open_claims = {row["claim_id"]: row for row in report["unresolved_candidates"]}
    severities = {claim_id: row["severity"] for claim_id, row in findings.items()}
    gaps = [f"attack-chains: {gap['reason']} ({gap['scope']} {gap['id']}): {gap['detail']}" for gap in ledger["gaps"]]
    kept = []
    for chain in ledger["chains"]:
        missing = [claim_id for claim_id in chain["causal_claim_ids"] if claim_id not in findings and claim_id not in open_claims]
        if missing:
            gaps.append(f"attack-chains: chain {chain['chain_id']} cites claim(s) {missing[:4]} the report does not "
                        f"carry; not reported")
            continue
        kept.append(chain)
    limit = reported_max if reported_max is not None else tunables.value("14-attack-chain-composition", "chains_reported_max")
    rows = []
    for position, chain in enumerate(refute.rank(kept, severities=severities)):
        links = []
        for link in chain["links"]:
            if link["claim_id"]:
                label = (findings[link["claim_id"]]["title"] if link["claim_id"] in findings
                         else open_claims[link["claim_id"]]["hypothesis"])
                ref = link["claim_id"]
            else:
                label = next((citation.get("label") for citation in link["citations"] if citation.get("label")),
                             link["fact_ref"])
                ref = link["fact_ref"]
            links.append({"index": link["index"], "stage": link["stage"], "ref": ref, "label": _clip(label),
                          "link_state": link["link_state"],
                          "severity": severities.get(link["claim_id"]) if link["claim_id"] else None})
        refutation = chain["refutation"]
        rows.append({"rank": position + 1, "chain_id": chain["chain_id"], "state": chain["state"],
                     "impact_kind": chain["impact_kind"], "objective": _clip(chain["objective"], 300),
                     "narrative": chain["narrative"], "weakest": chain["weakest"], "links": links,
                     "edges": [{"from": edge["from"], "to": edge["to"], "basis": edge["basis"],
                                "downgraded_from": edge["downgraded_from"]} for edge in chain["edges"]],
                     "boundaries_crossed": chain.get("boundaries_crossed", []),
                     "refutation": {"disposition": refutation["disposition"], "target": refutation["target"],
                                    "mechanism": _clip(refutation["mechanism"], 600) if refutation["mechanism"] else None,
                                    "citations": len(refutation["citations"])}})
    body, appendix = rows[:limit], rows[limit:]
    return {"schema": SCHEMA, "run_id": report["run_id"], "status": "PUBLISHED",
            "reason": None if rows else "the lane published no surviving chain",
            "binding": {**binding, "artifact_sha256": loaded["artifact_sha256"]},
            "chains": body,
            "appendix": [{key: row[key] for key in ("rank", "chain_id", "state", "impact_kind", "objective")}
                         for row in appendix],
            "refuted_count": len(ledger["dropped"]), "coverage": ledger["coverage"], "gaps": gaps, "note": NOTE}
