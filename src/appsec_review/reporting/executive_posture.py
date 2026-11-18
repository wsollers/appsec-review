"""Pure deterministic executive posture, attack-chain card, remediation roadmap, and named gap builders.

Shared between ``job_final_report_publication.report`` (JSON projection) and ``reporting.executive_report``
(LaTeX/PDF and HTML document builder) without circular imports. Never reads wall clock, locale, or files.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from .dimensions import DIMENSIONS, predicate_of

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_ACTIVE_CHAIN_STATUSES = frozenset({"confirmed", "qualified_supported", "confirmed_chain", "qualified_chain"})


def _clean_sev(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in _SEVERITY_RANK else "unrated"


def _chain_items(report: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
    chains_src = report.get("attack_chains")
    if isinstance(chains_src, Mapping):
        return chains_src.get("items") or ()
    return ((report.get("attachments") or {}).get("attack_chains")) or ()


def build_executive_posture(report: Mapping[str, Any], radar: Mapping[str, Any]) -> dict[str, Any]:
    """Deterministic Executive Risk Posture Banner & Release Readiness Summary."""
    findings = report.get("findings") or ()
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unrated": 0}
    for pkg in findings:
        sev = _clean_sev((pkg.get("ship_block") or {}).get("technical_severity"))
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    chain_claims: set[str] = set()
    for ch in _chain_items(report):
        if ch.get("status") in _ACTIVE_CHAIN_STATUSES:
            for cid in ch.get("component_claim_ids") or ():
                chain_claims.add(str(cid))

    confirmed_claim_ids = {str(pkg.get("claim_id")) for pkg in findings if pkg.get("claim_id")}
    chain_elevated_count = len(chain_claims & confirmed_claim_ids)

    supply_chain_count = 0
    for pkg in findings:
        if pkg.get("reachability") not in {"symbol_reachable", "confirmed_reachable"}:
            continue
        pred = predicate_of(pkg)
        if pred == "supply_chain_compromise":
            supply_chain_count += 1
        elif pred == "insecure_configuration" and any(
            tok in str(pkg.get("title") or "").lower()
            for tok in ("cve-", "ghsa-", "dependency", "package", "advisory", "supply", "sbom", "library")
        ):
            supply_chain_count += 1

    cov_conf = radar["coverage_confidence"]
    status = report.get("status") or {}
    review_complete = bool(status.get("review_complete"))
    ship_by_status = (((report.get("summary") or {}).get("ship_block") or {}).get("by_status")) or {}

    blocking = int(ship_by_status.get("ship_blocking", 0)) + int(
        ship_by_status.get("ship_blocking_pending_distinct_verification", 0)
    )
    if blocking > 0:
        readiness = "BLOCK_RELEASE"
    elif not review_complete or int(cov_conf["gap_axes"]) > 0 or int(ship_by_status.get("decision_pending", 0)) > 0:
        readiness = "REVIEW_REQUIRED_GAPS_PRESENT"
    else:
        readiness = "READY_WITH_RESIDUAL_ACCEPTANCE"

    return {
        "release_readiness": readiness,
        "confirmed_by_severity": sev_counts,
        "chain_elevated_findings_count": chain_elevated_count,
        "reachable_supply_chain_advisories_count": supply_chain_count,
        "ship_blocking_count": blocking,
        "coverage_confidence_index": {
            "score": cov_conf["confidence_score"],
            "verified_axes": cov_conf["verified_axes"],
            "gap_axes": cov_conf["gap_axes"],
            "unverified_axis_ids": [ax["domain_id"] for ax in radar.get("axes", ()) if ax.get("coverage_status") in {"unverified_gap", "partial_coverage_gap"}],
            "statement": cov_conf["summary_statement"],
        },
    }


def _domain_id_for_pkg(pkg: Mapping[str, Any]) -> str:
    pred = predicate_of(pkg)
    if pred is not None:
        for dim in DIMENSIONS:
            if pred in dim.predicates:
                return dim.domain_id
    return "unclassified"


def build_attack_chain_cards(
    report: Mapping[str, Any], *, manifest_items: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    """Multi-Step Attack Chains & Trust-Boundary Breaches projection (`entry -> hop -> sink`)."""
    all_pkgs = (
        *(report.get("findings") or ()),
        *(report.get("verification_backlog") or ()),
        *(report.get("withheld") or ()),
    )
    by_claim = {str(pkg["claim_id"]): pkg for pkg in all_pkgs if pkg.get("claim_id")}
    by_chain = {row["chain_id"]: row for row in manifest_items}

    cards: list[dict[str, Any]] = []
    for ch in _chain_items(report):
        claim_ids = [str(cid) for cid in (ch.get("component_claim_ids") or ())]
        steps: list[dict[str, Any]] = []
        domains_seen: list[str] = []
        for idx, cid in enumerate(claim_ids):
            role = "entry" if idx == 0 else ("sink" if idx == len(claim_ids) - 1 else "hop")
            pkg = by_claim.get(cid)
            sev = _clean_sev(((pkg or {}).get("ship_block") or {}).get("technical_severity"))
            dom_id = _domain_id_for_pkg(pkg) if pkg else "unclassified"
            if dom_id != "unclassified" and dom_id not in domains_seen:
                domains_seen.append(dom_id)
            steps.append({
                "step_index": idx + 1,
                "role": role,
                "claim_id": cid,
                "finding_package_id": pkg.get("finding_package_id") if pkg else None,
                "title": str((pkg or {}).get("title") or cid),
                "domain_id": dom_id,
                "technical_severity": sev,
            })
        composed = _clean_sev(by_chain.get(ch["chain_id"], {}).get("composed_severity"))

        trust_boundary = (
            " -> ".join(domains_seen)
            if len(domains_seen) >= 2
            else (domains_seen[0] if domains_seen else "application_trust_boundary")
        )
        cards.append({
            "chain_id": str(ch["chain_id"]),
            "status": str(ch["status"]),
            "composed_severity": composed,
            "trust_boundary_crossed": trust_boundary,
            "step_count": len(steps),
            "steps": steps,
            "gap_count": int(ch.get("gap_count", 0)) + int(composed == "unrated"),
            "severity_gap": "chain_severity_unrated" if composed == "unrated" else None,
        })
    return cards


def build_remediation_roadmap(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Risk-first remediation roadmap (`critical` -> `high` -> `chain` -> quick-win dep/config -> rest)."""
    findings = report.get("findings") or ()
    val_rows = ((report.get("remediation_validation") or {}).get("items")) or ()
    plan_rows = ((report.get("remediation_planning") or {}).get("items")) or ()
    poc_rows = ((report.get("poc_outcomes") or {}).get("items")) or ()

    val_by_pkg = {str((r.get("finding") or {}).get("finding_package_id")): r for r in val_rows}
    plan_by_pkg = {str((r.get("finding") or {}).get("finding_package_id")): r for r in plan_rows}
    poc_by_pkg = {str(r.get("finding_package_id")): r for r in poc_rows}
    chain_claims = {
        str(cid)
        for ch in _chain_items(report)
        if ch.get("status") in _ACTIVE_CHAIN_STATUSES
        for cid in (ch.get("component_claim_ids") or ())
    }

    entries: list[tuple[tuple[int, int, str], dict[str, Any]]] = []
    for pkg in findings:
        pkg_id = str(pkg["finding_package_id"])
        cid = str(pkg["claim_id"])
        sev = _clean_sev((pkg.get("ship_block") or {}).get("technical_severity"))
        in_chain = cid in chain_claims
        dom_id = _domain_id_for_pkg(pkg)
        is_quick_win = dom_id in {
            "supply_chain_dependencies",
            "ci_cd_build_integrity",
            "container_deployment_hardening",
        }
        if sev == "critical":
            tier_rank, priority_tier = 0, "critical"
        elif sev == "high":
            tier_rank, priority_tier = 1, "high"
        elif in_chain:
            tier_rank, priority_tier = 2, "chain_elevated"
        elif is_quick_win:
            tier_rank, priority_tier = 3, "quick_win_dependency_or_config"
        else:
            tier_rank, priority_tier = 4, "residual_confirmed"

        val = val_by_pkg.get(pkg_id)
        plan = plan_by_pkg.get(pkg_id)
        raw_val_status = str((val or {}).get("status") or "")
        raw_plan_status = str((plan or {}).get("status") or "")
        if raw_val_status in {"build_checked", "validated_compile_only", "succeeded"}:
            validation_status = "build_checked"
        elif raw_val_status == "static_checked":
            validation_status = "static_checked"
        elif raw_val_status == "in_memory_patch_and_syntax_verified":
            validation_status = "in_memory_patch_and_syntax_verified"
        elif raw_plan_status in {"proposal_generated", "proposed"} and (plan or {}).get("plan") is not None:
            validation_status = "proposal_only"
        else:
            validation_status = "manual_design_required"

        poc = poc_by_pkg.get(pkg_id)
        raw_poc_status = str((poc or {}).get("status") or "")
        poc_status = (
            "compile_only_verified"
            if raw_poc_status == "compile_verified"
            else (raw_poc_status or "not_available")
        )
        sev_order = _SEVERITY_RANK.get(sev, 5)
        row = {
            "finding_package_id": pkg_id,
            "claim_id": cid,
            "title": str(pkg.get("title") or pkg_id),
            "priority_tier": priority_tier,
            "technical_severity": sev,
            "ship_block_status": str((pkg.get("ship_block") or {}).get("status") or "decision_pending"),
            "domain_id": dom_id,
            "chain_participating": in_chain,
            "validation_status": validation_status,
            "poc_posture": {
                "status": poc_status,
                "generated_code_execution": "not_performed_by_policy",
            },
        }
        entries.append(((tier_rank, sev_order, pkg_id), row))

    entries.sort(key=lambda pair: pair[0])
    return [{"rank": rank, **item} for rank, (_, item) in enumerate(entries, start=1)]


def build_named_coverage_gaps(
    limitations_or_report: Sequence[Mapping[str, Any]] | Mapping[str, Any],
    radar: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Explicit Named Coverage Gaps & Blind Spots Table."""
    limitations = (
        limitations_or_report.get("limitations") or ()
        if isinstance(limitations_or_report, Mapping)
        else limitations_or_report
    )
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for lim in limitations:
        if lim.get("kind") not in {"gap", "not_run"}:
            continue
        lid = str(lim["limitation_id"])
        if lid in seen:
            continue
        seen.add(lid)
        stmt = str(lim.get("statement") or "")
        category = (
            "syntactic_fallback_only"
            if "syntactic_fallback" in stmt.lower() or "syntactic fallback" in stmt.lower()
            else ("stage_not_run" if lim.get("kind") == "not_run" else "producer_or_review_gap")
        )
        rows.append({
            "gap_id": lid,
            "category": category,
            "affected_scope": str(lim.get("source") or lid.split(":", 1)[-1]),
            "disposition": "UNVERIFIED_GAP",
            "statement": stmt,
        })
    for axis in radar.get("axes") or ():
        if axis.get("coverage_status") in {"unverified_gap", "partial_coverage_gap"}:
            gid = f"radar_domain:{axis['domain_id']}"
            if gid in seen:
                continue
            seen.add(gid)
            rows.append({
                "gap_id": gid,
                "category": str(axis["coverage_status"]),
                "affected_scope": str(axis["label"]),
                "disposition": "UNVERIFIED_COVERAGE_GAP",
                "statement": (
                    f"{axis['label']} ({axis['key']}): verified coverage is "
                    f"{axis['series']['verified_coverage']['score']:.1f}% "
                    f"({axis['coverage_status']}). Missing or incomplete coverage is never evidence of cleanliness."
                ),
            })
    if isinstance(limitations_or_report, Mapping):
        for card in limitations_or_report.get("attack_chain_cards") or ():
            if card.get("severity_gap"):
                rows.append({
                    "gap_id": f"chain_severity_unrated:{card['chain_id']}",
                    "category": "producer_or_review_gap",
                    "affected_scope": card["chain_id"],
                    "disposition": "UNVERIFIED_GAP",
                    "statement": "The certified chain manifest does not provide a composed severity rating.",
                })
    return rows


__all__ = [
    "build_attack_chain_cards",
    "build_executive_posture",
    "build_named_coverage_gaps",
    "build_remediation_roadmap",
]
