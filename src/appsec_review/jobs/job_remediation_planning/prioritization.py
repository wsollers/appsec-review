"""Risk-first candidate ordering for remediation planning (T-174).

Orders confirmed findings by risk tier rather than alphabetical ``finding_id`` so capped runs
always remediate critical, high, chain-elevated and reachable medium findings before lower-risk
items, with deterministic tie-breaking by ``finding_id`` and ``claim_id``.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

PRIORITY_RANKING_SCHEMA = "appsec-review/remediation-priority-ranking/1"

_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "informational"})


def _normalized_severity(finding: Mapping[str, Any]) -> str:
    for key in ("technical_severity", "severity", "standalone_severity"):
        raw = finding.get(key)
        if isinstance(raw, str) and raw.strip().lower() in _VALID_SEVERITIES:
            return raw.strip().lower()
    return "informational"


def _composed_severity(finding: Mapping[str, Any]) -> str | None:
    raw = finding.get("composed_severity")
    if isinstance(raw, str) and raw.strip().lower() in _VALID_SEVERITIES:
        return raw.strip().lower()
    return None


def _is_chain_elevated(finding: Mapping[str, Any], standalone: str, composed: str | None) -> bool:
    if bool(finding.get("chain_elevated")):
        return True
    if composed in {"critical", "high"} and standalone not in {"critical"}:
        if composed == "critical" or standalone != "high":
            return True
    chain_ids = finding.get("chain_ids")
    if isinstance(chain_ids, Sequence) and not isinstance(chain_ids, (str, bytes)) and len(chain_ids) > 0:
        if standalone in {"medium", "low"}:
            return True
    return False


def _is_reachable(finding: Mapping[str, Any]) -> bool:
    if "reachable" in finding and isinstance(finding["reachable"], bool):
        return finding["reachable"]
    reach = finding.get("reachability")
    if isinstance(reach, str):
        return reach.strip().lower() in {"reachable", "confirmed", "verified", "direct", "true"}
    exploitability = finding.get("exploitability")
    if isinstance(exploitability, str) and exploitability.strip().lower() in {"unreachable", "none"}:
        return False
    return bool(finding.get("entry_points") or finding.get("poc") or finding.get("direct_evidence"))


def _numeric_score(finding: Mapping[str, Any]) -> float:
    for key in ("score", "risk_score", "priority_score", "cvss_score"):
        val = finding.get(key)
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return max(0.0, min(100.0, float(val)))
    scoring = finding.get("scoring")
    if isinstance(scoring, Mapping):
        for key in ("score", "risk_score", "composite_score"):
            val = scoring.get(key)
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                return max(0.0, min(100.0, float(val)))
    return 0.0


def _finding_identifier(finding: Mapping[str, Any]) -> str:
    for key in ("finding_id", "finding_package_id"):
        val = finding.get(key)
        if isinstance(val, str) and val:
            return val
    return ""


def finding_risk_sort_key(finding: Mapping[str, Any]) -> tuple[int, float, str, str]:
    """Compute deterministic risk-first sort key:

    0: critical (standalone or chain-composed critical)
    1: high (standalone)
    2: chain-elevated (e.g. medium+medium -> high/critical chain participant)
    3: reachable medium
    4: non-reachable medium
    5: low
    6: informational
    Within each tier: descending numeric score, then ascending ``finding_id`` and ``claim_id``.
    """
    standalone = _normalized_severity(finding)
    composed = _composed_severity(finding)
    chain_elevated = _is_chain_elevated(finding, standalone, composed)
    reachable = _is_reachable(finding)
    score = _numeric_score(finding)

    if standalone == "critical":
        tier = 0
    elif standalone == "high":
        tier = 1
    elif chain_elevated:
        tier = 2
    elif standalone == "medium" and reachable:
        tier = 3
    elif standalone == "medium":
        tier = 4
    elif standalone == "low":
        tier = 5
    else:
        tier = 6

    finding_id = _finding_identifier(finding)
    claim_id = str(finding.get("claim_id") or "")
    return (tier, -score, finding_id, claim_id)


def rank_findings_risk_first(findings: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Return ``findings`` sorted in strict risk-first order."""
    return sorted(findings, key=finding_risk_sort_key)


def build_priority_ranking_record(
    ranked_findings: Sequence[Mapping[str, Any]],
    *,
    max_candidates: int,
) -> dict[str, Any]:
    """Build ``appsec-review/remediation-priority-ranking/1`` artifact for auditability and telemetry."""
    cap = max(1, int(max_candidates))
    items: list[dict[str, Any]] = []
    for idx, finding in enumerate(ranked_findings, start=1):
        standalone = _normalized_severity(finding)
        composed = _composed_severity(finding)
        chain_elevated = _is_chain_elevated(finding, standalone, composed)
        reachable = _is_reachable(finding)
        score = _numeric_score(finding)
        finding_pkg_id = str(finding.get("finding_package_id") or finding.get("finding_id") or f"finding-{idx}")
        claim_id = str(finding.get("claim_id") or f"claim-{idx}")
        items.append({
            "rank": idx,
            "finding_package_id": finding_pkg_id,
            "claim_id": claim_id,
            "severity": standalone,
            "composed_severity": composed,
            "chain_elevated": chain_elevated,
            "reachable": reachable,
            "score": round(score, 4),
            "selected": idx <= cap,
        })
    selected_count = sum(1 for item in items if item["selected"])
    return {
        "schema": PRIORITY_RANKING_SCHEMA,
        "max_candidates": cap,
        "total_confirmed": len(items),
        "selected_count": selected_count,
        "capped_count": len(items) - selected_count,
        "items": items,
    }


__all__ = [
    "PRIORITY_RANKING_SCHEMA",
    "build_priority_ranking_record",
    "finding_risk_sort_key",
    "rank_findings_risk_first",
]
