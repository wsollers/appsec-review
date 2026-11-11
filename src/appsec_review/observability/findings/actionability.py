"""Actionability: can a developer act on a finding as written? (finding-metrics.md section 5.9, T-069).

Per published finding, the presence of a resolving entry-to-sink path, stated preconditions, an
attacker position, an owner, a remediation, and whether the remediation was validated.

Doctrine:

* An item that was not established (``None``) is ``unknown``. It is never counted as present, and
  it is listed as missing for the finding, because the developer cannot act on it either way.
* Shares are over published findings, each carrying numerator, denominator and a Wilson interval.
  With no published finding a share has an empty denominator; it is never zero.
* Completeness is a property of the report as written. It is not a correctness label.
* Outputs are sorted and deterministic; inputs are never mutated.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .contracts import check_snapshot, is_published, ratio

MAX_PER_FINDING_ROWS = 500
ACTIONABILITY_FLAGS = ("entry_to_sink_path", "preconditions", "remediation", "remediation_validated")
ACTIONABILITY_ITEMS = (*ACTIONABILITY_FLAGS, "owner", "attacker_position")
# A validated remediation is reported but not required for a finding to be complete.
COMPLETENESS_ITEMS = tuple(item for item in ACTIONABILITY_ITEMS if item != "remediation_validated")


def _item_state(finding: Mapping[str, Any], item: str) -> str:
    """``present``, ``absent`` or ``unknown`` for one actionability item of one finding."""
    if item == "owner":
        owner = finding.get("owner")
        return "present" if isinstance(owner, str) and owner else "absent"
    if item == "attacker_position":
        return "absent" if finding.get("attacker_position") is None else "present"
    flag = (finding.get("actionability") or {}).get(item)
    return "unknown" if flag is None else "present" if flag else "absent"


def completeness(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Completeness shares over the published findings of a snapshot and the per-finding gaps.

    ``items`` gives ``present``, ``absent``, ``unknown`` and ``share`` (present / published) for
    each of ``ACTIONABILITY_ITEMS``. ``complete`` counts findings where every one of
    ``COMPLETENESS_ITEMS`` is present. ``per_finding`` lists, for at most ``MAX_PER_FINDING_ROWS``
    findings in ``finding_id`` order, the items of ``ACTIONABILITY_ITEMS`` that are absent or
    unknown; ``per_finding_truncated`` counts the rows left out.
    """
    published = sorted((finding for finding in check_snapshot(snapshot)["findings"] if is_published(finding)),
                       key=lambda finding: finding["finding_id"])
    tallies = {item: {"present": 0, "absent": 0, "unknown": 0} for item in ACTIONABILITY_ITEMS}
    complete: list[str] = []
    rows: list[dict[str, Any]] = []
    for finding in published:
        states = {item: _item_state(finding, item) for item in ACTIONABILITY_ITEMS}
        for item, state in states.items():
            tallies[item][state] += 1
        if all(states[item] == "present" for item in COMPLETENESS_ITEMS):
            complete.append(finding["finding_id"])
        rows.append({"finding_id": finding["finding_id"], "severity": finding.get("severity"),
                     "missing": sorted(item for item, state in states.items() if state != "present")})
    total = len(published)
    return {
        "available": True, "published": total,
        "items": {item: {**tallies[item], "share": ratio(tallies[item]["present"], total, interval=True)}
                  for item in ACTIONABILITY_ITEMS},
        "complete": {"count": len(complete), "share": ratio(len(complete), total, interval=True),
                     "finding_ids": complete},
        "per_finding": rows[:MAX_PER_FINDING_ROWS],
        "per_finding_truncated": max(0, len(rows) - MAX_PER_FINDING_ROWS),
    }


__all__ = ["ACTIONABILITY_FLAGS", "ACTIONABILITY_ITEMS", "COMPLETENESS_ITEMS", "MAX_PER_FINDING_ROWS", "completeness"]
