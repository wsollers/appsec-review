"""Triage metrics: how much triage removed, and whether it removed the right things (section 5.2, T-062).

Doctrine:

* A triage outcome is not a label. Whether a lead was real comes from ``labels`` (answer key, audit
  sample, developer outcome, crash), never from the review's own dismissal.
* No ratio that can be maximised by doing nothing is emitted alone. A triage that dismisses every
  lead removes every false lead, so ``false_lead_removal`` is always computed beside
  ``true_lead_retention``, which that triage drives to zero. No combined "reduction" ratio is emitted.
* Silence (``no_claim_raised``) and a reasoned refutation (``dismissed_by_adjudication``) are
  different outcomes and are reported as separate ratios and separate stages.
* A lead that was never admitted was never triaged: it is counted and excluded from every ratio.
  An unresolved lead is neither retained nor removed.
* A missing input is ``unavailable(reason)``, never zero. Every proportion is over leads or controls,
  which are independent units, and carries a Wilson interval.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from appsec_review.observability.triage_reduction import DISPOSITIONS, REDUCED_DISPOSITIONS, SURVIVED_DISPOSITIONS

from .contracts import AUDIT_SAMPLE_SCHEMA, MAX_LEADS, TRIAGE_STAGES, LabelOutcome, ratio, unavailable

LEAD_FIELDS = ("lead_id", "admitted", "disposition", "removed_stage", "family", "scanner", "control_id")
SILENCE_DISPOSITION = "no_claim_raised"
SILENCE_STAGE = "red_no_proposal"

_OUTCOMES = tuple(item.value for item in LabelOutcome)
_TRUE, _FALSE, _UNRESOLVED = (LabelOutcome.TRUE.value, LabelOutcome.FALSE.value, LabelOutcome.UNRESOLVED.value)


def _count(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"triage reduction {name} must be a non-negative integer")
    return value


def split_ratios(section: Mapping[str, Any] | None) -> dict[str, Any]:
    """The ``triage_reduction`` disposition partition as separate ratios, never one "reduction".

    Over resolved leads (survived, dismissed or no claim raised): the share dismissed by
    adjudication, the share where no claim was raised, and the share that survived. Over admitted
    leads: the unresolved share, the pile a team has to triage by hand.
    """
    if not section or section.get("available") is not True:
        return unavailable("triage_reduction_unavailable")
    table = section.get("admitted_dispositions")
    if not isinstance(table, Mapping) or set(table) != set(DISPOSITIONS):
        raise ValueError("triage reduction section lacks the admitted disposition partition")
    dispositions = {name: _count(table[name], name) for name in DISPOSITIONS}
    admitted = sum(dispositions.values())
    leads = section.get("leads")
    if isinstance(leads, Mapping) and leads.get("admitted") is not None and leads["admitted"] != admitted:
        raise ValueError("triage reduction dispositions do not partition the admitted leads")
    survived = sum(dispositions[name] for name in SURVIVED_DISPOSITIONS)
    resolved = survived + sum(dispositions[name] for name in REDUCED_DISPOSITIONS)
    return {
        "available": True,
        "admitted": admitted,
        "resolved": resolved,
        "dismissed_over_resolved": ratio(dispositions["dismissed_by_adjudication"], resolved, interval=True),
        "no_claim_over_resolved": ratio(dispositions[SILENCE_DISPOSITION], resolved, interval=True),
        "survived_over_resolved": ratio(survived, resolved, interval=True),
        "unresolved_share": ratio(dispositions["unresolved"], admitted, interval=True),
        "accounting_complete": section.get("accounting_complete") is True,
    }


def _name(value: Any, name: str, *, optional: bool = True) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value or len(value) > 512 or "\n" in value or "\r" in value:
        raise ValueError(f"lead {name} must be a short single-line string")
    if optional and value == "null":
        raise ValueError(f"lead {name} 'null' is reserved for a value that was not established")
    return value


def _lead(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("a lead record must be an object")
    unknown = sorted(str(key) for key in set(value) - set(LEAD_FIELDS))
    if unknown:
        raise ValueError(f"lead record has unknown fields: {', '.join(unknown)}")
    lead_id = _name(value.get("lead_id"), "lead_id", optional=False)
    admitted, disposition, stage = value.get("admitted"), value.get("disposition"), value.get("removed_stage")
    if not isinstance(admitted, bool):
        raise ValueError(f"lead {lead_id!r} must state whether it was admitted")
    if disposition is not None and (not isinstance(disposition, str) or disposition not in DISPOSITIONS):
        raise ValueError(f"lead {lead_id!r} disposition {disposition!r} is outside the closed vocabulary")
    if stage is not None and (not isinstance(stage, str) or stage not in TRIAGE_STAGES):
        raise ValueError(f"lead {lead_id!r} removed_stage {stage!r} is outside the closed vocabulary")
    if admitted != (disposition is not None):
        raise ValueError(f"lead {lead_id!r}: an admitted lead has a disposition and an unadmitted lead has none")
    removed = disposition in REDUCED_DISPOSITIONS
    if removed != (stage is not None):
        raise ValueError(f"lead {lead_id!r}: a removed lead names the stage that removed it and no other lead does")
    if removed and (disposition == SILENCE_DISPOSITION) != (stage == SILENCE_STAGE):
        raise ValueError(f"lead {lead_id!r}: no claim raised is the red_no_proposal stage and nothing else is")
    return {"lead_id": lead_id, "admitted": admitted, "disposition": disposition, "removed_stage": stage,
            "family": _name(value.get("family"), "family"), "scanner": _name(value.get("scanner"), "scanner"),
            "control_id": _name(value.get("control_id"), "control_id"),
            "status": ("survived" if disposition in SURVIVED_DISPOSITIONS else "removed" if removed
                       else "unresolved" if admitted else None)}


def _leads(leads: Any) -> list[dict[str, Any]]:
    if isinstance(leads, (str, bytes, Mapping)) or not isinstance(leads, Iterable):
        raise ValueError("leads must be a sequence of lead records")
    rows: dict[str, dict[str, Any]] = {}
    for value in leads:
        if len(rows) >= MAX_LEADS:
            raise ValueError("more leads than the bounded number per triage computation")
        row = _lead(value)
        if row["lead_id"] in rows:
            raise ValueError(f"leads repeat lead id {row['lead_id']!r}")
        rows[row["lead_id"]] = row
    return [rows[lead_id] for lead_id in sorted(rows)]


def _outcomes(labels: Any) -> dict[str, str]:
    if not isinstance(labels, Mapping):
        raise ValueError("labels must map a lead id to a label")
    outcomes = {}
    for lead_id, label in labels.items():
        outcome = label.get("outcome") if isinstance(label, Mapping) else None
        if not isinstance(outcome, str) or outcome not in _OUTCOMES:
            raise ValueError(f"label of {lead_id!r} has an outcome outside the closed vocabulary")
        outcomes[lead_id] = outcome
    return outcomes


def _paired(rows: Iterable[Mapping[str, Any]], outcomes: Mapping[str, str]) -> dict[str, Any]:
    """Retention and removal over one group of admitted leads; always both."""
    tally = {(_TRUE, "survived"): 0, (_TRUE, "removed"): 0, (_FALSE, "survived"): 0, (_FALSE, "removed"): 0}
    true = false = 0
    for row in rows:
        outcome = outcomes.get(row["lead_id"])
        true += outcome == _TRUE
        false += outcome == _FALSE
        if (outcome, row["status"]) in tally:
            tally[(outcome, row["status"])] += 1
    return {
        "true_leads": true,
        "false_leads": false,
        "true_lead_retention": ratio(tally[(_TRUE, "survived")],
                                     tally[(_TRUE, "survived")] + tally[(_TRUE, "removed")], interval=True),
        "false_lead_removal": ratio(tally[(_FALSE, "removed")],
                                    tally[(_FALSE, "survived")] + tally[(_FALSE, "removed")], interval=True),
    }


def _grouped(rows: list[dict[str, Any]], field: str, outcomes: Mapping[str, str]) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault("null" if row[field] is None else row[field], []).append(row)
    return {key: _paired(groups[key], outcomes) for key in sorted(groups)}


def effectiveness(leads: Iterable[Mapping[str, Any]], labels: Mapping[str, Mapping[str, Any]] | None
                  ) -> dict[str, Any]:
    """Labelled triage effectiveness over admitted leads.

    ``true_lead_retention`` (labelled-true leads that survived / labelled-true leads resolved) is the
    counterweight of ``false_lead_removal`` (labelled-false leads removed / labelled-false leads
    resolved); they are always emitted together, overall and per family and scanner. An unresolved
    lead is in neither denominator. ``control_false_positive_rate`` is over distinct negative
    controls: those with a surviving lead / those with an admitted lead.
    """
    rows = _leads(leads)
    if labels is None:
        return unavailable("no_lead_labels")
    outcomes = _outcomes(labels)
    admitted = [row for row in rows if row["admitted"]]
    labelled = [row for row in admitted if row["lead_id"] in outcomes]
    true_by_stage = dict.fromkeys(TRIAGE_STAGES, 0)
    false_by_stage = dict.fromkeys(TRIAGE_STAGES, 0)
    unresolved = {_TRUE: 0, _FALSE: 0}
    survivors = {_TRUE: 0, _FALSE: 0}
    for row in labelled:
        outcome = outcomes[row["lead_id"]]
        if outcome not in survivors:
            continue
        if row["status"] == "removed":
            (true_by_stage if outcome == _TRUE else false_by_stage)[row["removed_stage"]] += 1
        elif row["status"] == "survived":
            survivors[outcome] += 1
        else:
            unresolved[outcome] += 1
    controls = {row["control_id"] for row in admitted if row["control_id"] is not None}
    reported = {row["control_id"] for row in admitted
                if row["control_id"] is not None and row["status"] == "survived"}
    known = {row["lead_id"] for row in rows}
    return {
        "available": True,
        "admitted": len(admitted),
        "labelled": len(labelled),
        "unlabelled": len(admitted) - len(labelled),
        "label_unresolved": sum(1 for row in labelled if outcomes[row["lead_id"]] == _UNRESOLVED),
        **_paired(admitted, outcomes),
        "true_leads_removed_by_stage": true_by_stage,
        "false_leads_removed_by_stage": false_by_stage,
        "true_leads_unresolved": unresolved[_TRUE],
        "false_leads_unresolved": unresolved[_FALSE],
        "retained_precision": ratio(survivors[_TRUE], survivors[_TRUE] + survivors[_FALSE], interval=True),
        "control_false_positive_rate": ratio(len(reported), len(controls), interval=True),
        "by_family": _grouped(admitted, "family", outcomes),
        "by_scanner": _grouped(admitted, "scanner", outcomes),
        "true_leads_not_admitted": sum(1 for row in rows
                                       if not row["admitted"] and outcomes.get(row["lead_id"]) == _TRUE),
        "labels_without_lead": sum(1 for lead_id in outcomes if lead_id not in known),
    }


def audit_miss_rate(sample: Mapping[str, Any], audit_labels: Mapping[str, Mapping[str, Any]] | None
                    ) -> dict[str, Any]:
    """Of the sampled removed leads a person decided, the share that were real after all.

    ``sample`` is an ``audit-sample/1`` export and ``audit_labels`` its admitted ``lead_id -> label``
    map. A sample member without a decided label is ``unresolved`` and outside the ratio. Misses are
    also split by how the lead was removed, so silence and refutation stay apart.
    """
    if not isinstance(sample, Mapping) or sample.get("schema") != AUDIT_SAMPLE_SCHEMA:
        raise ValueError("unsupported audit sample schema")
    members = sample.get("sample")
    if not isinstance(members, (list, tuple)):
        raise ValueError("audit sample members are invalid")
    dispositions: dict[str, str] = {}
    for member in members:
        lead_id = _name(member.get("lead_id") if isinstance(member, Mapping) else None, "lead_id", optional=False)
        if lead_id in dispositions or member.get("disposition") not in REDUCED_DISPOSITIONS:
            raise ValueError("audit sample repeats a lead or holds a lead that was not removed")
        dispositions[lead_id] = member["disposition"]      # type: ignore[index]
    if audit_labels is None:
        return unavailable("no_audit_labels")
    outcomes = _outcomes(audit_labels)
    outside = sorted(str(lead_id) for lead_id in set(outcomes) - set(dispositions))
    if outside:
        raise ValueError(f"audit labels name leads outside the sample: {', '.join(outside[:5])}")
    missed = dict.fromkeys(REDUCED_DISPOSITIONS, 0)
    false = 0
    for lead_id in sorted(dispositions):
        outcome = outcomes.get(lead_id, _UNRESOLVED)
        if outcome == _TRUE:
            missed[dispositions[lead_id]] += 1
        false += outcome == _FALSE
    true = sum(missed.values())
    return {
        "available": True,
        "sample_size": len(dispositions),
        "labelled_true": true,
        "labelled_false": false,
        "unresolved": len(dispositions) - true - false,
        "missed_by_disposition": missed,
        "miss_rate": ratio(true, true + false, interval=True),
    }


__all__ = ["LEAD_FIELDS", "SILENCE_DISPOSITION", "SILENCE_STAGE", "audit_miss_rate", "effectiveness",
           "split_ratios"]
