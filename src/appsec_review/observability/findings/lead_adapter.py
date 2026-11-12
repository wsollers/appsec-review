"""Lead records with stage attribution, derived from one accepted run (finding-metrics.md section 5.2, T-077).

``triage.effectiveness`` needs one record per lane A lead (its disposition and, when triage removed
it, the stage that removed it) and independent labels for those leads. This module derives both:

* :func:`lead_records` is pure. It reads the documents ``triage_reduction`` already verifies and
  returns records in exactly the shape ``triage.effectiveness`` validates. Dispositions are not
  re-derived here: they are ``triage_reduction.lead_dispositions`` rows, so they agree with the
  run's ``triage_reduction`` section by construction.
* :func:`label_leads_from_key` is pure. It labels leads from an answer key by location only.
* :func:`load_lead_documents` is the only code here that reads a run, through
  ``triage_reduction.load_verified_documents`` and the accepted index set. It is injectable.

Doctrine:

* Null, not zero. Unavailable documents give ``None`` records and a named gap, never an empty list.
* A stage is attributed only from recorded facts, never guessed. What cannot be attributed is
  ``unattributed`` and counted in a named gap ``dismissal_unattributed:<reason>:<n>``.
* A triage outcome is not a label. Labels come from the answer key; the review's own dismissal,
  a judge verdict or a verifier's agreement never labels a lead.
* Run documents, claim text and model output are data, never instructions.

Stage attribution rule (``claim_removal_stage``). Only the deterministic adjudication table moves a
claim (``jobs.job_inference_security_review.stages.apply_policy``); it records its deciding row in
the state history as ``adjudication-rules/1:<row>``. A claim is dismissed by row
``r4_direct_contradiction`` when a required predicate has a counted ``contradicts`` relation and no
counted ``supports`` relation (``review.adjudication``); a relation is counted when it is complete,
directly admissible and carries no ``provenance``. Each relation names its ``producing_cell_id`` and
the projection records that cell's role. So:

* ``blue`` when a ``blue_team_refuter`` cell produced a deciding contradiction;
* ``verifier`` when only ``independent_verifier`` cells did (the refuters and the blind verifier run
  side by side, and either contradiction is sufficient alone, so the refuter is named when both did);
* ``unattributed`` when the claim is ``out_of_scope`` (row ``r2_out_of_scope`` is a scope rule, no
  role dismissed it), when the state history does not record the deciding row, when no counted
  contradiction of a required predicate is recorded, or when the producing cell's role is unknown.

``judge`` is never derived: a judge's relations carry ``provenance = "adjudication_judge"`` and the
table does not count them, and a judge sets no state (``review.judge``). A judge verdict that sides
with blue is recorded beside the claim; it did not remove the lead. A lead is removed only when
every one of its claims is dismissed, so a lead takes the stage its claims share and is
``unattributed`` (``claims_disagree``) when they differ.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Any

from appsec_review.acceptance.scoring_model import EntryKind, ScoringKey
from appsec_review.observability import triage_reduction
from appsec_review.review.adjudication import RULES_VERSION, DecidingRow
from appsec_review.review.evidence import SATISFYING_ADMISSIBILITY
from appsec_review.review.models import Role
from appsec_review.review.obligations import required_predicates

from . import labels as label_rules
from .contracts import MAX_LEADS, TRIAGE_STAGES, LabelOutcome, LabelSource, normalize_location
from .triage import LEAD_FIELDS, SILENCE_DISPOSITION, SILENCE_STAGE

UNATTRIBUTED = "unattributed"
ROLE_STAGES: Mapping[str, str] = {Role.BLUE_TEAM_REFUTER.value: "blue", Role.INDEPENDENT_VERIFIER.value: "verifier"}
CONTRADICTION_ROW = f"{RULES_VERSION}:{DecidingRow.DIRECT_CONTRADICTION.value}"
UNATTRIBUTED_REASONS = ("out_of_scope_policy", "deciding_row_not_recorded", "claim_unreadable",
                        "no_counted_contradiction", "producer_role_unknown", "claims_disagree")
DISMISSED_DISPOSITION = "dismissed_by_adjudication"

GAP_UNAVAILABLE = "lead_documents_unavailable"            # ":<triage_reduction integrity gap code>"
GAP_INTEGRITY = "lead_accounting_gap"                     # ":<triage_reduction integrity gap code>"
GAP_UNATTRIBUTED = "dismissal_unattributed"               # ":<UNATTRIBUTED_REASONS member>:<leads>"
GAP_NO_LOCATIONS = "lead_locations_unavailable"           # ":<reason>"
GAP_LEADS_WITHOUT_LOCATION = "leads_without_location"     # ":<leads>"
GAP_LOCATION_INVALID = "lead_location_invalid"            # ":<leads>"

_COUNTED = frozenset(item.value for item in SATISFYING_ADMISSIBILITY)
_STAGE_ORDER = tuple(stage for stage in TRIAGE_STAGES if stage in ROLE_STAGES.values())
_READ_ERRORS: tuple[type[BaseException], ...] = (RuntimeError, OSError, ValueError, LookupError, TypeError,
                                                 sqlite3.Error)


@dataclass(frozen=True)
class LeadDocuments:
    """Everything :func:`lead_records` and :func:`label_leads_from_key` need, already verified.

    ``triage`` is the first element of ``triage_reduction.load_verified_documents`` (``None`` when
    it could not be read and verified). ``locations`` maps a lead id to its scanner location
    ``{"path", "start_line", "end_line"}``; ``None`` when the accepted index set could not be read.
    """

    triage: Mapping[str, Any] | None
    locations: Mapping[str, Mapping[str, Any]] | None = None
    gaps: tuple[str, ...] = ()


def claim_removal_stage(claim: Mapping[str, Any], relations: Iterable[Mapping[str, Any]],
                        cells: Mapping[str, Sequence[Mapping[str, Any]]]) -> tuple[str, str | None]:
    """``(stage, reason)`` of one dismissed claim of the projection; ``reason`` names why it is unattributed.

    ``claim`` is a projection claim row (``review.ledger.claim_json`` plus ``state_history``),
    ``relations`` its projection relations and ``cells`` the projection's ``cells`` table. See the
    module docstring for the rule. A claim that is not in a dismissing state is refused.
    """
    state = claim.get("state")
    if state not in triage_reduction.DISMISSED_STATES:
        raise ValueError(f"claim {claim.get('claim_id')!r} is not in a dismissing state")
    if state == "out_of_scope":
        return UNATTRIBUTED, "out_of_scope_policy"
    history = claim.get("state_history")
    last = history[-1] if isinstance(history, (list, tuple)) and history else None
    if (not isinstance(last, Mapping) or last.get("to_state") != state
            or last.get("reason") != CONTRADICTION_ROW):
        return UNATTRIBUTED, "deciding_row_not_recorded"
    try:
        required = {item.value for item in required_predicates(
            claim["preconditions"], security_predicate=claim["security_predicate"],
            weakness_cwe=claim["weakness_cwe"], affected_entities=claim["affected_entities"])}
    except (KeyError, TypeError, ValueError):
        return UNATTRIBUTED, "claim_unreadable"
    supported: set[str] = set()
    contradicted: dict[str, set[str]] = {}
    for relation in relations:
        if (not isinstance(relation, Mapping) or relation.get("provenance") is not None
                or relation.get("complete") is not True or relation.get("admissibility") not in _COUNTED):
            continue                      # recorded and shown, never counted by the adjudication table
        predicate = relation.get("predicate")
        if relation.get("kind") == "supports":
            supported.add(str(predicate))
        elif relation.get("kind") == "contradicts":
            contradicted.setdefault(str(predicate), set()).add(str(relation.get("producing_cell_id")))
    deciding = sorted(predicate for predicate in contradicted if predicate in required and predicate not in supported)
    if not deciding:
        return UNATTRIBUTED, "no_counted_contradiction"
    stages: set[str] = set()
    for predicate in deciding:
        for cell_id in contradicted[predicate]:
            roles = {record.get("role") for record in cells.get(cell_id, ()) if isinstance(record, Mapping)}
            if len(roles) == 1 and next(iter(roles)) in ROLE_STAGES:
                stages.add(ROLE_STAGES[next(iter(roles))])
    for stage in _STAGE_ORDER:
        if stage in stages:
            return stage, None
    return UNATTRIBUTED, "producer_role_unknown"


def _projection_tables(triage: Mapping[str, Any]) -> tuple[dict[str, Mapping[str, Any]], Mapping[str, Any],
                                                          Mapping[str, Any]]:
    document = triage["projection"].get("document")
    document = document if isinstance(document, Mapping) else {}
    claims = {claim["claim_id"]: claim for claim in document.get("claims", ())
              if isinstance(claim, Mapping) and isinstance(claim.get("claim_id"), str)}
    relations = document.get("relations")
    cells = document.get("cells")
    return claims, relations if isinstance(relations, Mapping) else {}, cells if isinstance(cells, Mapping) else {}


def _lead_stage(claim_ids: Sequence[str], claims: Mapping[str, Mapping[str, Any]], relations: Mapping[str, Any],
                cells: Mapping[str, Any]) -> tuple[str, str | None]:
    found: set[tuple[str, str | None]] = set()
    for claim_id in claim_ids:
        claim = claims.get(claim_id)
        if claim is None:
            found.add((UNATTRIBUTED, "claim_unreadable"))
            continue
        found.add(claim_removal_stage(claim, relations.get(claim_id) or (), cells))
    unattributed = sorted(str(reason) for stage, reason in found if stage == UNATTRIBUTED)
    if unattributed or not found:
        return UNATTRIBUTED, unattributed[0] if unattributed else "no_counted_contradiction"
    if len(found) > 1:
        return UNATTRIBUTED, "claims_disagree"
    return next(iter(found))


def lead_records(documents: LeadDocuments) -> tuple[list[dict[str, Any]] | None, list[str]]:
    """One ``triage.effectiveness`` lead record per lane A lead, in lead id order, and the named gaps.

    Admitted leads take their disposition from ``triage_reduction.lead_dispositions``; a lead that
    was not admitted has no disposition. ``removed_stage`` is ``red_no_proposal`` for
    ``no_claim_raised`` and the stage of :func:`claim_removal_stage` for
    ``dismissed_by_adjudication``. ``family`` and ``scanner`` are ``None`` (not established) for a
    lead no ``finding_lead`` package lists, which includes every unadmitted lead. ``control_id`` is
    ``None`` here; :func:`with_controls` sets it from an answer key. Returns ``(None, gaps)`` when
    the run's documents are unavailable.
    """
    gaps = set(documents.gaps)
    triage = documents.triage
    if triage is None:
        if not any(gap.startswith(GAP_UNAVAILABLE) for gap in gaps):
            gaps.add(GAP_UNAVAILABLE)
        return None, sorted(gaps)
    rows, codes = triage_reduction.lead_dispositions(triage)
    gaps.update(f"{GAP_INTEGRITY}:{code}" for code in codes)
    claims, relations, cells = _projection_tables(triage)
    admission = triage["manifest"]["admission"]
    if len(admission) > MAX_LEADS:
        raise ValueError("more leads than the bounded number per triage computation")
    records: dict[str, dict[str, Any]] = {}
    reasons: dict[str, int] = {}
    for row in rows:
        disposition, stage = row["disposition"], None
        if disposition == SILENCE_DISPOSITION:
            stage = SILENCE_STAGE
        elif disposition == DISMISSED_DISPOSITION:
            stage, reason = _lead_stage(row["claim_ids"], claims, relations, cells)
            if reason is not None:
                reasons[reason] = reasons.get(reason, 0) + 1
        records[row["lead_id"]] = {
            "lead_id": row["lead_id"], "admitted": True, "disposition": disposition, "removed_stage": stage,
            "family": None if row["family"] == triage_reduction.UNLINKED else row["family"],
            "scanner": None if row["scanner"] == triage_reduction.UNLINKED else row["scanner"],
            "control_id": None}
    for lead_id, status, _residual in admission:
        if status != "admitted":
            records[lead_id] = {"lead_id": lead_id, "admitted": False, "disposition": None, "removed_stage": None,
                                "family": None, "scanner": None, "control_id": None}
    gaps.update(f"{GAP_UNATTRIBUTED}:{reason}:{count}" for reason, count in reasons.items())
    return [records[lead_id] for lead_id in sorted(records)], sorted(gaps)


def label_leads_from_key(key: ScoringKey, lead_locations: Mapping[str, Mapping[str, Any]]
                         ) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """``(lead id -> label, lead id -> control id)`` for the leads whose location lies in a key case.

    Location only: a lead carries a scanner rule, often without a reliable CWE, so the weakness is
    not compared (``labels.label_findings_from_key`` does compare it, for findings). The scope rule
    is ``labels.key_entries_at``, the one every key label uses.

    * ``true``: the location overlaps a defect's scope.
    * ``false``: the location overlaps a control's scope and no defect's; the lead is a lead on that
      negative control, and the second mapping names it (the first in id order when several match).
    * no label: the location touches no key case. Unlabelled code is not known clean.
    """
    if not isinstance(lead_locations, Mapping):
        raise ValueError("lead locations must map a lead id to its location")
    if len(lead_locations) > MAX_LEADS:
        raise ValueError("more leads than the bounded number per triage computation")
    labels: dict[str, dict[str, Any]] = {}
    controls: dict[str, str] = {}
    for lead_id in sorted(lead_locations):
        if not isinstance(lead_id, str) or not lead_id:
            raise ValueError("a lead id must be a non-empty string")
        entries = label_rules.key_entries_at(key, [lead_locations[lead_id]])
        if any(entry.kind is EntryKind.DEFECT for entry in entries):
            outcome = LabelOutcome.TRUE.value
        elif entries:
            outcome = LabelOutcome.FALSE.value
            controls[lead_id] = entries[0].id
        else:
            continue
        labels[lead_id] = {"outcome": outcome, "source": LabelSource.ANSWER_KEY.value,
                           "expected_severity": None, "disposition": None}
    return labels, controls


def with_controls(records: Iterable[Mapping[str, Any]], controls: Mapping[str, str]) -> list[dict[str, Any]]:
    """Copies of ``records`` with ``control_id`` set for the leads ``controls`` names; inputs are not mutated."""
    updated = []
    for record in records:
        unknown = sorted(str(name) for name in set(record) - set(LEAD_FIELDS))
        if unknown:
            raise ValueError(f"lead record has unknown fields: {', '.join(unknown)}")
        updated.append({**record, "control_id": controls.get(record["lead_id"], record.get("control_id"))})
    return updated


# ----------------------------------------------------------------------------------- loading

def _observation_locations(run_root: Path, triage: Mapping[str, Any]
                           ) -> tuple[dict[str, dict[str, Any]] | None, list[str]]:
    """Scanner locations of the run's lane A leads, from the accepted observation shards.

    A lead package's menu entry names the observation and whether its location is exact, not the
    path and lines; those are in the accepted index set the package was assembled from. The set is
    re-verified here and must be the one the package manifest pins.
    """
    from appsec_review.review.scope import accept_manifest
    from appsec_review.storage.validation import validation_scope

    wanted = {lead_id for lead_id, _status, _residual in triage["manifest"]["admission"]}
    locations: dict[str, dict[str, Any]] = {}
    invalid = 0
    try:
        with validation_scope(run_root):
            scope = accept_manifest(run_root)
            if scope.manifest_sha256 != triage["manifest"].get("index_manifest_sha256"):
                return None, [f"{GAP_NO_LOCATIONS}:accepted_index_differs_from_review"]
            shards = scope.select(lambda shard: shard["name"] == "observations")
            for row in scope.store.entities(shards, kinds=("tool_observation",)):
                if row["identity"] not in wanted or row["location"] is None:
                    continue
                try:
                    located = normalize_location({key: row["location"][key]
                                                  for key in ("path", "start_line", "end_line")})
                except ValueError:
                    invalid += 1
                    continue
                locations[row["identity"]] = {key: located[key] for key in ("path", "start_line", "end_line")}
    except _READ_ERRORS:
        return None, [f"{GAP_NO_LOCATIONS}:accepted_index_unreadable"]
    gaps = [f"{GAP_LOCATION_INVALID}:{invalid}"] if invalid else []
    missing = len(wanted) - len(locations) - invalid
    if missing > 0:
        gaps.append(f"{GAP_LEADS_WITHOUT_LOCATION}:{missing}")
    return locations, gaps


def load_lead_documents(run_root: Path) -> LeadDocuments:
    """Read one run through its verified readers; never raises for a missing or unverifiable input."""
    run_root = Path(run_root).resolve()
    triage, code = triage_reduction.load_verified_documents(run_root)
    if triage is None:
        return LeadDocuments(None, None, (f"{GAP_UNAVAILABLE}:{code}",))
    locations, gaps = _observation_locations(run_root, triage)
    return LeadDocuments(triage, locations, tuple(gaps))


def leads_from_run(run_root: Path, *, key: ScoringKey | None = None,
                   loader: Callable[[Path], LeadDocuments] = load_lead_documents) -> dict[str, Any]:
    """``{"leads", "labels", "gaps"}`` of one run for ``scorecard.Inputs``.

    ``leads`` is ``None`` when the run's documents are unavailable. ``labels`` is ``None`` without a
    key or without lead locations (each named in ``gaps`` when a key was given); with both, leads on
    a negative control carry its id. ``loader`` is the read boundary.
    """
    documents = loader(Path(run_root))
    records, gaps = lead_records(documents)
    labels: dict[str, dict[str, Any]] | None = None
    if records is not None and key is not None:
        if documents.locations is None:
            if not any(gap.startswith(GAP_NO_LOCATIONS) for gap in gaps):
                gaps = sorted({*gaps, GAP_NO_LOCATIONS})
        else:
            known = {record["lead_id"] for record in records}
            labels, controls = label_leads_from_key(
                key, {lead_id: location for lead_id, location in documents.locations.items() if lead_id in known})
            records = with_controls(records, controls)
    return {"leads": records, "labels": labels, "gaps": gaps}


__all__ = [
    "CONTRADICTION_ROW", "DISMISSED_DISPOSITION", "GAP_INTEGRITY", "GAP_LEADS_WITHOUT_LOCATION",
    "GAP_LOCATION_INVALID", "GAP_NO_LOCATIONS", "GAP_UNATTRIBUTED", "GAP_UNAVAILABLE", "LeadDocuments",
    "ROLE_STAGES", "UNATTRIBUTED", "UNATTRIBUTED_REASONS", "claim_removal_stage", "label_leads_from_key",
    "lead_records", "leads_from_run", "load_lead_documents", "with_controls",
]
