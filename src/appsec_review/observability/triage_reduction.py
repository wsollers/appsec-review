"""Per-run triage reduction: admitted scanner leads versus what survives review.

The ``triage_reduction`` run-metrics section answers the before/after-triage question for lane A
(``Lane.LEAD``): of the scanner leads admitted for review, how many survived as supported or
confirmed claims, how many were dismissed by adjudication, how many the red cells examined and
raised no claim for, and how many remain unresolved.

Doctrine:

* A dismissed or no-claim lead is a triage outcome, never a confirmed false positive.
* A lead that was never admitted was never triaged. It is reported as unreviewed, by its
  ``residual_coverage``, and is excluded from every ratio.
* An unresolved lead (blocked, unaccounted, insufficient evidence, coverage gap, non-final claim,
  or a proposal without a linked claim) never counts as reduced. Any unresolved lead, an
  incomplete review, or an integrity gap sets ``accounting_complete`` to false.
* Unavailable inputs yield ``available: false`` with null counts, never zero, and named
  ``integrity_gap_codes``.
* Lane B (hunt) claims are not scanner-derived; their count is reported as excluded.

Section shape (``TRIAGE_REDUCTION_SCHEMA``)::

    {
      "schema": TRIAGE_REDUCTION_SCHEMA,
      "available": bool,
      "scope": SCOPE,
      "sources": {<name>: {"path": str, "sha256": str}} | None,
      "leads": {"collected": int|None, "admitted": int|None, "not_admitted": int|None,
                "not_admitted_by_residual_coverage": {<residual_coverage>: int} | None,
                "non_lead_observations": int|None},
      "admitted_dispositions": {<DISPOSITIONS>: int|None},
      "dismissed_by_claim_state": {<DISMISSED_STATES>: int|None},
      "unresolved_by_reason": {<UNRESOLVED_REASONS>: int|None},
      "hunt_lane_claims_excluded": int|None,
      "reduction": {"ratio_over_resolved": float|None, "lower_bound_over_admitted": float|None,
                    "resolved_denominator": int|None, "admitted_denominator": int|None},
      "by_family": {<lead_family>: {"admitted": int, <DISPOSITIONS>: int}} | None,
      "by_scanner": {<scanner>: {"admitted": int, <DISPOSITIONS>: int}} | None,
      "review_incomplete": bool|None,
      "accounting_complete": bool,
      "integrity_gap_codes": [<INTEGRITY_GAP_CODES>, ...],
      "interpretation": INTERPRETATION,
    }

Ratios:

* ``ratio_over_resolved`` = (dismissed_by_adjudication + no_claim_raised) /
  (survived_confirmed + survived_supported + dismissed_by_adjudication + no_claim_raised).
* ``lower_bound_over_admitted`` = (dismissed_by_adjudication + no_claim_raised) / admitted;
  unresolved leads count as not reduced.
* Each ratio is null when its denominator is zero or the section is unavailable.

Sources and linkage (``triage_reduction_metrics``):

* Only run-owned artifacts bound by the accepted ``job_inference_security_review`` handoff are read,
  each re-hashed against its reference: the review handoff (``publication.publish_handoff``), the
  lane A package set and its verified package manifest (``packages.assemble_lead_packages``), the
  lane A document (``lead_review.teams``, which carries ``lead_accounting`` and ``proposals``), and
  the claim ledger receipt with its sibling projection (``publication.publish_claim_ledger``). The
  manifest and the receipt are also cross-checked against the review handoff. No target is scanned.
* Each admitted lead maps to its ``finding_lead`` package through the package's lead menu and takes
  its red outcome from the lane A ``lead_accounting``. A ``proposal`` lead's claims are those the
  lane document's ``proposals`` attributes to the package, lane A claims carrying the package id,
  and claims whose origin cells ran on the package; a ``duplicate`` claim is replaced by the claim
  its ``duplicate_of`` chain ends at.
* ``dismissed_by_claim_state`` counts each distinct dismissing state once per dismissed lead, so a
  lead dismissed by claims in two states increments both and the sum may exceed
  ``dismissed_by_adjudication``.
* ``hunt_lane_claims_excluded`` counts every lane B claim record in the projection, duplicates
  included.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

TRIAGE_REDUCTION_SCHEMA = "appsec-review/triage-reduction-metrics/1"
SCOPE = "lane_a_scanner_leads"
INTERPRETATION = ("triage outcomes for admitted scanner leads; dismissed and no-claim leads are not "
                  "confirmed false positives, and unresolved or unadmitted leads are never counted as reduced")

DISPOSITIONS = ("survived_confirmed", "survived_supported", "dismissed_by_adjudication",
                "no_claim_raised", "unresolved")
SURVIVED_DISPOSITIONS = ("survived_confirmed", "survived_supported")
REDUCED_DISPOSITIONS = ("dismissed_by_adjudication", "no_claim_raised")

# Final claim states that dismiss a lead's claim. ``duplicate`` resolves to its canonical claim.
DISMISSED_STATES = ("contradicted", "not_reachable", "not_exploitable_in_observed_configuration",
                    "out_of_scope")
# Final claim states that leave the lead's question open.
UNRESOLVED_CLAIM_STATES = ("insufficient_evidence", "coverage_gap", "proposed")

UNRESOLVED_REASONS = ("blocked", "unaccounted", "insufficient_evidence", "coverage_gap",
                      "claim_not_final", "proposal_without_claim")

INTEGRITY_GAP_CODES = (
    "review_handoff_unavailable",      # no accepted, hash-verified inference review handoff
    "lead_manifest_unavailable",       # lead package manifest missing or failed verification
    "lane_document_unavailable",       # lane A document missing or failed verification
    "claim_projection_unavailable",    # claim ledger projection missing or failed verification
    "lead_outcome_mismatch",           # per-lead outcomes disagree with handoff leads_by_outcome
    "lead_outcome_missing",            # an admitted lead has no red outcome
    "lead_package_unlinked",           # an admitted lead has no finding_lead package
    "duplicate_unresolved",            # a duplicate claim does not resolve to a canonical claim
    "review_incomplete",               # handoff accounting marks lane A review incomplete
    # Appended by the metric computation: a lane A proposal names a claim the projection lacks.
    "proposal_claim_missing",
)


def empty_dispositions() -> dict[str, int]:
    return dict.fromkeys(DISPOSITIONS, 0)


def unavailable_section(codes: Iterable[str]) -> dict[str, Any]:
    """The section when its inputs cannot be read and verified: null counts, named gaps."""
    gap_codes = sorted(set(codes))
    unknown = [code for code in gap_codes if code not in INTEGRITY_GAP_CODES]
    if unknown or not gap_codes:
        raise ValueError(f"unavailable triage reduction needs known integrity gap codes: {unknown or gap_codes}")
    return {
        "schema": TRIAGE_REDUCTION_SCHEMA,
        "available": False,
        "scope": SCOPE,
        "sources": None,
        "leads": {"collected": None, "admitted": None, "not_admitted": None,
                  "not_admitted_by_residual_coverage": None, "non_lead_observations": None},
        "admitted_dispositions": dict.fromkeys(DISPOSITIONS),
        "dismissed_by_claim_state": dict.fromkeys(DISMISSED_STATES),
        "unresolved_by_reason": dict.fromkeys(UNRESOLVED_REASONS),
        "hunt_lane_claims_excluded": None,
        "reduction": {"ratio_over_resolved": None, "lower_bound_over_admitted": None,
                      "resolved_denominator": None, "admitted_denominator": None},
        "by_family": None,
        "by_scanner": None,
        "review_incomplete": None,
        "accounting_complete": False,
        "integrity_gap_codes": gap_codes,
        "interpretation": INTERPRETATION,
    }


REVIEW_JOB = "job_inference_security_review"
_REVIEW_OUTPUT_SCHEMA = "appsec-review/inference-security-review/1"
_REVIEW_HANDOFF_SCHEMA = "appsec-review/inference-review-handoff/3"
_LANE_PACKAGES_SCHEMA = "appsec-review/inference-review-lane-packages/1"
_LANE_SCHEMA = "appsec-review/inference-review-lane/1"
_RECEIPT_SCHEMA = "appsec-review/claim-ledger-head/1"
_PROJECTION_SCHEMA = "appsec-review/claim-projection/1"
_LEAD_OUTCOMES = ("proposal", "no_proposal", "blocked", "unaccounted")
UNLINKED = "(unlinked)"            # family and scanner of an admitted lead no finding_lead package lists
_UNLINKED = UNLINKED
_READ_ERRORS: tuple[type[BaseException], ...] = (ValueError, OSError, KeyError, TypeError, AttributeError)


class _Unavailable(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise _Unavailable(code)


def _ref(value: Any, code: str) -> dict[str, str]:
    _require(isinstance(value, Mapping) and isinstance(value.get("path"), str)
             and isinstance(value.get("sha256"), str), code)
    return {"path": value["path"], "sha256": value["sha256"]}


def _output_ref(outputs: Mapping[str, Any], unit_id: str, code: str) -> dict[str, str]:
    output = outputs.get(unit_id)
    _require(isinstance(output, Mapping), code)
    return _ref(output.get("artifact"), code)


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator > 0 else None


def _stage(code: str, load, *args):
    """Run one verified read; any read or verification failure names the stage's gap code."""
    from appsec_review.review.models import IntegrityError
    try:
        return load(*args)
    except _Unavailable:
        raise
    except (IntegrityError, *_READ_ERRORS) as exc:
        raise _Unavailable(code) from exc


def _load_review(run_root: Path) -> dict[str, Any]:
    from appsec_review.indexing.store import accepted_handoff
    from appsec_review.jobs.bound_artifacts import read_bound_json

    code = "review_handoff_unavailable"
    accepted = accepted_handoff(run_root, REVIEW_JOB)
    _require(accepted is not None and accepted.handoff.get("job_id") == REVIEW_JOB, code)
    outputs = accepted.handoff.get("outputs")
    _require(isinstance(outputs, Mapping), code)
    published = outputs.get("publication.publish_handoff")
    _require(isinstance(published, Mapping) and published.get("schema") == _REVIEW_OUTPUT_SCHEMA, code)
    review_ref = _ref(published.get("artifact"), code)
    review = read_bound_json(run_root, review_ref)
    _require(isinstance(review, Mapping) and review.get("schema") == _REVIEW_HANDOFF_SCHEMA
             and review.get("run_id") == run_root.name, code)
    lanes = [lane for lane in review["accounting"]["lanes"] if lane.get("lane") == "lead"]
    _require(len(lanes) == 1, code)
    by_outcome = lanes[0]["leads_by_outcome"]
    _require(isinstance(by_outcome, Mapping) and isinstance(lanes[0]["review_incomplete"], bool), code)
    return {
        "outputs": outputs,
        "lead_package_manifest_sha256": review.get("lead_package_manifest_sha256"),
        "projection_sha256": review["projection_sha256"],
        "ledger_head_sha256": review["ledger_head_sha256"],
        "leads_by_outcome": {outcome: int(by_outcome.get(outcome, 0)) for outcome in _LEAD_OUTCOMES},
        "review_incomplete": lanes[0]["review_incomplete"],
        "sources": {"job_handoff": {"path": accepted.path, "sha256": accepted.sha256},
                    "review_handoff": review_ref},
    }


def _load_manifest(run_root: Path, review: Mapping[str, Any]) -> dict[str, Any]:
    from appsec_review.jobs.bound_artifacts import read_bound_json, resolve_bound
    from appsec_review.review.packages import verify_package_manifest

    code = "lead_manifest_unavailable"
    set_ref = _output_ref(review["outputs"], "packages.assemble_lead_packages", code)
    document = read_bound_json(run_root, set_ref)
    _require(isinstance(document, Mapping) and document.get("schema") == _LANE_PACKAGES_SCHEMA
             and document.get("lane") == "lead", code)
    manifest_ref = _ref(document.get("package_manifest"), code)
    manifest_path = resolve_bound(run_root, manifest_ref)
    manifest = verify_package_manifest(manifest_path)       # content hash and every package's bytes
    _require(manifest["content_sha256"] == document.get("package_manifest_content_sha256")
             == review["lead_package_manifest_sha256"], code)
    admission = []
    for row in manifest["admission"]:
        _require(isinstance(row.get("lead_id"), str) and row.get("status") in ("admitted", "not_admitted")
                 and isinstance(row.get("residual_coverage"), str), code)
        admission.append((row["lead_id"], row["status"], row["residual_coverage"]))
    _require(len({lead_id for lead_id, _, _ in admission}) == len(admission), code)
    packages_dir = PurePosixPath(manifest_ref["path"]).parent / "packages"
    lead_packages: dict[str, list[tuple[str, str, str]]] = {}
    for entry in manifest["packages"]:
        if entry.get("kind") != "finding_lead" or entry.get("lane") != "lead":
            continue
        body = read_bound_json(run_root, {"path": (packages_dir / f"{entry['package_id']}.json").as_posix(),
                                          "sha256": entry["sha256"]})
        lead_packages[entry["package_id"]] = [
            (str(lead["observation_id"]), str(lead.get("lead_family") or _UNLINKED),
             str(lead.get("scanner") or _UNLINKED)) for lead in body["lead_menu"]]
    non_lead = manifest["counts"]["non_lead_observations"]
    non_lead_total = sum(int(value) for value in non_lead.values()) if isinstance(non_lead, Mapping) else int(non_lead)
    return {"admission": admission, "lead_packages": lead_packages, "non_lead_observations": non_lead_total,
            "index_manifest_sha256": manifest.get("manifest_sha256"),      # the accepted index set the leads came from
            "sources": {"lead_packages": set_ref, "lead_package_manifest": manifest_ref}}


def _load_lane(run_root: Path, review: Mapping[str, Any]) -> dict[str, Any]:
    from appsec_review.jobs.bound_artifacts import read_bound_json

    code = "lane_document_unavailable"
    lane_ref = _output_ref(review["outputs"], "lead_review.teams", code)
    document = read_bound_json(run_root, lane_ref)
    _require(isinstance(document, Mapping) and document.get("schema") == _LANE_SCHEMA
             and document.get("lane") == "lead", code)
    accounting: dict[str, dict[str, Any]] = {}
    for package_id, leads in document["lead_accounting"].items():
        accounting[str(package_id)] = {
            str(lead): (summary.get("outcome") if isinstance(summary, Mapping) else summary)
            for lead, summary in leads.items()}
    proposals = {str(claim_id): tuple(str(item) for item in packages)
                 for claim_id, packages in document["proposals"].items()}
    return {"lead_accounting": accounting, "proposals": proposals, "sources": {"lane_document": lane_ref}}


def _load_projection(run_root: Path, review: Mapping[str, Any]) -> dict[str, Any]:
    from appsec_review.jobs.bound_artifacts import read_bound_json

    code = "claim_projection_unavailable"
    receipt_ref = _output_ref(review["outputs"], "publication.publish_claim_ledger", code)
    receipt = read_bound_json(run_root, receipt_ref)
    _require(isinstance(receipt, Mapping) and receipt.get("schema") == _RECEIPT_SCHEMA
             and receipt.get("projection_sha256") == review["projection_sha256"]
             and receipt.get("ledger_head_sha256") == review["ledger_head_sha256"], code)
    projection_ref = {"path": (PurePosixPath(receipt_ref["path"]).parent / "projection.json").as_posix(),
                      "sha256": receipt.get("projection_file_sha256")}
    projection = read_bound_json(run_root, projection_ref)
    _require(isinstance(projection, Mapping) and projection.get("schema") == _PROJECTION_SCHEMA
             and projection.get("ledger_head_sha256") == review["ledger_head_sha256"], code)
    claims = {}
    for claim in projection["claims"]:
        _require(isinstance(claim.get("claim_id"), str) and isinstance(claim.get("state"), str), code)
        claims[claim["claim_id"]] = {"lane": claim["lane"], "package_id": claim["package_id"],
                                     "state": claim["state"], "duplicate_of": claim.get("duplicate_of"),
                                     "origin_cell_ids": tuple(claim.get("origin_cell_ids") or ())}
    cells = {str(cell_id): {str(record["package_id"]) for record in records}
             for cell_id, records in projection["cells"].items()}
    # ``document`` is the verified projection itself, for adapters that read what the section does
    # not (relations, cell roles, state history); the section never reads it.
    return {"claims": claims, "cell_packages": cells, "document": projection,
            "sources": {"claim_ledger_receipt": receipt_ref, "claim_projection": projection_ref}}


def _canonical(claim_id: str, claims: Mapping[str, Mapping[str, Any]]) -> str | None:
    """Follow ``duplicate_of`` to the claim it ends at; ``None`` when the chain breaks or cycles."""
    seen = set()
    while claim_id in claims and claims[claim_id]["state"] == "duplicate":
        if claim_id in seen:
            return None
        seen.add(claim_id)
        target = claims[claim_id]["duplicate_of"]
        if not isinstance(target, str):
            return None
        claim_id = target
    return claim_id if claim_id in claims else None


def _claims_by_package(lane: Mapping[str, Any], projection: Mapping[str, Any]) -> dict[str, set[str]]:
    """Package id -> claims linked to it: lane proposals, lane A claim packages, origin-cell packages."""
    index: dict[str, set[str]] = {}
    for claim_id, owners in lane["proposals"].items():
        for package_id in owners:
            index.setdefault(package_id, set()).add(claim_id)
    for claim_id, claim in projection["claims"].items():
        packages = {package_id for cell in claim["origin_cell_ids"]
                    for package_id in projection["cell_packages"].get(cell, ())}
        if claim["lane"] == "lead" and isinstance(claim["package_id"], str):
            packages.add(claim["package_id"])
        for package_id in packages:
            index.setdefault(package_id, set()).add(claim_id)
    return index


def _linked_claims(packages: Iterable[str], index: Mapping[str, set[str]]) -> set[str]:
    return {claim_id for package_id in packages for claim_id in index.get(package_id, ())}


def _proposal_disposition(claim_ids: set[str], projection: Mapping[str, Any], gaps: set[str]
                          ) -> tuple[str, str | None, set[str], set[str]]:
    """(disposition, unresolved reason, dismissing states, deciding canonical claims) of a proposing lead.

    The deciding claims are the canonical claims in the state that decided the disposition: the
    confirmed (else supported) ones of a surviving lead, every claim of a dismissed lead, none of an
    unresolved one.
    """
    claims = projection["claims"]
    resolved: dict[str, str] = {}
    not_final = False
    for claim_id in claim_ids:
        if claim_id not in claims:
            gaps.add("proposal_claim_missing")
            not_final = True
            continue
        canonical = _canonical(claim_id, claims)
        if canonical is None:
            gaps.add("duplicate_unresolved")
            not_final = True
            continue
        resolved[canonical] = claims[canonical]["state"]
    states = set(resolved.values())
    if not claim_ids:
        return "unresolved", "proposal_without_claim", set(), set()
    for survivor in SURVIVED_DISPOSITIONS:
        state = survivor.removeprefix("survived_")
        if state in states:
            return survivor, None, set(), {claim_id for claim_id, value in resolved.items() if value == state}
    for reason in ("insufficient_evidence", "coverage_gap"):
        if reason in states:
            return "unresolved", reason, set(), set()
    if not_final or not states or not states <= set(DISMISSED_STATES):
        return "unresolved", "claim_not_final", set(), set()
    return "dismissed_by_adjudication", None, states, set(resolved)


def load_verified_documents(run_root: Any) -> tuple[dict[str, Any] | None, str | None]:
    """The four verified inputs of the section, or ``(None, <integrity gap code>)``.

    ``{"review", "manifest", "lane", "projection"}``: the accepted review handoff, the lane A package
    manifest, the lane A document and the claim projection, each read once through the hash-bound
    readers named in the module docstring. This is the only run read of the section and of the
    adapters that derive records from the same documents (``observability.findings.lead_adapter``).
    It never raises for a missing or unverifiable input.
    """
    from appsec_review.storage.validation import validation_scope

    root = Path(run_root).resolve()
    try:
        with validation_scope(root):
            review = _stage("review_handoff_unavailable", _load_review, root)
            manifest = _stage("lead_manifest_unavailable", _load_manifest, root, review)
            lane = _stage("lane_document_unavailable", _load_lane, root, review)
            projection = _stage("claim_projection_unavailable", _load_projection, root, review)
    except _Unavailable as unavailable:
        return None, unavailable.code
    return {"review": review, "manifest": manifest, "lane": lane, "projection": projection}, None


def lead_dispositions(documents: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """One row per admitted lane A lead, in lead id order, and the integrity gap codes found.

    ``documents`` is the first element of :func:`load_verified_documents`. A row is
    ``{"lead_id", "disposition", "unresolved_reason", "dismissed_states", "claim_ids", "family",
    "scanner"}``: the disposition is the one the section counts for that lead, ``dismissed_states``
    and ``claim_ids`` are sorted, and ``claim_ids`` names the canonical claims that decided a
    surviving or dismissed disposition (empty otherwise). ``family`` and ``scanner`` are
    ``UNLINKED`` for a lead no ``finding_lead`` package lists.
    """
    manifest, lane, projection = documents["manifest"], documents["lane"], documents["projection"]
    gaps: set[str] = set()
    packages_of: dict[str, list[str]] = {}
    menu: dict[str, tuple[str, str]] = {}
    for package_id, leads in sorted(manifest["lead_packages"].items()):
        for lead_id, family, scanner in leads:
            packages_of.setdefault(lead_id, []).append(package_id)
            menu.setdefault(lead_id, (family, scanner))
    claim_index = _claims_by_package(lane, projection)
    rows: list[dict[str, Any]] = []
    admitted = [lead_id for lead_id, status, _ in manifest["admission"] if status == "admitted"]
    for lead_id in sorted(admitted):
        packages = packages_of.get(lead_id, [])
        if not packages:
            gaps.add("lead_package_unlinked")
        outcomes = []
        for package_id in packages:
            outcome = lane["lead_accounting"].get(package_id, {}).get(lead_id)
            if outcome not in _LEAD_OUTCOMES:
                gaps.add("lead_outcome_missing")
                outcome = "unaccounted"
            outcomes.append(outcome)
        reason: str | None = None
        states: set[str] = set()
        deciding: set[str] = set()
        if not outcomes:
            disposition, reason = "unresolved", "unaccounted"
        elif "proposal" in outcomes:
            disposition, reason, states, deciding = _proposal_disposition(
                _linked_claims(packages, claim_index), projection, gaps)
        elif all(outcome == "no_proposal" for outcome in outcomes):
            disposition = "no_claim_raised"
        else:
            disposition = "unresolved"
            reason = "blocked" if "blocked" in outcomes else "unaccounted"
        family, scanner = menu.get(lead_id, (_UNLINKED, _UNLINKED))
        rows.append({"lead_id": lead_id, "disposition": disposition, "unresolved_reason": reason,
                     "dismissed_states": sorted(states), "claim_ids": sorted(deciding),
                     "family": family, "scanner": scanner})
    return rows, sorted(gaps)


def _compute(review: Mapping[str, Any], manifest: Mapping[str, Any], lane: Mapping[str, Any],
             projection: Mapping[str, Any]) -> dict[str, Any]:
    rows, row_gaps = lead_dispositions({"manifest": manifest, "lane": lane, "projection": projection})
    gaps: set[str] = set(row_gaps)
    observed = Counter(outcome for leads in lane["lead_accounting"].values() for outcome in leads.values()
                       if outcome in _LEAD_OUTCOMES)
    if any(observed[outcome] != review["leads_by_outcome"][outcome] for outcome in _LEAD_OUTCOMES):
        gaps.add("lead_outcome_mismatch")

    dispositions = empty_dispositions()
    dismissed_states = dict.fromkeys(DISMISSED_STATES, 0)
    unresolved = dict.fromkeys(UNRESOLVED_REASONS, 0)
    by_family: dict[str, dict[str, int]] = {}
    by_scanner: dict[str, dict[str, int]] = {}
    admitted = [row["lead_id"] for row in rows]
    for lead in rows:
        disposition = lead["disposition"]
        dispositions[disposition] += 1
        if lead["unresolved_reason"] is not None:
            unresolved[lead["unresolved_reason"]] += 1
        for state in lead["dismissed_states"]:
            dismissed_states[state] += 1
        for table, key in ((by_family, lead["family"]), (by_scanner, lead["scanner"])):
            row = table.setdefault(key, {"admitted": 0, **empty_dispositions()})
            row["admitted"] += 1
            row[disposition] += 1

    if review["review_incomplete"]:
        gaps.add("review_incomplete")
    reduced = sum(dispositions[name] for name in REDUCED_DISPOSITIONS)
    resolved = reduced + sum(dispositions[name] for name in SURVIVED_DISPOSITIONS)
    not_admitted = Counter(residual for _, status, residual in manifest["admission"] if status == "not_admitted")
    hunt_claims = sum(1 for claim in projection["claims"].values() if claim["lane"] == "hunt")
    return {
        "schema": TRIAGE_REDUCTION_SCHEMA,
        "available": True,
        "scope": SCOPE,
        "sources": dict(sorted({**review["sources"], **manifest["sources"], **lane["sources"],
                                **projection["sources"]}.items())),
        "leads": {"collected": len(manifest["admission"]), "admitted": len(admitted),
                  "not_admitted": sum(not_admitted.values()),
                  "not_admitted_by_residual_coverage": dict(sorted(not_admitted.items())),
                  "non_lead_observations": manifest["non_lead_observations"]},
        "admitted_dispositions": dispositions,
        "dismissed_by_claim_state": dismissed_states,
        "unresolved_by_reason": unresolved,
        "hunt_lane_claims_excluded": hunt_claims,
        "reduction": {"ratio_over_resolved": _ratio(reduced, resolved),
                      "lower_bound_over_admitted": _ratio(reduced, len(admitted)),
                      "resolved_denominator": resolved, "admitted_denominator": len(admitted)},
        "by_family": dict(sorted(by_family.items())),
        "by_scanner": dict(sorted(by_scanner.items())),
        "review_incomplete": review["review_incomplete"],
        "accounting_complete": dispositions["unresolved"] == 0 and not review["review_incomplete"] and not gaps,
        "integrity_gap_codes": sorted(gaps),
        "interpretation": INTERPRETATION,
    }


def triage_reduction_metrics(run_root: Any) -> dict[str, Any]:
    """Compute the ``triage_reduction`` section from the run's verified review artifacts.

    Never raises for missing or unverifiable inputs; returns ``unavailable_section`` with the
    named integrity gap code of the first input that could not be read and verified instead.
    """
    documents, code = load_verified_documents(run_root)
    if documents is None:
        return unavailable_section([str(code)])
    return _compute(documents["review"], documents["manifest"], documents["lane"], documents["projection"])
