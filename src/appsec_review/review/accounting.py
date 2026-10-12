"""Exact claim, cell, and evidence-request accounting over a ledger projection (design rule 6).

Accounting violations are ``publication_error`` records and block publication. Ordinary gaps never
do; they only drive ``DEGRADED`` outcomes and ``review_incomplete``.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from appsec_review.review.identity import make_id
from appsec_review.review.ledger import EvidenceRequestOutcome, Projection
from appsec_review.review.models import CellStatus, ClaimState, Gap, GapClass, Lane

FINAL_CLAIM_STATES = frozenset(ClaimState) - {ClaimState.PROPOSED}


class PoolOutcome(StrEnum):
    COMPLETE = "COMPLETE"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"
    EMPTY = "EMPTY"


class ViolationCode(StrEnum):
    CLAIM_NOT_FINAL = "claim_not_final"
    DUPLICATE_WITHOUT_TARGET = "duplicate_without_target"
    DUPLICATE_DANGLING = "duplicate_dangling"
    DUPLICATE_OF_NON_CANONICAL = "duplicate_of_non_canonical"
    CELL_MISSING_TERMINAL = "cell_missing_terminal"
    CELL_MULTIPLE_TERMINAL = "cell_multiple_terminal"
    CELL_UNEXPECTED = "cell_unexpected"
    CELL_LANE_MISMATCH = "cell_lane_mismatch"
    PACKAGE_LANE_MISMATCH = "package_lane_mismatch"
    EVIDENCE_REQUEST_NOT_OPENED = "evidence_request_not_opened"
    EVIDENCE_REQUEST_NOT_TERMINAL = "evidence_request_not_terminal"
    EVIDENCE_REQUEST_MULTIPLE_TERMINAL = "evidence_request_multiple_terminal"
    PARTITION_MISMATCH = "partition_mismatch"


def violation(code: ViolationCode, subject_id: str) -> Gap:
    return Gap(make_id("gap", 1, {"gap_class": GapClass.PUBLICATION_ERROR.value, "subject_id": subject_id,
                                  "predicate": None, "round": 0, "reason": code.value}),
               GapClass.PUBLICATION_ERROR, subject_id, code.value)


@dataclass(frozen=True, slots=True)
class LaneAccounting:
    lane: Lane
    claims_by_state: Mapping[ClaimState, int]
    claims_total: int
    cells_expected: int
    cells_by_status: Mapping[CellStatus, int]
    cells_missing: int
    packages_expected: int
    gapped_cells: int
    gapped_packages: int
    gap_ratio: float
    review_incomplete: bool
    outcome: PoolOutcome
    duplicate_proposals: int = 0         # proposals this lane made of a claim id another proposal owns

    def to_json(self) -> dict[str, Any]:
        return {"lane": self.lane.value, "outcome": self.outcome.value, "claims_total": self.claims_total,
                "duplicate_proposals": self.duplicate_proposals,
                "claims_by_state": {state.value: self.claims_by_state[state] for state in ClaimState},
                "cells_expected": self.cells_expected,
                "cells_by_status": {status.value: self.cells_by_status[status] for status in CellStatus},
                "cells_missing": self.cells_missing, "packages_expected": self.packages_expected,
                "gapped_cells": self.gapped_cells, "gapped_packages": self.gapped_packages,
                "gap_ratio": self.gap_ratio, "review_incomplete": self.review_incomplete}


@dataclass(frozen=True, slots=True)
class Accounting:
    lanes: tuple[LaneAccounting, ...]
    claims_total: int
    claims_by_state: Mapping[ClaimState, int]
    gaps_by_class: Mapping[GapClass, int]
    evidence_requests_by_outcome: Mapping[EvidenceRequestOutcome, int]
    incomplete_gap_ratio: float
    gap_ratio: float
    review_incomplete: bool
    outcome: PoolOutcome
    violations: tuple[Gap, ...]
    duplicate_proposals: int = 0

    @property
    def exact(self) -> bool:
        return not self.violations

    def lane(self, lane: Lane) -> LaneAccounting:
        return next(item for item in self.lanes if item.lane is lane)

    def to_json(self) -> dict[str, Any]:
        return {"exact": self.exact, "outcome": self.outcome.value, "review_incomplete": self.review_incomplete,
                "incomplete_gap_ratio": self.incomplete_gap_ratio, "gap_ratio": self.gap_ratio,
                "claims_total": self.claims_total, "duplicate_proposals": self.duplicate_proposals,
                "claims_by_state": {state.value: self.claims_by_state[state] for state in ClaimState},
                "gaps_by_class": {gap_class.value: self.gaps_by_class[gap_class] for gap_class in GapClass},
                "evidence_requests_by_outcome": {
                    outcome.value: self.evidence_requests_by_outcome[outcome] for outcome in EvidenceRequestOutcome},
                "lanes": [lane.to_json() for lane in self.lanes],
                "violations": [{"gap_id": gap.gap_id, "subject_id": gap.subject_id, "reason": gap.reason}
                               for gap in self.violations]}


def _ratio(gapped: int, expected: int) -> float:
    return gapped / expected if expected else 0.0


def _outcome(expected_cells: int, expected_packages: int, statuses: Counter[CellStatus], gapped: int) -> PoolOutcome:
    if not expected_cells and not expected_packages:
        return PoolOutcome.EMPTY
    if expected_cells and not statuses[CellStatus.SUCCEEDED]:
        terminal = sum(statuses.values())
        if terminal and statuses[CellStatus.CANCELED] == terminal:
            return PoolOutcome.CANCELED
        return PoolOutcome.FAILED
    return PoolOutcome.DEGRADED if gapped else PoolOutcome.COMPLETE


def _combine(outcomes: list[PoolOutcome]) -> PoolOutcome:
    active = [outcome for outcome in outcomes if outcome is not PoolOutcome.EMPTY]
    if not active:
        return PoolOutcome.EMPTY
    if all(outcome is PoolOutcome.COMPLETE for outcome in active):
        return PoolOutcome.COMPLETE
    if all(outcome is PoolOutcome.CANCELED for outcome in active):
        return PoolOutcome.CANCELED
    if all(outcome in (PoolOutcome.FAILED, PoolOutcome.CANCELED) for outcome in active):
        return PoolOutcome.FAILED
    return PoolOutcome.DEGRADED


def exact_accounting(projection: Projection, expected_cells: Mapping[str, Lane],
                     expected_packages: Mapping[str, Lane], *, incomplete_gap_ratio: float) -> Accounting:
    """Account for every claim, expected cell, package, and evidence request exactly once.

    ``expected_cells`` and ``expected_packages`` map each identity to its lane. A cell is gapped
    when its terminal status is not ``succeeded`` or its terminal record is missing; a package is
    gapped when a gap names it as subject. ``review_incomplete`` is set when the overall or any
    lane's gapped/expected ratio exceeds ``incomplete_gap_ratio``.
    """
    if not 0.0 <= incomplete_gap_ratio <= 1.0:
        raise ValueError("incomplete_gap_ratio must lie in [0, 1]")
    violations: list[Gap] = []
    claims = {claim_id: view.claim for claim_id, view in projection.claims.items()}
    for claim_id, claim in claims.items():
        if claim.state not in FINAL_CLAIM_STATES:
            violations.append(violation(ViolationCode.CLAIM_NOT_FINAL, claim_id))
        if claim.state is ClaimState.DUPLICATE:
            target = claims.get(claim.duplicate_of) if claim.duplicate_of else None
            if claim.duplicate_of is None:
                violations.append(violation(ViolationCode.DUPLICATE_WITHOUT_TARGET, claim_id))
            elif target is None:
                violations.append(violation(ViolationCode.DUPLICATE_DANGLING, claim_id))
            elif target.state is ClaimState.DUPLICATE or target.claim_id == claim_id:
                violations.append(violation(ViolationCode.DUPLICATE_OF_NON_CANONICAL, claim_id))

    for cell_id in sorted(set(expected_cells) | set(projection.cells)):
        records = projection.cells.get(cell_id, ())
        if cell_id not in expected_cells:
            violations.append(violation(ViolationCode.CELL_UNEXPECTED, cell_id))
        elif not records:
            violations.append(violation(ViolationCode.CELL_MISSING_TERMINAL, cell_id))
        elif len(records) > 1:
            violations.append(violation(ViolationCode.CELL_MULTIPLE_TERMINAL, cell_id))
        elif records[0].lane is not expected_cells[cell_id]:
            violations.append(violation(ViolationCode.CELL_LANE_MISMATCH, cell_id))
        elif records[0].package_id in expected_packages and expected_packages[records[0].package_id] is not records[0].lane:
            violations.append(violation(ViolationCode.PACKAGE_LANE_MISMATCH, cell_id))

    request_outcomes: Counter[EvidenceRequestOutcome] = Counter()
    for request_id, request in projection.evidence_requests.items():
        if request.opened != 1:
            violations.append(violation(ViolationCode.EVIDENCE_REQUEST_NOT_OPENED, request_id))
        if not request.outcomes:
            violations.append(violation(ViolationCode.EVIDENCE_REQUEST_NOT_TERMINAL, request_id))
        elif len(request.outcomes) > 1:
            violations.append(violation(ViolationCode.EVIDENCE_REQUEST_MULTIPLE_TERMINAL, request_id))
        else:
            request_outcomes[request.outcomes[0]] += 1

    gapped_packages = {gap.subject_id for gap in projection.gaps if gap.subject_id in expected_packages}
    duplicates = {lane: sum(view.duplicate_proposals[lane] for view in projection.claims.values()) for lane in Lane}
    lanes: list[LaneAccounting] = []
    for lane in Lane:
        lane_claims = Counter(claim.state for claim in claims.values() if claim.lane is lane)
        cell_ids = sorted(cell_id for cell_id, cell_lane in expected_cells.items() if cell_lane is lane)
        statuses: Counter[CellStatus] = Counter()
        missing = 0
        for cell_id in cell_ids:
            records = projection.cells.get(cell_id, ())
            if len(records) == 1:
                statuses[records[0].status] += 1
            else:
                missing += 1
        gapped_cells = missing + sum(count for status, count in statuses.items() if status is not CellStatus.SUCCEEDED)
        packages = [package for package, package_lane in expected_packages.items() if package_lane is lane]
        lane_gapped_packages = sum(package in gapped_packages for package in packages)
        expected = len(cell_ids) + len(packages)
        ratio = _ratio(gapped_cells + lane_gapped_packages, expected)
        claims_total = sum(1 for claim in claims.values() if claim.lane is lane)
        if sum(lane_claims.values()) != claims_total or sum(statuses.values()) + missing != len(cell_ids):
            violations.append(violation(ViolationCode.PARTITION_MISMATCH, f"lane:{lane.value}"))
        lanes.append(LaneAccounting(
            lane, {state: lane_claims[state] for state in ClaimState}, claims_total, len(cell_ids),
            {status: statuses[status] for status in CellStatus}, missing, len(packages), gapped_cells,
            lane_gapped_packages, ratio, ratio > incomplete_gap_ratio,
            _outcome(len(cell_ids), len(packages), statuses, gapped_cells + lane_gapped_packages),
            duplicates[lane]))

    total_claims = Counter(claim.state for claim in claims.values())
    if sum(lane.claims_total for lane in lanes) != len(claims) or sum(total_claims.values()) != len(claims):
        violations.append(violation(ViolationCode.PARTITION_MISMATCH, "claims"))
    expected_total = len(expected_cells) + len(expected_packages)
    gap_ratio = _ratio(sum(lane.gapped_cells + lane.gapped_packages for lane in lanes), expected_total)
    gap_classes = Counter(gap.gap_class for gap in projection.gaps)
    unique = {gap.gap_id: gap for gap in violations}
    return Accounting(
        lanes=tuple(lanes), claims_total=len(claims),
        claims_by_state={state: total_claims[state] for state in ClaimState},
        gaps_by_class={gap_class: gap_classes[gap_class] for gap_class in GapClass},
        evidence_requests_by_outcome={outcome: request_outcomes[outcome] for outcome in EvidenceRequestOutcome},
        incomplete_gap_ratio=incomplete_gap_ratio, gap_ratio=gap_ratio,
        review_incomplete=gap_ratio > incomplete_gap_ratio or any(lane.review_incomplete for lane in lanes),
        outcome=_combine([lane.outcome for lane in lanes]),
        violations=tuple(sorted(unique.values(), key=lambda gap: (gap.subject_id, gap.reason))),
        duplicate_proposals=sum(duplicates.values()),
    )
