from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.review.accounting import PoolOutcome, ViolationCode, exact_accounting
from appsec_review.review.ledger import EventKind, EvidenceRequestOutcome, LedgerWriter, project
from appsec_review.review.models import CellStatus, ClaimState, GapClass, Lane, Predicate
from tests.review.test_ledger import cell, cell_id, claim, gap, request_id

S = ClaimState


def _ledger(tmp_path: Path, *, cells: dict[str, tuple[Lane, CellStatus]], extra=None, claims=None):
    writer = LedgerWriter(tmp_path / "ledger.jsonl", "unit")
    for name, (lane, final) in (claims or {}).items():
        target = claim(name, lane, "package-a" if lane is Lane.LEAD else "package-h")
        writer.propose_claim(target)
        if final is S.SUPPORTED:
            writer.transition(target.claim_id, S.PROPOSED, S.SUPPORTED, reason="r5")
        elif final is not None:
            writer.transition(target.claim_id, S.PROPOSED, final, reason="r5")
    for name, (lane, status) in cells.items():
        writer.cell_terminal(cell(name, lane, status, "package-a" if lane is Lane.LEAD else "package-h"))
    if extra:
        extra(writer)
    return project(writer.events)


def _codes(accounting) -> set[tuple[str, str]]:
    return {(gap.reason, gap.subject_id) for gap in accounting.violations}


EXPECTED_PACKAGES = {"package-a": Lane.LEAD, "package-h": Lane.HUNT}


def test_exact_accounting_complete(tmp_path: Path) -> None:
    projection = _ledger(tmp_path, cells={"a1": (Lane.LEAD, CellStatus.SUCCEEDED), "h1": (Lane.HUNT, CellStatus.SUCCEEDED)},
                         claims={"a": (Lane.LEAD, S.SUPPORTED), "b": (Lane.HUNT, S.CONTRADICTED)})
    accounting = exact_accounting(projection, {cell_id("a1"): Lane.LEAD, cell_id("h1"): Lane.HUNT},
                                  EXPECTED_PACKAGES, incomplete_gap_ratio=0.25)
    assert accounting.exact and accounting.violations == ()
    assert accounting.outcome is PoolOutcome.COMPLETE and not accounting.review_incomplete
    assert accounting.claims_by_state[S.SUPPORTED] == 1 and accounting.claims_by_state[S.CONTRADICTED] == 1
    lead = accounting.lane(Lane.LEAD)
    assert lead.claims_total == 1 and lead.cells_by_status[CellStatus.SUCCEEDED] == 1
    assert sum(lead.claims_by_state.values()) == lead.claims_total
    assert accounting.to_json()["lanes"][0]["lane"] == "lead"


def test_missing_and_double_terminal_cells_are_publication_errors(tmp_path: Path) -> None:
    def twice(writer: LedgerWriter) -> None:
        writer.cell_terminal(cell("a2", Lane.LEAD, CellStatus.FAILED))
    projection = _ledger(tmp_path, cells={"a2": (Lane.LEAD, CellStatus.SUCCEEDED), "x": (Lane.LEAD, CellStatus.SUCCEEDED)},
                         extra=twice)
    accounting = exact_accounting(projection, {cell_id("a1"): Lane.LEAD, cell_id("a2"): Lane.LEAD},
                                  EXPECTED_PACKAGES, incomplete_gap_ratio=0.25)
    assert _codes(accounting) == {
        (ViolationCode.CELL_MISSING_TERMINAL.value, cell_id("a1")),
        (ViolationCode.CELL_MULTIPLE_TERMINAL.value, cell_id("a2")),
        (ViolationCode.CELL_UNEXPECTED.value, cell_id("x")),
    }
    assert not accounting.exact
    assert all(gap.gap_class is GapClass.PUBLICATION_ERROR for gap in accounting.violations)
    assert accounting.lane(Lane.LEAD).cells_missing == 2


def test_cell_lane_mismatch(tmp_path: Path) -> None:
    projection = _ledger(tmp_path, cells={"a1": (Lane.LEAD, CellStatus.SUCCEEDED)})
    accounting = exact_accounting(projection, {cell_id("a1"): Lane.HUNT}, EXPECTED_PACKAGES, incomplete_gap_ratio=0.5)
    assert _codes(accounting) == {(ViolationCode.CELL_LANE_MISMATCH.value, cell_id("a1"))}


def test_duplicate_checks(tmp_path: Path) -> None:
    a, b, c, d = (claim(name) for name in "abcd")
    ghost = claim("ghost")

    def duplicates(writer: LedgerWriter) -> None:
        for target in (a, b, c, d):
            writer.propose_claim(target)
        writer.transition(a.claim_id, S.PROPOSED, S.SUPPORTED, reason="r5")
        writer.mark_duplicate(b.claim_id, ghost.claim_id, reason="dangling")
        writer.mark_duplicate(c.claim_id, a.claim_id, reason="ok")
        writer.mark_duplicate(d.claim_id, c.claim_id, reason="chain")
    accounting = exact_accounting(_ledger(tmp_path, cells={}, extra=duplicates), {}, {}, incomplete_gap_ratio=0.25)
    assert _codes(accounting) == {
        (ViolationCode.DUPLICATE_DANGLING.value, b.claim_id),
        (ViolationCode.DUPLICATE_OF_NON_CANONICAL.value, d.claim_id),
    }
    assert accounting.claims_by_state[S.DUPLICATE] == 3


def test_claim_left_proposed_is_not_final(tmp_path: Path) -> None:
    projection = _ledger(tmp_path, cells={}, claims={"a": (Lane.LEAD, None)})
    accounting = exact_accounting(projection, {}, EXPECTED_PACKAGES, incomplete_gap_ratio=0.25)
    assert _codes(accounting) == {(ViolationCode.CLAIM_NOT_FINAL.value, claim("a").claim_id)}


def test_evidence_requests_must_be_terminal_once(tmp_path: Path) -> None:
    target = claim("a")

    def requests(writer: LedgerWriter) -> None:
        for name in ("open", "done", "twice"):
            writer.open_request(request_id(name), target.claim_id, Predicate.SECURITY_IMPACT, "source_span")
        writer.close_request(request_id("done"), target.claim_id, EvidenceRequestOutcome.UNSATISFIED, reason="x")
        writer.close_request(request_id("twice"), target.claim_id, EvidenceRequestOutcome.SATISFIED, reason="x")
        writer.close_request(request_id("twice"), target.claim_id, EvidenceRequestOutcome.WITHDRAWN, reason="x")
        writer.close_request(request_id("orphan"), target.claim_id, EvidenceRequestOutcome.SUPERSEDED, reason="x")
    accounting = exact_accounting(_ledger(tmp_path, cells={}, claims={"a": (Lane.LEAD, S.INSUFFICIENT_EVIDENCE)},
                                          extra=requests), {}, {}, incomplete_gap_ratio=0.25)
    assert _codes(accounting) == {
        (ViolationCode.EVIDENCE_REQUEST_NOT_TERMINAL.value, request_id("open")),
        (ViolationCode.EVIDENCE_REQUEST_MULTIPLE_TERMINAL.value, request_id("twice")),
        (ViolationCode.EVIDENCE_REQUEST_NOT_OPENED.value, request_id("orphan")),
    }
    assert accounting.evidence_requests_by_outcome[EvidenceRequestOutcome.UNSATISFIED] == 1
    assert accounting.evidence_requests_by_outcome[EvidenceRequestOutcome.SUPERSEDED] == 1


def _cells(prefix: str, lane: Lane, total: int, failed: int) -> dict[str, tuple[Lane, CellStatus]]:
    return {f"{prefix}{index}": (lane, CellStatus.FAILED if index < failed else CellStatus.SUCCEEDED)
            for index in range(total)}


@pytest.mark.parametrize("failed,incomplete", [(0, False), (2, False), (3, True)])
def test_review_incomplete_threshold(tmp_path: Path, failed: int, incomplete: bool) -> None:
    # 2 packages + 8 lead + 8 hunt cells = 18 expected; lane ratio for 2 failed is 2/9 <= 0.25.
    cells = {**_cells("a", Lane.LEAD, 8, failed), **_cells("h", Lane.HUNT, 8, 0)}
    accounting = exact_accounting(_ledger(tmp_path, cells=cells), {cell_id(name): lane for name, (lane, _) in cells.items()},
                                  EXPECTED_PACKAGES, incomplete_gap_ratio=0.25)
    assert accounting.exact
    assert accounting.review_incomplete is incomplete
    assert accounting.lane(Lane.LEAD).review_incomplete is incomplete
    assert accounting.lane(Lane.HUNT).review_incomplete is False
    assert accounting.outcome is (PoolOutcome.DEGRADED if failed else PoolOutcome.COMPLETE)


def test_gapped_package_counts_toward_ratio(tmp_path: Path) -> None:
    cells = _cells("h", Lane.HUNT, 1, 0)
    projection = _ledger(tmp_path, cells=cells, extra=lambda writer: writer.record_gap(gap("package-h", GapClass.COVERAGE_GAP)))
    accounting = exact_accounting(projection, {cell_id("h0"): Lane.HUNT}, {"package-h": Lane.HUNT},
                                  incomplete_gap_ratio=0.25)
    hunt = accounting.lane(Lane.HUNT)
    assert hunt.gapped_packages == 1 and hunt.gap_ratio == 0.5 and hunt.review_incomplete
    assert hunt.outcome is PoolOutcome.DEGRADED and accounting.exact
    assert accounting.gaps_by_class[GapClass.COVERAGE_GAP] == 1


def test_whole_lane_failure_degrades_the_pool(tmp_path: Path) -> None:
    cells = {**_cells("a", Lane.LEAD, 3, 3), **_cells("h", Lane.HUNT, 3, 0)}
    accounting = exact_accounting(_ledger(tmp_path, cells=cells), {cell_id(name): lane for name, (lane, _) in cells.items()},
                                  EXPECTED_PACKAGES, incomplete_gap_ratio=0.25)
    assert accounting.lane(Lane.LEAD).outcome is PoolOutcome.FAILED
    assert accounting.lane(Lane.HUNT).outcome is PoolOutcome.COMPLETE
    assert accounting.outcome is PoolOutcome.DEGRADED and accounting.review_incomplete and accounting.exact


def test_pool_outcomes_empty_failed_canceled(tmp_path: Path) -> None:
    assert exact_accounting(_ledger(tmp_path, cells={}), {}, {}, incomplete_gap_ratio=0.25).outcome is PoolOutcome.EMPTY
    cells = {"a0": (Lane.LEAD, CellStatus.CANCELED), "h0": (Lane.HUNT, CellStatus.TIMED_OUT)}
    accounting = exact_accounting(_ledger(tmp_path / "x", cells=cells),
                                  {cell_id(name): lane for name, (lane, _) in cells.items()},
                                  EXPECTED_PACKAGES, incomplete_gap_ratio=0.25)
    assert accounting.lane(Lane.LEAD).outcome is PoolOutcome.CANCELED
    assert accounting.lane(Lane.HUNT).outcome is PoolOutcome.FAILED
    assert accounting.outcome is PoolOutcome.FAILED


def test_ratio_bounds() -> None:
    with pytest.raises(ValueError):
        exact_accounting(project([]), {}, {}, incomplete_gap_ratio=1.5)


def test_event_kinds_are_closed() -> None:
    assert [kind.value for kind in EventKind] == [
        "claim_proposed", "relation_added", "evidence_request_opened", "evidence_request_closed",
        "duplicate_marked", "state_transition", "gap_recorded", "cell_terminal"]
