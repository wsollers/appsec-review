"""The run overview's triage reduction box: counts, ratios, gaps and wording."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any, Iterator

import pytest

from appsec_review.config.telemetry_report import TelemetryReportSettings
from appsec_review.observability.triage_reduction import (INTERPRETATION, SCOPE, TRIAGE_REDUCTION_SCHEMA,
                                                        unavailable_section)
from appsec_review.reporting.model import Box, Bullets, Fields, Para, Table
from appsec_review.reporting.telemetry import TelemetryInputs
from appsec_review.reporting.telemetry.overview import TRIAGE_LIMIT, overview_sections
from appsec_review.reporting.telemetry_render import REPORT_PATH, render_telemetry_report
from appsec_review.reporting.tokens import BoxKind

from .fixture import HOSTILE
from .telemetry_fixture import build_telemetry_run

ROOT = Path(__file__).resolve().parents[2]
TITLE = "Triage reduction"


def _section(**overrides: Any) -> dict[str, Any]:
    section: dict[str, Any] = {
        "schema": TRIAGE_REDUCTION_SCHEMA, "available": True, "scope": SCOPE,
        "sources": {"lane_a": {"path": "data/review/lane-a.json", "sha256": "0" * 64}},
        "leads": {"collected": 11, "admitted": 8, "not_admitted": 3,
                  "not_admitted_by_residual_coverage": {"lead_cap": 1, "no_rule_owner": 2},
                  "non_lead_observations": 4},
        "admitted_dispositions": {"survived_confirmed": 1, "survived_supported": 2,
                                  "dismissed_by_adjudication": 3, "no_claim_raised": 2, "unresolved": 0},
        "dismissed_by_claim_state": {"contradicted": 2, "not_reachable": 1,
                                     "not_exploitable_in_observed_configuration": 0, "out_of_scope": 0},
        "unresolved_by_reason": {"blocked": 0, "unaccounted": 0, "insufficient_evidence": 0,
                                 "coverage_gap": 0, "claim_not_final": 0, "proposal_without_claim": 0},
        "hunt_lane_claims_excluded": 5,
        "reduction": {"ratio_over_resolved": 5 / 8, "lower_bound_over_admitted": 5 / 8,
                      "resolved_denominator": 8, "admitted_denominator": 8},
        "by_family": {"injection": {"admitted": 3, "survived_confirmed": 1, "survived_supported": 0,
                                    "dismissed_by_adjudication": 1, "no_claim_raised": 1, "unresolved": 0},
                      "memory": {"admitted": 5, "survived_confirmed": 0, "survived_supported": 2,
                                 "dismissed_by_adjudication": 2, "no_claim_raised": 1, "unresolved": 0}},
        "by_scanner": {"cppcheck": {"admitted": 8, "survived_confirmed": 1, "survived_supported": 2,
                                    "dismissed_by_adjudication": 3, "no_claim_raised": 2, "unresolved": 0}},
        "review_incomplete": False, "accounting_complete": True, "integrity_gap_codes": [],
        "interpretation": INTERPRETATION,
    }
    section.update(overrides)
    return section


def _inputs(summary: dict[str, Any]) -> TelemetryInputs:
    return TelemetryInputs(
        run_id="2026-11-02-0001", summary=summary, summary_source="summary.json", summary_sha256=None,
        events=(), events_sha256=None, torn_tail=False, run_started_at=None, run_ended_at=None,
        completion_status="UNKNOWN", source_date_epoch=0, jobs=(), named_gaps=())


def _box(section: Any = None, *, present: bool = True) -> Box:
    summary = {"triage_reduction": section} if present else {}
    blocks = overview_sections(_inputs(summary))
    titles = [block.title for block in blocks if isinstance(block, Box)]
    assert titles.index(TITLE) == titles.index("Project images and finding lifecycle") + 1
    return next(block for block in blocks if isinstance(block, Box) and block.title == TITLE)


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif dataclasses.is_dataclass(value):
        for field in dataclasses.fields(value):
            yield from _strings(getattr(value, field.name))
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from _strings(item)


def _fields(box: Box) -> dict[str, str]:
    return {row.label: row.value for item in box.items if isinstance(item, Fields) for row in item.rows}


def _tables(box: Box) -> dict[str, Table]:
    return {item.headers[0]: item for item in box.items if isinstance(item, Table)}


def _bullets(box: Box) -> list[str]:
    return [text for item in box.items if isinstance(item, Bullets) for text in item.items]


def _text(box: Box) -> str:
    return " ".join(_strings(box))


def test_complete_section_renders_counts_ratios_and_breakdowns() -> None:
    box = _box(_section())
    assert (box.kind, box.chip, box.meta) == (BoxKind.RESULT, "TRIAGE", "5 of 8 admitted reduced")
    fields = _fields(box)
    assert fields["Scope"] == "lane A scanner leads"
    assert (fields["Leads collected"], fields["Admitted for review"]) == ("11", "8")
    assert fields["Not admitted (unreviewed)"] == "3 (by residual coverage: lead_cap: 1, no_rule_owner: 2)"
    assert (fields["Non-lead observations"], fields["Hunt-lane claims excluded"]) == ("4", "5")
    assert fields["Dismissed or no claim, of resolved"] == "62.5% of 8 resolved leads"
    assert fields["Lower bound, of admitted"] == "62.5% of 8 admitted leads"
    assert (fields["Accounting complete"], fields["Review incomplete"]) == ("yes", "no")
    assert fields["Dismissed by claim state"] == (
        "contradicted: 2, not_reachable: 1, not_exploitable_in_observed_configuration: 0, out_of_scope: 0")
    tables = _tables(box)
    assert [(row[0].text, row[1].text) for row in tables["Admitted-lead disposition"].rows] == [
        ("Survived as confirmed claim", "1"), ("Survived as supported claim", "2"),
        ("Dismissed by adjudication", "3"), ("Examined, no claim raised", "2"),
        ("Unresolved (never counted as reduced)", "0")]
    assert [[cell.text for cell in row] for row in tables["Lead family"].rows] == [
        ["memory", "5", "0", "2", "2", "1", "0"], ["injection", "3", "1", "0", "1", "1", "0"]]
    assert [row[0].text for row in tables["Scanner"].rows] == ["cppcheck"]
    assert not _bullets(box)


def test_incomplete_accounting_and_integrity_gaps_are_gap_styled() -> None:
    section = _section(
        admitted_dispositions={"survived_confirmed": 1, "survived_supported": 2, "dismissed_by_adjudication": 3,
                               "no_claim_raised": 2, "unresolved": 4},
        leads={"collected": 15, "admitted": 12, "not_admitted": 3, "not_admitted_by_residual_coverage": {},
               "non_lead_observations": 0},
        reduction={"ratio_over_resolved": 5 / 8, "lower_bound_over_admitted": 5 / 12,
                   "resolved_denominator": 8, "admitted_denominator": 12},
        review_incomplete=True, accounting_complete=False,
        integrity_gap_codes=["review_incomplete", "a_future_gap_code"])
    box = _box(section)
    assert (box.kind, box.chip) == (BoxKind.GAP, None)
    assert box.meta == "5 of 12 admitted reduced, accounting incomplete"
    fields = _fields(box)
    assert fields["Not admitted (unreviewed)"] == "3"
    assert fields["Lower bound, of admitted"] == "41.7% of 12 admitted leads"
    assert (fields["Accounting complete"], fields["Review incomplete"]) == ("no", "yes")
    assert _bullets(box) == ["Integrity gap: review_incomplete", "Integrity gap: a_future_gap_code"]
    assert "not a clean result" in _text(box)
    # an integrity gap alone, with complete accounting, still takes gap styling
    assert _box(_section(integrity_gap_codes=["lead_outcome_mismatch"])).kind == BoxKind.GAP


def test_unavailable_section_shows_unavailable_never_zero() -> None:
    box = _box(unavailable_section(["lead_manifest_unavailable", "claim_projection_unavailable"]))
    assert (box.kind, box.meta) == (BoxKind.GAP, "unavailable")
    fields = _fields(box)
    for label in ("Leads collected", "Admitted for review", "Not admitted (unreviewed)", "Non-lead observations",
                  "Hunt-lane claims excluded", "Dismissed or no claim, of resolved", "Lower bound, of admitted",
                  "Review incomplete"):
        assert fields[label] == "unavailable", label
    assert fields["Accounting complete"] == "no"
    assert "0" not in [row[1].text for row in _tables(box)["Admitted-lead disposition"].rows]
    assert {row[1].text for row in _tables(box)["Admitted-lead disposition"].rows} == {"unavailable"}
    assert not any(":" in value and ": 0" in value for value in fields.values())
    assert set(_tables(box)) == {"Admitted-lead disposition"}            # no per-family/scanner tables
    assert _bullets(box) == ["Integrity gap: claim_projection_unavailable",
                             "Integrity gap: lead_manifest_unavailable"]
    assert "shown as unavailable, not zero" in _text(box)


@pytest.mark.parametrize("summary_section,present", [(None, False), ("not a mapping", True),
                                                     ({"schema": "appsec-review/triage-reduction-metrics/0"}, True)])
def test_missing_or_unrecognised_section_renders_unavailable(summary_section: Any, present: bool) -> None:
    box = _box(summary_section, present=present)
    assert (box.kind, box.meta) == (BoxKind.GAP, "unavailable")
    paragraphs = [item.text for item in box.items if isinstance(item, Para)]
    assert paragraphs[0].startswith("Triage reduction: unavailable;")
    assert "not zero reduction" in paragraphs[0]
    assert not any(isinstance(item, (Fields, Table)) for item in box.items)


def test_zero_denominator_ratio_renders_unavailable() -> None:
    section = _section(
        leads={"collected": 2, "admitted": 2, "not_admitted": 0, "not_admitted_by_residual_coverage": {},
               "non_lead_observations": 0},
        admitted_dispositions={"survived_confirmed": 0, "survived_supported": 0, "dismissed_by_adjudication": 0,
                               "no_claim_raised": 0, "unresolved": 2},
        reduction={"ratio_over_resolved": None, "lower_bound_over_admitted": 0.0,
                   "resolved_denominator": 0, "admitted_denominator": 2},
        accounting_complete=False)
    fields = _fields(_box(section))
    assert fields["Dismissed or no claim, of resolved"] == "unavailable (no resolved leads)"
    assert fields["Lower bound, of admitted"] == "0.0% of 2 admitted leads"


def test_wording_never_concludes_false_positives() -> None:
    sections = (_section(), _section(accounting_complete=False, integrity_gap_codes=["review_incomplete"]),
                unavailable_section(["review_handoff_unavailable"]), None)
    for section in sections:
        box = _box(section, present=section is not None)
        mentions = [text for text in _strings(box) if "false positive" in text.lower()]
        assert mentions, "the interpretation line must be present"
        for text in mentions:
            assert text.lower().count("false positive") == 1
            assert "not confirmed false positives" in text
        assert "unresolved or unadmitted leads are never counted as reduced" in _text(box)


def test_breakdown_tables_are_capped_ordered_and_cleaned() -> None:
    families = {f"family-{index:02d}": {"admitted": index, "unresolved": None} for index in range(TRIAGE_LIMIT + 4)}
    families[HOSTILE] = {"admitted": 100}
    table = _tables(_box(_section(by_family=families)))["Lead family"]
    assert len(table.rows) == TRIAGE_LIMIT and table.omitted is not None and table.omitted.omitted == 5
    names = [row[0].text for row in table.rows]
    assert names[1:3] == ["family-15", "family-14"]
    assert HOSTILE not in names and not any(ord(char) < 0x20 for char in names[0])
    assert table.rows[1][-1].text == "n/a"                       # not recorded, never zero


def test_tex_render_includes_the_triage_reduction_box(tmp_path: Path) -> None:
    run = build_telemetry_run(tmp_path)
    path = run / "data" / "telemetry" / "summary.json"
    summary = json.loads(path.read_bytes())
    summary["triage_reduction"] = _section(accounting_complete=False, integrity_gap_codes=["review_incomplete"])
    path.write_text(json.dumps(summary), encoding="utf-8")
    result = render_telemetry_report(run, TelemetryReportSettings(render_pdf=False), repository_root=ROOT,
                                     executor_factory=lambda *a: pytest.fail("tex_only must not render"))
    assert result.status == "tex_only"
    tex = (run / REPORT_PATH / "telemetry-report.tex").read_text(encoding="utf-8")
    box_line = next(line for line in tex.splitlines() if "{Triage reduction}" in line)
    assert "{gap}" in box_line
    assert "Dismissed by adjudication" in tex and "62.5\\% of 8 resolved leads" in tex
    assert "Integrity gap: review\\_\\allowbreak{}incomplete" in tex
