"""The smoke scorecard over synthetic score rows: funnel stages, axes, per-axis metrics, radar series, the
document, the rendering receipt on a fake executor, and the run-to-run trend. No real run and no real key."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

import pytest

from appsec_review.reporting import smoke_scorecard
from appsec_review.reporting.latex import render_latex
from appsec_review.reporting.model import RadarChart
from appsec_review.reporting.smoke_score import (
    AXIS_IDS, SCHEMA, STAGES, SmokeScoreError, axis_metrics, axis_of, stage_of,
)
from appsec_review.reporting.smoke_scorecard import (STAGE_OWNERS,
    RECEIPT_SCHEMA, compare_axes, compare_text, load_score, radar_axes, radar_series, render_scorecard,
    smoke_scorecard_document,
)

ROOT = Path(__file__).resolve().parents[3]
TEMPLATE = ROOT / "containers" / "report" / "latex" / "template"
PDF = b"%PDF-1.5\n" + b"fixture " * 8 + b"\n%%EOF\n"


def lead(admission="admitted", exclusion=None, reported="info", effective="high") -> dict:
    return {"lead_id": "asr:tool_observation:" + "1" * 64, "family": "source_sast", "scanner": "tool-semgrep",
            "rule_id": "rules.x", "start_line": 10, "admission": admission, "exclusion": exclusion,
            "reported_severity": reported, "effective_severity": effective}


def claim(state) -> dict:
    return {"claim_id": f"claim-{state}", "state": state, "lane": "lead", "package_id": "finding_lead-1"}


def finding(state="confirmed", bucket="publishable", technical="high") -> dict:
    return {"finding_package_id": f"finding-{state}", "claim_id": f"claim-{state}", "state": state, "bucket": bucket,
            "technical_severity": technical}


def row(klass="true_positive_code", *, leads=(), packages=(), claims=(), findings=(), reported=False, components=None,
        axis="memory_safety", real_severity=None, item_id="TP-X") -> dict:
    """A scored item row with the fields ``stage_of`` and ``axis_metrics`` read; the scorer fills the rest."""
    return {"id": item_id, "class": klass, "expected_disposition": "reported", "cwe": "CWE-120", "axis": axis,
            "axis_basis": "key", "real_severity": real_severity, "file": "src/a.cpp", "function": "f",
            "span": {"start_line": 10, "end_line": 12}, "match_basis": "span", "package": "zlib", "version": "1.2.11",
            "identifiers": ["CVE-2018-25032"], "location": None, "in_accepted_scope": True, "disposition": "first_party",
            "facets": [], "facets_available": True, "dependency_rows": [],
            "components": components if components is not None else [], "leads": list(leads),
            "packages": list(packages), "claims": list(claims), "judge_verdicts": [], "finding_packages": list(findings),
            "reported": reported, "citing_lines": [], "observed_disposition": "not_observed", "outcome": "miss",
            "outcome_reason": "", "stage": "", "stage_evidence": ""}


def staged(**changes) -> dict:
    item = row(**changes)
    item["stage"], item["stage_evidence"] = stage_of(item)
    return item


UNIT = {"package_id": "hunt-1", "lane": "hunt", "kind": "hunt", "via": "unit", "red_cells": []}
LEAD_PACKAGE = {"package_id": "finding_lead-1", "lane": "lead", "kind": "finding_lead", "via": "lead", "red_cells": []}


def red_cell(status="invalid", *classes, role="red_team_analyst", number=1) -> dict:
    return {"cell_id": f"cell-{number}", "role": role, "status": status, "gap_classes": list(classes)}


# Run 2026-11-16-0005 lane A: every red cell of a package rejected on shape, twice; the item has no claim.
REJECTED = {**LEAD_PACKAGE, "red_cells": [red_cell("invalid", "schema_error"), red_cell("invalid", "schema_error", number=2)]}
DECLINED = {**LEAD_PACKAGE, "red_cells": [red_cell("succeeded"), red_cell("invalid", "schema_error", number=2)]}
DENIED = {**LEAD_PACKAGE, "red_cells": [red_cell("invalid", "authority_error")]}
HUNT_REJECTED = {**UNIT, "red_cells": [red_cell("invalid", "schema_error", role="hypothesis_hunter")]}

CODE_CASES = sorted([
    ("not_observed", dict()),
    ("not_admitted", dict(leads=[lead("not_admitted", "vendored"), lead("not_admitted", None, "unknown", "info")])),
    ("no_claim_admitted", dict(leads=[lead()], packages=[LEAD_PACKAGE])),
    ("no_claim_hunted", dict(packages=[UNIT])),
    ("answer_rejected", dict(leads=[lead()], packages=[REJECTED])),
    ("answer_rejected_hunted", dict(packages=[HUNT_REJECTED])),
    ("no_claim_one_cell_declined", dict(leads=[lead()], packages=[DECLINED])),
    ("no_claim_denied_not_schema", dict(leads=[lead()], packages=[DENIED])),
    ("no_claim_rejected_then_declined", dict(leads=[lead()], packages=[REJECTED, {**UNIT, "red_cells": [red_cell("succeeded")]}])),
    ("unverified_after_rejection", dict(leads=[lead()], packages=[REJECTED], claims=[claim("supported")])),
    ("out_of_scope", dict(leads=[lead()], claims=[claim("out_of_scope"), claim("duplicate")])),
    ("refuted", dict(leads=[lead()], claims=[claim("contradicted"), claim("out_of_scope")])),
    ("unverified_supported", dict(leads=[lead()], claims=[claim("supported"), claim("contradicted")])),
    ("unverified_backlog", dict(leads=[lead()], claims=[claim("supported")],
                                findings=[finding("supported", "verification_backlog", None)])),
    ("unverified_insufficient", dict(packages=[UNIT], claims=[claim("insufficient_evidence")])),
    ("confirmed_publishable", dict(leads=[lead()], claims=[claim("confirmed")], findings=[finding()])),
    ("confirmed_reported", dict(leads=[lead()], claims=[claim("confirmed")], findings=[finding()], reported=True)),
], key=lambda case: case[0])
EXPECTED_CODE = {"not_observed": "not_observed", "not_admitted": "not_admitted", "no_claim_admitted": "no_claim",
                 "no_claim_hunted": "no_claim", "answer_rejected": "answer_rejected", "answer_rejected_hunted": "answer_rejected",
                 "no_claim_one_cell_declined": "no_claim", "no_claim_denied_not_schema": "no_claim",
                 "no_claim_rejected_then_declined": "no_claim", "unverified_after_rejection": "unverified",
                 "out_of_scope": "out_of_scope", "refuted": "refuted",
                 "unverified_supported": "unverified", "unverified_backlog": "unverified",
                 "unverified_insufficient": "unverified", "confirmed_publishable": "confirmed",
                 "confirmed_reported": "confirmed"}


@pytest.mark.parametrize("case", CODE_CASES, ids=[case[0] for case in CODE_CASES])
def test_code_true_positives_reach_exactly_the_specified_stage(case) -> None:
    name, changes = case
    stage, evidence = stage_of(row(**changes))
    assert stage == EXPECTED_CODE[name] and stage in STAGES
    assert evidence


def test_answer_rejected_evidence_names_the_cells_and_roles() -> None:
    stage, evidence = stage_of(row(leads=[lead()], packages=[REJECTED]))
    assert stage == "answer_rejected"
    assert evidence == ("2 red cell(s) over 1 package(s) all ended invalid with schema_error gaps (red_team_analyst); "
                        "the analyst answer was rejected on shape, no claim was proposed")
    assert "answer_rejected" in STAGE_OWNERS and STAGES.index("answer_rejected") == STAGES.index("no_claim") + 1


def test_not_admitted_evidence_records_exclusions_and_severities() -> None:
    stage, evidence = stage_of(row(leads=[lead("not_admitted", "vendored"), lead("not_admitted", None, "unknown", "info")]))
    assert stage == "not_admitted"
    assert "exclusion none x1, vendored x1" in evidence
    assert "reported severity info,unknown" in evidence and "effective severity high,info" in evidence


def test_not_observed_evidence_names_the_planted_site() -> None:
    assert stage_of(row())[1] == "no scanner lead at src/a.cpp:10-12 and no claim"


DEPENDENCY_CASES = sorted([
    ("not_identified", dict(), "not_identified"),
    ("no_version", dict(components=[{"identity": "asr:dependency_package:" + "2" * 64, "version": None}]), "no_version"),
    ("no_advisory", dict(components=[{"identity": "asr:dependency_package:" + "2" * 64, "version": "1.2.11"}]), "no_advisory"),
    ("advisory_not_admitted", dict(leads=[lead("not_admitted", "vendored")]), "not_admitted"),
    ("advisory_no_claim", dict(leads=[lead()], packages=[LEAD_PACKAGE]), "no_claim"),
    ("advisory_unverified", dict(leads=[lead()], claims=[claim("supported")]), "unverified"),
    ("reported", dict(leads=[lead()], claims=[claim("confirmed")], findings=[finding()], reported=True), "reported"),
], key=lambda case: case[0])


@pytest.mark.parametrize("case", DEPENDENCY_CASES, ids=[case[0] for case in DEPENDENCY_CASES])
def test_dependency_true_positives_walk_the_dependency_funnel(case) -> None:
    _name, changes, expected = case
    stage, evidence = stage_of(row("true_positive_dependency", **changes))
    assert stage == expected
    if expected == "no_advisory":
        assert "zlib 1.2.11" in evidence and "CVE-2018-25032" in evidence


@pytest.mark.parametrize("klass", ["false_positive", "fixed_code", "fixed_dependency"])
def test_negatives_are_correctly_passed_or_false_report(klass) -> None:
    passed = stage_of(row(klass, leads=[lead()], claims=[claim("contradicted")]))
    assert passed == ("correctly_passed", "not reported; claim states contradicted")
    assert stage_of(row(klass, packages=[UNIT])) == ("correctly_passed", "not reported; in a hunt unit, no lead and no claim")
    stage, evidence = stage_of(row(klass, leads=[lead()], claims=[claim("confirmed")], findings=[finding()], reported=True))
    assert stage == "false_report" and "reached the report" in evidence


def test_axis_comes_from_the_key_else_the_cwe_else_the_class() -> None:
    assert axis_of({"class": "true_positive_code", "cwe": "CWE-120", "axis": "dead_code"}) == ("dead_code", "key")
    assert axis_of({"class": "true_positive_code", "cwe": "CWE-78"}) == ("control_injection", "cwe_rollup")
    assert axis_of({"class": "true_positive_code", "cwe": "cwe-190"}) == ("numeric_handling", "cwe_rollup")
    assert axis_of({"class": "true_positive_code", "cwe": "CWE-416"}) == ("memory_safety", "cwe_rollup")
    assert axis_of({"class": "true_positive_code", "cwe": "CWE-134"}) == ("format_string", "cwe")
    assert axis_of({"class": "true_positive_code", "cwe": "CWE-362"}) == ("concurrency", "cwe_rollup")
    assert axis_of({"class": "true_positive_dependency", "cve": "CVE-1"}) == ("supply_chain", "class")
    assert axis_of({"class": "false_positive"}) == ("unassigned", "none")
    assert axis_of({"class": "false_positive", "axis": "not_an_axis", "cwe": "CWE-20"}) == ("unassigned", "none")


def _rows() -> list[dict]:
    return [
        staged(item_id="TP-1", axis="memory_safety", real_severity="high", leads=[lead(effective="medium")],
               claims=[claim("confirmed")], findings=[finding(technical="high")], reported=True),
        staged(item_id="TP-2", axis="memory_safety", real_severity="critical", leads=[lead("not_admitted", None, "info", "info")]),
        staged(item_id="TP-3", axis="memory_safety", real_severity="low", packages=[UNIT], claims=[claim("supported")]),
        staged(item_id="FP-1", klass="false_positive", axis="memory_safety", leads=[lead()], claims=[claim("contradicted")]),
        staged(item_id="FX-1", klass="fixed_code", axis="memory_safety", leads=[lead()], claims=[claim("confirmed")],
               findings=[finding()], reported=True),
        staged(item_id="TP-4", axis="control_injection", leads=[lead()], claims=[claim("confirmed")], findings=[finding()]),
        staged(item_id="TP-D1", klass="true_positive_dependency", axis="supply_chain",
               components=[{"identity": "asr:dependency_package:" + "2" * 64, "version": "1.2.11"}]),
        staged(item_id="FP-2", klass="false_positive", axis="unassigned"),
    ]


def test_axis_metrics_count_recall_precision_coverage_stages_and_confidence() -> None:
    by_axis = {axis["axis"]: axis for axis in axis_metrics(_rows())}
    assert list(by_axis) == ["memory_safety", "control_injection", "supply_chain", "unassigned"]
    memory = by_axis["memory_safety"]
    assert (memory["planted"], memory["confirmed"], memory["covered"]) == (3, 1, 2)
    assert memory["recall"] == pytest.approx(1 / 3, abs=1e-4) and memory["coverage"] == pytest.approx(2 / 3, abs=1e-4)
    assert (memory["negatives"], memory["correctly_passed"], memory["false_reports"]) == (2, 1, 1)
    assert memory["precision"] == 0.5 and memory["low_confidence"] is False
    assert memory["stages"] == {"confirmed": 1, "correctly_passed": 1, "false_report": 1, "not_admitted": 1, "unverified": 1}
    injection = by_axis["control_injection"]
    assert injection["recall"] == 1.0 and injection["precision"] == 1.0 and injection["low_confidence"] is True
    supply = by_axis["supply_chain"]
    assert supply["recall"] == 0.0 and supply["precision"] is None and supply["coverage"] == 0.0
    assert supply["stages"] == {"no_advisory": 1}
    assert by_axis["unassigned"]["recall"] is None and by_axis["unassigned"]["negatives"] == 1


def test_severity_handling_is_keyed_only_where_real_severity_is_present() -> None:
    by_axis = {axis["axis"]: axis for axis in axis_metrics(_rows())}
    severity = by_axis["memory_safety"]["severity"]
    assert severity["keyed"] is True and severity["planted_high_admitted_below"] == 2
    by_id = {item["id"]: item for item in severity["items"]}
    assert by_id["TP-1"] == {"id": "TP-1", "planted": "high", "admitted_effective": "medium", "admitted_basis": "admitted_leads",
                             "published_technical": "high", "planted_high_admitted_below": True}
    assert by_id["TP-2"]["admitted_basis"] == "all_leads" and by_id["TP-2"]["admitted_effective"] == "info"
    assert by_id["TP-2"]["planted_high_admitted_below"] is True
    assert by_id["TP-3"] == {"id": "TP-3", "planted": "low", "admitted_effective": None, "admitted_basis": "no_lead",
                             "published_technical": None, "planted_high_admitted_below": False}
    assert "FP-1" not in by_id
    assert by_axis["control_injection"]["severity"] == {"keyed": False, "planted_high_admitted_below": 0, "items": []}


def test_radar_axes_are_the_keyed_axes_padded_to_three_in_vocabulary_order() -> None:
    axes = axis_metrics(_rows())
    assert radar_axes(axes) == ["memory_safety", "control_injection", "supply_chain"]
    assert radar_axes([axis for axis in axes if axis["axis"] == "supply_chain"]) == ["memory_safety", "numeric_handling", "supply_chain"]
    assert radar_axes([]) == list(AXIS_IDS[:3])
    series = {item.label: item for item in radar_series(axes, radar_axes(axes))}
    assert series["Recall"].values == pytest.approx((1 / 3, 1.0, 0.0), abs=1e-4)
    assert series["Recall"].displays == ("1/3", "1/1", "0/1")
    assert series["Precision"].values == (0.5, 1.0, 0.0) and series["Precision"].displays == ("1/2", "1/1", "0/0")
    assert series["Coverage"].values == pytest.approx((2 / 3, 1.0, 0.0), abs=1e-4)
    assert series["Coverage"].displays == ("2/3", "1/1", "0/1")
    padded = radar_series(axes, ["memory_safety", "numeric_handling", "supply_chain"])
    assert padded[0].values[1] == 0.0 and padded[0].displays[1] == "not keyed"


def score(rows=None, *, report=True) -> dict:
    rows = _rows() if rows is None else rows
    return {"schema": SCHEMA, "run_id": "2026-11-16-0004", "authority": "measurement",
            "answer_key": {"schema": "appsec-review/smoke-answer-key/1", "sha256": "ab" * 32, "language": "cpp", "tag": "v1.1.0",
                           "commit": "0" * 40, "planted": len(rows), "version": "1.1.0", "chains": 1, "path": None},
            "structural_checks": [], "check_counts": {}, "jobs": [], "model_calls": {"receipts": 0, "by_job": {}, "review_budget": None},
            "keyed": {"items": rows, "metrics": {"report_available": report}, "by_axis": axis_metrics(rows),
                      "funnel": {}, "complexity": None, "publication_available": {}},
            "evidence_paths": [], "gaps": []}


def test_document_is_deterministic_and_carries_the_radar_tables_and_limits() -> None:
    first, second = smoke_scorecard_document(score()), smoke_scorecard_document(score())
    assert first == second
    assert first.title == "Smoke scorecard" and first.run_id == "2026-11-16-0004" and first.status_badge == "SCORED"
    assert first.ledger_head == "ab" * 32 and first.head_label == "answer key sha256"
    stats = first.blocks[0]
    assert [(stat.label, stat.value) for stat in stats.items] == [
        ("Planted true positives", "5"), ("Confirmed", "2"), ("Recall", "40%"), ("Precision", "67%"), ("False reports", "1")]
    chart = next(block for block in first.blocks if isinstance(block, RadarChart))
    assert [axis.key for axis in chart.axes] == ["MEM", "INJ", "SUP"] and chart.clamped == 0
    assert [series.label for series in chart.series] == ["Recall", "Precision", "Coverage"]
    legend = {(row.kind, row.key): row.meaning for row in chart.legend}
    assert "low confidence" in legend[("axis", "INJ")] and "low confidence" not in legend[("axis", "MEM")]
    assert legend[("axis", "SUP")].startswith("planted 1, confirmed 0, covered 0, negatives 0, false reports 0")
    tex = render_latex(first, TEMPLATE)
    assert tex == render_latex(second, TEMPLATE)
    assert "Funnel by axis" in tex and "Stage reached by each of the 8 planted items" in tex
    assert "What this does not say" in tex and "not keyed" not in tex.split("Severity handling", 1)[1][:400]
    assert "1 planted high" not in tex and "2 planted high items admitted below planted severity" in tex
    assert "Control and injection" in tex and "low{-}confidence" in tex   # the renderer escapes the hyphen


def test_document_without_real_severity_says_severity_is_not_keyed_and_not_evaluable_without_a_report() -> None:
    rows = [staged(item_id="TP-1", axis="memory_safety")]
    document = smoke_scorecard_document(score(rows, report=False))
    assert document.status_badge == "NOT EVALUABLE"
    tex = render_latex(document, TEMPLATE)
    assert "Severity handling: not keyed" in tex and "outcomes are not" in tex
    with pytest.raises(SmokeScoreError, match="no keyed scoring"):
        smoke_scorecard_document({**score(rows), "keyed": None})
    with pytest.raises(SmokeScoreError, match="needs a"):
        smoke_scorecard_document({**score(rows), "schema": "other"})


@dataclass
class _Result:
    exit_code: int
    timed_out: bool = False
    oom_killed: bool = False
    file_size_limit_reached: bool = False
    terminal_status: str = "SUCCEEDED"
    image_id: str = "sha256:" + "e" * 64


def executor_factory(seen: list, *, exit_code=0, pdf=PDF, raise_error: Exception | None = None):
    class FakeExecutor:
        def __init__(self, catalog, root):
            self.catalog, self.root = catalog, root

        def execute(self, request):
            seen.append(request)
            if raise_error is not None:
                raise raise_error
            if pdf is not None:
                (request.scratch_root / "report.pdf").write_bytes(pdf)
            (request.scratch_root / "report.log").write_bytes(b"Overfull \\hbox (1pt)\nOverfull \\vbox\n")
            (request.scratch_root / "report.pdfinfo.txt").write_bytes(b"Title: x\nPages:          3\n")
            return _Result(exit_code)
    return FakeExecutor


def _run(tmp_path: Path) -> Path:
    run = tmp_path / "runs" / "2026-11-16-0004"
    (run / "data" / "jobs").mkdir(parents=True)
    return run


def test_rendered_receipt_binds_tex_pdf_template_and_tool_and_writes_only_under_verification(tmp_path) -> None:
    run = _run(tmp_path)
    seen: list = []
    receipt = render_scorecard(run, score(), repository_root=ROOT, executor_factory=executor_factory(seen))
    out = run / "data" / "verification"
    assert receipt["schema"] == RECEIPT_SCHEMA and receipt["status"] == "rendered" and receipt["named_gaps"] == []
    assert receipt["pages"] == 3 and receipt["overfull_boxes"] == 2
    assert (out / "smoke-scorecard.pdf").read_bytes() == PDF and receipt["pdf_sha256"] == smoke_scorecard._sha256(PDF)
    assert receipt["tex_sha256"] == smoke_scorecard._sha256((out / "smoke-scorecard.tex").read_bytes())
    assert receipt["files"] == ["smoke-scorecard.log", "smoke-scorecard.pdf", "smoke-scorecard.pdfinfo.txt",
                                "smoke-scorecard.tex", "smoke-scorecard-receipt.json"]
    assert {row["name"] for row in receipt["template"]["files"]} == {"appsec-report.cls", "appsec-palette.tex", "report-skeleton.tex"}
    assert receipt["tool"]["id"] == "tool-report-latex" and receipt["tool"]["image_tag"].startswith("appsec-review/tool-report-latex:")
    assert receipt["execution"]["exit_code"] == 0 and receipt["execution"]["image_id"].startswith("sha256:")
    request = seen[0]
    assert request.working_directory == "/scratch" and request.environment == {"SOURCE_DATE_EPOCH": "0"}
    assert [(mount.target, mount.read_only) for mount in request.extra_mounts] == [("/template", True), ("/input", True)]
    assert json.loads((out / "smoke-scorecard-receipt.json").read_text(encoding="utf-8")) == receipt
    files = sorted(path.relative_to(run).as_posix() for path in run.rglob("*") if path.is_file())
    assert files == sorted(f"data/verification/{name}" for name in receipt["files"])
    assert not list(out.glob(".smoke-scorecard-staging-*"))


def test_render_failed_receipt_keeps_the_tex_and_names_the_gap(tmp_path) -> None:
    run = _run(tmp_path)
    receipt = render_scorecard(run, score(), repository_root=ROOT, executor_factory=executor_factory([], exit_code=1))
    assert receipt["status"] == "render_failed" and receipt["named_gaps"] == ["smoke_scorecard_render_failed"]
    assert receipt["pdf_sha256"] is None and receipt["tex_sha256"] and not (run / "data" / "verification" / "smoke-scorecard.pdf").exists()
    invalid = render_scorecard(run, score(), repository_root=ROOT, executor_factory=executor_factory([], pdf=b"not a pdf"))
    assert invalid["named_gaps"] == ["smoke_scorecard_pdf_invalid"] and invalid["status"] == "render_failed"


def test_unavailable_image_is_a_named_gap_never_an_exception(tmp_path) -> None:
    run = _run(tmp_path)
    receipt = render_scorecard(run, score(), repository_root=ROOT,
                               executor_factory=executor_factory([], raise_error=RuntimeError("image not present: secret-token-abc")))
    assert receipt["status"] == "render_failed" and receipt["named_gaps"] == ["smoke_scorecard_renderer_unavailable"]
    assert receipt["execution"]["error"].startswith("RuntimeError:") and receipt["pages"] is None
    assert (run / "data" / "verification" / "smoke-scorecard.tex").is_file()


def test_latex_only_receipt_when_the_pdf_is_not_requested_and_a_stale_pdf_is_removed(tmp_path) -> None:
    run = _run(tmp_path)
    render_scorecard(run, score(), repository_root=ROOT, executor_factory=executor_factory([]))
    receipt = render_scorecard(run, score(), repository_root=ROOT, executor_factory=executor_factory([]), render_pdf=False)
    assert receipt["status"] == "latex_only" and receipt["named_gaps"] == ["smoke_scorecard_pdf_not_requested"]
    assert receipt["files"] == ["smoke-scorecard.tex", "smoke-scorecard-receipt.json"]
    assert not (run / "data" / "verification" / "smoke-scorecard.pdf").exists()


def test_compare_prints_per_axis_recall_and_precision_deltas(tmp_path) -> None:
    base_rows = [staged(item_id="TP-1", axis="memory_safety"), staged(item_id="TP-4", axis="control_injection", leads=[lead()],
                                                                        claims=[claim("confirmed")], findings=[finding()])]
    base = {**score(base_rows), "run_id": "2026-11-16-0003"}
    current = score()
    rows = {row["axis"]: row for row in compare_axes(base, current)}
    assert list(rows) == ["memory_safety", "control_injection", "supply_chain", "unassigned"]
    assert rows["memory_safety"]["recall_delta"] == pytest.approx(1 / 3, abs=1e-4) and rows["memory_safety"]["precision_delta"] is None
    assert rows["control_injection"]["recall_delta"] == 0.0 and rows["supply_chain"]["recall_from"] is None
    text = compare_text(base, current)
    assert text.startswith("trend: 2026-11-16-0003 -> 2026-11-16-0004") and "memory_safety" in text and "+0.3333" in text
    other = tmp_path / "runs" / "2026-11-16-0003" / "data" / "verification"
    other.mkdir(parents=True)
    (other / "smoke-score.json").write_text(json.dumps(base), encoding="utf-8")
    assert load_score(other.parents[1])["run_id"] == "2026-11-16-0003"
    with pytest.raises(SmokeScoreError, match="not a readable smoke score"):
        load_score(tmp_path / "runs" / "missing")
    (other / "smoke-score.json").write_text(json.dumps({**base, "keyed": None}), encoding="utf-8")
    with pytest.raises(SmokeScoreError, match="no per-axis keyed scoring"):
        load_score(other.parents[1])
