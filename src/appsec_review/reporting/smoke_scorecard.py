"""The smoke scorecard: one keyed smoke score as a document, a LaTeX file and a PDF, plus the run-to-run trend.

``smoke_scorecard_document`` is a pure function of a ``appsec-review/smoke-score/1`` document that carries
keyed scoring: the same score always yields an equal :class:`Document` (headline statistics, the radar chart
with the ``Recall``, ``Precision`` and ``Coverage`` series over the key's axes, the per-axis funnel table, the
per-item stage table, the severity-handling table, what the scorecard does not say, and provenance).
``render_scorecard`` writes it under ``runs/<run-id>/data/verification/`` as ``smoke-scorecard.tex``,
``smoke-scorecard.pdf`` (through the pinned ``tool-report-latex`` image, offline, read-only inputs) and a
receipt ``smoke-scorecard-receipt.json`` whose status is ``rendered``, ``render_failed`` or ``latex_only``;
an unavailable image is a named gap in the receipt, never a failure of the scoring. ``compare_text`` prints the
per-axis recall and precision deltas between two scored runs from their ``smoke-score.json`` files.

The scorecard is an operator-side consumer of the answer key: it reads the score document, never the key
itself, writes only under ``data/verification/``, and nothing here is reachable from a job.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
import shutil
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Sequence
import uuid

from appsec_review.container_runtime.catalog import load_catalog
from appsec_review.container_runtime.executor import ContainerExecutor, ExecutionRequest, Mount
from appsec_review.review.secret_redaction import redact_message
from appsec_review.signing.core import SignatureVerificationError
from appsec_review.storage import atomic_bytes, canonical_json, platform_file_sha256
from .digest import bullets, field, table
from .dossier_render import TOOL_ID, template_identity
from .latex import render_latex
from .model import (Box, Document, Fields, Heading, Para, RADAR_MAX_AXES, RADAR_MIN_AXES, RadarAxis, RadarChart,
                    RadarLegendRow, RadarSeries, Stat, Stats)
from .smoke_score import (AXIS_IDS, AXIS_KEY, AXIS_LABEL, CODE_STAGES, CONFIRMED_STAGES, DEPENDENCY_STAGES, JSON_NAME,
                          LOW_CONFIDENCE_PLANTED, NEGATIVE_CLASSES, NEGATIVE_STAGES, OUTPUT_DIRECTORY,
                          POSITIVE_CLASSES, SCHEMA, UNASSIGNED_AXIS, SmokeScoreError)
from .text import clean
from .tokens import BoxKind, Limits

RENDERER = "appsec-review/smoke-scorecard/1"
RECEIPT_SCHEMA = "appsec-review/smoke-scorecard-receipt/1"
TITLE = "Smoke scorecard"
TEX_NAME, PDF_NAME, RECEIPT_NAME = "smoke-scorecard.tex", "smoke-scorecard.pdf", "smoke-scorecard-receipt.json"
LOG_NAME, PDFINFO_NAME = "smoke-scorecard.log", "smoke-scorecard.pdfinfo.txt"
LIMITS = Limits(text_chars=1200, value_chars=200, rows=96, ids=32)
MAX_TEX_BYTES = 8 * 1024 * 1024
MAX_PDF_BYTES = 16 * 1024 * 1024
RENDER_TIMEOUT_SECONDS = 600
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ExecutorFactory = Callable[..., ContainerExecutor]
_PAGES = re.compile(r"^Pages:\s+(\d+)", re.MULTILINE)

# Who decides each stage: the part of the pipeline a loss at that stage points at.
STAGE_OWNERS: dict[str, str] = {
    "not_observed": "scanners (no lead at the planted site, and no hunter claim)",
    "not_admitted": "admission policy (leads existed; none admitted; lead-severity triage and exclusions)",
    "no_claim": "analysts (admitted or hunted; no claim proposed)",
    "answer_rejected": "answer shape contract (every red cell on the item's packages ended invalid with a schema_error gap; the analysis was lost to the validator, not declined)",
    "out_of_scope": "scope rule (every claim decided out_of_scope)",
    "refuted": "verifier and judge (contradicted, not reachable or not exploitable)",
    "unverified": "verifier and judge (supported or insufficient evidence; decision pending)",
    "confirmed": "judge (confirmed finding package, publishable)",
    "not_identified": "inventory (no dependency_package row for the package)",
    "no_version": "inventory (component row without a version)",
    "no_advisory": "advisory matching (version known; no lead names the advisory)",
    "reported": "gate and report (dependency finding reached the report)",
    "correctly_passed": "whole pipeline (a fixed or false-positive item that was not reported)",
    "false_report": "whole pipeline (a fixed or false-positive item that was reported)",
}
SERIES = (
    ("Recall", "confirmed", "recall", "confirmed true positives over planted true positives of the axis; "
                                      "1.0 means every planted item was confirmed and publishable"),
    ("Precision", "supported", "precision", "confirmed true positives over confirmed plus false reports (fixed or "
                                            "false-positive items of the axis that reached the report)"),
    ("Coverage", "proposed", "coverage", "planted true positives the review looked at (admitted or hunted: stage "
                                         "no_claim or later) over planted true positives"),
)
SCALE_NOTE = ("Every spoke is a fraction of the axis's own planted items: the rim (1.0) is every item counted, "
              "the raw counts are in the key and the table. An axis with fewer than "
              f"{LOW_CONFIDENCE_PLANTED} planted items is low-confidence and marked in the key; an axis the key "
              "does not cover is drawn at zero. A short spoke is a loss of the run on planted items, never a "
              "statement about the target.")
NOT_EVIDENCE = ("The scorecard measures the run's published records against the planted items of one small corpus. "
                "It is not evidence about the target, and a high score on it is not a clearance of anything.")


def _pct(value: Any) -> str:
    return "n/a" if value is None else f"{float(value):.0%}"


def _ratio_text(value: Any) -> str:
    return "n/a" if value is None else f"{float(value):.2f}"


def _plural(count: int, noun: str) -> str:
    plural = "axes" if noun == "axis" else noun + "s"
    return f"{count} {noun if count == 1 else plural}"


def radar_axes(axis_rows: Sequence[Mapping[str, Any]]) -> list[str]:
    """The key's axes that carry items, in vocabulary order, padded from the fixed list to at least three."""
    present = {str(row["axis"]) for row in axis_rows if row["axis"] != UNASSIGNED_AXIS}
    axes = [axis for axis in AXIS_IDS if axis in present]
    for axis in AXIS_IDS:
        if len(axes) >= RADAR_MIN_AXES:
            break
        if axis not in axes:
            axes.append(axis)
    return sorted(axes, key=AXIS_IDS.index)[:RADAR_MAX_AXES]


def radar_series(axis_rows: Sequence[Mapping[str, Any]], axes: Sequence[str]) -> list[RadarSeries]:
    by_axis = {str(row["axis"]): row for row in axis_rows}
    series = []
    for label, tone, metric, _meaning in SERIES:
        values, displays = [], []
        for axis in axes:
            row = by_axis.get(axis)
            if row is None:
                values.append(0.0)
                displays.append("not keyed")
                continue
            value = row.get(metric)
            values.append(float(value) if isinstance(value, (int, float)) else 0.0)
            if metric == "recall":
                displays.append(f"{row['confirmed']}/{row['planted']}")
            elif metric == "precision":
                displays.append(f"{row['confirmed']}/{row['confirmed'] + row['false_reports']}")
            else:
                displays.append(f"{row['covered']}/{row['planted']}")
        series.append(RadarSeries(label, tone, tuple(values), tuple(displays)))
    return series


def _axis_meaning(row: Mapping[str, Any] | None) -> str:
    if row is None:
        return "not in the key: no planted item on this axis (drawn at zero)"
    text = (f"planted {row['planted']}, confirmed {row['confirmed']}, covered {row['covered']}, negatives "
            f"{row['negatives']}, false reports {row['false_reports']}")
    if row["low_confidence"]:
        text += f"; low confidence (fewer than {LOW_CONFIDENCE_PLANTED} planted)"
    return text


def _radar(axis_rows: Sequence[Mapping[str, Any]]) -> RadarChart:
    axes = radar_axes(axis_rows)
    by_axis = {str(row["axis"]): row for row in axis_rows}
    legend = [RadarLegendRow("series", label, label, meaning) for label, _tone, _metric, meaning in SERIES]
    legend += [RadarLegendRow("axis", AXIS_KEY[axis], AXIS_LABEL[axis], _axis_meaning(by_axis.get(axis))) for axis in axes]
    return RadarChart("Recall, precision and coverage per axis",
                      tuple(RadarAxis(AXIS_LABEL[axis], AXIS_KEY[axis]) for axis in axes),
                      tuple(radar_series(axis_rows, axes)), scale_note=SCALE_NOTE, legend=tuple(legend))


def _stage_counts(row: Mapping[str, Any]) -> str:
    stages = row.get("stages") or {}
    return ", ".join(f"{stage} {stages[stage]}" for stage in (*CODE_STAGES, *DEPENDENCY_STAGES, *NEGATIVE_STAGES)
                     if stages.get(stage)) or "none"


def _headline(items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    positives = [row for row in items if row["class"] in POSITIVE_CLASSES]
    negatives = [row for row in items if row["class"] in NEGATIVE_CLASSES]
    confirmed = sum(1 for row in positives if row["stage"] in CONFIRMED_STAGES)
    false_reports = sum(1 for row in negatives if row["stage"] == "false_report")
    return {"planted": len(positives), "confirmed": confirmed, "negatives": len(negatives), "false_reports": false_reports,
            "recall": confirmed / len(positives) if positives else None,
            "precision": confirmed / (confirmed + false_reports) if confirmed + false_reports else None}


def _severity_box(axis_rows: Sequence[Mapping[str, Any]]) -> Box:
    rows = []
    flagged = 0
    for axis in axis_rows:
        handling = axis.get("severity") or {}
        flagged += int(handling.get("planted_high_admitted_below") or 0)
        for item in handling.get("items") or ():
            rows.append((item["id"], axis["label"], item["planted"], item["admitted_effective"] or "none",
                         item["admitted_basis"].replace("_", " "), item["published_technical"] or "none",
                         "yes" if item["planted_high_admitted_below"] else "no"))
    if not rows:
        return Box(BoxKind.GAP, "Severity handling: not keyed", chip="NOTICE", items=(
            Para("The answer key carries no real_severity, so the severity the review admitted on and published is "
                 "not compared with a planted severity. The lead rows of smoke-score.json still record each lead's "
                 "reported and effective severity."),))
    return Box(BoxKind.RESULT, f"Severity handling: {_plural(flagged, 'planted high item')} admitted below planted severity",
               items=(Para("Planted severity against the most severe effective severity of the leads the review admitted "
                           "(all leads at the site when none was admitted) and the technical severity published with the "
                           "finding packages. The flag is set when a planted critical or high item was admitted on a "
                           "lower effective severity."),
                      table(("Item", "Axis", "Planted", "Admitted on", "Basis", "Published", "High admitted below"), rows,
                            LIMITS, widths=(.09, .2, .1, .12, .14, .12, .17))))


def smoke_scorecard_document(score: Mapping[str, Any], *, source_date_epoch: int = 0) -> Document:
    """The scorecard document for one keyed ``appsec-review/smoke-score/1`` score."""
    if score.get("schema") != SCHEMA:
        raise SmokeScoreError(f"the scorecard needs a {SCHEMA} document")
    keyed = score.get("keyed")
    if not isinstance(keyed, Mapping):
        raise SmokeScoreError("the smoke score has no keyed scoring; the scorecard needs the answer key")
    items: Sequence[Mapping[str, Any]] = keyed["items"]
    axis_rows: Sequence[Mapping[str, Any]] = keyed["by_axis"]
    head = _headline(items)
    report_available = bool(keyed["metrics"].get("report_available"))
    key_record = score.get("answer_key") if isinstance(score.get("answer_key"), Mapping) else {}
    run_id = clean(score["run_id"])
    low = [row for row in axis_rows if row["axis"] != UNASSIGNED_AXIS and row["low_confidence"]]
    unassigned = next((row for row in axis_rows if row["axis"] == UNASSIGNED_AXIS), None)
    funnel_rows = [(row["key"], row["label"], row["planted"], row["confirmed"], _ratio_text(row["recall"]),
                    _ratio_text(row["precision"]), _ratio_text(row["coverage"]), row["negatives"], row["false_reports"],
                    _stage_counts(row), "low" if row["low_confidence"] else "ok") for row in axis_rows]
    item_rows = [(row["id"], AXIS_LABEL.get(row["axis"], "Unassigned"), row["class"], row["expected_disposition"],
                  row["stage"], row["outcome"], row["stage_evidence"]) for row in items]
    corpus = [f"{row['label']}: {_plural(row['planted'], 'planted true positive')}, {_plural(row['negatives'], 'negative')}"
              + (" (low confidence)" if row["low_confidence"] and row["axis"] != UNASSIGNED_AXIS else "")
              for row in axis_rows]
    blocks: list[Any] = [
        Stats((Stat("Planted true positives", str(head["planted"])),
               Stat("Confirmed", str(head["confirmed"]), "confirmed" if head["confirmed"] else "neutral"),
               Stat("Recall", _pct(head["recall"]), "confirmed" if head["recall"] == 1 else "neutral"),
               Stat("Precision", _pct(head["precision"]), "confirmed" if head["precision"] == 1 else "neutral"),
               Stat("False reports", str(head["false_reports"]), "contradicted" if head["false_reports"] else "neutral"))),
        Heading(1, "Recall, precision and coverage by axis", "axes"),
        _radar(axis_rows),
        Box(BoxKind.EVIDENCE, "Funnel by axis", items=(
            Para("Each axis groups the planted items the key assigns to it (its axis field, or the axis its CWE rolls up "
                 "to). Planted counts true positives; negatives are fixed and false-positive items. Stage counts say "
                 "where each item stopped: the owner of each stage is in the operations document."),
            table(("Key", "Axis", "Planted", "Confirmed", "Recall", "Precision", "Coverage", "Negatives", "False reports",
                   "Stages", "Confidence"), funnel_rows, LIMITS,
                  widths=(.05, .12, .065, .09, .06, .075, .075, .08, .075, .2, .09)),
            Para(f"{_plural(len(low), 'axis')} with fewer than {LOW_CONFIDENCE_PLANTED} planted items "
                 f"{'is' if len(low) == 1 else 'are'} low-confidence: "
                 + (", ".join(row["label"] for row in low) if low else "none") + ".", muted=True),
            *((Para(f"{_plural(unassigned['planted'] + unassigned['negatives'], 'item')} carry no axis and no CWE the "
                    "vocabulary rolls up; they are counted in the Unassigned row and on no spoke.", muted=True),)
              if unassigned else ()))),
        Heading(1, "Planted items", "items"),
        Box(BoxKind.RESULT, f"Stage reached by each of the {_plural(len(items), 'planted item')}", items=(
            table(("Item", "Axis", "Class", "Expected", "Stage", "Outcome", "Evidence"), item_rows, LIMITS,
                  widths=(.085, .13, .14, .11, .12, .08, .3)),
            Para("Outcome is the key's expected disposition against the report (hit, miss, not_evaluable); stage is "
                 "the furthest point the item reached in the review before it was lost, or confirmed.", muted=True))),
        Heading(1, "Severity handling", "severity"),
        _severity_box(axis_rows),
        Heading(1, "What this does not say", "limits"),
        Box(BoxKind.GAP, "Limits of the scorecard", items=(
            bullets([NOT_EVIDENCE,
                     "Corpus size per axis: " + "; ".join(corpus) + ".",
                     f"An axis with fewer than {LOW_CONFIDENCE_PLANTED} planted items is marked low-confidence in the "
                     "key rows: one item decides its whole recall.",
                     "Precision counts only planted negatives that were reported; findings the run reported outside "
                     "the planted items are neither right nor wrong here and are counted in smoke-score.json as "
                     "unmatched.",
                     "The answer key is read by the operator-side scorer only; no job, prompt, configuration or "
                     "guidance reads it." + ("" if report_available else
                                             " The run published no final report, so outcomes are not_evaluable.")],
                    LIMITS, chars=600),)),
        Heading(1, "Provenance", "provenance"),
        Box(BoxKind.PROVENANCE, "Inputs", items=(Fields((
            field("Score document", f"{OUTPUT_DIRECTORY.as_posix()}/{JSON_NAME} ({SCHEMA})", LIMITS, mono=True),
            field("Answer key sha256", key_record.get("sha256"), LIMITS, mono=True),
            field("Answer key", f"{key_record.get('schema')} language {key_record.get('language')} tag "
                                f"{key_record.get('tag')} version {key_record.get('version') or 'unversioned'} "
                                f"planted {key_record.get('planted')} chains {key_record.get('chains', 0)}", LIMITS),
            field("Report available", "yes" if report_available else "no", LIMITS),
            field("Renderer", RENDERER, LIMITS, mono=True))),)),
    ]
    return Document(title=TITLE, run_id=run_id, subtitle=f"Keyed smoke scoring of run {run_id}",
                    status_badge="SCORED" if report_available else "NOT EVALUABLE",
                    status_tone="confirmed" if report_available else "unresolved", source_date_epoch=source_date_epoch,
                    ledger_head=clean(key_record.get("sha256")), blocks=tuple(blocks), renderer=RENDERER,
                    head_label="answer key sha256")


# -- rendering ------------------------------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _copy_bounded(source: Path, destination: Path, limit: int) -> bytes | None:
    if source.is_file() and not source.is_symlink() and source.stat().st_size <= limit:
        data = source.read_bytes()
        atomic_bytes(destination, data)
        return data
    return None


def _render_pdf(run: Path, out: Path, tex: bytes, epoch: int, template: Path, root: Path,
                executor_factory: ExecutorFactory, tool_identity: dict[str, Any]) -> tuple[bytes | None, list[str], dict[str, Any] | None, dict[str, Any]]:
    staging = out / f".smoke-scorecard-staging-{uuid.uuid4().hex}"
    inputs, scratch = staging / "input", staging / "scratch"
    scratch.mkdir(parents=True)
    inputs.mkdir()
    atomic_bytes(inputs / "report.tex", tex)
    atomic_bytes(inputs / "source-date-epoch", f"{epoch}\n".encode())
    extras: dict[str, Any] = {"pages": None, "overfull_boxes": None}
    try:
        catalog = load_catalog(root)
        tool = replace(catalog.tool(TOOL_ID), timeout_seconds=RENDER_TIMEOUT_SECONDS)
        catalog = replace(catalog, tools=MappingProxyType({**catalog.tools, TOOL_ID: tool}))
        tool_identity.update(image_tag=tool.tag, version=tool.version,
                             manifest_sha256=platform_file_sha256(tool.manifest_path))
        result = executor_factory(catalog, run).execute(ExecutionRequest(
            tool_id=TOOL_ID, argv=(tool.executable,), target_root=inputs, scratch_root=scratch,
            extra_mounts=(Mount(template, "/template"), Mount(inputs, "/input")),
            environment={"SOURCE_DATE_EPOCH": str(epoch)},
            working_directory="/scratch", file_size_limit_bytes=MAX_PDF_BYTES))
        log = _copy_bounded(scratch / "report.log", out / LOG_NAME, MAX_PDF_BYTES)
        info = _copy_bounded(scratch / "report.pdfinfo.txt", out / PDFINFO_NAME, MAX_PDF_BYTES)
        if log is not None:
            extras["overfull_boxes"] = log.count(b"Overfull")
        if info is not None:
            found = _PAGES.search(info.decode("utf-8", "replace"))
            extras["pages"] = int(found.group(1)) if found else None
        execution = {"terminal_status": result.terminal_status, "exit_code": result.exit_code,
                     "timed_out": result.timed_out, "oom_killed": result.oom_killed,
                     "file_size_limit_reached": result.file_size_limit_reached, "image_id": result.image_id}
        pdf = scratch / "report.pdf"
        if result.timed_out:
            return None, ["smoke_scorecard_render_timeout"], execution, extras
        if (result.exit_code != 0 or result.oom_killed or result.file_size_limit_reached
                or not pdf.is_file() or pdf.is_symlink()):
            return None, ["smoke_scorecard_render_failed"], execution, extras
        data = pdf.read_bytes() if pdf.stat().st_size <= MAX_PDF_BYTES else b""
        if len(data) <= 32 or not data.startswith(b"%PDF-") or not data.rstrip().endswith(b"%%EOF"):
            return None, ["smoke_scorecard_pdf_invalid"], execution, extras
        return data, [], execution, extras
    except (OSError, RuntimeError, ValueError, SignatureVerificationError) as exc:
        # Image absent, pin mismatch, no container runtime or no signing policy on this host: the scorecard
        # records the gap; the scoring stands.
        detail = redact_message(f"{type(exc).__name__}: {exc}", bound=240) or type(exc).__name__
        return None, ["smoke_scorecard_renderer_unavailable"], {"error": detail}, extras
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def render_scorecard(run_dir: Path, score: Mapping[str, Any], *, repository_root: Path | None = None,
                     executor_factory: ExecutorFactory = ContainerExecutor, render_pdf: bool = True,
                     source_date_epoch: int = 0) -> dict[str, Any]:
    """Write the scorecard .tex (and .pdf) with its receipt under ``data/verification/``; returns the receipt.

    Status ``rendered`` (tex and a valid PDF), ``latex_only`` (``render_pdf`` false) or ``render_failed`` (the
    image did not produce a valid PDF, or was unavailable: see ``named_gaps``). Never raises for a rendering
    problem; a missing template or an unreadable score is a caller error and does raise.
    """
    run = Path(run_dir).resolve()
    out = run / OUTPUT_DIRECTORY
    out.mkdir(parents=True, exist_ok=True)
    root = Path(repository_root or REPOSITORY_ROOT).resolve()
    template = root / "containers" / "report" / "latex" / "template"
    identity = template_identity(template)
    document = smoke_scorecard_document(score, source_date_epoch=source_date_epoch)
    tex = render_latex(document, template).encode("utf-8")
    for stale in (TEX_NAME, PDF_NAME, LOG_NAME, PDFINFO_NAME, RECEIPT_NAME):
        (out / stale).unlink(missing_ok=True)       # never leave an older PDF beside a newer .tex
    tool_identity: dict[str, Any] = {"id": TOOL_ID}
    gaps: list[str] = []
    execution: dict[str, Any] | None = None
    extras: dict[str, Any] = {"pages": None, "overfull_boxes": None}
    pdf: bytes | None = None
    tex_sha256: str | None = None
    if len(tex) > MAX_TEX_BYTES:
        status = "render_failed"
        gaps.append("smoke_scorecard_tex_too_large")
    else:
        atomic_bytes(out / TEX_NAME, tex)
        tex_sha256 = _sha256(tex)
        if not render_pdf:
            status = "latex_only"
            gaps.append("smoke_scorecard_pdf_not_requested")
        else:
            pdf, render_gaps, execution, extras = _render_pdf(run, out, tex, source_date_epoch, template, root,
                                                              executor_factory, tool_identity)
            gaps.extend(render_gaps)
            status = "rendered" if pdf is not None else "render_failed"
            if pdf is not None:
                atomic_bytes(out / PDF_NAME, pdf)
    receipt = {
        "schema": RECEIPT_SCHEMA, "run_id": clean(score["run_id"]), "status": status,
        "score_sha256": _sha256(canonical_json(score)), "tex_sha256": tex_sha256,
        "pdf_sha256": _sha256(pdf) if pdf is not None else None,
        "pages": extras["pages"], "overfull_boxes": extras["overfull_boxes"],
        "files": sorted(name for name in (TEX_NAME, PDF_NAME, LOG_NAME, PDFINFO_NAME) if (out / name).is_file()) + [RECEIPT_NAME],
        "template": identity, "tool": tool_identity, "renderer": RENDERER, "source_date_epoch": source_date_epoch,
        "execution": execution, "named_gaps": sorted(set(gaps)),
        "policy": {"network": "none", "shell_escape": False, "input_read_only": True, "template_read_only": True,
                   "run_evidence": "read_only", "writes": OUTPUT_DIRECTORY.as_posix()},
    }
    atomic_bytes(out / RECEIPT_NAME, canonical_json(receipt))
    return receipt


def receipt_line(receipt: Mapping[str, Any], run_dir: Path) -> str:
    out = (Path(run_dir) / OUTPUT_DIRECTORY).as_posix()
    line = f"scorecard: {receipt['status']} -> {out}/{TEX_NAME}"
    if receipt.get("pdf_sha256"):
        line += f" and {out}/{PDF_NAME} (pages={receipt.get('pages')}, overfull_boxes={receipt.get('overfull_boxes')})"
    if receipt.get("named_gaps"):
        line += "; gaps: " + ", ".join(receipt["named_gaps"])
    return line


# -- trend -----------------------------------------------------------------------------------------------------


def load_score(run_dir: Path) -> dict[str, Any]:
    """A scored run's ``smoke-score.json``; a run that was not scored with a key is a usage error."""
    path = Path(run_dir) / OUTPUT_DIRECTORY / JSON_NAME
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SmokeScoreError(f"{path} is not a readable smoke score: {exc}") from exc
    if not isinstance(document, Mapping) or document.get("schema") != SCHEMA:
        raise SmokeScoreError(f"{path} is not {SCHEMA}")
    if not isinstance(document.get("keyed"), Mapping) or not isinstance(document["keyed"].get("by_axis"), list):
        raise SmokeScoreError(f"{path} carries no per-axis keyed scoring; score that run with the key first")
    return dict(document)


def _delta(before: Any, after: Any) -> float | None:
    if isinstance(before, (int, float)) and isinstance(after, (int, float)):
        return round(float(after) - float(before), 4)
    return None


def compare_axes(base: Mapping[str, Any], current: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Per axis: recall and precision in both runs and their deltas (``None`` where either side is undefined)."""
    before = {row["axis"]: row for row in base["keyed"]["by_axis"]}
    after = {row["axis"]: row for row in current["keyed"]["by_axis"]}
    rows = []
    for axis in (*AXIS_IDS, UNASSIGNED_AXIS):
        if axis not in before and axis not in after:
            continue
        b, a = before.get(axis, {}), after.get(axis, {})
        rows.append({"axis": axis, "planted_from": b.get("planted"), "planted_to": a.get("planted"),
                     "recall_from": b.get("recall"), "recall_to": a.get("recall"),
                     "recall_delta": _delta(b.get("recall"), a.get("recall")),
                     "precision_from": b.get("precision"), "precision_to": a.get("precision"),
                     "precision_delta": _delta(b.get("precision"), a.get("precision"))})
    return rows


def compare_text(base: Mapping[str, Any], current: Mapping[str, Any]) -> str:
    def signed(value: float | None) -> str:
        return "n/a" if value is None else f"{value:+.4f}"

    lines = [f"trend: {base['run_id']} -> {current['run_id']} (per-axis recall and precision)"]
    for row in compare_axes(base, current):
        lines.append(f"  {row['axis']:<20} planted {row['planted_from']}->{row['planted_to']}  "
                     f"recall {row['recall_from']}->{row['recall_to']} ({signed(row['recall_delta'])})  "
                     f"precision {row['precision_from']}->{row['precision_to']} ({signed(row['precision_delta'])})")
    return "\n".join(lines) + "\n"


__all__ = ["RECEIPT_SCHEMA", "RENDERER", "STAGE_OWNERS", "compare_axes", "compare_text", "load_score", "radar_axes",
           "radar_series", "receipt_line", "render_scorecard", "smoke_scorecard_document"]
