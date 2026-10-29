"""Render the end-of-review telemetry report to LaTeX and PDF with the pinned report image.

``render_telemetry_report`` reads a run directory read-only (``pipeline.jsonl`` and the metrics
summary; neither is ever written) and writes ``data/telemetry/report/``:

* ``telemetry-report.tex``, and ``telemetry-report.pdf`` when the container produced a valid PDF;
* ``report.log`` and ``report.pdfinfo.txt`` when the renderer left them;
* ``receipt.json`` (``appsec-review/telemetry-report-receipt/1``, canonical JSON).

Everything is assembled in a fresh sibling staging directory and swapped in by rename, so a re-render
never mixes old and new files. A rendering failure (missing image, non-zero exit, timeout, invalid PDF,
oversized LaTeX) is a ``failed`` receipt with named gaps, never an exception and never a change to the
run's completion status. ``enabled = false`` is a no-op: nothing is read or written and the returned,
unpersisted receipt has status ``disabled`` (an earlier report directory is left as it was).
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import shutil
from types import MappingProxyType
from typing import Any, Callable, Mapping
import uuid

from appsec_review.config.telemetry_report import TelemetryReportSettings
from appsec_review.container_runtime.catalog import load_catalog
from appsec_review.container_runtime.executor import ContainerExecutor, ExecutionRequest, Mount
from appsec_review.review.secret_redaction import redact_message
from appsec_review.storage import atomic_bytes, canonical_json, file_sha256
from .dossier_render import TOOL_ID, template_identity
from .latex import render_latex
from .telemetry import build_document, load_inputs

RECEIPT_SCHEMA = "appsec-review/telemetry-report-receipt/1"
REPORT_PATH = Path("data") / "telemetry" / "report"
TEX_NAME, PDF_NAME, RECEIPT_NAME = "telemetry-report.tex", "telemetry-report.pdf", "receipt.json"
RETAINED_LOGS = ("report.log", "report.pdfinfo.txt")
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ExecutorFactory = Callable[..., ContainerExecutor]


@dataclass(frozen=True, slots=True)
class TelemetryReportReceipt:
    """The receipt record plus where it was written (``None`` when disabled)."""

    record: Mapping[str, Any]
    report_dir: Path | None

    @property
    def status(self) -> str:
        return self.record["status"]

    @property
    def named_gaps(self) -> tuple[str, ...]:
        return tuple(self.record["named_gaps"])


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _copy_bounded(source: Path, destination: Path, limit: int) -> bool:
    if source.is_file() and not source.is_symlink() and source.stat().st_size <= limit:
        atomic_bytes(destination, source.read_bytes())
        return True
    return False


def _render_pdf(run_dir: Path, staging: Path, tex: bytes, epoch: int, settings: TelemetryReportSettings,
                template: Path, repository_root: Path, executor_factory: ExecutorFactory,
                tool_identity: dict[str, Any]) -> tuple[bytes | None, list[str], dict[str, Any] | None]:
    inputs, scratch = staging / "input", staging / "scratch"
    inputs.mkdir()
    scratch.mkdir()
    atomic_bytes(inputs / "report.tex", tex)
    atomic_bytes(inputs / "source-date-epoch", f"{epoch}\n".encode())
    try:
        catalog = load_catalog(repository_root)
        tool = replace(catalog.tool(TOOL_ID), tag=settings.image_tag, expected_image_id=settings.image_id,
                       timeout_seconds=settings.timeout_seconds)
        catalog = replace(catalog, tools=MappingProxyType({**catalog.tools, TOOL_ID: tool}))
        tool_identity.update(version=tool.version, manifest_sha256=file_sha256(tool.manifest_path))
        result = executor_factory(catalog, run_dir).execute(ExecutionRequest(
            tool_id=TOOL_ID, argv=(tool.executable,), target_root=inputs, scratch_root=scratch,
            extra_mounts=(Mount(template, "/template"), Mount(inputs, "/input")),
            environment={"SOURCE_DATE_EPOCH": str(epoch)},
            working_directory="/scratch", file_size_limit_bytes=settings.max_pdf_bytes))
        for name in RETAINED_LOGS:
            _copy_bounded(scratch / name, staging / name, settings.max_pdf_bytes)
        execution = {"terminal_status": result.terminal_status, "exit_code": result.exit_code,
                     "timed_out": result.timed_out, "oom_killed": result.oom_killed,
                     "file_size_limit_reached": result.file_size_limit_reached, "image_id": result.image_id}
        pdf = scratch / "report.pdf"
        if result.timed_out:
            return None, ["telemetry_report_render_timeout"], execution
        if (result.exit_code != 0 or result.oom_killed or result.file_size_limit_reached
                or not pdf.is_file() or pdf.is_symlink()):
            return None, ["telemetry_report_render_failed"], execution
        data = pdf.read_bytes() if pdf.stat().st_size <= settings.max_pdf_bytes else b""
        if len(data) <= 32 or not data.startswith(b"%PDF-") or not data.rstrip().endswith(b"%%EOF"):
            return None, ["telemetry_report_pdf_invalid"], execution
        return data, [], execution
    except (OSError, RuntimeError, ValueError) as exc:
        # Image absent or pin mismatch: an end-of-run report records the gap instead of failing the run.
        detail = redact_message(f"{type(exc).__name__}: {exc}", bound=240) or type(exc).__name__
        return None, ["telemetry_report_renderer_unavailable"], {"error": detail}
    finally:
        # Only these two freshly created staging directories are disposable.
        shutil.rmtree(inputs, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def _swap_in(staging: Path, report_dir: Path) -> None:
    retired = None
    if report_dir.exists():
        retired = report_dir.with_name(f".report-retired-{uuid.uuid4().hex}")
        report_dir.rename(retired)
    staging.rename(report_dir)
    if retired is not None:
        shutil.rmtree(retired)


def render_telemetry_report(run_dir: Path, settings: TelemetryReportSettings, *,
                            repository_root: Path | None = None,
                            executor_factory: ExecutorFactory = ContainerExecutor) -> TelemetryReportReceipt:
    """Render ``run_dir``'s telemetry report; returns the receipt (status ``rendered``, ``tex_only``,
    ``failed`` or ``disabled``)."""
    run = Path(run_dir).resolve()
    if not settings.enabled:
        record = {"schema": RECEIPT_SCHEMA, "run_id": run.name, "status": "disabled",
                  "named_gaps": ["telemetry_report_disabled_by_policy"],
                  "settings_sha256": settings.settings_sha256()}
        return TelemetryReportReceipt(MappingProxyType(record), None)
    root = Path(repository_root or REPOSITORY_ROOT).resolve()
    template = root / "containers" / "report" / "latex" / "template"
    identity = template_identity(template)
    inputs = load_inputs(run)
    document = build_document(inputs)
    tex = render_latex(document, template).encode("utf-8")
    report_dir = run / REPORT_PATH
    report_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = report_dir.with_name(f".report-staging-{uuid.uuid4().hex}")
    staging.mkdir()
    tool_identity: dict[str, Any] = {"id": TOOL_ID, "image_tag": settings.image_tag, "image_id": settings.image_id}
    render_gaps: list[str] = []
    pdf: bytes | None = None
    execution: dict[str, Any] | None = None
    try:
        if len(tex) > settings.max_tex_bytes:
            status, tex_sha256 = "failed", None
            render_gaps.append("telemetry_report_tex_too_large")
        else:
            atomic_bytes(staging / TEX_NAME, tex)
            tex_sha256 = _sha256(tex)
            if not settings.render_pdf:
                status = "tex_only"
                render_gaps.append("telemetry_report_pdf_disabled_by_policy")
            else:
                pdf, gaps, execution = _render_pdf(run, staging, tex, document.source_date_epoch, settings,
                                                   template, root, executor_factory, tool_identity)
                render_gaps.extend(gaps)
                status = "rendered" if pdf is not None else "failed"
                if pdf is not None:
                    atomic_bytes(staging / PDF_NAME, pdf)
        if template_identity(template) != identity:
            raise RuntimeError("telemetry report template changed during rendering")
        record = {
            "schema": RECEIPT_SCHEMA, "run_id": inputs.run_id, "status": status,
            "summary_source": inputs.summary_source, "summary_sha256": inputs.summary_sha256,
            "events_sha256": inputs.events_sha256, "tex_sha256": tex_sha256,
            "pdf_sha256": _sha256(pdf) if pdf is not None else None,
            "files": sorted([*(path.name for path in staging.iterdir()), RECEIPT_NAME]),
            "template": identity, "tool": tool_identity, "renderer": document.renderer,
            "source_date_epoch": document.source_date_epoch, "settings_sha256": settings.settings_sha256(),
            "execution": execution,
            "named_gaps": sorted(set(document.named_gaps) | set(render_gaps)),
            "policy": {"network": "none", "shell_escape": False, "input_read_only": True,
                       "template_read_only": True, "run_evidence": "read_only"},
        }
        atomic_bytes(staging / RECEIPT_NAME, canonical_json(record))
        _swap_in(staging, report_dir)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return TelemetryReportReceipt(MappingProxyType(record), report_dir)


__all__ = ["RECEIPT_SCHEMA", "REPORT_PATH", "TelemetryReportReceipt", "TelemetryReportSettings",
           "render_telemetry_report"]
