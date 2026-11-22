"""Render the executive PDF of ``final-report.json`` through the pinned ``tool-report-latex`` image.

``bind_dossiers`` reads the dossier documents the gate certified, each through
:func:`appsec_review.jobs.bound_artifacts.read_bound_json`, so the bytes are proven against the gate's
hash before a word of them reaches the report; claimed JSON that is missing, changed or malformed
fails integrity validation. ``render_executive_latex`` is the pure function from the report
and the bound dossiers to ``final-report.tex``. ``render_executive_pdf`` writes the LaTeX, runs the
container once with ``SOURCE_DATE_EPOCH=0``, keeps only a valid PDF, retains the renderer's logs, and
writes a receipt (``appsec-review/final-report-pdf-receipt/1``). A rendering failure retains the LaTeX
and names the gap; it never produces an invented PDF and never changes a finding.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from appsec_review.container_runtime.catalog import load_catalog
from appsec_review.container_runtime.executor import ContainerExecutor, ExecutionRequest, Mount
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.jobs.completion_contracts import DOSSIER_SCHEMA
from appsec_review.reporting.dossier_render import TOOL_ID
from appsec_review.reporting.dossier_receipts import verify_additional_formats
from appsec_review.reporting.executive_report import RENDERER, BoundDossier, executive_document
from appsec_review.reporting.executive_latex import render_latex, template_identity
from appsec_review.review.models import IntegrityError
from appsec_review.review.secret_redaction import redact_message
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, platform_file_sha256

from .settings import FinalReportSettings

RECEIPT_SCHEMA = "appsec-review/final-report-pdf-receipt/1"
TEX_NAME, PDF_NAME, RECEIPT_NAME = "final-report.tex", "final-report.pdf", "receipt.json"
RETAINED_LOGS = ("report.log", "report.pdfinfo.txt", "report.txt")
SOURCE_DATE_EPOCH = 0
ExecutorFactory = Callable[..., ContainerExecutor]

REASONS = {
    "rendered": ("Rendered deterministically from final-report.json and the gate-bound dossier JSON through the "
                 "pinned tool-report-latex image (SOURCE_DATE_EPOCH 0)."),
    "not_rendered": ("PDF rendering is disabled by policy (render_pdf = false); the LaTeX source is retained and "
                     "no PDF is produced."),
    "render_failed": "The renderer did not produce a valid PDF; the LaTeX source and the renderer logs are retained.",
}


def template_dir(repository_root: Path) -> Path:
    return Path(repository_root) / "containers" / "report" / "latex" / "template"


def bind_dossiers(run_root: Path, report: Mapping[str, Any],
                  bindings: Sequence[Mapping[str, Any]] | None = None) -> tuple[BoundDossier, ...]:
    """The gate-certified dossier documents, each hash- and identity-checked, or an integrity failure.

    With ``bindings`` (the gate's binding set), a dossier reference the gate did not bind is an
    :class:`IntegrityError`: the report reads nothing the gate does not bind.
    """
    bound = None if bindings is None else {(row["path"], row["sha256"]) for row in bindings}
    result = []
    for item in report["dossiers"]["items"]:
        reference = item["files"]["json"]
        if bound is not None and (reference["path"], reference["sha256"]) not in bound:
            raise IntegrityError(f"dossier {item['dossier_id']} is not bound by the accepted gate")
        document = read_bound_json(run_root, reference)
        if not isinstance(document, Mapping) or document.get("schema") != DOSSIER_SCHEMA:
            raise IntegrityError(f"executive dossier {item['dossier_id']} has an unsupported schema")
        if (document.get("dossier_id") != item["dossier_id"] or document.get("finding") != item["finding"]
                or document.get("kind") != item["kind"] or document.get("run_id") != report["run_id"]
                or document.get("visibility") != "protected_developer"):
            raise IntegrityError(f"executive dossier {item['dossier_id']} disagrees with its certified identity")
        receipt_ref = item["files"]["receipt"]
        if bound is not None and (receipt_ref["path"], receipt_ref["sha256"]) not in bound:
            raise IntegrityError(f"dossier receipt {item['dossier_id']} is not bound by the accepted gate")
        receipt = read_bound_json(run_root, receipt_ref)
        formats = verify_additional_formats(run_root, receipt, bound=bound)
        if (receipt.get("dossier_id") != item["dossier_id"] or receipt.get("run_id") != report["run_id"]
                or receipt.get("status") != item["status"]
                or receipt.get("files") != {name: item["files"][name] for name in ("json", "latex", "pdf")}):
            raise IntegrityError(f"dossier receipt {item['dossier_id']} disagrees with its certified identity")
        result.append(BoundDossier(item["dossier_id"], item["kind"], dict(item["finding"]), document,
                                   additional_formats=formats))
    return tuple(sorted(result, key=lambda row: row.dossier_id))


def render_executive_latex(report: Mapping[str, Any], dossiers: Sequence[BoundDossier], template: Path) -> bytes:
    """``final-report.tex``: a pure function of the report document and the bound dossiers."""
    text = render_latex(executive_document(report, dossiers, source_date_epoch=SOURCE_DATE_EPOCH), template)
    again = render_latex(executive_document(report, dossiers, source_date_epoch=SOURCE_DATE_EPOCH), template)
    if text != again:
        raise IntegrityError("executive report rendering is not deterministic")
    return text.encode("utf-8")


def valid_pdf(data: bytes, limit: int) -> bool:
    return 32 < len(data) <= limit and data.startswith(b"%PDF-") and data.rstrip().endswith(b"%%EOF")


def _retain_execution(root: Path, output: Path, result: Any, limit: int) -> dict[str, str] | None:
    execution_path = root / result.receipt_path
    if not execution_path.is_file():
        return None
    execution = json.loads(execution_path.read_bytes())
    for key in ("stdout_path", "stderr_path"):
        stream = root / execution[key]
        if stream.is_file() and not stream.is_symlink() and stream.stat().st_size <= limit:
            destination = output / ("container-" + key.removesuffix("_path") + ".bin")
            atomic_bytes(destination, stream.read_bytes())
            execution[key] = destination.relative_to(root).as_posix()
    retained = output / "container-execution.json"
    atomic_json(retained, execution)
    return artifact_ref(root, retained)


def render_executive_pdf(run_root: Path, output_dir: Path, report: Mapping[str, Any],
                         dossiers: Sequence[BoundDossier], *, report_ref: Mapping[str, str],
                         settings: FinalReportSettings, repository_root: Path,
                         executor_factory: ExecutorFactory = ContainerExecutor) -> dict[str, Any]:
    """Write ``final-report.tex``, the PDF when the container produced a valid one, and the receipt."""
    root = Path(run_root).resolve()
    output = Path(output_dir).resolve()
    if root not in output.parents:
        raise IntegrityError("executive report output must be run-owned")
    output.mkdir(parents=True, exist_ok=True)
    if any((output / name).exists() for name in (TEX_NAME, PDF_NAME, RECEIPT_NAME)):
        raise IntegrityError("executive report output directory is not fresh")
    template = template_dir(repository_root)
    identity = template_identity(template)
    tex = render_executive_latex(report, dossiers, template)
    if len(tex) > settings.max_pdf_bytes:
        raise IntegrityError("executive report LaTeX exceeds max_pdf_bytes")
    atomic_bytes(output / TEX_NAME, tex)
    files: dict[str, Any] = {"latex": artifact_ref(root, output / TEX_NAME), "pdf": None}
    gaps = [row.gap for row in dossiers if row.gap]
    tool_identity: dict[str, Any] = {"id": TOOL_ID, "tag": settings.image_tag, "image_id": settings.image_id}
    execution_ref = None
    pdf_sha256 = None
    if not settings.render_pdf:
        status = "not_rendered"
        gaps.append("final_report_pdf_disabled_by_policy")
    else:
        status = "render_failed"
        inputs, scratch = output / "input", output / "scratch"
        inputs.mkdir()
        scratch.mkdir()
        atomic_bytes(inputs / "report.tex", tex)
        atomic_bytes(inputs / "source-date-epoch", f"{SOURCE_DATE_EPOCH}\n".encode())
        try:
            catalog = load_catalog(repository_root)
            tool = replace(catalog.tool(TOOL_ID), tag=settings.image_tag, expected_image_id=settings.image_id,
                           timeout_seconds=settings.render_timeout_seconds)
            catalog = replace(catalog, tools=MappingProxyType({**catalog.tools, TOOL_ID: tool}))
            tool_identity.update(version=tool.version, manifest_sha256=platform_file_sha256(tool.manifest_path),
                                 runtime_policy_sha256=platform_file_sha256(catalog.runtime_policy))
            result = executor_factory(catalog, root).execute(ExecutionRequest(
                tool_id=TOOL_ID, argv=(tool.executable,), target_root=inputs, scratch_root=scratch,
                extra_mounts=(Mount(template, "/template"), Mount(inputs, "/input")),
                environment={"SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH)},
                working_directory="/scratch", file_size_limit_bytes=settings.max_pdf_bytes))
            execution_ref = _retain_execution(root, output, result, settings.max_pdf_bytes)
            for name in RETAINED_LOGS:
                source = scratch / name
                if source.is_file() and not source.is_symlink() and source.stat().st_size <= settings.max_pdf_bytes:
                    atomic_bytes(output / name, source.read_bytes())
            pdf = scratch / "report.pdf"
            data = b""
            if (result.exit_code == 0 and not result.timed_out and not result.oom_killed
                    and not result.file_size_limit_reached and pdf.is_file() and not pdf.is_symlink()
                    and pdf.stat().st_size <= settings.max_pdf_bytes):
                data = pdf.read_bytes()
            if valid_pdf(data, settings.max_pdf_bytes):
                atomic_bytes(output / PDF_NAME, data)
                files["pdf"] = artifact_ref(root, output / PDF_NAME)
                pdf_sha256 = files["pdf"]["sha256"]
                status = "rendered"
            else:
                gaps.append(f"final_report_pdf_render_failed: {result.terminal_status}, exit={result.exit_code}")
        except ValueError as exc:
            # A changed immutable tool pin or configuration is an integrity failure, not a rendering gap.
            raise IntegrityError(f"executive report renderer configuration or image integrity failure: {exc}") from exc
        except (OSError, RuntimeError) as exc:
            gaps.append("final_report_pdf_renderer_unavailable: " + type(exc).__name__ + ": "
                        + (redact_message(str(exc), bound=240) or "No diagnostic supplied."))
        finally:
            # Only these two freshly created, run-owned staging directories are disposable.
            shutil.rmtree(inputs)
            shutil.rmtree(scratch)
    if template_identity(template) != identity:
        raise IntegrityError("report template changed during rendering")
    receipt = {
        "schema": RECEIPT_SCHEMA, "run_id": report["run_id"], "status": status, "reason": REASONS[status],
        "renderer": RENDERER, "report": dict(report_ref), "files": files,
        "tex_sha256": hashlib.sha256(tex).hexdigest(), "pdf_sha256": pdf_sha256,
        "source_date_epoch": SOURCE_DATE_EPOCH, "template": identity, "tool": tool_identity,
        "settings_sha256": settings.settings_sha256(), "execution": execution_ref,
        "dossiers": {"certified": len(dossiers), "read": sum(1 for row in dossiers if row.document),
                     "unavailable": [row.dossier_id for row in dossiers if row.gap]},
        "named_gaps": sorted(set(gaps)),
        "policy": {"network": "none", "shell_escape": False, "input_read_only": True, "template_read_only": True,
                   "source_excerpts": "not_included", "generated_code_execution": "not_performed_by_policy"},
    }
    atomic_bytes(output / RECEIPT_NAME, canonical_json(receipt))
    return {"status": status, "reason": REASONS[status], "files": {**files, "receipt": artifact_ref(root, output / RECEIPT_NAME)},
            "tex_sha256": receipt["tex_sha256"], "pdf_sha256": pdf_sha256, "gaps": receipt["named_gaps"]}


__all__ = ["RECEIPT_SCHEMA", "TEX_NAME", "PDF_NAME", "RECEIPT_NAME", "bind_dossiers", "render_executive_latex",
           "render_executive_pdf", "template_dir", "valid_pdf"]
