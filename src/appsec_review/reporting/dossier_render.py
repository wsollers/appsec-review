"""Retain dossier JSON/LaTeX/Markdown/HTML/PDF through the commissioned container runtime."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import html
import json
from pathlib import Path
import shutil
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Callable, Mapping

from appsec_review.container_runtime.catalog import load_catalog
from appsec_review.container_runtime.executor import ContainerExecutor, ExecutionRequest, Mount
from appsec_review.jobs.bound_artifacts import artifact_ref
from appsec_review.review.models import IntegrityError
from appsec_review.review.secret_redaction import redact_message
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, platform_file_sha256
from .dossiers import dossier_document
from .dossier_receipts import RECEIPT_SCHEMA, verify_additional_formats
from .html import render_html
from .latex import render_latex
from .code_flow import role_title, to_mermaid
from .model import Block, Box, Bullets, Code, Fields, FlowDiagram, Heading, Para, Stats, Table, Truncation

if TYPE_CHECKING:
    from appsec_review.jobs.job_dossier_publication.settings import DossierPublicationSettings

TOOL_ID = "tool-report-latex"
ExecutorFactory = Callable[..., ContainerExecutor]


def _md_text(value: str) -> str:
    text = html.escape(value, quote=False).replace("\\", "\\\\").replace("\n", " ")
    for token in ("`", "*", "_", "[", "]", "#", "|"):
        text = text.replace(token, "\\" + token)
    return text


def _md_code(value: str) -> str:
    fence = "`"
    while fence in value:
        fence += "`"
    return f"{fence} {value.replace(chr(10), ' ')} {fence}"


def _md_truncation(cut: Truncation | None) -> list[str]:
    return [] if cut is None else [
        f"Bounded omission: {cut.omitted} {cut.unit}; SHA-256 {_md_code(cut.sha256)}."]


def render_dossier_html(dossier: Mapping[str, Any]) -> str:
    """Render a deterministic, self-contained HTML developer dossier."""
    return render_html(dossier_document(dossier))


def _render_block(block: Block) -> list[str]:
    lines: list[str] = []
    if isinstance(block, Heading):
        lines.extend(["#" * (block.level + 1) + " " + _md_text(block.text), ""])
        if block.subtitle:
            lines.extend([_md_text(block.subtitle), ""])
    elif isinstance(block, Stats):
        lines.extend(f"- **{_md_text(stat.label)}**: {_md_code(stat.value)}" for stat in block.items)
    elif isinstance(block, FlowDiagram):
        if block.lane_badge:
            lines.extend([f"**Verification lane**: {_md_code(block.lane_badge)}", ""])
        mermaid_body = to_mermaid(block)
        fence = "```"
        while fence in mermaid_body:
            fence += "`"
        lines.extend([f"{fence}mermaid", mermaid_body, fence, ""])
        if block.caption:
            lines.extend([f"*{_md_text(block.caption)}*", ""])
        lines.append("| Step | Role | Location | Operation |")
        lines.append("| --- | --- | --- | --- |")
        for idx, node in enumerate(block.nodes, start=1):
            loc_cell = _md_code(node.location) if node.location else "-"
            op_parts = [_md_text(node.label)]
            if node.detail:
                op_parts.append(_md_code(node.detail))
            lines.append(
                f"| {idx} | {_md_text(role_title(node.role))} | {loc_cell} | {' - '.join(op_parts)} |"
            )
    elif isinstance(block, Box):
        lines.extend([f"### {_md_text(block.title)}", ""])
        for label in (block.meta, block.chip, *block.badges):
            if label:
                lines.extend([_md_text(label), ""])
        for item in block.items:
            if isinstance(item, Para):
                lines.extend([_md_text(item.text), *_md_truncation(item.truncation)])
            elif isinstance(item, Fields):
                for row in item.rows:
                    value = _md_code(row.value) if row.mono else _md_text(row.value)
                    lines.extend([f"- **{_md_text(row.label)}**: {value}",
                                  *_md_truncation(row.truncation)])
            elif isinstance(item, Code):
                fence = "```"
                while fence in item.text:
                    fence += "`"
                lines.extend([_md_text(item.caption), "", fence + "text", item.text, fence,
                              *_md_truncation(item.truncation)])
            elif isinstance(item, Bullets):
                lines.extend("- " + _md_text(value) for value in item.items)
                lines.extend(_md_truncation(item.omitted))
            elif isinstance(item, Table):
                lines.append("| " + " | ".join(_md_text(value) for value in item.headers) + " |")
                lines.append("| " + " | ".join("---" for _ in item.headers) + " |")
                for row in item.rows:
                    lines.append("| " + " | ".join(_md_text(cell.text) for cell in row) + " |")
                lines.extend(_md_truncation(item.omitted))
            else:
                raise TypeError(f"unsupported dossier Markdown item: {type(item).__name__}")
            lines.append("")
    else:
        raise TypeError(f"unsupported dossier Markdown block: {type(block).__name__}")
    return lines


def render_dossier_markdown(dossier: Mapping[str, Any]) -> str:
    """Render the same bounded document as HTML/LaTeX, without a second content projection."""
    document = dossier_document(dossier)
    lines = [
        f"# {_md_text(document.title)}: {_md_text(document.subtitle)}",
        "",
        f"- **Run**: {_md_code(document.run_id)}",
        f"- **Dossier ID**: {_md_code(dossier['dossier_id'])}",
        f"- **Kind**: {_md_code(dossier['kind'])}",
        f"- **Visibility**: {_md_code(dossier['visibility'])} (PROTECTED DEVELOPER ARTIFACT - DO NOT DISTRIBUTE)",
        "",
    ]
    for block in document.blocks:
        lines.extend(_render_block(block))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def template_identity(directory: Path) -> dict[str, Any]:
    files = []
    for name in ("appsec-report.cls", "appsec-palette.tex", "report-skeleton.tex"):
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(f"dossier template is missing or symbolic: {name}")
        files.append({"name": name, "sha256": platform_file_sha256(path)})
    return {"files": files, "sha256": hashlib.sha256(canonical_json(files)).hexdigest()}


def render_dossier(run_root: Path, output_dir: Path, dossier: Mapping[str, Any], *,
                   settings: DossierPublicationSettings, repository_root: Path,
                   executor_factory: ExecutorFactory = ContainerExecutor) -> dict[str, Any]:
    """Write once in an attempt-owned directory; rendering failure never creates a success PDF."""
    root = Path(run_root).resolve()
    output = Path(output_dir).resolve()
    if root not in output.parents or output.exists():
        raise IntegrityError("dossier output must be a new, run-owned attempt directory")
    output.mkdir(parents=True)
    template = Path(repository_root) / "containers" / "report" / "latex" / "template"
    identity = template_identity(template)
    json_path, latex_path, receipt_path = (output / name for name in ("dossier.json", "dossier.tex", "receipt.json"))
    md_path, html_path = output / "dossier.md", output / "dossier.html"
    model_bytes = canonical_json(dossier)
    doc = dossier_document(dossier)
    latex = render_latex(doc, template)
    md_bytes = render_dossier_markdown(dossier).encode("utf-8")
    html_bytes = render_html(doc).encode("utf-8")
    if max(len(model_bytes), len(latex.encode("utf-8")), len(md_bytes), len(html_bytes)) > settings.max_artifact_bytes:
        raise IntegrityError("dossier JSON, Markdown, HTML, or LaTeX exceeds max_artifact_bytes")
    atomic_bytes(json_path, model_bytes)
    atomic_bytes(latex_path, latex.encode("utf-8"))
    atomic_bytes(md_path, md_bytes)
    atomic_bytes(html_path, html_bytes)
    files: dict[str, Any] = {"json": artifact_ref(root, json_path), "latex": artifact_ref(root, latex_path), "pdf": None}
    formats = {"markdown": artifact_ref(root, md_path), "html": artifact_ref(root, html_path)}
    status, gaps = "latex_only", []
    execution_ref = None
    tool_identity: dict[str, Any] = {"id": TOOL_ID, "tag": settings.image_tag, "image_id": settings.image_id}
    if not settings.render_pdf:
        gaps.append("dossier_pdf_disabled_by_policy")
    else:
        inputs, scratch = output / "input", output / "scratch"
        inputs.mkdir()
        scratch.mkdir()
        atomic_bytes(inputs / "report.tex", latex_path.read_bytes())
        atomic_bytes(inputs / "source-date-epoch", b"0\n")
        try:
            catalog = load_catalog(repository_root)
            tool = replace(catalog.tool(TOOL_ID), tag=settings.image_tag, expected_image_id=settings.image_id,
                           timeout_seconds=settings.render_timeout_seconds)
            catalog = replace(catalog, tools=MappingProxyType({**catalog.tools, TOOL_ID: tool}))
            tool_identity.update(version=tool.version, manifest_sha256=platform_file_sha256(tool.manifest_path),
                                 runtime_policy_sha256=platform_file_sha256(catalog.runtime_policy))
            executor = executor_factory(catalog, root)
            result = executor.execute(ExecutionRequest(
                tool_id=TOOL_ID, argv=(tool.executable,), target_root=inputs, scratch_root=scratch,
                extra_mounts=(Mount(template, "/template"), Mount(inputs, "/input")),
                working_directory="/scratch", file_size_limit_bytes=settings.max_artifact_bytes))
            execution_path = root / result.receipt_path
            if execution_path.is_file():
                retained = output / "container-execution.json"
                execution = json.loads(execution_path.read_bytes())
                for key in ("stdout_path", "stderr_path"):
                    stream = root / execution[key]
                    if stream.is_file() and not stream.is_symlink() and stream.stat().st_size <= settings.max_artifact_bytes:
                        destination = output / ("container-" + key.removesuffix("_path") + ".bin")
                        atomic_bytes(destination, stream.read_bytes())
                        execution[key] = destination.relative_to(root).as_posix()
                atomic_json(retained, execution)
                execution_ref = artifact_ref(root, retained)
            for name in ("report.log", "report.pdfinfo.txt", "report.txt"):
                source = scratch / name
                if source.is_file() and not source.is_symlink() and source.stat().st_size <= settings.max_artifact_bytes:
                    atomic_bytes(output / name, source.read_bytes())
            pdf = scratch / "report.pdf"
            valid = (result.exit_code == 0 and not result.timed_out and not result.oom_killed
                     and not result.file_size_limit_reached and pdf.is_file() and not pdf.is_symlink()
                     and 32 < pdf.stat().st_size <= settings.max_artifact_bytes)
            if valid:
                data = pdf.read_bytes()
                valid = data.startswith(b"%PDF-") and data.rstrip().endswith(b"%%EOF")
            if valid:
                atomic_bytes(output / "dossier.pdf", data)
                files["pdf"] = artifact_ref(root, output / "dossier.pdf")
                status = "rendered"
            else:
                status = "render_failed"
                gaps.append("dossier_render_failed: " + result.terminal_status + f", exit={result.exit_code}")
        except ValueError as exc:
            # A changed immutable tool pin/configuration is not an ordinary rendering gap.
            raise IntegrityError(f"dossier renderer configuration or image integrity failure: {exc}") from exc
        except (OSError, RuntimeError) as exc:
            status = "render_failed"
            gaps.append("dossier_renderer_unavailable: " + type(exc).__name__ + ": "
                        + (redact_message(str(exc), bound=240) or "No diagnostic supplied."))
        finally:
            # Only these two freshly created, run-owned staging directories are disposable.
            shutil.rmtree(inputs)
            shutil.rmtree(scratch)
    if template_identity(template) != identity:
        raise IntegrityError("dossier template changed during rendering")
    receipt = {
        "schema": RECEIPT_SCHEMA, "dossier_id": dossier["dossier_id"], "run_id": dossier["run_id"],
        "status": status, "visibility": "protected_developer", "files": files,
        "additional_formats": formats,
        "renderer": dossier["renderer"], "source_date_epoch": 0, "template": identity, "tool": tool_identity,
        "settings_sha256": settings.settings_sha256(), "execution": execution_ref, "gaps": gaps,
        "policy": {"network": "none", "shell_escape": False, "input_read_only": True, "template_read_only": True,
                   "generated_code_execution": "not_performed_by_policy"},
    }
    verify_additional_formats(root, receipt)
    atomic_json(receipt_path, receipt)
    return {"dossier_id": dossier["dossier_id"], "kind": dossier["kind"], "finding": dossier["finding"],
            "status": status, "files": {**files, "receipt": artifact_ref(root, receipt_path)},
            "gap_ids": sorted(set(dossier["gaps"]) | set(gaps))}
