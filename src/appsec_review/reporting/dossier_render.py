"""Retain dossier JSON/LaTeX/PDF through the commissioned container runtime, not a second runner."""
from __future__ import annotations

from dataclasses import replace
import hashlib
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
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256
from .dossiers import dossier_document
from .latex import render_latex

if TYPE_CHECKING:
    from appsec_review.jobs.job_dossier_publication.settings import DossierPublicationSettings

TOOL_ID = "tool-report-latex"
RECEIPT_SCHEMA = "appsec-review/dossier-rendering-receipt/1"
ExecutorFactory = Callable[..., ContainerExecutor]


def template_identity(directory: Path) -> dict[str, Any]:
    files = []
    for name in ("appsec-report.cls", "appsec-palette.tex", "report-skeleton.tex"):
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(f"dossier template is missing or symbolic: {name}")
        files.append({"name": name, "sha256": file_sha256(path)})
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
    model_bytes = canonical_json(dossier)
    latex = render_latex(dossier_document(dossier), template)
    if max(len(model_bytes), len(latex.encode("utf-8"))) > settings.max_artifact_bytes:
        raise IntegrityError("dossier JSON or LaTeX exceeds max_artifact_bytes")
    atomic_bytes(json_path, model_bytes)
    atomic_bytes(latex_path, latex.encode("utf-8"))
    files: dict[str, Any] = {"json": artifact_ref(root, json_path), "latex": artifact_ref(root, latex_path), "pdf": None}
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
            tool_identity.update(version=tool.version, manifest_sha256=file_sha256(tool.manifest_path),
                                 runtime_policy_sha256=file_sha256(catalog.runtime_policy))
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
        "renderer": dossier["renderer"], "source_date_epoch": 0, "template": identity, "tool": tool_identity,
        "settings_sha256": settings.settings_sha256(), "execution": execution_ref, "gaps": gaps,
        "policy": {"network": "none", "shell_escape": False, "input_read_only": True, "template_read_only": True,
                   "generated_code_execution": "not_performed_by_policy"},
    }
    atomic_json(receipt_path, receipt)
    return {"dossier_id": dossier["dossier_id"], "kind": dossier["kind"], "finding": dossier["finding"],
            "status": status, "files": {**files, "receipt": artifact_ref(root, receipt_path)},
            "gap_ids": sorted(set(dossier["gaps"]) | set(gaps))}
