"""Retain dossier JSON/LaTeX/Markdown/HTML/PDF through the commissioned container runtime."""
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
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, platform_file_sha256
from .dossiers import dossier_document
from .html import render_html
from .latex import render_latex

if TYPE_CHECKING:
    from appsec_review.jobs.job_dossier_publication.settings import DossierPublicationSettings

TOOL_ID = "tool-report-latex"
RECEIPT_SCHEMA = "appsec-review/dossier-rendering-receipt/1"
ExecutorFactory = Callable[..., ContainerExecutor]


def _md_cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def render_dossier_html(dossier: Mapping[str, Any]) -> str:
    """Render a deterministic, self-contained HTML developer dossier."""
    return render_html(dossier_document(dossier))


def render_dossier_markdown(dossier: Mapping[str, Any]) -> str:
    """Render a deterministic Markdown developer dossier with all structured T-176 sections."""
    badge = dossier.get("classification_badge") or {}
    timeline = dossier.get("taint_path_timeline") or ()
    adj = dossier.get("adjudication_summary") or {}
    poc_sum = dossier.get("poc_harness_summary") or {}
    rem_guide = dossier.get("remediation_guide") or {}
    title = dossier.get("title") or dossier["finding"]["finding_package_id"]
    lines = [
        f"# Developer Finding Dossier: {title}",
        "",
        f"- **Run**: `{dossier['run_id']}`",
        f"- **Dossier ID**: `{dossier['dossier_id']}`",
        f"- **Kind**: `{dossier['kind']}`",
        f"- **Visibility**: `{dossier['visibility']}` (`PROTECTED DEVELOPER ARTIFACT - DO NOT DISTRIBUTE`)",
        "",
        "## Protected Handling & Non-Execution Assurance",
        "",
    ]
    for notice in dossier.get("notices") or ():
        lines.append(f"- {notice}")
    lines.extend([
        "",
        "## Severity, CWE/OWASP Mapping & Reachability Badge",
        "",
        f"- **State**: `{dossier['state']}`",
        f"- **Reachability Badge**: `{badge.get('reachability_badge') or dossier['state']}`",
        f"- **Technical Severity**: `{badge.get('severity') or dossier['ship_block'].get('technical_severity') or 'unassessed'}`",
        f"- **Weakness CWE**: `{badge.get('weakness_cwe') or dossier.get('weakness_cwe') or 'not_recorded'}`",
        f"- **OWASP Top 10 (2025)**: `{badge.get('owasp_2025') or 'unmapped'}`",
        f"- **Security Radar Domain**: {badge.get('radar_domain_label') or 'Unclassified'} (`{badge.get('radar_domain_id') or 'unclassified'}`)",
        f"- **Resolution Tier**: `{badge.get('resolution_tier') or 'not_recorded'}`",
        f"- **Corroborating Scanners / Cells**: `{', '.join(badge.get('corroborating_scanners') or ()) or 'none'}`",
        f"- **Finding Package**: `{dossier['finding']['finding_package_id']}`",
        f"- **Claim**: `{dossier['finding']['claim_id']}`",
        f"- **Release Recommendation**: `{dossier['ship_block'].get('status') or 'not_recorded'}`",
        "",
        "## Finding Statement",
        "",
        dossier.get("statement") or "No claim statement was recorded.",
        "",
    ])
    if dossier.get("preconditions"):
        lines.extend(["### Preconditions", ""])
        for item in dossier["preconditions"]:
            lines.append(f"- {item}")
        lines.append("")
    if dossier.get("missing_predicates"):
        lines.extend(["### Open Proof Obligations", ""])
        for item in dossier["missing_predicates"]:
            lines.append(f"- `{item}`")
        lines.append("")

    lines.extend([
        "## Source-to-Sink Call & Taint Path Timeline",
        "",
    ])
    if timeline:
        lines.extend([
            "| Step | Role | Location | Symbol | Taint Transform | Guard Disposition |",
            "|---:|---|---|---|---|---|",
        ])
        for step in timeline:
            lines.append(
                f"| {step['step_index']} | `{_md_cell(step['role'])}` | `{_md_cell(step['location'])}` "
                f"| `{_md_cell(step['symbol'])}` | {_md_cell(step['taint_transform'])} "
                f"| {_md_cell(step['guard_disposition'])} |"
            )
        lines.append("")
    else:
        lines.extend(["No source-to-sink path steps were recorded.", ""])

    lines.extend([
        "## Adjudication & Red/Blue/Verifier Evidence Summary",
        "",
        f"- **Verifier Posture**: `{adj.get('verifier_posture') or 'bounded_adjudication'}`",
        f"- **Exploitability Basis (Red)**: {adj.get('exploitability_basis') or 'Not recorded.'}",
        f"- **Guard Evaluation (Blue)**: {adj.get('guard_bypass_summary') or 'Not recorded.'}",
        f"- **Counted Direct Citations**: `{len(adj.get('counted_direct_citations') or ())}`",
        f"- **Analyst-Assessed Citations**: `{len(adj.get('analyst_assessed_citations') or ())}`",
        "",
    ])
    if adj.get("resolving_citations"):
        lines.extend([
            "| Relation | Locator | Line Span | Content SHA-256 |",
            "|---|---|---|---|",
        ])
        for cit in adj["resolving_citations"]:
            lines.append(
                f"| `{_md_cell(cit['relation_id'])}` | `{_md_cell(cit['locator'])}` "
                f"| `{_md_cell(cit['line_span'])}` | `{_md_cell(cit['content_sha256'][:16])}` |"
            )
        lines.append("")

    if dossier.get("sources"):
        lines.extend(["## Bounded Source Excerpts", ""])
        for src in dossier["sources"]:
            span = f"lines {src['start_line']}-{src['end_line']}" if src.get("start_line") else "span unrecorded"
            lines.extend([
                f"### `{src['path'] or src['entity_id']}` ({span}, `{src['mapping_method']}`)",
                "",
                "```text",
                src.get("excerpt") or "",
                "```",
                "",
            ])

    lines.extend([
        "## Compile-Verified Proof-of-Concept Harness Summary",
        "",
        f"- **Compile Status**: `{poc_sum.get('compile_status') or 'not_available'}`",
        f"- **Compile-Only Verified**: `{'yes' if poc_sum.get('compile_only_verified') else 'no'}`",
        f"- **Safety Badge**: `{poc_sum.get('safety_badge') or 'not_performed_by_policy'}`",
        f"- **Generated Code Execution**: `{poc_sum.get('generated_code_execution') or 'not_performed_by_policy'}`",
        f"- **Summary**: {poc_sum.get('summary') or ''}",
        "",
    ])
    if dossier.get("poc") and dossier["poc"].get("source"):
        lines.extend([
            "### Generated Function Source (NOT RUN)",
            "",
            "```text",
            dossier["poc"]["source"],
            "```",
            "",
        ])

    lines.extend([
        "## Validated Remediation Patch & Verification Checklist",
        "",
        f"- **Validation Tier**: `{rem_guide.get('validation_tier') or 'manual_design_required'}`",
        f"- **Violated Invariant**: {rem_guide.get('violated_invariant') or 'Not recorded.'}",
        f"- **Corrected Invariant**: {rem_guide.get('corrected_invariant') or 'Not recorded.'}",
        "",
    ])
    if rem_guide.get("proposed_diff"):
        lines.extend([
            "### Proposed Unified Remediation Diff",
            "",
            "```diff",
            rem_guide["proposed_diff"],
            "```",
            "",
        ])
    if rem_guide.get("concrete_fix_steps"):
        lines.extend(["### Concrete Fix Guidance", ""])
        for step in rem_guide["concrete_fix_steps"]:
            lines.append(f"- {step}")
        lines.append("")
    if rem_guide.get("verification_checklist"):
        lines.extend(["### Regression & Verification Checklist", ""])
        for chk in rem_guide["verification_checklist"]:
            lines.append(f"- [ ] {chk}")
        lines.append("")

    if dossier.get("gaps") or dossier.get("truncations"):
        lines.extend(["## Coverage Gaps & Bounded Omissions", ""])
        for gap in dossier.get("gaps") or ():
            lines.append(f"- {gap}")
        for cut in dossier.get("truncations") or ():
            lines.append(f"- truncated `{cut['field']}`: omitted {cut['omitted']} {cut['unit']} (sha256 `{cut['sha256'][:16]}`)")
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
        "renderer": dossier["renderer"], "source_date_epoch": 0, "template": identity, "tool": tool_identity,
        "settings_sha256": settings.settings_sha256(), "execution": execution_ref, "gaps": gaps,
        "policy": {"network": "none", "shell_escape": False, "input_read_only": True, "template_read_only": True,
                   "generated_code_execution": "not_performed_by_policy"},
    }
    atomic_json(receipt_path, receipt)
    return {"dossier_id": dossier["dossier_id"], "kind": dossier["kind"], "finding": dossier["finding"],
            "status": status, "files": {**files, "receipt": artifact_ref(root, receipt_path)},
            "gap_ids": sorted(set(dossier["gaps"]) | set(gaps))}
