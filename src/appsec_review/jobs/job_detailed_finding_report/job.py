"""``job_detailed_finding_report``: terminal visual defect report with 3a, 3b, and 3c diagrams.

Units:
- ``load.accepted_inputs`` verifies the accepted ``job_final_publication_gate`` handoff and certified
  bindings plus the optional ``job_code_graph_index`` ``alternate_cpg`` handoff/artifacts via
  ``accepted_upstream`` under ``validation_scope``.
- ``report.assemble`` builds the schema-validated ``detailed-finding-report.json`` pairing every
  gate-certified defect with deterministic 3a taint/invariant, 3b call-fanout slice, and 3c
  intra-procedural CFG ``FlowDiagram`` models.
- ``report.render`` writes standalone ``.svg``, ``.mmd``, and ``.dot`` vector diagram files under
  ``diagrams/<defect_slug>/`` plus deterministic ``detailed-finding-report.md`` (relative SVG image
  embeds) and ``detailed-finding-report.html`` (self-contained inline SVGs).
- ``report.render_pdf`` renders ``detailed-finding-report.tex`` (vector TikZ diagrams) and compiles
  ``detailed-finding-report.pdf`` through ``appsec-review/tool-report-latex:1.0.0``.
- ``acceptance.publish_handoff`` re-proves all upstream bindings and output bytes and publishes the
  schema-validated handoff with ``strict_gaps=True``.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import time
from types import MappingProxyType
from typing import Any, Callable, Mapping

from jsonschema import Draft202012Validator

from appsec_review.applicability import resolved_configuration_identity
from appsec_review.container_runtime.catalog import load_catalog
from appsec_review.container_runtime.executor import ContainerExecutor, ExecutionRequest, Mount
from appsec_review.interchange import GapCode, ProducerStatus, producer_gap
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound, read_bound_json, resolve_bound
from appsec_review.jobs.completion_contracts import DOSSIER_SCHEMA
from appsec_review.jobs.engineering_contracts import (
    DETAILED_FINDING_REPORT_HANDOFF_SCHEMA,
    DETAILED_FINDING_REPORT_SCHEMA,
    FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA,
    FINAL_PUBLICATION_GATE_SCHEMA,
)
from appsec_review.jobs.job_final_publication_gate.verify import (
    _verify_package_accounting,
    verify_gate_snapshot as _verify_bindings,
)
from appsec_review.jobs.job_final_report_publication.pdf import (
    RECEIPT_SCHEMA,
    RETAINED_LOGS,
    SOURCE_DATE_EPOCH,
    template_dir,
    valid_pdf,
)
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.reporting.detailed_finding_report import (
    assert_no_redaction_markers,
    build_detailed_finding_report,
    render_detailed_html,
    render_detailed_latex,
    render_detailed_markdown,
    write_defect_diagram_files,
)
from appsec_review.reporting.dossier_render import TOOL_ID
from appsec_review.reporting.executive_latex import template_identity
from appsec_review.reporting.executive_report import RENDERER as RECEIPT_RENDERER
from appsec_review.review.models import IntegrityError
from appsec_review.review.secret_redaction import redact_message
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.runtime.configuration import configuration_snapshot
from appsec_review.runtime.consume import accepted_upstream
from appsec_review.runtime.inputs import observe_output
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, platform_file_sha256
from appsec_review.storage.shared import consume_handoff, safe_path, verify_handoff
from appsec_review.storage.validation import validation_scope

from .contracts import DETAILED_FINDING_REPORT_SCHEMA_SHA256, GATE_SCHEMA_SHA256
from .datasets import CONTRACT, DATASETS
from .settings import DetailedFindingReportSettings

JOB_ID = "job_detailed_finding_report"
GATE_JOB = "job_final_publication_gate"
CODE_GRAPH_JOB = "job_code_graph_index"
ALTERNATE_CPG_SCHEMA = "appsec-review/alternate-cpg/1"
SCHEMA_ROOT = Path("docs") / "schemas" / "detailed-finding-report" / "v1"
GATE_SCHEMA_ROOT = Path("docs") / "schemas" / "final-report"
TOPOLOGY = {
    "load": ("accepted_inputs",),
    "report": ("assemble", "render", "render_pdf"),
    "acceptance": ("publish_handoff",),
}
VERIFIED_INPUTS_JSON = "verified-inputs.json"
REPORT_JSON = "detailed-finding-report.json"
REPORT_MARKDOWN = "detailed-finding-report.md"
REPORT_HTML = "detailed-finding-report.html"
TEX_NAME = "detailed-finding-report.tex"
PDF_NAME = "detailed-finding-report.pdf"
RECEIPT_NAME = "receipt.json"
PDF_RECEIPT_SCHEMA_NAME = "final-report-pdf-receipt"
ExecutorFactory = Callable[..., ContainerExecutor]

PDF_REASONS = {
    "rendered": (
        "Rendered deterministically from detailed-finding-report.json and gate-bound dossiers "
        "through the pinned tool-report-latex image (SOURCE_DATE_EPOCH 0)."
    ),
    "not_rendered": (
        "PDF rendering is disabled by policy (render_pdf = false); the LaTeX source is retained "
        "and no PDF is produced."
    ),
    "render_failed": (
        "The renderer did not produce a valid PDF; the LaTeX source and renderer logs are retained."
    ),
}

_VALIDATOR_CACHE: dict[tuple[str, str], Draft202012Validator] = {}


def _configuration_profile(run_root: Path, resolved_config_sha256: str | None = None) -> dict[str, Any]:
    resolved_file = run_root / "data" / "configuration" / "resolved.json"
    if not resolved_file.is_file():
        return {"name": "dev", "sha256": None}
    base_sha = resolved_configuration_identity(run_root)
    if resolved_config_sha256 is not None and resolved_config_sha256 != base_sha:
        record = configuration_snapshot(run_root, resolved_config_sha256).document
    else:
        record = json.loads(resolved_file.read_text(encoding="utf-8"))
    profile = record.get("configuration_profile") or {"name": "dev", "sha256": None}
    return {"name": str(profile["name"]), "sha256": profile.get("sha256")}


def _settings(unit: UnitContext) -> DetailedFindingReportSettings:
    raw = unit.job.config.settings
    if not raw:
        return DetailedFindingReportSettings.defaults()
    return DetailedFindingReportSettings.from_mapping(raw)


def _validate(context: Any, _result: Any) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("detailed finding report topology does not match configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"detailed finding report task configuration mismatch: {step}")
    raw = context.config.settings
    if not isinstance(raw, Mapping):
        DetailedFindingReportSettings.from_mapping(raw)
    elif raw:
        parsed = DetailedFindingReportSettings.from_mapping(raw)
        if not parsed.enabled:
            raise ValueError("job_detailed_finding_report is disabled in configuration")


def _validator(repo_root: Path, filename: str) -> Draft202012Validator:
    expected = DETAILED_FINDING_REPORT_SCHEMA_SHA256[filename]
    schema_path = repo_root / SCHEMA_ROOT / filename
    try:
        raw = schema_path.read_bytes()
    except OSError as exc:
        raise IntegrityError(f"detailed finding report schema unavailable: {filename}") from exc
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise IntegrityError(f"detailed finding report schema digest mismatch: {filename}")
    key = (str(schema_path), actual)
    cached = _VALIDATOR_CACHE.get(key)
    if cached is None:
        cached = Draft202012Validator(json.loads(raw.decode("utf-8")))
        _VALIDATOR_CACHE[key] = cached
    return cached


def _check_detailed_schema(repo_root: Path, filename: str, document: Any) -> None:
    validator = _validator(repo_root, filename)
    errors = sorted(validator.iter_errors(document), key=lambda err: list(err.absolute_path))
    if errors:
        formatted = "; ".join(
            f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
            for err in errors[:3]
        )
        raise IntegrityError(f"{filename} validation failed: {formatted}")


def _gate_schemas(repo_root: Path) -> SchemaSet:
    schema_dir = repo_root / GATE_SCHEMA_ROOT
    for filename, expected in GATE_SCHEMA_SHA256.items():
        path = schema_dir / filename
        if not path.is_file():
            raise IntegrityError(f"gate/receipt schema unavailable: {filename}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise IntegrityError(f"gate/receipt schema digest mismatch: {filename}")
    return SchemaSet(schema_dir)


def _check_gate_schema(schemas: SchemaSet, name: str, document: Any) -> None:
    errors = schemas.errors(name, document)
    if errors:
        raise IntegrityError(f"{name} does not satisfy its schema: {'; '.join(errors[:3])}")


def _bind_gate_dossiers(
    run_root: Path,
    gate: Mapping[str, Any],
) -> dict[str, tuple[dict[str, Any], dict[str, str]]]:
    bound = {(str(row["path"]), str(row["sha256"])) for row in gate.get("bindings", ())}
    attached = sorted(
        (row for row in gate.get("attachments", {}).get("dossiers", ()) if isinstance(row, Mapping)),
        key=lambda row: (
            0 if row.get("kind") == "confirmed_finding" else 1,
            str(row.get("dossier_id") or ""),
        ),
    )
    by_pkg: dict[str, tuple[dict[str, Any], dict[str, str]]] = {}
    for row in attached:
        files_map = row.get("files") if isinstance(row.get("files"), Mapping) else row
        json_entry = files_map["json"]
        receipt_entry = files_map["receipt"]
        json_ref = {"path": str(json_entry["path"]), "sha256": str(json_entry["sha256"])}
        receipt_ref = {"path": str(receipt_entry["path"]), "sha256": str(receipt_entry["sha256"])}
        if (json_ref["path"], json_ref["sha256"]) not in bound:
            raise IntegrityError(f"gate dossier JSON not in bindings: {json_ref['path']}")
        if (receipt_ref["path"], receipt_ref["sha256"]) not in bound:
            raise IntegrityError(f"gate dossier receipt not in bindings: {receipt_ref['path']}")
        read_bound_json(run_root, receipt_ref)
        doc = read_bound_json(run_root, json_ref)
        if not isinstance(doc, Mapping) or doc.get("schema") != DOSSIER_SCHEMA:
            raise IntegrityError(f"unexpected dossier schema: {json_ref['path']}")
        if doc.get("run_id") != gate.get("run_id") or doc.get("dossier_id") != row.get("dossier_id"):
            raise IntegrityError(f"dossier identity mismatch: {json_ref['path']}")
        if doc.get("visibility") != "protected_developer":
            raise IntegrityError(f"dossier visibility mismatch: {json_ref['path']}")
        if isinstance(row.get("finding"), Mapping) and doc.get("finding") != row.get("finding"):
            raise IntegrityError(f"dossier finding binding mismatch: {json_ref['path']}")
        pkg_id = str(
            row.get("finding_package_id")
            or (row.get("finding") or {}).get("finding_package_id")
            or (doc.get("finding") or {}).get("finding_package_id")
            or ""
        )
        if pkg_id and pkg_id not in by_pkg:
            by_pkg[pkg_id] = (dict(doc), json_ref)
    return by_pkg


def _artifact_from_handoff(
    handoff_artifacts: Mapping[str, dict[str, str]],
    raw: Any,
    *,
    label: str,
) -> dict[str, str] | None:
    if isinstance(raw, Mapping) and raw.get("path") and raw.get("sha256"):
        path = str(raw["path"])
        sha = str(raw["sha256"])
        if handoff_artifacts and path in handoff_artifacts and handoff_artifacts[path]["sha256"] != sha:
            raise IntegrityError(f"code_graph_index {label} digest disagrees with handoff artifacts: {path}")
        if handoff_artifacts and path not in handoff_artifacts:
            raise IntegrityError(f"code_graph_index {label} is not bound in handoff artifacts: {path}")
        return {"path": path, "sha256": sha}
    if isinstance(raw, str) and raw:
        bound_ref = handoff_artifacts.get(raw)
        if bound_ref is None:
            raise IntegrityError(f"code_graph_index {label} path is not bound in handoff artifacts: {raw}")
        return dict(bound_ref)
    return None


def _resolve_optional_code_graph(
    run_root: Path,
    *,
    gate_target_snapshot: str,
) -> dict[str, Any]:
    cg_up = accepted_upstream(run_root, CODE_GRAPH_JOB, required=False)
    if cg_up is None:
        return {
            "code_graph_status": "UNAVAILABLE",
            "code_graph_handoff": None,
            "alternate_cpg_summary": None,
            "cpg_nodes_ref": None,
            "cpg_edges_ref": None,
            "code_graph_gap_reason": (
                "job_code_graph_index has no accepted upstream handoff; 3b call-fanout and 3c CFG "
                "diagrams used honest dossier structural fallbacks."
            ),
        }
    cg_handoff = cg_up.handoff
    if cg_handoff.get("run_id") != run_root.name or cg_handoff.get("job_id") != CODE_GRAPH_JOB:
        raise IntegrityError("code_graph_index handoff identity does not match this run")
    cg_snap = str(cg_handoff.get("target_snapshot") or "none")
    if gate_target_snapshot not in ("none", "") and cg_snap not in ("none", "") and cg_snap != gate_target_snapshot:
        raise IntegrityError(
            f"conflicting target snapshots between {GATE_JOB} ({gate_target_snapshot}) "
            f"and {CODE_GRAPH_JOB} ({cg_snap})"
        )
    verify_handoff(run_root, cg_handoff)
    consume_handoff(run_root, cg_handoff)

    cg_handoff_ref = {"path": cg_up.path, "sha256": cg_up.sha256}
    handoff_artifacts = {
        str(item["path"]): {"path": str(item["path"]), "sha256": str(item["sha256"])}
        for item in cg_handoff.get("artifacts", ())
        if isinstance(item, Mapping) and item.get("path") and item.get("sha256")
    }
    outputs = cg_handoff.get("outputs") if isinstance(cg_handoff.get("outputs"), Mapping) else {}
    pub_out = outputs.get("acceptance.publish_handoff") if isinstance(outputs, Mapping) else None
    cg_status_raw = str(
        (pub_out if isinstance(pub_out, Mapping) else {}).get("terminal_status")
        or cg_handoff.get("completion_status")
        or "COMPLETED"
    )
    summary_ref: dict[str, str] | None = None
    if isinstance(pub_out, Mapping) and "alternate_cpg" in pub_out:
        summary_ref = _artifact_from_handoff(
            handoff_artifacts, pub_out.get("alternate_cpg"), label="alternate_cpg summary"
        )
    if summary_ref is None:
        attempt_id = str(cg_handoff.get("attempt_id") or "")
        expected_rel = (
            f"data/jobs/{CODE_GRAPH_JOB}/attempts/{attempt_id}/steps/acceptance/"
            f"tasks/publish_handoff/alternate-cpg-summary.json"
        )
        if expected_rel in handoff_artifacts:
            summary_ref = dict(handoff_artifacts[expected_rel])
        else:
            matches = sorted(
                path for path in handoff_artifacts if path.endswith("/alternate-cpg-summary.json")
            )
            if len(matches) == 1:
                summary_ref = dict(handoff_artifacts[matches[0]])

    if summary_ref is None:
        return {
            "code_graph_status": "COMPLETED_WITH_GAPS",
            "code_graph_handoff": cg_handoff_ref,
            "alternate_cpg_summary": None,
            "cpg_nodes_ref": None,
            "cpg_edges_ref": None,
            "code_graph_gap_reason": (
                "job_code_graph_index accepted handoff did not publish alternate-cpg-summary.json; "
                "3b/3c diagrams used honest dossier structural fallbacks."
            ),
        }

    observe_output(run_root, CODE_GRAPH_JOB, "alternate_cpg", summary_ref)
    summary_doc = read_bound_json(run_root, summary_ref)
    if not isinstance(summary_doc, Mapping) or summary_doc.get("schema") != ALTERNATE_CPG_SCHEMA:
        raise IntegrityError(f"alternate-cpg-summary.json schema mismatch: {summary_ref['path']}")
    if summary_doc.get("run_id") not in (None, run_root.name):
        raise IntegrityError("alternate-cpg-summary.json run_id mismatch")

    artifacts = summary_doc.get("artifacts") if isinstance(summary_doc.get("artifacts"), Mapping) else {}
    nodes_ref = _artifact_from_handoff(handoff_artifacts, artifacts.get("nodes"), label="cpg-nodes.jsonl")
    edges_ref = _artifact_from_handoff(handoff_artifacts, artifacts.get("edges"), label="cpg-edges.jsonl")
    if nodes_ref is None or edges_ref is None:
        return {
            "code_graph_status": "COMPLETED_WITH_GAPS",
            "code_graph_handoff": cg_handoff_ref,
            "alternate_cpg_summary": summary_ref,
            "cpg_nodes_ref": None,
            "cpg_edges_ref": None,
            "code_graph_gap_reason": (
                "alternate-cpg-summary.json has no bound nodes/edges JSONL artifacts; "
                "3b/3c diagrams used honest dossier structural fallbacks."
            ),
        }

    nodes_path = resolve_bound(run_root, nodes_ref)
    edges_path = resolve_bound(run_root, edges_ref)
    if platform_file_sha256(nodes_path) != nodes_ref["sha256"]:
        raise IntegrityError(f"alternate_cpg nodes digest mismatch: {nodes_ref['path']}")
    if platform_file_sha256(edges_path) != edges_ref["sha256"]:
        raise IntegrityError(f"alternate_cpg edges digest mismatch: {edges_ref['path']}")
    observe_output(run_root, CODE_GRAPH_JOB, "alternate_cpg", nodes_ref)
    observe_output(run_root, CODE_GRAPH_JOB, "alternate_cpg", edges_ref)

    summary_status = str(summary_doc.get("terminal_status") or summary_doc.get("status") or "COMPLETED")
    effective_status = (
        "COMPLETED_WITH_GAPS"
        if cg_status_raw not in ("COMPLETED", "SUCCEEDED")
        or summary_status not in ("COMPLETED", "SUCCEEDED", "OK")
        or summary_doc.get("gaps")
        else "COMPLETED"
    )
    gap_reason = (
        "job_code_graph_index or alternate-cpg-summary reported partial coverage; uncovered "
        "functions used honest dossier fallbacks."
        if effective_status == "COMPLETED_WITH_GAPS"
        else None
    )
    return {
        "code_graph_status": effective_status,
        "code_graph_handoff": cg_handoff_ref,
        "alternate_cpg_summary": summary_ref,
        "cpg_nodes_ref": nodes_ref,
        "cpg_edges_ref": edges_ref,
        "code_graph_gap_reason": gap_reason,
    }


def _load_verified_upstream(run_root: Path, gate_schemas: SchemaSet) -> dict[str, Any]:
    with validation_scope(run_root):
        gate_up = accepted_upstream(run_root, GATE_JOB, required=True)
        assert gate_up is not None
        if gate_up.handoff.get("run_id") != run_root.name or gate_up.handoff.get("job_id") != GATE_JOB:
            raise IntegrityError("accepted gate handoff identity does not match this run")
        verify_handoff(run_root, gate_up.handoff)
        consume_handoff(run_root, gate_up.handoff)

        published = (gate_up.handoff.get("outputs") or {}).get("acceptance.publish_handoff")
        if (
            not isinstance(published, Mapping)
            or published.get("schema") != FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA
            or not isinstance(published.get("artifact"), Mapping)
        ):
            raise IntegrityError("accepted gate handoff does not publish a supported gate document")
        gate_doc_ref = {
            "path": str(published["artifact"]["path"]),
            "sha256": str(published["artifact"]["sha256"]),
        }
        observe_output(run_root, GATE_JOB, "publication_gate_decisions", gate_doc_ref)
        gate = read_bound_json(run_root, gate_doc_ref)
        _check_gate_schema(gate_schemas, "final-publication-gate", gate)
        if (
            not isinstance(gate, dict)
            or gate.get("schema") != FINAL_PUBLICATION_GATE_SCHEMA
            or published.get("item_count") != gate["package_counts"]["total"]
        ):
            raise IntegrityError("gate document disagrees with its accepted handoff")
        _verify_package_accounting(gate)
        _verify_bindings(run_root, gate)
        bound_dossiers = _bind_gate_dossiers(run_root, gate)

        cg_info = _resolve_optional_code_graph(
            run_root,
            gate_target_snapshot=str(gate_up.handoff.get("target_snapshot") or "none"),
        )

    return {
        "gate_handoff": {"path": gate_up.path, "sha256": gate_up.sha256},
        "gate_document": gate_doc_ref,
        "gate": gate,
        "bound_dossiers": bound_dossiers,
        **cg_info,
    }


def _gap_ref(run_root: Path, ref: Mapping[str, Any]) -> dict[str, Any]:
    path = safe_path(run_root, str(ref["path"]))
    return {
        "path": str(ref["path"]),
        "sha256": str(ref["sha256"]),
        "size_bytes": path.stat().st_size,
    }


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


def _render_detailed_pdf(
    run_root: Path,
    output_dir: Path,
    report: Mapping[str, Any],
    *,
    report_ref: Mapping[str, str],
    certified_dossier_count: int,
    read_dossier_count: int,
    settings: DetailedFindingReportSettings,
    repository_root: Path,
    executor_factory: ExecutorFactory = ContainerExecutor,
) -> dict[str, Any]:
    root = Path(run_root).resolve()
    output = Path(output_dir).resolve()
    if root not in output.parents:
        raise IntegrityError("detailed finding report PDF output must be run-owned")
    output.mkdir(parents=True, exist_ok=True)
    if any((output / name).exists() for name in (TEX_NAME, PDF_NAME, RECEIPT_NAME)):
        raise IntegrityError("detailed finding report PDF output directory is not fresh")

    template = template_dir(repository_root)
    identity = template_identity(template)
    tex = render_detailed_latex(report, template_dir=template)
    if tex != render_detailed_latex(report, template_dir=template):
        raise IntegrityError("detailed finding report LaTeX rendering is not deterministic")
    assert_no_redaction_markers(tex.decode("utf-8"), artifact_name=TEX_NAME)
    if len(tex) > settings.max_pdf_bytes:
        raise IntegrityError("detailed finding report LaTeX exceeds max_pdf_bytes")

    atomic_bytes(output / TEX_NAME, tex)
    files: dict[str, Any] = {"latex": artifact_ref(root, output / TEX_NAME), "pdf": None}
    gaps: list[str] = []
    tool_identity: dict[str, Any] = {
        "id": TOOL_ID,
        "tag": settings.image_tag,
        "image_id": settings.image_id,
    }
    execution_ref = None
    pdf_sha256 = None

    if not settings.render_pdf:
        status = "not_rendered"
        gaps.append("detailed_finding_report_pdf_disabled_by_policy")
    else:
        status = "render_failed"
        inputs, scratch = output / "input", output / "scratch"
        inputs.mkdir()
        scratch.mkdir()
        atomic_bytes(inputs / "report.tex", tex)
        atomic_bytes(inputs / "source-date-epoch", f"{SOURCE_DATE_EPOCH}\n".encode())
        try:
            catalog = load_catalog(repository_root)
            tool = replace(
                catalog.tool(TOOL_ID),
                tag=settings.image_tag,
                expected_image_id=settings.image_id,
                timeout_seconds=settings.render_timeout_seconds,
            )
            catalog = replace(catalog, tools=MappingProxyType({**catalog.tools, TOOL_ID: tool}))
            tool_identity.update(
                version=tool.version,
                manifest_sha256=platform_file_sha256(tool.manifest_path),
                runtime_policy_sha256=platform_file_sha256(catalog.runtime_policy),
            )
            result = executor_factory(catalog, root).execute(
                ExecutionRequest(
                    tool_id=TOOL_ID,
                    argv=(tool.executable,),
                    target_root=inputs,
                    scratch_root=scratch,
                    extra_mounts=(Mount(template, "/template"), Mount(inputs, "/input")),
                    environment={"SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH)},
                    working_directory="/scratch",
                    file_size_limit_bytes=settings.max_pdf_bytes,
                )
            )
            execution_ref = _retain_execution(root, output, result, settings.max_pdf_bytes)
            for name in RETAINED_LOGS:
                source = scratch / name
                if source.is_file() and not source.is_symlink() and source.stat().st_size <= settings.max_pdf_bytes:
                    atomic_bytes(output / name, source.read_bytes())
            pdf_file = scratch / "report.pdf"
            data = b""
            if (
                result.exit_code == 0
                and not result.timed_out
                and not result.oom_killed
                and not result.file_size_limit_reached
                and pdf_file.is_file()
                and not pdf_file.is_symlink()
                and pdf_file.stat().st_size <= settings.max_pdf_bytes
            ):
                data = pdf_file.read_bytes()
            if valid_pdf(data, settings.max_pdf_bytes):
                atomic_bytes(output / PDF_NAME, data)
                files["pdf"] = artifact_ref(root, output / PDF_NAME)
                pdf_sha256 = files["pdf"]["sha256"]
                status = "rendered"
            else:
                gaps.append(
                    f"detailed_finding_report_pdf_render_failed: {result.terminal_status}, exit={result.exit_code}"
                )
        except ValueError as exc:
            raise IntegrityError(
                f"detailed finding report renderer configuration or image integrity failure: {exc}"
            ) from exc
        except (OSError, RuntimeError) as exc:
            gaps.append(
                "detailed_finding_report_pdf_renderer_unavailable: "
                + type(exc).__name__
                + ": "
                + (redact_message(str(exc), bound=240) or "No diagnostic supplied.").replace("<redacted:", "[redacted:")
            )
        finally:
            shutil.rmtree(inputs, ignore_errors=True)
            shutil.rmtree(scratch, ignore_errors=True)

    if template_identity(template) != identity:
        raise IntegrityError("report template changed during rendering")

    receipt = {
        "schema": RECEIPT_SCHEMA,
        "run_id": str(report["run_id"]),
        "status": status,
        "reason": PDF_REASONS[status],
        "renderer": RECEIPT_RENDERER,
        "report": {"path": str(report_ref["path"]), "sha256": str(report_ref["sha256"])},
        "files": files,
        "tex_sha256": hashlib.sha256(tex).hexdigest(),
        "pdf_sha256": pdf_sha256,
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "template": identity,
        "tool": tool_identity,
        "settings_sha256": settings.settings_sha256(),
        "execution": execution_ref,
        "dossiers": {
            "certified": int(certified_dossier_count),
            "read": int(read_dossier_count),
            "unavailable": [],
        },
        "named_gaps": sorted(set(gaps)),
        "policy": {
            "network": "none",
            "shell_escape": False,
            "input_read_only": True,
            "template_read_only": True,
            "source_excerpts": "not_included",
            "generated_code_execution": "not_performed_by_policy",
        },
    }
    atomic_bytes(output / RECEIPT_NAME, canonical_json(receipt))
    return {
        "status": status,
        "reason": PDF_REASONS[status],
        "files": {**files, "receipt": artifact_ref(root, output / RECEIPT_NAME)},
        "tex_sha256": receipt["tex_sha256"],
        "pdf_sha256": pdf_sha256,
        "gaps": receipt["named_gaps"],
    }


def pdf_record(receipt: Mapping[str, Any], files: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "state": receipt["status"],
        "reason": receipt["reason"],
        "file": files["pdf"],
        "sha256": receipt["pdf_sha256"],
        "latex": files["latex"],
        "receipt": files["receipt"],
    }


def build_job(
    *,
    repository_root: Path | None = None,
    executor_factory: ExecutorFactory = ContainerExecutor,
) -> Job:
    """Construct the ``job_detailed_finding_report`` review-graph producer."""

    def _root(unit: UnitContext) -> Path:
        return Path(repository_root or unit.job.repository_root).resolve()

    def load_inputs(unit: UnitContext) -> Mapping[str, Any]:
        run_root = unit.job.run_root
        gate_schemas = _gate_schemas(_root(unit))
        verified = _load_verified_upstream(run_root, gate_schemas)
        gate = verified["gate"]

        load_gaps: list[dict[str, Any]] = []
        cg_status = verified["code_graph_status"]
        cg_reason = verified["code_graph_gap_reason"]
        if cg_status == "UNAVAILABLE":
            load_gaps.append(
                producer_gap(
                    GapCode.INPUT_UNAVAILABLE,
                    cg_reason or "job_code_graph_index accepted handoff unavailable.",
                    scope_id=CODE_GRAPH_JOB,
                    retryable=False,
                )
            )
        elif cg_status == "COMPLETED_WITH_GAPS":
            ev = [_gap_ref(run_root, verified["code_graph_handoff"])] if verified["code_graph_handoff"] else ()
            load_gaps.append(
                producer_gap(
                    GapCode.PRODUCER_REPORTED_GAP,
                    cg_reason or "job_code_graph_index completed with partial coverage.",
                    scope_id=CODE_GRAPH_JOB,
                    retryable=False,
                    evidence_refs=ev,
                )
            )

        manifest = {
            "gate_handoff": verified["gate_handoff"],
            "gate_document": verified["gate_document"],
            "gate_status": gate["status"],
            "review_status": gate["review"]["status"],
            "package_counts": gate["package_counts"],
            "binding_count": len(gate.get("bindings", ())),
            "bound_dossier_count": len(verified["bound_dossiers"]),
            "code_graph_status": cg_status,
            "code_graph_handoff": verified["code_graph_handoff"],
            "alternate_cpg_summary": verified["alternate_cpg_summary"],
            "cpg_nodes_ref": verified["cpg_nodes_ref"],
            "cpg_edges_ref": verified["cpg_edges_ref"],
            "code_graph_gap_reason": cg_reason,
        }
        manifest_path = unit.unit_root / VERIFIED_INPUTS_JSON
        atomic_json(manifest_path, manifest)
        return {
            **manifest,
            "artifact": artifact_ref(run_root, manifest_path),
            "gaps": load_gaps,
            "terminal_status": (
                ProducerStatus.COMPLETED_WITH_GAPS.value
                if load_gaps
                else ProducerStatus.SUCCEEDED.value
            ),
        }

    def assemble(unit: UnitContext) -> Mapping[str, Any]:
        started = time.monotonic()
        run_root = unit.job.run_root
        repo_root = _root(unit)
        settings = _settings(unit)
        loaded = unit.output("load.accepted_inputs")

        gate = read_bound_json(run_root, loaded["gate_document"])
        _verify_bindings(run_root, gate)
        bound_dossiers = _bind_gate_dossiers(run_root, gate)

        nodes_path = resolve_bound(run_root, loaded["cpg_nodes_ref"]) if loaded["cpg_nodes_ref"] else None
        edges_path = resolve_bound(run_root, loaded["cpg_edges_ref"]) if loaded["cpg_edges_ref"] else None

        extra_limitations: list[dict[str, str]] = []
        if loaded.get("code_graph_gap_reason"):
            extra_limitations.append({
                "code": f"code_graph_{loaded['code_graph_status'].lower()}",
                "reason": str(loaded["code_graph_gap_reason"]),
            })

        report, _diagrams = build_detailed_finding_report(
            gate,
            bound_dossiers,
            gate_handoff=loaded["gate_handoff"],
            gate_document=loaded["gate_document"],
            configuration_profile=_configuration_profile(run_root, unit.job.resolved_config_sha256),
            code_graph_handoff=loaded["code_graph_handoff"],
            alternate_cpg_summary=loaded["alternate_cpg_summary"],
            code_graph_status=loaded["code_graph_status"],
            cpg_nodes_path=nodes_path,
            cpg_edges_path=edges_path,
            include_backlog=settings.include_backlog,
            max_fanout_nodes=settings.max_fanout_nodes,
            max_cfg_nodes=settings.max_cfg_nodes,
            extra_limitations=extra_limitations,
        )
        _check_detailed_schema(repo_root, "detailed-finding-report.schema.json", report)
        report_bytes = canonical_json(report)
        assert_no_redaction_markers(report_bytes.decode("utf-8"), artifact_name=REPORT_JSON)

        out_path = unit.unit_root / REPORT_JSON
        atomic_bytes(out_path, report_bytes)
        counts = report["summary"]
        assemble_gaps: list[dict[str, Any]] = []
        gate_ev = [_gap_ref(run_root, loaded["gate_document"])]
        for lim in report.get("limitations", ()):
            if isinstance(lim, Mapping) and lim.get("code") == "dossier_unavailable_for_publishable_defect":
                assemble_gaps.append(
                    producer_gap(
                        GapCode.INPUT_UNAVAILABLE,
                        str(lim["reason"]),
                        scope_id="dossier_binding",
                        retryable=False,
                        evidence_refs=gate_ev,
                    )
                )
        unit.job.events.write(
            "DETAILED_FINDING_REPORT_ASSEMBLED",
            publishable_defects=counts["publishable_defect_count"],
            backlog_defects=counts["backlog_defect_count"],
            diagrams=counts["diagram_count"],
            cpg_fanout_resolved=counts["cpg_fanout_resolved_count"],
            cpg_cfg_resolved=counts["cpg_cfg_resolved_count"],
            code_graph_status=loaded["code_graph_status"],
            duration_ms=max(0, round((time.monotonic() - started) * 1000)),
        )
        return {
            "artifact": artifact_ref(run_root, out_path),
            "counts": counts,
            "settings": settings.identity(),
            "gaps": assemble_gaps,
            "terminal_status": (
                ProducerStatus.COMPLETED_WITH_GAPS.value
                if assemble_gaps
                else ProducerStatus.SUCCEEDED.value
            ),
        }

    def render(unit: UnitContext) -> Mapping[str, Any]:
        run_root = unit.job.run_root
        settings = _settings(unit)
        assembled = unit.output("report.assemble")
        report = read_bound_json(run_root, assembled["artifact"])
        _check_detailed_schema(_root(unit), "detailed-finding-report.schema.json", report)

        written_diagrams = write_defect_diagram_files(report, unit.unit_root)
        diagram_refs: list[dict[str, Any]] = []
        for item in written_diagrams:
            svg_file = Path(item["svg_path"])
            mmd_file = Path(item["mermaid_path"])
            dot_file = Path(item["dot_path"])
            for diag_path in (svg_file, mmd_file, dot_file):
                assert_no_redaction_markers(
                    diag_path.read_text(encoding="utf-8"),
                    artifact_name=diag_path.name,
                )
            diagram_refs.append({
                "defect_slug": str(item["defect_slug"]),
                "diagram": str(item["diagram"]),
                "svg": artifact_ref(run_root, svg_file),
                "mermaid": artifact_ref(run_root, mmd_file),
                "dot": artifact_ref(run_root, dot_file),
            })

        md_text = render_detailed_markdown(report)
        if md_text != render_detailed_markdown(report):
            raise IntegrityError("detailed finding report Markdown rendering is not deterministic")
        assert_no_redaction_markers(md_text, artifact_name=REPORT_MARKDOWN)

        html_text = render_detailed_html(report)
        if html_text != render_detailed_html(report):
            raise IntegrityError("detailed finding report HTML rendering is not deterministic")
        assert_no_redaction_markers(html_text, artifact_name=REPORT_HTML)

        md_path = unit.unit_root / REPORT_MARKDOWN
        html_path = unit.unit_root / REPORT_HTML
        atomic_bytes(md_path, md_text.encode("utf-8"))
        atomic_bytes(html_path, html_text.encode("utf-8"))
        return {
            "artifact": artifact_ref(run_root, md_path),
            "html": artifact_ref(run_root, html_path),
            "diagram_files": diagram_refs,
            "settings": settings.identity(),
            "gaps": [],
            "terminal_status": ProducerStatus.SUCCEEDED.value,
        }

    def render_pdf(unit: UnitContext) -> Mapping[str, Any]:
        started = time.monotonic()
        run_root = unit.job.run_root
        repo_root = _root(unit)
        settings = _settings(unit)
        gate_schemas = _gate_schemas(repo_root)
        loaded = unit.output("load.accepted_inputs")
        assembled = unit.output("report.assemble")

        gate = read_bound_json(run_root, loaded["gate_document"])
        bound_dossiers = _bind_gate_dossiers(run_root, gate)
        report = read_bound_json(run_root, assembled["artifact"])

        result = _render_detailed_pdf(
            run_root,
            unit.unit_root,
            report,
            report_ref=assembled["artifact"],
            certified_dossier_count=len(gate.get("attachments", {}).get("dossiers", ())),
            read_dossier_count=len(bound_dossiers),
            settings=settings,
            repository_root=repo_root,
            executor_factory=executor_factory,
        )
        receipt_doc = read_bound_json(run_root, result["files"]["receipt"])
        _check_gate_schema(gate_schemas, PDF_RECEIPT_SCHEMA_NAME, receipt_doc)

        receipt_ev = [_gap_ref(run_root, result["files"]["receipt"])]
        pdf_gaps: list[dict[str, Any]] = []
        for gap_msg in result["gaps"]:
            is_retryable = result["status"] == "render_failed"
            code = GapCode.PRODUCER_FAILED if result["status"] == "render_failed" else GapCode.PRODUCER_REPORTED_GAP
            pdf_gaps.append(
                producer_gap(
                    code,
                    gap_msg,
                    scope_id="detailed_pdf",
                    retryable=is_retryable,
                    evidence_refs=receipt_ev,
                )
            )

        unit.job.events.write(
            "DETAILED_FINDING_REPORT_PDF_RENDERED",
            status=result["status"],
            defects=report["summary"]["total_defect_count"],
            gap_count=len(pdf_gaps),
            render_pdf=settings.render_pdf,
            duration_ms=max(0, round((time.monotonic() - started) * 1000)),
        )
        return {
            "status": result["status"],
            "reason": result["reason"],
            "files": result["files"],
            "tex_sha256": result["tex_sha256"],
            "pdf_sha256": result["pdf_sha256"],
            "settings": settings.pdf_identity(),
            "gaps": pdf_gaps,
            "terminal_status": (
                ProducerStatus.COMPLETED_WITH_GAPS.value
                if pdf_gaps
                else ProducerStatus.SUCCEEDED.value
            ),
        }

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        run_root = unit.job.run_root
        repo_root = _root(unit)
        settings = _settings(unit)
        gate_schemas = _gate_schemas(repo_root)

        loaded, assembled, rendered, pdf = (
            unit.output(name)
            for name in ("load.accepted_inputs", "report.assemble", "report.render", "report.render_pdf")
        )

        # Re-prove upstream gate + optional alternate CPG under validation_scope.
        reverified = _load_verified_upstream(run_root, gate_schemas)
        if reverified["gate_handoff"] != loaded["gate_handoff"]:
            raise IntegrityError("accepted gate handoff changed during detailed finding report execution")
        if reverified["code_graph_handoff"] != loaded["code_graph_handoff"]:
            raise IntegrityError("accepted code_graph_index handoff changed during detailed finding report execution")

        report = read_bound_json(run_root, assembled["artifact"])
        _check_detailed_schema(repo_root, "detailed-finding-report.schema.json", report)
        if report["provenance"]["gate_handoff"] != loaded["gate_handoff"]:
            raise IntegrityError("detailed finding report is not bound to the accepted gate handoff")
        assert_no_redaction_markers(
            read_bound(run_root, assembled["artifact"]).decode("utf-8"),
            artifact_name=REPORT_JSON,
        )

        expected_md = render_detailed_markdown(report).encode("utf-8")
        if read_bound(run_root, rendered["artifact"]) != expected_md:
            raise IntegrityError("detailed-finding-report.md does not match detailed-finding-report.json")
        assert_no_redaction_markers(expected_md.decode("utf-8"), artifact_name=REPORT_MARKDOWN)

        expected_html = render_detailed_html(report).encode("utf-8")
        if read_bound(run_root, rendered["html"]) != expected_html:
            raise IntegrityError("detailed-finding-report.html does not match detailed-finding-report.json")
        assert_no_redaction_markers(expected_html.decode("utf-8"), artifact_name=REPORT_HTML)

        diagram_files = list(rendered["diagram_files"])
        if len(diagram_files) != report["summary"]["diagram_count"]:
            raise IntegrityError("standalone diagram file count disagrees with detailed-finding-report.json")
        for diag in diagram_files:
            for key in ("svg", "mermaid", "dot"):
                raw_diag = read_bound(run_root, diag[key])
                assert_no_redaction_markers(raw_diag.decode("utf-8"), artifact_name=diag[key]["path"])

        files = pdf["files"]
        receipt = read_bound_json(run_root, files["receipt"])
        _check_gate_schema(gate_schemas, PDF_RECEIPT_SCHEMA_NAME, receipt)
        tex = read_bound(run_root, files["latex"])
        if tex != render_detailed_latex(report, template_dir=template_dir(repo_root)):
            raise IntegrityError("detailed-finding-report.tex does not match detailed-finding-report.json")
        assert_no_redaction_markers(tex.decode("utf-8"), artifact_name=TEX_NAME)
        if receipt["tex_sha256"] != hashlib.sha256(tex).hexdigest() or receipt["report"] != assembled["artifact"]:
            raise IntegrityError("PDF receipt does not match detailed-finding-report.json and LaTeX")
        if receipt["status"] == "rendered":
            if files["pdf"] is None or receipt["pdf_sha256"] != files["pdf"]["sha256"]:
                raise IntegrityError("PDF receipt claims rendered without matching PDF digest")
            if not valid_pdf(read_bound(run_root, files["pdf"]), settings.max_pdf_bytes):
                raise IntegrityError("detailed-finding-report.pdf is not a valid PDF")
        elif files["pdf"] is not None or receipt["pdf_sha256"] is not None:
            raise IntegrityError("PDF file is present without a rendered receipt")

        gaps = [*loaded["gaps"], *assembled["gaps"], *pdf["gaps"]]
        terminal_status = (
            ProducerStatus.COMPLETED_WITH_GAPS.value
            if gaps
            else ProducerStatus.SUCCEEDED.value
        )
        counts = report["summary"]
        handoff = {
            "schema": DETAILED_FINDING_REPORT_HANDOFF_SCHEMA,
            "report_schema": DETAILED_FINDING_REPORT_SCHEMA,
            "artifact": assembled["artifact"],
            "markdown": rendered["artifact"],
            "html": rendered["html"],
            "diagram_files": diagram_files,
            "gate_handoff": loaded["gate_handoff"],
            "code_graph_handoff": loaded["code_graph_handoff"],
            "status": report["status"],
            "summary": {
                "publishable_defect_count": counts["publishable_defect_count"],
                "backlog_defect_count": counts["backlog_defect_count"],
                "total_defect_count": counts["total_defect_count"],
                "diagram_count": counts["diagram_count"],
                "cpg_fanout_resolved_count": counts["cpg_fanout_resolved_count"],
                "cpg_cfg_resolved_count": counts["cpg_cfg_resolved_count"],
                "fallback_fanout_count": counts["fallback_fanout_count"],
                "fallback_cfg_count": counts["fallback_cfg_count"],
            },
            "item_count": counts["total_defect_count"],
            "pdf": pdf_record(receipt, files),
            "gaps": gaps,
            "terminal_status": terminal_status,
        }
        _check_detailed_schema(repo_root, "detailed-finding-report-handoff.schema.json", handoff)

        unit.job.events.write(
            "DETAILED_FINDING_REPORT_PUBLISHED",
            gate_status=report["status"]["gate_status"],
            code_graph_status=report["status"]["code_graph_status"],
            publishable_defects=counts["publishable_defect_count"],
            backlog_defects=counts["backlog_defect_count"],
            diagrams=counts["diagram_count"],
            pdf=receipt["status"],
            terminal_status=terminal_status,
        )
        return handoff

    units = (
        Unit("load.accepted_inputs", load_inputs),
        Unit("report.assemble", assemble, ("load.accepted_inputs",)),
        Unit("report.render", render, ("load.accepted_inputs", "report.assemble")),
        Unit("report.render_pdf", render_pdf, ("load.accepted_inputs", "report.assemble")),
        Unit(
            "acceptance.publish_handoff",
            publish,
            ("load.accepted_inputs", "report.assemble", "report.render", "report.render_pdf"),
        ),
    )
    implementation = None
    return Job(
        JOB_ID,
        "detailed_finding_report",
        UnitExecutor(units).execute,
        input_validators=(_validate,),
        schema_identity=DETAILED_FINDING_REPORT_HANDOFF_SCHEMA,
        implementation_identity=implementation,
        validation_identity=implementation,
        units=units,
        datasets=DATASETS,
        strict_gaps=True,
        contract=CONTRACT,
    )
