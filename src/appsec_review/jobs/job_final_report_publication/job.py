"""``job_final_report_publication``: the terminal, deterministic report of the review pipeline.

Units: ``load.accepted_gate`` re-verifies the accepted ``job_final_publication_gate`` handoff, the
gate document and every artifact the gate binds, ``report.assemble`` writes the schema-validated
``final-report.json``, ``report.render`` renders ``final-report.md`` and ``final-report.html`` from
that JSON, ``report.render_pdf`` renders the executive ``final-report.pdf`` (with its ``final-report.tex``
and a receipt) from that JSON plus the gate-bound dossier documents, and ``acceptance.publish_handoff``
re-proves every file and publishes the hash-pinned handoff. The job calls no model and reads nothing
the gate does not bind.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Mapping

from appsec_review.applicability import resolved_configuration_identity
from appsec_review.container_runtime.executor import ContainerExecutor
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound, read_bound_json
from appsec_review.jobs.engineering_contracts import (
    FINAL_REPORT_HANDOFF_SCHEMA, FINAL_REPORT_SCHEMA,
)
from appsec_review.jobs.job_final_publication_gate.verify import (
    load_accepted_gate, verify_gate_snapshot as _verify_bindings,
)
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.reporting.dimensions import radar_telemetry
from appsec_review.reporting.executive_report import render_executive_html
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_bytes, atomic_json

from .datasets import CONTRACT, DATASETS
from .pdf import (
    ExecutorFactory, bind_dossiers, render_executive_latex, render_executive_pdf, template_dir, valid_pdf,
)
from .render import render_markdown
from .report import build_report
from .settings import FinalReportSettings

JOB_ID = "job_final_report_publication"
GATE_JOB = "job_final_publication_gate"
SCHEMA_ROOT = Path("docs") / "schemas" / "final-report"
TOPOLOGY = {"load": ("accepted_gate",), "report": ("assemble", "render", "render_pdf"),
            "acceptance": ("publish_handoff",)}
IMPLEMENTATION = "appsec-review/final-report-publication/1"
REPORT_JSON = "final-report.json"
REPORT_MARKDOWN = "final-report.md"
REPORT_HTML = "final-report.html"
PDF_RECEIPT = "final-report-pdf-receipt"


def _configuration_profile(run_root: Path) -> Mapping[str, Any]:
    """The runtime profile (name and layer hash) the run was configured with, from its verified resolved configuration."""
    resolved_configuration_identity(run_root)
    record = json.loads((run_root / "data" / "configuration" / "resolved.json").read_text(encoding="utf-8"))
    profile = record.get("configuration_profile") or {"name": "dev", "sha256": None}
    return {"name": profile["name"], "sha256": profile.get("sha256")}


def _settings(unit: UnitContext) -> FinalReportSettings:
    return FinalReportSettings.from_mapping(unit.job.config.settings)


def _validate(context: Any, _result: Any) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("final report topology does not match configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"final report task configuration mismatch: {step}")
    FinalReportSettings.from_mapping(context.config.settings)


def _check(schemas: SchemaSet, name: str, document: Any) -> None:
    errors = schemas.errors(name, document)
    if errors:
        raise IntegrityError(f"{name} does not satisfy its schema: {'; '.join(errors[:3])}")


def pdf_record(receipt: Mapping[str, Any], files: Mapping[str, Any]) -> dict[str, Any]:
    """The handoff's ``pdf`` field: the executive PDF's outcome, from its receipt."""
    return {"state": receipt["status"], "reason": receipt["reason"], "file": files["pdf"],
            "sha256": receipt["pdf_sha256"], "latex": files["latex"], "receipt": files["receipt"]}


def build_job(*, repository_root: Path | None = None,
              executor_factory: ExecutorFactory = ContainerExecutor) -> Job:
    """``repository_root`` is injectable for acceptance tests whose configuration lives elsewhere;
    ``executor_factory`` lets unit tests stand in for the container runtime of the PDF renderer."""

    def _root(unit: UnitContext) -> Path:
        return Path(repository_root or unit.job.repository_root).resolve()

    def _schemas(unit: UnitContext) -> SchemaSet:
        return SchemaSet(_root(unit) / SCHEMA_ROOT)

    def load(unit: UnitContext) -> Mapping[str, Any]:
        run_root = unit.job.run_root
        accepted, gate = load_accepted_gate(
            run_root, _schemas(unit), expected_handoff_sha256=unit.job.upstream_handoffs.get(GATE_JOB))
        published = accepted.handoff["outputs"]["acceptance.publish_handoff"]
        reference = published["artifact"]
        counts = gate["package_counts"]
        gate_handoff = {"path": accepted.path, "sha256": accepted.sha256}
        return {"gate_handoff": gate_handoff,
                "gate_document": {"path": reference["path"], "sha256": reference["sha256"]},
                "gate_status": gate["status"], "review_status": gate["review"]["status"],
                "package_counts": counts, "binding_count": len(gate["bindings"]),
                "gaps": [], "terminal_status": "SUCCEEDED"}

    def assemble(unit: UnitContext) -> Mapping[str, Any]:
        started = time.monotonic()
        loaded = unit.output("load.accepted_gate")
        gate = read_bound_json(unit.job.run_root, loaded["gate_document"])
        report = build_report(gate, gate_handoff=loaded["gate_handoff"], gate_document=loaded["gate_document"],
                              configuration_profile=_configuration_profile(unit.job.run_root))
        _check(_schemas(unit), "final-report", report)
        path = unit.unit_root / REPORT_JSON
        atomic_json(path, report)
        tracker = report.get("radar_tracker") or {}
        radar_conf = tracker.get("coverage_confidence") or {}
        r_tel = radar_telemetry(tracker)
        posture = report.get("executive_posture") or {}
        unit.job.events.write(
            "FINAL_REPORT_ASSEMBLED",
            findings=len(report["findings"]),
            publishable_count=len(report["findings"]),
            backlog_count=len(report["verification_backlog"]),
            withheld_count=len(report["withheld"]),
            attachment_count=sum(len(rows) for rows in gate["attachments"].values()),
            gap_count=sum(item["kind"] == "gap" for item in report["limitations"]),
            duration_ms=max(0, round((time.monotonic() - started) * 1000)),
            verification_backlog=len(report["verification_backlog"]),
            limitation_count=len(report["limitations"]),
            certified_outcome_counts={name: len(gate["attachments"][name])
                                       for name in sorted(gate["attachments"])},
            radar_verified_axes=int(radar_conf.get("verified_axes", 0)),
            radar_gap_axes=int(radar_conf.get("gap_axes", 0)),
            coverage_confidence_score=int(radar_conf.get("confidence_score", 0)),
            chain_elevated_count=int(posture.get("chain_elevated_findings_count", 0)),
            remediation_roadmap_count=len(report.get("remediation_roadmap") or ()),
            named_gap_count=len(report.get("named_coverage_gaps") or ()),
            radar_counts_by_axis_and_series=r_tel["reporting.radar_counts_by_axis_and_series"],
            funnel_conversion_rates=r_tel["reporting.funnel_conversion_rates"],
            runtime_verified=False,
        )
        return {"artifact": artifact_ref(unit.job.run_root, path), "gaps": [], "terminal_status": "SUCCEEDED"}

    def render(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        report = read_bound_json(unit.job.run_root, unit.output("report.assemble")["artifact"])
        text = render_markdown(report, evidence_ids=settings.markdown_evidence_ids, gap_ids=settings.markdown_gap_ids)
        if text != render_markdown(report, evidence_ids=settings.markdown_evidence_ids, gap_ids=settings.markdown_gap_ids):
            raise IntegrityError("report rendering is not deterministic")
        html_text = render_executive_html(report)
        if html_text != render_executive_html(report):
            raise IntegrityError("executive HTML rendering is not deterministic")
        path = unit.unit_root / REPORT_MARKDOWN
        html_path = unit.unit_root / REPORT_HTML
        atomic_bytes(path, text.encode("utf-8"))
        atomic_bytes(html_path, html_text.encode("utf-8"))
        return {
            "artifact": artifact_ref(unit.job.run_root, path),
            "html": artifact_ref(unit.job.run_root, html_path),
            "settings": settings.identity(),
            "gaps": [],
            "terminal_status": "SUCCEEDED",
        }

    def render_pdf(unit: UnitContext) -> Mapping[str, Any]:
        started = time.monotonic()
        settings = _settings(unit)
        run_root = unit.job.run_root
        loaded, assembled = unit.output("load.accepted_gate"), unit.output("report.assemble")
        gate = read_bound_json(run_root, loaded["gate_document"])
        report = read_bound_json(run_root, assembled["artifact"])
        dossiers = bind_dossiers(run_root, report, gate["bindings"])
        result = render_executive_pdf(run_root, unit.unit_root, report, dossiers, report_ref=assembled["artifact"],
                                      settings=settings, repository_root=_root(unit), executor_factory=executor_factory)
        _check(_schemas(unit), PDF_RECEIPT, read_bound_json(run_root, result["files"]["receipt"]))
        unit.job.events.write("FINAL_REPORT_PDF_RENDERED", status=result["status"], findings=len(report["findings"]),
                              dossiers_certified=len(dossiers), dossiers_read=sum(1 for row in dossiers if row.document),
                              gap_count=len(result["gaps"]), render_pdf=settings.render_pdf,
                              duration_ms=max(0, round((time.monotonic() - started) * 1000)))
        return {"status": result["status"], "reason": result["reason"], "files": result["files"],
                "tex_sha256": result["tex_sha256"], "pdf_sha256": result["pdf_sha256"],
                "settings": settings.pdf_identity(), "gaps": list(result["gaps"]),
                "terminal_status": "SUCCEEDED" if not result["gaps"] else "COMPLETED_WITH_GAPS"}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        run_root = unit.job.run_root
        settings = _settings(unit)
        loaded, assembled, rendered, pdf = (unit.output(name) for name in (
            "load.accepted_gate", "report.assemble", "report.render", "report.render_pdf"))
        gate = read_bound_json(run_root, loaded["gate_document"])
        _verify_bindings(run_root, gate)
        report = read_bound_json(run_root, assembled["artifact"])
        _check(_schemas(unit), "final-report", report)
        expected = render_markdown(report, evidence_ids=settings.markdown_evidence_ids,
                                   gap_ids=settings.markdown_gap_ids).encode("utf-8")
        if read_bound(run_root, rendered["artifact"]) != expected:
            raise IntegrityError("final-report.md is not the rendering of final-report.json")
        if report["provenance"]["gate_handoff"] != loaded["gate_handoff"]:
            raise IntegrityError("final report is not bound to the accepted gate handoff")
        if rendered.get("html") is not None:
            expected_html = render_executive_html(report).encode("utf-8")
            if read_bound(run_root, rendered["html"]) != expected_html:
                raise IntegrityError("final-report.html is not the rendering of final-report.json")
        files = pdf["files"]
        receipt = read_bound_json(run_root, files["receipt"])
        _check(_schemas(unit), PDF_RECEIPT, receipt)
        tex = read_bound(run_root, files["latex"])
        if tex != render_executive_latex(report, bind_dossiers(run_root, report, gate["bindings"]), template_dir(_root(unit))):
            raise IntegrityError("final-report.tex is not the rendering of final-report.json and its bound dossiers")
        if receipt["tex_sha256"] != hashlib.sha256(tex).hexdigest() or receipt["report"] != assembled["artifact"]:
            raise IntegrityError("the executive PDF receipt does not name the published report and LaTeX")
        if receipt["status"] == "rendered":
            if files["pdf"] is None or receipt["pdf_sha256"] != files["pdf"]["sha256"]:
                raise IntegrityError("the executive PDF receipt claims a rendering without the PDF it hashes")
            if not valid_pdf(read_bound(run_root, files["pdf"]), settings.max_pdf_bytes):
                raise IntegrityError("final-report.pdf is not a valid PDF")
        elif files["pdf"] is not None or receipt["pdf_sha256"] is not None:
            raise IntegrityError("a PDF is published without a rendered receipt")
        gaps = [f"{item['limitation_id']}: {item['statement']}"[:300] for item in report["limitations"]
                if item["kind"] == "gap"] + [gap[:300] for gap in pdf["gaps"]]
        counts = report["summary"]["package_counts"]
        posture = report.get("executive_posture") or {}
        unit.job.events.write(
            "FINAL_REPORT_PUBLISHED",
            publication=report["status"]["publication"],
            review_complete=report["status"]["review_complete"],
            findings=counts["publishable"],
            verification_backlog=counts["verification_backlog"],
            withheld=counts["withheld"],
            release_readiness=posture.get("release_readiness", "UNKNOWN"),
            pdf=receipt["status"],
        )
        return {
            "schema": FINAL_REPORT_HANDOFF_SCHEMA,
            "report_schema": FINAL_REPORT_SCHEMA,
            "artifact": assembled["artifact"],
            "markdown": rendered["artifact"],
            **({"html": rendered["html"]} if rendered.get("html") is not None else {}),
            "gate_handoff": loaded["gate_handoff"],
            "status": report["status"],
            "package_counts": counts,
            "item_count": counts["publishable"] + counts["verification_backlog"],
            "pdf": pdf_record(receipt, files),
            "poc_handoff": report["provenance"].get("poc_handoff"),
            "gaps": gaps,
            "terminal_status": "SUCCEEDED" if not gaps else "COMPLETED_WITH_GAPS",
        }

    units = (
        Unit("load.accepted_gate", load),
        Unit("report.assemble", assemble, ("load.accepted_gate",)),
        Unit("report.render", render, ("report.assemble",)),
        Unit("report.render_pdf", render_pdf, ("load.accepted_gate", "report.assemble")),
        Unit("acceptance.publish_handoff", publish,
             ("load.accepted_gate", "report.assemble", "report.render", "report.render_pdf")),
    )
    implementation = None
    return Job(JOB_ID, "final_report_publication", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=FINAL_REPORT_HANDOFF_SCHEMA, implementation_identity=implementation,
               validation_identity=implementation, units=units, datasets=DATASETS, contract=CONTRACT)
