"""``job_final_report_publication``: the terminal, deterministic report of the review pipeline.

Units: ``load.accepted_gate`` re-verifies the accepted ``job_final_publication_gate`` handoff, the
gate document and every artifact the gate binds, ``report.assemble`` writes the schema-validated
``final-report.json``, ``report.render`` renders ``final-report.md`` from that JSON, and
``acceptance.publish_handoff`` re-proves both files and publishes the hash-pinned handoff. The job
calls no model and reads nothing the gate does not bind. PDF rendering is a later step.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Mapping

from appsec_review.applicability import resolved_configuration_identity
from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound, read_bound_json, resolve_bound
from appsec_review.jobs.engineering_contracts import (
    FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA, FINAL_PUBLICATION_GATE_SCHEMA, FINAL_REPORT_HANDOFF_SCHEMA,
    FINAL_REPORT_SCHEMA,
)
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_bytes, atomic_json

from .datasets import CONSUMES, DATASETS
from .render import render_markdown
from .report import build_report
from .settings import FinalReportSettings

JOB_ID = "job_final_report_publication"
GATE_JOB = "job_final_publication_gate"
SCHEMA_ROOT = Path("docs") / "schemas" / "final-report"
TOPOLOGY = {"load": ("accepted_gate",), "report": ("assemble", "render"), "acceptance": ("publish_handoff",)}
IMPLEMENTATION = "appsec-review/final-report-publication/1"
REPORT_JSON = "final-report.json"
REPORT_MARKDOWN = "final-report.md"


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


def _verify_bindings(run_root: Path, gate: Mapping[str, Any]) -> None:
    if gate["run_id"] != run_root.name:
        raise IntegrityError("gate snapshot belongs to another run")
    bindings = {(row["path"], row["sha256"]) for row in gate["bindings"]}
    for row in gate["bindings"]:
        resolve_bound(run_root, row)

    def included(value: Any) -> None:
        if isinstance(value, Mapping):
            if {"path", "sha256"} <= set(value) and (value["path"], value["sha256"]) not in bindings:
                raise IntegrityError("gate attachment is not among its certified bindings")
            for item in value.values():
                included(item)
        elif isinstance(value, list):
            for item in value:
                included(item)

    included(gate["inputs"])
    included(gate["capabilities"])
    included(gate["attachments"])


def build_job(*, repository_root: Path | None = None) -> Job:
    """``repository_root`` is injectable for acceptance tests whose configuration lives elsewhere."""

    def _root(unit: UnitContext) -> Path:
        return Path(repository_root or unit.job.repository_root).resolve()

    def _schemas(unit: UnitContext) -> SchemaSet:
        return SchemaSet(_root(unit) / SCHEMA_ROOT)

    def load(unit: UnitContext) -> Mapping[str, Any]:
        run_root = unit.job.run_root
        try:
            accepted = accepted_handoff(run_root, GATE_JOB)
        except ValueError as exc:
            raise IntegrityError(f"accepted {GATE_JOB} handoff cannot be verified: {exc}") from exc
        if accepted is None or accepted.handoff.get("job_id") != GATE_JOB:
            raise IntegrityError(f"an accepted {GATE_JOB} handoff is required")
        claimed_gate = unit.job.upstream_handoffs.get(GATE_JOB)
        if claimed_gate is not None and claimed_gate != accepted.sha256:
            raise IntegrityError("accepted gate differs from the report attempt's upstream identity")
        published = (accepted.handoff.get("outputs") or {}).get("acceptance.publish_handoff")
        if not isinstance(published, Mapping) or published.get("schema") != FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA:
            raise IntegrityError("accepted gate handoff does not publish a supported gate document")
        reference = published["artifact"]
        gate = read_bound_json(run_root, reference)
        _check(_schemas(unit), "final-publication-gate", gate)
        if gate["schema"] != FINAL_PUBLICATION_GATE_SCHEMA or published.get("item_count") != gate["package_counts"]["total"]:
            raise IntegrityError("gate document disagrees with its accepted handoff")
        counts = gate["package_counts"]
        if counts["total"] != len(gate["packages"]) or sorted(
                item["finding_package_id"] for item in gate["packages"]) != sorted(
                identity for ids in gate["buckets"].values() for identity in ids):
            raise IntegrityError("gate package accounting is not exact")
        _verify_bindings(run_root, gate)
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
        unit.job.events.write("FINAL_REPORT_ASSEMBLED", findings=len(report["findings"]),
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
                              runtime_verified=False)
        return {"artifact": artifact_ref(unit.job.run_root, path), "gaps": [], "terminal_status": "SUCCEEDED"}

    def render(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        report = read_bound_json(unit.job.run_root, unit.output("report.assemble")["artifact"])
        text = render_markdown(report, evidence_ids=settings.markdown_evidence_ids, gap_ids=settings.markdown_gap_ids)
        if text != render_markdown(report, evidence_ids=settings.markdown_evidence_ids, gap_ids=settings.markdown_gap_ids):
            raise IntegrityError("report rendering is not deterministic")
        path = unit.unit_root / REPORT_MARKDOWN
        atomic_bytes(path, text.encode("utf-8"))
        return {"artifact": artifact_ref(unit.job.run_root, path), "settings": settings.identity(),
                "gaps": [], "terminal_status": "SUCCEEDED"}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        run_root = unit.job.run_root
        settings = _settings(unit)
        loaded, assembled, rendered = (unit.output(name) for name in (
            "load.accepted_gate", "report.assemble", "report.render"))
        _verify_bindings(run_root, read_bound_json(run_root, loaded["gate_document"]))
        report = read_bound_json(run_root, assembled["artifact"])
        _check(_schemas(unit), "final-report", report)
        expected = render_markdown(report, evidence_ids=settings.markdown_evidence_ids,
                                   gap_ids=settings.markdown_gap_ids).encode("utf-8")
        if read_bound(run_root, rendered["artifact"]) != expected:
            raise IntegrityError("final-report.md is not the rendering of final-report.json")
        if report["provenance"]["gate_handoff"] != loaded["gate_handoff"]:
            raise IntegrityError("final report is not bound to the accepted gate handoff")
        gaps = [f"{item['limitation_id']}: {item['statement']}"[:300] for item in report["limitations"]
                if item["kind"] == "gap"]
        counts = report["summary"]["package_counts"]
        unit.job.events.write("FINAL_REPORT_PUBLISHED", publication=report["status"]["publication"],
                              review_complete=report["status"]["review_complete"], findings=counts["publishable"],
                              verification_backlog=counts["verification_backlog"], withheld=counts["withheld"])
        return {"schema": FINAL_REPORT_HANDOFF_SCHEMA, "report_schema": FINAL_REPORT_SCHEMA,
                "artifact": assembled["artifact"], "markdown": rendered["artifact"],
                "gate_handoff": loaded["gate_handoff"], "status": report["status"],
                "package_counts": counts, "item_count": counts["publishable"] + counts["verification_backlog"],
                "pdf": report["renderers"]["pdf"], "poc_handoff": report["provenance"].get("poc_handoff"),
                "gaps": gaps,
                "terminal_status": "SUCCEEDED" if not gaps else "COMPLETED_WITH_GAPS"}

    units = (
        Unit("load.accepted_gate", load),
        Unit("report.assemble", assemble, ("load.accepted_gate",)),
        Unit("report.render", render, ("report.assemble",)),
        Unit("acceptance.publish_handoff", publish, ("load.accepted_gate", "report.assemble", "report.render")),
    )
    package = Path(__file__).parent
    implementation = None
    return Job(JOB_ID, "final_report_publication", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=FINAL_REPORT_HANDOFF_SCHEMA, implementation_identity=implementation,
               validation_identity=implementation, units=units, datasets=DATASETS, consumes=CONSUMES)
