"""``job_final_report_publication``: the terminal, deterministic report of the review pipeline.

Units: ``load.accepted_gate`` re-verifies the accepted ``job_final_publication_gate`` handoff, the
gate document and every artifact the gate binds, ``report.assemble`` writes the schema-validated
``final-report.json``, ``report.render`` renders ``final-report.md`` from that JSON, and
``acceptance.publish_handoff`` re-proves both files and publishes the hash-pinned handoff. The job
calls no model and reads nothing the gate does not bind. PDF rendering is a later step.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound, read_bound_json, resolve_bound
from appsec_review.jobs.engineering_contracts import (
    FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA, FINAL_PUBLICATION_GATE_SCHEMA, FINAL_REPORT_HANDOFF_SCHEMA,
    FINAL_REPORT_SCHEMA, POC_GENERATION_HANDOFF_SCHEMA, POC_GENERATION_SCHEMA,
)
from appsec_review.jobs.job_final_publication_gate import JOB_ID as GATE_JOB
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_bytes, atomic_json

from .datasets import CONSUMES, DATASETS
from .render import render_markdown
from .report import build_report
from .settings import FinalReportSettings

JOB_ID = "job_final_report_publication"
POC_JOB = "job_poc_generation"
SCHEMA_ROOT = Path("docs") / "schemas" / "final-report"
POC_SCHEMA_ROOT = Path("docs") / "schemas" / "poc-generation"
TOPOLOGY = {"load": ("accepted_gate",), "report": ("assemble", "render"), "acceptance": ("publish_handoff",)}
IMPLEMENTATION = "appsec-review/final-report-publication/1"
REPORT_JSON = "final-report.json"
REPORT_MARKDOWN = "final-report.md"


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


def load_poc(run_root: Path, schemas: SchemaSet, gate_handoff: Mapping[str, str]) -> dict[str, Any] | None:
    """The run's accepted PoC summary, re-proved from bytes, or ``None`` when the PoC job has not run.

    A PoC handoff built from a different gate handoff is *stale*: it is reported as such and its outcomes are
    not shown. Every file the summary names is re-hashed, so a changed reproducer is an integrity failure.
    """
    try:
        accepted = accepted_handoff(run_root, POC_JOB)
    except ValueError as exc:
        raise IntegrityError(f"accepted {POC_JOB} handoff cannot be verified: {exc}") from exc
    if accepted is None:
        return None
    published = (accepted.handoff.get("outputs") or {}).get("publish.publish_handoff")
    if (accepted.handoff.get("job_id") != POC_JOB or not isinstance(published, Mapping)
            or published.get("schema") != POC_GENERATION_HANDOFF_SCHEMA):
        raise IntegrityError("accepted PoC handoff does not publish a supported summary")
    document = read_bound_json(run_root, published["artifact"])
    _check(schemas, "poc-generation", document)
    if document["schema"] != POC_GENERATION_SCHEMA or published.get("item_count") != len(document["candidates"]):
        raise IntegrityError("PoC summary disagrees with its accepted handoff")
    stale = document["upstream"]["gate_handoff"] != dict(gate_handoff)
    if not stale:
        for row in document["candidates"]:
            for reference in (row["files"] or {}).values():
                resolve_bound(run_root, reference)
    return {"handoff": {"path": accepted.path, "sha256": accepted.sha256}, "document": document, "stale": stale}


def build_job(*, repository_root: Path | None = None) -> Job:
    """``repository_root`` is injectable for acceptance tests whose configuration lives elsewhere."""

    def _root(unit: UnitContext) -> Path:
        return Path(repository_root or unit.job.repository_root).resolve()

    def _schemas(unit: UnitContext) -> SchemaSet:
        return SchemaSet(_root(unit) / SCHEMA_ROOT)

    def _poc(unit: UnitContext, gate_handoff: Mapping[str, str]) -> dict[str, Any] | None:
        return load_poc(unit.job.run_root, SchemaSet(_root(unit) / POC_SCHEMA_ROOT), gate_handoff)

    def load(unit: UnitContext) -> Mapping[str, Any]:
        run_root = unit.job.run_root
        try:
            accepted = accepted_handoff(run_root, GATE_JOB)
        except ValueError as exc:
            raise IntegrityError(f"accepted {GATE_JOB} handoff cannot be verified: {exc}") from exc
        if accepted is None or accepted.handoff.get("job_id") != GATE_JOB:
            raise IntegrityError(f"an accepted {GATE_JOB} handoff is required")
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
        for binding in gate["bindings"]:                       # every artifact the gate bound, from bytes
            resolve_bound(run_root, binding)
        for key in ("job_handoff", "review_handoff", "claim_ledger", "projection", "coverage_matrix"):
            if gate["inputs"][key] not in gate["bindings"]:
                raise IntegrityError(f"gate input is not among its bindings: {key}")
        gate_handoff = {"path": accepted.path, "sha256": accepted.sha256}
        poc = _poc(unit, gate_handoff)
        return {"gate_handoff": gate_handoff,
                "gate_document": {"path": reference["path"], "sha256": reference["sha256"]},
                "gate_status": gate["status"], "review_status": gate["review"]["status"],
                "package_counts": counts, "binding_count": len(gate["bindings"]),
                "poc": None if poc is None else {"handoff": poc["handoff"], "stale": poc["stale"]},
                "gaps": [], "terminal_status": "SUCCEEDED"}

    def assemble(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("load.accepted_gate")
        gate = read_bound_json(unit.job.run_root, loaded["gate_document"])
        poc = _poc(unit, loaded["gate_handoff"])
        if (None if poc is None else {"handoff": poc["handoff"], "stale": poc["stale"]}) != loaded["poc"]:
            raise IntegrityError("the PoC handoff changed between load and assemble")
        report = build_report(gate, gate_handoff=loaded["gate_handoff"], gate_document=loaded["gate_document"],
                              poc=poc)
        _check(_schemas(unit), "final-report", report)
        path = unit.unit_root / REPORT_JSON
        atomic_json(path, report)
        unit.job.events.write("FINAL_REPORT_ASSEMBLED", findings=len(report["findings"]),
                              verification_backlog=len(report["verification_backlog"]),
                              limitation_count=len(report["limitations"]))
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
    implementation = hashlib.sha256(
        IMPLEMENTATION.encode() + b"".join(path.read_bytes() for path in sorted(package.glob("*.py")))).hexdigest()
    return Job(JOB_ID, "final_report_publication", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=FINAL_REPORT_HANDOFF_SCHEMA, implementation_identity=implementation,
               validation_identity=implementation, units=units, datasets=DATASETS, consumes=CONSUMES)
