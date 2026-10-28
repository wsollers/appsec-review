"""``job_final_publication_gate``: deterministic publication gate over the accepted inference review.

Units: ``load.verify_review`` re-verifies the accepted ``job_inference_security_review`` handoff and
every artifact it binds from bytes (an integrity failure fails the job), ``gate.classify`` places
every finding package in exactly one of publishable, verification backlog or withheld and names the
limitations, and ``acceptance.publish_handoff`` publishes the schema-validated gate document. The job
calls no model and never reinterprets a claim state or a ship-block status.
"""
from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.applicability import resolved_configuration_identity
from appsec_review.jobs.engineering_contracts import (
    FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA, FINAL_PUBLICATION_GATE_SCHEMA,
)
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json

from . import classify as classifier
from .datasets import CONSUMES, DATASETS
from .settings import FinalPublicationGateSettings
from appsec_review.jobs.accepted_review import load_accepted_review
from .attachments import PRODUCERS, require, reverify_snapshot, verify_attachments

JOB_ID = "job_final_publication_gate"
SCHEMA_ROOT = Path("docs") / "schemas" / "final-report"
TOPOLOGY = {"load": ("verify_review",), "gate": ("classify",), "acceptance": ("publish_handoff",)}
IMPLEMENTATION = "appsec-review/final-publication-gate/1"


def _settings(unit: UnitContext) -> FinalPublicationGateSettings:
    return FinalPublicationGateSettings.from_mapping(unit.job.config.settings)


def _artifact(unit: UnitContext, name: str, document: Any) -> dict[str, Any]:
    path = unit.unit_root / name
    atomic_json(path, document)
    return artifact_ref(unit.job.run_root, path)


def _validate(context: Any, _result: Any) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("final publication gate topology does not match configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"final publication gate task configuration mismatch: {step}")
    FinalPublicationGateSettings.from_mapping(context.config.settings)


def build_job(*, repository_root: Path | None = None) -> Job:
    """``repository_root`` is injectable for acceptance tests whose configuration lives elsewhere."""

    def repo(unit: UnitContext) -> Path:
        return Path(repository_root or unit.job.repository_root).resolve()

    def verify(unit: UnitContext) -> Mapping[str, Any]:
        started = time.monotonic()
        settings = _settings(unit)
        schemas = SchemaSet(repo(unit) / SCHEMA_DIRECTORY)
        verified = load_accepted_review(unit.job.run_root, schemas, max_packages=settings.max_packages)
        document = verified.document
        configuration_sha = resolved_configuration_identity(unit.job.run_root)
        configuration_path = unit.job.run_root / "data" / "configuration" / "resolved.json"
        configuration = json.loads(configuration_path.read_text(encoding="utf-8"))
        jobs = configuration["jobs"]
        enabled = {name: bool(jobs.get(job, {}).get("settings", {}).get("enabled", False))
                   for name, (job, *_rest) in PRODUCERS.items()}
        # Chain work is an unconditional bounded stage of the accepted review.
        enabled["attack_chains"] = True
        # A manual producer is admitted only by an exact upstream identity, never mere discovery.
        upstream = unit.job.upstream_handoffs
        claimed_review = upstream.get("job_inference_security_review")
        require(claimed_review is None or claimed_review == document["inputs"]["job_handoff"]["sha256"],
                "accepted review differs from the gate attempt's upstream identity")
        if "job_poc_generation" in upstream:
            enabled["poc_generation"] = True
        document.update(verify_attachments(unit.job.run_root, document, repository_root=repo(unit), enabled=enabled))
        document["bindings"].append({"path": configuration_path.relative_to(unit.job.run_root).as_posix(),
                                     "sha256": configuration_sha})
        poc = document["capabilities"]["poc_generation"]
        if "job_poc_generation" in upstream:
            require(poc["handoff"] is not None and poc["handoff"]["sha256"] == upstream["job_poc_generation"],
                    "manually admitted PoC handoff differs from its explicit upstream identity")
        for name, (job, *_rest) in PRODUCERS.items():
            record = document["capabilities"][name]
            if record["enabled"] and job in upstream:
                require(record["handoff"] is not None and record["handoff"]["sha256"] == upstream[job],
                        f"accepted {job} differs from the gate attempt's upstream identity")
        unit.job.events.write(
            "FINAL_PUBLICATION_GATE_CAPABILITIES_VERIFIED",
            attachment_count=sum(len(rows) for rows in document["attachments"].values()),
            gap_count=sum(row["gap_count"] for row in document["capabilities"].values()),
            omitted_count=sum(row["omitted_count"] for row in document["capabilities"].values()),
            outcomes=dict(Counter(row["disposition"] for row in document["capabilities"].values())),
            duration_ms=max(0, round((time.monotonic() - started) * 1000)),
            dispositions={name: row["disposition"] for name, row in sorted(document["capabilities"].items())},
            attachment_counts={name: len(rows) for name, rows in sorted(document["attachments"].items())},
            gap_counts={name: row["gap_count"] for name, row in sorted(document["capabilities"].items())},
            omitted_counts={name: row["omitted_count"] for name, row in sorted(document["capabilities"].items())},
            enabled={name: row["enabled"] for name, row in sorted(document["capabilities"].items())},
            explicit_poc_admission="job_poc_generation" in upstream)
        unit.job.events.write("FINAL_PUBLICATION_GATE_REVIEW_VERIFIED", status=document["review"]["status"],
                              package_count=len(document["packages"]), binding_count=len(document["bindings"]))
        return {"artifact": _artifact(unit, "verified-review.json", document),
                "review_status": document["review"]["status"], "package_count": len(document["packages"]),
                "binding_count": len(document["bindings"]), "gaps": [], "terminal_status": "SUCCEEDED"}

    def classify(unit: UnitContext) -> Mapping[str, Any]:
        verified = read_bound_json(unit.job.run_root, unit.output("load.verify_review")["artifact"])
        classification = classifier.classify(verified)
        return {"artifact": _artifact(unit, "classification.json", classification),
                "package_counts": classification["package_counts"], "status": classification["status"],
                "gaps": [], "terminal_status": "SUCCEEDED"}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        run_root = unit.job.run_root
        verified = read_bound_json(run_root, unit.output("load.verify_review")["artifact"])
        classification = read_bound_json(run_root, unit.output("gate.classify")["artifact"])
        document = classifier.gate_document(FINAL_PUBLICATION_GATE_SCHEMA, verified, classification)
        reverify_snapshot(run_root, verified)
        schemas = SchemaSet(repo(unit) / SCHEMA_ROOT)
        errors = schemas.errors("final-publication-gate", document)
        if errors:
            raise IntegrityError(f"gate document does not satisfy its schema: {'; '.join(errors[:3])}")
        counts = document["package_counts"]
        if counts["total"] != len(document["packages"]) or counts["total"] != sum(
                len(ids) for ids in document["buckets"].values()):
            raise IntegrityError("gate package accounting is not exact")
        artifact = _artifact(unit, "final-publication-gate.json", document)
        gaps = [f"{item['limitation_id']}: {item['statement']}"[:300]
                for item in document["limitations"] if item["kind"] == "gap"]
        unit.job.events.write("FINAL_PUBLICATION_GATE_PUBLISHED", status=document["status"],
                              publishable=counts["publishable"], verification_backlog=counts["verification_backlog"],
                              withheld=counts["withheld"], limitation_count=len(document["limitations"]))
        return {"schema": FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA, "artifact": artifact, "status": document["status"],
                "review_status": document["review"]["status"], "package_counts": counts,
                "limitation_ids": [item["limitation_id"] for item in document["limitations"]],
                "item_count": counts["total"], "gaps": gaps,
                "terminal_status": "SUCCEEDED" if not gaps else "COMPLETED_WITH_GAPS"}

    units = (
        Unit("load.verify_review", verify),
        Unit("gate.classify", classify, ("load.verify_review",)),
        Unit("acceptance.publish_handoff", publish, ("load.verify_review", "gate.classify")),
    )
    package = Path(__file__).parent
    implementation = None
    return Job(JOB_ID, "final_publication_gate", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA, implementation_identity=implementation,
               validation_identity=implementation, units=units, datasets=DATASETS, consumes=CONSUMES)
