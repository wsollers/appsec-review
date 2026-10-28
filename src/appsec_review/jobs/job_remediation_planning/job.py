"""A real bounded writer creates immutable exact patches and separate safe regression specifications."""
from __future__ import annotations

from pathlib import Path
import time
from typing import Any, Callable, Mapping

from appsec_review.config.remediation import RemediationPlanningSettings
from appsec_review.inference import Infer
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json, resolve_bound
from appsec_review.jobs.completion_contracts import (
    REMEDIATION_PLAN_SCHEMA, REMEDIATION_PLANNING_HANDOFF_SCHEMA, REMEDIATION_PLANNING_JOB,
    REMEDIATION_PLANNING_SCHEMA, nonexecution_assurance,
)
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json
from .contracts import ANSWER_FIELDS, STATUSES, PlanAnswer, verify_patch_scope, verify_plan
from .datasets import CONSUMES, DATASETS
from .inputs import CoreFactory, SourceReader, binding, confirmed_findings, evidence_relations, load_review, retrieval_core
from .model import emit_model_event, guidance, run_model
from .patches import PatchError

JOB_ID = REMEDIATION_PLANNING_JOB
TOPOLOGY = {"load": ("verify_inputs",), "assess": ("propose",), "acceptance": ("publish_handoff",)}
SCHEMA_ROOT = Path("docs") / "schemas" / "remediation"


def write_json(unit: UnitContext, name: str, document: Any) -> dict[str, str]:
    path = unit.unit_root / name
    if path.exists():
        raise IntegrityError("attempt-owned remediation artifact already exists")
    atomic_json(path, document)
    return artifact_ref(unit.job.run_root, path)


def _validate(context: Any, _result: Any) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY) or any(
            tuple(context.config.step(step).tasks) != tasks for step, tasks in TOPOLOGY.items()):
        raise ValueError("remediation planning topology does not match central configuration")
    RemediationPlanningSettings.from_mapping(context.config.settings)


def build_job(*, infer: Infer | None = None, builds_factory: Callable[[Path], AcceptedBuilds] | None = None,
              core_factory: CoreFactory | None = None, repository_root: Path | None = None) -> Job:
    def repo(unit: UnitContext) -> Path:
        return Path(repository_root or unit.job.repository_root)

    def settings(unit: UnitContext) -> RemediationPlanningSettings:
        return RemediationPlanningSettings.from_mapping(unit.job.config.settings)

    def loaded(unit: UnitContext) -> Mapping[str, Any]:
        return read_bound_json(unit.job.run_root, unit.output("load.verify_inputs")["artifact"])

    def load(unit: UnitContext) -> Mapping[str, Any]:
        configured = settings(unit)
        review = load_review(unit.job.run_root, repo(unit), configured.bounds)
        candidates = confirmed_findings(review)
        unit.job.events.write("REMEDIATION_PLANNING_INPUTS_VERIFIED", confirmed_count=len(candidates),
                              admitted_count=min(len(candidates), configured.bounds.max_candidates),
                              omitted_count=max(0, len(candidates) - configured.bounds.max_candidates),
                              supported_excluded_count=len(review["partition"]["supported"]))
        return {"artifact": write_json(unit, "inputs.json", {"review": review, "candidates": candidates}),
                "item_count": len(candidates), "gaps": [], "terminal_status": "SUCCEEDED"}

    def assess(unit: UnitContext) -> Mapping[str, Any]:
        configured, root = settings(unit), unit.job.run_root
        document = loaded(unit)
        review = document["review"]
        builds = (builds_factory or AcceptedBuilds)(root)
        core = None
        text, guidance_sha = "", ""
        rows = []
        from appsec_review.inference import infer as default_infer
        for index, finding in enumerate(document["candidates"]):
            started = time.monotonic()
            identity = binding(finding)
            gap_ids: list[str] = []
            row: dict[str, Any] = {"finding": identity, "status": "insufficient_evidence", "plan": None,
                                   "reason": "", "gap_ids": gap_ids}
            if index >= configured.bounds.max_candidates:
                row.update(status="capped", reason="candidate_bound_reached")
            else:
                relations = evidence_relations(root, review, finding)
                if not relations:
                    row["reason"] = "confirmed_finding_has_no_resolving_evidence"
                else:
                    if core is None:
                        core = (core_factory or retrieval_core)(root, review)
                    reader = SourceReader(builds, core, relations, configured.bounds)
                    reader.resolve()
                    source_context = {"finding": identity, "adjudication_id": finding["adjudication_id"],
                                      "relations": relations, "files": list(reader.files.values()),
                                      "gaps": reader.gaps}
                    context_ref = write_json(unit, f"{index}/source-context.json", source_context)
                    if not text:
                        text, guidance_sha = guidance(repo(unit), root, "remediation_writer")
                    evidence_ids = {item["relation_id"] for item in relations}
                    task = {"kind": "remediation_proposal", "finding": identity, "title": finding["title"],
                            "accepted_evidence": relations, "source_files": list(reader.files.values()),
                            "source_gaps": reader.gaps,
                            "answer_fields": sorted(ANSWER_FIELDS),
                            "answer_shape": {
                                "status": "proposal_generated | manual_design_required | insufficient_evidence",
                                "reason": "<bounded explanation>",
                                "violated_invariant": "<current violated security requirement>",
                                "corrected_invariant": "<intended safety requirement>",
                                "evidence_ids": ["<supplied relation_id>"],
                                "patch": "<exact patch object, or null for non-proposal outcomes>",
                                **{key: ["<bounded assessment>"] for key in (
                                    "compatibility_effects", "affected_interfaces", "residual_risks",
                                    "deployment_prerequisites", "validation_checks", "scope_limitations")},
                                "regression_spec": {
                                    "fixtures": ["<synthetic fixture>"], "assertions": ["<safety assertion>"],
                                    "positive_cases": ["<valid input>"], "negative_cases": ["<rejected input>"],
                                    "before": "<baseline expected behavior>", "after": "<corrected behavior>",
                                    "safety_assertion": "<non-faulting, separately derived specification>"}},
                            "patch_format": {"schema": "appsec-review/remediation-exact-patch/1",
                              "files": [{"path": "<admitted path>", "before_sha256": "<original hash or null>",
                                         "absence_proof": False, "edits": [
                                             {"start": 0, "end": 0, "old": "", "new": "<replacement>"}]}]},
                            "regression_spec_fields": ["fixtures", "assertions", "positive_cases", "negative_cases",
                                                       "before", "after", "safety_assertion"]}
                    answer, receipt = run_model(
                        infer=infer or default_infer, profile=configured.writer, role="remediation_writer",
                        cell_id=f"remediation-writer:{finding['claim_id']}", guidance_text=text,
                        guidance_sha256=guidance_sha, task=task, retrieve=reader.retrieve,
                        validate=lambda value: PlanAnswer.from_mapping(
                            value, configured.bounds, evidence_ids=evidence_ids).document)
                    receipt_ref = write_json(unit, f"{index}/writer-receipt.json", receipt)
                    emit_model_event(unit.job.events, receipt)
                    if answer is None:
                        row["reason"] = receipt["reason"]
                    else:
                        parsed = PlanAnswer.from_mapping(answer, configured.bounds, evidence_ids=evidence_ids)
                        patch_ref = None
                        try:
                            if parsed.patch is not None:
                                verify_patch_scope(parsed.patch, reader.files, builds, configured.bounds)
                                patch_ref = write_json(unit, f"{index}/patch.json", parsed.patch.document)
                        except PatchError as exc:
                            row["reason"] = f"invalid_patch:{str(exc)[:180]}"
                        else:
                            plan = {"schema": REMEDIATION_PLAN_SCHEMA, "run_id": review["run_id"],
                                    "upstream": {"review_handoff": review["inputs"]["review_handoff"],
                                                 "poc_handoff": None},
                                    "finding": identity, "adjudication_id": finding["adjudication_id"],
                                    **{key: value for key, value in answer.items() if key != "patch"},
                                    "patch": patch_ref, "assurance": nonexecution_assurance(),
                                    "provenance": {"settings_sha256": configured.settings_sha256(),
                                                   "source_context": context_ref, "writer_receipt": receipt_ref,
                                                   "guidance_bundle_sha256": guidance_sha},
                                    "gaps": list(reader.gaps)}
                            reference = write_json(unit, f"{index}/plan.json", plan)
                            verify_plan(root, reference, review_handoff=review["inputs"]["review_handoff"],
                                        finding=identity, schemas=SchemaSet(repo(unit) / SCHEMA_ROOT))
                            row.update(status=answer["status"], reason=answer["reason"], plan=reference)
                            gap_ids.extend(reader.gaps)
            if row["status"] != "proposal_generated":
                gap_ids.append(f"remediation_planning:{finding['claim_id']}:{row['status']}")
            rows.append(row)
            unit.job.events.write("REMEDIATION_PLANNING_CANDIDATE_COMPLETED", claim_id=finding["claim_id"],
                                  outcome=row["status"], gap_count=len(gap_ids),
                                  duration_ms=max(0, int((time.monotonic() - started) * 1000)),
                                  output_bytes=sum(path.stat().st_size for path in (unit.unit_root / str(index)).rglob("*")
                                                   if path.is_file()))
        return {"artifact": write_json(unit, "outcomes.json", {"items": rows}), "gaps": [],
                "terminal_status": "SUCCEEDED"}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        configured = settings(unit)
        document = loaded(unit)
        review = document["review"]
        fresh = load_review(unit.job.run_root, repo(unit), configured.bounds)
        if fresh["inputs"]["review_handoff"] != review["inputs"]["review_handoff"]:
            raise IntegrityError("accepted review changed while remediation was planned")
        for reference in review["bindings"]:
            resolve_bound(unit.job.run_root, reference)
        rows = read_bound_json(unit.job.run_root, unit.output("assess.propose")["artifact"])["items"]
        if [row["finding"] for row in rows] != [binding(item) for item in document["candidates"]]:
            raise IntegrityError("planning outcomes do not exactly account for confirmed intake")
        schemas = SchemaSet(repo(unit) / SCHEMA_ROOT)
        for row in rows:
            if row["plan"] is not None:
                verify_plan(unit.job.run_root, row["plan"], review_handoff=review["inputs"]["review_handoff"],
                            finding=row["finding"], schemas=schemas)
        gaps = sorted({gap for row in rows for gap in row["gap_ids"]})
        summary = {"schema": REMEDIATION_PLANNING_SCHEMA, "run_id": review["run_id"],
                   "upstream": {"review_handoff": review["inputs"]["review_handoff"], "poc_handoff": None},
                   "items": rows, "gaps": gaps}
        schemas.validate("planning", summary)
        reference = write_json(unit, "remediation-planning.json", summary)
        unit.job.events.write("REMEDIATION_PLANNING_PUBLISHED", item_count=len(rows), gap_count=len(gaps),
                              outcome_counts={status: sum(row["status"] == status for row in rows) for status in STATUSES},
                              output_bytes=(unit.job.run_root / reference["path"]).stat().st_size)
        return {"schema": REMEDIATION_PLANNING_HANDOFF_SCHEMA,
                "artifact": reference, "item_count": len(rows),
                "gaps": gaps, "terminal_status": "COMPLETED_WITH_GAPS" if gaps else
                ("SUCCEEDED" if rows else "SKIPPED_NA")}

    units = (Unit("load.verify_inputs", load), Unit("assess.propose", assess, ("load.verify_inputs",)),
             Unit("acceptance.publish_handoff", publish, ("load.verify_inputs", "assess.propose")))
    return Job(JOB_ID, "remediation_planning", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=REMEDIATION_PLANNING_HANDOFF_SCHEMA, units=units, datasets=DATASETS, consumes=CONSUMES)
