"""Opt-in specialized-worker experiments at the production request and validation boundaries.

These adapters do not run jobs, builds, patches or reviews. Synthetic producer artifacts are
inputs; only the external model boundary may be scripted. Results establish protocol behavior,
not model efficacy or a verified correction.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Mapping

from appsec_review.config import PlanningFeedbackSettings
from appsec_review.config.remediation import RemediationPlanningSettings
from appsec_review.guidance import pin_bundle, render_prompt
from appsec_review.guidance.workers import worker_bundle
from appsec_review.inference import Infer, ModelRequest, ModelResult, ReviewModelRequest, infer
from appsec_review.inference.request import plan_prompt, review_prompt
from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds
from appsec_review.jobs.job_remediation_planning.contracts import PlanAnswer, verify_patch_scope
from appsec_review.jobs.job_remediation_planning.inputs import (
    SourceReader, confirmed_findings, evidence_relations, writer_task,
)
from appsec_review.jobs.job_remediation_planning.model import run_model
from appsec_review.jobs.job_remediation_planning.patches import PatchError
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA, bounded_feedback, feedback_request
from appsec_review.retrieval import RetrievalCore
from appsec_review.review.competence import LIMITATION
from appsec_review.review.evaluation import procedure_variant
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import IntegrityError
from appsec_review.storage import atomic_json
from appsec_review.storage.shared import safe_path


@dataclass(frozen=True)
class WorkerCompetenceResult:
    result: Mapping[str, Any] | None
    receipt: Mapping[str, Any]
    requests: tuple[ModelRequest | ReviewModelRequest, ...]


class _Capture:
    def __init__(self, output: Path, transport: Infer | None, live: bool) -> None:
        if transport is None and not live:
            raise ValueError("live inference requires explicit live=True")
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=False)
        self.send = transport or infer
        self.live = live
        self.requests: list[ModelRequest | ReviewModelRequest] = []

    def __call__(self, request: ModelRequest | ReviewModelRequest, *, timeout_seconds: int) -> ModelResult:
        self.requests.append(request)
        number = len(self.requests)
        prompt = (plan_prompt(request) if isinstance(request, ModelRequest)
                  else review_prompt(request, include_guidance=True))
        atomic_json(self.output / f"turn-{number}-request.json", asdict(request))
        atomic_json(self.output / f"turn-{number}-prompt.json", prompt)
        answer = self.send(request, timeout_seconds=timeout_seconds)
        atomic_json(self.output / f"turn-{number}-answer.json", asdict(answer))
        return answer

    def finish(self, result: Mapping[str, Any] | None, receipt: Mapping[str, Any]) -> WorkerCompetenceResult:
        record = {"schema": "appsec-review/worker-competence/1",
                  "execution": "live" if self.live else "scripted", "limitation": LIMITATION,
                  "result": result, "receipt": dict(receipt)}
        atomic_json(self.output / "result.json", record)
        return WorkerCompetenceResult(result, record["receipt"], tuple(self.requests))


def run_planning_case(
    root: Path, request: ModelRequest, *, catalog: Mapping[str, Any], source_root: Path,
    family: str, limits: PlanningFeedbackSettings, call_timeout_seconds: int, output: Path,
    transport: Infer | None = None, live: bool = False, variant: str = "full",
) -> WorkerCompetenceResult:
    """Exercise the actual exact-inventory evidence/repair loop and final recipe admission.

    The caller supplies an inert catalog and the same bounded ModelRequest used by the planner.
    Guidance, rendering, additive inventory, file reads and admission are production functions.
    No evidence or recipe is accepted merely because it appears in an experiment answer key.
    """
    if request.schema != PROPOSAL_SCHEMA or len(request.allowed_build_systems) != 1:
        raise ValueError("planning competence requires one production proposal/3 build-system group")
    capture = _Capture(output, transport, live)
    bundle = worker_bundle(root, "build_planning", family=family,
                           model=asdict(request), build_system=request.allowed_build_systems[0])
    bundle = procedure_variant(bundle, variant)
    pin_bundle(capture.output, bundle)
    sections = {section["name"]: section for section in bundle["sections"]}
    request = replace(
        request, role=sections["role"]["text"], persona=sections["persona"]["text"],
        guidance=render_prompt(bundle),
        summary={**request.summary, "feedback_limits": asdict(limits),
                 "guidance_bundle_sha256": bundle["sha256"]})
    request = feedback_request(request, catalog, limits)
    identity = {"source_fingerprint": catalog["source_fingerprint"],
                "catalog_handoff_sha256": catalog["catalog_handoff_sha256"],
                "request_sha256": sha256_hex(asdict(request)), "variant": variant}
    atomic_json(capture.output / "inputs.json", {
        "catalog": dict(catalog), "limits": asdict(limits), "identity": identity,
        "call_timeout_seconds": call_timeout_seconds})

    def read_document(item: Mapping[str, Any], bound: int) -> bytes:
        with safe_path(source_root, item["path"]).open("rb") as stream:
            return stream.read(bound + 1)

    result = bounded_feedback(
        capture, request, catalog=catalog, limits=limits, read_document=read_document,
        cache_root=capture.output / "data" / "planning-feedback", identity=identity,
        guidance_sha256=bundle["sha256"], call_timeout_seconds=call_timeout_seconds)
    return capture.finish(result["proposal"], {
        **{key: value for key, value in result.items() if key != "proposal"},
        "worker": "build_planning", "guidance_sha256": bundle["sha256"],
        "variant": variant, "identity": identity,
    })


def run_remediation_case(
    root: Path, *, review: Mapping[str, Any], finding_id: str, core: RetrievalCore,
    settings: RemediationPlanningSettings, output: Path,
    transport: Infer | None = None, live: bool = False, variant: str = "full",
) -> WorkerCompetenceResult:
    """Exercise confirmed-only intake, real source/build resolution and exact patch validation.

    ``review`` is an already admitted review document, just as at the production assess boundary.
    Its projection reference and the run's accepted native-build receipts are read normally.
    This adapter neither fabricates upstream review state nor applies or executes a patch.
    """
    if not settings.enabled:
        raise ValueError("remediation planning is disabled")
    if review.get("run_id") != core.run_root.name:
        raise IntegrityError("competence review belongs to a different run")
    candidates = confirmed_findings(review)
    findings = {item["finding_package_id"]: item for item in candidates}
    if finding_id not in findings:
        raise ValueError("competence finding is not in the accepted confirmed partition")
    if finding_id not in {item["finding_package_id"] for item in candidates[:settings.bounds.max_candidates]}:
        raise ValueError("competence finding exceeds the configured candidate bound")
    capture = _Capture(output, transport, live)
    finding = findings[finding_id]
    relations = evidence_relations(core.run_root, review, finding)
    if not relations:
        return capture.finish(None, {"worker": "remediation_writer", "status": "insufficient_evidence",
                                     "reason": "confirmed_finding_has_no_resolving_evidence"})
    builds = AcceptedBuilds(core.run_root)
    reader = SourceReader(builds, core, relations, settings.bounds)
    reader.resolve()
    task = writer_task(finding, relations, reader)
    bundle = procedure_variant(worker_bundle(root, "remediation_writer"), variant)
    pin_bundle(core.run_root, bundle)
    atomic_json(capture.output / "inputs.json", {
        "settings": asdict(settings), "task": task, "manifest_sha256": core.manifest_sha256})
    evidence_ids = {item["relation_id"] for item in relations}
    answer, receipt = run_model(
        infer=capture, profile=settings.writer, role="remediation_writer",
        cell_id=f"remediation-writer:{finding['claim_id']}", guidance_text=render_prompt(bundle),
        guidance_sha256=bundle["sha256"], task=task, retrieve=reader.retrieve,
        validate=lambda value: PlanAnswer.from_mapping(
            value, settings.bounds, evidence_ids=evidence_ids).document)
    status = "insufficient_evidence" if answer is None else answer["status"]
    if answer is not None:
        parsed = PlanAnswer.from_mapping(answer, settings.bounds, evidence_ids=evidence_ids)
        try:
            if parsed.patch is not None:
                verify_patch_scope(parsed.patch, reader.files, builds, settings.bounds)
        except PatchError as exc:
            status = "invalid_patch"
            receipt = {**receipt, "patch_error": str(exc)}
            answer = None
    return capture.finish(answer, {
        "worker": "remediation_writer", "status": status, "model_receipt": receipt,
        "guidance_sha256": bundle["sha256"], "variant": variant,
        "source_gaps": reader.gaps, "manifest_sha256": core.manifest_sha256,
    })
