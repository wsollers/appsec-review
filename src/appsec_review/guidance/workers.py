"""Job-selected contracts for specialized workers; transports never choose guidance."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Mapping

from appsec_review.application_paths import application_root
from .compose import (
    _read, compose_selected_bundle, load_registry, pin_bundle, render_prompt, text_sha256,
)
from .fragments import (
    GuidanceError, TASK_FRONT_MATTER_KEYS, load_tool_names, split_front_matter, tool_mentions,
    validate_fragment_text, validate_procedure_text,
)
from .skills import load_runtime_skill


@dataclass(frozen=True)
class Worker:
    job: str
    role: str
    task: str
    response: str
    citation: str
    persona: str | None = None
    skill: str | None = None


SPECIALIZED_WORKERS = {
    "build_planning": Worker("job_target_analysis_plan", "build_engineer_{family}",
        "target_analysis_planning", "appsec-review/target-analysis-proposal/3", "inventory_path_sha256",
        "devops_engineer", "target-analysis-planning"),
    "build_repair": Worker("job_project_build", "build_engineer_{family}", "build_image_repair",
        "appsec-review/build-image-repair/3", "supplied_build_context", "devops_engineer", "build-image-repair"),
    "post_build": Worker("job_post_build_security_assessment", "build_security_assessor",
        "post_build_security_assessment", "appsec-review/build-security-inference-proposal/1",
        "build_evidence_id", "build_supply_chain", "post-build-security-assessment"),
    "dependency_repository": Worker("job_dependency_intelligence", "native_dependency_resolver",
        "native_repository_resolution", "appsec-review/native-dependency-resolution-proposal/1",
        "allowed_evidence_ref", "dependency_repository_investigator", "native-dependency-resolution"),
    "native_curation": Worker("job_dependency_intelligence", "native_sbom_investigator",
        "native_component_curation", "appsec-review/native-component-curation/1", "candidate_path",
        "native_dependency_analyst", "native-sbom-investigation"),
    "native_plan": Worker("job_dependency_intelligence", "native_sbom_investigator",
        "native_metadata_investigation", "appsec-review/native-metadata-plan/1", "candidate_path",
        "native_dependency_analyst", "native-sbom-investigation"),
    "native_metadata": Worker("job_dependency_intelligence", "native_sbom_investigator",
        "native_metadata_investigation", "appsec-review/native-metadata-proposal/1", "native_source_ref",
        "native_dependency_analyst", "native-sbom-investigation"),
    "poc_writer": Worker("job_poc_generation", "poc_writer", "write_poc_function",
        "appsec-review/poc-writer-answer/1", "poc_source_location", skill="poc-writer"),
    "remediation_writer": Worker("job_remediation_planning", "remediation_writer", "remediation_proposal",
        "appsec-review/worker-turn/1", "relation_id"),
    "remediation_reviewer": Worker("job_remediation_validation", "remediation_reviewer",
        "remediation_assessment", "appsec-review/worker-turn/1", "relation_id"),
}
BUILD_FAMILIES = ("native", "rust", "go", "java", "node", "dotnet", "python", "php", "wasm")
REVIEW_DISPATCHED = frozenset({
    "hypothesis_hunter", "red_team_analyst", "blue_team_refuter", "independent_verifier",
    "adjudication_judge", "attack_chain_analyst", "lead_triager",
})
WORKBENCH_DISPATCHED = frozenset({"control_assessor", "independent_reviewer"})
DETERMINISTIC_ROLES = frozenset({
    "independent_scorer", "finding_adjudicator", "component_classifier", "applicability_router",
    "evidence_verifier", "result_adjudicator", "completeness_reviewer",
})
NON_DISPATCHED_ROLES = frozenset({"poc_designer", "poc_verifier"})


def worker_root(repository_root: Path) -> Path:
    root = Path(repository_root)
    if not (root / "pipeline" / "guidance" / "registry.json").is_file():
        root = application_root("pipeline/guidance/registry.json")
    return root


def _validate_selected(text: str, *, owner: str, tools: frozenset[str],
                       allowed_tools: tuple[str, ...] = ()) -> None:
    # Specialized task documents include their closed response fields and existing limits.
    # They are not knowledge-only review procedures, but cannot replace the shared rules.
    if re.search(r"(?i)\b(?:ignore|override|replace)\s+(?:the\s+)?(?:governing|shared)\b"
                 r"|\byou\s+(?:may|can)\s+(?:execute|browse|widen|ignore|override|use any)\b"
                 r"|(?m:^\s*(?:granted_tools|readable_roots|permissions|authority|tools|model|provider|"
                 r"reasoning|max_queries|max_turns|timeout_seconds)\s*[:=])", text):
        raise GuidanceError(f"{owner} widens shared authority")
    unlisted = set(tool_mentions(text, tools)) - set(allowed_tools)
    if unlisted:
        raise GuidanceError(f"{owner} names unlisted retrieval operations: {sorted(unlisted)}")


def worker_bundle(repository_root: Path, worker_id: str, *, family: str | None = None,
                  model: Mapping[str, Any] | None = None,
                  texts: Mapping[str, str] | None = None, build_system: str | None = None) -> dict[str, Any]:
    """Assemble one real worker, including rich non-registry persona files and selected skills.

    ``texts`` preserves the existing build-publication interface for already loaded fragments.
    It is application-owned, not an input accepted from a worker or target.
    """
    if worker_id not in SPECIALIZED_WORKERS:
        raise GuidanceError(f"unknown specialized worker: {worker_id}")
    worker = SPECIALIZED_WORKERS[worker_id]
    if ("{family}" in worker.role) != (family is not None) or (
            family is not None and family not in BUILD_FAMILIES):
        raise GuidanceError("worker build family is not selected or supported")
    root = worker_root(repository_root)
    registry = load_registry(root)
    role = worker.role.format(family=family)
    tools = load_tool_names(root)
    supplied = dict(texts or {})
    if set(supplied) - {"role", "persona", "procedure"}:
        raise GuidanceError("unknown selected worker text section")
    role_record = registry["roles"][role]
    role_file = f"build-engineer-{family}" if family else role
    role_path = f"pipeline/prompt-fragments/roles/{role_file}.md"
    role_text = supplied.get("role")
    if role_text is None:
        role_text = (role_record["responsibility"] if worker_id == "post_build" else
                     _read(root, role_path, role))
    _validate_selected(role_text, owner=role, tools=tools)
    if worker_id.startswith("native_") or worker_id.startswith("remediation_"):
        validate_procedure_text(role, role_text, tools)
    sections = [{"name": "role", "id": role, "text": role_text,
                 "record": role_record, "source_sha256": text_sha256(role_text)}]
    if worker.persona:
        persona_path = ("pipeline/prompt-fragments/personas/devops-engineer.md" if family else
                        f"pipeline/prompt-fragments/personas/{worker.persona}.md")
        persona_text = supplied.get("persona")
        if persona_text is None:
            persona_text = _read(root, persona_path, worker.persona)
        _validate_selected(persona_text, owner=worker.persona, tools=tools)
        if worker_id.startswith("native_"):
            validate_fragment_text(worker.persona, persona_text, tools)
        sections.append({"name": "persona", "id": worker.persona, "text": persona_text,
                         "source_sha256": text_sha256(persona_text)})
    task_record = registry["tasks"].get("dependency-intelligence", {}).get(worker.task)
    if worker.job == "job_dependency_intelligence" and task_record is None:
        raise GuidanceError(f"dependency task is not registered: {worker.task}")
    task_text = (_read(root, task_record["path"], worker.task) if task_record else
                 f"Answer {worker.task} using the supplied structured task and its closed response contract.")
    _validate_selected(task_text, owner=worker.task, tools=tools)
    if task_text.startswith("---\n"):
        record, _ = split_front_matter(task_text, TASK_FRONT_MATTER_KEYS)
        if record["id"] != worker.task or record["roles"] != (role,) or record["requests_tools"]:
            raise GuidanceError("selected specialized task changes its role or tool contract")
    sections.append({"name": "task", "id": worker.task, "text": task_text,
                     "response_schema": worker.response, "citation_contract": worker.citation,
                     "source_sha256": text_sha256(task_text)})
    if worker.skill:
        procedure = load_runtime_skill(root, worker.skill, job_id=worker.job, fallback_to_package=False)
        if "procedure" in supplied and supplied["procedure"] != procedure.text:
            raise GuidanceError("selected procedure differs from its registered runtime skill")
        _validate_selected(procedure.body, owner=procedure.name, tools=tools)
        if worker_id.startswith("native_"):
            validate_procedure_text(worker.task, task_text, tools)
            validate_procedure_text(worker.skill, procedure.body, tools)
        sections.append({"name": "procedures", "items": [{
            "id": procedure.name, "path": procedure.path, "text": procedure.text,
            "source_sha256": procedure.sha256}]})
    model_identity = {key: str(model[key]) for key in ("provider", "model", "reasoning")} if model else {}
    if build_system is not None:
        if family is None or not re.fullmatch(r"[a-z0-9_-]+", build_system):
            raise GuidanceError("invalid selected build-system identity")
        model_identity["build_system"] = build_system
    return compose_selected_bundle(root, job=worker.job, role=role, sections=sections,
                                   identity={"worker": worker_id, **model_identity})


def publish_worker_guidance(repository_root: Path, run_root: Path, worker_id: str, *,
                            family: str | None = None, model: Mapping[str, Any] | None = None,
                            texts: Mapping[str, str] | None = None,
                            build_system: str | None = None) -> tuple[str, str]:
    bundle = worker_bundle(repository_root, worker_id, family=family, model=model, texts=texts,
                           build_system=build_system)
    pinned = pin_bundle(run_root, bundle)
    return render_prompt(bundle), pinned["bundle_sha256"]
