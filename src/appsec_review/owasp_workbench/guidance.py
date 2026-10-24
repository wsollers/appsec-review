from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from appsec_review.guidance import compose as shared
from appsec_review.guidance.fragments import load_tool_names, validate_procedure_text
from appsec_review.guidance.skills import load_runtime_skill


ROLES = {
    "component_classifier", "applicability_router", "control_assessor",
    "evidence_verifier", "independent_reviewer", "result_adjudicator",
}
PERSONAS = {
    "authentication_session", "authorization_access_control", "cryptography_data_protection",
    "api_web", "mobile_platform", "build_supply_chain", "deployment_operations",
}
PROCEDURES = {
    "applicability_router": "effective-control-verification",
    "control_assessor": "effective-control-verification",
    "evidence_verifier": "predicate-verification",
    "independent_reviewer": "predicate-verification",
    "result_adjudicator": "conflict-resolution",
}
KNOWLEDGE_SECTIONS = ("Viewpoint", "Effective controls", "False positives", "Evidence by predicate", "Hand-offs")


def load_registry(repository_root: Path) -> dict[str, Any]:
    # The shared loader validates the whole registry, including closed inference records. This
    # workbench owns and requires its bounded subset; other jobs' roles and personas do not widen
    # this workbench's allowlists.
    registry = shared.load_registry(repository_root)
    if not ROLES <= set(registry.get("roles", {})) or not PERSONAS <= set(registry.get("personas", {})):
        raise ValueError("role/persona registry is incomplete")
    for name in sorted(ROLES):
        value = registry["roles"][name]
        if set(value) != {"responsibility"} or not str(value["responsibility"]).strip():
            raise ValueError(f"role {name} repeats or widens shared authority")
    for name in sorted(PERSONAS):
        if not str(registry["personas"][name].get("viewpoint", "")).strip():
            raise ValueError(f"persona {name} repeats or widens shared authority")
    if set(registry.get("assignment", {})) != {"domain_persona"}:
        raise ValueError("guidance assignment policy is not deterministic")
    mapping = registry["assignment"]["domain_persona"]
    if any(value not in PERSONAS for value in mapping.values()):
        raise ValueError("guidance assignment refers to an unknown persona")
    return registry


def assign(registry: Mapping[str, Any], *, role: str, domain: str | None) -> dict[str, str | None]:
    if role not in ROLES:
        raise ValueError(f"unknown worker role: {role}")
    persona = registry["assignment"]["domain_persona"].get(domain) if domain else None
    if persona is not None and persona not in PERSONAS:
        raise ValueError("assignment selected an unknown persona")
    return {"role": role, "persona": persona}


def compose(repository_root: Path, *, role: str, persona: str | None,
            task: Mapping[str, Any]) -> dict[str, Any]:
    registry = load_registry(repository_root)
    if role not in ROLES or (persona is not None and persona not in PERSONAS):
        raise ValueError("guidance composition uses an unknown role or persona")
    allowed_task = {"task_id", "question", "proof_obligations", "prohibited_claims"}
    if set(task) != allowed_task or not str(task["question"]).strip():
        raise ValueError("task prompt must contain only the bounded question contract")
    governing = shared.governing_rules(repository_root)
    role_text = str(registry["roles"][role]["responsibility"])
    specialist = None
    if persona is not None:
        source_id = registry["persona_migrations"].get(persona, persona)
        fragment = shared.load_fragment(repository_root, registry, kind="persona", fragment_id=source_id)
        specialist = {
            "id": persona, "source_id": source_id, "source_sha256": fragment.sha256,
            "path": registry["personas"][source_id]["path"],
            "text": "\n\n".join(f"## {heading}\n{fragment.sections[heading]}" for heading in KNOWLEDGE_SECTIONS),
        }
    procedures = []
    if role in PROCEDURES:
        procedure = load_runtime_skill(repository_root, PROCEDURES[role], job_id="job_owasp_control_assessment",
                                       fallback_to_package=False)
        validate_procedure_text(f"procedure {procedure.name}", procedure.body, load_tool_names(repository_root))
        procedures.append({"id": procedure.name, "path": procedure.path, "text": procedure.text,
                           "source_sha256": procedure.sha256})
    bundle = {
        "schema": "appsec-review/guidance-bundle/1",
        "registry_version": registry["version"],
        "governing_rules": governing,
        "role": {"id": role, "text": role_text},
        "persona": specialist,
        "procedures": procedures,
        "task": dict(task),
    }
    bundle["sha256"] = shared.bundle_sha256(bundle)
    return bundle


def pin_bundle(run_root: Path, bundle: Mapping[str, Any]) -> dict[str, str]:
    return shared.pin_bundle(run_root, bundle,
                             files={"governing-rules.md": str(bundle.get("governing_rules", ""))})
