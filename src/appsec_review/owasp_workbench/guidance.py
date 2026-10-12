from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from appsec_review.guidance import compose as shared


ROLES = {
    "component_classifier", "applicability_router", "control_assessor",
    "evidence_verifier", "independent_reviewer", "result_adjudicator",
}
PERSONAS = {
    "authentication_session", "authorization_access_control", "cryptography_data_protection",
    "api_web", "mobile_platform", "build_supply_chain", "deployment_operations",
}


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
    persona_text = None if persona is None else str(registry["personas"][persona]["viewpoint"])
    bundle = {
        "schema": "appsec-review/guidance-bundle/1",
        "registry_version": registry["version"],
        "governing_rules": governing,
        "role": {"id": role, "text": role_text},
        "persona": None if persona is None else {"id": persona, "text": persona_text},
        "task": dict(task),
    }
    bundle["sha256"] = shared.bundle_sha256(bundle)
    return bundle


def pin_bundle(run_root: Path, bundle: Mapping[str, Any]) -> dict[str, str]:
    return shared.pin_bundle(run_root, bundle,
                             files={"governing-rules.md": str(bundle.get("governing_rules", ""))})
