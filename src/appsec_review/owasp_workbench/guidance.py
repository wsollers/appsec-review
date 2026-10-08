from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from appsec_review.storage import atomic_bytes, atomic_json, canonical_json


ROLES = {
    "component_classifier", "applicability_router", "control_assessor",
    "evidence_verifier", "independent_reviewer", "result_adjudicator",
}
PERSONAS = {
    "authentication_session", "authorization_access_control", "cryptography_data_protection",
    "api_web", "mobile_platform", "build_supply_chain", "deployment_operations",
}


def load_registry(repository_root: Path) -> dict[str, Any]:
    path = Path(repository_root) / "pipeline" / "guidance" / "registry.json"
    registry = json.loads(path.read_text(encoding="utf-8"))
    if registry.get("schema") != "appsec-review/guidance-registry/1":
        raise ValueError("unsupported guidance registry")
    if set(registry.get("roles", {})) != ROLES or set(registry.get("personas", {})) != PERSONAS:
        raise ValueError("role/persona registry is incomplete")
    for name, value in registry["roles"].items():
        if set(value) != {"responsibility"} or not str(value["responsibility"]).strip():
            raise ValueError(f"role {name} repeats or widens shared authority")
    for name, value in registry["personas"].items():
        if set(value) != {"viewpoint"} or not str(value["viewpoint"]).strip():
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
    governing_path = Path(repository_root) / "pipeline" / "prompt-fragments" / "governing-rules.md"
    governing = governing_path.read_text(encoding="utf-8")
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
    bundle["sha256"] = hashlib.sha256(canonical_json(bundle)).hexdigest()
    return bundle


def pin_bundle(run_root: Path, bundle: Mapping[str, Any]) -> dict[str, str]:
    identity = str(bundle.get("sha256", ""))
    if len(identity) != 64:
        raise ValueError("guidance bundle identity is invalid")
    root = Path(run_root) / "data" / "guidance" / identity
    atomic_json(root / "bundle.json", dict(bundle))
    atomic_bytes(root / "governing-rules.md", str(bundle["governing_rules"]).encode("utf-8"))
    return {"bundle_sha256": identity,
            "path": (Path("data") / "guidance" / identity / "bundle.json").as_posix()}
