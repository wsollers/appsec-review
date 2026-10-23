"""Bounded model assistance for unresolved native repository identities only."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
import hashlib
from pathlib import Path
from typing import Any

from appsec_review.guidance.compose import load_registry
from appsec_review.guidance.skills import load_runtime_skill
from appsec_review.inference import Infer, ModelRequest
from appsec_review.storage import atomic_bytes, canonical_json
from appsec_review.storage.shared import publish_named

from .resolution import apply_model_resolution


PROPOSAL_SCHEMA = "appsec-review/native-dependency-resolution-proposal/1"
PERSONA_ID = "dependency_repository_investigator"
ROLE_ID = "native_dependency_resolver"
TASK_ID = "native_repository_resolution"
RUNTIME_SKILL_ID = "native-dependency-resolution"


def _guidance(repository_root: Path, run_root: Path, model: Mapping[str, Any]) -> tuple[str, str]:
    registry = load_registry(repository_root)
    persona_record = registry["personas"].get(PERSONA_ID)
    role_record = registry["roles"].get(ROLE_ID)
    task_record = registry["tasks"].get("dependency-intelligence", {}).get(TASK_ID)
    if (not isinstance(persona_record, Mapping) or not isinstance(role_record, Mapping) or
            not isinstance(task_record, Mapping)):
        raise ValueError("dependency resolution guidance is not registered")
    paths = {
        "persona.md": repository_root / "pipeline/prompt-fragments/personas/dependency_repository_investigator.md",
        "role.md": repository_root / "pipeline/prompt-fragments/roles/native_dependency_resolver.md",
        "task.md": repository_root / str(task_record["path"]),
    }
    skill = load_runtime_skill(repository_root, RUNTIME_SKILL_ID, job_id="job_dependency_intelligence")
    files = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
    files["skill.md"] = skill.text
    identity = {"provider": model["provider"], "model": model["model"], "reasoning": model["reasoning"],
                "persona": PERSONA_ID, "role": ROLE_ID, "task": TASK_ID,
                "runtime_skill_sha256": skill.sha256}
    content = b"\0".join([*(files[name].encode() for name in sorted(files)), canonical_json(identity)])
    digest = hashlib.sha256(content).hexdigest()
    destination = run_root / "data" / "guidance" / digest
    for name, text in sorted(files.items()):
        path = destination / name
        payload = text.encode()
        if path.is_file() and path.read_bytes() != payload:
            raise ValueError("dependency inference guidance changed after pinning")
        publish_named(run_root, path, payload, namespace="guidance", computation=identity)
    metadata = canonical_json({**identity, "guidance_sha256": digest})
    metadata_path = destination / "model-identity.json"
    if metadata_path.is_file() and metadata_path.read_bytes() != metadata:
        raise ValueError("dependency inference model identity changed after pinning")
    publish_named(run_root, metadata_path, metadata, namespace="guidance", computation=identity)
    joined = "\n\n".join((files["persona.md"], files["role.md"], files["task.md"], files["skill.md"]))
    return joined, digest


def resolve_with_inference(dependency: Mapping[str, Any], *, repository_root: Path, run_root: Path,
                           model: Mapping[str, Any], supported_hosts: tuple[str, ...], infer: Infer | None,
                           max_candidate_bytes: int) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Resolve one native candidate or return a dependency-scoped gap record."""
    dependency_id = str(dependency["dependency_id"])
    if dependency.get("repository") is not None or "native_candidate" not in dependency:
        return dict(dependency), None
    if not bool(model.get("enabled")):
        return dict(dependency), {"dependency_id": dependency_id, "kind": "model_unavailable",
                                  "detail": "native repository inference is disabled"}
    if infer is None:
        return dict(dependency), {"dependency_id": dependency_id, "kind": "model_unavailable",
                                  "detail": "native repository inference transport is unavailable"}
    candidate = dependency["native_candidate"]
    payload = canonical_json(candidate)
    if len(payload) > max_candidate_bytes:
        return dict(dependency), {"dependency_id": dependency_id, "kind": "bounds",
                                  "detail": "native candidate exceeds the inference input byte bound"}
    guidance, guidance_sha = _guidance(repository_root, run_root, model)
    evidence = [str(item.get("evidence_id")) for item in dependency.get("observations", ())]
    evidence.extend(str(item.get("command_id") or item.get("artifact_sha256"))
                    for item in candidate.get("observations", ()) if isinstance(item, Mapping))
    summary = {"candidate": candidate, "allowed_evidence_refs": sorted(set(evidence)),
               "supported_repository_hosts": list(supported_hosts),
               "guidance_bundle_sha256": guidance_sha}
    request = ModelRequest(
        schema=PROPOSAL_SCHEMA, persona=PERSONA_ID, role=ROLE_ID, guidance=guidance,
        summary=summary, allowed_scanners=(), allowed_build_systems=(), allowed_components=(),
        allowed_paths=(), allowed_build_units=(), provider=str(model["provider"]), model=str(model["model"]),
        reasoning=str(model["reasoning"]), max_input_tokens=int(model["max_input_tokens"]),
        max_output_tokens=int(model["max_output_tokens"]),
    )
    if len(canonical_json(summary)) + len(guidance.encode()) > request.max_input_tokens * 4:
        return dict(dependency), {"dependency_id": dependency_id, "kind": "bounds",
                                  "detail": "native inference request exceeds its token-derived byte bound"}
    errors: list[str] = []
    for attempt in range(int(model["retries"]) + 1):
        try:
            result = infer(request, timeout_seconds=int(model["timeout_seconds"]))
            proposal = result.proposal
            if (proposal.get("schema") == PROPOSAL_SCHEMA and
                    proposal.get("candidate_id") == candidate.get("candidate_id") and
                    proposal.get("repository") is None and proposal.get("confidence") == 0):
                return dict(dependency), None
            resolved = apply_model_resolution(dependency, proposal, supported_hosts=supported_hosts)
            return resolved, None
        except Exception as exc:
            errors = [f"{type(exc).__name__}: {exc}"[:2048]]
            if attempt < int(model["retries"]):
                request = replace(request, repair_errors=tuple(errors), prior_response=None)
    return dict(dependency), {"dependency_id": dependency_id, "kind": "model_failure",
                              "detail": errors[0] if errors else "native repository inference failed"}


__all__ = ["PERSONA_ID", "PROPOSAL_SCHEMA", "ROLE_ID", "RUNTIME_SKILL_ID", "TASK_ID",
           "resolve_with_inference"]
