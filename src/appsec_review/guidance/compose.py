"""Shared guidance registry, hash-pinned bundle assembly, and run pinning.

Assembly order (design "Guidance assembly"): governing rules, one role record, one persona record
(role-selected sections plus generated coverage), one stack profile, one task prompt, and a
generated capability/budget receipt carried as structured metadata. Every section is hash-pinned
and the canonical bundle hash names its run directory. Conflicts fail assembly; ordering never
resolves authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from appsec_review.jobs.job_security_tagging.crosswalk import Crosswalk
from appsec_review.jobs.job_security_tagging.taxonomy import Vocabulary
from appsec_review.review.models import ClaimState, IntegrityError, RelationKind, Role
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json

from .coverage import expand_coverage
from .fragments import (
    Fragment, GuidanceError, TaskPrompt, load_tool_names, parse_fragment, parse_role_text, parse_task,
    policy_keys, text_sha256,
)
from .routing import GENERALIST, STACK_IDS


REGISTRY_SCHEMA = "appsec-review/guidance-registry/1"
BUNDLE_SCHEMA = "appsec-review/guidance-bundle/2"
REGISTRY_PATH = Path("pipeline") / "guidance" / "registry.json"
GOVERNING_PATH = Path("pipeline") / "prompt-fragments" / "governing-rules.md"
REVIEW_JOB = "inference-security-review"
SECTION_ORDER = ("governing_rules", "role", "persona", "stack", "task", "receipt")
LENSES = ("generative", "skeptical")
PERSONA_VIEWS = {
    "generative": ("Viewpoint", "Coverage", "Likely failure modes", "Evidence by predicate"),
    "skeptical": ("Viewpoint", "Effective controls", "False positives", "Evidence by predicate"),
}
LEGACY_ROLE_KEYS = frozenset({"responsibility"})
INFERENCE_ROLE_KEYS = frozenset({"responsibility", "path", "lens", "output_schema", "outputs",
                                 "prohibited", "tools"})
ROLE_POLICY_KEYS = ("lens", "output_schema", "outputs", "prohibited", "tools")
ROLE_OUTPUTS = frozenset({*(state.value for state in ClaimState), *(kind.value for kind in RelationKind),
                          "score", "poc_plan", "poc_result", "attack_chain"})
PROHIBITED_DECISIONS = frozenset({
    "assign_severity", "set_claim_state", "accept_claim", "propose_claim", "refute_claim",
    "see_other_cell_output", "see_red_reasoning", "widen_scope", "request_unlisted_tool",
    "read_target_guidance", "execute_code", "change_configuration", "override_score",
})
REGISTRY_KEYS = frozenset({"schema", "version", "roles", "personas", "stacks", "tasks", "assignment",
                           "persona_migrations", "runtime_skills"})
TASK_INPUT_FORBIDDEN = frozenset({"readable_roots", "tools", "granted_tools", "authority", "role", "persona",
                                  "stack", "model", "model_profile", "budget", "permissions"})
_KEY = re.compile(r"^[a-z][a-z0-9_]*$")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GuidanceError(message)


def section_sha256(section: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json({k: v for k, v in section.items() if k != "sha256"})).hexdigest()


def bundle_sha256(bundle: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json({k: v for k, v in bundle.items() if k != "sha256"})).hexdigest()


# ---------------------------------------------------------------------------------------------
# Registry

def _fragment_path(value: object, *, owner: str, directory: str) -> str:
    _require(isinstance(value, str), f"{owner} path must be a string")
    path = PurePosixPath(str(value))
    _require(not path.is_absolute() and ".." not in path.parts and path.suffix == ".md"
             and path.parent.as_posix() == directory, f"{owner} path must be {directory}/<id>.md")
    _require(path.stem == owner.split(" ", 1)[1], f"{owner} file name must equal its id")
    return path.as_posix()


def validate_registry(registry: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the whole registry: legacy OWASP/build records and closed inference records."""
    _require(registry.get("schema") == REGISTRY_SCHEMA, "unsupported guidance registry")
    _require(set(registry) <= REGISTRY_KEYS, "guidance registry has unknown top-level keys")
    _require(isinstance(registry.get("version"), str) and bool(registry["version"]), "registry version is required")
    roles = registry.get("roles", {})
    for name, value in roles.items():
        _require(isinstance(value, Mapping) and str(value.get("responsibility", "")).strip() != "",
                 f"role {name} has no responsibility")
        keys = set(value)
        if keys == LEGACY_ROLE_KEYS:
            continue
        _require(keys == INFERENCE_ROLE_KEYS and name in {member.value for member in Role},
                 f"role {name} repeats or widens shared authority")
        _fragment_path(value["path"], owner=f"role {name}", directory="pipeline/prompt-fragments/roles")
        _require(value["lens"] in LENSES, f"role {name} lens is invalid")
        _require(isinstance(value["output_schema"], str) and bool(value["output_schema"]),
                 f"role {name} output_schema is required")
        for key, closed in (("outputs", ROLE_OUTPUTS), ("prohibited", PROHIBITED_DECISIONS)):
            items = value[key]
            _require(isinstance(items, list) and len(items) == len(set(items)) and set(items) <= closed,
                     f"role {name} {key} uses an unknown value")
        _require(isinstance(value["tools"], list) and len(value["tools"]) == len(set(value["tools"]))
                 and value["tools"] == sorted(value["tools"]), f"role {name} tools must be a sorted unique list")
    missing_roles = sorted(member.value for member in Role
                           if set(roles.get(member.value, {})) != INFERENCE_ROLE_KEYS)
    _require(not missing_roles, f"inference roles are missing or incomplete: {', '.join(missing_roles)}")
    personas = registry.get("personas", {})
    for name, value in personas.items():
        _require(isinstance(value, Mapping) and bool(value) and set(value) <= {"viewpoint", "path"},
                 f"persona {name} repeats or widens shared authority")
        if "viewpoint" in value:
            _require(str(value["viewpoint"]).strip() != "", f"persona {name} viewpoint is empty")
        if "path" in value:
            _fragment_path(value["path"], owner=f"persona {name}", directory="pipeline/prompt-fragments/personas")
    _require("path" in personas.get(GENERALIST, {}), "the generalist persona is required")
    stacks = registry.get("stacks", {})
    _require(set(stacks) == set(STACK_IDS), "stack registry must list exactly the stack-routing/1 profiles")
    for name, value in stacks.items():
        _require(isinstance(value, Mapping) and set(value) == {"path"}, f"stack {name} record is not closed")
        _fragment_path(value["path"], owner=f"stack {name}", directory="pipeline/prompt-fragments/stacks")
    for job, tasks in registry.get("tasks", {}).items():
        _require(isinstance(tasks, Mapping) and bool(tasks), f"task group {job} is empty")
        for name, value in tasks.items():
            _require(isinstance(value, Mapping) and set(value) == {"path"}, f"task {name} record is not closed")
            _fragment_path(value["path"], owner=f"task {name}", directory=f"pipeline/guidance/tasks/{job}")
    for old, new in registry.get("persona_migrations", {}).items():
        _require("viewpoint" in personas.get(old, {}), f"persona migration source is unknown: {old}")
        _require("path" in personas.get(new, {}), f"persona migration target is unknown: {new}")
    return dict(registry)


def load_registry(repository_root: Path) -> dict[str, Any]:
    path = Path(repository_root) / REGISTRY_PATH
    return validate_registry(json.loads(path.read_text(encoding="utf-8")))


def governing_rules(repository_root: Path) -> str:
    return (Path(repository_root) / GOVERNING_PATH).read_text(encoding="utf-8")


def _read(repository_root: Path, relative: str, owner: str) -> str:
    path = Path(repository_root) / relative
    _require(path.is_file(), f"{owner} file is unavailable: {relative}")
    return path.read_text(encoding="utf-8")


def load_fragment(repository_root: Path, registry: Mapping[str, Any], *, kind: str, fragment_id: str,
                  tools: frozenset[str] | None = None) -> Fragment:
    table = registry["personas"] if kind == "persona" else registry["stacks"] if kind == "stack" else None
    _require(table is not None, f"unknown fragment kind: {kind}")
    record = table.get(fragment_id)
    _require(record is not None and "path" in record, f"unknown {kind} id: {fragment_id}")
    tools = load_tool_names(repository_root) if tools is None else tools
    text = _read(repository_root, record["path"], f"{kind} {fragment_id}")
    return parse_fragment(text, kind=kind, tools=tools, expected_id=fragment_id)


def load_task(repository_root: Path, registry: Mapping[str, Any], *, task_id: str, job: str = REVIEW_JOB,
              tools: frozenset[str] | None = None) -> TaskPrompt:
    record = registry.get("tasks", {}).get(job, {}).get(task_id)
    _require(record is not None, f"unknown task id: {job}/{task_id}")
    tools = load_tool_names(repository_root) if tools is None else tools
    return parse_task(_read(repository_root, record["path"], f"task {task_id}"), tools=tools, expected_id=task_id)


def load_persona_covers(repository_root: Path, registry: Mapping[str, Any] | None = None) -> dict[str, tuple[str, ...]]:
    """Parse every inference persona file and return ``{persona_id: covers}`` for routing."""
    registry = load_registry(repository_root) if registry is None else registry
    tools = load_tool_names(repository_root)
    return {name: load_fragment(repository_root, registry, kind="persona", fragment_id=name, tools=tools).covers
            for name, value in sorted(registry["personas"].items()) if "path" in value}


# ---------------------------------------------------------------------------------------------
# Assembly

def _sealed(section: dict[str, Any]) -> dict[str, Any]:
    section["sha256"] = section_sha256(section)
    return section


def _json_value(value: Any, owner: str) -> Any:
    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError) as exc:
        raise GuidanceError(f"{owner} must be canonical JSON") from exc


def compose_bundle(repository_root: Path, *, role: str, persona: str, stack: str, task: str,
                   task_input: Mapping[str, Any], capability: Mapping[str, Any], vocabulary: Vocabulary,
                   crosswalk: Crosswalk, job: str = REVIEW_JOB) -> dict[str, Any]:
    """Assemble one hash-pinned inference guidance bundle, or fail before dispatch."""
    root = Path(repository_root)
    registry = load_registry(root)
    tools = load_tool_names(root)
    _require(role in {member.value for member in Role}, f"unknown inference role id: {role}")
    role_record = registry["roles"][role]
    _require(set(role_record["tools"]) <= tools, f"role {role} allowlist names a tool outside the catalog")
    role_text = _read(root, role_record["path"], f"role {role}")
    parse_role_text(role_text, role_id=role, tools=role_record["tools"])
    persona_fragment = load_fragment(root, registry, kind="persona", fragment_id=persona, tools=tools)
    stack_fragment = load_fragment(root, registry, kind="stack", fragment_id=stack, tools=tools)
    task_prompt = load_task(root, registry, task_id=task, job=job, tools=tools)

    _require(role in task_prompt.roles, f"task {task} is not assigned to role {role}")
    unlisted = sorted(set(task_prompt.requests_tools) - set(role_record["tools"]))
    _require(not unlisted, f"task {task} requests a tool absent from role {role}: {', '.join(unlisted)}")

    _require(isinstance(task_input, Mapping) and all(_KEY.fullmatch(str(key)) for key in task_input),
             "task input keys must be lower_snake_case")
    widened = sorted(set(task_input) & TASK_INPUT_FORBIDDEN)
    _require(not widened, f"task input attempts to widen capability or scope: {', '.join(widened)}")
    task_input = _json_value(dict(task_input), "task input")

    _require(isinstance(capability, Mapping) and all(_KEY.fullmatch(str(key)) for key in capability),
             "capability receipt keys must be lower_snake_case")
    granted = capability.get("granted_tools")
    _require(isinstance(granted, (list, tuple)), "capability receipt must list granted_tools")
    if not set(granted) <= set(role_record["tools"]):
        raise IntegrityError(f"capability grants tools outside role {role}: "
                             f"{', '.join(sorted(set(granted) - set(role_record['tools'])))}")
    capability = _json_value({**capability, "granted_tools": sorted(granted)}, "capability receipt")

    lens = role_record["lens"]
    coverage = expand_coverage(persona_fragment.covers, persona_fragment.standards, vocabulary, crosswalk)
    persona_sections = [{"heading": heading,
                         "text": coverage["text"] if heading == "Coverage" else persona_fragment.sections[heading]}
                        for heading in PERSONA_VIEWS[lens]]
    governing = governing_rules(root)

    defined: dict[str, list[str]] = {}
    for name, keys in (
        ("governing_rules", policy_keys(governing)),
        ("role", set(ROLE_POLICY_KEYS) | policy_keys(role_text)),
        ("persona", policy_keys("\n".join(persona_fragment.sections.values()))),
        ("stack", policy_keys("\n".join(stack_fragment.sections.values()))),
        ("task", {"roles", "requests_tools"} | policy_keys(task_prompt.text) | set(task_input)),
        ("receipt", set(capability)),
    ):
        for key in keys:
            defined.setdefault(key, []).append(name)
    duplicated = {key: names for key, names in sorted(defined.items()) if len(names) > 1}
    _require(not duplicated, "policy key is defined by more than one section: "
             + "; ".join(f"{key} in {', '.join(names)}" for key, names in duplicated.items()))

    sections = [
        _sealed({"name": "governing_rules", "id": "governing-rules", "text": governing}),
        _sealed({"name": "role", "id": role, "text": role_text,
                 "record": {key: role_record[key] for key in ROLE_POLICY_KEYS}}),
        _sealed({"name": "persona", "id": persona, "version": persona_fragment.version, "lens": lens,
                 "sections": persona_sections, "coverage_sha256": coverage["sha256"],
                 "source_sha256": persona_fragment.sha256}),
        _sealed({"name": "stack", "id": stack, "version": stack_fragment.version,
                 "sections": [{"heading": heading, "text": text} for heading, text in stack_fragment.sections.items()],
                 "source_sha256": stack_fragment.sha256}),
        _sealed({"name": "task", "id": task, "job": job, "version": task_prompt.version, "text": task_prompt.text,
                 "requests_tools": list(task_prompt.requests_tools), "input": task_input,
                 "source_sha256": task_prompt.sha256}),
        _sealed({"name": "receipt", "capability": capability}),
    ]
    bundle: dict[str, Any] = {
        "schema": BUNDLE_SCHEMA, "registry_version": registry["version"], "job": job,
        "sections": sections, "section_sha256": {section["name"]: section["sha256"] for section in sections},
    }
    bundle["sha256"] = bundle_sha256(bundle)
    return bundle


def verify_bundle(bundle: Mapping[str, Any]) -> str:
    """Recompute section and bundle hashes; any mismatch is a framework-integrity failure."""
    identity = str(bundle.get("sha256", ""))
    _require(bool(re.fullmatch(r"[0-9a-f]{64}", identity)), "guidance bundle identity is invalid")
    if bundle.get("schema") == BUNDLE_SCHEMA:
        sections = bundle["sections"]
        if [section["name"] for section in sections] != list(SECTION_ORDER):
            raise IntegrityError("guidance bundle sections are not in assembly order")
        for section in sections:
            recorded = bundle["section_sha256"].get(section["name"])
            if section_sha256(section) != section["sha256"] or recorded != section["sha256"]:
                raise IntegrityError(f"guidance section hash mismatch: {section['name']}")
    if bundle_sha256(bundle) != identity:
        raise IntegrityError("guidance bundle hash mismatch")
    return identity


def render_prompt(bundle: Mapping[str, Any]) -> str:
    """Render a v2 bundle as delimited sections; the receipt stays structured JSON."""
    verify_bundle(bundle)
    _require(bundle.get("schema") == BUNDLE_SCHEMA, "only inference guidance bundles render")
    parts: list[str] = []
    for section in bundle["sections"]:
        if section["name"] in {"persona", "stack"}:
            body = "\n\n".join(f"## {item['heading']}\n{item['text']}" for item in section["sections"])
        elif section["name"] == "task":
            task_input = canonical_json(section["input"]).decode().strip()
            body = section["text"] + "\n\nTask input (structured):\n" + task_input
        elif section["name"] == "receipt":
            receipt = canonical_json(section["capability"]).decode().strip()
            body = "Capability receipt (trusted structured metadata):\n" + receipt
        else:
            body = section["text"].strip()
        label = section.get("id", section["name"])
        parts.append(f"<<<{section['name']} id={label} sha256={section['sha256']}>>>\n{body.strip()}\n"
                     f"<<<end {section['name']}>>>")
    return "\n\n".join(parts) + "\n"


def pin_bundle(run_root: Path, bundle: Mapping[str, Any], *,
               files: Mapping[str, str] | None = None) -> dict[str, str]:
    """Store a verified bundle once under ``runs/<run>/data/guidance/<bundle-sha256>/``."""
    identity = verify_bundle(bundle)
    root = Path(run_root) / "data" / "guidance" / identity
    atomic_json(root / "bundle.json", dict(bundle))
    extra = dict(files or {})
    if bundle.get("schema") == BUNDLE_SCHEMA:
        extra.setdefault("prompt.md", render_prompt(bundle))
    for name, text in sorted(extra.items()):
        _require(bool(re.fullmatch(r"[a-z0-9][a-z0-9.\-]*\.md", name)), f"pinned guidance file name is invalid: {name}")
        atomic_bytes(root / name, text.encode("utf-8"))
    return {"bundle_sha256": identity, "path": (Path("data") / "guidance" / identity / "bundle.json").as_posix()}


__all__ = [
    "BUNDLE_SCHEMA", "PERSONA_VIEWS", "SECTION_ORDER", "bundle_sha256", "compose_bundle", "governing_rules",
    "load_fragment", "load_persona_covers", "load_registry", "load_task", "pin_bundle", "render_prompt",
    "section_sha256", "text_sha256", "validate_registry", "verify_bundle",
]
