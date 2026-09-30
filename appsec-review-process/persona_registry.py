#!/usr/bin/env python3
"""Where persona and role records live (brief J): one folder per record under ``personas/``.

    personas/persona.schema.json   personas/role.schema.json
    personas/personas/<persona-id>/persona.json   prompt.md
    personas/roles/<role-id>/role.json            prompt.md

The folder tree sits beside the registry directory ``pipeline/`` (``<registry_dir>/../personas``), so a
test that copies a registry directory copies the ``personas`` directory next to it. Every other registry
record kind (job templates, domains, tooling profiles, output contracts) stays
``pipeline/<kind>/<id>.json`` (brief K; ``registry_paths`` owns those paths);
callers name a kind by its old registry directory (``"personas"``, ``"roles"``, ``"domains"`` ...)
and this module answers where that record's file is.

A persona may list knowledge packs (``knowledge_packs``, ADR-0034): ``pipeline/knowledge-packs/<id>.json``
records that give an attacker or domain-specialist persona its exploit-class focus. A pack is part of
the persona's input identity, so :func:`knowledge_pack_rels` is the one place a job's code hash map
finds the packs behind the ``persona.json`` files it already hashes. A job template may assign packs
per persona (its ``knowledge_packs`` map, ADR-0034 addendum 1); :func:`resolve_pack_ids` is the one
resolution rule (named in the map: exactly those packs; not named: the ``persona.json`` default).

``loaded`` is the one normalisation between the file and every reader: on disk every persona
carries every key, with an explicit empty value where a field does not apply; loaded, an empty
optional field is left out, exactly as the records were before they moved. That keeps the rendered
prompt section, the pinned record hash and every job's assembled prompt byte-identical.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

import registry_paths
import tunables

ROOT = Path(__file__).resolve().parent
FOLDER_ROOT = ROOT / "personas"
PROMPT_FILE = "prompt.md"
# registry directory name -> (record file in each folder, schema file, the record's own id field)
KINDS: dict[str, tuple[str, str, str]] = {
    "personas": ("persona.json", "persona.schema.json", "persona_id"),
    "roles": ("role.json", "role.schema.json", "role_id"),
}
# Optional fields present on disk with an empty value ([] or {}) and left out when loaded.
ELIDED_WHEN_EMPTY: dict[str, tuple[str, ...]] = {
    "personas": ("best_used_in_lanes", "knowledge_packs", "provenance"),
    "roles": (),
}


def folder_root(registry_dir: Path) -> Path:
    """The ``personas`` folder tree that belongs to ``registry_dir``."""
    return Path(registry_dir).parent / FOLDER_ROOT.name


def record_path(registry_dir: Path, directory: str, record_id: str) -> tuple[Path, Path]:
    """(root the path must stay beneath, path of the record file) for one registry record."""
    if directory in KINDS:
        root = folder_root(registry_dir)
        return root, root / directory / record_id / KINDS[directory][0]
    return Path(registry_dir), Path(registry_dir) / directory / (record_id + ".json")


def prompt_path(registry_dir: Path, directory: str, record_id: str) -> Path:
    return folder_root(registry_dir) / directory / record_id / PROMPT_FILE


def record_ids(registry_dir: Path, directory: str) -> list[str]:
    """Every record id of one kind, sorted: folder names for personas/roles, file stems otherwise."""
    if directory in KINDS:
        base = folder_root(registry_dir) / directory
        return sorted(path.name for path in base.iterdir() if path.is_dir()) if base.is_dir() else []
    return sorted(path.stem for path in (Path(registry_dir) / directory).glob("*.json"))


def loaded(directory: str, record: Mapping[str, Any]) -> dict[str, Any]:
    """The record as every reader sees it: empty optional fields left out (see module docstring)."""
    elided = ELIDED_WHEN_EMPTY.get(directory, ())
    return {key: value for key, value in record.items()
            if not (key in elided and value in ([], {}))}


# ---- knowledge packs (ADR-0034) ----------------------------------------------------------------------

KNOWLEDGE_PACKS = registry_paths.KNOWLEDGE_PACKS
KNOWLEDGE_PACK_SCHEMA = "knowledge-pack.schema.json"
# Only these persona categories may list packs; verifiers, defenders, scorers and report personas
# judge evidence, not whether it matches a pack (ADR-0034 item 2).
PACK_CATEGORIES = ("attacker", "domain-specialist")
# The per-persona cap is the shared tunable ``knowledge_packs_per_persona_max`` (ADR-0034 addendum 2),
# enforced by ``knowledge_packs.py check`` on persona defaults and job-template maps alike.
TEMPLATE_PACKS_KEY = "knowledge_packs"
_PERSONA_REL = re.compile(r"personas/personas/([a-z0-9][a-z0-9-]*)/persona\.json\Z")
_TEMPLATE_REL = re.compile(re.escape(registry_paths.rel(registry_paths.JOB_TEMPLATES)) + r"/([0-9a-z][0-9a-z-]*)\.json\Z")


def packs_per_persona_max() -> int:
    """The most knowledge packs one persona may be given, from either source (shared tunable)."""
    return int(tunables.shared("knowledge_packs_per_persona_max"))


def persona_pack_ids(registry_dir: Path, persona_id: str) -> list[str]:
    """The pack ids the persona's ``persona.json`` on disk lists, in order ([] when it lists none)."""
    path = record_path(registry_dir, "personas", persona_id)[1]
    value = json.loads(path.read_text(encoding="utf-8")).get("knowledge_packs") or []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"personas/{persona_id}: knowledge_packs is not a list of pack ids")
    return list(value)


def knowledge_pack_path(registry_dir: Path, pack_id: str) -> Path:
    return record_path(registry_dir, KNOWLEDGE_PACKS, pack_id)[1]


def _pack_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{where}: knowledge_packs is not a list of pack ids")
    return list(value)


def template_pack_map(template: Mapping[str, Any] | None) -> dict[str, list[str]]:
    """A job template's ``knowledge_packs`` map (persona id -> pack ids, ADR-0034 addendum 1); ``{}``
    when the template carries none. Raises ValueError when the value is not such a map."""
    value = (template or {}).get(TEMPLATE_PACKS_KEY)
    if value is None:
        return {}
    where = f"job template {(template or {}).get('job_template_id', '?')}"
    if not isinstance(value, dict):
        raise ValueError(f"{where}: knowledge_packs is not a map of persona id to pack ids")
    return {persona_id: _pack_list(packs, f"{where} persona {persona_id}") for persona_id, packs in value.items()}


def resolve_pack_ids(template: Mapping[str, Any] | None, persona_id: str,
                     registry_dir: Path = registry_paths.REGISTRY,
                     persona_record: Mapping[str, Any] | None = None) -> list[str]:
    """The knowledge packs ``persona_id`` runs with in ``template`` (ADR-0034 addendum 1), the one
    resolution rule every reader uses: a persona named in the template's ``knowledge_packs`` map gets
    exactly those packs (``[]`` removes them); a persona not named gets its ``persona.json`` default.
    ``persona_record`` is that persona.json when the caller has already read it; ``template`` None
    means no job context (a persona folder's ``prompt.md``), so the default."""
    overrides = template_pack_map(template)
    if persona_id in overrides:
        return list(overrides[persona_id])
    if persona_record is not None:
        return _pack_list(persona_record.get("knowledge_packs") or [], f"personas/{persona_id}")
    return persona_pack_ids(registry_dir, persona_id)


def template_persona_ids(template: Mapping[str, Any]) -> set[str]:
    """Every persona a job template may run as: its composed persona, ``persona_variants`` and the
    ``stage_personas`` pools."""
    ids = {(template.get("composition") or {}).get("persona_id")}
    variants = template.get("persona_variants") or []
    if isinstance(variants, list):
        ids.update(v for v in variants if isinstance(v, str))
    stages = template.get("stage_personas") or {}
    if isinstance(stages, dict):
        for values in stages.values():
            if isinstance(values, list):
                ids.update(v for v in values if isinstance(v, str))
    ids.discard(None)
    return ids


def knowledge_pack_rels(paths: Iterable[str], registry_dir: Path = registry_paths.REGISTRY) -> list[str]:
    """Process-relative paths (``pipeline/knowledge-packs/<id>.json``) of every pack a job resolves for
    the ``personas/personas/<id>/persona.json`` files among ``paths``; sorted, unique. The job templates
    among ``paths`` (``pipeline/job-templates/<id>.json``) decide: a persona gets
    :func:`resolve_pack_ids` for each of those templates it belongs to, its ``persona.json`` default
    when it belongs to none, and every pack a listed template's ``knowledge_packs`` map assigns is
    included. A job adds these to the code hash map that already holds those persona and template
    files, so editing a pack it uses re-executes the job."""
    paths = [str(path) for path in paths]
    templates = []
    for path in paths:
        match = _TEMPLATE_REL.fullmatch(path)
        if match:
            template_path = registry_paths.template(match.group(1), registry_dir)
            templates.append(json.loads(template_path.read_text(encoding="utf-8")))
    packs: set[str] = set()
    for template in templates:
        for values in template_pack_map(template).values():
            packs.update(values)
    for path in paths:
        match = _PERSONA_REL.fullmatch(path)
        if not match:
            continue
        persona_id = match.group(1)
        owners = [template for template in templates if persona_id in template_persona_ids(template)]
        if not owners:
            packs.update(persona_pack_ids(registry_dir, persona_id))
        for template in owners:
            packs.update(resolve_pack_ids(template, persona_id, registry_dir))
    return [registry_paths.rel(KNOWLEDGE_PACKS, pack_id) for pack_id in sorted(packs)]
