#!/usr/bin/env python3
"""Prompt assembler (D01 construction, Phase 5b item 2): turns a job template's declared
``prompt_sections`` into the one pinned ``outer_prompt`` file ``persona_invocation.resolve_request``
requires -- a path (relative to ``persona_invocation.PROMPT_ROOT``) plus a sha256 and a byte count.

Every registry-record section (``persona``, ``role``, ``domain``, ``tooling_profile``,
``output_contract``) renders as a labeled fenced JSON block over the *exact bytes*
``persona_invocation.load_composition`` will independently re-load and hash from the same registry
directory. This module never re-derives, paraphrases, or summarizes a registry record -- it reads
the record, validates it against its own schema (the same schema persona_invocation validates
against), and writes its canonical JSON form. What the persona reads and what persona_invocation
pins can never drift apart, because they are read from the same file.

Two sections are literal file bytes, not a registry record: ``governing_rules``
(``pipeline/prompt-fragments/governing-rules.md``, shared by every future job template that lists
it) and ``buildenv_catalog`` (``tooling/buildenv-catalog.json``). One section, ``task``, is the
literal bytes of the job template's own ``task_prompt`` file.

This module is a pure reader plus one write: the write is the assembled prompt file itself, placed
under the attempt's own scratch directory via ``execution_state.data_path`` (the same run-owned,
symlink-checked, atomic-write path every other job output in this process uses). It does not call
into ``persona_invocation`` and does not build a request; the request builder (Phase 5b item 3)
calls this module first, then uses its return value to fill ``request["outer_prompt"]``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import hashlib

import persona_registry
from execution_state import atomic_bytes, beneath, identifier
from schema_validate import SchemaStore, validate_document
import registry_paths

ROOT = Path(__file__).resolve().parent
REGISTRY_DIR = registry_paths.REGISTRY
PROMPT_ROOT = ROOT  # matches persona_invocation.PROMPT_ROOT: paths are named relative to this tree
GOVERNING_RULES_PATH = registry_paths.PROMPT_FRAGMENTS_DIR / "governing-rules.md"
BUILDENV_CATALOG_PATH = ROOT / "tooling" / "buildenv-catalog.json"
# Deliberately NOT under runs/<run_id>/.../attempts/<attempt_id>/: persona_invocation's own
# _read_pinned refuses an outer_prompt that sits inside the attempt ("an attempt never reads
# itself"), and this module's render is a pure function of job_template_id and the registry --
# nothing about it is run-, job-, or attempt-specific, so it does not belong under runs/ at all.
# One cached file per job_template_id, regenerated (not appended to) on every call.
PROMPT_CACHE_DIR = ROOT / "prompt-cache"

# section name -> (registry directory, schema file, composition key, the record's own id field).
# Deliberately not imported from persona_invocation.COMPOSITION_KINDS: this module stays a plain
# reader of registry JSON with no dependency on the dispatch protocol. The composition key is
# always `<section>_id` (job-template.schema.json's fixed `composition` shape); the record's own id
# field usually matches it, except output_contract's record field is `contract_id`, not
# `output_contract_id` -- persona_invocation.COMPOSITION_KINDS carries the same asymmetry.
RECORD_SECTIONS: dict[str, tuple[str, str, str, str]] = {
    "persona": ("personas", "persona.schema.json", "persona_id", "persona_id"),
    "role": ("roles", "role.schema.json", "role_id", "role_id"),
    "domain": ("domains", "domain.schema.json", "domain_id", "domain_id"),
    "tooling_profile": ("tooling-profiles", "tooling-profile.schema.json", "tooling_profile_id", "tooling_profile_id"),
    "output_contract": ("output-contracts", "output-contract.schema.json", "output_contract_id", "contract_id"),
}

LITERAL_SECTIONS: dict[str, tuple[Path, str]] = {
    "governing_rules": (GOVERNING_RULES_PATH, "Governing Rules"),
    "buildenv_catalog": (BUILDENV_CATALOG_PATH, "Build Environment Catalog"),
}


class PromptAssemblyError(ValueError):
    """The job template, a section it names, or a file a section points at is missing or invalid.
    Raised before anything is written. Messages name registry directories and section names only
    (trusted, fixed text and registry ids), never bytes read from a record or a prompt file."""


def _read_utf8(path: Path, root: Path, label: str) -> str:
    try:
        checked = beneath(root, path)
        text = checked.read_text(encoding="utf-8")
    except (OSError, ValueError):
        raise PromptAssemblyError(f"{label}: missing, unreadable, or outside its root") from None
    try:
        text.encode("utf-8").decode("utf-8")
    except UnicodeDecodeError:
        raise PromptAssemblyError(f"{label}: is not UTF-8") from None
    return text


def load_job_template(job_template_id: str, store: SchemaStore) -> dict[str, Any]:
    path = REGISTRY_DIR / "job-templates" / f"{identifier(job_template_id)}.json"
    text = _read_utf8(path, REGISTRY_DIR, f"job template {job_template_id!r}")
    try:
        template = json.loads(text)
    except ValueError:
        raise PromptAssemblyError(f"job template {job_template_id!r} is not valid JSON") from None
    errors = validate_document(template, "job-template.schema.json", store)
    if errors or template.get("job_template_id") != job_template_id:
        raise PromptAssemblyError(f"job template {job_template_id!r} is invalid or misnamed")
    return template


def _render_record(section: str, composition: Mapping[str, str], store: SchemaStore) -> str:
    directory, schema, composition_key, record_field = RECORD_SECTIONS[section]
    record_id = composition.get(composition_key)
    if not isinstance(record_id, str) or not record_id:
        raise PromptAssemblyError(f"job template composition is missing {composition_key}")
    root, path = persona_registry.record_path(REGISTRY_DIR, directory, identifier(record_id))
    text = _read_utf8(path, root, f"{section} record {record_id!r}")
    try:
        record = json.loads(text)
    except ValueError:
        raise PromptAssemblyError(f"{section} record {record_id!r} is not valid JSON") from None
    if validate_document(record, schema, store) or record.get(record_field) != record_id:
        raise PromptAssemblyError(f"{section} record {record_id!r} is invalid or misnamed")
    return render_record_section(section, record_id, persona_registry.loaded(directory, record))


def render_record_section(section: str, record_id: str, record: Mapping[str, Any]) -> str:
    """The exact prompt section for one loaded registry record (a persona or role folder's
    ``prompt.md`` is this text; ``catalog_personas.py check`` keeps the two equal)."""
    body = json.dumps(record, indent=2, sort_keys=True)
    heading = section.replace("_", " ").title()
    return f"## {heading} ({record_id})\n\n```json\n{body}\n```\n"


def _render_literal(section: str) -> str:
    path, heading = LITERAL_SECTIONS[section]
    text = _read_utf8(path, path.parent, section)
    return f"## {heading}\n\n{text.strip()}\n"


def _render_task(template: Mapping[str, Any]) -> str:
    task_prompt = template.get("task_prompt")
    if not isinstance(task_prompt, str) or not task_prompt:
        raise PromptAssemblyError("job template has no task_prompt")
    repo_root = ROOT.parent
    path = repo_root / task_prompt
    text = _read_utf8(path, repo_root, f"task_prompt {task_prompt!r}")
    return f"## Task\n\n{text.strip()}\n"


def render_section(section: str, template: Mapping[str, Any], store: SchemaStore) -> str:
    if section == "task":
        return _render_task(template)
    if section in LITERAL_SECTIONS:
        return _render_literal(section)
    if section in RECORD_SECTIONS:
        return _render_record(section, template["composition"], store)
    raise PromptAssemblyError(f"unknown prompt section {section!r}")


def _with_variant(template: dict[str, Any], section: str, record_id: str | None) -> dict[str, Any]:
    """The template as rendered for one of its registry-declared ``persona_variants`` (ADR-0021)
    or ``role_variants`` (ADR-0024)."""
    key = section + "_id"
    if record_id is None or record_id == template["composition"][key]:
        return template
    variants = template.get(section + "_variants") or []
    if not isinstance(variants, list) or record_id not in variants:
        raise PromptAssemblyError(f"{section} is not one of the job template's {section}_variants")
    return {**template, "composition": {**template["composition"], key: record_id}}


def prompt_source_paths(job_template_id: str) -> tuple[str, ...]:
    """Every file the assembled prompt for ``job_template_id`` is built from, as paths relative to
    ``ROOT`` (the form a worker's code fingerprint keys use): the template itself, each declared
    literal section, the task prompt, and the record of every rendered composition section for the
    default composition and every ``persona_variants``/``role_variants``/``stage_personas``/
    ``stage_roles`` entry. A worker adds these to its fingerprint so an edit to any rendered file
    forces a rerun (the shared governing rules included). Reads the template JSON only; does not
    validate or render, so it cannot fail on a record the assembler would reject."""
    template_path = REGISTRY_DIR / "job-templates" / f"{identifier(job_template_id)}.json"
    template = json.loads(template_path.read_text(encoding="utf-8"))
    sections = template.get("prompt_sections") or []
    paths = [template_path]
    for section in sections:
        if section in LITERAL_SECTIONS:
            paths.append(LITERAL_SECTIONS[section][0])
        elif section == "task" and template.get("task_prompt"):
            paths.append(ROOT.parent / template["task_prompt"])
    ids: dict[str, set[str]] = {section: set() for section in RECORD_SECTIONS if section in sections}
    for section in ids:
        ids[section].add(template["composition"][RECORD_SECTIONS[section][2]])
    for section, keys in (("persona", ("persona_variants", "stage_personas")),
                          ("role", ("role_variants", "stage_roles"))):
        if section not in ids:
            continue
        for key in keys:
            value = template.get(key) or []
            for item in (value.values() if isinstance(value, dict) else value):
                ids[section].update([item] if isinstance(item, str) else item)
    for section, record_ids in ids.items():
        directory = RECORD_SECTIONS[section][0]
        paths += [persona_registry.record_path(REGISTRY_DIR, directory, identifier(record_id))[1]
                  for record_id in sorted(record_ids)]
    return tuple(dict.fromkeys(path.resolve().relative_to(ROOT.resolve()).as_posix() for path in paths))


def assemble_prompt_text(job_template_id: str, store: SchemaStore | None = None,
                         persona_id: str | None = None, role_id: str | None = None) -> tuple[str, dict]:
    """Pure: resolves the job template and renders every declared section in order. Returns
    (text, template). Raises PromptAssemblyError on anything missing, invalid, or unknown -- never
    writes, so a caller that only wants to preview or hash the prompt need not touch disk.
    ``persona_id`` renders the persona section for one of the template's ``persona_variants``,
    ``role_id`` the role section for one of its ``role_variants``; the returned template is the
    registry record, unchanged."""
    store = store or SchemaStore()
    registered = load_job_template(job_template_id, store)
    template = _with_variant(_with_variant(registered, "persona", persona_id), "role", role_id)
    sections = template.get("prompt_sections")
    if not isinstance(sections, list) or not sections:
        raise PromptAssemblyError(f"job template {job_template_id!r} declares no prompt_sections")
    rendered = [render_section(section, template, store) for section in sections]
    text = "\n".join(rendered).rstrip() + "\n"
    return text, registered


def assemble_outer_prompt(job_template_id: str, *, store: SchemaStore | None = None,
                          persona_id: str | None = None, role_id: str | None = None) -> dict[str, Any]:
    """Assembles and writes the outer prompt for `job_template_id` to its cache path under
    ``PROMPT_CACHE_DIR`` (never under any run's ``attempts/`` tree -- see that constant's
    comment), and returns ``{path, sha256, bytes}`` -- ``path`` relative to ``PROMPT_ROOT``,
    ``sha256`` in the ``sha256:<64 hex>`` form ``persona_invocation`` pins, ``bytes`` the exact
    byte count written. The request builder passes this dict straight through as
    ``request["outer_prompt"]``. Not run-, job-, or attempt-scoped: every call for the same
    ``job_template_id`` regenerates the same cache file from the current registry state, so two
    attempts of the same job template share one outer_prompt file and its pin, and a registry
    edit is picked up on the next call without any stale per-attempt copy to invalidate."""
    text, template = assemble_prompt_text(job_template_id, store, persona_id, role_id)
    data = text.encode("utf-8")
    folder = PROMPT_CACHE_DIR / identifier(job_template_id)
    if role_id is not None and role_id != template["composition"]["role_id"]:
        folder = folder / "roles" / identifier(role_id)   # one pinned prompt per role variant
    if persona_id is not None and persona_id != template["composition"]["persona_id"]:
        folder = folder / "personas" / identifier(persona_id)   # one pinned prompt per variant
    output_path = beneath(PROMPT_CACHE_DIR, folder / "outer_prompt.md")
    atomic_bytes(output_path, data)
    relative = output_path.resolve().relative_to(PROMPT_ROOT.resolve()).as_posix()
    return {
        "path": relative,
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("job_template_id")
    parser.add_argument("--print", action="store_true", help="render and print the assembled prompt text, write nothing")
    args = parser.parse_args()

    if args.print:
        rendered_text, _ = assemble_prompt_text(args.job_template_id)
        print(rendered_text)
    else:
        result = assemble_outer_prompt(args.job_template_id)
        print(json.dumps(result, indent=2))
