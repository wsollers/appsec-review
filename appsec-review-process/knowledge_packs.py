#!/usr/bin/env python3
"""Knowledge pack registry check (ADR-0034 item 6).

A knowledge pack is ``pipeline/knowledge-packs/<pack_id>.json`` (schema ``knowledge-pack.schema.json``):
an exploit-class focus record an attacker or domain-specialist persona lists in its ``knowledge_packs``
key. ``check`` validates, read-only:

- every pack against its schema, its file name against its ``pack_id``, and its caps;
- id formats: ``attack_reference.TECHNIQUE_ID`` / ``CAPEC_ID`` / ``CWE_ID``, and tactic shortnames
  against the resolved ATT&CK table when one resolves, else against ``CHAIN_STAGE_TACTICS``;
- every persona's ``knowledge_packs`` default and every job template's ``knowledge_packs`` map
  (persona id -> pack ids, ADR-0034 addendum 1) names existing packs, at most the shared tunable
  ``knowledge_packs_per_persona_max`` per persona, and gives packs only to ``attacker`` /
  ``domain-specialist`` personas; a template map may name only existing personas the template runs as
  (its composed persona, ``persona_variants`` or ``stage_personas``);
- when a MITRE snapshot resolves, every technique, CAPEC pattern and tactic is ``OK`` in it (and every
  CWE in the snapshot's CWE catalog when that resolves). With no snapshot the ids are format-checked
  only and the result says so; a missing snapshot is never a failure.

    python3 -B appsec-review-process/knowledge_packs.py check

Pack text is trusted, reviewed registry content; this module never renders or interprets it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import attack_reference
import persona_registry
import registry_paths
from schema_validate import SchemaStore, validate_document

SCHEMA_ID = "appsec-review/knowledge-pack/0.1"
KEY_ORDER = ("schema", "pack_id", "display_name", "summary", "applies_to", "looks_for", "preconditions",
             "proof_obligations", "false_positive_traps", "refs", "must_not")
REF_KEYS = ("attack_tactics", "attack_techniques", "capec", "cwe")
CAPS = {"looks_for": 12, "preconditions": 8, "proof_obligations": 8, "false_positive_traps": 8}
REF_CAP = 15
FORMATS = {"attack_techniques": attack_reference.TECHNIQUE_ID, "capec": attack_reference.CAPEC_ID,
           "cwe": attack_reference.CWE_ID}
FALLBACK_TACTICS = frozenset(t for tactics in attack_reference.CHAIN_STAGE_TACTICS.values() for t in tactics)
_RESOLVE = object()   # sentinel: resolve the snapshot from this host


def pack_ids(registry_dir: Path = registry_paths.REGISTRY) -> list[str]:
    return persona_registry.record_ids(registry_dir, persona_registry.KNOWLEDGE_PACKS)


def _pack_errors(path: Path, store: SchemaStore, tactics: frozenset[str]) -> tuple[dict | None, list[str]]:
    label = f"knowledge-packs/{path.name}"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, [f"{label}: unreadable or not JSON"]
    if not isinstance(record, dict):
        return None, [f"{label}: is not a JSON object"]
    errors = [f"{label}: {error}" for error in validate_document(record, persona_registry.KNOWLEDGE_PACK_SCHEMA, store)]
    if record.get("schema") != SCHEMA_ID:
        errors.append(f"{label}: schema is not {SCHEMA_ID}")
    if record.get("pack_id") != path.stem:
        errors.append(f"{label}: pack_id does not match the file name")
    if tuple(record) != KEY_ORDER:
        errors.append(f"{label}: keys are not exactly the schema keys in order")
    for key, cap in CAPS.items():
        if isinstance(record.get(key), list) and len(record[key]) > cap:
            errors.append(f"{label}: {key} has more than {cap} entries")
    refs = record.get("refs") if isinstance(record.get("refs"), dict) else {}
    for key in REF_KEYS:
        values = refs.get(key) if isinstance(refs.get(key), list) else []
        if len(values) > REF_CAP:
            errors.append(f"{label}: refs.{key} has more than {REF_CAP} ids")
        for value in values:
            if key == "attack_tactics":
                if not isinstance(value, str) or value not in tactics:
                    errors.append(f"{label}: refs.attack_tactics {value!r} is not a known ATT&CK tactic shortname")
            elif not isinstance(value, str) or not FORMATS[key].fullmatch(value):
                errors.append(f"{label}: refs.{key} {value!r} is not a well-formed id")
    return record, errors


def _resolve_reference():
    reference, gap = attack_reference.load()
    return reference, (gap or {}).get("code")


def _resolve_cwe():
    try:
        import cwe_catalog
        catalog = cwe_catalog.current()
    except Exception as exc:   # never fail the check because the snapshot or catalog is unusable
        return None, f"CWE catalog unusable: {type(exc).__name__}"
    if catalog.source != cwe_catalog.FEED:
        return None, (catalog.gap or {}).get("code") or "CWE feed not used"
    return catalog, None


def _snapshot_errors(packs: dict[str, dict], reference: Any, cwe: Any) -> list[str]:
    errors: list[str] = []
    for pack_id, record in sorted(packs.items()):
        refs = record.get("refs") or {}
        label = f"knowledge-packs/{pack_id}.json"
        if reference is not None:
            for value in refs.get("attack_techniques") or []:
                status = reference.validate_technique(value)
                if status != attack_reference.OK:
                    errors.append(f"{label}: refs.attack_techniques {value} is {status} in the MITRE snapshot")
            for value in refs.get("capec") or []:
                status = reference.validate_capec(value)
                if status != attack_reference.OK:
                    errors.append(f"{label}: refs.capec {value} is {status} in the MITRE snapshot")
        if cwe is not None:
            for value in refs.get("cwe") or []:
                try:
                    cwe.validate(value)
                except ValueError:
                    errors.append(f"{label}: refs.cwe {value} is not a current id in the MITRE CWE catalog")
    return errors


def _pack_list_errors(label: str, packs: Any, category: Any, known: set[str], cap: int) -> list[str]:
    """The rules one persona's packs obey, whichever source gives them (persona default or template map)."""
    if not isinstance(packs, list) or not all(isinstance(item, str) for item in packs):
        return [f"{label}: knowledge_packs is not a list of pack ids"]
    errors = []
    if len(packs) > cap:
        errors.append(f"{label}: lists more than {cap} knowledge packs")
    if len(packs) != len(set(packs)):
        errors.append(f"{label}: lists a knowledge pack twice")
    for pack_id in packs:
        if pack_id not in known:
            errors.append(f"{label}: knowledge pack {pack_id!r} does not exist")
    if packs and category not in persona_registry.PACK_CATEGORIES:
        errors.append(f"{label}: only {' and '.join(persona_registry.PACK_CATEGORIES)} personas may list "
                      f"knowledge packs (category {category!r})")
    return errors


def _persona_records(registry_dir: Path) -> tuple[dict[str, dict], list[str]]:
    records, errors = {}, []
    for persona_id in persona_registry.record_ids(registry_dir, "personas"):
        path = persona_registry.record_path(registry_dir, "personas", persona_id)[1]
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            errors.append(f"personas/{persona_id}: persona.json unreadable")
            continue
        records[persona_id] = record if isinstance(record, dict) else {}
    return records, errors


def _persona_errors(personas: dict[str, dict], known: set[str], cap: int) -> list[str]:
    errors = []
    for persona_id, record in sorted(personas.items()):
        label = f"personas/{persona_id}"
        if "knowledge_packs" not in record:
            errors.append(f"{label}: has no knowledge_packs key")
            continue
        errors += _pack_list_errors(label, record["knowledge_packs"], record.get("category"), known, cap)
    return errors


def _template_errors(registry_dir: Path, personas: dict[str, dict], known: set[str], cap: int) -> list[str]:
    """Every job template's ``knowledge_packs`` map (ADR-0034 addendum 1): a map of existing persona
    ids the template runs as, each to packs that obey the same rules as a persona default."""
    errors = []
    for path in sorted((registry_dir / registry_paths.JOB_TEMPLATES).glob("*.json")):
        label = f"{registry_paths.JOB_TEMPLATES}/{path.name}"
        try:
            template = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            errors.append(f"{label}: unreadable or not JSON")
            continue
        if not isinstance(template, dict) or "knowledge_packs" not in template:
            continue
        value = template["knowledge_packs"]
        if not isinstance(value, dict):
            errors.append(f"{label}: knowledge_packs is not a map of persona id to pack ids")
            continue
        runs_as = persona_registry.template_persona_ids(template)
        for persona_id, packs in value.items():
            where = f"{label}: knowledge_packs[{persona_id!r}]"
            if persona_id not in personas:
                errors.append(f"{where}: persona does not exist")
                continue
            if persona_id not in runs_as:
                errors.append(f"{where}: persona is not one the template runs as "
                              "(composition persona, persona_variants or stage_personas)")
            errors += _pack_list_errors(where, packs, personas[persona_id].get("category"), known, cap)
    return errors


def check(registry_dir: Path = registry_paths.REGISTRY, *, reference: Any = _RESOLVE,
          cwe: Any = _RESOLVE, cap: int | None = None) -> tuple[list[str], list[str]]:
    """(errors, notes). ``reference`` / ``cwe`` are the resolved ATT&CK/CAPEC table and CWE catalog
    (``None`` for "no snapshot"); by default they are resolved from this host, never raising. ``cap``
    is the packs-per-persona limit, by default the tunable ``knowledge_packs_per_persona_max``."""
    registry_dir = Path(registry_dir)
    cap = persona_registry.packs_per_persona_max() if cap is None else int(cap)
    store = SchemaStore()
    notes: list[str] = []
    if reference is _RESOLVE:
        reference, gap = _resolve_reference()
    else:
        gap = None if reference is not None else attack_reference.GAP_MISSING
    if cwe is _RESOLVE:
        cwe, cwe_gap = _resolve_cwe()
    else:
        cwe_gap = None if cwe is not None else "CWE_REFERENCE_MISSING"
    if reference is not None:
        tactics = frozenset(row["shortname"] for row in reference.tactics.values())
        notes.append("ATT&CK techniques, CAPEC patterns and tactics validated against MITRE snapshot "
                     f"{reference.identity.get('snapshot_id', 'unknown')}")
    else:
        tactics = FALLBACK_TACTICS
        notes.append(f"no MITRE snapshot resolved ({gap}): ATT&CK/CAPEC ids were format-checked only and "
                     "tactics checked against CHAIN_STAGE_TACTICS")
    notes.append(f"CWE ids validated against MITRE CWE catalog {cwe.used}" if cwe is not None else
                 f"no MITRE CWE catalog resolved ({cwe_gap}): CWE ids were format-checked only")
    errors: list[str] = []
    packs: dict[str, dict] = {}
    directory = registry_dir / persona_registry.KNOWLEDGE_PACKS
    if not directory.is_dir():
        errors.append(f"{persona_registry.KNOWLEDGE_PACKS}/ directory is missing")
    for pack_id in pack_ids(registry_dir):
        record, problems = _pack_errors(persona_registry.knowledge_pack_path(registry_dir, pack_id), store, tactics)
        errors += problems
        if record is not None:
            packs[pack_id] = record
    errors += _snapshot_errors(packs, reference, cwe)
    known = set(pack_ids(registry_dir))
    personas, problems = _persona_records(registry_dir)
    errors += problems
    errors += _persona_errors(personas, known, cap)
    errors += _template_errors(registry_dir, personas, known, cap)
    return errors, notes


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args not in ([], ["check"]):
        print("usage: knowledge_packs.py check", file=sys.stderr)
        return 2
    errors, notes = check()
    for note in notes:
        print(f"note: {note}")
    print("\n".join(errors) if errors else f"knowledge packs: ok ({len(pack_ids())} packs)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
