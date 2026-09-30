#!/usr/bin/env python3
"""Knowledge pack registry check (ADR-0034 item 6).

A knowledge pack is ``pipeline/knowledge-packs/<pack_id>.json`` (schema ``knowledge-pack.schema.json``):
an exploit-class focus record an attacker or domain-specialist persona lists in its ``knowledge_packs``
key. ``check`` validates, read-only:

- every pack against its schema, its file name against its ``pack_id``, and its caps;
- id formats: ``attack_reference.TECHNIQUE_ID`` / ``CAPEC_ID`` / ``CWE_ID``, and tactic shortnames
  against the resolved ATT&CK table when one resolves, else against ``CHAIN_STAGE_TACTICS``;
- every persona's ``knowledge_packs`` names existing packs (at most two), and only ``attacker`` /
  ``domain-specialist`` personas list any;
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


def _persona_errors(registry_dir: Path, known: set[str]) -> list[str]:
    errors = []
    for persona_id in persona_registry.record_ids(registry_dir, "personas"):
        label = f"personas/{persona_id}"
        path = persona_registry.record_path(registry_dir, "personas", persona_id)[1]
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            errors.append(f"{label}: persona.json unreadable")
            continue
        if "knowledge_packs" not in record:
            errors.append(f"{label}: has no knowledge_packs key")
            continue
        packs = record["knowledge_packs"]
        if not isinstance(packs, list) or not all(isinstance(item, str) for item in packs):
            errors.append(f"{label}: knowledge_packs is not a list of pack ids")
            continue
        if len(packs) > persona_registry.PACKS_PER_PERSONA_MAX:
            errors.append(f"{label}: lists more than {persona_registry.PACKS_PER_PERSONA_MAX} knowledge packs")
        if len(packs) != len(set(packs)):
            errors.append(f"{label}: lists a knowledge pack twice")
        for pack_id in packs:
            if pack_id not in known:
                errors.append(f"{label}: knowledge pack {pack_id!r} does not exist")
        if packs and record.get("category") not in persona_registry.PACK_CATEGORIES:
            errors.append(f"{label}: only {' and '.join(persona_registry.PACK_CATEGORIES)} personas may list "
                          f"knowledge packs (category {record.get('category')!r})")
    return errors


def check(registry_dir: Path = registry_paths.REGISTRY, *, reference: Any = _RESOLVE,
          cwe: Any = _RESOLVE) -> tuple[list[str], list[str]]:
    """(errors, notes). ``reference`` / ``cwe`` are the resolved ATT&CK/CAPEC table and CWE catalog
    (``None`` for "no snapshot"); by default they are resolved from this host, never raising."""
    registry_dir = Path(registry_dir)
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
    errors += _persona_errors(registry_dir, set(pack_ids(registry_dir)))
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
