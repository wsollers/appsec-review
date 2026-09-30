#!/usr/bin/env python3
"""Registry persona records derived from ``docs/personas-and-registry/persona-catalog.md``.

The catalog is the human-readable source; ``personas/personas/<id>/persona.json`` is what jobs load. This
tool turns each catalog ``### <persona-id>`` section that has no registry record into one
(``appsec-review/persona/0.1``) and marks it with a ``provenance`` block so a reviewer can tell a
catalog-derived record from a hand-authored one. It never rewrites a hand-authored record (one
without ``provenance.generated_by == GENERATOR``; a hand-owned record keeps ``"provenance": {}``).

It also keeps every persona and role folder's ``prompt.md`` equal to the prompt section
``persona_prompt_assembly`` renders for that record, so the folder shows what the model reads.

    python3 -B appsec-review-process/catalog_personas.py generate   # write missing/generated records, prompt.md
    python3 -B appsec-review-process/catalog_personas.py check      # every catalog persona has a record;
                                                                    # every prompt.md is current

Content is taken from the catalog text: the lead sentence becomes ``primary_failure_mode_caught``,
``Inputs``/``Consumes`` become ``required_inputs``, ``Outputs`` become ``outputs``, ``Must not``
bullets and ``Must ...`` sentences become ``must_not``, ``Best lanes`` become ``best_used_in_lanes``,
``Knowledge packs`` (pack ids, ADR-0034) become ``knowledge_packs``
and every other labelled list (``Looks for``, ``Feeds`` ...) is kept under ``assumptions``. Where the
catalog gives no inputs or outputs, a fixed, clearly-labelled placeholder is used instead of an
invented list. Two baseline prohibitions every catalog persona shares are appended to ``must_not``.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import persona_registry
import registry_paths
from persona_prompt_assembly import render_persona_prompt, render_record_section

ROOT = Path(__file__).resolve().parent
CATALOG = ROOT.parent / "docs" / "personas-and-registry" / "persona-catalog.md"
PERSONAS = persona_registry.FOLDER_ROOT / "personas"
GENERATOR = "catalog_personas.py"
SCHEMA = "appsec-review/persona/0.1"

SECTION_CATEGORY = {
    "Core Attacker And Abuse Personas": "attacker",
    "Domain Specialist Personas": "domain-specialist",
    "Defensive And Verification Personas": "defender",
    "QA, Test, And Collection Personas": "evidence-ingestion",
    "Document And Intelligence Personas": "evidence-ingestion",
    "Stakeholder-Focused Output Personas": "stakeholder-output",
    "Synthesis And Decision Personas": "synthesis",
}
# Catalog personas whose own text makes them verifiers/outputs rather than their section default.
CATEGORY_OVERRIDE = {
    "evidence-only-verifier": "verifier", "standards-mapping-auditor": "verifier",
    "completeness-auditor": "verifier", "qa-lead": "stakeholder-output",
}
INPUT_LABELS = ("inputs", "consumes")
OUTPUT_LABELS = ("outputs", "useful outputs")
LANE_LABELS = ("best lanes", "best lane")
PACK_LABELS = ("knowledge packs", "knowledge pack")
BASELINE_MUST_NOT = ["invent evidence, citations or standards mappings",
                     "promote a candidate observation to a verified finding without independent verification"]
NO_INPUTS = "accepted upstream artifacts and cited evidence for the assigned surface (catalog lists no specific inputs)"
NO_OUTPUTS = "evidence-bound observations within this persona's focus (catalog lists no specific outputs)"


def _key(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("`", "")).strip()


def parse(text: str) -> dict[str, dict]:
    """Every ``### id`` section under a persona group: {id: {category, lead, lists, sentences}}."""
    personas: dict[str, dict] = {}
    group, current, label = None, None, None
    paragraph: list[str] = []

    def flush() -> None:
        if current is not None and paragraph:
            current["paragraphs"].append(_clean(" ".join(paragraph)))
        paragraph.clear()

    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("## "):
            flush()
            group, current, label = line[3:].strip(), None, None
            continue
        if line.startswith("### "):
            flush()
            if group in SECTION_CATEGORY:
                persona_id = line[4:].strip()
                current = personas[persona_id] = {"group": group, "paragraphs": [], "lists": {}}
            else:
                current = None
            label = None
            continue
        if current is None:
            continue
        stripped = line.strip()
        if re.fullmatch(r"[A-Z][A-Za-z /,-]*:", stripped):
            flush()
            label = stripped[:-1].lower()
            current["lists"].setdefault(label, [])
            continue
        if stripped.startswith("- "):
            flush()
            if label is None:
                label = "notes"
                current["lists"].setdefault(label, [])
            current["lists"][label].append(_clean(stripped[2:]))
            continue
        if raw.startswith("  ") and stripped and label and current["lists"].get(label):
            current["lists"][label][-1] = _clean(current["lists"][label][-1] + " " + stripped)
            continue
        if not stripped:
            flush()
            continue
        if label is not None and paragraph == [] and current["lists"].get(label):
            label = None   # a paragraph after a list closes the list
        paragraph.append(stripped)
    flush()
    return personas


def _display(persona_id: str) -> str:
    words = {"api": "API", "llm": "LLM", "iam": "IAM", "rest": "REST", "rfc": "RFC", "qa": "QA",
             "pii": "PII", "nsa": "NSA", "stig": "STIG", "owasp": "OWASP", "doc": "Doc"}
    return " ".join(words.get(part, part.capitalize()) for part in persona_id.split("-"))


def _must_not_from_sentence(sentence: str) -> str | None:
    match = re.match(r"(?i)^must not (.+?)\.?$", sentence)
    if match:
        return match.group(1)
    match = re.match(r"(?i)^must (distinguish|cite) (.+?)\.?$", sentence)
    if match:
        verb, rest = match.group(1).lower(), match.group(2)
        return f"fail to {verb} {rest}"
    return None


def record(persona_id: str, section: dict) -> dict:
    lists = {label: items for label, items in section["lists"].items() if items}
    paragraphs = list(section["paragraphs"])
    lead = paragraphs[0] if paragraphs else _display(persona_id)
    rest = paragraphs[1:]
    category = CATEGORY_OVERRIDE.get(persona_id, SECTION_CATEGORY[section["group"]])
    must_not, notes = [], []
    for sentence in rest:
        derived = _must_not_from_sentence(sentence)
        (must_not.append(derived) if derived else notes.append(sentence))
    must_not = list(lists.pop("must not", [])) + must_not
    for label in ("must distinguish", "must preserve"):
        if label in lists:
            verb = label.split()[1]
            must_not.append(f"fail to {verb}: " + "; ".join(lists.pop(label)))
    inputs = next((lists.pop(label) for label in INPUT_LABELS if label in lists), None)
    outputs = next((lists.pop(label) for label in OUTPUT_LABELS if label in lists), None)
    if outputs is None and "focused outputs" in lists:
        outputs = lists.pop("focused outputs")
    lanes = next((lists.pop(label) for label in LANE_LABELS if label in lists), None)
    packs = next((lists.pop(label) for label in PACK_LABELS if label in lists), None)
    assumptions: dict = {"posture": lead}
    for label, items in sorted(lists.items()):
        assumptions[_key(label)] = items
    if notes:
        assumptions["notes"] = notes
    value = {"schema": SCHEMA, "persona_id": persona_id, "display_name": _display(persona_id),
             "category": category, "primary_failure_mode_caught": lead}
    value["best_used_in_lanes"] = lanes or []
    value.update({"assumptions": assumptions,
                  "required_inputs": inputs or [NO_INPUTS],
                  "outputs": outputs or [NO_OUTPUTS],
                  "must_not": must_not + [item for item in BASELINE_MUST_NOT if item not in must_not],
                  "knowledge_packs": packs or [],
                  "provenance": {"generated_by": GENERATOR,
                                 "source": f"docs/personas-and-registry/persona-catalog.md#{persona_id}",
                                 "reviewed": False,
                                 "note": ("Derived mechanically from the catalog prose; not yet reviewed by "
                                          "a human. Edit the catalog and regenerate, or hand-edit and remove "
                                          "this provenance block to take ownership.")}})
    return value


def _hand_authored(path: Path) -> bool:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True
    return (value.get("provenance") or {}).get("generated_by") != GENERATOR


def prompt_text(folder: Path, directory: str) -> str:
    """The prompt section for the record in one persona or role folder (its prompt.md). A persona's
    includes the ``knowledge_packs`` section its packs render into (ADR-0034), read from the registry
    directory beside the folder tree."""
    file_name, _, field = persona_registry.KINDS[directory]
    record = json.loads((folder / file_name).read_text(encoding="utf-8"))
    if directory == "personas":
        registry_dir = folder.parent.parent.parent / registry_paths.DIRNAME
        return render_persona_prompt(record[field], record, registry_dir)
    section = directory[:-1]   # personas -> persona, roles -> role
    return render_record_section(section, record[field], persona_registry.loaded(directory, record))


def _folders(root: Path) -> list[tuple[str, Path]]:
    return [(directory, folder) for directory in persona_registry.KINDS
            for folder in sorted((root / directory).iterdir()) if folder.is_dir()]


def generate(catalog: Path = CATALOG, personas: Path = PERSONAS) -> list[str]:
    written = []
    for persona_id, section in sorted(parse(catalog.read_text(encoding="utf-8")).items()):
        path = personas / persona_id / "persona.json"
        if path.exists() and _hand_authored(path):
            continue
        data = json.dumps(record(persona_id, section), indent=2, ensure_ascii=False) + "\n"
        if not path.exists() or path.read_text(encoding="utf-8") != data:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data, encoding="utf-8", newline="\n")
            written.append(persona_id)
    for directory, folder in _folders(personas.parent):
        path = folder / persona_registry.PROMPT_FILE
        text = prompt_text(folder, directory)
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8", newline="\n")
            written.append(f"{directory}/{folder.name}/{persona_registry.PROMPT_FILE}")
    return written


def check(catalog: Path = CATALOG, personas: Path = PERSONAS) -> list[str]:
    errors = []
    for persona_id, section in sorted(parse(catalog.read_text(encoding="utf-8")).items()):
        path = personas / persona_id / "persona.json"
        if not path.is_file():
            errors.append(f"catalog persona {persona_id} has no registry record")
        elif not _hand_authored(path):
            expected = json.dumps(record(persona_id, section), indent=2, ensure_ascii=False) + "\n"
            if path.read_text(encoding="utf-8") != expected:
                errors.append(f"generated persona {persona_id} is stale; run catalog_personas.py generate")
    for directory, folder in _folders(personas.parent):
        path = folder / persona_registry.PROMPT_FILE
        try:
            current = path.read_text(encoding="utf-8") == prompt_text(folder, directory)
        except (OSError, ValueError, KeyError):
            current = False
        if not current:
            errors.append(f"{directory}/{folder.name}/{persona_registry.PROMPT_FILE} is missing or stale; "
                          "run catalog_personas.py generate")
    return errors


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "check"
    if command == "generate":
        print("\n".join(generate()) or "nothing to write")
    elif command == "check":
        problems = check()
        print("\n".join(problems) or "catalog personas: ok")
        raise SystemExit(1 if problems else 0)
    else:
        raise SystemExit("usage: catalog_personas.py generate|check")
