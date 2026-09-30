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

``loaded`` is the one normalisation between the file and every reader: on disk every persona
carries every key, with an explicit empty value where a field does not apply; loaded, an empty
optional field is left out, exactly as the records were before they moved. That keeps the rendered
prompt section, the pinned record hash and every job's assembled prompt byte-identical.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

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
    "personas": ("best_used_in_lanes", "provenance"),
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
