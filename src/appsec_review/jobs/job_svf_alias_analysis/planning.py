"""Module planning for ``job_svf_alias_analysis`` (docs/architecture/svf-alias-producer.md, S-D5).

One module per captured link command: the bitcode of exactly the compile units whose objects that
command consumes, with static archives expanded through their own captured link (archive) command.
Compile units no link command consumes become single-unit modules. Every reason a module cannot be
closed-world is attached to the module here, before any tool runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from appsec_review.storage import canonical_json


MODULE_LINK = "link"
MODULE_TRANSLATION_UNIT = "translation_unit"
NOT_IN_LINK_UNIT = "not_in_link_unit"
ARCHIVE_MEMBERS_UNRESOLVED = "archive_members_unresolved"
LINK_INPUT_UNRESOLVED = "link_input_unresolved"
_STATIC_SUFFIXES = (".a", ".lib")
_SHARED_SUFFIXES = (".so", ".dylib", ".dll")


@dataclass(frozen=True, slots=True)
class PlannedModule:
    module_id: str
    kind: str
    label: str
    compile_indexes: tuple[int, ...]
    open_world_reasons: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {"module_id": self.module_id, "kind": self.kind, "label": self.label,
                "compile_indexes": list(self.compile_indexes),
                "open_world_reasons": list(self.open_world_reasons), "notes": list(self.notes)}


@dataclass(frozen=True, slots=True)
class ModulePlan:
    modules: tuple[PlannedModule, ...]
    omitted: tuple[PlannedModule, ...] = ()
    gaps: tuple[str, ...] = field(default=())

    def as_dict(self) -> dict[str, Any]:
        return {"modules": [item.as_dict() for item in self.modules],
                "omitted": [item.as_dict() for item in self.omitted], "gaps": list(self.gaps)}


def module_id(kind: str, label: str, indexes: Sequence[int]) -> str:
    digest = hashlib.sha256(canonical_json({"kind": kind, "label": label, "indexes": list(indexes)})).hexdigest()
    return "m-" + digest[:16]


def _suffix(path: str) -> str:
    return PurePosixPath(path).suffix.lower()


def _is_shared(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return _suffix(path) in _SHARED_SUFFIXES or ".so." in name


def plan_modules(compile_rows: Sequence[Mapping[str, Any]], link_commands: Sequence[Mapping[str, Any]], *,
                 max_modules: int) -> ModulePlan:
    """Plan modules over ``compile_rows`` (container compile-database order) and link commands.

    ``compile_rows[i]`` must carry ``output_path`` (the object it produced, possibly ``None``) and
    ``target_path``. A link input that is an object maps to its compile unit; a static archive is
    expanded through the captured command that produced it; a shared library stays outside the
    module (its code is reached only through unresolved externals, which the driver reports). Any
    other unresolved input is named on the module.
    """
    if max_modules < 1:
        raise ValueError("max_modules must be positive")
    by_object: dict[str, int] = {}
    for index, row in enumerate(compile_rows):
        output = row.get("output_path")
        if isinstance(output, str) and output:
            by_object.setdefault(output, index)
    producers = {str(item["output_path"]): item for item in link_commands}

    def resolve_input(path: str, seen: frozenset[str]) -> tuple[set[int], list[str], list[str]]:
        if path in by_object:
            return {by_object[path]}, [], []
        if _is_shared(path):
            return set(), [], [f"shared library input kept external: {path}"]
        command = producers.get(path)
        if _suffix(path) in _STATIC_SUFFIXES:
            if command is None or path in seen:
                return set(), [ARCHIVE_MEMBERS_UNRESOLVED], [f"static archive members unresolved: {path}"]
            indexes: set[int] = set()
            reasons: list[str] = []
            notes: list[str] = []
            for member in command.get("input_paths", ()):
                found, more_reasons, more_notes = resolve_input(str(member), seen | {path})
                indexes |= found
                reasons += more_reasons
                notes += more_notes
            return indexes, reasons, notes
        return set(), [LINK_INPUT_UNRESOLVED], [f"link input has no compile unit: {path}"]

    linked: list[PlannedModule] = []
    consumed: set[int] = set()
    archives = {path for path in producers if _suffix(path) in _STATIC_SUFFIXES}
    for output in sorted(producers):
        if output in archives:
            continue  # archives are expanded into the executables and shared libraries that link them
        indexes: set[int] = set()
        reasons: list[str] = []
        notes: list[str] = []
        for path in producers[output].get("input_paths", ()):
            found, more_reasons, more_notes = resolve_input(str(path), frozenset({output}))
            indexes |= found
            reasons += more_reasons
            notes += more_notes
        if not indexes:
            continue
        consumed |= indexes
        ordered = tuple(sorted(indexes))
        linked.append(PlannedModule(module_id(MODULE_LINK, output, ordered), MODULE_LINK, output, ordered,
                                    tuple(dict.fromkeys(reasons)), tuple(dict.fromkeys(notes))))
    standalone = [
        PlannedModule(module_id(MODULE_TRANSLATION_UNIT, str(row["target_path"]), (index,)),
                      MODULE_TRANSLATION_UNIT, str(row["target_path"]), (index,), (NOT_IN_LINK_UNIT,))
        for index, row in enumerate(compile_rows) if index not in consumed
    ]
    ordered_modules = [*linked, *standalone]
    kept, omitted = ordered_modules[:max_modules], ordered_modules[max_modules:]
    gaps = (f"module bound reached: {len(omitted)} of {len(ordered_modules)} planned modules were not analyzed",) \
        if omitted else ()
    return ModulePlan(tuple(kept), tuple(omitted), gaps)
