"""Deterministic continuity derived from the accepted native build (``same_native_executable``).

Two source files that the accepted language build compiles into objects linked into one executable
or shared library execute inside one process image, so identity and privilege continuity across an
edge between constructs in those files hold at that stage. The derivation reads only run-owned,
hash-bound build facts (the protected compile database and the link database of an accepted native
build unit) and never a model's prose. Two different binaries do not prove separation, so the
derivation never contradicts; it either establishes the two dimensions or leaves them unresolved
with a named reason. Trust boundary, artifact/deployment and temporal continuity need deployment,
zone and timing facts this source does not have and always stay unresolved here.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

SAME_NATIVE_EXECUTABLE = "same_native_executable"
BASIS = "accepted_native_build_facts_not_model_prose"
SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm"})
STATIC_LIBRARY_SUFFIXES = (".a", ".lib")
NOT_LOCATED = "entity_has_no_accepted_source_location"
NOT_COMPILED = "source_not_compiled_by_accepted_native_build"
NOT_LINKED = "objects_not_linked_into_one_accepted_executable"
REASONS_UNRESOLVED = {
    "trust_boundary": "same_native_executable_derivation_has_no_zone_or_enforcement_facts",
    "artifact_deployment": "same_native_executable_derivation_has_no_deployment_facts",
    "temporal": "same_native_executable_derivation_has_no_temporal_facts",
}


def _static(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() in STATIC_LIBRARY_SUFFIXES


@dataclass(frozen=True, slots=True)
class CompiledObject:
    source_path: str
    source_sha256: str | None
    object_path: str
    object_sha256: str | None
    argv_sha256: str

    def document(self) -> dict[str, Any]:
        return {"source_path": self.source_path, "source_sha256": self.source_sha256,
                "object_path": self.object_path, "object_sha256": self.object_sha256,
                "argv_sha256": self.argv_sha256}


@dataclass(frozen=True, slots=True)
class LinkStep:
    command_sha256: str
    input_path: str
    output_path: str


@dataclass(frozen=True, slots=True)
class Derivation:
    """The outcome of deriving ``same_native_executable`` for one pair of source paths."""

    established: bool
    reason: str
    build_unit_id: str
    link_database_sha256: str
    document: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class UnitLinkFacts:
    """The compile and link rows of one accepted native build unit, indexed for the derivation."""

    build_unit_id: str
    compile_database: Mapping[str, str]       # {"path", "sha256"} of the bound protected compile database
    link_database: Mapping[str, str]          # {"path", "sha256"} of the bound link database
    objects: Mapping[str, tuple[CompiledObject, ...]]   # source path -> objects compiled from it
    links: Mapping[str, tuple[LinkStep, ...]]           # link input path -> link steps consuming it

    @classmethod
    def from_rows(cls, build_unit_id: str, compile_rows: Sequence[Mapping[str, Any]],
                  link_rows: Sequence[Mapping[str, Any]], *, compile_database: Mapping[str, str],
                  link_database: Mapping[str, str]) -> "UnitLinkFacts":
        objects: dict[str, list[CompiledObject]] = {}
        for row in compile_rows:
            if not isinstance(row, Mapping) or row.get("tool_kind") != "compiler":
                continue
            inputs = [item for item in row.get("inputs", ()) if isinstance(item, Mapping)
                      and isinstance(item.get("workspace_path"), str)
                      and PurePosixPath(item["workspace_path"]).suffix.lower() in SOURCE_SUFFIXES]
            outputs = [item for item in row.get("outputs", ()) if isinstance(item, Mapping)
                       and isinstance(item.get("workspace_path"), str)]
            argv_sha = row.get("argv_sha256")
            if not inputs or not outputs or not isinstance(argv_sha, str):
                continue
            for source in inputs:
                for output in outputs:
                    objects.setdefault(source["workspace_path"], []).append(CompiledObject(
                        source["workspace_path"], _sha(source.get("sha256")), output["workspace_path"],
                        _sha(output.get("sha256")), argv_sha))
        links: dict[str, list[LinkStep]] = {}
        for row in link_rows:
            if (not isinstance(row, Mapping) or not isinstance(row.get("output_path"), str)
                    or not isinstance(row.get("command_sha256"), str) or not isinstance(row.get("input_paths"), list)):
                continue
            for item in row["input_paths"]:
                if isinstance(item, str):
                    links.setdefault(item, []).append(LinkStep(row["command_sha256"], item, row["output_path"]))
        return cls(build_unit_id, dict(compile_database), dict(link_database),
                   {key: tuple(sorted(set(value), key=lambda item: (item.object_path, item.argv_sha256)))
                    for key, value in objects.items()},
                   {key: tuple(sorted(set(value), key=lambda item: (item.output_path, item.command_sha256)))
                    for key, value in links.items()})

    def binaries(self, source_path: str) -> dict[str, tuple[CompiledObject, LinkStep, str | None]]:
        """Final executables and shared libraries ``source_path`` links into: path -> (object, final link, via)."""
        found: dict[str, tuple[CompiledObject, LinkStep, str | None]] = {}
        for compiled in self.objects.get(source_path, ()):
            for step in self.links.get(compiled.object_path, ()):
                if _static(step.output_path):
                    # One hop: a static library is consumed by the link that produces the executable.
                    for hop in self.links.get(step.output_path, ()):
                        if not _static(hop.output_path):
                            found.setdefault(hop.output_path, (compiled, hop, step.output_path))
                else:
                    found.setdefault(step.output_path, (compiled, step, None))
        return found


def _sha(value: Any) -> str | None:
    return value if isinstance(value, str) and len(value) == 64 else None


class NativeLinkFacts:
    """Lookup over every accepted native build unit of the run."""

    def __init__(self, units: Sequence[UnitLinkFacts]) -> None:
        if not units:
            raise ValueError("native link facts need at least one accepted native build unit")
        self.units = tuple(sorted(units, key=lambda unit: unit.build_unit_id))

    @classmethod
    def from_run(cls, run_root: Path, *, loader: Callable[[Path], Mapping[str, Any]] | None = None
                 ) -> "NativeLinkFacts | None":
        """The run's accepted native build facts, or ``None`` when the run has no accepted native build.

        A bound compile or link database that changed after acceptance raises ``IntegrityError`` (from the
        accepted-build loader), never a different answer.
        """
        from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds
        if loader is None:
            from appsec_review.jobs.job_language_build import load_accepted_language_build

            def loader(root: Path) -> Mapping[str, Any]:
                # The review job declares job_language_build as an optional input: read it as one.
                return load_accepted_language_build(root, required=False)
        records = AcceptedBuilds(run_root, loader=loader).native_link_facts()
        units = [UnitLinkFacts.from_rows(record["build_unit_id"], record["compile_rows"], record["link_rows"],
                                         compile_database=record["protected_compile_commands"],
                                         link_database=record["link_database"]) for record in records]
        return cls(units) if units else None

    def derive(self, left_path: str | None, right_path: str | None) -> Derivation:
        """Whether ``left_path`` and ``right_path`` link into one accepted executable or shared library."""
        chosen = self.units[0]
        left = right = None
        link = None
        established, reason = False, NOT_LOCATED
        if left_path is not None and right_path is not None:
            reason = NOT_COMPILED
            for unit in self.units:
                lefts, rights = unit.binaries(left_path), unit.binaries(right_path)
                if lefts or rights:
                    chosen = unit
                if lefts and rights:
                    reason = NOT_LINKED
                    common = sorted(set(lefts) & set(rights))
                    if common:
                        binary = common[0]
                        left_object, final, left_via = lefts[binary]
                        right_object, _final, right_via = rights[binary]
                        left, right = left_object.document(), right_object.document()
                        link = {"output_path": binary, "command_sha256": final.command_sha256,
                                "left_via": left_via, "right_via": right_via}
                        established, reason = True, SAME_NATIVE_EXECUTABLE
                        break
                    if left is None:
                        left = next(iter(lefts.values()))[0].document()
                        right = next(iter(rights.values()))[0].document()
        document = {"policy": SAME_NATIVE_EXECUTABLE, "basis": BASIS, "build_unit_id": chosen.build_unit_id,
                    "bound_files": {"protected_compile_commands": dict(chosen.compile_database),
                                    "link_database": dict(chosen.link_database)},
                    "left": left, "right": right, "link": link}
        return Derivation(established, reason, chosen.build_unit_id, chosen.link_database["sha256"], document)


__all__ = ["BASIS", "CompiledObject", "Derivation", "LinkStep", "NativeLinkFacts", "REASONS_UNRESOLVED",
           "SAME_NATIVE_EXECUTABLE", "UnitLinkFacts"]
