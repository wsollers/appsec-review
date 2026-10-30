"""Native build-output classification for one build unit: layout facts, capture, heuristics.

``register`` runs after the build commands and before the catalogue walk and records every
root in the unit's :class:`BuildOutputDispositions`. ``gaps`` runs after the walk, when each
tree's file and byte counts are known, and returns the unit's aggregated named gaps.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from appsec_review.config.assurance import ScopeRole
from appsec_review.jobs.build_output_scope import (
    BuildOutputDispositions, heuristic_gap, summarized_content_gap,
)
from appsec_review.jobs.job_language_build import native_layout
from appsec_review.jobs.job_language_build.native_layout import (
    DEPENDENCY_SOURCE, ROLE_DISPOSITIONS, LayoutRoot, Preexisting, discover, heuristic_roots,
)
from appsec_review.jobs.job_language_build.output_attribution import attribute, dependency_outputs

BUILD_DEPENDENCY = ScopeRole.BUILD_DEPENDENCY.value
# FOLLOW-UP(runtime_dependency): ScopeRole.RUNTIME_DEPENDENCY is owned by the dependency output
# filtering work (commit e9ae8d09, not yet on main). Until it lands, shared libraries a target
# ELF loads stay build_dependency, which routes to the same supply_chain lane.
_RUNTIME = getattr(ScopeRole, "RUNTIME_DEPENDENCY", None)
RUNTIME_DEPENDENCY = _RUNTIME.value if _RUNTIME is not None else None
_LINKED = frozenset({"executable", "shared-library", "static-library"})


@dataclass(slots=True)
class NativeClassification:
    """What ``register`` found, carried to the catalogue and to ``gaps``."""

    gaps: list[str] = field(default_factory=list)
    tagged_outputs: frozenset[str] = frozenset()
    file_api_query: str | None = None


def _covered(path: str, roots: Iterable[str]) -> bool:
    return any(path == root or path.startswith(root + "/") for root in roots)


def register(dispositions: BuildOutputDispositions, workspace: Path, *, build_dir: str, source_dir: str,
             build_system: str | None, preexisting_files: Iterable[str],
             captures: Sequence[Sequence[Mapping[str, Any]]], rows: Sequence[Mapping[str, Any]],
             capture_complete: bool, file_api_query: str | None = None,
             msbuild_properties: Mapping[str, str] | None = None) -> NativeClassification:
    """Discover and register this unit's dependency, bookkeeping and generator roots."""
    policy = dispositions.policy
    build_dir = "" if build_dir in {"", "."} else build_dir.strip("/")
    # The query this job wrote is not target content: it must not make the build tree look
    # target-owned to the "created by the build" tests.
    query_dir = _join(build_dir, ".cmake/api/v1/query") + "/" if file_api_query else None
    preexisting = Preexisting(path for path in preexisting_files
                              if query_dir is None or not path.startswith(query_dir))
    facts = discover(workspace, build_dir=build_dir, source_dir=source_dir, build_system=build_system,
                     preexisting=preexisting, discovery=policy.discovery, file_api_query=file_api_query,
                     msbuild_properties=msbuild_properties)
    for source in facts.sources:
        dispositions.add_layout_source(source.kind, source.path, source.sha256)
    result = NativeClassification(gaps=list(facts.gaps), file_api_query=file_api_query)
    roots: list[LayoutRoot] = list(facts.roots)
    sources = {root.root: root.name for root in roots if root.role == DEPENDENCY_SOURCE}
    ninja_rows = [{"inputs": list(inputs), "outputs": list(outputs), "origin": _join(build_dir, "build.ninja")}
                  for outputs, inputs in facts.ninja_edges]
    ninja_tagged: tuple[str, ...] = ()
    if ninja_rows and sources:
        ninja_roots, ninja_tagged = dependency_outputs(ninja_rows, sources, build_dir=build_dir,
                                                       preexisting=preexisting)
        roots.extend(dataclasses.replace(root, basis="build-system-fact") for root in ninja_roots)
    fact_roots = [root.root for root in roots]
    attribution = attribute(captures, [*rows, *ninja_rows], capture_complete=capture_complete,
                            preexisting=preexisting,
                            initial_directory=_logical(source_dir), build_dir=build_dir,
                            dependency_sources=sources,
                            evidence_ref="execution-capture")
    result.gaps.extend(attribution.gaps)
    roots.extend(root for root in attribution.roots if not _covered(root.root, fact_roots))
    covered = [root.root for root in roots]
    roots.extend(root for root in heuristic_roots(workspace, preexisting, covered)
                 if not _covered(root.root, covered))
    for root in roots:
        if dispositions.configured_directory(root.root):
            continue  # a configured [build_outputs] exclusion already names this tree
        disposition, keep_linked = ROLE_DISPOSITIONS[root.role]
        dispositions.classify_tree(
            root.root, disposition=disposition, basis=root.basis, name=root.name, reason=root.reason,
            evidence_ref=root.evidence_ref, confidence=root.confidence,
            scope_role=BUILD_DEPENDENCY if disposition == "supply_chain" else None, keep_linked=keep_linked)
    result.tagged_outputs = frozenset((*ninja_tagged, *attribution.tagged_outputs))
    return result


def _join(*parts: str) -> str:
    return "/".join(part for part in parts if part not in {"", "."})


def _logical(source_dir: str) -> str:
    relative = _join(*source_dir.strip("/").split("/"))
    return native_layout.WORKSPACE_LOGICAL + ("/" + relative if relative else "")


def tag_and_promote(artifacts: Sequence[dict[str, Any]], tagged_outputs: Collection[str]) -> None:
    """Tag dependency-sourced linked outputs in mixed directories; upgrade loaded libraries.

    Runs before ``apply_scope``. A kept shared library from a dependency tree whose file name or
    soname a target-lane executable or library names in ``DT_NEEDED`` becomes a runtime
    dependency when that scope role exists.
    """
    for artifact in artifacts:
        if (artifact.get("workspace_path") in tagged_outputs and artifact.get("scope_role") is None
                and artifact.get("kind") in _LINKED):
            artifact.update(scope_role=BUILD_DEPENDENCY, build_output_tag="dependency-sourced-output")
    if RUNTIME_DEPENDENCY is None:
        return
    needed = {str(name) for artifact in artifacts if artifact.get("scope_role") is None
              for name in artifact.get("loader_dependencies") or ()}
    for artifact in artifacts:
        if artifact.get("scope_role") != BUILD_DEPENDENCY or artifact.get("kind") != "shared-library":
            continue
        names = {str(artifact.get("workspace_path", "")).rsplit("/", 1)[-1], artifact.get("loader_soname")}
        if needed & {name for name in names if name}:
            artifact["scope_role"] = RUNTIME_DEPENDENCY


def gaps(dispositions: BuildOutputDispositions) -> list[str]:
    """One summarised gap per evidence source over supply-chain trees, plus heuristic gaps."""
    groups: dict[str, list[Mapping[str, Any]]] = {}
    heuristic: list[str] = []
    for root in dispositions.roots():
        if root["basis"] == "heuristic":
            heuristic.append(heuristic_gap(root["root"], root["disposition"], root["confidence"]))
        if root["disposition"] != "supply_chain":
            continue
        source = str(root.get("evidence_ref") or root["root"]).split("#", 1)[0]
        groups.setdefault(source, []).append(root)
    summarized: list[str] = []
    for source, members in sorted(groups.items()):
        names = {str(member["name"]) for member in members}
        noun = "native dependency" if len(names) == 1 else "native dependencies"
        summarized.append(summarized_content_gap(
            len(names), noun, sum(int(member["files"]) for member in members),
            sum(int(member["bytes"]) for member in members), source, "supply_chain"))
    return [*summarized, *heuristic]
