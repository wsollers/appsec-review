"""Execution-capture attribution of native build output to dependency or target content.

Two observations come from the capture the job already records:

- **Fetched trees.** The writer of every file the build creates is the image its pid was
  running, so a created directory whose build-system file a fetcher (``git``, ``curl``,
  ``tar``, ``cmake -E tar``, ``meson subprojects``) wrote, and whose created files fetchers
  mostly wrote, is a dependency source root.
- **Dependency outputs.** A compiler or linker output whose inputs all lie in dependency source
  roots, or are themselves dependency outputs, is dependency output. The highest directory
  holding only such outputs, and nothing the snapshot or the target's own sources hold, is a
  dependency output root. A directory mixing target and dependency outputs is never
  reclassified; its dependency outputs are returned for individual tagging.

An incomplete capture disables both and raises ``build-output-capture-incomplete``.
"""

from __future__ import annotations

import posixpath
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.container_runtime.capture_files import resolve_file_events
from appsec_review.jobs.job_language_build.native_layout import (
    BUILD_SYSTEM_FILES, DEPENDENCY_BOOKKEEPING, DEPENDENCY_OUTPUT, DEPENDENCY_SOURCE, WORKSPACE_LOGICAL,
    LayoutRoot, Preexisting, collapse,
)

CAPTURE_INCOMPLETE_GAP = "build-output-capture-incomplete"
_FETCHERS = frozenset({"curl", "wget", "tar", "bsdtar", "gtar", "unzip", "gzip", "gunzip", "xz", "unxz",
                       "bzip2", "bunzip2", "zstd", "unzstd", "7z", "7za", "patch"})
_CREATING = frozenset({"write", "read-write", "rename-target", "link-target"})


@dataclass(frozen=True, slots=True)
class Attribution:
    roots: list[LayoutRoot] = field(default_factory=list)
    # Dependency-sourced outputs that share a directory with target outputs.
    tagged_outputs: tuple[str, ...] = ()
    gaps: list[str] = field(default_factory=list)


def is_fetcher(executable: str, argv: Sequence[str]) -> bool:
    """Whether an exec image downloads or unpacks content rather than compiling it."""
    name = posixpath.basename(executable)
    if name in _FETCHERS or name == "git" or name.startswith("git-"):
        return True
    arguments = [str(value) for value in argv[1:]]
    if name == "cmake":
        return "-P" in arguments or any(arguments[index:index + 2] == ["-E", "tar"]
                                        for index in range(len(arguments)))
    if name == "meson" or (name.startswith("python") and arguments
                           and posixpath.basename(arguments[0]) in {"meson", "meson.py"}):
        return "subprojects" in arguments
    return False


def _key(event: Mapping[str, Any]) -> tuple[int, int]:
    return int(event.get("timestamp_ns", 0)), int(event.get("ordinal", 0))


def _images(events: Sequence[Mapping[str, Any]]) -> dict[int, tuple[list[tuple[int, int]], list[bool]]]:
    """Per pid, the time-ordered fetcher flag of the image it ran, inherited across forks."""
    timeline: dict[int, tuple[list[tuple[int, int]], list[bool]]] = {}

    def current(pid: int, at: tuple[int, int]) -> bool | None:
        keys, flags = timeline.get(pid, ([], []))
        index = bisect_right(keys, at) - 1
        return flags[index] if index >= 0 else None

    def record(pid: int, at: tuple[int, int], fetcher: bool) -> None:
        keys, flags = timeline.setdefault(pid, ([], []))
        keys.append(at)
        flags.append(fetcher)

    for event in sorted((item for item in events if item.get("kind") in {"process_exec", "process_fork"}),
                        key=_key):
        pid, at = int(event.get("pid", 0)), _key(event)
        if event["kind"] == "process_fork":
            inherited = current(pid, at)
            if inherited is not None:
                record(int(event.get("child_pid", -1)), at, inherited)
        elif event.get("result") == 0 and isinstance(event.get("executable"), str):
            argv = event.get("argv") if isinstance(event.get("argv"), list) else []
            record(pid, at, is_fetcher(str(event["executable"]), argv))
    return timeline


def created_writers(captures: Iterable[Sequence[Mapping[str, Any]]], *, initial_directory: str,
                    preexisting: Preexisting) -> dict[str, bool]:
    """Workspace-relative created files mapped to whether a fetcher created them last."""
    writers: dict[str, bool] = {}
    for events in captures:
        timeline = _images(events)
        resolved, _skipped = resolve_file_events(events, initial_directory)
        for event in resolved:
            if not event.succeeded:
                continue
            if not (event.path.startswith(WORKSPACE_LOGICAL + "/")):
                continue
            relative = event.path[len(WORKSPACE_LOGICAL) + 1:]
            if event.operation in {"unlink", "rename-source"}:
                writers.pop(relative, None)
                continue
            if event.operation not in _CREATING or not (event.creates or relative in writers):
                continue
            if preexisting.has_files_under(relative):
                continue
            keys, flags = timeline.get(event.pid, ([], []))
            index = bisect_right(keys, (event.timestamp_ns, event.ordinal)) - 1
            writers[relative] = bool(flags[index]) if index >= 0 else False
    return writers


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def fetched_roots(writers: Mapping[str, bool], preexisting: Preexisting, *, evidence_ref: str
                  ) -> list[LayoutRoot]:
    """Created directories a fetcher populated, each holding its own build-system file."""
    candidates = sorted({posixpath.dirname(path) for path, fetched in writers.items()
                         if fetched and posixpath.basename(path) in BUILD_SYSTEM_FILES})
    shallowest: list[str] = []
    for candidate in candidates:
        if candidate and not any(_under(candidate, kept) for kept in shallowest):
            shallowest.append(candidate)
    roots: list[LayoutRoot] = []
    for directory in shallowest:
        if not preexisting.created(directory):
            continue
        inside = [fetched for path, fetched in writers.items() if _under(path, directory)]
        fetched = sum(inside)
        if fetched * 2 <= len(inside):
            continue
        base = posixpath.basename(directory)
        name = base[:-4] if base.endswith("-src") and len(base) > 4 else base
        reason = (f"created during the build; {fetched} of {len(inside)} created files written by a fetcher "
                  f"and it holds its own build-system file")
        roots.append(LayoutRoot(directory, DEPENDENCY_SOURCE, "execution-capture", "high", name, reason,
                                evidence_ref))
        parent = posixpath.dirname(directory)
        prefix = posixpath.dirname(parent)
        if posixpath.basename(parent) == "src" and posixpath.basename(prefix) == f"{base}-prefix":
            # ExternalProject: <name>-prefix/src/<name> with -build, -stamp and tmp beside it.
            for path, role in ((f"{parent}/{base}-build", DEPENDENCY_OUTPUT),
                               (f"{parent}/{base}-stamp", DEPENDENCY_BOOKKEEPING),
                               (f"{prefix}/tmp", DEPENDENCY_BOOKKEEPING)):
                if preexisting.created(path) and any(_under(file, path) for file in writers):
                    roots.append(LayoutRoot(path, role, "execution-capture", "high", name,
                                            f"ExternalProject layout beside fetched {directory}", evidence_ref))
    return roots


def _paths(values: object) -> list[str]:
    result: list[str] = []
    for value in values if isinstance(values, list) else []:
        path = value.get("workspace_path") if isinstance(value, Mapping) else value
        if isinstance(path, str) and path:
            result.append(path)
    return result


def dependency_outputs(rows: Sequence[Mapping[str, Any]], sources: Mapping[str, str], *, build_dir: str,
                       preexisting: Preexisting) -> tuple[list[LayoutRoot], tuple[str, ...]]:
    """Dependency output roots, plus dependency outputs left in mixed directories."""
    edges = [(_paths(row.get("outputs")), _paths(row.get("inputs")), str(row.get("origin") or "execution-capture"))
             for row in rows]
    source_roots = sorted(sources)

    def source_of(path: str) -> str | None:
        return next((root for root in source_roots if _under(path, root)), None)

    dependency: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for outputs, inputs, origin in edges:
            if not outputs or not inputs or all(output in dependency for output in outputs):
                continue
            if all(source_of(path) is not None or path in dependency for path in inputs):
                for output in outputs:
                    dependency.setdefault(output, origin)
                changed = True
    target_outputs = sorted({output for outputs, _inputs, _origin in edges for output in outputs
                             if output not in dependency})
    target_inputs = sorted({path for outputs, inputs, _origin in edges for path in inputs
                            if source_of(path) is None and path not in dependency})

    def holds(directory: str, paths: Sequence[str]) -> bool:
        return any(_under(path, directory) for path in paths)

    def eligible(directory: str) -> bool:
        return (bool(directory) and directory != build_dir and preexisting.created(directory)
                and not holds(directory, target_outputs) and not holds(directory, target_inputs)
                and not any(_under(root, directory) for root in source_roots))

    def name_of(output: str) -> str:
        pending, seen, names = [output], set(), set()
        while pending:
            path = pending.pop()
            if path in seen:
                continue
            seen.add(path)
            root = source_of(path)
            if root is not None:
                names.add(sources[root])
            for outputs, inputs, _origin in edges:
                if path in outputs:
                    pending.extend(inputs)
        return names.pop() if len(names) == 1 else ""

    found: dict[str, tuple[str, str]] = {}
    tagged: list[str] = []
    for output, origin in sorted(dependency.items()):
        if source_of(output) is not None:
            continue  # built inside its own source root, already supply-chain content
        directory, best = posixpath.dirname(output), None
        while eligible(directory):
            best = directory
            directory = posixpath.dirname(directory)
        if best is None:
            tagged.append(output)
            continue
        current = found.get(best)
        name = name_of(output)
        found[best] = (origin if current is None else current[0],
                       name if current is None or current[1] == name else "")
    roots = [LayoutRoot(root, DEPENDENCY_OUTPUT, "execution-capture", "fact",
                        name or posixpath.basename(root),
                        "every captured compile and link output under it has only dependency-source inputs",
                        origin)
             for root, (origin, name) in found.items()]
    return collapse(roots), tuple(tagged)


def attribute(captures: Iterable[Sequence[Mapping[str, Any]]], rows: Sequence[Mapping[str, Any]], *,
              capture_complete: bool, preexisting: Preexisting, initial_directory: str, build_dir: str,
              dependency_sources: Mapping[str, str], evidence_ref: str = "execution-capture") -> Attribution:
    """Attribute created trees and compile outputs; known dependency sources seed the output pass."""
    if not capture_complete:
        return Attribution(gaps=[f"{CAPTURE_INCOMPLETE_GAP}: capture-basis build-output classification "
                                 "disabled; layout metadata and heuristics still apply"])
    writers = created_writers(captures, initial_directory=initial_directory, preexisting=preexisting)
    fetched = fetched_roots(writers, preexisting, evidence_ref=evidence_ref)
    sources = dict(dependency_sources)
    for root in fetched:
        if root.role == DEPENDENCY_SOURCE and not any(_under(root.root, known) for known in sources):
            sources[root.root] = root.name
    outputs, tagged = dependency_outputs(rows, sources, build_dir=build_dir, preexisting=preexisting)
    return Attribution(roots=fetched + outputs, tagged_outputs=tagged)
