"""Bounded readers for native build-system layout metadata (docs/architecture/native-build-output-discovery.md).

A native build creates dependency trees inside the workspace: CMake ``FetchContent`` sources and
build trees, Meson wrap subprojects, vcpkg manifest-mode installs and Conan generator output.
These readers find them from metadata the build system itself wrote, without executing any build
tool:

- ``CMakeCache.txt``: the ``<PROJECT>_SOURCE_DIR``/``_BINARY_DIR``/``_IS_TOP_LEVEL`` entries that
  ``project()`` writes, ``FETCHCONTENT_BASE_DIR`` and ``FETCHCONTENT_SOURCE_DIR_<NAME>``, and
  ``VCPKG_INSTALLED_DIR``;
- the CMake file API ``codemodel-v2`` reply for the stateless ``client-appsec-review`` query;
- Meson ``meson-info`` introspection;
- a static ``build.ninja`` parse (``build``, ``subninja`` and ``include``);
- the vcpkg ``status`` database and ``info/*.list`` ownership records;
- MSBuild ``OutDir``/``IntDir`` and Conan generator directories.

Every metadata file read is pinned by SHA-256 and counted against the configured bounds. A missing
file is silence; an oversized, excess or malformed file is a named gap, and nothing it would have
classified is classified, so that tree stays per-file target content. A dependency tree is only
reported when it was created during the build: content present in the pre-build snapshot is
accepted target content (a committed subproject is annotated, never reclassified).
"""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
from typing import Any
from xml.etree import ElementTree

from appsec_review.config.build_outputs import BuildOutputDiscovery


WORKSPACE_LOGICAL = "/workspace"
FILE_API_CLIENT = "client-appsec-review"
FILE_API_QUERY = {"requests": [{"kind": "codemodel", "version": 2},
                               {"kind": "cmakeFiles", "version": 1}]}
BUILD_SYSTEM_FILES = frozenset({"CMakeLists.txt", "meson.build", "configure", "Makefile", "makefile",
                                "GNUmakefile"})
# The design's dependency directory names plus job_dependency_intelligence's vendored-source set.
HEURISTIC_NAMES = frozenset({"_deps", "subprojects", "vcpkg_installed", "external", "third_party",
                             "third-party", "vendor", "vendors", "deps", "dependencies"})

# Layout roles and how a cataloguer treats each (build_output_scope dispositions).
DEPENDENCY_SOURCE = "dependency-source"
DEPENDENCY_OUTPUT = "dependency-output"
DEPENDENCY_BOOKKEEPING = "dependency-bookkeeping"
GENERATOR_OUTPUT = "generator-output"
TARGET_SUBPROJECT = "target-subproject"
ROLE_DISPOSITIONS: Mapping[str, tuple[str, bool]] = {
    DEPENDENCY_SOURCE: ("supply_chain", True),
    DEPENDENCY_OUTPUT: ("supply_chain", True),
    DEPENDENCY_BOOKKEEPING: ("evidence", False),
    GENERATOR_OUTPUT: ("supply_chain", False),
    TARGET_SUBPROJECT: ("per_file", False),
}

_CACHE_LINE = re.compile(r'^(?:"([^"]+)"|([^:="]+)):([A-Z_]+)=(.*)$')
_MSBUILD_MACRO = re.compile(r"\$\(([A-Za-z_][A-Za-z0-9_]*)\)")
_MSBUILD_MACROS = frozenset({"Configuration", "Platform", "ProjectDir", "SolutionDir"})


@dataclass(frozen=True, slots=True)
class LayoutSource:
    kind: str
    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class LayoutRoot:
    """One directory a build-system fact or installer record names, with its role."""

    root: str
    role: str
    basis: str
    confidence: str
    name: str
    reason: str
    evidence_ref: str


@dataclass(slots=True)
class LayoutFacts:
    roots: list[LayoutRoot] = field(default_factory=list)
    sources: list[LayoutSource] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    # Static Ninja edges for builds no CMake or Meson metadata describes: (outputs, inputs).
    ninja_edges: list[tuple[tuple[str, ...], tuple[str, ...]]] = field(default_factory=list)
    # MSBuild output and intermediate directories; target content, recorded for attribution.
    output_directories: list[str] = field(default_factory=list)


# Paths -------------------------------------------------------------------------------------


def workspace_relative(value: Any, base: str = "", *, workspace: Path | None = None) -> str | None:
    """Map a container, host or base-relative path to a workspace-relative POSIX path.

    Returns ``""`` for the workspace root and ``None`` for anything outside it or malformed.
    """
    if not isinstance(value, str) or not value or "\0" in value:
        return None
    text = value.replace("\\", "/")
    host = workspace.resolve().as_posix() if workspace is not None else None
    if text == WORKSPACE_LOGICAL or text.startswith(WORKSPACE_LOGICAL + "/"):
        logical = text[len(WORKSPACE_LOGICAL):]
    elif host is not None and (text == host or text.startswith(host + "/")):
        logical = text[len(host):]
    elif text.startswith("/") or re.match(r"^[A-Za-z]:/", text):
        return None
    else:
        logical = posixpath.join(base, text) if base else text
    relative = posixpath.normpath(logical.lstrip("/") or ".")
    if relative == ".." or relative.startswith("../"):
        return None
    return "" if relative == "." else relative


def _join(*parts: str) -> str:
    return "/".join(part for part in parts if part not in {"", "."})


def _under(path: str, root: str) -> bool:
    return not root or path == root or path.startswith(root + "/")


class Preexisting:
    """Answers whether a workspace directory held any file before the build started."""

    def __init__(self, files: Iterable[str]) -> None:
        self._files = sorted(files)

    def has_files_under(self, directory: str) -> bool:
        if not directory:
            return bool(self._files)
        prefix = directory + "/"
        index = bisect_left(self._files, prefix)
        return (index < len(self._files) and self._files[index].startswith(prefix)) or \
            directory in self._files

    def created(self, directory: str) -> bool:
        return bool(directory) and not self.has_files_under(directory)


# Bounded reading ---------------------------------------------------------------------------


class SourceReader:
    """Reads layout metadata files under the configured count and byte bounds."""

    def __init__(self, workspace: Path, discovery: BuildOutputDiscovery) -> None:
        self.workspace = workspace
        self.discovery = discovery
        self.sources: list[LayoutSource] = []
        self.gaps: list[str] = []
        self.skipped = 0

    def exists(self, relative: str) -> bool:
        path = self.workspace / Path(*PurePosixPath(relative).parts) if relative else self.workspace
        return path.exists() and not path.is_symlink()

    def read(self, relative: str, kind: str) -> bytes | None:
        """The file's bytes, or ``None`` when absent or over a bound (bounds raise a gap)."""
        path = self.workspace / Path(*PurePosixPath(relative).parts)
        try:
            if path.is_symlink() or not path.is_file():
                return None
            size = path.stat().st_size
        except OSError:
            return None
        if len(self.sources) >= self.discovery.max_layout_sources:
            self.skipped += 1
            return None
        if size > self.discovery.max_layout_source_bytes:
            self.gaps.append(f"build-output-layout-source-bound-exceeded: {relative} is {size} bytes, over "
                             f"max_layout_source_bytes {self.discovery.max_layout_source_bytes}; "
                             "the trees it describes stay per-file target content")
            return None
        try:
            data = path.read_bytes()
        except OSError as exc:
            self.gaps.append(f"build-output-layout-source-unreadable: {relative}: {exc}")
            return None
        self.sources.append(LayoutSource(kind, relative, hashlib.sha256(data).hexdigest()))
        return data

    def text(self, relative: str, kind: str) -> str | None:
        data = self.read(relative, kind)
        if data is None:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            self.malformed(relative, exc)
            return None

    def json(self, relative: str, kind: str) -> Any:
        text = self.text(relative, kind)
        if text is None:
            return None
        try:
            return json.loads(text)
        except ValueError as exc:
            self.malformed(relative, exc)
            return None

    def malformed(self, relative: str, reason: Any) -> None:
        self.gaps.append(f"build-output-layout-source-malformed: {relative}: {reason}; "
                         "the trees it describes stay per-file target content")

    def finish(self) -> list[str]:
        if self.skipped:
            self.gaps.append(f"build-output-layout-source-limit: {self.skipped} metadata files beyond "
                             f"max_layout_sources {self.discovery.max_layout_sources} were not read; "
                             "the trees they describe stay per-file target content")
            self.skipped = 0
        return self.gaps


# CMake -------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CMakeProject:
    name: str
    source: str | None
    binary: str | None
    top_level: bool
    evidence_ref: str


@dataclass(frozen=True, slots=True)
class CMakeLayout:
    path: str
    home: str | None
    binary: str | None
    fetch_base: str | None
    fetch_overrides: Mapping[str, str]
    vcpkg_installed: str | None
    vcpkg_triplet: str | None
    projects: tuple[CMakeProject, ...]


def read_cmake_cache(reader: SourceReader, build_dir: str) -> CMakeLayout | None:
    relative = _join(build_dir, "CMakeCache.txt")
    text = reader.text(relative, "cmake-cache")
    if text is None:
        return None
    entries: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith(("//", "#")):
            continue
        match = _CACHE_LINE.match(line)
        if match:
            entries[match.group(1) or match.group(2)] = match.group(4)
    if "CMAKE_CACHEFILE_DIR" not in entries and "CMAKE_HOME_DIRECTORY" not in entries:
        reader.malformed(relative, "no CMAKE_HOME_DIRECTORY or CMAKE_CACHEFILE_DIR entry")
        return None
    ws = reader.workspace

    def mapped(value: str | None) -> str | None:
        return workspace_relative(value, workspace=ws) if value else None

    home = mapped(entries.get("CMAKE_HOME_DIRECTORY"))
    binary = mapped(entries.get("CMAKE_CACHEFILE_DIR"))
    if binary is None:
        binary = build_dir if build_dir not in {"", "."} else ""
    fetch_base = mapped(entries.get("FETCHCONTENT_BASE_DIR")) or _join(binary, "_deps")
    overrides = {key[len("FETCHCONTENT_SOURCE_DIR_"):]: value for key, raw in entries.items()
                 if key.startswith("FETCHCONTENT_SOURCE_DIR_") and (value := mapped(raw))}
    projects = []
    for key, value in sorted(entries.items()):
        if not key.endswith("_SOURCE_DIR") or key.startswith(("CMAKE_", "FETCHCONTENT_")):
            continue
        name = key[:-len("_SOURCE_DIR")]
        if f"{name}_BINARY_DIR" not in entries:
            continue
        source = mapped(value)
        top = entries.get(f"{name}_IS_TOP_LEVEL", "").upper() in {"ON", "TRUE", "1", "YES"} or (
            source is not None and source == home)
        projects.append(CMakeProject(name, source, mapped(entries[f"{name}_BINARY_DIR"]), top,
                                     f"{relative}#{name}_SOURCE_DIR"))
    return CMakeLayout(relative, home, binary, fetch_base, overrides,
                       mapped(entries.get("VCPKG_INSTALLED_DIR")), entries.get("VCPKG_TARGET_TRIPLET"),
                       tuple(projects))


def write_cmake_file_api_query(workspace: Path, build_dir: str) -> str:
    """Write the stateless client query CMake answers on its next configure; returns its path."""
    relative = _join(build_dir, ".cmake/api/v1/query", FILE_API_CLIENT, "query.json")
    path = workspace / Path(*PurePosixPath(relative).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(FILE_API_QUERY, sort_keys=True) + "\n", encoding="utf-8")
    return relative


def read_cmake_file_api(reader: SourceReader, build_dir: str) -> tuple[CMakeProject, ...] | None:
    """Projects from the codemodel-v2 reply to our client query; ``None`` when there is no reply."""
    reply = _join(build_dir, ".cmake/api/v1/reply")
    directory = reader.workspace / Path(*PurePosixPath(reply).parts)
    try:
        indices = sorted(entry.name for entry in os.scandir(directory)
                         if entry.name.startswith("index-") and entry.name.endswith(".json")
                         and entry.is_file(follow_symlinks=False))
    except OSError:
        return None
    if not indices:
        return None
    index_path = _join(reply, indices[-1])
    index = reader.json(index_path, "cmake-file-api-index")
    if index is None:
        return ()
    codemodel_file = None
    client = index.get("reply", {}).get(FILE_API_CLIENT, {}) if isinstance(index, Mapping) else {}
    responses = client.get("query.json", {}).get("responses", ()) if isinstance(client, Mapping) else ()
    candidates = [*(responses if isinstance(responses, list) else ()),
                  *(index.get("objects", ()) if isinstance(index, Mapping) else ())]
    for item in candidates:
        if isinstance(item, Mapping) and item.get("kind") == "codemodel" and isinstance(item.get("jsonFile"), str):
            codemodel_file = item["jsonFile"]
            break
    if codemodel_file is None or "/" in codemodel_file or "\\" in codemodel_file:
        reader.malformed(index_path, "no codemodel reply")
        return ()
    model_path = _join(reply, codemodel_file)
    model = reader.json(model_path, "cmake-file-api-codemodel")
    if model is None:
        return ()
    try:
        source_top = workspace_relative(model["paths"]["source"], workspace=reader.workspace)
        build_top = workspace_relative(model["paths"]["build"], workspace=reader.workspace)
        configuration = model["configurations"][0]
        directories = configuration["directories"]
        projects = []
        for project in configuration["projects"]:
            first = directories[project["directoryIndexes"][0]]
            source = workspace_relative(first["source"], source_top or "", workspace=reader.workspace)
            binary = workspace_relative(first["build"], build_top or "", workspace=reader.workspace)
            projects.append(CMakeProject(str(project["name"]), source, binary, "parentIndex" not in project,
                                         f"{model_path}#projects/{project['name']}"))
    except (KeyError, IndexError, TypeError, AttributeError) as exc:
        reader.malformed(model_path, f"unexpected codemodel shape: {exc!r}")
        return ()
    return tuple(projects)


def cmake_roots(cache: CMakeLayout | None, codemodel: Sequence[CMakeProject] | None,
                preexisting: Preexisting) -> list[LayoutRoot]:
    """Dependency source, output and sub-build roots for projects a FetchContent build created."""
    fetch_base = cache.fetch_base if cache is not None else None
    if fetch_base is None and codemodel:
        top = next((project for project in codemodel if project.top_level), None)
        fetch_base = _join(top.binary, "_deps") if top is not None and top.binary is not None else None
    overrides = set(cache.fetch_overrides.values()) if cache is not None else set()
    roots: dict[str, LayoutRoot] = {}
    for project in [*(cache.projects if cache is not None else ()), *(codemodel or ())]:
        source = project.source
        if project.top_level or not source or not preexisting.created(source):
            continue
        if not ((fetch_base and _under(source, fetch_base) and source != fetch_base) or source in overrides):
            continue
        reason = "FetchContent source" if fetch_base and _under(source, fetch_base) else "FetchContent override source"
        roots.setdefault(source, LayoutRoot(source, DEPENDENCY_SOURCE, "build-system-fact", "fact",
                                            project.name, reason, project.evidence_ref))
        if project.binary and preexisting.created(project.binary):
            roots.setdefault(project.binary, LayoutRoot(
                project.binary, DEPENDENCY_OUTPUT, "build-system-fact", "fact", project.name,
                "FetchContent build tree", project.evidence_ref.replace("_SOURCE_DIR", "_BINARY_DIR")))
        leaf = PurePosixPath(source)
        if leaf.name.endswith("-src"):
            subbuild = str(leaf.with_name(leaf.name[:-len("-src")] + "-subbuild"))
            roots.setdefault(subbuild, LayoutRoot(subbuild, DEPENDENCY_BOOKKEEPING, "build-system-fact", "fact",
                                                  project.name, "FetchContent download sub-build",
                                                  project.evidence_ref))
    return collapse(roots.values())


# Meson -------------------------------------------------------------------------------------


def read_meson_info(reader: SourceReader, build_dir: str, preexisting: Preexisting) -> list[LayoutRoot] | None:
    """Subproject source and output roots from Meson introspection; ``None`` without ``meson-info``."""
    info_dir = _join(build_dir, "meson-info")
    if not reader.exists(info_dir):
        return None
    info = reader.json(_join(info_dir, "meson-info.json"), "meson-info")
    projects = reader.json(_join(info_dir, "intro-projects.json"), "meson-intro-projects")
    targets = reader.json(_join(info_dir, "intro-targets.json"), "meson-intro-targets")
    if info is None or projects is None or targets is None:
        return []
    try:
        source_top = workspace_relative(info["directories"]["source"], workspace=reader.workspace)
        build_top = workspace_relative(info["directories"]["build"], workspace=reader.workspace)
        subproject_dir = str(projects.get("subproject_dir") or "subprojects")
        names = [str(item["name"]) for item in projects.get("subprojects", ())]
        if source_top is None or build_top is None or not isinstance(targets, list):
            raise TypeError("source or build directory is outside the workspace")
    except (KeyError, TypeError, AttributeError) as exc:
        reader.malformed(info_dir, f"unexpected introspection shape: {exc!r}")
        return []
    source_base, build_base = _join(source_top, subproject_dir), _join(build_top, subproject_dir)
    sources: dict[str, str] = {}
    outputs: dict[str, set[str]] = {}
    for target in targets:
        if not isinstance(target, Mapping) or not target.get("subproject"):
            continue
        name = str(target["subproject"])
        defined = workspace_relative(target.get("defined_in"), workspace=reader.workspace)
        if defined and _under(defined, source_base) and defined != source_base:
            sources.setdefault(name, _join(source_base, defined[len(source_base) + 1:].split("/")[0]))
        for filename in target.get("filename") or ():
            output = workspace_relative(filename, build_top, workspace=reader.workspace)
            if output and _under(output, build_base) and output != build_base:
                outputs.setdefault(name, set()).add(_join(build_base, output[len(build_base) + 1:].split("/")[0]))
    roots: list[LayoutRoot] = []
    reference = _join(info_dir, "intro-targets.json")
    for name in sorted(set(names) | set(sources) | set(outputs)):
        source = sources.get(name, _join(source_base, name))
        created = preexisting.created(source)
        for root, role in [(source, DEPENDENCY_SOURCE), *((item, DEPENDENCY_OUTPUT)
                                                           for item in sorted(outputs.get(name, ())))]:
            if created:
                reason = "Meson wrap subproject" if role == DEPENDENCY_SOURCE else "Meson subproject build output"
                roots.append(LayoutRoot(root, role, "build-system-fact", "fact", name, reason, reference))
            else:
                roots.append(LayoutRoot(root, TARGET_SUBPROJECT, "build-system-fact", "fact", name,
                                        f"committed Meson subproject {name} stays target content", reference))
    return roots


# Ninja -------------------------------------------------------------------------------------


def _ninja_tokens(text: str) -> list[str]:
    tokens, current, index = [], [], 0
    while index < len(text):
        char = text[index]
        if char == "$" and index + 1 < len(text):
            following = text[index + 1]
            if following in " :$":
                current.append(following)
                index += 2
                continue
            current.append("$" + following)
            index += 2
            continue
        if char == " ":
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)
        index += 1
    if current:
        tokens.append("".join(current))
    return tokens


def _ninja_split_colon(text: str) -> tuple[str, str] | None:
    index = 0
    while index < len(text):
        if text[index] == "$":
            index += 2
            continue
        if text[index] == ":":
            return text[:index], text[index + 1:]
        index += 1
    return None


def _ninja_lines(text: str) -> Iterable[str]:
    pending = ""
    for raw in text.splitlines():
        line = raw if not pending else pending + raw.lstrip(" ")
        stripped = line.rstrip()
        trailing = len(stripped) - len(stripped.rstrip("$"))
        if trailing % 2 == 1:
            pending = stripped[:-1]
            continue
        pending = ""
        yield line


def read_ninja(reader: SourceReader, build_dir: str) -> list[tuple[tuple[str, ...], tuple[str, ...]]] | None:
    """Static ``build`` edges (outputs, inputs) of ``build.ninja`` and what it includes.

    ``None`` when there is no ``build.ninja`` or the edge bound was exceeded (a gap).
    Paths holding unexpanded variables are skipped; order-only inputs are not inputs.
    """
    start = _join(build_dir, "build.ninja")
    if not reader.exists(start):
        return None
    edges: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
    pending, seen = [start], set()
    limit = reader.discovery.max_ninja_edges

    def mapped(values: Iterable[str]) -> tuple[str, ...]:
        return tuple(item for value in values if "$" not in value
                     and (item := workspace_relative(value, build_dir, workspace=reader.workspace)))

    while pending:
        current = pending.pop(0)
        if current in seen:
            continue
        seen.add(current)
        text = reader.text(current, "ninja")
        if text is None:
            continue
        for line in _ninja_lines(text):
            if line.startswith(("subninja ", "include ")):
                target = _ninja_tokens(line.split(" ", 1)[1].strip())
                if target and "$" not in target[0]:
                    included = workspace_relative(target[0], build_dir, workspace=reader.workspace)
                    if included:
                        pending.append(included)
                continue
            if not line.startswith("build "):
                continue
            split = _ninja_split_colon(line[len("build "):])
            if split is None:
                reader.malformed(current, "a build statement has no ':'")
                return None
            outputs = [token for token in _ninja_tokens(split[0]) if token != "|"]
            right = _ninja_tokens(split[1])
            if not right or right[0] == "phony":
                continue
            inputs: list[str] = []
            for token in right[1:]:
                if token in {"||", "|@"}:
                    break
                if token != "|":
                    inputs.append(token)
            if len(edges) >= limit:
                reader.gaps.append(f"build-output-ninja-edge-bound-exceeded: {start} has more than "
                                   f"max_ninja_edges {limit} edges; Ninja-derived attribution is not used")
                return None
            edges.append((mapped(outputs), mapped(inputs)))
    return edges


# vcpkg -------------------------------------------------------------------------------------


def read_vcpkg_installed(reader: SourceReader, installed: str, preexisting: Preexisting) -> LayoutRoot | None:
    """The manifest-mode installed tree when vcpkg's own status database records it."""
    if not installed or not reader.exists(installed) or not preexisting.created(installed):
        return None
    status_path = _join(installed, "vcpkg/status")
    status = reader.text(status_path, "vcpkg-status")
    if status is None:
        return None
    ports = []
    for paragraph in re.split(r"\n\s*\n", status):
        fields = dict(line.split(": ", 1) for line in paragraph.splitlines() if ": " in line)
        if fields.get("Status", "").endswith(" installed") and fields.get("Package"):
            if fields.get("Feature"):
                continue
            ports.append((fields["Package"], fields.get("Version", ""), fields.get("Architecture", "")))
    if not ports:
        reader.malformed(status_path, "no installed port is recorded")
        return None
    info_dir = reader.workspace / Path(*PurePosixPath(_join(installed, "vcpkg/info")).parts)
    try:
        lists = sorted(entry.name for entry in os.scandir(info_dir)
                       if entry.name.endswith(".list") and entry.is_file(follow_symlinks=False))
    except OSError:
        lists = []
    owned = 0
    for name in lists:
        gaps, skipped = len(reader.gaps), reader.skipped
        text = reader.text(_join(installed, "vcpkg/info", name), "vcpkg-info")
        if text is None:
            if len(reader.gaps) > gaps or reader.skipped > skipped:
                return None  # an ownership record over a bound: the tree stays per-file
            continue
        owned += sum(1 for line in text.splitlines() if line and not line.endswith("/"))
    names = ", ".join(sorted(port for port, _version, _triplet in ports)[:8])
    return LayoutRoot(installed, DEPENDENCY_OUTPUT, "installer-record", "fact", "vcpkg",
                      f"vcpkg manifest-mode install of {len(ports)} ports ({names}); {owned} files recorded "
                      "in vcpkg/info", status_path)


# MSBuild and Conan (phase 3) ----------------------------------------------------------------


def read_msbuild_dirs(reader: SourceReader, project_files: Sequence[str],
                      properties: Mapping[str, str]) -> list[str]:
    """Literal or recipe-expandable ``OutDir``/``IntDir`` values; anything else is a gap."""
    directories: list[str] = []
    for project in project_files:
        text = reader.text(project, "msbuild-project")
        if text is None:
            continue
        try:
            document = ElementTree.fromstring(text)
        except ElementTree.ParseError as exc:
            reader.malformed(project, exc)
            continue
        base = posixpath.dirname(project)
        values = {"ProjectDir": (base + "/") if base else "", **properties}
        for element in document.iter():
            tag = element.tag.rsplit("}", 1)[-1]
            if tag not in {"OutDir", "IntDir"} or not (element.text or "").strip():
                continue
            raw = element.text.strip()
            unsupported = sorted({name for name in _MSBUILD_MACRO.findall(raw)
                                  if name not in _MSBUILD_MACROS or name not in values})
            if unsupported or "%(" in raw or "@(" in raw:
                reader.gaps.append(f"build-output-msbuild-directory-unresolved: {project} {tag} {raw!r} uses "
                                   f"{', '.join(unsupported) or 'item metadata'} the recipe does not state")
                continue
            expanded = _MSBUILD_MACRO.sub(lambda match: values[match.group(1)], raw).replace("\\", "/")
            mapped = workspace_relative(expanded.rstrip("/"), base, workspace=reader.workspace)
            if mapped and mapped not in directories:
                directories.append(mapped)
    return directories


def read_conan_generators(reader: SourceReader, build_dir: str, preexisting: Preexisting) -> list[LayoutRoot]:
    """Dedicated, build-created Conan ``generators`` directories under the build directory."""
    roots = []
    base = reader.workspace / Path(*PurePosixPath(build_dir).parts) if build_dir not in {"", "."} else reader.workspace
    candidates = [_join(build_dir, "generators")]
    try:
        candidates.extend(_join(build_dir, entry.name, "generators") for entry in sorted(
            os.scandir(base), key=lambda entry: entry.name) if entry.is_dir(follow_symlinks=False))
    except OSError:
        pass
    for candidate in candidates:
        marker = next((name for name in ("conan_toolchain.cmake", "conanbuild.sh", "conanbuild.bat",
                                          "conaninfo.txt") if reader.exists(_join(candidate, name))), None)
        if marker is None or not preexisting.created(candidate):
            continue
        evidence = _join(candidate, marker)
        if reader.read(evidence, "conan-generator") is None:
            continue
        roots.append(LayoutRoot(candidate, GENERATOR_OUTPUT, "build-system-fact", "fact", "conan-generators",
                                "Conan generator output", evidence))
    return roots


# Heuristic ---------------------------------------------------------------------------------


def heuristic_roots(workspace: Path, preexisting: Preexisting, covered: Iterable[str]) -> list[LayoutRoot]:
    """Build-created children of dependency-named directories that no fact covers.

    Confidence is ``medium`` when the child holds its own build-system file and ``low`` for a
    name alone. Pre-existing content is never a candidate.
    """
    covered = sorted(set(covered))
    roots: list[LayoutRoot] = []

    def is_covered(path: str) -> bool:
        return any(_under(path, root) or _under(root, path) for root in covered)

    def descend(directory: Path, relative: str) -> None:
        try:
            with os.scandir(directory) as iterator:
                entries = sorted((entry for entry in iterator if entry.is_dir(follow_symlinks=False)
                                  and not entry.is_symlink()), key=lambda entry: entry.name)
        except OSError:
            return
        named = PurePosixPath(relative).name.casefold() in HEURISTIC_NAMES if relative else False
        for entry in entries:
            child = _join(relative, entry.name)
            if entry.name in {".git", ".hg", ".svn"} or any(_under(child, root) for root in covered):
                continue
            if named and preexisting.created(child) and not is_covered(child):
                build_file = any((Path(entry.path) / name).is_file() for name in BUILD_SYSTEM_FILES)
                roots.append(LayoutRoot(child, DEPENDENCY_SOURCE, "heuristic", "medium" if build_file else "low",
                                        entry.name, f"build-created child of '{PurePosixPath(relative).name}'"
                                        + (" holding its own build-system file" if build_file else ""),
                                        child))
                continue
            descend(Path(entry.path), child)

    descend(workspace, "")
    return roots


# Composition -------------------------------------------------------------------------------


def collapse(roots: Iterable[LayoutRoot]) -> list[LayoutRoot]:
    """Drop roots nested inside another root of the same role; the outer one already governs."""
    ordered = sorted(roots, key=lambda item: (item.root.count("/"), item.root))
    kept: list[LayoutRoot] = []
    for item in ordered:
        if any(other.role == item.role and _under(item.root, other.root) for other in kept):
            continue
        kept.append(item)
    return sorted(kept, key=lambda item: item.root)


def discover(workspace: Path, *, build_dir: str, source_dir: str, build_system: str | None,
             preexisting: Preexisting, discovery: BuildOutputDiscovery,
             file_api_query: str | None = None, msbuild_properties: Mapping[str, str] | None = None) -> LayoutFacts:
    """Read every applicable metadata source for one native build unit (no heuristic)."""
    build_dir = "" if build_dir in {"", "."} else build_dir.strip("/")
    reader = SourceReader(workspace, discovery)
    facts = LayoutFacts()
    cache = read_cmake_cache(reader, build_dir)
    codemodel = None
    if file_api_query is not None or cache is not None:
        codemodel = read_cmake_file_api(reader, build_dir)
        if codemodel is None and file_api_query is not None:
            facts.gaps.append(f"cmake-file-api-reply-missing: {_join(build_dir, '.cmake/api/v1/reply') or '.'} "
                              "holds no reply to the appsec-review query; CMake layout comes from the cache only")
    roots = cmake_roots(cache, codemodel, preexisting) if (cache is not None or codemodel) else []
    meson = read_meson_info(reader, build_dir, preexisting)
    roots.extend(meson or ())
    if cache is None and meson is None:
        edges = read_ninja(reader, build_dir)
        facts.ninja_edges = edges or []
    installed = (cache.vcpkg_installed if cache is not None and cache.vcpkg_installed else
                 _join(build_dir, "vcpkg_installed"))
    vcpkg = read_vcpkg_installed(reader, installed, preexisting)
    if vcpkg is not None:
        roots.append(vcpkg)
    roots.extend(read_conan_generators(reader, build_dir, preexisting))
    if build_system == "msbuild":
        projects = sorted(str(path.relative_to(workspace).as_posix())
                          for path in (workspace / Path(*PurePosixPath(source_dir).parts)).glob("*.vcxproj")
                          if path.is_file() and not path.is_symlink())
        facts.output_directories = read_msbuild_dirs(reader, projects, dict(msbuild_properties or {}))
    facts.roots = roots
    facts.sources = list(reader.sources)
    facts.gaps.extend(reader.finish())
    return facts
