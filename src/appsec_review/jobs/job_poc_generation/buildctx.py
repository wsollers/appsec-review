"""The accepted native build that contains a PoC's sink, read from the run (never from the target).

``job_language_build`` leaves, per native build unit, a hash-bound workspace (source and build
outputs, with a manifest of file hashes), a protected compile database holding the exact argv of
every compiler invocation the build captured, the image the build ran in and the object files it
produced. This module finds the unit and the compiler invocation of the sink's translation unit and
copies the verified workspace into a disposable scratch directory. The copy is hash-checked file by
file: a workspace that changed after acceptance is an :class:`IntegrityError`, not a different build.

The language-build receipts are consumed through the same loader the sanitizer job uses, so the
integrity rules (accepted pointer, receipt set hash, swift policy) are the ones the build owner wrote.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from appsec_review.container_runtime.project_images import derived_base_image_id
from appsec_review.indexing.build_facts import classify_command
from appsec_review.review.models import IntegrityError
from appsec_review.storage import canonical_json, file_sha256

COMPILE_DATABASE_SCHEMA = "appsec-review/protected-compile-commands/1"
SOURCE_SUFFIXES = {".c": "c", ".cc": "cxx", ".cpp": "cxx", ".cxx": "cxx", ".c++": "cxx"}
HEADER_SUFFIXES = (".h", ".hh", ".hpp", ".hxx", ".inc", ".ipp", ".tcc")
CONTAINER_ROOT = "/workspace"
OBJECT_KINDS = ("object", "static-library")
SHARED_KINDS = ("shared-library",)


@dataclass(frozen=True, slots=True)
class CompileCommand:
    """The exact compiler invocation the accepted build used for the translation unit."""

    argv: tuple[str, ...]
    source: str                       # workspace-relative path of the translation unit
    language: str                     # c or cxx
    working_directory: str            # workspace-relative directory to run derived commands in
    basis: str                        # exact (the sink's file was compiled) or unit_default (a header)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json(list(self.argv))).hexdigest()

    def facts(self) -> dict[str, Any]:
        """The safe, classified view of the command (``indexing.build_facts``); never the raw argv."""
        tokens = classify_command(self.argv, target_prefixes=(CONTAINER_ROOT,))
        keep = {"include_path", "define", "undefine", "language_standard", "security_flag", "warning",
                "optimization", "debug", "flag", "library"}
        flags = [token["safe_value"] for token in tokens if token["kind"] in keep and token.get("safe_value")]
        standard = next((token["safe_value"] for token in tokens if token["kind"] == "language_standard"), None)
        return {"compiler": PurePosixPath(self.argv[0]).name, "language": self.language, "standard": standard,
                "include_paths": [token["safe_value"] for token in tokens
                                  if token["kind"] == "include_path" and token.get("safe_value")],
                "defines": [token["safe_value"] for token in tokens
                            if token["kind"] in {"define", "undefine"} and token.get("safe_value")],
                "flags": flags[:48], "source": self.source, "command_sha256": self.sha256,
                "normalization_rule": "appsec-review/safe-command-facts/1", "basis": self.basis}


@dataclass(frozen=True, slots=True)
class BuildUnit:
    """One accepted native build unit as the PoC compile check needs it."""

    build_unit_id: str
    build_system: str
    root: str
    receipt_fingerprint: str
    workspace: Path
    workspace_manifest: Mapping[str, str]
    manifest_sha256: str
    image_tag: str
    image_id: str
    image_user: str
    command: CompileCommand
    objects: tuple[str, ...]          # workspace-relative object and static-library outputs of the build
    shared_libraries: tuple[str, ...]
    gaps: tuple[str, ...] = ()
    # The pinned base when the image is a runtime-derived project image (see derived_base_image_id).
    image_derived_from: str | None = None

    def identity(self) -> dict[str, Any]:
        return {"build_unit_id": self.build_unit_id, "receipt_fingerprint": self.receipt_fingerprint,
                "workspace_manifest_sha256": self.manifest_sha256, "image_id": self.image_id,
                "command_sha256": self.command.sha256, "source": self.command.source}


@dataclass(frozen=True, slots=True)
class Located:
    """The outcome of looking for the build of one source file."""

    unit: BuildUnit | None
    reason: str                       # "" when found, else a short named reason
    code: str = "found"               # found | not_c_family | no_native_build | no_compile_command


def language_of(path: str) -> str | None:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in SOURCE_SUFFIXES:
        return SOURCE_SUFFIXES[suffix]
    return "cxx" if suffix in HEADER_SUFFIXES else None


class MissingBuild(ValueError):
    """The run has no accepted language build at all (a gap about the run, not an integrity failure)."""


class AcceptedBuilds:
    """Lookup over the run's accepted language build."""

    def __init__(self, run_root: Path, *, loader: Callable[[Path], Mapping[str, Any]] | None = None,
                 file_limit: int = 100_000) -> None:
        self.run_root = Path(run_root).resolve()
        if loader is None:
            from appsec_review.jobs.job_language_build import load_accepted_language_build as loader
        self._loader = loader
        self.file_limit = file_limit
        self._accepted: Mapping[str, Any] | None = None
        self._rows: dict[str, list[Mapping[str, Any]]] = {}

    @property
    def accepted(self) -> Mapping[str, Any]:
        if self._accepted is None:
            try:
                self._accepted = self._loader(self.run_root)
            except ValueError as exc:
                if "handoff is required" in str(exc):
                    raise MissingBuild("the run has no accepted language build") from exc
                raise IntegrityError(f"the accepted language build cannot be verified: {exc}") from exc
        return self._accepted

    @property
    def handoff_sha256(self) -> str | None:
        value = self.accepted.get("language_build_handoff_sha256")
        return str(value) if value else None

    def _bound(self, reference: Any, what: str) -> Path:
        if not isinstance(reference, Mapping):
            raise IntegrityError(f"accepted build lacks its {what}")
        path = (self.run_root / str(reference.get("path", ""))).resolve()
        if self.run_root not in path.parents or not path.is_file() or path.is_symlink():
            raise IntegrityError(f"accepted build {what} is unavailable")
        if file_sha256(path) != reference.get("sha256"):
            raise IntegrityError(f"accepted build {what} changed after acceptance")
        return path

    def _compile_rows(self, receipt: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        identity = str(receipt["build_unit_id"])
        if identity not in self._rows:
            path = self._bound(receipt.get("protected_compile_commands"), "protected compile database")
            document = json.loads(path.read_text(encoding="utf-8"))
            if document.get("schema") != COMPILE_DATABASE_SCHEMA:
                raise IntegrityError("accepted build compile database schema is unsupported")
            self._rows[identity] = [row for row in document.get("rows", ()) if isinstance(row, Mapping)]
        return self._rows[identity]

    def locate(self, source_path: str) -> Located:
        """The native build unit and compiler invocation that cover ``source_path`` (target-relative)."""
        language = language_of(source_path)
        if language is None:
            return Located(None, f"{PurePosixPath(source_path).suffix or 'this file'} is not C or C++ source",
                           "not_c_family")
        try:
            accepted = self.accepted
        except MissingBuild as exc:
            return Located(None, str(exc), "no_native_build")
        receipts = sorted((item for item in accepted.get("receipts", ()) if isinstance(item, Mapping)
                           and item.get("family") == "native" and item.get("terminal_status") == "SUCCEEDED"),
                          key=lambda item: str(item["build_unit_id"]))
        if not receipts:
            return Located(None, "the run has no successful accepted native build", "no_native_build")
        wanted = PurePosixPath(source_path).as_posix()
        for receipt in receipts:
            manifest_path = self._bound(receipt.get("workspace_manifest"), "workspace manifest")
            files = json.loads(manifest_path.read_text(encoding="utf-8")).get("files") or {}
            if wanted not in files:
                continue
            command = self._command(receipt, wanted, language)
            if command is None:
                return Located(None, f"no captured compiler invocation covers {wanted}", "no_compile_command")
            return Located(self._unit(receipt, files, manifest_path, command), "")
        return Located(None, f"no accepted native build contains {wanted}", "no_native_build")

    def _command(self, receipt: Mapping[str, Any], wanted: str, language: str) -> CompileCommand | None:
        rows = [row for row in self._compile_rows(receipt) if row.get("tool_kind") == "compiler"
                and isinstance(row.get("argv"), list) and "-c" in row["argv"]
                and not str(row["argv"][0]).startswith("/capture/")]

        def source_of(row: Mapping[str, Any]) -> str | None:
            for item in row.get("inputs", ()):
                if isinstance(item, Mapping) and language_of(str(item.get("workspace_path", ""))) \
                        and PurePosixPath(str(item["workspace_path"])).suffix.lower() in SOURCE_SUFFIXES:
                    return str(item["workspace_path"])
            return None

        exact = [row for row in rows if source_of(row) == wanted]
        basis = "exact"
        chosen = exact[:1]
        if not chosen and PurePosixPath(wanted).suffix.lower() in HEADER_SUFFIXES:
            ordered = sorted((row for row in rows if source_of(row)), key=lambda row: str(source_of(row)))
            chosen, basis = ordered[:1], "unit_default"
        if not chosen:
            return None
        row = chosen[0]
        source = str(source_of(row))
        argv = tuple(str(item) for item in row["argv"])
        recipe = receipt.get("recipe") if isinstance(receipt.get("recipe"), Mapping) else {}
        return CompileCommand(argv, source, SOURCE_SUFFIXES[PurePosixPath(source).suffix.lower()],
                              _working_directory(argv, str(recipe.get("build_dir") or ".")), basis)

    def _unit(self, receipt: Mapping[str, Any], files: Mapping[str, str], manifest_path: Path,
              command: CompileCommand) -> BuildUnit:
        workspace = (self.run_root / str(receipt.get("workspace", ""))).resolve()
        if self.run_root not in workspace.parents or not workspace.is_dir():
            raise IntegrityError("accepted build workspace is unavailable")
        image = receipt.get("image") if isinstance(receipt.get("image"), Mapping) else {}
        gaps: list[str] = []
        objects, shared = [], []
        for item in receipt.get("artifacts", ()):
            if not isinstance(item, Mapping) or not isinstance(item.get("workspace_path"), str):
                continue
            if item["workspace_path"] not in files:
                continue
            if item.get("kind") in OBJECT_KINDS:
                objects.append(item["workspace_path"])
            elif item.get("kind") in SHARED_KINDS:
                shared.append(item["workspace_path"])
        if not objects and not shared:
            gaps.append("the accepted build recorded no object or library output to check symbols against")
        for key in ("image_tag", "image_id", "user"):
            if not image.get(key):
                gaps.append(f"the accepted build image record lacks {key}")
        return BuildUnit(
            str(receipt["build_unit_id"]), str(receipt.get("build_system")), str(receipt.get("root")),
            str(receipt.get("fingerprint")), workspace, dict(files), file_sha256(manifest_path),
            str(image.get("image_tag", "")), str(image.get("image_id", "")), str(image.get("user", "")),
            command, tuple(sorted(set(objects))), tuple(sorted(set(shared))), tuple(gaps),
            derived_base_image_id(image))

    # -- the disposable copy -----------------------------------------------------------------------
    def materialize(self, unit: BuildUnit, destination: Path, *, byte_limit: int) -> int:
        """Copy the manifest's files into ``destination``, verifying each hash; the copy's file count."""
        if len(unit.workspace_manifest) > self.file_limit:
            raise ValueError(f"the accepted workspace has {len(unit.workspace_manifest)} files; the bound is "
                             f"{self.file_limit}")
        destination.mkdir(parents=True, exist_ok=True)
        total = 0
        for relative, digest in sorted(unit.workspace_manifest.items()):
            logical = PurePosixPath(relative)
            if logical.is_absolute() or ".." in logical.parts:
                raise IntegrityError("accepted workspace manifest names a path outside the workspace")
            source = unit.workspace.joinpath(*logical.parts)
            if source.is_symlink() or not source.is_file():
                raise IntegrityError(f"accepted build workspace file is missing: {relative}")
            data = source.read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                raise IntegrityError(f"accepted build workspace file changed after acceptance: {relative}")
            total += len(data)
            if total > byte_limit:
                raise ValueError(f"the accepted workspace exceeds {byte_limit} bytes")
            target = destination.joinpath(*logical.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        return len(unit.workspace_manifest)


_RELATIVE_PATHS = re.compile(r"^(?:-I|-isystem|-iquote|-idirafter|-include|-L)(?!/)(.+)$")


def _working_directory(argv: Sequence[str], build_dir: str) -> str:
    """Where derived commands run: the build directory when the captured command uses relative paths."""
    relative = False
    pending = False
    for item in argv[1:]:
        if pending:
            relative = relative or not item.startswith("/")
            pending = False
        elif item in {"-I", "-isystem", "-iquote", "-idirafter", "-include"}:
            pending = True
        elif _RELATIVE_PATHS.match(item):
            relative = True
        elif item.startswith("@") and not item.startswith("@/"):
            relative = True
    parts = PurePosixPath(build_dir)
    if not relative or build_dir in {"", "."} or parts.is_absolute() or ".." in parts.parts:
        return "."
    return parts.as_posix()


class Headers:
    """Resolve a project header name against the include directories of the sink's compile command."""

    def __init__(self, unit: BuildUnit) -> None:
        self.unit = unit
        self.directories = _include_directories(unit.command)

    def resolve(self, include: str) -> str | None:
        logical = PurePosixPath(include)
        if logical.is_absolute() or ".." in logical.parts:
            return None
        for directory in self.directories:
            candidate = (PurePosixPath(directory) / logical).as_posix() if directory != "." else logical.as_posix()
            if candidate in self.unit.workspace_manifest:
                return candidate
        return None

    def search_directories(self) -> tuple[str, ...]:
        return tuple(self.directories)


def _include_directories(command: CompileCommand) -> list[str]:
    found: list[str] = []
    pending = False
    base = PurePosixPath(command.working_directory)

    def add(value: str) -> None:
        path = PurePosixPath(value)
        if path.is_absolute():
            try:
                relative = path.relative_to(CONTAINER_ROOT).as_posix()
            except ValueError:
                return
        else:
            relative = (base / path).as_posix()
        relative = str(PurePosixPath(relative)) if relative not in {"", "."} else "."
        normal = _normalise(relative)
        if normal is not None and normal not in found:
            found.append(normal)

    for item in command.argv[1:]:
        if pending:
            add(item)
            pending = False
        elif item in {"-I", "-isystem", "-iquote", "-idirafter"}:
            pending = True
        elif item.startswith(("-I", "-isystem", "-iquote", "-idirafter")):
            add(re.sub(r"^-(?:I|isystem|iquote|idirafter)", "", item))
    add(str(PurePosixPath(command.source).parent))
    return found


def _normalise(relative: str) -> str | None:
    parts: list[str] = []
    for part in PurePosixPath(relative).parts:
        if part == "..":
            if not parts:
                return None
            parts.pop()
        elif part != ".":
            parts.append(part)
    return "/".join(parts) if parts else "."


def declarations(unit: BuildUnit, headers: Headers, names: Sequence[str], *, source_bytes: int,
                 max_files: int, max_lines: int, types_only: bool = False) -> list[dict[str, Any]]:
    """Prototype lines of ``names`` in the project headers on the compile command's include path.

    Bounded by file count, file size and lines per declaration; the rows carry the file and line so a
    reader can resolve them. A name with no prototype in the searched headers is simply absent (the
    brief records which headers were searched).
    """
    base_names = [name.rsplit("::", 1)[-1] for name in names if name]
    if not base_names:
        return []
    alternatives = "|".join(re.escape(name) for name in dict.fromkeys(base_names))
    calls = "" if types_only else rf"(?:{alternatives})\s*\(|"
    pattern = re.compile(rf"(?<![A-Za-z0-9_])(?:{calls}(?:struct|class|union|enum)(?:\s+class)?\s+"
                         rf"(?:{alternatives})\b|using\s+(?:{alternatives})\s*=|typedef[^;]*\b(?:{alternatives})\s*;)")
    candidates = sorted(path for path in unit.workspace_manifest
                        if path.endswith(HEADER_SUFFIXES) and any(
                            path == directory or path.startswith(directory.rstrip("/") + "/") or directory == "."
                            for directory in headers.search_directories()))
    rows: list[dict[str, Any]] = []
    for relative in candidates[:max_files]:
        source = unit.workspace.joinpath(*PurePosixPath(relative).parts)
        try:
            if source.stat().st_size > source_bytes:
                continue
            lines = source.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for index, line in enumerate(lines):
            if not pattern.search(line) or line.lstrip().startswith(("//", "*", "/*")):
                continue
            end = index
            record = re.match(r"\s*(?:typedef\s+)?(?:struct|class|union|enum)\b[^;]*$", line) is not None
            while end + 1 < len(lines) and end - index + 1 < max_lines and (
                    (record and not lines[end].lstrip().startswith("}")) or
                    (not record and ";" not in lines[end] and "{" not in lines[end])):
                end += 1
            rows.append({"path": relative, "lines": f"{index + 1}-{end + 1}",
                         "text": [f"{number + 1}| {lines[number].rstrip()[:200]}" for number in range(index, end + 1)]})
    return rows[:24]


__all__ = ["AcceptedBuilds", "BuildUnit", "CompileCommand", "Headers", "Located", "declarations", "language_of"]
