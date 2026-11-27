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


#: Receipt terminal statuses whose build products the lookup may use when the receipt predates
#: ``build_outcome``. A gap on an accepted build is a named limit of that build, not the absence of a
#: build; FAILED, BLOCKED and NOT_APPLICABLE receipts have no products.
ACCEPTED_BUILD_STATUSES = frozenset({"SUCCEEDED", "COMPLETED_WITH_GAPS"})


def _has_build_products(receipt: Mapping[str, Any]) -> bool:
    """``build_outcome == "built"`` when the receipt carries it; the accepted statuses for older receipts."""
    from appsec_review.jobs.build_outcome import build_succeeded
    try:
        return build_succeeded(receipt, legacy_statuses=ACCEPTED_BUILD_STATUSES)
    except ValueError as exc:
        raise IntegrityError(f"accepted build receipt is invalid: {exc}") from exc


class MissingBuild(ValueError):
    """The run has no accepted language build at all (a gap about the run, not an integrity failure)."""


def _owned_path(root: Path, relative: str, what: str) -> Path:
    logical = PurePosixPath(relative)
    if logical.is_absolute() or ".." in logical.parts or not logical.parts or "\\" in relative:
        raise IntegrityError(f"{what} names a path outside the workspace")
    current = root
    for part in logical.parts:
        current = current / part
        if current.is_symlink():
            raise IntegrityError(f"{what} is a substituted symlink: {relative}")
    if any(parent.is_symlink() for parent in (root, *root.parents)) or root.resolve() not in current.resolve().parents:
        raise IntegrityError(f"{what} is outside the workspace")
    return current


def workspace_bytes(workspace: Path, manifest: Mapping[str, str], relative: str, *,
                    byte_limit: int) -> bytes | None:
    """Read at most the byte bound plus a sentinel, then verify the exact accepted bytes.

    An oversized file supplies no text. A missing, substituted or changed accepted file is an
    integrity failure, not a retrieval miss or permission to try a different source tree.
    """
    source = _owned_path(workspace, relative, "accepted workspace manifest")
    if relative not in manifest:
        raise IntegrityError(f"source is not in the accepted workspace manifest: {relative}")
    try:
        if not source.is_file():
            raise IntegrityError(f"accepted build workspace file is missing: {relative}")
        with source.open("rb") as stream:
            data = stream.read(byte_limit + 1)
    except OSError as exc:
        raise IntegrityError(f"accepted build workspace file is unavailable: {relative}") from exc
    if len(data) > byte_limit:
        return None
    if hashlib.sha256(data).hexdigest() != manifest[relative]:
        raise IntegrityError(f"accepted build workspace file changed after acceptance: {relative}")
    return data


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
        path = _owned_path(self.run_root, str(reference.get("path", "")), f"accepted build {what}")
        if not path.is_file():
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

    def native_link_facts(self) -> list[dict[str, Any]]:
        """Per accepted native unit, its bound compile-database rows and link-database rows.

        Used by the attack-chain ``same_native_executable`` derivation (``review/native_continuity.py``).
        A unit without a bound link database is skipped (nothing links without it); an empty list means the
        run has no accepted native build. A bound file that changed is an ``IntegrityError``.
        """
        try:
            accepted = self.accepted
        except MissingBuild:
            return []
        receipts = sorted((item for item in accepted.get("receipts", ()) if isinstance(item, Mapping)
                           and item.get("family") == "native"
                           and item.get("terminal_status") in ACCEPTED_BUILD_STATUSES),
                          key=lambda item: str(item["build_unit_id"]))
        result = []
        for receipt in receipts:
            link_ref = receipt.get("link_database")
            if not isinstance(link_ref, Mapping):
                continue
            rows = self._compile_rows(receipt)
            link_path = self._bound(link_ref, "link database")
            link_rows = json.loads(link_path.read_text(encoding="utf-8"))
            if not isinstance(link_rows, list):
                raise IntegrityError("accepted build link database is not a list of link commands")
            compile_ref = receipt["protected_compile_commands"]
            result.append({"build_unit_id": str(receipt["build_unit_id"]), "compile_rows": rows,
                           "link_rows": [row for row in link_rows if isinstance(row, Mapping)],
                           "protected_compile_commands": {"path": str(compile_ref["path"]),
                                                          "sha256": str(compile_ref["sha256"])},
                           "link_database": {"path": str(link_ref["path"]), "sha256": str(link_ref["sha256"])}})
        return result

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
        # The receipt's ``build_outcome`` says whether the build completed; its ``terminal_status`` says
        # whether the receipt is clean. A ``COMPLETED_WITH_GAPS`` native build whose products exist (compile
        # database, workspace manifest, image) but which recorded provenance gaps, such as output-classification
        # heuristics, unknown delivery facts or an unknown compiler in the capture, is still a build. Run
        # 2026-11-16-0003 lost every remediation plan and PoC to "no_native_build" because its only native
        # build carried 17 such gaps; the bound products are verified below and a missing one is still refused.
        receipts = sorted((item for item in accepted.get("receipts", ()) if isinstance(item, Mapping)
                           and item.get("family") == "native" and _has_build_products(item)),
                          key=lambda item: str(item["build_unit_id"]))
        if not receipts:
            return Located(None, "the run has no successful accepted native build", "no_native_build")
        wanted = PurePosixPath(source_path).as_posix()
        contained = False
        for receipt in receipts:
            manifest_path = self._bound(receipt.get("workspace_manifest"), "workspace manifest")
            files = json.loads(manifest_path.read_text(encoding="utf-8")).get("files") or {}
            if wanted not in files:
                continue
            contained = True
            command = self._command(receipt, wanted, language)
            if command is None:
                continue
            return Located(self._unit(receipt, files, manifest_path, command), "")
        if contained:
            return Located(None, f"no captured compiler invocation with a recorded workspace working directory "
                           f"covers {wanted}", "no_compile_command")
        return Located(None, f"no accepted native build contains {wanted}", "no_native_build")

    def _command(self, receipt: Mapping[str, Any], wanted: str, language: str) -> CompileCommand | None:
        rows = [row for row in self._compile_rows(receipt) if row.get("tool_kind") == "compiler"
                and isinstance(row.get("argv"), list) and "-c" in row["argv"]
                and not str(row["argv"][0]).startswith("/capture/")
                and _working_directory(row.get("working_directory")) is not None]

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
        return CompileCommand(argv, source, SOURCE_SUFFIXES[PurePosixPath(source).suffix.lower()],
                              _working_directory(row["working_directory"]), basis)

    def _unit(self, receipt: Mapping[str, Any], files: Mapping[str, str], manifest_path: Path,
              command: CompileCommand) -> BuildUnit:
        workspace = _owned_path(self.run_root, str(receipt.get("workspace", "")), "accepted build workspace")
        if not workspace.is_dir():
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
    def materialize(self, unit: BuildUnit, destination: Path, *, byte_limit: int,
                    file_limit: int | None = None) -> int:
        """Copy the manifest's files into ``destination``, verifying each hash; the copy's file count."""
        limit = self.file_limit if file_limit is None else file_limit
        if len(unit.workspace_manifest) > limit:
            raise ValueError(f"the accepted workspace has {len(unit.workspace_manifest)} files; the bound is "
                             f"{limit}")
        destination.mkdir(parents=True, exist_ok=True)
        total = 0
        for relative in sorted(unit.workspace_manifest):
            logical = PurePosixPath(relative)
            data = workspace_bytes(unit.workspace, unit.workspace_manifest, relative, byte_limit=byte_limit - total)
            if data is None:
                raise ValueError(f"the accepted workspace exceeds {byte_limit} bytes")
            total += len(data)
            target = destination.joinpath(*logical.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        return len(unit.workspace_manifest)


def _working_directory(recorded: Any) -> str | None:
    """Map only a captured cwd; argv, build roots and recipe directories cannot supply one."""
    if (not isinstance(recorded, str) or not recorded or "\\" in recorded or ":" in recorded
            or any(ord(char) < 32 or ord(char) == 127 for char in recorded)):
        return None
    if recorded == CONTAINER_ROOT:
        return "."
    value = recorded.removeprefix(CONTAINER_ROOT + "/")
    if value == ".":
        return value
    parts = PurePosixPath(value)
    if (parts.is_absolute() or value != parts.as_posix()
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        return None
    return value


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
    add(str(PurePosixPath(CONTAINER_ROOT) / PurePosixPath(command.source).parent))
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
        data = workspace_bytes(unit.workspace, unit.workspace_manifest, relative, byte_limit=source_bytes)
        if data is None:
            continue
        try:
            lines = data.decode("utf-8").splitlines()
        except UnicodeDecodeError:
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


_TU_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]')
_TU_FUNC_START_RE = re.compile(
    r'^(?:(?P<qual>(?:extern\s+(?!"C")|static\s+|inline\s+|constexpr\s+|virtual\s+)+))?'
    r"(?P<ret>[A-Za-z_~][\w:\s\*&<>]*?)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_:]*)\s*\("
)
_TU_SKIP_NAMES = frozenset({
    "if", "for", "while", "switch", "catch", "return", "sizeof", "alignof", "decltype", "static_assert",
    "main", "wmain", "WinMain", "wWinMain", "DllMain", "_start", "_main", "DllEntryPoint",
    "LLVMFuzzerTestOneInput",
})
_STDDEF_TOKENS_RE = re.compile(r"\b(?:size_t|ptrdiff_t|nullptr_t)\b")
_STDINT_TOKENS_RE = re.compile(r"\b(?:u?int(?:8|16|32|64|ptr|max)_t|ssize_t)\b")


def tu_declarations(
    unit: BuildUnit,
    existing_rows: Sequence[Mapping[str, Any]],
    names: Sequence[str],
    *,
    headers: Headers | None = None,
    allowed_std_headers: Sequence[str] = (),
    source_bytes: int = 65536,
    max_lines: int = 12,
) -> tuple[list[dict[str, Any]], str | None]:
    """Extract non-static top-level C/C++ function prototypes from the sink TU when absent from headers."""
    if unit.command.language not in ("c", "cpp", "cxx"):
        return [], None
    wanted = {name.rsplit("::", 1)[-1].strip() for name in names if name and name.strip()} - _TU_SKIP_NAMES
    if not wanted:
        return [], None
    already_declared: set[str] = set()
    for row in existing_rows:
        joined = "\n".join(str(line).split("|", 1)[-1] for line in row.get("text", ()))
        for candidate in wanted:
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(candidate)}\s*\(", joined):
                already_declared.add(candidate)
    missing = wanted - already_declared
    if not missing:
        return [], None
    raw = workspace_bytes(unit.workspace, unit.workspace_manifest, unit.command.source, byte_limit=source_bytes)
    if raw is None:
        return [], None
    lines = raw.decode("utf-8", errors="replace").splitlines()

    allowed_std = set(allowed_std_headers)
    safe_includes: list[str] = []
    for line in lines[:120]:
        inc_match = _TU_INCLUDE_RE.match(line)
        if not inc_match:
            continue
        delim, hdr = inc_match.group(1), inc_match.group(2).strip()
        if hdr in allowed_std:
            directive = f"#include <{hdr}>" if delim == "<" else f'#include "{hdr}"'
            if directive not in safe_includes:
                safe_includes.append(directive)
        elif headers is not None and headers.resolve(hdr) is not None:
            directive = f'#include "{hdr}"' if delim == '"' else f"#include <{hdr}>"
            if directive not in safe_includes:
                safe_includes.append(directive)

    rows: list[dict[str, Any]] = []
    protos: list[str] = []
    seen_protos: set[str] = set()
    idx = 0
    while idx < len(lines):
        stripped = lines[idx].strip()
        if not stripped or stripped.startswith(("//", "/*", "*", "#")):
            idx += 1
            continue
        if lines[idx][:1] in (" ", "\t", "{", "}"):
            idx += 1
            continue
        match = _TU_FUNC_START_RE.match(lines[idx])
        if not match:
            idx += 1
            continue
        qual = (match.group("qual") or "").split()
        if "static" in qual or "inline" in qual:
            idx += 1
            continue
        fn_name = match.group("name").rsplit("::", 1)[-1]
        if fn_name in _TU_SKIP_NAMES or fn_name not in missing:
            idx += 1
            continue
        sig_lines = [lines[idx]]
        end = idx
        while end + 1 < len(lines) and len(sig_lines) < max_lines:
            joined_sig = " ".join(part.strip() for part in sig_lines)
            if "{" in joined_sig or ";" in joined_sig:
                break
            end += 1
            sig_lines.append(lines[end])
        joined_sig = " ".join(part.strip() for part in sig_lines)
        if "{" not in joined_sig:
            idx += 1
            continue
        proto = joined_sig.split("{", 1)[0].strip()
        if not proto or not proto.endswith(")"):
            idx += 1
            continue
        if proto not in seen_protos:
            seen_protos.add(proto)
            protos.append(f"{proto};")
            snippet = [f"{line_no + 1}| {lines[line_no].rstrip()[:200]}"
                       for line_no in range(idx, min(end + 1, idx + max_lines))]
            rows.append({
                "path": unit.command.source,
                "lines": f"{idx + 1}-{min(end + 1, idx + max_lines)}",
                "text": snippet,
                "predeclared": True,
            })
        idx = end + 1

    if not protos:
        return [], None
    joined_protos = "\n".join(protos)
    auto_std: list[str] = []
    if _STDDEF_TOKENS_RE.search(joined_protos):
        if unit.command.language in ("cpp", "cxx"):
            auto_std.extend(("#include <cstddef>", "#include <stddef.h>"))
        else:
            auto_std.append("#include <stddef.h>")
    if _STDINT_TOKENS_RE.search(joined_protos):
        if unit.command.language in ("cpp", "cxx"):
            auto_std.extend(("#include <cstdint>", "#include <stdint.h>"))
        else:
            auto_std.append("#include <stdint.h>")
    if "ssize_t" in joined_protos and "#include <sys/types.h>" not in safe_includes:
        auto_std.append("#include <sys/types.h>")
    header_lines = ["#pragma once"]
    for directive in (*auto_std, *safe_includes):
        if directive not in header_lines:
            header_lines.append(directive)
    header_lines.extend(protos)
    return rows, "\n".join(header_lines) + "\n"


__all__ = ["AcceptedBuilds", "BuildUnit", "CompileCommand", "Headers", "Located", "declarations", "language_of",
           "tu_declarations"]
