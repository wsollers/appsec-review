"""Inert exact-edit patches: byte baselines, explicit new-file absence, no fuzzy matching."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from typing import Any, Mapping

from appsec_review.config.remediation import RemediationBounds, exact
from appsec_review.review.models import IntegrityError
from appsec_review.storage import canonical_json

PATCH_SCHEMA = "appsec-review/remediation-exact-patch/1"
_SHA = re.compile(r"[0-9a-f]{64}")
_COMPONENT = re.compile(r"[A-Za-z0-9_.+-]{1,120}")
_RESERVED = re.compile(r"(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?", re.IGNORECASE)


class PatchError(ValueError):
    """Untrusted proposal cannot be applied exactly under patch policy."""


def relative_path(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 240 or not value:
        raise PatchError("patch path must be a bounded relative path")
    path = PurePosixPath(value)
    if (path.is_absolute() or PureWindowsPath(value).is_absolute() or "\\" in value
            or value != path.as_posix() or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(not _COMPONENT.fullmatch(part) or _RESERVED.fullmatch(part) or part.endswith(".")
                   for part in path.parts)):
        raise PatchError(f"unsafe relative patch path: {value}")
    return value


def safe_file(root: Path, relative: str, *, missing: bool = False) -> Path:
    relative_path(relative)
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise IntegrityError("remediation workspace is not a regular directory")
    target = root
    for part in PurePosixPath(relative).parts:
        target = target / part
        if target.is_symlink() or (hasattr(target, "is_junction") and target.is_junction()):
            raise IntegrityError(f"symlink or junction in remediation workspace: {relative}")
    resolved = target.resolve()
    if root.resolve() not in resolved.parents:
        raise IntegrityError(f"remediation path escapes workspace: {relative}")
    if target.exists() and not target.is_file():
        raise IntegrityError(f"remediation path is not a regular file: {relative}")
    if not missing and not target.is_file():
        raise PatchError(f"baseline file is missing: {relative}")
    return target


@dataclass(frozen=True, slots=True)
class ExactPatch:
    document: Mapping[str, Any]

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(row["path"] for row in self.document["files"])


def parse_patch(value: Any, bounds: RemediationBounds) -> ExactPatch:
    try:
        body = exact(value, {"schema", "files"}, "exact patch")
        if body["schema"] != PATCH_SCHEMA or not isinstance(body["files"], list) \
                or not 1 <= len(body["files"]) <= bounds.max_patch_files:
            raise PatchError("invalid exact patch schema or file count")
        if len(canonical_json(body)) > bounds.max_patch_bytes:
            raise PatchError("patch byte bound exceeded")
        names: set[str] = set()
        edit_count = 0
        for row in body["files"]:
            exact(row, {"path", "before_sha256", "absence_proof", "edits"}, "patch file")
            name = relative_path(row["path"])
            if name.casefold() in names or any(name.casefold().startswith(other + "/")
                                               or other.startswith(name.casefold() + "/") for other in names):
                raise PatchError("duplicate or overlapping patch file")
            names.add(name.casefold())
            digest = row["before_sha256"]
            if digest is None:
                if row["absence_proof"] is not True:
                    raise PatchError("new file requires an explicit absence proof")
            elif not isinstance(digest, str) or not _SHA.fullmatch(digest) or row["absence_proof"] is not False:
                raise PatchError("existing file requires exact baseline hash and no absence proof")
            if not isinstance(row["edits"], list) or not row["edits"]:
                raise PatchError("patch file must declare exact edits")
            last_end = -1
            for edit in row["edits"]:
                exact(edit, {"start", "end", "old", "new"}, "exact edit")
                start, end = edit["start"], edit["end"]
                if (type(start) is not int or type(end) is not int or start < 0 or end < start
                        or start < last_end or (start == end == last_end)
                        or any(not isinstance(edit[key], str) for key in ("old", "new"))
                        or len(edit["old"].encode("utf-8")) != end - start):
                    raise PatchError("malformed, unordered or overlapping byte edits")
                if edit["old"] == edit["new"]:
                    raise PatchError("no-op edit is not a proposal")
                if digest is None and (start != 0 or end != 0 or edit["old"] != "" or len(row["edits"]) != 1):
                    raise PatchError("new file must be one insertion at byte zero")
                last_end = end
                edit_count += 1
        if edit_count > bounds.max_edits:
            raise PatchError("exact edit bound exceeded")
        return ExactPatch(body)
    except ValueError as exc:
        if isinstance(exc, PatchError):
            raise
        raise PatchError(str(exc)) from exc


def patched_bytes(patch: ExactPatch, root: Path, manifest: Mapping[str, str],
                  bounds: RemediationBounds) -> dict[str, bytes]:
    """Check all files before returning any writes; hashes alone never permit a fuzzy edit."""
    outputs: dict[str, bytes] = {}
    for row in patch.document["files"]:
        name, digest = row["path"], row["before_sha256"]
        target = safe_file(root, name, missing=digest is None)
        if digest is None:
            if target.exists() or name in manifest or any(key.casefold() == name.casefold() for key in manifest):
                raise PatchError(f"new-file absence proof failed: {name}")
            data = b""
        else:
            if manifest.get(name) != digest:
                raise PatchError(f"patch baseline does not match accepted manifest: {name}")
            data = target.read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                raise IntegrityError(f"accepted baseline changed: {name}")
        if len(data) > bounds.max_file_bytes:
            raise PatchError(f"baseline file bound exceeded: {name}")
        for edit in reversed(row["edits"]):
            if data[edit["start"]:edit["end"]] != edit["old"].encode("utf-8") or edit["end"] > len(data):
                raise PatchError(f"exact edit does not match baseline bytes: {name}")
            data = data[:edit["start"]] + edit["new"].encode("utf-8") + data[edit["end"]:]
        if len(data) > bounds.max_file_bytes:
            raise PatchError(f"patched file bound exceeded: {name}")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PatchError("patch must produce UTF-8 source/configuration") from exc
        outputs[name] = data
    return outputs


_BUILD_NAMES = frozenset({"cmakelists.txt", "makefile", "gnumakefile", "dockerfile", "meson.build",
                          "meson_options.txt", "package.json", "package-lock.json", "pyproject.toml",
                          "setup.py", "setup.cfg", "cargo.toml", "cargo.lock", "build.rs", ".clang-tidy",
                          ".clangd", ".clang-format", "compile_commands.json", "conftest.py"})
_BUILD_SUFFIXES = frozenset({".cmake", ".mk", ".sh", ".bat", ".cmd", ".ps1", ".py", ".js", ".mjs",
                             ".cjs", ".so", ".dll", ".exe", ".cfg", ".rsp", ".pth", ".targets", ".props"})


def unsafe_build_changes(patch: ExactPatch) -> list[str]:
    """Changes to tool loading or executable build configuration are never automatically replayed."""
    return [name for name in patch.paths if PurePosixPath(name).name.casefold() in _BUILD_NAMES
            or PurePosixPath(name).suffix.casefold() in _BUILD_SUFFIXES
            or any(part.casefold() in {".git", ".github", ".config", "cmake"} for part in PurePosixPath(name).parts)]


def apply_exact(patch: ExactPatch, root: Path, manifest: Mapping[str, str], bounds: RemediationBounds) -> None:
    outputs = patched_bytes(patch, root, manifest, bounds)
    for relative, data in outputs.items():
        target = safe_file(root, relative, missing=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
