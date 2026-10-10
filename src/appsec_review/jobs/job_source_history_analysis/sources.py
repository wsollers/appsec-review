"""Bounded, non-executing resolution of a target's Git metadata.

Everything under ``.git`` is target-controlled data.  This module reads only the few files needed to
pin the reviewed history (``HEAD``, one ref, ``packed-refs``, ``shallow``, ``objects/info/alternates``,
and allowlisted format keys from ``config``) with size-bounded parsers.  It never runs Git and never
uses the target's configuration for anything except detecting unsupported repository formats.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any


MAX_METADATA_BYTES = 1024 * 1024
MAX_PACKED_REFS_BYTES = 64 * 1024 * 1024
MAINLINE_REFS = ("refs/heads/main", "refs/heads/master")
_HEX = {"sha1": re.compile(r"[0-9a-f]{40}"), "sha256": re.compile(r"[0-9a-f]{64}")}
_REF_NAME = re.compile(r"refs/[A-Za-z0-9._/-]{1,240}")
IDENTITY_SCHEMA = "appsec-review/source-history-identity/1"


@dataclass(frozen=True, slots=True)
class GitSource:
    """One resolved history source, or the reason it does not apply."""

    decision: str
    reason: str
    git_dir: str | None = None
    object_format: str = "sha1"
    mainline_ref: str | None = None
    snapshot_commit: str | None = None
    head_commit: str | None = None
    shallow: tuple[str, ...] = ()
    observations: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["shallow"] = list(self.shallow)
        value["observations"] = list(self.observations)
        return value


def _read(path: Path, limit: int = MAX_METADATA_BYTES) -> bytes | None:
    if path.is_symlink() or not path.is_file():
        return None
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"git metadata exceeds its bound: {path.name}")
    return data


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _config_keys(data: bytes) -> tuple[dict[str, str], bool]:
    """Return lowercase ``section.key`` values for unscoped sections plus whether includes exist."""
    values: dict[str, str] = {}
    section: str | None = None
    includes = False
    for raw in data.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        header = re.fullmatch(r"\[\s*([A-Za-z0-9.-]+)(\s+\"[^\"]*\")?\s*\]", line)
        if header:
            name = header.group(1).lower()
            includes = includes or name in {"include", "includeif"}
            section = None if header.group(2) else name
            continue
        if section is None:
            continue
        key, _, value = line.partition("=")
        value = value.split("#", 1)[0].split(";", 1)[0].strip().strip('"')
        values[f"{section}.{key.strip().lower()}"] = value.lower()
    return values, includes


def locate_git_dir(target_root: Path) -> tuple[Path | None, str]:
    """Locate the repository directory without following anything outside the target."""
    root = target_root.resolve(strict=True)
    dot_git = root / ".git"
    if dot_git.is_symlink():
        return None, "history_source_outside_target"
    if dot_git.is_dir():
        return dot_git, "git_directory"
    if dot_git.is_file():
        data = _read(dot_git, 4096) or b""
        match = re.fullmatch(rb"gitdir: ([^\r\n\0]+)\r?\n?", data)
        if match is None:
            return None, "gitfile_unreadable"
        candidate = Path(match.group(1).decode("utf-8", "replace"))
        resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
        if not _inside(resolved, root) or not resolved.is_dir():
            return None, "history_source_outside_target"
        return resolved, "gitfile"
    return None, "no_git_metadata"


def _resolve_ref(git_dir: Path, ref: str, object_format: str) -> str | None:
    if not _REF_NAME.fullmatch(ref) or ".." in ref or "//" in ref:
        raise ValueError("git ref name is unsafe")
    loose = _read(git_dir / ref)
    if loose is not None:
        value = loose.decode("ascii", "replace").strip()
        return value if _HEX[object_format].fullmatch(value) else None
    packed = _read(git_dir / "packed-refs", MAX_PACKED_REFS_BYTES)
    if packed is None:
        return None
    for line in packed.decode("utf-8", "replace").splitlines():
        if line.startswith(("#", "^")):
            continue
        value, _, name = line.partition(" ")
        if name == ref and _HEX[object_format].fullmatch(value):
            return value
    return None


def resolve_git_source(target_root: Path) -> GitSource:
    git_dir, how = locate_git_dir(target_root)
    if git_dir is None:
        decision = "SKIPPED_NA" if how == "no_git_metadata" else "GAP"
        return GitSource(decision, how)
    root = target_root.resolve(strict=True)
    relative = git_dir.relative_to(root).as_posix()
    observations: list[str] = []
    objects = git_dir / "objects"
    if objects.is_symlink() or not objects.is_dir() or not _inside(objects.resolve(), root):
        return GitSource("GAP", "history_source_outside_target", relative)
    if (git_dir / "commondir").exists():
        return GitSource("GAP", "linked_worktree_not_supported", relative)
    config, includes = _config_keys(_read(git_dir / "config") or b"")
    if includes:
        observations.append("config_includes_ignored")
    object_format = config.get("extensions.objectformat", "sha1")
    if object_format not in _HEX:
        return GitSource("GAP", "unsupported_object_format", relative)
    if "extensions.partialclone" in config or any(
            key.endswith(".promisor") and value == "true" for key, value in config.items()):
        return GitSource("GAP", "partial_clone_objects_missing", relative, object_format)
    if config.get("extensions.refstorage", "files") != "files":
        return GitSource("GAP", "unsupported_ref_storage", relative, object_format)
    alternates = _read(git_dir / "objects" / "info" / "alternates")
    if alternates is not None:
        objects = objects.resolve()
        for line in alternates.decode("utf-8", "replace").splitlines():
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            candidate = Path(entry)
            if candidate.is_absolute() or not _inside((objects / candidate).resolve(), root):
                return GitSource("GAP", "alternates_unresolvable", relative, object_format)
        observations.append("relative_alternates_inside_target")
    if (git_dir / "refs" / "replace").is_dir() and any((git_dir / "refs" / "replace").iterdir()):
        observations.append("replace_refs_ignored")
    if (git_dir / "info" / "grafts").exists():
        observations.append("grafts_ignored")
    head_value = (_read(git_dir / "HEAD", 4096) or b"").decode("ascii", "replace").strip()
    head: str | None = None
    for _ in range(5):
        if head_value.startswith("ref: "):
            head_value = _resolve_ref(git_dir, head_value[5:].strip(), object_format) or ""
            continue
        head = head_value if _HEX[object_format].fullmatch(head_value) else None
        break
    mainline_ref = next((ref for ref in MAINLINE_REFS if _resolve_ref(git_dir, ref, object_format)), None)
    snapshot = _resolve_ref(git_dir, mainline_ref, object_format) if mainline_ref else head
    if mainline_ref is None:
        observations.append("mainline_not_found_using_head")
    elif head is not None and snapshot != head:
        observations.append("head_differs_from_mainline")
    if snapshot is None:
        return GitSource("SKIPPED_NA", "no_commits", relative, object_format, mainline_ref,
                         observations=tuple(observations))
    shallow_data = _read(git_dir / "shallow")
    shallow: list[str] = []
    if shallow_data is not None:
        for line in shallow_data.decode("ascii", "replace").split():
            if not _HEX[object_format].fullmatch(line):
                return GitSource("GAP", "shallow_file_invalid", relative, object_format)
            shallow.append(line)
    return GitSource("SUCCEEDED", "resolved", relative, object_format, mainline_ref, snapshot, head,
                     tuple(sorted(set(shallow))), tuple(observations))


def history_identity(target_root: Path | None) -> str:
    """Cheap deterministic identity of the history the job would analyze, for resume planning."""
    if target_root is None:
        source: dict[str, Any] = {"decision": "SKIPPED_NA", "reason": "no_target"}
    else:
        try:
            source = resolve_git_source(Path(target_root)).as_dict()
        except (OSError, ValueError) as exc:
            source = {"decision": "GAP", "reason": f"metadata_unreadable:{type(exc).__name__}"}
    payload = json.dumps({"schema": IDENTITY_SCHEMA, "git": source}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def blob_id(data: bytes, object_format: str) -> str:
    digest = hashlib.sha256() if object_format == "sha256" else hashlib.sha1(usedforsecurity=False)
    digest.update(b"blob %d\0" % len(data))
    digest.update(data)
    return digest.hexdigest()
