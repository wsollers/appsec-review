#!/usr/bin/env python3
"""Validate, selectively extract, and inventory an untrusted tool distribution archive.

Shared by catalog tool images through the ``shared`` named build context.

The archive is data. Every member is validated before anything is written: no absolute or
drive-qualified names, no traversal, no duplicate or file/directory-conflicting names, no
special files, no links that escape the extraction root, and bounded member count, expanded
bytes, and compression ratio. Only members under the reviewed closure prefixes are written.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tomllib
from typing import Iterable, Sequence
import zipfile


INVENTORY_SCHEMA = "appsec-review/tool-closure-inventory/1"
_DRIVE = re.compile(r"^[A-Za-z]:")
_CHUNK = 1024 * 1024


class UnsafeArchive(ValueError):
    """The archive violates the extraction contract; nothing should be trusted from it."""


@dataclass(frozen=True, slots=True)
class Member:
    name: str
    kind: str  # file | dir | symlink | hardlink | special
    size: int
    compressed_size: int | None = None
    link_target: str | None = None
    mode: int = 0o644


@dataclass(frozen=True, slots=True)
class Limits:
    max_members: int
    max_total_bytes: int
    max_member_ratio: float
    max_archive_ratio: float


def normalize_name(name: str) -> PurePosixPath:
    """Return the safe relative path for a member name or raise UnsafeArchive."""
    if not name or "\x00" in name:
        raise UnsafeArchive(f"empty or NUL-containing member name: {name!r}")
    if "\\" in name:
        raise UnsafeArchive(f"backslash in member name: {name!r}")
    if _DRIVE.match(name):
        raise UnsafeArchive(f"drive-qualified member name: {name!r}")
    if name.startswith("/"):
        raise UnsafeArchive(f"absolute member name: {name!r}")
    parts = [part for part in name.rstrip("/").split("/")]
    if any(part in {"", ".", ".."} for part in parts):
        raise UnsafeArchive(f"non-canonical or traversing member name: {name!r}")
    return PurePosixPath(*parts)


def _link_destination(member_path: PurePosixPath, target: str, *, hard: bool) -> PurePosixPath:
    if not target or "\x00" in target or "\\" in target or _DRIVE.match(target) or target.startswith("/"):
        raise UnsafeArchive(f"link escapes extraction root: {member_path} -> {target!r}")
    base = [] if hard else list(member_path.parent.parts)
    for part in target.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not base:
                raise UnsafeArchive(f"link escapes extraction root: {member_path} -> {target!r}")
            base.pop()
        else:
            base.append(part)
    if not base:
        raise UnsafeArchive(f"link escapes extraction root: {member_path} -> {target!r}")
    return PurePosixPath(*base)


def validate_members(members: Sequence[Member], limits: Limits, archive_bytes: int) -> list[PurePosixPath]:
    """Validate the whole member list and return normalized paths in archive order."""
    if len(members) > limits.max_members:
        raise UnsafeArchive(f"archive has {len(members)} members; limit is {limits.max_members}")
    total = 0
    paths: list[PurePosixPath] = []
    kinds: dict[PurePosixPath, str] = {}
    for member in members:
        path = normalize_name(member.name)
        if path in kinds:
            raise UnsafeArchive(f"duplicate member: {path}")
        if member.kind == "special":
            raise UnsafeArchive(f"device, FIFO, or other special member: {path}")
        if member.mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
            raise UnsafeArchive(f"setuid, setgid, or sticky member: {path}")
        if member.size < 0:
            raise UnsafeArchive(f"negative member size: {path}")
        total += member.size
        if total > limits.max_total_bytes:
            raise UnsafeArchive(f"expanded size exceeds {limits.max_total_bytes} bytes")
        if member.compressed_size is not None and member.size > 0:
            ratio = member.size / max(member.compressed_size, 1)
            if ratio > limits.max_member_ratio:
                raise UnsafeArchive(f"compression ratio {ratio:.1f} exceeds limit for {path}")
        if member.kind == "symlink":
            _link_destination(path, member.link_target or "", hard=False)
        elif member.kind == "hardlink":
            _link_destination(path, member.link_target or "", hard=True)
            raise UnsafeArchive(f"hard links are not accepted: {path}")
        kinds[path] = member.kind
        paths.append(path)
    if total / max(archive_bytes, 1) > limits.max_archive_ratio:
        raise UnsafeArchive("archive expansion ratio exceeds limit")
    for path, kind in kinds.items():
        for parent in path.parents:
            if parent == PurePosixPath("."):
                break
            parent_kind = kinds.get(parent)
            if parent_kind is not None and parent_kind != "dir":
                raise UnsafeArchive(f"member {path} lies beneath non-directory member {parent}")
    return paths


def _zip_members(archive: zipfile.ZipFile) -> list[Member]:
    members = []
    for info in archive.infolist():
        mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if info.is_dir() or file_type == stat.S_IFDIR:
            kind = "dir"
        elif file_type == stat.S_IFLNK:
            kind = "symlink"
        elif file_type in {0, stat.S_IFREG}:
            kind = "file"
        else:
            kind = "special"
        target = None
        if kind == "symlink":
            if info.file_size > 4096:
                raise UnsafeArchive(f"oversized symlink target: {info.filename}")
            target = archive.read(info).decode("utf-8")
        members.append(Member(info.filename, kind, info.file_size, info.compress_size, target,
                              stat.S_IMODE(mode) or (0o755 if kind == "dir" else 0o644)))
    return members


def _tar_members(archive: tarfile.TarFile) -> list[Member]:
    members = []
    for info in archive.getmembers():
        if info.isdir():
            kind = "dir"
        elif info.issym():
            kind = "symlink"
        elif info.islnk():
            kind = "hardlink"
        elif info.isreg():
            kind = "file"
        else:
            kind = "special"
        members.append(Member(info.name, kind, info.size if kind == "file" else 0, None,
                              info.linkname if kind in {"symlink", "hardlink"} else None, info.mode))
    return members


def _selected(path: PurePosixPath, include: Sequence[str]) -> bool:
    if not include:
        return True
    text = path.as_posix()
    return any(text == prefix.rstrip("/") or text.startswith(prefix.rstrip("/") + "/") for prefix in include)


def _write_stream(source, destination: Path, declared: int, mode: int) -> None:
    written = 0
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                         0o755 if mode & 0o111 else 0o644)
    with os.fdopen(descriptor, "wb") as stream:
        while chunk := source.read(_CHUNK):
            written += len(chunk)
            if written > declared:
                raise UnsafeArchive(f"member expands beyond its declared size: {destination.name}")
            stream.write(chunk)
    if written != declared:
        raise UnsafeArchive(f"member size does not match its header: {destination.name}")


def _safe_parent(root: Path, path: PurePosixPath) -> Path:
    current = root
    for part in path.parent.parts:
        current = current / part
        if current.is_symlink():
            raise UnsafeArchive(f"extraction would traverse a symlink: {path}")
        current.mkdir(mode=0o755, exist_ok=True)
    return current / path.name


def extract(archive_path: Path, destination: Path, limits: Limits,
            include: Sequence[str] = ()) -> list[PurePosixPath]:
    """Validate every member, then write only the included closure beneath ``destination``."""
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise UnsafeArchive(f"extraction root is not empty: {destination}")
    root = destination.resolve()
    archive_bytes = archive_path.stat().st_size
    written: list[PurePosixPath] = []
    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            members = _zip_members(archive)
            paths = validate_members(members, limits, archive_bytes)
            for member, path, info in zip(members, paths, archive.infolist()):
                if not _selected(path, include):
                    continue
                target = _safe_parent(root, path)
                if member.kind == "dir":
                    target.mkdir(mode=0o755, exist_ok=True)
                elif member.kind == "symlink":
                    os.symlink(member.link_target or "", target)
                else:
                    with archive.open(info) as source:
                        _write_stream(source, target, member.size, member.mode)
                written.append(path)
    elif tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path) as archive:
            infos = archive.getmembers()
            members = _tar_members(archive)
            paths = validate_members(members, limits, archive_bytes)
            for member, path, info in zip(members, paths, infos):
                if not _selected(path, include):
                    continue
                target = _safe_parent(root, path)
                if member.kind == "dir":
                    target.mkdir(mode=0o755, exist_ok=True)
                elif member.kind == "symlink":
                    os.symlink(member.link_target or "", target)
                else:
                    source = archive.extractfile(info)
                    if source is None:
                        raise UnsafeArchive(f"unreadable member: {path}")
                    with source:
                        _write_stream(source, target, member.size, member.mode)
                written.append(path)
    else:
        raise UnsafeArchive(f"unsupported archive format: {archive_path.name}")
    missing = sorted(prefix for prefix in include
                     if not any(_selected(path, (prefix,)) for path in written))
    if missing:
        raise UnsafeArchive(f"reviewed closure members are absent: {', '.join(missing)}")
    return written


def _kind(path: Path, head: bytes) -> str:
    if head.startswith(b"\x7fELF"):
        return "elf"
    if path.suffix == ".jar":
        return "jar"
    if head.startswith(b"#!"):
        return "script"
    return "data"


def _jar_details(path: Path) -> dict[str, list[str]]:
    coordinates: set[str] = set()
    native: set[str] = set()
    with zipfile.ZipFile(path) as jar:
        for info in jar.infolist():
            name = info.filename
            if name.startswith("META-INF/maven/") and name.endswith("/pom.properties") and info.file_size <= 65536:
                values = {}
                for line in jar.read(info).decode("utf-8", "replace").splitlines():
                    key, sep, value = line.partition("=")
                    if sep:
                        values[key.strip()] = value.strip()
                if {"groupId", "artifactId", "version"} <= values.keys():
                    coordinates.add(f"{values['groupId']}:{values['artifactId']}:{values['version']}")
            elif name.endswith((".so", ".dll", ".dylib", ".jnilib")) or ".so." in name.rsplit("/", 1)[-1]:
                native.add(name)
    return {"maven": sorted(coordinates), "native_libraries": sorted(native)}


def inventory(root: Path, archive: dict[str, object], include: Iterable[str]) -> dict[str, object]:
    """Return a deterministic inventory of every regular file and link beneath ``root``."""
    entries = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            entries.append({"path": relative, "kind": "symlink", "target": os.readlink(path)})
            continue
        if not path.is_file():
            continue
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            head = stream.read(4)
            digest.update(head)
            while chunk := stream.read(_CHUNK):
                digest.update(chunk)
        entry: dict[str, object] = {
            "path": relative, "kind": _kind(path, head), "bytes": path.stat().st_size,
            "sha256": digest.hexdigest(), "executable": bool(path.stat().st_mode & 0o111),
        }
        if entry["kind"] == "jar":
            entry.update(_jar_details(path))
        entries.append(entry)
    return {
        "schema": INVENTORY_SCHEMA,
        "archive": archive,
        "include": sorted(include),
        "totals": {
            "files": sum(1 for item in entries if item["kind"] != "symlink"),
            "bytes": sum(int(item.get("bytes", 0)) for item in entries),
            "jars": sum(1 for item in entries if item["kind"] == "jar"),
            "elf": sum(1 for item in entries if item["kind"] == "elf"),
            "scripts": sum(1 for item in entries if item["kind"] == "script"),
        },
        "files": entries,
    }


def manifest_versions(root: Path, jars: Sequence[str]) -> str:
    """Return ``<Implementation-Title> <Implementation-Version>`` lines from verified JAR manifests."""
    lines = []
    for relative in jars:
        with zipfile.ZipFile(root / normalize_name(relative)) as jar:
            fields = {}
            for line in jar.read("META-INF/MANIFEST.MF").decode("utf-8").splitlines():
                key, sep, value = line.partition(": ")
                if sep:
                    fields[key] = value.strip()
        title, version = fields.get("Implementation-Title"), fields.get("Implementation-Version")
        if not title or not version:
            raise UnsafeArchive(f"manifest lacks implementation identity: {relative}")
        lines.append(f"{title} {version}")
    return "".join(line + "\n" for line in lines)


def load_policy(path: Path) -> tuple[Limits, tuple[str, ...], tuple[str, ...]]:
    """Read the reviewed closure allowlist, limits, and version JARs from ``tool.toml``."""
    closure = tomllib.loads(path.read_text(encoding="utf-8"))["closure"]
    limits = Limits(int(closure["max_members"]), int(closure["max_expanded_bytes"]),
                    float(closure["max_member_compression_ratio"]),
                    float(closure["max_archive_expansion_ratio"]))
    return limits, tuple(closure["include"]), tuple(closure.get("version_jars", ()))


def verify_archive(archive: Path, lock_path: Path) -> dict[str, object]:
    """Re-verify the archive against its asset-lock size, SHA-256, and upstream SHA-512."""
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    entries = [item for item in lock["artifacts"] if item.get("role") == "archive"]
    if len(entries) != 1:
        raise UnsafeArchive("asset lock must declare exactly one archive")
    entry = entries[0]
    sha256, sha512, size = hashlib.sha256(), hashlib.sha512(), 0
    with archive.open("rb") as stream:
        while chunk := stream.read(_CHUNK):
            sha256.update(chunk)
            sha512.update(chunk)
            size += len(chunk)
    if size != entry["bytes"] or sha256.hexdigest() != entry["sha256"] or sha512.hexdigest() != entry["sha512"]:
        raise UnsafeArchive("archive does not match the asset lock")
    return {"name": entry["name"], "sha256": entry["sha256"], "bytes": entry["bytes"]}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--policy", type=Path, required=True, help="tool.toml with a [closure] table")
    parser.add_argument("--lock", type=Path, required=True, help="assets.lock.json for the archive")
    parser.add_argument("--inventory", type=Path, help="write the deterministic inventory here")
    parser.add_argument("--expect-inventory", type=Path,
                        help="fail unless the extracted closure equals this reviewed inventory")
    parser.add_argument("--version-file", type=Path,
                        help="write implementation identities from the policy's version JARs")
    args = parser.parse_args(argv)
    try:
        limits, include, version_jars = load_policy(args.policy)
        archive = verify_archive(args.archive, args.lock)
        extract(args.archive, args.destination, limits, include)
        document = inventory(args.destination, archive, include)
        if args.inventory:
            args.inventory.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        if args.expect_inventory:
            if json.loads(args.expect_inventory.read_text(encoding="utf-8")) != document:
                raise UnsafeArchive("extracted closure differs from the reviewed inventory")
        if args.version_file:
            if not version_jars:
                raise UnsafeArchive("policy declares no version JARs for --version-file")
            args.version_file.write_text(manifest_versions(args.destination, version_jars), encoding="utf-8")
    except (UnsafeArchive, KeyError, zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
        print(f"REJECTED {exc}", file=sys.stderr)
        return 2
    print(f"EXTRACTED files={document['totals']['files']} bytes={document['totals']['bytes']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
