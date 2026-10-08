"""Bounded, non-executing produced-artifact classification and container inspection."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import io
from pathlib import Path, PurePosixPath
import struct
import tarfile
from typing import Any
import zipfile


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    members: int = 10_000
    expanded_bytes: int = 512 * 1024 * 1024
    member_bytes: int = 128 * 1024 * 1024
    ratio: int = 1_000
    depth: int = 4


def _safe_member(name: str) -> bool:
    if not name or "\x00" in name or name.startswith(("/", "\\")):
        return False
    normalized = name.replace("\\", "/")
    if len(normalized) >= 2 and normalized[1] == ":":
        return False
    return not any(part in {"", ".", ".."} for part in PurePosixPath(normalized).parts)


def classify(path: Path, producer: Mapping[str, Any], *, probe_bytes: int = 1024 * 1024) -> dict[str, Any]:
    """Classify from bounded bytes plus accepted producer metadata, never extension alone."""
    with path.open("rb") as stream:
        head = stream.read(probe_bytes)
    declared = str(producer.get("kind", "")).lower()
    result: dict[str, Any] = {"format": "unknown", "container": False,
                              "classification_basis": ["bounded-magic"]}
    if head.startswith(b"\x7fELF"):
        result.update(format="elf", family="native")
    elif head.startswith(b"\0asm"):
        result.update(format="wasm", family="wasm")
    elif head.startswith(b"\xca\xfe\xba\xbe"):
        result.update(format="jvm-class", family="jvm")
    elif head.startswith(b"MZ"):
        managed = b"BSJB" in head or declared in {"managed-assembly", "dotnet-assembly"}
        result.update(format="dotnet-assembly" if managed else "pe", family="dotnet" if managed else "native")
    elif len(head) >= 2 and head[:2] in {b"L\x01", b"d\x86", b"\xaa\x64"}:
        result.update(format="coff", family="native")
    elif head.startswith(b"PK\x03\x04"):
        result.update(format="zip", family="archive", container=True)
        try:
            with zipfile.ZipFile(path) as archive:
                names = {item.filename for item in archive.infolist()[:20_000]}
            if "META-INF/MANIFEST.MF" in names:
                result.update(format="jvm-archive", family="jvm")
            elif any(name.endswith(".dist-info/WHEEL") for name in names):
                result.update(format="python-wheel", family="python")
            elif "package.json" in names:
                result.update(format="node-package", family="node")
            elif "AndroidManifest.xml" in names:
                result.update(format="android-package", family="archive")
        except (OSError, zipfile.BadZipFile):
            result["corrupt"] = True
    elif head.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00")):
        result.update(format="compressed-archive", family="archive", container=True)
    elif len(head) > 265 and head[257:263] in {b"ustar\0", b"ustar "}:
        result.update(format="tar", family="archive", container=True)
    elif head.startswith((b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"!<arch>\n", b"\xed\xab\xee\xdb")):
        result.update(format="installer", family="archive", container=True)
    elif b"__HALT_COMPILER" in head and b"GBMB" in head:
        result.update(format="php-phar", family="php", container=True)
    elif declared in {"python-bytecode", "pyc"} and len(head) >= 16:
        result.update(format="python-bytecode", family="python",
                      classification_basis=["bounded-header", "accepted-producer-kind"])
    elif declared in {"native-extension", "shared-library", "executable", "object", "static-library"}:
        result.update(format="unrecognized-native", family="native",
                      classification_basis=["bounded-magic", "accepted-producer-kind"])
    elif declared in {"node-bundle", "javascript-bundle", "generated-output", "package"}:
        result.update(format="generated-bundle", family="node",
                      classification_basis=["bounded-content", "accepted-producer-kind"])
    producer_family = str(producer.get("producer", {}).get("family", "")).lower()
    if result["format"] in {"zip", "compressed-archive", "tar"}:
        if declared in {"wheel", "source-distribution", "sdist", "zipapp", "python-package"}:
            result.update(format="python-package", family="python")
        elif declared in {"jar", "war", "ear", "jvm-archive"}:
            result.update(format="jvm-archive", family="jvm")
        elif declared in {"phar", "php-package"}:
            result.update(format="php-package", family="php")
        elif declared in {"node-package", "package-archive"} and producer_family == "node":
            result.update(format="node-package", family="node")
    result["declared_kind"] = declared
    return result


def inspect_archive(path: Path, limits: ArchiveLimits = ArchiveLimits(), *, depth: int = 0) -> dict[str, Any]:
    """Inspect archive metadata without extracting members or following links."""
    if depth > limits.depth:
        return {"members": [], "gaps": ["archive nesting depth exceeded"], "safe": False}
    members: list[dict[str, Any]] = []
    gaps: list[str] = []
    total = 0
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                infos = archive.infolist()
                if len(infos) > limits.members:
                    gaps.append("archive member count exceeded")
                for info in infos[:limits.members]:
                    mode = (info.external_attr >> 16) & 0o170000
                    unsafe = not _safe_member(info.filename) or mode == 0o120000
                    if unsafe:
                        gaps.append(f"archive member rejected: {info.filename[:256]}")
                        continue
                    total += info.file_size
                    if info.file_size > limits.member_bytes:
                        gaps.append(f"archive member byte limit exceeded: {info.filename[:256]}")
                    if info.file_size > max(1, info.compress_size) * limits.ratio:
                        gaps.append(f"archive expansion ratio exceeded: {info.filename[:256]}")
                    members.append({"path": info.filename, "size_bytes": info.file_size,
                                    "compressed_bytes": info.compress_size, "crc32": f"{info.CRC:08x}"})
        else:
            with tarfile.open(path, mode="r:*") as archive:
                for index, info in enumerate(archive):
                    if index >= limits.members:
                        gaps.append("archive member count exceeded")
                        break
                    if not _safe_member(info.name) or info.issym() or info.islnk() or not (info.isfile() or info.isdir()):
                        gaps.append(f"archive member rejected: {info.name[:256]}")
                        continue
                    total += info.size
                    if info.size > limits.member_bytes:
                        gaps.append(f"archive member byte limit exceeded: {info.name[:256]}")
                    members.append({"path": info.name, "size_bytes": info.size, "type": "directory" if info.isdir() else "file"})
    except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile) as exc:
        gaps.append(f"corrupt or unsupported archive: {type(exc).__name__}")
    if total > limits.expanded_bytes:
        gaps.append("archive expanded byte limit exceeded")
    return {"members": members, "member_count": len(members), "expanded_bytes": total,
            "gaps": list(dict.fromkeys(gaps)), "safe": not gaps}


def parse_wasm(data: bytes) -> dict[str, Any]:
    if not data.startswith(b"\0asm") or len(data) < 8:
        raise ValueError("invalid WebAssembly header")
    def leb(offset: int) -> tuple[int, int]:
        value = shift = 0
        for _ in range(5):
            if offset >= len(data): raise ValueError("truncated WebAssembly LEB128")
            byte = data[offset]; offset += 1; value |= (byte & 0x7f) << shift
            if not byte & 0x80: return value, offset
            shift += 7
        raise ValueError("WebAssembly LEB128 exceeds bound")
    def name(offset: int, end: int) -> tuple[str, int]:
        size, offset = leb(offset)
        if size > 4096 or offset + size > end:
            raise ValueError("WebAssembly name exceeds bound or section")
        return data[offset:offset + size].decode("utf-8", errors="replace"), offset + size
    def limits(offset: int, end: int) -> tuple[dict[str, int], int]:
        flags, offset = leb(offset)
        minimum, offset = leb(offset)
        value = {"minimum": minimum, "shared": int(bool(flags & 0x2)), "memory64": int(bool(flags & 0x4))}
        if flags & 0x1:
            maximum, offset = leb(offset); value["maximum"] = maximum
        if offset > end: raise ValueError("WebAssembly limits exceed section")
        return value, offset
    sections, imports, exports, memories, tables, custom = [], [], [], [], [], []
    offset = 8
    while offset < len(data) and len(sections) < 10_000:
        section_id = data[offset]; offset += 1
        size, offset = leb(offset)
        end = offset + size
        if end > len(data): raise ValueError("truncated WebAssembly section")
        sections.append({"id": section_id, "size_bytes": size})
        cursor = offset
        if section_id == 0 and cursor < end:
            value, _ = name(cursor, end); custom.append(value)
        elif section_id == 2:
            count, cursor = leb(cursor)
            if count > 10_000: raise ValueError("WebAssembly import count exceeds bound")
            for _ in range(count):
                module, cursor = name(cursor, end); field, cursor = name(cursor, end)
                if cursor >= end: raise ValueError("truncated WebAssembly import")
                kind = data[cursor]; cursor += 1
                row: dict[str, Any] = {"module": module, "name": field, "kind": kind}
                if kind == 0: row["type_index"], cursor = leb(cursor)
                elif kind == 1:
                    if cursor >= end: raise ValueError("truncated WebAssembly table import")
                    row["element_type"] = data[cursor]; cursor += 1
                    row["limits"], cursor = limits(cursor, end)
                elif kind == 2: row["limits"], cursor = limits(cursor, end)
                elif kind == 3: cursor += 2
                elif kind == 4:
                    _, cursor = leb(cursor); row["type_index"], cursor = leb(cursor)
                else: raise ValueError("unknown WebAssembly import kind")
                imports.append(row)
        elif section_id == 4:
            count, cursor = leb(cursor)
            if count > 10_000: raise ValueError("WebAssembly table count exceeds bound")
            for _ in range(count):
                if cursor >= end: raise ValueError("truncated WebAssembly table")
                element = data[cursor]; cursor += 1
                value, cursor = limits(cursor, end); tables.append({"element_type": element, **value})
        elif section_id == 5:
            count, cursor = leb(cursor)
            if count > 10_000: raise ValueError("WebAssembly memory count exceeds bound")
            for _ in range(count):
                value, cursor = limits(cursor, end); memories.append(value)
        elif section_id == 7:
            count, cursor = leb(cursor)
            if count > 10_000: raise ValueError("WebAssembly export count exceeds bound")
            for _ in range(count):
                field, cursor = name(cursor, end)
                if cursor >= end: raise ValueError("truncated WebAssembly export")
                kind = data[cursor]; cursor += 1
                index, cursor = leb(cursor); exports.append({"name": field, "kind": kind, "index": index})
        offset = end
    if offset != len(data): raise ValueError("WebAssembly section count exceeds bound")
    version = int.from_bytes(data[4:8], "little")
    capabilities = sorted({row["module"] for row in imports} |
                          {f"{row['module']}::{row['name']}" for row in imports})
    return {"version": version, "encoding": "module" if version == 1 else "component-or-unknown",
            "sections": sections, "custom_sections": custom, "imports": imports, "exports": exports,
            "memories": memories, "tables": tables, "capabilities": capabilities,
            "has_imports": bool(imports), "has_exports": bool(exports),
            "has_memory": bool(memories), "has_tables": bool(tables),
            "features": {"shared_memory": any(row.get("shared") for row in memories),
                         "memory64": any(row.get("memory64") for row in memories),
                         "multiple_memories": len(memories) > 1,
                         "reference_tables": any(row.get("element_type") != 0x70 for row in tables)}}


def builtin_observation(path: Path, classification: Mapping[str, Any], capability: str,
                        limits: ArchiveLimits) -> tuple[dict[str, Any], list[str]]:
    fmt = classification["format"]
    gaps: list[str] = []
    if capability == "inventory":
        value: dict[str, Any] = {"classification": dict(classification), "size_bytes": path.stat().st_size}
        if classification.get("container"):
            value["archive"] = inspect_archive(path, limits)
            gaps.extend(value["archive"]["gaps"])
        return value, gaps
    with path.open("rb") as stream:
        data = stream.read(16 * 1024 * 1024)
    if capability == "native" and fmt == "elf":
        if len(data) < 20: return {}, ["ELF header is truncated"]
        endian = "little" if data[5] == 1 else "big" if data[5] == 2 else "unknown"
        order = "<" if endian == "little" else ">"
        machine = struct.unpack(order + "H", data[18:20])[0] if endian != "unknown" else None
        return {"binary_format": "ELF", "class_bits": {1: 32, 2: 64}.get(data[4]),
                "endian": endian, "machine": machine, "symbols": "requires-pinned-scanner",
                "imports": "requires-pinned-scanner", "hardening": "requires-pinned-scanner"}, [
                "native symbols/imports/exports/loader and hardening require a pinned scanner"]
    if capability == "native" and fmt in {"pe", "coff", "dotnet-assembly", "unrecognized-native"}:
        return {"binary_format": fmt, "managed": fmt == "dotnet-assembly"}, [
            "PE/COFF symbols/imports/exports/loader and hardening require a pinned scanner"]
    if capability == "jvm" and fmt == "jvm-class":
        if len(data) < 8: return {}, ["JVM class header is truncated"]
        return {"major_version": int.from_bytes(data[6:8], "big"),
                "minor_version": int.from_bytes(data[4:6], "big")}, [
                "JVM bytecode security rules require a pinned scanner"]
    if capability == "jvm" and fmt == "jvm-archive":
        return {"archive": inspect_archive(path, limits)}, ["JVM bytecode security rules require a pinned scanner"]
    if capability == "wasm" and fmt == "wasm":
        try: return parse_wasm(data), ["WebAssembly feature and capability policy requires a pinned validator"]
        except ValueError as exc: return {}, [f"WebAssembly parse failure: {exc}"]
    if capability == "packages":
        value = {"package_format": fmt}
        if classification.get("container"): value["archive"] = inspect_archive(path, limits)
        return value, ["SBOM/dependency vulnerability matching requires available pinned Syft and vulnerability data"]
    return {}, [f"unsupported format for {capability}: {fmt}"]
