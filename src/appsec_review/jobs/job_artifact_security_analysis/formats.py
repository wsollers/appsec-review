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

from appsec_review.media_assets import MEDIA_ASSET_FAMILY, recognize as recognize_asset


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


_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": (">", 28), b"\xce\xfa\xed\xfe": ("<", 28),
    b"\xfe\xed\xfa\xcf": (">", 32), b"\xcf\xfa\xed\xfe": ("<", 32),
}
_FAT_MAGICS = {
    b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True), b"\xbf\xba\xfe\xca": ("<", True),
}


def _java_header(data: bytes, *, file_bytes: int) -> str | None:
    """Distinguish a malformed discriminator from an unfinished bounded JVM header walk."""
    if len(data) < 10:
        return None
    minor, major, count = struct.unpack_from(">HHH", data, 4)
    if major < 45 or (minor not in {0, 65535} and not (major == 45 and minor <= 3)) or count < 1:
        return None
    offset, index = 10, 1
    sizes = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4,
             12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}
    while index < count:
        if offset >= len(data):
            return "partial" if offset + 15 <= file_bytes else None
        tag = data[offset]
        offset += 1
        if tag == 1:
            if offset + 2 > len(data):
                return "partial" if offset + 16 <= file_bytes else None
            size = int.from_bytes(data[offset:offset + 2], "big")
            offset += 2
        elif tag in sizes:
            size = sizes[tag]
        else:
            return None
        offset += size
        index += 2 if tag in {5, 6} else 1
        if index > count or offset + 14 > file_bytes:
            return None
    if offset + 14 > file_bytes:
        return None
    return "complete" if offset + 14 <= len(data) else "partial"


def _universal_macho(path: Path, head: bytes) -> dict[str, Any]:
    order, wide = _FAT_MAGICS[head[:4]]
    try:
        if len(head) < 8:
            raise ValueError("universal Mach-O header is truncated")
        count = struct.unpack_from(order + "I", head, 4)[0]
        width = 32 if wide else 20
        table_end = 8 + count * width
        if not 1 <= count <= 128:
            raise ValueError("universal Mach-O architecture count is invalid or exceeds bound")
        if table_end > len(head):
            raise ValueError("universal Mach-O architecture table is truncated or exceeds probe bound")
        size = path.stat().st_size
        ranges = []
        with path.open("rb") as stream:
            for index in range(count):
                fields = struct.unpack_from(order + ("IIQQII" if wide else "IIIII"), head, 8 + index * width)
                cpu, subtype, offset, length, align = fields[:5]
                if (align > 63 or offset % (1 << align) or offset < table_end or length < 28
                        or offset + length > size or (wide and fields[5] != 0)):
                    raise ValueError("universal Mach-O slice range or alignment is invalid")
                if any(offset < end and start < offset + length for start, end in ranges):
                    raise ValueError("universal Mach-O slices overlap")
                ranges.append((offset, offset + length))
                stream.seek(offset)
                header = stream.read(32)
                thin = _MACHO_MAGICS.get(header[:4])
                if thin is None or length < thin[1] or len(header) < thin[1]:
                    raise ValueError("universal Mach-O slice header is invalid or truncated")
                slice_cpu, slice_subtype = struct.unpack_from(thin[0] + "II", header, 4)
                if (slice_cpu, slice_subtype) != (cpu, subtype):
                    raise ValueError("universal Mach-O slice architecture disagrees with table")
        return {"format": "macho", "family": "native", "universal": True, "architecture_count": count}
    except ValueError as exc:
        java_header = (_java_header(head, file_bytes=path.stat().st_size)
                       if head[:4] == b"\xca\xfe\xba\xbe" else None)
        if java_header is not None:
            return {"format": "jvm-class", "family": "jvm", "classification_complete": java_header == "complete",
                    **({"gaps": ["JVM classification incomplete: constant pool/header exceeds bounded probe"]}
                       if java_header == "partial" else {})}
        return {"format": "unrecognized-native", "family": "native", "gaps": [str(exc)]}


def classify(path: Path, producer: Mapping[str, Any], *, name: str = "",
             probe_bytes: int = 1024 * 1024) -> dict[str, Any]:
    """Classify from bounded bytes plus accepted producer metadata.

    An extension alone never classifies executable, object, or archive content. ``name`` (the
    artifact's own file name) is consulted only for media/asset files whose bytes matched none of
    those formats, through the unambiguous suffixes declared in ``appsec_review.media_assets``.
    """
    with path.open("rb") as stream:
        head = stream.read(probe_bytes)
    declared = str(producer.get("kind", "")).lower()
    result: dict[str, Any] = {"format": "unknown", "container": False,
                              "classification_basis": ["bounded-magic"]}
    if head.startswith(b"\x7fELF"):
        result.update(format="elf", family="native")
    elif head[:4] in _MACHO_MAGICS:
        result.update(format="macho", family="native")
    elif head[:4] in _FAT_MAGICS:
        result.update(_universal_macho(path, head))
    elif head.startswith(b"\0asm"):
        result.update(format="wasm", family="wasm")
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
            result["zip_member_kinds"] = {
                "class": sum(1 for name in names if name.endswith(".class")),
                "dex": sum(1 for name in names if name.endswith(".dex"))}
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
    elif head.startswith((b"!<arch>\n", b"!<thin>\n")):
        # Unix ar: static libraries (.a) and Rust crate libraries (.rlib) are members lists, not
        # tar or zip, and are inspected by the bounded ar reader below.
        result.update(format="ar-archive", family="archive", container=True)
    elif head.startswith((b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"\xed\xab\xee\xdb")):
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
    kinds = result.pop("zip_member_kinds", None)
    if result["format"] == "jvm-archive" and isinstance(kinds, Mapping) and not kinds["class"]:
        # A jar-named zip without JVM class files is not bytecode: Android dexBuilder outputs carry
        # classes.dex, and resource-only jars (e.g. a Maven package of a non-standard source layout)
        # carry nothing a bytecode analyzer can open.
        if kinds["dex"]:
            result.update(format="dex-archive", family="android",
                          classification_basis=[*result["classification_basis"], "bounded-member-names"])
        else:
            result.update(format="jvm-resource-archive", family="jvm",
                          classification_basis=[*result["classification_basis"], "bounded-member-names"])
    # Media/asset magic outranks a producer kind; a suffix is a fallback only for bytes nothing else
    # recognized (``unknown``), never for content a producer declared as native or bundled.
    by_kind = "accepted-producer-kind" in result["classification_basis"]
    if (result["format"] == "unknown" or by_kind) and (
            asset := recognize_asset(head, "" if by_kind else name or path.name)) is not None:
        result.update(format=asset.format, family=MEDIA_ASSET_FAMILY,
                      asset_category=asset.asset.category.value,
                      classification_basis=["bounded-magic"] if asset.basis == "bounded-magic"
                      else ["bounded-magic-unrecognized", "media-suffix"])
    result["declared_kind"] = declared
    return result


_AR_HEADER = 60
_AR_SPECIAL = {"/", "//", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64"}


def _ar_members(path: Path, limits: ArchiveLimits, *, thin: bool) -> tuple[list[dict[str, Any]], int, list[str]]:
    """List Unix ar members (GNU, BSD, and thin) from headers only; member data is never read
    beyond the GNU long-name table, and nothing is extracted."""
    members: list[dict[str, Any]] = []
    gaps: list[str] = []
    total = 0
    long_names = b""
    size_bytes = path.stat().st_size
    with path.open("rb") as stream:
        offset = 8
        while offset + _AR_HEADER <= size_bytes:
            stream.seek(offset)
            header = stream.read(_AR_HEADER)
            if header[58:60] != b"`\n":
                gaps.append("ar archive member header is malformed")
                break
            raw_name = header[:16].decode("ascii", "replace").rstrip()
            try:
                size = int(header[48:58].decode("ascii").strip() or "0")
            except ValueError:
                gaps.append("ar archive member size is malformed")
                break
            if size < 0:
                gaps.append("ar archive member size is negative")
                break
            data_offset = offset + _AR_HEADER
            name = raw_name
            if raw_name == "//":
                if size > limits.member_bytes:
                    gaps.append("ar long-name table exceeds the member byte limit")
                    break
                long_names = stream.read(size)
            elif raw_name.startswith("#1/"):
                # BSD: the name occupies the first N bytes of the member data.
                try:
                    length = int(raw_name[3:])
                except ValueError:
                    gaps.append("ar archive BSD member name is malformed")
                    break
                if length < 0 or length > size:
                    gaps.append("ar archive BSD member name length is invalid")
                    break
                name = stream.read(min(length, 4096)).split(b"\0", 1)[0].decode("utf-8", "replace")
            elif raw_name.startswith("/") and raw_name[1:].isdigit():
                start = int(raw_name[1:])
                end = long_names.find(b"/\n", start)
                name = long_names[start:end if end >= 0 else None].decode("utf-8", "replace")
            else:
                name = raw_name[:-1] if raw_name.endswith("/") and raw_name not in _AR_SPECIAL else raw_name
            if raw_name not in _AR_SPECIAL and raw_name != "//":
                if len(members) >= limits.members:
                    gaps.append("archive member count exceeded")
                    break
                if not _safe_member(name):
                    gaps.append(f"archive member rejected: {name[:256]}")
                else:
                    total += size
                    if size > limits.member_bytes:
                        gaps.append(f"archive member byte limit exceeded: {name[:256]}")
                    members.append({"path": name, "size_bytes": size, "type": "file"})
            # Thin archives store only headers (and the name table); member data lives elsewhere.
            stored = size if (not thin or raw_name in _AR_SPECIAL or raw_name == "//") else 0
            if data_offset + stored > size_bytes:
                gaps.append("ar archive member data is truncated")
                break
            offset = data_offset + stored + (stored % 2)
        else:
            if offset < size_bytes:
                gaps.append("ar archive ends inside a member header")
    return members, total, gaps


def inspect_archive(path: Path, limits: ArchiveLimits = ArchiveLimits(), *, depth: int = 0) -> dict[str, Any]:
    """Inspect archive metadata without extracting members or following links."""
    if depth > limits.depth:
        return {"members": [], "gaps": ["archive nesting depth exceeded"], "safe": False}
    members: list[dict[str, Any]] = []
    gaps: list[str] = []
    total = 0
    try:
        with path.open("rb") as stream:
            magic = stream.read(8)
        if magic in {b"!<arch>\n", b"!<thin>\n"}:
            members, total, ar_gaps = _ar_members(path, limits, thin=magic == b"!<thin>\n")
            gaps.extend(ar_gaps)
        elif zipfile.is_zipfile(path):
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
    def leb(offset: int, end: int = len(data), bits: int = 32) -> tuple[int, int]:
        value = shift = 0
        for _ in range((bits + 6) // 7):
            if offset >= end: raise ValueError("truncated WebAssembly LEB128")
            byte = data[offset]; offset += 1; value |= (byte & 0x7f) << shift
            if value >= 1 << bits: raise ValueError("WebAssembly LEB128 exceeds bound")
            if not byte & 0x80: return value, offset
            shift += 7
        raise ValueError("WebAssembly LEB128 exceeds bound")
    def name(offset: int, end: int) -> tuple[str, int]:
        size, offset = leb(offset, end)
        if size > 4096 or offset + size > end:
            raise ValueError("WebAssembly name exceeds bound or section")
        return data[offset:offset + size].decode("utf-8", errors="replace"), offset + size
    def limits(offset: int, end: int) -> tuple[dict[str, int], int]:
        flags, offset = leb(offset, end)
        if flags > 7 or (flags & 2 and not flags & 1):
            raise ValueError("WebAssembly limits flags are invalid or unsupported")
        bits = 64 if flags & 4 else 32
        minimum, offset = leb(offset, end, bits)
        value = {"minimum": minimum, "shared": int(bool(flags & 0x2)), "memory64": int(bool(flags & 0x4))}
        if flags & 0x1:
            maximum, offset = leb(offset, end, bits); value["maximum"] = maximum
            if maximum < minimum: raise ValueError("WebAssembly limits maximum is below minimum")
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
            count, cursor = leb(cursor, end)
            if count > 10_000: raise ValueError("WebAssembly import count exceeds bound")
            for _ in range(count):
                module, cursor = name(cursor, end); field, cursor = name(cursor, end)
                if cursor >= end: raise ValueError("truncated WebAssembly import")
                kind = data[cursor]; cursor += 1
                row: dict[str, Any] = {"module": module, "name": field, "kind": kind}
                if kind == 0: row["type_index"], cursor = leb(cursor, end)
                elif kind == 1:
                    if cursor >= end: raise ValueError("truncated WebAssembly table import")
                    row["element_type"] = data[cursor]; cursor += 1
                    row["limits"], cursor = limits(cursor, end)
                elif kind == 2: row["limits"], cursor = limits(cursor, end)
                elif kind == 3: cursor += 2
                elif kind == 4:
                    _, cursor = leb(cursor, end); row["type_index"], cursor = leb(cursor, end)
                else: raise ValueError("unknown WebAssembly import kind")
                imports.append(row)
        elif section_id == 4:
            count, cursor = leb(cursor, end)
            if count > 10_000: raise ValueError("WebAssembly table count exceeds bound")
            for _ in range(count):
                if cursor >= end: raise ValueError("truncated WebAssembly table")
                element = data[cursor]; cursor += 1
                value, cursor = limits(cursor, end); tables.append({"element_type": element, **value})
        elif section_id == 5:
            count, cursor = leb(cursor, end)
            if count > 10_000: raise ValueError("WebAssembly memory count exceeds bound")
            for _ in range(count):
                value, cursor = limits(cursor, end); memories.append(value)
        elif section_id == 7:
            count, cursor = leb(cursor, end)
            if count > 10_000: raise ValueError("WebAssembly export count exceeds bound")
            for _ in range(count):
                field, cursor = name(cursor, end)
                if cursor >= end: raise ValueError("truncated WebAssembly export")
                kind = data[cursor]; cursor += 1
                index, cursor = leb(cursor, end); exports.append({"name": field, "kind": kind, "index": index})
        if section_id in {2, 4, 5, 7} and cursor != end:
            raise ValueError("WebAssembly entries do not match section bounds")
        offset = end
    if offset != len(data): raise ValueError("WebAssembly section count exceeds bound")
    version = int.from_bytes(data[4:8], "little")
    capabilities = sorted({row["module"] for row in imports} |
                          {f"{row['module']}::{row['name']}" for row in imports})
    all_memories = [*memories, *(row["limits"] for row in imports if row["kind"] == 2)]
    all_tables = [*tables, *(row for row in imports if row["kind"] == 1)]
    return {"version": version, "encoding": "module" if version == 1 else "component-or-unknown",
            "sections": sections, "custom_sections": custom, "imports": imports, "exports": exports,
            "memories": memories, "tables": tables, "capabilities": capabilities,
            "has_imports": bool(imports), "has_exports": bool(exports),
            "has_memory": bool(all_memories), "has_tables": bool(all_tables),
            "features": {"shared_memory": any(row.get("shared") for row in all_memories),
                         "memory64": any(row.get("memory64") for row in all_memories),
                         "multiple_memories": len(all_memories) > 1,
                         "reference_tables": any(row.get("element_type") != 0x70 for row in all_tables)}}


def builtin_observation(path: Path, classification: Mapping[str, Any], capability: str,
                        limits: ArchiveLimits) -> tuple[dict[str, Any], list[str]]:
    fmt = classification["format"]
    gaps: list[str] = list(classification.get("gaps", ()))
    if capability == "inventory":
        value: dict[str, Any] = {"classification": dict(classification), "size_bytes": path.stat().st_size}
        if classification.get("container"):
            value["archive"] = inspect_archive(path, limits)
            gaps.extend(value["archive"]["gaps"])
        return value, gaps
    if capability == "packages":
        value = {"package_format": fmt}
        if classification.get("container"):
            value["archive"] = inspect_archive(path, limits)
            gaps.extend(value["archive"]["gaps"])
            if not gaps:
                value["security_risks"], risk_gaps = _packaged_archive_risks(path, limits)
                gaps.extend(risk_gaps)
        return value, [*gaps, "SBOM/dependency vulnerability matching requires available pinned Syft and vulnerability data"]
    with path.open("rb") as stream:
        data = stream.read(16 * 1024 * 1024)
        input_truncated = bool(stream.read(1)) if capability == "wasm" else False
    if capability == "native" and fmt == "elf":
        if len(data) < 20: return {}, ["ELF header is truncated"]
        endian = "little" if data[5] == 1 else "big" if data[5] == 2 else "unknown"
        order = "<" if endian == "little" else ">"
        machine = struct.unpack(order + "H", data[18:20])[0] if endian != "unknown" else None
        risks, risk_gaps = _elf_hardening(data, binary_name=path.name)
        return {"binary_format": "ELF", "class_bits": {1: 32, 2: 64}.get(data[4]),
                "endian": endian, "machine": machine, "symbols": "requires-pinned-scanner",
                "imports": "requires-pinned-scanner", "hardening": "bounded-header-indicators",
                "security_risks": risks}, [
                *gaps, *risk_gaps, "native symbols/imports/exports/loader and stack canary assessment require a pinned scanner"]
    if capability == "native" and fmt == "macho":
        return {"binary_format": fmt, "universal": classification.get("universal", False)}, [
            *gaps, "Mach-O symbols/imports/exports/loader and hardening require a pinned scanner"]
    if capability == "native" and fmt in {"pe", "coff", "dotnet-assembly", "unrecognized-native"}:
        return {"binary_format": fmt, "managed": fmt == "dotnet-assembly"}, [
            *gaps, "PE/COFF symbols/imports/exports/loader and hardening require a pinned scanner"]
    if capability == "jvm" and fmt == "jvm-class":
        if len(data) < 8: return {}, ["JVM class header is truncated"]
        return {"major_version": int.from_bytes(data[6:8], "big"),
                "minor_version": int.from_bytes(data[4:6], "big")}, [
                *gaps, "JVM bytecode security rules require a pinned scanner"]
    if capability == "jvm" and fmt == "jvm-archive":
        return {"archive": inspect_archive(path, limits)}, ["JVM bytecode security rules require a pinned scanner"]
    if capability == "jvm" and fmt == "jvm-resource-archive":
        archive = inspect_archive(path, limits)
        return {"archive": archive, "class_count": 0}, list(archive["gaps"])
    if capability == "wasm" and fmt == "wasm":
        if input_truncated:
            return {"input_complete": False, "inspected_bytes": len(data)}, [
                *gaps, "WebAssembly input truncated at builtin byte bound; resource and feature facts unavailable",
                "WebAssembly feature and capability policy requires a pinned validator"]
        try: return parse_wasm(data), ["WebAssembly feature and capability policy requires a pinned validator"]
        except ValueError as exc: return {}, [f"WebAssembly parse failure: {exc}"]
    return {}, [f"unsupported format for {capability}: {fmt}"]


import re as _re

_PACKAGED_SECRET_RULES: tuple[tuple[str, _re.Pattern[str], str], ...] = (
    ("SECRET_PRIVATE_KEY", _re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
     "Packaged configuration embeds a PEM private key header."),
    ("SECRET_AWS_ACCESS_KEY", _re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "Packaged configuration embeds an AWS access key identifier."),
    ("SECRET_GITHUB_TOKEN", _re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b"),
     "Packaged configuration embeds a GitHub personal/server token."),
    ("SECRET_HARDCODED_CREDENTIAL", _re.compile(
        r"(?i)\b(?:jwt[_-]?secret|api[_-]?secret|client[_-]?secret|private[_-]?key|db[_-]?password)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_-]{12,}['\"]?"
    ), "Packaged configuration assigns a hardcoded secret or credential value."),
)

_CONTAINER_RISK_RULES: tuple[tuple[str, _re.Pattern[str], str], ...] = (
    ("CONTAINER_PRIVILEGED_MODE", _re.compile(r"(?i)\bprivileged\s*:\s*true\b|--privileged\b"),
     "Matched a privileged-execution directive."),
    ("CONTAINER_ROOT_USER", _re.compile(r"(?im)(?:^\s*USER\s+(?:root|0(?::0)?)\s*$|\buser\s*:\s*['\"]?(?:root|0)['\"]?\s*$)"),
     "Matched an explicit root-user directive."),
    ("CONTAINER_DEBUG_PORT", _re.compile(r"(?im)(?:^\s*EXPOSE\s+[^\n]*\b(2375|5005|5678|9229|2345|40000)\b|\bports\s*:\s*(?:\n\s*-\s*['\"]?(?:\d+:)?(2375|5005|5678|9229|2345|40000)\b))"),
     "Matched a sensitive remote debug or daemon port directive."),
    ("CONTAINER_HOST_NETWORK", _re.compile(r"(?i)\b(?:network_mode\s*:\s*['\"]?host['\"]?|hostNetwork\s*:\s*true)\b"),
     "Matched a host-network directive."),
)


def inspect_packaged_text_risks(text: str, *, member_path: str) -> list[dict[str, Any]]:
    """Redacted text-pattern candidates, not proof of active configuration or usable credentials."""
    risks: list[dict[str, Any]] = []
    for check_id, pattern, message in _PACKAGED_SECRET_RULES:
        if pattern.search(text):
            risks.append({
                "check_id": check_id,
                "category": "packaged_secret",
                "severity": None,
                "subject": member_path,
                "member_path": member_path,
                "message": f"Text-pattern candidate: {message} Requires configuration review. ({member_path})",
                "assessment_basis": "text-pattern",
                "lead_candidate": True,
                "attack_class": "packaged_hardcoded_secret",
                "severity_hint": "unknown",
            })
    for check_id, pattern, message in _CONTAINER_RISK_RULES:
        m = pattern.search(text)
        if m:
            port = next((g for g in m.groups() if g), None) if m.groups() else None
            entry: dict[str, Any] = {
                "check_id": check_id,
                "category": "container_security",
                "severity": None,
                "subject": member_path,
                "member_path": member_path,
                "message": f"Text-pattern candidate: {message} Requires configuration review. ({member_path})",
                "assessment_basis": "text-pattern",
                "lead_candidate": True,
                "attack_class": "dangerous_container_configuration",
                "severity_hint": "unknown",
            }
            if port:
                entry["port"] = port
            risks.append(entry)
    return risks


_CONFIG_SUFFIXES = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env"}


def _is_packaged_config_member(name: str) -> bool:
    member = PurePosixPath(name)
    return member.suffix.lower() in _CONFIG_SUFFIXES or member.name.lower() in {"dockerfile", ".env"}


def _inspect_ar_packaged_configs(
    stream,
    size_bytes: int,
    limits: ArchiveLimits,
    *,
    thin: bool,
    inspect,
    gaps: list[str],
    seen: set[str],
) -> None:
    """Inspect inline config members in Unix ar archives without dereferencing thin external paths."""
    offset = 8
    long_names = b""
    member_index = 0
    while offset + _AR_HEADER <= size_bytes:
        stream.seek(offset)
        header = stream.read(_AR_HEADER)
        if len(header) != _AR_HEADER or header[58:60] != b"`\n":
            raise ValueError("ar archive member header is malformed")
        raw_name = header[:16].decode("ascii", "replace").rstrip()
        try:
            size = int(header[48:58].decode("ascii").strip() or "0")
        except ValueError as exc:
            raise ValueError("ar archive member size is malformed") from exc
        if size < 0:
            raise ValueError("ar archive member size is negative")
        data_offset = offset + _AR_HEADER
        stored = size if (not thin or raw_name in _AR_SPECIAL or raw_name == "//") else 0
        if data_offset + stored > size_bytes:
            raise ValueError("ar archive member data is truncated")
        if raw_name == "//":
            if size > limits.member_bytes:
                raise ValueError("ar long-name table exceeds the member byte limit")
            long_names = stream.read(size)
        elif raw_name not in _AR_SPECIAL:
            payload_offset = data_offset
            payload_size = size
            if raw_name.startswith("#1/"):
                try:
                    bsd_len = int(raw_name[3:])
                except ValueError as exc:
                    raise ValueError("ar archive BSD member name is malformed") from exc
                if bsd_len < 0 or bsd_len > size or (thin and bsd_len > 0):
                    raise ValueError("ar archive BSD member name length is invalid")
                name = stream.read(min(bsd_len, 4096)).split(b"\0", 1)[0].decode("utf-8", "replace")
                payload_offset = data_offset + bsd_len
                payload_size = size - bsd_len
            elif raw_name.startswith("/") and raw_name[1:].isdigit():
                start = int(raw_name[1:])
                end = long_names.find(b"/\n", start)
                name = long_names[start:end if end >= 0 else None].decode("utf-8", "replace")
            else:
                name = raw_name[:-1] if raw_name.endswith("/") else raw_name
            if member_index >= limits.members:
                raise ValueError("packaged member count exceeded")
            member_index += 1
            if not _safe_member(name):
                raise ValueError(f"unsafe packaged member path: {name[:256]}")
            if _is_packaged_config_member(name):
                if thin:
                    if name in seen:
                        raise ValueError("duplicate packaged member path")
                    seen.add(name)
                    gaps.append(f"packaged configuration external thin-archive member not inspected: {name[:256]}")
                else:
                    def _read_slice(pos: int = payload_offset, total_len: int = payload_size):
                        read_pos = 0

                        def _read(limit: int = -1) -> bytes:
                            nonlocal read_pos
                            avail = total_len - read_pos
                            if avail <= 0:
                                return b""
                            take = avail if limit < 0 else min(limit, avail)
                            stream.seek(pos + read_pos)
                            chunk = stream.read(take)
                            read_pos += len(chunk)
                            return chunk

                        return _read

                    inspect(name, payload_size, _read_slice())
        offset = data_offset + stored + (stored % 2)
    if offset < size_bytes:
        raise ValueError("ar archive ends inside a member header")


def _packaged_archive_risks(path: Path, limits: ArchiveLimits) -> tuple[list[dict[str, Any]], list[str]]:
    risks: list[dict[str, Any]] = []
    gaps: list[str] = []
    remaining = limits.expanded_bytes
    seen: set[str] = set()

    def inspect(name: str, size: int, read) -> None:
        nonlocal remaining
        if name in seen:
            raise ValueError("duplicate packaged member path")
        seen.add(name)
        if not _is_packaged_config_member(name):
            return
        # Text matching is deliberately narrower than archive inventory; report every selected omission.
        bound = min(limits.member_bytes, remaining, 1024 * 1024)
        if size > bound:
            gaps.append(f"packaged configuration byte bound exceeded: {name[:256]}")
            return
        data = read(bound + 1)
        remaining -= len(data)
        if len(data) != size:
            raise ValueError("packaged member size differs from metadata")
        try:
            text = data.decode("utf-8")
        except UnicodeError:
            gaps.append(f"packaged configuration is not UTF-8: {name[:256]}")
            return
        risks.extend(inspect_packaged_text_risks(text, member_path=name))

    try:
        with path.open("rb") as stream:
            magic = stream.read(8)
            if magic in {b"!<arch>\n", b"!<thin>\n"}:
                stream.seek(0, 2)
                _inspect_ar_packaged_configs(
                    stream, stream.tell(), limits,
                    thin=magic == b"!<thin>\n", inspect=inspect, gaps=gaps, seen=seen,
                )
                return risks, gaps
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                for index, info in enumerate(archive.infolist()):
                    if index >= limits.members:
                        raise ValueError("packaged member count exceeded")
                    if not info.is_dir():
                        with archive.open(info) as member:
                            inspect(info.filename, info.file_size, member.read)
        else:
            with tarfile.open(path, mode="r:*") as archive:
                for index, info in enumerate(archive):
                    if index >= limits.members:
                        raise ValueError("packaged member count exceeded")
                    if info.isfile():
                        with archive.extractfile(info) as member:
                            inspect(info.name, info.size, member.read)
    except (OSError, EOFError, ValueError, RuntimeError, tarfile.TarError, zipfile.BadZipFile) as exc:
        # Do not publish an ambiguous first/last member when a name occurs twice.
        return [], [*gaps, f"packaged configuration inspection incomplete: {exc}"]
    return risks, gaps


def _elf_hardening(data: bytes, *, binary_name: str) -> tuple[list[dict[str, Any]], list[str]]:
    if len(data) < 16 or not data.startswith(b"\x7fELF") or data[4] not in {1, 2}:
        return [], ["ELF header is invalid or truncated"]
    is_64 = data[4] == 2
    endian = "<" if data[5] == 1 else (">" if data[5] == 2 else None)
    if endian is None or len(data) < (64 if is_64 else 52):
        return [], ["ELF header is invalid or truncated"]
    if (data[6] != 1 or struct.unpack_from(endian + "I", data, 20)[0] != 1
            or struct.unpack_from(endian + "H", data, 52 if is_64 else 40)[0] != (64 if is_64 else 52)):
        return [], ["ELF header is invalid: unsupported version or header size"]
    e_type = struct.unpack_from(endian + "H", data, 16)[0]
    risks: list[dict[str, Any]] = []
    gaps: list[str] = []
    # ET_EXEC (2) instead of ET_DYN (3) indicates a non-PIE fixed-address executable.
    if e_type == 2:
        risks.append({
            "check_id": "CHECK_PIE",
            "category": "binary_hardening",
            "severity": None,
            "subject": binary_name,
            "binary": binary_name,
            "indicator": "ET_EXEC",
            "message": f"ELF header for {binary_name} declares ET_EXEC (a non-PIE indicator).",
            "lead_candidate": True,
            "attack_class": "binary_missing_hardening",
            "severity_hint": "unknown",
            "assessment_basis": "ELF-header",
        })
    # Parse bounded program headers for PT_GNU_STACK (0x6474e551) and PT_GNU_RELRO (0x6474e552).
    try:
        if is_64:
            e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 54)
        else:
            e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 42)
        has_relro = False
        exec_stack = False
        if e_phnum == 0:
            gaps.append("ELF has no program headers; segment hardening assessment unavailable")
        elif e_phoff < (64 if is_64 else 52) or e_phentsize < (56 if is_64 else 32) or e_phnum > 128:
            gaps.append("ELF program header table is invalid or exceeds bound")
        elif e_phoff + e_phnum * e_phentsize > len(data):
            gaps.append("ELF program header table is truncated at the input bound")
        else:
            for idx in range(e_phnum):
                off = e_phoff + idx * e_phentsize
                p_type = struct.unpack_from(endian + "I", data, off)[0]
                p_flags = struct.unpack_from(endian + "I", data, off + (4 if is_64 else 24))[0]
                if p_type == 0x6474E551 and (p_flags & 0x1):  # PF_X on PT_GNU_STACK
                    exec_stack = True
                if p_type == 0x6474E552:
                    has_relro = True
            if exec_stack:
                risks.append({
                    "check_id": "CHECK_NX",
                    "category": "binary_hardening",
                    "severity": None,
                    "subject": binary_name,
                    "binary": binary_name,
                    "indicator": "PT_GNU_STACK_PF_X",
                    "message": f"ELF program headers for {binary_name} request an executable stack.",
                    "lead_candidate": True,
                    "attack_class": "binary_missing_hardening",
                    "severity_hint": "unknown",
                    "assessment_basis": "ELF-program-headers",
                })
            if e_type in {2, 3} and not has_relro:
                risks.append({
                    "check_id": "CHECK_RELRO",
                    "category": "binary_hardening",
                    "severity": None,
                    "subject": binary_name,
                    "binary": binary_name,
                    "indicator": "MISSING_PT_GNU_RELRO",
                    "message": f"ELF program-header table for {binary_name} contains no PT_GNU_RELRO entry.",
                    "lead_candidate": True,
                    "attack_class": "binary_missing_hardening",
                    "severity_hint": "unknown",
                    "assessment_basis": "ELF-program-headers",
                })
    except struct.error:
        gaps.append("ELF program header table is malformed")
    return risks, gaps


def inspect_elf_hardening_indicators(data: bytes, *, binary_name: str) -> list[dict[str, Any]]:
    """Observed ELF header/segment indicators only; absent symbol strings prove no canary property."""
    return _elf_hardening(data, binary_name=binary_name)[0]
