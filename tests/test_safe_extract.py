"""Fixture tests for the shared, untrusted-archive extraction helper.

The helper (containers/tools/shared/safe_extract.py) runs inside tool image builds. These tests use
small local archives only; they never invoke Docker or reach the network.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "shared_safe_extract", ROOT / "containers" / "tools" / "shared" / "safe_extract.py")
assert _SPEC and _SPEC.loader
safe_extract = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = safe_extract  # dataclasses resolve their defining module during execution
_SPEC.loader.exec_module(safe_extract)


LIMITS = safe_extract.Limits(max_members=64, max_total_bytes=1 << 20, max_member_ratio=50.0,
                             max_archive_ratio=1000.0)


def _zip(path: Path, entries: list[tuple[str, bytes | None, int | None]]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if mode is not None:
                info.external_attr = mode << 16
            if name.endswith("/"):
                info.external_attr |= 0x10
            archive.writestr(info, data or b"")
    return path


def _tar(path: Path, entries: list[tarfile.TarInfo], data: dict[str, bytes] | None = None) -> Path:
    with tarfile.open(path, "w") as archive:
        for info in entries:
            payload = (data or {}).get(info.name)
            if payload is not None:
                info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload) if payload is not None else None)
    return path


def test_extraction_accepts_a_nested_archive_and_installs_only_the_closure(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "ok.zip", [
        ("joern-cli/", None, stat.S_IFDIR | 0o755),
        ("joern-cli/lib/a.jar", b"jar-bytes", stat.S_IFREG | 0o644),
        ("joern-cli/frontends/c2cpg/bin/c2cpg", b"#!/bin/sh\n", stat.S_IFREG | 0o755),
        ("joern-cli/frontends/other/bin/tool", b"\x7fELF", stat.S_IFREG | 0o755),
        ("joern-cli/link", b"lib/a.jar", stat.S_IFLNK | 0o777),
    ])
    out = tmp_path / "out"
    written = safe_extract.extract(archive, out, LIMITS,
                                   ("joern-cli/lib", "joern-cli/frontends/c2cpg", "joern-cli/link"))
    assert (out / "joern-cli" / "lib" / "a.jar").read_bytes() == b"jar-bytes"
    launcher = out / "joern-cli" / "frontends" / "c2cpg" / "bin" / "c2cpg"
    assert launcher.stat().st_mode & 0o111
    assert not (out / "joern-cli" / "frontends" / "other").exists()
    assert (out / "joern-cli" / "link").is_symlink()
    assert PurePosixPath("joern-cli/frontends/other/bin/tool") not in written


@pytest.mark.parametrize("name", ["../escape.txt", "joern-cli/../../escape.txt", "joern-cli/./x",
                                  "joern-cli//x"])
def test_extraction_rejects_traversal_and_non_canonical_names(tmp_path: Path, name: str) -> None:
    archive = _zip(tmp_path / "bad.zip", [(name, b"x", stat.S_IFREG | 0o644)])
    with pytest.raises(safe_extract.UnsafeArchive):
        safe_extract.extract(archive, tmp_path / "out", LIMITS)
    assert not (tmp_path / "escape.txt").exists()


@pytest.mark.parametrize("name", ["/etc/passwd", "C:/Windows/evil.dll", "c:evil", "joern-cli\\..\\x"])
def test_extraction_rejects_absolute_drive_and_backslash_names(tmp_path: Path, name: str) -> None:
    member = safe_extract.Member(name, "file", 1)
    with pytest.raises(safe_extract.UnsafeArchive):
        safe_extract.validate_members([member], LIMITS, 1)


@pytest.mark.parametrize("target", ["../../outside", "/etc/passwd", "../..", "C:/x"])
def test_extraction_rejects_escaping_symlinks(tmp_path: Path, target: str) -> None:
    archive = _zip(tmp_path / "link.zip", [("joern-cli/link", target.encode(), stat.S_IFLNK | 0o777)])
    with pytest.raises(safe_extract.UnsafeArchive, match="escapes"):
        safe_extract.extract(archive, tmp_path / "out", LIMITS)
    assert not (tmp_path / "out" / "joern-cli" / "link").exists()


def test_extraction_rejects_hard_links_including_escaping_ones(tmp_path: Path) -> None:
    escaping = tarfile.TarInfo("joern-cli/hard")
    escaping.type, escaping.linkname = tarfile.LNKTYPE, "../../etc/passwd"
    with pytest.raises(safe_extract.UnsafeArchive, match="escapes"):
        safe_extract.extract(_tar(tmp_path / "a.tar", [escaping]), tmp_path / "a", LIMITS)
    regular = tarfile.TarInfo("joern-cli/file")
    internal = tarfile.TarInfo("joern-cli/hard")
    internal.type, internal.linkname = tarfile.LNKTYPE, "joern-cli/file"
    with pytest.raises(safe_extract.UnsafeArchive, match="hard links"):
        safe_extract.extract(_tar(tmp_path / "b.tar", [regular, internal], {"joern-cli/file": b"x"}),
                             tmp_path / "b", LIMITS)


def test_extraction_rejects_special_and_setuid_members(tmp_path: Path) -> None:
    fifo = tarfile.TarInfo("joern-cli/pipe")
    fifo.type = tarfile.FIFOTYPE
    with pytest.raises(safe_extract.UnsafeArchive, match="special"):
        safe_extract.extract(_tar(tmp_path / "f.tar", [fifo]), tmp_path / "f", LIMITS)
    archive = _zip(tmp_path / "s.zip", [("joern-cli/su", b"x", stat.S_IFREG | stat.S_ISUID | 0o755)])
    with pytest.raises(safe_extract.UnsafeArchive, match="setuid"):
        safe_extract.extract(archive, tmp_path / "s", LIMITS)


@pytest.mark.parametrize("entries", [
    [("joern-cli/a", b"1", None), ("joern-cli/a", b"2", None)],
    [("joern-cli/a/", None, stat.S_IFDIR | 0o755), ("joern-cli/a", b"2", None)],
    [("joern-cli/a", b"file", None), ("joern-cli/a/b", b"nested", None)],
    [("joern-cli/l", b"d", stat.S_IFLNK | 0o777), ("joern-cli/d/", None, stat.S_IFDIR | 0o755),
     ("joern-cli/l/x", b"through-link", None)],
], ids=["duplicate", "dir-and-file", "file-as-parent", "through-symlink"])
def test_extraction_rejects_duplicate_or_conflicting_members(tmp_path: Path, entries) -> None:
    with pytest.warns(UserWarning) if entries[0][0] == entries[1][0] else _no_warning():
        archive = _zip(tmp_path / "dup.zip", entries)
    with pytest.raises(safe_extract.UnsafeArchive):
        safe_extract.extract(archive, tmp_path / "out", LIMITS)


class _no_warning:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_extraction_enforces_member_count_and_expanded_byte_limits(tmp_path: Path) -> None:
    many = _zip(tmp_path / "many.zip", [(f"joern-cli/{index}", b"x", None) for index in range(65)])
    with pytest.raises(safe_extract.UnsafeArchive, match="members"):
        safe_extract.extract(many, tmp_path / "many", LIMITS)
    large = _zip(tmp_path / "large.zip", [("joern-cli/big", bytes(range(256)) * 8193, None)])
    with pytest.raises(safe_extract.UnsafeArchive, match="expanded size"):
        safe_extract.extract(large, tmp_path / "large", LIMITS)


def test_extraction_enforces_compression_ratio_limits(tmp_path: Path) -> None:
    bomb = _zip(tmp_path / "bomb.zip", [("joern-cli/zeros", b"\0" * 500_000, None)])
    with pytest.raises(safe_extract.UnsafeArchive, match="compression ratio"):
        safe_extract.extract(bomb, tmp_path / "bomb", LIMITS)
    tight = safe_extract.Limits(64, 1 << 20, 1e9, 2.0)
    with pytest.raises(safe_extract.UnsafeArchive, match="expansion ratio"):
        safe_extract.validate_members([safe_extract.Member("joern-cli/x", "file", 300)], tight, 100)


def test_extraction_rejects_members_that_exceed_their_declared_size(tmp_path: Path) -> None:
    source = io.BytesIO(b"x" * 10)
    with pytest.raises(safe_extract.UnsafeArchive, match="declared size"):
        safe_extract._write_stream(source, tmp_path / "out", 4, 0o644)


def test_extraction_requires_every_reviewed_closure_prefix(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "partial.zip", [("joern-cli/lib/a.jar", b"x", None)])
    with pytest.raises(safe_extract.UnsafeArchive, match="frontends/c2cpg"):
        safe_extract.extract(archive, tmp_path / "out", LIMITS,
                             ("joern-cli/lib", "joern-cli/frontends/c2cpg"))


def test_helper_cli_reverifies_lock_and_compares_inventory(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "joern-cli-linux-x86_64.zip", [
        ("joern-cli/lib/io.joern.c2cpg-1.jar", _jar("c2cpg", "1"), None),
    ])
    data = archive.read_bytes()
    lock = tmp_path / "lock.json"
    lock.write_text(json.dumps({"artifacts": [{
        "role": "archive", "name": archive.name, "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(), "sha512": hashlib.sha512(data).hexdigest(),
    }]}), encoding="utf-8")
    policy = tmp_path / "tool.toml"
    policy.write_text('[closure]\ninclude = ["joern-cli/lib"]\n'
                      'version_jars = ["joern-cli/lib/io.joern.c2cpg-1.jar"]\nmax_members = 8\n'
                      'max_expanded_bytes = 1048576\nmax_member_compression_ratio = 50.0\n'
                      'max_archive_expansion_ratio = 10.0\n', encoding="utf-8")
    inventory, version = tmp_path / "inventory.json", tmp_path / "VERSION"
    argv = [str(archive), str(tmp_path / "a"), "--policy", str(policy), "--lock", str(lock)]
    assert safe_extract.main(argv + ["--inventory", str(inventory), "--version-file", str(version)]) == 0
    assert version.read_text(encoding="utf-8") == "c2cpg 1\n"
    assert safe_extract.main([str(archive), str(tmp_path / "b"), "--policy", str(policy), "--lock",
                              str(lock), "--expect-inventory", str(inventory)]) == 0
    tampered = json.loads(inventory.read_text(encoding="utf-8"))
    tampered["files"][0]["sha256"] = "0" * 64
    inventory.write_text(json.dumps(tampered), encoding="utf-8")
    assert safe_extract.main([str(archive), str(tmp_path / "c"), "--policy", str(policy), "--lock",
                              str(lock), "--expect-inventory", str(inventory)]) == 2
    wrong = json.loads(lock.read_text(encoding="utf-8"))
    wrong["artifacts"][0]["sha512"] = "0" * 128
    lock.write_text(json.dumps(wrong), encoding="utf-8")
    assert safe_extract.main(argv[:1] + [str(tmp_path / "d")] + argv[2:]) == 2


def _jar(title: str, version: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as jar:
        jar.writestr("META-INF/MANIFEST.MF", f"Manifest-Version: 1.0\nImplementation-Title: {title}\n"
                                             f"Implementation-Version: {version}\n")
    return buffer.getvalue()


def test_helper_cli_rejects_a_version_file_without_version_jars(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "tool.zip", [("tool/bin/x", b"#!/bin/sh\n", stat.S_IFREG | 0o755)])
    data = archive.read_bytes()
    lock = tmp_path / "lock.json"
    lock.write_text(json.dumps({"artifacts": [{
        "role": "archive", "name": archive.name, "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(), "sha512": hashlib.sha512(data).hexdigest(),
    }]}), encoding="utf-8")
    policy = tmp_path / "tool.toml"
    policy.write_text('[closure]\ninclude = ["tool/bin"]\nmax_members = 8\nmax_expanded_bytes = 1048576\n'
                      'max_member_compression_ratio = 50.0\nmax_archive_expansion_ratio = 10.0\n',
                      encoding="utf-8")
    argv = [str(archive), str(tmp_path / "a"), "--policy", str(policy), "--lock", str(lock)]
    assert safe_extract.main(argv) == 0
    assert safe_extract.main([str(archive), str(tmp_path / "b"), "--policy", str(policy), "--lock",
                              str(lock), "--version-file", str(tmp_path / "VERSION")]) == 2
