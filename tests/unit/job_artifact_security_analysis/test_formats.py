"""Unit tests for formats.py: classify, inspect_archive, parse_wasm, and builtin_observation."""

from __future__ import annotations

import io
from pathlib import Path
import struct
import tarfile
import zipfile

import pytest

from appsec_review.jobs.job_artifact_security_analysis.formats import (
    ArchiveLimits,
    _safe_member,
    builtin_observation,
    classify,
    inspect_archive,
    parse_wasm,
)


def _leb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _wasm_section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _leb128(len(payload)) + payload


def _wasm_name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _leb128(len(raw)) + raw


def _ar_entry(name: str, data: bytes, *, size_text: str | None = None, end: bytes = b"`\n") -> bytes:
    size_str = f"{len(data):<10}" if size_text is None else f"{size_text:<10}"[:10]
    header = (
        f"{name:<16}"[:16].encode("ascii")
        + f"{0:<12}".encode("ascii")
        + f"{0:<6}".encode("ascii")
        + f"{0:<6}".encode("ascii")
        + f"{'100644':<8}".encode("ascii")
        + size_str.encode("ascii")
        + end
    )
    assert len(header) == 60
    pad = b"\n" if len(data) % 2 else b""
    return header + data + pad


@pytest.mark.parametrize(
    ("member", "expected"),
    (
        ("", False),
        (".", True),
        ("a\x00b", False),
        ("/etc/passwd", False),
        ("\\windows\\win.ini", False),
        ("C:/temp/a", False),
        ("../escape", False),
        ("a/../b", False),
        ("a/./b", True),
        ("pkg/sub/file.txt", True),
    ),
)
def test_safe_member_enforces_relative_non_traversal_paths(member: str, expected: bool) -> None:
    assert _safe_member(member) is expected


def test_classify_recognizes_binary_container_producer_and_media_formats(tmp_path: Path) -> None:
    def check(filename: str, data: bytes, producer: dict, *, name: str = "") -> dict:
        path = tmp_path / filename
        path.write_bytes(data)
        return classify(path, producer, name=name)

    assert check("looks.jar", b"\x7fELF\x02\x01" + b"\0" * 32, {"kind": "jar"})["format"] == "elf"
    for idx, magic in enumerate((b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")):
        assert check(f"mach{idx}", magic + b"\0" * 12, {})["format"] == "macho"
    assert check("mod.txt", b"\0asm\x01\0\0\0", {"kind": "generated-output"})["format"] == "wasm"
    assert check("cls.bin", b"\xca\xfe\xba\xbe\0\0\0\x3d", {})["format"] == "jvm-class"
    assert check("native.exe", b"MZ" + b"\0" * 32, {}) == {
        "format": "pe",
        "family": "native",
        "container": False,
        "classification_basis": ["bounded-magic"],
        "declared_kind": "",
    }
    assert check("managed_bsjb.dll", b"MZ\0\0BSJB", {})["format"] == "dotnet-assembly"
    assert check("managed_decl.dll", b"MZ\0\0", {"kind": "managed-assembly"})["family"] == "dotnet"
    for idx, coff_magic in enumerate((b"L\x01", b"d\x86", b"\xaa\x64")):
        assert check(f"obj{idx}.obj", coff_magic + b"\0" * 10, {})["format"] == "coff"

    # Zip variants
    plain_zip = tmp_path / "plain.zip"
    with zipfile.ZipFile(plain_zip, "w") as zf:
        zf.writestr("readme.txt", "hi")
    assert classify(plain_zip, {})["format"] == "zip"

    jar_with_class = tmp_path / "app.jar"
    with zipfile.ZipFile(jar_with_class, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        zf.writestr("com/example/App.class", b"\xca\xfe\xba\xbe")
    assert classify(jar_with_class, {})["format"] == "jvm-archive"

    dex_jar = tmp_path / "dex.jar"
    with zipfile.ZipFile(dex_jar, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        zf.writestr("classes.dex", b"dex\n035\0")
    dex_cls = classify(dex_jar, {})
    assert dex_cls["format"] == "dex-archive" and dex_cls["family"] == "android"

    res_jar = tmp_path / "res.jar"
    with zipfile.ZipFile(res_jar, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        zf.writestr("config.properties", "a=1\n")
    assert classify(res_jar, {})["format"] == "jvm-resource-archive"

    wheel = tmp_path / "pkg.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("pkg-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\n")
    assert classify(wheel, {})["format"] == "python-wheel"

    node_zip = tmp_path / "node.zip"
    with zipfile.ZipFile(node_zip, "w") as zf:
        zf.writestr("package.json", "{}")
    assert classify(node_zip, {})["format"] == "node-package"

    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
    assert classify(apk, {})["format"] == "android-package"

    corrupt_zip = check("corrupt.zip", b"PK\x03\x04not-a-valid-zip", {})
    assert corrupt_zip["format"] == "zip" and corrupt_zip["corrupt"] is True

    # Compressed, tar, ar, installer, phar, and declared archive overrides
    assert check("sdist.gz", b"\x1f\x8b" + b"\0" * 20, {"kind": "sdist"})["format"] == "python-package"
    assert check("bz.bz2", b"BZh9" + b"\0" * 20, {"kind": "phar"})["format"] == "php-package"
    assert check("xz.xz", b"\xfd7zXZ\x00" + b"\0" * 20, {"kind": "package-archive", "producer": {"family": "node"}})["format"] == "node-package"
    assert check("xz_non_node.xz", b"\xfd7zXZ\x00" + b"\0" * 20, {"kind": "package-archive", "producer": {"family": "rust"}})["format"] == "compressed-archive"

    tar_path = tmp_path / "sample.tar"
    with tarfile.open(tar_path, "w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = 2
        tf.addfile(info, io.BytesIO(b"hi"))
    assert classify(tar_path, {"kind": "war"})["format"] == "jvm-archive"
    assert classify(tar_path, {})["format"] == "tar"

    assert check("lib.a", b"!<arch>\n", {})["format"] == "ar-archive"
    assert check("thin.a", b"!<thin>\n", {})["format"] == "ar-archive"
    assert check("pkg.msi", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", {})["format"] == "installer"
    assert check("pkg.rpm", b"\xed\xab\xee\xdb\0\0", {})["format"] == "installer"
    assert check("app.phar", b"<?php __HALT_COMPILER(); ?>GBMB", {})["format"] == "php-phar"

    # Producer-kind fallbacks & media precedence
    assert check("mod.pyc", b"x" * 16, {"kind": "pyc"})["format"] == "python-bytecode"
    assert check("short.pyc", b"x" * 8, {"kind": "pyc"})["format"] == "unknown"
    assert check("custom.so", b"RAWBYTES", {"kind": "shared-library"})["format"] == "unrecognized-native"
    assert check("bundle.js", b"console.log(1)", {"kind": "javascript-bundle"})["format"] == "generated-bundle"

    png_magic = b"\x89PNG\r\n\x1a\n" + b"\0" * 24
    media_over_kind = check("icon.bin", png_magic, {"kind": "executable"})
    assert media_over_kind["family"] == "media-asset"
    assert media_over_kind["classification_basis"] == ["bounded-magic"]

    svg_suffix = check("logo.svg", b"<svg xmlns='http://www.w3.org/2000/svg'/>", {}, name="logo.svg")
    assert svg_suffix["family"] == "media-asset"
    assert svg_suffix["classification_basis"] == ["bounded-magic-unrecognized", "media-suffix"]

    # Suffix must NOT override accepted-producer-kind when magic is unrecognized
    not_media = check("bundle.svg", b"plain bundle bytes", {"kind": "generated-output"}, name="bundle.svg")
    assert not_media["format"] == "generated-bundle"


def test_inspect_archive_handles_zip_tar_ar_and_rejects_unsafe_or_oversized_inputs(tmp_path: Path) -> None:
    assert inspect_archive(tmp_path / "any", ArchiveLimits(depth=1), depth=2) == {
        "members": [],
        "gaps": ["archive nesting depth exceeded"],
        "safe": False,
    }

    # Zip limits: member count, traversal, symlink, member_bytes, ratio, expanded_bytes
    unsafe_zip = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(unsafe_zip, "w") as zf:
        zf.writestr("../escape", b"bad")
        sym = zipfile.ZipInfo("link")
        sym.external_attr = 0o120777 << 16
        zf.writestr(sym, b"target")
        zf.writestr("big.txt", b"A" * 2048, compress_type=zipfile.ZIP_DEFLATED)
        zf.writestr("extra.txt", b"B" * 10)
    zip_res = inspect_archive(
        unsafe_zip,
        ArchiveLimits(members=3, member_bytes=512, expanded_bytes=1024, ratio=2),
    )
    assert zip_res["safe"] is False
    assert "archive member count exceeded" in zip_res["gaps"]
    assert "archive member rejected: ../escape" in zip_res["gaps"]
    assert "archive member rejected: link" in zip_res["gaps"]
    assert "archive member byte limit exceeded: big.txt" in zip_res["gaps"]
    assert "archive expansion ratio exceeded: big.txt" in zip_res["gaps"]
    assert "archive expanded byte limit exceeded" in zip_res["gaps"]

    # Tar: valid directory + file, symlink, FIFO, member_bytes, member count
    tar_file = tmp_path / "mixed.tar"
    with tarfile.open(tar_file, "w") as tf:
        d = tarfile.TarInfo("dir")
        d.type = tarfile.DIRTYPE
        tf.addfile(d)
        f = tarfile.TarInfo("dir/ok.txt")
        f.size = 20
        tf.addfile(f, io.BytesIO(b"x" * 20))
        sym = tarfile.TarInfo("sym")
        sym.type, sym.linkname = tarfile.SYMTYPE, "../x"
        tf.addfile(sym)
        fifo = tarfile.TarInfo("pipe")
        fifo.type = tarfile.FIFOTYPE
        tf.addfile(fifo)
        extra = tarfile.TarInfo("extra.txt")
        extra.size = 1
        tf.addfile(extra, io.BytesIO(b"y"))
    tar_res = inspect_archive(tar_file, ArchiveLimits(members=4, member_bytes=10))
    assert tar_res["safe"] is False
    assert [m["type"] for m in tar_res["members"]] == ["directory", "file"]
    assert "archive member byte limit exceeded: dir/ok.txt" in tar_res["gaps"]
    assert "archive member rejected: sym" in tar_res["gaps"]
    assert "archive member rejected: pipe" in tar_res["gaps"]
    assert "archive member count exceeded" in tar_res["gaps"]
    full_tar = inspect_archive(tar_file, ArchiveLimits(members=10, member_bytes=100))
    assert len(full_tar["members"]) == 3

    # Corrupt archive
    corrupt = tmp_path / "corrupt.tar"
    corrupt.write_bytes(b"not a tar or zip")
    corrupt_res = inspect_archive(corrupt)
    assert corrupt_res["safe"] is False
    assert corrupt_res["gaps"][0].startswith("corrupt or unsupported archive:")

    # Unix ar: GNU long names, BSD #1/ names, special symbol table '/', unsafe name, member byte limit, odd-byte pad
    long_table = b"very_long_member_name.o/\nunterminated_name.o"
    bsd_payload = b"bsd_name.o\x00\x00obj"
    ar_good = tmp_path / "libgood.a"
    ar_good.write_bytes(
        b"!<arch>\n"
        + _ar_entry("/", b"sym")
        + _ar_entry("//", long_table)
        + _ar_entry("/0", b"123")
        + _ar_entry("/25", b"12")
        + _ar_entry(f"#1/{len(bsd_payload)}", bsd_payload)
        + _ar_entry("short.o/", b"a" * 60)
        + _ar_entry("../bad/", b"x")
    )
    ar_res = inspect_archive(ar_good, ArchiveLimits(member_bytes=50))
    assert [m["path"] for m in ar_res["members"]] == [
        "very_long_member_name.o",
        "unterminated_name.o",
        "bsd_name.o",
        "short.o",
    ]
    assert "archive member byte limit exceeded: short.o" in ar_res["gaps"]
    assert "archive member rejected: ../bad" in ar_res["gaps"]

    # Thin ar archive: header declares external size without inline member bytes
    thin_ar = tmp_path / "thin.a"
    thin_ar.write_bytes(b"!<thin>\n" + _ar_entry("ext.o/", b"", size_text="4096"))
    thin_res = inspect_archive(thin_ar)
    assert thin_res["safe"] is True and thin_res["expanded_bytes"] == 4096

    # Malformed / truncated ar variants
    for name, raw_bytes, limits, expected_gap in (
        ("bad_end.a", b"!<arch>\n" + _ar_entry("a.o", b"x", end=b"!\n")[:60], ArchiveLimits(), "header is malformed"),
        ("bad_size.a", b"!<arch>\n" + _ar_entry("a.o", b"", size_text="notint"), ArchiveLimits(), "size is malformed"),
        ("big_long.a", b"!<arch>\n" + _ar_entry("//", b"abcd"), ArchiveLimits(member_bytes=2), "long-name table exceeds"),
        ("bad_bsd.a", b"!<arch>\n" + _ar_entry("#1/xyz", b"abcd"), ArchiveLimits(), "BSD member name is malformed"),
        ("count_ar.a", b"!<arch>\n" + _ar_entry("a.o", b"x") + _ar_entry("b.o", b"y"), ArchiveLimits(members=1), "member count exceeded"),
        ("trunc_ar.a", b"!<arch>\n" + _ar_entry("a.o", b"", size_text="99"), ArchiveLimits(), "member data is truncated"),
        ("tail_ar.a", b"!<arch>\n" + _ar_entry("a.o", b"xy") + b"trailing", ArchiveLimits(), "ends inside a member header"),
    ):
        p = tmp_path / name
        p.write_bytes(raw_bytes)
        res = inspect_archive(p, limits)
        assert any(expected_gap in gap for gap in res["gaps"]), (name, res["gaps"])


def test_parse_wasm_parses_sections_features_and_rejects_malformed_modules() -> None:
    custom_empty = _wasm_section(0, b"")
    custom_named = _wasm_section(0, _wasm_name("producers") + b"\x00")
    imports_payload = (
        _leb128(5)
        + _wasm_name("env") + _wasm_name("fn") + b"\x00" + _leb128(0)
        + _wasm_name("env") + _wasm_name("tbl") + b"\x01\x70\x01" + _leb128(1) + _leb128(4)
        + _wasm_name("env") + _wasm_name("mem") + b"\x02\x07" + _leb128(1) + _leb128(8)
        + _wasm_name("wasi") + _wasm_name("glob") + b"\x03\x7f\x01"
        + _wasm_name("wasi") + _wasm_name("tag") + b"\x04" + _leb128(0) + _leb128(2)
    )
    tables_payload = _leb128(1) + b"\x6f\x00" + _leb128(2)  # externref != 0x70
    memories_payload = (
        _leb128(2)
        + b"\x07" + _leb128(1) + _leb128(2)  # max + shared + memory64
        + b"\x00" + _leb128(1)
    )
    exports_payload = _leb128(1) + _wasm_name("run") + b"\x00" + _leb128(0)
    module = (
        b"\0asm\x01\0\0\0"
        + custom_empty
        + custom_named
        + _wasm_section(2, imports_payload)
        + _wasm_section(4, tables_payload)
        + _wasm_section(5, memories_payload)
        + _wasm_section(7, exports_payload)
    )
    parsed = parse_wasm(module)
    assert parsed["version"] == 1 and parsed["encoding"] == "module"
    assert parsed["custom_sections"] == ["producers"]
    assert len(parsed["imports"]) == 5
    assert parsed["exports"] == [{"name": "run", "kind": 0, "index": 0}]
    assert parsed["capabilities"] == [
        "env",
        "env::fn",
        "env::mem",
        "env::tbl",
        "wasi",
        "wasi::glob",
        "wasi::tag",
    ]
    assert parsed["features"] == {
        "shared_memory": True,
        "memory64": True,
        "multiple_memories": True,
        "reference_tables": True,
    }

    comp = parse_wasm(b"\0asm\x02\0\0\0")
    assert comp["version"] == 2 and comp["encoding"] == "component-or-unknown"

    bad_cases = [
        (b"nope", "invalid WebAssembly header"),
        (b"\0asm\x01\0\0\0\x01\x80", "truncated WebAssembly LEB128"),
        (b"\0asm\x01\0\0\0\x01\x80\x80\x80\x80\x80\x01", "LEB128 exceeds bound"),
        (b"\0asm\x01\0\0\0\x01\x05\x00", "truncated WebAssembly section"),
        (b"\0asm\x01\0\0\0" + _wasm_section(0, _leb128(5000)), "name exceeds bound or section"),
        (b"\0asm\x01\0\0\0" + _wasm_section(5, _leb128(1) + b"\x01\x01"), "truncated WebAssembly LEB128"),
        (
            b"\0asm\x01\0\0\0" + bytes([5]) + _leb128(2) + b"\x01\x01\x01\x02",
            "limits exceed section",
        ),
        (b"\0asm\x01\0\0\0" + _wasm_section(2, _leb128(10_001)), "import count exceeds bound"),
        (b"\0asm\x01\0\0\0" + _wasm_section(2, _leb128(1) + _wasm_name("m") + _wasm_name("f")), "truncated WebAssembly import"),
        (b"\0asm\x01\0\0\0" + _wasm_section(2, _leb128(1) + _wasm_name("m") + _wasm_name("f") + b"\x01"), "truncated WebAssembly table import"),
        (b"\0asm\x01\0\0\0" + _wasm_section(2, _leb128(1) + _wasm_name("m") + _wasm_name("f") + b"\x09"), "unknown WebAssembly import kind"),
        (b"\0asm\x01\0\0\0" + _wasm_section(4, _leb128(10_001)), "table count exceeds bound"),
        (b"\0asm\x01\0\0\0" + _wasm_section(4, _leb128(1)), "truncated WebAssembly table"),
        (b"\0asm\x01\0\0\0" + _wasm_section(5, _leb128(10_001)), "memory count exceeds bound"),
        (b"\0asm\x01\0\0\0" + _wasm_section(7, _leb128(10_001)), "export count exceeds bound"),
        (b"\0asm\x01\0\0\0" + _wasm_section(7, _leb128(1) + _wasm_name("e")), "truncated WebAssembly export"),
        (b"\0asm\x01\0\0\0" + (b"\x01\x00" * 10_001), "section count exceeds bound"),
    ]
    for payload, message in bad_cases:
        with pytest.raises(ValueError, match=message):
            parse_wasm(payload)


def test_builtin_observation_covers_all_inspector_capabilities_and_fallbacks(tmp_path: Path) -> None:
    limits = ArchiveLimits()

    # inventory: plain + container with gap
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"hello")
    obs, gaps = builtin_observation(plain, {"format": "unknown", "container": False}, "inventory", limits)
    assert obs["size_bytes"] == 5 and gaps == []

    bad_zip = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad_zip, "w") as zf:
        zf.writestr("../escape", b"x")
    obs, gaps = builtin_observation(bad_zip, {"format": "zip", "container": True}, "inventory", limits)
    assert "archive" in obs and any("rejected" in g for g in gaps)

    # native: truncated ELF, little/big/unknown ELF, PE/.NET
    short_elf = tmp_path / "short.elf"
    short_elf.write_bytes(b"\x7fELF\x02")
    assert builtin_observation(short_elf, {"format": "elf"}, "native", limits) == (
        {},
        ["ELF header is truncated"],
    )

    elf_le = tmp_path / "le.elf"
    elf_le.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 12 + struct.pack("<H", 62))
    obs, gaps = builtin_observation(elf_le, {"format": "elf"}, "native", limits)
    assert obs["class_bits"] == 64 and obs["endian"] == "little" and obs["machine"] == 62 and gaps

    elf_be = tmp_path / "be.elf"
    elf_be.write_bytes(b"\x7fELF\x01\x02" + b"\0" * 12 + struct.pack(">H", 8))
    obs, _ = builtin_observation(elf_be, {"format": "elf"}, "native", limits)
    assert obs["class_bits"] == 32 and obs["endian"] == "big" and obs["machine"] == 8

    elf_unk = tmp_path / "unk.elf"
    elf_unk.write_bytes(b"\x7fELF\x09\x09" + b"\0" * 14)
    obs, _ = builtin_observation(elf_unk, {"format": "elf"}, "native", limits)
    assert obs["class_bits"] is None and obs["endian"] == "unknown" and obs["machine"] is None

    obs, gaps = builtin_observation(plain, {"format": "dotnet-assembly"}, "native", limits)
    assert obs == {"binary_format": "dotnet-assembly", "managed": True} and gaps

    # jvm: truncated class, valid class, jvm-archive, jvm-resource-archive
    short_cls = tmp_path / "Short.class"
    short_cls.write_bytes(b"\xca\xfe\xba\xbe")
    assert builtin_observation(short_cls, {"format": "jvm-class"}, "jvm", limits) == (
        {},
        ["JVM class header is truncated"],
    )
    ok_cls = tmp_path / "Ok.class"
    ok_cls.write_bytes(b"\xca\xfe\xba\xbe\x00\x01\x00\x3d")
    obs, gaps = builtin_observation(ok_cls, {"format": "jvm-class"}, "jvm", limits)
    assert obs == {"major_version": 61, "minor_version": 1} and gaps

    good_zip = tmp_path / "good.jar"
    with zipfile.ZipFile(good_zip, "w") as zf:
        zf.writestr("a.txt", "ok")
    obs, gaps = builtin_observation(good_zip, {"format": "jvm-archive"}, "jvm", limits)
    assert "archive" in obs and gaps
    obs, gaps = builtin_observation(good_zip, {"format": "jvm-resource-archive"}, "jvm", limits)
    assert obs["class_count"] == 0 and gaps == []

    # wasm: valid + malformed
    wasm_ok = tmp_path / "ok.wasm"
    wasm_ok.write_bytes(b"\0asm\x01\0\0\0")
    obs, gaps = builtin_observation(wasm_ok, {"format": "wasm"}, "wasm", limits)
    assert obs["version"] == 1 and "pinned validator" in gaps[0]
    obs, gaps = builtin_observation(plain, {"format": "wasm"}, "wasm", limits)
    assert obs == {} and "WebAssembly parse failure" in gaps[0]

    # packages: non-container + container; unsupported fallback
    obs, gaps = builtin_observation(plain, {"format": "generated-bundle", "container": False}, "packages", limits)
    assert obs == {"package_format": "generated-bundle"} and gaps
    obs, gaps = builtin_observation(good_zip, {"format": "python-wheel", "container": True}, "packages", limits)
    assert obs["package_format"] == "python-wheel" and "archive" in obs and gaps
    assert builtin_observation(plain, {"format": "unknown"}, "native", limits) == (
        {},
        ["unsupported format for native: unknown"],
    )
