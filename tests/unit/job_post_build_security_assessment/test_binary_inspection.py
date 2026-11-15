from __future__ import annotations

from pathlib import Path
import struct

import pytest

from appsec_review.jobs.job_post_build_security_assessment import assessment
from appsec_review.jobs.job_post_build_security_assessment.assessment import inspect_binary


def _write_rich_elf64_pie(path: Path) -> None:
    shstr_names = [
        "",
        ".shstrtab",
        ".dynstr",
        ".dynsym",
        ".symtab",
        ".rela.dyn",
        ".debug_info",
        ".note.gnu.build-id",
    ]
    shstr_offsets: dict[str, int] = {}
    shstr = bytearray()
    for name in shstr_names:
        shstr_offsets[name] = len(shstr)
        shstr.extend(name.encode("ascii") + b"\x00")

    dyn_names = [
        "",
        "libc.so.6",
        "/opt/rpath",
        "/opt/runpath",
        "__stack_chk_fail",
        "__memcpy_chk",
        "exported_fn",
    ]
    dyn_offsets: dict[str, int] = {}
    dynstr = bytearray()
    for name in dyn_names:
        dyn_offsets[name] = len(dynstr)
        dynstr.extend(name.encode("ascii") + b"\x00")

    dynsym = b"".join(
        [
            struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0),
            struct.pack("<IBBHQQ", dyn_offsets["__stack_chk_fail"], 0x12, 0, 0, 0, 0),
            struct.pack("<IBBHQQ", dyn_offsets["__memcpy_chk"], 0x12, 0, 0, 0, 0),
            struct.pack("<IBBHQQ", dyn_offsets["exported_fn"], 0x12, 0, 1, 0x1200, 16),
        ]
    )
    interp = b"/lib64/ld-linux-x86-64.so.2\x00"
    note = struct.pack("<III", 4, 8, 3) + b"GNU\x00" + bytes.fromhex("0102030405060708")

    phnum = 5
    phoff = 64
    phentsize = 56
    cursor = phoff + phnum * phentsize

    interp_off = cursor
    cursor += len(interp)
    cursor = (cursor + 7) & ~7

    dynstr_off = cursor
    cursor += len(dynstr)
    cursor = (cursor + 7) & ~7

    dynsym_off = cursor
    cursor += len(dynsym)
    cursor = (cursor + 7) & ~7

    shstr_off = cursor
    cursor += len(shstr)
    cursor = (cursor + 7) & ~7

    note_off = cursor
    cursor += len(note)
    cursor = (cursor + 7) & ~7

    dyn_entries = b"".join(
        struct.pack("<qQ", tag, val)
        for tag, val in [
            (5, dynstr_off),
            (10, len(dynstr)),
            (1, dyn_offsets["libc.so.6"]),
            (15, dyn_offsets["/opt/rpath"]),
            (29, dyn_offsets["/opt/runpath"]),
            (0x6FFFFFFB, 1),
            (0, 0),
        ]
    )
    dyn_off = cursor
    cursor += len(dyn_entries)
    cursor = (cursor + 7) & ~7

    shoff = cursor
    total_load = shoff + 8 * 64

    phdrs = b"".join(
        [
            struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total_load, total_load, 4096),
            struct.pack("<IIQQQQQQ", 3, 4, interp_off, interp_off, 0, len(interp), len(interp), 1),
            struct.pack("<IIQQQQQQ", 2, 6, dyn_off, dyn_off, 0, len(dyn_entries), len(dyn_entries), 8),
            struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16),
            struct.pack("<IIQQQQQQ", 0x6474E552, 4, 0, 0, 0, 64, 64, 1),
        ]
    )

    shdrs = b"".join(
        [
            struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            struct.pack("<IIQQQQIIQQ", shstr_offsets[".shstrtab"], 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0),
            struct.pack("<IIQQQQIIQQ", shstr_offsets[".dynstr"], 3, 0, dynstr_off, dynstr_off, len(dynstr), 0, 0, 1, 0),
            struct.pack("<IIQQQQIIQQ", shstr_offsets[".dynsym"], 11, 0, dynsym_off, dynsym_off, len(dynsym), 2, 0, 8, 24),
            struct.pack("<IIQQQQIIQQ", shstr_offsets[".symtab"], 2, 0, dynsym_off, dynsym_off, len(dynsym), 2, 0, 8, 24),
            struct.pack("<IIQQQQIIQQ", shstr_offsets[".rela.dyn"], 4, 0, 0, 0, 0, 0, 0, 8, 24),
            struct.pack("<IIQQQQIIQQ", shstr_offsets[".debug_info"], 1, 0, 0, 0, 0, 0, 0, 1, 0),
            struct.pack("<IIQQQQIIQQ", shstr_offsets[".note.gnu.build-id"], 7, 0, 0, note_off, len(note), 0, 0, 4, 0),
        ]
    )

    image = bytearray(total_load)
    image[:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        image,
        16,
        3,
        62,
        1,
        0x1000,
        phoff,
        shoff,
        0,
        64,
        phentsize,
        phnum,
        64,
        8,
        1,
    )
    image[phoff : phoff + len(phdrs)] = phdrs
    image[interp_off : interp_off + len(interp)] = interp
    image[dynstr_off : dynstr_off + len(dynstr)] = dynstr
    image[dynsym_off : dynsym_off + len(dynsym)] = dynsym
    image[shstr_off : shstr_off + len(shstr)] = shstr
    image[note_off : note_off + len(note)] = note
    image[dyn_off : dyn_off + len(dyn_entries)] = dyn_entries
    image[shoff : shoff + len(shdrs)] = shdrs
    path.write_bytes(image)


def _write_elf32_be_exec_with_unmapped_dynamic(path: Path) -> None:
    dynstr = b"\x00sym32\x00"
    dynsym = struct.pack(">IIIBBH", 1, 0, 4, 0x12, 0, 1)
    dyn_entries = struct.pack(">iI", 5, 0xDEAD0000) + struct.pack(">iI", 0, 0)
    phoff = 52
    phdrs = b"".join(
        [
            struct.pack(">IIIIIIII", 2, 116, 0x2000, 0, len(dyn_entries), len(dyn_entries), 6, 4),
            struct.pack(">IIIIIIII", 0x6474E551, 0, 0, 0, 0, 0, 7, 4),
        ]
    )
    dyn_off = phoff + len(phdrs)
    dynstr_off = dyn_off + len(dyn_entries)
    dynsym_off = dynstr_off + len(dynstr)
    shoff = dynsym_off + len(dynsym)
    shdrs = b"".join(
        [
            struct.pack(">IIIIIIIIII", 0, 3, 0, 0, dynstr_off, len(dynstr), 0, 0, 1, 0),
            struct.pack(">IIIIIIIIII", 0, 11, 0, 0, dynsym_off, len(dynsym), 0, 0, 4, 16),
        ]
    )
    image = bytearray(shoff + len(shdrs))
    image[:16] = b"\x7fELF" + bytes([1, 2, 1, 0]) + bytes(8)
    struct.pack_into(
        ">HHIIIIIHHHHHH",
        image,
        16,
        2,
        20,
        1,
        0x1000,
        phoff,
        shoff,
        0,
        52,
        32,
        3,  # declare 3 phdrs so the 3rd hits the truncated-phdr break cleanly
        40,
        3,  # declare 3 shdrs so the 3rd hits the truncated-shdr break cleanly
        99,  # shstrndx out of range -> empty strings fallback
    )
    image[phoff : phoff + len(phdrs)] = phdrs
    image[dyn_off : dyn_off + len(dyn_entries)] = dyn_entries
    image[dynstr_off : dynstr_off + len(dynstr)] = dynstr
    image[dynsym_off : dynsym_off + len(dynsym)] = dynsym
    image[shoff : shoff + len(shdrs)] = shdrs
    path.write_bytes(image)


def _write_rich_pe(path: Path, *, pe64: bool = True, dll: bool = True) -> None:
    pe_offset = 0x40
    optional_size = 240 if pe64 else 224
    section_offset = pe_offset + 24 + optional_size
    rdata_raw = 0x200
    debug_raw = 0x400
    image = bytearray(0x480)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    characteristics = 0x2002 if dll else 0x0002
    struct.pack_into(
        "<HHIIIHH",
        image,
        pe_offset + 4,
        0x8664 if pe64 else 0x14C,
        2,
        1700000000,
        4,
        2,
        optional_size,
        characteristics,
    )
    optional = pe_offset + 24
    struct.pack_into("<H", image, optional, 0x20B if pe64 else 0x10B)
    struct.pack_into("<H", image, optional + 70, 0x4160)
    dir_count_off = optional + (108 if pe64 else 92)
    dir_off = optional + (112 if pe64 else 96)
    struct.pack_into("<I", image, dir_count_off, 16)
    struct.pack_into("<II", image, dir_off + 0 * 8, 0x1000, 40)
    struct.pack_into("<II", image, dir_off + 1 * 8, 0x1050, 40)
    struct.pack_into("<II", image, dir_off + 5 * 8, 0x2000, 8)
    struct.pack_into("<II", image, dir_off + 6 * 8, 0x2008, 28)

    image[section_offset : section_offset + 8] = b".rdata\x00\x00"
    struct.pack_into(
        "<IIIIIIHHI",
        image,
        section_offset + 8,
        0x200,
        0x1000,
        0x200,
        rdata_raw,
        0,
        0,
        1,
        0,
        0x40000040,
    )
    sec2 = section_offset + 40
    image[sec2 : sec2 + 8] = b".debug\x00\x00"
    struct.pack_into(
        "<IIIIIIHHI",
        image,
        sec2 + 8,
        0x40,
        0x2000,
        0x40,
        debug_raw,
        0,
        0,
        0,
        0,
        0x40000040,
    )

    # Export directory at RVA 0x1000 (file offset 0x200); export string at header RVA 0x0010 (< section_offset)
    image[0x10 : 0x10 + 12] = b"ExportedApi\x00"
    struct.pack_into("<IIHHIIIIIII", image, rdata_raw, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0x1028, 0)
    struct.pack_into("<I", image, rdata_raw + 0x28, 0x0010)

    # Import descriptor at RVA 0x1050 (file offset 0x250)
    struct.pack_into("<IIIII", image, rdata_raw + 0x50, 0x1080, 0, 0, 0x10B0, 0x1080)
    image[rdata_raw + 0xB0 : rdata_raw + 0xBD] = b"KERNEL32.dll\x00"
    image[rdata_raw + 0xC0 : rdata_raw + 0xCE] = b"\x00\x00CreateFileW\x00"
    if pe64:
        struct.pack_into("<QQQ", image, rdata_raw + 0x80, 0x10C0, (1 << 63) | 42, 0)
    else:
        struct.pack_into("<III", image, rdata_raw + 0x80, 0x10C0, (1 << 31) | 42, 0)
    path.write_bytes(image)


def _write_macho(path: Path, *, bits64: bool = True, big_endian: bool = False) -> None:
    endian = ">" if big_endian else "<"
    magic = {
        ("<", True): b"\xcf\xfa\xed\xfe",
        (">", True): b"\xfe\xed\xfa\xcf",
        ("<", False): b"\xce\xfa\xed\xfe",
        (">", False): b"\xfe\xed\xfa\xce",
    }[(endian, bits64)]

    dylib_str = b"/usr/lib/libSystem.B.dylib\x00\x00"
    lc_dylib = struct.pack(endian + "III", 0xC, 12 + len(dylib_str), 12) + dylib_str
    rpath_str = b"@executable_path/../Frameworks\x00\x00"
    lc_rpath = struct.pack(endian + "III", 0x8000001C, 12 + len(rpath_str), 12) + rpath_str
    uuid_bytes = bytes(range(1, 17))
    lc_uuid = struct.pack(endian + "II", 0x1B, 24) + uuid_bytes
    lc_bad = struct.pack(endian + "II", 0x99, 4)  # size < 8 triggers clean break

    cmds = lc_dylib + lc_rpath + lc_uuid + lc_bad
    flags = 0x200000 | 0x1000000 | 0x02000000
    if bits64:
        hdr = magic + struct.pack(endian + "iiIIIII", 0x01000007, 3, 2, 5, len(cmds), flags, 0)
    else:
        hdr = magic + struct.pack(endian + "iiIIII", 7, 3, 6, 5, len(cmds), flags)
    path.write_bytes(hdr + cmds)


def test_elf_64_and_32_inspection_and_malformed_cases(tmp_path: Path) -> None:
    pie = tmp_path / "app.pie"
    _write_rich_elf64_pie(pie)
    rec = inspect_binary(pie)
    assert rec["format"] == "ELF" and rec["kind"] == "pie_executable" and rec["bits"] == 64
    assert rec["executed"] is False
    assert rec["interpreter"] == "/lib64/ld-linux-x86-64.so.2"
    assert rec["dependencies"] == ["libc.so.6"]
    assert rec["rpath"] == ["/opt/rpath"]
    assert rec["runpath"] == ["/opt/runpath"]
    assert rec["build_id"] == "0102030405060708"
    assert rec["imports"] == ["__memcpy_chk", "__stack_chk_fail"]
    assert rec["exports"] == ["exported_fn"]
    assert rec["relocations"] == [".rela.dyn"]
    assert rec["debug"] == {"present": True, "sections": [".debug_info"]}
    assert rec["symbols"]["present"] is True and rec["symbols"]["stripped"] is False
    assert rec["hardening"] == {
        "pie": True,
        "relro": True,
        "now": True,
        "nx_stack": True,
        "control_flow": None,
        "stack_canary": True,
        "fortify": True,
    }
    assert rec["gaps"] == []

    be32 = tmp_path / "app32.be"
    _write_elf32_be_exec_with_unmapped_dynamic(be32)
    rec32 = inspect_binary(be32)
    assert rec32["format"] == "ELF" and rec32["kind"] == "executable" and rec32["bits"] == 32
    assert rec32["hardening"]["pie"] is False
    assert rec32["hardening"]["nx_stack"] is False
    assert rec32["exports"] == ["sym32"]
    assert "ELF dynamic string table could not be resolved" in rec32["gaps"]

    bad_elf = tmp_path / "bad.elf"
    bad_elf.write_bytes(b"\x7fELF\x09\x09" + bytes(64))
    assert inspect_binary(bad_elf)["format"] == "malformed"


def test_pe_coff_macho_archive_bitcode_linkmap_and_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pe64 = tmp_path / "lib.dll"
    _write_rich_pe(pe64, pe64=True, dll=True)
    r64 = inspect_binary(pe64)
    assert r64["format"] == "PE/COFF" and r64["kind"] == "dll" and r64["bits"] == 64
    assert r64["dependencies"] == ["KERNEL32.dll"]
    assert r64["imports"] == ["KERNEL32.dll!CreateFileW", "KERNEL32.dll!ordinal:42"]
    assert r64["exports"] == ["ExportedApi"]
    assert r64["relocations"] == [".rdata", "base-relocations"]
    assert r64["debug"] == {"present": True, "sections": [".debug"]}
    assert r64["symbols"] == {"present": True, "stripped": False}
    assert r64["hardening"]["guard_cf"] is True

    pe32 = tmp_path / "app32.exe"
    _write_rich_pe(pe32, pe64=False, dll=False)
    r32 = inspect_binary(pe32)
    assert r32["kind"] == "executable" and r32["bits"] == 32
    assert r32["imports"] == ["KERNEL32.dll!CreateFileW", "KERNEL32.dll!ordinal:42"]

    pe_nodir = tmp_path / "nodir.exe"
    nodir_bytes = bytearray(0x80 + 24 + 0x60)
    nodir_bytes[:2] = b"MZ"
    struct.pack_into("<I", nodir_bytes, 0x3C, 0x80)
    nodir_bytes[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", nodir_bytes, 0x84, 0x8664, 0, 0, 0, 0, 0x60, 0x0002)
    pe_nodir.write_bytes(nodir_bytes)
    assert "PE data-directory table is unavailable or truncated" in inspect_binary(pe_nodir)["gaps"]

    for name, bad_bytes in [("short.exe", b"MZshort"), ("badsig.exe", b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40) + b"NOPE" + bytes(32))]:
        p = tmp_path / name
        p.write_bytes(bad_bytes)
        assert inspect_binary(p)["format"] == "malformed"

    coff = tmp_path / "unit.obj"
    coff_sec = b".drectve" + struct.pack("<IIIIIIHHI", 4, 0, 4, 60, 0, 0, 2, 0, 0x00100A00)
    coff.write_bytes(struct.pack("<HHIIIHH", 0x14C, 1, 0, 4, 1, 0, 0) + coff_sec + b"abcd")
    rcoff = inspect_binary(coff)
    assert rcoff["format"] == "COFF" and rcoff["bits"] == 32
    assert rcoff["relocations"] == [".drectve"]
    assert rcoff["debug"] == {"present": True, "sections": [".drectve"]}

    bad_coff = tmp_path / "bad.obj"
    bad_coff.write_bytes(struct.pack("<HHIIIHH", 0x9999, 1, 0, 0, 0, 0, 0))
    assert inspect_binary(bad_coff)["format"] == "malformed"
    trunc_coff = tmp_path / "trunc.obj"
    trunc_coff.write_bytes(struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 0, 0))
    assert inspect_binary(trunc_coff)["format"] == "malformed"

    m64 = tmp_path / "app.macho"
    _write_macho(m64, bits64=True, big_endian=False)
    rm64 = inspect_binary(m64)
    assert rm64["format"] == "Mach-O" and rm64["kind"] == "executable" and rm64["bits"] == 64
    assert rm64["dependencies"] == ["/usr/lib/libSystem.B.dylib"]
    assert rm64["rpath"] == ["@executable_path/../Frameworks"]
    assert rm64["build_id"] == bytes(range(1, 17)).hex()
    assert rm64["hardening"] == {"pie": True, "no_heap_execution": True, "app_extension_safe": True}

    m32 = tmp_path / "lib.dylib"
    _write_macho(m32, bits64=False, big_endian=True)
    rm32 = inspect_binary(m32)
    assert rm32["format"] == "Mach-O" and rm32["kind"] == "dylib" and rm32["bits"] == 32

    ar = tmp_path / "odd.a"
    payload = b"12345"  # odd length exercises 2-byte archive member alignment
    hdr = (
        "odd.o/".ljust(16)
        + "0".ljust(12)
        + "0".ljust(6)
        + "0".ljust(6)
        + "100644".ljust(8)
        + str(len(payload)).ljust(10)
        + "`\n"
    ).encode("ascii")
    ar.write_bytes(b"!<arch>\n" + hdr + payload + b"\n" + hdr + payload + b"\n")
    rar = inspect_binary(ar)
    assert rar["format"] == "archive" and len(rar["archive_members"]) == 2

    empty_ar = tmp_path / "empty.a"
    empty_ar.write_bytes(b"!<thin>\n" + b"x" * 60)
    assert "archive member table was empty or unsupported" in inspect_binary(empty_ar)["gaps"]

    bad_size_ar = tmp_path / "badsize.a"
    bad_hdr = ("bad.o/".ljust(48) + "not-an-int" + "`\n").encode("ascii")
    bad_size_ar.write_bytes(b"!<arch>\n" + bad_hdr)
    assert inspect_binary(bad_size_ar)["archive_members"] == []

    bc = tmp_path / "mod.bc"
    bc.write_bytes(b"BC\xc0\xde\x01\x02\x03\x04")
    assert inspect_binary(bc)["format"] == "LLVM bitcode"

    lmap = tmp_path / "app.linkmap"
    lmap.write_text("# Path: app\n", encoding="utf-8")
    assert inspect_binary(lmap)["format"] == "link-map"

    misc = tmp_path / "notes.txt"
    misc.write_text("plain text", encoding="utf-8")
    assert inspect_binary(misc)["format"] == "unsupported"

    sym = tmp_path / "link.so"
    sym.symlink_to(misc)
    with pytest.raises(ValueError, match="regular non-symlink file"):
        inspect_binary(sym)
    with pytest.raises(ValueError, match="regular non-symlink file"):
        inspect_binary(tmp_path / "missing.bin")

    monkeypatch.setattr(assessment, "MAX_BINARY_BYTES", 4)
    over = inspect_binary(misc)
    assert over["format"] == "unsupported"
    assert over["gaps"] == ["artifact exceeds binary inspection byte bound"]
