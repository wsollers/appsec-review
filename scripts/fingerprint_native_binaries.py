#!/usr/bin/env python3
"""
fingerprint_native_binaries.py — closes the "46% of the SBOM is unscanned
Windows binaries" coverage gap (see cve-triage-2026-09-08-v2-server-ranked.md
and the goal-conformance review's Part B Scenario 2) by walking a set of
confirmed-real paths that syft could not resolve to a package identity, and
for every .dll/.exe found:

  - computing a SHA256 hash (identity/tamper-detection — this is the part
    that actually answers "is this the binary we think it is," which no
    other step in this toolbox does for anything in this bucket)
  - extracting embedded PE VERSIONINFO metadata (FileVersion, ProductVersion,
    CompanyName, ProductName, OriginalFilename, InternalName) via `pefile` —
    parses the PE resource section directly from file bytes, so this works
    identically on Windows, Linux, or inside the toolbox's Docker container;
    no Win32 API calls, no ctypes, no platform dependency
  - flagging a mismatch between the filename and the binary's own embedded
    OriginalFilename/ProductName (the specific tamper-detection signal named
    in Part B Scenario 2 of the goal-conformance review)
  - flagging any section/segment that is writable AND executable at once
    (PE section Characteristics for .dll/.exe; ELF PT_LOAD program-header
    flags for .so) — legitimate compiler output essentially never produces
    this; it's the classic packer / self-modifying-code / hand-rolled-loader
    signature, and the single highest-value signal this script produces
  - flagging any section whose byte-level Shannon entropy is high enough to
    suggest packed/encrypted/compressed content (PE only — ELF section-level
    entropy is not computed in this pass)
  - reporting whether debug info is present or stripped (PE debug directory
    / PDB reference; ELF .symtab presence via pyelftools when installed)
  - reporting whether a PE binary carries an Authenticode signature block at
    all, and — if the optional `cryptography` package is installed —
    attempting to extract the signer's certificate subject. This is
    PRESENCE detection only: it does not validate the certificate chain,
    check revocation, or confirm the signature is cryptographically valid
    over the file's current bytes. A real chain-validation verdict needs
    `signtool verify /pa` (Windows) or an equivalent tool with a real trust
    store — this script tells you whether there's something there to check,
    not whether that something is trustworthy.

Two outputs, written to -o/--output:
  - binary-fingerprints.csv / .md   — full detail, one row per binary
  - native-dependencies.csv         — new rows APPENDED (never overwrites an
    existing row for a path already present) into the exact schema
    build_layered_sbom.py's `native-template` subcommand already uses
    (path, guessed_product, guessed_version, confidence,
    purl_if_constructible, cve_lookup_status, notes) — so this script fills
    that CSV in automatically instead of the fully-manual walk the playbook
    originally called for, and the two tools stay compatible: run this
    first, then `native-template` again if you want to hand-seed anything
    it couldn't identify.

Requires `pefile` (pip install pefile --break-system-packages). Pure stdlib
otherwise — same "run anywhere" philosophy as profile_repo.py.

IMPORTANT — smoke-test before the real run: PE version-resource parsing has
edge cases (packed/obfuscated binaries, resources compiled by non-MSVC
toolchains, corrupt/absent resource sections) that are much cheaper to find
against one known-good file than against the real evidence tree. Before
pointing this at F:\\Barracuda, run it against a handful of files you already
know the answer for, e.g.:

    python3 fingerprint_native_binaries.py C:\\Windows\\System32\\kernel32.dll -o smoke-test

...and confirm the ProductVersion/CompanyName columns come back populated
and sane (e.g. "Microsoft Corporation") before trusting the real run.

Usage — RECOMMENDED: run against the whole confirmed-real fsh-server tree in
one pass, not just the two/three components the CVE triage already named.
The 46%-unscanned-binary gap is repo-wide (any native binary syft couldn't
resolve to a package identity), not specific to the PHP interpreter and
WOD/ApiUpload — those were just the components already confirmed real when
the gap was first written up. Scanning broadly and classifying afterward
(same pattern already used for the SBOM/CVE work: gather everything, sort
real-vs-vendored-vs-build-tooling second) is more reliable than trying to
guess every relevant subpath up front:

    python3 fingerprint_native_binaries.py "F:\\Barracuda\\fsh-server" \\
        -o F:\\Barracuda\\evidence-server\\native-binaries

This will also pick up things outside the three previously-named paths —
e.g. vendored .so-shaped native libs under Server/lib/libs (tcmalloc,
lua++, zlib), FASTBuild tool binaries, and anything else with no
package-manager manifest. That's intentional: let the native-dependencies.csv
output carry the full picture, then classify real-vs-build-tooling-vs-vendored
the same way architecture-discovered-2026-09-08.md already does for source
components, rather than filtering at scan time and risking a silent miss.

Default extensions scanned: .dll, .exe (PE), .so, .dylib (shared objects),
.a, .lib (static archives), .pdb (debug symbols) — matches profile_repo.py's
own BINARY_NATIVE_EXTS list, so this script's coverage lines up with what
the repo profiler already inventories as "native/opaque binaries." Add
--ext .sys or --ext .ocx if you find other Windows binary types worth
including.

Narrower alternative, if you specifically want just the two originally-named
components re-run quickly (e.g. after a partial fix):
    python3 fingerprint_native_binaries.py \\
        "F:\\Barracuda\\fsh-server\\Server\\www\\gdip\\tools\\php-7.3.19-nts-Win32-VC15-x64" \\
        "F:\\Barracuda\\fsh-server\\GM\\gaiya\\WOD" \\
        "F:\\Barracuda\\fsh-server\\GM\\gaiya\\文件上传接口\\ApiUpload" \\
        -o F:\\Barracuda\\evidence-server\\native-binaries
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import pefile
except ImportError:
    sys.exit(
        "This script requires pefile: pip install pefile --break-system-packages\n"
        "(pure-Python PE parser — reads the file's own bytes, no Windows API "
        "needed, works on any OS.)"
    )

# Optional — only used for deeper ELF metadata (SONAME, needed-library list,
# stripped-symbol detection). Not required: every binary still gets hashed,
# format-tagged, and W^X-segment-checked without it (that check is done with
# stdlib struct against the raw program header table, deliberately not
# gated behind an optional dependency since it's the primary new signal).
try:
    from elftools.elf.elffile import ELFFile  # type: ignore
    _HAVE_PYELFTOOLS = True
except ImportError:
    _HAVE_PYELFTOOLS = False

# Optional — only used to pull the signer's certificate subject out of an
# Authenticode signature once we already know one is present (from the PE
# security data directory). Presence/size of the signature is always
# reported without this; only the "who signed it" detail needs it.
try:
    from cryptography.hazmat.primitives.serialization import pkcs7 as _pkcs7
    _HAVE_CRYPTOGRAPHY = True
except ImportError:
    _HAVE_CRYPTOGRAPHY = False

# Same rationale as profile_repo.py's DEFAULT_EXCLUDE_DIRS — never descend
# into VCS internals or build/cache output that can't be a real shipped
# binary.
DEFAULT_EXCLUDE_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "__pycache__", ".pytest_cache",
}

# Matches profile_repo.py's BINARY_NATIVE_EXTS exactly, so this script's
# coverage lines up with what the repo profiler already inventories as
# "native/opaque binaries" — .dll/.exe (PE), .so/.dylib (shared objects),
# .a/.lib (static archives), .pdb (debug symbols, occasionally worth hashing
# for provenance even though they carry no runtime behavior themselves).
# Originally this defaulted to .dll/.exe only, which under-covers the actual
# "components with no package-manager manifest" gap the CVE triage
# identified — that gap isn't PE-specific, it's "any native binary syft
# couldn't resolve," and this repo has already been profiled as containing
# vendored .so-shaped native libs too (tcmalloc/lua++/zlib under
# Server/lib/libs), not just Windows binaries.
DEFAULT_EXTS = {".dll", ".exe", ".so", ".dylib", ".a", ".lib", ".pdb"}

NATIVE_TEMPLATE_HEADER = [
    "path", "guessed_product", "guessed_version", "confidence",
    "purl_if_constructible", "cve_lookup_status", "notes",
]

FINGERPRINT_HEADER = [
    "path", "bytes", "sha256",
    "file_version", "product_version",
    "company_name", "product_name", "original_filename", "internal_name",
    "name_mismatch", "parse_status",
    "rwx_sections", "high_entropy_sections", "debug_status", "pdb_reference",
    "signature_status", "signer_cn",
]


def _parsed_ok(status: str) -> bool:
    """True for any 'ok'-class status, including ELF's 'ok (...)' variants —
    exact-match against the literal string "ok" under-counts ELF rows since
    their status carries extra detail (SONAME availability, etc.)."""
    return status == "ok" or status.startswith("ok (")


@dataclass
class BinaryRecord:
    path: str
    size_bytes: int
    sha256: str
    file_version: str | None = None
    product_version: str | None = None
    company_name: str | None = None
    product_name: str | None = None
    original_filename: str | None = None
    internal_name: str | None = None
    parse_status: str = "ok"
    name_mismatch: bool = False
    # Hardening/tamper signals — populated for PE via section table + data
    # directories, for ELF via program-header W^X check; left empty/"N/A"
    # for formats where the concept doesn't apply (ar-archive, PDB, unknown).
    rwx_sections: list[str] = field(default_factory=list)
    high_entropy_sections: list[str] = field(default_factory=list)
    debug_status: str = "N/A"
    pdb_reference: str | None = None
    signature_status: str = "N/A"
    signer_cn: str | None = None


MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",  # 32-bit, both byte orders
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",  # 64-bit, both byte orders
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",  # fat/universal binary
}

ELF_MACHINE_NAMES = {
    0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64",
    0x08: "MIPS", 0x14: "PowerPC", 0x02: "SPARC",
}
ELF_TYPE_NAMES = {1: "REL (object)", 2: "EXEC", 3: "DYN (shared object/PIE)", 4: "CORE"}


def sniff_format(path: Path) -> str:
    """Cheap magic-byte identification so every native binary gets a format
    tag even when it isn't PE — 'unknown' just means this script's sniff
    list didn't recognize it, not that the file is suspicious by itself."""
    try:
        with path.open("rb") as f:
            head = f.read(8)
    except OSError:
        return "unreadable"
    if head[:2] == b"MZ":
        return "PE"
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:4] in MACHO_MAGICS:
        return "Mach-O"
    if head[:8] == b"!<arch>\n":
        return "ar-archive"  # static library (.a/.lib) — ar format
    if head[:4] == b"Micro" or b"Microsoft C/C++ MSF" in head:
        return "PDB"
    return "unknown"


def extract_elf_info(path: Path) -> tuple[dict[str, str | None], str]:
    """Best-effort ELF metadata. Header fields (architecture, file type) are
    parsed directly with stdlib struct — no dependency needed for that much.
    SONAME (the closest ELF equivalent to a PE ProductName/version) requires
    walking the dynamic section, which is only attempted if pyelftools is
    installed; otherwise this reports architecture/type only and says so."""
    fields: dict[str, str | None] = {
        "file_version": None, "product_version": None,
        "company_name": None, "product_name": None,
        "original_filename": None, "internal_name": None,
    }
    try:
        with path.open("rb") as f:
            ident = f.read(20)
        if len(ident) < 20 or ident[:4] != b"\x7fELF":
            return fields, "parse_error: not a valid ELF file"
        ei_class = ident[4]  # 1=32-bit, 2=64-bit
        import struct
        if ei_class == 2:
            e_type, e_machine = struct.unpack_from("<HH", ident, 16)
        else:
            e_type, e_machine = struct.unpack_from("<HH", ident, 16)
        arch = ELF_MACHINE_NAMES.get(e_machine, f"machine=0x{e_machine:x}")
        etype = ELF_TYPE_NAMES.get(e_type, f"type={e_type}")
        fields["product_name"] = f"ELF {arch} {etype}"
    except Exception as e:
        return fields, f"parse_error: {e}"

    if _HAVE_PYELFTOOLS:
        try:
            with path.open("rb") as f:
                elf = ELFFile(f)
                dynsec = elf.get_section_by_name(".dynamic")
                if dynsec is not None:
                    for tag in dynsec.iter_tags():
                        if tag.entry.d_tag == "DT_SONAME":
                            fields["internal_name"] = tag.soname
        except Exception:
            pass  # SONAME is a bonus, not required — don't fail the row over it
        return fields, "ok (ELF header + SONAME where present)"
    return fields, "ok (ELF header only — install pyelftools for SONAME/needed-library detection)"


HIGH_ENTROPY_THRESHOLD = 7.2  # bits/byte, out of a max of 8.0 — a section this
# dense is either compressed, encrypted, or packed; ordinary compiled code
# and data sections (even with embedded strings/tables) essentially never
# land above ~6.5-7.0. This is a signal to investigate, not proof by itself.


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def analyze_pe_hardening(path: Path) -> dict[str, Any]:
    """The part of this script that actually answers the questions asked:
    which sections are writable+executable at once (the classic packer/
    self-modifying-code signature, and a real hardening failure even absent
    a packer — legitimate MSVC/clang output essentially never emits this),
    which sections look packed/encrypted by entropy, whether the binary
    still carries a debug directory (stripped vs. not), and whether an
    Authenticode signature block is present at all (presence only — this
    does NOT validate the certificate chain; that needs `signtool verify`
    or equivalent against a real trust store, which a static file-read
    can't do and shouldn't claim to)."""
    result: dict[str, Any] = {
        "sections": [], "rwx_sections": [], "high_entropy_sections": [],
        "debug_status": "unknown", "pdb_reference": None,
        "signature_status": "unknown", "signature_size": 0, "signer_cn": None,
    }
    try:
        pe = pefile.PE(str(path), fast_load=True)
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
            ])
        except Exception:
            pass  # section/debug/signature checks below degrade individually, not fatally

        # --- section permissions + entropy ---
        EXEC = 0x20000000
        WRITE = 0x80000000
        READ = 0x40000000
        for sec in pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            flags = sec.Characteristics
            perms = "".join([
                "R" if flags & READ else "-",
                "W" if flags & WRITE else "-",
                "X" if flags & EXEC else "-",
            ])
            try:
                data = sec.get_data()
                entropy = round(shannon_entropy(data), 2) if data else 0.0
            except Exception:
                entropy = None
            entry = {"name": name, "perms": perms, "entropy": entropy}
            result["sections"].append(entry)
            if (flags & WRITE) and (flags & EXEC):
                result["rwx_sections"].append(f"{name} ({perms})")
            if entropy is not None and entropy >= HIGH_ENTROPY_THRESHOLD:
                result["high_entropy_sections"].append(f"{name} (entropy={entropy})")

        # --- debug directory (stripped vs. not) ---
        dbg_dir = getattr(pe, "DIRECTORY_ENTRY_DEBUG", None)
        if not dbg_dir:
            result["debug_status"] = "stripped (no debug directory)"
        else:
            result["debug_status"] = "has debug directory"
            for dbg in dbg_dir:
                pdb = getattr(getattr(dbg, "entry", None), "PdbFileName", None)
                if pdb:
                    try:
                        result["pdb_reference"] = pdb.rstrip(b"\x00").decode("utf-8", errors="replace")
                    except Exception:
                        pass

        # --- Authenticode signature presence ---
        try:
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
            sig_size = sec_dir.Size
            sig_offset = sec_dir.VirtualAddress  # a raw file offset for this one directory, not an RVA
        except Exception:
            sig_size, sig_offset = 0, 0

        if sig_size <= 0:
            result["signature_status"] = "UNSIGNED (no Authenticode certificate table)"
        else:
            result["signature_status"] = "SIGNED (Authenticode certificate table present — chain NOT validated by this script)"
            result["signature_size"] = sig_size
            if _HAVE_CRYPTOGRAPHY:
                try:
                    with path.open("rb") as f:
                        f.seek(sig_offset)
                        raw = f.read(sig_size)
                    # WIN_CERTIFICATE header: dwLength(4) wRevision(2) wCertificateType(2), then the PKCS#7 blob
                    pkcs7_der = raw[8:]
                    certs = _pkcs7.load_der_pkcs7_certificates(pkcs7_der)
                    if certs:
                        # The signer is conventionally the first cert with a matching key-usage in a real
                        # validation; for a presence-only report, the first certificate's subject is reported
                        # as a best-effort label, not a validated identity.
                        subj = certs[0].subject
                        cn_attrs = subj.get_attributes_for_oid(__import__("cryptography.x509.oid", fromlist=["NameOID"]).NameOID.COMMON_NAME)
                        if cn_attrs:
                            result["signer_cn"] = cn_attrs[0].value
                except Exception as e:
                    result["signer_cn"] = None
                    result["signature_status"] += f" (signer CN extraction failed: {e})"

        pe.close()
    except Exception as e:
        result["debug_status"] = f"parse_error: {e}"
        result["signature_status"] = f"parse_error: {e}"
    return result


def analyze_elf_wx_segments(path: Path) -> dict[str, Any]:
    """W^X (writable-and-executable-at-once) PT_LOAD segment check, parsed
    directly from the raw ELF program header table with stdlib struct — no
    dependency required for this specific check, since it's the primary
    signal this feature exists for. Stripped-symbol detection (a separate,
    lower-priority question) still prefers pyelftools when available and
    says plainly when it isn't."""
    import struct
    result: dict[str, Any] = {"wx_segments": [], "debug_status": "unknown", "note": None}
    try:
        with path.open("rb") as f:
            ident = f.read(16)
            if len(ident) < 16 or ident[:4] != b"\x7fELF":
                result["note"] = "not a valid ELF file"
                return result
            is64 = ident[4] == 2
            little_endian = ident[5] == 1
            endian = "<" if little_endian else ">"
            f.seek(0)
            if is64:
                header = f.read(64)
                e_phoff, = struct.unpack_from(endian + "Q", header, 32)
                e_phentsize, e_phnum = struct.unpack_from(endian + "HH", header, 54)
            else:
                header = f.read(52)
                e_phoff, = struct.unpack_from(endian + "I", header, 28)
                e_phentsize, e_phnum = struct.unpack_from(endian + "HH", header, 42)

            f.seek(e_phoff)
            phdrs = f.read(e_phentsize * e_phnum)
            PT_LOAD = 1
            PF_X, PF_W = 0x1, 0x2
            for i in range(e_phnum):
                entry = phdrs[i * e_phentsize:(i + 1) * e_phentsize]
                if len(entry) < e_phentsize:
                    continue
                if is64:
                    p_type, p_flags = struct.unpack_from(endian + "II", entry, 0)
                else:
                    # 32-bit Elf_Phdr field order differs: p_flags comes after p_memsz, not right after p_type
                    p_type, = struct.unpack_from(endian + "I", entry, 0)
                    p_flags, = struct.unpack_from(endian + "I", entry, 24)
                if p_type == PT_LOAD and (p_flags & PF_X) and (p_flags & PF_W):
                    result["wx_segments"].append(f"PT_LOAD segment {i} (flags=0x{p_flags:x}, R{'W' if p_flags & 2 else '-'}{'X' if p_flags & 1 else '-'})")
    except Exception as e:
        result["note"] = f"parse_error: {e}"
        return result

    if _HAVE_PYELFTOOLS:
        try:
            with path.open("rb") as f:
                elf = ELFFile(f)
                symtab = elf.get_section_by_name(".symtab")
                result["debug_status"] = "has .symtab (not stripped)" if symtab is not None else "stripped (no .symtab)"
        except Exception:
            result["debug_status"] = "unknown (pyelftools parse failed)"
    else:
        result["debug_status"] = "unknown — install pyelftools to check .symtab presence"
    return result


def sha256_of(path: Path, chunk_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def _decode_string_table_value(string_table: dict, key: bytes) -> str | None:
    val = string_table.get(key)
    if val is None:
        return None
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="replace").strip("\x00").strip() or None
        except Exception:
            return None
    return str(val).strip() or None


def extract_pe_version_info(path: Path) -> tuple[dict[str, str | None], str]:
    """Returns (fields, parse_status). fields has the six string-table keys
    we care about, each None if not present. parse_status is 'ok',
    'no_version_resource', or 'parse_error: <detail>' — always returned,
    never raised, so one bad file never aborts a batch run."""
    fields: dict[str, str | None] = {
        "file_version": None, "product_version": None,
        "company_name": None, "product_name": None,
        "original_filename": None, "internal_name": None,
    }
    try:
        pe = pefile.PE(str(path), fast_load=True)
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
            )
        except Exception as e:
            pe.close()
            return fields, f"parse_error: could not parse resource directory ({e})"

        if not hasattr(pe, "FileInfo") or not pe.FileInfo:
            pe.close()
            return fields, "no_version_resource"

        found_string_table = False
        for file_info_list in pe.FileInfo:
            for entry in file_info_list:
                if entry.Key == b"StringFileInfo":
                    for st in entry.StringTable:
                        found_string_table = True
                        fields["file_version"] = _decode_string_table_value(st.entries, b"FileVersion") or fields["file_version"]
                        fields["product_version"] = _decode_string_table_value(st.entries, b"ProductVersion") or fields["product_version"]
                        fields["company_name"] = _decode_string_table_value(st.entries, b"CompanyName") or fields["company_name"]
                        fields["product_name"] = _decode_string_table_value(st.entries, b"ProductName") or fields["product_name"]
                        fields["original_filename"] = _decode_string_table_value(st.entries, b"OriginalFilename") or fields["original_filename"]
                        fields["internal_name"] = _decode_string_table_value(st.entries, b"InternalName") or fields["internal_name"]

        # Fall back to the numeric VS_FIXEDFILEINFO version if no string
        # table carried FileVersion/ProductVersion as text (some toolchains
        # only populate the binary struct, not the string table).
        if not fields["file_version"] and getattr(pe, "VS_FIXEDFILEINFO", None):
            try:
                ffi = pe.VS_FIXEDFILEINFO[0]
                fields["file_version"] = "%d.%d.%d.%d" % (
                    ffi.FileVersionMS >> 16, ffi.FileVersionMS & 0xFFFF,
                    ffi.FileVersionLS >> 16, ffi.FileVersionLS & 0xFFFF,
                )
            except Exception:
                pass

        pe.close()
        if not found_string_table and not fields["file_version"]:
            return fields, "no_version_resource"
        return fields, "ok"
    except pefile.PEFormatError as e:
        return fields, f"parse_error: not a valid PE file ({e})"
    except Exception as e:
        return fields, f"parse_error: {e}"


def walk_targets(roots: list[Path], exts: set[str], exclude_dirs: set[str]) -> list[Path]:
    import os
    found: list[Path] = []
    for root in roots:
        if root.is_file():
            if root.suffix.lower() in exts:
                found.append(root)
            continue
        if not root.exists():
            print(f"WARNING: {root} does not exist — skipping", file=sys.stderr)
            continue
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=lambda e: None):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if fpath.suffix.lower() in exts:
                    found.append(fpath)
    return found


def fingerprint_one(fpath: Path, root_for_relpath: Path) -> BinaryRecord:
    try:
        rel = str(fpath.relative_to(root_for_relpath)).replace("\\", "/")
    except ValueError:
        rel = str(fpath).replace("\\", "/")

    try:
        size = fpath.stat().st_size
    except OSError as e:
        return BinaryRecord(path=rel, size_bytes=-1, sha256="", parse_status=f"stat_error: {e}")

    try:
        digest = sha256_of(fpath)
    except OSError as e:
        digest = ""
        hash_error = f"hash_error: {e}"
    else:
        hash_error = None

    fmt = sniff_format(fpath)
    hardening: dict[str, Any] = {}
    if fmt == "PE":
        fields, parse_status = extract_pe_version_info(fpath)
        hardening = analyze_pe_hardening(fpath)
    elif fmt == "ELF":
        fields, parse_status = extract_elf_info(fpath)
        elf_wx = analyze_elf_wx_segments(fpath)
        hardening = {
            "rwx_sections": elf_wx["wx_segments"],
            "high_entropy_sections": [],
            "debug_status": elf_wx["debug_status"],
            "pdb_reference": None,
            "signature_status": "N/A (ELF has no Authenticode-equivalent embedded signature; "
                                 "check for a detached .sig/.asc file alongside, if any)",
            "signer_cn": None,
        }
    else:
        fields = {
            "file_version": None, "product_version": None, "company_name": None,
            "product_name": None, "original_filename": None, "internal_name": None,
        }
        if fmt == "ar-archive":
            parse_status = "non-PE format (ar-archive / static lib) — hash recorded, no per-file version metadata (static archives don't carry one; identify by filename/strings or the object files inside)"
        elif fmt == "Mach-O":
            parse_status = "non-PE format (Mach-O) — hash recorded, no version metadata extracted (not expected on this Windows-hosted target; flag if seen)"
        elif fmt == "PDB":
            parse_status = "non-PE format (PDB debug symbols) — hash recorded for provenance; no runtime behavior to version-check"
        elif fmt == "unreadable":
            parse_status = "unreadable — permission or I/O error reading file header"
        else:
            parse_status = f"unknown format (magic bytes not recognized) — hash recorded, no version metadata extracted"
    if hash_error:
        parse_status = f"{parse_status}; {hash_error}" if parse_status != "ok" else hash_error

    # Name-mismatch heuristic: the binary's own embedded OriginalFilename
    # should match (case-insensitively) the filename it's actually shipped
    # under. A mismatch isn't proof of tampering by itself (renamed vendor
    # utilities happen for boring reasons) but it's exactly the cheap signal
    # named in the goal-conformance review's Part B Scenario 2 — flag it,
    # don't silently accept it.
    mismatch = False
    orig = fields.get("original_filename")
    if orig and orig.lower() != fpath.name.lower():
        mismatch = True

    return BinaryRecord(
        path=rel,
        size_bytes=size,
        sha256=digest,
        file_version=fields.get("file_version"),
        product_version=fields.get("product_version"),
        company_name=fields.get("company_name"),
        product_name=fields.get("product_name"),
        original_filename=fields.get("original_filename"),
        internal_name=fields.get("internal_name"),
        parse_status=parse_status,
        name_mismatch=mismatch,
        rwx_sections=hardening.get("rwx_sections", []),
        high_entropy_sections=hardening.get("high_entropy_sections", []),
        debug_status=hardening.get("debug_status", "N/A"),
        pdb_reference=hardening.get("pdb_reference"),
        signature_status=hardening.get("signature_status", "N/A"),
        signer_cn=hardening.get("signer_cn"),
    )


def guess_product_version(rec: BinaryRecord) -> tuple[str, str]:
    """Best-effort (product, version) pair for the native-dependencies.csv
    row — prefers ProductName/ProductVersion, falls back to the bare
    filename stem and FileVersion, never fabricates a value that wasn't
    actually read from the binary."""
    product = rec.product_name or Path(rec.path).stem
    version = rec.product_version or rec.file_version or "UNKNOWN"
    return product, version


def merge_native_dependencies_csv(output_dir: Path, records: list[BinaryRecord]) -> int:
    template_path = output_dir / "native-dependencies.csv"
    existing_rows: list[dict[str, str]] = []
    if template_path.exists():
        with template_path.open(newline="", encoding="utf-8") as f:
            existing_rows = list(csv.DictReader(f))
    existing_paths = {row["path"] for row in existing_rows}

    added = 0
    for rec in records:
        if rec.path in existing_paths:
            continue  # never clobber a row a human (or a prior run) already has
        product, version = guess_product_version(rec)
        purl = f"pkg:generic/{product}@{version}" if rec.product_version or rec.file_version else ""
        notes_bits = [f"sha256={rec.sha256[:16]}..." if rec.sha256 else "sha256=<unavailable>"]
        if rec.company_name:
            notes_bits.append(f"company={rec.company_name}")
        if rec.name_mismatch:
            notes_bits.append(
                f"NAME MISMATCH: file is '{Path(rec.path).name}' but embedded "
                f"OriginalFilename is '{rec.original_filename}' — verify before clearing"
            )
        if rec.rwx_sections:
            notes_bits.append(f"RWX SECTION(S): {', '.join(rec.rwx_sections)} — writable+executable memory, a packer/self-modifying-code signal")
        if rec.high_entropy_sections:
            notes_bits.append(f"HIGH-ENTROPY SECTION(S): {', '.join(rec.high_entropy_sections)} — possibly packed/encrypted/compressed")
        if "UNSIGNED" in (rec.signature_status or ""):
            notes_bits.append("UNSIGNED")
        elif "SIGNED" in (rec.signature_status or ""):
            notes_bits.append(f"signed{f' by {rec.signer_cn}' if rec.signer_cn else ' (signer CN not extracted)'}")
        if "stripped" in (rec.debug_status or "").lower():
            notes_bits.append("stripped (no debug info)")
        if not _parsed_ok(rec.parse_status):
            notes_bits.append(f"parse_status={rec.parse_status}")

        existing_rows.append({
            "path": rec.path,
            "guessed_product": product,
            "guessed_version": version,
            "confidence": "auto-extracted from VersionInfo/ELF-header — verify" if _parsed_ok(rec.parse_status) else "NO VERSION RESOURCE — needs manual identification",
            "purl_if_constructible": purl,
            "cve_lookup_status": "not looked up yet",
            "notes": "; ".join(notes_bits),
        })
        existing_paths.add(rec.path)
        added += 1

    with template_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=NATIVE_TEMPLATE_HEADER)
        writer.writeheader()
        writer.writerows(existing_rows)
    return added


def render_markdown(records: list[BinaryRecord], roots: list[str]) -> str:
    lines = ["# Native binary fingerprint report\n"]
    lines.append(f"Generated {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Roots scanned: {', '.join('`' + r + '`' for r in roots)}\n")
    lines.append(f"**{len(records)} binaries fingerprinted.**\n")

    no_version = [r for r in records if not _parsed_ok(r.parse_status)]
    mismatches = [r for r in records if r.name_mismatch]
    rwx = [r for r in records if r.rwx_sections]
    high_entropy = [r for r in records if r.high_entropy_sections]
    unsigned = [r for r in records if "UNSIGNED" in (r.signature_status or "")]
    stripped = [r for r in records if "stripped" in (r.debug_status or "").lower()]

    if rwx:
        lines.append(f"## 🔴 {len(rwx)} binarie(s) with a writable+executable (W^X-violating) section — check these FIRST\n")
        lines.append("Legitimate MSVC/clang/Go/Rust output essentially never emits a section that is both writable "
                     "and executable at once — this is the signature of a packer, a JIT/self-modifying-code stub, "
                     "or a hand-crafted loader. Not proof of malice by itself, but it is the single highest-value "
                     "signal this script produces for finding something a vendor would rather you not look at "
                     "closely (see the goal-conformance review's Part B Scenario 2).\n")
        for r in rwx:
            lines.append(f"- `{r.path}` — {', '.join(r.rwx_sections)}")
        lines.append("")

    if high_entropy:
        lines.append(f"## 🟠 {len(high_entropy)} binarie(s) with a high-entropy section (≥{HIGH_ENTROPY_THRESHOLD} bits/byte) — possibly packed/encrypted/compressed\n")
        for r in high_entropy:
            lines.append(f"- `{r.path}` — {', '.join(r.high_entropy_sections)}")
        lines.append("")

    if unsigned:
        lines.append(f"## {len(unsigned)} unsigned PE binarie(s)\n")
        lines.append("No Authenticode certificate table at all — not necessarily wrong (plenty of internal tools "
                     "ship unsigned) but worth cross-checking against whether this vendor's release process is "
                     "supposed to sign its production binaries.\n")
        for r in unsigned[:30]:
            lines.append(f"- `{r.path}`")
        if len(unsigned) > 30:
            lines.append(f"- ... (+{len(unsigned) - 30} more)")
        lines.append("")

    if stripped:
        lines.append(f"## {len(stripped)} binarie(s) with debug info stripped / no symbol table\n")
        lines.append("Expected and normal for release builds — listed for completeness, not as a finding by itself.\n")
        for r in stripped[:20]:
            lines.append(f"- `{r.path}`")
        if len(stripped) > 20:
            lines.append(f"- ... (+{len(stripped) - 20} more)")
        lines.append("")

    if mismatches:
        lines.append(f"## ⚠ {len(mismatches)} filename/embedded-name mismatch(es) — check these first\n")
        for r in mismatches:
            lines.append(f"- `{r.path}` — filename says `{Path(r.path).name}`, embedded OriginalFilename says `{r.original_filename}`")
        lines.append("")

    if no_version:
        lines.append(f"## {len(no_version)} binarie(s) with no readable version resource\n")
        lines.append("These need identification some other way (strings pass, hash lookup against a known-good corpus, or vendor documentation) — a missing version resource is not evidence of anything by itself, but it does mean this script can't auto-populate a guessed product/version for them.\n")
        for r in no_version[:30]:
            lines.append(f"- `{r.path}` — {r.parse_status}")
        if len(no_version) > 30:
            lines.append(f"- ... (+{len(no_version) - 30} more, see the CSV)")
        lines.append("")

    by_company: dict[str, int] = defaultdict(int)
    for r in records:
        by_company[r.company_name or "(unknown)"] += 1
    lines.append("## By CompanyName (embedded)\n")
    lines.append("| Company | Count |")
    lines.append("|---|---|")
    for company, count in sorted(by_company.items(), key=lambda kv: -kv[1]):
        lines.append(f"| {company} | {count} |")
    lines.append("")

    lines.append("## Full inventory\n")
    lines.append("| Path | Size | Product | Version | Company | Mismatch? | RWX? | Signed? | Debug | Status |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for r in sorted(records, key=lambda x: x.path):
        size_str = f"{r.size_bytes / 1024:.0f} KB" if r.size_bytes >= 0 else "?"
        signed_short = "signed" if "SIGNED" in (r.signature_status or "") and "UNSIGNED" not in (r.signature_status or "") else ("unsigned" if "UNSIGNED" in (r.signature_status or "") else "-")
        debug_short = "stripped" if "stripped" in (r.debug_status or "").lower() else ("has debug" if "has debug" in (r.debug_status or "").lower() or "not stripped" in (r.debug_status or "").lower() else "-")
        lines.append(
            f"| `{r.path}` | {size_str} | {r.product_name or '-'} | "
            f"{r.product_version or r.file_version or '-'} | {r.company_name or '-'} | "
            f"{'⚠ YES' if r.name_mismatch else 'no'} | {'🔴 YES' if r.rwx_sections else 'no'} | "
            f"{signed_short} | {debug_short} | {r.parse_status} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("roots", nargs="+", type=Path, help="One or more directories (or individual files) to fingerprint")
    ap.add_argument("-o", "--output", type=Path, required=True, help="Output directory")
    ap.add_argument("--ext", action="append", default=[], help="Additional extension to include (repeatable), e.g. --ext .sys. Default: .dll, .exe")
    ap.add_argument("--exclude-dir", action="append", default=[], help="Additional directory NAME to skip wherever it appears (repeatable)")
    args = ap.parse_args()

    exts = set(DEFAULT_EXTS) | {e if e.startswith(".") else f".{e}" for e in args.ext}
    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir)
    args.output.mkdir(parents=True, exist_ok=True)

    roots = [r.resolve() for r in args.roots]
    print(f"Scanning {len(roots)} root(s) for {sorted(exts)} ...", file=sys.stderr)
    files = walk_targets(roots, exts, exclude_dirs)
    print(f"Found {len(files)} matching file(s). Fingerprinting ...", file=sys.stderr)

    # Relative paths in the CSV/MD are computed per-file against whichever
    # scanned root actually contains it (roots need not share a common
    # ancestor — each is independent).
    records: list[BinaryRecord] = []
    for i, fpath in enumerate(files, 1):
        # find which root this file is under
        parent_root = next((r for r in roots if str(fpath).startswith(str(r))), roots[0])
        rec = fingerprint_one(fpath, parent_root)
        records.append(rec)
        if i % 50 == 0:
            print(f"  ... {i}/{len(files)}", file=sys.stderr)

    fp_csv = args.output / "binary-fingerprints.csv"
    with fp_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FINGERPRINT_HEADER)
        writer.writeheader()
        for r in records:
            writer.writerow({
                "path": r.path, "bytes": r.size_bytes, "sha256": r.sha256,
                "file_version": r.file_version or "", "product_version": r.product_version or "",
                "company_name": r.company_name or "", "product_name": r.product_name or "",
                "original_filename": r.original_filename or "", "internal_name": r.internal_name or "",
                "name_mismatch": "YES" if r.name_mismatch else "",
                "parse_status": r.parse_status,
                "rwx_sections": "; ".join(r.rwx_sections),
                "high_entropy_sections": "; ".join(r.high_entropy_sections),
                "debug_status": r.debug_status,
                "pdb_reference": r.pdb_reference or "",
                "signature_status": r.signature_status,
                "signer_cn": r.signer_cn or "",
            })

    fp_md = args.output / "binary-fingerprints.md"
    fp_md.write_text(render_markdown(records, [str(r) for r in roots]), encoding="utf-8")

    added = merge_native_dependencies_csv(args.output, records)

    parse_ok = sum(1 for r in records if _parsed_ok(r.parse_status))
    mismatches = sum(1 for r in records if r.name_mismatch)
    rwx_count = sum(1 for r in records if r.rwx_sections)
    high_entropy_count = sum(1 for r in records if r.high_entropy_sections)
    unsigned_count = sum(1 for r in records if "UNSIGNED" in (r.signature_status or ""))
    stripped_count = sum(1 for r in records if "stripped" in (r.debug_status or "").lower())
    print(f"\nWrote {fp_csv}", file=sys.stderr)
    print(f"Wrote {fp_md}", file=sys.stderr)
    print(f"Updated {args.output / 'native-dependencies.csv'} — {added} new row(s) added (existing rows never overwritten)", file=sys.stderr)
    print(f"\nSummary: {len(records)} binaries, {parse_ok} with a readable version resource, "
          f"{len(records) - parse_ok} without, {mismatches} filename/embedded-name mismatch(es).", file=sys.stderr)
    print(f"Hardening signals: {rwx_count} with a W^X (writable+executable) section, "
          f"{high_entropy_count} with a high-entropy section, {unsigned_count} unsigned, "
          f"{stripped_count} debug-stripped.", file=sys.stderr)
    if rwx_count:
        print("REVIEW THE W^X SECTIONS FIRST — this is the highest-value signal this script produces.", file=sys.stderr)
    elif mismatches:
        print("REVIEW THE MISMATCHES FIRST — they're the next-cheapest tamper-detection signal this script produces.", file=sys.stderr)


if __name__ == "__main__":
    main()
