#!/opt/binary-analysis-venv/bin/python3
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import lief
import pefile
from elftools.elf.elffile import ELFFile
from elftools.elf.gnuversions import GNUVerSymSection

# Dynamic export table (brief Q, docs/reachability-entry-points.md source 2). Read from the dynamic
# symbol table / export directory only, never from .symtab or source text. Every defined function
# symbol is listed with its raw binding and visibility; the reader (appsec-review-process/
# entry_exports.py) decides what is an entry. "complete" is false whenever anything was cut or
# could not be read, and the reader then treats the library's exports as unknown.
EXPORTS_SCHEMA = "appsec-review/dynamic-exports/1"
MAX_EXPORTS = 100_000
MAX_NAME = 4096


def demangle(names: list) -> tuple:
    """Itanium names through binutils c++filt, one per line; (list or None, gap or None)."""
    if not names:
        return [], None
    try:
        done = subprocess.run(["c++filt"], input="\n".join(names) + "\n", capture_output=True,
                              text=True, timeout=120, check=True)
    except (OSError, subprocess.SubprocessError):
        return None, "demangler-unavailable"
    lines = done.stdout.split("\n")[:len(names)]
    if len(lines) != len(names):
        return None, "demangler-output-mismatch"
    return [line.strip()[:MAX_NAME] for line in lines], None


def exports_block(fmt: str, kind: str, table: str, functions: list, gaps: list) -> dict:
    gaps = list(gaps)
    if len(functions) > MAX_EXPORTS:
        functions, gaps = functions[:MAX_EXPORTS], gaps + ["export-table-truncated"]
    names, gap = demangle([row["symbol"] for row in functions])
    if gap:
        gaps.append(gap)
    for index, row in enumerate(functions):
        row["demangled"] = names[index] if names is not None else None
    functions.sort(key=lambda row: (row["symbol"], row["binding"], row["visibility"]))
    return {"schema": EXPORTS_SCHEMA, "format": fmt, "artifact_kind": kind, "table": table,
            "complete": not gaps, "gaps": sorted(set(gaps)), "functions": functions}


def elf_exports(elf: ELFFile) -> dict:
    interp = any(segment.header.p_type == "PT_INTERP" for segment in elf.iter_segments())
    kind = ("shared-library" if elf.header.e_type == "ET_DYN" and not interp else
            "executable" if elf.header.e_type in ("ET_EXEC", "ET_DYN") else "unknown")
    dynsym = next((section for section in elf.iter_sections() if section.header.sh_type == "SHT_DYNSYM"), None)
    if dynsym is None:
        return exports_block("elf", kind, ".dynsym", [], ["dynamic-symbol-table-absent"])
    versym = next((section for section in elf.iter_sections() if isinstance(section, GNUVerSymSection)), None)
    functions = []
    for index, symbol in enumerate(dynsym.iter_symbols()):
        if (not symbol.name or symbol["st_shndx"] == "SHN_UNDEF" or
                symbol["st_info"]["type"] not in ("STT_FUNC", "STT_GNU_IFUNC")):
            continue
        hidden = False
        if versym is not None and index < versym.num_symbols():
            ndx = versym.get_symbol(index).entry["ndx"]
            hidden = isinstance(ndx, int) and bool(ndx & 0x8000)
        functions.append({"symbol": symbol.name[:MAX_NAME],
                          "binding": str(symbol["st_info"]["bind"]).replace("STB_", ""),
                          "visibility": str(symbol["st_other"]["visibility"]).replace("STV_", ""),
                          "version_hidden": hidden})
    return exports_block("elf", kind, ".dynsym", functions, [])


def pe_exports(pe) -> dict:
    kind = "shared-library" if pe.FILE_HEADER.Characteristics & 0x2000 else "executable"
    functions, gaps = [], []
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    executable = [(section.VirtualAddress, section.VirtualAddress + max(section.Misc_VirtualSize, section.SizeOfRawData))
                  for section in pe.sections if section.Characteristics & 0x20000000]
    for symbol in (directory.symbols if directory is not None else []):
        if symbol.forwarder:
            continue  # implemented by another module; not a function of this artifact
        if not any(low <= symbol.address < high for low, high in executable):
            continue  # data export
        if not symbol.name:
            gaps.append("export-by-ordinal-only")
            continue
        functions.append({"symbol": symbol.name.decode("utf-8", "replace")[:MAX_NAME], "binding": "GLOBAL",
                          "visibility": "DEFAULT", "version_hidden": False})
    return exports_block("pe", kind, "export-directory", functions, gaps)


def guarded_exports(reader, parsed, fmt: str) -> dict:
    """An unreadable export table is an incomplete one; it never breaks the rest of the summary."""
    try:
        return reader(parsed)
    except Exception:  # noqa: BLE001 - hostile input; record the gap, keep the summary
        return {"schema": EXPORTS_SCHEMA, "format": fmt, "artifact_kind": "unknown", "table": None,
                "complete": False, "gaps": ["export-table-unreadable"], "functions": []}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def elf_summary(path: Path) -> dict:
    with path.open("rb") as handle:
        elf = ELFFile(handle)
        sections = [section.name for section in elf.iter_sections()]
        symbols = []
        for section in elf.iter_sections():
            if section.header.sh_type in ("SHT_SYMTAB", "SHT_DYNSYM"):
                symbols.extend(sym.name for sym in section.iter_symbols() if sym.name)
        return {
            "format": "elf",
            "elf_class": elf.elfclass,
            "machine": elf.header.e_machine,
            "entrypoint": hex(elf.header.e_entry),
            "sections": sections[:200],
            "symbol_count": len(symbols),
            "symbols_sample": symbols[:200],
            "has_debug_sections": any(name.startswith(".debug") for name in sections),
            "dynamic_exports": guarded_exports(elf_exports, elf, "elf"),
        }


def pe_summary(path: Path) -> dict:
    pe = pefile.PE(str(path), fast_load=False)
    sections = [section.Name.rstrip(b"\x00").decode("utf-8", "replace") for section in pe.sections]
    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imports.append(entry.dll.decode("utf-8", "replace"))
    debug_types = []
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        debug_types = [entry.struct.Type for entry in pe.DIRECTORY_ENTRY_DEBUG]
    return {
        "format": "pe",
        "machine": hex(pe.FILE_HEADER.Machine),
        "entrypoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "sections": sections,
        "imports": imports[:200],
        "debug_types": debug_types,
        "dynamic_exports": guarded_exports(pe_exports, pe, "pe"),
    }


def lief_summary(path: Path) -> dict:
    parsed = lief.parse(str(path))
    if parsed is None:
        return {"lief_format": None}
    symbols = [symbol.name for symbol in getattr(parsed, "symbols", []) if getattr(symbol, "name", "")]
    return {
        "lief_format": str(parsed.format),
        "libraries": list(getattr(parsed, "libraries", []))[:200],
        "exported_functions": [str(item) for item in getattr(parsed, "exported_functions", [])[:200]],
        "symbol_count": len(symbols),
    }


def main() -> int:
    path = Path(sys.argv[1])
    data = {
        "path": str(path),
        "sha256": sha256(path),
    }
    with path.open("rb") as handle:
        magic = handle.read(4)
    try:
        if magic == b"\x7fELF":
            data.update(elf_summary(path))
        elif magic[:2] == b"MZ":
            data.update(pe_summary(path))
        else:
            data["format"] = "unknown"
    except Exception as exc:
        data["parser_error"] = repr(exc)
    try:
        data["lief"] = lief_summary(path)
    except Exception as exc:
        data["lief_error"] = repr(exc)
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
