#!/opt/binary-analysis-venv/bin/python3
import hashlib
import json
import sys
from pathlib import Path

import lief
import pefile
from elftools.elf.elffile import ELFFile


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
