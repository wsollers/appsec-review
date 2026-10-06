#!/usr/bin/env python3
"""CodeQL reachability packs for brief E (ADR-0022 decision 6): pins, symbol data extension, run plan.

The query templates live in ``data/codeql-reachability/<lang>/`` (pack ``appsec/<lang>-reachability``,
library pinned to the codeql-bundle-v2.27.0 version). Advisory symbols reach QL ONLY as rows of
the extensible predicate ``vulnerableSymbol(package, symbol)`` in a generated model pack
``appsec/<lang>-reachability-symbols``; rows are validated by ``dep_reachability.SYMBOL`` /
``PACKAGE`` first and written as JSON (a YAML subset), so no text is ever spliced into a query.

The queries run only inside the pinned ``audit-codeql`` image, offline (``plan`` builds the argv;
``scripts/smoke_codeql_reachability.sh`` runs it in WSL). The decoded CSVs are what
``dep_reachability_engines.CodeqlEngine`` reads.

    python3 dep_reachability_codeql.py symbols --language go --symbols symbols.json --out /tmp/pack
    python3 dep_reachability_codeql.py check
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dep_reachability

PACK_ROOT = Path(__file__).resolve().parents[1] / "data" / "codeql-reachability"
BUNDLE = "codeql-bundle-v2.27.0"
# Library versions shipped in the bundle (github/codeql tag codeql-cli/v2.27.0, <lang>/ql/lib/qlpack.yml).
PACK_PINS = {"go": ("codeql/go-all", "7.3.1"), "java": ("codeql/java-all", "9.3.0"),
             "csharp": ("codeql/csharp-all", "7.3.0"), "javascript": ("codeql/javascript-all", "2.10.1"),
             "python": ("codeql/python-all", "7.2.5")}
QUERIES = ("CallEdges", "EntryPoints", "Reachability", "TaintReach")
# CodeQL extractor names and the database build mode available offline.
EXTRACTOR = {"go": ("go", "autobuild"), "java": ("java", "none"), "csharp": ("csharp", "none"),
             "javascript": ("javascript", "none"), "python": ("python", "none")}
CODEQL = "/opt/codeql/codeql"


def _pack_source(path: Path) -> bool:
    """The committed pack sources. Files CodeQL writes into the mounted folder during a run (for example
    ``codeql-pack.lock.yml``) are not pack identity: hashing them changed 06's fingerprint on every resume
    (runs 20261004T054551Z-357581 and 20261006T150309Z-fdd8d6 re-ran 06-reachability-codeql each time)."""
    return path.name == "qlpack.yml" or path.suffix in (".ql", ".qll")


def pack_files(language: str) -> dict[str, bytes]:
    folder = PACK_ROOT / language
    return {path.name: path.read_bytes() for path in sorted(folder.iterdir())
            if path.is_file() and not path.is_symlink() and _pack_source(path)}


def pack_sha256(language: str) -> str:
    """sha256 over the pack's files (name + bytes), bound into 06 inputs and each run plan."""
    digest = hashlib.sha256()
    for name, data in pack_files(language).items():
        digest.update(name.encode() + b"\0" + hashlib.sha256(data).digest())
    return "sha256:" + digest.hexdigest()


def check_pins() -> list[str]:
    """Every pack's qlpack.yml names exactly its PACK_PINS dependency and version, and every query exists."""
    errors = []
    for language, (pack, version) in sorted(PACK_PINS.items()):
        folder = PACK_ROOT / language
        text = (folder / "qlpack.yml").read_text() if (folder / "qlpack.yml").is_file() else ""
        if not re.search(rf"^name: appsec/{language}-reachability$", text, re.M):
            errors.append(f"{language}: qlpack.yml name is not appsec/{language}-reachability")
        deps = re.findall(r"^\s+(codeql/[a-z-]+):\s*(\S+)\s*$", text, re.M)
        if deps != [(pack, version)]:
            errors.append(f"{language}: dependencies {deps} are not the pin {pack} {version}")
        for query in QUERIES:
            if not (folder / f"{query}.ql").is_file():
                errors.append(f"{language}: {query}.ql is missing")
        if "extensible predicate vulnerableSymbol(string package, string symbol);" not in (
                (folder / "Symbols.qll").read_text() if (folder / "Symbols.qll").is_file() else ""):
            errors.append(f"{language}: Symbols.qll does not declare vulnerableSymbol")
    return errors


def data_extension(language: str, symbols: Iterable[dict[str, Any]]) -> dict[str, bytes]:
    """The generated model pack (qlpack.yml + symbols.model.yml); raises on an unvalidated row."""
    if language not in PACK_PINS:
        raise ValueError(f"no CodeQL reachability pack for {language}")
    rows = []
    for item in symbols:
        package, symbol = item.get("package"), item.get("symbol")
        if (not isinstance(symbol, str) or not dep_reachability.SYMBOL.fullmatch(symbol) or
                not isinstance(package, str) or not dep_reachability.PACKAGE.fullmatch(package)):
            raise ValueError("symbol rows must be validated {package, symbol} pairs")
        rows.append([package, symbol])
    rows = sorted({tuple(row) for row in rows})
    pack = (f"name: appsec/{language}-reachability-symbols\nversion: 0.0.1\nlibrary: true\n"
            f"extensionTargets:\n  appsec/{language}-reachability: \"*\"\ndataExtensions:\n  - symbols.model.yml\n")
    model = json.dumps({"extensions": [{"addsTo": {"pack": f"appsec/{language}-reachability",
                                                   "extensible": "vulnerableSymbol"},
                                        "data": [list(row) for row in rows]}]}, indent=1) + "\n"
    return {"qlpack.yml": pack.encode(), "symbols.model.yml": model.encode()}


def plan(language: str, *, threads: int = 2, ram_mb: int = 4096) -> list[list[str]]:
    """The container argv sequence (no shell): create the database, run each query, decode to CSV.

    Mounts: /workspace (checkout, read-only), /inputs/pack (this pack, read-only),
    /inputs/symbols (generated model pack, read-only), /scratch (writable).
    """
    extractor, mode = EXTRACTOR[language]
    create = [CODEQL, "database", "create", "/scratch/db", f"--language={extractor}", "--source-root=/workspace",
              f"--threads={threads}", f"--ram={ram_mb}", "--overwrite"]
    create.append("--build-mode=none" if mode == "none" else "--build-mode=autobuild")
    steps = [create]
    for query in QUERIES:
        steps.append([CODEQL, "query", "run", "--database=/scratch/db",
                      "--additional-packs=/inputs/pack:/inputs/symbols:/opt/codeql/qlpacks",
                      f"--model-packs=appsec/{language}-reachability-symbols", f"--threads={threads}",
                      f"--ram={ram_mb}", f"--output=/scratch/graph/{query}.bqrs", f"/inputs/pack/{query}.ql"])
        steps.append([CODEQL, "bqrs", "decode", "--format=csv", f"--output=/scratch/graph/{query}.csv",
                      f"/scratch/graph/{query}.bqrs"])
    return steps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    symbols = sub.add_parser("symbols", help="write the generated symbols model pack")
    symbols.add_argument("--language", required=True, choices=sorted(PACK_PINS))
    symbols.add_argument("--symbols", type=Path, required=True, help='JSON [{"package": .., "symbol": ..}]')
    symbols.add_argument("--out", type=Path, required=True)
    show = sub.add_parser("plan", help="print the container argv sequence as JSON")
    show.add_argument("--language", required=True, choices=sorted(PACK_PINS))
    sub.add_parser("check", help="verify pack pins and files")
    args = parser.parse_args(argv)
    if args.command == "check":
        errors = check_pins()
        print("\n".join(errors) or "codeql-reachability packs: OK")
        return 1 if errors else 0
    if args.command == "plan":
        print(json.dumps({"language": args.language, "pack_sha256": pack_sha256(args.language), "bundle": BUNDLE,
                          "steps": plan(args.language)}, indent=1))
        return 0
    rows, rejected = dep_reachability.clean_symbols(json.loads(args.symbols.read_text()), "reviewed-map")
    if rejected:
        print(f"{rejected} symbol row(s) rejected", file=sys.stderr)
    rows = [row for row in rows if row["package"]]
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in data_extension(args.language, rows).items():
        (args.out / name).write_bytes(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
