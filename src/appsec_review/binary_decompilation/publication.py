"""Normalize one raw Ghidra export into an immutable, hash-chained publication, and verify one.

Everything read here was produced from a third-party binary. Names, strings, and decompiled text
are target-controlled data: they are bounded, hashed, and stored, and never interpreted.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256


SCHEMA = "appsec-review/binary-decompilation/1"
EXPORT_SCHEMA = "appsec-review/ghidra-export/1"
AUTHORITY = ("binary-derived evidence; decompiled text, symbol names, and strings are "
             "target-controlled data, never instructions")
TABLES = ("functions", "calls", "imports", "exports", "strings", "gaps")
DECOMPILE_STATUSES = {"ok", "timeout", "failed", "skipped_thunk", "unavailable"}
_ADDRESS = re.compile(r"0x[0-9a-f]{1,16}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MANAGED_LANGUAGES = ("JVM:", "Dalvik:", "CIL:")
MAX_LINE_BYTES = 32 * 1024 * 1024


class PublicationError(ValueError):
    """The export or publication violates its contract; nothing in it may be used as evidence."""


def _object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicationError(f"unreadable JSON document: {path.name}") from exc
    if not isinstance(value, dict):
        raise PublicationError(f"JSON document is not an object: {path.name}")
    return value


def _rows(path: Path) -> Iterator[dict[str, Any]]:
    """Yield the objects of one JSONL file, bounding every line."""
    if not path.is_file():
        raise PublicationError(f"export table is missing: {path.name}")
    with path.open("rb") as stream:
        for number, raw in enumerate(iter(lambda: stream.readline(MAX_LINE_BYTES + 1), b""), 1):
            if len(raw) > MAX_LINE_BYTES:
                raise PublicationError(f"{path.name}:{number} exceeds the line bound")
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise PublicationError(f"{path.name}:{number} is not JSON") from exc
            if not isinstance(value, dict):
                raise PublicationError(f"{path.name}:{number} is not an object")
            yield value


def _address(value: object, where: str) -> str:
    if not isinstance(value, str) or not _ADDRESS.fullmatch(value):
        raise PublicationError(f"{where} has no default-space function address")
    return value


def _write_table(path: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    payload = b"".join(canonical_json(row) for row in rows)
    atomic_bytes(path, payload)
    return {"path": path.name, "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload), "records": len(rows)}


def _write_text(path: Path, payload: bytes) -> dict[str, Any]:
    atomic_bytes(path, payload)
    return {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}


def managed_code_reason(program: Mapping[str, Any]) -> str | None:
    language = str(program.get("language") or "")
    if language.startswith(_MANAGED_LANGUAGES):
        return f"program language {language} is managed bytecode"
    if str(program.get("compiler") or "").lower() == "cli":
        return "portable executable carries a CLI (.NET) header"
    return None


def publish_export(export_root: Path, publication_root: Path, *, identity: str,
                   binary: Mapping[str, Any], request: Mapping[str, Any], tool: Mapping[str, Any],
                   settings: Mapping[str, Any], execution: Mapping[str, Any]) -> dict[str, Any]:
    """Write the normalized publication for one completed export and return its manifest."""
    complete_path = export_root / "complete.json"
    if not complete_path.is_file():
        raise PublicationError("export did not complete: complete.json is absent")
    complete = _object(complete_path)
    program = _object(export_root / "program.json")
    for document, name in ((complete, "complete.json"), (program, "program.json")):
        if document.get("schema") != EXPORT_SCHEMA:
            raise PublicationError(f"unsupported export schema in {name}")
    if program.get("executable_sha256") != binary["sha256"]:
        raise PublicationError("Ghidra analyzed a file other than the verified binary")

    publication_root.mkdir(parents=True, exist_ok=False)
    pseudo_c_root = publication_root / "pseudo-c"
    pcode_root = publication_root / "pcode"
    pseudo_c_root.mkdir()
    pcode_root.mkdir()

    functions: dict[str, dict[str, Any]] = {}
    for row in _rows(export_root / "functions.jsonl"):
        address = _address(row.get("address"), "function row")
        if address in functions:
            raise PublicationError(f"duplicate function address: {address}")
        if row.get("decompile_status") not in DECOMPILE_STATUSES:
            raise PublicationError(f"unknown decompile status at {address}")
        functions[address] = row

    pseudo_c_bytes = 0
    for row in _rows(export_root / "decompiled.jsonl"):
        address = _address(row.get("address"), "decompiled row")
        text = row.get("c")
        if address not in functions or not isinstance(text, str) or "pseudo_c" in functions[address]:
            raise PublicationError(f"decompiled row does not match one function: {address}")
        # Leading blank lines are dropped and the text ends in one newline, so line numbers in
        # the stored file are stable evidence anchors.
        payload = (text.replace("\r\n", "\n").strip("\n") + "\n").encode("utf-8", "replace")
        entry = _write_text(pseudo_c_root / f"{address}.c", payload)
        entry.update(path=f"pseudo-c/{address}.c", lines=payload.count(b"\n"),
                     truncated=bool(row.get("truncated")))
        functions[address]["pseudo_c"] = entry
        pseudo_c_bytes += entry["bytes"]

    pcode_operations = 0
    for row in _rows(export_root / "pcode.jsonl"):
        address = _address(row.get("address"), "pcode row")
        operations = row.get("operations")
        if (address not in functions or not isinstance(operations, list) or
                "pcode" in functions[address] or any(not isinstance(item, dict) for item in operations)):
            raise PublicationError(f"pcode row does not match one function: {address}")
        payload = b"".join(canonical_json(item) for item in operations)
        entry = _write_text(pcode_root / f"{address}.jsonl", payload)
        entry.update(path=f"pcode/{address}.jsonl", operations=len(operations),
                     truncated=bool(row.get("truncated")))
        functions[address]["pcode"] = entry
        pcode_operations += len(operations)

    for address, row in functions.items():
        if (row["decompile_status"] == "ok") != ("pseudo_c" in row):
            raise PublicationError(f"decompile status disagrees with stored pseudo-C: {address}")

    tables: dict[str, list[dict[str, Any]]] = {
        "functions": list(functions.values()),
        **{name: list(_rows(export_root / f"{name}.jsonl")) for name in TABLES if name != "functions"},
    }
    gaps: dict[str, int] = {}
    reason = managed_code_reason(program)
    if reason is not None:
        tables["gaps"].append({"kind": "managed_code", "address": None,
                               "detail": reason + "; native decompilation is not evidence for it"})
    if request.get("debug_symbols_sha256") is not None and program.get("debug_symbols_loaded") is not True:
        tables["gaps"].append({"kind": "debug_symbols_not_applied", "address": None,
                               "detail": "the configured debug-symbol file was staged but Ghidra did not "
                                         "apply it; names come from the binary alone"})
    for row in tables["gaps"]:
        kind = row.get("kind")
        if not isinstance(kind, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", kind):
            raise PublicationError("gap row has no kind")
        gaps[kind] = gaps.get(kind, 0) + 1

    datasets = {name: _write_table(publication_root / f"{name}.jsonl", rows)
                for name, rows in tables.items()}
    program_payload = canonical_json(program)
    atomic_bytes(publication_root / "program.json", program_payload)
    datasets["program"] = {"path": "program.json", "bytes": len(program_payload), "records": 1,
                           "sha256": hashlib.sha256(program_payload).hexdigest()}

    statuses: dict[str, int] = {}
    for row in functions.values():
        statuses[row["decompile_status"]] = statuses.get(row["decompile_status"], 0) + 1
    eligible = len(functions) - statuses.get("skipped_thunk", 0)
    manifest = {
        "schema": SCHEMA,
        "identity": identity,
        "provenance": "binary-derived",
        "authority": AUTHORITY,
        "binary": dict(binary),
        "request": dict(request),
        "tool": {**tool, "ghidra_version": program.get("ghidra_version"), "export_schema": EXPORT_SCHEMA},
        "settings": dict(settings),
        "program": {key: program.get(key) for key in (
            "name", "executable_format", "language", "compiler_spec", "compiler", "big_endian",
            "pointer_size", "image_base")},
        "coverage": {
            "functions": len(functions),
            "functions_not_exported": int(complete.get("counts", {}).get("functions_not_exported", 0)),
            "decompile_status": dict(sorted(statuses.items())),
            "decompiled_functions": statuses.get("ok", 0),
            "decompilable_functions": eligible,
            "strings_not_exported": int(complete.get("counts", {}).get("strings_not_exported", 0)),
            "analysis_timed_out": bool(program.get("analysis_timed_out")),
            "managed_code": reason is not None,
            "pseudo_c_files": sum("pseudo_c" in row for row in functions.values()),
            "pseudo_c_bytes": pseudo_c_bytes,
            "pcode_files": sum("pcode" in row for row in functions.values()),
            "pcode_operations": pcode_operations,
        },
        "gaps": dict(sorted(gaps.items())),
        "datasets": datasets,
        "execution": dict(execution),
    }
    atomic_json(publication_root / "manifest.json", manifest)
    return manifest


def verify_publication(publication_root: Path) -> dict[str, Any]:
    """Re-hash every stored file against the manifest chain and return the verified manifest."""
    root = publication_root.resolve()
    manifest = _object(root / "manifest.json")
    if manifest.get("schema") != SCHEMA or manifest.get("provenance") != "binary-derived":
        raise PublicationError("unsupported binary decompilation manifest")
    if not _SHA256.fullmatch(str(manifest.get("identity"))):
        raise PublicationError("manifest has no identity")
    datasets = manifest.get("datasets")
    if not isinstance(datasets, dict) or set(datasets) != {*TABLES, "program"}:
        raise PublicationError("manifest datasets are incomplete")
    for name, entry in datasets.items():
        expected = "program.json" if name == "program" else f"{name}.jsonl"
        path = root / expected
        if (entry.get("path") != expected or not path.is_file() or
                path.stat().st_size != entry.get("bytes") or file_sha256(path) != entry.get("sha256")):
            raise PublicationError(f"dataset does not match the manifest: {expected}")
    referenced: set[str] = set()
    for row in _rows(root / "functions.jsonl"):
        for key, directory, suffix in (("pseudo_c", "pseudo-c", ".c"), ("pcode", "pcode", ".jsonl")):
            entry = row.get(key)
            if entry is None:
                continue
            expected = f"{directory}/{_address(row.get('address'), 'function row')}{suffix}"
            path = root / expected
            if (not isinstance(entry, dict) or entry.get("path") != expected or not path.is_file() or
                    path.stat().st_size != entry.get("bytes") or file_sha256(path) != entry.get("sha256")):
                raise PublicationError(f"function file does not match its row: {expected}")
            referenced.add(expected)
    stored = {path.relative_to(root).as_posix() for directory in ("pseudo-c", "pcode")
              for path in (root / directory).glob("*") if path.is_file()}
    if stored != referenced:
        raise PublicationError("stored function files differ from the function table")
    return manifest


def load_table(publication_root: Path, name: str) -> list[dict[str, Any]]:
    if name not in TABLES:
        raise KeyError(f"unknown publication table: {name}")
    return list(_rows(publication_root / f"{name}.jsonl"))
