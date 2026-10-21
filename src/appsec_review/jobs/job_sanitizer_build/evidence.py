"""Proof that instrumentation took effect, read from the produced ELF and never by running it.

A binary built with ``-fsanitize=address`` calls the AddressSanitizer runtime (``__asan_init``,
``__asan_report_*``, ``__asan_memcpy``) or carries it; one built with ``-fsanitize=undefined``
references ``__ubsan_handle_*`` or links the UBSan runtime. The symbol tables and ``DT_NEEDED``
entries are parsed with the bounded in-repository ELF reader. An output whose symbol tables are
absent (stripped) proves nothing either way and is reported as ``no_symbol_tables`` so a caller
never mistakes silence for a negative or a positive result.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
import re
import struct
from typing import Any

from appsec_review.jobs.job_language_build import elf


EVIDENCE_SCHEMA = "appsec-review/sanitizer-runtime-evidence/1"
RUNTIME_SYMBOL_PREFIXES = {"address": "__asan_", "undefined": "__ubsan_"}
RUNTIME_LIBRARIES = {
    "address": re.compile(r"lib(?:clang_rt\.)?asan[A-Za-z0-9_.+-]*\.so[0-9.]*"),
    "undefined": re.compile(r"lib(?:clang_rt\.)?ubsan[A-Za-z0-9_.+-]*\.so[0-9.]*"),
}
LINKED_KINDS = frozenset({"executable", "shared-library"})
INSPECTED_KINDS = LINKED_KINDS | {"object"}
CATALOGED_KINDS = INSPECTED_KINDS
_LISTED_SYMBOLS = 8


def runtime_evidence(path: Path, kind: str) -> dict[str, Any]:
    """Per-sanitizer runtime references of one produced file.

    ``evidence_status`` is ``resolved`` when a symbol table was read, ``no_symbol_tables`` when the
    file has none and no runtime library is named by it, ``unparsed`` when the ELF was malformed and
    ``not_inspected`` for a kind this reader does not open (static archives).
    """
    result: dict[str, Any] = {"schema": EVIDENCE_SCHEMA, "evidence_status": "not_inspected",
                              "symbol_tables": [], "needed_libraries": [],
                              "sanitizers": {name: _absent() for name in RUNTIME_SYMBOL_PREFIXES}}
    if kind not in INSPECTED_KINDS:
        return result
    try:
        symbols = elf.symbol_names(path, tuple(RUNTIME_SYMBOL_PREFIXES.values()))
        needed = elf.loader_facts(path)["needed"] if kind in LINKED_KINDS else []
    except (OSError, ValueError, struct.error) as exc:
        return {**result, "evidence_status": "unparsed", "error": str(exc)[:200]}
    result.update(symbol_tables=list(symbols["tables"]), needed_libraries=list(needed),
                  parser=elf.SYMBOL_PARSER_IDENTITY)
    names = sorted({*symbols["defined"], *symbols["undefined"]})
    for name, prefix in RUNTIME_SYMBOL_PREFIXES.items():
        matched = [item for item in names if item.startswith(prefix)]
        libraries = [item for item in needed if RUNTIME_LIBRARIES[name].fullmatch(item)]
        result["sanitizers"][name] = {
            "runtime_referenced": bool(matched or libraries), "symbol_count": len(matched),
            "symbols": matched[:_LISTED_SYMBOLS], "runtime_libraries": libraries,
            "imports_runtime": any(item.startswith(prefix) for item in symbols["undefined"]),
        }
    referenced = any(item["runtime_referenced"] for item in result["sanitizers"].values())
    result["evidence_status"] = "resolved" if symbols["tables"] or referenced else "no_symbol_tables"
    return result


def _absent() -> dict[str, Any]:
    return {"runtime_referenced": False, "symbol_count": 0, "symbols": [], "runtime_libraries": [],
            "imports_runtime": False}


def referenced(evidence: Mapping[str, Any], sanitizers: Sequence[str]) -> bool:
    return all(bool(evidence["sanitizers"][name]["runtime_referenced"]) for name in sanitizers)


def any_referenced(evidence: Mapping[str, Any]) -> bool:
    return any(bool(item["runtime_referenced"]) for item in evidence["sanitizers"].values())
