"""Deterministic adapters for native-SAST compile databases and raw analyzer output.

Target source and analyzer messages are untrusted data.  These adapters retain only closed rule
identity, category and fresh source citations; they never emit a finding or severity.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any
import xml.etree.ElementTree as ET

SOURCE_PREFIX = "/scratch/src/"
WORKSPACE_PREFIX = "/workspace/"
SUPPORTED_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm"}
COMPILERS = {"/opt/llvm/bin/clang", "/opt/llvm/bin/clang++", "/opt/llvm/bin/clang-cl"}
CATEGORIES = {
    "buffer-safety", "null-dereference", "resource-lifetime", "undefined-behavior",
    "api-misuse", "portability", "maintainability", "other-static-analysis",
}


class AdapterError(ValueError):
    pass


def _sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _replace_root(value: str) -> str:
    if "\x00" in value:
        raise AdapterError("compile database contains NUL")
    return value.replace("/scratch/src", "/workspace")


def adapt_compile_database(value: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """Validate E02's database and deterministically retarget its private build-copy root."""
    if not isinstance(value, list) or not value:
        raise AdapterError("compile database must be a non-empty array")
    adapted: list[dict[str, Any]] = []
    unsupported: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict) or not isinstance(raw.get("file"), str):
            raise AdapterError(f"compile database entry {index} has no file")
        source = raw["file"].replace("\\", "/")
        if not source.startswith(SOURCE_PREFIX):
            raise AdapterError(f"compile database entry {index} is outside /scratch/src")
        relative = source[len(SOURCE_PREFIX):]
        pure = PurePosixPath(relative)
        if (not relative or pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts)):
            raise AdapterError(f"compile database entry {index} has a non-normal source path")
        if relative in seen:
            raise AdapterError(f"compile database repeats translation unit {relative}")
        seen.add(relative)
        if pure.suffix.lower() not in SUPPORTED_SUFFIXES:
            unsupported.append(relative)
            continue
        entry = {key: raw[key] for key in sorted(raw)}
        entry["file"] = WORKSPACE_PREFIX + relative
        directory = entry.get("directory")
        if not isinstance(directory, str) or not directory.startswith("/scratch/src"):
            raise AdapterError(f"compile database entry {index} has an invalid directory")
        entry["directory"] = _replace_root(directory)
        if (not isinstance(entry.get("arguments"), list) or
                not all(isinstance(word, str) for word in entry["arguments"])):
            raise AdapterError(f"compile database entry {index} requires an argv array")
        words = entry["arguments"]
        if not words or words[0] not in COMPILERS:
            raise AdapterError(f"compile database entry {index} does not use fixed in-image Clang")
        lowered = [word.lower() for word in words]
        unsafe = (any(word.startswith("@") for word in words) or
                  any(word.startswith("-xclang") or
                      word in {"-load", "-plugin", "-add-plugin", "-wrapper", "-cc1"} or
                      word.startswith(("-fplugin", "-fpass-plugin", "--config", "-specs=",
                                       "/clang:-load", "/clang:-plugin", "/clang:-fplugin"))
                      for word in lowered))
        if unsafe:
            raise AdapterError(f"compile database entry {index} can load or wrap compiler code")
        entry.pop("command", None)
        entry["arguments"] = [_replace_root(word) for word in words]
        adapted.append(entry)
    adapted.sort(key=lambda item: item["file"])
    unsupported.sort()
    if not adapted:
        raise AdapterError("compile database contains no supported native translation units")
    return adapted, unsupported


def canonical_sha(value: Any) -> str:
    # Match execution_state.atomic_json so this is also the published adapted file's digest.
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def citation(raw_path: Any, target: Path) -> tuple[str, Path]:
    if not isinstance(raw_path, str) or not raw_path:
        raise AdapterError("analyzer record has no source path")
    value = raw_path.replace("\\", "/")
    for prefix in (WORKSPACE_PREFIX, SOURCE_PREFIX):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    pure = PurePosixPath(value)
    if (pure.is_absolute() or not value or
            any(part in ("", ".", "..") for part in pure.parts)):
        raise AdapterError("analyzer source path is not normalized beneath the target")
    resolved = (target / Path(*pure.parts)).resolve()
    try:
        resolved.relative_to(target.resolve())
    except ValueError as exc:
        raise AdapterError("analyzer source path leaves the target") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise AdapterError("analyzer citation does not resolve to a regular source file")
    return pure.as_posix(), resolved


def category(tool: str, rule: str, raw_category: str = "") -> str:
    value = (rule + " " + raw_category).lower()
    if any(token in value for token in ("buffer", "arraybound", "outofbound", "memcpy", "strcpy")):
        return "buffer-safety"
    if any(token in value for token in ("null", "nullptr")):
        return "null-dereference"
    if any(token in value for token in ("resource", "leak", "useafter", "doublefree")):
        return "resource-lifetime"
    if any(token in value for token in ("undefined", "uninit", "divisionbyzero", "overflow")):
        return "undefined-behavior"
    if any(token in value for token in ("portability", "platform")):
        return "portability"
    if tool == "clang-tidy" and any(token in value for token in ("readability", "modernize", "performance")):
        return "maintainability"
    if any(token in value for token in ("security", "cert-", "api", "insecure")):
        return "api-misuse"
    return "other-static-analysis"


def _lead(tool_id: str, unit_id: str, rule: Any, raw_path: Any, line: Any, column: Any,
          target: Path, raw_category: str = "") -> dict[str, Any]:
    if not isinstance(rule, str) or not rule or len(rule) > 256:
        raise AdapterError("analyzer record has an invalid rule id")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise AdapterError("analyzer record has an invalid line")
    if not isinstance(column, int) or isinstance(column, bool) or column < 1:
        column = 1
    path, source = citation(raw_path, target)
    data = source.read_bytes()
    lines = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
    if line > lines:
        raise AdapterError("analyzer citation line is beyond the current source file")
    record = {"tool_id": tool_id, "unit_id": unit_id, "rule_id": rule, "path": path,
              "start_line": line, "start_column": column, "source_sha256": _sha(source),
              "category": category(tool_id, rule, raw_category)}
    record["lead_id"] = "lead_" + hashlib.sha256(json.dumps(
        record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
    return record


def _kept(build, dropped: list[str] | None):
    """ADR-0013: a record that cites a file outside the checkout (a generated header in the build
    tree, a system header) or past its end is dropped and counted, not fatal to the unit."""
    try:
        return build()
    except AdapterError as exc:
        if dropped is None or "citation" not in str(exc) and "source path" not in str(exc):
            raise
        dropped.append(str(exc))
        return None


def clang_tidy_leads(raw: Any, *, unit_id: str, target: Path,
                     dropped: list[str] | None = None) -> list[dict[str, Any]]:
    if not isinstance(raw, dict) or not isinstance(raw.get("findings"), list):
        raise AdapterError("clang-tidy output has no findings array")
    result = [x for x in (_kept(lambda item=item: _lead("clang-tidy", unit_id, item.get("check"), item.get("file"),
                                                          item.get("line"), item.get("col"), target), dropped)
                          for item in raw["findings"] if isinstance(item, dict)) if x is not None]
    return sorted(result, key=_sort_key)


def cppcheck_leads(raw_xml: str, *, unit_id: str, target: Path,
                   dropped: list[str] | None = None) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as exc:
        raise AdapterError("cppcheck output is not XML") from exc
    result: list[dict[str, Any]] = []
    for error in root.findall(".//error"):
        locations = error.findall("location")
        if not locations:
            continue
        location = locations[0]
        try:
            line = int(location.attrib.get("line", ""))
            column = int(location.attrib.get("column", "1"))
        except ValueError as exc:
            raise AdapterError("cppcheck location is invalid") from exc
        lead = _kept(lambda: _lead("cppcheck", unit_id, error.attrib.get("id"),
                                   location.attrib.get("file"), line, column, target,
                                   error.attrib.get("verbose", "")), dropped)
        if lead is not None:
            result.append(lead)
    return sorted(result, key=_sort_key)


def csa_leads(raw: Any, *, unit_id: str, target: Path,
              dropped: list[str] | None = None) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise AdapterError("CSA output is not an array")
    result = [x for x in (_kept(lambda item=item: _lead("clang-static-analyzer", unit_id, item.get("checker"),
                                                          item.get("file"), item.get("line"), item.get("col"), target,
                                                          str(item.get("category", ""))), dropped)
                          for item in raw if isinstance(item, dict)) if x is not None]
    return sorted(result, key=_sort_key)


def _sort_key(value: dict[str, Any]) -> tuple:
    return (value["path"], value["start_line"], value["start_column"],
            value["tool_id"], value["rule_id"])
