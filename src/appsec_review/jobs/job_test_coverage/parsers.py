"""Bounded, non-executing parsers for common test-coverage exchange formats."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Mapping
import xml.etree.ElementTree as ET


@dataclass(frozen=True, slots=True)
class CoverageTotals:
    lines_total: int = 0
    lines_covered: int = 0
    branches_total: int = 0
    branches_covered: int = 0
    functions_total: int = 0
    functions_covered: int = 0

    def __post_init__(self) -> None:
        values = (self.lines_total, self.lines_covered, self.branches_total,
                  self.branches_covered, self.functions_total, self.functions_covered)
        if any(value < 0 for value in values):
            raise ValueError("coverage counts cannot be negative")
        if (self.lines_covered > self.lines_total or self.branches_covered > self.branches_total or
                self.functions_covered > self.functions_total):
            raise ValueError("covered count exceeds total count")

    def as_dict(self) -> dict[str, int | float | None]:
        value: dict[str, int | float | None] = {
            "lines_total": self.lines_total, "lines_covered": self.lines_covered,
            "branches_total": self.branches_total, "branches_covered": self.branches_covered,
            "functions_total": self.functions_total, "functions_covered": self.functions_covered,
        }
        for name in ("lines", "branches", "functions"):
            total, covered = getattr(self, f"{name}_total"), getattr(self, f"{name}_covered")
            value[f"{name}_rate"] = round(covered / total, 8) if total else None
        return value

    def __add__(self, other: "CoverageTotals") -> "CoverageTotals":
        return CoverageTotals(*(a + b for a, b in zip(
            (self.lines_total, self.lines_covered, self.branches_total,
             self.branches_covered, self.functions_total, self.functions_covered),
            (other.lines_total, other.lines_covered, other.branches_total,
             other.branches_covered, other.functions_total, other.functions_covered), strict=True)))


@dataclass(frozen=True, slots=True)
class CoverageFile:
    source_path: str
    totals: CoverageTotals


@dataclass(frozen=True, slots=True)
class CoverageDocument:
    format: str
    files: tuple[CoverageFile, ...]
    gaps: tuple[str, ...] = ()


def _checked_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} is not an integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not an integer") from exc
    if result < 0:
        raise ValueError(f"{label} cannot be negative")
    return result


def _merge(files: list[CoverageFile]) -> tuple[CoverageFile, ...]:
    values: dict[str, CoverageTotals] = {}
    for item in files:
        values[item.source_path] = values.get(item.source_path, CoverageTotals()) + item.totals
    return tuple(CoverageFile(path, values[path]) for path in sorted(values))


def _lcov(data: bytes, max_rows: int) -> CoverageDocument:
    try:
        lines = data.decode("utf-8-sig", errors="strict").splitlines()
    except UnicodeError as exc:
        raise ValueError("LCOV is not valid UTF-8") from exc
    if len(lines) > max_rows:
        raise ValueError(f"LCOV row bound exceeded ({max_rows})")
    files: list[CoverageFile] = []
    path: str | None = None
    line_hits: dict[int, int] = {}
    branches: set[tuple[int, str, str]] = set()
    covered_branches: set[tuple[int, str, str]] = set()
    functions: dict[str, int] = {}

    def finish() -> None:
        nonlocal path, line_hits, branches, covered_branches, functions
        if path is not None:
            files.append(CoverageFile(path, CoverageTotals(
                len(line_hits), sum(hit > 0 for hit in line_hits.values()),
                len(branches), len(covered_branches), len(functions),
                sum(hit > 0 for hit in functions.values()))))
        path, line_hits, branches, covered_branches, functions = None, {}, set(), set(), {}

    for number, raw in enumerate(lines, 1):
        if raw.startswith("SF:"):
            if path is not None:
                finish()
            path = raw[3:].strip()
            if not path:
                raise ValueError(f"LCOV row {number} has an empty source path")
        elif raw.startswith("DA:"):
            if path is None:
                raise ValueError(f"LCOV row {number} precedes SF")
            values = raw[3:].split(",")
            if len(values) < 2:
                raise ValueError(f"LCOV row {number} is malformed")
            line_hits[_checked_int(values[0], "LCOV line")] = _checked_int(values[1], "LCOV hits")
        elif raw.startswith("BRDA:"):
            if path is None:
                raise ValueError(f"LCOV row {number} precedes SF")
            values = raw[5:].split(",")
            if len(values) != 4:
                raise ValueError(f"LCOV row {number} is malformed")
            key = (_checked_int(values[0], "LCOV branch line"), values[1], values[2])
            branches.add(key)
            if values[3] != "-" and _checked_int(values[3], "LCOV branch hits") > 0:
                covered_branches.add(key)
        elif raw.startswith("FN:"):
            values = raw[3:].split(",", 1)
            if len(values) != 2 or not values[1]:
                raise ValueError(f"LCOV row {number} is malformed")
            _checked_int(values[0], "LCOV function line")
            functions.setdefault(values[1], 0)
        elif raw.startswith("FNDA:"):
            values = raw[5:].split(",", 1)
            if len(values) != 2 or not values[1]:
                raise ValueError(f"LCOV row {number} is malformed")
            functions[values[1]] = _checked_int(values[0], "LCOV function hits")
        elif raw == "end_of_record":
            finish()
    finish()
    if not files:
        raise ValueError("LCOV contains no source records")
    return CoverageDocument("lcov", _merge(files))


def _xml_root(data: bytes, max_rows: int) -> ET.Element:
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("coverage XML declarations are not allowed")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError("coverage XML is malformed") from exc
    if sum(1 for _ in root.iter()) > max_rows:
        raise ValueError(f"coverage XML node bound exceeded ({max_rows})")
    return root


_CONDITION = re.compile(r"\((\d+)\s*/\s*(\d+)\)")


def _cobertura(data: bytes, max_rows: int) -> CoverageDocument:
    root = _xml_root(data, max_rows)
    if root.tag.rsplit("}", 1)[-1] != "coverage":
        raise ValueError("Cobertura root element is not coverage")
    files: list[CoverageFile] = []
    for cls in root.iter():
        if cls.tag.rsplit("}", 1)[-1] != "class" or not cls.get("filename"):
            continue
        line_hits: dict[int, int] = {}
        branches_total = branches_covered = 0
        methods_total = methods_covered = 0
        for child in cls.iter():
            name = child.tag.rsplit("}", 1)[-1]
            if name == "line" and child.get("number") is not None:
                line_hits[_checked_int(child.get("number"), "Cobertura line")] = max(
                    line_hits.get(_checked_int(child.get("number"), "Cobertura line"), 0),
                    _checked_int(child.get("hits", "0"), "Cobertura hits"))
                if child.get("branch") == "true":
                    match = _CONDITION.search(child.get("condition-coverage", ""))
                    if match:
                        branches_covered += _checked_int(match.group(1), "Cobertura covered branches")
                        branches_total += _checked_int(match.group(2), "Cobertura branches")
            elif name == "method":
                methods_total += 1
                method_hits = [_checked_int(line.get("hits", "0"), "Cobertura method hits")
                               for line in child.iter() if line.tag.rsplit("}", 1)[-1] == "line"]
                methods_covered += bool(method_hits and any(method_hits))
        files.append(CoverageFile(str(cls.get("filename")), CoverageTotals(
            len(line_hits), sum(value > 0 for value in line_hits.values()),
            branches_total, branches_covered, methods_total, methods_covered)))
    if not files:
        raise ValueError("Cobertura contains no class source records")
    return CoverageDocument("cobertura", _merge(files))


def _counter(element: ET.Element, kind: str) -> tuple[int, int]:
    rows = [item for item in element if item.tag.rsplit("}", 1)[-1] == "counter" and item.get("type") == kind]
    if not rows:
        return 0, 0
    missed = sum(_checked_int(row.get("missed", "0"), f"JaCoCo {kind} missed") for row in rows)
    covered = sum(_checked_int(row.get("covered", "0"), f"JaCoCo {kind} covered") for row in rows)
    return missed + covered, covered


def _jacoco(data: bytes, max_rows: int) -> CoverageDocument:
    root = _xml_root(data, max_rows)
    if root.tag.rsplit("}", 1)[-1] != "report":
        raise ValueError("JaCoCo root element is not report")
    files: list[CoverageFile] = []
    for package in root.iter():
        if package.tag.rsplit("}", 1)[-1] != "package":
            continue
        prefix = str(package.get("name", "")).strip("/")
        methods_by_source: dict[str, tuple[int, int]] = {}
        for cls in package:
            if cls.tag.rsplit("}", 1)[-1] != "class" or not cls.get("sourcefilename"):
                continue
            total, covered = _counter(cls, "METHOD")
            old = methods_by_source.get(str(cls.get("sourcefilename")), (0, 0))
            methods_by_source[str(cls.get("sourcefilename"))] = (old[0] + total, old[1] + covered)
        for source in package:
            if source.tag.rsplit("}", 1)[-1] != "sourcefile" or not source.get("name"):
                continue
            lines, covered_lines = _counter(source, "LINE")
            branches, covered_branches = _counter(source, "BRANCH")
            functions, covered_functions = methods_by_source.get(str(source.get("name")), (0, 0))
            path = f"{prefix}/{source.get('name')}" if prefix else str(source.get("name"))
            files.append(CoverageFile(path, CoverageTotals(
                lines, covered_lines, branches, covered_branches, functions, covered_functions)))
    if not files:
        raise ValueError("JaCoCo contains no sourcefile records")
    return CoverageDocument("jacoco", _merge(files))


def _summary_counts(summary: Mapping[str, Any], name: str) -> tuple[int, int]:
    value = summary.get(name, {})
    if not isinstance(value, Mapping):
        raise ValueError(f"LLVM {name} summary is invalid")
    return _checked_int(value.get("count", 0), f"LLVM {name} count"), _checked_int(
        value.get("covered", 0), f"LLVM {name} covered")


def _llvm(data: bytes, max_rows: int) -> CoverageDocument:
    try:
        root = json.loads(data.decode("utf-8-sig", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("LLVM coverage JSON is malformed") from exc
    if not isinstance(root, Mapping) or not isinstance(root.get("data"), list):
        raise ValueError("LLVM coverage JSON has no data array")
    files: list[CoverageFile] = []
    for export in root["data"]:
        if not isinstance(export, Mapping) or not isinstance(export.get("files"), list):
            raise ValueError("LLVM coverage data row has no files array")
        for item in export["files"]:
            if len(files) >= max_rows:
                raise ValueError(f"LLVM file row bound exceeded ({max_rows})")
            if not isinstance(item, Mapping) or not isinstance(item.get("filename"), str):
                raise ValueError("LLVM coverage file row is invalid")
            summary = item.get("summary")
            if not isinstance(summary, Mapping):
                raise ValueError("LLVM coverage file summary is invalid")
            lines, covered_lines = _summary_counts(summary, "lines")
            branches, covered_branches = _summary_counts(summary, "branches")
            functions, covered_functions = _summary_counts(summary, "functions")
            files.append(CoverageFile(item["filename"], CoverageTotals(
                lines, covered_lines, branches, covered_branches, functions, covered_functions)))
    if not files:
        raise ValueError("LLVM coverage JSON contains no source records")
    return CoverageDocument("llvm", _merge(files))


def parse_coverage(data: bytes, format_name: str, *, max_rows: int = 100_000) -> CoverageDocument:
    """Parse one already-bounded artifact. The caller owns byte and file-count bounds."""
    if max_rows < 1:
        raise ValueError("coverage row bound must be positive")
    parser = {"lcov": _lcov, "cobertura": _cobertura, "jacoco": _jacoco, "llvm": _llvm}.get(format_name)
    if parser is None:
        raise ValueError(f"unsupported coverage format: {format_name}")
    return parser(data, max_rows)
