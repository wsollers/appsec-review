"""Bounded, non-executing parsers for common test-coverage exchange formats."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import re
from typing import Any, Mapping
import xml.etree.ElementTree as ET
from xml.parsers import expat


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
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ValueError(f"{label} is not an integer")
    if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
        raise ValueError(f"{label} is not an integer")
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{label} is not an integer") from exc
    if result < 0:
        raise ValueError(f"{label} cannot be negative")
    return result


@dataclass
class _LcovSource:
    lines: dict[int, int] = field(default_factory=dict)
    branches: set[tuple[int, str, str]] = field(default_factory=set)
    covered_branches: set[tuple[int, str, str]] = field(default_factory=set)
    functions: dict[str, int] = field(default_factory=dict)

    def totals(self) -> CoverageTotals:
        return CoverageTotals(
            len(self.lines), sum(hit > 0 for hit in self.lines.values()),
            len(self.branches), len(self.covered_branches), len(self.functions),
            sum(hit > 0 for hit in self.functions.values()))


def _merge(files: list[CoverageFile]) -> tuple[CoverageFile, ...]:
    values: dict[str, CoverageTotals] = {}
    for item in files:
        if item.source_path in values:
            raise ValueError(f"overlapping source summaries cannot be unioned: {item.source_path}")
        values[item.source_path] = item.totals
    return tuple(CoverageFile(path, values[path]) for path in sorted(values))


def _lcov(data: bytes, max_rows: int) -> CoverageDocument:
    try:
        lines = data.decode("utf-8-sig", errors="strict").splitlines()
    except UnicodeError as exc:
        raise ValueError("LCOV is not valid UTF-8") from exc
    if len(lines) > max_rows:
        raise ValueError(f"LCOV row bound exceeded ({max_rows})")
    sources: dict[str, _LcovSource] = {}
    source: _LcovSource | None = None

    for number, raw in enumerate(lines, 1):
        if raw.startswith("SF:"):
            path = raw[3:].strip()
            if not path:
                raise ValueError(f"LCOV row {number} has an empty source path")
            source = sources.setdefault(path, _LcovSource())
        elif raw.startswith("DA:"):
            if source is None:
                raise ValueError(f"LCOV row {number} precedes SF")
            values = raw[3:].split(",")
            if len(values) < 2:
                raise ValueError(f"LCOV row {number} is malformed")
            line = _checked_int(values[0], "LCOV line")
            source.lines[line] = max(source.lines.get(line, 0), _checked_int(values[1], "LCOV hits"))
        elif raw.startswith("BRDA:"):
            if source is None:
                raise ValueError(f"LCOV row {number} precedes SF")
            values = raw[5:].split(",")
            if len(values) != 4:
                raise ValueError(f"LCOV row {number} is malformed")
            key = (_checked_int(values[0], "LCOV branch line"), values[1], values[2])
            source.branches.add(key)
            if values[3] != "-" and _checked_int(values[3], "LCOV branch hits") > 0:
                source.covered_branches.add(key)
        elif raw.startswith("FN:"):
            if source is None:
                raise ValueError(f"LCOV row {number} precedes SF")
            values = raw[3:].split(",", 1)
            if len(values) != 2 or not values[1]:
                raise ValueError(f"LCOV row {number} is malformed")
            _checked_int(values[0], "LCOV function line")
            source.functions.setdefault(values[1], 0)
        elif raw.startswith("FNDA:"):
            if source is None:
                raise ValueError(f"LCOV row {number} precedes SF")
            values = raw[5:].split(",", 1)
            if len(values) != 2 or not values[1]:
                raise ValueError(f"LCOV row {number} is malformed")
            source.functions[values[1]] = max(
                source.functions.get(values[1], 0), _checked_int(values[0], "LCOV function hits"))
        elif raw == "end_of_record":
            source = None
    if not sources:
        raise ValueError("LCOV contains no source records")
    return CoverageDocument("lcov", tuple(
        CoverageFile(path, sources[path].totals()) for path in sorted(sources)))


def _xml_root(data: bytes, max_rows: int, *, allow_jacoco_doctype: bool = False) -> ET.Element:
    guard = expat.ParserCreate()
    count = 0
    declaration: tuple[int, int] | None = None

    def element(_name: str, _attributes: Mapping[str, str]) -> None:
        nonlocal count
        count += 1
        if count > max_rows:
            raise ValueError(f"coverage XML node bound exceeded ({max_rows})")

    def reject_declaration(*_args: Any) -> None:
        raise ValueError("coverage XML declarations are not allowed")

    def doctype(name: str, system: str | None, public: str | None, internal: int) -> None:
        nonlocal declaration
        if not (allow_jacoco_doctype and name == "report" and not internal
                and public == "-//JACOCO//DTD Report 1.1//EN" and system == "report.dtd"):
            reject_declaration()
        # With no internal subset, Expat reports the closing '>' byte offset. Only the
        # validated declaration is removed from the tree input, retaining its byte encoding.
        end = guard.CurrentByteIndex
        openings = []
        for encoding in ("ascii", "utf-16-le", "utf-16-be"):
            token = "<!DOCTYPE".encode(encoding)
            closing = ">".encode(encoding)
            start = data.rfind(token, 0, end)
            if start >= 0 and data[end:end + len(closing)] == closing:
                openings.append((start, len(closing)))
        if not openings:
            raise ValueError("coverage XML declaration encoding is unsupported")
        start, width = max(openings)
        declaration = (start, end + width)

    # Inspect actual declarations in the declared encoding before building a tree. The one
    # allowed external identifier is inert metadata: neither parser resolves external DTDs.
    guard.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    guard.StartElementHandler = element
    guard.StartDoctypeDeclHandler = doctype
    guard.EntityDeclHandler = reject_declaration
    guard.ExternalEntityRefHandler = reject_declaration
    guard.SkippedEntityHandler = reject_declaration
    try:
        guard.Parse(data, True)
        # An unprocessed external DTD lets Expat silently omit unknown attribute entities.
        # Without that header the tree parser rejects them; the evidence buffer stays intact.
        tree_data = data if declaration is None else data[:declaration[0]] + data[declaration[1]:]
        return ET.fromstring(tree_data)
    except (expat.ExpatError, ET.ParseError) as exc:
        raise ValueError("coverage XML is malformed") from exc


_CONDITION = re.compile(r"\((\d+)\s*/\s*(\d+)\)")


def _cobertura(data: bytes, max_rows: int) -> CoverageDocument:
    root = _xml_root(data, max_rows)
    if root.tag.rsplit("}", 1)[-1] != "coverage":
        raise ValueError("Cobertura root element is not coverage")
    sources: dict[str, tuple[dict[int, int], dict[int, dict[str | None, tuple[int, int]]],
                             dict[tuple[str, str, str], bool]]] = {}
    for class_index, cls in enumerate(root.iter()):
        if cls.tag.rsplit("}", 1)[-1] != "class" or not cls.get("filename"):
            continue
        path = str(cls.get("filename"))
        line_hits, source_branches, methods = sources.setdefault(path, ({}, {}, {}))
        # A class lists each line once under <lines> and again under its <method>; branch counts
        # are kept per line, like hits, so a line reported twice is counted once.
        line_branches: dict[int, tuple[int, int]] = {}
        for method_index, child in enumerate(cls.iter()):
            name = child.tag.rsplit("}", 1)[-1]
            if name == "line" and child.get("number") is not None:
                number = _checked_int(child.get("number"), "Cobertura line")
                line_hits[number] = max(line_hits.get(number, 0),
                                        _checked_int(child.get("hits", "0"), "Cobertura hits"))
                if child.get("branch") == "true":
                    match = _CONDITION.search(child.get("condition-coverage", ""))
                    if not match:
                        raise ValueError("Cobertura branch condition-coverage is missing or malformed")
                    covered = _checked_int(match.group(1), "Cobertura covered branches")
                    total = _checked_int(match.group(2), "Cobertura branches")
                    if total == 0 or covered > total:
                        raise ValueError("Cobertura branch counts are invalid")
                    previous = line_branches.get(number)
                    if previous is not None and previous != (total, covered):
                        raise ValueError("overlapping Cobertura branch annotations disagree")
                    line_branches[number] = (total, covered)
            elif name == "method":
                key = (str(cls.get("name", f"@class-{class_index}")),
                       str(child.get("name", f"@method-{method_index}")),
                       str(child.get("signature", "")))
                method_hits = [_checked_int(line.get("hits", "0"), "Cobertura method hits")
                               for line in child.iter() if line.tag.rsplit("}", 1)[-1] == "line"]
                methods[key] = methods.get(key, False) or any(method_hits)
        class_name = cls.get("name")
        if class_name is not None and not class_name.strip():
            class_name = None
        for number, counts in line_branches.items():
            classes = source_branches.setdefault(number, {})
            if classes and (class_name is None or None in classes):
                raise ValueError("overlapping Cobertura branch summaries lack class identity")
            previous = classes.get(class_name)
            if previous is not None:
                # Only the same class/line can overlap. Fractions cannot identify a union of
                # two partial observations; equal denominators alone never identify branches.
                total, covered = counts
                old_total, old_covered = previous
                if total != old_total or (0 < covered < total and 0 < old_covered < total):
                    raise ValueError("overlapping Cobertura branch summaries cannot be unioned")
                counts = (total, max(covered, old_covered))
            classes[class_name] = counts
    if not sources:
        raise ValueError("Cobertura contains no class source records")
    files = []
    for path, (line_hits, branches, methods) in sorted(sources.items()):
        files.append(CoverageFile(path, CoverageTotals(
            len(line_hits), sum(value > 0 for value in line_hits.values()),
            sum(total for classes in branches.values() for total, _ in classes.values()),
            sum(covered for classes in branches.values() for _, covered in classes.values()),
            len(methods), sum(methods.values()))))
    return CoverageDocument("cobertura", tuple(files))


def _counter(element: ET.Element, kind: str) -> tuple[int, int]:
    rows = [item for item in element if item.tag.rsplit("}", 1)[-1] == "counter" and item.get("type") == kind]
    if not rows:
        return 0, 0
    missed = sum(_checked_int(row.get("missed", "0"), f"JaCoCo {kind} missed") for row in rows)
    covered = sum(_checked_int(row.get("covered", "0"), f"JaCoCo {kind} covered") for row in rows)
    return missed + covered, covered


def _jacoco(data: bytes, max_rows: int) -> CoverageDocument:
    root = _xml_root(data, max_rows, allow_jacoco_doctype=True)
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
