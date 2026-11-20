"""Bounded reader for a Joern ``neo4jcsv`` export of a seeded CPG.

``joern-export --repr all --format neo4jcsv`` writes one ``nodes_<LABEL>_{header,data}.csv`` and
``edges_<LABEL>_{header,data}.csv`` pair per label that occurs in the CPG. This module reads the
handful the review path needs and nothing else:

* ``METHOD``             the functions of the seeded files (path, lines, signature, whether a body was parsed);
* ``CALL``               the calls inside each function (operators are counted, not listed);
* ``CONTROL_STRUCTURE``  the branches inside each function, with the condition expression when Joern has one;
* ``AST``                the parent links that place a node in its enclosing function;
* ``REACHING_DEF``       Joern's data-dependence edges, counted per function.

Honest limits, each a named gap rather than a silent omission. c2cpg emits no call-graph or CFG edge
files, so a call is matched to a callee by name only (``callee_resolved`` says whether Joern itself
resolved it). A node outside every parsed method is not counted. Rows, bytes and AST depth are bounded;
any cut is reported in ``CpgExport.gaps``. Nothing here executes the export or reads the target.
"""
from __future__ import annotations

import csv
import hashlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any

from appsec_review.storage import canonical_json

EXPORT_SCHEMA = "appsec-review/cpg-export/1"
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ROWS = 400_000
MAX_AST_DEPTH = 96
MAX_CALLS_PER_FUNCTION = 200
MAX_BRANCHES_PER_FUNCTION = 100
MAX_TEXT = 200
OPERATOR_PREFIX = "<operator>"
UNRESOLVED_PREFIX = "<unresolved"
PSEUDO_METHODS = frozenset({"<global>", "<includes>"})
_SPECIAL = {":ID": "id", ":LABEL": "label", ":START_ID": "start", ":END_ID": "end", ":TYPE": "type"}
_CSV_LOCK = RLock()
NO_CALL_EDGES_GAP = ("cpg_calls_name_matched: c2cpg exports no call-graph edges, so a callee is identified by "
                     "name; 'callee_resolved' is true only where Joern itself resolved the target")
NO_CFG_GAP = "cpg_no_cfg_edges: c2cpg exports no control-flow edges; branches are listed, successors are not"


@dataclass(frozen=True, slots=True)
class CpgCall:
    name: str
    line: int | None
    code: str
    callee_resolved: bool

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "line": self.line, "code": self.code, "callee_resolved": self.callee_resolved}


@dataclass(frozen=True, slots=True)
class CpgBranch:
    kind: str
    line: int | None
    code: str
    condition: str | None

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "line": self.line, "code": self.code, "condition": self.condition}


@dataclass(slots=True)
class CpgFunction:
    function_id: str
    name: str
    full_name: str
    signature: str
    path: str
    line: int | None
    line_end: int | None
    has_body: bool
    calls: list[CpgCall] = field(default_factory=list)
    branches: list[CpgBranch] = field(default_factory=list)
    operator_calls: int = 0
    reaching_def_edges: int = 0
    cut: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"function_id": self.function_id,
                "name": self.name, "full_name": self.full_name, "signature": self.signature, "path": self.path,
                "line": self.line, "line_end": self.line_end, "has_body": self.has_body,
                "calls": [call.as_dict() for call in self.calls], "branches": [item.as_dict() for item in self.branches],
                "operator_calls": self.operator_calls, "reaching_def_edges": self.reaching_def_edges,
                "cut": list(self.cut)}


@dataclass(slots=True)
class CpgExport:
    functions: list[CpgFunction] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"schema": EXPORT_SCHEMA, "functions": [item.as_dict() for item in self.functions],
                "gaps": list(self.gaps)}


def _int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _text(value: str) -> str:
    return " ".join(str(value).split())[:MAX_TEXT]


def _read(directory: Path, kind: str, label: str, gaps: list[str], *,
          required: bool = False) -> Iterator[dict[str, str]]:
    """Read bounded, shape-checked tables; absent optional labels differ from broken pairs."""
    header, data = directory / f"{kind}_{label}_header.csv", directory / f"{kind}_{label}_data.csv"
    if not any(path.exists() or path.is_symlink() for path in (header, data)) and not required:
        return
    if not all(path.is_file() and not path.is_symlink() for path in (header, data)):
        gaps.append(f"cpg_export_incomplete: {kind}_{label} lacks a regular header/data pair")
        return
    for path in (header, data):
        if path.stat().st_size > MAX_FILE_BYTES:
            gaps.append(f"cpg_export_limit: {path.name} exceeds {MAX_FILE_BYTES} bytes and was not read")
            return
    needed = {"start", "end"} if kind == "edges" else {"id"}
    if label == "METHOD":
        needed |= {"NAME", "FILENAME"}
    elif label == "CALL":
        needed.add("NAME")
    elif label == "CONTROL_STRUCTURE":
        needed.add("CONTROL_STRUCTURE_TYPE")
    # csv's field cap is process-global. Serialize our readers and restore the caller's cap,
    # including malformed/short-circuit reads, rather than changing subsequent consumers.
    with _CSV_LOCK:
        previous = csv.field_size_limit(1 << 20)
        try:
            with header.open(newline="", encoding="utf-8") as stream:
                reader = csv.reader(stream, strict=True)
                names = next(reader, [])
                if next(reader, None) is not None:
                    raise ValueError("header contains more than one row")
            columns = [_SPECIAL.get(name, name.split(":")[0]) for name in names]
            if not needed <= set(columns) or len(set(columns)) != len(columns) or "" in columns:
                raise ValueError("header lacks required or unique columns")
            with data.open(newline="", encoding="utf-8") as stream:
                for index, row in enumerate(csv.reader(stream, strict=True)):
                    if index >= MAX_ROWS:
                        gaps.append(f"cpg_export_limit: {data.name} was cut at {MAX_ROWS} rows")
                        return
                    if len(row) != len(columns):
                        raise ValueError(f"row {index + 1} does not match header width")
                    record = dict(zip(columns, row))
                    if any(not record[key] for key in ("start", "end") if kind == "edges") \
                            or (kind == "nodes" and not record["id"]):
                        raise ValueError(f"row {index + 1} lacks node identity")
                    yield record
        except (csv.Error, UnicodeError, OSError, ValueError) as exc:
            gaps.append(f"cpg_export_invalid: {kind}_{label}: {type(exc).__name__}: {exc}")
        finally:
            csv.field_size_limit(previous)


def read_export(directory: Path) -> CpgExport:
    """Functions of the seeded files with their calls, branches and data-dependence counts."""
    out = CpgExport()
    gaps = out.gaps
    methods: dict[str, CpgFunction] = {}
    for row in _read(directory, "nodes", "METHOD", gaps):
        name, path = row.get("NAME", ""), row.get("FILENAME", "")
        if not name or name in PSEUDO_METHODS or path.startswith("<") or row.get("IS_EXTERNAL") == "true":
            continue
        code = row.get("CODE", "")
        methods[row["id"]] = CpgFunction(
            function_id=hashlib.sha256(canonical_json({
                key: row.get(key) for key in ("id", "NAME", "FULL_NAME", "SIGNATURE", "FILENAME",
                                              "LINE_NUMBER", "LINE_NUMBER_END")})).hexdigest(),
            name=name[:MAX_TEXT], full_name=row.get("FULL_NAME", name)[:MAX_TEXT],
            signature=row.get("SIGNATURE", "")[:MAX_TEXT],
            path=path, line=_int(row.get("LINE_NUMBER", "")), line_end=_int(row.get("LINE_NUMBER_END", "")),
            has_body="{" in code)
    if not methods:
        gaps.append("cpg_export_no_methods: the export holds no function of the seeded files")
        return out
    parents: dict[str, str] = {}
    for row in _read(directory, "edges", "AST", gaps, required=any(fn.has_body for fn in methods.values())):
        parents[row["end"]] = row["start"]

    owners: dict[str, CpgFunction | None] = {}
    ownership_gaps: set[str] = set()

    def owner(node: str) -> CpgFunction | None:
        if node in owners:
            return owners[node]
        seen, current = set(), node
        found = None
        for depth in range(MAX_AST_DEPTH + 1):
            if current in methods:
                found = methods[current]
                break
            if current in seen:
                ownership_gaps.add("cpg_ast_cycle: facts on cyclic AST paths have no resolved owner")
                break
            seen.add(current)
            if current not in parents:
                ownership_gaps.add("cpg_ast_orphan: facts outside parsed methods have no resolved owner")
                break
            if depth == MAX_AST_DEPTH:
                ownership_gaps.add(f"cpg_ast_depth_limit: facts beyond {MAX_AST_DEPTH} AST hops have no resolved owner")
                break
            current = parents[current]
        # Cache only this query, never its ancestors: a cut is not proof of their ownership.
        owners[node] = found
        return found

    codes: dict[str, str] = {}
    for label in ("CALL", "IDENTIFIER", "LITERAL"):
        for row in _read(directory, "nodes", label, gaps):
            codes[row["id"]] = _text(row.get("CODE", ""))
            if label != "CALL":
                continue
            function = owner(row["id"])
            name = row.get("NAME", "")
            if function is None:
                continue
            if name.startswith(OPERATOR_PREFIX):
                function.operator_calls += 1
            elif len(function.calls) >= MAX_CALLS_PER_FUNCTION:
                if "calls" not in function.cut:
                    function.cut.append("calls")
            else:
                full = row.get("METHOD_FULL_NAME", "")
                function.calls.append(CpgCall(name[:MAX_TEXT], _int(row.get("LINE_NUMBER", "")), _text(row.get("CODE", "")),
                                              bool(full) and not full.startswith(UNRESOLVED_PREFIX)
                                              and "<unknownFullName>" not in full))
    conditions: dict[str, str] = {}
    for row in _read(directory, "edges", "CONDITION", gaps):
        conditions[row["start"]] = row["end"]
    for row in _read(directory, "nodes", "CONTROL_STRUCTURE", gaps):
        function = owner(row["id"])
        if function is None:
            continue
        if len(function.branches) >= MAX_BRANCHES_PER_FUNCTION:
            if "branches" not in function.cut:
                function.cut.append("branches")
            continue
        function.branches.append(CpgBranch(row.get("CONTROL_STRUCTURE_TYPE", "")[:32], _int(row.get("LINE_NUMBER", "")),
                                           _text(row.get("CODE", "")), codes.get(conditions.get(row["id"], "")) or None))
    for row in _read(directory, "edges", "REACHING_DEF", gaps):
        function = owner(row["start"])
        if function is not None:
            function.reaching_def_edges += 1
    out.functions = sorted(methods.values(), key=lambda item: (item.path, item.line or 0, item.name, item.function_id))
    for function in out.functions:
        function.calls.sort(key=lambda item: (item.line or 0, item.name))
        function.branches.sort(key=lambda item: (item.line or 0, item.kind))
    gaps.extend([NO_CALL_EDGES_GAP, NO_CFG_GAP])
    for function in out.functions:
        if function.cut:
            gaps.append(f"cpg_export_limit: {function.name} lists a bounded subset of its {'/'.join(function.cut)}")
    out.gaps = sorted(set(gaps) | ownership_gaps)
    return out

