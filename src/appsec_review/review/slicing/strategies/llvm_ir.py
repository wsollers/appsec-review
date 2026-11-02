"""``llvm_ir_def_use``: interacters and a bounded backward slice from LLVM IR def-use records.

Precision: ``Precision.COMPILER``. The facts are clang's own ``-O0 -g`` LLVM IR, read by
``jobs/job_cpp_compiled_analysis/llvm_ir.py`` (``DefUse`` / ``IrFunction.flow()``), not identifier text.

Input (``SliceSources.ir_flows(path)``) is a sequence of mappings, each one of:

* **a function flow row** - the payload of an ``ir_entity`` flow row: the llvm-ir producer's entity
  payload, or the ``producer_neighborhood`` ``fact == "flow"`` row payload copied into shard
  ``graph-<scope_id>-producers`` by ``jobs/job_code_graph_index/producers.py``. A store entity row that
  wraps it under ``"payload"`` is accepted too. Only these keys are read::

      {"function": "copy_field",                      # optional label used in gaps
       "flow": {"def_use": [{"value": "%9", "def_line": 12, "use_lines": [12], "use_count": 1},
                            {"value": "%7", "def_line": None, "use_lines": [11, 12, 14], "use_count": 4}],
                "truncated": []}}                       # "blocks"/"def_use" when the producer cut the function

* **a bare def-use record** ``{"value": str, "def_line": int | None, "use_lines": [int, ...],
  "use_count": int}`` (one element of ``flow.def_use``).

``def_line`` and ``use_lines`` are source lines of ``path`` (``DILocation`` lines of the instruction that
defines / reads the value). ``None`` means the source is unavailable for the file; an empty sequence means
available and empty.

Algorithm, per function span that holds an anchor (lines never leave that span):

1. Interacters (``Reason.INTERACTER``): the use lines of every value *defined* on an anchor line, and the
   other lines touching a *lineless* value that an anchor line touches. At ``-O0`` clang keeps every local
   variable and parameter in a stack slot (``alloca``) that carries no debug location, so a record with
   ``def_line: None`` is in practice a variable's slot and its ``use_lines`` are the lines that load or store
   it, including its declaration (``llvm.dbg.declare``). Sharing a slot is the compiler's version of the
   LLMxCPG "shares an identifier with the path" interacter.
2. Backward slice (``Reason.BACKWARD_DEF``) over anchors and interacters, to a fixpoint of at most
   ``MAX_ROUNDS`` rounds: a value used on a selected line contributes its ``def_line``; a slot touched by a
   selected line contributes the slot's *earlier* lines (its candidate stores). A closure still growing
   after ``MAX_ROUNDS`` stops with a ``slice_truncated`` gap.

Limitations: the record does not say whether a slot line stores or loads, so "earlier line" approximates
reaching stores and misses loop-carried stores below the read; lines come from debug locations, so a macro
or a multi-line statement is attributed to the line clang chose; memory reached through pointers is left to
``svf_points_to``. A file with no rows, a span no record touches, a function the producer truncated, a
malformed record and a cut closure are named gaps, never a clean empty slice.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from appsec_review.review.slicing.contract import (
    GAP_NOT_APPLICABLE, GAP_PARTIAL, GAP_TRUNCATED, FunctionSpan, LineKey, Precision, Reason, SliceContribution,
    SliceLine, SliceRequest, StrategyState,
)

NAME = "llvm_ir_def_use"
MAX_ROUNDS = 8
_CUT_FLAGS = frozenset({"blocks", "def_use"})   # producer cuts that drop def-use detail (llvm_ir.parse_module)


@dataclass(frozen=True, slots=True)
class _Flow:
    def_line: int | None
    use_lines: tuple[int, ...]


@dataclass(slots=True)
class _Function:
    label: str | None
    cut: tuple[str, ...]
    flows: list[_Flow] = field(default_factory=list)


def _line(value: Any) -> int | None:
    return value if type(value) is int and value >= 1 else None


def _flow(raw: Any) -> _Flow | None:
    if not isinstance(raw, Mapping):
        return None
    def_line, uses = raw.get("def_line"), raw.get("use_lines")
    if def_line is not None and _line(def_line) is None:
        return None
    if not isinstance(uses, (list, tuple)) or any(_line(item) is None for item in uses):
        return None
    return _Flow(def_line, tuple(sorted(set(uses))))


def _read(rows: Iterable[Any]) -> tuple[list[_Function], int]:
    """Function flow rows and bare records of one file, and the number of malformed entries."""
    functions: list[_Function] = []
    loose = _Function(None, ())
    malformed = 0
    for row in rows:
        if not isinstance(row, Mapping):
            malformed += 1
            continue
        holder: Mapping[str, Any] = row
        if not isinstance(row.get("flow"), Mapping) and isinstance(row.get("payload"), Mapping):
            holder = row["payload"]
        flow = holder.get("flow")
        if isinstance(flow, Mapping):
            items = flow.get("def_use")
            if not isinstance(items, (list, tuple)):
                malformed += 1
                continue
            flags = flow.get("truncated") if isinstance(flow.get("truncated"), (list, tuple)) else ()
            label = holder.get("function") or row.get("name")
            function = _Function(str(label) if label else None,
                                 tuple(sorted({str(flag) for flag in flags} & _CUT_FLAGS)))
            for item in items:
                parsed = _flow(item)
                if parsed is None:
                    malformed += 1
                else:
                    function.flows.append(parsed)
            functions.append(function)
        elif "use_lines" in row:
            parsed = _flow(row)
            if parsed is None:
                malformed += 1
            else:
                loose.flows.append(parsed)
        else:
            malformed += 1
    if loose.flows:
        functions.append(loose)
    return functions, malformed


def _touches(flow: _Flow, span: FunctionSpan) -> bool:
    lines = (*flow.use_lines, *((flow.def_line,) if flow.def_line is not None else ()))
    return any(span.first <= line <= span.last for line in lines)


def _slice_span(span: FunctionSpan, anchors: frozenset[int], flows: list[_Flow]) -> tuple[dict[int, set[Reason]], bool]:
    """Lines of ``span`` related to its anchor lines, and whether ``MAX_ROUNDS`` cut the closure."""
    def inside(line: int) -> bool:
        return span.first <= line <= span.last

    by_use: dict[int, list[_Flow]] = defaultdict(list)
    by_def: dict[int, list[_Flow]] = defaultdict(list)
    for flow in flows:
        for line in flow.use_lines:
            if inside(line):
                by_use[line].append(flow)
        if flow.def_line is not None and inside(flow.def_line):
            by_def[flow.def_line].append(flow)
    found: dict[int, set[Reason]] = defaultdict(set)

    def add(line: int, reason: Reason) -> None:
        if inside(line) and line not in anchors:
            found[line].add(reason)

    for anchor in sorted(anchors):
        for flow in by_def.get(anchor, ()):
            for line in flow.use_lines:
                add(line, Reason.INTERACTER)
        for flow in by_use.get(anchor, ()):
            if flow.def_line is None:
                for line in flow.use_lines:
                    add(line, Reason.INTERACTER)
    selected = set(anchors) | set(found)

    def step(frontier: set[int]) -> set[int]:
        new: set[int] = set()
        for line in sorted(frontier):
            for flow in by_use.get(line, ()):
                candidates = (flow.def_line,) if flow.def_line is not None else \
                    tuple(item for item in flow.use_lines if item < line)
                new.update(item for item in candidates if inside(item) and item not in selected)
        return new

    frontier, rounds = set(selected), 0
    while frontier:
        new = step(frontier)
        if not new:
            break
        if rounds == MAX_ROUNDS:
            return found, True
        rounds += 1
        for line in new:
            found[line].add(Reason.BACKWARD_DEF)
        selected |= new
        frontier = new
    return found, False


class LlvmIrDefUse:
    """Compiler-precision slice from LLVM IR def-use records (see the module docstring for the input)."""

    name = NAME
    precision = Precision.COMPILER

    def expand(self, request: SliceRequest) -> SliceContribution:
        anchors: dict[FunctionSpan, set[int]] = defaultdict(set)
        for anchor in request.anchors:
            span = request.span_for(anchor.key)
            if span is not None:
                anchors[span].add(anchor.key.line)
        if not anchors:
            return self._none(f"{GAP_NOT_APPLICABLE}: {NAME}: no anchor line lies inside a function span")
        spans = sorted(anchors, key=lambda item: (item.path, item.first, item.last, item.file_sha256))
        files: dict[str, list[_Function] | None] = {}
        gaps: list[str] = []
        for path in sorted({span.path for span in spans}):
            rows = request.sources.ir_flows(path)
            if rows is None:
                files[path] = None
                continue
            files[path], malformed = _read(rows)
            if malformed:
                gaps.append(f"{GAP_PARTIAL}: {NAME}: {malformed} malformed LLVM IR def-use entr"
                            f"{'y' if malformed == 1 else 'ies'} in {path} were ignored")
        missing = sorted(path for path, functions in files.items() if functions is None)
        if missing:
            gaps.insert(0, f"{GAP_NOT_APPLICABLE}: {NAME}: no LLVM IR def-use rows for {', '.join(missing)} "
                           "(not a compiled C/C++ file, or job_cpp_compiled_analysis did not cover it)")
        lines: dict[LineKey, set[Reason]] = defaultdict(set)
        covered = 0
        for span in spans:
            functions = files[span.path]
            if functions is None:
                continue
            touching = [item for item in functions if any(_touches(flow, span) for flow in item.flows)]
            if not touching:
                gaps.append(f"{GAP_NOT_APPLICABLE}: {NAME}: no LLVM IR def-use record falls inside "
                            f"{span.path}:{span.first}-{span.last} (the function is not in the published IR)")
                continue
            covered += 1
            for item in touching:
                if item.cut:
                    gaps.append(f"{GAP_PARTIAL}: {NAME}: the LLVM IR flow of {item.label or span.path} is truncated "
                                f"({', '.join(item.cut)}); definitions in {span.path}:{span.first}-{span.last} "
                                "may be missing")
            found, cut = _slice_span(span, frozenset(anchors[span]), [flow for item in touching for flow in item.flows])
            if cut:
                gaps.append(f"{GAP_TRUNCATED}: {NAME}: the backward closure in {span.path}:{span.first}-{span.last} "
                            f"stopped after MAX_ROUNDS={MAX_ROUNDS} rounds")
            for line, reasons in found.items():
                lines[LineKey(span.path, span.file_sha256, line)].update(reasons)
        if not covered:
            return self._none(*gaps)
        contributed = tuple(SliceLine(key, frozenset(reasons), NAME, Precision.COMPILER)
                            for key, reasons in sorted(lines.items()))
        state = StrategyState.PARTIAL if gaps else StrategyState.APPLIED
        return SliceContribution(NAME, Precision.COMPILER, state, contributed, tuple(gaps))

    @staticmethod
    def _none(*gaps: str) -> SliceContribution:
        return SliceContribution(NAME, Precision.COMPILER, StrategyState.NOT_APPLICABLE, (), tuple(gaps))


__all__ = ["GAP_PARTIAL", "LlvmIrDefUse", "MAX_ROUNDS", "NAME"]
