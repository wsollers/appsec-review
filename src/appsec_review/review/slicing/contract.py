"""Dataflow-bounded package slice contract (``package-slice/1``).

A finding-lead package whose lead has a correlated ``dataflow_path`` fact is bounded by that path rather
than by call-graph depth (docs/architecture/review-protocol-v2.md section 4). The model-facing source is a
*slice*: the path's anchor lines (source, steps, sink, guards, ranges, sanitizers) plus the lines that a
pluggable set of strategies relate to them (interacting identifiers, backward definitions, aliases), all
inside the functions the path passes through. This follows LLMxCPG (arXiv:2507.16585): path, interacters,
backward slice over both.

This module is the shared, pure contract. Strategies implement ``SliceStrategy`` and are named in the
central TOML (``jobs.job_inference_security_review.settings.packages.slice_strategies``); the composer
(``review.slicing.compose``) runs every configured strategy, unions their lines (each line keeps its
highest-precision basis), applies the line budget, and returns a ``SliceResult``. A strategy that cannot
run reports ``not_applicable`` or ``failed`` with a named gap; missing data is never a clean slice.

The slice record stores identities, paths, file hashes and line numbers only. Source text is read when a
cell's view is built, from the accepted source index, and verified against the recorded file hash.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any, Protocol, runtime_checkable

SLICE_RULE = "appsec-review/package-slice/1"
SLICE_PRODUCER = "dataflow_slice"
PATH_BASIS = "dataflow_path"


class Bound(str, Enum):
    """Which bound selected a lead package's neighborhood."""

    DATAFLOW_PATH = "dataflow_path"
    CALL_DEPTH = "call_depth"


class Precision(IntEnum):
    """Basis precision of a slice line; a line keeps the highest precision that produced it."""

    LEXICAL = 1    # identifier tokens of verified source text
    SYNTAX = 2     # tree-sitter syntax projection (names, definitions, references)
    COMPILER = 3   # compiler-derived facts (LLVM IR def-use, SVF points-to)
    PATH = 4       # the CodeQL dataflow path itself (anchors)

    @property
    def label(self) -> str:
        return self.name.lower()


class Reason(str, Enum):
    """Why a line is in the slice."""

    SOURCE = "source"
    SINK = "sink"
    PATH_STEP = "path_step"
    GUARD = "guard"
    RANGE = "range"
    SANITIZER = "sanitizer"
    INTERACTER = "interacter"          # shares an identifier with a path line (LLMxCPG "interacter")
    BACKWARD_DEF = "backward_def"      # defines a value used on a path or interacter line
    ALIAS = "alias"                    # touches a memory object a path line may point to
    FUNCTION_HEADER = "function_header"


ANCHOR_REASONS = frozenset({Reason.SOURCE, Reason.SINK, Reason.PATH_STEP, Reason.GUARD, Reason.RANGE,
                            Reason.SANITIZER})


class StrategyState(str, Enum):
    APPLIED = "applied"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    FAILED = "failed"


# Gap reason prefixes (producer ``dataflow_slice``). Inherited path gaps (truncated_steps, omitted_paths,
# ambiguous_step_location) are copied from the path facts unchanged.
GAP_PATH_UNAVAILABLE = "dataflow_path_unavailable"
GAP_NOT_APPLICABLE = "slice_strategy_not_applicable"
GAP_FAILED = "slice_strategy_failed"
GAP_LEXICAL_ONLY = "slice_lexical_only"
GAP_TRUNCATED = "slice_truncated"
GAP_SOURCE_UNAVAILABLE = "slice_source_unavailable"
GAP_STEP_UNLOCATED = "path_step_unlocated"


@dataclass(frozen=True, slots=True, order=True)
class LineKey:
    """A 1-based line of a verified source file."""

    path: str
    file_sha256: str
    line: int

    def __post_init__(self) -> None:
        if not self.path or not self.file_sha256:
            raise ValueError("a slice line needs a path and a file hash")
        if type(self.line) is not int or self.line < 1:
            raise ValueError("a slice line number is a positive integer")


@dataclass(frozen=True, slots=True)
class Anchor:
    """A line that the dataflow path (or a fact attached to it) names directly."""

    key: LineKey
    reason: Reason
    ref: str                        # logical identity of the fact that named the line
    function: str | None = None     # symbol identity of the enclosing function, when the step names one
    symbol: str | None = None       # display text of the step (e.g. the expression), when present

    def __post_init__(self) -> None:
        if self.reason not in ANCHOR_REASONS:
            raise ValueError(f"{self.reason} is not an anchor reason")


@dataclass(frozen=True, slots=True)
class FunctionSpan:
    """The inclusive extent of one function the path passes through; strategies stay inside spans."""

    path: str
    file_sha256: str
    first: int
    last: int
    function: str | None = None
    truncated: bool = False

    def __post_init__(self) -> None:
        if not 1 <= self.first <= self.last:
            raise ValueError("a function span is 1 <= first <= last")

    def contains(self, key: LineKey) -> bool:
        return key.path == self.path and key.file_sha256 == self.file_sha256 and self.first <= key.line <= self.last


@dataclass(frozen=True, slots=True)
class SliceLine:
    key: LineKey
    reasons: frozenset[Reason]
    basis: str                      # strategy name, or ``PATH_BASIS`` for anchors
    precision: Precision

    def __post_init__(self) -> None:
        if not self.reasons:
            raise ValueError("a slice line needs at least one reason")


@dataclass(frozen=True, slots=True)
class SliceContribution:
    """One strategy's output. ``lines`` must lie inside the request's function spans."""

    strategy: str
    precision: Precision
    state: StrategyState
    lines: tuple[SliceLine, ...] = ()
    gaps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.state in (StrategyState.NOT_APPLICABLE, StrategyState.FAILED, StrategyState.PARTIAL) and not self.gaps:
            raise ValueError(f"a {self.state.value} strategy must name a gap")
        if self.state in (StrategyState.NOT_APPLICABLE, StrategyState.FAILED) and self.lines:
            raise ValueError(f"a {self.state.value} strategy contributes no lines")


@runtime_checkable
class SliceSources(Protocol):
    """Read-only accepted data a strategy may use. ``None`` means the source is unavailable for this run
    or file (the strategy reports ``not_applicable`` with a gap); an empty sequence means available and
    empty. Implementations are deterministic for a given accepted scope."""

    def source_lines(self, path: str, file_sha256: str) -> tuple[Sequence[str] | None, str | None]:
        """Verified UTF-8 lines of the file, or ``(None, reason)``."""

    def ir_flows(self, path: str) -> Sequence[Mapping[str, Any]] | None:
        """``ir_entity`` flow rows (LLVM IR def-use, ``job_cpp_compiled_analysis``) located in ``path``."""

    def svf_records(self, path: str, line: int) -> Sequence[Mapping[str, Any]] | None:
        """SVF ``points_to_set``/``memory_object``/``indirect_call_targets`` records at ``path:line``."""

    def syntax_rows(self, path: str) -> Sequence[Mapping[str, Any]] | None:
        """Accepted tree-sitter ``ast_node`` syntax-projection rows located in ``path``."""


@dataclass(frozen=True, slots=True)
class SliceRequest:
    anchors: tuple[Anchor, ...]
    functions: tuple[FunctionSpan, ...]
    sources: SliceSources

    def span_for(self, key: LineKey) -> FunctionSpan | None:
        return next((span for span in self.functions if span.contains(key)), None)

    def anchor_lines(self) -> tuple[LineKey, ...]:
        return tuple(sorted({anchor.key for anchor in self.anchors}))


@runtime_checkable
class SliceStrategy(Protocol):
    name: str
    precision: Precision

    def expand(self, request: SliceRequest) -> SliceContribution:
        """Lines related to the request's anchors, inside its function spans. Must not raise for missing
        data (report ``not_applicable``); an unexpected exception is recorded by the composer as
        ``failed``."""


@dataclass(frozen=True, slots=True)
class SliceBudget:
    max_lines: int = 120
    max_lines_per_function: int = 40

    def __post_init__(self) -> None:
        for name in ("max_lines", "max_lines_per_function"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_lines_per_function > self.max_lines:
            raise ValueError("max_lines_per_function must not exceed max_lines")


@dataclass(frozen=True, slots=True)
class StrategyOutcome:
    name: str
    precision: Precision
    state: StrategyState
    lines: int
    gaps: tuple[str, ...] = ()

    def record(self) -> dict[str, Any]:
        return {"name": self.name, "precision": self.precision.label, "state": self.state.value,
                "lines": self.lines, "gaps": list(self.gaps)}


@dataclass(frozen=True, slots=True)
class SliceResult:
    """The composed slice. ``functions`` holds every span with at least one kept line."""

    functions: tuple[FunctionSpan, ...]
    lines: tuple[SliceLine, ...]
    strategies: tuple[StrategyOutcome, ...]
    omitted_lines: int = 0
    gaps: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()     # identities of the dataflow_path facts that anchored it

    def record(self) -> dict[str, Any]:
        """The ``package-slice/1`` record (deterministic; identities and line numbers only)."""
        by_span: dict[FunctionSpan, list[SliceLine]] = {span: [] for span in self.functions}
        for line in self.lines:
            span = next((item for item in self.functions if item.contains(line.key)), None)
            if span is None:
                raise ValueError(f"slice line {line.key} is outside every function span")
            by_span[span].append(line)
        functions = []
        for span in sorted(self.functions, key=lambda item: (item.path, item.first, item.last)):
            kept = sorted(by_span[span], key=lambda item: item.key.line)
            functions.append({
                "path": span.path, "file_sha256": span.file_sha256, "function": span.function,
                "first": span.first, "last": span.last, "truncated": span.truncated,
                "lines": [{"line": item.key.line, "reasons": sorted(reason.value for reason in item.reasons),
                           "basis": item.basis, "precision": item.precision.label} for item in kept]})
        return {"rule": SLICE_RULE, "paths": sorted(self.paths), "functions": functions,
                "strategies": [item.record() for item in self.strategies],
                "omitted": {"lines": self.omitted_lines}, "gaps": sorted(set(self.gaps))}


__all__ = [
    "ANCHOR_REASONS", "Anchor", "Bound", "FunctionSpan", "GAP_FAILED", "GAP_LEXICAL_ONLY", "GAP_NOT_APPLICABLE",
    "GAP_PATH_UNAVAILABLE", "GAP_SOURCE_UNAVAILABLE", "GAP_STEP_UNLOCATED", "GAP_TRUNCATED", "LineKey",
    "PATH_BASIS", "Precision", "Reason", "SLICE_PRODUCER", "SLICE_RULE", "SliceBudget", "SliceContribution",
    "SliceLine", "SliceRequest", "SliceResult", "SliceSources", "SliceStrategy", "StrategyOutcome", "StrategyState",
]
