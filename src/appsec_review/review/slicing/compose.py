"""Slice composer: run the configured strategies over a ``SliceRequest`` and build the ``SliceResult``.

Every configured strategy runs, in configured order. An exception is isolated as a ``failed`` outcome with
the gap ``slice_strategy_failed: <name>: <ExceptionType>``; it never propagates. Contributed lines outside the
request's function spans are dropped and named (``slice_out_of_span: <name>: <n> lines ...``).

Union: lines are keyed by ``LineKey``; reasons are unioned; a line's ``basis``/``precision`` is the
highest-precision contribution (ties: the first strategy in configured order). Anchor lines are always in the
slice with ``Precision.PATH`` and basis ``dataflow_path``. When no strategy applied (all ``not_applicable`` or
``failed``, or none configured) the slice holds only the anchors and says so in a gap.

Budget (D6): first ``max_lines_per_function`` per span, then ``max_lines`` in total. Lines are dropped in
this order: non-anchor lines before anchors; lowest precision first; then the farthest from the nearest
anchor line of the same span; then the highest line number. ``omitted_lines`` counts every dropped line and
``slice_truncated: <n> lines omitted`` names it (anchors dropped, only when anchors alone exceed the budget,
get their own ``slice_truncated`` gap).

A span whose kept non-anchor lines all have ``lexical`` precision is named
``slice_lexical_only: <path>:<first>-<last>``:
those lines share identifiers with the path but nothing more precise relates them to it.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from appsec_review.review.slicing.contract import (
    GAP_FAILED, GAP_LEXICAL_ONLY, GAP_NOT_APPLICABLE, GAP_STEP_UNLOCATED, GAP_TRUNCATED, PATH_BASIS, FunctionSpan,
    LineKey, Precision, Reason, SliceBudget, SliceContribution, SliceLine, SliceRequest, SliceResult, SliceStrategy,
    StrategyOutcome, StrategyState,
)

GAP_OUT_OF_SPAN = "slice_out_of_span"
GAP_NO_EXPANSION = f"{GAP_NOT_APPLICABLE}: all_strategies: no configured strategy applied; the slice holds only " \
                   "the path anchors"
_ANCHOR_ORDER = -1
_FAR = 10 ** 9


@dataclass(slots=True)
class _Merged:
    precision: Precision
    order: int
    basis: str
    reasons: set[Reason] = field(default_factory=set)


def compose(request: SliceRequest, strategies: Sequence[SliceStrategy], budget: SliceBudget, *,
            inherited_gaps: Iterable[str] = (), paths: Iterable[str] = ()) -> SliceResult:
    """The composed, budgeted slice for ``request``. Never raises for a strategy's failure."""
    gaps: list[str] = list(inherited_gaps)
    merged: dict[LineKey, _Merged] = {}

    anchor_keys: set[LineKey] = set()
    for anchor in request.anchors:
        if request.span_for(anchor.key) is None:
            gaps.append(f"{GAP_STEP_UNLOCATED}: {anchor.ref}: anchor {anchor.key.path}:{anchor.key.line} lies "
                        "outside every function span")
            continue
        anchor_keys.add(anchor.key)
        entry = merged.setdefault(anchor.key, _Merged(Precision.PATH, _ANCHOR_ORDER, PATH_BASIS))
        entry.reasons.add(anchor.reason)

    outcomes: list[StrategyOutcome] = []
    for order, strategy in enumerate(strategies):
        name = str(getattr(strategy, "name", type(strategy).__name__))
        precision = getattr(strategy, "precision", Precision.LEXICAL)
        try:
            contribution = strategy.expand(request)
            if not isinstance(contribution, SliceContribution):
                raise TypeError(f"{name} returned {type(contribution).__name__}, not a SliceContribution")
        except Exception as exc:  # noqa: BLE001 - a strategy failure is a named gap, never a composer failure
            gap = f"{GAP_FAILED}: {name}: {type(exc).__name__}"
            outcomes.append(StrategyOutcome(name, precision, StrategyState.FAILED, 0, (gap,)))
            gaps.append(gap)
            continue
        outcome_gaps = list(contribution.gaps)
        contributed: set[LineKey] = set()
        outside = 0
        for line in contribution.lines:
            if request.span_for(line.key) is None:
                outside += 1
                continue
            contributed.add(line.key)
            entry = merged.get(line.key)
            if entry is None:
                entry = merged[line.key] = _Merged(line.precision, order, line.basis)
            elif line.precision > entry.precision or (line.precision == entry.precision and order < entry.order):
                entry.precision, entry.order, entry.basis = line.precision, order, line.basis
            entry.reasons.update(line.reasons)
        if outside:
            outcome_gaps.append(f"{GAP_OUT_OF_SPAN}: {name}: {outside} lines outside the function spans were dropped")
        outcomes.append(StrategyOutcome(name, precision, contribution.state, len(contributed),
                                        tuple(dict.fromkeys(outcome_gaps))))
        gaps.extend(outcome_gaps)
    if not any(item.state in (StrategyState.APPLIED, StrategyState.PARTIAL) for item in outcomes):
        gaps.append(GAP_NO_EXPANSION)

    lines = [SliceLine(key, frozenset(entry.reasons), entry.basis, entry.precision) for key, entry in merged.items()]
    kept, omitted, anchors_omitted = _trim(request, lines, anchor_keys, budget)
    if omitted:
        gaps.append(f"{GAP_TRUNCATED}: {omitted} lines omitted")
    if anchors_omitted:
        gaps.append(f"{GAP_TRUNCATED}: {anchors_omitted} path anchor lines omitted; the anchors alone exceed the "
                    "line budget")

    functions = tuple(span for span in request.functions if any(span.contains(line.key) for line in kept))
    for span in functions:
        extra = [line for line in kept if span.contains(line.key) and line.key not in anchor_keys]
        if extra and all(line.precision == Precision.LEXICAL for line in extra):
            gaps.append(f"{GAP_LEXICAL_ONLY}: {span.path}:{span.first}-{span.last}")
    return SliceResult(functions=functions, lines=tuple(sorted(kept, key=lambda line: line.key)),
                       strategies=tuple(outcomes), omitted_lines=omitted, gaps=tuple(dict.fromkeys(gaps)),
                       paths=tuple(sorted(set(paths))))


def _trim(request: SliceRequest, lines: Sequence[SliceLine], anchor_keys: set[LineKey], budget: SliceBudget
          ) -> tuple[list[SliceLine], int, int]:
    """Apply the per-function then total line caps; returns (kept, omitted, anchors omitted)."""
    span_of = {line.key: request.span_for(line.key) for line in lines}
    anchors_by_span: dict[FunctionSpan, list[int]] = {}
    for key in anchor_keys:
        anchors_by_span.setdefault(span_of[key], []).append(key.line)

    def drop_first(line: SliceLine) -> tuple[bool, int, int, int, LineKey]:
        near = anchors_by_span.get(span_of[line.key], ())
        distance = min((abs(line.key.line - anchor) for anchor in near), default=_FAR)
        return (line.key in anchor_keys, int(line.precision), -distance, -line.key.line, line.key)

    by_span: dict[FunctionSpan | None, list[SliceLine]] = {}
    for line in lines:
        by_span.setdefault(span_of[line.key], []).append(line)
    kept: list[SliceLine] = []
    dropped: list[SliceLine] = []
    for members in by_span.values():
        ordered = sorted(members, key=drop_first)
        cut = max(0, len(ordered) - budget.max_lines_per_function)
        dropped.extend(ordered[:cut])
        kept.extend(ordered[cut:])
    if len(kept) > budget.max_lines:
        ordered = sorted(kept, key=drop_first)
        cut = len(ordered) - budget.max_lines
        dropped.extend(ordered[:cut])
        kept = ordered[cut:]
    return kept, len(dropped), sum(1 for line in dropped if line.key in anchor_keys)


__all__ = ["GAP_NO_EXPANSION", "GAP_OUT_OF_SPAN", "compose"]
