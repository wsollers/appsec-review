"""Slice anchors: correlated CodeQL ``dataflow_path`` facts -> a ``SliceRequest`` (``package-slice/2``).

Input shape consumed (``graph.normalize`` ``_Builder.path_fact``, family ``dataflow_path``). Each entry of
``paths`` is ``(fact identity, mapping)`` where the mapping is the fact payload's ``result``; a full payload
(``{"result": {...}, "gaps": [...]}``) is also accepted and its ``gaps`` are read as the path's gaps::

    {
      "steps": [{"n": int, "role": "source"|"step"|"call"|"return"|"sink",
                 "location": SourceLocation dict | None,   # path, file_sha256, start_line, end_line, ambiguous, ...
                 "symbol": "asr:symbol:<sha>" | None,      # CodeQL-export symbol of the step's function
                 "display": str}],
      "guards": ["asr:guard_fact:<sha>", ...] | [{"identity": str, "location": SourceLocation dict}, ...],
      "ranges": [{"identity": str, "location": SourceLocation dict}, ...],   # optional; not emitted today
      "sanitizers": [{"api": str, "location": SourceLocation dict | None}],
      "truncated_steps": bool,
      "gaps": [str, ...],                                  # optional: the fact payload's gaps
      "source": {...}, "sink": {...}, ...                  # not used here
    }

Roles map to anchor reasons: ``source`` -> SOURCE, ``sink`` -> SINK, ``step``/``call``/``return`` (and any
other role) -> PATH_STEP; located guards -> GUARD, located ranges -> RANGE, located sanitizers -> SANITIZER.
Every line of a location (``start_line..end_line``, at most ``MAX_LOCATION_LINES``) becomes one anchor whose
``ref`` is the path identity (a guard's or range's own identity when it carries one), ``function`` the step's
symbol identity and ``symbol`` its display text (a sanitizer's API name).

Today the normalizer publishes guards as bare ``guard_fact`` identities without locations; those cannot be
anchored here and are recorded as ``path_step_unlocated`` gaps. The integration may resolve them to
``{identity, location}`` mappings before calling :func:`build_request`.

Function spans. Each anchor line's enclosing *named* function or method comes from ``review.slicing.spans``.
That module tries the file's accepted tree-sitter rows first (``sources.syntax_rows``, matched by file hash).
Next it tries the graph symbols' function-name lines for the file (``function_headers``), preferring the
step's own symbol. Last, it uses the language's text rules, which cover every catalog language: brace,
indentation and ``def``/``end`` extents with language-specific header patterns, comments and literals. The
innermost enclosing function wins. Lambdas, closures and blocks stay inside it. An extent cut by
``max_function_lines`` is ``truncated``. A line outside every named function (for example module-level code),
or in a language no layer resolves, gets no span. Its anchors are dropped with a
``slice_function_unresolved`` gap that names the language and the layers tried; the slicer never invents a
window. A fallback past damaged or incomplete tree-sitter rows adds a ``slice_function_fallback`` gap.
Overlapping extents in one file are merged into one ``FunctionSpan``, whose ``basis`` is the least precise
of the bases merged into it.

Gaps (all named, prefixed with the path identity where they come from one path):
``slice_source_unavailable: <path>: <reason>`` when the source text is unavailable (its anchors are dropped),
``path_step_unlocated: <path id> step <n>: ...`` for a missing/invalid/ambiguous location (ambiguous
locations still anchor), and the inherited path gaps ``truncated_steps``, ``omitted_paths`` and
``ambiguous_step_location`` as ``<path id>: <gap>``.
"""
from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from appsec_review.review.slicing import spans as function_spans
from appsec_review.review.slicing.contract import (
    GAP_PATH_UNAVAILABLE, GAP_SOURCE_UNAVAILABLE, GAP_STEP_UNLOCATED, GAP_TRUNCATED, Anchor, FunctionSpan, LineKey,
    Reason, SliceRequest, SliceSources,
)
from appsec_review.review.slicing.spans import Extent, Header

GAP_FUNCTION_UNRESOLVED = "slice_function_unresolved"
INHERITED_GAPS = ("truncated_steps", "omitted_paths", "ambiguous_step_location")
MAX_LOCATION_LINES = 8

_ROLES = {"source": Reason.SOURCE, "sink": Reason.SINK}
_IDENTITY = re.compile(r"^asr:[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


def build_request(paths: Sequence[tuple[str, Mapping[str, Any]]], sources: SliceSources, *,
                  max_function_lines: int,
                  function_headers: Mapping[tuple[str, str], Sequence[Header]] | None = None,
                  ) -> tuple[SliceRequest, tuple[str, ...]]:
    """The slice request for a lead's correlated paths, and the named gaps found building it.

    ``function_headers`` maps ``(path, file_sha256)`` to the graph symbols' function-name lines in that file.
    """
    if isinstance(max_function_lines, bool) or not isinstance(max_function_lines, int) or max_function_lines < 1:
        raise ValueError("max_function_lines must be a positive integer")
    gaps: list[str] = []
    anchors: set[Anchor] = set()
    for identity, fact in sorted(paths, key=lambda item: item[0]):
        anchors.update(_path_anchors(identity, fact, gaps))

    by_file: dict[tuple[str, str], list[Anchor]] = defaultdict(list)
    for anchor in anchors:
        by_file[(anchor.key.path, anchor.key.file_sha256)].append(anchor)
    kept: list[Anchor] = []
    spans: list[FunctionSpan] = []
    for (path, sha), file_anchors in sorted(by_file.items()):
        lines, reason = sources.source_lines(path, sha)
        if lines is None:
            gaps.append(f"{GAP_SOURCE_UNAVAILABLE}: {path}: {reason or 'no reason given'}")
            continue
        try:
            rows = sources.syntax_rows(path)
        except Exception as exc:  # noqa: BLE001 - spans fall back to text; the syntax strategy reports the failure
            rows = None
            gaps.append(f"{function_spans.GAP_FUNCTION_FALLBACK}: tree_sitter rows for {path} could not be read "
                        f"({type(exc).__name__}); function spans use the text rules")
        headers = tuple((function_headers or {}).get((path, sha), ()))
        resolutions: dict[tuple[int, str | None], function_spans.Resolution] = {}
        located: list[tuple[Anchor, Extent]] = []
        for anchor in sorted(file_anchors, key=_anchor_order):
            line = anchor.key.line
            if line > len(lines):
                gaps.append(f"{GAP_STEP_UNLOCATED}: {anchor.ref}: line {line} is beyond the end of {path}")
                continue
            cache = (line, anchor.function)
            if cache not in resolutions:
                resolutions[cache] = function_spans.resolve(
                    lines, line, path, sha, rows=rows, headers=headers, function=anchor.function,
                    max_lines=max_function_lines)
            resolution = resolutions[cache]
            gaps.extend(f"{note} ({path}:{line})" for note in resolution.notes)
            if resolution.extent is None:
                gaps.append(f"{GAP_FUNCTION_UNRESOLVED}: {path}:{line}: {resolution.reason}; the "
                            f"{anchor.reason.value} anchor is not sliced")
                continue
            located.append((anchor, resolution.extent))
        file_spans = _merge(path, sha, located)
        spans.extend(file_spans)
        kept.extend(anchor for anchor, _extent in located)
    request = SliceRequest(anchors=tuple(sorted(kept, key=_anchor_order)), functions=tuple(spans), sources=sources)
    return request, tuple(dict.fromkeys(gaps))


def _anchor_order(anchor: Anchor) -> tuple[Any, ...]:
    return (anchor.key, anchor.reason.value, anchor.ref, anchor.function or "", anchor.symbol or "")


def _path_anchors(identity: str, fact: Mapping[str, Any], gaps: list[str]) -> list[Anchor]:
    if not isinstance(fact, Mapping):
        gaps.append(f"{GAP_PATH_UNAVAILABLE}: {identity}: the path fact is not a mapping")
        return []
    fact_gaps = fact.get("gaps") or ()
    if "steps" not in fact and isinstance(fact.get("result"), Mapping):
        fact = fact["result"]
        fact_gaps = [*fact_gaps, *(fact.get("gaps") or ())]
    inherited = [str(gap) for gap in fact_gaps if isinstance(gap, str) and gap.startswith(INHERITED_GAPS)]
    if fact.get("truncated_steps") and not any(gap.startswith("truncated_steps") for gap in inherited):
        inherited.append("truncated_steps: middle steps of the path were dropped")
    gaps.extend(f"{identity}: {gap}" for gap in inherited)

    steps = fact.get("steps")
    if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)) or not steps:
        gaps.append(f"{GAP_PATH_UNAVAILABLE}: {identity}: the path fact carries no steps")
        return []
    anchors: list[Anchor] = []
    for index, step in enumerate(steps):
        if not isinstance(step, Mapping):
            gaps.append(f"{GAP_STEP_UNLOCATED}: {identity} step {index}: the step is not a mapping")
            continue
        n = step.get("n", index)
        function = step.get("symbol")
        display = step.get("display")
        anchors.extend(_located(
            step.get("location"), _ROLES.get(str(step.get("role")), Reason.PATH_STEP), identity,
            f"{identity} step {n}", gaps,
            function=function if isinstance(function, str) and _IDENTITY.match(function) else None,
            symbol=display if isinstance(display, str) and display else None))
    for key, reason in (("guards", Reason.GUARD), ("ranges", Reason.RANGE)):
        for entry in fact.get(key) or ():
            if isinstance(entry, Mapping) and entry.get("location") is not None:
                ref = entry.get("identity")
                ref = ref if isinstance(ref, str) and ref else identity
                anchors.extend(_located(entry["location"], reason, ref, f"{identity} {reason.value} {ref}", gaps))
            else:
                name = entry.get("identity") if isinstance(entry, Mapping) else entry
                gaps.append(f"{GAP_STEP_UNLOCATED}: {identity} {reason.value} {name}: no location in the path fact")
    for entry in fact.get("sanitizers") or ():
        api = entry.get("api") if isinstance(entry, Mapping) else None
        api = api if isinstance(api, str) and api else None
        anchors.extend(_located(entry.get("location") if isinstance(entry, Mapping) else None, Reason.SANITIZER,
                                identity, f"{identity} sanitizer {api or '?'}", gaps, symbol=api))
    return anchors


def _located(location: Any, reason: Reason, ref: str, where: str, gaps: list[str], *,
             function: str | None = None, symbol: str | None = None) -> list[Anchor]:
    """One anchor per line of a ``SourceLocation`` dict; a missing or invalid location is a gap."""
    if not isinstance(location, Mapping):
        gaps.append(f"{GAP_STEP_UNLOCATED}: {where}: no location")
        return []
    path, sha = location.get("path"), location.get("file_sha256")
    start, end = location.get("start_line"), location.get("end_line", location.get("start_line"))
    if (not isinstance(path, str) or not path or not isinstance(sha, str) or not _SHA.match(sha)
            or type(start) is not int or start < 1 or type(end) is not int or end < start):
        gaps.append(f"{GAP_STEP_UNLOCATED}: {where}: invalid location")
        return []
    if location.get("ambiguous"):
        gaps.append(f"{GAP_STEP_UNLOCATED}: {where}: ambiguous location at {path}:{start}")
    if end - start + 1 > MAX_LOCATION_LINES:
        gaps.append(f"{GAP_TRUNCATED}: {where} spans {end - start + 1} lines; only its first line is anchored")
        end = start
    return [Anchor(LineKey(path, sha, line), reason, ref, function=function, symbol=symbol)
            for line in range(start, end + 1)]


def _merge(path: str, sha: str, located: Sequence[tuple[Anchor, Extent]]) -> list[FunctionSpan]:
    """Non-overlapping spans of one file: overlapping extents merge, keeping their anchors' function and the
    least precise span basis."""
    groups: list[list[Any]] = []        # [first, last, truncated, functions, basis rank]
    for anchor, extent in sorted(located, key=lambda item: (item[1].first, item[1].last)):
        rank = function_spans.basis_rank(extent.basis)
        if groups and extent.first <= groups[-1][1]:
            group = groups[-1]
            group[1], group[2], group[4] = max(group[1], extent.last), group[2] or extent.truncated, max(group[4], rank)
        else:
            group = [extent.first, extent.last, extent.truncated, set(), rank]
            groups.append(group)
        if anchor.function:
            group[3].add(anchor.function)
    return [FunctionSpan(path, sha, first, last, function=next(iter(functions)) if len(functions) == 1 else None,
                         truncated=truncated, basis=function_spans.SPAN_BASES[rank])
            for first, last, truncated, functions, rank in groups]


__all__ = ["GAP_FUNCTION_UNRESOLVED", "INHERITED_GAPS", "MAX_LOCATION_LINES", "build_request"]
