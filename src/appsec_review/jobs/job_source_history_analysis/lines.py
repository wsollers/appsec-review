"""Line-level history: zero-context hunks, region mapping, fix-on-fix matching, symbol attribution.

Spans are inclusive 1-based line ranges.  A ``-U0`` hunk ``@@ -a,b +c,d @@`` touches old lines
``a..a+b-1`` and new lines ``c..c+d-1``.  A zero-length side (a pure insertion or deletion) has no
lines of its own, so it is represented by its two neighbouring lines ``(max(1, x), x + 1)``: a
change at a boundary touches the code on both sides of it.

Region mapping carries a span from a file version into the next one.  A line outside every hunk
shifts by the net size of the hunks before it.  A line inside a hunk maps to that hunk's whole
replacement region, so code that was rewritten later still maps to the code that replaced it.
This over-approximates attribution and never drops a touched region.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import re
from typing import Any


LINE_HISTORY_IDENTITY = "appsec-review/history-line-regions/1"
FIX_ON_FIX_IDENTITY = "appsec-review/fix-on-fix/1"
DAY = 86_400
Hunk = Sequence[int]
Span = tuple[int, int]
_HUNK = re.compile(rb"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_COMMIT = re.compile(rb"\x01([0-9a-f]{40}|[0-9a-f]{64})")


def parse_file_history(data: bytes) -> list[dict[str, Any]]:
    """Parse ``--format=%x01%H -U0`` output, newest first.

    Diff body lines always start with ``+``, ``-``, space, or backslash, so a line that starts with
    ``\\x01`` is a commit header and a line that starts with ``@@ -`` is a hunk header.
    """
    commits: list[dict[str, Any]] = []
    for raw in data.split(b"\n"):
        header = _COMMIT.fullmatch(raw)
        if header is not None:
            commits.append({"commit": header.group(1).decode(), "hunks": [], "binary": False})
            continue
        if not commits:
            if raw.strip():
                raise ValueError("file history output does not begin with a commit header")
            continue
        if raw.startswith(b"@@ -"):
            hunk = _HUNK.match(raw)
            if hunk is None:
                raise ValueError("file history hunk header is malformed")
            old_start, old_length, new_start, new_length = hunk.groups()
            commits[-1]["hunks"].append([int(old_start), 1 if old_length is None else int(old_length),
                                         int(new_start), 1 if new_length is None else int(new_length)])
        elif raw.startswith(b"Binary files "):
            commits[-1]["binary"] = True
    return commits


def _region(start: int, length: int) -> Span:
    return (start, start + length - 1) if length > 0 else (max(1, start), start + 1)


def old_regions(hunks: Iterable[Hunk]) -> list[Span]:
    return [_region(int(hunk[0]), int(hunk[1])) for hunk in hunks]


def new_regions(hunks: Iterable[Hunk]) -> list[Span]:
    return [_region(int(hunk[2]), int(hunk[3])) for hunk in hunks]


def overlaps(left: Span, right: Span) -> bool:
    return left[0] <= right[1] and right[0] <= left[1]


def _map_line(line: int, hunks: Sequence[Hunk]) -> Span:
    delta = 0
    for old_start, old_length, new_start, new_length in hunks:
        if old_length > 0 and old_start <= line <= old_start + old_length - 1:
            return _region(new_start, new_length)
        # An insertion after line ``a`` and a replacement ending at ``a+b-1`` both shift later lines.
        if (old_start + old_length if old_length else old_start + 1) <= line:
            delta += new_length - old_length
    mapped = max(1, line + delta)
    return mapped, mapped


def map_span(span: Span, hunks: Sequence[Hunk]) -> Span:
    """Map a span in a commit's pre-image to its post-image."""
    low, high = _map_line(span[0], hunks), _map_line(span[1], hunks)
    points = [*low, *high]
    for hunk in hunks:
        if hunk[1] > 0 and overlaps(span, _region(hunk[0], hunk[1])):
            points.extend(_region(hunk[2], hunk[3]))
    return min(points), max(points)


def map_forward(span: Span, chain: Sequence[Sequence[Hunk]]) -> Span:
    """Map through each later commit's hunks, oldest first."""
    for hunks in chain:
        span = map_span(span, hunks)
    return span


def _clamp(span: Span, line_total: int) -> Span:
    last = max(1, line_total)
    return min(span[0], last), min(span[1], last)


class FileLines:
    """The newest-first ``-U0`` history of one file whose working tree equals the snapshot blob."""

    def __init__(self, history: Sequence[Mapping[str, Any]], line_total: int):
        self.history = list(history)
        self.position = {str(item["commit"]): index for index, item in enumerate(self.history)}
        self.line_total = line_total

    def hunks(self, change_id: str) -> Sequence[Hunk] | None:
        index = self.position.get(change_id)
        if index is None or self.history[index]["binary"]:
            return None
        return self.history[index]["hunks"]

    def chain(self, after: str, before: str | None = None) -> list[Sequence[Hunk]] | None:
        """Hunks of the commits strictly after ``after`` (and before ``before``), oldest first."""
        start = self.position.get(after)
        end = -1 if before is None else self.position.get(before)
        if start is None or end is None or end >= start:
            return None
        chain = [self.history[index] for index in range(start - 1, end, -1)]
        if any(item["binary"] for item in chain):
            return None
        return [item["hunks"] for item in chain]

    def snapshot_regions(self, change_id: str) -> list[tuple[Span, Hunk]] | None:
        """Each hunk of ``change_id`` with its post-image region carried to the snapshot."""
        hunks, chain = self.hunks(change_id), self.chain(change_id)
        if hunks is None or chain is None:
            return None
        return [(_clamp(map_forward(region, chain), self.line_total), hunk)
                for region, hunk in zip(new_regions(hunks), hunks)]


def _symbols_at(span: Span, symbols: Sequence[Mapping[str, Any]]) -> list[str]:
    return [str(symbol["symbol_id"]) for symbol in symbols
            if any(overlaps(span, (int(low), int(high))) for low, high in symbol["own_lines"])]


def attribute(changes: Sequence[Mapping[str, Any]], lines: FileLines,
              symbols: Sequence[Mapping[str, Any]]) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """Attribute each change's hunks to the innermost snapshot symbols their regions reach.

    Returns ``{symbol_id: [{change_id, added, deleted}]}`` and the changes that could not be mapped.
    A hunk that reaches several symbols counts its full size toward each of them.
    """
    touched: dict[str, dict[str, dict[str, Any]]] = {}
    unmapped: list[str] = []
    for change in changes:
        change_id = str(change["change_id"])
        regions = lines.snapshot_regions(change_id)
        if regions is None:
            unmapped.append(change_id)
            continue
        for region, hunk in regions:
            for symbol_id in _symbols_at(region, symbols):
                record = touched.setdefault(symbol_id, {}).setdefault(
                    change_id, {"change_id": change_id, "added": 0, "deleted": 0})
                record["added"] += int(hunk[3])
                record["deleted"] += int(hunk[1])
    return ({symbol_id: list(records.values()) for symbol_id, records in sorted(touched.items())},
            sorted(unmapped))


def fix_on_fix(changes: Sequence[Mapping[str, Any]], *, lines: FileLines | None, lines_reason: str | None,
               symbols: Sequence[Mapping[str, Any]] | None, symbols_reason: str | None,
               interval_days: int) -> dict[str, Any]:
    """Match later fixes that rework an earlier fix's lines or function within ``interval_days``.

    ``changes`` are in-window ranking changes for one file, newest first, each with ``change_id``,
    ``effective_time``, and ``fix``.  A pair is a match on ``line_overlap`` when the earlier fix's
    post-image regions, carried through the intervening commits, intersect the later fix's
    pre-image regions.  Otherwise it is a match on ``same_function`` when both fixes reach the same
    innermost snapshot symbol.  A pair whose line history or symbol spans are missing is
    ``undetermined`` with a reason, never a non-match.
    """
    fixes = [change for change in reversed(changes) if change.get("fix")]
    events: list[dict[str, Any]] = []
    undetermined: list[dict[str, Any]] = []
    pair_count = 0
    for index, earlier in enumerate(fixes):
        for later in fixes[index + 1:]:
            interval = int(later["effective_time"]) - int(earlier["effective_time"])
            if interval > interval_days * DAY:
                break
            pair_count += 1
            pair = {"earlier_change": earlier["change_id"], "later_change": later["change_id"],
                    "interval_days": round(interval / DAY, 6)}
            if lines is None:
                undetermined.append({**pair, "reason": lines_reason or "line_history_unavailable"})
                continue
            earlier_hunks, later_hunks = lines.hunks(earlier["change_id"]), lines.hunks(later["change_id"])
            between = lines.chain(earlier["change_id"], later["change_id"])
            if earlier_hunks is None or later_hunks is None or between is None:
                undetermined.append({**pair, "reason": "line_history_incomplete"})
                continue
            carried = [map_forward(region, between) for region in new_regions(earlier_hunks)]
            matched = [(region, target) for region in carried for target in old_regions(later_hunks)
                       if overlaps(region, target)]
            later_regions = lines.snapshot_regions(later["change_id"])
            common: list[str] = []
            if symbols is not None:
                earlier_regions = lines.snapshot_regions(earlier["change_id"])
                if earlier_regions is not None and later_regions is not None:
                    common = sorted(set(sym for region, _ in earlier_regions for sym in _symbols_at(region, symbols)) &
                                    set(sym for region, _ in later_regions for sym in _symbols_at(region, symbols)))
            location = None
            if later_regions:
                spans = [region for region, _ in later_regions]
                location = {"start_line": min(span[0] for span in spans), "end_line": max(span[1] for span in spans)}
            if matched:
                region, target = matched[0]
                events.append({**pair, "basis": "line_overlap", "symbols": common,
                               "earlier_region_at_later_parent": list(region), "later_region": list(target),
                               "snapshot_location": location})
            elif common:
                events.append({**pair, "basis": "same_function", "symbols": common, "snapshot_location": location})
            elif symbols is None:
                undetermined.append({**pair, "reason": symbols_reason or "symbol_spans_unavailable"})
    if pair_count and len(undetermined) == pair_count and not events:
        status = "unavailable"
    elif undetermined:
        status = "partial"
    else:
        status = "complete"
    # Undetermined pairs with no confirmed event leave the count unknown, never zero.
    return {"rules": FIX_ON_FIX_IDENTITY, "status": status, "candidate_pair_count": pair_count,
            "count": None if undetermined and not events else len(events), "events": events,
            "undetermined": undetermined}
