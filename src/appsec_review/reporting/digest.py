"""Bounded, readable digests of run values: the building blocks the loader assembles boxes from."""
from __future__ import annotations

from collections import Counter
import re
from typing import Any, Iterable, Mapping, Sequence

from .model import Bullets, Cell, Code, Field, Fields, IdList, Item, Para, Table, Truncation
from .text import bound, bound_lines, canonical, clean, sha256_value
from .tokens import Limits

STATE_WORDS = frozenset({
    "confirmed", "supported", "contradicted", "not_reachable", "insufficient_evidence", "unresolved",
    "proposed", "not_exploitable_in_observed_configuration", "duplicate", "out_of_scope", "coverage_gap"})
_STATE_KEYS = ("stance", "verdict", "state", "disposition", "conclusion", "outcome", "status")
_ID_CELL = re.compile(r"(?:asr:[a-z][a-z0-9_]*:[0-9a-f]{64}|(?:cell|claim|gap|finding_lead|hunt)-[0-9a-f]{32,64})")


def scalar(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        if all(not isinstance(item, (dict, list, tuple)) for item in value):
            return ", ".join(scalar(item) for item in value) if value else "none"
    return canonical(value)


def val(value: Any, limit: int) -> tuple[str, Truncation | None]:
    return bound(scalar(value), limit)


def abbrev(identity: Any, keep: int = 12) -> str:
    """``asr:kind:<hex>`` shortened for tables; full identities appear in id lists and fields."""
    text = clean(identity)
    parts = text.split(":")
    if len(parts) == 3 and len(parts[2]) > keep + 4:
        return f"{parts[0]}:{parts[1]}:{parts[2][:keep]}..."
    if "-" in text and len(text) > 40:
        head, _, tail = text.rpartition("-")
        if len(tail) > keep + 4 and all(char in "0123456789abcdef" for char in tail):
            return f"{head}-{tail[:keep]}..."
    return text[: keep * 4] + ("..." if len(text) > keep * 4 else "")


def field(label: str, value: Any, limits: Limits, *, mono: bool = False, limit: int | None = None) -> Field:
    text, cut = val(value, limit or limits.value_chars)
    return Field(label, text, mono=mono, truncation=cut)


def state_field(label: str, state: Any) -> Field:
    text = clean(state)
    return Field(label, text, badge=text if text in STATE_WORDS else None)


def table(headers: Sequence[str], rows: Sequence[Sequence[Any]], limits: Limits, *,
          widths: Sequence[float] | None = None, mono: Sequence[bool] | None = None,
          badges: Sequence[bool] | None = None, max_rows: int | None = None) -> Table:
    """A table of at most ``max_rows`` rows; the rest are counted and hashed, never silently dropped."""
    max_rows = max_rows or limits.rows
    count = len(headers)
    mono = tuple(mono) if mono else (False,) * count
    badges = tuple(badges) if badges else (False,) * count
    widths = tuple(widths) if widths else tuple(round(0.96 / count, 3) for _ in range(count))
    shown = rows[:max_rows]
    out: list[tuple[Cell, ...]] = []
    for row in shown:
        cells: list[Cell] = []
        for index in range(count):
            raw = row[index] if index < len(row) else ""
            text, _cut = val(raw, limits.value_chars)
            if _ID_CELL.fullmatch(text):
                text = abbrev(text)
            token = clean(raw)
            cells.append(Cell(text, mono=mono[index],
                              badge=token if badges[index] and token in STATE_WORDS else None))
        out.append(tuple(cells))
    omitted = None
    if len(rows) > len(shown):
        rest = rows[len(shown):]
        omitted = Truncation(omitted=len(rest), unit="rows", sha256=sha256_value([list(map(scalar, row)) for row in rest]))
    return Table(tuple(headers), tuple(out), widths, omitted)


def id_list(label: str, ids: Sequence[Any], limits: Limits, *, shown: int | None = None) -> IdList:
    shown = shown if shown is not None else limits.ids
    clean_ids = [clean(item) for item in ids]
    head = tuple(bound(item, 96)[0] for item in clean_ids[:shown])
    omitted = None
    if len(clean_ids) > shown:
        rest = clean_ids[shown:]
        omitted = Truncation(omitted=len(rest), unit="more", sha256=sha256_value(rest))
    return IdList(label, head, omitted)


def counts_text(counter: Mapping[str, int], limit: int = 8) -> str:
    items = sorted(counter.items(), key=lambda pair: (-pair[1], pair[0]))
    text = ", ".join(f"{name} {count}" for name, count in items[:limit])
    return text + (f", +{len(items) - limit} more" if len(items) > limit else "") if items else "none"


def code(value: Any, limits: Limits, caption: str = "") -> Code:
    text, cut = bound_lines(value, limits.code_lines, limits.code_chars)
    return Code(text, cut, caption)


def bullets(values: Iterable[Any], limits: Limits, *, shown: int | None = None, chars: int = 420) -> Bullets:
    items = list(values)
    shown = shown if shown is not None else limits.rows
    head = tuple(bound(scalar(item), chars)[0] for item in items[:shown])
    omitted = None
    if len(items) > shown:
        rest = [scalar(item) for item in items[shown:]]
        omitted = Truncation(omitted=len(rest), unit="more", sha256=sha256_value(rest))
    return Bullets(head, omitted)


def digest_mapping(value: Mapping[str, Any], limits: Limits, *, skip: Sequence[str] = ("schema",),
                   depth: int = 0) -> list[Item]:
    """A generic readable view of a model answer or other mapping, with every part bounded.

    Scalars become fields, lists of strings become bullets, lists of mappings become a table over
    their commonest scalar keys, and nested mappings are flattened one level before falling back to
    bounded canonical JSON. The shape of a model's free-form answer is never trusted.
    """
    items: list[Item] = []
    rows: list[Field] = []

    def flush() -> None:
        if rows:
            items.append(Fields(tuple(rows)))
            rows.clear()

    ordered = sorted(value.items(), key=lambda pair: (pair[0] not in _STATE_KEYS,))
    for key, raw in ordered:
        label = bound(key, 48)[0]
        if key in skip:
            continue
        if isinstance(raw, Mapping):
            flush()
            if depth < 1 and raw:
                items.append(Para(f"{label}", muted=True))
                items.extend(digest_mapping(raw, limits, skip=(), depth=depth + 1))
            else:
                items.append(code(canonical(raw), limits, caption=label))
        elif isinstance(raw, (list, tuple)):
            flush()
            if not raw:
                rows.append(Field(label, "none"))
            elif all(isinstance(entry, str) for entry in raw):
                items.append(Para(f"{label} ({len(raw)})", muted=True))
                items.append(bullets(raw, limits))
            elif all(isinstance(entry, Mapping) for entry in raw):
                items.append(Para(f"{label} ({len(raw)})", muted=True))
                items.append(_mapping_table(raw, limits))
            else:
                rows.append(field(label, raw, limits))
        elif isinstance(raw, str) and len(raw) > limits.value_chars:
            flush()
            text, cut = bound(raw, limits.text_chars)
            items.append(Para(f"{label}", muted=True))
            items.append(Para(text, cut))
        else:
            text = clean(raw) if isinstance(raw, str) else scalar(raw)
            if label in _STATE_KEYS and text in STATE_WORDS:
                rows.append(state_field(label, text))
            else:
                rows.append(field(label, raw, limits))
    flush()
    return items


def _mapping_table(entries: Sequence[Mapping[str, Any]], limits: Limits) -> Table:
    keys: Counter[str] = Counter()
    for entry in entries[: limits.rows * 2]:
        for key, raw in entry.items():
            if not isinstance(raw, (Mapping, list, tuple)) or (isinstance(raw, (list, tuple)) and all(
                    not isinstance(item, (Mapping, list, tuple)) for item in raw)):
                keys[key] += 1
    chosen = [key for key, _ in sorted(keys.items(), key=lambda pair: (-pair[1], pair[0]))][:4]
    if not chosen:
        chosen = ["value"]
        rows = [[canonical(entry)] for entry in entries]
    else:
        rows = [[entry.get(key, "") for key in chosen] for entry in entries]
    return table([bound(key, 24)[0] for key in chosen], rows, limits,
                 badges=[key in _STATE_KEYS for key in chosen])
