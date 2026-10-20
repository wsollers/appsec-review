"""Compare the content of two attempts' artifacts, each masked with its own environment's roots.

A normalized job output reduces artifacts to signatures: a JSON digest, or a SQLite file's row
counts and entity kinds. Two drivers of one job (docs/processes/local-dagster-parity.md) must
produce the same content, each spelling paths for its own environment, so every artifact is opened
and compared here with the two sides masked separately: SQLite table by table and row by row, JSON
field by field, and other text line by line. Raw bytes legitimately differ when a file embeds its
environment's paths or when SQLite lays pages out differently; content must not.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import json
from pathlib import Path
import sqlite3
from typing import Any

from .diff import Difference
from .normalize import Masks, canonical, normalize_value

ROW_EXAMPLES = 5
FIELD_EXAMPLES = 20


def _pairs(left: Iterable[Mapping[str, Any]], left_masks: Masks, right: Iterable[Mapping[str, Any]],
           right_masks: Masks) -> tuple[list[tuple[str, Mapping, Mapping]], list[tuple[str, str]]]:
    """Artifacts paired by masked path, and the masked paths present on one side only."""
    grouped: dict[str, tuple[list, list]] = {}
    for side, artifacts, masks in ((0, left, left_masks), (1, right, right_masks)):
        for artifact in artifacts:
            grouped.setdefault(masks.text(str(artifact.get("path", ""))), ([], []))[side].append(artifact)
    pairs, unmatched = [], []
    for masked, (lefts, rights) in sorted(grouped.items()):
        lefts, rights = sorted(lefts, key=canonical), sorted(rights, key=canonical)
        pairs += [(masked, a, b) for a, b in zip(lefts, rights)]
        unmatched += [(masked, "left")] * max(0, len(lefts) - len(rights))
        unmatched += [(masked, "right")] * max(0, len(rights) - len(lefts))
    return pairs, unmatched


def _sqlite_rows(path: Path, masks: Masks) -> dict[str, list[str]]:
    database = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    try:
        tables = [row[0] for row in database.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        # FTS shadow tables are derived from the content tables; comparing those is enough.
        return {table: sorted(canonical(normalize_value(list(row), masks))
                              for row in database.execute(f'SELECT * FROM "{table}"'))
                for table in tables if not table.startswith(("sqlite_", "search_fts"))}
    finally:
        database.close()


def _fields(left: Any, right: Any, prefix: str = "") -> list[tuple[str, str, str]]:
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return [item for key in sorted(set(left) | set(right))
                for item in _fields(left.get(key), right.get(key), f"{prefix}.{key}")]
    if isinstance(left, list) and isinstance(right, list) and len(left) == len(right):
        return [item for index, (a, b) in enumerate(zip(left, right))
                for item in _fields(a, b, f"{prefix}[{index}]")]
    return [] if left == right else [(prefix or ".", canonical(left), canonical(right))]


def _compare(job_id: str, masked: str, left: Path, left_masks: Masks, right: Path,
             right_masks: Masks) -> list[Difference]:
    if left.suffix == ".sqlite":
        try:
            a, b = _sqlite_rows(left, left_masks), _sqlite_rows(right, right_masks)
        except sqlite3.Error as exc:
            return [Difference(job_id, "content", f"{masked}", "<readable sqlite>", type(exc).__name__)]
        differences = []
        for table in sorted(set(a) | set(b)):
            only_left = sorted(set(a.get(table, ())) - set(b.get(table, ())))
            only_right = sorted(set(b.get(table, ())) - set(a.get(table, ())))
            if table not in a or table not in b:
                differences.append(Difference(job_id, "content", f"{masked}#{table}",
                                              "<table>" if table in a else "<absent>",
                                              "<table>" if table in b else "<absent>"))
            for row in only_left[:ROW_EXAMPLES]:
                differences.append(Difference(job_id, "content", f"{masked}#{table}", row, "<absent>"))
            for row in only_right[:ROW_EXAMPLES]:
                differences.append(Difference(job_id, "content", f"{masked}#{table}", "<absent>", row))
            hidden = max(0, len(only_left) - ROW_EXAMPLES) + max(0, len(only_right) - ROW_EXAMPLES)
            if hidden:
                differences.append(Difference(job_id, "content", f"{masked}#{table}", "",
                                              f"... {hidden} more differing rows"))
        return differences
    raw_left, raw_right = left.read_bytes(), right.read_bytes()
    try:
        text_left, text_right = raw_left.decode("utf-8"), raw_right.decode("utf-8")
    except UnicodeDecodeError:
        if raw_left == raw_right:
            return []
        return [Difference(job_id, "content", masked, "<bytes>", "<different bytes>")]
    if left.suffix == ".json":
        try:
            fields = _fields(normalize_value(json.loads(text_left), left_masks),
                             normalize_value(json.loads(text_right), right_masks))
        except json.JSONDecodeError:
            fields = None
        if fields is not None:
            differences = [Difference(job_id, "content", f"{masked}{path}", a, b)
                           for path, a, b in fields[:FIELD_EXAMPLES]]
            if len(fields) > FIELD_EXAMPLES:
                differences.append(Difference(job_id, "content", masked, "",
                                              f"... {len(fields) - FIELD_EXAMPLES} more differing fields"))
            return differences
    lines_left = left_masks.text(text_left).splitlines()
    lines_right = right_masks.text(text_right).splitlines()
    if lines_left == lines_right:
        return []
    index = next((i for i, (a, b) in enumerate(zip(lines_left, lines_right)) if a != b),
                 min(len(lines_left), len(lines_right)))
    return [Difference(job_id, "content", f"{masked}:{index + 1}",
                       lines_left[index] if index < len(lines_left) else "<end>",
                       lines_right[index] if index < len(lines_right) else "<end>")]


def content_differences(job_id: str, left_run: Path, left_handoff: Mapping[str, Any] | None, left_masks: Masks,
                        right_run: Path, right_handoff: Mapping[str, Any] | None,
                        right_masks: Masks) -> list[Difference]:
    """Content differences between the artifacts two attempts of ``job_id`` published.

    The attempt's own ``result.json`` is skipped: its unit outputs are already compared by the
    normalized output, and the rest of it is per-driver bookkeeping.
    """
    if left_handoff is None or right_handoff is None:
        return []

    def published(handoff: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        result = dict(handoff.get("resolving_paths") or {}).get("result")
        return [item for item in handoff.get("artifacts", ()) if item.get("path") != result]

    pairs, unmatched = _pairs(published(left_handoff), left_masks, published(right_handoff), right_masks)
    differences = [Difference(job_id, "content", masked, "<artifact>" if side == "left" else "<absent>",
                              "<artifact>" if side == "right" else "<absent>") for masked, side in unmatched]
    # Identical bytes are compared too: a path written in one environment's spelling by both sides
    # is correct for at most one of them, and only per-side masking shows which.
    for masked, left, right in pairs:
        left_path, right_path = Path(left_run) / str(left["path"]), Path(right_run) / str(right["path"])
        if not left_path.is_file() or not right_path.is_file():
            differences.append(Difference(job_id, "content", masked, str(left_path.is_file()),
                                          str(right_path.is_file())))
            continue
        differences += _compare(job_id, masked, left_path, left_masks, right_path, right_masks)
    return differences
