"""Classify differences between an accepted normalized job output and a candidate."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import json
import re
from typing import Any

from .normalize import canonical

CLASSES = ("job-status", "gap-added", "gap-removed", "finding-added", "finding-removed", "coverage",
           "content", "integrity", "environment", "volatile")
# Classes that never fail a comparison: raw volatile values, and identifiers, hashes and paths that
# are populated on both sides but spelled for each side's own run and environment.
NON_FAILING = frozenset({"volatile", "environment"})


@dataclass(frozen=True, order=True)
class Difference:
    job_id: str
    kind: str
    path: str
    expected: str = ""
    actual: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"job_id": self.job_id, "class": self.kind, "path": self.path,
                "expected": self.expected, "actual": self.actual}


def _flatten(value: Any, prefix: str = "") -> dict[str, str]:
    if isinstance(value, Mapping) and value and "<summary>" not in value:
        flat: dict[str, str] = {}
        for key, child in value.items():
            flat.update(_flatten(child, f"{prefix}.{key}" if prefix else str(key)))
        return flat
    if isinstance(value, list) and value:
        flat = {}
        for index, child in enumerate(value):
            flat.update(_flatten(child, f"{prefix}[{index}]"))
        return flat
    return {prefix: canonical(value)}


def _compare_flat(job_id: str, kind: str, root: str, expected: Any, actual: Any) -> list[Difference]:
    left, right = _flatten(expected, root), _flatten(actual, root)
    return [Difference(job_id, kind, key, left.get(key, "<absent>"), right.get(key, "<absent>"))
            for key in sorted(set(left) | set(right)) if left.get(key) != right.get(key)]


def _counted(items: Iterable[Mapping[str, Any]], fields: tuple[str, ...]) -> Counter:
    counts: Counter = Counter()
    for item in items:
        counts[canonical({field: item.get(field) for field in fields})] += int(item.get("count", 1))
    return counts


def _multiset(job_id: str, added: str, removed: str, expected: Counter, actual: Counter) -> list[Difference]:
    differences = []
    for key in sorted(set(expected) | set(actual)):
        delta = actual.get(key, 0) - expected.get(key, 0)
        if delta > 0:
            differences.append(Difference(job_id, added, key, str(expected.get(key, 0)), str(actual.get(key, 0))))
        elif delta < 0:
            differences.append(Difference(job_id, removed, key, str(expected.get(key, 0)), str(actual.get(key, 0))))
    return differences


def _artifacts(document: Mapping[str, Any]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for item in document.get("artifacts", ()):
        grouped.setdefault(str(item.get("path")), []).append(
            canonical({key: value for key, value in item.items() if key != "path"}))
    return {path: sorted(values) for path, values in grouped.items()}


def diff_job_outputs(expected: Mapping[str, Any] | None, actual: Mapping[str, Any] | None,
                     job_id: str | None = None) -> list[Difference]:
    """Every difference between two normalized outputs of one job, classified."""

    job_id = job_id or str((expected or actual or {}).get("job_id", "?"))
    if expected is None or actual is None:
        return [Difference(job_id, "job-status", "output",
                           "<absent>" if expected is None else str(expected.get("status")),
                           "<absent>" if actual is None else str(actual.get("status")))]
    differences: list[Difference] = []
    differences += _compare_flat(job_id, "job-status", "status", expected.get("status"), actual.get("status"))
    differences += _compare_flat(job_id, "job-status", "handoff", expected.get("handoff"), actual.get("handoff"))
    differences += _compare_flat(job_id, "job-status", "steps", expected.get("steps"), actual.get("steps"))
    differences += _multiset(job_id, "gap-added", "gap-removed",
                             _counted(expected.get("gaps", ()), ("unit", "gap")),
                             _counted(actual.get("gaps", ()), ("unit", "gap")))
    differences += _multiset(job_id, "finding-added", "finding-removed",
                             _counted(expected.get("findings", ()), ("unit", "source", "record")),
                             _counted(actual.get("findings", ()), ("unit", "source", "record")))
    for section in ("units", "failed_units", "skipped_units", "outputs"):
        differences += _compare_flat(job_id, "coverage", section, expected.get(section), actual.get(section))
    left, right = _artifacts(expected), _artifacts(actual)
    for path in sorted(set(left) | set(right)):
        if left.get(path) != right.get(path):
            differences.append(Difference(job_id, "coverage", f"artifacts[{path}]",
                                          canonical(left.get(path, "<absent>")),
                                          canonical(right.get(path, "<absent>"))))
    differences += _compare_flat(job_id, "volatile", "volatile", expected.get("volatile"), actual.get("volatile"))
    return differences


def failing(differences: Iterable[Difference]) -> list[Difference]:
    """Differences that fail a comparison: everything except volatile and environment ones."""

    return [item for item in differences if item.kind not in NON_FAILING]


_HEX = re.compile(r"(?:sha256:)?[0-9a-f]{32,}")
_IDENTIFIERS = re.compile(r"<(?:run-id|uuid|attempt|sha256|image-digest|dagster_run_id|dagster_node|"
                          r"container_id|container_name|digest|image_id)>")


def _value_kind(encoded: str) -> str | None:
    """``path``, ``hash`` or ``identifier`` for a populated environment-specific value, else None."""
    try:
        value = json.loads(encoded)
    except ValueError:
        return None
    if not isinstance(value, str) or not value.strip():
        return None
    if _HEX.fullmatch(value) or value == "<sha256>":
        return "hash"
    if _IDENTIFIERS.fullmatch(value):
        return "identifier"
    if "/" in value or value.startswith("<") and value.endswith(">"):
        return "path"
    return None


def _signatures_without_hashes(encoded: str) -> Any:
    try:
        return sorted(canonical({key: value for key, value in json.loads(item).items() if key != "sha256"})
                      for item in json.loads(encoded))
    except (ValueError, TypeError, AttributeError):
        return None


def classify_environment(differences: Iterable[Difference]) -> list[Difference]:
    """Reclass coverage and content differences that are only environment spellings.

    Both sides must hold a populated value of the same kind (a path, a hash, or an identifier such
    as a run, attempt or Dagster id); a missing, empty or differently shaped value still fails.
    An artifact signature may differ only in its digest, which the content comparison covers.
    """
    result = []
    for item in differences:
        if item.kind in {"coverage", "content"}:
            if item.path.startswith("artifacts["):
                stripped = _signatures_without_hashes(item.expected)
                if stripped is not None and stripped == _signatures_without_hashes(item.actual):
                    item = Difference(item.job_id, "environment", item.path, item.expected, item.actual)
            else:
                kind = _value_kind(item.expected)
                if kind is not None and kind == _value_kind(item.actual):
                    item = Difference(item.job_id, "environment", item.path, item.expected, item.actual)
        result.append(item)
    return result
