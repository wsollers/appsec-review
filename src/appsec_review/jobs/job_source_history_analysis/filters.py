"""Explicit, versioned rules that keep non-reviewable paths and formatting churn out of ranking.

Exclusion only removes a file or change from the hotspot ranking.  Its metrics, the matching
category, and the matching pattern are still published so the exclusion stays auditable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from functools import lru_cache
import re
from typing import Any

from .settings import FilterRules


FILTER_IDENTITY = "appsec-review/history-path-filters/1"
FORMATTING_IDENTITY = "appsec-review/history-formatting-rules/1"
_FORMATTING_PREFIX = re.compile(r"^(style|format|fmt|lint)(\([^)]{0,64}\))?!?:", re.I)
_FORMATTING_WORDS = re.compile(
    r"\b(re-?format(?:ted|ting|s)?|format(?:ted|ting)? (?:code|sources?|files?|all)|apply (?:black|prettier|"
    r"clang-format|gofmt|rustfmt|ruff format|isort|eslint --fix)|(?:black|prettier|clang-format|gofmt|rustfmt|"
    r"isort) (?:run|pass|reformat)|whitespace(?: only)?(?: changes?| cleanup)?|trailing whitespace|"
    r"line endings?|indentation)\b", re.I)


@lru_cache(maxsize=4096)
def _compiled(pattern: str) -> re.Pattern[str]:
    """Translate a POSIX glob: ``**/`` spans directories, ``*`` and ``?`` stay inside one segment.

    A pattern without ``/`` matches the file name at any depth, like ``.gitignore``.
    """
    if "/" not in pattern:
        pattern = "**/" + pattern
    output, index = [], 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            output.append("(?:[^/]+/)*")
            index += 3
        elif pattern.startswith("**", index):
            output.append(".*")
            index += 2
        elif pattern[index] == "*":
            output.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            output.append("[^/]")
            index += 1
        else:
            output.append(re.escape(pattern[index]))
            index += 1
    return re.compile("".join(output))


def matches(path: str, pattern: str) -> bool:
    return _compiled(pattern).fullmatch(path) is not None


def path_exclusion(path: str, rules: FilterRules) -> dict[str, str] | None:
    """Return the first matching exclusion category and pattern, in fixed category order."""
    for category, patterns in rules.category_patterns():
        for pattern in patterns:
            if matches(path, pattern):
                return {"category": category, "pattern": pattern, "rules": FILTER_IDENTITY}
    return None


def is_test_path(path: str, rules: FilterRules) -> bool:
    return any(matches(path, pattern) for pattern in rules.test)


def formatting_change(subject: str, files: Iterable[Mapping[str, Any]], tolerance: float) -> bool:
    """A formatting change names formatting in its subject *and* has balanced additions and deletions.

    The balance test rejects a subject that merely mentions formatting while adding behaviour.
    Binary-only and empty changes are never formatting changes.
    """
    if not (_FORMATTING_PREFIX.search(subject) or _FORMATTING_WORDS.search(subject)):
        return False
    added = sum(int(entry["added"]) for entry in files)
    deleted = sum(int(entry["deleted"]) for entry in files)
    if not added and not deleted:
        return False
    return abs(added - deleted) <= tolerance * max(added, deleted)
