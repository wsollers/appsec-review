"""Target-relative POSIX glob patterns shared by every path classifier.

One matcher serves the source-history ranking filters
(``[jobs.job_source_history_analysis.settings.filters]``) and the review source dispositions
(``[jobs.job_inference_security_review.settings.source_dispositions]``), so both tables read the
same way:

- ``**/`` spans any number of directories (``**/third_party/**`` matches at any depth);
- ``*`` and ``?`` stay inside one path segment;
- a pattern without ``/`` matches the file name at any depth (``*.min.js``, ``test_*``).

Patterns are target-relative: no leading ``/``, no empty, ``.`` or ``..`` segments, at most 256
patterns of at most 256 characters each.
"""
from __future__ import annotations

from functools import lru_cache
import re
from typing import Any

GLOB_PATTERN = re.compile(r"[A-Za-z0-9_.*?/@+-]{1,256}")
MAX_PATTERNS = 256


@lru_cache(maxsize=4096)
def compile_glob(pattern: str) -> re.Pattern[str]:
    """Translate a POSIX glob into a full-match regular expression (see the module docstring)."""
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
    return compile_glob(pattern).fullmatch(path) is not None


def validate_glob_patterns(value: Any, field: str) -> tuple[str, ...]:
    """Validate one list of target-relative POSIX globs; ``field`` names the setting in the error."""
    if not isinstance(value, list) or len(value) > MAX_PATTERNS or not all(
            isinstance(item, str) and GLOB_PATTERN.fullmatch(item) and
            all(part not in {"", ".", ".."} for part in item.split("/")) for item in value):
        raise ValueError(f"{field} must be a list of at most {MAX_PATTERNS} target-relative POSIX glob patterns")
    if len(set(value)) != len(value):
        raise ValueError(f"{field} repeats a pattern")
    return tuple(value)


__all__ = ["GLOB_PATTERN", "MAX_PATTERNS", "compile_glob", "matches", "validate_glob_patterns"]
