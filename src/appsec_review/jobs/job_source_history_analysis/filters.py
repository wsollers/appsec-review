"""Explicit, versioned rules that keep non-reviewable paths and formatting churn out of ranking.

Exclusion only removes a file or change from the hotspot ranking.  Its metrics, the matching
category, and the matching pattern are still published so the exclusion stays auditable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import re
from typing import Any

from appsec_review.path_globs import compile_glob, matches

from .settings import FilterRules


FILTER_IDENTITY = "appsec-review/history-path-filters/2"
FORMATTING_IDENTITY = "appsec-review/history-formatting-rules/1"
_FORMATTING_PREFIX = re.compile(r"^(style|format|fmt|lint)(\([^)]{0,64}\))?!?:", re.I)
_FORMATTING_WORDS = re.compile(
    r"\b(re-?format(?:ted|ting|s)?|format(?:ted|ting)? (?:code|sources?|files?|all)|apply (?:black|prettier|"
    r"clang-format|gofmt|rustfmt|ruff format|isort|eslint --fix)|(?:black|prettier|clang-format|gofmt|rustfmt|"
    r"isort) (?:run|pass|reformat)|whitespace(?: only)?(?: changes?| cleanup)?|trailing whitespace|"
    r"line endings?|indentation)\b", re.I)


# The glob semantics are shared with the review source dispositions (path_globs.py).
_compiled = compile_glob


_NON_DOCUMENTATION_TXT = re.compile(
    r"^(?:cmakelists\.txt|meson_options\.txt|(?:requirements|constraints)(?:[-_.][\w.-]+)?\.txt)$",
    re.I,
)
_TOOLING_CONFIG_PATTERNS = (
    ".editorconfig", "**/.editorconfig",
    ".gitignore", "**/.gitignore",
    ".gitattributes", "**/.gitattributes",
    ".gitmodules", "**/.gitmodules",
    ".mailmap",
    ".clang-format", "**/.clang-format",
    ".clang-tidy", "**/.clang-tidy",
    ".prettierrc", "**/.prettierrc",
    ".prettierignore", "**/.prettierignore",
    ".eslintignore", "**/.eslintignore",
    ".dockerignore", "**/.dockerignore",
)


_SECURITY_RELEVANT_BASENAME_RE = re.compile(
    r"^(?:dockerfile(?:\.[\w.-]+)?|containerfile(?:\.[\w.-]+)?|"
    r"cmakelists\.txt|gnumakefile|makefile(?:\.[\w.-]+)?|"
    r"meson\.build|meson_options\.txt|configure\.(?:ac|in)|makefile\.am)$",
    re.I,
)
_SECURITY_RELEVANT_EXTS = frozenset({
    ".s", ".asm", ".nasm", ".ipp", ".inl", ".tpp", ".txx", ".inc", ".m", ".mm", ".cmake", ".mk",
})


def _is_build_or_manifest_txt(path: str) -> bool:
    basename = path.rsplit("/", 1)[-1]
    return bool(_NON_DOCUMENTATION_TXT.fullmatch(basename))


def is_security_relevant_build_or_code_path(path: str) -> bool:
    basename = path.rsplit("/", 1)[-1]
    if _SECURITY_RELEVANT_BASENAME_RE.fullmatch(basename):
        return True
    dot = basename.rfind(".")
    return dot > 0 and basename[dot:].lower() in _SECURITY_RELEVANT_EXTS


def path_exclusion(path: str, rules: FilterRules) -> dict[str, str] | None:
    """Return the first matching exclusion category and pattern, in fixed category order."""
    for category, patterns in rules.category_patterns():
        for pattern in patterns:
            if category == "documentation" and _is_build_or_manifest_txt(path):
                continue
            if matches(path, pattern):
                return {"category": category, "pattern": pattern, "rules": FILTER_IDENTITY}
    for pattern in _TOOLING_CONFIG_PATTERNS:
        if matches(path, pattern):
            return {"category": "tooling", "pattern": pattern, "rules": FILTER_IDENTITY}
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
