"""Configured path exclusions: target files and folders a review deliberately leaves out of analysis.

A global ``[exclusions]`` table applies to every job that selects target files; a job's own
``[jobs.<id>.exclusions]`` table adds patterns for that job alone. Both hold one key::

    [exclusions]
    patterns = [".gitignore", "docs/", "third_party/vendored/**"]

Pattern semantics, matched against the target-relative POSIX path:

- without ``/``: a glob over any single path component, so ``.gitignore`` or ``*.md`` match that
  file anywhere and ``fixtures`` matches every folder of that name;
- ending in ``/``: a folder; without another ``/`` it matches the folder anywhere, otherwise it is
  anchored at the target root (``docs/api/``). Everything beneath it is excluded;
- containing ``/`` elsewhere: anchored at the target root and globbed against the whole path, and
  also excludes everything beneath a matching folder.

Exclusions narrow what is analysed, never what the target is: the target's source fingerprint
still covers every byte. Each excluded path is recorded once with the pattern and scope that
excluded it, so a configured exclusion is visible without being reported as a coverage gap.

Only jobs that select target files honour a job-level table; naming one on any other job fails at
load rather than being silently ignored.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
from typing import Any

GLOBAL_SCOPE = "global"
# Jobs that select target files themselves and apply their own job-level patterns. Every job that
# reads the accepted catalog inherits the global (and catalog-level) exclusions through it.
JOB_LEVEL_SUPPORT: frozenset[str] = frozenset({
    "job_review_intake", "job_target_catalog", "job_source_history_analysis",
})


@dataclass(frozen=True, slots=True)
class ExclusionRule:
    pattern: str
    scope: str

    def matches(self, path: str) -> bool:
        parts = PurePosixPath(path).parts
        directory = self.pattern.endswith("/")
        body = self.pattern.rstrip("/")
        if "/" not in body:
            # Any component; a folder pattern only matches components that have something below.
            components = parts[:-1] if directory else parts
            return any(fnmatchcase(part, body) for part in components)
        prefixes = ["/".join(parts[:index]) for index in range(1, len(parts) + (0 if directory else 1))]
        return any(fnmatchcase(prefix, body) for prefix in prefixes)

    def matches_directory(self, path: str) -> bool:
        """Whether every path beneath the folder ``path`` is excluded, so a walk may prune it."""
        parts = PurePosixPath(path).parts
        body = self.pattern.rstrip("/")
        if "/" not in body:
            return any(fnmatchcase(part, body) for part in parts)
        return any(fnmatchcase("/".join(parts[:index]), body) for index in range(1, len(parts) + 1))

    def as_dict(self) -> dict[str, str]:
        return {"pattern": self.pattern, "scope": self.scope}


@dataclass(frozen=True, slots=True)
class PathExclusions:
    """The ordered exclusion rules one job applies: global first, then the job's own."""

    rules: tuple[ExclusionRule, ...] = ()

    def match(self, path: str) -> ExclusionRule | None:
        return next((rule for rule in self.rules if rule.matches(path)), None)

    def match_directory(self, path: str) -> ExclusionRule | None:
        return next((rule for rule in self.rules if rule.matches_directory(path)), None)

    def scoped(self, scope: str) -> "PathExclusions":
        return PathExclusions(tuple(rule for rule in self.rules if rule.scope == scope))

    def __bool__(self) -> bool:
        return bool(self.rules)


def _patterns(value: Any, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, Mapping) or set(value) - {"patterns"}:
        raise ValueError(f"{field} must be a table with only a patterns list")
    patterns = value.get("patterns", [])
    if not isinstance(patterns, list):
        raise ValueError(f"{field}.patterns must be a list of strings")
    result = []
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern.strip() or pattern != pattern.strip():
            raise ValueError(f"{field}.patterns entries must be non-empty strings without surrounding space")
        parts = PurePosixPath(pattern.rstrip("/")).parts
        if pattern.startswith("/") or "\\" in pattern or not parts or ".." in parts or "." in parts:
            raise ValueError(f"{field}.patterns entry must be a target-relative POSIX pattern: {pattern!r}")
        if pattern in result:
            raise ValueError(f"{field}.patterns repeats {pattern!r}")
        result.append(pattern)
    return tuple(result)


def global_exclusions(document: Mapping[str, Any]) -> tuple[str, ...]:
    return _patterns(document.get("exclusions"), "exclusions")


def job_exclusions(job_id: str, job_value: Mapping[str, Any], global_patterns: tuple[str, ...]) -> PathExclusions:
    own = _patterns(job_value.get("exclusions"), f"jobs.{job_id}.exclusions")
    if own and job_id not in JOB_LEVEL_SUPPORT:
        raise ValueError(f"jobs.{job_id}.exclusions is not supported: {job_id} does not select target files; "
                         f"supported jobs are {', '.join(sorted(JOB_LEVEL_SUPPORT))}")
    overlap = sorted(set(own) & set(global_patterns))
    if overlap:
        raise ValueError(f"jobs.{job_id}.exclusions repeats global patterns: {', '.join(overlap)}")
    return PathExclusions(tuple(ExclusionRule(pattern, GLOBAL_SCOPE) for pattern in global_patterns) +
                          tuple(ExclusionRule(pattern, job_id) for pattern in own))
