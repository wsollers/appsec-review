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

The global table may also name classes of non-code assets, excluded by file-name suffix::

    [[exclusions.asset_classes]]
    name = "raster-image"
    reason = "raster and icon images are not code"
    suffixes = [".png", ".jpg"]

A suffix matches the end of the file name, case-insensitively, so ``.sav.gz`` is a suffix and
``.png`` does not match ``sprite.pngx``. An asset exclusion is a policy decision, not a coverage
gap: the inventory lists each excluded file with its class and totals files and bytes per class.
Suffixes that can carry code or build logic (``NEVER_ASSET_SUFFIXES``) are refused at load.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
import re
from typing import Any

GLOBAL_SCOPE = "global"
# Suffixes that are never an asset class, whatever the configuration says: they can carry code,
# build logic or packed content, and ``.obj`` is also a compiler object.
NEVER_ASSET_SUFFIXES: frozenset[str] = frozenset({
    ".obj", ".o", ".a", ".so", ".dll", ".exe", ".lib", ".zip", ".tar", ".gz", ".bz2", ".xz", ".zst", ".7z",
    ".jar", ".svg", ".xpm", ".xml", ".json", ".yml", ".yaml", ".toml", ".lua", ".py", ".sh", ".cmake",
    ".m4", ".in", ".am", ".ac", ".build", ".mk", ".c", ".h", ".cc", ".cpp", ".hpp", ".js", ".ts",
    ".java", ".go", ".rs", ".cs", ".rb", ".php", ".pl", ".ps1", ".bat", ".cmd", ".html", ".css", ".po",
    # A target's documentation may be delivered as a PDF instead of buildable doc sources.
    ".pdf",
})
# Jobs that select target files themselves and apply their own job-level patterns. Every job that
# reads the accepted catalog inherits the global (and catalog-level) exclusions through it.
JOB_LEVEL_SUPPORT: frozenset[str] = frozenset({
    "job_review_intake", "job_target_catalog", "job_source_history_analysis",
})


@dataclass(frozen=True, slots=True)
class ExclusionRule:
    pattern: str
    scope: str
    # Set on a rule made from an asset class: ``pattern`` is then ``*<suffix>`` and matches the
    # end of the file name only, case-insensitively.
    asset_class: str | None = None

    def matches(self, path: str) -> bool:
        if self.asset_class is not None:
            return PurePosixPath(path).name.lower().endswith(self.pattern[1:])
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
        if self.asset_class is not None:
            return False  # an asset class names files, never a folder
        parts = PurePosixPath(path).parts
        body = self.pattern.rstrip("/")
        if "/" not in body:
            return any(fnmatchcase(part, body) for part in parts)
        return any(fnmatchcase("/".join(parts[:index]), body) for index in range(1, len(parts) + 1))

    def as_dict(self) -> dict[str, str]:
        if self.asset_class is not None:
            return {"pattern": self.pattern, "scope": self.scope, "asset_class": self.asset_class}
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


def _patterns(value: Any, field: str, *, asset_classes: bool = False) -> tuple[str, ...]:
    if value is None:
        return ()
    allowed = {"patterns", "asset_classes"} if asset_classes else {"patterns"}
    if not isinstance(value, Mapping) or set(value) - allowed:
        raise ValueError(f"{field} must be a table with only a patterns list" +
                         (" and asset_classes" if asset_classes else ""))
    return validate_patterns(value.get("patterns", []), f"{field}.patterns")


def asset_class_rules(document: Mapping[str, Any]) -> tuple[ExclusionRule, ...]:
    """The global ``[[exclusions.asset_classes]]`` tables as suffix rules, in declared order."""
    table = document.get("exclusions")
    classes = table.get("asset_classes", []) if isinstance(table, Mapping) else []
    if not isinstance(classes, list):
        raise ValueError("exclusions.asset_classes must be an array of tables")
    rules: list[ExclusionRule] = []
    names: set[str] = set()
    seen: dict[str, str] = {}
    for index, item in enumerate(classes):
        where = f"exclusions.asset_classes[{index}]"
        if not isinstance(item, Mapping) or set(item) != {"name", "reason", "suffixes"}:
            raise ValueError(f"{where} must be a table with exactly name, reason and suffixes")
        name, reason, suffixes = item["name"], item["reason"], item["suffixes"]
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name) or name in names:
            raise ValueError(f"{where}.name must be a unique lower-case kebab identifier")
        names.add(name)
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"{where}.reason must say why the class is not analysed")
        if not isinstance(suffixes, list) or not suffixes:
            raise ValueError(f"{where}.suffixes must be a non-empty list")
        for suffix in suffixes:
            if not isinstance(suffix, str) or not re.fullmatch(r"(\.[a-z0-9_+-]+)+", suffix):
                raise ValueError(f"{where}.suffixes entries must be lower-case file-name suffixes "
                                 f"such as '.png' or '.sav.gz': {suffix!r}")
            if suffix in NEVER_ASSET_SUFFIXES:
                raise ValueError(f"{where}.suffixes may not exclude {suffix}: it can carry code, build "
                                 "logic or packed content")
            if suffix in seen:
                raise ValueError(f"{where}.suffixes repeats {suffix} (already in class {seen[suffix]})")
            seen[suffix] = name
            rules.append(ExclusionRule("*" + suffix, GLOBAL_SCOPE, name))
    return tuple(rules)


def validate_patterns(patterns: Any, field: str) -> tuple[str, ...]:
    """Validate one list of target-relative POSIX exclusion patterns; ``field`` names it in errors."""
    if not isinstance(patterns, list):
        raise ValueError(f"{field} must be a list of strings")
    result: list[str] = []
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern.strip() or pattern != pattern.strip():
            raise ValueError(f"{field} entries must be non-empty strings without surrounding space")
        parts = PurePosixPath(pattern.rstrip("/")).parts
        if pattern.startswith("/") or "\\" in pattern or not parts or ".." in parts or "." in parts:
            raise ValueError(f"{field} entry must be a target-relative POSIX pattern: {pattern!r}")
        if pattern in result:
            raise ValueError(f"{field} repeats {pattern!r}")
        result.append(pattern)
    return tuple(result)


def global_exclusions(document: Mapping[str, Any]) -> tuple[str, ...]:
    return _patterns(document.get("exclusions"), "exclusions", asset_classes=True)


def job_exclusions(job_id: str, job_value: Mapping[str, Any], global_patterns: tuple[str, ...],
                   asset_rules: tuple[ExclusionRule, ...] = ()) -> PathExclusions:
    own = _patterns(job_value.get("exclusions"), f"jobs.{job_id}.exclusions")
    if own and job_id not in JOB_LEVEL_SUPPORT:
        raise ValueError(f"jobs.{job_id}.exclusions is not supported: {job_id} does not select target files; "
                         f"supported jobs are {', '.join(sorted(JOB_LEVEL_SUPPORT))}")
    overlap = sorted(set(own) & set(global_patterns))
    if overlap:
        raise ValueError(f"jobs.{job_id}.exclusions repeats global patterns: {', '.join(overlap)}")
    return PathExclusions(tuple(ExclusionRule(pattern, GLOBAL_SCOPE) for pattern in global_patterns) +
                          tuple(ExclusionRule(pattern, job_id) for pattern in own) + tuple(asset_rules))


INVENTORY_FILE_BYTES_DEFAULT = 2 * 1024 * 1024


def inventory_max_file_bytes(document: Mapping[str, Any]) -> int:
    """The ``[inventory] max_file_bytes`` bound: the largest target file intake and the catalog read."""
    table = document.get("inventory")
    if table is None:
        return INVENTORY_FILE_BYTES_DEFAULT
    if not isinstance(table, Mapping) or set(table) != {"max_file_bytes"}:
        raise ValueError("[inventory] must be a table with only max_file_bytes")
    value = table["max_file_bytes"]
    if type(value) is not int or not 1 <= value <= 64 * 1024 * 1024:
        raise ValueError("inventory.max_file_bytes must be an integer between 1 and 67108864")
    return value
