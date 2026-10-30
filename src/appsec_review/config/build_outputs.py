"""Typed ``[build_outputs]`` policy: named build-output exclusions and discovery bounds.

A build workspace holds more than the target's own output: fetched dependency sources, their
build trees, and build-system bookkeeping. The build-output cataloguers classify those trees
(docs/architecture/native-build-output-discovery.md). This module parses the operator policy
that governs them::

    [build_outputs]
    heuristic_min_confidence = "medium"   # "high" | "medium" | "low" | "off"

    [build_outputs.discovery]
    cmake_file_api = true
    max_layout_sources = 64
    max_layout_source_bytes = 16777216
    max_layout_roots = 512
    max_ninja_edges = 200000
    max_kept_per_root = 256

    [[build_outputs.exclusions]]
    name = "cmake-fetchcontent-subbuild"
    reason = "..."
    patterns = ["*-subbuild/"]
    families = ["native"]                 # optional; omitted means every family

Patterns have exactly the ``[exclusions]`` semantics (config/exclusions.py), applied to the
workspace-relative path. Each excluded path is recorded with the rule's name, pattern and the
``build_outputs`` scope; a configured exclusion is a named exclusion, never a coverage gap.
An absent table means the discovery defaults and no exclusions; the shipped rules live in
``appsec-review.toml``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any

from .exclusions import ExclusionRule, validate_patterns

SCOPE = "build_outputs"
FAMILIES: frozenset[str] = frozenset({
    "native", "go", "dotnet", "node", "python", "rust", "php", "java", "wasm",
})
CONFIDENCE_LEVELS: tuple[str, ...] = ("low", "medium", "high")
_HEURISTIC_SETTINGS = frozenset({*CONFIDENCE_LEVELS, "off"})
_NAME = re.compile(r"[a-z0-9-]+")
_TOP_KEYS = frozenset({"heuristic_min_confidence", "discovery", "exclusions"})
_RULE_KEYS = frozenset({"name", "reason", "patterns", "families"})
_DISCOVERY_BOUNDS = ("max_layout_sources", "max_layout_source_bytes", "max_layout_roots",
                     "max_ninja_edges", "max_kept_per_root")


@dataclass(frozen=True, slots=True)
class BuildOutputDiscovery:
    cmake_file_api: bool = True
    max_layout_sources: int = 64
    max_layout_source_bytes: int = 16 * 1024 * 1024
    max_layout_roots: int = 512
    max_ninja_edges: int = 200_000
    max_kept_per_root: int = 256

    def view(self) -> dict[str, Any]:
        return {"cmake_file_api": self.cmake_file_api,
                **{key: getattr(self, key) for key in _DISCOVERY_BOUNDS}}


@dataclass(frozen=True, slots=True)
class BuildOutputExclusion:
    """One named operator rule. ``families`` empty means every build family."""

    name: str
    reason: str
    patterns: tuple[str, ...]
    families: tuple[str, ...] = ()

    def applies_to(self, family: str) -> bool:
        return not self.families or family in self.families

    def rules(self) -> tuple[ExclusionRule, ...]:
        return tuple(ExclusionRule(pattern, SCOPE) for pattern in self.patterns)

    def view(self) -> dict[str, Any]:
        value: dict[str, Any] = {"name": self.name, "reason": self.reason, "patterns": list(self.patterns)}
        if self.families:
            value["families"] = list(self.families)
        return value


@dataclass(frozen=True, slots=True)
class BuildOutputPolicy:
    heuristic_min_confidence: str = "medium"
    discovery: BuildOutputDiscovery = field(default_factory=BuildOutputDiscovery)
    exclusions: tuple[BuildOutputExclusion, ...] = ()

    def view(self) -> dict[str, Any]:
        return {"heuristic_min_confidence": self.heuristic_min_confidence,
                "discovery": self.discovery.view(),
                "exclusions": [rule.view() for rule in self.exclusions]}

    @property
    def identity(self) -> str:
        """SHA-256 of the canonical policy; it enters every build checkpoint fingerprint."""
        canonical = json.dumps(self.view(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def rules_for(self, family: str) -> tuple[tuple[ExclusionRule, BuildOutputExclusion], ...]:
        """The ordered ``(rule, exclusion)`` pairs one build family applies."""
        return tuple((rule, exclusion) for exclusion in self.exclusions if exclusion.applies_to(family)
                     for rule in exclusion.rules())

    def heuristic_accepted(self, confidence: str) -> bool:
        """Whether a heuristic of ``confidence`` may reclassify a tree, rather than only annotate it."""
        if self.heuristic_min_confidence == "off" or confidence not in CONFIDENCE_LEVELS:
            return False
        return CONFIDENCE_LEVELS.index(confidence) >= CONFIDENCE_LEVELS.index(self.heuristic_min_confidence)


def _positive_int(value: Any, field_name: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{field_name} must be a positive integer")
    return value


def _discovery(value: Any) -> BuildOutputDiscovery:
    if value is None:
        return BuildOutputDiscovery()
    if not isinstance(value, Mapping):
        raise ValueError("build_outputs.discovery must be a table")
    unknown = sorted(set(value) - {"cmake_file_api", *_DISCOVERY_BOUNDS})
    if unknown:
        raise ValueError(f"build_outputs.discovery has unknown keys: {', '.join(unknown)}")
    defaults = BuildOutputDiscovery()
    cmake_file_api = value.get("cmake_file_api", defaults.cmake_file_api)
    if type(cmake_file_api) is not bool:
        raise ValueError("build_outputs.discovery.cmake_file_api must be a boolean")
    bounds = {key: _positive_int(value.get(key, getattr(defaults, key)), f"build_outputs.discovery.{key}")
              for key in _DISCOVERY_BOUNDS}
    return BuildOutputDiscovery(cmake_file_api=cmake_file_api, **bounds)


def _exclusion(value: Any, index: int) -> BuildOutputExclusion:
    where = f"build_outputs.exclusions[{index}]"
    if not isinstance(value, Mapping):
        raise ValueError(f"{where} must be a table")
    unknown = sorted(set(value) - _RULE_KEYS)
    if unknown:
        raise ValueError(f"{where} has unknown keys: {', '.join(unknown)}")
    name = value.get("name")
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise ValueError(f"{where}.name must match [a-z0-9-]+")
    reason = value.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError(f"{where}.reason must be a non-empty string")
    if "patterns" not in value:
        raise ValueError(f"{where}.patterns is required")
    patterns = validate_patterns(value["patterns"], f"{where}.patterns")
    if not patterns:
        raise ValueError(f"{where}.patterns must name at least one pattern")
    families_value = value.get("families", [])
    if (not isinstance(families_value, list) or
            any(not isinstance(item, str) or item not in FAMILIES for item in families_value)):
        raise ValueError(f"{where}.families must list build families from: {', '.join(sorted(FAMILIES))}")
    if len(set(families_value)) != len(families_value):
        raise ValueError(f"{where}.families repeats a family")
    return BuildOutputExclusion(name=name, reason=reason, patterns=patterns, families=tuple(families_value))


def parse_build_outputs(value: Any) -> BuildOutputPolicy:
    """Parse the top-level ``[build_outputs]`` table; ``None`` gives the defaults with no rules."""
    if value is None:
        return BuildOutputPolicy()
    if not isinstance(value, Mapping):
        raise ValueError("[build_outputs] must be a table")
    unknown = sorted(set(value) - _TOP_KEYS)
    if unknown:
        raise ValueError(f"build_outputs has unknown keys: {', '.join(unknown)}")
    heuristic = value.get("heuristic_min_confidence", "medium")
    if heuristic not in _HEURISTIC_SETTINGS:
        raise ValueError("build_outputs.heuristic_min_confidence must be one of high, medium, low, off")
    rules_value = value.get("exclusions", [])
    if not isinstance(rules_value, list):
        raise ValueError("build_outputs.exclusions must be an array of tables")
    rules = tuple(_exclusion(item, index) for index, item in enumerate(rules_value))
    names = [rule.name for rule in rules]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ValueError(f"build_outputs.exclusions repeats names: {', '.join(duplicates)}")
    return BuildOutputPolicy(heuristic_min_confidence=str(heuristic), discovery=_discovery(value.get("discovery")),
                             exclusions=rules)


BUILD_OUTPUT_JOBS: frozenset[str] = frozenset({
    "job_language_build", "job_project_build", "job_sanitizer_build",
})


def reject_misplaced(job_id: str, job_value: Mapping[str, Any]) -> None:
    """Build-output policy is one top-level table; a job-level copy fails rather than being ignored."""
    settings = job_value.get("settings")
    if "build_outputs" in job_value or (isinstance(settings, Mapping) and "build_outputs" in settings):
        raise ValueError(f"jobs.{job_id}.build_outputs is not supported: [build_outputs] is a top-level table")
