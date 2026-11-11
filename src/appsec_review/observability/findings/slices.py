"""Game threat-model slices of the finding set (finding-metrics.md section 4.4, T-070).

Every count and ratio of the domain can be cut by severity band, ship-block status, weakness
family, lane, component and the three game dimensions: attacker position, ownership and build
configuration. This module holds the operator-supplied path rules that establish ownership, build
configuration and component, and the slicing helpers.

Doctrine:

* A dimension that was not established for a finding stays ``None`` and is reported as its own
  ``"null"`` row. It is never folded into a default the operator did not state.
* Nothing is inferred beyond the deterministic rules below. A finding whose locations disagree
  keeps ``None``; an already established value is never overridden; ``attacker_position`` is never
  inferred from a path.
* Rules are target-specific data supplied by the operator, validated closed (unknown keys are
  refused) and identified by ``SliceRules.sha256`` so a result can name the rules it was cut with.
* These dimensions are not part of finding identity: annotating never changes a fingerprint.
* Outputs are sorted and deterministic; inputs are never mutated.

Glob semantics (``glob_match``): a pattern and a path are compared segment by segment. A segment
that is exactly ``**`` matches any number of whole segments, including zero. Inside any other
segment ``*`` matches any run of characters (including none) and ``?`` exactly one character;
neither crosses a ``/``, and a ``**`` that is only part of a segment behaves as ``*``. Every other
character, including ``[``, is literal. Matching is case-sensitive and anchored to the whole path.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
import copy
from dataclasses import dataclass
from typing import Any

from .contracts import (
    LANES, SEVERITY_BANDS, SHIP_BLOCK_STATUSES, AttackerPosition, BuildConfiguration, Ownership, check_snapshot,
    counts, digest, is_published, normalize_path, weakness_family)

SLICE_RULES_SCHEMA = "appsec-review/finding-slice-rules/1"
MAX_GLOBS = 256                # per rule list
MAX_COMPONENTS = 256           # per rules document
MAX_GLOB_CHARS = 256           # per glob
MAX_COMPONENT_NAME_CHARS = 512  # the bound of the finding record's ``component`` field

CLOSED_DIMENSIONS: Mapping[str, tuple[str, ...]] = {
    "attacker_position": tuple(item.value for item in AttackerPosition),
    "build_configuration": tuple(item.value for item in BuildConfiguration),
    "lane": tuple(LANES),
    "ownership": tuple(item.value for item in Ownership),
    "severity": tuple(SEVERITY_BANDS),
    "ship_block_status": tuple(SHIP_BLOCK_STATUSES),
}
OPEN_DIMENSIONS = ("component", "weakness_family")
DIMENSIONS = tuple(sorted((*CLOSED_DIMENSIONS, *OPEN_DIMENSIONS)))

_OWNERSHIP_KEYS = ("engine", "middleware", "default")
_BUILD_KEYS = ("editor_or_test", "development", "default")


# --------------------------------------------------------------------------------------- globs

def _wildcard(pattern: str, text: str) -> bool:
    """``*`` and ``?`` within one segment, in time bounded by ``len(pattern) * len(text)``."""
    p = t = 0
    star, mark = -1, 0
    while t < len(text):
        if p < len(pattern) and pattern[p] == "*":
            star, mark = p, t
            p += 1
        elif p < len(pattern) and (pattern[p] == "?" or pattern[p] == text[t]):
            p += 1
            t += 1
        elif star >= 0:
            mark += 1
            p, t = star + 1, mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def glob_match(pattern: str, path: str) -> bool:
    """Whether a target-relative POSIX ``path`` matches ``pattern`` (semantics in the module docstring)."""
    patterns, segments = pattern.split("/"), path.split("/")
    p = s = 0
    star, mark = -1, 0
    while s < len(segments):
        if p < len(patterns) and patterns[p] == "**":
            star, mark = p, s
            p += 1
        elif p < len(patterns) and _wildcard(patterns[p], segments[s]):
            p += 1
            s += 1
        elif star >= 0:
            mark += 1
            p, s = star + 1, mark
        else:
            return False
    while p < len(patterns) and patterns[p] == "**":
        p += 1
    return p == len(patterns)


def _glob(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_GLOB_CHARS:
        raise ValueError(f"{where}: a glob must be a non-empty string of at most {MAX_GLOB_CHARS} characters")
    if "\\" in value or "\n" in value or "\r" in value or value.startswith("/"):
        raise ValueError(f"{where}: glob is not a target-relative POSIX pattern: {value!r}")
    segments = value.split("/")
    if "" in segments or "." in segments or ".." in segments:
        raise ValueError(f"{where}: glob has an empty, '.' or '..' segment: {value!r}")
    return value


def _globs(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{where} must be a list of globs")
    if len(value) > MAX_GLOBS:
        raise ValueError(f"{where} exceeds the bounded number of globs")
    return tuple(sorted({_glob(item, where) for item in value}))


def _section(document: Mapping[str, Any], name: str, keys: tuple[str, ...], default: str
             ) -> tuple[tuple[str, ...], tuple[str, ...], str | None]:
    section = document.get(name, {})
    if not isinstance(section, Mapping):
        raise ValueError(f"slice rules {name} must be an object")
    unknown = sorted(str(key) for key in set(section) - set(keys))
    if unknown:
        raise ValueError(f"slice rules {name} has unknown keys: {', '.join(unknown)}")
    fallback = section.get("default")
    if fallback is not None and fallback != default:
        raise ValueError(f"slice rules {name} default must be {default!r} or null")
    return (_globs(section.get(keys[0], ()), f"slice rules {name}.{keys[0]}"),
            _globs(section.get(keys[1], ()), f"slice rules {name}.{keys[1]}"), fallback)


# --------------------------------------------------------------------------------------- rules

@dataclass(frozen=True)
class SliceRules:
    """Validated slice rules. Build with ``load_rules``; ``sha256`` identifies the normalized document."""

    engine: tuple[str, ...]
    middleware: tuple[str, ...]
    ownership_default: str | None
    editor_or_test: tuple[str, ...]
    development: tuple[str, ...]
    build_configuration_default: str | None
    components: tuple[tuple[str, tuple[str, ...]], ...]
    sha256: str

    def document(self) -> dict[str, Any]:
        """The normalized rules document ``sha256`` was computed over."""
        return _document(self.engine, self.middleware, self.ownership_default, self.editor_or_test,
                         self.development, self.build_configuration_default, self.components)

    def ownership(self, path: str) -> str | None:
        """Engine, else middleware, else the stated default (which may be ``None``)."""
        if any(glob_match(glob, path) for glob in self.engine):
            return Ownership.ENGINE.value
        if any(glob_match(glob, path) for glob in self.middleware):
            return Ownership.MIDDLEWARE.value
        return self.ownership_default

    def build_configuration(self, path: str) -> str | None:
        """Editor-or-test, else development, else the stated default (which may be ``None``)."""
        if any(glob_match(glob, path) for glob in self.editor_or_test):
            return BuildConfiguration.EDITOR_OR_TEST.value
        if any(glob_match(glob, path) for glob in self.development):
            return BuildConfiguration.DEVELOPMENT.value
        return self.build_configuration_default

    def component(self, path: str) -> str | None:
        """The first component in declared order with a matching glob, else ``None``."""
        for name, globs in self.components:
            if any(glob_match(glob, path) for glob in globs):
                return name
        return None


def _document(engine, middleware, ownership_default, editor_or_test, development, build_default, components
              ) -> dict[str, Any]:
    return {
        "schema": SLICE_RULES_SCHEMA,
        "ownership": {"engine": list(engine), "middleware": list(middleware), "default": ownership_default},
        "build_configuration": {"editor_or_test": list(editor_or_test), "development": list(development),
                                "default": build_default},
        "components": [{"name": name, "paths": list(globs)} for name, globs in components],
    }


def load_rules(document: Any) -> SliceRules:
    """Validate an operator-supplied ``finding-slice-rules/1`` document.

    ``schema`` is required; ``ownership``, ``build_configuration`` and ``components`` default to
    no globs and a ``None`` default, which establishes nothing. Glob lists are sets (stored sorted
    and de-duplicated); component order is significant and kept. Unknown keys are refused.
    """
    if not isinstance(document, Mapping) or document.get("schema") != SLICE_RULES_SCHEMA:
        raise ValueError("unsupported finding slice rules schema")
    unknown = sorted(str(key) for key in set(document) - {"schema", "ownership", "build_configuration", "components"})
    if unknown:
        raise ValueError(f"slice rules have unknown keys: {', '.join(unknown)}")
    engine, middleware, ownership_default = _section(document, "ownership", _OWNERSHIP_KEYS,
                                                     Ownership.FIRST_PARTY.value)
    editor_or_test, development, build_default = _section(document, "build_configuration", _BUILD_KEYS,
                                                          BuildConfiguration.SHIPPING.value)
    raw_components = document.get("components", ())
    if not isinstance(raw_components, (list, tuple)):
        raise ValueError("slice rules components must be a list")
    if len(raw_components) > MAX_COMPONENTS:
        raise ValueError("slice rules exceed the bounded number of components")
    components: list[tuple[str, tuple[str, ...]]] = []
    names: set[str] = set()
    for item in raw_components:
        if not isinstance(item, Mapping) or set(item) != {"name", "paths"}:
            raise ValueError("a slice rules component must be an object with exactly name and paths")
        name = item["name"]
        if (not isinstance(name, str) or not name or len(name) > MAX_COMPONENT_NAME_CHARS or "\n" in name
                or "\r" in name or name == "null"):
            raise ValueError("a component name must be a short single-line string other than 'null'")
        if name in names:
            raise ValueError(f"slice rules repeat the component {name!r}")
        names.add(name)
        components.append((name, _globs(item["paths"], f"slice rules component {name!r} paths")))
    frozen = tuple(components)
    sha256 = digest(_document(engine, middleware, ownership_default, editor_or_test, development, build_default,
                              frozen))
    return SliceRules(engine=engine, middleware=middleware, ownership_default=ownership_default,
                      editor_or_test=editor_or_test, development=development,
                      build_configuration_default=build_default, components=frozen, sha256=sha256)


# ------------------------------------------------------------------------------------ annotate

def _agreed(values: Iterable[str | None]) -> str | None:
    distinct = set(values)
    return next(iter(distinct)) if len(distinct) == 1 else None


def annotate(finding: Mapping[str, Any], rules: SliceRules) -> dict[str, Any]:
    """A new finding record with unset ``ownership``, ``build_configuration`` and ``component`` classified.

    Each location path is classified by ``rules``; the finding gets a value only when every
    location agrees, otherwise the dimension stays ``None``. An established value is never
    overridden and ``attacker_position`` is never inferred. Every other field, including the
    fingerprint, is carried unchanged; the input is not mutated.
    """
    if not isinstance(rules, SliceRules):
        raise ValueError("annotate needs SliceRules built by load_rules")
    if not isinstance(finding, Mapping):
        raise ValueError("finding record must be an object")
    locations = finding.get("locations")
    if not isinstance(locations, (list, tuple)) or not locations:
        raise ValueError("finding needs at least one location")
    paths = [normalize_path(item.get("path") if isinstance(item, Mapping) else None) for item in locations]
    result = copy.deepcopy(dict(finding))
    for dimension, classify in (("ownership", rules.ownership), ("build_configuration", rules.build_configuration),
                                ("component", rules.component)):
        if result.get(dimension) is None:
            result[dimension] = _agreed(classify(path) for path in paths)
    return result


def annotate_snapshot(snapshot: Mapping[str, Any], rules: SliceRules) -> dict[str, Any]:
    """A new ``finding-snapshot/1`` with every finding annotated; fingerprints and all else unchanged."""
    checked = check_snapshot(snapshot)
    result = {key: copy.deepcopy(value) for key, value in checked.items() if key != "findings"}
    result["findings"] = [annotate(finding, rules) for finding in checked["findings"]]
    return {key: result[key] for key in checked}


# ------------------------------------------------------------------------------------- slicing

def _key(finding: Mapping[str, Any], dimension: str) -> str:
    value = weakness_family(finding.get("weakness_cwe")) if dimension == "weakness_family" else finding.get(dimension)
    if value is None:
        return "null"
    if dimension in OPEN_DIMENSIONS and (not isinstance(value, str) or value == "null"):
        raise ValueError(f"finding {dimension} {value!r} cannot be told apart from the null row")
    return str(value)


def slice_counts(findings: Iterable[Mapping[str, Any]], dimension: str) -> dict[str, int]:
    """Finding counts by ``dimension`` with ``"null"`` as its own last row.

    Closed dimensions are zero-filled over their vocabulary in vocabulary order; the open
    dimensions ``weakness_family`` and ``component`` list the observed keys sorted.
    """
    if dimension not in DIMENSIONS:
        raise ValueError(f"unknown slice dimension {dimension!r}")
    keys = [_key(finding, dimension) for finding in findings]
    if dimension in CLOSED_DIMENSIONS:
        return counts((None if key == "null" else key for key in keys), CLOSED_DIMENSIONS[dimension])
    table = {key: 0 for key in sorted(set(keys) - {"null"})}
    table["null"] = 0
    for key in keys:
        table[key] += 1
    return table


def sliced(findings: Iterable[Mapping[str, Any]], dimension: str,
           metric: Callable[[list[Mapping[str, Any]]], Any]) -> dict[str, Any]:
    """``metric`` applied to each slice of ``dimension``, keys sorted.

    Empty closed-vocabulary slices and the ``"null"`` slice are always present, so a metric
    reports its own empty denominator instead of a missing row.
    """
    items = list(findings)
    groups: dict[str, list[Mapping[str, Any]]] = {key: [] for key in slice_counts(items, dimension)}
    for finding in items:
        groups[_key(finding, dimension)].append(finding)
    return {key: metric(groups[key]) for key in sorted(groups)}


def routing(findings: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Published findings by where they can be fixed.

    A team cannot fix engine or middleware code in place, so those findings are routed as
    dependency findings and counted separately; a finding whose ownership was not established is
    its own group, never assumed first-party.
    """
    groups: dict[str, list[str]] = {"fixable_in_place": [], "route_as_dependency": [], "ownership_unknown": []}
    published = 0
    for finding in findings:
        if not is_published(finding):
            continue
        published += 1
        ownership = finding.get("ownership")
        if ownership is None:
            groups["ownership_unknown"].append(finding["finding_id"])
        elif ownership == Ownership.FIRST_PARTY.value:
            groups["fixable_in_place"].append(finding["finding_id"])
        elif ownership in (Ownership.ENGINE.value, Ownership.MIDDLEWARE.value):
            groups["route_as_dependency"].append(finding["finding_id"])
        else:
            raise ValueError(f"finding ownership {ownership!r} is outside its closed vocabulary")
    return {"published": published,
            **{name: {"count": len(ids), "finding_ids": sorted(ids)} for name, ids in groups.items()}}


__all__ = [
    "CLOSED_DIMENSIONS", "DIMENSIONS", "MAX_COMPONENTS", "MAX_COMPONENT_NAME_CHARS", "MAX_GLOBS", "MAX_GLOB_CHARS",
    "OPEN_DIMENSIONS", "SLICE_RULES_SCHEMA", "SliceRules", "annotate", "annotate_snapshot", "glob_match",
    "load_rules", "routing", "slice_counts", "sliced",
]
