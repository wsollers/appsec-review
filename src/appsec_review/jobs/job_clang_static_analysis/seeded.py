"""Seeded Clang-Tidy and Clang Static Analyzer: analyze only the translation units that hold findings.

Seeded mode (``docs/architecture/seeded-neighborhoods.md``) selects, with the shared
``appsec_review.seeding`` module, the accepted compile units whose source can contain a seed and writes
only those into the compile database the analyzers read. There is no whole-program fallback: a seed no
supported unit contains is a named gap, and a seed whose unit failed to compile or analyze stays
``unresolved`` with the failure, never clean. A unit the analyzers do not support is not applicable.

Every diagnostic in a seeded unit is kept. Each one is labelled against the seed set and, when the
seeded LLVM IR run published function ranges, against the neighborhood: ``at_seed``,
``in_seed_function``, ``in_neighborhood`` or ``outside_neighborhood``. Without ranges the label is
``unclassified`` and the gap is named. Labels never change coverage, which stays ``partial``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
from typing import Any

from appsec_review import seeding
from appsec_review.config.seeding import SeededSettings
from appsec_review.jobs.cpp_seeded import (  # noqa: F401
    Selection, UNIT_PREFIX, plan_for, project_of, section_for as _section_for, select, settings_of,
)
from appsec_review.storage import canonical_json

SEEDED_IMPL = "clang-static-seeded/2"
AT_SEED, IN_SEED_FUNCTION, IN_NEIGHBORHOOD = "at_seed", "in_seed_function", "in_neighborhood"
OUTSIDE, UNCLASSIFIED = "outside_neighborhood", "unclassified"
LABELS = (AT_SEED, IN_SEED_FUNCTION, IN_NEIGHBORHOOD, OUTSIDE, UNCLASSIFIED)
MAX_SEEDS_PER_DIAGNOSTIC = 20
NEIGHBORHOOD_UNAVAILABLE = (
    "neighborhood_unavailable: no seeded LLVM IR neighborhood was accepted for this project, so "
    "diagnostics away from a seed line are labelled unclassified, not outside the neighborhood")


@dataclass(frozen=True, slots=True)
class Neighborhood:
    """Function ranges published by the seeded LLVM IR run of the same project, or nothing."""

    ranges: Mapping[str, tuple[str, int, int]] = field(default_factory=dict)
    depth: Mapping[str, int] = field(default_factory=dict)
    seed_functions: Mapping[tuple[str, int, int], tuple[str, ...]] = field(default_factory=dict)
    compile_units: Mapping[str, str] = field(default_factory=dict)

    @property
    def known(self) -> bool:
        return bool(self.ranges)

    def sha256(self) -> str:
        return hashlib.sha256(canonical_json({
            "ranges": {k: list(v) for k, v in sorted(self.ranges.items())},
            "depth": dict(sorted(self.depth.items())),
            "seeds": sorted([*key, list(names)] for key, names in self.seed_functions.items()),
            "compile_units": dict(sorted(self.compile_units.items())),
        })).hexdigest()


def neighborhood_of(accepted: Mapping[str, Any], case_id: str) -> Neighborhood:
    """The IR handoff of a project from the accepted compiled-analysis result (empty when absent)."""
    outputs = accepted.get("result", {}).get("outputs", {})
    handoff = (outputs.get("ir.projects", {}).get("projects", {}).get(case_id, {}) or {}).get("handoff")
    if not isinstance(handoff, Mapping) or not isinstance(handoff.get("ranges"), Mapping):
        return Neighborhood()
    ranges = {str(name): (str(value[0]), int(value[1]), int(value[2]))
              for name, value in handoff["ranges"].items()}
    depth = {str(name): int(value) for name, value in handoff.get("neighborhood", {}).items()}
    seeds: dict[tuple[str, int, int], set[str]] = {}
    for row in handoff.get("seed_functions", ()):
        seeds.setdefault((str(row[0]), int(row[1]), int(row[2])), set()).add(str(row[3]))
    compile_units = {str(name): function["compile_unit_id"]
                     for name, function in handoff.get("functions", {}).items()
                     if isinstance(function, Mapping) and isinstance(function.get("compile_unit_id"), str)
                     and function["compile_unit_id"] and name in ranges}
    return Neighborhood(ranges, depth, {key: tuple(sorted(names)) for key, names in sorted(seeds.items())},
                        compile_units)


def identity_values(settings: SeededSettings, scope_seeds: seeding.ScopeSeeds, hood: Neighborhood,
                    plan: seeding.SeedPlan) -> dict[str, Any]:
    return {"seeded": {**settings.identity(), "seeds": [list(row) for row in sorted(scope_seeds.rows)],
                       "seed_priorities": sorted([*seed.key, seed.rank] for seed in scope_seeds.seeds),
                       "seed_sources": sorted([*seed.key, [source.as_dict() for source in sorted(
                           seed.sources, key=seeding.ledger.SeedSource.key)]] for seed in scope_seeds.seeds),
                       "population": {"total": scope_seeds.total, "dropped": scope_seeds.dropped,
                                      "not_in_database": plan.not_in_database, "unlocated": plan.unlocated},
                       "neighborhood": hood.sha256(), "impl": SEEDED_IMPL}}


def classify(path: str, line: int, scope_seeds: seeding.ScopeSeeds, hood: Neighborhood) -> dict[str, Any]:
    """Classify a physical location without guessing which TU produced the diagnostic."""
    hits: list[tuple[str, int, int]] = []
    label = None
    for seed in scope_seeds.seeds:
        if seed.path == path and seed.start_line <= line <= seed.end_line:
            hits.append(seed.key)
            label = AT_SEED
    matches = {name: end - start for name, (source, start, end) in hood.ranges.items()
               if source == path and start <= line <= end}
    # Range width can choose an innermost function within a TU, never the TU itself.
    best: dict[str | None, int] = {}
    for name, width in matches.items():
        compile_unit = hood.compile_units.get(name)
        best[compile_unit] = min(width, best.get(compile_unit, width))
    functions = {name for name, width in matches.items() if width == best[hood.compile_units.get(name)]}
    possible: list[tuple[str, int, int]] = []
    if functions:
        for seed in scope_seeds.seeds:
            if seed.key in hits:
                continue
            associated = set(hood.seed_functions.get(seed.key, ()))
            if functions <= associated:
                hits.append(seed.key)
                label = label or IN_SEED_FUNCTION
            elif functions & associated:
                possible.append(seed.key)
        label = label or IN_NEIGHBORHOOD
    if label is None:
        label = OUTSIDE if hood.known else UNCLASSIFIED
    placement = {"label": label, "seeds": [list(key) for key in sorted(hits)[:MAX_SEEDS_PER_DIAGNOSTIC]],
                 "function": next(iter(functions)) if len(functions) == 1 else None,
                 "outside_neighborhood": label == OUTSIDE}
    if len(functions) > 1:
        placement.update(
            function_candidates=sorted(functions),
            function_ambiguity="multiple_innermost_functions_without_translation_unit",
            candidate_seeds=[list(key) for key in sorted(possible)[:MAX_SEEDS_PER_DIAGNOSTIC]],
        )
    return placement


@dataclass(frozen=True, slots=True)
class Run:
    """Everything a seeded scope run needs besides the scope itself."""

    settings: SeededSettings
    plan: seeding.SeedPlan
    scope_seeds: seeding.ScopeSeeds
    hood: Neighborhood


def section_for(run: Run, selection: Selection | None, failed: Mapping[tuple[str, int, int], str]) -> dict[str, Any]:
    return _section_for(run.settings, run.plan, run.scope_seeds, selection, failed, run.hood)
