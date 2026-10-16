"""Seeded C/C++ producers that replay or analyze compile units: the selection every one of them shares.

``select`` chooses, with ``appsec_review.seeding``, the accepted supported compile units whose source can
contain a seed. The seeded Clang-Tidy/Static Analyzer and CPG jobs both write only those rows into the
compile database their tool reads; there is no whole-program fallback (docs/architecture/seeded-neighborhoods.md).
A seed no supported unit contains is a named gap, an unsupported unit makes its seeds not applicable.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from appsec_review import seeding
from appsec_review.config.seeding import SeededSettings
from appsec_review.jobs.cpp_index_scopes import (
    IndexScope, container_compile_database, partition_compile_commands, project_prefix,
)
from appsec_review.runtime import UnitContext
from appsec_review.seeding import record, units as unit_selection

UNIT_PREFIX = "unit:"


def settings_of(unit: UnitContext) -> SeededSettings:
    return SeededSettings.from_job_settings(unit.job.config.settings)


def plan_for(unit: UnitContext, scopes: Sequence[IndexScope], settings: SeededSettings) -> seeding.SeedPlan:
    """Seeds of every runnable project from the accepted observation shards, in one pass."""
    return seeding.seed_plan(unit.job, [project_of(scope) for scope in scopes], settings)


def project_of(scope: IndexScope) -> seeding.ProjectScope:
    return seeding.ProjectScope(scope.case_id, scope.root,
                                tuple({"path": str(item["target_path"])} for item in scope.files))


@dataclass(frozen=True, slots=True)
class Selection:
    """Compile rows the analyzers receive, and what happened to each seed that selection could not serve."""

    rows: tuple[Mapping[str, Any], ...]
    container_rows: tuple[dict[str, Any], ...]
    by_seed: Mapping[tuple[str, int, int], tuple[str, ...]]
    reasons: Mapping[tuple[str, int, int], str]
    gaps: tuple[str, ...]


def select(scope: IndexScope, scope_seeds: seeding.ScopeSeeds, settings: SeededSettings) -> Selection:
    """Supported compile units that can contain a seed; unsupported units make their seeds not applicable."""
    supported, unsupported = partition_compile_commands(scope.compile_commands)
    rows = [dict(row, file=f"/scratch/source/{str(row['target_path'])[len(project_prefix(scope.root)):]}")
            for row in supported]
    reader = seeding.source_reader(scope.case_root / "source")
    chosen = unit_selection.select_units(rows, scope_seeds.seeds, unit_limit=settings.unit_limit,
                                         include_scan_files=settings.include_scan_files, read_text=reader)
    prefix = project_prefix(scope.root)
    not_applicable = {str(item.path)[len(prefix):] for item in unsupported}
    reasons: dict[tuple[str, int, int], str] = {}
    gaps = list(chosen.gaps)
    for key in chosen.uncovered:
        reasons[key] = record.REASON_NOT_APPLICABLE if key[0] in not_applicable else record.REASON_NO_UNIT
    if any(value == record.REASON_NOT_APPLICABLE for value in reasons.values()):
        gaps = [gap for gap in gaps if not gap.startswith(unit_selection.NO_UNIT_FOR_SEED)]
        missing = sum(1 for value in reasons.values() if value == record.REASON_NO_UNIT)
        if missing:
            gaps.append(f"{unit_selection.NO_UNIT_FOR_SEED}: {missing} seed location(s) lie in no analyzed "
                        "translation unit; their diagnostics are not covered")
    selected = [rows[index] for index in chosen.selected]
    by_seed = {key: tuple(unit_selection.relative_source(rows[index]) for index in indexes)
               for key, indexes in chosen.by_seed.items()}
    return Selection(tuple(selected), tuple(container_compile_database(scope.root, [
        supported[index] for index in chosen.selected])), by_seed, reasons, tuple(gaps))


def section_for(settings: SeededSettings, plan: seeding.SeedPlan, scope_seeds: seeding.ScopeSeeds,
                selection: Selection | None, failed: Mapping[tuple[str, int, int], str],
                hood: Any = None) -> dict[str, Any]:
    """The scope's seeded ledger: resolved seeds name the analysis units that cleanly covered them.

    ``hood`` is an optional neighborhood with ``known``, ``ranges`` and ``depth`` (the seeded IR run's).
    """
    reasons = dict(selection.reasons) if selection else {}
    reasons.update(failed)
    rows = []
    if selection:
        for key, rels in sorted(selection.by_seed.items()):
            if key not in reasons:
                rows.extend([*key, UNIT_PREFIX + rel] for rel in rels)
    document = {"columns": ["seed_path", "seed_start_line", "seed_end_line", "function_name"], "rows": rows}
    neighborhood = None
    if hood is not None and hood.known and rows:
        neighborhood = {"columns": ["function_name", "function_path", "function_start_line", "function_start_column", "depth"],
                        "rows": [[name, path, start, 1, hood.depth.get(name, 0)]
                                 for name, (path, start, _end) in sorted(hood.ranges.items())]}
    section = seeding.ledger.seeded_section(depth=settings.depth, seed_limit=settings.seed_limit,
                                            scope_seeds=scope_seeds, plan=plan, seed_functions=document,
                                            neighborhood=neighborhood)
    return record.with_reasons(section, reasons)
