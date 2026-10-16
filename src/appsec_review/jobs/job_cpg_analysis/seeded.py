"""Seeded Joern/c2cpg (enabled path only): build the CPG of the seeded translation units, never the program.

Selection is the shared ``appsec_review.jobs.cpp_seeded.select``. The subset compile database holds only
the selected units and c2cpg is told to skip every other C/C++ source file, so the container reads the
seeded files and nothing else. There is no whole-program fallback: with no seeds no container runs, and a
seed no supported unit contains is a named gap. The CPG is then exported once (``joern-export``, neo4jcsv, in
its own scratch) and ``export.read_export`` keeps a bounded per-function record. With an export the scope's
coverage is ``partial`` (a neighborhood, never the program); without one it stays ``unavailable`` and the
failure is a named gap. The ledger states which seeds a produced CPG retains as evidence.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Any

from appsec_review import seeding
from appsec_review.config.seeding import SeededSettings
from appsec_review.jobs.cpp_seeded import Selection

SEEDED_IMPL = "joern-seeded/2"
EXPORT_ARGV = ("/opt/joern/joern-cli/joern-export", "/scratch/cpg.bin", "-o", "/scratch/export",
               "--repr", "all", "--format", "neo4jcsv")
MAX_EXPORT_FILE_BYTES = 64 * 1024 * 1024
SOURCE_SUFFIXES = r"(?:c|cc|cpp|cxx|c\+\+|cp|h|hh|hpp|hxx|h\+\+|inl|ipp|tcc)"
NO_EXPORT_GAP = ("cpg_export_unavailable: the seeded CPG is retained as run-owned evidence only; its bounded "
                 "export did not complete, so no seeded CPG fact is published")
EXPORT_SCOPE_GAP = ("cpg_export_partial: the export lists calls, branches and reaching-definition counts of the "
                    "seeded files' functions only; it has no call-graph edges, no control-flow edges and no "
                    "source-mapped dataflow paths, and security acceptance is not complete")


@dataclass(frozen=True, slots=True)
class Run:
    """Seeded settings, the project-wide plan, and one scope's seeds."""

    settings: SeededSettings
    plan: seeding.SeedPlan
    scope_seeds: seeding.ScopeSeeds


def identity_values(settings: SeededSettings, scope_seeds: seeding.ScopeSeeds) -> dict[str, Any]:
    return {"seeded": {**settings.identity(), "seeds": [list(row) for row in sorted(scope_seeds.rows)],
                       "impl": SEEDED_IMPL, "export_argv": list(EXPORT_ARGV)}}


def selected_files(selection: Selection) -> list[str]:
    """Project-relative source paths of the selected units, sorted (the exact set c2cpg may read)."""
    return sorted({str(row["file"]).removeprefix("/target/source/").removeprefix("/scratch/source/")
                   for row in selection.container_rows})


def exclude_regex(files: list[str]) -> str:
    """A ``--exclude-regex`` that skips every C/C++ source or header file except ``files``.

    Directories and other files are unaffected; the pattern only matches names with a source suffix
    that are not one of the selected units.
    """
    allowed = "|".join(re.escape(name) for name in files)
    return rf"^(?!.*(?:{allowed})$).*\.{SOURCE_SUFFIXES}$"


def argv_for(base: tuple[str, ...], files: list[str]) -> tuple[str, ...]:
    return (*base, "--exclude-regex", exclude_regex(files))


def reasons(selection: Selection | None, produced: bool) -> Mapping[tuple[str, int, int], str]:
    """Seeds a produced CPG does not retain: selection failures, or all carried seeds when no CPG came out."""
    failed = dict(selection.reasons) if selection else {}
    if not produced and selection:
        failed.update({key: seeding.record.REASON_RUN_FAILED for key in selection.by_seed})
    return failed
