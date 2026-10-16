"""What every seeded producer records about its seeds, in one shape.

The full ledger is a hash-pinned run artifact; the compact record rides on the producer's index
identity so the graph job can build the ``codeql_database`` card's ``producers`` list without opening
any producer artifact. Statuses come from :mod:`appsec_review.seeding.ledger`; this module only adds
the *reason* an unresolved seed stayed unresolved and never decides a status itself.

Contract: ``docs/architecture/seeded-neighborhoods.md`` sections 4 and 7.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ledger import RESOLVED, SeedPlan, UNRESOLVED, NO_SEEDS_GAP

RECORD_SCHEMA = "appsec-review/seeded-producer-record/1"
MAX_RECORD_SEEDS = 200
MAX_RECORD_GAPS = 20

# Why a seed stayed unresolved in a producer (never a status: the status stays ``unresolved``).
REASON_NO_FUNCTION = "no_function"
REASON_NO_UNIT = "no_translation_unit"
REASON_RUN_FAILED = "producer_failed"
REASON_NOT_RUN = "not_run"
REASON_NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class ProjectScope:
    """A scope-shaped view of one project for seed extraction (duck-types ``SeedScope``)."""

    scope_id: str
    root: str
    files: Sequence[Mapping[str, Any]]


def coverage_gap(section: Mapping[str, Any]) -> str:
    """The one gap text that qualifies every seeded family and index as a sample, never the program."""
    return (f"seeded_neighborhood: facts cover functions within {section.get('depth')} call steps of "
            f"{section.get('resolved_seed_count', 0)} finding locations; absence outside it is not evidence")


def with_reasons(section: Mapping[str, Any],
                 reasons: Mapping[tuple[str, int, int], str]) -> dict[str, Any]:
    """Copy of a ledger section whose unresolved entries carry the reason the producer could not resolve them."""
    result = dict(section)
    ledger = []
    for entry in section.get("seeds", ()):
        entry = dict(entry)
        if entry["status"] == UNRESOLVED:
            key = (entry["path"], entry["start_line"], entry["end_line"])
            entry["reason"] = reasons.get(key, REASON_NO_FUNCTION)
        ledger.append(entry)
    result["seeds"] = ledger
    return result


def compact_record(section: Mapping[str, Any], *, ledger: Mapping[str, Any] | None = None,
                   skipped: bool = False) -> dict[str, Any]:
    """The bounded ``producer["seeded"]`` record; ``ledger`` is the artifact identity of the full section."""
    seeds = [[entry["path"], entry["start_line"], entry["end_line"], entry["status"]]
             for entry in section.get("seeds", ())][:MAX_RECORD_SEEDS]
    record = {
        "schema": RECORD_SCHEMA, "mode": section.get("mode", "whole_program"),
        "depth": section.get("depth"), "seed_limit": section.get("seed_limit"),
        "seed_count": section.get("seed_count", 0),
        "resolved_seed_count": section.get("resolved_seed_count", 0),
        "neighborhood_function_count": section.get("neighborhood_function_count", 0),
        "depth_histogram": dict(section.get("depth_histogram", {})),
        "status_counts": dict(section.get("status_counts", {})),
        "seeds": seeds, "skipped": bool(skipped),
        "gaps": list(section.get("gaps", ()))[:MAX_RECORD_GAPS],
    }
    if ledger is not None:
        record["ledger"] = {"path": ledger["path"], "sha256": ledger["sha256"]}
    return record


def skipped(section: Mapping[str, Any]) -> bool:
    return NO_SEEDS_GAP in section.get("gaps", ())


def resolved_keys(section: Mapping[str, Any]) -> frozenset[tuple[str, int, int]]:
    return frozenset((entry["path"], entry["start_line"], entry["end_line"])
                     for entry in section.get("seeds", ()) if entry["status"] == RESOLVED)


def seed_rows(plan: SeedPlan, scope_id: str) -> tuple[tuple[str, int, int], ...]:
    return plan.for_scope(scope_id).rows
