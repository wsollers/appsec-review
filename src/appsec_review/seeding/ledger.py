"""Seed extraction and the seed ledger shared by every seeded producer.

Contract: ``docs/architecture/seeded-neighborhoods.md`` and
``docs/architecture/seeded-codeql-neighborhoods.md`` sections 3, 4 and 6.

A *seed* is the line range of a finding that an earlier job already located. A seeded producer
(CodeQL, Clang AST/IR, Clang static analysis, CPG) runs outward from the functions containing the
seeds, so this module decides which locations seed which scope, and afterwards reports how each seed
resolved. It reads only accepted, hash verified ``observations`` index shards; it never scans the
target tree and never runs an analyzer. This is the only implementation of the ledger statuses.

Every seeded producer's own observations are excluded from the seed set, so the set is identical for
all producers and does not depend on which of them already ran.
"""

from __future__ import annotations

import csv
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import io
import json
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from appsec_review.indexing.store import ShardSet
from appsec_review.retrieval.observations import (
    SEVERITY_ORDER, classify, normalize_reported_severity, rule_of, scanner_of,
)
from appsec_review.retrieval.index import MANIFEST_SCHEMA
from appsec_review.storage import file_sha256



CODEQL_JOB = "job_codeql_analysis"
CLANG_STATIC_JOB = "job_clang_static_analysis"
CPG_JOB = "job_cpg_analysis"
COMPILED_JOB = "job_cpp_compiled_analysis"
# Jobs whose own observations never seed: the set must not depend on the producer being seeded.
SEEDED_PRODUCER_JOBS = frozenset({CODEQL_JOB, CLANG_STATIC_JOB, CPG_JOB, COMPILED_JOB})
SEEDED_PRODUCER_SCANNERS = frozenset({"codeql"})
OBSERVATION_INDEX = "observations"
MAX_SOURCES_PER_SEED = 8
MAX_FUNCTIONS_PER_SEED = 8
RESOLVED, UNRESOLVED = "resolved", "unresolved"
FILE_NOT_IN_DATABASE, OVER_LIMIT = "file_not_in_database", "over_limit"
LEDGER_STATUSES = (RESOLVED, UNRESOLVED, FILE_NOT_IN_DATABASE, OVER_LIMIT)
NO_SEEDS_GAP = "seeded export skipped: no finding locations map into this database"
_UNKNOWN_RANK = len(SEVERITY_ORDER)


class SeedScope(Protocol):
    """What the extractor needs of a scope: any producer's scope type fits (duck typed)."""

    scope_id: str
    root: str
    files: Sequence[Mapping[str, Any]]


class SeedIntegrityError(ValueError):
    """An upstream observation manifest or shard is not what the plan accepted."""


@dataclass(frozen=True, slots=True)
class SeedSource:
    scanner: str
    rule: str
    severity: str
    observation_id: str

    def key(self) -> tuple[str, str, str, str]:
        return (self.scanner, self.rule, self.observation_id, self.severity)

    def as_dict(self) -> dict[str, str]:
        return {"scanner": self.scanner, "rule": self.rule, "severity": self.severity,
                "observation_id": self.observation_id}


@dataclass(frozen=True, slots=True)
class Seed:
    """One distinct finding location in database-relative form (``File.getRelativePath()``)."""

    path: str
    start_line: int
    end_line: int
    sources: tuple[SeedSource, ...] = ()
    rank: int = _UNKNOWN_RANK

    @property
    def key(self) -> tuple[str, int, int]:
        return (self.path, self.start_line, self.end_line)


@dataclass(frozen=True, slots=True)
class ScopeSeeds:
    """The selected seeds of one scope plus what the selection left out."""

    scope_id: str
    seeds: tuple[Seed, ...] = ()
    total: int = 0
    dropped: int = 0

    @property
    def rows(self) -> tuple[tuple[str, int, int], ...]:
        return tuple(seed.key for seed in self.seeds)


@dataclass(frozen=True, slots=True)
class SeedPlan:
    """Seeds of every scope plus the counts that belong to no single scope."""

    scopes: Mapping[str, ScopeSeeds] = field(default_factory=dict)
    not_in_database: int = 0
    unlocated: int = 0

    def for_scope(self, scope_id: str) -> ScopeSeeds:
        return self.scopes.get(scope_id, ScopeSeeds(scope_id))

    def shared_gaps(self) -> list[str]:
        """Gaps that describe all databases alike; identical text so the summary deduplicates them."""
        gaps = []
        if self.not_in_database:
            gaps.append(f"seed_file_not_in_database: {self.not_in_database} finding locations lie in no "
                        "CodeQL database scope and cannot seed a neighborhood")
        if self.unlocated:
            gaps.append(f"seed_unlocated: {self.unlocated} source findings carry no line location and "
                        "cannot seed a neighborhood")
        return gaps


# ------------------------------------------------------------------------------ extraction


def database_path(scope: SeedScope, target_path: str) -> str:
    """Path of ``target_path`` as the scope's database stores it (relative to the scope root)."""
    root = scope.root.strip("/")
    if root in ("", "."):
        return target_path
    prefix = root + "/"
    return target_path[len(prefix):] if target_path.startswith(prefix) else target_path


def _target_path(raw: object) -> str | None:
    text = str(raw or "").replace("\\", "/")
    logical = PurePosixPath(text)
    if not text or logical.is_absolute() or ".." in logical.parts:
        return None
    return logical.as_posix()


def observation_shards(run_root: Path, manifests: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Hash-verified observation shards named by the plan's upstream manifests (seeded producers' own excluded)."""
    root = run_root.resolve()
    found: dict[tuple[str, str], Mapping[str, Any]] = {}
    for reference in manifests:
        path = (root / str(reference.get("path", ""))).resolve()
        if root not in path.parents or not path.is_file() or path.is_symlink():
            raise SeedIntegrityError("seed manifest is unavailable or escaped the run")
        if file_sha256(path) != reference.get("sha256"):
            raise SeedIntegrityError("seed manifest identity changed")
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("schema") != MANIFEST_SCHEMA:
            raise SeedIntegrityError("seed manifest schema is unsupported")
        for shard in document.get("indexes", ()):
            producer = shard.get("producer") or {}
            if shard.get("name") != OBSERVATION_INDEX or producer.get("job") in SEEDED_PRODUCER_JOBS:
                continue
            shard_path = (root / str(shard.get("relative_path", ""))).resolve()
            if root not in shard_path.parents or not shard_path.is_file():
                raise SeedIntegrityError("seed observation shard is unavailable")
            if file_sha256(shard_path) != shard.get("sha256"):
                raise SeedIntegrityError("seed observation shard identity changed")
            found[(str(shard["name"]), str(shard.get("shard_id", "default")))] = shard
    return [found[key] for key in sorted(found)]


class _Accumulator:
    def __init__(self) -> None:
        self.rank = _UNKNOWN_RANK
        self.sources: dict[str, SeedSource] = {}

    def add(self, rank: int, source: SeedSource) -> None:
        self.rank = min(self.rank, rank)
        self.sources[source.observation_id] = source
        if len(self.sources) > 4 * MAX_SOURCES_PER_SEED:  # keep only what can still be listed
            self.sources = {item.observation_id: item for item in sorted(
                self.sources.values(), key=SeedSource.key)[:MAX_SOURCES_PER_SEED]}


def extract_seeds(run_root: Path, manifests: Iterable[Mapping[str, Any]],
                  scopes: Sequence[SeedScope], *, seed_limit: int) -> SeedPlan:
    """Map the accepted tool observations onto the scopes' databases and bound the result."""
    if seed_limit < 1:
        raise ValueError("seed_limit must be a positive integer")
    by_path: dict[str, list[tuple[str, str]]] = {}
    for scope in scopes:
        for entry in scope.files:
            path = _target_path(entry.get("path"))
            if path is not None:
                by_path.setdefault(path, []).append((scope.scope_id, database_path(scope, path)))
    collected: dict[str, dict[tuple[str, int, int], _Accumulator]] = {scope.scope_id: {} for scope in scopes}
    outside: set[tuple[str, int, int]] = set()
    unlocated = 0
    shards = observation_shards(run_root, manifests)
    store = ShardSet(run_root, shards)
    for entity in store.entities(store.shards, kinds=("tool_observation",)):
        payload = entity["payload"] if isinstance(entity["payload"], Mapping) else {}
        if scanner_of(payload) in SEEDED_PRODUCER_SCANNERS or entity.get("job") in SEEDED_PRODUCER_JOBS:
            continue
        location = entity.get("location")
        path = _target_path(location.get("path")) if isinstance(location, Mapping) else None
        start = location.get("start_line") if isinstance(location, Mapping) else None
        if path is None or isinstance(start, bool) or not isinstance(start, int) or start < 1:
            unlocated += classify(payload) == "source_sast"
            continue
        end = location.get("end_line")
        end = end if isinstance(end, int) and not isinstance(end, bool) and end >= start else start
        owners = by_path.get(path)
        if not owners:
            outside.add((path, start, end))
            continue
        severity = normalize_reported_severity(payload)["value"]
        source = SeedSource(scanner_of(payload), rule_of(payload), severity, str(entity["identity"]))
        rank = SEVERITY_ORDER.get(severity, _UNKNOWN_RANK)
        for scope_id, relative in owners:
            collected[scope_id].setdefault((relative, start, end), _Accumulator()).add(rank, source)
    selected: dict[str, ScopeSeeds] = {}
    for scope_id, found in collected.items():
        ranked = sorted(found.items(), key=lambda item: (item[1].rank, item[0]))
        kept = ranked[:seed_limit]
        seeds = tuple(Seed(path, start, end, tuple(sorted(
            accumulator.sources.values(), key=SeedSource.key)[:MAX_SOURCES_PER_SEED]), accumulator.rank)
            for (path, start, end), accumulator in sorted(kept, key=lambda item: item[0]))
        selected[scope_id] = ScopeSeeds(scope_id, seeds, len(ranked), len(ranked) - len(kept))
    return SeedPlan(selected, len(outside), unlocated)


# ------------------------------------------------------------------------------ staging and identity


def scope_csv(mode: str, depth: int) -> str:
    """``scope.csv``: one header-less row ``<mode>,<depth>`` (``external predicate exportScope``)."""
    return _csv([(mode, depth)])


def seeds_csv(rows: Iterable[tuple[str, int, int]]) -> str:
    """``seeds.csv``: header-less ``<path>,<start>,<end>`` rows (``external predicate exportSeed``)."""
    return _csv(sorted(rows))


def _csv(rows: Iterable[Sequence[object]]) -> str:
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\n").writerows(rows)
    return buffer.getvalue()


def identity_fragment(mode: str, depth: int, seed_limit: int,
                      rows: Iterable[tuple[str, int, int]] | None) -> dict[str, Any]:
    """The export-identity binding of the scope: mode, depth, limit and the sorted seed set."""
    if mode != "seeded":
        return {"mode": mode}
    return {"mode": mode, "depth": depth, "seed_limit": seed_limit,
            "seeds": [list(row) for row in sorted(rows or ())]}


# ------------------------------------------------------------------------------ the ledger


def _column(document: Mapping[str, Any], *names: str) -> list[tuple[Any, ...]]:
    columns = list(document.get("columns", ()))
    indexes = [columns.index(name) for name in names]
    return [tuple(row[index] for index in indexes) for row in document.get("rows", ())]


def whole_program_section() -> dict[str, Any]:
    return {"mode": "whole_program", "depth": None, "seed_limit": None, "seed_count": 0,
            "resolved_seed_count": 0, "neighborhood_function_count": 0, "depth_histogram": {},
            "seeds": [], "status_counts": {}, "gaps": []}


def seeded_section(*, depth: int, seed_limit: int, scope_seeds: ScopeSeeds, plan: SeedPlan,
                   seed_functions: Mapping[str, Any] | None = None,
                   neighborhood: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Spec section 6 ``seeded`` object from the scope's seeds and the two report exports.

    Without report documents (the export was skipped) every seed stays unresolved-by-absence: the
    section then has ``seed_count`` 0 and only the gaps.
    """
    functions: dict[tuple[str, int, int], set[str]] = {}
    if seed_functions is not None:
        for path, start, end, name in _column(seed_functions, "seed_path", "seed_start_line",
                                              "seed_end_line", "function_name"):
            functions.setdefault((str(path), int(start), int(end)), set()).add(str(name))
    members: set[tuple[Any, ...]] = set()
    histogram: Counter[int] = Counter()
    if neighborhood is not None:
        for row in _column(neighborhood, "function_name", "function_path", "function_start_line",
                           "function_start_column", "depth"):
            if row[:4] not in members:
                members.add(row[:4])
                histogram[int(row[4])] += 1
    ledger = []
    for seed in scope_seeds.seeds:
        names = sorted(functions.get(seed.key, ()))
        ledger.append({"path": seed.path, "start_line": seed.start_line, "end_line": seed.end_line,
                       "status": RESOLVED if names else UNRESOLVED,
                       "functions": names[:MAX_FUNCTIONS_PER_SEED],
                       "sources": [source.as_dict() for source in seed.sources]})
    counts = Counter(item["status"] for item in ledger)
    if scope_seeds.dropped:
        counts[OVER_LIMIT] = scope_seeds.dropped
    if plan.not_in_database:
        counts[FILE_NOT_IN_DATABASE] = plan.not_in_database
    gaps = []
    if scope_seeds.dropped:
        gaps.append(f"seed_limit_exceeded: {scope_seeds.dropped} of {scope_seeds.total} seeds dropped")
    if counts[UNRESOLVED]:
        gaps.append(f"seed_unresolved: {counts[UNRESOLVED]} of {len(ledger)} seed locations lie in no "
                    "function body (file scope, macro or generated code)")
    if ledger and not counts[RESOLVED]:
        gaps.append("seeded neighborhood is empty: no seed location resolves to a function definition")
    gaps.extend(plan.shared_gaps())
    return {"mode": "seeded", "depth": depth, "seed_limit": seed_limit, "seed_count": len(ledger),
            "resolved_seed_count": counts[RESOLVED], "neighborhood_function_count": len(members),
            "depth_histogram": {str(key): histogram[key] for key in sorted(histogram)},
            "seeds": ledger, "status_counts": {key: counts[key] for key in LEDGER_STATUSES if counts[key]},
            "gaps": gaps}


def skipped_section(*, depth: int, seed_limit: int, scope_seeds: ScopeSeeds, plan: SeedPlan) -> dict[str, Any]:
    """The ``seeded`` object of a scope whose export was not run because nothing seeds it."""
    section = seeded_section(depth=depth, seed_limit=seed_limit, scope_seeds=scope_seeds, plan=plan)
    section["gaps"] = [NO_SEEDS_GAP, *section["gaps"]]
    return section
