"""Seed extraction and the seed ledger shared by every seeded producer.

Contract: ``docs/architecture/seeded-neighborhoods.md`` and
``docs/architecture/seeded-codeql-neighborhoods.md`` sections 3, 4 and 6.

A *seed* is a source range from an admitted observation or structural candidate, not by itself a
confirmed finding. A seeded producer
(CodeQL, Clang AST/IR, Clang static analysis, CPG) runs outward from the functions containing the
seeds, so this module decides which locations seed which scope, and afterwards reports how each seed
resolved. It reads hash-verified observation shards and explicitly enabled admitted structural
inputs; it never scans the target tree or runs an analyzer. This is the only implementation of
the ledger statuses.

The shared upstream pass excludes seeded producers' own observations. CodeQL export can also
supply its verified current observation shards and enable structural fallback candidates.
Candidate inclusion changes query scope only; it confers no evidence or execution authority.
Selection is deterministic for the supplied inputs; different supplied inputs need not produce
identical seed sets.
"""

from __future__ import annotations

import csv
import hashlib
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, is_dataclass
import io
import json
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from appsec_review.indexing.store import ShardSet
from appsec_review.retrieval.observations import (
    SEVERITY_ORDER, classify, normalize_reported_severity, rule_of, scanner_of,
)
from appsec_review.retrieval.index import MANIFEST_SCHEMA
from appsec_review.storage import canonical_json, file_sha256



CODEQL_JOB = "job_codeql_analysis"
CLANG_STATIC_JOB = "job_clang_static_analysis"
CPG_JOB = "job_cpg_analysis"
COMPILED_JOB = "job_cpp_compiled_analysis"
# Seeded-producer observations excluded from the shared upstream pass.
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
    severity: str | None
    observation_id: str
    origin: str = "upstream_observation"
    tier: str = "observation"
    entity_kind: str = "tool_observation"

    def key(self) -> tuple[str, ...]:
        return (self.scanner, self.rule, self.observation_id, self.severity or "",
                self.origin, self.tier, self.entity_kind)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


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
    shared_identity: str | None = None
    extra_identity: str | None = None
    extra_not_in_database: int = 0
    extra_unlocated: int = 0
    shared_not_in_database: int | None = None

    def accounting(self, scope_id: str | None = None) -> dict[str, Any]:
        return {
            "scope_id": scope_id, "meaning": "query_seeds_not_findings",
            "shared": {"identity": self.shared_identity, "aggregation": "non_additive",
                       "not_in_database": self.shared_not_in_database if self.shared_not_in_database is not None
                       else self.not_in_database - self.extra_not_in_database,
                       "unlocated": self.unlocated - self.extra_unlocated},
            "additional": {"identity": self.extra_identity, "aggregation": "non_additive",
                           "not_in_database": self.extra_not_in_database, "unlocated": self.extra_unlocated},
        }

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


def bounded_seed_sources(values: object, *, limit: int = MAX_SOURCES_PER_SEED) -> list[dict[str, str]]:
    """The existing card bounds, also used when compacting source metadata for a card."""
    keys = ("scanner", "rule", "severity", "observation_id", "origin", "tier", "entity_kind")
    return [{key: str(source[key])[:300] for key in keys if source.get(key) is not None}
            for source in (values[:limit] if isinstance(values, (list, tuple)) else ())
            if isinstance(source, Mapping)]


def bounded_seed_accounting(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or value.get("meaning") != "query_seeds_not_findings":
        return None
    result: dict[str, Any] = {"meaning": value["meaning"],
                             "scope_id": str(value["scope_id"])[:300] if value.get("scope_id") is not None else None}
    for key in ("shared", "additional"):
        raw = value.get(key)
        if not isinstance(raw, Mapping) or raw.get("aggregation") != "non_additive":
            return None
        identity = raw.get("identity")
        result[key] = {
            "identity": identity if isinstance(identity, str) and len(identity) == 64
            and all(char in "0123456789abcdef" for char in identity) else None,
            "aggregation": "non_additive",
            **{count: raw.get(count) if type(raw.get(count)) is int and raw[count] >= 0 else None
               for count in ("not_in_database", "unlocated")},
        }
    return result


@dataclass(frozen=True, slots=True)
class PreparedSeeds:
    """An attempt-local immutable snapshot of admitted shared candidates, before seed-limit selection."""

    run_root: Path
    identity: str
    input_identity: str
    observations: tuple[tuple[str, tuple[Seed, ...]], ...]
    structural: tuple[tuple[str, tuple[Any, ...]], ...]
    outside_locations: tuple[tuple[str, int, int], ...]
    unlocated: int

    @property
    def not_in_database(self) -> int:
        return len(self.outside_locations)

    def accounting(self) -> dict[str, Any]:
        return SeedPlan(not_in_database=self.not_in_database, unlocated=self.unlocated,
                        shared_identity=self.identity).accounting()


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
            _add_shard(found, (str(shard["name"]), str(shard.get("shard_id", "default"))), shard)
    return [found[key] for key in sorted(found)]


def _add_shard(found: dict, key: tuple[str, str], shard: Mapping[str, Any]) -> None:
    if key in found and canonical_json(found[key]) != canonical_json(shard):
        raise SeedIntegrityError("seed shard identity conflicts across supplied inputs")
    found[key] = shard


class _Accumulator:
    def __init__(self) -> None:
        self.rank = _UNKNOWN_RANK
        self.sources: dict[str, SeedSource] = {}

    def add(self, rank: int, source: SeedSource) -> None:
        self.rank = min(self.rank, rank)
        prior = self.sources.get(source.observation_id)
        self.sources[source.observation_id] = min((prior, source), key=SeedSource.key) if prior else source
        if len(self.sources) > 4 * MAX_SOURCES_PER_SEED:  # keep only what can still be listed
            self.sources = {item.observation_id: item for item in sorted(
                self.sources.values(), key=SeedSource.key)[:MAX_SOURCES_PER_SEED]}


def _verify_extra_observation_shards(run_root: Path,
                                     extra_shards: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Hash-verify direct observation shards (such as CodeQL's own normalized scope shards)."""
    root = run_root.resolve()
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for raw_shard in extra_shards:
        shard = asdict(raw_shard) if is_dataclass(raw_shard) and not isinstance(raw_shard, type) else raw_shard
        if not isinstance(shard, Mapping) or shard.get("name") != OBSERVATION_INDEX:
            raise SeedIntegrityError("seed observation shard entry is malformed")
        rel = str(shard.get("relative_path") or shard.get("path") or "")
        shard_path = (root / rel).resolve()
        if root not in shard_path.parents or not shard_path.is_file() or shard_path.is_symlink():
            raise SeedIntegrityError("seed observation shard is unavailable")
        if file_sha256(shard_path) != shard.get("sha256"):
            raise SeedIntegrityError("seed observation shard identity changed")
        normalized = dict(shard)
        normalized["relative_path"] = rel
        _add_shard(found, (OBSERVATION_INDEX, str(shard.get("shard_id") or rel)), normalized)
    return [found[key] for key in sorted(found)]


def _structural_shards(run_root: Path, manifests: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Hash-verified priority, analysis, and source shards named by upstream manifests."""
    root = run_root.resolve()
    allowed = frozenset({"priority", "analysis", "source"})
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
            if shard.get("name") not in allowed:
                continue
            shard_path = (root / str(shard.get("relative_path", ""))).resolve()
            if root not in shard_path.parents or not shard_path.is_file() or shard_path.is_symlink():
                raise SeedIntegrityError("seed structural shard is unavailable")
            if file_sha256(shard_path) != shard.get("sha256"):
                raise SeedIntegrityError("seed structural shard identity changed")
            _add_shard(found, (str(shard["name"]), str(shard.get("shard_id", "default"))), shard)
    return [found[key] for key in sorted(found)]


def _structural_fallback_seeds(
    run_root: Path,
    manifests: Sequence[Mapping[str, Any]],
    by_path: Mapping[str, Sequence[tuple[str, str]]],
    scope_ids: Sequence[str],
) -> dict[str, list[tuple[tuple[int, float, float, tuple[str, int, int]], Seed]]]:
    """Ranked structural fallback seeds (priority hotspots -> CFG functions -> catalog symbols)."""
    per_scope: dict[str, dict[tuple[str, int, int], tuple[tuple[int, float, float, tuple[str, int, int]], Seed]]] = {
        scope_id: {} for scope_id in scope_ids
    }
    shards = _structural_shards(run_root, manifests)
    if not shards:
        return {scope_id: [] for scope_id in scope_ids}
    store = ShardSet(run_root, shards)
    for entity in store.entities(store.shards, kinds=("hotspot", "ast_node", "symbol")):
        kind = str(entity.get("kind") or "")
        payload = entity["payload"] if isinstance(entity.get("payload"), Mapping) else {}
        location = entity.get("location")
        path = _target_path(location.get("path")) if isinstance(location, Mapping) else None
        start = location.get("start_line") if isinstance(location, Mapping) else None
        if path is None or isinstance(start, bool) or not isinstance(start, int) or start < 1:
            continue
        owners = by_path.get(path)
        if not owners:
            continue
        end = location.get("end_line")
        end = end if isinstance(end, int) and not isinstance(end, bool) and end >= start else start
        identity = str(entity["identity"])
        if kind == "hotspot":
            tier = _UNKNOWN_RANK + 1
            metric_a = -float(payload.get("score") or payload.get("priority_score") or 0.0)
            metric_b = 0.0
            source = SeedSource("priority", str(payload.get("category") or "hotspot"), None, identity,
                                "structural", "priority_hotspot", "hotspot")
        elif kind == "ast_node":
            cfg = payload.get("cfg")
            if not isinstance(cfg, Mapping):
                continue
            tier = _UNKNOWN_RANK + 2
            metric_a = -float(cfg.get("cyclomatic_complexity") or 0.0)
            metric_b = -float(cfg.get("guard_count") or 0.0)
            source = SeedSource("tree-sitter", str(cfg.get("function_name") or "cfg_function"), None, identity,
                                "structural", "cfg_function", "ast_node")
        else:
            tier = _UNKNOWN_RANK + 3
            metric_a = 0.0
            metric_b = 0.0
            source = SeedSource("target-catalog", str(payload.get("kind") or "symbol"), None, identity,
                                "structural", "catalog_symbol", "symbol")
        for scope_id, relative in owners:
            span = (relative, start, end)
            sort_key = (tier, metric_a, metric_b, span)
            bucket = per_scope[scope_id]
            existing = bucket.get(span)
            if existing is None or sort_key < existing[0]:
                bucket[span] = (sort_key, Seed(relative, start, end, (source,), tier))
    return {sid: sorted(bucket.values(), key=lambda item: item[0]) for sid, bucket in per_scope.items()}


def _scope_paths(scopes: Sequence[SeedScope]) -> dict[str, list[tuple[str, str]]]:
    by_path: dict[str, list[tuple[str, str]]] = {}
    for scope in scopes:
        for entry in scope.files:
            path = _target_path(entry.get("path"))
            if path is not None:
                by_path.setdefault(path, []).append((scope.scope_id, database_path(scope, path)))
    return by_path


def _seed_input_identity(manifests: Sequence[Mapping[str, Any]], scopes: Sequence[SeedScope],
                         structural: bool) -> str:
    return hashlib.sha256(canonical_json({
        "manifests": sorted({(str(item.get("path")), str(item.get("sha256"))) for item in manifests}),
        "scopes": [{"scope_id": scope.scope_id, "root": scope.root,
                    "files": sorted((dict(item) for item in scope.files), key=canonical_json)}
                   for scope in sorted(scopes, key=lambda scope: scope.scope_id)],
        "structural": structural,
    })).hexdigest()


def _ingest_observations(run_root: Path, shard_list: Sequence[Mapping[str, Any]],
                         by_path: Mapping[str, Sequence[tuple[str, str]]],
                         collected: dict[str, dict[tuple[str, int, int], _Accumulator]], *,
                         exclude_seeded_producers: bool) -> tuple[tuple[tuple[str, int, int], ...], int]:
    outside: set[tuple[str, int, int]] = set()
    unlocated = 0
    store = ShardSet(run_root, shard_list)
    for entity in store.entities(store.shards, kinds=("tool_observation",)):
        payload = entity["payload"] if isinstance(entity["payload"], Mapping) else {}
        if exclude_seeded_producers and (
            scanner_of(payload) in SEEDED_PRODUCER_SCANNERS or entity.get("job") in SEEDED_PRODUCER_JOBS
        ):
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
        source = SeedSource(scanner_of(payload), rule_of(payload), severity, str(entity["identity"]),
                            "upstream_observation" if exclude_seeded_producers else "current_observation")
        rank = SEVERITY_ORDER.get(severity, _UNKNOWN_RANK)
        for scope_id, relative in owners:
            collected[scope_id].setdefault((relative, start, end), _Accumulator()).add(rank, source)
    return tuple(sorted(outside)), unlocated


def prepare_seeds(run_root: Path, manifests: Iterable[Mapping[str, Any]],
                   scopes: Sequence[SeedScope], *, include_structural_fallbacks: bool = False) -> PreparedSeeds:
    """Read shared evidence once under the caller's admitted read scope; retain only immutable candidates."""
    manifest_list = list(manifests)
    by_path = _scope_paths(scopes)
    collected: dict[str, dict[tuple[str, int, int], _Accumulator]] = {scope.scope_id: {} for scope in scopes}
    outside, unlocated = _ingest_observations(
        run_root, observation_shards(run_root, manifest_list), by_path, collected, exclude_seeded_producers=True)
    fallbacks = (_structural_fallback_seeds(run_root, manifest_list, by_path, [s.scope_id for s in scopes])
                 if include_structural_fallbacks else {})
    observations = tuple((scope_id, tuple(
        Seed(*span, tuple(sorted(value.sources.values(), key=SeedSource.key)[:MAX_SOURCES_PER_SEED]), value.rank)
        for span, value in sorted(found.items()))) for scope_id, found in sorted(collected.items()))
    structural = tuple((key, tuple(values)) for key, values in sorted(fallbacks.items()))
    identity = hashlib.sha256(canonical_json({
        "scopes": _seed_input_identity((), scopes, include_structural_fallbacks),
        "observations": [(key, [asdict(seed) for seed in seeds]) for key, seeds in observations],
        "structural": [(key, [(order, asdict(seed)) for order, seed in values]) for key, values in structural],
        "outside_locations": outside, "unlocated": unlocated,
    })).hexdigest()
    return PreparedSeeds(
        run_root.resolve(), identity, _seed_input_identity(manifest_list, scopes, include_structural_fallbacks),
        observations, structural, outside, unlocated)


def extract_seeds(run_root: Path, manifests: Iterable[Mapping[str, Any]],
                  scopes: Sequence[SeedScope], *, seed_limit: int,
                  extra_observation_shards: Sequence[Mapping[str, Any]] = (),
                  include_structural_fallbacks: bool = False,
                  prepared: PreparedSeeds | None = None) -> SeedPlan:
    """Select shared plus current observations before structural fallbacks, using the same typed budget."""
    if seed_limit < 1:
        raise ValueError("seed_limit must be a positive integer")
    manifest_list = list(manifests)
    if prepared is None:
        prepared = prepare_seeds(run_root, manifest_list, scopes,
                                 include_structural_fallbacks=include_structural_fallbacks)
    elif (prepared.run_root != run_root.resolve() or
          prepared.input_identity != _seed_input_identity(manifest_list, scopes, include_structural_fallbacks)):
        raise SeedIntegrityError("prepared seed inputs differ from the admitted run, manifests or scopes")
    collected: dict[str, dict[tuple[str, int, int], _Accumulator]] = {scope.scope_id: {} for scope in scopes}
    for scope_id, seeds in prepared.observations:
        for seed in seeds:
            value = collected[scope_id].setdefault(seed.key, _Accumulator())
            for source in seed.sources:
                value.add(seed.rank, source)
    extra_shards = _verify_extra_observation_shards(run_root, extra_observation_shards)
    outside, unlocated = _ingest_observations(
        run_root, extra_shards, _scope_paths(scopes), collected, exclude_seeded_producers=False)
    fallbacks = dict(prepared.structural)

    selected: dict[str, ScopeSeeds] = {}
    for scope_id, found in collected.items():
        ranked = sorted(found.items(), key=lambda item: (item[1].rank, item[0]))
        kept = ranked[:seed_limit]
        chosen: dict[tuple[str, int, int], Seed] = {
            (path, start, end): Seed(
                path, start, end,
                tuple(sorted(accumulator.sources.values(), key=SeedSource.key)[:MAX_SOURCES_PER_SEED]),
                accumulator.rank,
            )
            for (path, start, end), accumulator in kept
        }
        if len(chosen) < seed_limit and scope_id in fallbacks:
            for _sort_key, fb_seed in fallbacks[scope_id]:
                if fb_seed.key in chosen:
                    continue
                chosen[fb_seed.key] = fb_seed
                if len(chosen) >= seed_limit:
                    break
        seeds = tuple(chosen[key] for key in sorted(chosen))
        selected[scope_id] = ScopeSeeds(scope_id, seeds, max(len(ranked), len(seeds)), len(ranked) - len(kept))
    return SeedPlan(
        selected, len(set(prepared.outside_locations) | set(outside)), prepared.unlocated + unlocated,
        shared_identity=prepared.identity,
        extra_identity=hashlib.sha256(canonical_json(extra_shards)).hexdigest() if extra_shards else None,
        extra_not_in_database=len(outside), extra_unlocated=unlocated,
        shared_not_in_database=prepared.not_in_database)


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
            "gaps": gaps, "accounting": plan.accounting(scope_seeds.scope_id)}


def skipped_section(*, depth: int, seed_limit: int, scope_seeds: ScopeSeeds, plan: SeedPlan) -> dict[str, Any]:
    """The ``seeded`` object of a scope whose export was not run because nothing seeds it."""
    section = seeded_section(depth=depth, seed_limit=seed_limit, scope_seeds=scope_seeds, plan=plan)
    section["gaps"] = [NO_SEEDS_GAP, *section["gaps"]]
    return section
