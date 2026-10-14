"""Accepted-manifest scope assembly for the inference security review (contract gates 1-2).

``accept_manifest`` resolves the run's accepted index pointer, verifies the producer handoff, the
manifest, every physical shard and each shard's embedded identity through the retrieval verifiers,
and returns an immutable :class:`AcceptedScope`. Any mismatch is an :class:`IntegrityError`; it is
never converted into a gap. The scope's evidence map names available and missing coverage per
producer, components, build units and reference-intelligence freshness. An unavailable producer
is a coverage gap, never evidence that a target is clean.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
import json
from pathlib import Path, PurePosixPath
from typing import Any

from appsec_review.indexing.store import ShardSet, shard_key, shard_summary
from appsec_review.retrieval.core import RetrievalGap, resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.review.identity import make_id
from appsec_review.review.models import Gap, GapClass, IntegrityError
from appsec_review.storage import file_sha256


SCOPE_RULE = "appsec-review/review-scope/1"
GAP_STATES = ("missing", "skipped", "failed", "unavailable", "partial", "stale", "ambiguous", "truncated")
DEPENDENCY_SHARDS = frozenset({"osv_scanner", "grype"})
REFERENCE_QUERY_SETS = ("dependency_advisories", "reference_intelligence")


@dataclass(frozen=True, slots=True)
class ScopeGap:
    """One named coverage gap in the contract's package gap shape."""

    producer: str
    scope: str
    state: str
    reason: str

    def __post_init__(self) -> None:
        if self.state not in GAP_STATES:
            raise ValueError(f"invalid gap state: {self.state}")
        if not self.producer or not self.scope or not self.reason:
            raise ValueError("a gap names its producer, scope and reason")

    @property
    def gap_id(self) -> str:
        return make_id("gap", 1, {"producer": self.producer, "scope": self.scope, "state": self.state,
                                  "reason": self.reason})

    def record(self) -> dict[str, str]:
        return {"gap_id": self.gap_id, "producer": self.producer, "scope": self.scope, "state": self.state,
                "reason": self.reason[:1000]}

    def to_gap(self) -> Gap:
        return Gap(self.gap_id, GapClass.COVERAGE_GAP, f"{self.producer}:{self.scope}", self.reason[:1000])


def sorted_gaps(gaps: Iterable[ScopeGap]) -> tuple[ScopeGap, ...]:
    unique = {gap.gap_id: gap for gap in gaps}
    return tuple(unique[key] for key in sorted(unique))


def _job(shard: Mapping[str, Any]) -> str | None:
    return (shard.get("producer") or {}).get("job")


def _sid(shard: Mapping[str, Any]) -> str:
    return str(shard.get("shard_id", "default"))


def _query_set(shard: Mapping[str, Any]) -> str | None:
    return (shard.get("producer") or {}).get("query_set")


def _is_codeql(shard: Mapping[str, Any]) -> bool:
    return shard["name"] == "observations" and (_job(shard) == "job_codeql_analysis" or _sid(shard).startswith("codeql"))


def _is_ci(shard: Mapping[str, Any]) -> bool:
    return shard["name"] == "observations" and (_job(shard) == "job_ci_configuration_analysis"
                                                 or _sid(shard).startswith("ci_"))


def _is_artifact(shard: Mapping[str, Any]) -> bool:
    return shard["name"] == "observations" and (_job(shard) == "job_artifact_security_analysis"
                                                 or _sid(shard) == "artifact-security")


def _is_dependency(shard: Mapping[str, Any]) -> bool:
    return shard["name"] == "observations" and _sid(shard) in DEPENDENCY_SHARDS


def _is_source_sast(shard: Mapping[str, Any]) -> bool:
    return (shard["name"] == "observations" and
            (_job(shard) == "job_clang_static_analysis" or
             (_job(shard) == "job_evidence_collection" and
              not (_is_dependency(shard) or _is_codeql(shard) or _is_ci(shard) or _is_artifact(shard)))))


def _precomputed(query_set: str) -> Callable[[Mapping[str, Any]], bool]:
    return lambda shard: shard["name"] == "precomputed" and _query_set(shard) == query_set


def _index(name: str, job: str | None = None) -> Callable[[Mapping[str, Any]], bool]:
    return lambda shard: shard["name"] == name and (job is None or _job(shard) in (job, None))


# Producer name -> accepted-shard selector. Lead families and review units name these producers.
PRODUCERS: Mapping[str, Callable[[Mapping[str, Any]], bool]] = {
    "catalog_source": _index("source"),
    "catalog_components": _index("components"),
    "catalog_build": _index("build", "job_target_catalog"),
    "source_sast": _is_source_sast,
    "codeql": _is_codeql,
    "artifact_scanner": _is_artifact,
    "dependency_scanner": _is_dependency,
    "ci_configuration": _is_ci,
    "post_build_hardening": _index("build_security"),
    "review_prioritization": _index("priority"),
    "source_history": _index("history"),
    "security_tagging": _index("tags"),
    "test_coverage": _index("analysis", "job_test_coverage"),
    "profile_data": _index("analysis", "job_profile_data"),
    "dependency_intelligence": _index("inventory", "job_dependency_intelligence"),
    "scanner_correlation": _precomputed("scanner_correlation"),
    "dependency_advisories": _precomputed("dependency_advisories"),
    "reference_intelligence": _precomputed("reference_intelligence"),
    "control_evidence": _precomputed("control_evidence"),
    # Code-graph facts (docs/architecture/code-graph-precomputation.md 7.4): one ``graph`` shard per
    # (CodeQL scope, family); every non-complete (scope, family) coverage row is a named gap here.
    "code_graph": _index("graph", "job_code_graph_index"),
}


@dataclass(frozen=True, slots=True)
class ProducerCoverage:
    producer: str
    state: str                                  # available | partial | stale | missing
    shards: tuple[Mapping[str, Any], ...]
    gaps: tuple[ScopeGap, ...]

    def record(self) -> dict[str, Any]:
        return {"producer": self.producer, "state": self.state,
                "shards": ShardSet.identities(self.shards), "gap_ids": [gap.gap_id for gap in self.gaps]}


@dataclass(frozen=True, slots=True)
class Component:
    component_id: str
    root: str
    identity: str


@dataclass(frozen=True, slots=True)
class BuildUnit:
    build_unit_id: str
    root: str
    identity: str
    languages: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SourceFile:
    path: str
    identity: str
    language: str | None


def _root_of(value: Any) -> str:
    text = str(value or ".").replace("\\", "/").strip("/")
    return "." if text in {"", "."} else str(PurePosixPath(text))


def _under(path: str, root: str) -> bool:
    return root == "." or path == root or path.startswith(root + "/")


def _longest(path: str | None, items: Iterable[Any], key: Callable[[Any], str]) -> Any | None:
    if path is None:
        return None
    matches = [item for item in items if _under(path, key(item))]
    if not matches:
        return None
    return sorted(matches, key=lambda item: (-len(key(item)) if key(item) != "." else 0, key(item),
                                             getattr(item, "identity", "")))[0]


@dataclass(frozen=True, slots=True)
class AcceptedScope:
    """The verified accepted inputs of one review run and their evidence map."""

    run_id: str
    run_root: Path
    manifest_path: Path
    manifest_sha256: str
    target_snapshot: str
    shards: tuple[Mapping[str, Any], ...]
    components: tuple[Component, ...]
    build_units: tuple[BuildUnit, ...]
    source_files: tuple[SourceFile, ...]
    producers: tuple[ProducerCoverage, ...]
    freshness: Mapping[str, str]
    gaps: tuple[ScopeGap, ...]
    _sha: Mapping[tuple[str, str], str] = field(default_factory=dict, repr=False)

    @property
    def store(self) -> ShardSet:
        return ShardSet(self.run_root, self.shards)

    def producer(self, name: str) -> ProducerCoverage:
        for item in self.producers:
            if item.producer == name:
                return item
        raise KeyError(name)

    def shard_sha256(self, shard: Mapping[str, Any]) -> str:
        return self._sha[shard_key(shard)]

    def select(self, predicate: Callable[[Mapping[str, Any]], bool]) -> tuple[Mapping[str, Any], ...]:
        return tuple(shard for shard in self.shards if predicate(shard))

    def component_for(self, path: str | None) -> Component | None:
        return _longest(path, self.components, lambda item: item.root)

    def build_unit_for(self, path: str | None) -> BuildUnit | None:
        return _longest(path, self.build_units, lambda item: item.root)

    def source_for(self, path: str | None) -> SourceFile | None:
        if path is None:
            return None
        for item in self.source_files:
            if item.path == path:
                return item
        return None

    @property
    def index_names(self) -> tuple[str, ...]:
        return tuple(sorted({str(shard["name"]) for shard in self.shards}))

    @property
    def query_sets(self) -> tuple[str, ...]:
        return tuple(sorted({str(_query_set(shard)) for shard in self.shards
                             if shard["name"] == "precomputed" and _query_set(shard)}))

    def verify(self) -> None:
        """Re-hash every accepted shard; called again before packages are published."""
        for shard in self.shards:
            path = (self.run_root / str(shard["relative_path"])).resolve()
            if self.run_root not in path.parents or not path.is_file() or file_sha256(path) != shard["sha256"]:
                raise IntegrityError(f"accepted shard changed during assembly: {shard['name']}/{_sid(shard)}")
        if file_sha256(self.manifest_path) != self.manifest_sha256:
            raise IntegrityError("accepted manifest changed during assembly")

    def evidence_map(self) -> dict[str, Any]:
        """Deterministic map of available and missing coverage; never a clean verdict."""
        languages: dict[str, int] = {}
        for item in self.source_files:
            languages[item.language or "unknown"] = languages.get(item.language or "unknown", 0) + 1
        return {
            "schema": "appsec-review/review-evidence-map/1", "rule": SCOPE_RULE, "run_id": self.run_id,
            "manifest_sha256": self.manifest_sha256, "target_snapshot": self.target_snapshot,
            "producers": [item.record() for item in self.producers],
            "available": sorted(item.producer for item in self.producers if item.state != "missing"),
            "missing": sorted(item.producer for item in self.producers if item.state == "missing"),
            "components": [{"component_id": item.component_id, "root": item.root, "identity": item.identity,
                            "trust_boundary_id": None} for item in self.components],
            "build_units": [{"build_unit_id": item.build_unit_id, "root": item.root, "identity": item.identity,
                             "languages": list(item.languages)} for item in self.build_units],
            "languages": dict(sorted(languages.items())),
            "reference_freshness": dict(sorted(self.freshness.items())),
            "indexes": list(self.index_names), "query_sets": list(self.query_sets),
            "gaps": [gap.record() for gap in self.gaps],
        }


def _verified(run_root: Path, manifest_path: Path | None = None,
              manifest_sha256: str | None = None) -> tuple[Path, str, Mapping[str, Any]]:
    try:
        if manifest_path is None or manifest_sha256 is None:
            manifest_path, accepted_sha = resolve_accepted_manifest(run_root)
        else:
            manifest_path = Path(manifest_path).resolve()
            accepted_sha = manifest_sha256
        manifest, actual = load_verified_manifest(run_root, manifest_path, accepted_sha)
    except (RetrievalGap, ValueError, OSError, json.JSONDecodeError, TypeError) as exc:
        raise IntegrityError(f"accepted index set failed verification: {exc}") from exc
    if actual != accepted_sha:
        raise IntegrityError("accepted manifest hash does not match the accepted pointer")
    if manifest.get("run_id") != run_root.name:
        raise IntegrityError("accepted manifest run isolation mismatch")
    return manifest_path, actual, manifest


def _check_embedded(run_root: Path, shards: Iterable[Mapping[str, Any]], snapshot: str) -> None:
    for shard in shards:
        try:
            summary = shard_summary(run_root, shard)
        except Exception as exc:  # unreadable shard content is an integrity failure
            raise IntegrityError(f"accepted shard is unreadable: {shard['name']}/{_sid(shard)}") from exc
        if not summary["counts_agree"]:
            raise IntegrityError(f"accepted shard row counts contradict its metadata: {shard['name']}/{_sid(shard)}")
        if summary["target_snapshot"] != snapshot:
            raise IntegrityError(f"accepted shard snapshot mismatch: {shard['name']}/{_sid(shard)}")


def _coverage(store: ShardSet, name: str, shards: tuple[Mapping[str, Any], ...]) -> ProducerCoverage:
    if not shards:
        gap = ScopeGap(name, "run", "missing", f"no accepted {name} shard in the accepted index set; "
                                               "its coverage is unknown, not clean")
        return ProducerCoverage(name, "missing", (), (gap,))
    gaps: list[ScopeGap] = []
    stale = False
    for row in store.coverage(shards):
        if row["status"] == "complete":
            continue
        stale = stale or row["status"] == "stale"
        state = {"stale": "stale", "unavailable": "unavailable"}.get(row["status"], "partial")
        gaps.append(ScopeGap(name, f"{row['index']}/{row['shard_id']}:{row['area']}", state,
                             str(row["gap"] or f"coverage {row['status']} without a published reason")))
    published = {gap.reason for gap in gaps}
    for shard in shards:
        for text in shard.get("gaps", ()):
            if str(text) in published:
                continue
            stale = stale or str(text).startswith("stale")
            gaps.append(ScopeGap(name, f"{shard['name']}/{_sid(shard)}", "stale" if str(text).startswith("stale")
                                 else "partial", str(text)))
    ordered = sorted_gaps(gaps)
    return ProducerCoverage(name, "stale" if stale else "partial" if ordered else "available", shards, ordered)


def accept_manifest(run_root: Path, *, manifest_path: Path | None = None,
                    manifest_sha256: str | None = None) -> AcceptedScope:
    """Verify the run's accepted index set and build its evidence map (gates 1 and 2)."""
    run_root = Path(run_root).resolve()
    manifest_path, manifest_sha, manifest = _verified(run_root, manifest_path, manifest_sha256)
    snapshot = str(manifest.get("target_snapshot", ""))
    shards = tuple(sorted((dict(item) for item in manifest.get("indexes", ())), key=shard_key))
    _check_embedded(run_root, shards, snapshot)
    store = ShardSet(run_root, shards)
    producers = tuple(_coverage(store, name, tuple(shard for shard in shards if select(shard)))
                      for name, select in sorted(PRODUCERS.items()))
    by_name = {item.producer: item for item in producers}

    components = sorted({Component(str(row["native_id"]), _root_of(row["payload"].get("root")), row["identity"])
                         for row in store.entities(by_name["catalog_components"].shards, kinds=("component",))},
                        key=lambda item: (item.component_id, item.identity))
    units: dict[str, BuildUnit] = {}
    for row in store.entities(by_name["catalog_build"].shards, kinds=("build_action",)):
        unit_id = row["payload"].get("build_unit_id")
        if not isinstance(unit_id, str) or not unit_id:
            continue
        languages = row["payload"].get("languages") or ()
        candidate = BuildUnit(unit_id, _root_of(row["payload"].get("root")), row["identity"],
                              tuple(sorted(str(item) for item in languages)))
        if unit_id in units and units[unit_id] != candidate:
            raise IntegrityError(f"accepted build catalog declares build unit {unit_id} twice")
        units[unit_id] = candidate
    sources: dict[str, SourceFile] = {}
    for row in store.entities(by_name["catalog_source"].shards, kinds=("source_file",)):
        path = (row["location"] or {}).get("path") or row["payload"].get("path") or row["native_id"]
        language = row["payload"].get("language")
        sources.setdefault(str(path), SourceFile(str(path), row["identity"],
                                                 str(language) if language else None))

    freshness = {name: by_name[name].state for name in REFERENCE_QUERY_SETS}
    gaps: list[ScopeGap] = [gap for item in producers for gap in item.gaps]
    if not components:
        gaps.append(ScopeGap("catalog_components", "run", "unavailable",
                             "no accepted component entity; hunts are scoped to the unassigned component"))
    if not units:
        gaps.append(ScopeGap("catalog_build", "run", "unavailable",
                             "no accepted build unit; hunts are not partitioned by build unit"))
    return AcceptedScope(
        run_id=run_root.name, run_root=run_root, manifest_path=manifest_path, manifest_sha256=manifest_sha,
        target_snapshot=snapshot, shards=shards, components=tuple(components),
        build_units=tuple(units[key] for key in sorted(units)),
        source_files=tuple(sources[key] for key in sorted(sources)), producers=producers,
        freshness=freshness, gaps=sorted_gaps(gaps),
        _sha={shard_key(shard): str(shard["sha256"]) for shard in shards})
