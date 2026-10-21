"""First-stage precomputed query sets over accepted shards, links and pinned reference feeds.

Each product reads only accepted, hash-pinned inputs and publishes bounded ``precomputed_fact``
records with a coverage row named for its query set. A missing producer or input yields a scoped
``unavailable`` row and no facts; an incomplete input yields ``partial`` with named gaps. An empty
result is never published as a clean one. No product executes target code or a scanner.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sqlite3
from typing import Any
from urllib.parse import unquote

from appsec_review.indexing.derive import Derived, fact
from appsec_review.indexing.links import (
    ARTIFACT_KINDS, CATALOG, REDACTED, advisory_identity, advisory_pairs, catalog_sources, package_identity,
    LinkContext,
)
from appsec_review.indexing.store import ShardSet, digest
from appsec_review.retrieval.model import RelationKind, RelationRecord
from appsec_review.retrieval.precomputed import QUERY_SETS, RETIRED_GRAPH_SETS
from appsec_review.storage import file_sha256


FIRST_STAGE_SETS = (
    "build_provenance", "artifact_inventory", "dependency_advisories", "scanner_correlation", "ci_trust",
    "history_context", "control_evidence", "reference_intelligence", "symbol_links", "document_context",
)
_CWE = re.compile(r"(?i)\bcwe[-_/ ]?0*(\d{1,5})\b")
# A pinned reference feed older than its freshness bound makes the whole product's coverage stale.
_STALE_GAP = re.compile(r"^(?:[a-z]+_)?stale_feed:")


@dataclass(frozen=True, slots=True)
class ProductContext:
    run_root: Path
    snapshot: str
    shards: ShardSet                       # accepted shards plus this attempt's link shards
    links: Mapping[str, Mapping[str, Any]]  # link family -> shard identity
    feeds: Mapping[str, Mapping[str, Any]]
    owasp: Mapping[str, Any]
    max_facts: int
    rule_version: str = ""

    @property
    def link_context(self) -> LinkContext:
        return LinkContext(self.snapshot, self.shards, self.max_facts)


@dataclass(frozen=True, slots=True)
class ProductRule:
    query_set: str
    version: str
    select: Callable[[ShardSet], tuple[Mapping[str, Any], ...]]
    build: Callable[[ProductContext, tuple[Mapping[str, Any], ...]], Derived]
    links: tuple[str, ...] = ()
    feeds: tuple[str, ...] = ()
    owasp: bool = False


def _upstream(selected: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    return ShardSet.identities(selected)[:16]


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value and value != REDACTED else None


def _coverage_gaps(shards: ShardSet, selected: Sequence[Mapping[str, Any]], limit: int = 15) -> list[str]:
    gaps: list[str] = []
    for row in shards.coverage(selected):
        if row["status"] != "complete":
            gaps.append(f"{row['index']}/{row['shard_id']}: {row['area']}: {row['status']}: "
                        f"{str(row['gap'] or 'no reason published')[:200]}")
    return list(dict.fromkeys(gaps))[:limit]


def _finish(derived: Derived, query_set: str, *, unavailable: str | None = None) -> Derived:
    """Attach the query-set coverage row; zero facts is never reported as complete."""
    if unavailable is not None:
        derived.entities.clear()
        derived.relations.clear()
        derived.gap(unavailable)
        derived.coverage.append((query_set, "unavailable", unavailable))
    elif not derived.entities:
        reason = "; ".join(derived.gaps[:5]) or "accepted inputs contained no subject for this query set"
        derived.gap(f"no {query_set} fact was derivable: {reason}"[:400])
        derived.coverage.append((query_set, "partial", derived.gaps[-1]))
    else:
        stale = [gap for gap in derived.gaps if _STALE_GAP.match(gap)]
        gaps = [*stale, *(gap for gap in derived.gaps if gap not in stale)]
        derived.coverage.append((query_set, "stale" if stale else "partial" if derived.gaps else "complete",
                                 "; ".join(gaps[:5])[:1000] or None))
    derived.count("facts", len(derived.entities))
    return derived


def _link_shard(context: ProductContext, family: str) -> tuple[Mapping[str, Any], ...]:
    shard = context.links.get(family)
    return (shard,) if shard is not None else ()


# --- artifact inventory ---------------------------------------------------------------------------------

def _select_artifact_inventory(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return (*shards.select(index="artifacts"), *shards.select(index="build", job=CATALOG))


def _build_units(shards: ShardSet) -> dict[str, str]:
    return {row["native_id"]: row["identity"]
            for row in shards.entities(shards.select(index="build", job=CATALOG), kinds=("build_action",))}


def _build_artifact_inventory(context: ProductContext, selected: tuple[Mapping[str, Any], ...]) -> Derived:
    derived, shards, name = Derived(), context.shards, "artifact_inventory"
    catalogs = shards.select(index="artifacts", prefix="catalog-")
    if not catalogs:
        return _finish(derived, name, unavailable="artifact index is unavailable: no accepted "
                                                  "job_artifact_indexing catalog shards")
    units = _build_units(shards)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in shards.entities(catalogs, kinds=ARTIFACT_KINDS):
        grouped[str(row["payload"].get("build_unit_id") or "unknown")].append(row)
    members: dict[str, int] = defaultdict(int)
    for relation in shards.relations(shards.select(index="artifacts", prefix="members-"),
                                     kinds=(RelationKind.CONTAINS.value,)):
        members[relation["source_id"]] += 1
    coverage_gaps = _coverage_gaps(shards, shards.select(index="artifacts"))
    for unit in sorted(grouped)[:context.max_facts]:
        rows = sorted(grouped[unit], key=lambda row: row["identity"])
        families: dict[str, int] = defaultdict(int)
        formats: dict[str, int] = defaultdict(int)
        for row in rows:
            families[row["kind"]] += 1
            formats[str(row["payload"].get("kind") or "unknown")] += 1
        unrecognized = families.get("build_artifact", 0)
        gaps = [f"unrecognized_format: {unrecognized} artifact(s) have no specific artifact family"] \
            if unrecognized else []
        derived.entities.append(fact(
            context.snapshot, name, context.rule_version, {"build_unit": unit},
            name=f"artifact inventory {unit}", text=f"artifact inventory build unit {unit} " + " ".join(sorted(formats)),
            subject_identity=units.get(unit), status="partial" if gaps else "complete", gaps=gaps,
            basis="accepted artifact catalog and archive-member shards", upstream=_upstream(catalogs),
            result={"build_unit_id": unit, "artifact_count": len(rows), "by_family": dict(sorted(families.items())),
                    "by_format": dict(sorted(formats.items())),
                    "archive_member_count": sum(members.get(row["identity"], 0) for row in rows),
                    "artifacts": [{"identity": row["identity"], "name": row["name"], "kind": row["kind"],
                                   "format": row["payload"].get("kind"), "sha256": row["payload"].get("sha256"),
                                   "size_bytes": row["payload"].get("size_bytes")} for row in rows[:40]],
                    "artifacts_truncated": max(0, len(rows) - 40)}))
    if len(grouped) > context.max_facts:
        derived.gap(f"truncated: {len(grouped) - context.max_facts} build unit(s) exceeded the fact bound")
    for unit in sorted(set(units) - set(grouped))[:10]:
        derived.gap(f"build unit {unit}: no produced artifact was catalogued")
    for gap in coverage_gaps:
        derived.gap(gap)
    return _finish(derived, name)


# --- build provenance -----------------------------------------------------------------------------------

def _select_build_provenance(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return (*shards.select(index="artifacts"), *shards.select(index="build"), *shards.select(index="build_security"),
            *shards.select(index="observations", prefix="artifact-security"),
            *shards.select(index="source", job=CATALOG))


def _build_build_provenance(context: ProductContext, selected: tuple[Mapping[str, Any], ...]) -> Derived:
    derived, shards, name = Derived(), context.shards, "build_provenance"
    catalogs = shards.select(index="artifacts", prefix="catalog-")
    if not catalogs:
        return _finish(derived, name, unavailable="build provenance is unavailable: no accepted artifact catalog "
                                                  "shards to anchor a source/build/artifact chain")
    link_shards = _link_shard(context, "representation")
    generated: dict[str, list[dict[str, Any]]] = defaultdict(list)
    compiles: dict[str, list[str]] = defaultdict(list)
    links_into: dict[str, list[str]] = defaultdict(list)
    for relation in shards.relations((*shards.select(index="artifacts"), *shards.select(index="build")), kinds=(
            RelationKind.GENERATED_FROM.value, RelationKind.COMPILES_TO.value, RelationKind.LINKS_INTO.value)):
        if relation["kind"] == RelationKind.GENERATED_FROM.value:
            generated[relation["source_id"]].append(relation)
        elif relation["kind"] == RelationKind.COMPILES_TO.value:
            compiles[relation["target_id"]].append(relation["source_id"])
        else:
            links_into[relation["target_id"]].append(relation["source_id"])
    same_as: dict[str, list[dict[str, Any]]] = defaultdict(list)
    equivalent: dict[str, str] = {}
    for relation in shards.relations(link_shards, kinds=(RelationKind.SAME_AS.value,)):
        same_as[relation["target_id"]].append(relation)
        if relation["exact"]:
            equivalent[relation["source_id"]] = relation["target_id"]
    observed: dict[str, list[str]] = defaultdict(list)
    for relation in shards.relations(shards.select(index="observations", prefix="artifact-security"),
                                     kinds=(RelationKind.OBSERVED_AT.value,)):
        observed[relation["target_id"]].append(relation["source_id"])
    catalog_ids = set(catalog_sources(context.link_context)[0].values())

    def sources_of(artifact: str) -> tuple[list[str], int]:
        found: list[str] = []
        frontier, seen = [artifact], {artifact}
        for _depth in range(4):
            following: list[str] = []
            for current in frontier:
                for unit in compiles.get(current, ()):
                    for relation in generated.get(unit, ()):
                        source = equivalent.get(relation["target_id"], relation["target_id"])
                        if source in catalog_ids and source not in found:
                            found.append(source)
                for linked in links_into.get(current, ()):
                    if linked not in seen:
                        seen.add(linked)
                        following.append(linked)
            frontier = following
            if not frontier:
                break
        return sorted(found)[:20], max(0, len(found) - 20)

    rows = list(shards.entities(catalogs, kinds=ARTIFACT_KINDS, limit=context.max_facts + 1))
    if len(rows) > context.max_facts:
        rows = rows[:context.max_facts]
        derived.gap(f"truncated: artifact fact bound of {context.max_facts} reached")
    for row in rows:
        identity = row["identity"]
        representations = sorted(same_as.get(identity, ()), key=lambda item: item["source_id"])
        actions = sorted(generated.get(identity, ()), key=lambda item: (-item["confidence"], item["target_id"]))
        sources: list[str] = []
        truncated_sources = 0
        for candidate in [identity, *(item["source_id"] for item in representations if item["exact"])]:
            values, extra = sources_of(candidate)
            sources.extend(value for value in values if value not in sources)
            truncated_sources += extra
        observations = sorted(set(observed.get(identity, ())))
        gaps: list[str] = []
        if not actions:
            gaps.append("missing_capture: no producing build action was attributed to this artifact")
        elif not any(item["exact"] for item in actions):
            gaps.append("ambiguous_producing_action: the receipt did not attribute the artifact to a unique action")
        if not sources:
            gaps.append("missing_source_map: no exact compile-unit to source chain reaches this artifact")
        gaps.append("exact build argv and environment are protected; only command hashes are published")
        fact_record = fact(
            context.snapshot, name, context.rule_version, {"artifact": identity},
            name=f"build provenance {row['name']}",
            text=f"build provenance {row['name']} {row['payload'].get('kind')} {row['payload'].get('build_unit_id')}",
            subject_identity=identity, status="partial" if len(gaps) > 1 else "complete", gaps=gaps,
            basis="accepted GENERATED_FROM, COMPILES_TO and LINKS_INTO relations joined through exact "
                  "representation links", upstream=_upstream((*catalogs, *link_shards)),
            result={"artifact": {"identity": identity, "name": row["name"], "kind": row["kind"],
                                 "build_unit_id": row["payload"].get("build_unit_id"),
                                 "sha256": row["payload"].get("sha256")},
                    "producing_actions": [{"identity": item["target_id"], "exact": item["exact"],
                                           "confidence": item["confidence"], "ambiguity": item["ambiguity"]}
                                          for item in actions[:8]],
                    "producing_actions_truncated": max(0, len(actions) - 8),
                    "representations": [{"identity": item["source_id"], "exact": item["exact"],
                                         "mapping_method": item["payload"].get("mapping_method"),
                                         "confidence": item["confidence"]} for item in representations[:8]],
                    "sources": sources[:20], "sources_truncated": truncated_sources,
                    "link_input_count": len(links_into.get(identity, ())),
                    "observations": observations[:8], "observation_count": len(observations)})
        derived.entities.append(fact_record)
        for target in (*sources[:20], *observations[:8]):
            derived.relations.append(RelationRecord(RelationKind.DERIVED_FROM, fact_record.identity.value, target,
                                                    True, 1.0, None, {"query_set": name}))
    for gap in _coverage_gaps(shards, link_shards, 5):
        derived.gap(gap)
    return _finish(derived, name)


# --- dependency advisories and reference intelligence -----------------------------------------------------

def _feed_database(context: ProductContext, feed: str, logical: str) -> tuple[sqlite3.Connection | None, str | None]:
    pin = context.feeds.get(feed) or {}
    if pin.get("status") != "pinned":
        return None, f"{feed} feed is unavailable: {pin.get('reason', 'no pinned snapshot')}"
    path = Path(str(pin["directory"])) / logical
    expected = (pin.get("files") or {}).get(logical)
    if not path.is_file() or expected is None or file_sha256(path) != expected:
        return None, f"{feed} feed identity mismatch for {logical}"
    database = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
    database.row_factory = sqlite3.Row
    return database, None


def _feed_reference(context: ProductContext, feed: str) -> dict[str, Any]:
    pin = context.feeds.get(feed) or {}
    return {key: pin.get(key) for key in ("feed_id", "status", "snapshot_id", "manifest_sha256", "published_at",
                                          "stale", "reason")}


def _select_dependency_advisories(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return (*shards.select(index="observations", job="job_evidence_collection"),
            *shards.select(index="observations", job="job_artifact_security_analysis"),
            *shards.select(index="inventory", job="job_dependency_intelligence"))


_PURL_OSV_ECOSYSTEM = {
    "cargo": "crates.io", "composer": "Packagist", "gem": "RubyGems", "golang": "Go",
    "maven": "Maven", "npm": "npm", "nuget": "NuGet", "pypi": "PyPI",
}


def _purl_osv_identity(purl: object, fallback_name: object) -> tuple[str | None, str | None, str]:
    """Map a bounded Package URL to OSV ecosystem/name, retaining name-only fallback uncertainty."""
    fallback = str(fallback_name).strip()[:512] if fallback_name is not None else ""
    if not isinstance(purl, str) or not purl.startswith("pkg:") or len(purl) > 4096:
        return None, fallback or None, "name-only"
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    package_type, separator, path = body.partition("/")
    if not separator or package_type.casefold() not in _PURL_OSV_ECOSYSTEM:
        return None, fallback or None, "unsupported-purl-type"
    # The version delimiter is the final literal @. Encoded npm scopes therefore remain intact.
    path = path.rsplit("@", 1)[0]
    parts = [unquote(item) for item in path.split("/") if item]
    if not parts:
        return None, fallback or None, "malformed-purl"
    kind = package_type.casefold()
    if kind == "maven" and len(parts) >= 2:
        name = f"{parts[-2]}:{parts[-1]}"
    elif kind == "golang":
        name = "/".join(parts)
    elif kind == "npm" and len(parts) >= 2 and parts[-2].startswith("@"):
        name = f"{parts[-2]}/{parts[-1]}"
    else:
        name = parts[-1]
    return _PURL_OSV_ECOSYSTEM[kind], name[:512], "purl-ecosystem-and-name"


def _inventory_advisory_pairs(database: sqlite3.Connection, dependencies: Sequence[Mapping[str, Any]], *,
                              max_pairs: int) -> tuple[list[dict[str, Any]], list[tuple[str, str, str | None]],
                                                       list[str]]:
    """Attempt bounded OSV package lookup for every heuristic/normalized dependency entity."""
    pairs: list[dict[str, Any]] = []
    coverage: list[tuple[str, str, str | None]] = []
    gaps: list[str] = []
    for row in dependencies:
        identity = str(row.get("identity", ""))
        payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
        ecosystem, lookup_name, identity_basis = _purl_osv_identity(payload.get("purl"), payload.get("name"))
        area = f"dependency-advisory-lookup:{identity}"
        if not lookup_name:
            reason = "dependency identity has no package name usable for OSV lookup"
            coverage.append((area, "unavailable", reason))
            gaps.append(f"unresolved_dependency_identity: {identity}: {reason}")
            continue
        remaining = max_pairs - len(pairs)
        if remaining <= 0:
            gaps.append(f"truncated: dependency inventory advisory pairs exceeded {max_pairs}")
            coverage.append((area, "unavailable", "dependency advisory pair bound exhausted"))
            continue
        if ecosystem:
            records = database.execute(
                "SELECT DISTINCT p.advisory_id, p.ecosystem, p.name FROM package p "
                "WHERE p.ecosystem=? AND p.name=? COLLATE NOCASE ORDER BY p.advisory_id LIMIT ?",
                (ecosystem, lookup_name, remaining + 1),
            ).fetchall()
        else:
            records = database.execute(
                "SELECT DISTINCT p.advisory_id, p.ecosystem, p.name FROM package p "
                "WHERE p.name=? COLLATE NOCASE ORDER BY p.ecosystem, p.advisory_id LIMIT ?",
                (lookup_name, remaining + 1),
            ).fetchall()
        truncated = len(records) > remaining
        records = records[:remaining]
        uncertainty = ("version applicability is not evaluated by the feed index" if ecosystem else
                       "ecosystem and version applicability are unresolved for name-only lookup")
        coverage.append((area, "partial" if records or not ecosystem else "complete",
                         uncertainty if records or not ecosystem else None))
        if truncated:
            gaps.append(f"truncated: {identity}: OSV package matches exceeded remaining pair bound {remaining}")
        for advisory, matched_ecosystem, matched_name in records:
            pairs.append({
                "package": str(payload.get("name") or matched_name),
                "version": _text(payload.get("version")), "purl": _text(payload.get("purl")),
                "advisory": str(advisory), "severity": None,
                "scanner": "dependency-intelligence-osv-lookup", "observation": identity,
                "dependency_identity": identity, "lookup_basis": "dependency-inventory-osv-lookup",
                "osv_ecosystem": str(matched_ecosystem), "osv_package_name": str(matched_name),
                "identity_basis": identity_basis, "applicability_verified": False,
                "maximal_exposure": payload.get("maximal_exposure"),
                "resolution_basis": payload.get("resolution_basis"),
            })
    return pairs, coverage, gaps


def _fixed_versions(raw: str, package: str) -> list[str]:
    try:
        document = json.loads(raw)
    except ValueError:
        return []
    found: list[str] = []
    for affected in document.get("affected", ()) if isinstance(document, Mapping) else ():
        if not isinstance(affected, Mapping) or (affected.get("package") or {}).get("name") != package:
            continue
        for value in affected.get("ranges", ()):
            for event in value.get("events", ()) if isinstance(value, Mapping) else ():
                if isinstance(event, Mapping) and isinstance(event.get("fixed"), str):
                    found.append(event["fixed"][:64])
    return sorted(set(found))[:5]


_CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
CVSS_VERSION_PREFERENCE = ("4.0", "3.1", "3.0", "2.0")
REFERENCE_FEEDS = ("osv", "nvd", "kev", "epss")
REFERENCE_FEED_FILES = {"osv": "index/osv.sqlite", "nvd": "index/nvd.sqlite", "kev": "index/kev.sqlite",
                        "epss": "index/epss.sqlite"}
_MAX_CVES = 4


def advisory_cve_ids(advisory: str, aliases: Sequence[str]) -> list[str]:
    """CVE ids of an advisory: the advisory id itself when it is a CVE, then its OSV aliases."""
    found = [advisory] if _CVE_ID.fullmatch(advisory) else []
    found.extend(item for item in aliases if isinstance(item, str) and _CVE_ID.fullmatch(item))
    return sorted(set(found))


def preferred_cvss(metrics: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    """The NVD metric to band by: CVSS v4.0, then v3.1, then v3.0, then v2; primary source first."""
    ranked = [item for item in metrics if isinstance(item, Mapping) and isinstance(item.get("base_score"), (int, float))
              and str(item.get("version")) in CVSS_VERSION_PREFERENCE]
    ranked.sort(key=lambda item: (CVSS_VERSION_PREFERENCE.index(str(item["version"])),
                                  0 if "Primary" in str(item.get("family") or "") else 1,
                                  -float(item["base_score"]), str(item.get("vector"))))
    return ranked[0] if ranked else None


def _reference_joins(context: ProductContext, databases: Mapping[str, sqlite3.Connection | None],
                     feed_gaps: Mapping[str, str | None], cve_ids: Sequence[str]) -> tuple[dict[str, Any], list[str]]:
    """Join CVE ids to the pinned NVD, KEV and EPSS indexes; every miss is a named per-join gap."""
    from appsec_review.jobs.job_third_party_data_sync.steps.epss_sync.feed import lookup as epss_lookup
    from appsec_review.jobs.job_third_party_data_sync.steps.kev_sync.feed import lookup as kev_lookup
    from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.index import lookup as nvd_lookup
    gaps: list[str] = []
    joined: dict[str, Any] = {"nvd": [], "kev": [], "epss": []}
    status: dict[str, str] = {}
    selected = list(cve_ids)[:_MAX_CVES]
    if len(cve_ids) > _MAX_CVES:
        gaps.append(f"truncated: {len(cve_ids) - _MAX_CVES} CVE alias(es) beyond the per-advisory bound")
    for feed, lookup in (("nvd", nvd_lookup), ("kev", kev_lookup), ("epss", epss_lookup)):
        database = databases.get(feed)
        if not selected:
            status[feed] = "no_cve_identity"
            continue
        if database is None:
            status[feed] = "unavailable"
            gaps.append(f"{feed}_feed_unavailable: {feed_gaps.get(feed)}")
            continue
        status[feed] = "joined"
        if (context.feeds.get(feed) or {}).get("stale"):
            status[feed] = "stale"
            gaps.append(f"{feed}_stale_feed: the pinned {feed.upper()} snapshot is older than the configured "
                        "freshness bound")
        for cve in selected:
            record = lookup(database, cve)
            if feed == "kev":
                joined["kev"].append({"cve_id": cve, "listed": record is not None,
                                      **({key: record[key] for key in ("date_added", "due_date",
                                                                       "known_ransomware_use", "vulnerability_name",
                                                                       "catalog_version")} if record else {})})
                continue
            if record is None:
                gaps.append(f"{feed}_identity_mismatch: {cve} is not present in the pinned {feed.upper()} snapshot")
                continue
            if feed == "epss":
                joined["epss"].append({key: record[key] for key in ("cve_id", "epss", "percentile", "score_date",
                                                                    "model_version")})
                continue
            if str(record.get("status") or "").lower() == "rejected":
                gaps.append(f"nvd_rejected_cve: {cve} is Rejected in the pinned NVD snapshot")
            joined["nvd"].append({"cve_id": cve, "status": record["status"], "published": record["published"],
                                  "last_modified": record["last_modified"],
                                  "description": (record["description_en"] or "")[:512] or None,
                                  "cwes": list(record["weaknesses"])[:8], "cvss": list(record["cvss"])[:6],
                                  "raw_sha256": record["raw_sha256"]})
    listed = [item["listed"] for item in joined["kev"]]
    percentiles = [float(item["percentile"]) for item in joined["epss"]]
    cvss = [metric for item in joined["nvd"] for metric in item["cvss"]]
    preferred = preferred_cvss(cvss)
    summary = {"cve_ids": list(selected),
               "kev_listed": True if any(listed) else (False if listed and status.get("kev") != "unavailable"
                                                       else None),
               "epss_max_percentile": max(percentiles) if percentiles else None,
               "max_cvss": max((float(item["base_score"]) for item in cvss
                                if isinstance(item.get("base_score"), (int, float))), default=None),
               "preferred_cvss": dict(preferred) if preferred else None}
    return {**joined, "join_status": status, "summary": summary}, gaps


def _build_dependency_advisories(context: ProductContext, selected: tuple[Mapping[str, Any], ...]) -> Derived:
    derived, shards, name = Derived(), context.shards, "dependency_advisories"
    scanners = [shard for shard in selected if shard.get("shard_id") in {"osv_scanner", "grype", "syft",
                                                                           "artifact-security"}]
    dependencies = [shard for shard in selected
                    if shard.get("producer", {}).get("job") == "job_dependency_intelligence"]
    if not scanners and not dependencies:
        return _finish(derived, name, unavailable="dependency advisories are unavailable: no accepted dependency "
                                                  "scanner or intelligence shards")
    databases: dict[str, sqlite3.Connection | None] = {}
    feed_gaps: dict[str, str | None] = {}
    for feed_name in REFERENCE_FEEDS:
        databases[feed_name], feed_gaps[feed_name] = _feed_database(context, feed_name, REFERENCE_FEED_FILES[feed_name])
    database, feed_gap = databases["osv"], feed_gaps["osv"]
    feed = _feed_reference(context, "osv")
    references = {feed_name: _feed_reference(context, feed_name) for feed_name in REFERENCE_FEEDS}
    grouped: dict[tuple[str, str | None, str | None, str], dict[str, Any]] = {}
    for row in shards.entities(scanners, kinds=("tool_observation",)):
        for pair in advisory_pairs(row):
            key = (pair["package"], pair["version"], pair["purl"], pair["advisory"])
            entry = grouped.setdefault(key, {**pair, "observations": [], "scanners": set(), "location": None,
                                             "lookup_bases": set(), "dependency_identities": set(),
                                             "inventory_context": []})
            entry["observations"].append(row["identity"])
            entry["scanners"].add(pair["scanner"] or row["shard_id"])
            entry["lookup_bases"].add("scanner-reported-match")
            entry["location"] = entry["location"] or row["location"]
    dependency_rows = list(shards.entities(dependencies, kinds=("dependency_package",)))
    if database is not None:
        inventory_pairs, lookup_coverage, lookup_gaps = _inventory_advisory_pairs(
            database, dependency_rows, max_pairs=context.max_facts)
        derived.coverage.extend(lookup_coverage)
        derived.gaps.extend(lookup_gaps)
        for pair in inventory_pairs:
            key = (pair["package"], pair["version"], pair["purl"], pair["advisory"])
            entry = grouped.setdefault(key, {**pair, "observations": [], "scanners": set(), "location": None,
                                             "lookup_bases": set(), "dependency_identities": set(),
                                             "inventory_context": []})
            entry["observations"].append(pair["observation"])
            entry["scanners"].add(pair["scanner"])
            entry["lookup_bases"].add(pair["lookup_basis"])
            entry["dependency_identities"].add(pair["dependency_identity"])
            entry["inventory_context"].append({key_name: pair.get(key_name) for key_name in (
                "dependency_identity", "identity_basis", "osv_ecosystem", "osv_package_name",
                "applicability_verified", "maximal_exposure", "resolution_basis")})
    elif dependency_rows:
        derived.gap(f"feed_unavailable: {feed_gap}; {len(dependency_rows)} dependency inventory row(s) "
                    "could not be checked against OSV")
    try:
        for key in sorted(grouped, key=lambda item: tuple(str(part) for part in item))[:context.max_facts]:
            entry = grouped[key]
            package, version, purl, advisory = key
            scanner_reported = "scanner-reported-match" in entry["lookup_bases"]
            versioned = bool(version or purl) and scanner_reported
            gaps = [] if versioned else (["missing_version: the scanner reported a package name only"]
                                         if scanner_reported else [])
            if "dependency-inventory-osv-lookup" in entry["lookup_bases"] and not scanner_reported:
                gaps.append("applicability_unverified: dependency identity matched an OSV package, but this "
                            "index does not evaluate whether the observed version is in an affected range")
            intelligence: dict[str, Any] = {"feed": feed, "advisory_known": None, "aliases": []}
            if database is None:
                gaps.append(f"feed_unavailable: {feed_gap}")
            else:
                record = database.execute("SELECT id, summary, modified, published, withdrawn, raw_json FROM advisory "
                                          "WHERE id = ?", (advisory,)).fetchone()
                if record is None:
                    gaps.append("identity_mismatch: advisory is not present in the pinned OSV snapshot")
                    intelligence["advisory_known"] = False
                else:
                    listed = database.execute("SELECT 1 FROM package WHERE advisory_id = ? AND name = ? LIMIT 1",
                                              (advisory, package)).fetchone() is not None
                    intelligence.update({
                        "advisory_known": True, "summary": str(record["summary"] or "")[:512],
                        "modified": record["modified"], "published": record["published"],
                        "withdrawn": record["withdrawn"], "package_listed": listed,
                        "aliases": [str(item[0])[:64] for item in database.execute(
                            "SELECT alias FROM alias WHERE advisory_id = ? ORDER BY alias LIMIT 10", (advisory,))],
                        "fixed_versions": _fixed_versions(str(record["raw_json"] or ""), package)})
                    if not listed:
                        gaps.append("uncertain_package_identity: the pinned advisory does not list this package name")
                if feed.get("stale"):
                    gaps.append("stale_feed: the pinned OSV snapshot is older than the configured freshness bound")
            cve_ids = advisory_cve_ids(advisory, intelligence["aliases"])
            if not cve_ids:
                gaps.append("no_cve_identity: neither the advisory id nor its OSV aliases name a CVE; NVD, KEV "
                            "and EPSS were not joined")
            joins, join_gaps = _reference_joins(context, databases, feed_gaps, cve_ids)
            gaps.extend(join_gaps)
            # The joins sit at the top of ``result`` so that nested CVSS metrics stay within the
            # shard payload depth bound (retrieval sanitizes deeper values to "<truncated>").
            reference = {"cve_ids": cve_ids, "nvd": joins["nvd"], "kev": joins["kev"], "epss": joins["epss"],
                         "join_status": joins["join_status"], "reference_summary": joins["summary"],
                         "feeds": references}
            subject = (sorted(entry["dependency_identities"])[0] if entry["dependency_identities"] else
                       package_identity(context.snapshot, package, version, purl).value)
            lookup_bases = sorted(entry["lookup_bases"])
            record_fact = fact(
                context.snapshot, name, context.rule_version,
                {"package": package, "version": version, "purl": purl, "advisory": advisory},
                name=f"{package} {advisory}", text=f"dependency advisory {package} {version or ''} {advisory}",
                subject_identity=subject, location=entry["location"], status="partial" if gaps else "complete",
                gaps=gaps, basis="accepted scanner match and/or dependency-inventory package identity joined to "
                                 "the pinned OSV snapshot and, by CVE id from the advisory id or its OSV aliases, "
                                 "to pinned NVD, KEV and EPSS snapshots; inventory lookup does not evaluate version "
                                 "applicability and every joined record is reference context, never target evidence",
                upstream=_upstream((*scanners, *dependencies, *_link_shard(context, "package_advisory"))),
                result={"package": package, "version": version, "purl": purl, "advisory": advisory,
                        "advisory_identity": advisory_identity(context.snapshot, advisory).value,
                        "severity": entry["severity"], "scanners": sorted(str(item) for item in entry["scanners"]),
                        "match_exact": versioned, "lookup_bases": lookup_bases,
                        "applicability_verified": scanner_reported,
                        "dependency_inventory": entry["inventory_context"][:8],
                        "observations": sorted(set(entry["observations"]))[:8],
                        "observation_count": len(set(entry["observations"])), "intelligence": intelligence,
                        **reference})
            derived.entities.append(record_fact)
            for observation in sorted(set(entry["observations"]))[:8]:
                derived.relations.append(RelationRecord(RelationKind.DERIVED_FROM, record_fact.identity.value,
                                                        observation, True, 1.0, None, {"query_set": name}))
    finally:
        for connection in databases.values():
            if connection is not None:
                connection.close()
    if len(grouped) > context.max_facts:
        derived.gap(f"truncated: {len(grouped) - context.max_facts} package/advisory pair(s) exceeded the fact bound")
    for feed_name in REFERENCE_FEEDS:
        prefix = "" if feed_name == "osv" else f"{feed_name}_"
        if databases[feed_name] is None:
            derived.gap(f"{prefix}feed_unavailable: {feed_gaps[feed_name]}")
        elif (context.feeds.get(feed_name) or {}).get("stale"):
            derived.gap(f"{prefix}stale_feed: the pinned {feed_name.upper()} snapshot is older than the configured "
                        "freshness bound")
    for gap in _coverage_gaps(shards, (*scanners, *dependencies)):
        derived.gap(gap)
    return _finish(derived, name)


def cwe_ids(payload: Mapping[str, Any]) -> list[str]:
    """CWE identifiers a producer attached to an observation's rule metadata."""
    found: list[str] = []

    def visit(value: Any, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(value, str):
            found.extend(f"CWE-{int(match)}" for match in _CWE.findall(value))
        elif isinstance(value, (list, tuple)):
            for item in value[:50]:
                visit(item, depth + 1)
        elif isinstance(value, Mapping):
            for item in list(value.values())[:50]:
                visit(item, depth + 1)
    mapping = payload.get("rule_mapping")
    visit(mapping.get("cwe") if isinstance(mapping, Mapping) else None)
    rule = payload.get("rule")
    if isinstance(rule, Mapping):
        properties = rule.get("properties")
        visit(properties.get("tags") if isinstance(properties, Mapping) else None)
    return sorted(set(found))


def cwe_attributes(raw: Any) -> dict[str, str]:
    """Bounded CWE attributes (``abstraction``, ``status``) the MITRE normalizer stored for a weakness."""
    try:
        value = json.loads(raw) if isinstance(raw, str) else {}
    except ValueError:
        return {}
    return {key: str(value[key])[:64] for key in ("abstraction", "status")
            if isinstance(value, Mapping) and isinstance(value.get(key), str)}


def _select_reference(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return shards.select(index="observations")


def _build_reference_intelligence(context: ProductContext, selected: tuple[Mapping[str, Any], ...]) -> Derived:
    derived, shards, name = Derived(), context.shards, "reference_intelligence"
    if not selected:
        return _finish(derived, name, unavailable="reference intelligence is unavailable: no accepted observation "
                                                  "shards carry weakness or advisory identities")
    grouped: dict[str, dict[str, Any]] = {}
    for row in shards.entities(selected, kinds=("tool_observation",)):
        for cwe in cwe_ids(row["payload"]):
            entry = grouped.setdefault(cwe, {"observations": [], "tools": set(), "rules": set()})
            entry["observations"].append(row["identity"])
            entry["tools"].add(str(row["payload"].get("tool_id") or row["payload"].get("producer") or row["shard_id"]))
            entry["rules"].add(row["name"])
    database, feed_gap = _feed_database(context, "mitre", "index/mitre.sqlite")
    feed = _feed_reference(context, "mitre")
    if not grouped and database is None:
        return _finish(derived, name, unavailable="reference intelligence is unavailable: accepted observations "
                                                  f"carry no CWE identity and {feed_gap}")
    try:
        for cwe in sorted(grouped, key=lambda value: int(value.split("-")[1]))[:context.max_facts]:
            entry = grouped[cwe]
            gaps: list[str] = []
            weakness: dict[str, Any] = {"feed": feed, "known": None}
            if database is None:
                gaps.append(f"feed_unavailable: {feed_gap}")
            else:
                record = database.execute("SELECT source, object_type, name, modified, raw_json FROM entry "
                                          "WHERE external_id = ? ORDER BY source LIMIT 1", (cwe,)).fetchone()
                if record is None:
                    weakness["known"] = False
                    gaps.append("identity_mismatch: weakness is not present in the pinned MITRE snapshot")
                else:
                    weakness.update({"known": True, "name": str(record["name"] or "")[:256],
                                     "source": record["source"], "object_type": record["object_type"],
                                     "modified": record["modified"],
                                     "abstraction": cwe_attributes(record["raw_json"]).get("abstraction")})
                if feed.get("stale"):
                    gaps.append("stale_feed: the pinned MITRE snapshot is older than the configured freshness bound")
            observations = sorted(set(entry["observations"]))
            record_fact = fact(
                context.snapshot, name, context.rule_version, {"weakness": cwe}, name=cwe,
                text=f"reference intelligence {cwe} {weakness.get('name') or ''}",
                status="partial" if gaps else "complete", gaps=gaps,
                basis="CWE identities published in accepted observation rule metadata joined to the pinned MITRE "
                      "snapshot by exact external id", upstream=_upstream(selected),
                result={"weakness_id": cwe, "weakness": weakness, "observation_count": len(observations),
                        "observations": observations[:8], "tools": sorted(entry["tools"])[:10],
                        "rules": sorted(entry["rules"])[:10]})
            derived.entities.append(record_fact)
            for observation in observations[:8]:
                derived.relations.append(RelationRecord(RelationKind.DERIVED_FROM, record_fact.identity.value,
                                                        observation, True, 1.0, None, {"query_set": name}))
    finally:
        if database is not None:
            database.close()
    if database is None:
        derived.gap(f"feed_unavailable: {feed_gap}")
    derived.gap("CAPEC and ATT&CK relationships are not normalized by the pinned feed index; only weakness "
                "identities are joined")
    derived.gap("producers that discard weakness identifiers (for example gosec and cppcheck normalizers) "
                "contribute no reference links")
    return _finish(derived, name)


# --- scanner correlation ----------------------------------------------------------------------------------

def _select_scanner_correlation(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return tuple(shard for shard in shards.select(index="observations")
                 if not str(shard.get("shard_id")).startswith(("joern-", "ci_")))


def _build_scanner_correlation(context: ProductContext, selected: tuple[Mapping[str, Any], ...]) -> Derived:
    derived, shards, name = Derived(), context.shards, "scanner_correlation"
    if not selected:
        return _finish(derived, name, unavailable="scanner correlation is unavailable: no accepted scanner "
                                                  "observation shards")
    leads: dict[tuple[str, str, int], dict[str, Any]] = {}
    unlocated = ambiguous = 0
    for row in shards.entities(selected, kinds=("tool_observation",)):
        location = row["location"]
        if location is None:
            unlocated += 1
            continue
        if location["ambiguous"]:
            ambiguous += 1
        payload = row["payload"]
        tool = str(payload.get("tool_id") or payload.get("tool") or payload.get("producer") or row["shard_id"])
        key = (location["path"], location["file_sha256"], int(location["start_line"]))
        lead = leads.setdefault(key, {"observations": [], "tools": set(), "rules": set(), "severities": set(),
                                      "suppressed": 0, "location": location})
        lead["observations"].append(row["identity"])
        lead["tools"].add(tool)
        lead["rules"].add(row["name"])
        if _text(payload.get("severity")):
            lead["severities"].add(payload["severity"])
        if payload.get("suppressions"):
            lead["suppressed"] += 1
    ordered = sorted(leads, key=lambda key: (-len(leads[key]["tools"]), key))
    for key in ordered[:context.max_facts]:
        lead = leads[key]
        observations = sorted(set(lead["observations"]))
        gaps = ["conflicting_rules: independent tools reported different rules at this line"] \
            if len(lead["tools"]) > 1 and len(lead["rules"]) > 1 else []
        record_fact = fact(
            context.snapshot, name, context.rule_version, {"path": key[0], "file_sha256": key[1], "line": key[2]},
            name=f"{key[0]}:{key[2]}", text=f"scanner lead {key[0]} line {key[2]} " + " ".join(sorted(lead["rules"])),
            subject_path=key[0], location=lead["location"], status="complete", gaps=gaps,
            basis="observations grouped by identical accepted file hash and start line; agreement between tools "
                  "is a review lead, not a confirmed finding", upstream=_upstream(selected),
            result={"line": key[2], "file_sha256": key[1], "independent_tools": len(lead["tools"]),
                    "tools": sorted(lead["tools"])[:10], "rules": sorted(lead["rules"])[:10],
                    "severities": sorted(lead["severities"]), "suppressed_count": lead["suppressed"],
                    "observation_count": len(observations), "observations": observations[:10]})
        derived.entities.append(record_fact)
        for observation in observations[:10]:
            derived.relations.append(RelationRecord(RelationKind.DERIVED_FROM, record_fact.identity.value,
                                                    observation, True, 1.0, None, {"query_set": name}))
    if len(ordered) > context.max_facts:
        derived.gap(f"truncated: {len(ordered) - context.max_facts} located lead(s) exceeded the fact bound")
    if unlocated:
        derived.gap(f"{unlocated} observation(s) have no source location and are reachable through artifact or "
                    "observation queries only")
    if ambiguous:
        derived.gap(f"conflicting_locations: {ambiguous} observation location(s) are explicitly ambiguous")
    for gap in _coverage_gaps(shards, selected):
        derived.gap(f"scanner coverage: {gap}")
    return _finish(derived, name)


# --- CI trust ---------------------------------------------------------------------------------------------

_SENSITIVE_CATEGORIES = (
    "permission-or-authorization", "privileged-runner-or-isolation", "secret-or-credential-exposure",
    "release-or-signing-integrity", "approval-or-protection-bypass", "artifact-or-cache-poisoning",
    "dependency-or-provenance-integrity", "unsafe-pipeline-command-execution",
)


def _select_ci_trust(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return (*shards.select(index="observations", prefix="ci_"), *shards.select(index="evidence", prefix="ci_"),
            *shards.select(index="history", prefix="change-context"))


def _build_ci_trust(context: ProductContext, selected: tuple[Mapping[str, Any], ...]) -> Derived:
    derived, shards, name = Derived(), context.shards, "ci_trust"
    ci_shards = (*shards.select(index="observations", prefix="ci_"), *shards.select(index="evidence", prefix="ci_"))
    if not ci_shards:
        return _finish(derived, name, unavailable="CI trust is unavailable: no accepted CI configuration shards "
                                                  "(job_ci_configuration_analysis did not publish in this run)")
    workflows: dict[str, dict[str, Any]] = {}
    for row in shards.entities(ci_shards, kinds=("tool_observation", "finding_package")):
        location = row["location"]
        if location is None:
            continue
        workflow = workflows.setdefault(location["path"], {
            "categories": defaultdict(lambda: {"count": 0, "findings": []}), "observations": 0, "tools": set(),
            "jobs": set(), "location": location})
        if row["kind"] == "finding_package":
            entry = workflow["categories"][row["name"]]
            entry["count"] += 1
            if len(entry["findings"]) < 5:
                entry["findings"].append({"identity": row["identity"], "line": location["start_line"]})
        else:
            workflow["observations"] += 1
            workflow["tools"].add(str(row["payload"].get("tool_id") or row["shard_id"]))
            if _text(row["payload"].get("job")):
                workflow["jobs"].add(row["payload"]["job"])
    deployments = sum(1 for _row in shards.entities(shards.select(index="history", prefix="change-context"),
                                                    kinds=("deployment_event",)))
    for path in sorted(workflows)[:context.max_facts]:
        workflow = workflows[path]
        categories = {category: value for category, value in sorted(workflow["categories"].items())}
        untrusted = "untrusted-trigger-execution" in categories
        sensitive = [category for category in _SENSITIVE_CATEGORIES if category in categories]
        gaps = ["dynamic expressions and reusable or external workflows are not resolved",
                "ci-to-build mapping unavailable: CI records carry no build-unit, artifact or deployment identity"]
        record_fact = fact(
            context.snapshot, name, context.rule_version, {"workflow": path, "file_sha256":
                                                            workflow["location"]["file_sha256"]},
            name=path, text=f"ci trust {path} " + " ".join(categories), subject_path=path,
            location={**workflow["location"], "start_line": 1, "end_line": workflow["location"]["start_line"]}
            if False else workflow["location"], status="partial", gaps=gaps,
            basis="canonical CI findings grouped per workflow definition; co-located categories are review leads, "
                  "not proven trigger-to-privilege paths", upstream=_upstream(ci_shards),
            result={"untrusted_trigger": untrusted, "sensitive_categories": sensitive,
                    "trust_path_candidates": [{"from": "untrusted-trigger-execution", "to": category,
                                               "basis": "same workflow definition"} for category in sensitive]
                    if untrusted else [],
                    "categories": {category: {"finding_count": value["count"], "findings": value["findings"]}
                                   for category, value in categories.items()},
                    "observation_count": workflow["observations"], "tools": sorted(workflow["tools"])[:10],
                    "jobs": sorted(workflow["jobs"])[:10], "deployment_events_in_run": deployments})
        derived.entities.append(record_fact)
        for value in categories.values():
            for finding in value["findings"]:
                derived.relations.append(RelationRecord(RelationKind.DERIVED_FROM, record_fact.identity.value,
                                                        finding["identity"], True, 1.0, None, {"query_set": name}))
    if len(workflows) > context.max_facts:
        derived.gap(f"truncated: {len(workflows) - context.max_facts} workflow(s) exceeded the fact bound")
    derived.gap("ci-to-build mapping unavailable: CI records carry no build-unit, artifact or deployment identity")
    for gap in _coverage_gaps(shards, ci_shards):
        derived.gap(gap)
    return _finish(derived, name)


# --- history context --------------------------------------------------------------------------------------

def _select_history_context(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return (*shards.select(index="history"), *shards.select(index="priority"))


_HISTORY_KEYS = ("change_count", "churn_lines", "relative_churn", "author_count", "top_author_share",
                 "minor_author_count", "fix_change_count", "security_fix_change_count", "repeat_fix_count",
                 "revert_count", "review_bypass_count", "test_touch_share", "young_line_share", "last_change_time",
                 "fix_on_fix_count", "component_id", "is_test")


def _build_history_context(context: ProductContext, selected: tuple[Mapping[str, Any], ...]) -> Derived:
    derived, shards, name = Derived(), context.shards, "history_context"
    history = shards.select(index="history")
    if not history:
        return _finish(derived, name, unavailable="history context is unavailable: no accepted source-history or "
                                                  "change-context shards (missing VCS metadata or job not run)")
    files: dict[str, dict[str, Any]] = {}
    for row in shards.entities(selected, kinds=("history_signal", "hotspot", "change_context_signal",
                                                 "priority_item")):
        location = row["location"]
        if location is None:
            continue
        entry = files.setdefault(location["path"], {"symbols": [], "location": None, "records": []})
        native, payload = row["native_id"], row["payload"]
        if row["kind"] == "history_signal" and native.startswith("file:"):
            entry["history"] = {"identity": row["identity"], **{key: payload.get(key) for key in _HISTORY_KEYS},
                                "sii": payload.get("sii"),
                                "recent_change_count": len(payload.get("recent_changes") or ())}
            entry["location"] = location
        elif row["kind"] == "history_signal" and native.startswith("symbol:"):
            entry["symbols"].append({"identity": row["identity"], "name": row["name"].split("::")[-1][:200],
                                     "start_line": location["start_line"], "end_line": location["end_line"],
                                     "change_count": payload.get("change_count"),
                                     "fix_change_count": payload.get("fix_change_count"),
                                     "sii_rank": (payload.get("sii") or {}).get("rank")})
        elif row["kind"] == "hotspot" and native.startswith("hotspot:file:"):
            entry["hotspot"] = {"identity": row["identity"], "rank": payload.get("rank"),
                                "tier": payload.get("tier"), "score": payload.get("score")}
        elif row["kind"] == "change_context_signal" and native.startswith("file:"):
            entry["change_context"] = {"identity": row["identity"], "rank": payload.get("rank"),
                                       "score": payload.get("score"), "metrics": payload.get("metrics"),
                                       "ownership": (payload.get("details") or {}).get("ownership")}
            entry["location"] = entry["location"] or location
        elif row["kind"] == "priority_item" and native.startswith("file:"):
            entry["priority"] = {"identity": row["identity"], "rank": payload.get("rank"),
                                 "score": payload.get("score")}
        entry["records"].append(row["identity"])
    sources: dict[str, dict[str, Any]] = {}
    for relation in shards.relations(_link_shard(context, "history_code"), kinds=(RelationKind.OBSERVED_AT.value,)):
        sources.setdefault(relation["source_id"], relation)
    candidates = [path for path, entry in files.items() if "history" in entry or "change_context" in entry]

    def order(path: str) -> tuple[Any, ...]:
        rank = ((files[path].get("history") or {}).get("sii") or {}).get("rank")
        return (rank is None, rank or 0, path)
    for path in sorted(candidates, key=order)[:context.max_facts]:
        entry = files[path]
        anchor = (entry.get("history") or entry.get("change_context"))["identity"]
        link = sources.get(anchor)
        gaps: list[str] = []
        if "history" not in entry:
            gaps.append("history signals unavailable for this file; only change-context is published")
        if "change_context" not in entry:
            gaps.append("change-context is unavailable or this file is outside its ranked selection")
        if link is None:
            gaps.append("missing_source_map: the history record is not linked to an accepted source file")
        elif not link["exact"]:
            gaps.append(f"ambiguous source binding: {link['ambiguity']}")
        symbols = sorted(entry["symbols"], key=lambda item: (item["sii_rank"] is None, item["sii_rank"] or 0,
                                                             item["start_line"]))
        record_fact = fact(
            context.snapshot, name, context.rule_version, {"path": path}, name=path,
            text=f"history context {path}", subject_path=path,
            subject_identity=link["target_id"] if link is not None and link["exact"] else None,
            location=entry["location"], status="partial" if gaps else "complete", gaps=gaps,
            basis="accepted history, change-context and priority records for one file; authors are pseudonymous",
            upstream=_upstream((*history, *_link_shard(context, "history_code"))),
            result={"history": entry.get("history"), "hotspot": entry.get("hotspot"),
                    "change_context": entry.get("change_context"), "priority": entry.get("priority"),
                    "symbols": symbols[:8], "symbol_count": len(symbols),
                    "source_binding": None if link is None else {
                        "source_file": link["target_id"], "exact": link["exact"],
                        "mapping_method": link["payload"].get("mapping_method")}})
        derived.entities.append(record_fact)
        for target in sorted(set(entry["records"]))[:12]:
            derived.relations.append(RelationRecord(RelationKind.DERIVED_FROM, record_fact.identity.value, target,
                                                    True, 1.0, None, {"query_set": name}))
    if len(candidates) > context.max_facts:
        derived.gap(f"truncated: {len(candidates) - context.max_facts} file(s) exceeded the fact bound")
    for gap in _coverage_gaps(shards, history):
        derived.gap(gap)
    return _finish(derived, name)


# --- control evidence -------------------------------------------------------------------------------------

def _select_control_evidence(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return shards.select(index="components")


def _build_control_evidence(context: ProductContext, selected: tuple[Mapping[str, Any], ...]) -> Derived:
    derived, shards, name = Derived(), context.shards, "control_evidence"
    if context.owasp.get("status") != "accepted":
        return _finish(derived, name, unavailable="control evidence is unavailable: "
                       + str(context.owasp.get("reason", "the OWASP workbench has no accepted index in this run")))
    components = {row["native_id"]: row["identity"]
                  for row in shards.entities(shards.select(index="components"), kinds=("component",))}
    known = shards.entity_ids()
    results: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for shard in context.owasp["shards"]:
        if shard.get("family") != "control-result":
            continue
        path = (context.run_root / str(shard["path"])).resolve()
        if context.run_root.resolve() not in path.parents or file_sha256(path) != shard.get("sha256"):
            raise ValueError("accepted OWASP control-result shard changed")
        for record in json.loads(path.read_text(encoding="utf-8")).get("records", ()):
            results.append((shard, record))
    results.sort(key=lambda pair: (str(pair[1].get("component_id")), str(pair[1].get("control_identity"))))
    unresolved_total = 0
    for shard, record in results[:context.max_facts]:
        citations = [item for item in record.get("evidence_used") or () if isinstance(item, Mapping)]
        evidence = []
        for citation in citations[:10]:
            source = str(citation.get("source_identity", ""))[:256]
            evidence.append({"source_identity": source, "resolved": source in known,
                             "artifact_sha256": citation.get("artifact_sha256"), "lines": citation.get("lines")})
        unresolved = sum(1 for item in evidence if not item["resolved"])
        unresolved_total += unresolved
        gaps = [str(gap)[:240] for gap in record.get("gaps") or ()][:5]
        if not citations:
            gaps.append("assessment_unavailable: no resolving evidence was supplied for this control")
        if unresolved:
            gaps.append(f"validator_gap: {unresolved} citation(s) do not resolve to an accepted retrieval identity")
        component = str(record.get("component_id"))
        record_fact = fact(
            context.snapshot, name, context.rule_version,
            {"row": record.get("row_id"), "control": record.get("control_identity"), "component": component},
            name=f"{record.get('control_identity')} {component}",
            text=f"control evidence {record.get('control_identity')} {component} {record.get('control_status')}",
            subject_identity=components.get(component), status="partial" if gaps else "complete", gaps=gaps,
            basis="accepted OWASP workbench control result; the workbench shard remains the authority and is "
                  "referenced, not copied", upstream=[{"name": "owasp/control-result",
                                                       "shard_id": str(shard.get("shard_id")),
                                                       "sha256": str(shard.get("sha256"))}],
            result={"control_identity": record.get("control_identity"), "component_id": component,
                    "applicability": record.get("applicability"), "control_status": record.get("control_status"),
                    "verification_status": record.get("verification_status"), "evidence": evidence,
                    "evidence_truncated": max(0, len(citations) - 10), "unresolved_evidence": unresolved,
                    "workbench_reference": {"family": "control-result", "shard_id": shard.get("shard_id"),
                                            "row_id": record.get("row_id"),
                                            "query": "query_owasp_workbench family=control-result"}})
        derived.entities.append(record_fact)
        for item in evidence:
            if item["resolved"]:
                derived.relations.append(RelationRecord(RelationKind.DERIVED_FROM, record_fact.identity.value,
                                                        item["source_identity"], True, 1.0, None,
                                                        {"query_set": name, "role": "control-evidence"}))
    if len(results) > context.max_facts:
        derived.gap(f"truncated: {len(results) - context.max_facts} control result(s) exceeded the fact bound")
    if unresolved_total:
        derived.gap(f"validator_gap: {unresolved_total} evidence citation(s) are free-form and do not resolve to "
                    "accepted retrieval identities")
    if not results:
        derived.gap("assessment_unavailable: the accepted workbench published no control results")
    return _finish(derived, name)


# --- symbol links -----------------------------------------------------------------------------------------

def _select_symbol_links(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return (*shards.select(index="analysis", job=CATALOG),
            *shards.select(index="analysis", job="job_cpp_symbol_index", prefix="clangd-"))


def _build_symbol_links(context: ProductContext, selected: tuple[Mapping[str, Any], ...]) -> Derived:
    derived, shards, name = Derived(), context.shards, "symbol_links"
    link_shards = _link_shard(context, "symbol_syntax")
    syntax: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for relation in shards.relations(link_shards, kinds=(RelationKind.DEFINES.value,)):
        syntax[relation["target_id"]].append(relation)
    outgoing: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    incoming: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for relation in shards.relations(selected, kinds=(RelationKind.CALLS.value, RelationKind.REFERENCES.value)):
        outgoing[relation["source_id"]][relation["kind"]] += 1
        incoming[relation["target_id"]][relation["kind"]] += 1
    symbols = [row for row in shards.entities(selected, kinds=("symbol",)) if row["location"] is not None]
    if not symbols:
        return _finish(derived, name, unavailable="symbol links are unavailable: no accepted symbols with source "
                                                  "locations")
    # Exactly linked symbols first, then ambiguous, then unlinked; stable by identity within each class.
    def rank(row: Mapping[str, Any]) -> tuple[int, str]:
        links = syntax.get(row["identity"], ())
        return (0 if any(item["exact"] for item in links) else 1 if links else 2, row["identity"])
    unlinked = 0
    for row in sorted(symbols, key=rank)[:context.max_facts]:
        links = sorted(syntax.get(row["identity"], ()), key=lambda item: (-item["confidence"], item["source_id"]))
        location = row["location"]
        gaps: list[str] = []
        if not links:
            unlinked += 1
            gaps.append("no accepted syntax node was linked to this symbol (unsupported language, parse gap or "
                        "generated source)")
        elif not any(item["exact"] for item in links):
            gaps.append("ambiguous: " + str(links[0]["ambiguity"]))
        record_fact = fact(
            context.snapshot, name, context.rule_version, {"symbol": row["identity"]}, name=row["name"],
            text=f"symbol links {row['name']}", subject_identity=row["identity"], location=location,
            status="complete" if links and any(item["exact"] for item in links) else "partial", gaps=gaps,
            basis="accepted symbol locations joined to Tree-sitter syntax nodes; line-only joins stay ambiguous",
            upstream=_upstream((*selected, *link_shards)),
            result={"symbol": {"identity": row["identity"], "name": row["name"],
                               "producer": row["payload"].get("producer") or "declaration-pattern",
                               "kind": row["payload"].get("kind"),
                               "language": row["payload"].get("language") or row["payload"].get("lang"),
                               "mapping_method": location["mapping_method"]},
                    "definition": {"start_line": location["start_line"], "end_line": location["end_line"],
                                   "start_column": location["start_column"], "end_column": location["end_column"],
                                   "file_sha256": location["file_sha256"]},
                    "syntax_links": [{"ast_node": item["source_id"], "exact": item["exact"],
                                      "confidence": item["confidence"],
                                      "mapping_method": item["payload"].get("mapping_method"),
                                      "syntax_type": item["payload"].get("syntax_type"),
                                      "start_byte": item["payload"].get("start_byte"),
                                      "end_byte": item["payload"].get("end_byte")} for item in links[:4]],
                    "calls_out": outgoing[row["identity"]].get("CALLS", 0),
                    "calls_in": incoming[row["identity"]].get("CALLS", 0),
                    "references_out": outgoing[row["identity"]].get("REFERENCES", 0),
                    "references_in": incoming[row["identity"]].get("REFERENCES", 0)})
        derived.entities.append(record_fact)
        for item in links[:4]:
            derived.relations.append(RelationRecord(
                RelationKind.DERIVED_FROM, record_fact.identity.value, item["source_id"], item["exact"],
                item["confidence"], item["ambiguity"], {"query_set": name}))
    if len(symbols) > context.max_facts:
        derived.gap(f"truncated: {len(symbols) - context.max_facts} symbol(s) exceeded the fact bound")
    if unlinked:
        derived.gap(f"{unlinked} symbol(s) have no linked syntax node")
    if not link_shards:
        derived.gap("symbol-to-syntax link shard is unavailable")
    for gap in _coverage_gaps(shards, link_shards, 5):
        derived.gap(gap)
    derived.gap("unresolved overloads, template instantiations and indirect dispatch are not resolved by this "
                "first-stage product")
    return _finish(derived, name)


def _select_document_context(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return shards.select(index="documents", job=CATALOG)


def _build_document_context(context: ProductContext, selected: tuple[Mapping[str, Any], ...]) -> Derived:
    """Join accepted declarations and intent by exact route or boundary keys.

    These are navigation facts for a reviewer. A missing test or declaration is a
    coverage question, and a matching test never proves that a control is enforced.
    """
    name = "document_context"
    derived = Derived()
    if not selected:
        return _finish(derived, name, unavailable="no accepted target document shard")
    shards = context.shards
    rows = [row for row in shards.entities(selected, kinds=("document_record",))
            if row.get("payload", {}).get("record_type") == "target_document"]
    routes: dict[tuple[str, str], dict[str, list[Mapping[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    boundaries: dict[str, dict[str, list[Mapping[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        payload = row["payload"]
        fields = payload.get("fields") or {}
        kind, subtype = payload.get("document_kind"), payload.get("subtype")
        if subtype in {"operation", "request"} and kind in {"openapi", "postman", "unit_test"}:
            method, route = fields.get("method"), fields.get("route")
            if isinstance(method, str) and isinstance(route, str) and route.startswith("/"):
                routes[(method, route)][str(kind)].append(row)
        elif kind == "dfd" and subtype == "boundary" and isinstance(fields.get("boundary_id"), str):
            boundaries[fields["boundary_id"]]["dfd"].append(row)
        elif kind == "threat_model" and subtype == "threat":
            for boundary in fields.get("boundaries", ()):
                if isinstance(boundary, str):
                    boundaries[boundary]["threat_model"].append(row)

    subjects: list[tuple[str, str, Mapping[str, list[Mapping[str, Any]]]]] = [
        ("route", f"{method} {route}", grouped) for (method, route), grouped in sorted(routes.items())
    ] + [("boundary", boundary, grouped) for boundary, grouped in sorted(boundaries.items())]
    upstream = _upstream(selected)
    for subject_type, key, grouped in subjects[:context.max_facts]:
        members = [row for kind in sorted(grouped) for row in sorted(grouped[kind], key=lambda item: item["identity"])]
        anchor = next((row for row in members if row["payload"].get("document_kind") in {"openapi", "dfd"}),
                      members[0])
        gaps = []
        if subject_type == "route" and not grouped.get("openapi"):
            gaps.append("no accepted OpenAPI declaration for this request")
        if subject_type == "boundary" and not grouped.get("dfd"):
            gaps.append("no accepted DFD boundary for this threat")
        record = fact(context.snapshot, name, context.rule_version,
                      {"subject_type": subject_type, "key": key}, name=f"{subject_type} {key}",
                      text=f"document context {subject_type} {key}",
                      result={"subject_type": subject_type, "key": key,
                              "members": {kind: [row["identity"] for row in grouped[kind]]
                                          for kind in sorted(grouped)},
                              "member_counts": {kind: len(grouped[kind]) for kind in sorted(grouped)},
                              "inference_use": "review context only; verify behavior in source or run evidence"},
                      basis="exact method and route or trust-boundary identifier in accepted target documents",
                      upstream=upstream, subject_identity=anchor["identity"],
                      subject_path=(anchor.get("location") or {}).get("path"),
                      status="partial" if gaps else "complete", gaps=gaps, location=anchor.get("location"),
                      fact_type=f"{subject_type}_context")
        derived.entities.append(record)
        for row in members[:32]:
            derived.relate(RelationKind.DERIVED_FROM, record.identity.value, row["identity"],
                           exact=True, confidence=1.0, method="document-key")
        if len(members) > 32:
            derived.gap(f"{subject_type} {key}: {len(members) - 32} document links exceeded the relation bound")
        for gap in gaps:
            derived.gap(f"{subject_type} {key}: {gap}")
    if len(subjects) > context.max_facts:
        derived.gap(f"truncated: {len(subjects) - context.max_facts} document subject(s) exceeded the fact bound")
    for gap in _coverage_gaps(shards, selected):
        derived.gap(gap)
    return _finish(derived, name)


PRODUCT_RULES: tuple[ProductRule, ...] = (
    ProductRule("build_provenance", "build-provenance/1", _select_build_provenance, _build_build_provenance,
                links=("representation",)),
    ProductRule("artifact_inventory", "artifact-inventory/1", _select_artifact_inventory, _build_artifact_inventory),
    ProductRule("dependency_advisories", "dependency-advisories/4", _select_dependency_advisories,
                _build_dependency_advisories, links=("package_advisory",), feeds=REFERENCE_FEEDS),
    ProductRule("scanner_correlation", "scanner-correlation/2", _select_scanner_correlation,
                _build_scanner_correlation),
    ProductRule("ci_trust", "ci-trust/1", _select_ci_trust, _build_ci_trust),
    ProductRule("history_context", "history-context/1", _select_history_context, _build_history_context,
                links=("history_code",)),
    ProductRule("control_evidence", "control-evidence/1", _select_control_evidence, _build_control_evidence,
                owasp=True),
    ProductRule("reference_intelligence", "reference-intelligence/2", _select_reference,
                _build_reference_intelligence, feeds=("mitre",)),
    ProductRule("symbol_links", "symbol-links/1", _select_symbol_links, _build_symbol_links,
                links=("symbol_syntax",)),
    ProductRule("document_context", "document-context/1", _select_document_context, _build_document_context),
)
assert tuple(rule.query_set for rule in PRODUCT_RULES) == FIRST_STAGE_SETS
# Stage-1 sets are live query sets; no retired graph set may come back as a product.
assert set(FIRST_STAGE_SETS) <= set(QUERY_SETS) and not set(FIRST_STAGE_SETS) & set(RETIRED_GRAPH_SETS)


def product_rule(query_set: str) -> ProductRule:
    return next(rule for rule in PRODUCT_RULES if rule.query_set == query_set)
