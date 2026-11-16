"""Deterministic CPE-range advisory lookup for native and generic components.

The pinned package scanners (Grype, osv-scanner) match package-manager coordinates, and cve-bin-tool
matches only the version strings its checkers know, inside binaries it is handed. A vendored C
library whose release this job corroborated from its own headers (``pkg:generic/<name>@<version>``)
therefore reaches no scanner. This module looks those components up, with no model and no network,
in the verified cve-bin-tool snapshot, which is the NVD CPE range database: ``cve_range`` rows name
a vendor/product pair and either one exact ``version`` or up to four range bounds, and
``cve_severity`` carries the NVD CVSS facts.

Every match is a **lead**, never a confirmed vulnerability: a CPE range says that NVD considers the
release affected, not that the affected code is compiled, reachable or unpatched here. Rows of
every vendor are consulted, because the same product name is used by forks and by unrelated
projects (``cloudflare/zlib``, ``ruby-lang/zlib``): a row whose vendor is the product itself,
``<product>_project`` or the product without its trailing release digits (NVD spells bzip2 as
``bzip/bzip2``) is reported with ``confidence: canonical``, any other vendor with
``confidence: alternate_vendor``. The vendor is always recorded, so a review can re-rate a lead
(``davegamble/cjson`` is the upstream author yet an alternate vendor under this rule). Version comparison is conservative: a bound that is not dotted
numeric, or a release whose suffix the comparison cannot order, is ``unknown`` and a named gap,
never a match and never a clean result. The match projection (``observation.matches``) is the one
``indexing.links.advisory_pairs`` reads for Grype and cve-bin-tool, so each match joins
``dependency_advisories`` unchanged, with ``match_basis: cpe-range`` and the tool identity
``native-advisory-lookup/1``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import time
from typing import Any
from urllib.parse import unquote

from appsec_review.storage import canonical_json


TOOL_ID = "native-advisory-lookup"
SCANNER_IDENTITY = "native-advisory-lookup/1"
CAPABILITY = "native_advisory_lookup"
MATCH_BASIS = "cpe-range"
FEED = "cve-bin-tool"
RECORD_SCHEMA = "appsec-review/native-advisory-record/1"
RESULT_SCHEMA = "appsec-review/native-advisory-lookup/1"
RECORD_KIND_FINDING, RECORD_KIND_SUMMARY = "finding", "scan_summary"
CATEGORY_VULNERABILITY = "vulnerability_matching"
CATEGORY_DIAGNOSTIC = "tool_diagnostic"
CONFIDENCE_CANONICAL, CONFIDENCE_ALTERNATE = "canonical", "alternate_vendor"
# Matcher rule versions: part of the observations shard fingerprint.
PARSER_IDENTITY = "native-advisory-parser/1"
NORMALIZER_IDENTITY = "native-advisory-normalizer/1"
MAPPING_IDENTITY = "native-advisory-dependency-map/1"
# PURL types the pinned package scanners already match through OSV ecosystems
# (``indexing.products._PURL_OSV_ECOSYSTEM``); every other type, and a purl-less native row, is this lookup's.
SCANNER_COVERED_PURL_TYPES = frozenset({"cargo", "composer", "gem", "golang", "maven", "npm", "nuget", "pypi"})
STATUS_AFFECTED, STATUS_NOT_AFFECTED, STATUS_UNKNOWN = "affected", "not_affected", "unknown"
DESCRIPTION_BOUND = 512
_NAME_BOUND = 128
_VERSION_BOUND = 64
_SEVERITY_CHUNK = 400
_NUMERIC = re.compile(r"^(\d+(?:\.\d+){0,3})(.*)$")
_CPE = re.compile(r"^cpe:2\.3:[aho*-]:([^:]*):([^:]*):")
RANGE_COLUMNS = ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")
_ROW_COLUMNS = ("cve_number", "vendor", "product", "version", *RANGE_COLUMNS, "data_source")

SnapshotResolver = Callable[[Path, Path], Mapping[str, Any]]


class NativeAdvisoryError(ValueError):
    """The lookup's own precondition failed (bounds, snapshot shape); callers report a gap."""


@dataclass(frozen=True, slots=True)
class LookupBounds:
    component_limit: int
    rows_per_component: int
    match_limit: int

    @classmethod
    def from_settings(cls, value: Any) -> "LookupBounds":
        if not isinstance(value, Mapping):
            raise ValueError("dependency-intelligence native_advisory_lookup settings must be a table")
        keys = ("component_limit", "rows_per_component", "match_limit")
        if set(value) != set(keys) or any(type(value[key]) is not int or value[key] < 1 for key in keys):
            raise ValueError("dependency-intelligence native_advisory_lookup bounds must be positive integers: "
                             + ", ".join(keys))
        return cls(*(int(value[key]) for key in keys))

    def as_dict(self) -> dict[str, int]:
        return {"component_limit": self.component_limit, "rows_per_component": self.rows_per_component,
                "match_limit": self.match_limit}


@dataclass(frozen=True, slots=True)
class Component:
    """One native/generic component to look up: a normalized product name and its corroborated release."""

    name: str
    version: str | None
    purl: str | None
    dependency_ids: tuple[str, ...]

    @property
    def subject(self) -> str:
        return f"{self.name}@{self.version}" if self.version else self.name


# --- component selection -----------------------------------------------------------------------------------

def purl_parts(value: Any) -> tuple[str, str, str | None] | None:
    """``(type, name, version)`` of a bounded Package URL, else ``None``."""
    if not isinstance(value, str) or not value.startswith("pkg:") or len(value) > 4096:
        return None
    body = value[4:].split("?", 1)[0].split("#", 1)[0]
    package_type, separator, path = body.partition("/")
    if not separator or not package_type:
        return None
    version = None
    head, at, tail = path.rpartition("@")
    if at and head and "/" not in tail:
        path, version = head, unquote(tail).strip() or None
    parts = [unquote(item) for item in path.split("/") if item]
    if not parts:
        return None
    return package_type.casefold(), parts[-1].strip(), version


def normalize_name(value: Any) -> str:
    return str(value or "").strip().casefold()[:_NAME_BOUND]


def select_components(dependencies: Sequence[Mapping[str, Any]], bounds: LookupBounds,
                      ) -> tuple[list[Component], list[dict[str, Any]], list[str]]:
    """The components the lookup takes, per-component gaps, and lookup-level gaps.

    A dependency row enters when its purl type has no scanner coverage, or when it has no purl at all
    (native linker, header or model-inferred rows). Rows with the same name and version collapse into
    one component that keeps every dependency id. A component without a version is a named gap per
    component: it is never looked up (a CPE range needs a version) and never silently dropped.
    """
    grouped: dict[tuple[str, str | None], dict[str, Any]] = {}
    gaps: list[dict[str, Any]] = []
    lookup_gaps: list[str] = []
    for row in dependencies:
        if not isinstance(row, Mapping):
            continue
        dependency_id = str(row.get("dependency_id") or "")
        parsed = purl_parts(row.get("purl"))
        if parsed is not None and parsed[0] in SCANNER_COVERED_PURL_TYPES:
            continue
        name = normalize_name(parsed[1] if parsed is not None else row.get("name"))
        if not name:
            continue
        version = None
        if parsed is not None and parsed[2]:
            version = parsed[2][:_VERSION_BOUND]
        elif isinstance(row.get("version"), str) and row["version"].strip():
            version = row["version"].strip()[:_VERSION_BOUND]
        key = (name, version)
        entry = grouped.setdefault(key, {"purl": None, "ids": []})
        if entry["purl"] is None and parsed is not None and isinstance(row.get("purl"), str):
            entry["purl"] = row["purl"][:512]
        if dependency_id and dependency_id not in entry["ids"]:
            entry["ids"].append(dependency_id)
    components: list[Component] = []
    for key in sorted(grouped, key=lambda item: (item[0], item[1] or "")):
        name, version = key
        entry = grouped[key]
        component = Component(name, version, entry["purl"], tuple(sorted(entry["ids"])))
        if version is None:
            gaps.append({"dependency_id": component.dependency_ids[0] if component.dependency_ids else None,
                         "kind": "advisory_version_unresolved", "component": name,
                         "detail": f"native component {name} has no corroborated version; the CPE range lookup "
                                   "did not run for it and reports no advisory (not a clean result)"})
            continue
        components.append(component)
    if len(components) > bounds.component_limit:
        dropped = components[bounds.component_limit:]
        components = components[:bounds.component_limit]
        lookup_gaps.append(f"truncated: {len(dropped)} native component(s) beyond component_limit "
                           f"{bounds.component_limit} were not looked up: "
                           + ", ".join(item.subject for item in dropped[:8]))
    return components, gaps, lookup_gaps


# --- version comparison -----------------------------------------------------------------------------------

def version_key(text: Any) -> tuple[tuple[int, ...], str] | None:
    """``(numeric parts, suffix)`` of a dotted-numeric release (1 to 4 parts), else ``None``."""
    if not isinstance(text, str):
        return None
    text = text.strip()
    if not text or text in {"*", "-"}:
        return None
    match = _NUMERIC.match(text)
    if match is None:
        return None
    return tuple(int(part) for part in match.group(1).split(".")), match.group(2)


def _compare_cores(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    left, right = left + (0,) * (width - len(left)), right + (0,) * (width - len(right))
    return (left > right) - (left < right)


def compare_versions(version: str, bound: str) -> int | None:
    """Sign of ``version - bound``, or ``None`` when the pair cannot be ordered conservatively.

    The bound must be purely dotted numeric (``1.2.12``); a dated, lettered or revision bound
    (``2023-11-16``, ``r118``, ``0.9.5a``) is uncomparable. The component release may carry a distro
    style suffix (``1.0.6-r3``, ``1.2.11+dfsg``): its numeric core orders strictly against the bound,
    but a core equal to the bound is uncomparable, because the suffix may carry the fix.
    """
    left, right = version_key(version), version_key(bound)
    if left is None or right is None or right[1]:
        return None
    order = _compare_cores(left[0], right[0])
    if order == 0 and left[1]:
        return None
    return order


def evaluate_row(version: str, row: Mapping[str, Any]) -> tuple[str, list[str]]:
    """``(status, reasons)`` of one ``cve_range`` row for a component release."""
    exact = str(row.get("version") or "").strip()
    if exact == "-":
        return STATUS_UNKNOWN, ["row is an unversioned CPE (version '-')"]
    if exact and exact != "*":
        if exact.casefold() == version.strip().casefold():
            return STATUS_AFFECTED, []
        return STATUS_NOT_AFFECTED, []
    checks = ((row.get("versionStartIncluding"), lambda order: order >= 0, ">="),
              (row.get("versionStartExcluding"), lambda order: order > 0, ">"),
              (row.get("versionEndIncluding"), lambda order: order <= 0, "<="),
              (row.get("versionEndExcluding"), lambda order: order < 0, "<"))
    unknown: list[str] = []
    for bound, accept, symbol in checks:
        if not isinstance(bound, str) or not bound.strip():
            continue
        order = compare_versions(version, bound)
        if order is None:
            unknown.append(f"{version} {symbol} {bound.strip()} is not comparable")
            continue
        if not accept(order):
            return STATUS_NOT_AFFECTED, []
    if unknown:
        return STATUS_UNKNOWN, unknown
    return STATUS_AFFECTED, []


def confidence_of(vendor: str, product: str) -> str:
    """``canonical`` for the product's own NVD vendor spellings, ``alternate_vendor`` for every other vendor.

    Canonical spellings are the product name itself (``zlib/zlib``), ``<product>_project``
    (``lz4_project/lz4``) and the product without its trailing release digits (``bzip/bzip2``).
    """
    vendor, product = vendor.strip().casefold(), product.strip().casefold()
    stem = product.rstrip("0123456789")
    canonical = {product, f"{product}_project"} | ({stem} if stem and stem != product else set())
    return CONFIDENCE_CANONICAL if vendor in canonical else CONFIDENCE_ALTERNATE


# --- snapshot access --------------------------------------------------------------------------------------

def verified_snapshot(repository_root: Path, run_root: Path) -> dict[str, Any]:
    """The current verified cve-bin-tool snapshot as the run froze its builder settings."""
    from appsec_review.jobs.job_third_party_data_sync.steps.cve_bin_tool_db_build import database as feed
    settings = feed.consumer_settings(repository_root, run_root)
    return feed.verify_consumer(settings, tool_version=settings.tool_version)


def snapshot_provenance(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    directory = Path(str(snapshot.get("directory") or ""))
    manifest_files: Mapping[str, Any] = {}
    manifest_path = directory / "manifest.json"
    if manifest_path.is_file():
        try:
            manifest_files = json.loads(manifest_path.read_text(encoding="utf-8")).get("files") or {}
        except (OSError, ValueError):
            manifest_files = {}
    cve_db = manifest_files.get("cve.db") if isinstance(manifest_files, Mapping) else None
    for key in ("snapshot_id", "manifest_sha256", "nvd_snapshot_id"):
        if not isinstance(snapshot.get(key), str) or not snapshot[key]:
            raise NativeAdvisoryError(f"cve-bin-tool snapshot lacks {key}")
    return {"feed": FEED, "snapshot_id": snapshot["snapshot_id"], "manifest_sha256": snapshot["manifest_sha256"],
            "nvd_snapshot_id": snapshot["nvd_snapshot_id"],
            "nvd_manifest_sha256": snapshot.get("nvd_manifest_sha256"),
            "cve_db_sha256": cve_db.get("sha256") if isinstance(cve_db, Mapping) else None,
            "tool_version": (snapshot.get("tool") or {}).get("tool_version")
            if isinstance(snapshot.get("tool"), Mapping) else None}


def open_database(snapshot: Mapping[str, Any]) -> sqlite3.Connection:
    path = Path(str(snapshot.get("directory") or "")) / "cve.db"
    if not path.is_file():
        raise NativeAdvisoryError("cve-bin-tool snapshot has no cve.db")
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


# --- lookup -------------------------------------------------------------------------------------------------

def _text(value: Any, bound: int = _NAME_BOUND) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:bound] if text else None


def _cpe_products(connection: sqlite3.Connection, purl: str) -> list[tuple[str, str]]:
    """``(vendor, product)`` pairs the snapshot's purl2cpe table maps the purl to (empty in practice)."""
    found: list[tuple[str, str]] = []
    try:
        rows = connection.execute("SELECT cpe FROM purl2cpe WHERE purl = ? ORDER BY cpe LIMIT 16", (purl,)).fetchall()
    except sqlite3.Error:
        return found
    for row in rows:
        match = _CPE.match(str(row[0]))
        if match is not None:
            found.append((match.group(1).casefold(), match.group(2).casefold()))
    return found


def lookup(connection: sqlite3.Connection, components: Sequence[Component], bounds: LookupBounds) -> dict[str, Any]:
    """Decide every ``cve_range`` row of each component's product name, across all vendors, in one scan."""
    started = time.monotonic()
    query_count = 0
    gaps: list[str] = []
    products: dict[str, list[Component]] = {}
    cpe_hints: dict[str, set[str]] = {}
    for component in components:
        products.setdefault(component.name, []).append(component)
        if component.purl:
            query_count += 1
            for vendor, product in _cpe_products(connection, component.purl):
                products.setdefault(product, [])
                if component not in products[product]:
                    products[product].append(component)
                cpe_hints.setdefault(component.subject, set()).add(f"{vendor}:{product}")
    rows_by_product: dict[str, list[dict[str, Any]]] = {name: [] for name in products}
    if products:
        names = sorted(products)
        query_count += 1
        sql = ("SELECT " + ", ".join(_ROW_COLUMNS) + " FROM cve_range WHERE product IN ("
               + ", ".join("?" for _ in names) + ") COLLATE NOCASE ORDER BY product, cve_number, vendor, version, "
               + ", ".join(RANGE_COLUMNS))
        for row in connection.execute(sql, names):
            record = {column: row[column] for column in _ROW_COLUMNS}
            rows_by_product.setdefault(normalize_name(record["product"]), []).append(record)
    matches: list[dict[str, Any]] = []
    component_rows: list[dict[str, Any]] = []
    truncated_matches = 0
    for component in components:
        own_products = sorted(name for name, members in products.items() if component in members)
        rows = [row for name in own_products for row in rows_by_product.get(name, ())]
        truncated = len(rows) > bounds.rows_per_component
        rows = rows[:bounds.rows_per_component]
        unknown: dict[str, list[str]] = {}
        affected: dict[tuple[str, str, str], dict[str, Any]] = {}
        rejected = 0
        for row in rows:
            status, reasons = evaluate_row(str(component.version), row)
            if status == STATUS_NOT_AFFECTED:
                rejected += 1
                continue
            if status == STATUS_UNKNOWN:
                unknown.setdefault(str(row["cve_number"]), []).extend(reasons)
                continue
            key = (str(row["cve_number"]), str(row["vendor"]), str(row["product"]))
            if key in affected:
                continue
            affected[key] = {
                "cve_id": key[0], "vendor": key[1], "product": key[2],
                "confidence": confidence_of(key[1], key[2]),
                "component": component.subject, "name": component.name, "version": component.version,
                "purl": component.purl, "dependency_ids": list(component.dependency_ids),
                "matched_row": {column: row[column] or None for column in ("version", *RANGE_COLUMNS)},
                "data_source": row["data_source"],
            }
        kept = sorted(affected.values(), key=lambda item: (item["cve_id"], item["confidence"], item["vendor"]))
        if len(matches) + len(kept) > bounds.match_limit:
            keep = max(0, bounds.match_limit - len(matches))
            truncated_matches += len(kept) - keep
            kept = kept[:keep]
        matches.extend(kept)
        component_gaps: list[str] = []
        if truncated:
            component_gaps.append(f"truncated: {component.subject}: more than {bounds.rows_per_component} CPE "
                                  "rows name this product; rows beyond the bound were not evaluated")
        for cve, reasons in sorted(unknown.items()):
            component_gaps.append(f"version_uncomparable: {component.subject}: {cve} could not be decided: "
                                  + "; ".join(sorted(set(reasons)))[:240])
        gaps.extend(component_gaps)
        component_rows.append({
            "name": component.name, "version": component.version, "purl": component.purl,
            "dependency_ids": list(component.dependency_ids), "products_queried": own_products,
            "purl2cpe": sorted(cpe_hints.get(component.subject, ())),
            "row_count": len(rows), "rows_truncated": truncated, "rows_rejected": rejected,
            "match_count": len(kept), "unknown_advisories": sorted(unknown),
            "status": ("matched" if kept else "undetermined" if unknown else "no_match"),
            "gaps": component_gaps,
        })
    if truncated_matches:
        gaps.append(f"truncated: {truncated_matches} CPE range match(es) beyond match_limit {bounds.match_limit} "
                    "were not recorded")
    severity = _severities(connection, sorted({item["cve_id"] for item in matches}))
    query_count += severity.pop("_queries")
    exploited = _exploited(connection, sorted({item["cve_id"] for item in matches}))
    query_count += exploited.pop("_queries")
    for item in matches:
        facts = severity.get(item["cve_id"]) or {}
        item.update({"severity": facts.get("severity"), "cvss_score": facts.get("score"),
                     "cvss_version": facts.get("cvss_version"), "cvss_vector": facts.get("cvss_vector"),
                     "description": facts.get("description"), "severity_source": facts.get("data_source"),
                     "last_modified": facts.get("last_modified"),
                     "known_exploited": bool(exploited.get(item["cve_id"]))})
        if not facts:
            gaps.append(f"severity_unavailable: {item['cve_id']} has no NVD severity row in the snapshot")
    return {"schema": RESULT_SCHEMA, "tool_identity": {"scanner": TOOL_ID, "identity": SCANNER_IDENTITY,
                                                        "match_basis": MATCH_BASIS},
            "bounds": bounds.as_dict(), "components": component_rows, "matches": matches,
            "component_count": len(components), "match_count": len(matches), "query_count": query_count,
            "gaps": list(dict.fromkeys(gaps)), "elapsed_ms": max(0, int((time.monotonic() - started) * 1000))}


def _chunks(values: Sequence[str], size: int) -> list[Sequence[str]]:
    return [values[index:index + size] for index in range(0, len(values), size)]


def _severities(connection: sqlite3.Connection, cves: Sequence[str]) -> dict[str, Any]:
    found: dict[str, Any] = {"_queries": 0}
    for chunk in _chunks(cves, _SEVERITY_CHUNK):
        found["_queries"] += 1
        sql = ("SELECT cve_number, severity, description, score, cvss_version, cvss_vector, data_source, last_modified "
               "FROM cve_severity WHERE data_source = 'NVD' AND cve_number IN (" + ", ".join("?" for _ in chunk)
               + ") ORDER BY cve_number")
        for row in connection.execute(sql, list(chunk)):
            score = row["score"]
            found[str(row["cve_number"])] = {
                "severity": _text(row["severity"], 32), "description": _text(row["description"], DESCRIPTION_BOUND),
                "score": float(score) if isinstance(score, (int, float)) and not isinstance(score, bool) else None,
                "cvss_version": _text(row["cvss_version"], 8), "cvss_vector": _text(row["cvss_vector"], 256),
                "data_source": _text(row["data_source"], 32), "last_modified": _text(row["last_modified"], 64)}
    return found


def _exploited(connection: sqlite3.Connection, cves: Sequence[str]) -> dict[str, Any]:
    found: dict[str, Any] = {"_queries": 0}
    for chunk in _chunks(cves, _SEVERITY_CHUNK):
        found["_queries"] += 1
        try:
            rows = connection.execute("SELECT cve_number FROM cve_exploited WHERE cve_number IN ("
                                      + ", ".join("?" for _ in chunk) + ")", list(chunk)).fetchall()
        except sqlite3.Error:
            return found
        for row in rows:
            found[str(row[0])] = True
    return found


# --- observations -------------------------------------------------------------------------------------------

def result_fingerprint(components: Sequence[Component], provenance: Mapping[str, Any], bounds: LookupBounds) -> str:
    return hashlib.sha256(canonical_json({
        "schema": RESULT_SCHEMA, "identity": SCANNER_IDENTITY, "bounds": bounds.as_dict(), "provenance": provenance,
        "components": [{"name": item.name, "version": item.version, "purl": item.purl,
                        "dependency_ids": list(item.dependency_ids)} for item in components]})).hexdigest()


def observation_records(result: Mapping[str, Any], provenance: Mapping[str, Any]) -> list[dict[str, Any]]:
    """One ``finding`` payload per match and one ``scan_summary`` per component, in a stable order.

    Each payload carries ``identity_key`` (the native identity the shard derives its entity id from) and
    ``native_id``/``name``/``text`` beside the indexed ``payload``; the job turns them into entities.
    """
    records: list[dict[str, Any]] = []
    for match in result["matches"]:
        subject = str(match["component"])
        payload = {
            "schema": RECORD_SCHEMA, "record_kind": RECORD_KIND_FINDING, "category": CATEGORY_VULNERABILITY,
            "tool_id": TOOL_ID, "scanner_identity": SCANNER_IDENTITY, "capability": CAPABILITY,
            "match_basis": MATCH_BASIS, "rule_id": match["cve_id"], "native_rule_id": match["cve_id"],
            "advisory_id": match["cve_id"], "severity": match.get("severity"),
            "native_severity": match.get("severity"), "cvss_score": match.get("cvss_score"),
            "cvss_version": match.get("cvss_version"), "cvss_vector": match.get("cvss_vector"),
            "data_source": match.get("severity_source") or match.get("data_source"),
            "description": match.get("description"), "known_exploited": match.get("known_exploited"),
            "message": (f"{match['cve_id']} affects {subject} (NVD CPE range match, {match['confidence']} vendor "
                        f"{match['vendor']}/{match['product']}); a lead, not a confirmed vulnerability")[:512],
            "subject": subject, "package_name": match["name"], "package_version": match["version"],
            "purl": match.get("purl"), "vendor": match["vendor"], "product": match["product"],
            "confidence": match["confidence"], "matched_row": match["matched_row"],
            "dependency_ids": list(match["dependency_ids"]), "provenance": dict(provenance),
            "observation": {"matches": [{
                "artifact": {"name": match["name"], "version": match["version"], "purl": match.get("purl")},
                "vulnerability": {"id": match["cve_id"], "severity": match.get("severity")},
            }]},
            "gaps": [],
        }
        records.append({
            "identity_key": {"lookup": SCANNER_IDENTITY, "component": subject, "cve": match["cve_id"],
                             "vendor": match["vendor"], "product": match["product"]},
            "native_id": f"{subject}:{match['cve_id']}:{match['vendor']}/{match['product']}"[:512],
            "name": match["cve_id"], "text": payload["message"][:1024], "payload": payload,
            "dependency_ids": list(match["dependency_ids"]),
        })
    for component in result["components"]:
        subject = f"{component['name']}@{component['version']}"
        payload = {
            "schema": RECORD_SCHEMA, "record_kind": RECORD_KIND_SUMMARY, "category": CATEGORY_DIAGNOSTIC,
            "tool_id": TOOL_ID, "scanner_identity": SCANNER_IDENTITY, "capability": CAPABILITY,
            "match_basis": MATCH_BASIS, "subject": subject, "package_name": component["name"],
            "package_version": component["version"], "purl": component.get("purl"),
            "products_queried": component["products_queried"], "purl2cpe": component["purl2cpe"],
            "row_count": component["row_count"], "rows_truncated": component["rows_truncated"],
            "rows_rejected": component["rows_rejected"], "match_count": component["match_count"],
            "unknown_advisories": component["unknown_advisories"], "scan_outcome": component["status"],
            "dependency_ids": list(component["dependency_ids"]), "provenance": dict(provenance),
            "gaps": list(component["gaps"]),
        }
        records.append({
            "identity_key": {"lookup": SCANNER_IDENTITY, "component": subject, "summary": True},
            "native_id": f"{subject}:summary"[:512], "name": CAPABILITY,
            "text": f"{CAPABILITY} of {subject}: {component['status']}, {component['match_count']} match(es)",
            "payload": payload, "dependency_ids": list(component["dependency_ids"]),
        })
    return records


__all__ = [
    "CAPABILITY", "CONFIDENCE_ALTERNATE", "CONFIDENCE_CANONICAL", "Component", "FEED", "LookupBounds",
    "MAPPING_IDENTITY", "MATCH_BASIS", "NORMALIZER_IDENTITY", "NativeAdvisoryError", "PARSER_IDENTITY",
    "RECORD_SCHEMA", "RESULT_SCHEMA", "SCANNER_COVERED_PURL_TYPES", "SCANNER_IDENTITY", "TOOL_ID",
    "compare_versions", "confidence_of", "evaluate_row", "lookup", "observation_records", "open_database",
    "purl_parts", "result_fingerprint", "select_components", "snapshot_provenance", "verified_snapshot",
    "version_key",
]
