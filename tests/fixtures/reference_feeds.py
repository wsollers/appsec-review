"""Publish small, offline reference-feed snapshots through the real sync code (no network).

Every helper writes fixture source files locally, runs the step's own normalize/index and publish
functions, and returns the feed root. ``pin_feeds`` then pins them exactly as
``job_review_data_indexing`` does. ``published_at`` is rewritten to a caller-chosen instant so that
fixtures are byte-stable and staleness is controllable.
"""
from __future__ import annotations

from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping
import zipfile
from xml.sax.saxutils import escape

from appsec_review.jobs.job_third_party_data_sync.steps.epss_sync import feed as epss_feed
from appsec_review.jobs.job_third_party_data_sync.steps.kev_sync import feed as kev_feed
from appsec_review.jobs.job_third_party_data_sync.steps.mitre_sync import feed as mitre_feed
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.feed import NvdPublisher
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.models import NvdSettings
from appsec_review.jobs.job_third_party_data_sync.steps.osv_sync import feed as osv_feed

FIXED_NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def _source(path: Path) -> dict[str, Any]:
    payload = path.read_bytes()
    return {"url": "https://fixture.invalid/" + path.name, "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload), "etag": None, "last_modified": None,
            "retrieved_at": "2026-10-12T00:00:00.000Z", "path": str(path)}


def set_published_at(root: Path, instant: str) -> None:
    pointer = json.loads((root / "current.json").read_text(encoding="utf-8"))
    pointer["published_at"] = instant
    (root / "current.json").write_text(json.dumps(pointer, sort_keys=True), encoding="utf-8")


def nvd_vulnerability(cve_id: str, *, modified: str = "2026-01-01T00:00:00.000", status: str = "Analyzed",
                      description: str = "Fixture vulnerability", cwes: Iterable[str] = (),
                      metrics: Mapping[str, Iterable[Mapping[str, Any]]] | None = None) -> dict[str, Any]:
    return {"cve": {"id": cve_id, "sourceIdentifier": "fixture", "published": "2026-01-01T00:00:00.000",
                    "lastModified": modified, "vulnStatus": status,
                    "descriptions": [{"lang": "en", "value": description}],
                    "weaknesses": [{"description": [{"lang": "en", "value": cwe} for cwe in cwes]}],
                    "metrics": {family: [{"type": "Primary", "cvssData": dict(item)} for item in values]
                                for family, values in (metrics or {}).items()}}}


class _NvdClient:
    def __init__(self, vulnerabilities: list[dict[str, Any]], pages: list[dict[str, Any]] | None = None):
        self.raw = json.dumps({"format": "NVD_CVE", "version": "2.0", "vulnerabilities": vulnerabilities},
                              separators=(",", ":")).encode()
        self.compressed = gzip.compress(self.raw, mtime=0)
        self.pages = pages or []

    def get_bytes(self, url: str, api_key: str | None = None) -> bytes:
        if url.endswith(".meta"):
            return (f"lastModifiedDate:2026-10-08T00:00:00.000Z\nsize:{len(self.raw)}\n"
                    f"gzSize:{len(self.compressed)}\nsha256:{hashlib.sha256(self.raw).hexdigest()}\n").encode()
        return json.dumps({"format": "NVD_CVE", "version": "2.0", "startIndex": 0, "resultsPerPage": len(self.pages),
                           "totalResults": len(self.pages), "vulnerabilities": self.pages}).encode()

    def download(self, url: str, destination: Path, api_key: str | None = None) -> int:
        destination.write_bytes(self.compressed)
        return len(self.compressed)


def nvd_settings(root: Path) -> NvdSettings:
    return NvdSettings.from_mapping(root, {"feed_root": str(root), "first_year": 2026,
                                           "request_delay_with_key_seconds": 0,
                                           "request_delay_without_key_seconds": 0})


def publish_nvd(root: Path, vulnerabilities: list[dict[str, Any]], *, now: datetime = FIXED_NOW,
                updates: list[dict[str, Any]] | None = None) -> Path:
    settings = nvd_settings(root)
    NvdPublisher(settings, client=_NvdClient(vulnerabilities), clock=lambda: now, pause=lambda _: None).sync("fixture")
    if updates:
        later = now.replace(hour=1)
        NvdPublisher(settings, client=_NvdClient(vulnerabilities, updates), clock=lambda: later,
                     pause=lambda _: None).sync("fixture")
    return root


def publish_osv(root: Path, records: list[dict[str, Any]], work: Path) -> Path:
    settings = osv_feed.OsvSettings.from_mapping(root, {"feed_root": str(root), "ecosystems": ["PyPI"]})
    work.mkdir(parents=True, exist_ok=True)
    archive_path = work / "PyPI.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for record in records:
            info = zipfile.ZipInfo(f"{record['id']}.json", date_time=(2026, 1, 1, 0, 0, 0))
            archive.writestr(info, json.dumps(record, sort_keys=True))
    fetched = {"schema": "appsec-review/osv-fetch/1", "ecosystems": ["PyPI"], "archives": {"PyPI": _source(archive_path)}}
    indexed = osv_feed.index(settings, fetched, work)
    osv_feed.publish(settings, fetched, indexed)
    return root


Consequence = tuple[Iterable[str], Iterable[str]]      # (scopes, technical impacts)


def cwe_xml(weaknesses: Mapping[str, tuple], *, namespace: str = "http://cwe.mitre.org/cwe-7") -> str:
    """A CWE catalog document in the published layout (namespaced, Common_Consequences per weakness).

    Each value is ``(name, abstraction)`` or ``(name, abstraction, consequences)`` where
    ``consequences`` is a sequence of ``(scopes, technical impacts)``.
    """
    rows = []
    for cwe, value in sorted(weaknesses.items()):
        name, abstraction = escape(value[0], {'"': "&quot;"}), value[1]
        consequences = value[2] if len(value) > 2 else ()
        body = "".join(
            "<Consequence>" + "".join(f"<Scope>{escape(scope)}</Scope>" for scope in scopes)
            + "".join(f"<Impact>{escape(impact)}</Impact>" for impact in impacts)
            + "<Note>fixture note</Note></Consequence>" for scopes, impacts in consequences)
        inner = f"<Description>fixture</Description><Common_Consequences>{body}</Common_Consequences>" if body else ""
        rows.append(f'<Weakness ID="{cwe.split("-")[1]}" Name="{name}" Abstraction="{abstraction}" '
                    f'Status="Stable">{inner}</Weakness>')
    return (f'<Weakness_Catalog xmlns="{namespace}" Version="4.20"><Weaknesses>{"".join(rows)}</Weaknesses>'
            f'</Weakness_Catalog>')


def publish_mitre(root: Path, weaknesses: Mapping[str, tuple], work: Path) -> Path:
    """``weaknesses``: ``{"CWE-120": ("Buffer Copy without ...", "Base", [(scopes, impacts), ...])}``;
    the consequence list is optional (see :func:`cwe_xml`)."""
    sources = {"enterprise_attack": {"kind": "attack", "url": "https://raw.githubusercontent.com/a.json",
                                     "version": "19.2"},
               "capec": {"kind": "capec", "url": "https://raw.githubusercontent.com/c.json", "version": "3.9"},
               "cwe": {"kind": "cwe", "url": "https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip", "version": "4.20"}}
    settings = mitre_feed.MitreSettings.from_mapping(root, {"feed_root": str(root), "source_selections": list(sources),
                                                            "sources": sources})
    work.mkdir(parents=True, exist_ok=True)
    bundle = {"type": "bundle", "objects": [{"type": "attack-pattern", "id": "attack-pattern--fixture",
                                             "name": "Fixture", "external_references": [{"external_id": "T1001"}]}]}
    (work / "enterprise_attack.json").write_text(json.dumps(bundle), encoding="utf-8")
    (work / "capec.json").write_text(json.dumps(bundle), encoding="utf-8")
    with zipfile.ZipFile(work / "cwe.zip", "w") as archive:
        archive.writestr(zipfile.ZipInfo("cwec_v4.20.xml", date_time=(2026, 1, 1, 0, 0, 0)), cwe_xml(weaknesses))
    fetched = {"schema": "appsec-review/mitre-fetch/1", "sources": {
        name: {**_source(work / (f"{name}.zip" if name == "cwe" else f"{name}.json")), "kind": value["kind"],
               "version": value["version"], "expected_sha256": None} for name, value in sources.items()}}
    normalized = mitre_feed.normalize(settings, fetched, work)
    mitre_feed.publish(settings, fetched, normalized)
    return root


def kev_settings(root: Path, **overrides: Any) -> kev_feed.KevSettings:
    return kev_feed.KevSettings.from_mapping(root, {"feed_root": str(root), "url": KEV_URL, **overrides})


def kev_document(entries: Iterable[Mapping[str, Any]], *, version: str = "2026.10.10") -> dict[str, Any]:
    items = [dict(item) for item in entries]
    return {"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": version,
            "dateReleased": "2026-10-10T12:00:00.000Z", "count": len(items), "vulnerabilities": items}


def kev_entry(cve_id: str, **extra: Any) -> dict[str, Any]:
    return {"cveID": cve_id, "vendorProject": "Fixture", "product": "fixture", "vulnerabilityName": f"{cve_id} flaw",
            "dateAdded": "2026-09-01", "shortDescription": "fixture", "requiredAction": "patch",
            "dueDate": "2026-09-22", "knownRansomwareCampaignUse": "Known", "notes": "", "cwes": ["CWE-400"], **extra}


def publish_kev(root: Path, document: Mapping[str, Any], work: Path) -> Path:
    settings = kev_settings(root)
    work.mkdir(parents=True, exist_ok=True)
    path = work / "known_exploited_vulnerabilities.json"
    path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    fetched = {"schema": "appsec-review/kev-fetch/1", "source": {**_source(path), "url": KEV_URL,
                                                                 "expected_sha256": None}}
    kev_feed.publish(settings, fetched, kev_feed.normalize(settings, fetched, work))
    return root


def epss_settings(root: Path, **overrides: Any) -> epss_feed.EpssSettings:
    return epss_feed.EpssSettings.from_mapping(root, {"feed_root": str(root), "url": EPSS_URL, **overrides})


def epss_bytes(rows: Iterable[tuple[str, float, float]], *, score_date: str = "2026-10-11T12:55:00Z") -> bytes:
    text = f"#model_version:v2025.03.14,score_date:{score_date}\ncve,epss,percentile\n"
    text += "".join(f"{cve},{score:.5f},{percentile:.5f}\n" for cve, score, percentile in rows)
    return gzip.compress(text.encode(), mtime=0)


def publish_epss(root: Path, payload: bytes, work: Path) -> Path:
    settings = epss_settings(root)
    work.mkdir(parents=True, exist_ok=True)
    path = work / "epss_scores.csv.gz"
    path.write_bytes(payload)
    fetched = {"schema": "appsec-review/epss-fetch/1", "source": {**_source(path), "url": EPSS_URL,
                                                                  "expected_sha256": None}}
    epss_feed.publish(settings, fetched, epss_feed.normalize(settings, fetched, work))
    return root


def resolved_document(roots: Mapping[str, Path]) -> dict[str, Any]:
    """A resolved-configuration fragment naming each feed root (``feed_pins`` input)."""
    steps = {"nvd": "nvd_sync", "osv": "osv_sync", "mitre": "mitre_sync", "kev": "kev_sync", "epss": "epss_sync",
             "cve-bin-tool": "cve_bin_tool_db_build"}
    return {"jobs": {"job_third_party_data_sync": {"steps": {
        steps[feed]: {"settings": {"feed_root": str(path)}} for feed, path in roots.items()}}}}


def pin_feeds(base: Path, roots: Mapping[str, Path], *, now: datetime = FIXED_NOW, max_age_days: int = 14,
              overrides: Mapping[str, int] | None = None) -> dict[str, dict[str, Any]]:
    from appsec_review.jobs.job_review_data_indexing.job import feed_pins
    return feed_pins(base, resolved_document(roots), max_age_days, now=now, max_age_overrides=overrides)
