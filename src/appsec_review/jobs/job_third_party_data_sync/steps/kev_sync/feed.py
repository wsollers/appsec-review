"""CISA Known Exploited Vulnerabilities (KEV) catalog synchronization: fetch, normalize, publish.

The catalog JSON is downloaded from a configured HTTPS URL on a host allowlist, bounded in bytes and
records, optionally verified against a configured SHA-256 pin, validated (unique well-formed CVE
ids, ISO dates, a declared count that matches), and normalized into ``index/kev.sqlite``. KEV is
reference context: a listing says a CVE is known to be exploited somewhere, never that the target
is affected or exploitable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Mapping
import urllib.parse

from appsec_review.jobs.job_third_party_data_sync.publication import HttpDownloader, publish_snapshot, verify_current

FEED_ID = "kev"
INDEX_SCHEMA = "appsec-review/kev-index/1"
LOGICAL_PATH = "index/kev.sqlite"
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_TEXT = 512


@dataclass(frozen=True, slots=True)
class KevSettings:
    feed_root: Path
    url: str
    sha256: str | None
    allowed_hosts: tuple[str, ...]
    max_source_bytes: int
    max_records: int
    timeout_seconds: float

    @classmethod
    def from_mapping(cls, root: Path, value: Mapping[str, Any]) -> "KevSettings":
        path = Path(str(value.get("feed_root", "")))
        url = str(value.get("url", ""))
        hosts = value.get("allowed_hosts", ["www.cisa.gov"])
        if not str(path) or not url:
            raise ValueError("KEV feed_root and url are required")
        if not isinstance(hosts, list) or not hosts or any(not isinstance(item, str) or not item for item in hosts):
            raise ValueError("KEV allowed_hosts must be a non-empty list of host names")
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in hosts:
            raise ValueError("KEV url must be HTTPS on an allowed host")
        expected = value.get("sha256")
        if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected)):
            raise ValueError("KEV sha256 pin is invalid")
        settings = cls(
            feed_root=(root / path).resolve() if not path.is_absolute() else path.resolve(),
            url=url, sha256=expected.lower() if expected else None, allowed_hosts=tuple(hosts),
            max_source_bytes=int(value.get("max_source_bytes", 32 * 1024 * 1024)),
            max_records=int(value.get("max_records", 50_000)),
            timeout_seconds=float(value.get("timeout_seconds", 120)),
        )
        if min(settings.max_source_bytes, settings.max_records) < 1 or settings.timeout_seconds <= 0:
            raise ValueError("KEV bounds must be positive")
        return settings


def fetch(settings: KevSettings, work: Path, downloader: HttpDownloader | None = None) -> dict[str, Any]:
    client = downloader or HttpDownloader(timeout_seconds=settings.timeout_seconds, user_agent="appsec-review-kev-sync/1")
    path = work / "known_exploited_vulnerabilities.json"
    record = client.download(settings.url, path, max_bytes=settings.max_source_bytes,
                             allowed_hosts=settings.allowed_hosts)
    if int(record["size_bytes"]) > settings.max_source_bytes or path.stat().st_size > settings.max_source_bytes:
        raise ValueError("KEV download exceeded the configured byte bound")
    if settings.sha256 and record["sha256"].lower() != settings.sha256:
        raise ValueError("KEV pinned source hash mismatch")
    return {"schema": "appsec-review/kev-fetch/1", "source": {**record, "path": str(path),
                                                              "expected_sha256": settings.sha256}}


def _date(value: Any, field: str, *, optional: bool = False) -> str | None:
    if value in (None, "") and optional:
        return None
    if not isinstance(value, str):
        raise ValueError(f"KEV {field} must be an ISO date")
    try:
        date.fromisoformat(value[:10])
    except ValueError:
        raise ValueError(f"KEV {field} must be an ISO date") from None
    return value[:10]


def _text(value: Any) -> str | None:
    return value.strip()[:_TEXT] if isinstance(value, str) and value.strip() else None


def normalize(settings: KevSettings, fetched: Mapping[str, Any], work: Path) -> dict[str, Any]:
    source = Path(fetched["source"]["path"])
    if source.stat().st_size > settings.max_source_bytes:
        raise ValueError("KEV source exceeds the configured byte bound")
    try:
        document = json.loads(source.read_text(encoding="utf-8-sig"))
    except ValueError as exc:
        raise ValueError(f"KEV catalog is not valid JSON: {exc}") from None
    vulnerabilities = document.get("vulnerabilities") if isinstance(document, Mapping) else None
    version = _text(document.get("catalogVersion")) if isinstance(document, Mapping) else None
    if not isinstance(vulnerabilities, list) or version is None:
        raise ValueError("KEV catalog has no catalogVersion or vulnerabilities array")
    released = _date(document.get("dateReleased"), "dateReleased")
    if len(vulnerabilities) > settings.max_records:
        raise ValueError("KEV record count exceeded the configured bound")
    declared = document.get("count")
    if declared is not None and declared != len(vulnerabilities):
        raise ValueError("KEV declared count does not match its vulnerabilities array")
    rows: dict[str, tuple[Any, ...]] = {}
    for item in vulnerabilities:
        if not isinstance(item, Mapping):
            raise ValueError("KEV vulnerability entry must be an object")
        cve = item.get("cveID")
        if not isinstance(cve, str) or not _CVE.fullmatch(cve):
            raise ValueError(f"KEV entry has an invalid cveID: {cve!r}")
        if cve in rows:
            raise ValueError(f"KEV catalog repeats {cve}")
        ransomware = _text(item.get("knownRansomwareCampaignUse"))
        rows[cve] = (cve, _text(item.get("vendorProject")), _text(item.get("product")),
                     _text(item.get("vulnerabilityName")), _date(item.get("dateAdded"), "dateAdded"),
                     _date(item.get("dueDate"), "dueDate", optional=True), ransomware,
                     json.dumps(sorted(str(value) for value in item.get("cwes") or () if isinstance(value, str))[:16],
                                separators=(",", ":")), version)
    database = work / "kev.sqlite"
    database.parent.mkdir(parents=True, exist_ok=True)
    if database.exists():
        database.unlink()
    with sqlite3.connect(database) as connection:
        connection.executescript("""
            PRAGMA journal_mode=DELETE;
            CREATE TABLE kev(cve_id TEXT PRIMARY KEY, vendor_project TEXT, product TEXT, vulnerability_name TEXT,
                             date_added TEXT NOT NULL, due_date TEXT, known_ransomware_use TEXT,
                             cwes_json TEXT NOT NULL, catalog_version TEXT NOT NULL);
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        connection.executemany("INSERT INTO kev VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (rows[key] for key in sorted(rows)))
        connection.executemany("INSERT INTO metadata VALUES (?, ?)", (
            ("schema", INDEX_SCHEMA), ("record_count", str(len(rows))), ("catalog_version", version),
            ("date_released", released or "")))
        connection.commit()
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("KEV SQLite quick_check failed")
    return {"schema": "appsec-review/kev-normalize/1", "database_path": str(database), "record_count": len(rows),
            "catalog_version": version, "date_released": released}


def publish(settings: KevSettings, fetched: Mapping[str, Any], normalized: Mapping[str, Any]) -> dict[str, Any]:
    source = {key: value for key, value in fetched["source"].items() if key not in {"path", "retrieved_at",
                                                                                   "etag", "last_modified"}}
    files = {"sources/known_exploited_vulnerabilities.json": Path(fetched["source"]["path"]),
             LOGICAL_PATH: Path(normalized["database_path"])}
    return publish_snapshot(settings.feed_root, feed_id=FEED_ID, schema="appsec-review/kev-snapshot/1", files=files,
                            manifest_fields={"source": source, "record_count": normalized["record_count"],
                                             "catalog_version": normalized["catalog_version"],
                                             "date_released": normalized["date_released"],
                                             "index_schema": INDEX_SCHEMA,
                                             "limitations": ["A KEV listing is reference context: the CVE is known "
                                                             "to be exploited somewhere, not that this target is "
                                                             "affected, reachable or exploitable."]})


def verify(settings: KevSettings) -> dict[str, Any]:
    identity = verify_current(settings.feed_root, FEED_ID)
    database = Path(identity["directory"]) / LOGICAL_PATH
    with sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True) as connection:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("KEV SQLite verification failed")
        count = connection.execute("SELECT COUNT(*) FROM kev").fetchone()[0]
    return {**identity, "record_count": count}


def lookup(database: sqlite3.Connection, cve_id: str) -> dict[str, Any] | None:
    row = database.execute("SELECT cve_id, vendor_project, product, vulnerability_name, date_added, due_date, "
                           "known_ransomware_use, catalog_version FROM kev WHERE cve_id = ?", (cve_id,)).fetchone()
    if row is None:
        return None
    keys = ("cve_id", "vendor_project", "product", "vulnerability_name", "date_added", "due_date",
            "known_ransomware_use", "catalog_version")
    return dict(zip(keys, tuple(row)))
