"""FIRST EPSS daily score synchronization: fetch, normalize, publish.

The daily ``epss_scores-current.csv.gz`` is downloaded from a configured HTTPS URL on a host
allowlist, bounded in compressed bytes, uncompressed bytes and records, optionally verified against
a SHA-256 pin, and validated: a ``#model_version:...,score_date:...`` comment line, a
``cve,epss,percentile`` header, unique well-formed CVE ids and probabilities in ``[0, 1]``. Rows
are normalized into ``index/epss.sqlite``. EPSS is a population-level exploitation probability; it
is reference context only and never evidence about the target.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
import gzip
import io
import math
from pathlib import Path
import re
import sqlite3
from typing import Any, Mapping
import urllib.parse

from appsec_review.jobs.job_third_party_data_sync.publication import HttpDownloader, publish_snapshot, verify_current

FEED_ID = "epss"
INDEX_SCHEMA = "appsec-review/epss-index/1"
LOGICAL_PATH = "index/epss.sqlite"
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


@dataclass(frozen=True, slots=True)
class EpssSettings:
    feed_root: Path
    url: str
    sha256: str | None
    allowed_hosts: tuple[str, ...]
    max_source_bytes: int
    max_uncompressed_bytes: int
    max_records: int
    timeout_seconds: float

    @classmethod
    def from_mapping(cls, root: Path, value: Mapping[str, Any]) -> "EpssSettings":
        path = Path(str(value.get("feed_root", "")))
        url = str(value.get("url", ""))
        hosts = value.get("allowed_hosts", ["epss.empiricalsecurity.com"])
        if not str(path) or not url:
            raise ValueError("EPSS feed_root and url are required")
        if not isinstance(hosts, list) or not hosts or any(not isinstance(item, str) or not item for item in hosts):
            raise ValueError("EPSS allowed_hosts must be a non-empty list of host names")
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in hosts:
            raise ValueError("EPSS url must be HTTPS on an allowed host")
        expected = value.get("sha256")
        if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected)):
            raise ValueError("EPSS sha256 pin is invalid")
        settings = cls(
            feed_root=(root / path).resolve() if not path.is_absolute() else path.resolve(),
            url=url, sha256=expected.lower() if expected else None, allowed_hosts=tuple(hosts),
            max_source_bytes=int(value.get("max_source_bytes", 64 * 1024 * 1024)),
            max_uncompressed_bytes=int(value.get("max_uncompressed_bytes", 256 * 1024 * 1024)),
            max_records=int(value.get("max_records", 1_000_000)),
            timeout_seconds=float(value.get("timeout_seconds", 120)),
        )
        if min(settings.max_source_bytes, settings.max_uncompressed_bytes, settings.max_records) < 1 or \
                settings.timeout_seconds <= 0:
            raise ValueError("EPSS bounds must be positive")
        return settings


def fetch(settings: EpssSettings, work: Path, downloader: HttpDownloader | None = None) -> dict[str, Any]:
    client = downloader or HttpDownloader(timeout_seconds=settings.timeout_seconds,
                                          user_agent="appsec-review-epss-sync/1")
    path = work / "epss_scores.csv.gz"
    record = client.download(settings.url, path, max_bytes=settings.max_source_bytes,
                             allowed_hosts=settings.allowed_hosts)
    if int(record["size_bytes"]) > settings.max_source_bytes or path.stat().st_size > settings.max_source_bytes:
        raise ValueError("EPSS download exceeded the configured byte bound")
    if settings.sha256 and record["sha256"].lower() != settings.sha256:
        raise ValueError("EPSS pinned source hash mismatch")
    return {"schema": "appsec-review/epss-fetch/1", "source": {**record, "path": str(path),
                                                               "expected_sha256": settings.sha256}}


def _probability(value: str, field: str, line: int) -> float:
    try:
        number = float(value)
    except ValueError:
        raise ValueError(f"EPSS line {line}: {field} is not a number") from None
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError(f"EPSS line {line}: {field} is outside [0, 1]")
    return number


def _text(path: Path, bound: int) -> str:
    with gzip.open(path, "rb") as stream:
        payload = stream.read(bound + 1)
    if len(payload) > bound:
        raise ValueError("EPSS decompression exceeded the configured uncompressed byte bound")
    return payload.decode("utf-8-sig")


def normalize(settings: EpssSettings, fetched: Mapping[str, Any], work: Path) -> dict[str, Any]:
    source = Path(fetched["source"]["path"])
    if source.stat().st_size > settings.max_source_bytes:
        raise ValueError("EPSS source exceeds the configured byte bound")
    try:
        text = _text(source, settings.max_uncompressed_bytes)
    except (OSError, EOFError, UnicodeDecodeError) as exc:
        raise ValueError(f"EPSS source is not a readable gzip CSV: {type(exc).__name__}") from None
    lines = text.splitlines()
    if not lines or not lines[0].startswith("#"):
        raise ValueError("EPSS file has no model_version/score_date comment line")
    fields = dict(item.split(":", 1) for item in lines[0][1:].split(",") if ":" in item)
    model_version, score_date = fields.get("model_version", "").strip(), fields.get("score_date", "").strip()
    try:
        datetime.fromisoformat(score_date.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("EPSS score_date is missing or not ISO 8601") from None
    if not model_version or len(model_version) > 64:
        raise ValueError("EPSS model_version is missing")
    reader = csv.reader(io.StringIO("\n".join(lines[1:])))
    header = next(reader, None)
    if header is None or [item.strip() for item in header] != ["cve", "epss", "percentile"]:
        raise ValueError("EPSS header must be cve,epss,percentile")
    rows: dict[str, tuple[Any, ...]] = {}
    for number, row in enumerate(reader, start=3):
        if not row:
            continue
        if len(row) != 3:
            raise ValueError(f"EPSS line {number} does not have three columns")
        cve = row[0].strip()
        if not _CVE.fullmatch(cve):
            raise ValueError(f"EPSS line {number} has an invalid CVE id")
        if cve in rows:
            raise ValueError(f"EPSS repeats {cve}")
        rows[cve] = (cve, _probability(row[1], "epss", number), _probability(row[2], "percentile", number),
                     score_date[:10], model_version)
        if len(rows) > settings.max_records:
            raise ValueError("EPSS record count exceeded the configured bound")
    if not rows:
        raise ValueError("EPSS file contains no scores")
    database = work / "epss.sqlite"
    database.parent.mkdir(parents=True, exist_ok=True)
    if database.exists():
        database.unlink()
    with sqlite3.connect(database) as connection:
        connection.executescript("""
            PRAGMA journal_mode=DELETE;
            CREATE TABLE epss(cve_id TEXT PRIMARY KEY, epss REAL NOT NULL, percentile REAL NOT NULL,
                              score_date TEXT NOT NULL, model_version TEXT NOT NULL);
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        connection.executemany("INSERT INTO epss VALUES (?, ?, ?, ?, ?)", (rows[key] for key in sorted(rows)))
        connection.executemany("INSERT INTO metadata VALUES (?, ?)", (
            ("schema", INDEX_SCHEMA), ("record_count", str(len(rows))), ("model_version", model_version),
            ("score_date", score_date)))
        connection.commit()
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("EPSS SQLite quick_check failed")
    return {"schema": "appsec-review/epss-normalize/1", "database_path": str(database), "record_count": len(rows),
            "model_version": model_version, "score_date": score_date}


def publish(settings: EpssSettings, fetched: Mapping[str, Any], normalized: Mapping[str, Any]) -> dict[str, Any]:
    source = {key: value for key, value in fetched["source"].items() if key not in {"path", "retrieved_at",
                                                                                   "etag", "last_modified"}}
    files = {"sources/epss_scores.csv.gz": Path(fetched["source"]["path"]),
             LOGICAL_PATH: Path(normalized["database_path"])}
    return publish_snapshot(settings.feed_root, feed_id=FEED_ID, schema="appsec-review/epss-snapshot/1", files=files,
                            manifest_fields={"source": source, "record_count": normalized["record_count"],
                                             "model_version": normalized["model_version"],
                                             "score_date": normalized["score_date"], "index_schema": INDEX_SCHEMA,
                                             "limitations": ["EPSS is a population-level probability of observed "
                                                             "exploitation activity; it is reference context, not "
                                                             "evidence about this target."]})


def verify(settings: EpssSettings) -> dict[str, Any]:
    identity = verify_current(settings.feed_root, FEED_ID)
    database = Path(identity["directory"]) / LOGICAL_PATH
    with sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True) as connection:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("EPSS SQLite verification failed")
        count = connection.execute("SELECT COUNT(*) FROM epss").fetchone()[0]
    return {**identity, "record_count": count}


def lookup(database: sqlite3.Connection, cve_id: str) -> dict[str, Any] | None:
    row = database.execute("SELECT cve_id, epss, percentile, score_date, model_version FROM epss WHERE cve_id = ?",
                           (cve_id,)).fetchone()
    return None if row is None else dict(zip(("cve_id", "epss", "percentile", "score_date", "model_version"),
                                             tuple(row)))
