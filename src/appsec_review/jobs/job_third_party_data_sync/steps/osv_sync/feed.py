from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
from typing import Any, Mapping
import urllib.parse
import zipfile

from appsec_review.jobs.job_third_party_data_sync.publication import HttpDownloader, publish_snapshot, verify_current


@dataclass(frozen=True, slots=True)
class OsvSettings:
    feed_root: Path
    ecosystems: tuple[str, ...]
    max_archive_bytes: int
    max_uncompressed_bytes: int
    max_records: int
    max_lookup_results: int
    timeout_seconds: float

    @classmethod
    def from_mapping(cls, root: Path, value: Mapping[str, Any]) -> "OsvSettings":
        path = Path(str(value.get("feed_root", "")))
        ecosystems_value = value.get("ecosystems")
        if not str(path) or not isinstance(ecosystems_value, list) or not ecosystems_value:
            raise ValueError("OSV feed_root and an explicit ecosystems list are required")
        ecosystems = tuple(str(item) for item in ecosystems_value)
        if len(ecosystems) != len(set(ecosystems)) or any(not item.strip() or "/" in item or "\\" in item for item in ecosystems):
            raise ValueError("OSV ecosystems must be unique safe names")
        settings = cls(
            feed_root=(root / path).resolve() if not path.is_absolute() else path.resolve(),
            ecosystems=ecosystems,
            max_archive_bytes=int(value.get("max_archive_bytes", 512 * 1024 * 1024)),
            max_uncompressed_bytes=int(value.get("max_uncompressed_bytes", 2 * 1024 * 1024 * 1024)),
            max_records=int(value.get("max_records", 500_000)),
            max_lookup_results=int(value.get("max_lookup_results", 500)),
            timeout_seconds=float(value.get("timeout_seconds", 300)),
        )
        if min(settings.max_archive_bytes, settings.max_uncompressed_bytes, settings.max_records, settings.max_lookup_results) < 1:
            raise ValueError("OSV bounds must be positive")
        return settings


def fetch(settings: OsvSettings, work: Path, downloader: HttpDownloader | None = None) -> dict[str, Any]:
    client = downloader or HttpDownloader(timeout_seconds=settings.timeout_seconds, user_agent="appsec-review-osv-sync/1")
    archives: dict[str, dict[str, Any]] = {}
    for ecosystem in settings.ecosystems:
        url = "https://storage.googleapis.com/osv-vulnerabilities/" + urllib.parse.quote(ecosystem, safe="") + "/all.zip"
        path = work / (urllib.parse.quote(ecosystem, safe="") + ".zip")
        source = client.download(url, path, max_bytes=settings.max_archive_bytes, allowed_hosts=("storage.googleapis.com",))
        archives[ecosystem] = {**source, "path": str(path)}
    return {"schema": "appsec-review/osv-fetch/1", "ecosystems": list(settings.ecosystems), "archives": archives}


def index(settings: OsvSettings, fetched: Mapping[str, Any], work: Path) -> dict[str, Any]:
    database = work / "osv.sqlite"
    database.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    expanded = 0
    with sqlite3.connect(database) as connection:
        connection.executescript("""
            PRAGMA journal_mode=DELETE;
            PRAGMA synchronous=FULL;
            CREATE TABLE advisory(id TEXT PRIMARY KEY, modified TEXT, published TEXT, withdrawn TEXT, summary TEXT, raw_json TEXT NOT NULL);
            CREATE TABLE package(advisory_id TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL);
            CREATE TABLE alias(advisory_id TEXT NOT NULL, alias TEXT NOT NULL);
            CREATE INDEX package_lookup ON package(ecosystem, name, advisory_id);
            CREATE INDEX alias_lookup ON alias(alias, advisory_id);
        """)
        for ecosystem, entry in fetched["archives"].items():
            with zipfile.ZipFile(entry["path"]) as archive:
                for member in archive.infolist():
                    if member.is_dir():
                        continue
                    member_path = Path(member.filename)
                    if member_path.is_absolute() or ".." in member_path.parts or member.file_size > settings.max_uncompressed_bytes:
                        raise ValueError(f"unsafe OSV archive member: {member.filename}")
                    expanded += member.file_size
                    if expanded > settings.max_uncompressed_bytes:
                        raise ValueError("OSV extraction exceeded configured uncompressed byte bound")
                    if member_path.suffix.lower() != ".json":
                        continue
                    document = json.loads(archive.read(member))
                    identifier = document.get("id")
                    if not isinstance(identifier, str) or not identifier:
                        raise ValueError(f"OSV record has no id: {member.filename}")
                    count += 1
                    if count > settings.max_records:
                        raise ValueError("OSV record count exceeded configured bound")
                    connection.execute(
                        "INSERT INTO advisory VALUES (?, ?, ?, ?, ?, ?)",
                        (identifier, document.get("modified"), document.get("published"), document.get("withdrawn"),
                         document.get("summary"), json.dumps(document, sort_keys=True, separators=(",", ":"))),
                    )
                    for alias in document.get("aliases", []):
                        if isinstance(alias, str):
                            connection.execute("INSERT INTO alias VALUES (?, ?)", (identifier, alias))
                    packages: set[tuple[str, str]] = set()
                    for affected in document.get("affected", []):
                        package = affected.get("package") if isinstance(affected, dict) else None
                        if isinstance(package, dict) and isinstance(package.get("ecosystem"), str) and isinstance(package.get("name"), str):
                            packages.add((package["ecosystem"], package["name"]))
                    for package_ecosystem, name in sorted(packages):
                        connection.execute("INSERT INTO package VALUES (?, ?, ?)", (identifier, package_ecosystem, name))
        connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.executemany("INSERT INTO metadata VALUES (?, ?)", (("record_count", str(count)), ("max_lookup_results", str(settings.max_lookup_results))))
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("OSV SQLite quick_check failed")
    return {"schema": "appsec-review/osv-index/1", "database_path": str(database), "record_count": count,
            "max_lookup_results": settings.max_lookup_results, "expanded_bytes": expanded}


def publish(settings: OsvSettings, fetched: Mapping[str, Any], indexed: Mapping[str, Any]) -> dict[str, Any]:
    files = {f"sources/{urllib.parse.quote(name, safe='')}.zip": Path(entry["path"])
             for name, entry in fetched["archives"].items()}
    files["index/osv.sqlite"] = Path(indexed["database_path"])
    sources = {name: {key: value for key, value in entry.items() if key != "path"}
               for name, entry in fetched["archives"].items()}
    return publish_snapshot(settings.feed_root, feed_id="osv", schema="appsec-review/osv-snapshot/1", files=files,
                            manifest_fields={"ecosystems": list(settings.ecosystems), "sources": sources,
                                             "record_count": indexed["record_count"],
                                             "max_lookup_results": settings.max_lookup_results,
                                             "limitations": ["OSV matches are applicability leads, not findings."]})


def verify(settings: OsvSettings) -> dict[str, Any]:
    identity = verify_current(settings.feed_root, "osv")
    database = Path(identity["directory"]) / "index" / "osv.sqlite"
    with sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True) as connection:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("OSV SQLite verification failed")
        count = connection.execute("SELECT COUNT(*) FROM advisory").fetchone()[0]
    return {**identity, "record_count": count}


def lookup_package(settings: OsvSettings, ecosystem: str, name: str, *, limit: int = 100) -> dict[str, Any]:
    if not ecosystem.strip() or not name.strip():
        raise ValueError("OSV package ecosystem and name are required")
    if not 1 <= limit <= settings.max_lookup_results:
        raise ValueError(f"OSV lookup limit must be between 1 and {settings.max_lookup_results}")
    identity = verify_current(settings.feed_root, "osv")
    database = Path(identity["directory"]) / "index" / "osv.sqlite"
    with sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True) as connection:
        rows = connection.execute(
            "SELECT a.id, a.modified, a.summary FROM package p JOIN advisory a ON a.id=p.advisory_id "
            "WHERE p.ecosystem=? AND p.name=? ORDER BY a.modified DESC, a.id LIMIT ?",
            (ecosystem, name, limit),
        ).fetchall()
    return {
        "schema": "appsec-review/osv-package-lookup/1",
        "snapshot_id": identity["snapshot_id"],
        "query": {"ecosystem": ecosystem, "name": name, "limit": limit},
        "items": [{"advisory_id": row[0], "modified": row[1], "summary": row[2]} for row in rows],
        "gap": None if rows else "NO_MATCH_IN_CONFIGURED_OSV_ECOSYSTEMS",
    }
