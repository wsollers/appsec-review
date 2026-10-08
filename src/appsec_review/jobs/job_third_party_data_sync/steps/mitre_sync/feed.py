from __future__ import annotations

from dataclasses import dataclass
import io
import json
from pathlib import Path
import sqlite3
from typing import Any, Mapping
import xml.etree.ElementTree as ET
import zipfile

from appsec_review.jobs.job_third_party_data_sync.publication import HttpDownloader, publish_snapshot, verify_current


REQUIRED_DEFAULTS = ("enterprise_attack", "capec", "cwe")
OPTIONAL_ATTACK = ("mobile_attack", "ics_attack")


@dataclass(frozen=True, slots=True)
class MitreSource:
    name: str
    kind: str
    url: str
    version: str
    sha256: str | None


@dataclass(frozen=True, slots=True)
class MitreSettings:
    feed_root: Path
    selections: tuple[str, ...]
    sources: Mapping[str, MitreSource]
    max_source_bytes: int
    max_uncompressed_bytes: int
    max_records: int
    max_lookup_results: int
    timeout_seconds: float

    @classmethod
    def from_mapping(cls, root: Path, value: Mapping[str, Any]) -> "MitreSettings":
        path = Path(str(value.get("feed_root", "")))
        selected_value = value.get("source_selections")
        source_value = value.get("sources")
        if not str(path) or not isinstance(selected_value, list) or not isinstance(source_value, Mapping):
            raise ValueError("MITRE feed_root, source_selections, and sources are required")
        selections = tuple(str(item) for item in selected_value)
        if not set(REQUIRED_DEFAULTS).issubset(selections):
            raise ValueError(f"MITRE defaults must include {list(REQUIRED_DEFAULTS)}")
        allowed = set(REQUIRED_DEFAULTS + OPTIONAL_ATTACK)
        if len(selections) != len(set(selections)) or not set(selections) <= allowed:
            raise ValueError("MITRE source selections are duplicated or unknown")
        sources: dict[str, MitreSource] = {}
        for name in selections:
            item = source_value.get(name)
            if not isinstance(item, Mapping):
                raise ValueError(f"MITRE source is not configured: {name}")
            expected = item.get("sha256")
            if expected is not None and (not isinstance(expected, str) or len(expected) != 64):
                raise ValueError(f"MITRE source sha256 is invalid: {name}")
            sources[name] = MitreSource(name, str(item.get("kind", "")), str(item.get("url", "")),
                                        str(item.get("version", "")), expected)
            if sources[name].kind not in ("attack", "capec", "cwe") or not sources[name].url or not sources[name].version:
                raise ValueError(f"MITRE source fields are invalid: {name}")
        settings = cls(
            feed_root=(root / path).resolve() if not path.is_absolute() else path.resolve(),
            selections=selections,
            sources=sources,
            max_source_bytes=int(value.get("max_source_bytes", 256 * 1024 * 1024)),
            max_uncompressed_bytes=int(value.get("max_uncompressed_bytes", 512 * 1024 * 1024)),
            max_records=int(value.get("max_records", 250_000)),
            max_lookup_results=int(value.get("max_lookup_results", 500)),
            timeout_seconds=float(value.get("timeout_seconds", 300)),
        )
        if min(settings.max_source_bytes, settings.max_uncompressed_bytes, settings.max_records, settings.max_lookup_results) < 1:
            raise ValueError("MITRE bounds must be positive")
        return settings


def fetch(settings: MitreSettings, work: Path, downloader: HttpDownloader | None = None) -> dict[str, Any]:
    client = downloader or HttpDownloader(timeout_seconds=settings.timeout_seconds, user_agent="appsec-review-mitre-sync/1")
    entries: dict[str, dict[str, Any]] = {}
    for name in settings.selections:
        source = settings.sources[name]
        suffix = ".zip" if source.kind == "cwe" else ".json"
        path = work / f"{name}{suffix}"
        record = client.download(source.url, path, max_bytes=settings.max_source_bytes,
                                 allowed_hosts=("raw.githubusercontent.com", "cwe.mitre.org"))
        if source.sha256 and record["sha256"].lower() != source.sha256.lower():
            raise ValueError(f"MITRE pinned source hash mismatch: {name}")
        entries[name] = {**record, "path": str(path), "kind": source.kind, "version": source.version,
                         "expected_sha256": source.sha256}
    return {"schema": "appsec-review/mitre-fetch/1", "sources": entries}


def _external_id(document: Mapping[str, Any]) -> str | None:
    for item in document.get("external_references", []):
        if isinstance(item, Mapping) and isinstance(item.get("external_id"), str):
            return item["external_id"]
    return None


def _xml_bytes(path: Path, bound: int) -> bytes:
    with zipfile.ZipFile(path) as archive:
        members = [member for member in archive.infolist() if not member.is_dir() and member.filename.lower().endswith(".xml")]
        if len(members) != 1:
            raise ValueError("CWE archive must contain exactly one XML document")
        member = members[0]
        relative = Path(member.filename)
        if relative.is_absolute() or ".." in relative.parts or member.file_size > bound:
            raise ValueError("unsafe CWE archive member")
        payload = archive.read(member)
    upper = payload[:65536].upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("CWE XML contains a prohibited DTD or entity declaration")
    return payload


def normalize(settings: MitreSettings, fetched: Mapping[str, Any], work: Path) -> dict[str, Any]:
    database = work / "mitre.sqlite"
    database.parent.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    total = 0
    with sqlite3.connect(database) as connection:
        connection.executescript("""
            PRAGMA journal_mode=DELETE;
            PRAGMA synchronous=FULL;
            CREATE TABLE entry(source TEXT NOT NULL, external_id TEXT NOT NULL, object_type TEXT NOT NULL,
                               name TEXT, description TEXT, modified TEXT, raw_json TEXT,
                               PRIMARY KEY(source, external_id));
            CREATE INDEX entry_lookup ON entry(external_id, source);
            CREATE INDEX entry_name ON entry(name, source);
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        for name, source in fetched["sources"].items():
            source_count = 0
            if source["kind"] in ("attack", "capec"):
                document = json.loads(Path(source["path"]).read_text(encoding="utf-8-sig"))
                objects = document.get("objects")
                if document.get("type") != "bundle" or not isinstance(objects, list):
                    raise ValueError(f"MITRE STIX source is not a bundle: {name}")
                for item in objects:
                    if not isinstance(item, Mapping):
                        continue
                    identifier = _external_id(item) or item.get("id")
                    if not isinstance(identifier, str):
                        continue
                    connection.execute("INSERT OR REPLACE INTO entry VALUES (?, ?, ?, ?, ?, ?, ?)",
                                       (name, identifier, str(item.get("type", "unknown")), item.get("name"),
                                        item.get("description"), item.get("modified"),
                                        json.dumps(item, sort_keys=True, separators=(",", ":"))))
                    source_count += 1
            else:
                payload = _xml_bytes(Path(source["path"]), settings.max_uncompressed_bytes)
                root = ET.parse(io.BytesIO(payload)).getroot()
                version = root.attrib.get("Version")
                if version and version != source["version"]:
                    raise ValueError(f"CWE version mismatch: expected {source['version']}, received {version}")
                for element in root.iter():
                    local = element.tag.rsplit("}", 1)[-1]
                    if local not in ("Weakness", "Category", "View") or "ID" not in element.attrib:
                        continue
                    identifier = ("CWE-" if local == "Weakness" else f"CWE-{local.upper()}-") + element.attrib["ID"]
                    connection.execute("INSERT OR REPLACE INTO entry VALUES (?, ?, ?, ?, ?, ?, ?)",
                                       (name, identifier, local.lower(), element.attrib.get("Name"), None, None, None))
                    source_count += 1
            total += source_count
            if total > settings.max_records:
                raise ValueError("MITRE record count exceeded configured bound")
            counts[name] = connection.execute("SELECT COUNT(*) FROM entry WHERE source = ?", (name,)).fetchone()[0]
        total = connection.execute("SELECT COUNT(*) FROM entry").fetchone()[0]
        connection.executemany("INSERT INTO metadata VALUES (?, ?)",
                               (("record_count", str(total)), ("max_lookup_results", str(settings.max_lookup_results))))
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("MITRE SQLite quick_check failed")
    return {"schema": "appsec-review/mitre-normalize/1", "database_path": str(database),
            "record_count": total, "source_counts": counts, "max_lookup_results": settings.max_lookup_results}


def publish(settings: MitreSettings, fetched: Mapping[str, Any], normalized: Mapping[str, Any]) -> dict[str, Any]:
    files = {f"sources/{Path(entry['path']).name}": Path(entry["path"]) for entry in fetched["sources"].values()}
    files["index/mitre.sqlite"] = Path(normalized["database_path"])
    sources = {name: {key: value for key, value in entry.items() if key != "path"}
               for name, entry in fetched["sources"].items()}
    return publish_snapshot(settings.feed_root, feed_id="mitre", schema="appsec-review/mitre-snapshot/1", files=files,
                            manifest_fields={"source_selections": list(settings.selections), "sources": sources,
                                             "record_count": normalized["record_count"],
                                             "source_counts": normalized["source_counts"],
                                             "max_lookup_results": settings.max_lookup_results,
                                             "limitations": ["MITRE references classify claims; they are not finding evidence."]})


def verify(settings: MitreSettings) -> dict[str, Any]:
    identity = verify_current(settings.feed_root, "mitre")
    database = Path(identity["directory"]) / "index" / "mitre.sqlite"
    with sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True) as connection:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("MITRE SQLite verification failed")
        count = connection.execute("SELECT COUNT(*) FROM entry").fetchone()[0]
    return {**identity, "record_count": count}
