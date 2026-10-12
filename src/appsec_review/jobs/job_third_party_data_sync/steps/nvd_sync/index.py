"""Compact, deterministic CVE lookup index built from the NVD metadata JSONL layers.

``index/nvd.sqlite`` is keyed by CVE id and holds only the reference fields the review consumes:
the English description, CWE weakness ids, CVSS metrics (family, version, vector, base score and
severity), NVD ``vulnStatus``, publication and last-modified timestamps, and the SHA-256 of the
canonical raw record. It is rebuilt from the parent snapshot's index plus the new layers
(incremental) or by replaying every layer of the snapshot chain; a later layer overrides an earlier
one when its ``last_modified`` is not older. The published file is written by sorted insertion
into a fresh database, so identical inputs give identical bytes.
"""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import closing
import gzip
import json
from pathlib import Path
import sqlite3
from typing import Any

INDEX_SCHEMA = "appsec-review/nvd-index/1"
LOGICAL_PATH = "index/nvd.sqlite"
MAX_DESCRIPTION = 4096
MAX_METRICS = 16
MAX_WEAKNESSES = 16
_COLUMNS = ("cve_id", "status", "published", "last_modified", "description_en", "weaknesses_json",
            "cvss_json", "raw_sha256")


def _text(value: Any, bound: int = 256) -> str | None:
    return value[:bound] if isinstance(value, str) and value else None


def _record(item: dict[str, Any]) -> tuple[Any, ...]:
    identifier = item.get("id")
    if not isinstance(identifier, str) or not identifier.startswith("CVE-"):
        raise ValueError(f"invalid NVD metadata identity: {identifier!r}")
    weaknesses = sorted({value for value in item.get("weaknesses") or () if isinstance(value, str)
                         and value.startswith("CWE-")})[:MAX_WEAKNESSES]
    metrics = []
    for metric in item.get("metrics") or ():
        if not isinstance(metric, dict):
            continue
        score = metric.get("base_score")
        metrics.append({"family": _text(metric.get("family"), 64), "version": _text(metric.get("version"), 16),
                        "vector": _text(metric.get("vector"), 256),
                        "base_score": float(score) if isinstance(score, (int, float))
                        and not isinstance(score, bool) else None,
                        "base_severity": _text(metric.get("base_severity"), 32)})
    metrics.sort(key=lambda value: json.dumps(value, sort_keys=True))
    return (identifier, _text(item.get("status"), 64), _text(item.get("published"), 64),
            _text(item.get("last_modified"), 64), _text(item.get("description_en"), MAX_DESCRIPTION),
            json.dumps(weaknesses, separators=(",", ":")),
            json.dumps(metrics[:MAX_METRICS], sort_keys=True, separators=(",", ":")),
            _text(item.get("raw_sha256"), 64))


def _iter_layer(path: Path) -> Iterable[dict[str, Any]]:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("NVD metadata line is not an object")
                yield value


def build_index(destination: Path, layers: Iterable[Path], *, base: Path | None = None) -> dict[str, Any]:
    """Merge ``layers`` (oldest first) over ``base`` into a deterministic SQLite index."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    work = destination.with_name(destination.name + ".work")
    for path in (destination, work):
        if path.exists():
            path.unlink()
    layer_count = 0
    with closing(sqlite3.connect(work)) as connection:
        connection.execute("CREATE TABLE cve(cve_id TEXT PRIMARY KEY, status TEXT, published TEXT, "
                           "last_modified TEXT, description_en TEXT, weaknesses_json TEXT NOT NULL, "
                           "cvss_json TEXT NOT NULL, raw_sha256 TEXT)")
        if base is not None:
            connection.execute("ATTACH DATABASE ? AS base", (str(base),))
            connection.execute(f"INSERT INTO cve SELECT {', '.join(_COLUMNS)} FROM base.cve")
            connection.commit()
            connection.execute("DETACH DATABASE base")
        upsert = (f"INSERT INTO cve({', '.join(_COLUMNS)}) VALUES ({', '.join('?' for _ in _COLUMNS)}) "
                  "ON CONFLICT(cve_id) DO UPDATE SET "
                  + ", ".join(f"{column}=excluded.{column}" for column in _COLUMNS[1:])
                  + " WHERE excluded.last_modified IS NULL OR cve.last_modified IS NULL "
                    "OR excluded.last_modified >= cve.last_modified")
        for layer in layers:
            layer_count += 1
            for item in _iter_layer(Path(layer)):
                connection.execute(upsert, _record(item))
        connection.commit()
    with closing(sqlite3.connect(destination)) as connection:
        connection.executescript("""
            PRAGMA journal_mode=DELETE;
            CREATE TABLE cve(cve_id TEXT PRIMARY KEY, status TEXT, published TEXT, last_modified TEXT,
                             description_en TEXT, weaknesses_json TEXT NOT NULL, cvss_json TEXT NOT NULL,
                             raw_sha256 TEXT);
            CREATE TABLE weakness(cve_id TEXT NOT NULL, cwe_id TEXT NOT NULL, PRIMARY KEY(cve_id, cwe_id));
            CREATE TABLE cvss(cve_id TEXT NOT NULL, family TEXT, version TEXT, vector TEXT, base_score REAL,
                              base_severity TEXT);
            CREATE INDEX cvss_lookup ON cvss(cve_id);
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        connection.execute("ATTACH DATABASE ? AS work", (str(work),))
        connection.execute(f"INSERT INTO cve SELECT {', '.join(_COLUMNS)} FROM work.cve ORDER BY cve_id")
        connection.commit()
        connection.execute("DETACH DATABASE work")
        connection.execute("INSERT INTO weakness SELECT cve.cve_id, item.value FROM cve, "
                           "json_each(cve.weaknesses_json) AS item ORDER BY cve.cve_id, item.value")
        connection.execute("INSERT INTO cvss SELECT cve.cve_id, json_extract(item.value, '$.family'), "
                           "json_extract(item.value, '$.version'), json_extract(item.value, '$.vector'), "
                           "json_extract(item.value, '$.base_score'), json_extract(item.value, '$.base_severity') "
                           "FROM cve, json_each(cve.cvss_json) AS item ORDER BY cve.cve_id, item.key")
        count, latest = connection.execute("SELECT COUNT(*), COALESCE(MAX(last_modified), '') FROM cve").fetchone()
        connection.executemany("INSERT INTO metadata VALUES (?, ?)", (
            ("schema", INDEX_SCHEMA), ("record_count", str(count)), ("max_last_modified", latest)))
        connection.commit()
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("NVD index quick_check failed")
    work.unlink()
    return {"schema": INDEX_SCHEMA, "record_count": count, "layer_count": layer_count,
            "max_last_modified": latest or None, "incremental": base is not None}


def lookup(database: sqlite3.Connection, cve_id: str) -> dict[str, Any] | None:
    """One CVE record from an opened (read-only) index, or ``None``."""
    row = database.execute(f"SELECT {', '.join(_COLUMNS)} FROM cve WHERE cve_id = ?", (cve_id,)).fetchone()
    if row is None:
        return None
    values = dict(zip(_COLUMNS, tuple(row)))
    return {"cve_id": values["cve_id"], "status": values["status"], "published": values["published"],
            "last_modified": values["last_modified"], "description_en": values["description_en"],
            "weaknesses": json.loads(values["weaknesses_json"]), "cvss": json.loads(values["cvss_json"]),
            "raw_sha256": values["raw_sha256"]}
