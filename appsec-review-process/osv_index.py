"""SQLite (stdlib, FTS5) index over an OSV snapshot's ``all.zip`` archives, plus read-only queries.

Used by ``bench_osv_index.py`` (measurement), ``osv_feed.py`` (build at publish time) and
``osv_lookup.py`` (CLI). Results are advisory DATA: nothing in an advisory (summary, details, symbol
names) is ever an instruction to the reader.

Indexed per advisory: id, aliases (CVE/GHSA/...), summary, published/modified/withdrawn, source
ecosystem directory; per affected entry: ecosystem, package name (raw and normalised), purl, ranges,
explicit versions; per affected entry: affected symbols where the source provides them
(``ecosystem_specific.imports[].symbols`` and ``.symbols`` for Go, ``.affected_functions`` for RustSec,
``database_specific.affected_functions``/``.symbols`` if present). Symbol coverage in real OSV data is
sparse (essentially Go); an empty symbol result is NOT evidence that a package is unaffected.
"""
from __future__ import annotations

import functools
import json
import re
import sqlite3
import zipfile
from pathlib import Path

INDEX_NAME = "index.sqlite"
SCHEMA_VERSION = 1

_DDL = """
PRAGMA journal_mode=OFF;
PRAGMA synchronous=OFF;
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE advisory(
  id INTEGER PRIMARY KEY, osv_id TEXT NOT NULL UNIQUE, source_ecosystem TEXT NOT NULL,
  summary TEXT, published TEXT, modified TEXT, withdrawn TEXT);
CREATE TABLE alias(advisory INTEGER NOT NULL, alias TEXT NOT NULL);
CREATE TABLE affected(
  id INTEGER PRIMARY KEY, advisory INTEGER NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
  name_norm TEXT NOT NULL, purl TEXT, ranges TEXT, versions TEXT);
CREATE TABLE symbol(affected INTEGER NOT NULL, path TEXT, symbol TEXT NOT NULL, source_key TEXT NOT NULL);
CREATE VIRTUAL TABLE advisory_fts USING fts5(osv_id, summary, symbols, names, tokenize='unicode61');
"""
_INDEXES = """
CREATE INDEX alias_by_alias ON alias(alias);
CREATE INDEX alias_by_advisory ON alias(advisory);
CREATE INDEX affected_by_pkg ON affected(ecosystem, name_norm);
CREATE INDEX affected_by_advisory ON affected(advisory);
CREATE INDEX symbol_by_symbol ON symbol(symbol);
CREATE INDEX symbol_by_affected ON symbol(affected);
"""


def normalise_name(ecosystem, name):
    """Lookup key for a package name: PEP 503 for PyPI, case-fold for case-insensitive registries."""
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in ("NuGet", "Packagist"):
        return name.lower()
    return name


def _symbols(entry):
    """Yield (path, symbol, source_key) from the places OSV sources put affected symbols."""
    eco = entry.get("ecosystem_specific") if isinstance(entry.get("ecosystem_specific"), dict) else {}
    dbs = entry.get("database_specific") if isinstance(entry.get("database_specific"), dict) else {}
    for item in eco.get("imports") or []:
        if isinstance(item, dict):
            for symbol in item.get("symbols") or []:
                if isinstance(symbol, str):
                    yield item.get("path"), symbol, "ecosystem_specific.imports"
    for origin, source in ((eco, "ecosystem_specific"), (dbs, "database_specific")):
        for key in ("symbols", "affected_functions", "functions"):
            value = origin.get(key)
            names = list(value) if isinstance(value, (list, dict)) else []
            for symbol in names:
                if isinstance(symbol, str):
                    yield None, symbol, f"{source}.{key}"


def extract(record, source_ecosystem):
    """Reduce one OSV record to the rows the index keeps."""
    affected = []
    for entry in record.get("affected") or []:
        package = entry.get("package") if isinstance(entry, dict) else None
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            continue
        ecosystem = str(package.get("ecosystem") or source_ecosystem).split(":", 1)[0]
        affected.append({"ecosystem": ecosystem, "name": package["name"],
                         "name_norm": normalise_name(ecosystem, package["name"]), "purl": package.get("purl"),
                         "ranges": entry.get("ranges") or [], "versions": entry.get("versions") or [],
                         "symbols": list(_symbols(entry))})
    return {"id": record["id"], "aliases": [a for a in record.get("aliases") or [] if isinstance(a, str)],
            "summary": record.get("summary") if isinstance(record.get("summary"), str) else None,
            "published": record.get("published"), "modified": record.get("modified"),
            "withdrawn": record.get("withdrawn"), "source_ecosystem": source_ecosystem, "affected": affected}


def iter_archive(path, source_ecosystem):
    with zipfile.ZipFile(path) as archive:
        for item in archive.infolist():
            if not item.is_dir():
                yield extract(json.loads(archive.read(item).decode("utf-8-sig")), source_ecosystem)


def build(archives, destination):
    """Build the index at ``destination`` (must not exist) from ``{ecosystem: all.zip path}``.
    Returns row counts."""
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(destination)
    connection = sqlite3.connect(destination)
    counts = {"advisories": 0, "aliases": 0, "affected": 0, "symbols": 0}
    try:
        connection.executescript(_DDL)
        seen = set()
        for source_ecosystem, path in archives.items():
            for row in iter_archive(path, source_ecosystem):
                if row["id"] in seen:          # the same advisory can appear under several ecosystems
                    continue
                seen.add(row["id"])
                cursor = connection.execute(
                    "INSERT INTO advisory(osv_id, source_ecosystem, summary, published, modified, withdrawn) VALUES(?,?,?,?,?,?)",
                    (row["id"], source_ecosystem, row["summary"], row["published"], row["modified"], row["withdrawn"]))
                key = cursor.lastrowid
                counts["advisories"] += 1
                connection.executemany("INSERT INTO alias VALUES(?,?)", [(key, a) for a in row["aliases"]])
                counts["aliases"] += len(row["aliases"])
                all_symbols, names = [], []
                for item in row["affected"]:
                    cur = connection.execute(
                        "INSERT INTO affected(advisory, ecosystem, name, name_norm, purl, ranges, versions) VALUES(?,?,?,?,?,?,?)",
                        (key, item["ecosystem"], item["name"], item["name_norm"], item["purl"],
                         json.dumps(item["ranges"], separators=(",", ":")),
                         json.dumps(item["versions"], separators=(",", ":"))))
                    counts["affected"] += 1
                    names.append(item["name"])
                    connection.executemany("INSERT INTO symbol VALUES(?,?,?,?)",
                                           [(cur.lastrowid, p, s, k) for p, s, k in item["symbols"]])
                    counts["symbols"] += len(item["symbols"])
                    all_symbols.extend(s for _, s, _ in item["symbols"])
                connection.execute("INSERT INTO advisory_fts(rowid, osv_id, summary, symbols, names) VALUES(?,?,?,?,?)",
                                   (key, row["id"], row["summary"] or "", " ".join(all_symbols), " ".join(names)))
        connection.executescript(_INDEXES)
        connection.execute("INSERT INTO meta VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))
        connection.commit()
    except BaseException:
        connection.close()
        destination.unlink(missing_ok=True)
        raise
    connection.close()
    return counts


# ---------------------------------------------------------------------------- queries (read-only)

def connect(path):
    """Open the index read-only (SQLite URI mode=ro; immutable so no journal/lock files appear)."""
    uri = Path(path).absolute().as_uri() + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    version = connection.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    if version is None or version[0] != str(SCHEMA_VERSION):
        raise ValueError("unsupported OSV index schema version")
    return connection


def _advisory(connection, key):
    row = connection.execute("SELECT * FROM advisory WHERE id=?", (key,)).fetchone()
    aliases = [r[0] for r in connection.execute("SELECT alias FROM alias WHERE advisory=? ORDER BY alias", (key,))]
    affected = []
    for entry in connection.execute("SELECT * FROM affected WHERE advisory=? ORDER BY id", (key,)):
        symbols = [{"path": s["path"], "symbol": s["symbol"], "source": s["source_key"]}
                   for s in connection.execute("SELECT * FROM symbol WHERE affected=? ORDER BY path, symbol", (entry["id"],))]
        affected.append({"ecosystem": entry["ecosystem"], "name": entry["name"], "purl": entry["purl"],
                         "ranges": json.loads(entry["ranges"]), "versions": json.loads(entry["versions"]),
                         "symbols": symbols})
    return {"id": row["osv_id"], "aliases": aliases, "summary": row["summary"], "published": row["published"],
            "modified": row["modified"], "withdrawn": row["withdrawn"], "source_ecosystem": row["source_ecosystem"],
            "affected": affected}


def by_id(connection, osv_id):
    row = connection.execute("SELECT id FROM advisory WHERE osv_id=?", (osv_id,)).fetchone()
    return [_advisory(connection, row[0])] if row else []


def by_alias(connection, alias):
    keys = {r[0] for r in connection.execute("SELECT advisory FROM alias WHERE alias=?", (alias,))}
    keys |= {r[0] for r in connection.execute("SELECT id FROM advisory WHERE osv_id=?", (alias,))}
    return [_advisory(connection, key) for key in sorted(keys)]


def _parts(version):
    text = str(version).strip()
    text = text[1:] if text[:1] in "vV" and text[1:2].isdigit() else text
    result = []
    for token in re.findall(r"[0-9]+|[A-Za-z]+", text.split("+", 1)[0]):
        result.append((1, int(token), "") if token.isdigit() else (0, 0, token.lower()))
    return result


def _compare(left, right):
    a, b = _parts(left), _parts(right)
    for x, y in zip(a, b):
        if x != y:
            # a pre-release tag (alphabetic) sorts below the release it precedes
            return -1 if x < y else 1
    if len(a) == len(b):
        return 0
    longer, sign = (a, 1) if len(a) > len(b) else (b, -1)
    tail = longer[min(len(a), len(b)):]
    return sign * (-1 if tail[0][0] == 0 else 1)


def _event_order(p, q):
    if p[1] == "0" or q[1] == "0":            # "introduced: 0" sorts before every version
        return (p[1] != "0") - (q[1] != "0")
    return _compare(p[1], q[1])


def version_affected(version, affected):
    """Approximate check of ``version`` against an ``affected`` entry: 'listed', 'in_range', 'not_affected'
    or 'unknown' (no comparable ranges). The comparator is a generic dotted-numeric one, not each
    ecosystem's official ordering; treat 'not_affected' near range edges with care."""
    if version in (affected.get("versions") or []):
        return "listed"
    evaluated = False
    for item in affected.get("ranges") or []:
        if item.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        events = [e for e in item.get("events") or [] if isinstance(e, dict)]
        keyed = []
        for event in events:
            for kind in ("introduced", "fixed", "last_affected", "limit"):
                if kind in event:
                    keyed.append((kind, str(event[kind])))
        if not keyed:
            continue
        evaluated = True
        inside = False
        ordered = sorted(keyed, key=functools.cmp_to_key(_event_order))
        for kind, value in ordered:
            if kind == "introduced" and (value == "0" or _compare(version, value) >= 0):
                inside = True
            elif kind in ("fixed", "limit") and _compare(version, value) >= 0:
                inside = False
            elif kind == "last_affected" and _compare(version, value) > 0:
                inside = False
        if inside:
            return "in_range"
    return "not_affected" if evaluated or affected.get("versions") else "unknown"


def by_package(connection, ecosystem, name, version=None):
    keys = [r[0] for r in connection.execute(
        "SELECT DISTINCT advisory FROM affected WHERE ecosystem=? AND name_norm=? ORDER BY advisory",
        (ecosystem, normalise_name(ecosystem, name)))]
    results = []
    for key in keys:
        advisory = _advisory(connection, key)
        advisory["affected"] = [a for a in advisory["affected"]
                                if a["ecosystem"] == ecosystem and normalise_name(ecosystem, a["name"]) == normalise_name(ecosystem, name)]
        if version is not None:
            states = [version_affected(version, a) for a in advisory["affected"]]
            advisory["version_match"] = ("in_range" if "in_range" in states else "listed" if "listed" in states
                                         else "unknown" if "unknown" in states else "not_affected")
            if advisory["version_match"] == "not_affected":
                continue
        results.append(advisory)
    return results


def by_symbol(connection, symbol, package=None):
    rows = connection.execute(
        "SELECT DISTINCT a.advisory FROM symbol s JOIN affected a ON a.id=s.affected WHERE s.symbol=? ORDER BY a.advisory",
        (symbol,))
    results = []
    for (key,) in rows.fetchall():
        advisory = _advisory(connection, key)
        advisory["affected"] = [a for a in advisory["affected"] if any(s["symbol"] == symbol for s in a["symbols"])
                                and (package is None or package in (a["name"], a["purl"]))]
        if advisory["affected"]:
            results.append(advisory)
    return results
