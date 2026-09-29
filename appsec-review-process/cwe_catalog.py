#!/usr/bin/env python3
"""Pinned offline CWE catalog and tool rule -> CWE map (ADR-0020).

* ``data/reference/cwe/cwe-catalog.json`` is a dated CWE id/name snapshot.  The committed file is a
  curated subset (the weaknesses the pipeline's tools and reviewers name).  ``intake`` replaces it
  from a user-supplied MITRE ``cwec_v*.xml`` or CWE CSV export -- never a network fetch.
* ``data/reference/cwe/rule-cwe-map.json`` maps ``(tool_id, rule_id)`` to CWE ids.  A lead that
  carries its own CWE tags (SARIF ``properties.tags``, Semgrep ``metadata.cwe``) is read as well.

Both files are hash-checked against ``cwe-lock.json`` at load; every CWE a tool or a reviewer names
is validated against the catalog.  An unknown id is rejected (reviewer reply -> repair round) or
dropped with a limitation (tool tag), never published.

Catalog in force (brief O1b): ``Catalog()`` reads the full MITRE CWE catalog from the resolved
``mitre_feed`` snapshot (same 14-day ceiling as ATT&CK/CAPEC).  When that snapshot is missing, older
than the ceiling or invalid, it falls back to the committed curated catalog exactly as before and
records the gap ``CWE_REFERENCE_MISSING`` / ``CWE_REFERENCE_STALE`` / ``CWE_REFERENCE_INVALID``;
never a block.  ``Catalog(directory)`` reads only the committed files (tests, ``intake``, ``relock``).
The rule map stays committed and hash-pinned in every case.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parent
CWE_DIR = ROOT.parent / "data" / "reference" / "cwe"
CATALOG = "cwe-catalog.json"
RULE_MAP = "rule-cwe-map.json"
LOCK = "cwe-lock.json"
CWE_ID = re.compile(r"^CWE-[1-9][0-9]{0,4}$")
TAG = re.compile(r"\bCWE[-_ :]?([1-9][0-9]{0,4})\b", re.I)
CATALOG_SCHEMA = "appsec-review/cwe-catalog/1.0"
COMMITTED = "committed-curated"
GAP_MISSING, GAP_STALE, GAP_INVALID = "CWE_REFERENCE_MISSING", "CWE_REFERENCE_STALE", "CWE_REFERENCE_INVALID"
MAX_XML_BYTES = 256 * 1024 ** 2
MIN_WEAKNESSES = 100


class CWEError(ValueError):
    pass


def _sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _load(directory: Path | None = None) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    directory = Path(directory or CWE_DIR)
    lock = json.loads((directory / LOCK).read_text())
    for name in (CATALOG, RULE_MAP):
        if lock.get(name) != _sha(directory / name):
            raise CWEError(f"{name} does not match its pinned hash in {LOCK}")
    catalog = json.loads((directory / CATALOG).read_text())
    rules = json.loads((directory / RULE_MAP).read_text())
    if (catalog.get("schema") != "appsec-review/cwe-catalog/1.0" or
            rules.get("schema") != "appsec-review/rule-cwe-map/1.0"):
        raise CWEError("CWE catalog or rule map schema is not recognised")
    return catalog, rules, lock


def _rule_index(rules: dict[str, Any], names: dict[str, str]) -> dict[tuple[str, str], list[str]]:
    index: dict[tuple[str, str], list[str]] = {}
    for row in rules["rules"]:
        if any(value not in names for value in row["cwe_ids"]):
            raise CWEError(f"rule map names a CWE outside the catalog: {row}")
        index[(row["tool_id"], row["rule_id"])] = list(row["cwe_ids"])
    return index


def _feed_catalog(feed_root: Any, now: datetime | None) -> tuple[dict[str, Any] | None, dict[str, Any] | None,
                                                                  dict[str, Any] | None]:
    """(table, snapshot identity, None) from a verified, in-ceiling feed snapshot, else (None, None, gap)."""
    try:
        import mitre_feed
        from dependency_snapshot_registry import SnapshotBlocked, SnapshotInvalid, SnapshotStale
    except ImportError as exc:
        return None, None, {"code": GAP_MISSING, "detail": f"MITRE feed code unavailable: {exc}"[:300]}
    try:
        identity = mitre_feed.resolve(feed_root, now=now or datetime.now(timezone.utc), kinds=("cwe",))
    except SnapshotBlocked as exc:
        return None, None, {"code": GAP_MISSING, "detail": str(exc)[:300]}
    except SnapshotStale as exc:
        return None, None, {"code": GAP_STALE, "detail": str(exc)[:300]}
    except (SnapshotInvalid, OSError, ValueError) as exc:
        return None, None, {"code": GAP_INVALID, "detail": f"{type(exc).__name__}: {exc}"[:300]}
    if not identity.get("cwe_catalog_path"):
        return None, None, {"code": GAP_MISSING, "detail": "the MITRE snapshot carries no CWE catalog"}
    try:
        path = Path(identity["cwe_catalog_path"])
        if _sha(path) != "sha256:" + identity["cwe_catalog_sha256"]:
            raise CWEError("snapshot CWE catalog changed after it was resolved")
        table = json.loads(path.read_text(encoding="utf-8"))
        if table.get("schema") != CATALOG_SCHEMA or not isinstance(table.get("entries"), list):
            raise CWEError("snapshot CWE catalog schema is not recognised")
    except (OSError, ValueError) as exc:
        return None, None, {"code": GAP_INVALID, "detail": f"{type(exc).__name__}: {exc}"[:300]}
    return table, identity, None


class Catalog:
    """The CWE catalog in force: the feed snapshot's full catalog, else the committed curated one."""

    def __init__(self, directory: Path | None = None, *, feed_root: Any = None, now: datetime | None = None):
        catalog, rules, lock = _load(directory)
        self.gap: dict[str, Any] | None = None
        self.deprecated: set[str] = set()
        table = identity = None
        if directory is None:
            table, identity, self.gap = _feed_catalog(feed_root, now)
        if table is not None:
            try:
                names = {row["cwe_id"]: row["name"] for row in table["entries"] if not row.get("deprecated")}
                self.rules = _rule_index(rules, names)
            except (CWEError, KeyError, TypeError) as exc:
                table, self.gap = None, {"code": GAP_INVALID, "detail": f"snapshot CWE catalog unusable: {exc}"[:300]}
        if table is not None:
            self.source = identity["snapshot_id"]
            self.version, self.as_of, self.names = table["version"], table["as_of"], names
            self.deprecated = {row["cwe_id"] for row in table["entries"] if row.get("deprecated")}
            self.identity = {"catalog_source": "mitre-feed", "catalog_version": self.version,
                             "catalog_as_of": self.as_of, "catalog_sha256": "sha256:" + identity["cwe_catalog_sha256"],
                             "rule_map_sha256": lock[RULE_MAP]}
        else:
            self.source = COMMITTED
            self.version, self.as_of = catalog["version"], catalog["as_of"]
            self.names = {row["cwe_id"]: row["name"] for row in catalog["entries"]}
            self.rules = _rule_index(rules, self.names)
            self.identity = {"catalog_version": self.version, "catalog_as_of": self.as_of,
                             "catalog_sha256": lock[CATALOG], "rule_map_sha256": lock[RULE_MAP]}
            if self.gap is not None:
                self.identity = {"catalog_source": COMMITTED, **self.identity, "gap": self.gap["code"]}

    def provenance(self) -> dict[str, Any]:
        """Which catalog was used (``snapshot_id`` or ``committed-curated``) and the gap, if any."""
        return {"catalog": self.source, "catalog_version": self.version,
                "gap": dict(self.gap, used=COMMITTED) if self.gap else None}

    def gap_line(self) -> str | None:
        if self.gap is None:
            return None
        return (f"{self.gap['code']}: the MITRE CWE snapshot was not usable ({self.gap['detail']}); CWE ids were "
                f"validated against the committed curated catalog ({self.version})")

    def validate(self, value: Any) -> str:
        """Canonical ``CWE-n`` for a known id, else CWEError naming the problem."""
        text = str(value).strip().upper() if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
        if text.isdigit():
            text = "CWE-" + text
        if not CWE_ID.match(text):
            raise CWEError(f"{value!r} is not a CWE id of the form CWE-<n>")
        if text in self.deprecated:
            raise CWEError(f"{text} is deprecated in the CWE catalog ({self.version})")
        if text not in self.names:
            raise CWEError(f"{text} is not in the pinned CWE catalog ({self.version})")
        return text

    def name(self, cwe_id: str) -> str:
        return self.names[self.validate(cwe_id)]

    def for_lead(self, tool_id: str, rule_id: str, tags: Iterable[str] = ()) -> tuple[list[str], list[str]]:
        """(CWE ids, limitations) for one tool lead from the pinned map and the lead's own tags."""
        found, notes = list(self.rules.get((tool_id, rule_id), [])), []
        for tag in tags or ():
            for number in TAG.findall(str(tag)):
                candidate = "CWE-" + number
                if candidate in self.names:
                    if candidate not in found:
                        found.append(candidate)
                else:
                    notes.append(f"{tool_id} {rule_id} tag {candidate} is not in the pinned CWE catalog; dropped")
        return found, notes


# ---- intake: import a user-supplied full catalog (no network) --------------------------------------

def _parse_tree(data: bytes, full: bool = False) -> tuple[ET.Element, list[dict[str, Any]]]:
    """The one CWE XML parser. ``full`` keeps deprecated weaknesses (flagged) plus status/abstraction."""
    root = ET.fromstring(data)
    rows = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "Weakness" and element.get("ID") and element.get("Name"):
            status = element.get("Status")
            if full:
                rows.append({"cwe_id": "CWE-" + element.get("ID"), "name": " ".join(element.get("Name").split()),
                             "status": status, "abstraction": element.get("Abstraction"),
                             "deprecated": status == "Deprecated"})
            elif status != "Deprecated":
                rows.append({"cwe_id": "CWE-" + element.get("ID"), "name": element.get("Name")})
    return root, rows


def _parse_xml(data: bytes) -> list[dict[str, str]]:
    return _parse_tree(data)[1]


def _parse_csv(data: bytes) -> list[dict[str, str]]:
    rows = []
    for row in csv.DictReader(io.StringIO(data.decode("utf-8-sig"))):
        raw = (row.get("CWE-ID") or row.get("CWE ID") or row.get("ID") or "").strip()
        name = (row.get("Name") or "").strip()
        if raw and name and (row.get("Status") or "").strip() != "Deprecated":
            rows.append({"cwe_id": raw if raw.upper().startswith("CWE-") else "CWE-" + raw, "name": name})
    return rows


# ---- feed: the full MITRE catalog published by mitre_feed.py (brief O1b) ------------------------------

def xml_from_zip(data: bytes) -> bytes:
    """The single ``cwec_v*.xml`` member of a MITRE CWE zip, size-capped before it is read."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise CWEError(f"CWE download is not a zip: {exc}") from None
    with archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        if len(members) != 1 or not re.fullmatch(r"cwec_v[0-9.]+\.xml", Path(members[0].filename).name):
            raise CWEError("CWE zip must hold exactly one cwec_v<version>.xml")
        if members[0].file_size > MAX_XML_BYTES:
            raise CWEError("CWE XML exceeds the size cap")
        with archive.open(members[0]) as handle:
            xml = handle.read(MAX_XML_BYTES + 1)
    if len(xml) > MAX_XML_BYTES:
        raise CWEError("CWE XML exceeds the size cap")
    return xml


def parse_feed(data: bytes) -> dict[str, Any]:
    """Parse a MITRE ``cwec_v<version>.xml.zip``: upstream version, release date and every weakness."""
    root, rows = _parse_tree(xml_from_zip(data), full=True)
    if root.tag.rsplit("}", 1)[-1] != "Weakness_Catalog" or not root.get("Version"):
        raise CWEError("CWE XML is not a versioned Weakness_Catalog")
    unique = {row["cwe_id"]: row for row in rows if CWE_ID.match(row["cwe_id"])}
    if sum(not row["deprecated"] for row in unique.values()) < MIN_WEAKNESSES:
        raise CWEError(f"CWE XML does not look like a full catalog (fewer than {MIN_WEAKNESSES} weaknesses)")
    return {"upstream_version": root.get("Version"), "date": root.get("Date"),
            "entries": [unique[key] for key in sorted(unique, key=lambda item: int(item[4:]))]}


def feed_table(parsed: dict[str, Any], file: str, sha256: str) -> dict[str, Any]:
    """The snapshot's derived catalog, the same shape as the committed ``cwe-catalog.json``."""
    date = parsed.get("date") if re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(parsed.get("date"))) else None
    return {"schema": CATALOG_SCHEMA, "version": f"CWE List {parsed['upstream_version']}", "as_of": date,
            "source": {"kind": "MITRE CWE feed snapshot (mitre_feed.py)", "file": file, "sha256": "sha256:" + sha256},
            "entries": parsed["entries"]}


def table_bytes(table: dict[str, Any]) -> bytes:
    return (json.dumps(table, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def _write_lock(directory: Path) -> dict[str, Any]:
    lock = {"schema": "appsec-review/cwe-lock/1.0", CATALOG: _sha(directory / CATALOG),
            RULE_MAP: _sha(directory / RULE_MAP)}
    (directory / LOCK).write_text(json.dumps(lock, indent=1) + "\n")
    return lock


def intake(source: Path, version: str, as_of: str, directory: Path | None = None) -> dict[str, Any]:
    directory = Path(directory or CWE_DIR)
    data = Path(source).read_bytes()
    rows = _parse_xml(data) if data.lstrip()[:1] == b"<" else _parse_csv(data)
    unique = {row["cwe_id"]: row for row in rows if CWE_ID.match(row["cwe_id"])}
    if len(unique) < 100:
        raise CWEError("intake source does not look like a CWE catalog export (fewer than 100 weaknesses)")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", as_of):
        raise CWEError("--as-of must be YYYY-MM-DD")
    rules = json.loads((directory / RULE_MAP).read_text())
    missing = sorted({value for row in rules["rules"] for value in row["cwe_ids"]} - set(unique))
    if missing:
        raise CWEError(f"the rule map names CWE ids absent from the new catalog: {missing}")
    catalog = {"schema": "appsec-review/cwe-catalog/1.0", "version": version, "as_of": as_of,
               "source": {"kind": "user-supplied MITRE CWE export", "file": Path(source).name,
                          "sha256": "sha256:" + hashlib.sha256(data).hexdigest()},
               "entries": [unique[key] for key in sorted(unique, key=lambda item: int(item[4:]))]}
    (directory / CATALOG).write_text(json.dumps(catalog, indent=1, ensure_ascii=False) + "\n")
    lock = _write_lock(directory)
    Catalog(directory)
    return lock


def relock(directory: Path | None = None) -> dict[str, Any]:
    """Re-pin after a reviewed edit of the rule map (the edit itself is the reviewed change)."""
    directory = Path(directory or CWE_DIR)
    lock = _write_lock(directory)
    Catalog(directory)
    return lock


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    take = sub.add_parser("intake", help="import a user-supplied MITRE CWE XML/CSV export")
    take.add_argument("source", type=Path)
    take.add_argument("--version", required=True)
    take.add_argument("--as-of", required=True)
    sub.add_parser("relock", help="re-pin the catalog and rule map hashes after a reviewed edit")
    sub.add_parser("check", help="verify the pinned files and report the catalog in force")
    args = parser.parse_args(argv)
    if args.command == "intake":
        print(json.dumps(intake(args.source, args.version, args.as_of), indent=1))
    elif args.command == "relock":
        print(json.dumps(relock(), indent=1))
    else:
        catalog = Catalog()
        print(json.dumps({**catalog.identity, **catalog.provenance()}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
