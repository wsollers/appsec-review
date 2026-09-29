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

The full catalog comes from the MITRE feed (brief O2, ADR-0026 addendum): ``mitre_feed.py`` publishes
the release-pinned ``cwec_v<version>.xml.zip`` and a derived ``cwe-catalog.json`` (same shape as the
committed file, built by ``derive_snapshot_catalog`` through ``_parse_xml``).  ``current()`` uses it
when the snapshot verifies and is inside the shared age ceiling; otherwise it falls back to the
committed curated catalog and records ``CWE_REFERENCE_MISSING`` / ``CWE_REFERENCE_STALE`` /
``CWE_REFERENCE_INVALID``.  A stale feed never blocks a review.  The rule map is always the committed,
hash-pinned file (the repository's own judgement, not upstream data).
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
COMMITTED = "committed-curated"
FEED = "mitre-feed"
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


class Catalog:
    """Validator over one catalog: the committed curated file (default) or a feed snapshot's derived
    table (``table``).  ``used`` names the catalog in force (``snapshot_id`` or ``committed-curated``);
    ``gap`` is the recorded reason a feed catalog was not used, if one was sought."""

    def __init__(self, directory: Path | None = None, *, table: dict[str, Any] | None = None,
                 table_sha256: str | None = None, snapshot_id: str | None = None,
                 gap: dict[str, Any] | None = None):
        catalog, rules, lock = _load(directory)
        if table is not None:
            if table.get("schema") != "appsec-review/cwe-catalog/1.0" or not table_sha256 or not snapshot_id:
                raise CWEError("feed CWE catalog schema or identity is not recognised")
            catalog = table
        self.version = catalog["version"]
        self.as_of = catalog["as_of"]
        self.names = {row["cwe_id"]: row["name"] for row in catalog["entries"]}
        self.deprecated = {row["cwe_id"] for row in catalog["entries"] if row.get("deprecated")}
        self.source = FEED if table is not None else COMMITTED
        self.snapshot_id = snapshot_id if table is not None else None
        self.used = self.snapshot_id or COMMITTED
        self.gap = dict(gap) if gap else None
        self.rules: dict[tuple[str, str], list[str]] = {}
        for row in rules["rules"]:
            if any(value not in self.names or value in self.deprecated for value in row["cwe_ids"]):
                raise CWEError(f"rule map names a CWE outside the catalog: {row}")
            self.rules[(row["tool_id"], row["rule_id"])] = list(row["cwe_ids"])
        # Stable across re-syncs of the same pin (no snapshot id): a stage's input binding.
        self.identity = {"catalog_version": self.version, "catalog_as_of": self.as_of,
                         "catalog_sha256": table_sha256 if table is not None else lock[CATALOG],
                         "rule_map_sha256": lock[RULE_MAP], "catalog_source": self.source,
                         **({"reference_gap": self.gap["code"]} if self.gap else {})}

    def known(self, cwe_id: str) -> bool:
        return cwe_id in self.names and cwe_id not in self.deprecated

    def validate(self, value: Any) -> str:
        """Canonical ``CWE-n`` for a known id, else CWEError naming the problem."""
        text = str(value).strip().upper() if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
        if text.isdigit():
            text = "CWE-" + text
        if not CWE_ID.match(text):
            raise CWEError(f"{value!r} is not a CWE id of the form CWE-<n>")
        if text not in self.names:
            raise CWEError(f"{text} is not in the pinned CWE catalog ({self.version})")
        if text in self.deprecated:
            raise CWEError(f"{text} is deprecated in the pinned CWE catalog ({self.version})")
        return text

    def name(self, cwe_id: str) -> str:
        return self.names[self.validate(cwe_id)]

    def limitation(self) -> str | None:
        """Report line for a feed catalog that was sought and not used (None when the feed was used)."""
        if not self.gap:
            return None
        reason = {GAP_MISSING: "no usable MITRE CWE snapshot is published on this host",
                  GAP_STALE: "the MITRE CWE snapshot is older than the reference age ceiling",
                  GAP_INVALID: "the MITRE CWE snapshot failed verification"}.get(self.gap["code"], "feed not used")
        # Fixed wording only: the gap detail may carry host paths or exception text.
        return (f"{self.gap['code']}: CWE ids validated against the committed curated catalog "
                f"({self.version}), not the full MITRE catalog; {reason}")

    def for_lead(self, tool_id: str, rule_id: str, tags: Iterable[str] = ()) -> tuple[list[str], list[str]]:
        """(CWE ids, limitations) for one tool lead from the pinned map and the lead's own tags."""
        found, notes = list(self.rules.get((tool_id, rule_id), [])), []
        for tag in tags or ():
            for number in TAG.findall(str(tag)):
                candidate = "CWE-" + number
                if self.known(candidate):
                    if candidate not in found:
                        found.append(candidate)
                else:
                    notes.append(f"{tool_id} {rule_id} tag {candidate} is not in the pinned CWE catalog; dropped")
        return found, notes


# ---- intake: import a user-supplied full catalog (no network) --------------------------------------

def _parse_xml(data: bytes, *, full: bool = False, meta: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Weakness rows of a MITRE ``cwec_v*.xml``.  Default (``intake``): id and name, deprecated rows
    dropped.  ``full`` (feed snapshot): every weakness, with ``status``/``abstraction`` when MITRE gives
    them and deprecated rows flagged, not dropped.  ``meta`` receives the catalog's Version and Date."""
    root = ET.fromstring(data)
    if meta is not None:
        meta.update({"version": root.get("Version"), "date": root.get("Date")})
    rows = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "Weakness" and element.get("ID") and element.get("Name"):
            deprecated = element.get("Status") == "Deprecated"
            if not full:
                if not deprecated:
                    rows.append({"cwe_id": "CWE-" + element.get("ID"), "name": element.get("Name")})
                continue
            row: dict[str, Any] = {"cwe_id": "CWE-" + element.get("ID"), "name": " ".join(element.get("Name").split())}
            for key, attribute in (("status", "Status"), ("abstraction", "Abstraction")):
                if element.get(attribute):
                    row[key] = element.get(attribute)
            row["deprecated"] = deprecated
            rows.append(row)
    return rows


def _parse_csv(data: bytes) -> list[dict[str, str]]:
    rows = []
    for row in csv.DictReader(io.StringIO(data.decode("utf-8-sig"))):
        raw = (row.get("CWE-ID") or row.get("CWE ID") or row.get("ID") or "").strip()
        name = (row.get("Name") or "").strip()
        if raw and name and (row.get("Status") or "").strip() != "Deprecated":
            rows.append({"cwe_id": raw if raw.upper().startswith("CWE-") else "CWE-" + raw, "name": name})
    return rows


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


# ---- the MITRE feed: derive the full catalog from the pinned zip, resolve it, fall back ---------------

def _xml_from_zip(data: bytes) -> tuple[str, bytes]:
    """The single ``cwec_v*.xml`` member of a MITRE zip, size-bounded and without a DTD."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise CWEError(f"CWE download is not a zip archive: {exc}") from None
    with archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        if len(members) != 1 or not re.fullmatch(r"cwec_v[0-9.]+\.xml", members[0].filename):
            raise CWEError("CWE zip must hold exactly one cwec_v<version>.xml")
        if members[0].file_size > MAX_XML_BYTES:
            raise CWEError("CWE XML exceeds the size cap")
        with archive.open(members[0]) as handle:
            xml = handle.read(MAX_XML_BYTES + 1)
    if len(xml) > MAX_XML_BYTES:
        raise CWEError("CWE XML exceeds the size cap")
    if b"<!DOCTYPE" in xml or b"<!ENTITY" in xml:
        raise CWEError("CWE XML carries a DTD; refused")
    return members[0].filename, xml


def derive_snapshot_catalog(data: bytes, version: str) -> dict[str, Any]:
    """The feed's derived table from the pinned ``cwec_v<version>.xml.zip`` bytes: same shape as the
    committed ``cwe-catalog.json`` and a pure function of the bytes (sorted, no fetch time)."""
    member, xml = _xml_from_zip(data)
    meta: dict[str, Any] = {}
    try:
        rows = _parse_xml(xml, full=True, meta=meta)
    except ET.ParseError as exc:
        raise CWEError(f"CWE XML does not parse: {exc}") from None
    if meta.get("version") != version:
        raise CWEError(f"CWE catalog is version {meta.get('version')!r}, pinned {version!r}")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(meta.get("date"))):
        raise CWEError("CWE catalog has no release date")
    unique = {row["cwe_id"]: row for row in rows if CWE_ID.match(row["cwe_id"])}
    if sum(not row["deprecated"] for row in unique.values()) < MIN_WEAKNESSES:
        raise CWEError("CWE download does not look like the MITRE catalog (fewer than 100 weaknesses)")
    return {"schema": "appsec-review/cwe-catalog/1.0", "version": f"CWE List {version}", "as_of": meta["date"],
            "source": {"kind": f"MITRE CWE feed (cwec_v{version}.xml.zip, mitre_feed.py)", "file": member,
                       "sha256": "sha256:" + hashlib.sha256(xml).hexdigest()},
            "entries": [unique[key] for key in sorted(unique, key=lambda item: int(item[4:]))]}


def summarize_zip(data: bytes, version: str) -> dict[str, Any]:
    """Parse check for ``mitre_feed.validate_source``: upstream version and weakness count."""
    table = derive_snapshot_catalog(data, version)
    return {"upstream_version": version, "record_count": len(table["entries"]),
            "deprecated_count": sum(1 for row in table["entries"] if row["deprecated"]), "marking_statements": []}


def table_bytes(table: dict[str, Any]) -> bytes:
    return (json.dumps(table, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def current(root: Any = None, *, now: datetime | None = None, max_age_seconds: int | None = None,
            directory: Path | None = None) -> Catalog:
    """The catalog in force: the feed's full catalog when the snapshot verifies and is inside the
    ceiling, else the committed curated catalog with the recorded gap.  Never blocks on the feed."""
    import mitre_feed
    from dependency_snapshot_registry import SnapshotBlocked, SnapshotInvalid, SnapshotStale
    now = now or datetime.now(timezone.utc)
    try:
        identity = mitre_feed.resolve_cwe(root, now=now, max_age_seconds=max_age_seconds)
        data = Path(identity["catalog_path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != identity["catalog_sha256"]:
            raise SnapshotInvalid("CWE catalog changed after verification")
        return Catalog(directory, table=json.loads(data), table_sha256="sha256:" + identity["catalog_sha256"],
                       snapshot_id=identity["snapshot_id"])
    except SnapshotBlocked as exc:
        gap = {"code": GAP_MISSING, "detail": str(exc)[:300]}
    except SnapshotStale as exc:
        gap = {"code": GAP_STALE, "detail": str(exc)[:300]}
    except (SnapshotInvalid, CWEError, OSError, ValueError, KeyError, TypeError) as exc:
        gap = {"code": GAP_INVALID, "detail": f"{type(exc).__name__}: {exc}"[:300]}
    return Catalog(directory, gap=gap)


def bound(value: dict[str, Any], root: Any = None, directory: Path | None = None) -> Catalog:
    """The catalog a recorded ``identity`` names, integrity-checked but not re-aged (the ceiling was
    applied when the binding was taken), so a re-validation reproduces the same result.  A feed table
    that is no longer published falls back to the curated catalog with ``CWE_REFERENCE_INVALID``."""
    value = value or {}
    if value.get("catalog_source") == FEED:
        catalog = current(root, max_age_seconds=sys.maxsize, directory=directory)
        if catalog.source == FEED and catalog.identity["catalog_sha256"] == value.get("catalog_sha256"):
            return catalog
        return Catalog(directory, gap={"code": GAP_INVALID,
                                       "detail": "the bound MITRE CWE catalog is no longer published"})
    gap = value.get("reference_gap")
    return Catalog(directory, gap={"code": gap, "detail": "recorded when this stage's inputs were bound"}
                   if gap in (GAP_MISSING, GAP_STALE, GAP_INVALID) else None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    take = sub.add_parser("intake", help="import a user-supplied MITRE CWE XML/CSV export")
    take.add_argument("source", type=Path)
    take.add_argument("--version", required=True)
    take.add_argument("--as-of", required=True)
    sub.add_parser("relock", help="re-pin the catalog and rule map hashes after a reviewed edit")
    sub.add_parser("check", help="verify the pinned files")
    resolved = sub.add_parser("current", help="the catalog in force: MITRE feed snapshot or curated fallback")
    resolved.add_argument("--root", type=Path)
    resolved.add_argument("--validate", help="also validate one CWE id against it")
    args = parser.parse_args(argv)
    if args.command == "intake":
        print(json.dumps(intake(args.source, args.version, args.as_of), indent=1))
    elif args.command == "relock":
        print(json.dumps(relock(), indent=1))
    elif args.command == "current":
        catalog = current(args.root)
        result = {**catalog.identity, "catalog_used": catalog.used, "entries": len(catalog.names),
                  **({"gap": catalog.gap} if catalog.gap else {})}
        if args.validate:
            try:
                result["validated"] = catalog.validate(args.validate)
            except CWEError as exc:
                result["rejected"] = str(exc)
        print(json.dumps(result, indent=1))
        return 1 if "rejected" in result else 0
    else:
        print(json.dumps(Catalog().identity, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
