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
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
CWE_DIR = ROOT.parent / "data" / "reference" / "cwe"
CATALOG = "cwe-catalog.json"
RULE_MAP = "rule-cwe-map.json"
LOCK = "cwe-lock.json"
CWE_ID = re.compile(r"^CWE-[1-9][0-9]{0,4}$")
TAG = re.compile(r"\bCWE[-_ :]?([1-9][0-9]{0,4})\b", re.I)


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
    def __init__(self, directory: Path | None = None):
        catalog, rules, lock = _load(directory)
        self.version = catalog["version"]
        self.as_of = catalog["as_of"]
        self.names = {row["cwe_id"]: row["name"] for row in catalog["entries"]}
        self.rules: dict[tuple[str, str], list[str]] = {}
        for row in rules["rules"]:
            if any(value not in self.names for value in row["cwe_ids"]):
                raise CWEError(f"rule map names a CWE outside the catalog: {row}")
            self.rules[(row["tool_id"], row["rule_id"])] = list(row["cwe_ids"])
        self.identity = {"catalog_version": self.version, "catalog_as_of": self.as_of,
                         "catalog_sha256": lock[CATALOG], "rule_map_sha256": lock[RULE_MAP]}

    def validate(self, value: Any) -> str:
        """Canonical ``CWE-n`` for a known id, else CWEError naming the problem."""
        text = str(value).strip().upper() if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
        if text.isdigit():
            text = "CWE-" + text
        if not CWE_ID.match(text):
            raise CWEError(f"{value!r} is not a CWE id of the form CWE-<n>")
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

def _parse_xml(data: bytes) -> list[dict[str, str]]:
    root = ET.fromstring(data)
    rows = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "Weakness" and element.get("ID") and element.get("Name"):
            if element.get("Status") != "Deprecated":
                rows.append({"cwe_id": "CWE-" + element.get("ID"), "name": element.get("Name")})
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    take = sub.add_parser("intake", help="import a user-supplied MITRE CWE XML/CSV export")
    take.add_argument("source", type=Path)
    take.add_argument("--version", required=True)
    take.add_argument("--as-of", required=True)
    sub.add_parser("relock", help="re-pin the catalog and rule map hashes after a reviewed edit")
    sub.add_parser("check", help="verify the pinned files")
    args = parser.parse_args(argv)
    if args.command == "intake":
        print(json.dumps(intake(args.source, args.version, args.as_of), indent=1))
    elif args.command == "relock":
        print(json.dumps(relock(), indent=1))
    else:
        print(json.dumps(Catalog().identity, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
