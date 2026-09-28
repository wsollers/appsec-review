#!/usr/bin/env python3
"""Dated, hash-pinned offline EPSS / CISA KEV snapshot (ADR-0020; approved by William 2026-09-28).

The pipeline never fetches EPSS or KEV.  An operator downloads the two public files outside the
pipeline and imports them with the explicit intake step::

    python3 appsec-review-process/epss_kev_snapshot.py intake \\
        --epss epss_scores-2026-09-27.csv.gz --kev known_exploited_vulnerabilities.json

which writes ``data/feeds/epss-kev/snapshot.json`` and pins its hash in ``snapshot.lock.json``.
``load()`` verifies the pin; an absent snapshot is not an error -- the report states
"EPSS/KEV not assessed".  A present snapshot whose bytes differ from the pin fails closed.
The report always shows "EPSS/KEV as of <date>".
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent
SNAPSHOT_DIR = ROOT.parent / "data" / "feeds" / "epss-kev"
SNAPSHOT = "snapshot.json"
LOCK = "snapshot.lock.json"
SCHEMA = "appsec-review/epss-kev-snapshot/1.0"
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class SnapshotError(ValueError):
    pass


def _sha_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _read(path: Path) -> bytes:
    data = Path(path).read_bytes()
    return gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data


def parse_epss(data: bytes) -> dict[str, Any]:
    text = data.decode("utf-8-sig")
    lines = text.splitlines()
    meta: dict[str, str] = {}
    if lines and lines[0].startswith("#"):
        for part in lines[0].lstrip("#").split(","):
            key, _, value = part.partition(":")
            meta[key.strip()] = value.strip()
        lines = lines[1:]
    scores = {}
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        cve = (row.get("cve") or "").strip()
        if not CVE.match(cve):
            continue
        try:
            epss, percentile = float(row["epss"]), float(row["percentile"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SnapshotError(f"EPSS row for {cve} is not numeric") from exc
        if not (0.0 <= epss <= 1.0 and 0.0 <= percentile <= 1.0):
            raise SnapshotError(f"EPSS row for {cve} is out of range")
        scores[cve] = {"epss": epss, "percentile": percentile}
    if not scores:
        raise SnapshotError("EPSS file has no cve,epss,percentile rows")
    score_date = (meta.get("score_date") or "")[:10]
    if not DATE.match(score_date):
        raise SnapshotError("EPSS file header lacks #model_version:...,score_date:YYYY-MM-DD...")
    return {"model_version": meta.get("model_version") or "unknown", "score_date": score_date,
            "scores": dict(sorted(scores.items()))}


def parse_kev(data: bytes) -> dict[str, Any]:
    value = json.loads(data)
    rows = value.get("vulnerabilities") if isinstance(value, dict) else None
    released = str(value.get("dateReleased") or "")[:10] if isinstance(value, dict) else ""
    if not isinstance(rows, list) or not DATE.match(released):
        raise SnapshotError("KEV file is not the CISA known_exploited_vulnerabilities.json shape")
    entries = {}
    for row in rows:
        cve = str(row.get("cveID") or "")
        if CVE.match(cve):
            entries[cve] = {"date_added": str(row.get("dateAdded") or "")[:10],
                            "due_date": str(row.get("dueDate") or "")[:10] or None,
                            "known_ransomware_campaign_use": str(row.get("knownRansomwareCampaignUse") or "Unknown")}
    return {"catalog_version": str(value.get("catalogVersion") or "unknown"), "date_released": released,
            "entries": dict(sorted(entries.items()))}


def intake(epss_path: Path, kev_path: Path, directory: Path | None = None) -> dict[str, Any]:
    """Import user-supplied EPSS and KEV files into a dated, pinned snapshot (no network)."""
    directory = Path(directory or SNAPSHOT_DIR)
    epss_raw, kev_raw = Path(epss_path).read_bytes(), Path(kev_path).read_bytes()
    epss, kev = parse_epss(_read(epss_path)), parse_kev(_read(kev_path))
    snapshot = {"schema": SCHEMA, "as_of": min(epss["score_date"], kev["date_released"]),
        "epss": {**{key: epss[key] for key in ("model_version", "score_date")},
                 "source": {"file": Path(epss_path).name, "sha256": _sha_bytes(epss_raw)},
                 "scores": epss["scores"]},
        "kev": {**{key: kev[key] for key in ("catalog_version", "date_released")},
                "source": {"file": Path(kev_path).name, "sha256": _sha_bytes(kev_raw)},
                "entries": kev["entries"]}}
    directory.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(snapshot, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (directory / SNAPSHOT).write_bytes(data)
    lock = {"schema": SCHEMA.replace("snapshot", "snapshot-lock"), "as_of": snapshot["as_of"],
            "snapshot_sha256": _sha_bytes(data), "epss_score_date": epss["score_date"],
            "kev_date_released": kev["date_released"], "epss_rows": len(epss["scores"]),
            "kev_rows": len(kev["entries"])}
    (directory / LOCK).write_text(json.dumps(lock, indent=1, sort_keys=True) + "\n")
    return lock


class Snapshot:
    def __init__(self, value: dict[str, Any], lock: dict[str, Any]):
        self.value, self.lock = value, lock
        self.as_of = value["as_of"]
        self.identity = {"as_of": self.as_of, "snapshot_sha256": lock["snapshot_sha256"],
                         "epss_score_date": value["epss"]["score_date"],
                         "epss_model_version": value["epss"]["model_version"],
                         "kev_date_released": value["kev"]["date_released"],
                         "kev_catalog_version": value["kev"]["catalog_version"]}

    def lookup(self, identifiers: list[str]) -> dict[str, Any]:
        """EPSS (max over aliases) and KEV membership for one advisory and its aliases."""
        cves = sorted({item for item in identifiers if CVE.match(str(item))})
        epss = [dict(cve=cve, **self.value["epss"]["scores"][cve]) for cve in cves
                if cve in self.value["epss"]["scores"]]
        kev = [dict(cve=cve, **self.value["kev"]["entries"][cve]) for cve in cves
               if cve in self.value["kev"]["entries"]]
        best = max(epss, key=lambda row: (row["epss"], row["cve"])) if epss else None
        return {"assessed": True, "as_of": self.as_of, "cves": cves,
                "epss": best["epss"] if best else None, "epss_percentile": best["percentile"] if best else None,
                "epss_cve": best["cve"] if best else None, "kev": bool(kev),
                "kev_entries": kev, "note": None if cves else "no CVE identifier among the advisory aliases"}


def load(directory: Path | None = None) -> Snapshot | None:
    directory = Path(directory or SNAPSHOT_DIR)
    snapshot, lock = directory / SNAPSHOT, directory / LOCK
    if not snapshot.exists() and not lock.exists():
        return None
    if not snapshot.is_file() or not lock.is_file() or snapshot.is_symlink():
        raise SnapshotError("EPSS/KEV snapshot or its lock is missing or unsafe")
    pin = json.loads(lock.read_text())
    data = snapshot.read_bytes()
    if _sha_bytes(data) != pin.get("snapshot_sha256"):
        raise SnapshotError("EPSS/KEV snapshot bytes differ from the pinned hash")
    value = json.loads(data)
    if value.get("schema") != SCHEMA or value.get("as_of") != pin.get("as_of"):
        raise SnapshotError("EPSS/KEV snapshot schema or date differs from its lock")
    return Snapshot(value, pin)


def not_assessed(identifiers: list[str]) -> dict[str, Any]:
    return {"assessed": False, "as_of": None, "cves": sorted({i for i in identifiers if CVE.match(str(i))}),
            "epss": None, "epss_percentile": None, "epss_cve": None, "kev": None, "kev_entries": [],
            "note": "EPSS/KEV not assessed: no pinned snapshot has been imported (epss_kev_snapshot.py intake)"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    take = sub.add_parser("intake", help="import user-supplied EPSS CSV(.gz) and KEV JSON files")
    take.add_argument("--epss", type=Path, required=True)
    take.add_argument("--kev", type=Path, required=True)
    take.add_argument("--directory", type=Path, default=None)
    show = sub.add_parser("check", help="verify the pinned snapshot")
    show.add_argument("--directory", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.command == "intake":
        print(json.dumps(intake(args.epss, args.kev, args.directory), indent=1))
    else:
        loaded = load(args.directory)
        print(json.dumps(loaded.identity if loaded else {"status": "not assessed"}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
