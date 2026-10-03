"""Immutable OSV bulk-data snapshot publisher (sibling of ``nvd_feed.py``).

Downloads ``<ECOSYSTEM>/all.zip`` from the public OSV GCS bucket for a fixed ecosystem set,
verifies each is a readable zip of JSON advisories, and publishes an immutable snapshot:

    <root>/snapshots/<snapshot_id>/manifest.json
    <root>/snapshots/<snapshot_id>/NOTICE.txt
    <root>/snapshots/<snapshot_id>/index.sqlite     (lookup index, hash-listed in the manifest)
    <root>/snapshots/<snapshot_id>/db/osv-scanner/<ecosystem>/all.zip

``db/`` is what OSV-Scanner's offline mode wants as its cache root (``<db>/osv-scanner/<eco>/all.zip``).
``<root>/current.json`` is advanced atomically only after the snapshot directory is complete.
Reference data only: nothing here establishes that a component is vulnerable in a given target.

A failure for one ecosystem is recorded in the manifest and never deletes the last good data:
the previous good archive for that ecosystem is carried forward (with its ORIGINAL fetched_at, so the
age ceiling still bites) or, if there never was one, the ecosystem is a recorded gap.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone

import osv_index
from execution_state import Blocked, Lock, atomic_json, beneath, event, file_hash, now, read_json


SCHEMA = "appsec-review/osv-snapshot-manifest/1"
POINTER_SCHEMA = "appsec-review/osv-current-pointer/1"
FEED_ID = "osv"
BASE_URL = "https://storage.googleapis.com/osv-vulnerabilities"
# Directory names exactly as the GCS bucket uses them (verified against the bucket 2026-09-29). P43: Debian and
# Alpine, OSV's names for the base-image OS ecosystems (records carry the release: Debian:10, Alpine:v3.24), so OSV
# corroborates Grype on base-image packages. Ubuntu is not fetched: P37's ubuntu build packages stay Grype-only.
ECOSYSTEMS = ("npm", "Go", "Maven", "crates.io", "NuGet", "Packagist", "PyPI", "Debian", "Alpine")
USER_AGENT = "appsec-review-osv-publisher/1"
DEFAULT_KEEP = 3
MAX_ARCHIVE_BYTES = 2 * 1024 ** 3          # transport cap per ecosystem archive
MAX_MEMBERS = 2_000_000
MAX_MEMBER_BYTES = 64 * 1024 ** 2           # one advisory
MAX_UNCOMPRESSED_BYTES = 16 * 1024 ** 3     # zip-bomb guard per archive
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}")
_SNAPSHOT_ID = re.compile(r"sha256-[0-9a-f]{16}")

# Licence by advisory-id prefix, from the OSV data-licence documentation. Anything not listed is
# recorded as "unspecified" so the NOTICE never over-claims. Verify against the upstream before
# redistributing anything: snapshots are NOT to be redistributed outside the run/host cache.
# P43 gap: the Debian (DLA, DTSA, DEBIAN; DSA as before) and Alpine (ALPINE) prefixes have no licence the repo can
# cite from OSV's documentation, so they are left out (recorded "unspecified") until verified upstream.
LICENCE_BY_PREFIX = {
    "GHSA": "CC-BY-4.0", "GO": "CC-BY-4.0", "PYSEC": "CC-BY-4.0", "OSV": "CC-BY-4.0",
    "RUSTSEC": "CC0-1.0", "MAL": "Apache-2.0", "GSD": "CC0-1.0", "CVE": "CC-BY-4.0",
    "OSEC": "CC-BY-4.0", "UBUNTU": "CC-BY-SA-4.0", "USN": "CC-BY-SA-4.0", "DSA": "unspecified",
}
NOTICE = """OSV bulk data attribution
=========================

This directory holds unmodified copies of the OSV (https://osv.dev) bulk advisory archives
retrieved from {base}. The archives aggregate advisories from many databases, each under its own
licence: CC-BY-4.0 (e.g. GitHub Advisory Database, Go vulndb, PyPA advisory DB, OSV.dev),
CC0-1.0 (e.g. RustSec, GSD), CC-BY-SA-4.0 (Ubuntu), and others. The per-advisory-prefix counts and
the licence recorded for each prefix are in manifest.json under "licences". Attribution: "Data from
OSV.dev and the individual advisory databases named in each record's id prefix and 'database_specific'
fields."

Do not redistribute these snapshots outside the run/host cache that produced them. Anything derived
from them and shared onward must keep this attribution and honour CC-BY-SA-4.0 where UBUNTU/USN
records are included.

This is reference data. It does not establish that a component in any reviewed target is affected,
reachable or exploitable.
"""


def utcnow():
    return datetime.now(timezone.utc)


def timestamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include an offset")
    return parsed.astimezone(timezone.utc)


def feed_root():
    configured = os.environ.get("APPSEC_OSV_ROOT")
    return Path(configured) if configured else Path(__file__).resolve().parents[1] / "data" / "feeds" / "osv"


def _safe_root(root):
    root = Path(root).absolute()
    if root == Path(root.anchor) or len(root.parts) < 3:
        raise ValueError(f"unsafe OSV root: {root}")
    return root


def source_url(ecosystem):
    if ecosystem not in ECOSYSTEMS:
        raise ValueError(f"unsupported OSV ecosystem: {ecosystem!r}")
    return f"{BASE_URL}/{ecosystem}/all.zip"


def download(url, destination, etag=None, timeout=300, max_bytes=MAX_ARCHIVE_BYTES):
    """Stream ``url`` to ``destination`` (must not exist). Returns a dict with ``not_modified``,
    ``size``, ``etag``. Injected in tests; the only network call in this module."""
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if etag:
        headers["If-None-Match"] = etag
    request = urllib.request.Request(url, headers=headers)
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return {"not_modified": True, "size": 0, "etag": etag}
        raise
    size = 0
    with response, Path(destination).open("xb") as output:
        if getattr(response, "status", 200) != 200:
            raise RuntimeError(f"OSV request returned HTTP {response.status}")
        declared = response.headers.get("Content-Length")
        if declared is not None and int(declared) > max_bytes:
            raise ValueError("OSV archive exceeds the transport size cap")
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise ValueError("OSV archive exceeds the transport size cap")
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())
        if declared is not None and int(declared) != size:
            raise ValueError("OSV archive transport length mismatch")
        received_etag = response.headers.get("ETag")
    return {"not_modified": False, "size": size, "etag": received_etag}


def _sha256(path):
    return file_hash(path)


def validate_archive(path):
    """The archive must be a fully CRC-readable zip whose every member is a JSON advisory object with
    an ``id``. Returns ``{"record_count", "prefixes": {prefix: count}}``. Fail closed on anything else."""
    path = Path(path)
    ids = set()
    prefixes = {}
    total = 0
    with zipfile.ZipFile(path) as archive:
        members = [item for item in archive.infolist() if not item.is_dir()]
        if not members:
            raise ValueError("OSV archive is empty")
        if len(members) > MAX_MEMBERS:
            raise ValueError("OSV archive has too many members")
        for item in members:
            name = item.filename
            if name.startswith("/") or ".." in name.split("/") or not name.endswith(".json"):
                raise ValueError(f"OSV archive member is not a safe .json path: {name!r}")
            if item.file_size > MAX_MEMBER_BYTES:
                raise ValueError("OSV advisory member exceeds the size cap")
            total += item.file_size
            if total > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("OSV archive expands beyond the size cap")
            with archive.open(item) as stream:
                data = stream.read(MAX_MEMBER_BYTES + 1)
            if len(data) > MAX_MEMBER_BYTES:
                raise ValueError("OSV advisory member exceeds the size cap")
            record = json.loads(data.decode("utf-8-sig"))     # CRC is verified as the member is read
            identifier = record.get("id") if isinstance(record, dict) else None
            if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
                raise ValueError(f"invalid OSV advisory identity in {name!r}")
            if identifier in ids:
                raise ValueError(f"duplicate OSV advisory identity: {identifier}")
            ids.add(identifier)
            prefix = identifier.split("-", 1)[0]
            prefixes[prefix] = prefixes.get(prefix, 0) + 1
    return {"record_count": len(ids), "prefixes": prefixes}


def _link_or_copy(source, target):
    Path(target).parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, target)
    except OSError:
        shutil.copyfile(source, target)


def _snapshot_id(manifest):
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return "sha256-" + hashlib.sha256(payload).hexdigest()[:16]


def _licences(entries):
    totals = {}
    for entry in entries.values():
        for prefix, count in (entry.get("prefixes") or {}).items():
            totals[prefix] = totals.get(prefix, 0) + count
    return {prefix: {"records": count, "licence": LICENCE_BY_PREFIX.get(prefix, "unspecified")}
            for prefix, count in sorted(totals.items())}


def _current(root):
    path = Path(root) / "current.json"
    return read_json(path) if path.exists() else None


def _previous_manifest(root, current):
    if not current:
        return None
    manifest_path = Path(root) / "snapshots" / current["snapshot_id"] / "manifest.json"
    if not manifest_path.is_file() or file_hash(manifest_path) != current["manifest_sha256"]:
        return None      # never trust or carry forward from a snapshot that does not verify
    return read_json(manifest_path)


def _prune(root, keep):
    directory = Path(root) / "snapshots"
    current = _current(root)
    keepers = {current["snapshot_id"]} if current else set()
    others = sorted((p for p in directory.iterdir() if p.is_dir() and p.name not in keepers),
                    key=lambda p: p.stat().st_mtime, reverse=True)
    for stale in others[max(keep - len(keepers), 0):]:
        shutil.rmtree(stale, ignore_errors=True)


def sync(root=None, coordinator_id=None, clock=utcnow, fetch_file=download,
         ecosystems=ECOSYSTEMS, keep=None):
    """Refresh every ecosystem and publish one immutable snapshot. Raises only if nothing usable
    exists for ANY ecosystem (then the prior pointer is left exactly as it was)."""
    root = _safe_root(root or feed_root())
    coordinator_id = coordinator_id or os.environ.get("DAGSTER_RUN_ID")
    if not coordinator_id:
        raise Blocked("OSV synchronization requires a coordinator identity")
    keep = keep if keep is not None else int(os.environ.get("APPSEC_OSV_KEEP", DEFAULT_KEEP))
    if keep < 1:
        raise ValueError("keep must be at least 1")
    started = clock()
    attempt_id = timestamp(started).replace(":", "") + "-" + uuid.uuid4().hex[:8]
    with Lock(root / "locks" / "writer.lock"):
        current = _current(root)
        previous = _previous_manifest(root, current)
        previous_entries = (previous or {}).get("ecosystems", {})
        staging = root / "staging" / attempt_id
        staging.mkdir(parents=True, exist_ok=False)
        entries = {}
        try:
            for ecosystem in ecosystems:
                entries[ecosystem] = _refresh_one(root, staging, ecosystem, previous, previous_entries.get(ecosystem),
                                                  started, fetch_file)
            usable = [name for name, entry in entries.items() if entry["status"] != "FAILED"]
            if not usable:
                raise RuntimeError("no OSV ecosystem produced a usable archive: "
                                   + "; ".join(f"{n}: {e.get('error')}" for n, e in entries.items()))
            index = _build_index(staging, entries)
            manifest = {
                "schema": SCHEMA, "feed_id": FEED_ID, "captured_at": timestamp(started),
                "parent_snapshot_id": current["snapshot_id"] if current else None,
                "source_base_url": BASE_URL, "ecosystems": entries,
                "data_timestamp": min(entries[n]["fetched_at"] for n in usable), "index": index,
                "gaps": sorted(n for n, e in entries.items() if e["status"] == "FAILED"),
                "licences": _licences(entries),
                "redistribution": "Do not redistribute outside the run/host cache; see NOTICE.txt.",
                "limitations": ["Reference data only; no match, reachability, exploitability or finding is established."],
            }
            snapshot_id = _snapshot_id(manifest)
            manifest["snapshot_id"] = snapshot_id
            (staging / "NOTICE.txt").write_text(NOTICE.format(base=BASE_URL), encoding="utf-8")
            atomic_json(staging / "manifest.json", manifest)
            destination = root / "snapshots" / snapshot_id
            if destination.exists():
                shutil.rmtree(staging)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(staging, destination)
            pointer = {"schema": POINTER_SCHEMA, "feed_id": FEED_ID, "snapshot_id": snapshot_id,
                       "manifest_sha256": file_hash(destination / "manifest.json"),
                       "published_at": now(), "data_timestamp": manifest["data_timestamp"]}
            atomic_json(root / "current.json", pointer)       # sole commit point
        except BaseException as exc:
            shutil.rmtree(staging, ignore_errors=True)
            try:
                event(_events(root), "OSV_SYNC_FAILED", attempt_id=attempt_id, error_type=type(exc).__name__)
            except OSError:
                pass
            raise
        try:
            event(_events(root), "OSV_SNAPSHOT_PUBLISHED", attempt_id=attempt_id, snapshot_id=snapshot_id,
                  gaps=manifest["gaps"])
            _prune(root, keep)
        except BaseException as diagnostic:      # post-commit housekeeping never recasts a publish as a failure
            print(f"OSV_POST_PUBLICATION_DIAGNOSTIC_FAILURE: {diagnostic}", file=sys.stderr, flush=True)
        return {**pointer, "gaps": manifest["gaps"]}


def _build_index(staging, entries):
    """SQLite/FTS5 lookup index over the staged archives (justified by docs/osv-index-measurement.md).
    A failure to index never blocks publication of the scanner data; it is recorded instead."""
    archives = {name: staging / "db" / "osv-scanner" / name / "all.zip"
                for name, entry in entries.items() if entry["status"] != "FAILED"}
    target = staging / osv_index.INDEX_NAME
    started = time.monotonic()
    try:
        counts = osv_index.build(archives, target)
    except Exception as exc:
        return {"status": "FAILED", "error": f"{type(exc).__name__}: {exc}"[:300]}
    return {"status": "OK", "path": osv_index.INDEX_NAME, "schema_version": osv_index.SCHEMA_VERSION,
            "sha256": _sha256(target), "size_bytes": target.stat().st_size, "counts": counts,
            "build_seconds": round(time.monotonic() - started, 2)}


def _events(root):
    path = Path(root) / "events.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _carry(root, staging, ecosystem, previous, prior_entry, reason):
    """Keep the last good archive for ``ecosystem`` (original fetched_at) or record a gap."""
    if prior_entry and prior_entry.get("status") != "FAILED" and previous:
        source = Path(root) / "snapshots" / previous["snapshot_id"] / "db" / "osv-scanner" / ecosystem / "all.zip"
        if source.is_file() and _sha256(source) == prior_entry["sha256"]:
            target = staging / "db" / "osv-scanner" / ecosystem / "all.zip"
            _link_or_copy(source, target)
            return {**{k: prior_entry[k] for k in prior_entry
                       if k not in ("status", "error", "carried_reason")},
                    "status": "CARRIED_FORWARD", "carried_reason": reason}
    return {"status": "FAILED", "source_url": source_url(ecosystem), "error": reason}


def _refresh_one(root, staging, ecosystem, previous, prior_entry, started, fetch_file):
    url = source_url(ecosystem)
    work = staging / "incoming" / ecosystem
    work.mkdir(parents=True, exist_ok=True)
    archive = work / "all.zip"
    prior_ok = bool(prior_entry and prior_entry.get("status") != "FAILED")
    try:
        result = fetch_file(url, archive, prior_entry.get("etag") if prior_ok else None)
        if result.get("not_modified"):
            if not prior_ok:
                raise ValueError("server reported not-modified without a prior archive")
            carried = _carry(root, staging, ecosystem, previous, prior_entry, "not-modified")
            if carried["status"] == "FAILED":
                raise ValueError("prior archive no longer verifies")
            # Unchanged upstream bytes re-confirmed now: freshness is the confirmation time.
            carried["fetched_at"] = timestamp(started)
            carried["status"] = "OK"
            carried.pop("carried_reason", None)
            shutil.rmtree(work, ignore_errors=True)
            return carried
        summary = validate_archive(archive)
        digest = _sha256(archive)
        size = archive.stat().st_size
        if size != result.get("size"):
            raise ValueError("OSV archive size differs from the transport length")
        target = staging / "db" / "osv-scanner" / ecosystem / "all.zip"
        target.parent.mkdir(parents=True, exist_ok=True)
        os.replace(archive, target)
        shutil.rmtree(work, ignore_errors=True)
        return {"status": "OK", "source_url": url, "fetched_at": timestamp(started), "etag": result.get("etag"),
                "sha256": digest, "size_bytes": size, "record_count": summary["record_count"],
                "prefixes": dict(sorted(summary["prefixes"].items()))}
    except (Exception,) as exc:
        shutil.rmtree(work, ignore_errors=True)
        reason = f"{type(exc).__name__}: {exc}"[:500]
        return _carry(root, staging, ecosystem, previous, prior_entry, reason)


def verify(root=None):
    """Re-hash the current snapshot against its manifest. Raises on any mismatch."""
    root = _safe_root(root or feed_root())
    current = _current(root)
    if current is None:
        raise Blocked("OSV has no published snapshot")
    if current.get("schema") != POINTER_SCHEMA:
        raise ValueError("invalid OSV current pointer schema")
    directory = beneath(root, root / "snapshots" / current["snapshot_id"])
    if file_hash(directory / "manifest.json") != current["manifest_sha256"]:
        raise ValueError("OSV current manifest hash mismatch")
    manifest = read_json(directory / "manifest.json")
    unsigned = {k: v for k, v in manifest.items() if k != "snapshot_id"}
    if manifest.get("schema") != SCHEMA or _snapshot_id(unsigned) != current["snapshot_id"]:
        raise ValueError("OSV snapshot identity mismatch")
    for ecosystem, entry in manifest["ecosystems"].items():
        if entry["status"] == "FAILED":
            continue
        path = directory / "db" / "osv-scanner" / ecosystem / "all.zip"
        if _sha256(path) != entry["sha256"] or path.stat().st_size != entry["size_bytes"]:
            raise ValueError(f"OSV archive integrity mismatch: {ecosystem}")
    index = manifest.get("index") or {}
    if index.get("status") == "OK":
        path = directory / index["path"]
        if _sha256(path) != index["sha256"] or path.stat().st_size != index["size_bytes"]:
            raise ValueError("OSV index integrity mismatch")
    return {"snapshot_id": current["snapshot_id"], "data_timestamp": manifest["data_timestamp"],
            "gaps": manifest["gaps"], "index": index.get("status", "ABSENT")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sync_parser = sub.add_parser("sync")
    sync_parser.add_argument("--root", type=Path)
    sync_parser.add_argument("--coordinator-id")
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--root", type=Path)
    args = parser.parse_args(argv)
    result = sync(args.root, args.coordinator_id) if args.command == "sync" else verify(args.root)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
