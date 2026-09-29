"""Immutable MITRE ATT&CK / CAPEC reference snapshot publisher (sibling of ``osv_feed.py``, ADR-0026).

Downloads release-pinned STIX 2.1 bundles (ATT&CK Enterprise by default, Mobile and ICS on request;
CAPEC from ``mitre/cti``), verifies each parses as the expected bundle at the pinned upstream version
and bytes, and publishes an immutable snapshot:

    <root>/snapshots/<snapshot_id>/manifest.json
    <root>/snapshots/<snapshot_id>/NOTICE.txt
    <root>/snapshots/<snapshot_id>/reference.json          (derived by attack_reference.py, hash-listed)
    <root>/snapshots/<snapshot_id>/sources/<source>.json    (unmodified upstream bundles)

``<root>/current.json`` is advanced atomically only after the snapshot directory is complete.
Reference data only: an ATT&CK technique or CAPEC pattern id labels a claim; it is never evidence.

A failure for one source is recorded in the manifest and never deletes the last good data: the
previous good bundle for that source is carried forward (with its ORIGINAL fetched_at, so the age
ceiling still bites) or, if there never was one, the source is a recorded gap.

``resolve()`` is the read side with the SCA registry's semantics (age from the ORIGINAL fetched_at,
``SnapshotBlocked`` / ``SnapshotStale`` / ``SnapshotInvalid``); the SCA registry is container-DB
shaped, so this feed is not bound into it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

import attack_reference
from dependency_snapshot_registry import SnapshotBlocked, SnapshotInvalid, SnapshotStale
from execution_state import Blocked, Lock, atomic_json, beneath, event, file_hash, now, read_json
import tunables


SCHEMA = "appsec-review/mitre-snapshot-manifest/1"
POINTER_SCHEMA = "appsec-review/mitre-current-pointer/1"
IDENTITY_SCHEMA = "appsec-review/mitre-reference-identity/1"
FEED_ID = "mitre"
USER_AGENT = "appsec-review-mitre-publisher/1"
DEFAULT_KEEP = 3
MAX_SOURCE_BYTES = 256 * 1024 ** 2
REFERENCE_NAME = "reference.json"
ATTACK_RELEASE = "19.2"
# Pinned by release tag, never master/latest at run time (verified 2026-09-29: the tags resolve and the
# bytes hash as below). Raising a pin is a reviewed change to this table.
_ATTACK = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v{v}/{d}-attack/{d}-attack-{v}.json"
SOURCES = {
    "enterprise-attack": {"kind": "attack", "url": _ATTACK.format(v=ATTACK_RELEASE, d="enterprise"),
                          "upstream_version": ATTACK_RELEASE, "licence": "MITRE ATT&CK Terms of Use",
                          "sha256": "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"},
    "mobile-attack": {"kind": "attack", "url": _ATTACK.format(v=ATTACK_RELEASE, d="mobile"),
                      "upstream_version": ATTACK_RELEASE, "licence": "MITRE ATT&CK Terms of Use",
                      "sha256": "acfa5ca2d93484476f79bf38590e2b55bb675fc0ce85e76bffa0af2c82dada64"},
    "ics-attack": {"kind": "attack", "url": _ATTACK.format(v=ATTACK_RELEASE, d="ics"),
                   "upstream_version": ATTACK_RELEASE, "licence": "MITRE ATT&CK Terms of Use",
                   "sha256": "08b83d2cea6b6d6752468ef0e62e2ab2a53c9443ef72c439ecccb07ab9e89da9"},
    "capec": {"kind": "capec",
              "url": "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v19.2/capec/2.1/stix-capec.json",
              "upstream_version": "3.9", "licence": "MITRE CAPEC Terms of Use",
              "sha256": "ee6244f48259c1963d0507535e1843d67ba08fe58b4dfe351c1b74f9e376fa69"},
}
DEFAULT_SOURCES = ("enterprise-attack", "capec")      # mobile/ICS: APPSEC_MITRE_SOURCES or --sources
NOTICE = """MITRE ATT&CK and CAPEC attribution
==================================

This directory holds unmodified copies of MITRE STIX 2.1 bundles retrieved from:
{urls}

ATT&CK: (c) 2015-2026 The MITRE Corporation. This work is reproduced and distributed with the
permission of The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE
Corporation. Licence (MITRE ATT&CK Terms of Use): The MITRE Corporation (MITRE) hereby grants you a
non-exclusive, royalty-free license to use ATT&CK for research, development, and commercial purposes.
Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright
designation and this license in any such copy.

CAPEC: (c) 2007-2023 The MITRE Corporation. CAPEC and the CAPEC logo are trademarks of The MITRE
Corporation. Licence (MITRE CAPEC Terms of Use): The MITRE Corporation (MITRE) hereby grants you a
non-exclusive, royalty-free license to use Common Attack Pattern Enumeration and Classification
(CAPEC) for research, development, and commercial purposes. Any copy you make for such purposes is
authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.

DISCLAIMERS: ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN ARE PROVIDED ON AN "AS IS" BASIS AND
THE CONTRIBUTOR, THE ORGANIZATION HE/SHE REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION,
ITS BOARD OF TRUSTEES, OFFICERS, AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED.

The copyright statements carried inside each bundle are recorded in manifest.json ("markings").
reference.json is derived from these bundles by attack_reference.py; it keeps this attribution.

This is reference data. An ATT&CK technique or CAPEC pattern id labels a claim; it never establishes
that a weakness exists, is reachable or is exploitable in any reviewed target.
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


def default_max_age_seconds():
    """The one reference-snapshot ceiling (OSV, NVD-derived checks, this feed): pipeline/tunables.json."""
    return int(tunables.shared("reference_snapshot_max_age_seconds"))


def feed_root():
    configured = os.environ.get("APPSEC_MITRE_FEED_ROOT")
    return Path(configured) if configured else Path(__file__).resolve().parents[1] / "data" / "feeds" / "mitre"


def configured_sources():
    configured = os.environ.get("APPSEC_MITRE_SOURCES")
    names = tuple(item.strip() for item in configured.split(",") if item.strip()) if configured else DEFAULT_SOURCES
    unknown = [name for name in names if name not in SOURCES]
    if unknown or not names:
        raise ValueError(f"unknown MITRE source(s): {unknown}; allowed: {sorted(SOURCES)}")
    return names


def _safe_root(root):
    root = Path(root).absolute()
    if root == Path(root.anchor) or len(root.parts) < 3:
        raise ValueError(f"unsafe MITRE root: {root}")
    return root


def download(url, destination, etag=None, timeout=300, max_bytes=MAX_SOURCE_BYTES):
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
            raise RuntimeError(f"MITRE request returned HTTP {response.status}")
        declared = response.headers.get("Content-Length")
        if declared is not None and int(declared) > max_bytes:
            raise ValueError("MITRE bundle exceeds the transport size cap")
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise ValueError("MITRE bundle exceeds the transport size cap")
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())
        if declared is not None and int(declared) != size:
            raise ValueError("MITRE bundle transport length mismatch")
        received_etag = response.headers.get("ETag")
    return {"not_modified": False, "size": size, "etag": received_etag}


def _sha256(path):
    return file_hash(path)


def validate_source(path, spec):
    """The bundle must parse as the expected STIX bundle at the pinned upstream version (and, when the
    spec pins bytes, hash to them). Returns the summary; fails closed on anything else."""
    path = Path(path)
    if path.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("MITRE bundle exceeds the size cap")
    if spec.get("sha256") and _sha256(path) != spec["sha256"]:
        raise ValueError("MITRE bundle bytes do not match the pinned sha256")
    data = path.read_bytes()
    summary = (attack_reference.summarize_attack if spec["kind"] == "attack" else attack_reference.summarize_capec)(data)
    if summary["upstream_version"] != spec["upstream_version"]:
        raise ValueError(f"MITRE bundle is version {summary['upstream_version']!r}, pinned {spec['upstream_version']!r}")
    return summary


def _link_or_copy(source, target):
    Path(target).parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, target)
    except OSError:
        shutil.copyfile(source, target)


def _snapshot_id(manifest):
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return "sha256-" + hashlib.sha256(payload).hexdigest()[:16]


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


def sync(root=None, coordinator_id=None, clock=utcnow, fetch_file=download, sources=None, keep=None,
         specs=None):
    """Refresh every source and publish one immutable snapshot. Raises only if nothing usable exists
    for ANY source (then the prior pointer is left exactly as it was). ``specs`` overrides the pinned
    source table (tests)."""
    root = _safe_root(root or feed_root())
    coordinator_id = coordinator_id or os.environ.get("DAGSTER_RUN_ID")
    if not coordinator_id:
        raise Blocked("MITRE synchronization requires a coordinator identity")
    specs = specs or SOURCES
    sources = tuple(sources or configured_sources())
    if any(name not in specs for name in sources):
        raise ValueError(f"unknown MITRE source in {sources}")
    keep = keep if keep is not None else int(os.environ.get("APPSEC_MITRE_KEEP", DEFAULT_KEEP))
    if keep < 1:
        raise ValueError("keep must be at least 1")
    started = clock()
    attempt_id = timestamp(started).replace(":", "") + "-" + uuid.uuid4().hex[:8]
    with Lock(root / "locks" / "writer.lock"):
        current = _current(root)
        previous = _previous_manifest(root, current)
        previous_entries = (previous or {}).get("sources", {})
        staging = root / "staging" / attempt_id
        staging.mkdir(parents=True, exist_ok=False)
        entries = {}
        try:
            for name in sources:
                entries[name] = _refresh_one(root, staging, name, specs[name], previous,
                                             previous_entries.get(name), started, fetch_file)
            usable = [name for name, entry in entries.items() if entry["status"] != "FAILED"]
            if not usable:
                raise RuntimeError("no MITRE source produced a usable bundle: "
                                   + "; ".join(f"{n}: {e.get('error')}" for n, e in entries.items()))
            reference = _build_reference(staging, entries)
            manifest = {
                "schema": SCHEMA, "feed_id": FEED_ID, "captured_at": timestamp(started),
                "parent_snapshot_id": current["snapshot_id"] if current else None,
                "sources": entries, "reference": reference,
                "data_timestamp": min(entries[n]["fetched_at"] for n in usable),
                "gaps": sorted(n for n, e in entries.items() if e["status"] == "FAILED"),
                "licences": {n: e["licence"] for n, e in sorted(entries.items())},
                "markings": sorted({s for e in entries.values() for s in e.get("marking_statements", [])}),
                "limitations": ["Reference data only; an ATT&CK or CAPEC id labels a claim and is never evidence."],
            }
            snapshot_id = _snapshot_id(manifest)
            manifest["snapshot_id"] = snapshot_id
            urls = "\n".join(f"  {n}: {e['source_url']}" for n, e in sorted(entries.items()))
            (staging / "NOTICE.txt").write_text(NOTICE.format(urls=urls), encoding="utf-8")
            atomic_json(staging / "manifest.json", manifest)
            shutil.rmtree(staging / "incoming", ignore_errors=True)
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
                event(_events(root), "MITRE_SYNC_FAILED", attempt_id=attempt_id, error_type=type(exc).__name__)
            except OSError:
                pass
            raise
        try:
            event(_events(root), "MITRE_SNAPSHOT_PUBLISHED", attempt_id=attempt_id, snapshot_id=snapshot_id,
                  gaps=manifest["gaps"])
            _prune(root, keep)
        except BaseException as diagnostic:      # post-commit housekeeping never recasts a publish as a failure
            print(f"MITRE_POST_PUBLICATION_DIAGNOSTIC_FAILURE: {diagnostic}", file=sys.stderr, flush=True)
        return {**pointer, "gaps": manifest["gaps"]}


def _build_reference(staging, entries):
    """Derive reference.json from the staged bundles. Unlike the OSV index this is the feed's product,
    so a derivation failure fails the publication (the prior pointer stays)."""
    sources = {name: (entry["kind"], (staging / "sources" / f"{name}.json").read_bytes())
               for name, entry in entries.items() if entry["status"] != "FAILED"}
    data = attack_reference.reference_bytes(attack_reference.derive(sources))
    target = staging / REFERENCE_NAME
    target.write_bytes(data)
    reference = json.loads(data)
    return {"path": REFERENCE_NAME, "schema": attack_reference.SCHEMA, "sha256": _sha256(target),
            "size_bytes": len(data),
            "counts": {"techniques": len((reference["attack"] or {}).get("techniques", [])),
                       "tactics": len((reference["attack"] or {}).get("tactics", [])),
                       "capec_patterns": len((reference["capec"] or {}).get("patterns", []))}}


def _events(root):
    path = Path(root) / "events.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _carry(root, staging, name, spec, previous, prior_entry, reason):
    """Keep the last good bundle for ``name`` (original fetched_at) or record a gap."""
    if prior_entry and prior_entry.get("status") != "FAILED" and previous:
        source = Path(root) / "snapshots" / previous["snapshot_id"] / "sources" / f"{name}.json"
        if source.is_file() and _sha256(source) == prior_entry["sha256"]:
            target = staging / "sources" / f"{name}.json"
            _link_or_copy(source, target)
            return {**{k: prior_entry[k] for k in prior_entry
                       if k not in ("status", "error", "carried_reason")},
                    "status": "CARRIED_FORWARD", "carried_reason": reason}
    return {"status": "FAILED", "kind": spec["kind"], "source_url": spec["url"], "licence": spec["licence"],
            "error": reason}


def _refresh_one(root, staging, name, spec, previous, prior_entry, started, fetch_file):
    url = spec["url"]
    work = staging / "incoming" / name
    work.mkdir(parents=True, exist_ok=True)
    bundle = work / "bundle.json"
    prior_ok = bool(prior_entry and prior_entry.get("status") != "FAILED" and prior_entry.get("source_url") == url)
    try:
        result = fetch_file(url, bundle, prior_entry.get("etag") if prior_ok else None)
        if result.get("not_modified"):
            if not prior_ok:
                raise ValueError("server reported not-modified without a prior bundle")
            carried = _carry(root, staging, name, spec, previous, prior_entry, "not-modified")
            if carried["status"] == "FAILED":
                raise ValueError("prior bundle no longer verifies")
            # Unchanged upstream bytes re-confirmed now: freshness is the confirmation time.
            carried["fetched_at"] = timestamp(started)
            carried["status"] = "OK"
            carried.pop("carried_reason", None)
            shutil.rmtree(work, ignore_errors=True)
            return carried
        size = bundle.stat().st_size
        if size != result.get("size"):
            raise ValueError("MITRE bundle size differs from the transport length")
        summary = validate_source(bundle, spec)
        digest = _sha256(bundle)
        target = staging / "sources" / f"{name}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        os.replace(bundle, target)
        shutil.rmtree(work, ignore_errors=True)
        return {"status": "OK", "kind": spec["kind"], "source_url": url, "fetched_at": timestamp(started),
                "etag": result.get("etag"), "sha256": digest, "size_bytes": size,
                "upstream_version": summary["upstream_version"], "record_count": summary["record_count"],
                "licence": spec["licence"], "marking_statements": summary["marking_statements"]}
    except (Exception,) as exc:
        shutil.rmtree(work, ignore_errors=True)
        reason = f"{type(exc).__name__}: {exc}"[:500]
        # A pin change (new URL) never carries the old release forward as if it were the new one.
        return _carry(root, staging, name, spec, previous, prior_entry if prior_ok else None, reason)


def _verified(root):
    """(pointer, manifest, directory) after re-hashing every published byte; raises on any mismatch."""
    current = _current(root)
    if current is None:
        raise SnapshotBlocked("MITRE has no published snapshot")
    if current.get("schema") != POINTER_SCHEMA or not isinstance(current.get("snapshot_id"), str):
        raise SnapshotInvalid("invalid MITRE current pointer schema")
    try:
        directory = beneath(root, root / "snapshots" / current["snapshot_id"])
    except ValueError as exc:
        raise SnapshotInvalid(str(exc)) from None
    if not (directory / "manifest.json").is_file():
        raise SnapshotBlocked("the MITRE snapshot named by current.json is not on disk")
    if file_hash(directory / "manifest.json") != current["manifest_sha256"]:
        raise SnapshotInvalid("MITRE current manifest hash mismatch")
    manifest = read_json(directory / "manifest.json")
    unsigned = {k: v for k, v in manifest.items() if k != "snapshot_id"}
    if (manifest.get("schema") != SCHEMA or manifest.get("snapshot_id") != current["snapshot_id"]
            or _snapshot_id(unsigned) != current["snapshot_id"]):
        raise SnapshotInvalid("MITRE snapshot identity mismatch")
    for name, entry in manifest["sources"].items():
        if entry["status"] == "FAILED":
            continue
        path = directory / "sources" / f"{name}.json"
        if not path.is_file() or path.is_symlink():
            raise SnapshotInvalid(f"MITRE bundle missing: {name}")
        if _sha256(path) != entry["sha256"] or path.stat().st_size != entry["size_bytes"]:
            raise SnapshotInvalid(f"MITRE bundle integrity mismatch: {name}")
    reference = manifest["reference"]
    path = directory / reference["path"]
    if (not path.is_file() or path.is_symlink() or _sha256(path) != reference["sha256"]
            or path.stat().st_size != reference["size_bytes"]):
        raise SnapshotInvalid("MITRE reference.json integrity mismatch")
    return current, manifest, directory


def verify(root=None):
    """Re-hash the current snapshot against its manifest. Raises on any mismatch."""
    root = _safe_root(root or feed_root())
    current, manifest, _ = _verified(root)
    return {"snapshot_id": current["snapshot_id"], "data_timestamp": manifest["data_timestamp"],
            "gaps": manifest["gaps"], "reference": manifest["reference"]["counts"],
            "upstream_versions": {n: e.get("upstream_version") for n, e in sorted(manifest["sources"].items())
                                  if e["status"] != "FAILED"}}


def resolve(root=None, *, now, max_age_seconds=None):
    """Verified identity of the current snapshot when its OLDEST usable source (original fetched_at)
    is within the ceiling. ``SnapshotBlocked`` when absent, ``SnapshotStale`` when over the ceiling,
    ``SnapshotInvalid`` on any integrity failure. ``now`` is required; never read from the clock here."""
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError("now must be a timezone-aware datetime")
    limit = max_age_seconds if max_age_seconds is not None else default_max_age_seconds()
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise SnapshotInvalid("an explicit non-negative age ceiling is required")
    root = _safe_root(root or feed_root())
    if not root.is_dir() or root.is_symlink():
        raise SnapshotBlocked("the MITRE feed root does not exist; the publisher has not run here")
    try:
        current, manifest, directory = _verified(root)
        oldest = min(parse_time(entry["fetched_at"]) for entry in manifest["sources"].values()
                     if entry["status"] != "FAILED")
    except (SnapshotBlocked, SnapshotInvalid):
        raise
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SnapshotInvalid(f"MITRE snapshot unreadable: {type(exc).__name__}") from None
    age = int((now.astimezone(timezone.utc) - oldest).total_seconds())
    if age < 0:
        raise SnapshotInvalid("MITRE snapshot timestamp is in the future")
    if age > limit:
        raise SnapshotStale(f"MITRE snapshot {current['snapshot_id']} is {age} seconds old; the limit is {limit}")
    return {"schema": IDENTITY_SCHEMA, "database_kind": FEED_ID, "snapshot_id": current["snapshot_id"],
            "manifest_sha256": current["manifest_sha256"], "data_timestamp": timestamp(oldest),
            "age_seconds": age, "max_age_seconds": limit, "gaps": manifest["gaps"],
            "reference_path": str(directory / manifest["reference"]["path"]),
            "reference_sha256": manifest["reference"]["sha256"],
            "upstream_versions": {n: e.get("upstream_version") for n, e in sorted(manifest["sources"].items())
                                  if e["status"] != "FAILED"}}



def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sync_parser = sub.add_parser("sync")
    sync_parser.add_argument("--root", type=Path)
    sync_parser.add_argument("--coordinator-id")
    sync_parser.add_argument("--sources", help=f"comma list from {sorted(SOURCES)}; default {','.join(DEFAULT_SOURCES)}")
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--root", type=Path)
    resolve_parser = sub.add_parser("resolve")
    resolve_parser.add_argument("--root", type=Path)
    resolve_parser.add_argument("--now", help="UTC timestamp; default the wall clock")
    resolve_parser.add_argument("--max-age-seconds", type=int)
    args = parser.parse_args(argv)
    if args.command == "sync":
        sources = [item.strip() for item in args.sources.split(",")] if args.sources else None
        result = sync(args.root, args.coordinator_id or "cli-" + uuid.uuid4().hex[:12], sources=sources)
    elif args.command == "verify":
        result = verify(args.root)
    else:
        try:
            result = resolve(args.root, now=parse_time(args.now) if args.now else utcnow(),
                             max_age_seconds=args.max_age_seconds)
        except SnapshotBlocked as exc:
            print(json.dumps({"status": "BLOCKED", "gap": attack_reference.GAP_MISSING, "cause": str(exc)})); return 2
        except SnapshotStale as exc:
            print(json.dumps({"status": "STALE", "gap": attack_reference.GAP_STALE, "cause": str(exc)})); return 3
        except SnapshotInvalid as exc:
            print(json.dumps({"status": "FAILED", "gap": attack_reference.GAP_INVALID, "cause": str(exc)})); return 4
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
