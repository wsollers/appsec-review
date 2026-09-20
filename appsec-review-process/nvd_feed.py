"""Asynchronous, immutable NVD JSON 2.0 snapshot publisher.

This is reference enrichment, not finding or affected-product proof. A first run
bootstraps the official yearly feeds. Later runs consume bounded CVE API 2.0
last-modified windows and publish delta layers over the immutable base.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

from execution_state import Blocked, Lock, atomic_json, beneath, event, file_hash, now, read_json


SCHEMA = "appsec-review/nvd-snapshot-manifest/1"
POINTER_SCHEMA = "appsec-review/nvd-current-pointer/1"
LEASE_SCHEMA = "appsec-review/nvd-writer-lease/1"
API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
FIRST_YEAR = 2002
WINDOW = timedelta(days=119)
PAGE_SIZE = 2000
LEASE_SECONDS = 180
HEARTBEAT_SECONDS = 30
USER_AGENT = "appsec-review-nvd-publisher/1"
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def utcnow():
    return datetime.now(timezone.utc)


def timestamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_time(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include an offset")
    return parsed.astimezone(timezone.utc)


def feed_root():
    configured = os.environ.get("APPSEC_NVD_ROOT")
    return Path(configured) if configured else Path(__file__).resolve().parents[1] / "data" / "feeds" / "nvd"


def _safe_root(root):
    root = Path(root).absolute()
    if root == Path(root.anchor) or len(root.parts) < 3:
        raise ValueError(f"unsafe NVD root: {root}")
    return root


def _append_event(root, kind, **details):
    path = Path(root) / "events.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    event(path, kind, **details)


def parse_meta(payload):
    result = {}
    for line in payload.decode("utf-8-sig").splitlines():
        key, separator, value = line.partition(":")
        if separator:
            result[key] = value.strip()
    required = {"lastModifiedDate", "size", "gzSize", "sha256"}
    if not required.issubset(result):
        raise ValueError(f"incomplete NVD feed metadata: missing {sorted(required - result.keys())}")
    if not re.fullmatch(r"[0-9A-Fa-f]{64}", result["sha256"]):
        raise ValueError("invalid NVD feed metadata sha256")
    result["size"] = int(result["size"])
    result["gzSize"] = int(result["gzSize"])
    parse_time(result["lastModifiedDate"])
    return result


def _headers(api_key=None):
    # NVD's static .json.gz endpoint currently returns 406 for narrower Accept
    # values, including application/gzip. */* works for both feeds and API 2.0.
    result = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if api_key:
        result["apiKey"] = api_key
    return result


def request_bytes(url, api_key=None, timeout=120):
    request = urllib.request.Request(url, headers=_headers(api_key))
    with urllib.request.urlopen(request, timeout=timeout) as response:
        status = getattr(response, "status", 200)
        if status != 200:
            raise RuntimeError(f"NVD request returned HTTP {status}")
        return response.read()


def download(url, destination, api_key=None, timeout=300):
    request = urllib.request.Request(url, headers=_headers(api_key))
    size = 0
    with urllib.request.urlopen(request, timeout=timeout) as response, Path(destination).open("xb") as output:
        status = getattr(response, "status", 200)
        if status != 200:
            raise RuntimeError(f"NVD request returned HTTP {status}")
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            output.write(chunk)
            size += len(chunk)
        output.flush()
        os.fsync(output.fileno())
    return size


def _gzip_properties(path):
    digest = hashlib.sha256()
    size = 0
    with gzip.open(path, "rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def iter_vulnerabilities(stream):
    """Incrementally decode the top-level vulnerabilities array."""
    decoder = json.JSONDecoder()
    text = io.TextIOWrapper(stream, encoding="utf-8-sig")
    buffer = ""
    eof = False
    marker = re.compile(r'"vulnerabilities"\s*:\s*\[')
    while True:
        chunk = text.read(1024 * 1024)
        if not chunk:
            eof = True
        buffer += chunk
        match = marker.search(buffer)
        if match:
            buffer = buffer[match.end():]
            break
        if eof:
            raise ValueError("NVD JSON has no vulnerabilities array")
        if len(buffer) > 4 * 1024 * 1024:
            buffer = buffer[-1024:]
    while True:
        buffer = buffer.lstrip()
        if buffer.startswith("]"):
            # Drain the stream so gzip validates its trailer/CRC.
            while text.read(1024 * 1024):
                pass
            return
        if buffer.startswith(","):
            buffer = buffer[1:].lstrip()
        try:
            value, end = decoder.raw_decode(buffer)
        except json.JSONDecodeError:
            chunk = text.read(1024 * 1024)
            if not chunk:
                raise ValueError("truncated NVD vulnerabilities array") from None
            buffer += chunk
            continue
        if not isinstance(value, dict):
            raise ValueError("NVD vulnerability entry must be an object")
        yield value
        buffer = buffer[end:]


def validate_feed(path, metadata):
    path = Path(path)
    if path.stat().st_size != metadata["gzSize"]:
        raise ValueError("NVD compressed feed size does not match metadata")
    size, digest = _gzip_properties(path)
    if size != metadata["size"] or digest.lower() != metadata["sha256"].lower():
        raise ValueError("NVD uncompressed feed hash or size does not match metadata")
    ids = set()
    with gzip.open(path, "rb") as stream:
        for wrapper in iter_vulnerabilities(stream):
            cve = wrapper.get("cve")
            identifier = cve.get("id") if isinstance(cve, dict) else None
            if not isinstance(identifier, str) or not _CVE.fullmatch(identifier):
                raise ValueError(f"invalid NVD CVE identity: {identifier!r}")
            if identifier in ids:
                raise ValueError(f"duplicate NVD CVE identity in feed: {identifier}")
            ids.add(identifier)
    return ids


def validate_api_page(value, expected_start):
    if not isinstance(value, dict) or value.get("format") != "NVD_CVE" or value.get("version") != "2.0":
        raise ValueError("unexpected NVD CVE API format/version")
    if value.get("startIndex") != expected_start:
        raise ValueError("NVD API pagination discontinuity")
    vulnerabilities = value.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("NVD API page has no vulnerabilities array")
    ids = []
    for wrapper in vulnerabilities:
        cve = wrapper.get("cve") if isinstance(wrapper, dict) else None
        identifier = cve.get("id") if isinstance(cve, dict) else None
        if not isinstance(identifier, str) or not _CVE.fullmatch(identifier):
            raise ValueError(f"invalid NVD CVE identity: {identifier!r}")
        ids.append(identifier)
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate NVD CVE identity in API page")
    return ids


class WriterLease:
    """Kernel exclusion plus visible lease/heartbeat diagnostics.

    Kernel ownership is authoritative. A fresh orphaned lease is not stolen; an
    expired one is recovered only after this coordinator acquires the kernel lock.
    """
    def __init__(self, root, attempt_id, coordinator_id, cursor):
        self.root = Path(root)
        self.attempt_id = attempt_id
        self.coordinator_id = coordinator_id
        self.cursor = cursor
        self.lock = Lock(self.root / "locks" / "writer.lock")
        self.path = self.root / "locks" / "lease.json"
        self.stop = threading.Event()
        self.thread = None
        self.heartbeat_error = None

    def _record(self, status):
        instant = utcnow()
        atomic_json(self.path, {
            "schema": LEASE_SCHEMA, "feed_id": "nvd", "status": status,
            "owner": {"host": socket.gethostname(), "process_id": os.getpid(),
                      "coordinator_id": self.coordinator_id},
            "attempt_id": self.attempt_id, "input_cursor": self.cursor,
            "heartbeat_at": timestamp(instant),
            "lease_expires_at": timestamp(instant + timedelta(seconds=LEASE_SECONDS)),
        })

    def _heartbeat(self):
        while not self.stop.wait(HEARTBEAT_SECONDS):
            try:
                self._record("RUNNING")
            except BaseException as exc:
                self.heartbeat_error = exc
                self.stop.set()
                return

    def __enter__(self):
        self.lock.__enter__()
        previous = read_json(self.path) if self.path.exists() else None
        if previous and previous.get("status") == "RUNNING":
            expires = parse_time(previous.get("lease_expires_at"))
            if expires > utcnow():
                self.lock.__exit__(None, None, None)
                raise Blocked("NVD writer lease is fresh although its process lock is absent; retry after lease expiry")
            recovery = self.root / "locks" / "recoveries" / (self.attempt_id + ".json")
            atomic_json(recovery, {"schema": "appsec-review/nvd-lease-recovery/1",
                                   "recovered_by": self.coordinator_id, "recovered_at": now(),
                                   "prior_lease": previous,
                                   "basis": "lease-expired-and-kernel-lock-acquired"})
        self._record("RUNNING")
        self.thread = threading.Thread(target=self._heartbeat, name="nvd-lease-heartbeat", daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=HEARTBEAT_SECONDS + 1)
        try:
            self._record("FAILED" if exc or self.heartbeat_error else "COMPLETE")
        finally:
            self.lock.__exit__(exc_type, exc, traceback)
        if exc is None and self.heartbeat_error:
            raise RuntimeError(f"NVD writer heartbeat failed: {self.heartbeat_error}")


def _put_blob(root, staged, suffix):
    digest = file_hash(staged)
    target = Path(root) / "blobs" / ("sha256-" + digest + suffix)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if file_hash(target) != digest:
            raise ValueError("content-addressed NVD blob hash mismatch")
        Path(staged).unlink()
    else:
        os.replace(staged, target)
    return {"path": target.relative_to(root).as_posix(), "sha256": digest,
            "size_bytes": target.stat().st_size}


def _snapshot_id(manifest):
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return "sha256-" + hashlib.sha256(payload).hexdigest()[:16]


def _publish(root, manifest):
    snapshot_id = _snapshot_id(manifest)
    manifest = {**manifest, "snapshot_id": snapshot_id}
    directory = Path(root) / "snapshots" / snapshot_id
    directory.mkdir(parents=True, exist_ok=False)
    atomic_json(directory / "manifest.json", manifest)
    manifest_sha = file_hash(directory / "manifest.json")
    pointer = {"schema": POINTER_SCHEMA, "feed_id": "nvd", "snapshot_id": snapshot_id,
               "manifest_sha256": manifest_sha, "published_at": now(),
               "cursor": manifest["cursor"]}
    # This is the sole commit point. Nothing allowed to fail the synchronization
    # runs after current.json advances.
    atomic_json(Path(root) / "current.json", pointer)
    return pointer


def bootstrap(root, staging, api_key=None, clock=utcnow, fetch=request_bytes,
              fetch_file=download, pause=time.sleep):
    started = clock()
    feeds = []
    all_ids = set()
    for year in range(FIRST_YEAR, started.year + 1):
        name = f"nvdcve-2.0-{year}"
        meta_url = f"{FEED_BASE}/{name}.meta"
        metadata = parse_meta(fetch(meta_url, api_key))
        staged = staging / (name + ".json.gz")
        fetched_size = fetch_file(f"{FEED_BASE}/{name}.json.gz", staged, api_key)
        if fetched_size != metadata["gzSize"]:
            raise ValueError(f"NVD {year} transport length mismatch")
        ids = validate_feed(staged, metadata)
        # Detect an impossible duplicate across yearly partitions as a fail-closed
        # source-shape check without retaining complete CVE bodies in memory.
        duplicate = all_ids.intersection(ids)
        if duplicate:
            raise ValueError(f"NVD CVE appears in multiple yearly feeds: {min(duplicate)}")
        all_ids.update(ids)
        feeds.append({"kind": "year", "year": year, "source_url": f"{FEED_BASE}/{name}.json.gz",
                      "metadata_url": meta_url, "source_metadata": metadata,
                      "record_count": len(ids), "blob": _put_blob(root, staged, ".json.gz")})
        if year < started.year:
            pause(1.0)
    return {"schema": SCHEMA, "feed_id": "nvd", "feed_schema": "NVD_CVE/2.0",
            "mode": "bootstrap", "parent_snapshot_id": None,
            "captured_at": now(), "coverage": {"first_year": FIRST_YEAR, "last_year": started.year},
            "cursor": timestamp(started), "record_count": len(all_ids), "layers": feeds,
            "limitations": ["Reference enrichment only; no product match, reachability, exploitability, severity, or finding is established."]}


def _api_url(start, end, index):
    query = urllib.parse.urlencode({"lastModStartDate": timestamp(start),
                                    "lastModEndDate": timestamp(end),
                                    "startIndex": index, "resultsPerPage": PAGE_SIZE})
    return API_BASE + "?" + query


def incremental(root, staging, current, api_key=None, clock=utcnow, fetch=request_bytes, pause=time.sleep):
    manifest_path = Path(root) / "snapshots" / current["snapshot_id"] / "manifest.json"
    if file_hash(manifest_path) != current["manifest_sha256"]:
        raise ValueError("current NVD manifest hash mismatch")
    parent = read_json(manifest_path)
    start = parse_time(parent["cursor"])
    finish = clock()
    if finish < start:
        raise ValueError("clock precedes the published NVD cursor")
    layers = []
    seen = set()
    window_start = start
    request_delay = 0.6 if api_key else 6.0
    while window_start < finish:
        window_end = min(window_start + WINDOW, finish)
        index = 0
        pages = []
        while True:
            url = _api_url(window_start, window_end, index)
            payload = fetch(url, api_key)
            value = json.loads(payload.decode("utf-8-sig"))
            ids = validate_api_page(value, index)
            duplicate = seen.intersection(ids)
            seen.update(ids)
            staged = staging / f"api-{len(layers):04d}-{index:09d}.json.gz"
            with staged.open("xb") as compressed:
                with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, mtime=0) as output:
                    # Preserve the exact response body. Duplicate IDs at inclusive
                    # window boundaries are accounted for in the manifest, not
                    # silently removed from source material.
                    output.write(payload)
            pages.append({"start_index": index, "record_count": len(ids),
                          "duplicate_count": len(duplicate), "source_url": url,
                          "blob": _put_blob(root, staged, ".json.gz")})
            total = value.get("totalResults")
            if not isinstance(total, int) or total < 0:
                raise ValueError("invalid NVD API totalResults")
            index += int(value.get("resultsPerPage", len(value["vulnerabilities"])))
            if index >= total:
                break
            pause(request_delay)
        layers.append({"kind": "api-last-modified", "start": timestamp(window_start),
                       "end": timestamp(window_end), "pages": pages})
        window_start = window_end
        if window_start < finish:
            pause(request_delay)
    return {"schema": SCHEMA, "feed_id": "nvd", "feed_schema": "NVD_CVE/2.0",
            "mode": "incremental", "parent_snapshot_id": current["snapshot_id"],
            "captured_at": now(), "coverage": {"last_modified_start": timestamp(start),
                                                "last_modified_end": timestamp(finish)},
            "cursor": timestamp(finish), "record_count": len(seen), "layers": layers,
            "limitations": ["Delta overlays its immutable parent; reference enrichment only and not vulnerability proof."]}


def verify(root=None):
    root = _safe_root(root or feed_root())
    current_path = root / "current.json"
    if not current_path.exists():
        raise Blocked("NVD has no published snapshot")
    current = read_json(current_path)
    if current.get("schema") != POINTER_SCHEMA:
        raise ValueError("invalid NVD current pointer schema")
    seen = set()
    snapshot_id = current["snapshot_id"]
    expected_hash = current["manifest_sha256"]
    while snapshot_id:
        if snapshot_id in seen:
            raise ValueError("NVD snapshot parent cycle")
        seen.add(snapshot_id)
        manifest_path = root / "snapshots" / snapshot_id / "manifest.json"
        if snapshot_id == current["snapshot_id"] and file_hash(manifest_path) != expected_hash:
            raise ValueError("NVD current manifest hash mismatch")
        manifest = read_json(manifest_path)
        if manifest.get("schema") != SCHEMA or manifest.get("snapshot_id") != snapshot_id:
            raise ValueError("invalid NVD snapshot manifest")
        unsigned = {key: value for key, value in manifest.items() if key != "snapshot_id"}
        if _snapshot_id(unsigned) != snapshot_id:
            raise ValueError("NVD snapshot identity mismatch")
        for layer in manifest.get("layers", []):
            blobs = [layer.get("blob")] if layer.get("blob") else [page.get("blob") for page in layer.get("pages", [])]
            for blob in blobs:
                path = beneath(root, root / blob["path"])
                if file_hash(path) != blob["sha256"] or path.stat().st_size != blob["size_bytes"]:
                    raise ValueError("NVD blob integrity mismatch")
        snapshot_id = manifest.get("parent_snapshot_id")
    return {"snapshot_id": current["snapshot_id"], "chain_length": len(seen), "cursor": current["cursor"]}


def sync(root=None, coordinator_id=None, api_key=None, clock=utcnow, fetch=request_bytes,
         fetch_file=download, pause=time.sleep):
    root = _safe_root(root or feed_root())
    coordinator_id = coordinator_id or os.environ.get("DAGSTER_RUN_ID")
    if not coordinator_id:
        raise Blocked("NVD synchronization requires a coordinator identity")
    api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY")
    attempt_id = timestamp(clock()).replace(":", "").replace(".", "-") + "-" + uuid.uuid4().hex[:8]
    staging = root / "staging" / attempt_id
    staging.mkdir(parents=True, exist_ok=False)
    current = read_json(root / "current.json") if (root / "current.json").exists() else None
    cursor = current.get("cursor") if current else None
    published = None
    try:
        with WriterLease(root, attempt_id, coordinator_id, cursor):
            atomic_json(staging / "attempt.json", {"attempt_id": attempt_id, "status": "RUNNING",
                                                    "started_at": now(), "coordinator_id": coordinator_id,
                                                    "input_cursor": cursor})
            manifest = (incremental(root, staging, current, api_key, clock, fetch, pause)
                        if current else bootstrap(root, staging, api_key, clock, fetch, fetch_file, pause))
            pointer = _publish(root, manifest)
            published = pointer
            # The last-good pointer is authoritative. Diagnostics after the commit
            # point are best effort and must never recast a published snapshot as a
            # failed refresh.
            try:
                atomic_json(root / "state.json", {**pointer, "last_attempt_id": attempt_id})
                atomic_json(staging / "attempt.json", {"attempt_id": attempt_id, "status": "COMPLETE",
                                                        "completed_at": now(), "published": pointer})
                _append_event(root, "NVD_SNAPSHOT_PUBLISHED", attempt_id=attempt_id,
                              snapshot_id=pointer["snapshot_id"], cursor=pointer["cursor"])
            except BaseException as diagnostic_error:
                print(f"NVD_POST_PUBLICATION_DIAGNOSTIC_FAILURE: {diagnostic_error}",
                      file=sys.stderr, flush=True)
            return pointer
    except BaseException as exc:
        if published is not None:
            print(f"NVD_POST_COMMIT_FAILURE: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            return published
        atomic_json(staging / "attempt.json", {"attempt_id": attempt_id, "status": "FAILED",
                                                "failed_at": now(), "error_type": type(exc).__name__,
                                                "error": str(exc), "prior_snapshot_id": current.get("snapshot_id") if current else None})
        try:
            _append_event(root, "NVD_SYNC_FAILED", attempt_id=attempt_id, error_type=type(exc).__name__)
        except BaseException as diagnostic_error:
            print(f"NVD_FAILURE_DIAGNOSTIC_FAILURE: {diagnostic_error}", file=sys.stderr, flush=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    sync_parser = subparsers.add_parser("sync")
    sync_parser.add_argument("--root", type=Path)
    sync_parser.add_argument("--coordinator-id")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--root", type=Path)
    args = parser.parse_args(argv)
    result = sync(args.root, args.coordinator_id) if args.command == "sync" else verify(args.root)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
