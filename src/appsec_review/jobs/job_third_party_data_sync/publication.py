from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
from typing import Any, Mapping
import urllib.parse
import urllib.request
import uuid

from appsec_review.storage import FileLock, atomic_json, file_sha256
from appsec_review.storage.atomic import canonical_json


def stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def require_beneath(root: Path, path: Path, label: str) -> Path:
    resolved_root = root.resolve()
    resolved = path.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValueError(f"{label} escapes {resolved_root}")
    return resolved


class HttpDownloader:
    def __init__(self, *, timeout_seconds: float = 300, user_agent: str = "appsec-review-feed-sync/1"):
        self.timeout_seconds = timeout_seconds
        self.user_agent = user_agent

    def download(self, url: str, destination: Path, *, max_bytes: int, allowed_hosts: tuple[str, ...]) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in allowed_hosts or parsed.username or parsed.password:
            raise ValueError(f"source URL is outside the configured HTTPS host allowlist: {url}")
        request = urllib.request.Request(url, headers={"User-Agent": self.user_agent, "Accept": "*/*"})
        digest = hashlib.sha256()
        total = 0
        destination.parent.mkdir(parents=True, exist_ok=True)
        context = ssl.create_default_context()
        with urllib.request.urlopen(request, timeout=self.timeout_seconds, context=context) as response, destination.open("xb") as output:
            status = getattr(response, "status", 200)
            if status != 200:
                raise RuntimeError(f"download returned HTTP {status}: {url}")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > max_bytes:
                raise ValueError(f"download exceeds configured byte bound: {url}")
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"download exceeded configured byte bound: {url}")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
            return {
                "url": url,
                "sha256": digest.hexdigest(),
                "size_bytes": total,
                "etag": response.headers.get("ETag"),
                "last_modified": response.headers.get("Last-Modified"),
                "retrieved_at": stamp(),
            }


def publish_snapshot(
    root: Path,
    *,
    feed_id: str,
    schema: str,
    files: Mapping[str, Path],
    manifest_fields: Mapping[str, Any],
) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    entries: dict[str, dict[str, Any]] = {}
    for logical, source in sorted(files.items()):
        logical_path = Path(logical)
        if logical_path.is_absolute() or ".." in logical_path.parts or not source.is_file() or source.is_symlink():
            raise ValueError(f"unsafe publication file: {logical}")
        entries[logical_path.as_posix()] = {
            "sha256": file_sha256(source),
            "size_bytes": source.stat().st_size,
        }
    unsigned = {
        "schema": schema,
        "feed_id": feed_id,
        **dict(manifest_fields),
        "files": entries,
    }
    snapshot_id = "sha256-" + hashlib.sha256(canonical_json(unsigned)).hexdigest()[:24]
    manifest = {**unsigned, "snapshot_id": snapshot_id}
    with FileLock(root / "locks" / "writer.lock"):
        stage = root / "staging" / (snapshot_id + "-" + uuid.uuid4().hex[:8])
        stage.mkdir(parents=True, exist_ok=False)
        try:
            for logical, source in sorted(files.items()):
                destination = require_beneath(stage, stage / logical, "snapshot destination")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            atomic_json(stage / "manifest.json", manifest)
            verify_snapshot_directory(stage, manifest)
            destination = root / "snapshots" / snapshot_id
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                existing = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
                verify_snapshot_directory(destination, existing)
                if existing != manifest:
                    raise ValueError("snapshot identity collision")
                shutil.rmtree(stage)
            else:
                os.replace(stage, destination)
            pointer = {
                "schema": "appsec-review/feed-pointer/1",
                "feed_id": feed_id,
                "snapshot_id": snapshot_id,
                "manifest_sha256": file_sha256(destination / "manifest.json"),
                "published_at": stamp(),
            }
            atomic_json(root / "current.json", pointer)
            return pointer
        except BaseException:
            if stage.exists():
                shutil.rmtree(stage)
            raise


def verify_snapshot_directory(directory: Path, manifest: Mapping[str, Any]) -> dict[str, Any]:
    if manifest.get("snapshot_id") is None or not isinstance(manifest.get("files"), Mapping):
        raise ValueError("invalid snapshot manifest")
    checked = 0
    for logical, entry in manifest["files"].items():
        path = require_beneath(directory, directory / logical, "manifest file")
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"published file is missing: {logical}")
        if path.stat().st_size != entry["size_bytes"] or file_sha256(path) != entry["sha256"]:
            raise ValueError(f"published file integrity mismatch: {logical}")
        checked += 1
    return {"snapshot_id": manifest["snapshot_id"], "verified_files": checked}


def verify_current(root: Path, expected_feed: str) -> dict[str, Any]:
    pointer = json.loads((root / "current.json").read_text(encoding="utf-8"))
    if pointer.get("schema") != "appsec-review/feed-pointer/1" or pointer.get("feed_id") != expected_feed:
        raise ValueError(f"invalid {expected_feed} current pointer")
    directory = require_beneath(root, root / "snapshots" / pointer["snapshot_id"], "snapshot")
    manifest_path = directory / "manifest.json"
    if file_sha256(manifest_path) != pointer["manifest_sha256"]:
        raise ValueError(f"{expected_feed} manifest hash mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("snapshot_id") != pointer["snapshot_id"] or manifest.get("feed_id") != expected_feed:
        raise ValueError(f"{expected_feed} snapshot identity mismatch")
    verified = verify_snapshot_directory(directory, manifest)
    return {**verified, "manifest_sha256": pointer["manifest_sha256"], "directory": str(directory)}


def publish_metadata(metadata_root: Path, kind: str, identity: str, value: Mapping[str, Any]) -> Path:
    if not identity or not identity.replace("_", "a").replace("-", "a").isalnum():
        raise ValueError("metadata identity is invalid")
    path = metadata_root / kind / f"{identity}.json"
    require_beneath(metadata_root, path, "metadata path")
    atomic_json(path, dict(value))
    return path
