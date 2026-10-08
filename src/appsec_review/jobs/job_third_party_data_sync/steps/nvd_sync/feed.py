"""Immutable NVD CVE 2.0 publisher used by the nvd_sync step."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Protocol
import urllib.parse
import urllib.request
import uuid

from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.models import NvdSettings
from appsec_review.storage import FileLock, atomic_json, file_sha256
from appsec_review.storage.atomic import canonical_json


MANIFEST_SCHEMA = "appsec-review/nvd-snapshot-manifest/1"
POINTER_SCHEMA = "appsec-review/nvd-current-pointer/1"
API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
USER_AGENT = "appsec-review-nvd-publisher/2"
LIMITATION = (
    "Reference enrichment only; this snapshot does not establish product applicability, "
    "reachability, exploitability, severity, or a security finding."
)
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include an offset")
    return parsed.astimezone(timezone.utc)


class NvdClient(Protocol):
    def get_bytes(self, url: str, api_key: str | None = None) -> bytes: ...

    def download(self, url: str, destination: Path, api_key: str | None = None) -> int: ...


class HttpNvdClient:
    def __init__(self, *, request_timeout: float = 120, download_timeout: float = 300,
                 max_download_bytes: int = 512 * 1024 * 1024,
                 max_api_response_bytes: int = 64 * 1024 * 1024):
        self.request_timeout = request_timeout
        self.download_timeout = download_timeout
        self.max_download_bytes = max_download_bytes
        self.max_api_response_bytes = max_api_response_bytes

    @staticmethod
    def _headers(api_key: str | None) -> dict[str, str]:
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if api_key:
            headers["apiKey"] = api_key
        return headers

    def get_bytes(self, url: str, api_key: str | None = None) -> bytes:
        request = urllib.request.Request(url, headers=self._headers(api_key))
        with urllib.request.urlopen(request, timeout=self.request_timeout) as response:
            if getattr(response, "status", 200) != 200:
                raise RuntimeError(f"NVD request returned HTTP {response.status}")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > self.max_api_response_bytes:
                raise ValueError("NVD response exceeds configured byte bound")
            payload = response.read(self.max_api_response_bytes + 1)
            if len(payload) > self.max_api_response_bytes:
                raise ValueError("NVD response exceeded configured byte bound")
            return payload

    def download(self, url: str, destination: Path, api_key: str | None = None) -> int:
        request = urllib.request.Request(url, headers=self._headers(api_key))
        size = 0
        with urllib.request.urlopen(request, timeout=self.download_timeout) as response, destination.open("xb") as output:
            if getattr(response, "status", 200) != 200:
                raise RuntimeError(f"NVD request returned HTTP {response.status}")
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                output.write(chunk)
                size += len(chunk)
                if size > self.max_download_bytes:
                    raise ValueError("NVD download exceeded configured byte bound")
            output.flush()
            os.fsync(output.fileno())
        return size


def parse_meta(payload: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for line in payload.decode("utf-8-sig").splitlines():
        key, separator, value = line.partition(":")
        if separator:
            result[key] = value.strip()
    required = {"lastModifiedDate", "size", "gzSize", "sha256"}
    if not required.issubset(result):
        raise ValueError(f"incomplete NVD metadata: missing {sorted(required - result.keys())}")
    if not re.fullmatch(r"[0-9A-Fa-f]{64}", result["sha256"]):
        raise ValueError("invalid NVD metadata sha256")
    result["size"] = int(result["size"])
    result["gzSize"] = int(result["gzSize"])
    parse_time(result["lastModifiedDate"])
    return result


def iter_vulnerabilities(stream: Any) -> Iterator[dict[str, Any]]:
    """Incrementally decode the top-level vulnerabilities array."""
    decoder = json.JSONDecoder()
    text = io.TextIOWrapper(stream, encoding="utf-8-sig")
    buffer = ""
    marker = re.compile(r'"vulnerabilities"\s*:\s*\[')
    while True:
        chunk = text.read(1024 * 1024)
        buffer += chunk
        match = marker.search(buffer)
        if match:
            buffer = buffer[match.end():]
            break
        if not chunk:
            raise ValueError("NVD JSON has no vulnerabilities array")
        if len(buffer) > 4 * 1024 * 1024:
            buffer = buffer[-1024:]
    while True:
        buffer = buffer.lstrip()
        if buffer.startswith("]"):
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


def _cve_id(wrapper: Mapping[str, Any]) -> str:
    cve = wrapper.get("cve")
    identifier = cve.get("id") if isinstance(cve, Mapping) else None
    if not isinstance(identifier, str) or not _CVE.fullmatch(identifier):
        raise ValueError(f"invalid NVD CVE identity: {identifier!r}")
    return identifier


def _metadata(wrapper: Mapping[str, Any]) -> dict[str, Any]:
    cve = wrapper["cve"]
    descriptions = cve.get("descriptions", [])
    english = next(
        (item.get("value") for item in descriptions if isinstance(item, Mapping) and item.get("lang") == "en"),
        None,
    )
    weaknesses = sorted({
        item.get("value")
        for group in cve.get("weaknesses", []) if isinstance(group, Mapping)
        for item in group.get("description", []) if isinstance(item, Mapping) and isinstance(item.get("value"), str)
    })
    metrics = []
    for family, values in cve.get("metrics", {}).items() if isinstance(cve.get("metrics"), Mapping) else ():
        if not isinstance(values, list):
            continue
        for value in values:
            data = value.get("cvssData") if isinstance(value, Mapping) else None
            if isinstance(data, Mapping):
                metrics.append({
                    "family": family,
                    "version": data.get("version"),
                    "vector": data.get("vectorString"),
                    "base_score": data.get("baseScore"),
                    "base_severity": data.get("baseSeverity"),
                })
    return {
        "id": cve["id"],
        "source_identifier": cve.get("sourceIdentifier"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "description_en": english,
        "weaknesses": weaknesses,
        "metrics": metrics,
        "raw_sha256": hashlib.sha256(canonical_json(wrapper)).hexdigest(),
    }


def _gzip_properties(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with gzip.open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def _write_metadata(wrappers: Iterator[dict[str, Any]], destination: Path) -> tuple[set[str], int]:
    identifiers: set[str] = set()
    count = 0
    with destination.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            for wrapper in wrappers:
                identifier = _cve_id(wrapper)
                if identifier in identifiers:
                    raise ValueError(f"duplicate NVD CVE identity: {identifier}")
                identifiers.add(identifier)
                compressed.write(canonical_json(_metadata(wrapper)))
                count += 1
    return identifiers, count


class NvdPublisher:
    def __init__(
        self,
        settings: NvdSettings,
        *,
        client: NvdClient | None = None,
        clock: Callable[[], datetime] = utcnow,
        pause: Callable[[float], None] = time.sleep,
    ):
        self.settings = settings
        self.client = client or HttpNvdClient(max_download_bytes=settings.max_download_bytes,
                                               max_api_response_bytes=settings.max_api_response_bytes)
        self.clock = clock
        self.pause = pause

    @property
    def root(self) -> Path:
        return self.settings.feed_root

    def _put_blob(self, staged: Path, suffix: str) -> dict[str, Any]:
        digest = file_sha256(staged)
        target = self.root / "blobs" / f"sha256-{digest}{suffix}"
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if file_sha256(target) != digest:
                raise ValueError("content-addressed NVD blob hash mismatch")
            staged.unlink()
        else:
            os.replace(staged, target)
        return {"path": target.relative_to(self.root).as_posix(), "sha256": digest,
                "size_bytes": target.stat().st_size}

    @staticmethod
    def _snapshot_id(manifest: Mapping[str, Any]) -> str:
        return "sha256-" + hashlib.sha256(canonical_json(manifest)).hexdigest()[:16]

    def _publish(self, manifest: dict[str, Any]) -> dict[str, Any]:
        snapshot_id = self._snapshot_id(manifest)
        signed = {**manifest, "snapshot_id": snapshot_id}
        directory = self.root / "snapshots" / snapshot_id
        directory.mkdir(parents=True, exist_ok=False)
        atomic_json(directory / "manifest.json", signed)
        pointer = {
            "schema": POINTER_SCHEMA,
            "feed_id": "nvd",
            "snapshot_id": snapshot_id,
            "manifest_sha256": file_sha256(directory / "manifest.json"),
            "published_at": timestamp(self.clock()),
            "cursor": signed["cursor"],
        }
        atomic_json(self.root / "current.json", pointer)
        return pointer

    def _bootstrap(self, staging: Path, api_key: str | None) -> dict[str, Any]:
        instant = self.clock()
        layers = []
        all_ids: set[str] = set()
        for year in range(self.settings.first_year, instant.year + 1):
            name = f"nvdcve-2.0-{year}"
            metadata_url = f"{FEED_BASE}/{name}.meta"
            source_url = f"{FEED_BASE}/{name}.json.gz"
            source_metadata = parse_meta(self.client.get_bytes(metadata_url, api_key))
            raw_path = staging / f"{name}.json.gz"
            if self.client.download(source_url, raw_path, api_key) != source_metadata["gzSize"]:
                raise ValueError(f"NVD {year} transport length mismatch")
            if raw_path.stat().st_size > self.settings.max_download_bytes:
                raise ValueError(f"NVD {year} download exceeded configured byte bound")
            size, digest = _gzip_properties(raw_path)
            if size != source_metadata["size"] or digest.lower() != source_metadata["sha256"].lower():
                raise ValueError(f"NVD {year} uncompressed hash or size mismatch")
            metadata_path = staging / f"{name}.metadata.jsonl.gz"
            with gzip.open(raw_path, "rb") as stream:
                identifiers, count = _write_metadata(iter_vulnerabilities(stream), metadata_path)
            duplicate = all_ids.intersection(identifiers)
            if duplicate:
                raise ValueError(f"NVD CVE appears in multiple yearly feeds: {min(duplicate)}")
            all_ids.update(identifiers)
            layers.append({
                "kind": "year",
                "year": year,
                "source_url": source_url,
                "metadata_url": metadata_url,
                "source_metadata": source_metadata,
                "record_count": count,
                "raw_blob": self._put_blob(raw_path, ".json.gz"),
                "metadata_blob": self._put_blob(metadata_path, ".metadata.jsonl.gz"),
            })
        return {
            "schema": MANIFEST_SCHEMA,
            "feed_id": "nvd",
            "feed_schema": "NVD_CVE/2.0",
            "mode": "bootstrap",
            "parent_snapshot_id": None,
            "captured_at": timestamp(instant),
            "coverage": {"first_year": self.settings.first_year, "last_year": instant.year},
            "cursor": timestamp(instant),
            "record_count": len(all_ids),
            "layers": layers,
            "limitations": [LIMITATION],
        }

    def _api_url(self, start: datetime, end: datetime, index: int) -> str:
        query = urllib.parse.urlencode({
            "lastModStartDate": timestamp(start),
            "lastModEndDate": timestamp(end),
            "startIndex": index,
            "resultsPerPage": self.settings.page_size,
        })
        return f"{API_BASE}?{query}"

    def _incremental(self, staging: Path, current: Mapping[str, Any], api_key: str | None) -> dict[str, Any]:
        manifest_path = self.root / "snapshots" / str(current["snapshot_id"]) / "manifest.json"
        if file_sha256(manifest_path) != current["manifest_sha256"]:
            raise ValueError("current NVD manifest hash mismatch")
        parent = json.loads(manifest_path.read_text(encoding="utf-8"))
        start = parse_time(parent["cursor"])
        finish = self.clock()
        if finish < start:
            raise ValueError("clock precedes the published NVD cursor")
        delay = (self.settings.request_delay_with_key_seconds if api_key
                 else self.settings.request_delay_without_key_seconds)
        layers = []
        seen: set[str] = set()
        window_start = start
        while window_start < finish:
            window_end = min(window_start + timedelta(days=self.settings.max_window_days), finish)
            index = 0
            pages = []
            while True:
                url = self._api_url(window_start, window_end, index)
                payload = self.client.get_bytes(url, api_key)
                value = json.loads(payload.decode("utf-8-sig"))
                if value.get("format") != "NVD_CVE" or value.get("version") != "2.0":
                    raise ValueError("unexpected NVD API format/version")
                if value.get("startIndex") != index or not isinstance(value.get("vulnerabilities"), list):
                    raise ValueError("NVD API pagination discontinuity")
                raw_path = staging / f"api-{len(layers):04d}-{index:09d}.json.gz"
                with raw_path.open("xb") as raw:
                    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as output:
                        output.write(payload)
                metadata_path = staging / f"api-{len(layers):04d}-{index:09d}.metadata.jsonl.gz"
                identifiers, count = _write_metadata(iter(value["vulnerabilities"]), metadata_path)
                duplicate_count = len(seen.intersection(identifiers))
                seen.update(identifiers)
                pages.append({
                    "start_index": index,
                    "record_count": count,
                    "duplicate_count": duplicate_count,
                    "source_url": url,
                    "raw_blob": self._put_blob(raw_path, ".json.gz"),
                    "metadata_blob": self._put_blob(metadata_path, ".metadata.jsonl.gz"),
                })
                total = value.get("totalResults")
                returned = value.get("resultsPerPage")
                if not isinstance(total, int) or total < 0 or not isinstance(returned, int) or returned < 0:
                    raise ValueError("invalid NVD API pagination values")
                index += returned
                if index >= total:
                    break
                if returned == 0:
                    raise ValueError("NVD API returned an empty nonterminal page")
                self.pause(delay)
            layers.append({"kind": "api-last-modified", "start": timestamp(window_start),
                           "end": timestamp(window_end), "pages": pages})
            window_start = window_end
            if window_start < finish:
                self.pause(delay)
        return {
            "schema": MANIFEST_SCHEMA,
            "feed_id": "nvd",
            "feed_schema": "NVD_CVE/2.0",
            "mode": "incremental",
            "parent_snapshot_id": current["snapshot_id"],
            "captured_at": timestamp(finish),
            "coverage": {"last_modified_start": timestamp(start), "last_modified_end": timestamp(finish)},
            "cursor": timestamp(finish),
            "record_count": len(seen),
            "layers": layers,
            "limitations": [LIMITATION],
        }

    def sync(self, coordinator_id: str, api_key: str | None = None) -> dict[str, Any]:
        if not coordinator_id.strip():
            raise ValueError("coordinator identity is required")
        self.root.mkdir(parents=True, exist_ok=True)
        attempt_id = timestamp(self.clock()).replace(":", "").replace(".", "-") + "-" + uuid.uuid4().hex[:8]
        staging = self.root / "staging" / attempt_id
        staging.mkdir(parents=True, exist_ok=False)
        current_path = self.root / "current.json"
        current = None
        attempt_path = staging / "attempt.json"
        try:
            with FileLock(self.root / "locks" / "writer.lock"):
                current = json.loads(current_path.read_text(encoding="utf-8")) if current_path.exists() else None
                atomic_json(attempt_path, {"attempt_id": attempt_id, "status": "RUNNING",
                                           "coordinator_id": coordinator_id,
                                           "input_snapshot_id": current.get("snapshot_id") if current else None})
                manifest = (self._incremental(staging, current, api_key) if current
                            else self._bootstrap(staging, api_key))
                pointer = self._publish(manifest)
                atomic_json(attempt_path, {"attempt_id": attempt_id, "status": "COMPLETE",
                                           "coordinator_id": coordinator_id, "published": pointer})
                return pointer
        except BaseException as exc:
            atomic_json(attempt_path, {"attempt_id": attempt_id, "status": "FAILED",
                                       "coordinator_id": coordinator_id,
                                       "error": {"type": type(exc).__name__, "message": str(exc)},
                                       "prior_snapshot_id": current.get("snapshot_id") if current else None})
            raise

    def verify(self) -> dict[str, Any]:
        current_path = self.root / "current.json"
        if not current_path.exists():
            raise FileNotFoundError("NVD has no published snapshot")
        current = json.loads(current_path.read_text(encoding="utf-8"))
        if current.get("schema") != POINTER_SCHEMA:
            raise ValueError("invalid NVD current pointer schema")
        seen: set[str] = set()
        snapshot_id = current["snapshot_id"]
        while snapshot_id:
            if snapshot_id in seen:
                raise ValueError("NVD snapshot parent cycle")
            seen.add(snapshot_id)
            manifest_path = self.root / "snapshots" / snapshot_id / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("snapshot_id") != snapshot_id:
                raise ValueError("invalid NVD snapshot manifest")
            if snapshot_id == current["snapshot_id"] and file_sha256(manifest_path) != current["manifest_sha256"]:
                raise ValueError("NVD current manifest hash mismatch")
            unsigned = {key: value for key, value in manifest.items() if key != "snapshot_id"}
            if self._snapshot_id(unsigned) != snapshot_id:
                raise ValueError("NVD snapshot identity mismatch")
            for layer in manifest.get("layers", []):
                records = layer.get("pages", [layer])
                for record in records:
                    for field in ("raw_blob", "metadata_blob"):
                        blob = record[field]
                        path = (self.root / blob["path"]).resolve()
                        if self.root.resolve() not in path.parents:
                            raise ValueError("NVD blob path escapes feed root")
                        if file_sha256(path) != blob["sha256"] or path.stat().st_size != blob["size_bytes"]:
                            raise ValueError("NVD blob integrity mismatch")
            snapshot_id = manifest.get("parent_snapshot_id")
        return {"snapshot_id": current["snapshot_id"], "chain_length": len(seen), "cursor": current["cursor"]}
