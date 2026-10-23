"""Immutable NVD CVE 2.0 publisher used by the nvd_sync step."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import gzip
import hashlib
import http.client
import io
import json
import logging
import os
from pathlib import Path
import re
import shutil
import time
from typing import Any, Protocol
import urllib.parse
import urllib.request
import urllib.error
import uuid
import zlib

from appsec_review.jobs.job_third_party_data_sync.publication import verify_snapshot_directory
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync import index as nvd_index
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.models import NvdSettings
from appsec_review.storage import FileLock, atomic_json, file_sha256
from appsec_review.storage.atomic import canonical_json


MANIFEST_SCHEMA = "appsec-review/nvd-snapshot-manifest/2"
# /1 manifests (no ``files``/``index``) remain valid parents of a /2 chain; they publish no index.
MANIFEST_SCHEMAS = ("appsec-review/nvd-snapshot-manifest/1", MANIFEST_SCHEMA)
POINTER_SCHEMA = "appsec-review/nvd-current-pointer/1"
API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
USER_AGENT = "appsec-review-nvd-publisher/2"
LIMITATION = (
    "Reference enrichment only; this snapshot does not establish product applicability, "
    "reachability, exploitability, severity, or a security finding."
)
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_LOG = logging.getLogger(__name__)


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

    def download(self, url: str, destination: Path, api_key: str | None = None, *,
                 expected_size: int | None = None) -> int: ...


class HttpNvdClient:
    def __init__(self, *, request_timeout: float = 120, download_timeout: float = 90,
                 max_download_bytes: int = 512 * 1024 * 1024,
                 max_api_response_bytes: int = 64 * 1024 * 1024,
                 max_attempts: int = 6, retry_delay_seconds: float = 5,
                 retry_max_delay_seconds: float = 60,
                 pause: Callable[[float], None] = time.sleep):
        self.request_timeout = request_timeout
        self.download_timeout = download_timeout
        self.max_download_bytes = max_download_bytes
        self.max_api_response_bytes = max_api_response_bytes
        self.max_attempts = max_attempts
        self.retry_delay_seconds = retry_delay_seconds
        self.retry_max_delay_seconds = retry_max_delay_seconds
        self.pause = pause

    @staticmethod
    def _headers(api_key: str | None) -> dict[str, str]:
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity"}
        if api_key:
            headers["apiKey"] = api_key
        return headers

    def _retry(self, error: Exception, attempt: int) -> None:
        delay = min(self.retry_delay_seconds * 2 ** (attempt - 1), self.retry_max_delay_seconds)
        if isinstance(error, urllib.error.HTTPError):
            retry_after = error.headers.get("Retry-After")
            error.close()
            if error.code not in {408, 429, 500, 502, 503, 504}:
                raise error
            if retry_after:
                try:
                    requested = (float(int(retry_after)) if retry_after.isdigit()
                                 else parsedate_to_datetime(retry_after).timestamp() - time.time())
                except (ValueError, TypeError, OverflowError):
                    _LOG.warning("NVD returned an invalid Retry-After header; using configured backoff")
                else:
                    if requested > self.retry_max_delay_seconds:
                        _LOG.error("NVD Retry-After exceeds the configured retry delay bound")
                        raise error
                    delay = max(delay, requested)
        elif not isinstance(error, (urllib.error.URLError, TimeoutError, ConnectionError,
                                    http.client.IncompleteRead, http.client.RemoteDisconnected)):
            raise error
        if attempt >= self.max_attempts:
            raise error
        _LOG.warning("NVD transport attempt %s/%s failed (%s); retrying in %ss",
                     attempt, self.max_attempts, error, delay)
        self.pause(delay)

    def get_bytes(self, url: str, api_key: str | None = None) -> bytes:
        request = urllib.request.Request(url, headers=self._headers(api_key))
        for attempt in range(1, self.max_attempts + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.request_timeout) as response:
                    if response.status != 200:
                        raise ValueError(f"NVD request returned HTTP {response.status}")
                    declared = response.headers.get("Content-Length")
                    length = int(declared) if declared is not None else None
                    if length is not None and not 0 <= length <= self.max_api_response_bytes:
                        raise ValueError("NVD response exceeds configured byte bound")
                    payload = response.read(self.max_api_response_bytes + 1)
                    if len(payload) > self.max_api_response_bytes:
                        raise ValueError("NVD response exceeded configured byte bound")
                    if length is not None and len(payload) < length:
                        raise http.client.IncompleteRead(payload, length - len(payload))
                    if length is not None and len(payload) != length:
                        raise ValueError("NVD response exceeds declared length")
                    return payload
            except (urllib.error.URLError, TimeoutError, ConnectionError,
                    http.client.IncompleteRead, http.client.RemoteDisconnected) as error:
                self._retry(error, attempt)
        raise RuntimeError("NVD request exhausted its attempt budget")

    def download(self, url: str, destination: Path, api_key: str | None = None, *,
                 expected_size: int | None = None) -> int:
        if expected_size is not None and not 0 < expected_size <= self.max_download_bytes:
            raise ValueError("NVD expected download size exceeds configured byte bound")
        if destination.exists():
            raise FileExistsError(destination)
        partial = destination.with_suffix(destination.suffix + ".partial")
        if partial.exists():
            _LOG.warning("Discarding an unverified NVD partial from an earlier invocation: %s", partial.name)
            partial.unlink()
        size = 0
        validator: tuple[str, str] | None = None
        total: int | None = None
        for attempt in range(1, self.max_attempts + 1):
            headers = self._headers(api_key)
            resume = size > 0 and validator is not None and total is not None
            if resume and validator is not None:
                headers.update({"Range": f"bytes={size}-", "If-Range": validator[1]})
            request = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=self.download_timeout) as response:
                    declared = response.headers.get("Content-Length")
                    length = int(declared) if declared is not None else None
                    if length is not None and not 0 <= length <= self.max_download_bytes:
                        raise ValueError("NVD download exceeds configured byte bound")
                    if response.status == 206:
                        match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)",
                                             response.headers.get("Content-Range", ""))
                        if not resume or validator is None or match is None:
                            raise ValueError("NVD returned an unsolicited or invalid partial response")
                        start, end, response_total = map(int, match.groups())
                        if (start != size or not start <= end < response_total
                                or response_total != total
                                or response.headers.get(validator[0]) != validator[1]
                                or (length is not None and length != end - start + 1)):
                            raise ValueError("NVD resumed response identity or byte range changed")
                        length = end - start + 1
                        mode = "ab"
                    elif response.status == 200:
                        if size:
                            _LOG.warning("NVD did not honor the range request; restarting the download")
                        if expected_size is not None and length is not None and length != expected_size:
                            raise ValueError("NVD Content-Length disagrees with feed metadata")
                        size, total = 0, expected_size if expected_size is not None else length
                        etag = response.headers.get("ETag")
                        modified = response.headers.get("Last-Modified")
                        validator = (("ETag", etag) if etag and not etag.startswith("W/")
                                     else ("Last-Modified", modified) if modified else None)
                        mode = "wb"
                    else:
                        raise ValueError(f"NVD download returned HTTP {response.status}")
                    received = 0
                    with partial.open(mode) as output:
                        for chunk in iter(lambda: response.read(64 * 1024), b""):
                            if size + len(chunk) > self.max_download_bytes:
                                raise ValueError("NVD download exceeded configured byte bound")
                            if total is not None and size + len(chunk) > total:
                                raise ValueError("NVD download exceeds expected total length")
                            if length is not None and received + len(chunk) > length:
                                raise ValueError("NVD download exceeds declared response length")
                            output.write(chunk)
                            size += len(chunk)
                            received += len(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                    if total is not None and size < total:
                        raise http.client.IncompleteRead(b"", total - size)
                    partial.replace(destination)
                    return size
            except (urllib.error.URLError, TimeoutError, ConnectionError,
                    http.client.IncompleteRead, http.client.RemoteDisconnected) as error:
                self._retry(error, attempt)
        raise RuntimeError("NVD download exhausted its attempt budget")


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
        self.client = client or HttpNvdClient(
            max_download_bytes=settings.max_download_bytes,
            max_api_response_bytes=settings.max_api_response_bytes,
            request_timeout=settings.request_timeout_seconds,
            download_timeout=settings.download_timeout_seconds,
            max_attempts=settings.max_attempts,
            retry_delay_seconds=settings.retry_delay_seconds,
            retry_max_delay_seconds=settings.retry_max_delay_seconds,
            pause=pause,
        )
        self.clock = clock
        self.pause = pause

    @property
    def root(self) -> Path:
        return self.settings.feed_root

    def _put_blob(self, staged: Path, suffix: str) -> dict[str, Any]:
        from appsec_review.storage.shared import _link, safe_path
        safe_path(self.root, staged.relative_to(self.root).as_posix())
        digest = file_sha256(staged)
        result = _link(self.root, staged, f"blobs/sha256-{digest}{suffix}", digest)
        staged.unlink()
        return result

    @staticmethod
    def _snapshot_id(manifest: Mapping[str, Any]) -> str:
        return "sha256-" + hashlib.sha256(canonical_json(manifest)).hexdigest()[:16]

    def _index(self, staging: Path, layers: list[Path], base: Path | None) -> tuple[Path, dict[str, Any]]:
        path = staging / "index" / "nvd.sqlite"
        summary = nvd_index.build_index(path, layers, base=base)
        return path, {"files": {nvd_index.LOGICAL_PATH: {"sha256": file_sha256(path),
                                                         "size_bytes": path.stat().st_size}},
                      "index": summary}

    @staticmethod
    def _metadata_paths(manifest: Mapping[str, Any]) -> list[str]:
        return [record["metadata_blob"]["path"] for layer in manifest.get("layers", [])
                for record in layer.get("pages", [layer])]

    def _chain(self, snapshot_id: str | None) -> list[dict[str, Any]]:
        """Manifests from the root bootstrap to ``snapshot_id``, oldest first."""
        from appsec_review.storage.shared import safe_path
        chain: list[dict[str, Any]] = []
        seen: set[str] = set()
        while snapshot_id:
            if snapshot_id in seen:
                raise ValueError("NVD snapshot parent cycle")
            seen.add(snapshot_id)
            manifest = json.loads(safe_path(self.root, f"snapshots/{snapshot_id}/manifest.json").read_bytes())
            chain.append(manifest)
            snapshot_id = manifest.get("parent_snapshot_id")
        return list(reversed(chain))

    def _extendable(self, current: Mapping[str, Any]) -> bool:
        """Whether an incremental layer can be indexed on top of ``current``.

        It can when the parent's index is intact, or when every manifest in its chain stored the
        metadata blobs a replay rebuilds the index from. A ``/1`` chain stored only raw feed blobs,
        so a missing ``/1`` index cannot be replayed and the feed is bootstrapped afresh instead.
        """
        from appsec_review.storage.shared import safe_path
        snapshot_id = str(current["snapshot_id"])
        parent = json.loads(safe_path(self.root, f"snapshots/{snapshot_id}/manifest.json").read_bytes())
        if self._parent_index(parent) is not None:
            return True
        return all("metadata_blob" in record for manifest in self._chain(snapshot_id)
                   for layer in manifest.get("layers", []) for record in layer.get("pages", [layer]))

    def _parent_index(self, parent: Mapping[str, Any]) -> Path | None:
        from appsec_review.storage.shared import safe_path
        entry = (parent.get("files") or {}).get(nvd_index.LOGICAL_PATH)
        path = safe_path(self.root, f"snapshots/{parent['snapshot_id']}/{nvd_index.LOGICAL_PATH}")
        if not isinstance(entry, Mapping) or not path.is_file() or file_sha256(path) != entry.get("sha256"):
            return None
        return path

    def _publish(self, manifest: dict[str, Any], index_path: Path) -> dict[str, Any]:
        from appsec_review.storage.feed_provenance import check_root, record_snapshot
        from appsec_review.storage.shared import current, safe_path
        check_root(self.root, "nvd", producing=True)
        if index_path.is_symlink() or not index_path.is_file():
            raise ValueError("NVD private index is missing or a symlink")
        if current() is not None:
            manifest = {**manifest, "publication_provenance": "required-v1"}
        snapshot_id = self._snapshot_id(manifest)
        signed = {**manifest, "snapshot_id": snapshot_id}
        directory = safe_path(self.root, f"snapshots/{snapshot_id}")
        stage = safe_path(self.root, f"staging/.snapshot-{uuid.uuid4().hex}")
        stage.mkdir(parents=True)
        try:
            (stage / "index").mkdir()
            os.link(index_path, stage / nvd_index.LOGICAL_PATH)
            atomic_json(stage / "manifest.json", signed)
            verify_snapshot_directory(stage, signed)
            directory.parent.mkdir(parents=True, exist_ok=True)
            if directory.exists():
                existing = safe_path(directory, "manifest.json")
                if existing.read_bytes() != canonical_json(signed):
                    raise ValueError("immutable NVD snapshot conflicts")
                verify_snapshot_directory(directory, signed)
            else:
                os.rename(stage, directory)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
        record_snapshot(self.root, "nvd", snapshot_id, computed=True)
        pointer = {
            "schema": POINTER_SCHEMA,
            "feed_id": "nvd",
            "snapshot_id": snapshot_id,
            "manifest_sha256": file_sha256(directory / "manifest.json"),
            "published_at": timestamp(self.clock()),
            "cursor": signed["cursor"],
        }
        atomic_json(self.root / "current.json", pointer)
        index_path.unlink()
        return pointer

    @staticmethod
    def _verify_year(path: Path, year: int, metadata: Mapping[str, Any]) -> None:
        if path.stat().st_size != metadata["gzSize"]:
            raise ValueError(f"NVD {year} transport length mismatch")
        size, digest = _gzip_properties(path)
        if size != metadata["size"] or digest.lower() != metadata["sha256"].lower():
            raise ValueError(f"NVD {year} uncompressed hash or size mismatch")

    def _year_download(self, year: int, source_url: str, metadata: Mapping[str, Any],
                       api_key: str | None) -> Path:
        if not 0 < metadata["gzSize"] <= self.settings.max_download_bytes:
            raise ValueError(f"NVD {year} download exceeds configured byte bound")
        cache = self.root / "downloads" / f"nvdcve-2.0-{year}.json.gz"
        cache.parent.mkdir(parents=True, exist_ok=True)
        if cache.exists():
            try:
                self._verify_year(cache, year, metadata)
            except (ValueError, gzip.BadGzipFile, EOFError, zlib.error) as error:
                _LOG.warning("Invalidating NVD %s cached download: %s", year, error)
                cache.unlink()
            else:
                _LOG.info("Reusing verified NVD %s download", year)
                return cache
        _LOG.info("Downloading NVD %s into the verified yearly cache", year)
        size = self.client.download(source_url, cache, api_key, expected_size=metadata["gzSize"])
        if size != metadata["gzSize"]:
            raise ValueError(f"NVD {year} transport length mismatch")
        self._verify_year(cache, year, metadata)
        return cache

    def _bootstrap(self, staging: Path, api_key: str | None) -> tuple[Path, dict[str, Any]]:
        instant = self.clock()
        layers = []
        all_ids: set[str] = set()
        for year in range(self.settings.first_year, instant.year + 1):
            name = f"nvdcve-2.0-{year}"
            metadata_url = f"{FEED_BASE}/{name}.meta"
            source_url = f"{FEED_BASE}/{name}.json.gz"
            source_metadata = parse_meta(self.client.get_bytes(metadata_url, api_key))
            raw_path = staging / f"{name}.json.gz"
            cache = self._year_download(year, source_url, source_metadata, api_key)
            shutil.copyfile(cache, raw_path)
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
        index_path, index_fields = self._index(
            staging, [self.root / layer["metadata_blob"]["path"] for layer in layers], None)
        return index_path, {
            **index_fields,
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

    def _incremental(self, staging: Path, current: Mapping[str, Any], api_key: str | None
                     ) -> tuple[Path, dict[str, Any]]:
        from appsec_review.storage.shared import safe_path
        manifest_path = safe_path(self.root, f"snapshots/{current['snapshot_id']}/manifest.json")
        if file_sha256(manifest_path) != current["manifest_sha256"]:
            raise ValueError("current NVD manifest hash mismatch")
        parent = json.loads(manifest_path.read_text(encoding="utf-8"))
        from appsec_review.storage.shared import current as current_attempt
        if current_attempt() is not None:
            from appsec_review.storage.feed_provenance import record_snapshot
            record_snapshot(self.root, "nvd", current["snapshot_id"], computed=False)
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
        new_layers = [safe_path(self.root, path) for path in self._metadata_paths({"layers": layers})]
        base = self._parent_index(parent)
        if base is None:      # a /1 parent or a missing parent index: replay the whole chain
            replay = [safe_path(self.root, path) for manifest in self._chain(str(current["snapshot_id"]))
                      for path in self._metadata_paths(manifest)]
            index_path, index_fields = self._index(staging, replay + new_layers, None)
        else:
            index_path, index_fields = self._index(staging, new_layers, base)
        return index_path, {
            **index_fields,
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
        from appsec_review.storage.feed_provenance import check_root
        from appsec_review.storage.shared import safe_path
        check_root(self.root, "nvd", producing=True)
        if not coordinator_id.strip():
            raise ValueError("coordinator identity is required")
        self.root.mkdir(parents=True, exist_ok=True)
        attempt_id = timestamp(self.clock()).replace(":", "").replace(".", "-") + "-" + uuid.uuid4().hex[:8]
        staging = safe_path(self.root, f"staging/{attempt_id}")
        staging.mkdir(parents=True, exist_ok=False)
        current_path = safe_path(self.root, "current.json")
        current = None
        attempt_path = staging / "attempt.json"
        try:
            with FileLock(self.root / "locks" / "writer.lock"):
                current = json.loads(current_path.read_text(encoding="utf-8")) if current_path.exists() else None
                atomic_json(attempt_path, {"attempt_id": attempt_id, "status": "RUNNING",
                                           "coordinator_id": coordinator_id,
                                           "input_snapshot_id": current.get("snapshot_id") if current else None})
                index_path, manifest = (self._incremental(staging, current, api_key)
                                        if current and self._extendable(current)
                                        else self._bootstrap(staging, api_key))
                pointer = self._publish(manifest, index_path)
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
        from appsec_review.jobs.job_third_party_data_sync.publication import verify_current
        verify_current(self.root, "nvd")
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
            if manifest.get("schema") not in MANIFEST_SCHEMAS or manifest.get("snapshot_id") != snapshot_id:
                raise ValueError("invalid NVD snapshot manifest")
            if snapshot_id == current["snapshot_id"] and file_sha256(manifest_path) != current["manifest_sha256"]:
                raise ValueError("NVD current manifest hash mismatch")
            unsigned = {key: value for key, value in manifest.items() if key != "snapshot_id"}
            if self._snapshot_id(unsigned) != snapshot_id:
                raise ValueError("NVD snapshot identity mismatch")
            if snapshot_id == current["snapshot_id"]:
                if nvd_index.LOGICAL_PATH not in (manifest.get("files") or {}):
                    raise ValueError("current NVD snapshot publishes no CVE index")
                verify_snapshot_directory(manifest_path.parent, manifest)
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
        head = json.loads((self.root / "snapshots" / current["snapshot_id"] / "manifest.json").read_text(encoding="utf-8"))
        return {"snapshot_id": current["snapshot_id"], "chain_length": len(seen), "cursor": current["cursor"],
                "index": {"path": nvd_index.LOGICAL_PATH, "sha256": head["files"][nvd_index.LOGICAL_PATH]["sha256"],
                          "record_count": head["index"]["record_count"]}}
