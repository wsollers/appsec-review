from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
from typing import Any, BinaryIO, Mapping
from urllib.parse import urljoin, urlsplit

import zstandard

from appsec_review.config.grype import GrypeSettings
from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, Mount
from appsec_review.jobs.job_third_party_data_sync.publication import HttpDownloader, publish_snapshot, verify_current
from appsec_review.storage import file_sha256
from appsec_review.storage.atomic import canonical_json


SNAPSHOT_SCHEMA = "appsec-review/grype-snapshot/2"
_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_VERSION = re.compile(r"6\.\d+\.\d+")
_FILES = frozenset({
    "6/vulnerability.db", "6/import.json", "source/latest.json",
    "validation/version.json", "validation/status.json",
})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Grype database timestamp is missing")
    instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if instant.tzinfo is None:
        raise ValueError("Grype database timestamp must include a timezone")
    return instant


def _fresh(settings: GrypeSettings, built: Any, now: datetime) -> None:
    age = (now - _time(built)).total_seconds()
    if age < -settings.max_future_seconds or age > settings.max_age_seconds:
        raise ValueError("Grype database build is stale or in the future")


def _json(path: Path, limit: int) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError(f"Grype JSON file is missing, unsafe or exceeds its bound: {path.name}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("Grype metadata must be a JSON object")
    return value


def _listing(settings: GrypeSettings, value: Mapping[str, Any], now: datetime) -> str:
    if (value.get("status") != "active" or not isinstance(value.get("schemaVersion"), str)
            or not _VERSION.fullmatch(value["schemaVersion"])
            or not isinstance(value.get("checksum"), str) or not _HASH.fullmatch(value["checksum"])):
        raise ValueError("Grype listing has no active, supported, hash-pinned database")
    _fresh(settings, value.get("built"), now)
    path = value.get("path")
    if (not isinstance(path, str) or not path or "\\" in path or "\0" in path
            or urlsplit(path).scheme or urlsplit(path).netloc or path.startswith("/")
            or urlsplit(path).query or urlsplit(path).fragment
            or any(part in ("", ".", "..") for part in path.split("/"))
            or not path.endswith(".tar.zst")):
        raise ValueError("Grype listing archive path is not a relative .tar.zst path")
    url = urljoin(settings.listing_url, path)
    settings.require_url(url)
    return url


def _source(path: Path, receipt: Mapping[str, Any], url: str, limit: int) -> dict[str, Any]:
    if (path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit
            or receipt.get("url") != url or receipt.get("size_bytes") != path.stat().st_size
            or receipt.get("sha256") != file_sha256(path)):
        raise ValueError("Grype downloaded bytes do not match their bounded source receipt")
    _time(receipt.get("retrieved_at"))
    return {**receipt, "path": str(path)}


def fetch(settings: GrypeSettings, work: Path, downloader: HttpDownloader | None = None, *,
          now: datetime | None = None) -> dict[str, Any]:
    instant = now or _now()
    client = downloader or HttpDownloader(timeout_seconds=settings.download_timeout_seconds, allow_redirects=False)
    work.mkdir(parents=True, exist_ok=True)
    listing_path = work / "latest.json"
    listing_source = _source(listing_path, client.download(
        settings.listing_url, listing_path, max_bytes=settings.max_listing_bytes,
        allowed_hosts=settings.allowed_hosts), settings.listing_url, settings.max_listing_bytes)
    listing = _json(listing_path, settings.max_listing_bytes)
    archive_url = _listing(settings, listing, instant)
    archive_path = work / "vulnerability-db.tar.zst"
    archive_source = _source(archive_path, client.download(
        archive_url, archive_path, max_bytes=settings.max_archive_bytes,
        allowed_hosts=settings.allowed_hosts), archive_url, settings.max_archive_bytes)
    if "sha256:" + archive_source["sha256"] != listing["checksum"]:
        raise ValueError("Grype archive checksum differs from its upstream listing")
    return {"schema": "appsec-review/grype-fetch/1", "listing": listing_source, "archive": archive_source}


def _fetched(settings: GrypeSettings, fetched: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    listing_source, archive_source = fetched["listing"], fetched["archive"]
    listing_path, archive_path = Path(listing_source["path"]), Path(archive_source["path"])
    _source(listing_path, listing_source, settings.listing_url, settings.max_listing_bytes)
    listing = _json(listing_path, settings.max_listing_bytes)
    url = _listing(settings, listing, now)
    _source(archive_path, archive_source, url, settings.max_archive_bytes)
    if "sha256:" + archive_source["sha256"] != listing["checksum"]:
        raise ValueError("Grype archive checksum differs from its upstream listing")
    return listing


class _ArchiveReader(io.RawIOBase):
    def __init__(self, stream: BinaryIO, settings: GrypeSettings):
        self.stream, self.limit, self.total = stream, settings.max_uncompressed_bytes, 0
        self.prefix = stream.read(18)
        parameters = zstandard.get_frame_parameters(self.prefix)
        if parameters.window_size > settings.max_zstd_window_bytes:
            raise ValueError("Grype archive exceeds its zstd window bound")
        self.decoder = zstandard.ZstdDecompressor(
            max_window_size=settings.max_zstd_window_bytes).decompressobj()
        self.pending = memoryview(b"")
        self.finished = False

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        while not self.pending and not self.finished:
            # Small compressed chunks bound each decoder return; stream_reader does not report a
            # truncated final frame. The explicit eof check must include the archive's checksum.
            chunk = self.prefix + self.stream.read(1024 - len(self.prefix))
            self.prefix = b""
            if not chunk:
                raise ValueError("Grype zstd archive is truncated")
            self.pending = memoryview(self.decoder.decompress(chunk))
            self.total += len(self.pending)
            if self.total > self.limit:
                raise ValueError("Grype archive exceeded its uncompressed byte bound")
            if self.decoder.eof:
                if self.decoder.unused_data or self.stream.read(1):
                    raise ValueError("Grype archive contains trailing compressed data")
                self.finished = True
        count = min(len(buffer), len(self.pending))
        buffer[:count] = self.pending[:count]
        self.pending = self.pending[count:]
        return count


def extract_database(settings: GrypeSettings, archive_path: Path, work: Path) -> Path:
    """Extract only the raw DB; Grype itself imports/hydrates it in the next bounded invocation."""
    work.mkdir(parents=True, exist_ok=False)
    database = work / "vulnerability.db"
    members = 0

    class DatabaseTarInfo(tarfile.TarInfo):
        def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
            nonlocal members
            members += 1
            if members > settings.max_archive_members:
                raise ValueError("Grype archive exceeded its member bound")
            # tarfile consumes extension bodies before yielding members; bound them before allocation.
            if self.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.XHDTYPE):
                raise ValueError("Grype archive contains an unsupported tar member type")
            if self.type == tarfile.XHDTYPE and not 0 < self.size <= settings.max_listing_bytes:
                raise ValueError("Grype archive tar metadata exceeds its byte bound")
            return super()._proc_member(archive)

    with archive_path.open("rb") as raw:
        with io.BufferedReader(_ArchiveReader(raw, settings)) as bounded:
            with tarfile.open(fileobj=bounded, mode="r|", tarinfo=DatabaseTarInfo) as archive:
                for member in archive:
                    if (member.name != "vulnerability.db" or not member.isfile() or member.issparse()
                            or set(member.pax_headers) - {"path", "mtime", "atime", "ctime"} or database.exists()
                            or not 0 < member.size <= settings.max_database_bytes):
                        raise ValueError("Grype archive contains an unsafe, duplicate, unexpected or oversized member")
                    source = archive.extractfile(member)
                    if source is None:
                        raise ValueError("Grype archive database is unreadable")
                    with source, database.open("xb") as output:
                        remaining = member.size
                        while remaining:
                            chunk = source.read(min(1024 * 1024, remaining))
                            if not chunk:
                                raise ValueError("Grype archive database is truncated")
                            output.write(chunk)
                            remaining -= len(chunk)
            while bounded.read(1024 * 1024):
                pass
    if not database.is_file():
        raise ValueError("Grype archive has no database")
    return database


def _command(executor: ContainerExecutor, settings: GrypeSettings, argv: tuple[str, ...],
             source: Path, scratch: Path, *, cache: Path | None = None) -> tuple[dict[str, Any], Path]:
    tool = executor.catalog.tool("tool-grype")
    environment = {
        "GRYPE_CHECK_FOR_APP_UPDATE": "false", "GRYPE_DB_AUTO_UPDATE": "false",
        "GRYPE_DB_VALIDATE_AGE": "true", "GRYPE_DB_VALIDATE_BY_HASH_ON_START": "true",
        "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": f"{settings.max_age_seconds}s",
        "GRYPE_DB_CACHE_DIR": "/database" if cache is not None else "/scratch/cache",
    }
    result = executor.execute(ExecutionRequest(
        "tool-grype", (tool.executable, *argv), source, scratch,
        extra_mounts=(Mount(cache, "/database", True),) if cache is not None else (),
        environment=environment, working_directory="/scratch",
        file_size_limit_bytes=settings.max_database_bytes, memory=settings.memory,
    ))
    if (result.exit_code != 0 or result.timed_out or result.oom_killed or result.file_size_limit_reached
            or result.stdout_truncated or result.stderr_truncated):
        raise RuntimeError(f"Grype {argv[0]} failed validation; receipt: {result.receipt_path}")
    return {"image": result.image_tag, "image_id": result.image_id, "tool_version": tool.version}, (
        executor.run_root / result.stdout_path)


def import_database(settings: GrypeSettings, fetched: Mapping[str, Any], work: Path,
                    executor: ContainerExecutor, *, now: datetime | None = None) -> dict[str, Any]:
    listing = _fetched(settings, fetched, now or _now())
    tool = executor.catalog.tool("tool-grype")
    if tool.version != settings.tool_version:
        raise ValueError("Grype catalog version differs from the configured database validator")
    image_id = executor.resolve_image(tool)
    # All three invocations must use the same observed, signature-checked image, even if its tag moves.
    pinned = replace(tool, expected_image_id=image_id, timeout_seconds=settings.run_timeout_seconds)
    executor = ContainerExecutor(replace(executor.catalog, tools={**executor.catalog.tools, "tool-grype": pinned}),
                                 executor.run_root, runner=executor.runner,
                                 image_verifier=executor._image_verifier)
    source = extract_database(settings, Path(fetched["archive"]["path"]), work / "input").parent
    tool_identity, version_path = _command(executor, settings, ("version", "-o", "json"), source, work / "version")
    version = _json(version_path, settings.max_listing_bytes)
    if version.get("version") != settings.tool_version:
        raise ValueError("Grype executable version differs from its configured release")
    _command(executor, settings, ("db", "import", "/target/vulnerability.db"), source, work / "import")
    cache = work / "import" / "cache"
    _cache_files(settings, cache)
    _, status_path = _command(executor, settings, ("db", "status", "-o", "json"),
                              source, work / "status", cache=cache)
    status = _json(status_path, settings.max_listing_bytes)
    _validated(settings, listing, status, version, _json(cache / "6/import.json", settings.max_listing_bytes),
               now or _now())
    return {"schema": "appsec-review/grype-import/1", "directory": str(cache), "tool": tool_identity,
            "version_path": str(version_path), "status_path": str(status_path),
            "files": {name: {"sha256": file_sha256(path), "size_bytes": path.stat().st_size}
                      for name, path in _cache_files(settings, cache).items()}}


def _cache_files(settings: GrypeSettings, cache: Path) -> dict[str, Path]:
    expected = {"6/vulnerability.db", "6/import.json"}
    files: dict[str, Path] = {}
    if cache.is_symlink() or not cache.is_dir():
        raise ValueError("Grype imported cache is missing or unsafe")
    # The importer sees a single raw DB, never the upstream archive. Its resulting cache is closed.
    for entry in cache.iterdir():
        if entry.name != "6" or entry.is_symlink() or not entry.is_dir():
            raise ValueError("Grype imported cache contains an unexpected entry")
        for path in entry.iterdir():
            name = f"6/{path.name}"
            limit = settings.max_database_bytes if name == "6/vulnerability.db" else settings.max_listing_bytes
            if (name not in expected or path.is_symlink() or not path.is_file()
                    or not 0 < path.stat().st_size <= limit):
                raise ValueError("Grype imported cache contains an unsafe or oversized file")
            files[name] = path
    if set(files) != expected:
        raise ValueError("Grype imported cache is incomplete")
    return files


def _validated(settings: GrypeSettings, listing: Mapping[str, Any], status: Mapping[str, Any],
               version: Mapping[str, Any], imported: Mapping[str, Any], now: datetime) -> None:
    _listing(settings, listing, now)
    if (status.get("valid") is not True or status.get("error") not in (None, "")
            or status.get("schemaVersion") != listing["schemaVersion"]
            or _time(status.get("built")) != _time(listing["built"])
            or status.get("path") != "/database/6/vulnerability.db"
            or version.get("version") != settings.tool_version
            or not isinstance(imported.get("digest"), str)
            or not re.fullmatch(r"xxh64:[0-9a-f]{16}", imported["digest"])
            or not isinstance(imported.get("client_version"), str)
            or not _VERSION.fullmatch(imported["client_version"])):
        raise ValueError("Grype database validation does not establish listing, tool and cache identity")


def publish(settings: GrypeSettings, fetched: Mapping[str, Any], imported: Mapping[str, Any], *,
            now: datetime | None = None) -> dict[str, Any]:
    listing = _fetched(settings, fetched, now or _now())
    files = _cache_files(settings, Path(imported["directory"]))
    for name, path in files.items():
        if imported["files"].get(name) != {"sha256": file_sha256(path), "size_bytes": path.stat().st_size}:
            raise ValueError("Grype imported database changed after validation")
    files.update({"source/latest.json": Path(fetched["listing"]["path"]),
                  "validation/version.json": Path(imported["version_path"]),
                  "validation/status.json": Path(imported["status_path"])})
    _validated(settings, listing, _json(files["validation/status.json"], settings.max_listing_bytes),
               _json(files["validation/version.json"], settings.max_listing_bytes),
               _json(files["6/import.json"], settings.max_listing_bytes), now or _now())
    tool = imported["tool"]
    if (tool.get("tool_version") != settings.tool_version or not isinstance(tool.get("image_id"), str)
            or not _HASH.fullmatch(tool["image_id"]) or not tool.get("image")):
        raise ValueError("Grype validator has no immutable tool identity")
    sources = {key: {k: v for k, v in fetched[key].items() if k != "path"} for key in ("listing", "archive")}
    return publish_snapshot(settings.feed_root, feed_id="grype", schema=SNAPSHOT_SCHEMA, files=files,
                            manifest_fields={"schema_version": listing["schemaVersion"], "built": listing["built"],
                                             "tool": tool, "sources": sources},
                            max_manifest_bytes=settings.max_listing_bytes * 2)


def verify(settings: GrypeSettings, *, now: datetime | None = None,
           expected_image_id: str | None = None) -> dict[str, Any]:
    """Resolve one bounded, fresh, hash-verified v6 cache; never refresh during consumption."""
    def bounded_manifest(manifest: Mapping[str, Any]) -> None:
        files = manifest.get("files")
        if manifest.get("schema") != SNAPSHOT_SCHEMA or not isinstance(files, Mapping) or set(files) != _FILES:
            raise ValueError("Grype snapshot lacks the validated publication contract")
        for name, entry in files.items():
            limit = settings.max_database_bytes if name == "6/vulnerability.db" else settings.max_listing_bytes
            if (not isinstance(entry, Mapping) or type(entry.get("size_bytes")) is not int
                    or not 0 < entry["size_bytes"] <= limit):
                raise ValueError("Grype snapshot file exceeds its consumer byte bound")

    identity = verify_current(settings.feed_root, "grype", manifest_validator=bounded_manifest,
                              max_manifest_bytes=settings.max_listing_bytes * 2)
    directory = Path(identity["directory"])
    manifest = _json(directory / "manifest.json", settings.max_listing_bytes * 2)
    if manifest.get("schema") != SNAPSHOT_SCHEMA or set(manifest["files"]) != _FILES:
        raise ValueError("Grype snapshot lacks the validated publication contract")
    unsigned = {key: value for key, value in manifest.items() if key != "snapshot_id"}
    if manifest["snapshot_id"] != "sha256-" + hashlib.sha256(canonical_json(unsigned)).hexdigest()[:24]:
        raise ValueError("Grype snapshot content identity mismatch")
    tool = manifest["tool"]
    if (tool.get("tool_version") != settings.tool_version or not isinstance(tool.get("image_id"), str)
            or not _HASH.fullmatch(tool["image_id"]) or not tool.get("image")
            or expected_image_id is not None and tool["image_id"] != expected_image_id):
        raise ValueError("Grype snapshot was not validated by the pinned consumer tool")
    listing = _json(directory / "source/latest.json", settings.max_listing_bytes)
    archive_url = _listing(settings, listing, now or _now())
    sources = manifest["sources"]
    if (sources["listing"].get("url") != settings.listing_url
            or sources["listing"].get("sha256") != manifest["files"]["source/latest.json"]["sha256"]
            or sources["listing"].get("size_bytes") != manifest["files"]["source/latest.json"]["size_bytes"]
            or sources["archive"].get("url") != archive_url
            or "sha256:" + sources["archive"].get("sha256", "") != listing["checksum"]
            or type(sources["archive"].get("size_bytes")) is not int
            or not 0 < sources["archive"]["size_bytes"] <= settings.max_archive_bytes
            or manifest.get("schema_version") != listing["schemaVersion"]
            or manifest.get("built") != listing["built"]):
        raise ValueError("Grype snapshot source provenance is incomplete")
    for source in sources.values():
        _time(source.get("retrieved_at"))
    if not 0 < (directory / "6/vulnerability.db").stat().st_size <= settings.max_database_bytes:
        raise ValueError("Grype published database exceeds its consumer byte bound")
    _validated(settings, listing, _json(directory / "validation/status.json", settings.max_listing_bytes),
               _json(directory / "validation/version.json", settings.max_listing_bytes),
               _json(directory / "6/import.json", settings.max_listing_bytes), now or _now())
    return {**identity, "tool": tool, "schema_version": manifest["schema_version"], "built": manifest["built"]}


def consumer_settings(repository_root: Path, run_root: Path) -> GrypeSettings:
    document = json.loads((run_root / "data/configuration/resolved.json").read_bytes())
    values = document["jobs"]["job_third_party_data_sync"]["steps"]["grype_db_sync"]["settings"]
    return GrypeSettings.from_mapping(repository_root, values)


def require_consumer_tool(settings: GrypeSettings, directory: Path, version: str, image_id: str) -> None:
    manifest = _json(directory / "manifest.json", settings.max_listing_bytes * 2)
    if (manifest.get("schema") != SNAPSHOT_SCHEMA or manifest["tool"].get("tool_version") != version
            or manifest["tool"].get("image_id") != image_id):
        raise RuntimeError("Grype consumer image/release differs from the database validator")
