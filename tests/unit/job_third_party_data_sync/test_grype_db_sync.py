from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import hashlib
import io
import json
from pathlib import Path
import tarfile
from types import SimpleNamespace
import urllib.request

import pytest
import zstandard

from appsec_review.config import load_config
from appsec_review.config.grype import GrypeSettings
from appsec_review.jobs.job_third_party_data_sync import build_job
from appsec_review.jobs.job_third_party_data_sync.steps.grype_db_sync import feed
from appsec_review.jobs.job_third_party_data_sync.publication import HttpDownloader
from appsec_review.runtime.contracts import DispatchClass, TargetAccess
from appsec_review.storage import file_sha256
from tests.fixtures.grype import BUILT, Docker, Downloader, IMAGE_ID, NOW, ROOT, archive_bytes, executor


def settings(tmp_path: Path, **values) -> GrypeSettings:
    return GrypeSettings.from_mapping(tmp_path, values)


def prepared(tmp_path: Path, *, docker: Docker | None = None):
    config = settings(tmp_path)
    fetched = feed.fetch(config, tmp_path / "fetch", Downloader(), now=NOW)
    imported = feed.import_database(config, fetched, tmp_path / "import", executor(tmp_path, docker), now=NOW)
    return config, fetched, imported


def test_supported_import_publishes_bounded_fresh_cache_and_pinned_provenance(tmp_path):
    docker = Docker()
    config, fetched, imported = prepared(tmp_path, docker=docker)
    pointer = feed.publish(config, fetched, imported, now=NOW)
    identity = feed.verify(config, now=NOW, expected_image_id=IMAGE_ID)
    directory = Path(identity["directory"])
    manifest = json.loads((directory / "manifest.json").read_bytes())
    assert manifest["schema"] == feed.SNAPSHOT_SCHEMA
    assert identity["snapshot_id"] == pointer["snapshot_id"]
    assert identity["tool"]["image_id"] == IMAGE_ID
    assert identity["built"] == BUILT and identity["schema_version"] == "6.1.3"
    assert manifest["sources"]["archive"]["sha256"] == fetched["archive"]["sha256"]
    for name, entry in manifest["files"].items():
        assert file_sha256(directory / name) == entry["sha256"]
        assert (directory / name).stat().st_size == entry["size_bytes"]
    assert set(manifest["files"]) == feed._FILES
    runs = [argv for argv, _ in docker.calls if argv[:2] == ("docker", "run")]
    assert len(runs) == 3
    assert all("--env" in argv and "GRYPE_DB_AUTO_UPDATE=false" in argv for argv in runs)
    assert all("GRYPE_DB_VALIDATE_AGE=true" in argv and "GRYPE_DB_VALIDATE_BY_HASH_ON_START=true" in argv
               for argv in runs)
    assert all(argv[argv.index("--ulimit") + 1] == f"fsize={config.max_database_bytes}:{config.max_database_bytes}"
               for argv in runs)
    assert feed.publish(config, fetched, imported, now=NOW)["snapshot_id"] == pointer["snapshot_id"]
    feed.require_consumer_tool(config, directory, "0.119.0", IMAGE_ID)
    with pytest.raises(RuntimeError, match="consumer image/release"):
        feed.require_consumer_tool(config, directory, "0.118.0", IMAGE_ID)


@pytest.mark.parametrize("values", [
    {"unknown": 1}, {"max_archive_bytes": True}, {"max_age_seconds": 0},
    {"max_archive_members": "8"}, {"schema_major": 5}, {"schema_major": True},
    {"feed_root": "../escape"}, {"feed_root": ""}, {"allowed_hosts": "grype.anchore.io"},
    {"allowed_hosts": ["grype.anchore.io", "grype.anchore.io"]}, {"tool_version": "latest"},
    {"listing_url": "http://grype.anchore.io/latest.json"},
    {"listing_url": "https://other.invalid/latest.json"}, {"memory": "unlimited"},
], ids=["unknown", "bool-bound", "age", "member-type", "schema", "schema-bool", "path", "empty-path",
        "hosts-type", "duplicate-hosts", "release", "http", "host", "memory"])
def test_typed_settings_reject_unknown_invalid_and_unbounded_values(tmp_path, values):
    with pytest.raises(ValueError):
        settings(tmp_path, **values)


@pytest.mark.parametrize("overrides", [
    {"status": "deprecated"}, {"schemaVersion": "5.0.0"}, {"checksum": "sha256:bad"},
    {"built": "2026-10-01T00:00:00Z"}, {"built": "2026-10-09T00:00:00Z"},
    {"built": "2026-10-07T12:00:00"}, {"path": "../escape.tar.zst"},
    {"path": "https://other.invalid/db.tar.zst"}, {"path": "/db.tar.zst"},
    {"path": "db.tar.zst?foo=bar"}, {"checksum": "sha256:" + "0" * 64},
], ids=["inactive", "schema", "checksum", "stale", "future", "naive-time", "traversal", "foreign-url",
        "absolute", "query", "hash-mismatch"])
def test_fetch_fails_without_provenance_or_freshness(tmp_path, overrides):
    config = settings(tmp_path)
    with pytest.raises(ValueError):
        feed.fetch(config, tmp_path / "fetch", Downloader(**overrides), now=NOW)
    assert not (config.feed_root / "current.json").exists()


def test_fetch_enforces_both_download_limits(tmp_path):
    for name in ("max_listing_bytes", "max_archive_bytes"):
        config = settings(tmp_path, **{name: 1})
        with pytest.raises(ValueError, match="byte bound"):
            feed.fetch(config, tmp_path / name, Downloader(), now=NOW)


@pytest.mark.parametrize("case", ["exact", "declared-large", "stream-large", "truncated", "redirect"])
def test_http_transport_enforces_bounds_and_refuses_redirects(tmp_path, monkeypatch, case):
    class Response(io.BytesIO):
        status = 200
        headers = {} if case == "stream-large" else {"Content-Length": "7" if case == "declared-large" else "6"}

    def opener(*handlers):
        def open_request(request, timeout):
            assert timeout == 3
            if case == "redirect":
                handler = next(item for item in handlers if isinstance(item, urllib.request.HTTPRedirectHandler))
                return handler.redirect_request(request, None, 302, "redirect", {}, "https://other.invalid/db")
            return Response(b"abc" if case == "truncated" else b"abcdefg" if case == "stream-large" else b"abcdef")
        return SimpleNamespace(open=open_request)
    monkeypatch.setattr(urllib.request, "build_opener", opener)
    client = HttpDownloader(timeout_seconds=3, allow_redirects=False)
    if case == "exact":
        receipt = client.download("https://grype.anchore.io/db", tmp_path / "db", max_bytes=6,
                                  allowed_hosts=("grype.anchore.io",))
        assert receipt["size_bytes"] == 6 and receipt["sha256"] == hashlib.sha256(b"abcdef").hexdigest()
    else:
        with pytest.raises(ValueError):
            client.download("https://grype.anchore.io/db", tmp_path / "db", max_bytes=6,
                            allowed_hosts=("grype.anchore.io",))


@pytest.mark.parametrize("kind", ["traversal", "absolute", "symlink", "hardlink", "device", "sparse",
                                  "unexpected", "duplicate", "oversized", "pax-size"])
def test_extraction_refuses_unsafe_archive_members(tmp_path, kind):
    member = tarfile.TarInfo("vulnerability.db")
    payload = b"db"
    config = settings(tmp_path)
    if kind == "traversal":
        member.name = "../escape"
    elif kind == "absolute":
        member.name = "/escape"
    elif kind in ("symlink", "hardlink", "device", "sparse"):
        member.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE,
                       "device": tarfile.CHRTYPE, "sparse": tarfile.GNUTYPE_SPARSE}[kind]
        member.linkname = "../escape"
    elif kind == "unexpected":
        member.name = "other.db"
    elif kind == "oversized":
        config = replace(config, max_database_bytes=1)
    elif kind == "pax-size":
        member.pax_headers = {"size": "1000000"}
    members = [(member, payload)] * (2 if kind == "duplicate" else 1)
    archive = tmp_path / "db.tar.zst"
    archive.write_bytes(archive_bytes(members))
    with pytest.raises((ValueError, tarfile.TarError)):
        feed.extract_database(config, archive, tmp_path / "output")
    assert not (tmp_path / "escape").exists()


def test_extraction_bounds_expansion_and_accepts_exact_threshold(tmp_path):
    archive = tmp_path / "db.tar.zst"
    archive.write_bytes(archive_bytes())
    expanded = zstandard.ZstdDecompressor().decompress(archive.read_bytes())
    assert feed.extract_database(settings(tmp_path, max_uncompressed_bytes=len(expanded)), archive,
                                 tmp_path / "exact").read_bytes() == b"fixture database"
    with pytest.raises(ValueError, match="uncompressed byte bound"):
        feed.extract_database(settings(tmp_path, max_uncompressed_bytes=len(expanded) - 1),
                              archive, tmp_path / "over")


def test_pax_timestamp_is_supported_but_metadata_and_members_are_bounded(tmp_path):
    member = tarfile.TarInfo("vulnerability.db")
    member.pax_headers = {"mtime": "1791374400.123"}
    archive = tmp_path / "db.tar.zst"
    archive.write_bytes(archive_bytes([(member, b"db")]))
    assert feed.extract_database(settings(tmp_path), archive, tmp_path / "good").read_bytes() == b"db"
    with pytest.raises(ValueError, match="member bound"):
        feed.extract_database(settings(tmp_path, max_archive_members=1), archive, tmp_path / "members")
    member.pax_headers = {"mtime": "1" * 66000}
    archive.write_bytes(archive_bytes([(member, b"db")]))
    with pytest.raises(ValueError, match="metadata exceeds"):
        feed.extract_database(settings(tmp_path), archive, tmp_path / "bad")


@pytest.mark.parametrize("kind", ["truncated-checksum", "trailing-frame", "window"])
def test_zstd_integrity_and_window_are_enforced(tmp_path, kind):
    payload = archive_bytes()
    config = settings(tmp_path)
    if kind == "truncated-checksum":
        payload = payload[:-1]
    elif kind == "trailing-frame":
        payload += archive_bytes()
    else:
        config = replace(config, max_zstd_window_bytes=1024)
    archive = tmp_path / "db.tar.zst"
    archive.write_bytes(payload)
    with pytest.raises((ValueError, zstandard.ZstdError)):
        feed.extract_database(config, archive, tmp_path / "output")


@pytest.mark.parametrize("docker", [
    Docker(version="0.118.0"), Docker(status={"valid": False}), Docker(status={"schemaVersion": "6.0.0"}),
    Docker(status={"built": "2026-10-06T00:00:00Z"}), Docker(status={"error": "invalid checksum"}),
    Docker(status={"path": "/elsewhere/vulnerability.db"}), Docker(fail="db import"), Docker(fail="db status"),
], ids=["tool-version", "invalid", "schema", "built", "error", "path", "import-failed", "status-failed"])
def test_import_requires_pinned_grype_validation(tmp_path, docker):
    with pytest.raises((ValueError, RuntimeError)):
        prepared(tmp_path, docker=docker)
    assert not (settings(tmp_path).feed_root / "current.json").exists()


def test_moved_image_pin_fails_before_import(tmp_path):
    class Moved(Docker):
        def __call__(self, argv, timeout):
            result = super().__call__(argv, timeout)
            if argv[:3] == ("docker", "image", "inspect") and len(self.calls) > 1:
                return replace(result, stdout=("sha256:" + "c" * 64).encode())
            return result
    docker = Moved()
    with pytest.raises(ValueError, match="digest mismatch"):
        prepared(tmp_path, docker=docker)
    assert not any(argv[:2] == ("docker", "run") for argv, _ in docker.calls)


@pytest.mark.parametrize("changed", ["archive", "listing", "database", "import", "status", "stale", "metadata"])
def test_failed_refresh_preserves_last_known_good_pointer(tmp_path, changed):
    config, fetched, imported = prepared(tmp_path)
    pointer = feed.publish(config, fetched, imported, now=NOW)
    prior = (config.feed_root / "current.json").read_bytes()
    paths = {"archive": Path(fetched["archive"]["path"]), "listing": Path(fetched["listing"]["path"]),
             "database": Path(imported["directory"]) / "6/vulnerability.db",
             "import": Path(imported["directory"]) / "6/import.json", "status": Path(imported["status_path"])}
    if changed == "metadata":
        fetched["archive"]["etag"] = "a" * (2 * config.max_listing_bytes)
    elif changed != "stale":
        paths[changed].write_bytes(b"changed")
    with pytest.raises((ValueError, json.JSONDecodeError)):
        feed.publish(config, fetched, imported, now=NOW + timedelta(days=6) if changed == "stale" else NOW)
    assert (config.feed_root / "current.json").read_bytes() == prior
    assert feed.verify(config, now=NOW)["snapshot_id"] == pointer["snapshot_id"]


def test_consumer_refuses_stale_mismatched_or_tampered_cache(tmp_path):
    config, fetched, imported = prepared(tmp_path)
    feed.publish(config, fetched, imported, now=NOW)
    with pytest.raises(ValueError, match="stale"):
        feed.verify(config, now=NOW + timedelta(days=6))
    with pytest.raises(ValueError, match="pinned consumer tool"):
        feed.verify(config, now=NOW, expected_image_id="sha256:" + "c" * 64)
    identity = feed.verify(config, now=NOW)
    (Path(identity["directory"]) / "6/vulnerability.db").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="integrity mismatch"):
        feed.verify(config, now=NOW)


def test_consumer_rejects_legacy_and_unbounded_manifest_before_hashing_payload(tmp_path):
    config, fetched, imported = prepared(tmp_path)
    pointer = feed.publish(config, fetched, imported, now=NOW)
    manifest_path = config.feed_root / "snapshots" / pointer["snapshot_id"] / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["files"]["6/vulnerability.db"]["size_bytes"] = config.max_database_bytes + 1
    manifest_path.write_text(json.dumps(manifest))
    pointer["manifest_sha256"] = file_sha256(manifest_path)
    (config.feed_root / "current.json").write_text(json.dumps(pointer))
    with pytest.raises(ValueError, match="consumer byte bound"):
        feed.verify(config, now=NOW)
    manifest["schema"] = "appsec-review/grype-snapshot/1"
    manifest_path.write_text(json.dumps(manifest))
    pointer["manifest_sha256"] = file_sha256(manifest_path)
    (config.feed_root / "current.json").write_text(json.dumps(pointer))
    with pytest.raises(ValueError, match="validated publication contract"):
        feed.verify(config, now=NOW)


def test_grype_is_an_independent_maintenance_branch_and_scanning_stays_disabled(tmp_path):
    config = load_config(ROOT / "appsec-review.toml")
    job = build_job()
    from appsec_review.runtime.registry import builtin_registry
    registry = builtin_registry()
    registry.require_matches(config.jobs, surface="grype-unit")
    assert tuple(unit.unit_id for unit in registry.build(job.job_id).units) == tuple(unit.unit_id for unit in job.units)
    assert job.contract.dispatch == DispatchClass.MAINTENANCE
    assert job.contract.target_access == TargetAccess.NONE and job.always_execute
    assert job.strict_gaps and config.tools.disable_grype
    units = {unit.unit_id: unit for unit in job.units}
    assert units["grype_db_sync.fetch"].dependencies == ()
    assert units["grype_db_sync.import"].dependencies == ("grype_db_sync.fetch",)
    assert units["grype_db_sync.publish"].dependencies == ("grype_db_sync.import",)
    assert tuple(config.job(job.job_id).step("grype_db_sync").tasks) == ("fetch", "import", "publish")
    text = (ROOT / "appsec-review.toml").read_text().replace("max_age_seconds = 432000", "max_age_seconds = false")
    path = tmp_path / "appsec-review.toml"
    path.write_text(text)
    with pytest.raises(ValueError, match="max_age_seconds"):
        load_config(path)
    text = (ROOT / "appsec-review.toml").read_text()
    beginning = text.index("[jobs.job_third_party_data_sync.steps.grype_db_sync.settings]")
    end = text.index("[jobs.job_third_party_data_sync.steps.grype_db_sync.tasks.fetch]", beginning)
    path.write_text(text[:beginning] + text[end:])
    defaulted = load_config(path)
    frozen = json.loads(defaulted.resolved_json)["jobs"][job.job_id]["steps"]["grype_db_sync"]["settings"]
    assert frozen == GrypeSettings.from_mapping(tmp_path, {}).view(tmp_path)


@pytest.mark.parametrize("valid", [True, False], ids=["fresh", "stale"])
def test_scanner_consumers_use_the_validated_offline_cache_or_a_named_gap(tmp_path, monkeypatch, valid):
    from appsec_review.jobs.job_artifact_security_analysis import scanners
    from appsec_review.jobs.job_evidence_collection.job import _prerequisites

    config, fetched, imported = prepared(tmp_path)
    feed.publish(config, fetched, imported, now=NOW)
    run = tmp_path / "run"
    document_path = run / "data/configuration/resolved.json"
    document_path.parent.mkdir(parents=True)
    document_path.write_bytes(load_config(ROOT / "appsec-review.toml").resolved_json)
    monkeypatch.setattr(feed, "_now", lambda: NOW if valid else NOW + timedelta(days=6))
    selected = SimpleNamespace(applicable=True)
    unit = SimpleNamespace(job=SimpleNamespace(repository_root=tmp_path, run_root=run),
                           output=lambda _: {"terminal_status": "SUCCEEDED", "scanner_output": "syft.json"})
    _, mounts, environment, gap = _prerequisites(unit, SimpleNamespace(tool_id="tool-grype"), selected)
    catalog = executor(run).catalog
    monkeypatch.setattr(scanners, "load_catalog", lambda _: catalog)
    runner = scanners.ContainerScannerRunner(tmp_path, run, run / "scratch")
    runner.executor = executor(run)
    identity = runner.identity("grype", {})
    if valid:
        assert gap is None and "unavailable" not in identity
        assert environment["GRYPE_DB_CACHE_DIR"] == "/database"
        assert all(mount.read_only for mount in mounts)
        assert identity["rules"]["snapshot_id"] == feed.verify(config, now=NOW)["snapshot_id"]
    else:
        assert "Grype database snapshot is unavailable" in gap and mounts == () and environment == {}
        assert "unavailable" in identity
