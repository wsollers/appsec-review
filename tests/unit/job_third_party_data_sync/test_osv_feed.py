"""osv_sync: settings, the per-ecosystem fetch plan, archive indexing bounds and de-duplication,
publication, verification and package lookup, against small zip archives written by the test."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import zipfile

import pytest

from appsec_review.jobs.job_third_party_data_sync.steps.osv_sync import feed as osv


def _settings(tmp_path: Path, **overrides) -> osv.OsvSettings:
    values = {"feed_root": str(tmp_path / "feeds" / "osv"), "ecosystems": ["PyPI", "npm"]}
    values.update(overrides)
    return osv.OsvSettings.from_mapping(tmp_path, values)


def _record(identifier: str, *packages: tuple[str, str], modified: str = "2026-01-01T00:00:00Z",
            aliases: tuple[str, ...] = (), **fields) -> dict:
    return {"id": identifier, "modified": modified, "aliases": list(aliases),
            "affected": [{"package": {"ecosystem": ecosystem, "name": name}} for ecosystem, name in packages],
            **fields}


def _archive(path: Path, members: dict[str, object]) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content if isinstance(content, (str, bytes)) else json.dumps(content))
    payload = path.read_bytes()
    return {"url": "https://storage.googleapis.com/osv-vulnerabilities/x/all.zip", "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload), "etag": None, "last_modified": None, "retrieved_at": "2026-11-12T00:00:00.000Z",
            "path": str(path)}


def _fetched(tmp_path: Path, archives: dict[str, dict[str, object]]) -> dict:
    return {"schema": "appsec-review/osv-fetch/1", "ecosystems": list(archives),
            "archives": {ecosystem: _archive(tmp_path / "work" / f"{ecosystem}.zip", members)
                         for ecosystem, members in archives.items()}}


# --- settings ---------------------------------------------------------------------------------------

def test_settings_require_an_explicit_ecosystem_list_and_positive_bounds(tmp_path: Path) -> None:
    settings = _settings(tmp_path, max_records=10, max_lookup_results=3)
    assert settings.feed_root == (tmp_path / "feeds" / "osv").resolve()
    assert settings.ecosystems == ("PyPI", "npm") and settings.max_records == 10 and settings.max_lookup_results == 3
    for overrides, message in (({"ecosystems": []}, "explicit ecosystems list"),
                               ({"ecosystems": "PyPI"}, "explicit ecosystems list"),
                               ({"ecosystems": ["PyPI", "PyPI"]}, "unique safe names"),
                               ({"ecosystems": ["a/b"]}, "unique safe names"),
                               ({"ecosystems": [" "]}, "unique safe names"),
                               ({"max_records": 0}, "bounds must be positive")):
        with pytest.raises(ValueError, match=message):
            _settings(tmp_path, **overrides)


# --- fetch ----------------------------------------------------------------------------------------

def test_fetch_downloads_each_ecosystem_archive_from_the_allowlisted_host_with_the_archive_bound(tmp_path: Path) -> None:
    settings = _settings(tmp_path, ecosystems=["PyPI", "crates.io"], max_archive_bytes=1234)
    calls: list = []

    class Downloader:
        def download(self, url, destination, *, max_bytes, allowed_hosts):
            calls.append((url, destination, max_bytes, allowed_hosts))
            return {"url": url, "sha256": "0" * 64, "size_bytes": 1}

    fetched = osv.fetch(settings, tmp_path / "work", Downloader())
    assert fetched["schema"] == "appsec-review/osv-fetch/1" and fetched["ecosystems"] == ["PyPI", "crates.io"]
    assert calls == [
        ("https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip", tmp_path / "work" / "PyPI.zip",
         1234, ("storage.googleapis.com",)),
        ("https://storage.googleapis.com/osv-vulnerabilities/crates.io/all.zip", tmp_path / "work" / "crates.io.zip",
         1234, ("storage.googleapis.com",)),
    ]
    assert fetched["archives"]["crates.io"] == {"url": calls[1][0], "sha256": "0" * 64, "size_bytes": 1,
                                                "path": str(tmp_path / "work" / "crates.io.zip")}


# --- index ----------------------------------------------------------------------------------------

def test_index_stores_each_advisory_once_with_its_aliases_and_every_affected_package(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    shared = _record("GHSA-shared", ("PyPI", "shared"), ("npm", "shared"), aliases=("CVE-2026-1",))
    fetched = _fetched(tmp_path, {
        "PyPI": {"PYSEC-1.json": _record("PYSEC-1", ("PyPI", "fixture"), ("PyPI", "fixture"), aliases=("CVE-2026-2",)),
                 "GHSA-shared.json": shared, "README.md": "ignored", "nested/dir/": ""},
        "npm": {"GHSA-shared.json": shared, "weird.JSON": _record("OSV-npm", ("npm", "left-pad"))},
    })
    indexed = osv.index(settings, fetched, tmp_path / "index")
    assert indexed["schema"] == osv.INDEX_SCHEMA == "appsec-review/osv-index/2"
    assert indexed["record_count"] == 3 and indexed["max_lookup_results"] == settings.max_lookup_results
    with sqlite3.connect(indexed["database_path"]) as connection:
        assert connection.execute("SELECT COUNT(*) FROM advisory").fetchone()[0] == 3
        assert connection.execute("SELECT advisory_id, alias FROM alias ORDER BY 1").fetchall() == [
            ("GHSA-shared", "CVE-2026-1"), ("PYSEC-1", "CVE-2026-2")]
        assert connection.execute("SELECT advisory_id, ecosystem, name FROM package ORDER BY 1, 2, 3").fetchall() == [
            ("GHSA-shared", "PyPI", "shared"), ("GHSA-shared", "npm", "shared"),
            ("OSV-npm", "npm", "left-pad"), ("PYSEC-1", "PyPI", "fixture")]
        metadata = dict(connection.execute("SELECT key, value FROM metadata").fetchall())
    assert metadata == {"record_count": "3", "max_lookup_results": str(settings.max_lookup_results),
                        "index_schema": osv.INDEX_SCHEMA, "ecosystems": '["PyPI","npm"]'}


@pytest.mark.parametrize(("members", "settings_overrides", "message"), [
    ({"../escape.json": _record("X", ("PyPI", "a"))}, {}, "unsafe OSV archive member"),
    ({"/abs.json": _record("X", ("PyPI", "a"))}, {}, "unsafe OSV archive member"),
    ({"noid.json": {"affected": []}}, {}, "OSV record has no id"),
    ({"a.json": _record("A", ("PyPI", "a")), "b.json": _record("B", ("PyPI", "b"))}, {"max_records": 1},
     "record count exceeded configured bound"),
    ({"big.json": _record("A", ("PyPI", "a"), summary="x" * 4096)}, {"max_uncompressed_bytes": 100},
     "unsafe OSV archive member"),
], ids=["dotdot", "absolute", "no-id", "too-many", "member-too-large"])
def test_index_refuses_unsafe_members_malformed_records_and_exceeded_bounds(
        tmp_path: Path, members, settings_overrides, message) -> None:
    settings = _settings(tmp_path, ecosystems=["PyPI"], **settings_overrides)
    fetched = _fetched(tmp_path, {"PyPI": members})
    with pytest.raises(ValueError, match=message):
        osv.index(settings, fetched, tmp_path / "index")


def test_index_bounds_the_total_expansion_across_members(tmp_path: Path) -> None:
    settings = _settings(tmp_path, ecosystems=["PyPI"], max_uncompressed_bytes=180)
    fetched = _fetched(tmp_path, {"PyPI": {"a.json": _record("A", ("PyPI", "a")), "b.json": _record("B", ("PyPI", "b"))}})
    with pytest.raises(ValueError, match="extraction exceeded configured uncompressed byte bound"):
        osv.index(settings, fetched, tmp_path / "index")


# --- publish, verify, lookup ------------------------------------------------------------------------

def _published(tmp_path: Path, **settings_overrides) -> tuple[osv.OsvSettings, dict]:
    settings = _settings(tmp_path, ecosystems=["PyPI"], **settings_overrides)
    fetched = _fetched(tmp_path, {"PyPI": {
        "old.json": _record("PYSEC-OLD", ("PyPI", "fixture"), modified="2025-01-01T00:00:00Z", summary="old"),
        "new.json": _record("PYSEC-NEW", ("PyPI", "fixture"), modified="2026-01-01T00:00:00Z", summary="new"),
        "other.json": _record("PYSEC-OTHER", ("PyPI", "other")),
    }})
    indexed = osv.index(settings, fetched, tmp_path / "index")
    return settings, osv.publish(settings, fetched, indexed)


def test_publish_pins_sources_and_index_and_verify_reads_the_record_count_back(tmp_path: Path) -> None:
    settings, pointer = _published(tmp_path)
    assert pointer["feed_id"] == "osv" and pointer["schema"] == "appsec-review/feed-pointer/1"
    manifest = json.loads((settings.feed_root / "snapshots" / pointer["snapshot_id"] / "manifest.json")
                          .read_text(encoding="utf-8"))
    assert set(manifest["files"]) == {"sources/PyPI.zip", "index/osv.sqlite"}
    assert manifest["ecosystems"] == ["PyPI"] and manifest["record_count"] == 3
    assert "path" not in manifest["sources"]["PyPI"] and manifest["sources"]["PyPI"]["size_bytes"] > 0
    assert manifest["limitations"] == ["OSV matches are applicability leads, not findings."]
    verified = osv.verify(settings)
    assert verified["snapshot_id"] == pointer["snapshot_id"] and verified["record_count"] == 3


def test_lookup_orders_newest_first_bounds_the_limit_and_names_a_miss_as_a_gap(tmp_path: Path) -> None:
    settings, pointer = _published(tmp_path, max_lookup_results=2)
    found = osv.lookup_package(settings, "PyPI", "fixture", limit=2)
    assert found["schema"] == "appsec-review/osv-package-lookup/1" and found["snapshot_id"] == pointer["snapshot_id"]
    assert [item["advisory_id"] for item in found["items"]] == ["PYSEC-NEW", "PYSEC-OLD"]
    assert found["items"][0]["summary"] == "new" and found["gap"] is None
    assert osv.lookup_package(settings, "PyPI", "fixture", limit=1)["items"] == [found["items"][0]]
    missing = osv.lookup_package(settings, "npm", "fixture", limit=1)
    assert missing["items"] == [] and missing["gap"] == "NO_MATCH_IN_CONFIGURED_OSV_ECOSYSTEMS"
    for ecosystem, name, limit, message in (("", "x", 1, "ecosystem and name are required"),
                                            ("PyPI", " ", 1, "ecosystem and name are required"),
                                            ("PyPI", "x", 0, "limit must be between 1 and 2"),
                                            ("PyPI", "x", 3, "limit must be between 1 and 2")):
        with pytest.raises(ValueError, match=message):
            osv.lookup_package(settings, ecosystem, name, limit=limit)


def test_verify_and_lookup_refuse_a_tampered_published_index(tmp_path: Path) -> None:
    settings, pointer = _published(tmp_path)
    database = settings.feed_root / "snapshots" / pointer["snapshot_id"] / "index" / "osv.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM advisory WHERE id = 'PYSEC-OTHER'")
    with pytest.raises(ValueError, match="integrity mismatch"):
        osv.verify(settings)
    with pytest.raises(ValueError, match="integrity mismatch"):
        osv.lookup_package(settings, "PyPI", "fixture", limit=1)
