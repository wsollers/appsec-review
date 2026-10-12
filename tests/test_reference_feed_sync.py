"""KEV and EPSS sync steps, the NVD CVE index, and per-run feed pinning (offline fixture feeds only)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import gzip
import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review.jobs.job_third_party_data_sync.publication import verify_current
from appsec_review.jobs.job_third_party_data_sync.steps.epss_sync import feed as epss_feed
from appsec_review.jobs.job_third_party_data_sync.steps.kev_sync import feed as kev_feed
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync import index as nvd_index
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.feed import NvdPublisher
from appsec_review.storage import file_sha256
from tests.fixtures.reference_feeds import (
    EPSS_URL, FIXED_NOW, KEV_URL, epss_bytes, epss_settings, kev_document, kev_entry, kev_settings, nvd_settings,
    nvd_vulnerability, pin_feeds, publish_epss, publish_kev, publish_nvd, set_published_at,
)

V31 = {"cvssMetricV31": [{"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                          "baseScore": 7.5, "baseSeverity": "HIGH"}]}


class Downloader:
    """Serves one local payload; records the requested URL and host allowlist."""

    def __init__(self, payload: bytes):
        self.payload = payload
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def download(self, url, destination, *, max_bytes, allowed_hosts):
        self.calls.append((url, tuple(allowed_hosts)))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.payload)
        import hashlib
        return {"url": url, "sha256": hashlib.sha256(self.payload).hexdigest(), "size_bytes": len(self.payload),
                "etag": None, "last_modified": None, "retrieved_at": "2026-10-12T00:00:00.000Z"}


def _rows(path: Path, sql: str) -> list[tuple]:
    connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    try:
        return connection.execute(sql).fetchall()
    finally:
        connection.close()


# --- KEV ---------------------------------------------------------------------------------------------


def _kev_cycle(tmp_path: Path, document: dict, **overrides) -> dict:
    settings = kev_settings(tmp_path / "kev", **overrides)
    payload = json.dumps(document).encode()
    fetched = kev_feed.fetch(settings, tmp_path / "work", Downloader(payload))
    normalized = kev_feed.normalize(settings, fetched, tmp_path / "work")
    kev_feed.publish(settings, fetched, normalized)
    return kev_feed.verify(settings)


def test_kev_valid_catalog_publishes_a_hash_pinned_sorted_index(tmp_path: Path) -> None:
    document = kev_document([kev_entry("CVE-2026-0003"), kev_entry("CVE-2026-0001", dueDate=None)])
    identity = _kev_cycle(tmp_path, document)
    assert identity["record_count"] == 2
    directory = Path(identity["directory"])
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["catalog_version"] == "2026.10.10" and manifest["date_released"] == "2026-10-10"
    assert manifest["files"]["index/kev.sqlite"]["sha256"] == file_sha256(directory / "index" / "kev.sqlite")
    rows = _rows(directory / "index" / "kev.sqlite",
                 "SELECT cve_id, vendor_project, product, vulnerability_name, date_added, due_date, "
                 "known_ransomware_use, catalog_version FROM kev")
    assert [row[0] for row in rows] == ["CVE-2026-0001", "CVE-2026-0003"]
    assert rows[0][5] is None and rows[1][5] == "2026-09-22" and rows[1][6] == "Known"
    # Republishing identical content yields the identical content-addressed snapshot.
    again = _kev_cycle(tmp_path / "second", document)
    assert again["snapshot_id"] == identity["snapshot_id"]


@pytest.mark.parametrize("document, message", [
    ({"catalogVersion": "1", "dateReleased": "2026-10-10", "vulnerabilities": "nope"}, "vulnerabilities"),
    (kev_document([kev_entry("CVE-26-1")]), "invalid cveID"),
    (kev_document([kev_entry("CVE-2026-0001"), kev_entry("CVE-2026-0001")]), "repeats"),
    (kev_document([kev_entry("CVE-2026-0001", dateAdded="yesterday")]), "dateAdded"),
    ({**kev_document([kev_entry("CVE-2026-0001")]), "count": 5}, "declared count"),
])
def test_kev_malformed_catalogs_fail_normalization_and_publish_nothing(tmp_path: Path, document, message) -> None:
    with pytest.raises(ValueError, match=message):
        _kev_cycle(tmp_path, document)
    assert not (tmp_path / "kev" / "current.json").exists()


def test_kev_oversize_hash_mismatch_and_host_allowlist(tmp_path: Path) -> None:
    document = kev_document([kev_entry("CVE-2026-0001")])
    with pytest.raises(ValueError, match="byte bound"):
        _kev_cycle(tmp_path / "a", document, max_source_bytes=16)
    with pytest.raises(ValueError, match="hash mismatch"):
        _kev_cycle(tmp_path / "b", document, sha256="0" * 64)
    with pytest.raises(ValueError, match="record count"):
        _kev_cycle(tmp_path / "c", kev_document([kev_entry("CVE-2026-0001"), kev_entry("CVE-2026-0002")]),
                   max_records=1)
    with pytest.raises(ValueError, match="allowed host"):
        kev_settings(tmp_path, url="https://evil.example/kev.json")
    downloader = Downloader(json.dumps(document).encode())
    kev_feed.fetch(kev_settings(tmp_path / "d"), tmp_path / "d" / "work", downloader)
    assert downloader.calls == [(KEV_URL, ("www.cisa.gov",))]


# --- EPSS --------------------------------------------------------------------------------------------


def _epss_cycle(tmp_path: Path, payload: bytes, **overrides) -> dict:
    settings = epss_settings(tmp_path / "epss", **overrides)
    fetched = epss_feed.fetch(settings, tmp_path / "work", Downloader(payload))
    normalized = epss_feed.normalize(settings, fetched, tmp_path / "work")
    epss_feed.publish(settings, fetched, normalized)
    return epss_feed.verify(settings)


def test_epss_valid_scores_publish_index_with_model_and_score_date(tmp_path: Path) -> None:
    identity = _epss_cycle(tmp_path, epss_bytes([("CVE-2026-0002", 0.01, 0.2), ("CVE-2026-0001", 0.42, 0.97)]))
    directory = Path(identity["directory"])
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["model_version"] == "v2025.03.14" and manifest["score_date"] == "2026-10-11T12:55:00Z"
    rows = _rows(directory / "index" / "epss.sqlite", "SELECT * FROM epss")
    assert rows == [("CVE-2026-0001", 0.42, 0.97, "2026-10-11", "v2025.03.14"),
                    ("CVE-2026-0002", 0.01, 0.2, "2026-10-11", "v2025.03.14")]


@pytest.mark.parametrize("payload, message", [
    (gzip.compress(b"cve,epss,percentile\nCVE-2026-0001,0.1,0.2\n", mtime=0), "comment line"),
    (gzip.compress(b"#model_version:v1,score_date:2026-10-11\ncve,score\nCVE-2026-0001,0.1\n", mtime=0), "header"),
    (epss_bytes([("CVE-2026-0001", 1.5, 0.2)]), "outside"),
    (epss_bytes([("CVE-2026-0001", 0.1, 0.2), ("CVE-2026-0001", 0.1, 0.2)]), "repeats"),
    (b"not a gzip stream", "gzip"),
])
def test_epss_malformed_files_fail_normalization(tmp_path: Path, payload: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _epss_cycle(tmp_path, payload)
    assert not (tmp_path / "epss" / "current.json").exists()


def test_epss_oversize_and_hash_mismatch(tmp_path: Path) -> None:
    payload = epss_bytes([(f"CVE-2026-{number:04d}", 0.1, 0.5) for number in range(1, 200)])
    with pytest.raises(ValueError, match="byte bound"):
        _epss_cycle(tmp_path / "a", payload, max_source_bytes=32)
    with pytest.raises(ValueError, match="uncompressed byte bound"):
        _epss_cycle(tmp_path / "b", payload, max_uncompressed_bytes=64)
    with pytest.raises(ValueError, match="hash mismatch"):
        _epss_cycle(tmp_path / "c", payload, sha256="f" * 64)
    with pytest.raises(ValueError, match="allowed host"):
        epss_settings(tmp_path, url="http://epss.empiricalsecurity.com/x.csv.gz")
    downloader = Downloader(payload)
    epss_feed.fetch(epss_settings(tmp_path / "d"), tmp_path / "d" / "work", downloader)
    assert downloader.calls == [(EPSS_URL, ("epss.empiricalsecurity.com",))]


# --- NVD index ----------------------------------------------------------------------------------------


def test_nvd_snapshot_publishes_a_deterministic_hash_pinned_cve_index(tmp_path: Path) -> None:
    vulnerabilities = [nvd_vulnerability("CVE-2026-0002", status="Rejected"),
                       nvd_vulnerability("CVE-2026-0001", cwes=["CWE-400"], metrics=V31)]
    roots = [publish_nvd(tmp_path / name / "nvd", vulnerabilities) for name in ("a", "b")]
    hashes = []
    for root in roots:
        identity = verify_current(root, "nvd")
        manifest = json.loads((Path(identity["directory"]) / "manifest.json").read_text())
        assert manifest["schema"] == "appsec-review/nvd-snapshot-manifest/2"
        assert manifest["index"]["record_count"] == 2 and manifest["index"]["schema"] == nvd_index.INDEX_SCHEMA
        hashes.append(manifest["files"]["index/nvd.sqlite"]["sha256"])
        assert NvdPublisher(nvd_settings(root)).verify()["index"]["sha256"] == hashes[-1]
    assert hashes[0] == hashes[1]
    path = Path(verify_current(roots[0], "nvd")["directory"]) / "index" / "nvd.sqlite"
    with sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True) as connection:
        record = nvd_index.lookup(connection, "CVE-2026-0001")
        assert nvd_index.lookup(connection, "CVE-2099-0001") is None
        assert nvd_index.lookup(connection, "CVE-2026-0002")["status"] == "Rejected"
    assert record["weaknesses"] == ["CWE-400"] and record["description_en"] == "Fixture vulnerability"
    assert record["cvss"] == [{"family": "cvssMetricV31", "version": "3.1", "base_score": 7.5,
                               "base_severity": "HIGH",
                               "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]
    assert len(record["raw_sha256"]) == 64
    assert _rows(path, "SELECT cve_id, cwe_id FROM weakness") == [("CVE-2026-0001", "CWE-400")]
    assert _rows(path, "SELECT cve_id, base_score FROM cvss") == [("CVE-2026-0001", 7.5)]


def test_nvd_incremental_index_applies_later_layers_by_last_modified(tmp_path: Path) -> None:
    base = [nvd_vulnerability("CVE-2026-0001", modified="2026-01-01T00:00:00.000", metrics=V31),
            nvd_vulnerability("CVE-2026-0002", modified="2026-01-01T00:00:00.000")]
    update = [nvd_vulnerability("CVE-2026-0001", modified="2026-10-12T00:30:00.000", status="Rejected"),
              nvd_vulnerability("CVE-2026-0003", modified="2026-10-12T00:30:00.000")]
    root = publish_nvd(tmp_path / "nvd", base, updates=update)
    identity = verify_current(root, "nvd")
    manifest = json.loads((Path(identity["directory"]) / "manifest.json").read_text())
    assert manifest["mode"] == "incremental" and manifest["index"]["incremental"] is True
    path = Path(identity["directory"]) / "index" / "nvd.sqlite"
    assert _rows(path, "SELECT cve_id, status FROM cve") == [
        ("CVE-2026-0001", "Rejected"), ("CVE-2026-0002", "Analyzed"), ("CVE-2026-0003", "Analyzed")]
    assert _rows(path, "SELECT COUNT(*) FROM cvss") == [(0,)]
    # Replaying every layer from scratch gives the same bytes as the incremental build.
    chain = NvdPublisher(nvd_settings(root))._chain(identity["snapshot_id"])
    layers = [root / item for manifest_item in chain for item in NvdPublisher._metadata_paths(manifest_item)]
    replay = tmp_path / "replay" / "nvd.sqlite"
    nvd_index.build_index(replay, layers)
    assert file_sha256(replay) == file_sha256(path)


def test_nvd_index_never_lets_an_older_record_override_a_newer_one(tmp_path: Path) -> None:
    def layer(name: str, records: list[dict]) -> Path:
        path = tmp_path / f"{name}.metadata.jsonl.gz"
        with gzip.open(path, "wt", encoding="utf-8") as stream:
            for item in records:
                stream.write(json.dumps(item) + "\n")
        return path

    first = layer("first", [{"id": "CVE-2026-0001", "status": "Modified", "last_modified": "2026-05-01T00:00:00.000",
                             "weaknesses": [], "metrics": []}])
    second = layer("second", [{"id": "CVE-2026-0001", "status": "Analyzed", "last_modified": "2026-01-01T00:00:00.000",
                               "weaknesses": [], "metrics": []}])
    third = layer("third", [{"id": "CVE-2026-0001", "status": "Rejected", "last_modified": "2026-05-01T00:00:00.000",
                             "weaknesses": [], "metrics": []}])
    out = tmp_path / "out.sqlite"
    nvd_index.build_index(out, [first, second])
    assert _rows(out, "SELECT status FROM cve") == [("Modified",)]
    nvd_index.build_index(out, [first, second, third])             # equal timestamps: the later layer wins
    assert _rows(out, "SELECT status FROM cve") == [("Rejected",)]


def test_tampered_nvd_index_fails_verification_and_pinning(tmp_path: Path) -> None:
    root = publish_nvd(tmp_path / "nvd", [nvd_vulnerability("CVE-2026-0001")])
    pins = pin_feeds(tmp_path, {"nvd": root})
    assert pins["nvd"]["status"] == "pinned" and "index/nvd.sqlite" in pins["nvd"]["files"]
    path = Path(pins["nvd"]["directory"]) / "index" / "nvd.sqlite"
    with path.open("ab") as handle:
        handle.write(b"x")
    with pytest.raises(ValueError, match="integrity"):
        NvdPublisher(nvd_settings(root)).verify()
    assert pin_feeds(tmp_path, {"nvd": root})["nvd"]["status"] == "unavailable"


# --- per-run pinning and freshness -----------------------------------------------------------------------


def test_feed_pins_expose_kev_and_epss_and_mark_stale_by_per_feed_bound(tmp_path: Path) -> None:
    kev = publish_kev(tmp_path / "kev", kev_document([kev_entry("CVE-2026-0001")]), tmp_path / "w1")
    epss = publish_epss(tmp_path / "epss", epss_bytes([("CVE-2026-0001", 0.4, 0.9)]), tmp_path / "w2")
    old = (FIXED_NOW - timedelta(days=5)).isoformat().replace("+00:00", "Z")
    set_published_at(kev, old)
    set_published_at(epss, old)
    pins = pin_feeds(tmp_path, {"kev": kev, "epss": epss}, overrides={"kev": 7, "epss": 3})
    assert pins["kev"]["status"] == "pinned" and pins["kev"]["stale"] is False and pins["kev"]["max_age_days"] == 7
    assert pins["epss"]["status"] == "pinned" and pins["epss"]["stale"] is True
    assert set(pins["kev"]["files"]) == {"index/kev.sqlite", "sources/known_exploited_vulnerabilities.json"}
    assert pins["osv"]["status"] == "unavailable" and pins["nvd"]["status"] == "unavailable"


def test_a_manifest_without_its_index_file_is_not_pinned(tmp_path: Path) -> None:
    kev = publish_kev(tmp_path / "kev", kev_document([kev_entry("CVE-2026-0001")]), tmp_path / "w")
    (Path(verify_current(kev, "kev")["directory"]) / "index" / "kev.sqlite").unlink()
    pins = pin_feeds(tmp_path, {"kev": kev})
    assert pins["kev"]["status"] == "unavailable" and "no verified current snapshot" in pins["kev"]["reason"]


def test_feed_pins_now_parameter_controls_staleness(tmp_path: Path) -> None:
    kev = publish_kev(tmp_path / "kev", kev_document([kev_entry("CVE-2026-0001")]), tmp_path / "w")
    set_published_at(kev, "2026-10-12T00:00:00.000Z")
    later = datetime(2026, 11, 30, tzinfo=timezone.utc)
    assert pin_feeds(tmp_path, {"kev": kev}, now=later, overrides={"kev": 7})["kev"]["stale"] is True
