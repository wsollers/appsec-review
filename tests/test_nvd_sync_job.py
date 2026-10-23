from __future__ import annotations

from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.feed import NvdPublisher, parse_meta, timestamp
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.models import NvdSettings
from tests.capture_fakes import build_capture_toml


def vulnerability(identifier: str, modified: str = "2026-01-01T00:00:00.000") -> dict:
    return {
        "cve": {
            "id": identifier,
            "sourceIdentifier": "security@example.test",
            "published": "2026-01-01T00:00:00.000",
            "lastModified": modified,
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Fixture vulnerability"}],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N",
                                                   "baseScore": 7.5, "baseSeverity": "HIGH"}}]
            },
        }
    }


class FakeClient:
    def __init__(self, raw_document: bytes):
        self.raw_document = raw_document
        self.compressed = gzip.compress(raw_document, mtime=0)
        self.fail = False

    def get_bytes(self, url: str, api_key: str | None = None) -> bytes:
        if self.fail:
            raise OSError("network unavailable")
        if url.endswith(".meta"):
            return (
                "lastModifiedDate:2026-10-08T00:00:00.000Z\n"
                f"size:{len(self.raw_document)}\n"
                f"gzSize:{len(self.compressed)}\n"
                f"sha256:{hashlib.sha256(self.raw_document).hexdigest()}\n"
            ).encode()
        page = {
            "format": "NVD_CVE",
            "version": "2.0",
            "startIndex": 0,
            "resultsPerPage": 1,
            "totalResults": 1,
            "vulnerabilities": [vulnerability("CVE-2026-1001", "2026-10-08T01:00:00.000")],
        }
        return json.dumps(page, separators=(",", ":")).encode()

    def download(self, url: str, destination: Path, api_key: str | None = None, *,
                 expected_size: int | None = None) -> int:
        destination.write_bytes(self.compressed)
        return len(self.compressed)


def write_config(root: Path) -> Path:
    path = root / "appsec-review.toml"
    path.write_text(
        """
[runtime]
runs_dir = "runs"
data_dir = "data"

[jobs.job_third_party_data_sync]
name = "third_party_data_sync"
workers = 1

[jobs.job_third_party_data_sync.schedule]
enabled = true
cron = "0 0 * * *"
timezone = "UTC"

[jobs.job_third_party_data_sync.steps.nvd_sync]
workers = 1

[jobs.job_third_party_data_sync.steps.nvd_sync.settings]
feed_root = "data/feeds/nvd"
api_key_env = "TEST_NVD_API_KEY"
first_year = 2026
page_size = 2000
max_window_days = 119
request_delay_with_key_seconds = 0
request_delay_without_key_seconds = 0

[jobs.job_third_party_data_sync.steps.nvd_sync.tasks.fetch]
workers = 1

[jobs.job_third_party_data_sync.steps.nvd_sync.tasks.process]
workers = 1

[jobs.job_third_party_data_sync.steps.nvd_sync.tasks.build]
workers = 1
""".strip() + "\n\n" + build_capture_toml(),
        encoding="utf-8",
    )
    return path


def test_bootstrap_then_incremental_job_publish_metadata_and_receipts(tmp_path: Path) -> None:
    raw = json.dumps({
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": [vulnerability("CVE-2026-1000")],
    }, separators=(",", ":")).encode()
    client = FakeClient(raw)
    instant = datetime(2026, 10, 8, tzinfo=timezone.utc)
    config = load_config(write_config(tmp_path))
    settings = NvdSettings.from_mapping(tmp_path, config.job("job_third_party_data_sync").step("nvd_sync").settings)
    publisher = NvdPublisher(settings, client=client, clock=lambda: instant, pause=lambda _: None)
    first = publisher.sync("first")
    feed_root = tmp_path / "data" / "feeds" / "nvd"
    current = json.loads((feed_root / "current.json").read_text(encoding="utf-8"))
    first_snapshot = current["snapshot_id"]
    manifest = json.loads((feed_root / "snapshots" / first_snapshot / "manifest.json").read_text(encoding="utf-8"))
    metadata_blob = feed_root / manifest["layers"][0]["metadata_blob"]["path"]
    with gzip.open(metadata_blob, "rt", encoding="utf-8") as stream:
        metadata = json.loads(stream.readline())

    assert first["snapshot_id"] == first_snapshot
    assert metadata["id"] == "CVE-2026-1000"
    assert metadata["weaknesses"] == ["CWE-79"]
    assert metadata["metrics"][0]["base_score"] == 7.5

    later = instant + timedelta(hours=2)
    publisher.clock = lambda: later
    publisher.sync("second")
    current = json.loads((feed_root / "current.json").read_text(encoding="utf-8"))
    receipt = publisher.verify()
    assert current["snapshot_id"] != first_snapshot
    assert receipt["chain_length"] == 2
    assert receipt["cursor"] == timestamp(later)


def test_failed_refresh_preserves_last_good_pointer(tmp_path: Path) -> None:
    raw = json.dumps({"format": "NVD_CVE", "version": "2.0",
                      "vulnerabilities": [vulnerability("CVE-2026-1000")]}, separators=(",", ":")).encode()
    client = FakeClient(raw)
    instant = datetime(2026, 10, 8, tzinfo=timezone.utc)
    settings = NvdSettings.from_mapping(tmp_path, {
        "feed_root": "data/feeds/nvd", "api_key_env": "TEST_NVD_API_KEY", "first_year": 2026,
        "page_size": 2000, "max_window_days": 119,
        "request_delay_with_key_seconds": 0, "request_delay_without_key_seconds": 0,
    })
    publisher = NvdPublisher(settings, client=client, clock=lambda: instant, pause=lambda _: None)
    first = publisher.sync("first")
    client.fail = True
    publisher.clock = lambda: instant + timedelta(hours=2)

    with pytest.raises(OSError, match="network unavailable"):
        publisher.sync("failed")

    current = json.loads((settings.feed_root / "current.json").read_text(encoding="utf-8"))
    assert current["snapshot_id"] == first["snapshot_id"]
    failed = [json.loads(path.read_text(encoding="utf-8"))
              for path in (settings.feed_root / "staging").glob("*/attempt.json")]
    assert any(attempt["status"] == "FAILED" for attempt in failed)


def test_tampered_blob_fails_verification(tmp_path: Path) -> None:
    raw = json.dumps({"format": "NVD_CVE", "version": "2.0",
                      "vulnerabilities": [vulnerability("CVE-2026-1000")]}, separators=(",", ":")).encode()
    client = FakeClient(raw)
    instant = datetime(2026, 10, 8, tzinfo=timezone.utc)
    settings = NvdSettings.from_mapping(tmp_path, {
        "feed_root": "data/feeds/nvd", "api_key_env": "TEST_NVD_API_KEY", "first_year": 2026,
        "page_size": 2000, "max_window_days": 119,
        "request_delay_with_key_seconds": 0, "request_delay_without_key_seconds": 0,
    })
    publisher = NvdPublisher(settings, client=client, clock=lambda: instant, pause=lambda _: None)
    publisher.sync("first")
    blob = next((settings.feed_root / "blobs").iterdir())
    blob.write_bytes(blob.read_bytes() + b"tamper")

    with pytest.raises(ValueError, match="blob integrity"):
        publisher.verify()


def test_a_v1_parent_without_an_index_is_bootstrapped_not_replayed(tmp_path: Path) -> None:
    raw = json.dumps({"format": "NVD_CVE", "version": "2.0",
                      "vulnerabilities": [vulnerability("CVE-2026-1000")]}, separators=(",", ":")).encode()
    instant = datetime(2026, 10, 8, tzinfo=timezone.utc)
    config = load_config(write_config(tmp_path))
    settings = NvdSettings.from_mapping(tmp_path, config.job("job_third_party_data_sync").step("nvd_sync").settings)
    feed_root = tmp_path / "data" / "feeds" / "nvd"
    # A /1 snapshot stored raw feed blobs only: no metadata blobs and no index to extend.
    legacy = "sha256-0000000000000001"
    (feed_root / "snapshots" / legacy).mkdir(parents=True)
    legacy_manifest = feed_root / "snapshots" / legacy / "manifest.json"
    legacy_manifest.write_text(json.dumps({
        "schema": "appsec-review/nvd-snapshot-manifest/1", "snapshot_id": legacy, "feed_id": "nvd",
        "feed_schema": "NVD_CVE/2.0", "mode": "bootstrap", "parent_snapshot_id": None,
        "captured_at": "2026-10-04T23:24:33+00:00", "cursor": "2026-10-04T23:23:40.624Z",
        "coverage": {"first_year": 2026, "last_year": 2026}, "record_count": 1, "limitations": [],
        "layers": [{"kind": "year", "year": 2026, "blob": {"path": "blobs/legacy.json.gz"},
                    "record_count": 1, "source_url": "https://nvd.example.test/2026.json.gz"}]}),
        encoding="utf-8")
    (feed_root / "current.json").write_text(json.dumps({
        "schema": "appsec-review/nvd-current-pointer/1", "feed_id": "nvd", "snapshot_id": legacy,
        "manifest_sha256": hashlib.sha256(legacy_manifest.read_bytes()).hexdigest(),
        "cursor": "2026-10-04T23:23:40.624Z", "published_at": "2026-10-04T23:24:33+00:00"}),
        encoding="utf-8")
    publisher = NvdPublisher(settings, client=FakeClient(raw), clock=lambda: instant, pause=lambda _: None)

    pointer = publisher.sync("after-legacy")

    manifest = json.loads((feed_root / "snapshots" / pointer["snapshot_id"] / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["mode"] == "bootstrap" and manifest.get("parent_snapshot_id") is None
    assert json.loads((feed_root / "current.json").read_text(encoding="utf-8"))["snapshot_id"] == pointer["snapshot_id"]
    assert (feed_root / "snapshots" / legacy / "manifest.json").is_file()
    assert publisher.verify()["chain_length"] == 1


def test_verified_year_cache_survives_a_later_year_failure(tmp_path: Path) -> None:
    clients = {year: FakeClient(json.dumps({
        "format": "NVD_CVE", "version": "2.0",
        "vulnerabilities": [vulnerability(f"CVE-{year}-1000")],
    }).encode()) for year in (2025, 2026)}
    downloads = []

    class YearClient:
        fail = True

        def get_bytes(self, url, api_key=None):
            year = int(url.rsplit("-", 1)[1].split(".", 1)[0])
            return clients[year].get_bytes(url, api_key)

        def download(self, url, destination, api_key=None, *, expected_size=None):
            year = int(url.rsplit("-", 1)[1].split(".", 1)[0])
            downloads.append(year)
            if self.fail and year == 2026:
                raise OSError("later year unavailable")
            return clients[year].download(url, destination, api_key, expected_size=expected_size)

    client = YearClient()
    settings = NvdSettings.from_mapping(tmp_path, {"feed_root": "data/feeds/nvd", "first_year": 2025})
    publisher = NvdPublisher(settings, client=client,
                             clock=lambda: datetime(2026, 10, 21, tzinfo=timezone.utc))
    with pytest.raises(OSError, match="later year unavailable"):
        publisher.sync("failed")
    assert not (settings.feed_root / "current.json").exists()
    assert (settings.feed_root / "downloads/nvdcve-2.0-2025.json.gz").is_file()
    client.fail = False
    publisher.sync("retry")
    assert downloads == [2025, 2026, 2026]
    assert publisher.verify()["index"]["record_count"] == 2


@pytest.mark.parametrize("change", ["corrupt-cache", "updated-source"])
def test_year_cache_is_revalidated_against_current_metadata(tmp_path: Path, change: str) -> None:
    client = FakeClient(b'{"vulnerabilities":[]}')
    settings = NvdSettings.from_mapping(tmp_path, {"feed_root": "data/feeds/nvd"})
    publisher = NvdPublisher(settings, client=client)
    url = "https://nvd.example/nvdcve-2.0-2026.json.gz"
    metadata = parse_meta(client.get_bytes(url + ".meta"))
    cache = publisher._year_download(2026, url, metadata, None)
    if change == "corrupt-cache":
        cache.write_bytes(b"x" * len(client.compressed))
    else:
        client.raw_document = b'{"vulnerabilities":[], "updated":true}'
        client.compressed = gzip.compress(client.raw_document, mtime=0)
        metadata = parse_meta(client.get_bytes(url + ".meta"))
    publisher._year_download(2026, url, metadata, None)
    assert cache.read_bytes() == client.compressed


def test_bad_year_hash_never_advances_pointer(tmp_path: Path) -> None:
    class BadHashClient(FakeClient):
        def get_bytes(self, url, api_key=None):
            metadata = super().get_bytes(url, api_key)
            return metadata.replace(hashlib.sha256(self.raw_document).hexdigest().encode(), b"0" * 64)

    client = BadHashClient(b'{"vulnerabilities":[]}')
    settings = NvdSettings.from_mapping(tmp_path, {"feed_root": "data/feeds/nvd", "first_year": 2026})
    publisher = NvdPublisher(settings, client=client,
                             clock=lambda: datetime(2026, 10, 21, tzinfo=timezone.utc))
    with pytest.raises(ValueError, match="uncompressed hash or size mismatch"):
        publisher.sync("bad-hash")
    assert not (settings.feed_root / "current.json").exists()
