from __future__ import annotations

from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_third_party_data_sync import build_job
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.feed import NvdPublisher, timestamp
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.models import NvdSettings
from appsec_review.runtime import JobRunner


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

    def download(self, url: str, destination: Path, api_key: str | None = None) -> int:
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
""".strip(),
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

    first = JobRunner(config).run(build_job(client=client, clock=lambda: instant, pause=lambda _: None), now=instant)
    feed_root = tmp_path / "data" / "feeds" / "nvd"
    current = json.loads((feed_root / "current.json").read_text(encoding="utf-8"))
    first_snapshot = current["snapshot_id"]
    manifest = json.loads((feed_root / "snapshots" / first_snapshot / "manifest.json").read_text(encoding="utf-8"))
    metadata_blob = feed_root / manifest["layers"][0]["metadata_blob"]["path"]
    with gzip.open(metadata_blob, "rt", encoding="utf-8") as stream:
        metadata = json.loads(stream.readline())

    assert first["status"]["status"] == "SUCCEEDED"
    assert metadata["id"] == "CVE-2026-1000"
    assert metadata["weaknesses"] == ["CWE-79"]
    assert metadata["metrics"][0]["base_score"] == 7.5

    later = instant + timedelta(hours=2)
    second = JobRunner(config).run(build_job(client=client, clock=lambda: later, pause=lambda _: None), now=later)
    current = json.loads((feed_root / "current.json").read_text(encoding="utf-8"))
    receipt = second["result"]["verification"]
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
