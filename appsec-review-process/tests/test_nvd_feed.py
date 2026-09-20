import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import nvd_feed
from schema_validate import validate_document


def vulnerability(identifier):
    return {"cve": {"id": identifier, "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-01-01T00:00:00.000"}}


class NvdFeedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "data" / "feeds" / "nvd"
        self.instant = nvd_feed.parse_time("2026-09-19T12:00:00Z")
        self.document = json.dumps({"format": "NVD_CVE", "version": "2.0",
                                    "vulnerabilities": [vulnerability("CVE-2026-1000")]},
                                   separators=(",", ":")).encode()
        self.compressed = gzip.compress(self.document, mtime=0)

    def tearDown(self):
        self.temporary.cleanup()

    def meta(self):
        return (f"lastModifiedDate:{nvd_feed.timestamp(self.instant)}\n"
                f"size:{len(self.document)}\n"
                f"gzSize:{len(self.compressed)}\n"
                f"sha256:{hashlib.sha256(self.document).hexdigest()}\n").encode()

    def test_transport_accepts_static_gzip_and_keeps_key_external(self):
        headers = nvd_feed._headers("test-key")
        self.assertEqual(headers["Accept"], "*/*")
        self.assertEqual(headers["apiKey"], "test-key")

    def fetch(self, url, api_key=None):
        if url.endswith(".meta"):
            return self.meta()
        return json.dumps({"format": "NVD_CVE", "version": "2.0", "startIndex": 0,
                           "resultsPerPage": 1, "totalResults": 1,
                           "vulnerabilities": [vulnerability("CVE-2026-1001")]},
                          separators=(",", ":")).encode()

    def fetch_file(self, url, destination, api_key=None):
        Path(destination).write_bytes(self.compressed)
        return len(self.compressed)

    def test_bootstrap_then_incremental_publish_and_verify(self):
        with patch.object(nvd_feed, "FIRST_YEAR", 2026):
            first = nvd_feed.sync(self.root, "dagster-bootstrap", clock=lambda: self.instant,
                                  fetch=self.fetch, fetch_file=self.fetch_file, pause=lambda _: None)
        self.assertEqual(nvd_feed.verify(self.root)["chain_length"], 1)
        current = json.loads((self.root / "current.json").read_text())
        manifest = json.loads((self.root / "snapshots" / current["snapshot_id"] / "manifest.json").read_text())
        lease = json.loads((self.root / "locks" / "lease.json").read_text())
        self.assertEqual(validate_document(current, "nvd-current-pointer.schema.json"), [])
        self.assertEqual(validate_document(manifest, "nvd-snapshot-manifest.schema.json"), [])
        self.assertEqual(validate_document(lease, "nvd-writer-lease.schema.json"), [])
        later = self.instant + nvd_feed.timedelta(hours=2)
        second = nvd_feed.sync(self.root, "dagster-incremental", clock=lambda: later,
                               fetch=self.fetch, fetch_file=self.fetch_file, pause=lambda _: None)
        self.assertNotEqual(first["snapshot_id"], second["snapshot_id"])
        receipt = nvd_feed.verify(self.root)
        self.assertEqual(receipt["chain_length"], 2)
        self.assertEqual(receipt["cursor"], nvd_feed.timestamp(later))

    def test_failed_refresh_does_not_advance_last_good_pointer(self):
        with patch.object(nvd_feed, "FIRST_YEAR", 2026):
            first = nvd_feed.sync(self.root, "dagster-bootstrap", clock=lambda: self.instant,
                                  fetch=self.fetch, fetch_file=self.fetch_file, pause=lambda _: None)

        def fail(url, api_key=None):
            raise OSError("network unavailable")

        with self.assertRaisesRegex(OSError, "network unavailable"):
            nvd_feed.sync(self.root, "dagster-failed", clock=lambda: self.instant + nvd_feed.timedelta(hours=2),
                          fetch=fail, fetch_file=self.fetch_file, pause=lambda _: None)
        self.assertEqual(json.loads((self.root / "current.json").read_text())["snapshot_id"],
                         first["snapshot_id"])
        failed = list((self.root / "staging").glob("*/attempt.json"))
        self.assertTrue(any(json.loads(path.read_text())["status"] == "FAILED" for path in failed))

    def test_tampered_blob_fails_verification(self):
        with patch.object(nvd_feed, "FIRST_YEAR", 2026):
            nvd_feed.sync(self.root, "dagster-bootstrap", clock=lambda: self.instant,
                          fetch=self.fetch, fetch_file=self.fetch_file, pause=lambda _: None)
        blob = next((self.root / "blobs").iterdir())
        blob.write_bytes(blob.read_bytes() + b"tamper")
        with self.assertRaisesRegex(ValueError, "blob integrity"):
            nvd_feed.verify(self.root)

    def test_fresh_orphan_lease_is_not_stolen(self):
        lease = self.root / "locks" / "lease.json"
        lease.parent.mkdir(parents=True)
        expiry = nvd_feed.utcnow() + nvd_feed.timedelta(minutes=2)
        lease.write_text(json.dumps({"schema": nvd_feed.LEASE_SCHEMA, "status": "RUNNING",
                                     "lease_expires_at": nvd_feed.timestamp(expiry)}))
        with self.assertRaisesRegex(nvd_feed.Blocked, "lease is fresh"):
            with nvd_feed.WriterLease(self.root, "attempt", "coordinator", None):
                pass


if __name__ == "__main__":
    unittest.main()
