import io
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import osv_feed
import osv_snapshot


def make_zip(ids, corrupt=None):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for identifier in ids:
            archive.writestr(identifier + ".json", json.dumps({
                "id": identifier, "aliases": ["CVE-2026-0001"],
                "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"},
                              "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}]}]}))
        if corrupt == "notjson":
            archive.writestr("bad.json", "{not json")
        if corrupt == "noid":
            archive.writestr("noid.json", "{}")
        if corrupt == "dup":
            archive.writestr("sub/x.json", json.dumps({"id": ids[0]}))
    return buffer.getvalue()


class FakeDownloader:
    def __init__(self, payloads, etags=True):
        self.payloads, self.calls, self.etags = payloads, [], etags

    def __call__(self, url, destination, etag=None, **_):
        ecosystem = url.rsplit("/", 2)[-2]
        self.calls.append((ecosystem, etag))
        value = self.payloads[ecosystem]
        if isinstance(value, Exception):
            raise value
        if etag and etag == "etag-" + ecosystem and value == "same":
            return {"not_modified": True, "size": 0, "etag": etag}
        Path(destination).write_bytes(value)
        return {"not_modified": False, "size": len(value), "etag": "etag-" + ecosystem}


T0 = datetime(2026, 9, 29, 0, 0, tzinfo=timezone.utc)


class OsvFeedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "data" / "feeds" / "osv"
        self.payloads = {e: make_zip([f"GHSA-{e[:2]}-0001", f"PYSEC-{e[:2]}-2"]) for e in osv_feed.ECOSYSTEMS}

    def tearDown(self):
        self.temporary.cleanup()

    def sync(self, at=T0, **payload_overrides):
        payloads = {**self.payloads, **payload_overrides}
        return osv_feed.sync(self.root, "run-1", clock=lambda: at, fetch_file=FakeDownloader(payloads))

    def test_ecosystem_names_match_gcs_directories(self):
        self.assertEqual(set(osv_feed.ECOSYSTEMS), {"npm", "Go", "Maven", "crates.io", "NuGet", "Packagist", "PyPI"})
        self.assertEqual(osv_feed.source_url("crates.io"),
                         "https://storage.googleapis.com/osv-vulnerabilities/crates.io/all.zip")
        with self.assertRaises(ValueError):
            osv_feed.source_url("../etc")

    def test_publish_layout_manifest_notice_and_verify(self):
        pointer = self.sync()
        self.assertEqual(osv_feed.verify(self.root)["gaps"], [])
        snap = self.root / "snapshots" / pointer["snapshot_id"]
        for e in osv_feed.ECOSYSTEMS:
            self.assertTrue((snap / "db" / "osv-scanner" / e / "all.zip").is_file())
        self.assertIn("Do not redistribute", (snap / "NOTICE.txt").read_text())
        manifest = json.loads((snap / "manifest.json").read_text())
        self.assertEqual(manifest["ecosystems"]["npm"]["record_count"], 2)
        self.assertEqual(manifest["licences"]["GHSA"]["licence"], "CC-BY-4.0")
        self.assertEqual(manifest["licences"]["PYSEC"]["records"], 7)
        self.assertEqual(manifest["data_timestamp"], "2026-09-29T00:00:00Z")

    def test_bad_archive_is_a_recorded_gap_and_does_not_break_publication(self):
        for kind in ("notjson", "noid", "dup"):
            with self.subTest(kind=kind):
                self.setUp()
                pointer = self.sync(NuGet=make_zip(["GHSA-a"], corrupt=kind))
                self.assertEqual(pointer["gaps"], ["NuGet"])
                self.assertFalse((self.root / "snapshots" / pointer["snapshot_id"] / "db" / "osv-scanner" / "NuGet").exists())
                self.assertEqual(osv_feed.verify(self.root)["gaps"], ["NuGet"])

    def test_not_a_zip_and_network_error_are_gaps(self):
        pointer = self.sync(Go=b"this is not a zip", PyPI=OSError("boom"))
        self.assertEqual(sorted(pointer["gaps"]), ["Go", "PyPI"])

    def test_failed_ecosystem_keeps_last_good_archive_with_original_age(self):
        first = self.sync()
        later = T0 + timedelta(hours=2)
        second = self.sync(later, Maven=OSError("down"))
        self.assertNotEqual(first["snapshot_id"], second["snapshot_id"])
        manifest = json.loads((self.root / "snapshots" / second["snapshot_id"] / "manifest.json").read_text())
        entry = manifest["ecosystems"]["Maven"]
        self.assertEqual(entry["status"], "CARRIED_FORWARD")
        self.assertEqual(entry["fetched_at"], "2026-09-29T00:00:00Z")
        self.assertIn("boom" if False else "down", entry["carried_reason"])
        self.assertEqual(manifest["data_timestamp"], "2026-09-29T00:00:00Z")
        self.assertEqual(manifest["gaps"], [])
        self.assertEqual(manifest["ecosystems"]["npm"]["fetched_at"], "2026-09-29T02:00:00Z")
        osv_feed.verify(self.root)

    def test_total_failure_leaves_prior_pointer_untouched(self):
        first = self.sync()
        before = (self.root / "current.json").read_bytes()
        broken = {e: OSError("down") for e in osv_feed.ECOSYSTEMS}
        # every ecosystem has a good prior, so they carry forward: still publishes
        second = osv_feed.sync(self.root, "r", clock=lambda: T0 + timedelta(hours=2),
                               fetch_file=FakeDownloader(broken))
        self.assertEqual(second["gaps"], [])
        # a fresh root with nothing prior and everything failing publishes nothing
        fresh = Path(self.temporary.name) / "fresh" / "feeds" / "osv"
        with self.assertRaises(RuntimeError):
            osv_feed.sync(fresh, "r", clock=lambda: T0, fetch_file=FakeDownloader(broken))
        self.assertFalse((fresh / "current.json").exists())
        self.assertEqual(list((fresh / "staging").iterdir()), [])
        self.assertNotEqual(before, b"")

    def test_not_modified_reuses_prior_bytes_and_refreshes_age(self):
        self.sync()
        payloads = {e: "same" for e in osv_feed.ECOSYSTEMS}
        downloader = FakeDownloader(payloads)
        pointer = osv_feed.sync(self.root, "r", clock=lambda: T0 + timedelta(hours=2), fetch_file=downloader)
        self.assertTrue(all(etag == "etag-" + e for e, etag in downloader.calls))
        manifest = json.loads((self.root / "snapshots" / pointer["snapshot_id"] / "manifest.json").read_text())
        self.assertEqual(manifest["data_timestamp"], "2026-09-29T02:00:00Z")
        self.assertEqual(manifest["ecosystems"]["npm"]["status"], "OK")
        osv_feed.verify(self.root)

    def test_prune_keeps_configured_number_and_current(self):
        for hours in range(5):
            osv_feed.sync(self.root, "r", clock=lambda h=hours: T0 + timedelta(hours=h),
                          fetch_file=FakeDownloader(self.payloads), keep=2)
        self.assertEqual(len(list((self.root / "snapshots").iterdir())), 2)
        osv_feed.verify(self.root)

    def test_requires_coordinator_and_safe_root(self):
        with self.assertRaises(Exception):
            osv_feed.sync(self.root, None, fetch_file=FakeDownloader(self.payloads))
        with self.assertRaises(ValueError):
            osv_feed.sync("/", "r", fetch_file=FakeDownloader(self.payloads))

    def test_verify_detects_tamper(self):
        pointer = self.sync()
        path = self.root / "snapshots" / pointer["snapshot_id"] / "db" / "osv-scanner" / "npm" / "all.zip"
        path.chmod(0o644)
        os.unlink(path)          # break any hardlink sharing before altering bytes
        path.write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            osv_feed.verify(self.root)


class OsvSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "data" / "feeds" / "osv"
        self.payloads = {e: make_zip([f"GHSA-{e[:2]}-1"]) for e in osv_feed.ECOSYSTEMS}

    def tearDown(self):
        self.temporary.cleanup()

    def publish(self, **overrides):
        return osv_feed.sync(self.root, "r", clock=lambda: T0,
                             fetch_file=FakeDownloader({**self.payloads, **overrides}))

    def test_ok_within_limit_returns_readonly_mount_dir(self):
        self.publish()
        result = osv_snapshot.resolve_snapshot(self.root, now=T0 + timedelta(days=13))
        self.assertTrue(result.usable)
        self.assertEqual(result.reason, "VERIFIED_WITHIN_LIMIT")
        self.assertTrue(Path(result.mount_dir, "osv-scanner", "npm", "all.zip").is_file())
        self.assertEqual(result.identity["max_age_seconds"], 1209600)
        self.assertEqual(result.gaps, ())

    def test_over_age_is_failed_not_ok_with_gap(self):
        self.publish()
        result = osv_snapshot.resolve_snapshot(self.root, now=T0 + timedelta(days=14, seconds=1))
        self.assertEqual((result.outcome, result.reason), ("FAILED", "SNAPSHOT_TOO_OLD"))
        self.assertIsNone(result.identity)
        self.assertIsNone(result.mount_dir)
        exact = osv_snapshot.resolve_snapshot(self.root, now=T0 + timedelta(days=14))
        self.assertTrue(exact.usable)

    def test_missing_root_and_pointer_are_blocked(self):
        self.assertEqual(osv_snapshot.resolve_snapshot(self.root, now=T0).reason, "DATA_ROOT_MISSING")
        self.root.mkdir(parents=True)
        result = osv_snapshot.resolve_snapshot(self.root, now=T0)
        self.assertEqual((result.outcome, result.reason), ("BLOCKED", "POINTER_MISSING"))

    def test_missing_ecosystem_is_a_recorded_gap_not_a_crash(self):
        self.publish(Go=b"garbage")
        result = osv_snapshot.resolve_snapshot(self.root, now=T0)
        self.assertTrue(result.usable)
        self.assertEqual(result.gaps, ("Go",))
        self.assertEqual(result.identity["gaps"][0]["ecosystem"], "Go")
        self.assertNotIn("Go", result.identity["ecosystems"])

    def test_tampered_archive_and_manifest_fail(self):
        pointer = self.publish()
        directory = self.root / "snapshots" / pointer["snapshot_id"]
        archive = directory / "db" / "osv-scanner" / "PyPI" / "all.zip"
        os.unlink(archive)
        archive.write_bytes(b"x")
        self.assertEqual(osv_snapshot.resolve_snapshot(self.root, now=T0).reason, "ARCHIVE_HASH_MISMATCH")
        os.unlink(archive)
        self.assertEqual(osv_snapshot.resolve_snapshot(self.root, now=T0).reason, "ARCHIVE_MISSING")
        manifest = directory / "manifest.json"
        manifest.write_text(manifest.read_text() + " ")
        self.assertEqual(osv_snapshot.resolve_snapshot(self.root, now=T0).reason, "MANIFEST_HASH_MISMATCH")

    def test_symlink_in_root_is_unsafe(self):
        pointer = self.publish()
        directory = self.root / "snapshots" / pointer["snapshot_id"]
        moved = directory.with_name("moved")
        directory.rename(moved)
        directory.symlink_to(moved)
        self.assertEqual(osv_snapshot.resolve_snapshot(self.root, now=T0).reason, "UNSAFE_PATH")

    def test_argument_validation_and_no_default_clock(self):
        with self.assertRaises(ValueError):
            osv_snapshot.resolve_snapshot(self.root, now=datetime(2026, 1, 1))
        with self.assertRaises(ValueError):
            osv_snapshot.resolve_snapshot(self.root, max_age=timedelta(0), now=T0)

    def test_binding_has_no_network_imports(self):
        source = Path(osv_snapshot.__file__).read_text()
        for forbidden in ("import socket", "import urllib", "import subprocess", "osv_feed", "execution_state"):
            self.assertNotIn(forbidden, source.replace("Like ``sca_nvd_snapshot``", "").split('"""', 2)[2])


if __name__ == "__main__":
    unittest.main()
