"""cve_bin_tool_db: the cve-bin-tool database is derived from the pinned NVD snapshot, never downloaded.

The NVD publication root is produced by the real `nvd_feed` publisher, driven offline with seven
real NVD 2.0 records (tests/fixtures/cve-bin-tool-real/nvd-zlib-cves.json): the 2016/2018 zlib CVEs
in the bootstrap feed, the 2022/2023 ones in an incremental API page. The builder container is
replaced by a runner; set CVE_BIN_TOOL_PYTHON to a Python with cve-bin-tool 3.4 installed to run the
real `scripts/tool-cve-bin-tool/build_db.py` instead (no Docker needed).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import cve_bin_tool_db as db  # noqa: E402
import nvd_feed  # noqa: E402  (fixture builder only)
import sca_nvd_snapshot as nvd  # noqa: E402

REAL = ROOT / "tests" / "fixtures" / "cve-bin-tool-real"
T0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
TOOL = {"image_digest": "sha256:" + "c" * 64, "tool_version": "3.4"}


def records():
    return json.loads((REAL / "nvd-zlib-cves.json").read_text())


class Publisher:
    """The real NVD publisher, offline: base = 2016/2018 CVEs, one API page = 2022/2023 CVEs."""

    def __init__(self, root):
        self.root = root
        cves = records()
        self.base = [c for c in cves if c["id"][4:8] in ("2016", "2018")]
        self.delta = [c for c in cves if c["id"][4:8] in ("2022", "2023")]
        self.document = json.dumps({"format": "NVD_CVE", "version": "2.0",
                                    "vulnerabilities": [{"cve": c} for c in self.base]}).encode()
        self.compressed = gzip.compress(self.document, mtime=0)

    def fetch(self, url, api_key=None):
        if url.endswith(".meta"):
            return (f"lastModifiedDate:{nvd_feed.timestamp(T0)}\nsize:{len(self.document)}\n"
                    f"gzSize:{len(self.compressed)}\nsha256:{hashlib.sha256(self.document).hexdigest()}\n").encode()
        return json.dumps({"format": "NVD_CVE", "version": "2.0", "startIndex": 0,
                           "resultsPerPage": len(self.delta), "totalResults": len(self.delta),
                           "vulnerabilities": [{"cve": c} for c in self.delta]}).encode()

    def fetch_file(self, url, destination, api_key=None):
        Path(destination).write_bytes(self.compressed)
        return len(self.compressed)

    def sync(self, instant):
        captured = instant.isoformat()
        with patch.object(nvd_feed, "FIRST_YEAR", 2026), patch.object(nvd_feed, "now", lambda: captured):
            return nvd_feed.sync(self.root, "offline-fixture", clock=lambda: instant, fetch=self.fetch,
                                 fetch_file=self.fetch_file, pause=lambda _: None)


def fake_runner(seen):
    """Stands in for the container: records the layers it was given and writes a minimal database."""
    def run(input_dir, output_dir, *, image_digest):
        layers = sorted((input_dir / "layers").glob("*.json.gz"))
        ids = [[item["cve"]["id"] for item in json.loads(gzip.decompress(p.read_bytes()))["vulnerabilities"]] for p in layers]
        seen.append({"image_digest": image_digest, "layers": ids})
        out = output_dir / "db"
        out.mkdir()
        with sqlite3.connect(out / "cve.db") as connection:
            connection.execute("CREATE TABLE cve_severity (cve_number TEXT, data_source TEXT)")
            connection.executemany("INSERT INTO cve_severity VALUES (?, 'NVD')", [(i,) for layer in ids for i in layer])
        with sqlite3.connect(out / "version_map.db") as mapping:
            mapping.execute("CREATE TABLE latest_update_sqlite (datestamp DATETIME PRIMARY KEY)")
            mapping.execute("INSERT INTO latest_update_sqlite VALUES (?)", (T0.timestamp(),))
        count = sum(len(layer) for layer in ids)
        (out / "build.json").write_text(json.dumps({"tool_version": "3.4", "layers": len(layers), "layer_records": count,
                                                    "cve_count": count, "range_count": 0, "sources": ["NVD"]}))
    return run


def real_runner(python):
    def run(input_dir, output_dir, *, image_digest):
        env = {**os.environ, "HOME": str(output_dir / "home")}
        completed = subprocess.run([python, "-B", str(db.BUILDER_DIR / "build_db.py"), str(input_dir), str(output_dir / "db")],
                                   env=env, capture_output=True, timeout=600)
        if completed.returncode:
            raise db.DbUnavailable("BUILD_FAILED", completed.stderr.decode(errors="replace")[-400:])
    return run


class CveBinToolDbTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.nvd_root, self.root = self.tmp / "nvd", self.tmp / "cve-bin-tool"
        self.publisher = Publisher(self.nvd_root)
        self.publisher.sync(T0)                          # bootstrap
        self.publisher.sync(T0 + timedelta(hours=2))     # one incremental API page
        self.seen = []

    def build(self, runner=None, at=T0 + timedelta(hours=3)):
        return db.build(self.root, self.nvd_root, clock=lambda: at, runner=runner or fake_runner(self.seen), tool=TOOL)

    def identity(self, at=T0 + timedelta(hours=3)):
        return nvd.resolve_snapshot(self.nvd_root, max_age=nvd.NO_AGE_LIMIT, now=at).identity

    def test_layers_are_replayed_base_first_then_deltas_in_order(self):
        self.build()
        (call,) = self.seen
        self.assertEqual(call["image_digest"], TOOL["image_digest"])
        self.assertEqual([sorted(layer) for layer in call["layers"]],
                         [["CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843", "CVE-2018-25032"],
                          ["CVE-2022-37434", "CVE-2023-45853"]])

    def test_publication_is_bound_to_the_nvd_snapshot_and_idempotent(self):
        pointer = self.build()
        manifest = json.loads((self.root / "snapshots" / pointer["snapshot_id"] / "manifest.json").read_text())
        identity = self.identity()
        self.assertEqual((manifest["nvd_snapshot_id"], manifest["nvd_manifest_sha256"]),
                         (identity["snapshot_id"], identity["manifest_sha256"]))
        self.assertEqual(manifest["sources"], ["NVD"])
        self.assertEqual(manifest["cve_count"], 7)
        self.assertEqual(self.build(), pointer)          # same NVD, image and builder: no rebuild
        self.assertEqual(len(self.seen), 1)
        resolved = db.resolve_db(self.root, nvd_identity=identity, tool=TOOL, now=T0 + timedelta(hours=4))
        self.assertEqual(resolved["snapshot_id"], pointer["snapshot_id"])

    def test_a_new_nvd_snapshot_makes_the_published_database_stale_until_rebuilt(self):
        self.build()
        self.publisher.sync(T0 + timedelta(hours=5))
        fresh = self.identity(T0 + timedelta(hours=6))
        with self.assertRaises(db.DbUnavailable) as caught:
            db.resolve_db(self.root, nvd_identity=fresh, tool=TOOL, now=T0 + timedelta(hours=6))
        self.assertEqual(caught.exception.reason, "DB_STALE_FOR_NVD_SNAPSHOT")
        self.build(at=T0 + timedelta(hours=6))
        db.resolve_db(self.root, nvd_identity=fresh, tool=TOOL, now=T0 + timedelta(hours=6))

    def test_preflight_refuses_tampering_another_image_and_an_expired_version_map(self):
        pointer = self.build()
        identity = self.identity()
        for tool, now, reason in ((dict(TOOL, image_digest="sha256:" + "d" * 64), T0, "DB_STALE_FOR_IMAGE"),
                                  (TOOL, T0 + timedelta(days=30), "DB_VERSION_MAP_EXPIRED")):
            with self.assertRaises(db.DbUnavailable) as caught:
                db.resolve_db(self.root, nvd_identity=identity, tool=tool, now=now)
            self.assertEqual(caught.exception.reason, reason)
        target = self.root / "snapshots" / pointer["snapshot_id"] / "cve.db"
        target.chmod(0o644)
        target.write_bytes(target.read_bytes() + b"\0")
        with self.assertRaises(db.DbUnavailable) as caught:
            db.resolve_db(self.root, nvd_identity=identity, tool=TOOL, now=T0)
        self.assertEqual(caught.exception.reason, "DB_INVALID")
        with self.assertRaises(db.DbUnavailable) as caught:
            db.resolve_db(self.tmp / "nowhere", nvd_identity=identity, tool=TOOL, now=T0)
        self.assertEqual(caught.exception.reason, "DB_MISSING")

    def test_a_failed_build_keeps_the_last_good_pointer(self):
        pointer = self.build()
        self.publisher.sync(T0 + timedelta(hours=5))
        def broken(input_dir, output_dir, *, image_digest):
            raise db.DbUnavailable("BUILD_FAILED", "builder exited 4")
        with self.assertRaises(db.DbUnavailable):
            self.build(runner=broken, at=T0 + timedelta(hours=6))
        self.assertEqual(json.loads((self.root / "current.json").read_text()), pointer)

    def test_a_database_with_another_source_or_no_rows_is_refused(self):
        def other_source(input_dir, output_dir, *, image_digest):
            fake_runner([])(input_dir, output_dir, image_digest=image_digest)
            with sqlite3.connect(output_dir / "db" / "cve.db") as connection:
                connection.execute("INSERT INTO cve_severity VALUES ('CVE-2026-0001', 'OSV')")
        with self.assertRaises(db.DbUnavailable) as caught:
            self.build(runner=other_source)
        self.assertEqual(caught.exception.reason, "BUILD_INVALID")
        self.assertFalse((self.root / "current.json").exists())

    def test_host_check_runs_the_scan_preflight(self):
        # prepare-host.sh step 4b: the reason the scan node would block on, before any run.
        at = T0 + timedelta(hours=4)
        with mock.patch.object(db, "pinned_tool", return_value=TOOL):
            with self.assertRaises(db.DbUnavailable) as caught:
                db.check(self.root, self.nvd_root, now=at)
            self.assertEqual(caught.exception.reason, "DB_MISSING")
            pointer = self.build()
            self.assertEqual(db.check(self.root, self.nvd_root, now=at)["snapshot_id"], pointer["snapshot_id"])
            with self.assertRaises(db.DbUnavailable) as caught:
                db.check(self.root, self.tmp / "no-nvd", now=at)
            self.assertTrue(caught.exception.reason.startswith("NVD_"), caught.exception.reason)

    def test_no_nvd_snapshot_means_no_database(self):
        with self.assertRaises(db.DbUnavailable) as caught:
            db.build(self.root, self.tmp / "no-nvd", clock=lambda: T0, runner=fake_runner([]), tool=TOOL)
        self.assertEqual(caught.exception.reason, "NVD_DATA_ROOT_MISSING")

    @unittest.skipUnless(os.environ.get("CVE_BIN_TOOL_PYTHON"), "set CVE_BIN_TOOL_PYTHON to run the real builder")
    def test_real_builder_loads_every_layer(self):
        pointer = self.build(runner=real_runner(os.environ["CVE_BIN_TOOL_PYTHON"]))
        directory = self.root / "snapshots" / pointer["snapshot_id"]
        with sqlite3.connect(f"file:{directory / 'cve.db'}?mode=ro", uri=True) as connection:
            ranges = connection.execute("SELECT cve_number, versionEndExcluding, versionEndIncluding FROM cve_range "
                                        "WHERE product = 'zlib' ORDER BY cve_number").fetchall()
        self.assertEqual([row[0] for row in ranges], ["CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843",
                                                      "CVE-2018-25032", "CVE-2022-37434", "CVE-2023-45853"])
        self.assertIn(("CVE-2022-37434", "", "1.2.12"), ranges)


if __name__ == "__main__":
    unittest.main()
