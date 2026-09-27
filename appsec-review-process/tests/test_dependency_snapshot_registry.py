from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import dependency_snapshot_registry as snapshots


class SnapshotRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.root = Path(self.temporary.name)
        self.source = self.root / "supplied"; self.source.mkdir(); (self.source / "db.bin").write_bytes(b"immutable-db")
        self.registry = self.root / "registry"

    def tearDown(self): self.temporary.cleanup()

    def metadata(self, kind="grype-db", timestamp="2026-09-27T11:00:00Z"):
        path = self.root / (kind + ".json")
        path.write_text(json.dumps({"database_kind": kind, "vendor_build": "vendor-20260927",
            "schema_version": "1.0", "snapshot_id": kind + "-20260927", "data_timestamp": timestamp}))
        return path

    def test_register_resolve_reuse_and_tamper_rejection(self):
        first = snapshots.register("grype-db", self.source, self.metadata(), self.registry)
        second = snapshots.register("grype-db", self.source, self.metadata(), self.registry)
        self.assertEqual(first, second)
        resolved = snapshots.resolve("grype-db", self.registry, max_age_seconds=7200,
                                     now=datetime(2026, 9, 27, 12, tzinfo=timezone.utc))
        self.assertEqual(resolved["sha256"], first["sha256"])
        Path(resolved["data_root"], "db.bin").write_bytes(b"tampered")
        with self.assertRaisesRegex(snapshots.SnapshotInvalid, "bytes changed"):
            snapshots.resolve("grype-db", self.registry, max_age_seconds=7200,
                              now=datetime(2026, 9, 27, 12, tzinfo=timezone.utc))

    def test_absent_and_stale_are_distinct(self):
        with self.assertRaisesRegex(snapshots.SnapshotBlocked, "absent"):
            snapshots.resolve("osv", self.registry, max_age_seconds=1,
                              now=datetime(2026, 9, 27, 12, tzinfo=timezone.utc))
        snapshots.register("osv", self.source, self.metadata("osv", "2026-09-01T00:00:00Z"), self.registry)
        with self.assertRaisesRegex(snapshots.SnapshotStale, "stale"):
            snapshots.resolve("osv", self.registry, max_age_seconds=60,
                              now=datetime(2026, 9, 27, 12, tzinfo=timezone.utc))

    def test_links_and_empty_supplies_fail_closed(self):
        empty = self.root / "empty"; empty.mkdir()
        with self.assertRaises(snapshots.SnapshotBlocked): snapshots.inventory(empty)
        link = self.source / "link"; link.symlink_to(self.source / "db.bin")
        with self.assertRaises(snapshots.SnapshotInvalid): snapshots.inventory(self.source)


if __name__ == "__main__": unittest.main()
