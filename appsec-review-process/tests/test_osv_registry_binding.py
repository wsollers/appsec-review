import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import dependency_b13_adapters as b13
import dependency_snapshot_registry as registry
import osv_feed
from test_osv_feed import FakeDownloader, make_zip, T0


class OsvRegistryBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name) / "data"
        self.feed, self.registry = base / "feeds" / "osv", base / "registry"
        self.payloads = {e: make_zip([f"GHSA-{e[:2]}-1"]) for e in osv_feed.ECOSYSTEMS}

    def tearDown(self):
        self.temporary.cleanup()

    def publish(self, **overrides):
        return osv_feed.sync(self.feed, "r", clock=lambda: T0, fetch_file=FakeDownloader({**self.payloads, **overrides}))

    def bind(self, days=1):
        return registry.register_osv_feed(self.feed, self.registry, max_age_seconds=1209600,
                                          now=T0 + timedelta(days=days))

    def test_all_seven_ecosystems_bound_and_resolvable_with_scanner_layout(self):
        self.publish()
        manifest = self.bind()
        paths = {f["path"] for f in manifest["files"]}
        for ecosystem in osv_feed.ECOSYSTEMS:
            self.assertIn(f"osv-scanner/{ecosystem}/all.zip", paths)
        resolved = registry.resolve("osv", self.registry, max_age_seconds=1209600, now=T0 + timedelta(days=2))
        self.assertEqual(resolved["freshness"], "fresh")
        self.assertTrue(Path(resolved["data_root"], "osv-scanner", "npm", "all.zip").is_file())
        # the fixed adapter contract (mount /inputs/osv-db, XDG_CACHE_HOME) is untouched
        self.assertIn({"name": "XDG_CACHE_HOME", "value": "/inputs/osv-db"},
                      b13.request("osv", run_id="r", adapter_attempt_id="a", source_snapshot_sha256="sha256:" + "0" * 64,
                                  image={"image_id": "i", "digest": "d"}, sbom_root=Path(self.temporary.name),
                                  database_root=Path(self.temporary.name),
                                  at="2026-09-29T00:00:00Z")["environment"])

    def test_rebinding_same_feed_snapshot_is_idempotent(self):
        self.publish()
        self.assertEqual(self.bind()["sha256"], self.bind()["sha256"])

    def test_over_age_feed_fails_sca_resolution(self):
        self.publish()
        with self.assertRaises(registry.SnapshotStale):
            self.bind(days=15)
        self.bind(days=1)
        with self.assertRaises(b13.AdapterBlocked) as caught:
            b13.resolve_registered_snapshot("osv", snapshot_registry=self.registry, max_age_seconds=1209600,
                                            now=T0 + timedelta(days=15))
        self.assertIn("stale", str(caught.exception))

    def test_missing_feed_is_blocked(self):
        with self.assertRaises(registry.SnapshotBlocked):
            self.bind()

    def test_missing_ecosystem_is_a_recorded_gap_not_a_crash(self):
        self.publish(NuGet=b"garbage")
        manifest = self.bind()
        paths = {f["path"] for f in manifest["files"]}
        self.assertNotIn("osv-scanner/NuGet/all.zip", paths)
        provenance = json.loads((Path(registry.resolve("osv", self.registry, max_age_seconds=1209600,
                                                       now=T0)["data_root"]) / "source-provenance.json").read_text())
        self.assertEqual([g["ecosystem"] for g in provenance["gaps"]], ["NuGet"])
        result = b13.resolve_registered_snapshot("osv", snapshot_registry=self.registry, max_age_seconds=1209600, now=T0)
        self.assertEqual(result["database"]["database_kind"], "osv")

    def test_copy_semantics_unchanged_for_supplied_mirrors(self):
        source = Path(self.temporary.name) / "mirror"
        (source / "osv-scanner" / "npm").mkdir(parents=True)
        (source / "osv-scanner" / "npm" / "all.zip").write_bytes(make_zip(["GHSA-x"]))
        meta = Path(self.temporary.name) / "meta.json"
        meta.write_text(json.dumps({"database_kind": "osv", "vendor_build": "hand", "schema_version": "1",
                                    "snapshot_id": "hand-1", "data_timestamp": "2026-09-28T00:00:00Z"}))
        out = registry.register("osv", source, meta, self.registry)
        copied = Path(out["data_root"]) / "osv-scanner" / "npm" / "all.zip"
        self.assertNotEqual((copied.stat().st_ino, copied.stat().st_dev),
                            ((source / "osv-scanner/npm/all.zip").stat().st_ino, (source / "osv-scanner/npm/all.zip").stat().st_dev))


if __name__ == "__main__":
    unittest.main()
