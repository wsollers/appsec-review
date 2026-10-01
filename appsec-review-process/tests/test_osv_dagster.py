import os
from datetime import timedelta
from functools import partial
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, os.environ.get("APPSEC_DEFINITIONS_DIR", str(Path(__file__).resolve().parents[2] / "orchestrator" / "dagster")))
import dagster
import osv_feed
from test_osv_feed import FakeDownloader, make_zip


class OsvDagsterTests(unittest.TestCase):
    def setUp(self):
        import definitions
        self.definitions = definitions
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name) / "data"
        self.feed, self.registry = base / "feeds" / "osv", base / "registry"
        payloads = {e: make_zip([f"GHSA-{e[:2]}-1"]) for e in osv_feed.ECOSYSTEMS}
        payloads["Go"] = b"broken"
        self.sync = partial(osv_feed.sync, self.feed, fetch_file=FakeDownloader(payloads))

    def tearDown(self):
        self.temporary.cleanup()

    def run_op(self):
        with patch.object(self.definitions, "sync_osv", lambda coordinator_id: self.sync(coordinator_id=coordinator_id)), \
             patch.object(self.definitions, "osv_feed_root", lambda: self.feed):
            return self.definitions.osv_sync_work(dagster.build_op_context())

    def test_job_runs_both_ops_and_keeps_the_nvd_tag_and_schedule(self):
        job = self.definitions.nvd_reference_sync
        self.assertEqual({n.name for n in job.nodes}, {"nvd_sync_work", "osv_sync_work", "mitre_sync_work", "cve_bin_tool_db_work"})
        self.assertEqual(job.tags["nvd_feed_id"], "nvd")
        self.assertEqual(job.tags["osv_feed_id"], "osv")
        self.assertEqual([s.name for s in self.definitions.defs.schedules], ["nvd_reference_schedule"])

    def test_op_publishes_with_gap_and_without_registry_does_not_bind(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("APPSEC_DEPENDENCY_REGISTRY_ROOT", None)
            snapshot_id = self.run_op()
        self.assertTrue(snapshot_id.startswith("sha256-"))
        self.assertFalse(self.registry.exists())
        self.assertEqual(osv_feed.verify(self.feed)["gaps"], ["Go"])

    def test_op_binds_into_registry_when_configured(self):
        from datetime import datetime, timezone
        import dependency_snapshot_registry as registry
        with patch.dict(os.environ, {"APPSEC_DEPENDENCY_REGISTRY_ROOT": str(self.registry)}):
            # the fake feed is stamped "now" by the op path; clock is real here
            with patch.object(osv_feed, "utcnow", lambda: datetime.now(timezone.utc)):
                self.run_op()
        resolved = registry.resolve("osv", self.registry, max_age_seconds=1209600, now=datetime.now(timezone.utc) + timedelta(hours=1))
        self.assertEqual(resolved["freshness"], "fresh")


if __name__ == "__main__":
    unittest.main()
