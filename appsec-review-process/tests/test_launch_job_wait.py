"""launch_job.py: a --wait timeout is not a launch failure (2026-10-01, zarathustra)."""
from __future__ import annotations

import io
from pathlib import Path
import sys
import unittest
from contextlib import redirect_stderr
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import launch_job  # noqa: E402


class WaitTimeoutExit(unittest.TestCase):
    def run_main(self, error):
        stderr = io.StringIO()
        with mock.patch.object(launch_job, "launch", side_effect=error), \
                mock.patch.object(launch_job.dev_restart, "run_mode", return_value="prod"), redirect_stderr(stderr):
            code = launch_job.main(["--run-id", "20261001T032047Z-fd64eb", "--job", "full_review", "--wait"])
        return code, stderr.getvalue()

    def test_monitoring_timeout_exits_3_with_its_own_label(self):
        code, err = self.run_main(launch_job.WaitTimeout("stopped watching after 600s; the Dagster run is still STARTED"))
        self.assertEqual(code, 3)
        self.assertIn("DAGSTER_WAIT_TIMEOUT", err)
        self.assertNotIn("DAGSTER_LAUNCH_FAILED", err)

    def test_real_launch_failure_still_exits_1(self):
        code, err = self.run_main(launch_job.Blocked("Dagster rejected launch"))
        self.assertEqual(code, 1)
        self.assertIn("DAGSTER_LAUNCH_FAILED", err)


if __name__ == "__main__":
    unittest.main()


class StaleImageGuard(unittest.TestCase):
    """Run 20261001T032047Z-fd64eb: the relaunch ran CodeQL Go on an audit-codeql built before its lane
    script changed (usage error, exit 2). A new launch now refuses drifted image builds."""

    def test_drifted_image_blocks_a_new_launch(self):
        with mock.patch.object(launch_job, "drifted_images", return_value=["audit-codeql"]), \
                mock.patch.dict(launch_job.os.environ, {}, clear=False):
            launch_job.os.environ.pop("APPSEC_ALLOW_STALE_IMAGES", None)
            with self.assertRaisesRegex(launch_job.Blocked, "audit-codeql.*prepare-host"):
                launch_job.check_images("full_review")

    def test_intake_and_explicit_override_are_not_checked(self):
        with mock.patch.object(launch_job, "drifted_images", return_value=["audit-codeql"]):
            launch_job.check_images("phase1_intake")
            with mock.patch.dict(launch_job.os.environ, {"APPSEC_ALLOW_STALE_IMAGES": "1"}):
                launch_job.check_images("full_review")

    def test_current_images_pass(self):
        with mock.patch.object(launch_job, "drifted_images", return_value=[]):
            launch_job.check_images("full_review")

    def test_real_registry_lookup_runs(self):
        self.assertIsInstance(launch_job.drifted_images(), list)
