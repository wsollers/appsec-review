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
