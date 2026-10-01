"""dagster_workflow: a failed workflow is visible in run-status.json (run 20261001T032047Z-fd64eb read READY)."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@unittest.skipUnless(importlib.util.find_spec("dagster"), "dagster is not installed")
class RunStatusFailureTests(unittest.TestCase):
    def test_failure_marks_run_status_and_keeps_intake_fields(self):
        import dagster_workflow as dw
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            (root / "run-status.json").write_text(json.dumps({"status": "READY", "phase1_status": "OK",
                                                              "last_message": "Validated reuse; work not invoked"}))
            with mock.patch.object(dw, "run_path", return_value=root):
                dw._mark_run_status_failed("run-1", "dagster-1", "step job_01 failed")
            data = json.loads((root / "run-status.json").read_text())
            self.assertEqual((data["status"], data["phase1_status"], data["last_message"]),
                             ("FAILED", "OK", "step job_01 failed"))
            self.assertIn("Status: FAILED", (root / "run-status.md").read_text())


if __name__ == "__main__":
    unittest.main()
