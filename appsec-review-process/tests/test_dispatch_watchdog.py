"""review_cli._dispatch_streaming: heartbeat carries idle time; the idle watchdog warns, and kills only when asked."""
from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import review_cli

SILENT = [sys.executable, "-c", "import sys,time;sys.stdin.read();time.sleep(60)"]
CHATTY = [sys.executable, "-c",
          "import sys,json;sys.stdin.read();print(json.dumps({'type':'result','total_cost_usd':0}))"]


class WatchdogTests(unittest.TestCase):
    def dispatch(self, argv, timeout=30, **env):
        keys = {"APPSEC_PIPELINE_LOG": "off", "APPSEC_HEARTBEAT_SECONDS": "1", **env}
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(os.environ, keys), \
                redirect_stderr(io.StringIO()) as err:
            result = review_cli._dispatch_streaming(argv, "prompt", timeout, Path(folder) / "t.jsonl")
        return result, err.getvalue()

    def test_a_normal_call_is_not_idle_killed(self) -> None:
        result, _ = self.dispatch(CHATTY, APPSEC_IDLE_KILL_SECONDS="2")
        self.assertFalse(result["idle_killed"])
        self.assertIsNotNone(result["final_result"])

    def test_silent_process_is_warned_but_not_killed_by_default(self) -> None:
        result, err = self.dispatch(SILENT, timeout=4, APPSEC_IDLE_WARN_SECONDS="1")
        self.assertTrue(result["timed_out"])            # only the ordinary timeout ended it
        self.assertFalse(result["idle_killed"])
        self.assertIn("IDLE: no stream event", err)
        self.assertIn("idle=", err)

    def test_kill_limit_stops_a_wedged_process_early(self) -> None:
        result, err = self.dispatch(SILENT, timeout=50, APPSEC_IDLE_WARN_SECONDS="1", APPSEC_IDLE_KILL_SECONDS="3")
        self.assertTrue(result["idle_killed"])
        self.assertFalse(result["timed_out"])
        self.assertIsNone(result["final_result"])
        self.assertIn("killed by the idle watchdog", err)


if __name__ == "__main__":
    unittest.main()
