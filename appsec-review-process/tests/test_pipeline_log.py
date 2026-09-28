"""Central pipeline log: capped lines, buffered async writes, bounded buffer, no split lines."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pipeline_log as pl


class PipelineLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / "logs" / "pipeline.log"
        with pl._lock:                     # nothing queued by an earlier test may leak into this file
            pl._buffer.clear()
            pl._dropped = 0
        os.environ["APPSEC_PIPELINE_LOG"] = str(self.path)
        self.addCleanup(self.folder.cleanup)
        self.addCleanup(os.environ.pop, "APPSEC_PIPELINE_LOG", None)

    def lines(self) -> list[str]:
        pl.flush()
        return self.path.read_text(encoding="utf-8").splitlines() if self.path.exists() else []

    def test_line_carries_context_and_newlines_become_escapes(self) -> None:
        pl.log("hello\nworld", run_id="r1", job="07-red-team")
        (line,) = self.lines()
        self.assertIn("run=r1", line)
        self.assertIn("job=07-red-team", line)
        self.assertTrue(line.endswith("hello\\nworld"))

    def test_long_lines_are_capped_with_a_marker(self) -> None:
        pl.log("x" * 5000)
        (line,) = self.lines()
        self.assertEqual(len(line), pl.MAX_LINE_CHARS)
        self.assertRegex(line, r"\.\.\.\[\+\d+ chars\]$")

    def test_off_disables_and_writes_nothing(self) -> None:
        os.environ["APPSEC_PIPELINE_LOG"] = "off"
        pl.log("nothing")
        pl.flush()
        self.assertFalse(self.path.exists())

    def test_log_returns_without_touching_disk(self) -> None:
        started = time.perf_counter()
        for _ in range(2000):
            pl.log("burst")
        self.assertLess(time.perf_counter() - started, 1.0)   # buffer append only

    def test_overflow_is_dropped_and_counted_not_blocking(self) -> None:
        old_max, real_flush = pl.MAX_BUFFERED_LINES, pl.flush
        pl.MAX_BUFFERED_LINES = 5
        pl.flush = lambda: None            # pause the background writer so the buffer really fills
        try:
            for index in range(20):
                pl.log(f"line-{index}")
        finally:
            pl.flush = real_flush
            pl.MAX_BUFFERED_LINES = old_max
        lines = self.lines()
        self.assertEqual(sum(" line-" in line for line in lines), 5)
        self.assertTrue(any("dropped 15 line(s)" in line for line in lines))

    def test_threads_write_whole_lines(self) -> None:
        def work(name: str) -> None:
            for index in range(200):
                pl.log(f"{name}-{index}")
        threads = [threading.Thread(target=work, args=(f"t{n}",)) for n in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        lines = self.lines()
        self.assertEqual(len(lines), 1600)
        self.assertTrue(all(line.split(" ", 2)[2].startswith("t") for line in lines))

    def test_processes_append_without_splitting_lines(self) -> None:
        code = ("import sys;sys.path.insert(0,%r);import pipeline_log as p;"
                "[p.log('proc-%%s-%%d' %% (sys.argv[1], i)) for i in range(100)]") % str(ROOT)
        procs = [subprocess.Popen([sys.executable, "-c", code, str(n)], env=dict(os.environ)) for n in range(4)]
        for proc in procs:
            self.assertEqual(proc.wait(timeout=60), 0)
        lines = self.lines()
        self.assertEqual(len(lines), 400)
        self.assertTrue(all(" proc-" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
