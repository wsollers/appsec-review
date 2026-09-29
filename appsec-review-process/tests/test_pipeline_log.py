"""Pipeline log: JSON lines, capped msg, per-run files, banners, context, buffered async writes."""
from __future__ import annotations

import json
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

ENV_KEYS = ["APPSEC_PIPELINE_LOG", "APPSEC_RUNS_ROOT"] + ["APPSEC_LOG_" + k.upper() for k in pl.CONTEXT_KEYS] + ["APPSEC_LOG_PROC"]


class PipelineLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.saved = {key: os.environ.pop(key, None) for key in ENV_KEYS}
        self.addCleanup(self.restore)
        pl._ctx.clear()
        with pl._lock:                     # nothing queued by an earlier test may leak into this one
            pl._buffer.clear()
            pl._dropped = 0
        self.path = Path(self.folder.name) / "logs" / "pipeline.log"
        os.environ["APPSEC_PIPELINE_LOG"] = str(self.path)

    def restore(self) -> None:
        pl._ctx.clear()
        for key, value in self.saved.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value

    def raw(self, path: Path | None = None) -> list[str]:
        pl.flush()
        path = path or self.path
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def records(self, path: Path | None = None) -> list[dict]:
        return [json.loads(line) for line in self.raw(path) if line.startswith("{")]

    def test_record_has_the_expected_fields_and_newlines_become_escapes(self) -> None:
        pl.log("hello\nworld", run_id="r1", job="07-red-team", step="reviewer", who="reviewer-03", attempt="a1")
        (rec,) = self.records()
        self.assertEqual({k: rec[k] for k in ("run", "job", "step", "who", "attempt", "level", "msg")},
                         {"run": "r1", "job": "07-red-team", "step": "reviewer", "who": "reviewer-03",
                          "attempt": "a1", "level": "info", "msg": "hello\\nworld"})
        self.assertEqual(rec["pid"], os.getpid())
        self.assertTrue(rec["proc"])
        self.assertRegex(rec["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")

    def test_msg_is_capped_with_a_marker(self) -> None:
        pl.log("x" * 5000)
        (rec,) = self.records()
        self.assertEqual(len(rec["msg"]), pl.MAX_MSG_CHARS)
        self.assertRegex(rec["msg"], r"\.\.\.\[\+\d+ chars\]$")

    def test_context_via_set_context_manager_and_environment(self) -> None:
        pl.set_context(run="r9", job="j", step="s")
        pl.log("a")
        with pl.context(who="w1"):
            pl.log("b")
        pl.log("c")
        a, b, c = self.records()
        self.assertEqual((a["run"], a["job"], a["step"], a.get("who")), ("r9", "j", "s", None))
        self.assertEqual(b["who"], "w1")
        self.assertNotIn("who", c)
        self.assertEqual(os.environ["APPSEC_LOG_JOB"], "j")      # children inherit through the environment

    def test_child_process_inherits_context_and_names_itself(self) -> None:
        pl.set_context(run="r1", job="j1", step="s1")
        code = "import sys;sys.path.insert(0,%r);import pipeline_log as p;p.log('from child')" % str(ROOT)
        env = dict(os.environ, APPSEC_LOG_PROC="worker")
        self.assertEqual(subprocess.run([sys.executable, "-c", code], env=env).returncode, 0)
        (rec,) = self.records()
        self.assertEqual((rec["run"], rec["job"], rec["step"], rec["proc"]), ("r1", "j1", "s1", "worker"))
        self.assertNotEqual(rec["pid"], os.getpid())

    def test_run_with_a_directory_gets_its_own_file_and_others_use_global(self) -> None:
        os.environ.pop("APPSEC_PIPELINE_LOG")
        runs = Path(self.folder.name) / "runs"
        (runs / "r1").mkdir(parents=True)
        os.environ["APPSEC_RUNS_ROOT"] = str(runs)
        pl.log("in run", run_id="r1")
        pl.log("no such run", run_id="ghost")
        pl.flush()
        own = pl.run_log_path("r1")
        self.assertEqual(own, runs / "r1" / "data" / "logs" / "pipeline.log")
        self.assertEqual([r["msg"] for r in self.records(own)], ["in run"])
        self.assertFalse((runs / "ghost").exists())

    def test_banner_is_three_hash_lines_then_a_marker_and_jq_style_parsing_skips_it(self) -> None:
        pl.log("before")
        pl.banner("r1", "resume", dagster_run="d1")
        pl.log("after")
        lines = self.raw()
        self.assertEqual(lines[1:4], [pl.BANNER_LINE] * 3)
        self.assertTrue(set(pl.BANNER_LINE) == {"#"})
        marker = json.loads(lines[4])
        self.assertEqual(marker["level"], "banner")
        self.assertIn("resume", marker["msg"])
        self.assertEqual([r["msg"] for r in self.records() if r["level"] != "banner"], ["before", "after"])

    def test_banner_once_writes_one_banner_per_key(self) -> None:
        os.environ.pop("APPSEC_PIPELINE_LOG")
        runs = Path(self.folder.name) / "runs"
        (runs / "r1").mkdir(parents=True)
        os.environ["APPSEC_RUNS_ROOT"] = str(runs)
        self.assertTrue(pl.banner_once("r1", "dagster-run-1", "resume"))
        self.assertFalse(pl.banner_once("r1", "dagster-run-1", "resume"))
        self.assertTrue(pl.banner_once("r1", "dagster-run-2", "resume"))
        lines = self.raw(pl.run_log_path("r1"))
        self.assertEqual(sum(line == pl.BANNER_LINE for line in lines), 6)

    def test_off_disables_and_writes_nothing(self) -> None:
        os.environ["APPSEC_PIPELINE_LOG"] = "off"
        pl.log("nothing")
        pl.banner("r1", "intake")
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
        recs = self.records()
        self.assertEqual(sum(r["msg"].startswith("line-") for r in recs), 5)
        self.assertTrue(any("dropped 15 line(s)" in r["msg"] for r in recs))

    def test_threads_write_whole_lines(self) -> None:
        def work(name: str) -> None:
            for index in range(200):
                pl.log(f"{name}-{index}")
        threads = [threading.Thread(target=work, args=(f"t{n}",)) for n in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(self.records()), 1600)

    def test_processes_append_without_splitting_lines(self) -> None:
        code = ("import sys;sys.path.insert(0,%r);import pipeline_log as p;"
                "[p.log('proc-%%s-%%d' %% (sys.argv[1], i)) for i in range(100)]") % str(ROOT)
        procs = [subprocess.Popen([sys.executable, "-c", code, str(n)], env=dict(os.environ)) for n in range(4)]
        for proc in procs:
            self.assertEqual(proc.wait(timeout=60), 0)
        self.assertEqual(len(self.records()), 400)     # every line parsed as JSON: none was split


if __name__ == "__main__":
    unittest.main()
