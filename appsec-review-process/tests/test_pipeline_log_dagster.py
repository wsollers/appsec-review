"""The logging op binds run/job/step/attempt, writes one banner per Dagster run, and stays transparent."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dagster import job, In, materialize_to_memory  # noqa: F401

import pipeline_log as pl
from pipeline_log_dagster import op

ENV = ["APPSEC_PIPELINE_LOG", "APPSEC_RUNS_ROOT"] + ["APPSEC_LOG_" + k.upper() for k in pl.CONTEXT_KEYS]


@op
def first(context):
    pl.log("inside first")
    return 1


@op(name="job_99_second", ins={"upstream": In(int)})
def second(context, upstream):
    pl.log("inside second")
    return upstream + 1


@op
def boom(context):
    raise ValueError("kaput")


@job
def two_steps():
    second(first())


@job
def failing():
    boom()


class DagsterLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.saved = {k: os.environ.pop(k, None) for k in ENV}
        self.addCleanup(self.restore)
        self.runs = Path(self.folder.name) / "runs"
        (self.runs / "eng1").mkdir(parents=True)
        os.environ["APPSEC_RUNS_ROOT"] = str(self.runs)

    def restore(self) -> None:
        for key, value in self.saved.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value

    def records(self) -> list[dict]:
        pl.flush()
        path = pl.run_log_path("eng1")
        lines = path.read_text().splitlines() if path.exists() else []
        return [json.loads(line) for line in lines if line.startswith("{")]

    def test_steps_carry_context_one_banner_and_start_finish_lines(self) -> None:
        result = two_steps.execute_in_process(tags={"engagement_run_id": "eng1"})
        self.assertTrue(result.success)
        self.assertEqual(result.output_for_node("job_99_second"), 2)
        recs = self.records()
        by_msg = {(r["job"], r["msg"].split(" after")[0]) for r in recs if r["level"] != "banner"}
        self.assertIn(("first", "inside first"), by_msg)
        self.assertIn(("job_99_second", "step start"), by_msg)
        self.assertIn(("job_99_second", "step finished"), by_msg)
        self.assertTrue(all(r["run"] == "eng1" and r["attempt"] for r in recs))
        self.assertEqual(sum(r["level"] == "banner" for r in recs), 1)          # once per Dagster run
        self.assertEqual(sum(l == pl.BANNER_LINE for l in pl.run_log_path("eng1").read_text().splitlines()), 3)
        self.assertNotIn("APPSEC_LOG_JOB", os.environ)                         # context cleared after each step

    def test_failure_is_logged_and_still_raised(self) -> None:
        result = failing.execute_in_process(tags={"engagement_run_id": "eng1"}, raise_on_error=False)
        self.assertFalse(result.success)
        failed = [r for r in self.records() if r["level"] == "error"]
        self.assertEqual(len(failed), 1)
        self.assertIn("ValueError: kaput", failed[0]["msg"])

    def test_without_the_run_tag_it_logs_to_the_global_file_and_does_not_break(self) -> None:
        os.environ["APPSEC_PIPELINE_LOG"] = str(Path(self.folder.name) / "g.log")
        self.assertTrue(two_steps.execute_in_process().success)
        pl.flush()
        self.assertTrue((Path(self.folder.name) / "g.log").exists())


if __name__ == "__main__":
    unittest.main()
