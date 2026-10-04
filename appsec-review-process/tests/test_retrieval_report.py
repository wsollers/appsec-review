"""orchestrator/retrieval-report.py --summary / --compare / --feedback / --check over a fixture run tree."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[2]


def _module(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO / "orchestrator" / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


report = _module("retrieval_report", "retrieval-report.py")
run_status = _module("run_status", "run-status.py")
BASE = ["input_list", "input_read", "input_grep", "evidence_search"]


class Tree:
    """Writes a run's retrieval audits, tool grants/usage and feedback the way input_mcp and the invoker do."""

    def __init__(self, runs: Path, run: str):
        self.data = runs / run / "data"
        self.serial = 0

    def call(self, job, attempt, tool, *, hits=1, refs=(), error=None, output_root=None, **result):
        self.serial += 1
        folder = self.data / "retrieval" / f"{self.serial:032x}"
        folder.mkdir(parents=True)
        request = {"time": f"2026-10-04T10:00:{self.serial % 60:02d}Z", "tool": tool, "arguments": {},
                   "job_id": job, "attempt_id": attempt, **({"output_root": str(output_root)} if output_root else {})}
        (folder / "request.json").write_text(json.dumps(request))
        if error:
            (folder / "error.json").write_text(json.dumps({"error": error}))
        else:
            (folder / "result.json").write_text(json.dumps({"hits": hits, "refs": list(refs), "bytes": 10, **result}))

    def invocation(self, job, attempt, granted, usage=None, feedback=None, cap=40):
        folder = self.data / "llm-transcripts" / job / attempt
        folder.mkdir(parents=True)
        (folder / "tool-grant.json").write_text(json.dumps({"tools": granted, "code_index": None,
                                                            "max_tool_calls_per_cell": cap}))
        if usage is not None:
            (folder / "tool-usage.json").write_text(json.dumps(usage))
        if feedback is not None:
            (folder / "tooling-feedback.json").write_text(json.dumps(feedback))


class Report(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.runs = Path(temp.name)
        patch = mock.patch.object(report, "RUNS", self.runs)
        patch.start()
        self.addCleanup(patch.stop)
        self.output = self.runs / "out-j1"
        self.output.mkdir()
        (self.output / "result.json").write_text(json.dumps(
            {"findings": [{"citations": [{"path": "src/a.c"}, {"path": "src/b.c"}]}]}))
        a = Tree(self.runs, "run-a")
        granted = BASE + ["code_symbol", "code_definition"]
        a.invocation("j1", "a1", granted, {"input_read": 5, "evidence_search": 10, "code_definition": 2},
                     {"useful_tools": ["input_read"], "unhelpful_tools": [{"tool": "evidence_search", "reason": "noisy"}],
                      "wanted": [{"kind": "query", "what": "Call graph of callers", "why": "trace input"}],
                      "coverage_confidence": "low", "would_change": "x" * 300})
        a.invocation("j1", "a2", granted, {"input_read": 1, "_budget_exhausted": 2},
                     {"wanted": [{"kind": "query", "what": "call graph of  callers."}], "coverage_confidence": "low"})
        a.invocation("j2", "b1", BASE, {}, {"coverage_confidence": "high"})
        for i in range(5):
            a.call("j1", "a1", "input_read", refs=["target:src/a.c"], output_root=self.output,
                   error="boom" if i == 0 else None)
        for i in range(10):
            a.call("j1", "a1", "evidence_search", hits=0 if i < 6 else 2, refs=[] if i < 6 else ["src/c.c"],
                   truncated=i == 9)
        for _ in range(2):
            a.call("j1", "a1", "code_definition", hits=0, complete=False,
                   reasons=["lsp-not-ready: no ready language server serves x.c"])
        a.call("j1", "a2", "input_read", refs=["target:src/a.c"], output_root=self.output)
        b = Tree(self.runs, "run-b")
        b.invocation("j1", "c1", BASE, {"input_read": 1})
        b.call("j1", "c1", "input_read", refs=["target:src/a.c"])
        clean = Tree(self.runs, "run-clean")
        clean.invocation("j1", "d1", ["input_read"], {"input_read": 1}, {"coverage_confidence": "high"})
        clean.call("j1", "d1", "input_read", refs=["target:src/a.c"])

    def summary(self, run="run-a"):
        return report.summarize(report.load(run))

    def test_summary_percentages(self):
        s = self.summary()
        self.assertEqual((s["served_invocations"], s["used_invocations"]), (3, 2))
        self.assertAlmostEqual(s["used_rate"], 0.6667)
        self.assertEqual(s["jobs"]["j1"]["used_rate"], 1.0)
        self.assertEqual(s["jobs"]["j2"]["used_rate"], 0.0)
        self.assertEqual(s["jobs"]["j2"]["granted_unused"], {t: 1 for t in BASE})
        self.assertEqual(s["jobs"]["j1"]["granted_unused"]["code_symbol"], 2)
        fam = s["families"]
        self.assertEqual((fam["input"]["granted_invocations"], fam["input"]["used_invocations"]), (3, 2))
        self.assertEqual((fam["input"]["calls"], fam["input"]["errors"]), (6, 1))
        self.assertEqual((fam["evidence"]["empty_rate"], fam["evidence"]["truncation_rate"]), (0.6, 0.1))
        self.assertEqual((fam["code_structural"]["granted_invocations"], fam["code_structural"]["calls"]), (2, 0))
        self.assertEqual(fam["code_lsp"]["used_rate"], 0.5)
        self.assertEqual(s["lsp"], {"granted": 2, "calls": 2, "failed": 2})
        self.assertEqual(s["cap_exhausted"], [{"job": "j1", "attempt": "a2", "refused": 2, "cap": 40}])
        cites = s["jobs"]["j1"]["citations"]
        self.assertEqual((cites["cited"], cites["backed"], cites["unbacked"], cites["backed_rate"]), (4, 2, 2, 0.5))
        self.assertIsNone(s["jobs"]["j2"]["citations"])

    def test_compare_deltas(self):
        deltas = report.compare(self.summary("run-a"), self.summary("run-b"))
        self.assertEqual(deltas["used_rate"], [0.6667, 1.0, -0.3333])
        self.assertEqual(deltas["served_invocations"], [3, 1, 2])
        self.assertEqual(deltas["families"]["input"]["calls"], [6, 1, 5])
        self.assertEqual(deltas["jobs"]["j2"]["used_rate"], [0.0, None, None])
        self.assertEqual(deltas["cap_exhausted"], [1, 0, 1])

    def test_feedback_aggregation_beside_the_measured_numbers(self):
        f = report.feedback(report.load("run-a"))
        j1 = f["j1"]
        self.assertEqual((j1["invocations"], j1["with_feedback"], j1["coverage_confidence"]), (2, 2, {"low": 2}))
        self.assertEqual(len(j1["wanted"]), 1)   # normalized and deduplicated
        wanted = j1["wanted"][0]
        self.assertEqual(wanted["count"], 2)
        self.assertIn("code_callers: not granted", wanted["measured"])
        self.assertEqual(j1["useful"]["input_read"]["measured"], "input_read: 6 calls, 0% empty, 17% errors")
        self.assertIn("60% empty", j1["unhelpful"]["evidence_search"]["measured"])
        self.assertLessEqual(len(j1["would_change"][0]), report.TEXT_MAX)
        self.assertEqual(f["j2"]["coverage_confidence"], {"high": 1})

    def test_model_text_is_flattened_and_truncated(self):
        self.assertEqual(report.text("a\nb\x1b[31m"), "a b [31m")
        self.assertEqual(len(report.text("y" * 999)), report.TEXT_MAX)

    def test_every_check_rule_fires_on_the_bad_run(self):
        loaded = report.load("run-a")
        rules = {rule for rule, _ in report.check(report.summarize(loaded), report.feedback(loaded))}
        self.assertEqual(rules, {"family-unused", "empty-rate", "error-rate", "cap-exhausted", "citation-backing",
                                 "lsp-down", "low-confidence"})

    def test_clean_run_passes_and_an_empty_run_is_a_gap(self):
        loaded = report.load("run-clean")
        self.assertEqual(report.check(report.summarize(loaded), report.feedback(loaded)), [])
        (self.runs / "run-empty" / "data").mkdir(parents=True)
        loaded = report.load("run-empty")
        self.assertEqual([r for r, _ in report.check(report.summarize(loaded), report.feedback(loaded))], ["no-evidence"])

    def main(self, *argv):
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["retrieval-report.py", *argv]), contextlib.redirect_stdout(out):
            code = report.main()
        return code, out.getvalue()

    def test_cli_modes_and_exit_codes(self):
        code, text = self.main("run-a", "--check")
        self.assertEqual(code, 1)
        self.assertIn("[lsp-down]", text)
        self.assertEqual(self.main("run-clean", "--check")[0], 0)
        code, text = self.main("run-a", "--summary", "--json", "--compare", "run-b")
        doc = json.loads(text)
        self.assertEqual((code, doc["compare"]["other_run_id"]), (0, "run-b"))
        code, text = self.main("run-a", "--summary", "--feedback", "--compare", "run-b")
        self.assertIn("== compare run-a vs run-b", text)
        self.assertIn("wanted    query: 'Call graph of callers'", text)
        code, text = self.main("run-a")   # the per-invocation default is unchanged
        self.assertIn("== j1  attempt a1", text)
        self.assertIn("cited paths 2: backed by a read/search 1 (50%)", text)

    def test_run_status_tooling_prints_findings_and_never_fails(self):
        repo = self.runs / "repo"
        (repo / "appsec-review-process").mkdir(parents=True)
        (repo / "appsec-review-process" / "runs").symlink_to(self.runs)
        (self.runs / "run-a" / "data" / "jobs" / "j1").mkdir(parents=True)
        out = io.StringIO()
        with mock.patch.object(run_status, "REPO", repo), contextlib.redirect_stdout(out), \
                mock.patch.object(sys, "argv", ["run-status.py", "run-a", "--tooling"]):
            code = run_status.main()
        self.assertEqual(code, 0)
        self.assertIn("tooling check: 7 finding(s)", out.getvalue())
        self.assertIn("[cap-exhausted] j1 attempt a2", out.getvalue())


if __name__ == "__main__":
    unittest.main()
