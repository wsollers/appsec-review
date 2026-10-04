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

    def call(self, job, attempt, tool, *, hits=1, refs=(), error=None, output_root=None, arguments=None, **result):
        self.serial += 1
        folder = self.data / "retrieval" / f"{self.serial:032x}"
        folder.mkdir(parents=True)
        request = {"time": f"2026-10-04T10:00:{self.serial % 60:02d}Z", "tool": tool, "arguments": arguments or {},
                   "job_id": job, "attempt_id": attempt, **({"output_root": str(output_root)} if output_root else {})}
        (folder / "request.json").write_text(json.dumps(request))
        if error:
            (folder / "error.json").write_text(json.dumps({"error": error}))
        else:
            (folder / "result.json").write_text(json.dumps({"hits": hits, "refs": list(refs), "bytes": 10, **result}))

    def invocation(self, job, attempt, granted, usage=None, feedback=None, cap=40, **grant):
        folder = self.data / "llm-transcripts" / job / attempt
        folder.mkdir(parents=True)
        (folder / "tool-grant.json").write_text(json.dumps({"tools": granted, "code_index": None,
                                                            "max_tool_calls_per_cell": cap, **grant}))
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


class Diagnose(unittest.TestCase):
    """--diagnose and citation backing on a run shaped like hello-autotools 20261004T054551Z-357581: a threat-model
    cell cites the file it was given (pinned, never fetched), files it looked at under another path form, a target
    file it never looked at and an invented one; evidence_read fails on a bare path, an upstream ref and a large
    limit; clangd never starts (image without a B16 record)."""
    JOB = "03-threat-model-dfd-stride"

    def setUp(self):
        import sqlite3
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.runs = Path(temp.name)
        patch = mock.patch.object(report, "RUNS", self.runs)
        patch.start()
        self.addCleanup(patch.stop)
        data = self.runs / "run-d" / "data"
        attempt = data / "jobs" / self.JOB / "attempts" / "w1" / "cells" / "c1"
        output = attempt / "outputs" / "persona"
        output.mkdir(parents=True)
        (attempt / "logs" / "persona").mkdir(parents=True)
        (attempt / "logs" / "persona" / "request.json").write_text(json.dumps({
            "output_root": "outputs/persona", "log_path": "logs/persona", "readable_inputs": [
                {"root": "target-repository", "path": "src/hello.c", "sha256": "sha256:" + "1" * 64},
                {"root": "workbench-bundle", "path": "base.json", "sha256": "sha256:" + "2" * 64}]}))
        (output / "result.json").write_text(json.dumps({"threats": [
            {"evidence_citations": [{"path": "src/hello.c", "line_range": "3-5"}, {"path": "src/invented.c"}]},
            {"evidence_citations": ["target-repository:src/main.c:12", "src/parse.c#L40", "./src/util.c"]},
            {"claim": {"citation_ids": ["c1", "c2"]}}]}))
        index = data / "jobs" / "02-evidence-index" / "whole"
        (index / "attempts" / "e1").mkdir(parents=True)
        (index / "accepted.json").write_text(json.dumps({"status": "OK", "attempt_id": "e1"}))
        db = sqlite3.connect(index / "attempts" / "e1" / "index.sqlite")
        db.execute("CREATE TABLE files(path TEXT PRIMARY KEY)")
        db.executemany("INSERT INTO files VALUES (?)", [(f"source/src/{n}.c",) for n in ("hello", "main", "util", "parse")])
        db.commit(); db.close()
        lsp = data / "lsp"
        (lsp / "failures").mkdir(parents=True)
        (lsp / "failures" / "cpp-default.json").write_text(json.dumps({"lock": "cpp-default", "attempts": 2, "at": "t",
            "error": "RuntimeError: audit-buildenv-cpp has no current B16 record with the bound digest"}))
        (lsp / "recordings" / "ab").mkdir(parents=True)
        (lsp / "recordings" / "ab" / "ab12.json").write_text(json.dumps({"method": "hover", "params": {"path": "src/main.c", "line": 3},
            "response": {"status": "GAP", "gaps": [{"kind": "lsp-server-failed", "detail": "clangd failed to start 2 time(s)"}]}}))
        xref = data / "jobs" / "02-lsp-xref"
        (xref / "attempts" / "l1").mkdir(parents=True)
        (xref / "accepted.json").write_text(json.dumps({"attempt_id": "l1"}))
        (xref / "attempts" / "l1" / "lsp-xref.json").write_text(json.dumps({"status": "OK_WITH_GAPS", "counts": {"asked": 0},
            "inputs": {"native_build": {"attempt_id": "n1"}},
            "servers": [{"server_key": "cpp", "variant": "autotools-default", "server": "clangd", "image_id": "audit-buildenv-cpp",
                         "image_digest": "sha256:" + "9" * 64, "build_input": {"kind": "compile_commands", "unit_id": "dir:."}}],
            "gaps": [{"kind": "lsp-server-failed", "detail": "cpp/autotools-default: lsp-server-failed: clangd failed to start"}]}))
        tree = Tree(self.runs, "run-d")
        tree.invocation(self.JOB, "t1", BASE + ["evidence_read", "code_callers", "code_hover"], {},
                        output_root=str(output), input_mode="inline+tools")
        tree.call(self.JOB, "t1", "input_read", refs=["target-repository:src/main.c"], arguments={"ref": "target-repository:src/main.c"})
        tree.call(self.JOB, "t1", "code_callers", refs=["src/parse.c:40"], arguments={"function": "parse"})
        tree.call(self.JOB, "t1", "evidence_read", error="path is not in the accepted index", arguments={"path": "src/hello.c"})
        tree.call(self.JOB, "t1", "evidence_read", error="path is not in the accepted index",
                  arguments={"path": "upstream-artifacts:outputs/component-map.json"})
        tree.call(self.JOB, "t1", "evidence_read", error="query bounds: see shared tunables evidence_query_results_max/"
                  "evidence_query_text_max", arguments={"path": "source/src/main.c", "limit": 200})
        tree.call(self.JOB, "t1", "evidence_read", refs=["source/src/main.c"], arguments={"path": "source/src/main.c"})
        tree.call(self.JOB, "t1", "code_hover", hits=0, complete=False, arguments={"path": "src/main.c", "line": 3},
                  reasons=["lsp-not-ready: no ready clangd (audit-buildenv-cpp) for c file src/main.c: lsp-not-ready: "
                           "no compile_commands (native-build-skipped)"])

    def test_pinned_inputs_and_normalized_paths_back_citations(self):
        cites = report.summarize(report.load("run-d"))["jobs"][self.JOB]["citations"]
        # Measured before this change: 0 of 5 backed (target-repository:...:12 and #L40 never matched the refs
        # read/surfaced, and the pinned file did not count).
        self.assertEqual((cites["cited"], cites["tool_backed"], cites["pinned_backed"], cites["unbacked"]), (5, 2, 1, 2))
        self.assertEqual((cites["backed"], cites["backed_rate"], cites["cited_ids"]), (3, 0.6, 2))
        self.assertEqual(cites["pinned_inputs_found"], 1)

    def test_path_forms_normalize_to_one(self):
        for ref in ("src/a.c", "target-repository:src/a.c", "target:src/a.c:12", "source/src/a.c", "./src/a.c",
                    "src/a.c#L3-L9", "/workspace/src/a.c", "/runs/r/data/jobs/02-evidence-index/whole/x/source/src/a.c",
                    "src/a.c:3-9", "target-repository:source/src/a.c:3"):
            self.assertEqual(report.norm(ref), "src/a.c", ref)
        self.assertEqual(report.norm("upstream-artifacts:outputs/m.json"), "upstream:outputs/m.json")
        self.assertEqual(report.norm("workbench-bundle:base.json"), "workbench-bundle:base.json")

    def test_diagnose_groups_errors_shapes_lsp_and_unbacked_citations(self):
        d = report.diagnose("run-d", report.load("run-d"))
        errors = d["errors"]["evidence_read"]
        self.assertEqual((errors["calls"], errors["errors"]), (4, 3))
        self.assertEqual((errors["causes"][0]["count"], len(errors["causes"][0]["examples"])), (2, 2))
        shapes = d["evidence_read"]["shapes"]
        self.assertEqual(shapes["bare repository path"]["errors"], 1)
        self.assertEqual(shapes["other root ref (upstream-artifacts:)"]["errors"], 1)
        self.assertEqual((shapes["source/ prefix (index form)"]["calls"], shapes["source/ prefix (index form)"]["errors"]), (2, 1))
        self.assertEqual(d["evidence_read"]["limit_over_window"], {"calls": 1, "errors": 1})
        self.assertEqual((d["evidence_read"]["failed_paths_naming_a_target_file"], d["evidence_read"]["failed_paths"]), (2, 3))
        lsp = d["lsp"]
        self.assertIn("B16 record", lsp["failures"][0]["error"])
        self.assertEqual(lsp["xref"]["servers"][0]["image_id"], "audit-buildenv-cpp")
        self.assertEqual(lsp["recorded_gaps"][0]["count"], 1)
        self.assertIn("lsp-not-ready", lsp["tool_reasons"][0]["cause"])
        self.assertIn("no compile_commands", lsp["tool_reasons"][0]["cause"])
        job = d["citations"][self.JOB]
        self.assertEqual(job["classes"], {"normalization-mismatch": 2, "pinned-inline": 1,
                                          "present-in-target-but-not-read": 1, "not-in-target": 1})
        self.assertEqual(job["input_modes"], {"inline+tools": 1})
        self.assertEqual({e["cited"]: e["class"] for e in job["examples"]}, {
            "src/hello.c": "pinned-inline", "src/invented.c": "not-in-target", "./src/util.c": "present-in-target-but-not-read",
            "target-repository:src/main.c:12": "normalization-mismatch", "src/parse.c#L40": "normalization-mismatch"})

    def test_cli_diagnose_prints_data_and_exits_zero(self):
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["retrieval-report.py", "run-d", "--diagnose"]), contextlib.redirect_stdout(out):
            self.assertEqual(report.main(), 0)
        printed = out.getvalue()
        for needle in ("evidence_read: 3 of 4 call(s) failed", "bare repository path", "start failure cpp-default x2",
                       "[pinned-inline] 'src/hello.c'", "[not-in-target] 'src/invented.c'", "cited by id 2"):
            self.assertIn(needle, printed)
        raw = io.StringIO()
        with mock.patch.object(sys, "argv", ["retrieval-report.py", "run-d", "--diagnose", "--json"]), \
                contextlib.redirect_stdout(raw):
            report.main()
        self.assertIn("citations", json.loads(raw.getvalue())["diagnose"])


if __name__ == "__main__":
    unittest.main()
