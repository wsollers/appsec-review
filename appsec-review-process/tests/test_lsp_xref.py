"""02-lsp-xref precompute (rows, budget gap, replay) and the code_* language-server MCP tools."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

PROCESS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROCESS))

import code_index  # noqa: E402
import code_query_mcp  # noqa: E402
import input_mcp  # noqa: E402
import lsp_service  # noqa: E402
import lsp_xref_job  # noqa: E402
from schema_validate import validate_document  # noqa: E402
from tests import lsp_fakes as fakes  # noqa: E402

LSP_TOOLS = ["code_definition", "code_references", "code_hover", "code_call_hierarchy"]


def code_index_db() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.executescript(code_index.DDL)
    for path in ("main.py", "util.py"):
        connection.execute("INSERT INTO files VALUES(?,?,?,?)", (path, None, "python", "cpg+treesitter"))
    connection.execute("INSERT INTO files VALUES(?,?,?,?)", ("data.json", None, "json", "treesitter"))
    rows = [(1, "main.py:helper", "helper", "helper", "main.py", 1, 2), (2, "main.py:main", "main", "main", "main.py", 5, 6),
            (3, "util.py:tool", "tool", "tool", "util.py", 1, 2)]
    for ident, full, name, qualified, path, start, end in rows:
        connection.execute("INSERT INTO methods VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                           (ident, full, name, qualified, None, path, start, end, "treesitter", 0, "python", None))
    connection.execute("INSERT INTO methods VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       (9, "print", "print", "print", None, None, None, None, "cpg-first-line", 1, "python", None))
    return connection


class Case(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.tmp = Path(temp.name).resolve()
        self.root = fakes.write_project(self.tmp / "checkout")
        self.base = self.tmp / "lsp"
        self.launcher = fakes.FakeLauncher()
        self.spawn = fakes.ThreadSpawner(self.launcher)
        self.addCleanup(self.spawn.shutdown)
        self.server = fakes.python_spec(self.root)

    def broker(self, **kwargs) -> lsp_service.Broker:
        kwargs.setdefault("launcher", self.launcher)
        kwargs.setdefault("spawn", self.spawn)
        return lsp_service.Broker("run-1", self.base, [self.server], **kwargs)

    def build(self, database: Path, *, max_queries: int = 1000, broker=None, gaps=()) -> dict:
        return lsp_xref_job.build(database, index=code_index_db(), target=self.root,
                                  servers=[self.server], native_units=None, broker=broker or self.broker(),
                                  max_queries=max_queries, input_gaps=list(gaps))


class Precompute(Case):
    def test_rows_for_every_function_tagged_with_server_and_variant(self):
        summary = self.build(self.tmp / "x.sqlite")
        self.assertEqual(summary["counts"]["functions"], 3)
        self.assertEqual(summary["counts"]["asked"], 3)
        self.assertEqual(summary["counts"]["queries"], 12)
        self.assertEqual(self.launcher.starts, 1)
        db = sqlite3.connect(self.tmp / "x.sqlite")
        self.assertEqual(db.execute("SELECT status FROM lsp_functions ORDER BY id").fetchall(), [("ok",)] * 3)
        self.assertEqual(db.execute("SELECT path, start_line, start_character, server_key, variant FROM lsp_definitions "
                                    "WHERE function_id=2").fetchall(), [("main.py", 5, 4, "python", "default")])
        # the out-of-root reference is dropped, the two in-root ones kept
        self.assertEqual(db.execute("SELECT COUNT(*) FROM lsp_references WHERE function_id=1").fetchone()[0], 2)
        self.assertEqual(sorted(db.execute("SELECT direction, peer_name FROM lsp_calls WHERE function_id=1").fetchall()),
                         [("incoming", "caller"), ("outgoing", "callee")])
        self.assertEqual(db.execute("SELECT server, server_version, image_digest FROM lsp_servers").fetchall(),
                         [("pylsp", "1.2", fakes.IMAGE["digest"])])
        self.assertEqual(db.execute("SELECT path, server_key FROM lsp_files ORDER BY path").fetchall(),
                         [("main.py", "python"), ("util.py", "python")])
        self.assertEqual(summary["capabilities"]["lsp"], True)

    def test_budget_overflow_is_a_gap_not_a_silent_cut(self):
        summary = self.build(self.tmp / "x.sqlite", max_queries=4)
        self.assertEqual(summary["counts"]["asked"], 1)
        gap = next(gap for gap in summary["gaps"] if gap["kind"] == "lsp-budget-exceeded")
        self.assertIn("2 function(s) not precomputed", gap["detail"])
        db = sqlite3.connect(self.tmp / "x.sqlite")
        self.assertEqual([row[0] for row in db.execute("SELECT status FROM lsp_functions ORDER BY id")],
                         ["ok", "budget", "budget"])

    def test_replay_rebuilds_the_same_rows_without_a_server(self):
        first = self.build(self.tmp / "a.sqlite")
        replay = lsp_service.Broker("run-1", self.base, [self.server], replay_only=True)
        second = self.build(self.tmp / "b.sqlite", broker=replay)
        self.assertEqual(second["content_sha256"], first["content_sha256"])
        self.assertEqual(second, first)
        self.assertEqual(replay.stats["replayed"], 12)
        self.assertEqual(self.launcher.starts, 1)

    def test_unresolved_includes_and_readiness_gaps_are_published(self):
        self.launcher.diagnostics = True
        summary = self.build(self.tmp / "x.sqlite", gaps=[{"kind": "lsp-not-ready",
                                                          "detail": "lsp-not-ready: no compile_commands"}])
        kinds = {gap["kind"] for gap in summary["gaps"]}
        self.assertTrue({"lsp-unresolved-includes", "lsp-not-ready"} <= kinds, kinds)

    def test_a_server_that_never_starts_leaves_gaps_and_no_rows(self):
        self.launcher.fail = 9
        summary = self.build(self.tmp / "x.sqlite")
        self.assertEqual(self.launcher.starts, 2)
        self.assertIn("lsp-server-failed", {gap["kind"] for gap in summary["gaps"]})
        self.assertEqual(summary["counts"]["definitions"], 0)
        db = sqlite3.connect(self.tmp / "x.sqlite")
        self.assertEqual({row[0] for row in db.execute("SELECT status FROM lsp_functions")}, {"partial"})
        # the failure is recorded too: a replay (the validator) reproduces the same gaps without a server
        replay = lsp_service.Broker("run-1", self.base, [self.server], replay_only=True)
        self.assertEqual(self.build(self.tmp / "y.sqlite", broker=replay), summary)


class Languages(Case):
    def test_census_list_is_optional_and_the_code_index_is_the_fallback(self):
        self.assertEqual(lsp_xref_job.index_files(code_index_db()),
                         {"main.py": "python", "util.py": "python", "data.json": "json"})
        self.assertIsNone(lsp_xref_job.census_languages({"schema": "x"}))
        census = {"languages_needing_server": ["cpp", {"language": "go"}], "languages": [
            {"language": "cpp", "files": 7}, {"language": "go", "files": 2}, {"language": "markdown", "files": 9}]}
        self.assertEqual(lsp_xref_job.census_languages(census), {"cpp": 7, "go": 2})
        (self.root / "go.mod").write_text("module x\n")
        (self.root / "vendor" / "dep").mkdir(parents=True)
        (self.root / "vendor" / "dep" / "go.mod").write_text("module y\n")
        inputs = lsp_service.build_inputs(self.root, lambda path: path.startswith("vendor/"))
        self.assertEqual(inputs, ["go.mod"])
        plan = lsp_service.server_plan({"cpp": 7, "go": 2, "python": 3, "bash": 1}, inputs)
        self.assertEqual([(row["server_key"], row["build_inputs"]) for row in plan],
                         [("cpp", []), ("go", ["go.mod"]), ("python", [])])


class Tools(Case):
    def publish(self) -> tuple[Path, str, dict]:
        jobs = self.tmp / "jobs"
        attempt = jobs / "02-lsp-xref" / "attempts" / "a1"
        attempt.mkdir(parents=True)
        summary = self.build(attempt / "lsp-xref.sqlite")
        document = {"schema": lsp_xref_job.SCHEMA, "run_id": "run-1", "job_id": lsp_xref_job.JOB,
                    "source_snapshot_sha256": fakes.SNAPSHOT, "status": "OK_WITH_GAPS" if summary["gaps"] else "OK",
                    "inputs": {"census": {}, "code_index": {}, "native_build": None},
                    "servers": [{**self.server["identity"], "identity_sha256": self.server["identity_sha256"],
                                 "build_input": self.server["build_input"], "spec": self.server}],
                    **summary, "claim_boundary": "STRUCTURAL_RETRIEVAL_NOT_FINDING_OR_RUNTIME_PROOF",
                    "sqlite": {"path": "lsp-xref.sqlite", "sha256": lsp_service._file_sha(attempt / "lsp-xref.sqlite"),
                               "bytes": (attempt / "lsp-xref.sqlite").stat().st_size}}
        self.assertEqual(validate_document(document, lsp_xref_job.SCHEMA_FILE), [])
        return jobs, "02-lsp-xref/attempts/a1/lsp-xref.json", document

    def index(self) -> code_query_mcp.LspIndex:
        jobs, ref, document = self.publish()
        return code_query_mcp.LspIndex("run-1", jobs, ref, document, broker=self.broker())

    def test_definition_and_callers_come_from_precomputed_rows(self):
        index = self.index()
        starts = self.launcher.starts
        definition = code_query_mcp.call(None, "code_definition", {"function": "main"}, lsp=index)
        self.assertTrue(definition["complete"], definition["reasons"])
        self.assertEqual([(row["path"], row["start_line"], row["via"]) for row in definition["rows"]],
                         [("main.py", 5, "precomputed")])
        self.assertEqual(definition["source"]["producer_job"], "02-lsp-xref")
        callers = code_query_mcp.call(None, "code_call_hierarchy", {"function": "helper", "direction": "incoming"},
                                      lsp=index)
        self.assertEqual([row["name"] for row in callers["rows"]], ["caller"])
        refs = code_query_mcp.call(None, "code_references", {"path": "main.py", "line": 1}, lsp=index)
        self.assertEqual(len(refs["rows"]), 2)
        self.assertEqual(self.launcher.starts, starts)   # answered without touching a server

    def test_hover_goes_live_once_then_replays_the_recording(self):
        index = self.index()
        first = code_query_mcp.call(None, "code_hover", {"path": "util.py", "line": 1, "symbol": "tool"}, lsp=index)
        self.assertEqual([row["via"] for row in first["rows"]], ["live"])
        self.assertIn("util.py:1", first["rows"][0]["text"])
        again = code_query_mcp.call(None, "code_hover", {"path": "util.py", "line": 1, "symbol": "tool"}, lsp=index)
        self.assertEqual(again["rows"][0]["via"], "recorded")
        self.assertEqual(again["rows"][0]["text"], first["rows"][0]["text"])

    def test_calls_per_cell_are_bounded(self):
        index = self.index()
        with mock.patch.object(code_query_mcp.tunables, "shared",
                               side_effect=lambda name: 2 if name == "code_query_lsp_calls_max" else
                               {"code_query_rows_default": 20, "code_query_rows_max": 200, "code_query_depth_max": 4,
                                "code_query_path_depth_max": 24, "code_query_paths_max": 10,
                                "code_query_path_nodes_max": 50000}[name]):
            code_query_mcp.call(None, "code_definition", {"function": "main"}, lsp=index)
            code_query_mcp.call(None, "code_definition", {"function": "main"}, lsp=index)
            with self.assertRaisesRegex(ValueError, "call budget"):
                code_query_mcp.call(None, "code_definition", {"function": "main"}, lsp=index)

    def test_a_database_that_changed_is_refused(self):
        jobs, ref, document = self.publish()
        document = {**document, "sqlite": {**document["sqlite"], "sha256": "sha256:" + "0" * 64}}
        with self.assertRaisesRegex(ValueError, "does not match"):
            code_query_mcp.LspIndex("run-1", jobs, ref, document)

    def test_grant_needs_the_profile_the_family_and_a_pinned_xref(self):
        profile = {"allowed_actions": ["query tool: code_symbol"] + [f"query tool: {name}" for name in LSP_TOOLS]}
        self.assertEqual(code_query_mcp.grantable(profile, {"cpg": True}, {"lsp": True}), ["code_symbol", *LSP_TOOLS])
        self.assertEqual(code_query_mcp.grantable(profile, {"cpg": True}, None), ["code_symbol"])
        self.assertEqual(code_query_mcp.grantable(profile, None, {"lsp": True}), [])
        ref = "supporting-evidence:02-lsp-xref/attempts/a1/lsp-xref.json"
        self.assertEqual(code_query_mcp.lsp_summary_ref([ref, "supporting-evidence:x.json"]), ref)
        for name in ("hypothesis-hunt-static", "claim-review-static", "owasp-participation-static"):
            profile = json.loads((PROCESS / "pipeline" / "tooling-profiles" / f"{name}.json").read_text())
            self.assertEqual([tool for tool in code_query_mcp.profile_tools(profile) if tool in LSP_TOOLS], LSP_TOOLS,
                             name)

    def test_input_server_registers_and_serves_the_tools(self):
        input_mcp.grant("supporting-evidence:02-code-index/attempts/a1/code-index.json", LSP_TOOLS)
        self.addCleanup(input_mcp.grant, None, [])
        self.assertEqual([tool["name"] for tool in input_mcp.SERVED][-4:], LSP_TOOLS)
        input_mcp.CODE["lsp"] = self.index()
        result = input_mcp.call("run-1", None, "code_definition", {"function": "tool"})
        self.assertEqual([(row["path"], row["start_line"]) for row in result["rows"]], [("util.py", 1)])

    def test_lsp_calls_are_audited_and_counted_by_the_retrieval_report(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("retrieval_report", PROCESS.parent / "orchestrator" / "retrieval-report.py")
        report = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(report)
        input_mcp.grant("supporting-evidence:02-code-index/attempts/a1/code-index.json", LSP_TOOLS)
        self.addCleanup(input_mcp.grant, None, [])
        input_mcp.CODE["lsp"] = self.index()
        runs = self.tmp / "runs"
        with mock.patch.object(input_mcp, "data_path", side_effect=lambda run, *p: runs.joinpath(run, "data", *p)), \
                mock.patch.dict(input_mcp.CONTEXT, {"job_id": "j", "attempt_id": "a"}, clear=True), \
                mock.patch.dict(input_mcp.USAGE, {}, clear=True), mock.patch.dict(input_mcp.BUDGET, {"max": None}), \
                mock.patch.object(report, "RUNS", runs):
            for arguments in ({"function": "main"}, {"path": "nowhere.py", "line": 1}):
                answer = input_mcp.handle("run-1", None, {"method": "tools/call", "params": {
                    "name": "code_definition", "arguments": arguments}})
                self.assertFalse(answer["isError"])
            summary = report.summarize(report.load("run-1"))
        self.assertEqual(len(list((runs / "run-1" / "data" / "retrieval").glob("*/result.json"))), 2)
        self.assertEqual(summary["tools"]["code_definition"]["calls"], 2)
        self.assertEqual(summary["families"]["code_lsp"]["calls"], 2)
        self.assertEqual(summary["lsp"]["failed"], 1)   # the path no language server serves


if __name__ == "__main__":
    unittest.main()
