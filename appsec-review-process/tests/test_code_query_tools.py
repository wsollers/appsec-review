"""Code index, code_* query tools, tool guides and the per-job tool grant (brief U, ADR-0032)."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import claude_cli_invoker as invoker
import code_index
import code_query_fixture as fx
import code_query_mcp as query
import input_mcp
import tool_guides


class IndexCase(unittest.TestCase):
    treesitter, exports = True, True

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.jobs = Path(self.tmp.name)
        self.ref, self.summary = fx.publish(self.jobs, treesitter=self.treesitter, exports=self.exports)
        self.index = query.CodeIndex(self.jobs, self.ref, self.summary)

    def ask(self, tool, args=None):
        return query.call(self.index, tool, args or {})

    def cites(self, result):
        return [row.get("cite") for row in result["rows"] if row.get("cite")]


class SymbolTests(IndexCase):
    def test_unique_symbol_is_returned_with_its_location(self):
        rows = self.ask("code_symbol", {"name": "main"})["rows"]
        cpg = [row for row in rows if row["source"] == "cpg"]
        self.assertEqual(len(cpg), 1)
        self.assertEqual(cpg[0]["cite"], "app/main.c:3")
        self.assertEqual({row["source"] for row in rows}, {"cpg", "treesitter"})   # both sources are shown, labelled

    def test_overloaded_name_returns_every_candidate(self):
        result = self.ask("code_symbol", {"name": "log_msg"})
        self.assertEqual(len(result["rows"]), 2)
        self.assertEqual(sorted(self.cites(result)), ["app/log.c:1", "lib/log.c:1"])

    def test_locate_finds_enclosing_function_and_reports_a_miss_as_incomplete(self):
        hit = self.ask("code_locate", {"path": "app/parse.c", "line": 9})
        self.assertEqual(hit["rows"][0]["function"], "parse_request")
        miss = self.ask("code_locate", {"path": "nope.c", "line": 1})
        self.assertFalse(miss["complete"])
        self.assertEqual(miss["rows"], [])

    def test_search_finds_names_and_literals(self):
        self.assertTrue(self.ask("code_search", {"text": "parse"})["rows"])
        self.assertEqual(self.ask("code_search", {"text": "zzzzzz"})["rows"], [])


class GraphTests(IndexCase):
    def test_callers_with_an_indirect_call_in_the_graph_is_not_complete(self):
        result = self.ask("code_callers", {"function": "on_message"})
        self.assertFalse(result["complete"])
        self.assertTrue(any(row.get("kind") == "escape" for row in result["rows"]))

    def test_resolved_callers_carry_locations_and_the_escape_is_still_reported(self):
        result = self.ask("code_callers", {"function": "copy_field"})
        self.assertIn("app/parse.c:8", self.cites(result))
        self.assertIn("app/net.c:4", self.cites(result))
        self.assertFalse(result["complete"])

    def test_ambiguous_call_is_not_resolved_silently(self):
        result = self.ask("code_callees", {"function": "cli_main"})
        self.assertFalse(result["complete"])
        self.assertFalse([row for row in result["rows"] if row.get("resolution") == "unique-name"])

    def test_path_to_a_sink_lists_the_path_and_the_escape(self):
        result = self.ask("code_path", {"to": "strcpy"})
        self.assertTrue([row for row in result["rows"] if row.get("kind") == "path"])
        self.assertFalse(result["complete"])

    def test_rows_are_capped_and_flagged_truncated(self):
        with mock.patch.object(query, "limits", return_value={**query.limits(), "rows_max": 1}):
            result = self.ask("code_callers", {"function": "copy_field", "limit": 500})
        self.assertTrue(result["truncated"])
        self.assertFalse(result["complete"])
        self.assertLessEqual(len(result["rows"]), 1)


class NativeTests(IndexCase):
    def test_unsafe_copy_family_lists_call_sites_with_arguments(self):
        result = self.ask("code_calls_to", {"family": "unsafe-copy"})
        self.assertEqual(sorted(self.cites(result)), ["app/parse.c:10", "app/parse.c:22"])
        self.assertFalse(result["complete"])          # macro/indirect calls are never listed by name
        self.assertTrue(any("len" in json.dumps(row) for row in result["rows"]))

    def test_address_taken_is_never_reported_complete(self):
        result = self.ask("code_address_taken")
        self.assertIn("app/parse.c:15", self.cites(result))
        self.assertFalse(result["complete"])

    def test_type_info_and_overrides_admit_the_missing_hierarchy(self):
        self.assertFalse(self.ask("code_type_info", {"type": "Widget"})["complete"])
        self.assertFalse(self.ask("code_overrides", {"method": "draw"})["complete"])


class OutlineAndExportTests(IndexCase):
    def test_outline_lists_functions_calls_and_imports(self):
        result = self.ask("code_file_outline", {"path": "app/main.c"})
        self.assertTrue(result["complete"])
        self.assertGreaterEqual(len(result["rows"]), 3)

    def test_exports_join_to_the_cpg(self):
        result = self.ask("code_exports")
        self.assertEqual(sorted(row["symbol"] for row in result["rows"]), ["log_msg", "parse_request"])


class MissingArtifactTests(IndexCase):
    treesitter, exports = False, False

    def test_capabilities_reflect_what_was_indexed(self):
        self.assertTrue(self.index.capabilities["cpg"])
        self.assertFalse(self.index.capabilities["treesitter"])
        self.assertFalse(self.index.capabilities["exports"])

    def test_outline_without_the_ast_is_a_gap_not_an_empty_answer(self):
        result = self.ask("code_file_outline", {"path": "app/main.c"})
        self.assertFalse(result["complete"])
        self.assertEqual(result["rows"], [])
        self.assertTrue(result["gaps"])


class SanitisingAndIntegrityTests(IndexCase):
    def test_names_are_control_stripped_and_length_capped(self):
        cleaned = code_index.clean("bad\x1b[31mname\n" + "x" * 5000)
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\n", cleaned)
        self.assertLessEqual(len(cleaned), code_index.NAME_LIMIT)

    def test_a_changed_database_is_refused(self):
        database = self.jobs / "02-code-index" / "attempts" / "a1" / code_index.SQLITE
        database.write_bytes(database.read_bytes() + b"x")
        with self.assertRaises(ValueError):
            query.CodeIndex(self.jobs, self.ref, self.summary)

    def test_a_ref_outside_an_accepted_code_index_attempt_is_refused(self):
        with self.assertRaises(ValueError):
            query.CodeIndex(self.jobs, "02-code-index/../x/code-index.json", self.summary)


class GrantTests(unittest.TestCase):
    PROFILE = {"allowed_actions": ["read", "query tool: code_symbol", "query tool: code_callers",
                                   "query tool: code_file_outline", "query tool: code_exports"]}

    def package(self, profile, summary=None, ref=None):
        inputs = []
        if summary is not None:
            inputs.append(SimpleNamespace(root="supporting-evidence", path=ref, data=json.dumps(summary).encode(),
                                          sha256="a" * 64))
        return SimpleNamespace(composition={"tooling_profile": profile}, inputs=tuple(inputs))

    def test_job_without_a_code_index_gets_no_code_tools(self):
        self.assertEqual(invoker.code_query_grant(self.package(self.PROFILE)), (None, ()))

    def test_job_whose_profile_lists_no_code_tools_gets_none_even_with_an_index(self):
        ref = "02-code-index/attempts/a1/code-index.json"
        package = self.package({"allowed_actions": ["read"]}, {"capabilities": {"cpg": True}}, ref)
        self.assertEqual(invoker.code_query_grant(package), (None, ()))

    def test_grant_is_limited_to_what_the_index_can_answer(self):
        ref = "02-code-index/attempts/a1/code-index.json"
        package = self.package(self.PROFILE, {"capabilities": {"cpg": True, "treesitter": False, "exports": False}}, ref)
        with mock.patch.object(query, "family_enabled", return_value=True):
            got_ref, tools = invoker.code_query_grant(package)
        self.assertEqual(got_ref, "supporting-evidence:" + ref)
        self.assertEqual(sorted(tools), ["code_callers", "code_symbol"])

    def test_a_disabled_family_removes_the_tool(self):
        ref = "02-code-index/attempts/a1/code-index.json"
        package = self.package(self.PROFILE, {"capabilities": {"cpg": True, "treesitter": True, "exports": True}}, ref)
        with mock.patch.object(query, "family_enabled", side_effect=lambda family: family != "graph"):
            _, tools = invoker.code_query_grant(package)
        self.assertNotIn("code_callers", tools)
        self.assertIn("code_symbol", tools)

    def test_unknown_tool_in_a_profile_is_an_error(self):
        with self.assertRaises(ValueError):
            query.profile_tools({"allowed_actions": ["query tool: code_nope"]})

    def test_allowed_tools_prompt_guides_and_server_come_from_one_list(self):
        granted = ("code_symbol", "code_callers")
        names = invoker.granted_tool_names(granted)
        argv = invoker._dispatch_argv("sonnet", "high", 1.0, 60, "/usr/bin/claude", Path("mcp.json"), granted)
        allowed = argv[argv.index("--allowedTools") + 1].split(",")
        self.assertEqual(allowed, [f"mcp__{invoker.INPUT_MCP_SERVER}__{name}" for name in names])
        text, used = tool_guides.render(names)
        covered = {tool for guide in tool_guides.catalog() if guide["guide"] in {u["guide"] for u in used}
                   for tool in guide["tools"]}
        self.assertTrue(set(names) <= covered)

    def test_a_job_without_code_tools_keeps_exactly_the_base_tools(self):
        self.assertEqual(invoker.granted_tool_names(()), [tool["name"] for tool in input_mcp.BASE_TOOLS])


class GuideTests(unittest.TestCase):
    def test_every_base_and_code_tool_has_a_guide(self):
        every = [tool["name"] for tool in input_mcp.BASE_TOOLS] + list(query.NAMES)
        tool_guides.select(every)             # raises when a tool has no guide

    def test_a_guide_is_included_only_for_a_granted_tool(self):
        text, used = tool_guides.render(["code_symbol"])
        self.assertIn("code_symbol", text)
        self.assertNotIn("code_exports", text)
        self.assertTrue(all(row["sha256"].startswith("sha256:") for row in used))

    def test_a_granted_tool_without_a_guide_is_an_error(self):
        with self.assertRaises(ValueError):
            tool_guides.select(["code_no_such_tool"])

    def test_guides_tell_the_model_results_are_untrusted(self):
        text, _ = tool_guides.render(["code_callers"])
        self.assertIn("untrusted", text)
        self.assertIn("complete=false", text)


class DependencyReachabilityTreesitterTests(unittest.TestCase):
    def test_no_accepted_job_means_no_binding(self):
        import dep_reachability_lifecycle as life
        from unittest import mock
        with mock.patch.object(life, "_accepted", return_value=(None, "engine-input-absent:02-treesitter-ast")):
            self.assertIsNone(life._treesitter_job("run", "sha256:x"))

    def test_accepted_job_is_bound_when_it_has_records(self):
        import dep_reachability_lifecycle as life
        from unittest import mock
        binding = {"attempt_id": "a1", "accepted_pointer_sha256": "sha256:p", "result_sha256": "sha256:r"}
        with mock.patch.object(life, "_accepted", return_value=(binding, None)), \
             mock.patch.object(life, "read_json", return_value={"records_file": {"path": "r"}}):
            self.assertEqual(life._treesitter_job("run", "sha256:x"), binding)
        with mock.patch.object(life, "_accepted", return_value=(binding, None)), \
             mock.patch.object(life, "read_json", return_value={"records_file": None}):
            self.assertIsNone(life._treesitter_job("run", "sha256:x"))


if __name__ == "__main__":
    unittest.main()
