"""Code tools for component characterization, the threat model and the OWASP validator (gap 5).

Their tooling profiles grant the read-only ``code_*`` query tools; a granting profile is served the
lookup tools at any input size (small inputs stay inlined as well); a profile that grants nothing
still gets nothing below the inline limit; the per-cell tool-call cap is recorded as a gap; and
``02-code-index`` is a graph dependency of the three jobs without a cycle."""
from __future__ import annotations

import graphlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import claude_cli_invoker as invoker
import code_query_mcp as query
import registry_paths
from job_graph import load_graph

PROFILES = ("component-evidence-router", "threat-model-static-evidence", "owasp-control-validator")
REF = "02-code-index/attempts/a1/code-index.json"
ALL_CAPABILITIES = {"cpg": True, "treesitter": True, "exports": True}


def profile(name: str) -> dict:
    return json.loads(registry_paths.record(registry_paths.TOOLING_PROFILES, name).read_text())


def package(tooling_profile: dict, *, index: bool = True, contract: dict | None = None, data: bytes = b"x\n"):
    inputs = [SimpleNamespace(root="target-repository", path=path, data=data, sha256="a" * 64)
              for path in ("configure.ac", "Makefile.am")]
    if index:
        inputs.append(SimpleNamespace(root="supporting-evidence", path=REF, sha256="b" * 64,
                                      data=json.dumps({"capabilities": ALL_CAPABILITIES}).encode()))
    return SimpleNamespace(
        composition={"tooling_profile": tooling_profile, **({"output_contract": contract} if contract else {})},
        prompt=b"OUTER", inputs=tuple(inputs),
        request={"model": {"family": "claude-sonnet-5"}, "run_id": "r", "budget": {"input_unit_limit": 10 ** 9}},
        allowed_claim_classes=("project_inventory", "safe_command_plan"))


class ProfileGrantTests(unittest.TestCase):
    def test_each_profile_lists_exactly_the_hunt_profiles_code_tools(self):
        hunt = query.profile_tools(profile("hypothesis-hunt-static"))
        self.assertEqual(len(hunt), 12)
        for name in PROFILES:
            with self.subTest(profile=name):
                self.assertEqual(query.profile_tools(profile(name)), hunt)

    def test_each_profile_yields_a_twelve_tool_grant_when_a_code_index_is_pinned(self):
        for name in PROFILES:
            with self.subTest(profile=name), mock.patch.object(query, "family_enabled", return_value=True):
                ref, tools = invoker.code_query_grant(package(profile(name)))
                self.assertEqual(ref, "supporting-evidence:" + REF)
                self.assertEqual(len(tools), 12)
                self.assertEqual(set(tools), set(query.NAMES) & set(tools))

    def test_profiles_keep_their_claim_limits_and_say_results_are_locators(self):
        for name in PROFILES:
            with self.subTest(profile=name):
                value = profile(name)
                self.assertIn("finding", " ".join(value["claim_limits"]["forbidden"]))
                self.assertTrue(any("locators" in action for action in value["allowed_actions"]))

    def test_a_granting_profile_without_an_index_records_why(self):
        pkg = package(profile("component-evidence-router"), index=False)
        self.assertEqual(invoker.code_query_grant(pkg), (None, ()))
        self.assertIn("no accepted 02-code-index", invoker.code_grant_gap(pkg, (None, ())))
        self.assertIsNone(invoker.code_grant_gap(package({"allowed_actions": ["read"]}), (None, ())))


class SmallInputModeTests(unittest.TestCase):
    def test_a_small_job_with_a_granting_profile_is_served_tools(self):
        with mock.patch.object(invoker.tunables, "shared", return_value=True):
            self.assertEqual(invoker.input_mode(10, 100, (None, ()), True), (True, (None, ())))

    def test_a_small_job_whose_profile_grants_nothing_gets_nothing(self):
        self.assertEqual(invoker.input_mode(10, 100, (None, ()), False), (False, (None, ())))
        self.assertFalse(invoker.profile_grants_tools(package({"allowed_actions": ["read"]})))

    def test_a_large_job_whose_profile_grants_nothing_still_gets_the_lookups(self):
        self.assertEqual(invoker.input_mode(1000, 100, (None, ()), False), (True, (None, ())))


class InvokeTests(unittest.TestCase):
    """End to end through ClaudeCliInvoker.invoke with a fake dispatch (no model, no network)."""

    def run_invoke(self, tooling_profile, *, index=True, usage=None):
        from tests.test_dev_dispatch import inventory
        contract = json.loads(registry_paths.contract("project-discovery").read_text())
        seen = {}

        def dispatch_fn(argv, prompt, timeout_seconds, transcript_path):
            seen.update(argv=argv, prompt=prompt)
            if "--mcp-config" in argv and usage is not None:
                config = json.loads(Path(argv[argv.index("--mcp-config") + 1]).read_text())
                args = config["mcpServers"][invoker.INPUT_MCP_SERVER]["args"]
                seen["server_args"] = args
                Path(args[args.index("--usage-file") + 1]).write_text(json.dumps(usage))
            return {"timed_out": False, "final_result": {"result": json.dumps(
                {"project_inventory": inventory(), "project_discovery_summary": "# s"})}}

        written = {}
        with tempfile.TemporaryDirectory() as out, \
                mock.patch.object(invoker.cbr, "resolve_claude_binary", return_value="/usr/bin/claude"), \
                mock.patch.object(invoker.rc, "load_model_config", return_value={"invocation": {"repair_attempts": 0}}), \
                mock.patch.object(invoker, "_persona_cache_enabled", return_value=False), \
                mock.patch.object(invoker.size_log, "observe"), \
                mock.patch.object(query, "family_enabled", return_value=True), \
                mock.patch.object(invoker.pi, "write_invoker_output",
                                  side_effect=lambda package, root, **kw: written.update(kw)):
            invoker.ClaudeCliInvoker(effort="medium", dispatch_fn=dispatch_fn).invoke(
                package(tooling_profile, index=index, contract=contract), output_root=Path(out),
                cancel=threading.Event())
        return seen, written

    def test_small_inputs_stay_inline_and_the_granting_profile_gets_its_tools(self):
        seen, written = self.run_invoke(profile("component-evidence-router"))
        argv = seen["argv"]
        allowed = argv[argv.index("--allowedTools") + 1].split(",")
        self.assertIn(f"mcp__{invoker.INPUT_MCP_SERVER}__evidence_search", allowed)
        self.assertIn(f"mcp__{invoker.INPUT_MCP_SERVER}__code_callers", allowed)
        self.assertIn("### target-repository:configure.ac", seen["prompt"])    # inlined, not an inventory
        self.assertIn("## Tool Guides", seen["prompt"])
        self.assertTrue(any(text.startswith("lookup tools granted:") for text in written["limitations"]))

    def test_a_profile_that_grants_nothing_gets_no_tools(self):
        seen, written = self.run_invoke({"allowed_actions": ["read"]}, index=False)
        argv = seen["argv"]
        self.assertNotIn("--mcp-config", argv)
        self.assertEqual(argv[argv.index("--allowedTools") + 1], "")
        self.assertNotIn("## Tool Guides", seen["prompt"])
        self.assertFalse(any("lookup tools granted" in text for text in written["limitations"]))

    def test_granting_profile_without_an_index_runs_on_the_lookups_with_a_gap(self):
        seen, written = self.run_invoke(profile("owasp-control-validator"), index=False)
        allowed = seen["argv"][seen["argv"].index("--allowedTools") + 1].split(",")
        self.assertIn(f"mcp__{invoker.INPUT_MCP_SERVER}__evidence_search", allowed)
        self.assertFalse(any("__code_" in name for name in allowed))
        self.assertTrue(any(text.startswith("coverage gap: code_* query tools not granted")
                            for text in written["limitations"]))

    def test_the_cap_reaches_the_server_and_refused_calls_are_a_receipt_gap(self):
        seen, written = self.run_invoke(profile("threat-model-static-evidence"),
                                        usage={"input_read": 200, "_budget_exhausted": 3})
        args = seen["server_args"]
        self.assertEqual(args[args.index("--max-tool-calls") + 1], str(invoker._max_tool_calls()))
        gaps = [text for text in written["limitations"] if "budget exhausted" in text]
        self.assertEqual(len(gaps), 1)
        self.assertIn("3 lookup call(s) refused", gaps[0])
        self.assertTrue(gaps[0].startswith("coverage gap:"))
        self.assertFalse(any("_budget_exhausted" in text for text in written["limitations"]))


class GraphTests(unittest.TestCase):
    JOBS = ("01-component-characterization", "03-threat-model-dfd-stride", "04-asvs-masvs")

    def test_the_code_index_is_a_required_dependency_of_the_three_jobs(self):
        graph = load_graph()["jobs"]
        for job in self.JOBS:
            with self.subTest(job=job):
                edge = [d for d in graph[job]["dependencies"] if d["job"] == "02-code-index"]
                self.assertEqual([(d["kind"], d["contract"]) for d in edge], [("required", "code-index")])

    def test_code_index_orders_before_component_characterization_without_a_cycle(self):
        graph = load_graph()["jobs"]
        order = list(graphlib.TopologicalSorter(
            {name: [d["job"] for d in node["dependencies"]] for name, node in graph.items()}).static_order())
        self.assertLess(order.index("02-code-index"), order.index("01-component-characterization"))
        self.assertLess(order.index("01-component-characterization"), order.index("03-threat-model-dfd-stride"))


class CodeIndexPinTests(unittest.TestCase):
    def test_no_accepted_code_index_is_a_reason_not_a_pin(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch("execution_state.data_path", side_effect=lambda *parts: Path(folder).joinpath(*parts[1:])):
            row, gap = invoker.code_index_pin("r")
        self.assertIsNone(row)
        self.assertIn("02-code-index", gap)

    def test_an_accepted_code_index_is_pinned_where_the_grant_finds_it(self):
        from test_supporting_evidence_menu import publish
        summary = json.dumps({"capabilities": ALL_CAPABILITIES}).encode()
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch("execution_state.data_path", side_effect=lambda *parts: Path(folder).joinpath(*parts[1:])):
            publish(Path(folder) / "jobs", "02-code-index", {"code-index.json": summary}, run="r")
            row, gap = invoker.code_index_pin("r")
        self.assertIsNone(gap)
        self.assertEqual((row["root"], row["path"], row["role"]),
                         ("supporting-evidence", REF, "evidence"))
        pinned = SimpleNamespace(root=row["root"], path=row["path"], data=summary, sha256=row["sha256"])
        pkg = SimpleNamespace(composition={"tooling_profile": profile("component-evidence-router")}, inputs=(pinned,))
        with mock.patch.object(query, "family_enabled", return_value=True):
            self.assertEqual(len(invoker.code_query_grant(pkg)[1]), 12)


if __name__ == "__main__":
    unittest.main()
