"""Focused tests for D02/D03 (02-dev-project-discovery and 02-devops-project-discovery automatic persona dispatch, Phase 5c).

Nothing here calls a model: the live call is the SAT's ``--dispatch`` proof. These cover the parts
that must hold regardless of what the model says -- claim building from ``project-inventory.json``,
prompt grouping of the upstream artifact, upstream staging, and the gate's accept/reuse/reject
behaviour with the persona dispatch itself stubbed.
"""
from __future__ import annotations

import inspect
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import claude_cli_invoker as cci
import discovery_gate
import execution_state as state
import persona_dispatch as pd

JOB = discovery_gate.CONSUMER_JOB
DEVOPS = discovery_gate.DEVOPS_JOB
ALLOWED = ("evidence_gap", "project_inventory", "safe_command_plan")


def item(root, path, data=b"x\n", sha="a" * 64):
    return SimpleNamespace(root=root, path=path, data=data, sha256=sha)


def citation(path, line_range=None):
    return {"source_type": "source_file", "path": path, "line_range": line_range,
            "tool_name": None, "tool_rule_id": None, "content_hash": "0" * 64, "note": "n"}


def inventory(cites=("configure.ac",), plan_cites=("Makefile.am",)):
    return {
        "schema": "appsec-review/project-discovery/1.0", "target": "t", "source_revision": "r",
        "projects": [{"project_id": "hello", "root": ".", "languages": ["C"], "manifests": ["configure.ac"],
                      "lockfiles": [], "candidate_buildenv_images": ["img:local"], "commands": ["make"],
                      "evidence_citations": [citation(p) for p in cites], "confidence": "high"}],
        "safe_command_plan": [{"project_id": "hello", "purpose": "build", "argv": ["make"],
                               "authorization": "script-execution-required", "side_effects": ["writes objects"],
                               "evidence_citations": [citation(p, "1-3") for p in plan_cites]}],
        "coverage_gaps": [],
    }


class ClaimBuilderTests(unittest.TestCase):
    def setUp(self):
        self.inputs = (item(pd.DEFAULT_READABLE_ROOT, "configure.ac"),
                       item(pd.DEFAULT_READABLE_ROOT, "Makefile.am"),
                       item(pd.UPSTREAM_ROOT_ID, "repository-partition-map.json"))
        self.target = tuple(i for i in self.inputs if i.root != pd.UPSTREAM_ROOT_ID)

    def test_one_project_claim_and_one_command_claim_with_resolved_citations(self):
        claims = cci._claims_from_project_inventory(inventory(), self.target, ALLOWED, "project-inventory.json")
        self.assertEqual([c["claim_class"] for c in claims], ["project_inventory", "safe_command_plan"])
        self.assertEqual(claims[0]["citations"][0]["path"], "configure.ac")
        self.assertEqual(claims[1]["citations"][0]["locator"], "1-3")
        self.assertTrue(all(c["file"] == "project-inventory.json" for c in claims))

    def test_unresolvable_citation_is_dropped_and_a_claim_left_bare_is_rejected(self):
        with self.assertRaises(cci.InvokerOutputError):
            cci._claims_from_project_inventory(
                inventory(cites=("not/a/pinned/file.txt",)), self.target, ALLOWED, "project-inventory.json")
        with self.assertRaises(cci.InvokerOutputError):
            cci._claims_from_project_inventory(
                inventory(plan_cites=("nope.mk",)), self.target, ALLOWED, "project-inventory.json")

    def test_a_partial_citation_list_keeps_only_the_resolvable_ones(self):
        claims = cci._claims_from_project_inventory(
            inventory(cites=("configure.ac", "ghost.txt")), self.target, ALLOWED, "project-inventory.json")
        self.assertEqual([c["path"] for c in claims[0]["citations"]], ["configure.ac"])

    def test_the_upstream_partition_map_is_never_citable_evidence(self):
        with self.assertRaises(cci.InvokerOutputError):
            cci._claims_from_project_inventory(
                inventory(cites=("repository-partition-map.json",)), self.target, ALLOWED, "project-inventory.json")

    def test_claim_class_outside_the_ceiling_and_empty_results_are_rejected(self):
        with self.assertRaises(cci.InvokerOutputError):
            cci._claims_from_project_inventory(inventory(), self.target, ("project_inventory",), "f.json")

    def test_a_result_with_no_unit_is_valid_only_when_a_coverage_gap_explains_it(self):
        empty = inventory()
        empty["projects"], empty["safe_command_plan"] = [], []
        empty["coverage_gaps"] = ["no devops unit is declared in any devops-routed partition"]
        self.assertEqual(cci._claims_from_project_inventory(empty, self.target, ALLOWED, "f.json"), [])
        empty["coverage_gaps"] = []
        with self.assertRaises(cci.InvokerOutputError):
            cci._claims_from_project_inventory(empty, self.target, ALLOWED, "f.json")

    def test_citation_for_an_unpinned_path_returns_none_instead_of_raising(self):
        self.assertIsNone(cci._citation_for(None, "source_file", "x", None))

    def test_both_result_schemas_have_a_claim_builder(self):
        self.assertIn("repository-partition-map.schema.json", cci._CLAIM_BUILDERS)
        self.assertIn("project-discovery.schema.json", cci._CLAIM_BUILDERS)


class PromptGroupingTests(unittest.TestCase):
    def test_target_only_keeps_the_original_heading_and_no_upstream_section(self):
        text = cci._render_readable_inputs((item(pd.DEFAULT_READABLE_ROOT, "a.c", b"int x;\n"),))
        self.assertIn("## Target Repository Files", text)
        self.assertNotIn("Upstream Accepted Artifacts", text)

    def test_upstream_artifact_is_under_its_own_heading_and_marked_not_citable(self):
        text = cci._render_readable_inputs((
            item(pd.DEFAULT_READABLE_ROOT, "a.c", b"int x;\n"),
            item(pd.UPSTREAM_ROOT_ID, "repository-partition-map.json", b"{}\n")))
        self.assertLess(text.index("## Target Repository Files"), text.index("## Upstream Accepted Artifacts"))
        section = text[text.index("## Upstream Accepted Artifacts"):]
        self.assertIn("repository-partition-map.json", section)
        self.assertNotIn("a.c", section)
        self.assertIn("NOT repository evidence", section)


class RequestBuilderTests(unittest.TestCase):
    def test_upstream_root_is_an_optional_build_request_parameter(self):
        parameter = inspect.signature(pd.build_request).parameters["upstream_root"]
        self.assertIsNone(parameter.default)
        self.assertNotEqual(pd.UPSTREAM_ROOT_ID, pd.DEFAULT_READABLE_ROOT)

    def test_walk_pins_every_file_under_the_upstream_root_with_the_upstream_root_id(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "repository-partition-map.json").write_text("{}\n", encoding="utf-8")
            entries = pd._walk_target(Path(directory), pd.UPSTREAM_ROOT_ID)
        self.assertEqual([(e["root"], e["path"], e["role"]) for e in entries],
                         [(pd.UPSTREAM_ROOT_ID, "repository-partition-map.json", "evidence")])


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.owner = Path(self.temporary.name)
        self.old_runs = state.RUNS
        state.RUNS = self.owner / "runs"
        self.run_id = "d02-fixture"
        (state.RUNS / self.run_id / "inputs").mkdir(parents=True)
        self.base = discovery_gate.root(self.run_id, JOB)
        self.base.mkdir(parents=True)
        discovery_gate.set_dispatch_mode(self.run_id, JOB, "automatic")
        self.record = {"job": JOB, "mode": "automatic", "target_root": str(self.owner),
                       "source_snapshot_sha256": "sha256:" + "b" * 64, "source_revision": "r",
                       "upstream": {"job": discovery_gate.ADOPTED_JOB, "attempt_id": "x",
                                    "repository-partition-map.json": "c" * 64},
                       "code": {"discovery_gate.py": "d" * 64}}
        self.value = {"schema": "appsec-review/project-discovery/1.0", "target": "t",
                      "source_revision": "r", "projects": [], "safe_command_plan": [],
                      "coverage_gaps": ["nothing to build"]}
        self.facts = {"dispatch_mode": "automatic", "persona_job_id": discovery_gate.DEV_PERSONA_JOB_ID,
                      "persona_attempt_id": "p" * 32, "persona_result_sha256": "e" * 64,
                      "model": {"family": "claude-sonnet-5"}}

    def tearDown(self):
        state.RUNS = self.old_runs
        self.temporary.cleanup()

    def run_gate(self, dispatch, dagster_id="dagster-a", force=False, job=JOB):
        with patch.object(discovery_gate, "_automatic_project_inputs",
                          side_effect=lambda run_id, j: {**self.record, "job": j}), \
             patch.object(discovery_gate, "_require_upstream_inputs"), \
             patch.object(discovery_gate, "_dispatch_project_persona", dispatch):
            return discovery_gate.run(self.run_id, dagster_id, job, force)

    def test_accepts_a_dispatched_result_in_the_existing_accepted_record_shape(self):
        calls = []

        def dispatch(run_id, base, record):
            calls.append(record)
            return dict(self.value), "# Summary\n", dict(self.facts)

        accepted = self.run_gate(dispatch)
        self.assertEqual((accepted["status"], accepted["job"], accepted["dispatch_mode"]),
                         ("OK", JOB, "automatic"))
        attempt = self.base / "attempts" / accepted["attempt_id"]
        self.assertEqual(state.read_json(attempt / "output.json"), self.value)
        self.assertTrue((attempt / "project-discovery-summary.md").is_file())
        self.assertEqual(state.read_json(attempt / "status.json")["persona_result_sha256"], "e" * 64)
        self.assertEqual(state.read_json(self.base / "latest.json"), {"attempt_id": accepted["attempt_id"]})
        self.assertEqual(state.read_json(attempt / "inputs.json")["upstream"], self.record["upstream"])
        self.assertEqual(discovery_gate.validate(self.run_id, JOB), attempt)
        self.assertEqual(calls[0]["run_id"], self.run_id)

    def test_same_inputs_reuse_the_accepted_result_without_a_second_model_call(self):
        count = []

        def dispatch(run_id, base, record):
            count.append(1)
            return dict(self.value), "# Summary\n", dict(self.facts)

        first = self.run_gate(dispatch)
        second = self.run_gate(dispatch, dagster_id="dagster-b")
        self.assertEqual(len(count), 1)
        self.assertEqual(second["attempt_id"], first["attempt_id"])
        self.run_gate(dispatch, dagster_id="dagster-c", force=True)
        self.assertEqual(len(count), 2)

    def test_changed_upstream_partition_map_is_a_different_input_and_re_dispatches(self):
        count = []

        def dispatch(run_id, base, record):
            count.append(1)
            return dict(self.value), "# Summary\n", dict(self.facts)

        self.run_gate(dispatch)
        self.record["upstream"] = {**self.record["upstream"], "repository-partition-map.json": "f" * 64}
        self.run_gate(dispatch, dagster_id="dagster-b")
        self.assertEqual(len(count), 2)

    def test_a_schema_invalid_result_is_rejected_and_nothing_is_published(self):
        bad = dict(self.value)
        del bad["safe_command_plan"]
        with self.assertRaises(state.Blocked):
            self.run_gate(lambda run_id, base, record: (bad, "# S\n", dict(self.facts)))
        self.assertFalse((self.base / "accepted.json").exists())
        self.assertFalse((self.base / "attempts").exists())

    def test_a_failed_dispatch_propagates_and_publishes_nothing(self):
        def dispatch(run_id, base, record):
            raise RuntimeError("persona dispatch did not complete OK")

        with self.assertRaises(RuntimeError):
            self.run_gate(dispatch)
        self.assertFalse((self.base / "accepted.json").exists())

    def test_supplied_mode_never_reaches_the_automatic_path(self):
        discovery_gate.set_dispatch_mode(self.run_id, JOB, "supplied")
        with patch.object(discovery_gate, "_run_project_automatic") as automatic:
            with self.assertRaises(Exception):
                discovery_gate._legacy_run(self.run_id, "dagster-a", JOB)
        automatic.assert_not_called()

    def test_automatic_mode_routes_to_the_automatic_path(self):
        with patch.object(discovery_gate, "_run_project_automatic", return_value="sentinel") as automatic:
            self.assertEqual(discovery_gate._legacy_run(self.run_id, "dagster-a", JOB), "sentinel")
        automatic.assert_called_once_with(self.run_id, "dagster-a", JOB, False)

    def test_devops_discovery_takes_the_same_path_with_its_own_persona_identity(self):
        self.assertEqual(discovery_gate.AUTOMATIC_PROJECT_JOBS[DEVOPS],
                         discovery_gate.DEVOPS_PERSONA_JOB_ID)
        self.assertNotEqual(discovery_gate.DEVOPS_PERSONA_JOB_ID, discovery_gate.DEV_PERSONA_JOB_ID)
        discovery_gate.set_dispatch_mode(self.run_id, DEVOPS, "automatic")
        discovery_gate.root(self.run_id, DEVOPS).mkdir(parents=True)
        seen = []

        def dispatch(run_id, base, record):
            seen.append((base.name, record["job"]))
            return dict(self.value), "# Summary\n", {**self.facts, "persona_job_id": discovery_gate.DEVOPS_PERSONA_JOB_ID}

        accepted = self.run_gate(dispatch, job=DEVOPS)
        self.assertEqual(seen, [(DEVOPS, DEVOPS)])
        self.assertEqual((accepted["job"], accepted["persona_job_id"]),
                         (DEVOPS, discovery_gate.DEVOPS_PERSONA_JOB_ID))
        attempt = discovery_gate.root(self.run_id, DEVOPS) / "attempts" / accepted["attempt_id"]
        self.assertEqual(discovery_gate.validate(self.run_id, DEVOPS), attempt)
        # The dev job in the same run is untouched: no accepted record appears for it.
        self.assertFalse((self.base / "accepted.json").exists())

    def test_only_the_project_discovery_jobs_have_an_automatic_path(self):
        self.assertEqual(set(discovery_gate.AUTOMATIC_PROJECT_JOBS), {JOB, DEVOPS})
        with self.assertRaises(state.Blocked):
            discovery_gate._run_project_automatic(self.run_id, "dagster-a", "02-sre-operations-topology")

    def test_upstream_staging_is_content_addressed_and_detects_tampering(self):
        source = self.owner / "map.json"
        source.write_text('{"target": "t"}\n', encoding="utf-8")
        digest = state.file_hash(source)
        directory = discovery_gate._stage_upstream_partition_map(self.base, source, digest)
        staged = directory / "repository-partition-map.json"
        self.assertEqual(state.file_hash(staged), digest)
        self.assertEqual(directory, discovery_gate._stage_upstream_partition_map(self.base, source, digest))
        staged.write_text("tampered\n", encoding="utf-8")
        with self.assertRaises(state.Blocked):
            discovery_gate._stage_upstream_partition_map(self.base, source, digest)


if __name__ == "__main__":
    unittest.main()
