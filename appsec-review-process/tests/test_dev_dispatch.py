"""Focused tests for D02-D04 (02-dev-project-discovery, 02-devops-project-discovery and 02-sre-operations-topology automatic persona dispatch, Phases 5c-5e).

Nothing here calls a model: the live call is the SAT's ``--dispatch`` proof. These cover the parts
that must hold regardless of what the model says -- claim building from ``project-inventory.json``,
prompt grouping of the upstream artifact, upstream staging, and the gate's accept/reuse/reject
behaviour with the persona dispatch itself stubbed.
"""
from __future__ import annotations

import inspect
import json
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
SRE = discovery_gate.SRE_JOB
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


TOPOLOGY_ALLOWED = ("health_check_inventory", "live_state_followup", "observability_gap",
                    "runtime_dependency_map", "service_inventory")


def topology(service_cites=("Dockerfile",), dependency_cites=("compose.yaml",)):
    return {
        "schema": "appsec-review/operations-topology/1.0", "target": "t", "source_revision": "r",
        "services": [
            {"service_id": "web", "name": "web", "kind": "service", "image_ref": "web:local",
             "ports": [{"port": 8080, "protocol": "tcp", "exposed": True}],
             "dependencies": [{"target_service_id": "db", "kind": "network", "basis": "declared",
                               "evidence_citations": [citation(p) for p in dependency_cites]}],
             "evidence_citations": [citation(p) for p in service_cites], "confidence": "high"},
            {"service_id": "db", "name": "db", "kind": "daemon", "image_ref": "postgres:16",
             "ports": [], "dependencies": [], "evidence_citations": [citation("compose.yaml")],
             "confidence": "medium"},
        ],
        "operational_notes": ["Live follow-up: is 8080 reachable from outside the host? (compose.yaml)"],
        "coverage_gaps": [],
    }


class TopologyClaimBuilderTests(unittest.TestCase):
    def setUp(self):
        self.target = (item(pd.DEFAULT_READABLE_ROOT, "Dockerfile"),
                       item(pd.DEFAULT_READABLE_ROOT, "compose.yaml"))

    def test_one_claim_per_service_and_per_dependency_with_resolved_citations(self):
        claims = cci._claims_from_operations_topology(topology(), self.target, TOPOLOGY_ALLOWED, "s.json")
        self.assertEqual([(c["claim_id"], c["claim_class"]) for c in claims],
                         [("service-web", "service_inventory"), ("dependency-web-0", "runtime_dependency_map"),
                          ("service-db", "service_inventory")])
        self.assertIn("8080/tcp published", claims[0]["statement"])
        self.assertEqual(claims[1]["citations"][0]["path"], "compose.yaml")

    def test_a_service_or_dependency_left_with_no_resolvable_citation_is_rejected(self):
        with self.assertRaises(cci.InvokerOutputError):
            cci._claims_from_operations_topology(topology(service_cites=("missing",)), self.target,
                                                 TOPOLOGY_ALLOWED, "s.json")
        with self.assertRaises(cci.InvokerOutputError):
            cci._claims_from_operations_topology(topology(dependency_cites=("missing",)), self.target,
                                                 TOPOLOGY_ALLOWED, "s.json")

    def test_upstream_artifacts_are_never_citable_evidence(self):
        with self.assertRaises(cci.InvokerOutputError):
            cci._claims_from_operations_topology(
                topology(service_cites=("devops-project-inventory.json",)), self.target,
                TOPOLOGY_ALLOWED, "s.json")

    def test_claim_class_outside_the_ceiling_is_rejected(self):
        with self.assertRaises(cci.InvokerOutputError):
            cci._claims_from_operations_topology(topology(), self.target, ("service_inventory",), "s.json")

    def test_no_service_is_valid_only_when_a_coverage_gap_explains_it(self):
        empty = topology()
        empty["services"] = []
        empty["coverage_gaps"] = ["no runnable unit is declared: the repository only builds a library"]
        self.assertEqual(cci._claims_from_operations_topology(empty, self.target, TOPOLOGY_ALLOWED, "s.json"), [])
        empty["coverage_gaps"] = []
        with self.assertRaises(cci.InvokerOutputError):
            cci._claims_from_operations_topology(empty, self.target, TOPOLOGY_ALLOWED, "s.json")

    def test_the_topology_claim_classes_are_inside_the_registry_ceiling(self):
        import persona_invocation as pi
        registry = ROOT / "registry"
        role = json.loads((registry / "roles" / "operations-topology-mapper.json").read_text(encoding="utf-8"))
        profile = json.loads((registry / "tooling-profiles" / "static-ops-topology-inspector.json")
                             .read_text(encoding="utf-8"))
        allowed = pi.claim_ceiling(role, profile)["allowed"]
        self.assertIn("service_inventory", allowed)
        self.assertIn("runtime_dependency_map", allowed)


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

    def test_every_automatic_result_schema_has_a_claim_builder(self):
        self.assertIn("repository-partition-map.schema.json", cci._CLAIM_BUILDERS)
        self.assertIn("project-discovery.schema.json", cci._CLAIM_BUILDERS)
        self.assertIn("operations-topology.schema.json", cci._CLAIM_BUILDERS)


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

    def test_only_the_chained_discovery_jobs_have_an_automatic_path(self):
        self.assertEqual(set(discovery_gate.AUTOMATIC_PROJECT_JOBS), {JOB, DEVOPS})
        self.assertEqual(set(discovery_gate.AUTOMATIC_JOBS), {JOB, DEVOPS, SRE})
        with self.assertRaises(state.Blocked):
            discovery_gate._run_project_automatic(self.run_id, "dagster-a", "02-build-index")

    def test_every_automatic_job_spec_matches_its_output_contract(self):
        registry = ROOT / "registry"
        for job, spec in discovery_gate.AUTOMATIC_JOBS.items():
            with self.subTest(job=job):
                template = json.loads((registry / "job-templates" / f"{job}.json").read_text(encoding="utf-8"))
                contract_id = template["composition"]["output_contract_id"]
                contract = json.loads((registry / "output-contracts" / f"{contract_id}.json")
                                      .read_text(encoding="utf-8"))
                self.assertEqual(contract["result_schema"]["artifact"], spec["result"])
                self.assertEqual(contract["result_schema"]["schema_file"], discovery_gate.SCHEMAS[job])
                self.assertEqual(set(contract["required_files"]), {spec["result"], spec["summary"], "status.json"})
                for upstream in spec["upstreams"]:
                    self.assertIn(upstream, discovery_gate.UPSTREAM_STAGED_NAME)
        self.assertEqual(discovery_gate.AUTOMATIC_JOBS[SRE]["upstreams"], (DEVOPS, discovery_gate.ADOPTED_JOB))
        self.assertEqual(discovery_gate.UPSTREAM_JOB[SRE], DEVOPS)

    def test_sre_topology_takes_the_same_path_with_its_own_identity_and_summary(self):
        ids = {spec["persona_job_id"] for spec in discovery_gate.AUTOMATIC_JOBS.values()}
        self.assertEqual(len(ids | {discovery_gate.PERSONA_JOB_ID}), 4)
        self.assertEqual(discovery_gate.AUTOMATIC_JOBS[SRE]["persona_job_id"], "d04-sretopology")
        discovery_gate.set_dispatch_mode(self.run_id, SRE, "automatic")
        base = discovery_gate.root(self.run_id, SRE)
        base.mkdir(parents=True)
        value = {"schema": "appsec-review/operations-topology/1.0", "target": "t", "source_revision": "r",
                 "services": [], "operational_notes": [], "coverage_gaps": ["no runnable unit declared"]}
        self.record["upstream"] = {"jobs": {DEVOPS: "a", discovery_gate.ADOPTED_JOB: "b"},
                                   "devops-project-inventory.json": "1" * 64,
                                   "repository-partition-map.json": "2" * 64}
        seen = []

        def dispatch(run_id, base_dir, record):
            seen.append((base_dir.name, record["job"]))
            return dict(value), "# Topology\n", {**self.facts, "persona_job_id": "d04-sretopology"}

        accepted = self.run_gate(dispatch, job=SRE)
        self.assertEqual(seen, [(SRE, SRE)])
        attempt = base / "attempts" / accepted["attempt_id"]
        self.assertEqual(state.read_json(attempt / "output.json"), value)
        self.assertTrue((attempt / "operations-topology-summary.md").is_file())
        self.assertFalse((attempt / "project-discovery-summary.md").exists())
        self.assertEqual(discovery_gate.validate(self.run_id, SRE), attempt)

    def test_upstream_record_keeps_the_one_upstream_shape_and_records_every_upstream_for_d04(self):
        files = {}
        for name, text in (("map.json", '{"target": "t"}\n'), ("devops.json", '{"projects": []}\n')):
            files[name] = self.owner / name
            files[name].write_text(text, encoding="utf-8")
        paths = {discovery_gate.ADOPTED_JOB: (self.owner / "att-map", files["map.json"]),
                 DEVOPS: (self.owner / "att-devops", files["devops.json"])}
        with patch.object(discovery_gate, "_accepted_upstream_path",
                          side_effect=lambda run_id, job, upstream: paths[upstream]):
            one = discovery_gate._upstream_record(self.run_id, JOB)
            two = discovery_gate._upstream_record(self.run_id, SRE)
        self.assertEqual(one, {"job": discovery_gate.ADOPTED_JOB, "attempt_id": "att-map",
                               "repository-partition-map.json": state.file_hash(files["map.json"])})
        self.assertEqual(two, {"jobs": {DEVOPS: "att-devops", discovery_gate.ADOPTED_JOB: "att-map"},
                               "devops-project-inventory.json": state.file_hash(files["devops.json"]),
                               "repository-partition-map.json": state.file_hash(files["map.json"])})
        self.assertEqual(set(discovery_gate._staged_upstream_files(two)),
                         {"devops-project-inventory.json", "repository-partition-map.json"})

    def test_two_upstream_files_stage_together_and_a_stray_file_is_rejected(self):
        sources = {}
        for name, text in (("repository-partition-map.json", '{"target": "t"}\n'),
                           ("devops-project-inventory.json", '{"projects": []}\n')):
            path = self.owner / ("src-" + name)
            path.write_text(text, encoding="utf-8")
            sources[name] = (path, state.file_hash(path))
        directory = discovery_gate._stage_upstream_files(self.base, sources)
        self.assertEqual({p.name for p in directory.iterdir()}, set(sources))
        self.assertEqual(directory, discovery_gate._stage_upstream_files(self.base, sources))
        (directory / "extra.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaises(state.Blocked):
            discovery_gate._stage_upstream_files(self.base, sources)

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
