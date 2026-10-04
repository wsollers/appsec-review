"""ADR-0034 graph wiring: the lifecycle of 04-owasp-candidate-search / -participation / -universe."""
from __future__ import annotations

from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import code_index  # noqa: E402
import execution_state  # noqa: E402
from execution_state import Blocked, atomic_json, file_hash, read_json, tree_hashes  # noqa: E402
from job_graph import load_graph  # noqa: E402
import owasp_candidate_search  # noqa: E402
import owasp_universe_jobs as jobs  # noqa: E402
from schema_validate import validate_document  # noqa: E402
import tunables  # noqa: E402

RUN = "adr34-wiring"
NEW = (jobs.CANDIDATES, jobs.PARTICIPATION, jobs.UNIVERSE)


class GraphWiringTests(unittest.TestCase):
    def test_graph_nodes_and_edges(self):
        graph = load_graph()["jobs"]
        edges = {job: {d["job"]: (d["kind"], d["allowed_skip_reasons"]) for d in graph[job]["dependencies"]} for job in NEW}
        self.assertEqual(edges[jobs.CANDIDATES], {
            "02-code-index": ("required", []), "02-code-property-graph": ("required", []),
            "02-treesitter-ast": ("required", ["not-applicable-language-absent"]),
            "02-source-sast": ("optional", ["not-applicable-after-partition-review"]),
            "02-evidence-index": ("required", []),
            "01-component-characterization": ("optional", ["not-applicable-after-partition-review"])})
        self.assertEqual(edges[jobs.PARTICIPATION], {jobs.CANDIDATES: ("required", []), "02-code-index": ("required", [])})
        self.assertEqual(edges[jobs.UNIVERSE], {jobs.CANDIDATES: ("required", []),
                                                jobs.PARTICIPATION: ("required", ["no-candidates"])})
        for consumer in ("04-owasp-validation-worklist", "04-asvs-masvs"):
            self.assertIn(jobs.UNIVERSE, {d["job"] for d in graph[consumer]["dependencies"]}, consumer)
        # every candidate-search dependency is bound to an artifact
        self.assertLessEqual({d["job"] for d in graph[jobs.CANDIDATES]["dependencies"]}, set(jobs.ARTIFACTS))

    def test_dagster_wiring_without_dagster(self):
        source = (ROOT / "dagster_workflow.py").read_text(encoding="utf-8")
        for job in NEW:
            self.assertTrue(f"LIFECYCLE_OPS['{job}']=" in source, job)
        self.assertFalse("owasp_component_routing" in source, "the standalone routing job is gone")
        self.assertTrue("max_parallel=owasp_validator_max_parallel())" in source, "T10 parallelism is not passed")
        self.assertGreater(tunables.value("04-owasp-validator-cell", "max_parallel"), 1)
        import owasp_workbench_lifecycle as workbench  # the cap: pool_persona_llm_slots
        self.assertEqual(workbench.dispatch_parallelism(10 ** 6), tunables.shared("pool_persona_llm_slots"))
        self.assertFalse(re.search(r"^import owasp_(candidate_search|participation|universe)\b", source, re.M))


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        runs = Path(self.temporary.name) / "runs"
        patcher = mock.patch.object(execution_state, "RUNS", runs)
        patcher.start(); self.addCleanup(patcher.stop)
        self.checkout = Path(self.temporary.name) / "checkout"
        self.checkout.mkdir()
        atomic_json(runs / RUN / "inputs" / "artifact-manifest.json", {"target": {"repo_path": str(self.checkout)}})

    def publish(self, job, status="OK", skip_reason=None, whole=False, content=b"{}"):
        base = execution_state.data_path(RUN, "jobs", job, *(["whole"] if whole else []))
        attempt = base / "attempts" / "a1"
        attempt.mkdir(parents=True)
        (attempt / jobs.ARTIFACTS[job]).write_bytes(content)
        atomic_json(attempt / "result.json", {"skip_reason": skip_reason})
        atomic_json(base / "accepted.json", {"run_id": RUN, "job": job, "status": status, "attempt_id": "a1",
                                             "hashes": tree_hashes(attempt), "envelope_path": "result.json",
                                             "envelope_sha256": file_hash(attempt / "result.json")})
        return attempt / jobs.ARTIFACTS[job]

    def publish_candidate_inputs(self, treesitter="OK", tags=True):
        database = Path(self.temporary.name) / "code-index.sqlite"
        connection = sqlite3.connect(database); connection.executescript(code_index.DDL); connection.commit(); connection.close()
        index = self.publish("02-code-index", content=database.read_bytes())
        self.publish("02-code-property-graph")
        if treesitter == "OK":
            self.publish("02-treesitter-ast", content=b'{"gaps": []}')
        else:
            self.publish("02-treesitter-ast", status="SKIPPED", skip_reason="not-applicable-language-absent")
        self.publish("02-evidence-index", whole=True)
        if tags:
            self.publish("01-component-characterization")
        return index

    def flags(self, argv):
        return {argv[i]: argv[i + 1] for i in range(0, len(argv), 2)}

    def test_candidate_search_cli_binds_accepted_inputs_and_omits_absent_optional(self):
        index = self.publish_candidate_inputs(treesitter="SKIPPED")
        inputs = jobs.current_inputs(RUN, jobs.CANDIDATES)
        self.assertEqual(inputs["absent_optional"], ["02-source-sast"])
        attempt = Path(self.temporary.name) / "attempt"
        flags = self.flags(jobs.argv(inputs, attempt))
        self.assertEqual(flags["--index"], str(index))
        self.assertEqual(flags["--evidence-run-id"], RUN)
        self.assertTrue(flags["--component-map"].endswith("component-purpose-map.json"))
        self.assertEqual(flags["--output"], str(attempt / "owasp-candidate-search.json"))
        self.assertEqual(flags["--source-root"], str(self.checkout.resolve()))
        self.assertNotIn("--treesitter-ast", flags)   # skipped by an allowed reason: the module records it
        self.assertNotIn("--source-sast", flags)      # optional and absent: a gap, never zero hits
        binding = inputs["bindings"]["02-code-index"]
        self.assertEqual((binding["attempt_id"], binding["artifact_sha256"]), ("a1", file_hash(index)))

    def test_required_input_absent_or_wrongly_skipped_blocks(self):
        self.publish("02-code-property-graph")
        with self.assertRaisesRegex(Blocked, "02-code-index"):
            jobs.current_inputs(RUN, jobs.CANDIDATES)
        self.publish("02-code-index")
        self.publish("02-treesitter-ast", status="SKIPPED", skip_reason="not-requested")
        self.publish("02-evidence-index", whole=True)
        with self.assertRaisesRegex(Blocked, "skipped for a reason"):
            jobs.current_inputs(RUN, jobs.CANDIDATES)

    def test_changed_accepted_tree_is_refused(self):
        path = self.publish("02-code-index")
        path.write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(Blocked, "not current"):
            jobs.accepted(RUN, "02-code-index")

    def test_candidate_search_publishes_a_schema_valid_accepted_document(self):
        """The real P1 CLI over an empty index: every chapter is a gap, published OK_WITH_GAPS, never N/A."""
        self.publish_candidate_inputs(tags=False)
        with mock.patch.object(owasp_candidate_search, "evidence_index_for", return_value=None) as evidence:
            pointer = jobs.run(jobs.CANDIDATES, RUN, "dagster-a")
        evidence.assert_called_once_with(RUN)
        self.assertEqual(pointer["status"], "OK_WITH_GAPS")
        attempt = jobs.root(RUN, jobs.CANDIDATES) / "attempts" / pointer["attempt_id"]
        document = read_json(attempt / "owasp-candidate-search.json")
        self.assertEqual(validate_document(document, "owasp-candidate-search.schema.json"), [])
        self.assertEqual([row["job_id"] for row in document["inputs"] if not row["accepted"]], ["02-source-sast"])
        self.assertEqual(document["candidates"], [])
        self.assertTrue(document["gaps"])
        envelope = read_json(attempt / "result.json")
        self.assertIn("optional input absent: 01-component-characterization", envelope["gaps"])
        # the universe reads exactly this publication
        import owasp_universe
        value, binding = owasp_universe._accepted_input(RUN, jobs.CANDIDATES, "owasp-candidate-search.json",
                                                        "owasp-candidate-search.schema.json", required=True)
        self.assertEqual((value, binding["attempt_id"]), (document, pointer["attempt_id"]))
        # unchanged inputs reuse the publication
        with mock.patch.object(owasp_candidate_search, "main", side_effect=AssertionError("re-ran")):
            self.assertEqual(jobs.run(jobs.CANDIDATES, RUN, "dagster-b")["attempt_id"], pointer["attempt_id"])

    def test_blocked_cli_run_is_never_accepted(self):
        self.publish_candidate_inputs()
        with mock.patch.object(owasp_candidate_search, "main", return_value=2), \
             self.assertRaisesRegex(Blocked, "exited 2"):
            jobs.run(jobs.CANDIDATES, RUN, "dagster-a")
        self.assertIsNone(jobs.accepted(RUN, jobs.CANDIDATES))

    def test_participation_publishes_itself(self):
        import owasp_participation
        with mock.patch.object(owasp_participation, "run", return_value={"attempt_id": "p1"}) as run:
            self.assertEqual(jobs.run_participation(RUN, "dagster-a", True), {"attempt_id": "p1"})
        run.assert_called_once_with(RUN, "dagster-a", True)

    def test_universe_is_projected_only_after_it_is_accepted(self):
        import owasp_universe
        order = []
        with mock.patch.object(owasp_universe, "run", side_effect=Blocked("over budget")), \
             mock.patch.object(jobs, "project", side_effect=lambda *a: order.append("project")), \
             self.assertRaisesRegex(Blocked, "over budget"):
            jobs.run_universe(RUN, "dagster-a")
        self.assertEqual(order, [])


if __name__ == "__main__":
    unittest.main()
