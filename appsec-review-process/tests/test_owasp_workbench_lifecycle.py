"""Automatic OWASP workbench chain (universe -> T03 -> T06 -> T10) feeding the 04-asvs-masvs join (ADR-0034)."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

PROCESS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROCESS))
import registry_paths
sys.path.insert(0, str(Path(__file__).resolve().parent))

import execution_state  # noqa: E402
from execution_state import Blocked  # noqa: E402
import owasp_dispatch  # noqa: E402
import owasp_dispatch_support as dispatch_support  # noqa: E402
import owasp_join_publisher  # noqa: E402
import owasp_workbench_lifecycle as workbench  # noqa: E402
import persona_invocation  # noqa: E402
import persona_invocation_support as invocation_support  # noqa: E402
import test_owasp_component_routing as routing_fixture  # noqa: E402
import test_owasp_universe as universe_fixture  # noqa: E402
import tunables  # noqa: E402

write_json = routing_fixture.write_json

try:        # the Dagster wiring is only importable where Dagster is installed
    from dagster import build_op_context
    import dagster_workflow
except ImportError:      # pragma: no cover - host without the Dagster virtualenv
    dagster_workflow = None


class WorkbenchCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        old_runs = execution_state.RUNS
        execution_state.RUNS = Path(self.temporary.name) / "runs"
        self.addCleanup(setattr, execution_state, "RUNS", old_runs)
        self.run_id = "owasp-workbench-lifecycle"
        self.run = execution_state.RUNS / self.run_id
        self.data = self.run / "data"
        write_json(self.run / "run-status.json", {"run_id": self.run_id, "status": "READY"})
        self.fixture = routing_fixture.OwaspComponentRoutingTests(methodName="runTest")
        self.fixture.run_id, self.fixture.run, self.fixture.data = self.run_id, self.run, self.data
        self.facts = owasp_dispatch.DispatchFacts(
            registry_dir=registry_paths.REGISTRY, allowed_models=(invocation_support.MODEL,),
            invoker_id=persona_invocation.FixtureInvoker.invoker_id,
            source_snapshot_sha256=invocation_support.SNAPSHOT, registry_ceiling=None)

    def publish(self, *, unresolved: bool = False, component_map: bool = True):
        """The accepted universe (hello-world-like: V1, V2, V5, V16 participate; ``unresolved``: no chapter
        participates) and, as report context, the component map."""
        if component_map:
            self.fixture._publish_component(self.fixture._freeciv_like_map())
        self.universe = universe_fixture.UniverseRun(self, self.run_id, candidates=[] if unresolved else None)
        return self.universe.publish()

    def dispatch(self, invoker=None, force: bool = False) -> dict:
        return workbench.run(self.run_id, "dagster-test", force, facts=self.facts,
                             invoker=invoker or dispatch_support.ValidatorInvoker(),
                             clock=lambda: dispatch_support.NOW, max_parallel=2,
                             wait_limit_seconds=dispatch_support.HANG_SECONDS)

    def join(self) -> dict:
        pointer = owasp_join_publisher.run(self.run_id, "dagster-test", self.facts)
        owasp_join_publisher.validate(self.run_id, self.facts, pointer)
        return pointer


class OwaspWorkbenchLifecycleTests(WorkbenchCase):
    def test_baseline_selection_is_the_adr_0009_asvs_l2_default(self):
        selection = workbench.selection(self.run_id)
        self.assertEqual(selection["approver"], workbench.BASELINE_APPROVER)
        self.assertEqual([(row["family"], row["edition"], row["profile_or_level"]) for row in selection["selections"]],
                         [("owasp_asvs", "5.0.0", "L2")])
        supplied = {**selection, "approver": "engagement-lead", "selection_id": "lead-approved"}
        write_json(self.run / "inputs" / workbench.SELECTION_INPUT, supplied)
        self.assertEqual(workbench.selection(self.run_id), supplied)

    def test_participating_chapters_dispatch_exactly_the_planned_cells_and_the_join_publishes(self):
        self.publish()
        invoker = dispatch_support.ValidatorInvoker()
        pointer = self.dispatch(invoker)
        self.assertIn(pointer["status"], {"OK", "OK_WITH_GAPS"})
        accounting = owasp_dispatch.load_verified_accounting(self.run_id, facts=self.facts)
        dispatched = [cell for cell in accounting["cells"] if cell["disposition"] == "dispatched"]
        self.assertEqual(len(dispatched), 4)  # one cell per participating chapter (V1, V2, V5, V16)
        self.assertEqual(len(invoker.packages), len(dispatched))
        request = json.loads((self.run / "inputs" / "owasp-batch-request.json").read_text())
        self.assertEqual(request["batch_config"]["path"], workbench.BATCH_CONFIG)
        self.assertIn(self.join()["status"], {"OK", "OK_WITH_GAPS"})

    def test_component_map_is_optional_report_context(self):
        self.publish(component_map=False)
        prepared = workbench.prepare_handoffs(self.run_id, "dagster-test")
        manifest = json.loads((self.data / "jobs" / "04-owasp-intel-lane-in" / "whole" / "attempts" /
                               prepared["lane_in"]["attempt_id"] / "outputs" / "owasp-input-manifest.json").read_text())
        self.assertEqual([row["input_id"] for row in manifest["entries"]],
                         ["asvs-universe", "asvs-participants-V1", "asvs-participants-V2", "asvs-participants-V5",
                          "asvs-participants-V16"])

    def test_no_participating_chapter_publishes_an_empty_accounting_the_join_consumes(self):
        self.publish(unresolved=True)
        invoker = dispatch_support.ValidatorInvoker()
        pointer = self.dispatch(invoker)
        self.assertIn(pointer["status"], {"OK", "OK_WITH_GAPS"})
        accounting = owasp_dispatch.load_verified_accounting(self.run_id, facts=self.facts)
        self.assertEqual([cell for cell in accounting["cells"] if cell["disposition"] == "dispatched"], [])
        self.assertEqual(invoker.packages, [])
        self.assertIn(self.join()["status"], {"OK", "OK_WITH_GAPS"})

        # An unchanged re-run reuses T03-T06 and the accepted accounting and dispatches nothing.
        prepared = workbench.prepare_handoffs(self.run_id, "dagster-test")
        self.assertTrue(all(prepared[name]["reused"] for name in ("lane_in", "applicability", "batching", "handoffs")))
        again = dispatch_support.ValidatorInvoker()
        reused = self.dispatch(again)
        self.assertTrue(reused["reused"])
        self.assertEqual(reused["attempt_id"], pointer["attempt_id"])


class RunDispatchRefusalTests(WorkbenchCase):
    """``run_dispatch`` starts no validator without an accepted, within-budget universe matching the handoffs."""

    def test_refuses_without_a_universe_before_any_call(self):
        spy = dispatch_support.ValidatorInvoker()
        with self.assertRaisesRegex(Blocked, "accepted 04-owasp-universe"):
            workbench.run_dispatch(self.run_id, "dagster-test", facts=self.facts, invoker=spy)
        self.assertEqual(spy.packages, [])
        with self.assertRaisesRegex(Blocked, "accepted 04-owasp-universe"):
            workbench.prepare_handoffs(self.run_id, "dagster-test")

    def test_refuses_a_blocked_universe(self):
        self.publish()
        pointer_path = self.data / "jobs" / "04-owasp-universe" / "whole" / "accepted.json"
        pointer = json.loads(pointer_path.read_text())
        routing_fixture.write_json(pointer_path, dict(pointer, status="BLOCKED"))
        spy = dispatch_support.ValidatorInvoker()
        with self.assertRaisesRegex(Blocked, "not accepted"):
            workbench.run_dispatch(self.run_id, "dagster-test", facts=self.facts, invoker=spy)
        self.assertEqual(spy.packages, [])

    def test_refuses_when_the_handoff_count_differs_from_the_plan(self):
        self.publish()
        workbench.prepare_handoffs(self.run_id, "dagster-test")
        pointer_path = self.data / "jobs" / "04-owasp-universe" / "whole" / "accepted.json"
        pointer = json.loads(pointer_path.read_text())
        universe_path = pointer_path.parent / "attempts" / pointer["attempt_id"] / "outputs" / "owasp-universe.json"
        universe = json.loads(universe_path.read_text())
        target = next(row for row in universe["targets"] if row["chapter_id"] == "V6")
        target.update(decision="participating", reason_code="participating_code_cited", planned_validator_calls=1,
                      participants=deepcopy(universe["targets"][4]["participants"]),
                      files=deepcopy(universe["targets"][4]["files"]),
                      evidence_bundle=deepcopy(universe["targets"][4]["evidence_bundle"]))
        universe["budget"]["planned_validator_calls"] += 1
        routing_fixture.write_json(universe_path, universe)
        pointer["artifacts"]["outputs/owasp-universe.json"] = routing_fixture.sha(universe_path)
        routing_fixture.write_json(pointer_path, pointer)
        spy = dispatch_support.ValidatorInvoker()
        with self.assertRaisesRegex(Blocked, "differ from the universe's planned 5"):
            workbench.run_dispatch(self.run_id, "dagster-test", facts=self.facts, invoker=spy)
        self.assertEqual(spy.packages, [])

    def test_parallelism_is_capped_by_the_persona_pool(self):
        slots = tunables.shared("pool_persona_llm_slots")
        self.assertEqual(workbench.dispatch_parallelism(None), slots)
        self.assertEqual(workbench.dispatch_parallelism(2), min(2, slots))
        self.assertEqual(workbench.dispatch_parallelism(slots + 7), slots)
        with self.assertRaises(ValueError):
            workbench.dispatch_parallelism(0)


@unittest.skipIf(dagster_workflow is None, "dagster is not installed")
class OwaspWorkbenchDagsterTests(WorkbenchCase):
    def test_full_review_runs_handoffs_and_dispatch_before_the_join(self):
        dependencies = dagster_workflow.full_review.graph.dependency_structure

        def upstream(name):
            return {output.node_name for output in dependencies.all_upstream_outputs_from_node(name)}
        self.assertIn("job_04_owasp_validation_worklist", upstream("job_04_owasp_validator_handoffs"))
        self.assertIn("job_01_component_characterization", upstream("job_04_owasp_validator_handoffs"))
        self.assertEqual(upstream("job_04_owasp_validator_dispatch"), {"job_04_owasp_validator_handoffs", "workflow_config"})
        self.assertIn("job_04_owasp_validator_dispatch", upstream("job_04_asvs_masvs"))
        self.assertEqual(dagster_workflow.owasp_validator_dispatch_work.pool, dagster_workflow.PERSONA_POOL)
        self.assertEqual(dagster_workflow.owasp_validator_handoffs_work.pool, dagster_workflow.CPU_POOL)

    def test_ops_publish_the_accounting_under_the_join_facts(self):
        self.publish(unresolved=True)
        configured = {"engagement_run_id": self.run_id, "force": False}
        invoker = dispatch_support.ValidatorInvoker()
        with mock.patch("standards_lifecycle.prepare_owasp_join", return_value=self.facts) as facts, \
                mock.patch.object(workbench, "live_invoker", return_value=invoker):
            handoffs = dagster_workflow.owasp_validator_handoffs_work(build_op_context(), configured, [])
            pointer = dagster_workflow.owasp_validator_dispatch_work(build_op_context(), configured, [handoffs])
        facts.assert_called_once_with(self.run_id)
        self.assertIn(handoffs["status"], {"OK", "OK_WITH_GAPS"})
        self.assertEqual(owasp_dispatch.load_verified_accounting(self.run_id, facts=self.facts)["attempt_id"],
                         pointer["attempt_id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
