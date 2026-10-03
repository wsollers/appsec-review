"""Acceptance tests for gap punch list items P22-P34 (docs/TODO/gap-punchlist-hello-autotools-2026-10-03.md).

Each test encodes the desired behaviour after the fix and is an expected failure until then.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from owasp_dispatch_support import DispatchCase  # noqa: E402
import test_full_review_input_assembly as assembly_tests  # noqa: E402
import test_owasp_component_routing as routing_tests  # noqa: E402
import test_owasp_join_report as join_tests  # noqa: E402
import test_bounded_analysis_workers as bounded_tests  # noqa: E402
import test_standards_lifecycle as standards_tests  # noqa: E402
import test_threat_model_reconciliation as reconciliation_tests  # noqa: E402
import test_threat_workbench as workbench_tests  # noqa: E402

import bounded_analysis_workers as workers  # noqa: E402
import control_feature_lifecycle as life  # noqa: E402
import execution_state  # noqa: E402
import full_review_input_assembly as assembly  # noqa: E402
import owasp_applicability  # noqa: E402
import owasp_component_routing as routing  # noqa: E402
import owasp_join_report as join  # noqa: E402
import standards_lifecycle as lifecycle  # noqa: E402
import threat_model_core as tm  # noqa: E402
import threat_model_reconciliation as tr  # noqa: E402
import threat_workbench as tw  # noqa: E402

SCHEMAS = ROOT.parent / "schemas"
H = "sha256:" + "a" * 64
NO_RULE = "No deterministic applicability rule matched this target."
ASSESSMENT_GAP = "control-specific assessment has not been performed"


class OwaspJoinGapTests(DispatchCase):
    chapters = ("V1",)
    honest_inputs = join_tests.OwaspJoinReportTests.honest_inputs
    mutable = staticmethod(join_tests.OwaspJoinReportTests.mutable)

    def _unresolved_rows(self, count: int, make_source):
        inputs = self.mutable(self.honest_inputs())
        base_assignment = inputs["plan"].worklist["assignments"][0]
        base_source = inputs["applicability"]["rows"][0]
        base_accounting = inputs["accounting"]["rows"][0]
        assignments, sources, accounting_rows = [], [], []
        for index in range(count):
            assignment, accounting = deepcopy(base_assignment), deepcopy(base_accounting)
            suffix = str(index)
            assignment.update(assignment_id="assignment-" + suffix, target_id="target-" + suffix,
                              control_id="control-" + suffix, source_row_hash="0" * 64)
            source = make_source(deepcopy(base_source))
            source.update(target_id=assignment["target_id"], control_id=assignment["control_id"])
            accounting.update(row_index=index, row_disposition="not_a_validator_assignment", fragments=[])
            assignments.append(assignment); sources.append(source); accounting_rows.append(accounting)
        inputs["plan"].worklist["assignments"] = assignments
        inputs["applicability"]["rows"] = sources
        inputs["accounting"]["rows"] = accounting_rows
        inputs["results"] = {}
        return join.derive(inputs)[join.GAPS]["gaps"]

    def test_p22_identical_statement_across_rows_is_one_gap(self):
        """P22: rows sharing one unresolved rationale yield one gap per (kind, statement) with all row indices."""
        rationale = "Shared unresolved rationale for every row."

        def source(row):
            row.update(applicability_status="cannot_determine", rationale=rationale)
            return row
        gaps = self._unresolved_rows(3, source)
        matching = [gap for gap in gaps if gap["statement"] == rationale]
        self.assertEqual(len(matching), 1, f"{len(matching)} gaps repeat the same statement")
        self.assertEqual(sorted(matching[0]["row_indices"]), [0, 1, 2])

    def test_p23_no_rule_cannot_determine_does_not_add_source_completeness_gap(self):
        """P23: a cannot_determine row whose only cause is "no rule" raises no source-completeness gap."""
        def source(row):
            return owasp_applicability._unresolved(row, NO_RULE, [])
        gaps = self._unresolved_rows(1, source)
        completeness = [gap["statement"] for gap in gaps if gap["statement"].startswith("Source completeness is")]
        self.assertEqual(completeness, [], "no-rule row still raises a source-completeness gap")


class OwaspComponentRoutingGapTests(unittest.TestCase):
    _cls = routing_tests.OwaspComponentRoutingTests
    _freeciv_like_map = _cls._freeciv_like_map
    _publish_component = _cls._publish_component
    _publish_lane_in = _cls._publish_lane_in

    def _setup(self, edit):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(setattr, execution_state, "RUNS", execution_state.RUNS)
        execution_state.RUNS = Path(self.temporary.name) / "runs"
        self.run_id = "freeciv-routing"
        self.run = execution_state.RUNS / self.run_id
        self.data = self.run / "data"
        routing_tests.write_json(self.run / "run-status.json", {"run_id": self.run_id, "status": "READY"})
        self.component_map = self._freeciv_like_map()
        edit(self.component_map)
        self.component_pointer = self._publish_component(self.component_map)
        self.manifest, self.manifest_path, self.t03_pointer = self._publish_lane_in()
        return routing.assemble(self.run_id)

    @staticmethod
    def _component(value, component_id):
        return next(row for row in value["functional_components"] if row["component_id"] == component_id)

    def test_p24_known_cli_without_network_trait_gets_domain_not_applicable_rule(self):
        """P24: a known high-confidence CLI component with no network trait gets domain-selector not_applicable rules."""
        def edit(value):
            row = self._component(value, "ruleset-loader")
            row.update(component_type="command-line application", coarse_group="native-runtime",
                       aliases=["cli"], confidence="high", deployability="deployable",
                       observed_purpose="Implements a local command-line tool.")
        request, _route = self._setup(edit)
        rules = [rule for rule in request["rules"] if rule["component_id"] == "ruleset-loader"]
        not_applicable = [rule for rule in rules if rule["decision"]["status"] == "not_applicable"
                          and rule["selector"]["domain_ids"]]
        self.assertTrue(not_applicable, f"no not_applicable domain rule for the CLI component: {rules}")

    def test_p25_medium_confidence_component_gets_rule_and_no_incomplete_gap(self):
        """P25: a medium-confidence (partial) component still gets a rule and no incomplete-classification gap."""
        def edit(value):
            self._component(value, "freeciv-server")["confidence"] = "medium"
        request, route = self._setup(edit)
        self.assertIn("freeciv-server", [rule["component_id"] for rule in request["rules"]],
                      "medium-confidence component received no applicability rule")
        incomplete = [gap for gap in route["gaps"] if gap["component_id"] == "freeciv-server"
                      and "classification is incomplete" in gap["summary"]]
        self.assertEqual(incomplete, [])


class StandardsLifecycleGapTests(unittest.TestCase):
    setup_paths = standards_tests.StandardsLifecycleTests.setup_paths
    standards = standards_tests

    def _worklist(self, component, records):
        def load(_run, spec):
            if spec[0] == lifecycle.COMPONENT[0]: return component, self.standards.COMPONENT_BIND
            if spec[0] == lifecycle.STANDARDS[0]: return self.standards.STANDARD, self.standards.STANDARDS_BIND
            raise AssertionError(spec)
        with tempfile.TemporaryDirectory() as folder:
            _run, p1, p2 = self.setup_paths(folder)
            with p1, p2, mock.patch.object(lifecycle, "_load", side_effect=load), \
                 mock.patch.object(lifecycle, "_record_documents", return_value=records):
                prepared = lifecycle.prepare_worklist("run-a", "04-owasp-validation-worklist")
                return prepared, execution_state.read_json(prepared["request_path"])

    @unittest.expectedFailure
    def test_p26_assessment_gap_is_one_summary_not_per_row(self):
        """P26: per-control rows do not each carry "control-specific assessment has not been performed"."""
        lanes = ["04-asvs-masvs"]
        component = {"source_snapshot_sha256": H, "functional_components": [
            {"component_id": "cli", "downstream_lanes": lanes}, {"component_id": "lib", "downstream_lanes": lanes}]}
        records = []
        for control in ("V1.1.1", "V1.1.2"):
            wrapper = deepcopy(self.standards.WRAPPER); wrapper["record_id"] = control
            records.append((dict(self.standards.STANDARD["records"][0], record_id=control), wrapper))
        _prepared, request = self._worklist(component, records)
        controls = request["payload"]["controls"]
        repeated = sum(control["gaps"].count(ASSESSMENT_GAP) for control in controls)
        self.assertLessEqual(repeated, 1, f"{repeated} rows repeat the assessment gap")

    @unittest.expectedFailure
    def test_p26_no_fallback_to_all_components_when_none_routed(self):
        """P26: with no component routed to the lane, the worklist does not fall back to every component."""
        component = {"source_snapshot_sha256": H, "functional_components": [
            {"component_id": "cli", "downstream_lanes": ["05-native-memory"]}]}
        prepared, _request = self._worklist(component, [(self.standards.STANDARD["records"][0], self.standards.WRAPPER)])
        self.assertEqual(prepared["control_count"], 0, "unrouted components were assessed by fallback")

    @unittest.expectedFailure
    def test_p28_hit_under_component_path_pattern_matches(self):
        """P28: an IaC hit whose location.path is under the component's path patterns yields one assessment."""
        component = {"source_snapshot_sha256": H, "functional_components": [{
            "component_id": "cli", "downstream_lanes": ["15-deployment-hardening"],
            "path_patterns": ["src/**"], "representative_locations": ["src/main.c"]}]}
        stig = {"work_items": [{"target_id": "cli", "control_id": "SRG-1", "standard_family": "DISA_STIG_SRG",
            "standard_version": "1", "applicability": "cannot_determine", "tailoring": "local",
            "citation_ids": ["c1"]}]}
        hit = {"hit_id": "h1", "tool_id": "hadolint", "rule": {"rule_id": "DL3002"},
               "location": {"path": "src/Dockerfile", "path_disposition": "published",
                            "start_line": 1, "end_line": 1}}
        self.assertNotIn("cli", str(hit))
        binding = {"attempt_id": "a", "artifact_path": "x", "artifact_sha256": H, "accepted_pointer_sha256": H}

        def load(_run, spec):
            if spec[0] == lifecycle.COMPONENT[0]: return component, self.standards.COMPONENT_BIND
            if spec[0] == "15-stig-srg-validation-worklist": return stig, {"job_id": "stig", **binding}
            if spec[0] == lifecycle.IAC[0]: return {"rule_hits": [hit]}, {"job_id": "iac", **binding}
            raise AssertionError(spec)
        with tempfile.TemporaryDirectory() as folder:
            _run, p1, p2 = self.setup_paths(folder)
            with p1, p2, mock.patch.object(lifecycle, "_load", side_effect=load):
                prepared = lifecycle.prepare_deployment("run-a")
        self.assertEqual(len(prepared["result"]["assessments"]), 1, "path-matched hit produced no assessment")
        self.assertFalse(any("no matching deployment assessment target" in gap for gap in prepared["result"]["gaps"]))


class FullReviewIacPresenceTests(unittest.TestCase):
    _cls = assembly_tests.FullReviewInputAssemblyTests
    setUp = _cls.setUp
    tearDown = _cls.tearDown
    _accepted_fuzz = _cls._accepted_fuzz
    _accepted_component = _cls._accepted_component

    @unittest.expectedFailure
    def test_p27_dockerfile_launches_iac_config_scan(self):
        """P27: a Dockerfile-only target launches 02-iac-config-scan instead of SKIPPED_NA."""
        (self.target / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        pointer = self._accepted_component()
        plan = assembly.derive_plan(pointer, self.run.absolute(), self.run / "inputs/derived-full-review-plan.json",
                                    run_id="review-1", generated_at=assembly_tests.STAMP)
        self.assertIn("02-iac-config-scan", [row["job_id"] for row in plan["launches"]],
                      "Dockerfile target skipped the IaC config scan")


class NativeMemoryGapTests(unittest.TestCase):
    def test_p29_zero_candidates_has_no_runtime_gap(self):
        """P29: native-memory with zero candidates reports no host/runtime gap and status OK."""
        bounded = bounded_tests
        value = workers.native_memory(run_id="r", attempt_id="a", source_generation=H, bindings=bounded.B,
            units=[{"unit_id": "u", "language": "c", "path": "src/a.c", "source_sha256": H, "signals": [],
                    "coverage": ["clang-static-analyzer"], "citations": bounded.C}])
        self.assertEqual(value["candidates"], [])
        self.assertEqual(value["gaps"], [])
        self.assertEqual(value["status"], "OK")


class DiscoverySchemaTests(unittest.TestCase):
    @staticmethod
    def _properties(name):
        return sorted(json.loads((SCHEMAS / name).read_text(encoding="utf-8"))["properties"])

    @unittest.expectedFailure
    def test_p30_project_discovery_schema_defines_absence_observations(self):
        """P30: project-discovery schema separates verified absence (absence_observations) from coverage gaps."""
        self.assertIn("absence_observations", self._properties("project-discovery.schema.json"))

    @unittest.expectedFailure
    def test_p30_operations_topology_schema_defines_absence_observations(self):
        """P30: operations-topology schema separates verified absence (absence_observations) from coverage gaps."""
        self.assertIn("absence_observations", self._properties("operations-topology.schema.json"))

    @unittest.expectedFailure
    def test_p34_dev_project_discovery_schema_defines_informational_notes(self):
        """P34: the 02-dev-project-discovery output schema defines informational_notes beside coverage_gaps."""
        import discovery_gate
        self.assertEqual(discovery_gate.SCHEMAS["02-dev-project-discovery"], "project-discovery.schema.json")
        self.assertIn("informational_notes", self._properties("project-discovery.schema.json"))


class ThreatWorkbenchGapTests(unittest.TestCase):
    setUp = workbench_tests.JoinTests.setUp

    def test_p31_unbuilt_cells_are_one_gap(self):
        """P31: with native traits, unbuilt ADR-0019 cells are reported in exactly one gap naming them."""
        model = tw.join(self.base, workbench_tests.record(self.base), self.replies)
        named = [gap for gap in model["gaps"] if "native-parser-input-specialist" in gap["statement"]
                 and "challenge-refutation-cell" in gap["statement"]]
        unbuilt = [gap for gap in model["gaps"] if gap["kind"] == "omitted_workcell"
                   and ("not built" in gap["statement"] or "challenge/refutation" in gap["statement"])]
        self.assertEqual(len(named), 1, f"unbuilt cells reported as {len(unbuilt)} separate gaps")
        self.assertEqual(unbuilt, named)


class ThreatModelAssumptionGapTests(unittest.TestCase):
    def test_p32_core_assumptions_are_not_counted_as_gaps(self):
        """P32: assumptions from component-map unknowns are not also published as threat-model gaps."""
        component = json.loads((ROOT / "tests/fixtures/component-characterization/hello-autotools.json").read_text())
        inputs = workbench_tests.core_inputs(component)
        inputs["code"] = tm._code_hashes()
        captured = {}

        def coordinate(base, **kwargs):
            attempt = Path(base) / "attempts/attempt-1"; attempt.mkdir(parents=True)
            return kwargs["execute_attempt"]({"attempt": attempt, "attempt_id": "attempt-1",
                                              "started_at": "2026-09-27T00:00:00Z"}, inputs, "sha256:" + "0" * 64)

        def record(_base, _attempt, **kwargs):
            captured.update(kwargs)
            return kwargs
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch.object(tm, "root", return_value=Path(folder)), \
             mock.patch.object(tm.tw, "execute", return_value=None), \
             mock.patch.object(tm, "coordinate_worker_lifecycle", side_effect=coordinate), \
             mock.patch.object(tm, "record_terminal_current", side_effect=record):
            tm.run("run1", "dagster-a")
        model = tm.build_model(inputs, "attempt-1")
        statements = [item["statement"] for item in model["assumptions"]]
        self.assertTrue(statements)
        self.assertEqual([gap for gap in captured["gaps"] if gap in statements], [],
                         "assumptions are double-counted as gaps")

    def test_p32_reconciliation_unchanged_assumptions_are_not_gaps(self):
        """P32: reconciliation with unchanged generations does not re-emit unchanged assumptions as gaps."""
        case = reconciliation_tests.ThreatModelReconciliationTests("test_unchanged_generations_preserve_unresolved_assumptions_without_promotion")
        case.setUp(); self.addCleanup(case.tearDown)
        value = tr.build_result(case.inputs, "reconcile-1")
        self.assertFalse(value["comparison"]["component_generation_changed"])
        self.assertEqual(value["status"], "OK", "unchanged assumptions still drive OK_WITH_GAPS")


class DynamicRescopeTests(unittest.TestCase):
    def test_p33_initial_dynamic_rescope_is_ok_without_gap(self):
        """P33: the first dynamic-rescope run (no prior accepted generation) is OK with no gap."""
        inputs = {"run_id": "run", "job_id": "dynamic-rescope", "source_generation": H, "code": {},
                  "intake": {}, "nodes": ["00-intake"], "edges": [], "changed_nodes": ["00-intake"],
                  "max_iterations": 1}
        with mock.patch.object(life.dynamic_rescope, "dependency_index", return_value={"nodes": ["00-intake"]}), \
             mock.patch.object(life.dynamic_rescope, "bounded_rescope",
                               return_value={"run_id": "run", "state": "INITIAL_BASELINE"}):
            _result, status, gaps, _skip = life._produce("run", "dynamic-rescope", inputs)
        self.assertEqual(gaps, [])
        self.assertEqual(status, "OK")


if __name__ == "__main__":
    unittest.main()
