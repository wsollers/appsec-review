from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from owasp_dispatch_support import DispatchCase, Routed, ValidatorInvoker, b14

import execution_state
import owasp_dispatch as od
import owasp_join_report as join
from schema_validate import SchemaStore, validate_document


class OwaspJoinReportTests(DispatchCase):
    chapters = ("V1",)

    def honest_inputs(self):
        self.dispatch()
        return join.load_verified_inputs(self.run_id, facts=self.facts())

    @staticmethod
    def mutable(inputs):
        return {"accounting": deepcopy(inputs["accounting"]),
            "plan": SimpleNamespace(worklist=od.thaw(inputs["plan"].worklist)),
            "applicability": deepcopy(inputs["applicability"]),
            "results": deepcopy(inputs["results"]),
            "input_manifest": deepcopy(inputs["input_manifest"]),
            "input_manifest_sha256": inputs["input_manifest_sha256"],
            "applicability_model_sha256": inputs["applicability_model_sha256"]}

    def test_verified_happy_path_is_deterministic_and_preserves_provenance(self):
        inputs = self.honest_inputs()
        first, second = join.derive(inputs), join.derive(inputs)
        self.assertEqual(first, second)
        matrix = first[join.MATRIX]
        self.assertEqual(matrix["denominators"], {"selected": 1, "applicable": 1, "assessed": 1, "satisfied": 1})
        row = matrix["rows"][0]
        self.assertEqual(row["joined_status"], "satisfied")
        self.assertTrue(row["assessment_results"])
        self.assertEqual(row["assessment_results"][0]["terminal"]["state"], "OK")
        self.assertEqual(first[join.ROUTES]["routes"], [])
        report = join.summary(first)
        self.assertIn("Approved by:", report); self.assertIn("Evidence admission cutoff:", report)
        self.assertIn("Permissions:", report); self.assertIn("not findings", report)

    def test_failed_cell_is_visible_and_yields_not_assessed(self):
        pointer = self.dispatch(Routed({1: b14.Raising(RuntimeError("fixture failure"))}))
        self.assertEqual(self.accounting(pointer)["rows"][0]["row_disposition"], "not_assessed")
        outputs = join.derive(join.load_verified_inputs(self.run_id, facts=self.facts()))
        row = outputs[join.MATRIX]["rows"][0]
        self.assertEqual(row["joined_status"], "not_assessed")
        self.assertTrue(any(item["kind"] == "execution" for item in outputs[join.GAPS]["gaps"]))

    def test_tampered_or_stale_accepted_result_fails_before_join(self):
        self.dispatch()
        pointer = self.result_pointer(1)
        result = self.data / "jobs/04-owasp-validator-result" / self.handoff_set["handoffs"][0]["batch_id"] / "attempts" / pointer["attempt_id"] / "outputs/control-assessment-result.json"
        result.write_text(result.read_text() + " ", encoding="utf-8")
        with self.assertRaises((od.DispatchRejected, execution_state.Blocked)):
            join.load_verified_inputs(self.run_id, facts=self.facts())

    def test_join_never_upgrades_partial_negative_or_missing_fragments(self):
        inputs = self.mutable(self.honest_inputs())
        result = next(iter(inputs["results"].values()))
        fragment = result["fragment_results"][0]
        obligation = fragment["proof_obligation_results"][0]
        obligation["outcome"] = "partially_satisfied"
        obligation["evidence_gaps"] = ["One mandatory clause lacks evidence."]
        fragment["assessment_status"] = fragment["final_control_status"] = "partially_satisfied"
        outputs = join.derive(inputs)
        self.assertEqual(outputs[join.MATRIX]["rows"][0]["joined_status"], "partially_satisfied")
        self.assertNotEqual(outputs[join.MATRIX]["rows"][0]["joined_status"], "satisfied")
        inputs["accounting"]["rows"][0]["row_disposition"] = "not_assessed"
        self.assertEqual(join.derive(inputs)[join.MATRIX]["rows"][0]["joined_status"], "not_assessed")

    def test_material_contradiction_is_preserved_as_a_gap(self):
        inputs = self.mutable(self.honest_inputs())
        result = next(iter(inputs["results"].values())); fragment = result["fragment_results"][0]
        obligation = fragment["proof_obligation_results"][0]
        counter = deepcopy(obligation["evidence_citations"][0])
        counter["citation_id"] += "-counter"; counter["observed_fact"] = "Canonical facts conflict."
        obligation.update(outcome="partially_satisfied", counterevidence_citations=[counter],
            contradictions=[{"contradiction_id": "contradiction-1",
                "citation_ids": [obligation["evidence_citations"][0]["citation_id"], counter["citation_id"]],
                "summary": "Canonical evidence conflicts.", "material": True, "resolved": False,
                "resolution": None}])
        fragment["assessment_status"] = fragment["final_control_status"] = "partially_satisfied"
        outputs = join.derive(inputs)
        self.assertEqual(outputs[join.MATRIX]["rows"][0]["joined_status"], "partially_satisfied")
        self.assertTrue(any(item["kind"] == "contradiction" for item in outputs[join.GAPS]["gaps"]))

    def test_na_cannot_determine_out_of_scope_and_denominators_remain_distinct(self):
        inputs = self.mutable(self.honest_inputs())
        base_assignment = inputs["plan"].worklist["assignments"][0]
        base_source = inputs["applicability"]["rows"][0]
        base_accounting = inputs["accounting"]["rows"][0]
        base_result = next(iter(inputs["results"].values()))
        assignments, sources, accounting_rows, results = [], [], [], {}
        statuses = ["applicable", "applicable", "applicable", "conditional", "not_applicable",
                    "cannot_determine", "out_of_scope"]
        for index, applicability in enumerate(statuses):
            assignment, source, accounting = deepcopy(base_assignment), deepcopy(base_source), deepcopy(base_accounting)
            suffix = str(index)
            assignment.update(assignment_id="assignment-" + suffix, target_id="target-" + suffix,
                              control_id="control-" + suffix, source_row_hash="0" * 64)
            source.update(target_id=assignment["target_id"], control_id=assignment["control_id"],
                          applicability_status=applicability)
            accounting.update(row_index=index, row_disposition=("not_a_validator_assignment" if index >= 4 else
                "not_assessed" if index == 3 else "deferred_to_validated_results"))
            accounting["fragments"] = [] if index >= 3 else deepcopy(base_accounting["fragments"])
            assignments.append(assignment); sources.append(source); accounting_rows.append(accounting)
            if index < 3:
                result = deepcopy(base_result); result["result_id"] += suffix
                fragment = result["fragment_results"][0]
                fragment.update(assignment_id=assignment["assignment_id"], target_id=assignment["target_id"],
                                control_id=assignment["control_id"])
                if index == 1:
                    fragment["assessment_status"] = fragment["final_control_status"] = "partially_satisfied"
                    fragment["proof_obligation_results"][0]["outcome"] = "partially_satisfied"
                elif index == 2:
                    fragment["assessment_status"] = fragment["final_control_status"] = "not_satisfied"
                    obligation = fragment["proof_obligation_results"][0]
                    counter = deepcopy(obligation["evidence_citations"][0])
                    counter["citation_id"] += "-negative"; counter["affirmative_contrary_evidence"] = True
                    obligation.update(outcome="not_satisfied", evidence_citations=[],
                                      counterevidence_citations=[counter])
                results[index + 1] = result
                accounting["fragments"][0]["cell_ordinal"] = index + 1
        inputs["plan"].worklist["assignments"] = assignments
        inputs["applicability"]["rows"] = sources
        inputs["accounting"]["rows"] = accounting_rows
        inputs["results"] = results
        outputs = join.derive(inputs); matrix = outputs[join.MATRIX]
        golden = json.loads((Path(__file__).parent / "fixtures/owasp-join-report/denominators.golden.json").read_text())
        self.assertEqual(matrix["denominators"], {key: golden[key] for key in ("selected", "applicable", "assessed", "satisfied")})
        self.assertEqual([row["joined_status"] for row in matrix["rows"]], golden["joined_statuses"])

    def test_dynamic_requests_stay_inert_and_dissent_rescope_are_visible(self):
        inputs = self.mutable(self.honest_inputs())
        result = next(iter(inputs["results"].values())); fragment = result["fragment_results"][0]
        obligation = fragment["proof_obligation_results"][0]
        citation = deepcopy(obligation["evidence_citations"][0])
        fragment["assessment_status"] = fragment["final_control_status"] = "dynamic_test_required"
        obligation.update(outcome="dynamic_test_required", evidence_citations=[],
                          evidence_gaps=["Runtime evidence is required."], dynamic_candidate_ids=["dyn-1"])
        result["dynamic_test_candidates"] = [{"candidate_id": "dyn-1", "fragment_id": fragment["fragment_id"],
            "target_id": fragment["target_id"], "control_id": fragment["control_id"], "component_id": fragment["component_id"],
            "obligation_id": obligation["obligation_id"], "reason_static_is_insufficient": "Runtime behavior is required.",
            "test_type": "safe request", "target_environment": "non-production", "prerequisites": [],
            "identity_and_data_requirements": [], "safety_constraints": ["No production access"],
            "observation_criteria": ["Capture response"], "pass_criteria": ["Control observed"],
            "fail_criteria": ["Control absent"], "inconclusive_criteria": ["Environment differs"],
            "capture_requirements": [], "redaction_requirements": [], "owner": "verification-owner",
            "reentry_path": "targeted reassessment", "state": "proposed", "authorization": "not_authorized",
            "execution": "not_executed", "target_contacted": False, "target_mutated": False}]
        result["dissent"] = [{"dissent_id": "dissent-1", "participant_id": "reviewer-2",
            "role": "standards-mapping-auditor", "summary": "Evidence scope remains disputed.",
            "citation_ids": [citation["citation_id"]], "resolved": False}]
        obligation["counterevidence_citations"] = [citation]
        inputs["applicability"]["rows"][0]["rescope_state"] = "required"
        inputs["applicability"]["rows"][0]["rescope_actions"] = ["Reclassify the component."]
        outputs = join.derive(inputs)
        request = outputs[join.DYNAMIC]["requests"][0]
        self.assertEqual((request["state"], request["authorization"], request["execution"]),
                         ("proposed", "not_authorized", "not_executed"))
        kinds = {item["kind"] for item in outputs[join.GAPS]["gaps"]}
        self.assertTrue({"dissent", "rescope", "evidence"} <= kinds)

    def test_multi_assignment_result_attributes_dynamic_candidate_only_to_exact_row(self):
        inputs = self.mutable(self.honest_inputs())
        assignment = inputs["plan"].worklist["assignments"][0]
        source = inputs["applicability"]["rows"][0]
        accounting = inputs["accounting"]["rows"][0]
        result = next(iter(inputs["results"].values()))
        fragment = result["fragment_results"][0]; obligation = fragment["proof_obligation_results"][0]
        obligation["dynamic_candidate_ids"] = ["dyn-row-one"]
        candidate = {"candidate_id": "dyn-row-one", "fragment_id": fragment["fragment_id"],
            "target_id": fragment["target_id"], "control_id": fragment["control_id"],
            "component_id": fragment["component_id"], "obligation_id": obligation["obligation_id"],
            "reason_static_is_insufficient": "Runtime behavior is required.", "test_type": "safe request",
            "target_environment": "non-production", "prerequisites": [], "identity_and_data_requirements": [],
            "safety_constraints": ["No production access"], "observation_criteria": ["Capture response"],
            "pass_criteria": ["Control observed"], "fail_criteria": ["Control absent"],
            "inconclusive_criteria": ["Environment differs"], "capture_requirements": [],
            "redaction_requirements": [], "owner": "verification-owner", "reentry_path": "targeted reassessment",
            "state": "proposed", "authorization": "not_authorized", "execution": "not_executed",
            "target_contacted": False, "target_mutated": False}
        result["dynamic_test_candidates"] = [candidate]
        second_assignment, second_source, second_accounting = deepcopy(assignment), deepcopy(source), deepcopy(accounting)
        second_assignment.update(assignment_id="assignment-second", target_id="target-second", control_id="V1.1.2")
        second_source.update(target_id="target-second", control_id="V1.1.2")
        second_accounting.update(row_index=1, row_disposition="not_assessed")
        second_fragment = deepcopy(fragment); second_fragment.update(fragment_id="fragment-second",
            assignment_id="assignment-second", target_id="target-second", control_id="V1.1.2")
        second_fragment["proof_obligation_results"][0].update(obligation_id="V1.1.2:1", dynamic_candidate_ids=[])
        result["fragment_results"].append(second_fragment)
        inputs["plan"].worklist["assignments"].append(second_assignment)
        inputs["applicability"]["rows"].append(second_source); inputs["accounting"]["rows"].append(second_accounting)
        outputs = join.derive(inputs); rows = outputs[join.MATRIX]["rows"]
        self.assertEqual(rows[0]["dynamic_candidate_ids"], ["dyn-row-one"])
        self.assertEqual(rows[1]["dynamic_candidate_ids"], [])
        self.assertEqual(rows[1]["joined_status"], "not_assessed")
        self.assertEqual([item["candidate_id"] for item in outputs[join.DYNAMIC]["requests"]], ["dyn-row-one"])

    def test_missing_dynamic_attribution_is_gap_and_ambiguous_identity_fails_closed(self):
        inputs = self.mutable(self.honest_inputs())
        result = next(iter(inputs["results"].values())); fragment = result["fragment_results"][0]
        obligation = fragment["proof_obligation_results"][0]; obligation["dynamic_candidate_ids"] = ["dyn-missing"]
        outputs = join.derive(inputs)
        self.assertEqual(outputs[join.MATRIX]["rows"][0]["dynamic_candidate_ids"], [])
        self.assertTrue(any(item["kind"] == "dynamic_manual" for item in outputs[join.GAPS]["gaps"]))
        candidate = deepcopy(result.get("dynamic_test_candidates", []))
        template = {"candidate_id": "dyn-missing", "fragment_id": fragment["fragment_id"],
            "target_id": fragment["target_id"], "control_id": fragment["control_id"], "component_id": fragment["component_id"],
            "obligation_id": obligation["obligation_id"], "reason_static_is_insufficient": "Runtime evidence required.",
            "test_type": "safe request", "target_environment": "non-production", "prerequisites": [],
            "identity_and_data_requirements": [], "safety_constraints": ["No production"],
            "observation_criteria": ["Observe"], "pass_criteria": ["Present"], "fail_criteria": ["Absent"],
            "inconclusive_criteria": ["Unknown"], "capture_requirements": [], "redaction_requirements": [],
            "owner": "verification-owner", "reentry_path": "reassess", "state": "proposed",
            "authorization": "not_authorized", "execution": "not_executed", "target_contacted": False,
            "target_mutated": False}
        result["dynamic_test_candidates"] = [template, deepcopy(template)]
        with self.assertRaisesRegex(execution_state.Blocked, "ambiguous"):
            join.derive(inputs)

    def test_bare_failure_cannot_promote_and_crosswalk_aliases_dedupe_without_proof_inflation(self):
        inputs = self.mutable(self.honest_inputs())
        result = next(iter(inputs["results"].values())); fragment = result["fragment_results"][0]
        obligation = fragment["proof_obligation_results"][0]; citation = obligation["evidence_citations"][0]
        fragment["assessment_status"] = fragment["final_control_status"] = "not_satisfied"
        obligation["outcome"] = "not_satisfied"
        route = {"route_id": "route-1", "fragment_id": fragment["fragment_id"], "target_id": fragment["target_id"],
            "control_id": fragment["control_id"], "component_id": fragment["component_id"],
            "obligation_ids": [obligation["obligation_id"]], "hypothesis": "The control failed",
            "evidence_citation_ids": [citation["citation_id"]], "recommended_role": "independent-verifier",
            "next_step": "Verify the mechanism independently.", "promotion_state": "candidate_only",
            "finding_created": False, "severity_assigned": False, "execution_authorized": False}
        result["candidate_verification_routes"] = [route]
        outputs = join.derive(inputs)
        self.assertEqual(outputs[join.ROUTES]["routes"], [])
        self.assertTrue(any(item["kind"] == "promotion" for item in outputs[join.GAPS]["gaps"]))
        route["hypothesis"] = "Missing validation may permit an untrusted value to reach the authorization decision."
        alias = {"record_id": "crosswalk-alias-1", "cre_leaf_id": "CRE-1", "snapshot_id": "snapshot-1",
            "source_record_hash": "a" * 64, "standard": "OWASP ASVS", "section_id": "V1.1.1",
            "version": "5.0", "link_type": "navigation_only"}
        alias_two = deepcopy(alias); alias_two["record_id"] = "crosswalk-alias-2"
        inputs["plan"].worklist["assignments"][0]["crosswalk_lineage"] = [alias, alias_two]
        duplicate = deepcopy(route); duplicate["route_id"] = "route-alias"
        result["candidate_verification_routes"].append(duplicate)
        outputs = join.derive(inputs)
        self.assertEqual(len(outputs[join.ROUTES]["routes"]), 1)
        promoted = outputs[join.ROUTES]["routes"][0]
        self.assertEqual(promoted["next_route"], "09-independent-verification")
        self.assertFalse(promoted["finding_created"]); self.assertFalse(promoted["severity_assigned"])
        self.assertEqual(promoted["proof_obligation_ids"], [obligation["obligation_id"]])
        self.assertEqual(len(promoted["crosswalk_aliases"]), 2)
        self.assertEqual(outputs[join.MATRIX]["rows"][0]["candidate_route_ids"], [promoted["route_id"]])

    def test_promotion_language_is_rejected_even_inside_allowed_fields(self):
        inputs = self.mutable(self.honest_inputs())
        result = next(iter(inputs["results"].values())); fragment = result["fragment_results"][0]
        obligation = fragment["proof_obligation_results"][0]; citation = obligation["evidence_citations"][0]
        fragment["assessment_status"] = fragment["final_control_status"] = "not_satisfied"
        obligation["outcome"] = "not_satisfied"
        result["candidate_verification_routes"] = [{"route_id": "route-claim", "fragment_id": fragment["fragment_id"],
            "target_id": fragment["target_id"], "control_id": fragment["control_id"],
            "component_id": fragment["component_id"], "obligation_ids": [obligation["obligation_id"]],
            "hypothesis": "This is a verified finding with severity: high.",
            "evidence_citation_ids": [citation["citation_id"]], "recommended_role": "independent-verifier",
            "next_step": "Verify independently.", "promotion_state": "candidate_only", "finding_created": False,
            "severity_assigned": False, "execution_authorized": False}]
        with self.assertRaises(execution_state.Blocked):
            join.derive(inputs)

    def test_closed_schemas_reject_forbidden_promotion_mutations(self):
        outputs = join.derive(self.honest_inputs()); matrix = outputs[join.MATRIX]
        for field, value in (("finding", True), ("severity", "high"), ("observed_runtime", True),
                             ("compliance", "pass")):
            changed = deepcopy(matrix); changed["rows"][0][field] = value
            self.assertTrue(validate_document(changed, "owasp-control-status-matrix.schema.json"), field)
        store = SchemaStore()
        def assert_closed(value, path="$"):
            if isinstance(value, dict):
                if value.get("type") == "object" or "properties" in value:
                    self.assertFalse(value.get("additionalProperties", True), path)
                for key, item in value.items(): assert_closed(item, f"{path}.{key}")
            elif isinstance(value, list):
                for index, item in enumerate(value): assert_closed(item, f"{path}[{index}]")
        for name in ("owasp-control-status-matrix.schema.json", "owasp-control-status-row.schema.json",
                     "owasp-coverage-gaps-report.schema.json", "owasp-joined-dynamic-requests.schema.json",
                     "owasp-candidate-promotion-routes.schema.json"):
            schema = store.load(name)
            self.assertEqual(schema["$id"], name)
            assert_closed(schema)


if __name__ == "__main__":
    unittest.main()
