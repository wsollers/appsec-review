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

import execution_state as state
from schema_validate import SchemaStore, validate_document
import threat_model_core as tm
import validate_job_output as output_validator


class ThreatModelCoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.owner = Path(self.temporary.name)
        fixture = ROOT / "tests/fixtures/component-characterization/hello-autotools.json"
        self.component = json.loads(fixture.read_text(encoding="utf-8"))
        self.inputs = {
            "run_id": "run1", "source_snapshot_sha256": self.component["source_snapshot_sha256"],
            "component_attempt_id": "component-1",
            "component_pointer_sha256": "sha256:" + "1" * 64,
            "component_envelope_sha256": "sha256:" + "2" * 64,
            "component_map_path": "data/jobs/01-component-characterization/attempts/component-1/component-purpose-map.json",
            "component_map_sha256": "3" * 64, "evidence_attempt_id": "evidence-1",
            "evidence_manifest_sha256": "sha256:" + "4" * 64,
            "evidence_path": "data/jobs/02-evidence-assembly/attempts/evidence-1/evidence/index.json",
            "evidence_sha256": "5" * 64, "component_map": self.component, "code": {},
        }

    def tearDown(self):
        self.temporary.cleanup()

    def test_deterministic_golden_schema_and_claim_ceiling(self):
        first = tm.build_model(self.inputs, "attempt-1")
        self.assertEqual(first, tm.build_model(deepcopy(self.inputs), "attempt-1"))
        self.assertEqual(validate_document(first, "integrated-threat-model.schema.json"), [])
        self.assertEqual(tm.validate_model(first, self.inputs), [])
        expected = json.loads((ROOT / "tests/fixtures/threat-model-core/model-expectations.json").read_text())
        self.assertEqual([item["element_id"] for item in first["elements"]], expected["element_ids"])
        self.assertEqual([item["flow_id"] for item in first["flows"]], expected["flow_ids"])
        self.assertEqual([item["boundary_id"] for item in first["trust_boundaries"]], expected["boundary_ids"])
        self.assertEqual(len(first["stride_hypotheses"]), expected["hypothesis_count"])
        self.assertEqual(first["rescope_triggers"][0]["trigger_id"], "trigger-f03-docs-become-executable")
        self.assertIn("bounded to 1 round", first["rescope_triggers"][0]["statement"])
        self.assertEqual(sorted({item["stride_category"] for item in first["stride_hypotheses"]}),
                         expected["stride_categories"])
        role = json.loads((ROOT / "registry/roles/threat-model-core.json").read_text())
        tooling = json.loads((ROOT / "registry/tooling-profiles/threat-model-static-evidence.json").read_text())
        self.assertEqual(set(role["allowed_outputs"]), set(tooling["claim_limits"]["allowed"]))
        self.assertTrue({"finding", "severity", "runtime_state"} <= set(role["forbidden_outputs"]))

    def test_uncited_and_dangling_dfd_records_fail_closed(self):
        model = tm.build_model(self.inputs, "attempt-1")
        uncited = deepcopy(model); uncited["elements"][0]["citations"] = []
        self.assertTrue(tm.validate_model(uncited, self.inputs))
        stale = deepcopy(model); stale["flows"][0]["citations"][0]["sha256"] = "0" * 64
        self.assertTrue(any("exact accepted" in error for error in tm.validate_model(stale, self.inputs)))
        endpoint = deepcopy(model); endpoint["flows"][0]["destination_element_id"] = "element-missing"
        self.assertTrue(any("dangling flow endpoint" in error for error in tm.validate_model(endpoint, self.inputs)))
        boundary = deepcopy(model); boundary["flows"][0]["boundary_ids"] = ["boundary-missing"]
        self.assertTrue(any("dangling trust boundary" in error for error in tm.validate_model(boundary, self.inputs)))

    def test_every_boundary_crossing_requires_complete_stride_accounting(self):
        model = tm.build_model(self.inputs, "attempt-1")
        missing = deepcopy(model); missing["stride_coverage"] = []
        self.assertTrue(any("every and only" in error for error in tm.validate_model(missing, self.inputs)))
        orphan = deepcopy(model); orphan["stride_hypotheses"] = orphan["stride_hypotheses"][1:]
        self.assertTrue(any("hypothesis decision has no candidate" in error for error in tm.validate_model(orphan, self.inputs)))
        unresolved = deepcopy(model)
        unresolved["stride_coverage"][0]["decisions"]["spoofing"] = "unresolved"
        unresolved["stride_hypotheses"] = [item for item in unresolved["stride_hypotheses"]
                                             if item["stride_category"] != "spoofing"]
        self.assertTrue(any("explicit gap" in error for error in tm.validate_model(unresolved, self.inputs)))

    def test_hypotheses_cannot_be_promoted_to_findings_severity_or_runtime_facts(self):
        for key, value in (("finding", True), ("severity", "high"), ("observed_runtime", True)):
            model = tm.build_model(self.inputs, "attempt-1")
            model["stride_hypotheses"][0][key] = value
            errors = tm.validate_model(model, self.inputs)
            self.assertTrue(errors, key)
            self.assertTrue(any(key in error or "prohibited" in error for error in errors), errors)

    def test_current_inputs_dereferences_exact_f03_bound_f02_artifact(self):
        run_root = self.owner / "runs/run1"; data = run_root / "data/jobs"
        component_base = data / tm.cc.JOB; component_attempt = component_base / "attempts/component-1"
        component_attempt.mkdir(parents=True)
        evidence_attempt = data / tm.cc.UPSTREAM_JOB / "attempts/evidence-1"
        evidence = evidence_attempt / "evidence/index.json"; evidence.parent.mkdir(parents=True)
        state.atomic_json(evidence, {"schema": "fixture/evidence/1"})
        manifest = {"producers": [{"artifacts": [{"path": "evidence/index.json",
            "producer_job_id": "02-evidence-index", "producer_path": "index.json",
            "sha256": tm.sha256(evidence) if hasattr(tm, "sha256") else "sha256:" + state.file_hash(evidence)}]}]}
        manifest_path = evidence_attempt / tm.cc.UPSTREAM_MANIFEST; state.atomic_json(manifest_path, manifest)
        component = deepcopy(self.component)
        component["evidence_manifest_lineage"]["producer_attempt_id"] = "evidence-1"
        component["evidence_manifest_lineage"]["manifest_sha256"] = "sha256:" + state.file_hash(manifest_path)
        component["functional_components"][0]["evidence_citations"][0] = {
            "source_type": "upstream_lane", "path": "evidence/index.json", "line_range": None,
            "tool_name": None, "tool_rule_id": None, "content_hash": state.file_hash(evidence),
            "note": "exact assembled fixture evidence"}
        state.atomic_json(component_attempt / tm.cc.RESULT, component)
        state.atomic_json(component_base / "accepted.json", {"attempt_id": "component-1",
            "envelope_sha256": "e" * 64})

        def fake_data(run_id, *parts):
            return run_root / "data" / Path(*parts)

        with mock.patch.object(tm.cc, "validate", return_value=component_attempt), \
             mock.patch.object(tm.cc, "root", return_value=component_base), \
             mock.patch.object(tm, "data_path", side_effect=fake_data), \
             mock.patch.object(tm, "run_path", return_value=run_root):
            inputs = tm.current_inputs("run1")
            self.assertEqual(inputs["evidence_sha256"], state.file_hash(evidence))
            evidence.write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(tm.Blocked, "evidence artifact changed"):
                tm.current_inputs("run1")
            state.atomic_json(evidence, {"schema": "fixture/evidence/1"})
            changed = deepcopy(component)
            changed["evidence_manifest_lineage"]["manifest_sha256"] = "sha256:" + "0" * 64
            state.atomic_json(component_attempt / tm.cc.RESULT, changed)
            with self.assertRaisesRegex(tm.Blocked, "evidence manifest changed"):
                tm.current_inputs("run1")

            state.atomic_json(component_attempt / tm.cc.RESULT, component)
            component["functional_components"][1]["evidence_citations"][0] = {
                "source_type": "upstream_lane", "path": "evidence/second.json", "line_range": None,
                "tool_name": None, "tool_rule_id": None, "content_hash": "a" * 64, "note": "ambiguous"}
            second = evidence_attempt / "evidence/second.json"; state.atomic_json(second, {"second": True})
            manifest["producers"][0]["artifacts"].append({"path": "evidence/second.json",
                "producer_job_id": "02-evidence-index", "producer_path": "second.json",
                "sha256": "sha256:" + state.file_hash(second)})
            state.atomic_json(manifest_path, manifest)
            component["evidence_manifest_lineage"]["manifest_sha256"] = "sha256:" + state.file_hash(manifest_path)
            state.atomic_json(component_attempt / tm.cc.RESULT, component)
            # ADR-0013: several cited artifacts bind the first (sorted), not a block
            self.assertIn("/evidence/", tm.current_inputs("run1")["evidence_path"])

        with mock.patch.object(tm.cc, "validate", side_effect=tm.Blocked("stale F03 accepted lineage")):
            with self.assertRaisesRegex(tm.Blocked, "stale F03 accepted lineage"):
                tm.current_inputs("run1")

    def test_attempt_validation_rebuilds_from_immutable_inputs(self):
        attempt = self.owner / "attempt-1"; attempt.mkdir()
        state.atomic_json(attempt / "inputs.json", self.inputs)
        state.atomic_json(attempt / tm.RESULT, tm.build_model(self.inputs, attempt.name))
        permission, lineage = tm._receipts(self.inputs)
        state.atomic_json(attempt / "permission.json", permission)
        state.atomic_json(attempt / "lineage.json", lineage)
        tm._validate_attempt(attempt, self.inputs)
        forged = tm.build_model(self.inputs, attempt.name)
        forged["flows"][0]["auth_context"] = "forged reseal"
        state.atomic_json(attempt / tm.RESULT, forged)
        with self.assertRaisesRegex(tm.Blocked, "differs from deterministic"):
            tm._validate_attempt(attempt, self.inputs)
        state.atomic_json(attempt / tm.RESULT, tm.build_model(self.inputs, attempt.name))
        forged = deepcopy(permission); forged["permissions"] = ["write-run-data"]
        state.atomic_json(attempt / "permission.json", forged)
        with self.assertRaisesRegex(tm.Blocked, "receipt differs"):
            tm._validate_attempt(attempt, self.inputs)
        state.atomic_json(attempt / "permission.json", permission)
        forged_lineage = deepcopy(lineage); forged_lineage["build_lineage_sha256"] = "sha256:" + "0" * 64
        state.atomic_json(attempt / "lineage.json", forged_lineage)
        with self.assertRaisesRegex(tm.Blocked, "receipt differs"):
            tm._validate_attempt(attempt, self.inputs)

    def test_prohibited_conclusion_text_and_generic_contract_policy_fail_closed(self):
        contract = json.loads((ROOT / "registry/output-contracts/threat-model-core.json").read_text())
        policy = output_validator.CLAIM_CLASS_POLICIES["threat-model-core"]
        self.assertEqual(policy["claim_class_id"], contract["claim_class"]["claim_class_id"])
        self.assertEqual(policy["allowed_assertions"], set(contract["claim_class"]["allowed_assertions"]))
        for text in ("Verified finding: auth bypass", "severity: high", "observed runtime exposure",
                     "the target is compliant", "the issue has been remediated"):
            model = tm.build_model(self.inputs, "attempt-1")
            model["stride_hypotheses"][0]["statement"] = text
            self.assertTrue(any("prohibited conclusion" in error for error in tm.validate_model(model, self.inputs)), text)
        attempt = self.owner / "contract"; attempt.mkdir()
        model = tm.build_model(self.inputs, "attempt-1")
        state.atomic_json(attempt / tm.RESULT, model)
        self.assertEqual(output_validator.validate_contract_result(attempt, contract, run_id="run1"), [])
        model["stride_hypotheses"][0]["statement"] = "severity: high"
        state.atomic_json(attempt / tm.RESULT, model)
        self.assertTrue(any("severity promotion" in error for error in
                            output_validator.validate_contract_result(attempt, contract, run_id="run1")))

    def test_owned_registry_records_are_schema_valid(self):
        store = SchemaStore()
        records = (("job-templates/03-threat-model-dfd-stride.json", "job-template.schema.json"),
            ("roles/threat-model-core.json", "role.schema.json"),
            ("domains/threat-model-core.json", "domain.schema.json"),
            ("tooling-profiles/threat-model-static-evidence.json", "tooling-profile.schema.json"),
            ("output-contracts/threat-model-core.json", "output-contract.schema.json"))
        for relative, schema in records:
            value = json.loads((ROOT / "registry" / relative).read_text())
            self.assertEqual(validate_document(value, schema, store), [], relative)


if __name__ == "__main__":
    unittest.main()
