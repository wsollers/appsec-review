from __future__ import annotations

from copy import deepcopy
import json
import os
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
import threat_model_reconciliation as tr
import validate_job_output as output_validator


class ThreatModelReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(); self.owner=Path(self.temporary.name)
        self.old_runs=state.RUNS; state.RUNS=self.owner/"runs"; self.run_id="threat-reconcile-fixture"
        component=json.loads((ROOT/"tests/fixtures/component-characterization/hello-autotools.json").read_text())
        baseline_inputs={"run_id":self.run_id,"source_snapshot_sha256":component["source_snapshot_sha256"],
            "component_attempt_id":"component-1","component_pointer_sha256":"sha256:"+"1"*64,
            "component_envelope_sha256":"sha256:"+"2"*64,
            "component_map_path":"data/jobs/01-component-characterization/attempts/component-1/component-purpose-map.json",
            "component_map_sha256":"3"*64,"evidence_attempt_id":"evidence-1",
            "evidence_manifest_sha256":"sha256:"+"4"*64,
            "evidence_path":"data/jobs/02-evidence-assembly/attempts/evidence-1/evidence/index.json",
            "evidence_sha256":"5"*64,"component_map":component,"code":{}}
        model=tm.build_model(baseline_inputs,"threat-1")
        baseline={"job_id":tm.JOB,"attempt_id":"threat-1","accepted_pointer_sha256":"sha256:"+"6"*64,
            "envelope_sha256":"sha256:"+"7"*64,"result_sha256":"sha256:"+"8"*64,
            "input_fingerprint":"sha256:"+"9"*64,"component_map_sha256":"sha256:"+"3"*64,
            "evidence_manifest_sha256":"sha256:"+"4"*64,
            "source_snapshot_sha256":component["source_snapshot_sha256"]}
        current={"job_id":tr.cc.JOB,"attempt_id":"component-1","accepted_pointer_sha256":"sha256:"+"a"*64,
            "envelope_sha256":"sha256:"+"b"*64,"result_sha256":"sha256:"+"c"*64,
            "input_fingerprint":"sha256:"+"d"*64,"component_map_sha256":"sha256:"+"3"*64,
            "evidence_manifest_sha256":"sha256:"+"4"*64,
            "source_snapshot_sha256":component["source_snapshot_sha256"]}
        self.inputs={"run_id":self.run_id,"source_snapshot_sha256":component["source_snapshot_sha256"],
            "baseline":baseline,"baseline_model":model,"baseline_inputs":baseline_inputs,
            "baseline_model_path":"data/jobs/03-threat-model-dfd-stride/attempts/threat-1/integrated-threat-model.json",
            "current":current,"current_component":deepcopy(component),
            "current_component_path":"data/jobs/01-component-characterization/attempts/component-1/component-purpose-map.json",
            "prospective_inputs":deepcopy(baseline_inputs),
            "control":{"schema":"appsec-review/threat-model-reconciliation-input/1.0","inputs":[]},
            "control_path":None,"control_sha256":None,"code":tr._code_hashes()}

    def tearDown(self):
        state.RUNS=self.old_runs; self.temporary.cleanup()

    def test_unchanged_generations_preserve_unresolved_assumptions_without_promotion(self):
        value=tr.build_result(self.inputs,"reconcile-1")
        self.assertEqual(validate_document(value,"threat-model-reconciliation.schema.json"),[])
        self.assertEqual(tr.validate_result(value,self.inputs),[])
        self.assertFalse(value["comparison"]["component_generation_changed"])
        self.assertFalse(value["comparison"]["evidence_generation_changed"])
        self.assertFalse(value["comparison"]["model_records"]["added"])
        self.assertEqual({item["status"] for item in value["unresolved_assumptions"]},{"unresolved"})
        self.assertNotIn("severity",json.dumps(value).lower())

    def test_component_evidence_and_model_deltas_request_l6a_regeneration(self):
        inputs=deepcopy(self.inputs)
        inputs["current"]["component_map_sha256"]="sha256:"+"e"*64
        inputs["current"]["evidence_manifest_sha256"]="sha256:"+"f"*64
        inputs["current_component"]["functional_components"][0]["observed_purpose"]="changed static purpose"
        inputs["prospective_inputs"]["component_map"]=deepcopy(inputs["current_component"])
        value=tr.build_result(inputs,"reconcile-1")
        self.assertTrue(value["comparison"]["component_generation_changed"])
        self.assertTrue(value["comparison"]["evidence_generation_changed"])
        self.assertTrue(value["comparison"]["components"]["changed"])
        self.assertIn("regenerate-l6a",{item["kind"] for item in value["actions"]})
        self.assertEqual(tr.validate_result(value,inputs),[])

    def test_reviewer_and_model_inputs_remain_unresolved_and_non_authoritative(self):
        inputs=deepcopy(self.inputs); assumption=inputs["baseline_model"]["assumptions"][0]["assumption_id"]
        inputs["control_path"]="data/controls/threat-model-reconciliation-input.json"
        inputs["control_sha256"]="sha256:"+"0"*64
        inputs["control"]["inputs"]=[{"input_id":"review-1","origin":"reviewer","target_record_id":assumption,
            "statement":"Check the deployment boundary.","source_identity":"security-reviewer",
            "model_identity_sha256":None,"prompt_sha256":None},{"input_id":"model-1","origin":"model",
            "target_record_id":None,"statement":"Consider an additional trust boundary.","source_identity":"offline-model",
            "model_identity_sha256":"sha256:"+"1"*64,"prompt_sha256":"sha256:"+"2"*64}]
        value=tr.build_result(inputs,"reconcile-1")
        self.assertEqual({item["claim_effect"] for item in value["external_inputs"]},{"none"})
        self.assertEqual({item["disposition"] for item in value["external_inputs"]},{"unresolved"})
        self.assertIn("review-1",next(item for item in value["unresolved_assumptions"]
            if item["assumption_id"]==assumption)["related_input_ids"])
        self.assertEqual(tr.validate_result(value,inputs),[])
        invalid=deepcopy(inputs); invalid["control"]["inputs"][0]["target_record_id"]="unknown-record"
        errors=tr.validate_result(tr.build_result(invalid,"reconcile-1"),invalid)
        self.assertTrue(any("unknown record" in item for item in errors))

    def test_common_envelope_lifecycle_reuses_and_rejects_resealed_output(self):
        with mock.patch.object(tr,"current_inputs",return_value=self.inputs):
            first=tr.run(self.run_id,"dagster-a"); second=tr.run(self.run_id,"dagster-b")
        self.assertEqual(first["attempt_id"],second["attempt_id"])
        attempt=tr.root(self.run_id)/"attempts"/first["attempt_id"]
        tr._validate_attempt(attempt,self.inputs)
        value=state.read_json(attempt/tr.RESULT); value["comparison"]["baseline_reproducible"]=False
        state.atomic_json(attempt/tr.RESULT,value)
        with self.assertRaisesRegex(state.Blocked,"deterministic immutable inputs"):
            tr._validate_attempt(attempt,self.inputs)

    def test_stale_l6a_snapshot_and_malformed_or_linked_control_fail_closed(self):
        baseline_inputs=deepcopy(self.inputs["baseline_inputs"]); baseline_inputs["code"]=tm._code_hashes()
        with mock.patch.object(tm,"current_inputs",return_value=baseline_inputs):
            pointer=tm.run(self.run_id,"stale-l6a")
        attempt=tm.root(self.run_id)/"attempts"/pointer["attempt_id"]
        model=state.read_json(attempt/tm.RESULT); model["flows"][0]["auth_context"]="resealed"
        state.atomic_json(attempt/tm.RESULT,model)
        with self.assertRaisesRegex(state.Blocked,"snapshot changed"):
            tr._accepted_l6a(self.run_id)

        malformed=state.data_path(self.run_id,"controls",tr.CONTROL)
        state.atomic_json(malformed,{"schema":"wrong","inputs":[]})
        with self.assertRaisesRegex(state.Blocked,"closed schema"):
            tr._control(self.run_id)
        malformed.unlink(); target=self.owner/"outside-control.json"; state.atomic_json(target,
            {"schema":"appsec-review/threat-model-reconciliation-input/1.0","inputs":[]})
        malformed.parent.mkdir(parents=True,exist_ok=True); malformed.symlink_to(target)
        with self.assertRaisesRegex(state.Blocked,"regular file"):
            tr._control(self.run_id)

    def test_registry_contract_and_input_schema_are_closed(self):
        store=SchemaStore()
        for relative,schema in (("job-templates/03-threat-model-reconciliation.json","job-template.schema.json"),
                ("output-contracts/threat-model-reconciliation.json","output-contract.schema.json"),
                ("../personas/roles/threat-model-reconciler/role.json","role.schema.json"),
                ("domains/threat-model-reconciliation.json","domain.schema.json"),
                ("tooling-profiles/threat-model-reconciliation.json","tooling-profile.schema.json")):
            value=json.loads((ROOT/"registry"/relative).read_text())
            self.assertEqual(validate_document(value,schema,store),[],relative)
        contract=json.loads((ROOT/"registry/output-contracts/threat-model-reconciliation.json").read_text())
        policy=output_validator.CLAIM_CLASS_POLICIES[tr.CONTRACT]
        self.assertEqual(policy["claim_class_id"],contract["claim_class"]["claim_class_id"])
        self.assertEqual(policy["allowed_assertions"],set(contract["claim_class"]["allowed_assertions"]))
        role=json.loads((ROOT/"personas/roles/threat-model-reconciler/role.json").read_text())
        tooling=json.loads((ROOT/"registry/tooling-profiles/threat-model-reconciliation.json").read_text())
        self.assertEqual(set(role["allowed_outputs"]),set(tooling["claim_limits"]["allowed"]))

    def test_l6a_to_l6b_common_envelope_qualification(self):
        baseline_inputs=deepcopy(self.inputs["baseline_inputs"]); baseline_inputs["code"]=tm._code_hashes()
        with mock.patch.object(tm,"current_inputs",return_value=baseline_inputs):
            l6a_pointer=tm.run(self.run_id,"qualification-l6a")
        l6a_attempt,model,_stored,baseline=tr._accepted_l6a(self.run_id)
        inputs=deepcopy(self.inputs); inputs["baseline"]=baseline; inputs["baseline_model"]=model
        inputs["baseline_inputs"]=baseline_inputs; inputs["baseline_model_path"]=tr._relative(self.run_id,l6a_attempt/tm.RESULT)
        inputs["current"]["component_map_sha256"]=baseline["component_map_sha256"]
        inputs["current"]["evidence_manifest_sha256"]=baseline["evidence_manifest_sha256"]
        assumption=model["assumptions"][0]["assumption_id"]
        control_path=state.data_path(self.run_id,"controls",tr.CONTROL)
        control={"schema":"appsec-review/threat-model-reconciliation-input/1.0","inputs":[
            {"input_id":"qualification-review","origin":"reviewer","target_record_id":assumption,
             "statement":"Validate the unresolved deployment assumption.","source_identity":"qualification-reviewer",
             "model_identity_sha256":None,"prompt_sha256":None},
            {"input_id":"qualification-model","origin":"model","target_record_id":None,
             "statement":"Consider whether another trust boundary is supported.","source_identity":"qualification-offline-model",
             "model_identity_sha256":"sha256:"+"a"*64,"prompt_sha256":"sha256:"+"b"*64}]}
        state.atomic_json(control_path,control); inputs["control"]=control
        inputs["control_path"]=tr._relative(self.run_id,control_path)
        inputs["control_sha256"]="sha256:"+state.file_hash(control_path)
        inputs["code"]=tr._code_hashes()
        with mock.patch.object(tr,"current_inputs",return_value=inputs):
            l6b_pointer=tr.run(self.run_id,"qualification-l6b"); l6b_attempt=tr.validate(self.run_id)
        result=state.read_json(l6b_attempt/tr.RESULT)
        self.assertEqual(result["status"],"OK_WITH_GAPS")
        self.assertEqual(len(result["external_inputs"]),2)
        output=os.environ.get("APPSEC_THREAT_QUALIFICATION_OUT")
        if output:
            state.atomic_json(Path(output),{"schema":"appsec-review/threat-model-happy-path-qualification/1.0",
                "input_kind":"canonical accepted component fixture (hello-autotools); Freeciv component acceptance remains separate",
                "run_id":self.run_id,"l6a":{"attempt_id":l6a_pointer["attempt_id"],
                    "envelope_sha256":"sha256:"+state.file_hash(l6a_attempt/"result.json"),
                    "elements":len(model["elements"]),"flows":len(model["flows"]),
                    "candidate_hypotheses":len(model["stride_hypotheses"])},
                "l6b":{"attempt_id":l6b_pointer["attempt_id"],
                    "envelope_sha256":"sha256:"+state.file_hash(l6b_attempt/"result.json"),
                    "unresolved_assumptions":len(result["unresolved_assumptions"]),
                    "external_inputs":len(result["external_inputs"]),"conflicts":len(result["conflicts"]),
                    "claim_effects":sorted({item["claim_effect"] for item in result["external_inputs"]})},
                "checks":["accepted L6A common envelope","reproducible L6A snapshot",
                    "accepted L6B common envelope","exact lineage receipts","reviewer/model inputs retained without claim effect"]})


if __name__=="__main__":
    unittest.main()
