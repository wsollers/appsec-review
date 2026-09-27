from __future__ import annotations
import json
from pathlib import Path
import sys, tempfile, unittest
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import completeness_feedback, deterministic_pool_merge, dynamic_rescope, evidence_quorum, remediation_retest
from execution_state import atomic_json

class ProcessTests(unittest.TestCase):
    def invoke(self,module,value):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/"input.json"; output=Path(directory)/"output.json"; atomic_json(source,value); result=module.run(source,output); self.assertEqual(json.loads(output.read_text()),result); return result
    def test_merge_and_quorum_are_separate_processes(self):
        candidate={"candidate_id":"c1","subject_id":"s1","assertion":"bounded","evidence_sha256":"sha256:"+"a"*64,"claim_class":"candidate_only"}
        merged=self.invoke(deterministic_pool_merge,{"run_id":"r1","expected_workers":[{"worker_id":"w1","producer_id":"p1","run_id":"r1"}],"worker_results":[{"worker_id":"w1","producer_id":"p1","run_id":"r1","status":"OK","candidates":[candidate]}]})
        quorum=self.invoke(evidence_quorum,{"run_id":"r1","merge":merged,"minimum_producers":1})
        self.assertEqual(quorum["decisions"][0]["decision"],"ADMITTED")
    def test_rescope_is_separate(self):
        value=self.invoke(dynamic_rescope,{"run_id":"r1","nodes":["a","b"],"edges":[{"upstream":"a","downstream":"b"}],"changed_nodes":["a"],"iteration":1,"max_iterations":2})
        self.assertEqual(value["affected_nodes"],["a","b"])
    def test_completeness_feedback_is_separate(self):
        value=self.invoke(completeness_feedback,{"run_id":"r1","expected":[{"obligation_id":"o1"}],"observed":[],"declared_gaps":[],"routes":{"o1":"02-source-sast"},"iteration":1,"max_iterations":2})
        self.assertEqual(value["feedback"]["terminal_state"],"TARGETED_ANALYSIS_REQUIRED")
    def test_remediation_retest_is_separate(self):
        environment={"source_sha256":"sha256:"+"a"*64,"build_sha256":"sha256:"+"b"*64,"target_sha256":"sha256:"+"c"*64,"change_ref":"patch-1"}; value=self.invoke(remediation_retest,{"run_id":"r1","verified_claims":[{"claim_id":"c1","status":"VERIFIED"}],"proposals":[{"proposal_id":"p1","claim_id":"c1","state":"AUTHORIZED","author_id":"author","change_ref":"patch-1","rationale":"Bounded fix proposal.","target_components":["component-1"]}],"retests":[{"proposal_id":"p1","original_environment":environment,"retest":{"environment":environment,"result":"PASSED","executor_id":"executor"},"verifier":{"producer_id":"verifier","decision":"VERIFIED"}}]})
        self.assertEqual(value["retests"][0]["state"],"FIXED")
    def test_each_process_can_publish_a_common_immutable_attempt(self):
        cases=[
          (deterministic_pool_merge,{"run_id":"r1","expected_workers":[],"worker_results":[]}),
          (dynamic_rescope,{"run_id":"r1","nodes":["a"],"edges":[],"changed_nodes":["a"],"iteration":1,"max_iterations":2}),
          (completeness_feedback,{"run_id":"r1","expected":[],"observed":[],"declared_gaps":[],"routes":{},"iteration":1,"max_iterations":2}),
          (remediation_retest,{"run_id":"r1","verified_claims":[],"proposals":[],"retests":[]})]
        with tempfile.TemporaryDirectory() as directory:
          for index,(module,value) in enumerate(cases):
            source=Path(directory)/f"input-{index}.json"; atomic_json(source,value); output=Path(directory)/f"attempt-{index}"
            module.run_attempt(source,output,attempt_id=f"a{index}",source_snapshot_sha256="sha256:"+"a"*64,started_at="2026-09-27T00:00:00Z",finished_at="2026-09-27T00:00:01Z")
            self.assertTrue((output/"result.json").is_file())

if __name__=="__main__": unittest.main()
