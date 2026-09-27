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
        merged=self.invoke(deterministic_pool_merge,{"run_id":"r1","expected_workers":[{"worker_id":"w1","producer_id":"p1"}],"worker_results":[{"worker_id":"w1","producer_id":"p1","status":"OK","candidates":[candidate]}]})
        quorum=self.invoke(evidence_quorum,{"run_id":"r1","merge":merged,"minimum_producers":1})
        self.assertEqual(quorum["decisions"][0]["decision"],"ADMITTED")
    def test_rescope_is_separate(self):
        value=self.invoke(dynamic_rescope,{"run_id":"r1","nodes":["a","b"],"edges":[{"upstream":"a","downstream":"b"}],"changed_nodes":["a"],"iteration":1,"max_iterations":2})
        self.assertEqual(value["affected_nodes"],["a","b"])
    def test_completeness_feedback_is_separate(self):
        value=self.invoke(completeness_feedback,{"run_id":"r1","expected":[{"obligation_id":"o1"}],"observed":[],"declared_gaps":[],"routes":{"o1":"worker"},"iteration":1,"max_iterations":2})
        self.assertEqual(value["feedback"]["terminal_state"],"TARGETED_ANALYSIS_REQUIRED")
    def test_remediation_retest_is_separate(self):
        environment={"image":"sha256:"+"a"*64}; value=self.invoke(remediation_retest,{"run_id":"r1","verified_claims":[{"claim_id":"c1","status":"VERIFIED"}],"proposals":[{"proposal_id":"p1","claim_id":"c1","state":"AUTHORIZED","author_id":"author"}],"retests":[{"proposal_id":"p1","original_environment":environment,"retest":{"environment":environment,"result":"PASSED","executor_id":"executor"},"verifier":{"producer_id":"verifier","decision":"VERIFIED"}}]})
        self.assertEqual(value["retests"][0]["state"],"FIXED")

if __name__=="__main__": unittest.main()
