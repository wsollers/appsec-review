from pathlib import Path
import json,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from execution_state import atomic_json
import completeness_audit, synthetic_hypothesis_resynthesis

class SeparateFeedbackTests(unittest.TestCase):
    def test_audit_then_resynthesis_are_distinct_attempts(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); audit_input=root/"audit-input.json"; audit_output=root/"audit.json"
            atomic_json(audit_input,{"run_id":"r1","subject_sha256":"sha256:"+"f"*64,"expected":[{"obligation_id":"o1"}],"observed":[],"declared_gaps":[]})
            audit=completeness_audit.run(audit_input,audit_output)
            feedback_input=root/"feedback-input.json"; feedback_output=root/"feedback.json"
            atomic_json(feedback_input,{"run_id":"r1","audit":audit,"routes":{"o1":"02-source-sast"},"iteration":1,"max_iterations":2})
            feedback=synthetic_hypothesis_resynthesis.run(feedback_input,feedback_output)
            self.assertEqual(feedback["terminal_state"],"TARGETED_ANALYSIS_REQUIRED")
            self.assertEqual(json.loads(feedback_output.read_text()),feedback)
            self.assertNotEqual(completeness_audit.JOB,synthetic_hypothesis_resynthesis.JOB)

if __name__=="__main__": unittest.main()
