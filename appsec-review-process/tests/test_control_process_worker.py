from __future__ import annotations
import json
from pathlib import Path
import sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from execution_state import Blocked
import control_process_worker as worker
from worker_result import validate_worker_result

class ControlProcessWorkerTests(unittest.TestCase):
    def test_atomic_common_attempt_and_immutable_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/"attempts/a1"; result=worker.publish(run_id="r1",job_id="dynamic-rescope",attempt_id="a1",contract_id="bounded-rescope-plan",result_name="bounded-rescope-plan.json",result={"schema":"fixture"},output_root=output,source_snapshot_sha256="sha256:"+"a"*64,input_binding={"input":"sha256:"+"b"*64},started_at="2026-09-27T00:00:00Z",finished_at="2026-09-27T00:00:01Z")
            self.assertFalse(validate_worker_result(json.loads((output/"result.json").read_text())))
            self.assertTrue(result["envelope_sha256"].startswith("sha256:"))
            with self.assertRaisesRegex(Blocked,"already exists"): worker.publish(run_id="r1",job_id="dynamic-rescope",attempt_id="a1",contract_id="bounded-rescope-plan",result_name="bounded-rescope-plan.json",result={},output_root=output,source_snapshot_sha256="sha256:"+"a"*64,input_binding={},started_at="x",finished_at="y")
    def test_failure_leaves_no_final_or_staging_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); output=root/"attempts/a1"
            with self.assertRaises(Blocked): worker.publish(run_id="r1",job_id="dynamic-rescope",attempt_id="a1",contract_id="bounded-rescope-plan",result_name="bounded-rescope-plan.json",result={},output_root=output,source_snapshot_sha256="bad",input_binding={},started_at="x",finished_at="y")
            self.assertFalse(output.exists()); self.assertEqual(list((root/"attempts").glob(".dynamic-rescope-*")) if (root/"attempts").exists() else [],[])

if __name__=="__main__": unittest.main()
