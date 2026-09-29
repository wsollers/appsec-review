from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import analysis_feature_lifecycle as life
import dep_reachability  # noqa: E402
from execution_state import Blocked, atomic_json, file_hash  # noqa: E402

SHA="sha256:"+"1"*64
BIND={"job_id":"01-component-characterization","attempt_id":"up-1","artifact_path":"component-map.json",
      "artifact_sha256":SHA,"accepted_pointer_sha256":"sha256:"+"2"*64}


class LifecycleTests(unittest.TestCase):
    def fake_coordinate(self, base, **kwargs):
        attempt=Path(base)/"attempts/a1"; attempt.mkdir(parents=True)
        inputs=kwargs["derive_inputs"](); atomic_json(attempt/"inputs.json",inputs)
        allocation={"attempt":attempt,"attempt_id":"a1","started_at":"2026-09-27T00:00:00Z"}
        return kwargs["execute_attempt"](allocation,inputs,kwargs["fingerprint_inputs"](inputs))

    @staticmethod
    def fake_record(base,attempt,**kwargs):
        kwargs["pre_envelope_validate"](attempt,{"status":kwargs["execution_status"]})
        return {"status":kwargs["execution_status"],"reason":kwargs.get("skip_reason")}

    def test_native_success_and_fuzz_skip_publish_exact_status(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder)
            native={"run_id":"run","job_id":"05-native-memory","source_generation":SHA,
                "assembly":BIND,"mode":"EXECUTE","reason":None,"bindings":[BIND],
                "applicability":{"source_status":"REQUESTED","source_reason":"accepted native unit",
                                 "source_sha256":SHA},
                "payload":[{"unit_id":"u","language":"cpp","path":"x.cpp","source_sha256":SHA,
                    "signals":[],"coverage":["static"],"citations":[{"citation_id":"c","artifact_path":"x.cpp",
                    "artifact_sha256":SHA,"locator":"x.cpp:1","observed_fact":"native source"}]}],"code":{}}
            fuzz={"run_id":"run","job_id":"13-fuzz-target-triage","source_generation":SHA,
                "assembly":BIND,"mode":"SKIPPED_NA","reason":life.SKIPS["13-fuzz-target-triage"],
                "applicability":{"source_status":"SKIPPED_NA",
                                 "source_reason":"component map routes no fuzz target",
                                 "source_sha256":SHA},
                "bindings":[BIND],"payload":[],"code":{}}
            records={"05-native-memory":native,"13-fuzz-target-triage":fuzz}
            with mock.patch.object(life,"current_inputs",side_effect=lambda _run,job:records[job]), \
                 mock.patch.object(life,"data_path",side_effect=lambda _run,*parts:base.joinpath(*parts)), \
                 mock.patch.object(life,"coordinate_worker_lifecycle",side_effect=self.fake_coordinate), \
                 mock.patch.object(life,"record_terminal_current",side_effect=self.fake_record):
                self.assertEqual(life.run("run","dag","05-native-memory")["status"],"OK_WITH_GAPS")
                skipped=life.run("run","dag","13-fuzz-target-triage")
                self.assertEqual(skipped,{"status":"SKIPPED","reason":"not-applicable-no-fuzz-target"})

    def test_cve_derives_run_owned_assessments_without_hand_input(self):
        """ADR-0022: 06 derives its evidence rows and per-match document; nothing is hand-supplied."""
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder); pointer=base/"sca-accepted.json"; pointer.write_text("{}\n")
            inputs={"run_id":"run","job_id":"06-cve-reachability",
                "source_generation":SHA,"sca":{"attempt_id":"s1","path":"x","sha256":SHA,"accepted_path":str(pointer)},
                "sca_matches_sha256":SHA,"source_binding":{},
                "generated_at":"2026-09-27T00:00:00Z","code":{}}
            rows=[{"match_ref":"VM-000001","classification":"reachable",
                   "evidence":[{"kind":"call","path":"app/main.c","sha256":SHA,"locator":"main@1"}]}]
            document=dep_reachability.analyse(sca={"matches":[]},sbom={"components":[]},files={},
                engine_set=dep_reachability.engines.EngineSet(),osv=None,osv_gap="osv-not-configured",reviewed=None)["document"]
            result={"schema":"appsec-review/cve-reachability/1.0","run_id":"run","job_id":"06-cve-reachability",
                "attempt_id":"a1","source_snapshot_sha256":SHA,
                "sca_binding":{"job_id":"02-sca-vulnerability-match","attempt_id":"s1",
                    "path":"outputs/sca-vulnerability-match.json","sha256":SHA},
                "assessments":[],"coverage_gaps":[],"claim_ceiling":"EVIDENCE_LEADS_ONLY"}
            def build(request,attempt_id):
                evidence=json.loads(Path(request["reachability_evidence"]).read_text())
                self.assertEqual(evidence,{"assessments":rows})
                return {"outputs/cve-reachability.json":(json.dumps(result)+"\n").encode(),
                        "outputs/reachability-evidence-identity.json":b'{"path":"automatic","sha256":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}\n'},[]
            with mock.patch.object(life,"current_inputs",return_value=inputs), \
                 mock.patch.object(life,"data_path",side_effect=lambda _run,*parts:base.joinpath(*parts)), \
                 mock.patch.object(life,"coordinate_worker_lifecycle",side_effect=self.fake_coordinate), \
                 mock.patch.object(life,"record_terminal_current",side_effect=self.fake_record), \
                 mock.patch.object(life,"_derive_reachability",return_value={"assessments":rows,"document":document,
                     "summary":life.dep_reachability_lifecycle.correlator.summary(document,{"components":[]},{"codeql":None,"ir":None})}), \
                 mock.patch.object(life.dependency_workers,"build_reachability",side_effect=build):
                self.assertEqual(life.run("run","dag","06-cve-reachability")["status"],"OK")
            written=[path for path in base.rglob("dependency-reachability.json")]
            self.assertEqual(len(written),1)
            published=json.loads(written[0].read_text())
            self.assertEqual(published["sca_binding"]["attempt_id"],"s1")
            self.assertEqual(life.validate_document(published,"dependency-reachability.schema.json"),[])
            summary=json.loads(next(base.rglob("dependency-reachability-summary.json")).read_text())
            self.assertEqual(life.validate_document(summary,"dependency-reachability-summary.schema.json"),[])
            self.assertEqual(summary["counts"],{"reachable":0,"unreachable":0,"conflict":0,"unknown":0})

    def test_skip_receipt_retains_canonical_reason_and_assembly_evidence(self):
        inputs={"run_id":"run","job_id":"13-fuzz-target-triage","source_generation":SHA,
            "assembly":BIND,"mode":"SKIPPED_NA","reason":life.SKIPS["13-fuzz-target-triage"],
            "applicability":{"source_status":"SKIPPED_NA",
                "source_reason":"component map routes no component to fuzz-target triage",
                "source_sha256":SHA},"bindings":[BIND],"payload":[],"code":{}}
        receipt=life._applicability("run","13-fuzz-target-triage",inputs)
        self.assertEqual(receipt["decision"],"SKIPPED_NA")
        self.assertEqual(receipt["reason"],"not-applicable-no-fuzz-target")
        self.assertEqual(receipt["evidence"]["artifact_sha256"],BIND["artifact_sha256"])
        self.assertEqual(life.validate_document(receipt,"analysis-applicability-receipt.schema.json"),[])

    def test_stale_assembly_request_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); attempt=root/"attempt"; (attempt/"requests").mkdir(parents=True)
            request=attempt/"requests/05-native-memory.json"; request.write_text("{}")
            assembly={"source_generation":SHA,"requests":[{"job_id":"05-native-memory","path":"requests/05-native-memory.json","sha256":"sha256:"+"9"*64}],"skipped":[]}
            with mock.patch.object(life,"_assembly",return_value=(assembly,BIND,attempt)):
                with self.assertRaisesRegex(Blocked,"request changed"):
                    life._bounded_inputs("run","05-native-memory")

    def test_newest_sca_failure_prevents_older_success_reuse(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder); attempt=base/"attempts/s1"; attempt.mkdir(parents=True)
            result=attempt/"outputs/sca-vulnerability-match.json"; result.parent.mkdir(); result.write_text("{}")
            pointer=base/"accepted.json"; pointer.write_text("{}")
            atomic_json(base/"latest.json",{"attempt_id":"failed-newer"})
            binding={"attempt_id":"s1","path":str(result),"sha256":SHA,"accepted_path":str(pointer)}
            with mock.patch.object(life.automatic,"_accepted_binding",return_value=(binding,result.parent)):
                with self.assertRaisesRegex(Blocked,"newest SCA attempt"):
                    life._sca("run")


if __name__=="__main__": unittest.main()
