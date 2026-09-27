import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import bounded_analysis_workers as workers
import native_memory_analysis, fuzz_target_triage, owasp_validation_worklist
import stig_srg_validation_worklist, deployment_hardening
import source_sast_language_adapters as language
from execution_state import Blocked
from schema_validate import validate_document
from worker_result import validate_worker_result

H="sha256:"+"a"*64
B=[{"job_id":"02-native-sast","attempt_id":"a1","artifact_path":"native-sast.json",
    "artifact_sha256":H,"accepted_pointer_sha256":"sha256:"+"b"*64}]
C=[{"citation_id":"c1","artifact_path":"native-sast.json","artifact_sha256":H,
    "locator":"src/a.c:4","observed_fact":"accepted analyzer signal at the cited line"}]

class BoundedWorkers(unittest.TestCase):
    def test_native_candidates_are_cited_open_and_never_host_verified(self):
        value=native_memory_analysis.analyze(run_id="r",attempt_id="a",source_generation=H,bindings=B,
          units=[{"unit_id":"u","language":"c","path":"src/a.c","source_sha256":H,
            "signals":[{"signal_id":"s","kind":"bounds","statement":"index lacks a local bound","line":4}],
            "coverage":["clang-static-analyzer"],"citations":C}])
        self.assertEqual(validate_document(value,"native-memory-analysis.schema.json"),[])
        self.assertFalse(value["candidates"][0]["host_verified"])
        self.assertEqual(value["proof_obligations"][0]["status"],"OPEN")
        hostile=copy.deepcopy(value); hostile["claim_limits"]["finding_created"]=True
        self.assertTrue(validate_document(hostile,"native-memory-analysis.schema.json"))

    def test_fuzz_triage_ranks_without_claiming_execution(self):
        value=fuzz_target_triage.analyze(run_id="r",attempt_id="a",source_generation=H,bindings=B,
          targets=[{"target_id":"t1","component_id":"c","entrypoint":"parse","input_model":"bytes",
                    "buildable":True,"deterministic":True,"isolation":"process","blockers":[],"citation_ids":["c1"]},
                   {"target_id":"t2","component_id":"c","entrypoint":"serve","input_model":"unknown",
                    "buildable":False,"deterministic":False,"isolation":"unknown","blockers":["needs harness"],"citation_ids":["c1"]}])
        self.assertEqual([x["target_id"] for x in value["targets"]],["t1","t2"])
        self.assertTrue(all(x["fuzz_execution"]=="NOT_PERFORMED" for x in value["targets"]))

    def test_owasp_stig_and_deployment_are_distinct_and_preserve_gaps(self):
        common={"run_id":"r","attempt_id":"a","source_generation":H,"bindings":B}
        o=owasp_validation_worklist.build(**common,controls=[{"control_id":"V1","standard_family":"OWASP",
          "standard_version":"ASVS-5.0","target_id":"web","applicability":"conditional","tailoring":"API only",
          "evidence_mode":"hybrid","citation_ids":["c1"],"gaps":["runtime evidence unavailable"]}])
        s=stig_srg_validation_worklist.build(**common,controls=[{"control_id":"SRG-1","standard_family":"DISA_STIG_SRG",
          "standard_version":"SRG-APP-000001","target_id":"image","applicability":"cannot_determine","tailoring":"container",
          "evidence_mode":"manual","citation_ids":["c1"],"gaps":["platform version unresolved"]}])
        d=deployment_hardening.analyze(**common,targets=[{"target_id":"image","platform":"linux-container","control_id":"SRG-1",
          "standard_family":"DISA_STIG_SRG","standard_version":"SRG-APP-000001","applicability":"conditional",
          "tailoring":"container","static_state":"declared","citation_ids":["c1"],"runtime_gaps":["runtime daemon state unavailable"]}])
        self.assertEqual({o["job_id"],s["job_id"],d["job_id"]},{"04-owasp-validation-worklist","15-stig-srg-validation-worklist","15-deployment-hardening"})
        self.assertEqual(o["work_items"][0]["assessment_status"],"NOT_ASSESSED")
        self.assertFalse(d["assessments"][0]["runtime_observed"])
        bad=copy.deepcopy(o["work_items"][0]); bad["gaps"]=[]
        with self.assertRaises(Blocked): workers.standards_worklist(family="owasp",**common,controls=[{k:bad[k] for k in {"control_id","standard_family","standard_version","target_id","applicability","tailoring","evidence_mode","citation_ids","gaps"}}])

    def test_common_envelope_receipts_and_exact_immutable_reuse(self):
        value=fuzz_target_triage.analyze(run_id="r",attempt_id="a",source_generation=H,bindings=B,targets=[])
        with tempfile.TemporaryDirectory() as folder:
            first=workers.publish_attempt(Path(folder),value,started_at="2026-01-01T00:00:00Z",finished_at="2026-01-01T00:00:01Z")
            second=workers.publish_attempt(Path(folder),value,started_at="x",finished_at="y")
            self.assertEqual(first,second); self.assertEqual(validate_worker_result(first),[])
            attempt=Path(folder)/"attempts/a"
            self.assertEqual(json.loads((attempt/"permission-receipt.json").read_text())["permissions"],workers.PERMISSIONS)
            forged=copy.deepcopy(value); forged["gaps"].append("forged")
            with self.assertRaises(Blocked): workers.publish_attempt(Path(folder),forged,started_at="x",finished_at="y")
            status=json.loads((attempt/"status.json").read_text()); status["records"]=99
            (attempt/"status.json").write_text(json.dumps(status))
            with self.assertRaises(Blocked): workers.publish_attempt(Path(folder),value,started_at="x",finished_at="y")

    def test_contradictory_citations_and_unknown_applicability_fail_closed(self):
        dup=[C[0],{**C[0],"observed_fact":"contradiction"}]
        with self.assertRaises(Blocked): native_memory_analysis.analyze(run_id="r",attempt_id="a",source_generation=H,bindings=B,
          units=[{"unit_id":"u","language":"c","path":"a.c","source_sha256":H,"signals":[],"coverage":["x"],"citations":dup}])
        with self.assertRaises(Blocked): owasp_validation_worklist.build(run_id="r",attempt_id="a",source_generation=H,bindings=B,
          controls=[{"control_id":"V1","standard_family":"OWASP","standard_version":"5","target_id":"x","applicability":"yes",
            "tailoring":"none","evidence_mode":"static","citation_ids":["c"],"gaps":[]}])

    def test_go_java_php_plans_are_pinned_offline_or_explicitly_unavailable(self):
        registry={key:{"digest":"sha256:"+char*64} for key,char in
          [("tool-gosec","1"),("tool-spotbugs","2")]}
        plan=language.build_plan(["php","go","java"],registry)
        self.assertEqual([x["language"] for x in plan],["go","java","php"])
        self.assertTrue(all(x["network"]=={"mode":"none","destinations":[]} and not x["executed"] for x in plan))
        php=next(x for x in plan if x["language"]=="php")
        self.assertEqual(php["status"],"UNAVAILABLE"); self.assertIn("pinned image",php["gap"])
        self.assertEqual(language.detected_languages(["a.go","A.java","x.php","README"]),["go","java","php"])

if __name__=="__main__": unittest.main()
