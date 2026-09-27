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
from execution_state import Blocked, atomic_json, file_hash, tree_hashes
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

    def test_exact_accepted_loader_rejects_stale_and_tampered_upstream(self):
        value=fuzz_target_triage.analyze(run_id="r",attempt_id="a",source_generation=H,bindings=B,targets=[])
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder); envelope=workers.publish_attempt(base,value,started_at="2026-01-01T00:00:00Z",finished_at="2026-01-01T00:00:01Z")
            attempt=base/"attempts/a"; atomic_json(base/"latest.json",{"attempt_id":"a"})
            pointer={"schema":"appsec-review/accepted-worker-result/1.0","status":"OK_WITH_GAPS","run_id":"r","job":"13-fuzz-target-triage",
              "attempt_id":"a","fingerprint":envelope["input_fingerprint"],"envelope_path":"result.json","envelope_sha256":file_hash(attempt/"result.json"),
              "hashes":tree_hashes(attempt),"accepted_at":"2026-01-01T00:00:02Z"}
            atomic_json(base/"accepted.json",pointer)
            loaded,binding=workers.load_accepted(base/"accepted.json",run_id="r",job_id="13-fuzz-target-triage",contract="fuzz-target-triage",artifact="fuzz-target-triage.json",schema="fuzz-target-triage.schema.json")
            self.assertEqual(loaded,value); self.assertEqual(binding["attempt_id"],"a")
            atomic_json(base/"latest.json",{"attempt_id":"newer"})
            with self.assertRaises(Blocked): workers.load_accepted(base/"accepted.json",run_id="r",job_id="13-fuzz-target-triage",contract="fuzz-target-triage",artifact="fuzz-target-triage.json",schema="fuzz-target-triage.schema.json")

    def test_go_java_php_plans_are_pinned_offline_or_explicitly_unavailable(self):
        registry={key:{"digest":"sha256:"+char*64} for key,char in
          [("tool-gosec","1"),("tool-spotbugs","2")]}
        plan=language.build_plan(["php","go","java"],registry)
        self.assertEqual(sorted(x["tool_id"] for x in plan),["gosec","phpcs","phpstan","psalm","spotbugs"])
        self.assertTrue(all(x["network"]=={"mode":"none","destinations":[]} and not x["executed"] for x in plan))
        php=[x for x in plan if x["language"]=="php"]
        self.assertEqual(len(php),3); self.assertTrue(all(x["status"]=="UNAVAILABLE" for x in php))
        self.assertTrue(all("pinned image" in x["gap"] for x in php))
        self.assertEqual(language.detected_languages(["a.go","A.java","x.php","README"]),["go","java","php"])

    def test_language_parsers_normalize_hits_and_reject_tamper(self):
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder); (target/"a.go").write_text("package a\nvar x=1\n"); (target/"A.java").write_text("class A {}\n")
            (target/"a.php").write_text("<?php\n$x=1;\n")
            fixtures={
              "gosec":json.dumps({"Issues":[{"rule_id":"G101","file":"/workspace/a.go","line":"2"}]}).encode(),
              "spotbugs":b'<BugCollection><BugInstance type="SQL_INJECTION"><SourceLine sourcepath="A.java" start="1"/></BugInstance></BugCollection>',
              "phpstan":json.dumps({"files":{"/workspace/a.php":{"messages":[{"identifier":"phpstan.x","line":2}]}}}).encode(),
              "psalm":json.dumps([{"type":"TaintedInput","file_name":"/workspace/a.php","line_from":2}]).encode(),
              "phpcs":json.dumps({"files":{"/workspace/a.php":{"messages":[{"source":"Security.Bad","line":2}]}}}).encode()}
            for tool,raw in fixtures.items():
                with self.subTest(tool=tool):
                    leads=language.normalize(tool,raw,target); self.assertEqual(len(leads),1)
                    self.assertEqual(leads[0]["tool_id"],tool)
            with self.assertRaises(ValueError): language.normalize("gosec",b'{"Issues":[{"rule_id":"G1","file":"../x","line":"1"}]}',target)

    def test_language_exit_semantics_distinguish_clean_hits_errors_and_timeouts(self):
        plan={"hit_exit_codes":[1]}
        self.assertTrue(language.accepted_terminal(plan,{"execution_status":"OK","exit_code":0,"cause":None}))
        self.assertTrue(language.accepted_terminal(plan,{"execution_status":"FAILED","exit_code":1,"cause":"CONTAINER_EXIT_NONZERO"}))
        self.assertFalse(language.accepted_terminal(plan,{"execution_status":"FAILED","exit_code":2,"cause":"CONTAINER_EXIT_NONZERO"}))
        self.assertFalse(language.accepted_terminal(plan,{"execution_status":"FAILED","exit_code":None,"cause":"TIMEOUT"}))

if __name__=="__main__": unittest.main()
