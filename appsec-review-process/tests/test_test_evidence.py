from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import shutil,sys,tempfile,unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import container_execution as ce
import evidence_assembly as assembly
import execution_state as state
import test_evidence as te
import validate_job_output as output_validator
from schema_validate import validate_document
from worker_result import artifact_records, terminal_envelope
import registry_paths

class TestEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.owner=Path(self.tmp.name); self.target=self.owner/"target"
        (self.target/"src").mkdir(parents=True); (self.target/"src/math.c").write_text("int add(int a,int b){return a+b;}\n")
        self.native={"source_revision":"rev1"}; self.unit={"unit_id":"root","image_id":"image_build_aaaaaaaaaaaa",
          "image_digest":"sha256:"+"1"*64,"compile_database":{"path":"compile_commands.json","sha256":"sha256:"+"2"*64,"entries":1},
          "binaries":[{"artifact_path":"bin/test","sha256":"sha256:"+"3"*64}]}
        self.source="sha256:"+"4"*64; self.lineage={"job_id":"02-native-build","attempt_id":"n1",
          "accepted_pointer_sha256":"sha256:"+"5"*64,"envelope_sha256":"sha256:"+"6"*64,
          "result_sha256":"sha256:"+"7"*64,"input_fingerprint":"sha256:"+"8"*64}
        params={name:None for name in te.pc.PARAMETER_NAMES}; params.update(command_profile_id="fixture-tests-v1",target_path=".")
        cap={"kind":"target-execution","version":"1.0","parameters":params,"origin":"staged-run-config"}
        self.grant={"schema":"appsec-review/permission-grant/1.0","grant_id":"fixture-test-grant","effect":"ALLOW",
          "authority":{"name":"Fixture Owner","role":"engagement-owner"},"issued_at":"2026-01-01T00:00:00Z",
          "expires_at":"2027-01-01T00:00:00Z","binding":{"run_id":"run1","source_snapshot_sha256":self.source,"job_id":"02-test-execution"},
          "justification":"Run the bounded tracked fixture test plan.","capabilities":[cap]}
        self.permit=te.permission("run1",self.source,"fixture-tests-v1",[self.grant],"2026-06-01T00:00:00Z")
    def tearDown(self): self.tmp.cleanup()

    def execution(self,raw=None,exit_code=0):
        raw=raw or {}
        return te.execution_record(run_id="run1",source=self.source,native_lineage=self.lineage,native=self.native,
          unit=self.unit,argv=["python3","tests/run.py"],environment=[{"name":"LANG","value":"C"}],timeout_seconds=30,
          permission_record=self.permit,exit_code=exit_code,raw_results=raw,artifact_root=self.owner)

    def test_permission_and_safe_boundary_request_are_exact(self):
        inputs={"source_snapshot_sha256":self.source,"target_path":str(self.target),"native_attempt_path":str(self.owner),
          "unit":self.unit,"control":{"command_profile_id":"fixture-tests-v1","argv":["python3","tests/run.py"],
          "environment":[{"name":"LANG","value":"C"}],"timeout_seconds":30,"authorization_time":"2026-06-01T00:00:00Z",
          "result_path":"results.xml","coverage_path":"coverage.info","grants":[self.grant]}}
        req=te.request("run1","attempt1",inputs)
        self.assertEqual(ce.request_errors(req,run_id="run1",job_id="02-test-execution",attempt_id="attempt1"),[])
        self.assertEqual(req["network"],{"mode":"none","destinations":[]}); self.assertEqual(req["permission"]["decision"]["decision"],"GRANTED")
        self.assertEqual(req["target_mounts"][0]["container_path"],"/workspace")

    def test_result_and_coverage_normalization_are_deterministic_evidence(self):
        result_path=self.owner/"results.xml"; coverage_path=self.owner/"coverage.info"
        shutil.copyfile(ROOT/"tests/fixtures/test-evidence/results.xml",result_path)
        shutil.copyfile(ROOT/"tests/fixtures/test-evidence/coverage.info",coverage_path)
        execution=self.execution({"test-results":result_path,"coverage":coverage_path},exit_code=1)
        self.assertEqual(execution["execution_status"],"FAIL")
        self.assertEqual(validate_document(execution,"test-execution.schema.json"),[])
        first=te.junit(execution,result_path); second=te.junit(execution,result_path)
        self.assertEqual(first,second); self.assertEqual(first["counts"],{"passed":1,"failed":1,"skipped":1})
        coverage=te.lcov(execution,coverage_path,self.target)
        self.assertEqual(coverage["files"][0]["source_sha256"],te.sha(self.target/"src/math.c"))
        self.assertTrue(coverage["coverage_gaps"])
        self.assertEqual(validate_document(coverage,"test-coverage.schema.json"),[])
        encoded=str(first).lower()+str(coverage).lower(); self.assertNotIn("severity",encoded); self.assertNotIn("finding",encoded)

    def test_malformed_duplicate_stale_and_missing_inputs_fail_or_gap(self):
        duplicate=self.owner/"duplicate.xml"; duplicate.write_text("<testsuite><testcase classname='a' name='x'/><testcase classname='a' name='x'/></testsuite>")
        with self.assertRaisesRegex(te.Blocked,"duplicate"): te.junit(self.execution(),duplicate)
        escaping=self.owner/"escape.info"; escaping.write_text("SF:/etc/passwd\nDA:1,1\nend_of_record\n")
        with self.assertRaisesRegex(te.Blocked,"escapes"): te.lcov(self.execution(),escaping,self.target)
        no_raw={"execution":self.execution(),"raw_path":None,"target_path":str(self.target)}
        result=te.derive_ingest(no_raw,te.RESULT_JOB); coverage=te.derive_ingest(no_raw,te.COVERAGE_JOB)
        self.assertTrue(result["coverage_gaps"]); self.assertTrue(coverage["coverage_gaps"])
        denied=deepcopy(self.permit); denied["decision"]["decision"]="DENIED"
        with self.assertRaisesRegex(te.Blocked,"permission denied"):
            te.execution_record(run_id="run1",source=self.source,native_lineage=self.lineage,native=self.native,unit=self.unit,
              argv=["x"],environment=[],timeout_seconds=1,permission_record=denied,exit_code=0,raw_results={})

    def test_unsupported_formats_preserve_raw_hash_and_control_paths_are_closed(self):
        raw=self.owner/"opaque.bin"; raw.write_bytes(b"opaque evidence")
        execution=self.execution({"test-results":raw,"coverage":raw})
        execution["result_format"]="unsupported"; execution["coverage_format"]="unsupported"
        inputs={"execution":execution,"raw_path":str(raw),"target_path":str(self.target)}
        self.assertEqual(te.derive_ingest(inputs,te.RESULT_JOB)["raw_sha256"],te.sha(raw))
        self.assertEqual(te.derive_ingest(inputs,te.COVERAGE_JOB)["raw_sha256"],te.sha(raw))
        request_inputs={"source_snapshot_sha256":self.source,"target_path":str(self.target),
          "native_attempt_path":str(self.owner),"unit":self.unit,
          "control":{"command_profile_id":"fixture-tests-v1","argv":["x"],"environment":[],
          "result_path":"../escape.xml","coverage_path":None,"timeout_seconds":1,
          "authorization_time":"2026-06-01T00:00:00Z","grants":[self.grant]}}
        with self.assertRaisesRegex(te.Blocked,"normalized relative"):
            te.request("run1","attempt1",request_inputs)

    def test_execution_inputs_bind_e02_tree_native_artifacts_image_and_permission(self):
        native_attempt=self.owner/"native"; native_attempt.mkdir()
        db=native_attempt/"compile_commands.json"; db.write_text("[]\n")
        binary=native_attempt/"bin/test"; binary.parent.mkdir(); binary.write_bytes(b"\x7fELFfixture")
        unit=deepcopy(self.unit); unit["compile_database"].update(sha256=te.sha(db))
        unit["binaries"]=[{"artifact_path":"bin/test","sha256":te.sha(binary)}]
        tree=te.source_tree_sha256(self.target)
        image={"schema":"appsec-review/container-image/1.0","image_id":unit["image_id"],
          "repository":"example.invalid/appsec/test","digest":unit["image_digest"],"digest_kind":"image-manifest",
          "dockerfile_sha256":None,"build_fingerprint_sha256":None,"build_attempt_id":None,
          "purpose":"Fixture test image","provenance":"Tracked test fixture"}
        te.atomic_json(native_attempt/"inputs.json",{"source_snapshot_sha256":self.source,"source_tree_sha256":tree,
          "image_records":{unit["image_id"]:{"value":image,"sha256":"sha256:"+"9"*64}}})
        controls=self.owner/"controls"; controls.mkdir(); control=controls/te.CONTROL
        te.atomic_json(control,{"schema":"appsec-review/test-execution-control/1","command_profile_id":"fixture-tests-v1",
          "unit_id":"root","argv":["python3","tests/run.py"],"environment":[{"name":"LANG","value":"C"}],
          "timeout_seconds":30,"authorization_time":"2026-06-01T00:00:00Z",
          "result_format":"junit-xml","result_path":"results.xml",
          "coverage_format":"lcov","coverage_path":"coverage.info","grants":[self.grant]})
        native={"source_revision":"rev1","units":[unit]}
        def fake_data(_run,*parts): return self.owner.joinpath(*parts)
        with mock.patch.object(te,"accepted",return_value=(native_attempt,native,self.lineage)), \
             mock.patch.object(te,"data_path",side_effect=fake_data), \
             mock.patch.object(te,"target",return_value=(self.target,self.source,tree,"rev1")):
            inputs=te.execution_inputs("run1")
            self.assertEqual(inputs["source_tree_sha256"],tree)
            self.assertEqual(inputs["unit"]["binaries"][0]["sha256"],te.sha(binary))
            bad=te.read_json(native_attempt/"inputs.json"); bad["source_tree_sha256"]="sha256:"+"0"*64
            te.atomic_json(native_attempt/"inputs.json",bad)
            with self.assertRaisesRegex(te.Blocked,"source-tree attestation"):
                te.execution_inputs("run1")

    def test_stage_control_uses_the_single_accepted_unit_and_closed_make_check_command(self):
        native={"source_revision":"rev1","units":[self.unit]}
        def fake_data(_run,*parts): return self.owner.joinpath(*parts)
        with mock.patch.object(te,"accepted",return_value=(self.owner,native,self.lineage)), \
             mock.patch.object(te,"target",return_value=(self.target,self.source,"sha256:"+"9"*64,"rev1")), \
             mock.patch.object(te,"data_path",side_effect=fake_data):
            path=te.stage_control("run1",authority="Fixture Owner")
        control=te.read_json(path)
        self.assertEqual(control["unit_id"],"root")
        self.assertEqual(control["argv"],["make","check"])
        self.assertEqual(control["result_format"],"unsupported")
        self.assertEqual(control["coverage_format"],"none")
        self.assertEqual(validate_document(control,"test-execution-control.schema.json"),[])

    def test_all_three_jobs_publish_f02_compatible_receipts(self):
        supply=self.owner/"supply"; build="sha256:"+"9"*64
        for index,(job,(artifact,_schema,contract)) in enumerate(te.SPECS.items()):
            attempt_id=f"{contract}-1"; producer=supply/"producers"/job; attempt=producer/"attempts"/attempt_id
            attempt.mkdir(parents=True); inputs={"source_snapshot_sha256":self.source,"build_lineage_sha256":build}
            permission,lineage=te.producer_receipts("run1",job,inputs)
            te.atomic_json(attempt/"permission.json",permission); te.atomic_json(attempt/"lineage.json",lineage)
            te.atomic_json(attempt/artifact,{"schema":f"fixture/{contract}"})
            envelope=terminal_envelope(run_id="run1",job_id=job,attempt_id=attempt_id,
              worker_kind="deterministic_python",execution_status="OK",acceptance_status="CURRENT",
              input_fingerprint="sha256:"+str(index+1)*64,output_contract=contract,
              started_at="2026-01-01T00:00:00Z",finished_at="2026-01-01T00:00:01Z",summary="fixture",
              artifacts=artifact_records(attempt,["permission.json","lineage.json",artifact]))
            te.atomic_json(attempt/"result.json",envelope)
            pointer={"schema":"appsec-review/accepted-worker-result/1.0","status":"OK","run_id":"run1",
              "job":job,"attempt_id":attempt_id,"fingerprint":envelope["input_fingerprint"],"envelope_path":"result.json",
              "envelope_sha256":state.file_hash(attempt/"result.json"),"hashes":state.tree_hashes(attempt),
              "accepted_at":"2026-01-01T00:00:02Z"}
            te.atomic_json(producer/"accepted.json",pointer); te.atomic_json(producer/"latest.json",{"attempt_id":attempt_id})
            instance=chr(ord('a')+index)*32; binding={"source_snapshot_sha256":self.source,
              "build_lineage_sha256":build,"permissions":te.PERMISSIONS[job],"terminal_instance_ids":[instance]}
            entry,copies=assembly._producer(supply,"run1",self.source,
              {"job":job,"contract":contract,"allowed_skip_reasons":[]},binding,
              {instance:{"state":"succeeded","group_id":job.removeprefix("02-")[:40]}})
            self.assertEqual(entry["disposition"],"accepted"); self.assertEqual(len(copies),3)

    def test_claim_policies_validate_owned_contracts_and_reject_promotions(self):
        result_path=self.owner/"results.xml"; coverage_path=self.owner/"coverage.info"
        shutil.copyfile(ROOT/"tests/fixtures/test-evidence/results.xml",result_path)
        shutil.copyfile(ROOT/"tests/fixtures/test-evidence/coverage.info",coverage_path)
        execution=self.execution({"test-results":result_path,"coverage":coverage_path})
        values={te.EXECUTION_JOB:execution,te.RESULT_JOB:te.junit(execution,result_path),
                te.COVERAGE_JOB:te.lcov(execution,coverage_path,self.target)}
        for job,(_artifact,_schema,contract_id) in te.SPECS.items():
            contract=te.read_json(registry_paths.contract(contract_id))
            policy=output_validator.CLAIM_CLASS_POLICIES[contract_id]
            self.assertEqual(policy["claim_class_id"],contract["claim_class"]["claim_class_id"])
            self.assertEqual(policy["allowed_assertions"],set(contract["claim_class"]["allowed_assertions"]))
            attempt=self.owner/("contract-"+contract_id); attempt.mkdir()
            te.atomic_json(attempt/contract["result_schema"]["artifact"],values[job])
            self.assertEqual(output_validator.validate_contract_result(attempt,contract,run_id="run1"),[])
            promoted=deepcopy(values[job]); promoted["severity"]="high"
            te.atomic_json(attempt/contract["result_schema"]["artifact"],promoted)
            errors=output_validator.validate_contract_result(attempt,contract,run_id="run1")
            self.assertTrue(any("severity promotion" in error for error in errors),errors)

    def test_ingest_recomputes_and_requires_current_source_tree(self):
        execution=self.execution(); current_tree=te.source_tree_sha256(self.target)
        execution["source_tree_sha256"]=current_tree; execution["checkout_identity_sha256"]=current_tree
        execution["source_revision"]="rev1"; attempt=self.owner/"execution"; attempt.mkdir()
        with mock.patch.object(te,"accepted",return_value=(attempt,execution,self.lineage)), \
             mock.patch.object(te,"target",return_value=(self.target,self.source,current_tree,"rev1")):
            self.assertEqual(te.ingest_inputs("run1",te.RESULT_JOB)["source_tree_sha256"],current_tree)
            forged=deepcopy(execution); forged["source_tree_sha256"]="sha256:"+"0"*64
            with mock.patch.object(te,"accepted",return_value=(attempt,forged,self.lineage)):
                with self.assertRaisesRegex(te.Blocked,"source-tree attestation is stale"):
                    te.ingest_inputs("run1",te.RESULT_JOB)
            (self.target/"src/math.c").write_text("int add(int a,int b){return a-b;}\n")
            stale_tree=te.source_tree_sha256(self.target)
            with mock.patch.object(te,"target",return_value=(self.target,self.source,stale_tree,"rev1")):
                with self.assertRaisesRegex(te.Blocked,"source-tree attestation is stale"):
                    te.ingest_inputs("run1",te.COVERAGE_JOB)

if __name__=="__main__": unittest.main()
