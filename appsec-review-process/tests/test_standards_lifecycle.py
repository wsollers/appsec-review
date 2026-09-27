"""Focused tests for automatic standards lifecycle construction."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import sys

ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import standards_lifecycle as lifecycle
from execution_state import Blocked, atomic_json, read_json

H="sha256:"+"a"*64
COMPONENT={"source_snapshot_sha256":H,"functional_components":[{
    "component_id":"cli","downstream_lanes":["04-asvs-masvs","15-deployment-hardening"]}]}
COMPONENT_BIND={"job_id":"01-component-characterization","attempt_id":"c1","artifact_path":"component-purpose-map.json","artifact_sha256":H,"accepted_pointer_sha256":H}
STANDARDS_BIND={"job_id":"02-standards-source-ingest","attempt_id":"s1","artifact_path":"standards-source.json","artifact_sha256":H,"accepted_pointer_sha256":H}
STANDARD={"records":[{"family":"owasp_asvs","record_type":"control","record_id":"V1.1.1","path":"standards/x.json","sha256":H}]}
WRAPPER={"family":"owasp_asvs","edition":"5.0.0","record_type":"control","record_id":"V1.1.1",
         "record":{"proof_obligations":[{"minimum_evidence_modes":["static_source"]}]}}

class StandardsLifecycleTests(unittest.TestCase):
    def setup_paths(self, folder):
        run=Path(folder)/"run"; (run/"inputs").mkdir(parents=True)
        atomic_json(run/"inputs/artifact-manifest.json",{"fixture":"identity"})
        def data(_run,*parts): return run/"data"/Path(*parts)
        return run, mock.patch.object(lifecycle,"run_path",return_value=run), mock.patch.object(lifecycle,"data_path",side_effect=data)

    def loader(self, run_id, spec):
        if spec[0]==lifecycle.COMPONENT[0]: return COMPONENT,COMPONENT_BIND
        if spec[0]==lifecycle.STANDARDS[0]: return STANDARD,STANDARDS_BIND
        raise AssertionError(spec)

    def test_owasp_request_is_target_and_standard_derived_and_reused(self):
        with tempfile.TemporaryDirectory() as folder:
            run,p1,p2=self.setup_paths(folder)
            with p1,p2,mock.patch.object(lifecycle,"_load",side_effect=self.loader), \
                 mock.patch.object(lifecycle,"_record_documents",return_value=[(STANDARD["records"][0],WRAPPER)]):
                first=lifecycle.prepare_worklist("run-a","04-owasp-validation-worklist")
                second=lifecycle.prepare_worklist("run-a","04-owasp-validation-worklist")
            self.assertEqual(first,second); request=read_json(first["request_path"])
            control=request["payload"]["controls"][0]
            self.assertEqual(control["target_id"],"cli")
            self.assertEqual(control["applicability"],"cannot_determine")
            self.assertEqual(control["evidence_mode"],"manual")
            self.assertTrue(control["gaps"])

    def test_missing_stig_sources_fail_closed_instead_of_empty_success(self):
        with tempfile.TemporaryDirectory() as folder:
            _run,p1,p2=self.setup_paths(folder)
            with p1,p2,mock.patch.object(lifecycle,"_load",side_effect=self.loader), \
                 mock.patch.object(lifecycle,"_record_documents",return_value=[(STANDARD["records"][0],WRAPPER)]), \
                 self.assertRaisesRegex(Blocked,"no accepted controls"):
                lifecycle.run_worklist("run-a","dagster-a","15-stig-srg-validation-worklist")

    def test_worklist_run_executes_worker_and_reuses_verified_publication(self):
        prepared={"request_path":Path("request.json"),"attempt_id":"auto-a","control_count":1,"generation":H}
        pointer={"attempt_id":"auto-a","status":"OK_WITH_GAPS"}
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder)/"job"
            with mock.patch.object(lifecycle,"prepare_worklist",return_value=prepared), \
                 mock.patch.object(lifecycle,"data_path",return_value=base), \
                 mock.patch("bounded_transform_orchestration.execute",return_value={"attempt_id":"auto-a"}) as execute, \
                 mock.patch.object(lifecycle,"_publish_bounded",return_value=pointer):
                self.assertEqual(lifecycle.run_worklist("run-a","dagster-a","04-owasp-validation-worklist"),pointer)
                execute.assert_called_once()
            with mock.patch.object(lifecycle,"prepare_worklist",return_value=prepared), \
                 mock.patch.object(lifecycle,"data_path",return_value=base), \
                 mock.patch.object(lifecycle,"_reusable",return_value=pointer), \
                 mock.patch("bounded_transform_orchestration.execute") as execute:
                self.assertEqual(lifecycle.run_worklist("run-a","dagster-a","04-owasp-validation-worklist"),pointer)
                execute.assert_not_called()

    def test_join_facts_are_derived_but_existing_chain_remains_authoritative(self):
        model={"provider":"anthropic","family":"haiku","model_id":"claude-3-5-haiku-20261001","snapshot":"claude-3-5-haiku-20261001"}
        with mock.patch.object(lifecycle,"_load",side_effect=self.loader), \
             mock.patch.object(lifecycle.mvr,"resolve_run_model_versions",return_value={}), \
             mock.patch.object(lifecycle.mvr,"model_identity_for",return_value=model):
            facts=lifecycle.prepare_owasp_join("run-a")
        self.assertEqual(facts.source_snapshot_sha256,H)
        self.assertEqual(facts.allowed_models,(model,))

    def test_deployment_keeps_no_match_as_explicit_gap(self):
        stig={"work_items":[{"target_id":"cli","control_id":"SRG-1","standard_family":"DISA_STIG_SRG",
            "standard_version":"1","applicability":"cannot_determine","tailoring":"local",
            "citation_ids":["c1"]}]}
        def load(_run,spec):
            if spec[0]==lifecycle.COMPONENT[0]: return COMPONENT,COMPONENT_BIND
            if spec[0]=="15-stig-srg-validation-worklist": return stig,{"job_id":"stig","attempt_id":"a","artifact_path":"s","artifact_sha256":H,"accepted_pointer_sha256":H}
            if spec[0]==lifecycle.IAC[0]: return {"rule_hits":[]},{"job_id":"iac","attempt_id":"a","artifact_path":"i","artifact_sha256":H,"accepted_pointer_sha256":H}
            raise AssertionError(spec)
        with tempfile.TemporaryDirectory() as folder:
            _run,p1,p2=self.setup_paths(folder)
            with p1,p2,mock.patch.object(lifecycle,"_load",side_effect=load):
                prepared=lifecycle.prepare_deployment("run-a")
        self.assertEqual(prepared["result"]["assessments"],[])
        self.assertTrue(prepared["result"]["gaps"])
        self.assertFalse(prepared["result"]["claim_limits"]["runtime_claimed"])

if __name__=="__main__": unittest.main()
