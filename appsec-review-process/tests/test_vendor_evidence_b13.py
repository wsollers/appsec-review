from pathlib import Path
import sys, tempfile, unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import vendor_evidence_b13 as b

class Runtime:
    images_dir=Path('/images'); host_flavor='linux'; docker_host=None; docker_executable=Path('/docker'); container_user='1:1'

class B13Tests(unittest.TestCase):
    def test_every_vendor_command_is_closed_offline_and_writes_scratch(self):
        for tool,spec in b.SPECS.items():
            self.assertTrue(spec.argv[0].startswith('/'))
            self.assertNotIn('sh', spec.argv[:1]); self.assertNotIn('-c', spec.argv)
            self.assertTrue(spec.output.endswith(('.json','.sarif','.log')))

    def call(self,status='OK',verify_errors=(),write=True):
        td=tempfile.TemporaryDirectory(); self.addCleanup(td.cleanup); root=Path(td.name)
        req={'bounded':True}
        def run(runtime,**kw):
            if write:
                (root/'scratch').mkdir(); (root/'scratch/gitleaks.json').write_text('[]')
            return {'execution_status':status,'cause':'TIMEOUT' if status=='FAILED' else None,'result_sha256':'sha256:'+'a'*64}
        def verify(*a,**kw): return list(verify_errors)
        return lambda: b.execute('gitleaks',runtime=Runtime(),run_id='r',job_id='02-secrets-inventory',attempt_id='a',attempt_root=root,request_document=req,run_container=run,verify=verify)

    def test_clean_and_hit_json_are_returned_only_after_verification(self):
        terminal,data=self.call()(); self.assertEqual(terminal['execution_status'],'OK'); self.assertEqual(data,b'[]')
    def test_tool_error_and_timeout_fail(self):
        with self.assertRaises(b.VendorToolFailed): self.call('FAILED')()
    def test_tampered_b13_result_fails_before_output_read(self):
        with self.assertRaisesRegex(b.VendorToolFailed,'verification'): self.call(verify_errors=['hash'])()
    def test_missing_output_fails(self):
        with self.assertRaisesRegex(b.VendorToolFailed,'missing'): self.call(write=False)()

    def test_bounded_parsers_drop_vendor_messages_and_reject_traversal(self):
        raw=b'[{"RuleID":"generic-api-key","File":"/inputs/src/a.py","StartLine":2,"EndLine":2,"Secret":"never"}]'
        self.assertEqual(b.normalize('gitleaks',raw),[{'rule_id':'generic-api-key','path':'src/a.py','start_line':2,'end_line':2}])
        self.assertNotIn('never',repr(b.normalize('gitleaks',raw)))
        with self.assertRaisesRegex(b.VendorToolFailed,'path'):
            b.normalize('gitleaks',b'[{"RuleID":"x","File":"../escape","StartLine":1,"EndLine":1}]')

    def test_collect_runs_each_tool_and_preserves_sibling_failure(self):
        td=tempfile.TemporaryDirectory(); self.addCleanup(td.cleanup); root=Path(td.name); source=root/'source'; source.mkdir()
        def fake_request(tool_id,**kw):
            if tool_id=='checkov': raise b.VendorToolBlocked('missing')
            return {'tool':tool_id,'permission':{},'image':{'image_id':'tool-hadolint','digest':'sha256:'+'a'*64},'argv':['/tool','--offline']}
        def fake_execute(tool_id,**kw): return ({'execution_status':'OK','request_sha256':'sha256:'+'1'*64,
            'result_sha256':'sha256:'+'2'*64,'permission_fingerprint_sha256':'sha256:'+'3'*64,'exit_code':0},b'[]')
        records={'tool-hadolint':{'repository':'docker.io/library/tool-hadolint','digest':'sha256:'+'a'*64,'build_attempt_id':'build-1'}}
        with mock.patch.object(b,'request',fake_request), mock.patch.object(b,'execute',fake_execute), mock.patch.object(b.ce,'load_image_registry',lambda *_:records):
            result=b.collect('02-iac-config-scan',['checkov','hadolint'],run_id='r',node_attempt_id='node',
                             source_root=source,source_sha='sha256:'+'a'*64,attempt_root=root/'attempt',
                             now='2026-09-27T12:00:00Z',runtime_factory=lambda *a: Runtime(),version_probe=lambda *a,**k:'2.15.1')
        self.assertEqual(result['checkov']['status'],'BLOCKED')
        self.assertEqual(result['hadolint']['status'],'OK')

    def test_container_metadata_projection_requires_real_digests_and_layers(self):
        import json
        raw=json.dumps({'source':{'metadata':{'manifestDigest':'sha256:'+'a'*64,'layers':[{'digest':'sha256:'+'b'*64,'size':9}],
             'config':{'digest':'sha256:'+'c'*64,'architecture':'amd64','os':'linux','user':None,'entrypoint':None,
                       'entrypointArgs':0,'command':None,'commandArgs':0,'ports':[],'envNames':[]}}}}).encode()
        facts=b.container_image_facts(raw,'image.tar')['image.tar']
        self.assertEqual(facts['layers'][0]['layer_bytes'],9)
        with self.assertRaises(b.VendorToolFailed): b.container_image_facts(b'{"source":{"metadata":{}}}','image.tar')

if __name__=='__main__': unittest.main()
