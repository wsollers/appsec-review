import json, shutil, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import static_intelligence_core as core
import validate_job_output as output_validator
from execution_state import file_hash, Blocked
from schema_validate import validate_document
import registry_paths

class StaticIntelTests(unittest.TestCase):
 def source(self,target):
  return {p.relative_to(target).as_posix():{"kind":"file","sha256":file_hash(p),"bytes":p.stat().st_size}
          for p in target.rglob('*') if p.is_file()}
 def test_four_extractors_are_deterministic_redacted_and_static(self):
  with tempfile.TemporaryDirectory() as d:
   target=Path(d); shutil.copytree(ROOT/'tests/fixtures/static-intelligence',target,dirs_exist_ok=True)
   files=self.source(target); binding={"job_id":"00-intake","attempt_id":"i","fingerprint":"f","source_fingerprint":"a"*64,"source_revision":"r","pointer_sha256":"sha256:"+"b"*64}
   for job,(contract,name,schema) in core.SPECS.items():
    one=core.extract(job,run_id='run',attempt_id='a',target=target,source=binding,source_files=files)
    two=core.extract(job,run_id='run',attempt_id='a',target=target,source=binding,source_files=files)
    self.assertEqual(one,two); self.assertEqual(validate_document(one,schema),[])
    self.assertTrue(one['static_only']); self.assertNotIn('sk-abcdefghijklmnopqrstuvwxyz',json.dumps(one))
    self.assertGreater(len(one['records']),0)
    self.assertTrue(all(r['semantics']=='DOCUMENTED_STATIC_INTENT' for r in one['records']))
 def test_readme_only_is_not_applicable_but_unexamined_entries_stay_gaps(self):
  with tempfile.TemporaryDirectory() as d:
   target=Path(d); (target/'README.md').write_text('# hello\n')
   files=self.source(target); source={"source_fingerprint":"a"*64}
   others=[job for job in core.SPECS if job!=core.DOC]  # gap 7: a README is a document-intake input
   for job in others:
    out=core.extract(job,run_id='r',attempt_id='a',target=target,source=source,source_files=files)
    self.assertEqual((out['status'],out['applicability'],out['records'],out['coverage_gaps']),
                     ('SKIPPED',core.SKIPPED_NA,[],[]))
    self.assertEqual(out['inventory'],{'files_examined':1,'non_file_entries':0,'candidates':0})
   out=core.extract(core.DOC,run_id='r',attempt_id='a',target=target,source=source,source_files=files)
   self.assertEqual((out['status'],out['inventory']['candidates'],out['documents'][0]['doc_class']),('OK',1,'readme'))
   # A link is not followed: absence of a candidate behind it is not established.
   files['docs']={'kind':'symlink','target':'../elsewhere'}
   for job in others:
    out=core.extract(job,run_id='r',attempt_id='a',target=target,source=source,source_files=files)
    self.assertEqual(out['status'],'OK_WITH_GAPS')
    self.assertEqual(out['coverage_gaps'],['readme-only-no-specialized-inputs:1-non-file-entries-unexamined'])
   del files['README.md']
   out=core.extract(core.DOC,run_id='r',attempt_id='a',target=target,source=source,source_files=files)
   self.assertEqual((out['status'],out['coverage_gaps']),('OK_WITH_GAPS',['no-applicable-inputs:1-non-file-entries-unexamined']))
 def test_assembly_edge_authorizes_the_not_applicable_skip(self):
  graph=json.loads((ROOT/'pipeline/job-graph.json').read_text())
  edges={d['job']:d for d in graph['jobs'][core.CONSUMER]['dependencies']}
  for job in core.SPECS: self.assertIn(core.SKIP_REASON,edges[job]['allowed_skip_reasons'],job)
 def test_shell_c_and_unity_tests_and_runnable_entrypoints_are_indexed(self):
  with tempfile.TemporaryDirectory() as d:
   target=Path(d); (target/'tests').mkdir()
   (target/'tests/run.sh').write_text('#!/bin/sh\nfunction test_a {\n:\n}\ntest_b () {\n:\n}\nrun_test test_c\n')
   (target/'tests/t.c').write_text('void test_d(void);\nvoid test_d(void) {\n}\nint main(void) { RUN_TEST(test_e); return 0; }\n')
   out=core.extract('02-test-intelligence-ingest',run_id='r',attempt_id='a',target=target,source={},source_files=self.source(target))
   got=sorted((r['path'],r['kind'],r['locator'],r['summary']) for r in out['records'])
   self.assertEqual(got,[('tests/run.sh','documented-test','line:2','test_a'),('tests/run.sh','documented-test','line:5','test_b'),
    ('tests/run.sh','documented-test','line:8','test_c'),('tests/run.sh','test-entrypoint','file','runnable test script tests/run.sh'),
    ('tests/t.c','documented-test','line:2','test_d'),('tests/t.c','documented-test','line:4','test_e')])
   self.assertEqual(out['status'],'OK')
 def test_openapi_yaml_and_bruno_are_bounded_deterministic_positive_inputs(self):
  with tempfile.TemporaryDirectory() as d:
   target=Path(d); shutil.copytree(ROOT/'tests/fixtures/static-intelligence/api',target/'api')
   files=self.source(target); source={"source_fingerprint":"a"*64}
   one=core.extract('02-api-collection-intelligence-ingest',run_id='r',attempt_id='a',target=target,source=source,source_files=files)
   two=core.extract('02-api-collection-intelligence-ingest',run_id='r',attempt_id='a',target=target,source=source,source_files=files)
   self.assertEqual(one,two); self.assertEqual(one['status'],'OK'); self.assertEqual(one['coverage_gaps'],[])
   by_path={}
   for record in one['records']: by_path.setdefault(record['path'],[]).append(record['summary'])
   self.assertEqual(by_path['api/openapi.yaml'],['GET /health','POST /reports'])
   self.assertEqual(by_path['api/get-user.bru'],['GET https://api.example.test/users/{{user_id}}'])
 def test_malformed_yaml_bruno_and_aliases_remain_explicit_gaps(self):
  with tempfile.TemporaryDirectory() as d:
   target=Path(d); (target/'api').mkdir()
   (target/'api/openapi.yaml').write_text('paths: [not: valid\n')
   (target/'api/broken.bru').write_text('get {\n  url: https://example.test\n')
   (target/'api/openapi-alias.yaml').write_text('openapi: 3.0.0\npaths: &routes {}\ncopy: *routes\n')
   out=core.extract('02-api-collection-intelligence-ingest',run_id='r',attempt_id='a',target=target,source={},source_files=self.source(target))
   self.assertEqual(out['records'],[]); self.assertEqual(out['status'],'OK_WITH_GAPS')
   self.assertEqual(out['coverage_gaps'],[
    'malformed-or-empty-api-collection:api/broken.bru',
    'malformed-or-empty-api-collection:api/openapi-alias.yaml',
    'malformed-or-empty-api-collection:api/openapi.yaml','zero-indexable-records'])
 def test_oversized_stale_and_hostile_content_fail_or_gap(self):
  with tempfile.TemporaryDirectory() as d:
   target=Path(d); (target/'docs').mkdir(); p=target/'docs/design.md'; p.write_bytes(b'x'*(core.MAX_FILE_BYTES+1))
   files=self.source(target); out=core.extract('02-doc-intelligence-ingest',run_id='r',attempt_id='a',target=target,source={},source_files=files)
   self.assertTrue(any(x.startswith('oversized-input:') for x in out['coverage_gaps']))
   files['docs/design.md']['sha256']='0'*64
   with self.assertRaises(Blocked): core.extract('02-doc-intelligence-ingest',run_id='r',attempt_id='a',target=target,source={},source_files=files)
 def test_registry_is_not_executable(self):
  for job,(contract,result,schema) in core.SPECS.items():
   t=json.loads((ROOT/registry_paths.template_rel(job)).read_text()); c=json.loads((ROOT/registry_paths.contract_rel(contract)).read_text())
   self.assertEqual(t['implemented'],job==core.DOC); self.assertEqual(c['result_schema'],{"artifact":result,"schema_file":schema})
   self.assertTrue(set(c['required_files'])<=set(t['outputs']['files']))
   self.assertEqual(output_validator._claim_class_errors(c,{"records":[]}),[])
   self.assertTrue(output_validator._claim_class_errors(c,{"severity":"high"}))
if __name__=='__main__': unittest.main()
