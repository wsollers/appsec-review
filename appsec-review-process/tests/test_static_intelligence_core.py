import json, shutil, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import static_intelligence_core as core
from execution_state import file_hash, Blocked
from schema_validate import validate_document

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
    self.assertTrue(all(r['semantics']=='DOCUMENTED_STATIC_INTENT' for r in one['records']))
 def test_readme_only_and_zero_input_are_honest_gaps(self):
  with tempfile.TemporaryDirectory() as d:
   target=Path(d); (target/'README.md').write_text('# hello\n')
   files=self.source(target); source={"source_fingerprint":"a"*64}
   for job in core.SPECS:
    out=core.extract(job,run_id='r',attempt_id='a',target=target,source=source,source_files=files)
    self.assertEqual(out['records'],[]); self.assertIn('readme-only-no-specialized-inputs',out['coverage_gaps'])
 def test_oversized_stale_and_hostile_content_fail_or_gap(self):
  with tempfile.TemporaryDirectory() as d:
   target=Path(d); (target/'docs').mkdir(); p=target/'docs/design.md'; p.write_bytes(b'x'*(core.MAX_FILE_BYTES+1))
   files=self.source(target); out=core.extract('02-doc-intelligence-ingest',run_id='r',attempt_id='a',target=target,source={},source_files=files)
   self.assertTrue(any(x.startswith('oversized-input:') for x in out['coverage_gaps']))
   files['docs/design.md']['sha256']='0'*64
   with self.assertRaises(Blocked): core.extract('02-doc-intelligence-ingest',run_id='r',attempt_id='a',target=target,source={},source_files=files)
 def test_registry_is_not_executable(self):
  for job,(contract,result,schema) in core.SPECS.items():
   t=json.loads((ROOT/f'registry/job-templates/{job}.json').read_text()); c=json.loads((ROOT/f'registry/output-contracts/{contract}.json').read_text())
   self.assertFalse(t['implemented']); self.assertEqual(c['result_schema'],{"artifact":result,"schema_file":schema})
   self.assertTrue(set(c['required_files'])<=set(t['outputs']['files']))
if __name__=='__main__': unittest.main()
