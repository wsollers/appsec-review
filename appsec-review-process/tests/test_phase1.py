"""Behavior qualification. All fixtures and subprocess diagnostics remain under a run's data/."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import execution_state as state
import phase1
import job_graph
import intake
import run_process

ROOT = state.ROOT
EVIDENCE = Path(os.environ['PHASE1_TEST_DATA']).resolve()
EVIDENCE.mkdir(parents=True, exist_ok=True)


class Phase1Tests(unittest.TestCase):
    def setUp(self):
        self.root = EVIDENCE / uuid.uuid4().hex[:6]
        self.root.mkdir()
        state.atomic_json(self.root / 'test.json', {'test':self._testMethodName})
        self.old_runs = state.RUNS
        state.RUNS = self.root / 'runs'
        self.target = self.root / 'target'; self.target.mkdir()
        (self.target / 'main.py').write_text('print("fixture")\n')
        self.run_id = 'fixture-a'
        self.new_run(self.run_id)

    def tearDown(self):
        state.RUNS = self.old_runs

    def new_run(self, run_id, permissions=None, engagement_output='', import_legacy=False):
        run_process.init_run(run_id)
        return phase1.stage(run_id, self.target, 'fixture', 'Behavior qualification', ['Linux','Windows'],
                            permissions=permissions, engagement_output=engagement_output, import_legacy=import_legacy)

    def run_job(self, **kw):
        return phase1.run_intake(self.run_id, **kw)

    def linux_manifest(self):
        manifest=state.read_json(phase1.manifest_path(self.run_id))
        manifest['intake_config']['executor_platform']='posix'
        state.atomic_json(phase1.manifest_path(self.run_id),manifest)

    def test_dagster_launcher_submits_config_and_reattaches(self):
        import launch_job
        self.linux_manifest()
        success={'runId':'server-run','status':'SUCCESS'}
        with patch.object(launch_job,'find_run',side_effect=[None,success]), patch.object(launch_job,'graphql',return_value={'launchRun':{'__typename':'LaunchRunSuccess','run':success}}) as api:
            first=launch_job.launch(self.run_id,launch_id='request-a',wait=True)
            second=launch_job.launch(self.run_id,launch_id='request-a',wait=True)
            self.assertEqual(first['dagster_run_id'],second['dagster_run_id'])
            self.assertEqual(api.call_count,1)
            params=api.call_args.args[1]['params']
            self.assertEqual(params['selector']['jobName'],'engagement_workflow')
            self.assertEqual(params['runConfigData']['resources']['workflow_settings']['config'],{'engagement_run_id':self.run_id,'force':False})
            self.assertFalse((phase1.job_root(self.run_id)/'attempts').exists())

    def test_dagster_launcher_uncertain_submission_never_retries(self):
        import launch_job
        self.linux_manifest()
        with patch.object(launch_job,'find_run',return_value=None), patch.object(launch_job,'graphql',side_effect=TimeoutError('lost response')) as api:
            with self.assertRaises(TimeoutError): launch_job.launch(self.run_id,launch_id='uncertain')
            with self.assertRaises(state.Blocked): launch_job.launch(self.run_id,launch_id='uncertain')
            self.assertEqual(api.call_count,1)
        record=state.read_json(state.data_path(self.run_id,'orchestration','launches','uncertain','request.json'))
        self.assertEqual(record['status'],'SUBMITTING')
        self.assertIn('--launch-id',record['resume_argv'])

    def test_dagster_launcher_failure_exit_and_no_host_conversion(self):
        import launch_job
        self.linux_manifest()
        with patch.object(launch_job,'find_run',return_value={'runId':'failed-run','status':'FAILURE'}):
            self.assertEqual(launch_job.main(['--run-id',self.run_id,'--wait']),1)
        manifest=state.read_json(phase1.manifest_path(self.run_id))
        manifest['intake_config']['executor_platform']='nt'
        state.atomic_json(phase1.manifest_path(self.run_id),manifest)
        with patch.object(launch_job,'graphql') as api:
            with self.assertRaises(state.Blocked): launch_job.launch(self.run_id)
            api.assert_not_called()

    def test_dagster_worker_arguments_are_registry_controlled(self):
        job=state.read_json(ROOT/'registry/job-templates/00-intake.json')
        self.assertEqual(phase1.worker_argv(job,self.root)[-1],str(self.root))
        job['execution']['worker']='../../target/run.py'
        with self.assertRaises(state.Blocked): phase1.worker_argv(job,self.root)

    def accepted(self):
        return phase1.accepted(self.run_id)

    def logs(self, name):
        p = self.root / 'logs' / name; p.mkdir(parents=True); return p

    def child(self, code, name='child', timeout=5, **kw):
        return state.execute([sys.executable,'-B','-c',code], self.root, self.logs(name), timeout, **kw)

    def test_A03_registry_and_semantic_rejection(self):
        for name in ('00-intake','00-validation'):
            job = state.read_json(ROOT/'registry/job-templates'/f'{name}.json')
            self.assertEqual(len(job_graph.composition(job)),5)
        bad = copy.deepcopy(job); bad['composition']['role_id']='missing-role'
        with self.assertRaises(FileNotFoundError): job_graph.composition(bad)
        bad = copy.deepcopy(job); bad['outputs']['files']=[]
        with self.assertRaisesRegex(ValueError,'omits'): job_graph.composition(bad)
        bad = copy.deepcopy(job); bad['composition']['role_id']='intake-coordinator'
        with self.assertRaisesRegex(ValueError,'incompatibility'): job_graph.composition(bad)

    def test_A04_all_scope_families(self):
        for family,files,native in [('native',{'main.cpp':'int main(){}','CMakeLists.txt':'project(x)'},True),
                                   ('nonnative',{'package.json':'{}'},False),('iac',{'main.tf':'resource "x" "y" {}'},False),
                                   ('mixed',{'client/a.cpp':'','client/CMakeLists.txt':'','server/package.json':'{}','infra/main.tf':'','api/openapi.yaml':'','ops/runbook.md':'','.github/workflows/check.yml':''},True)]:
            directory=self.root/family; directory.mkdir()
            for p,text in files.items():
                f=directory/p; f.parent.mkdir(parents=True,exist_ok=True); f.write_text(text)
            cfg=copy.deepcopy(phase1.config_for(self.run_id)); cfg['target']=str(directory)
            identity=intake.source_identity(directory); result=intake.inventory(identity,cfg)
            intake.validate_intake(result,identity,cfg)
            self.assertEqual(result['native']['applicable'],native)
            self.assertFalse(result['native']['compile_database_required_for_intake'])
            self.assertEqual(set(result['scope']['all_paths']),set(files))
            if family=='mixed': self.assertTrue({'cpp','typescript','iac','api','operations','cicd'} <= result['families'].keys())
            state.atomic_json(self.root/(family+'-result.json'),result)

    def test_A05_intake_vs_pregather(self):
        self.run_job()
        cfg=phase1.config_for(self.run_id)
        with self.assertRaisesRegex(state.Blocked,'missing'): phase1.validate_supplied(self.run_id,cfg,'pregather')
        out=state.data_path(self.run_id,cfg['engagement_relative']); out.mkdir(parents=True)
        (out/'job-status.json').write_text('{bad')
        with self.assertRaises(json.JSONDecodeError): phase1.validate_supplied(self.run_id,cfg,'intake')
        self.assertRaises(Exception,self.run_job)
        self.assertIsNone(self.accepted())

    def test_A05_supplied_status_semantics(self):
        cfg=phase1.config_for(self.run_id); out=state.data_path(self.run_id,cfg['engagement_relative']); out.mkdir(parents=True)
        state.atomic_json(out/'job-status.json',{'status':'FAILED'})
        with self.assertRaises(state.Blocked): phase1.validate_supplied(self.run_id,cfg,'intake')

    def test_A06_paths_and_two_runs(self):
        for value in ('../escape','x/y','x\\y','C:escape','..','CON'):
            with self.assertRaises(ValueError): state.run_path(value)
        with self.assertRaises(ValueError): state.data_path(self.run_id,'../../escape')
        a,_=self.run_job(); old=state.tree_hashes(phase1.job_root(self.run_id)/'attempts'/a['attempt_id'])
        self.new_run('fixture-b'); b,reused=phase1.run_intake('fixture-b')
        self.assertFalse(reused); self.assertNotEqual(a['attempt_id'],b['attempt_id'])
        self.assertEqual(old,state.tree_hashes(phase1.job_root(self.run_id)/'attempts'/a['attempt_id']))
        self.assertNotEqual(phase1.job_root(self.run_id),phase1.job_root('fixture-b'))

    def test_A06_symlink_escape(self):
        root=state.data_path(self.run_id); outside=self.root/'outside'; outside.mkdir()
        link=root/'escape'
        try:
            link.symlink_to(outside,target_is_directory=True)
        except OSError:
            if os.name != 'nt': raise
            result=subprocess.run(['cmd','/c','mklink','/J',str(link),str(outside)],capture_output=True)
            self.assertEqual(result.returncode,0)
        with self.assertRaises(ValueError): state.data_path(self.run_id,'escape/file')
        with self.assertRaises(ValueError): state.tree_hashes(root)

    def test_A07_reuse_force_and_immutable_bytes(self):
        first,reused=self.run_job(); self.assertFalse(reused)
        path=phase1.job_root(self.run_id)/'attempts'/first['attempt_id']; hashes=state.tree_hashes(path)
        with patch('phase1.execute',side_effect=AssertionError('work invoked on cache hit')):
            second,reused=self.run_job()
        self.assertTrue(reused); self.assertEqual(first['attempt_id'],second['attempt_id'])
        third,reused=self.run_job(force=True)
        self.assertFalse(reused); self.assertNotEqual(first['attempt_id'],third['attempt_id'])
        self.assertEqual(hashes,state.tree_hashes(path))

    def test_A08_source_config_and_tamper(self):
        first,_=self.run_job()
        (self.target/'untracked.txt').write_text('new dirty input')
        with self.assertRaisesRegex(state.Blocked,'stale'): self.accepted()
        second,_=self.run_job(); self.assertNotEqual(first['attempt_id'],second['attempt_id'])
        p=phase1.job_root(self.run_id)/'attempts'/second['attempt_id']/'outputs/intake.json'; p.write_text('{}')
        with self.assertRaisesRegex(state.Blocked,'hash mismatch'): self.accepted()
        third,_=self.run_job(); self.assertNotEqual(second['attempt_id'],third['attempt_id'])
        cfg=phase1.config_for(self.run_id)
        phase1.stage(self.run_id,self.target,'fixture','Changed business goal',cfg['platforms'])
        self.assertIsNone(self.accepted())

    def test_A08_prompt_schema_tool_changes(self):
        self.run_job()
        # Substitute an observed changed dependency hash without modifying governing files.
        original=job_graph.file_hash
        for marker in ('phase-1-implementation-prompt.md','intake.schema.json','intake.py','Dockerfile'):
            def changed(path): return '0'*64 if Path(path).name==marker else original(path)
            with patch('job_graph.file_hash',side_effect=changed):
                with self.assertRaises(state.Blocked): self.accepted()
        with patch('phase1.sys.version',sys.version+' tool-change'):
            with self.assertRaisesRegex(state.Blocked,'stale'): self.accepted()
        original_read=job_graph.read_json
        def changed_validator(path):
            result=original_read(path)
            if Path(path).name=='00-validation.json': result['timeout_seconds']+=1
            return result
        with patch('job_graph.read_json',side_effect=changed_validator):
            with self.assertRaisesRegex(state.Blocked,'stale'): self.accepted()

    def test_A08_source_changes_during_work(self):
        with phase1.Session(self.run_id) as session:
            session.prepare(); session.work()
            (self.target/'main.py').write_text('changed while working')
            with self.assertRaisesRegex(state.Blocked,'changed during'): session.publish()
        self.assertIsNone(self.accepted())

    def test_A08_descendant_invalidation(self):
        self.run_job()
        path=phase1.job_root(self.run_id,'02-repository-partition-discovery')/'accepted.json'
        state.atomic_json(path,{'status':'OK','attempt_id':'prior'})
        self.run_job(force=True)
        self.assertEqual(state.read_json(path)['status'],'INVALIDATED')

    def test_A09_duplicate_dispatch(self):
        with phase1.Session(self.run_id) as session:
            session.prepare()
            with self.assertRaises(state.Blocked): self.run_job()
            env=dict(os.environ,APPSEC_RUNS_ROOT=str(state.RUNS),PYTHONDONTWRITEBYTECODE='1')
            result=state.execute([sys.executable,'-B',str(ROOT/'phase1.py'),'intake','--run-id',self.run_id],
                                 self.root,self.logs('duplicate-process'),10,env=env)
            self.assertEqual(result['exit_code'],1)
            self.assertIn('active lock',(self.root/'logs/duplicate-process/stderr.log').read_text())
            session.work(); session.publish()
        self.assertEqual(self.accepted()['status'],'OK')

    def test_A09_process_crash_recovery(self):
        env=dict(os.environ,APPSEC_RUNS_ROOT=str(state.RUNS),PYTHONDONTWRITEBYTECODE='1')
        ready=self.root/'ready.json'
        code="import sys,os;sys.path.insert(0,sys.argv[1]);import phase1,execution_state as s; x=phase1.Session('fixture-a');x.__enter__();x.prepare();s.atomic_json(sys.argv[2],{'attempt':x.attempt.name});os._exit(23)"
        result=state.execute([sys.executable,'-B','-c',code,str(ROOT),str(ready)],self.root,self.logs('crash'),20,env=env)
        self.assertEqual(result['exit_code'],23)
        prior=phase1.job_root(self.run_id)/'attempts'/state.read_json(ready)['attempt']
        self.assertEqual(state.read_json(prior/'status.json')['status'],'RUNNING')
        result,reused=self.run_job(); self.assertFalse(reused)
        self.assertEqual(state.read_json(prior/'status.json')['cause'],'INTERRUPTED_WORKER')
        self.assertNotEqual(result['attempt_id'],prior.name)

    def test_A09_atomic_commit_failure(self):
        original=phase1.atomic_json
        def fail(path,value):
            if Path(path).name=='accepted.json' and value.get('status')=='OK': raise OSError('simulated disk full')
            return original(path,value)
        with patch('phase1.atomic_json',side_effect=fail):
            with self.assertRaisesRegex(OSError,'disk full'): self.run_job()
        self.assertIsNone(self.accepted())
        result,reused=self.run_job(); self.assertFalse(reused)

    def test_A10_graph_cycles_missing_contract_namespace(self):
        graph=job_graph.load_graph()
        bad=copy.deepcopy(graph); bad['jobs']['00-intake']['dependencies']=[{'job':'absent','kind':'required','contract':'x'}]
        with self.assertRaises(ValueError): job_graph.validate_graph(bad)
        bad=copy.deepcopy(graph); bad['jobs']['02-dev-project-discovery']['dependencies'][0]['contract']='wrong'
        with self.assertRaisesRegex(ValueError,'contract'): job_graph.validate_graph(bad)
        bad=copy.deepcopy(graph); bad['jobs']['00-intake']['dependencies']=[{'job':'00-intake','kind':'required','contract':'intake'}]
        with self.assertRaisesRegex(ValueError,'cycle'): job_graph.validate_graph(bad)
        bad=copy.deepcopy(graph); bad['jobs']['02-dev-project-discovery']['namespace']='00-intake'
        with self.assertRaisesRegex(ValueError,'namespace'): job_graph.validate_graph(bad)

    def test_A10_dependency_status_and_skip(self):
        dep={'job':'x','kind':'required','allowed_skip_reasons':[]}
        for result in (None,{'status':'FAILED'},{'status':'SKIPPED','reason':'unknown'}):
            with self.assertRaises(state.Blocked): job_graph.dependency_ok(dep,result)
        dep['kind']='optional'
        with self.assertRaises(state.Blocked): job_graph.dependency_ok(dep,{'status':'FAILED'})
        dep['enabled']=False; job_graph.dependency_ok(dep,None)
        dep['allowed_skip_reasons']=['not-applicable']; job_graph.dependency_ok(dep,{'status':'SKIPPED','reason':'not-applicable'})

    def test_A10_pre_blocks_work(self):
        cfg=phase1.config_for(self.run_id)
        phase1.stage(self.run_id,self.target,'fixture','Goal',cfg['platforms'],permissions=[])
        with patch('phase1.execute',side_effect=AssertionError('work must not run')):
            with self.assertRaises(state.Blocked): self.run_job()
        self.assertIsNone(self.accepted())

    def test_A10_post_blocks_handoff(self):
        with self.assertRaises((FileNotFoundError,ValueError)):
            self.run_job(command=[sys.executable,'-B','-c',"print('exit zero but no required output')"])
        with self.assertRaises(state.Blocked): phase1.handoff(self.run_id)

    def test_A11_large_concurrent_streams(self):
        code="import sys,threading; a=threading.Thread(target=lambda:sys.stdout.buffer.write(b'O'*4194304)); b=threading.Thread(target=lambda:sys.stderr.buffer.write(b'E'*4194304)); a.start();b.start();a.join();b.join()"
        result=self.child(code); self.assertEqual(result['exit_code'],0); self.assertNotIn('error',result)
        for name,char in [('stdout',b'O'),('stderr',b'E')]:
            data=(self.root/'logs/child'/f'{name}.log').read_bytes(); self.assertEqual(len(data),4194304); self.assertEqual(set(data),set(char))

    def test_A11_stderr_only_and_nonzero(self):
        result=self.child("import sys; print('warning only',file=sys.stderr)",'warning')
        self.assertEqual(result['exit_code'],0); self.assertNotIn('error',result)
        result=self.child("import sys; print('failure detail',file=sys.stderr);sys.exit(7)",'nonzero')
        self.assertEqual(result['exit_code'],7)

    def test_A11_startup_timeout_cancel(self):
        result=state.execute(['nonexistent-appsec-executable-497'],self.root,self.logs('startup'),3)
        self.assertTrue(result.get('error') or result['exit_code'] != 0)
        result=self.child('import time;time.sleep(10)','timeout',timeout=.2)
        self.assertTrue(result['timed_out'])
        cancel=threading.Event(); timer=threading.Timer(.2,cancel.set); timer.start()
        result=self.child('import time;time.sleep(10)','cancel',cancel=cancel)
        timer.join(); self.assertTrue(result['cancelled'])

    def test_A11_malformed_zero_exit(self):
        with phase1.Session(self.run_id) as session:
            session.prepare(); session.work()
            (session.attempt/'outputs/intake.json').write_text('{malformed')
            with self.assertRaises(json.JSONDecodeError): session.publish()
        self.assertIsNone(self.accepted())

    def test_A12_logging_failure_emergency(self):
        original=state.event; stderr=io.StringIO()
        def fail(path,kind,**kw):
            if kind=='STREAM': raise PermissionError('injected diagnostic permission failure')
            return original(path,kind,**kw)
        with contextlib.redirect_stderr(stderr),patch('execution_state.event',side_effect=fail):
            result=self.child("import sys,time;print('diagnostic',flush=True);time.sleep(1)")
        self.assertIn('error',result); self.assertIn('EMERGENCY_EVIDENCE_FAILURE',stderr.getvalue())
        (self.root/'emergency.txt').write_text(stderr.getvalue())

    def test_A12_state_permission_failure_and_recovery(self):
        original=phase1.atomic_json; stderr=io.StringIO()
        def fail(path,value):
            if Path(path).name=='status.json': raise PermissionError('injected read-only state store')
            return original(path,value)
        with contextlib.redirect_stderr(stderr),patch('phase1.atomic_json',side_effect=fail):
            with self.assertRaises(PermissionError): self.run_job()
        self.assertIsNone(self.accepted())
        result,reused=self.run_job(); self.assertFalse(reused)

    def test_A12_child_cleanup(self):
        marker=self.root/'escaped.txt'
        child="import time;from pathlib import Path;time.sleep(2);Path("+repr(str(marker))+").write_text('escaped')"
        code="import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',"+repr(child)+"]);print('spawned',flush=True);time.sleep(10)"
        result=self.child(code,'parent',timeout=.5); self.assertTrue(result['timed_out'])
        time.sleep(2.2); self.assertFalse(marker.exists())

    def test_A12_lost_worker_child_cleanup(self):
        marker=self.root/'orphan.txt'; ready=self.root/'spawned'
        child="import time;from pathlib import Path;time.sleep(3);Path("+repr(str(marker))+").write_text('escaped')"
        work="import subprocess,sys,time;from pathlib import Path;subprocess.Popen([sys.executable,'-c',"+repr(child)+"]);Path("+repr(str(ready))+").touch();time.sleep(20)"
        code="import sys;sys.path.insert(0,sys.argv[1]);from execution_state import execute;execute([sys.executable,'-c',sys.argv[2]],sys.argv[3],sys.argv[4],30)"
        logs=self.logs('lost-worker')
        with (logs/'parent-stdout.log').open('wb') as out,(logs/'parent-stderr.log').open('wb') as err:
            worker=subprocess.Popen([sys.executable,'-B','-c',code,str(ROOT),work,str(self.root),str(logs)],stdout=out,stderr=err)
            try:
                deadline=time.monotonic()+5
                while not ready.exists() and time.monotonic()<deadline: time.sleep(.025)
                self.assertTrue(ready.exists())
                worker.kill(); worker.wait(timeout=5)
                time.sleep(3.2); self.assertFalse(marker.exists())
            finally:
                if worker.poll() is None: worker.kill(); worker.wait()

    def test_A08_restaging_preserves_and_supplied_changes(self):
        first,_=self.run_job()
        before=state.read_json(state.run_path(self.run_id)/'run-status.json')
        phase1.stage(self.run_id,self.target,'fixture','Behavior qualification',['Linux','Windows'])
        self.assertEqual(before,state.read_json(state.run_path(self.run_id)/'run-status.json'))
        cfg=phase1.config_for(self.run_id); out=state.data_path(self.run_id,cfg['engagement_relative']);out.mkdir(parents=True)
        (out/'new-evidence.txt').write_text('new supplied evidence')
        with self.assertRaisesRegex(state.Blocked,'stale'): self.accepted()

    def test_A11_redacted_command(self):
        result=state.redact_argv(['tool','--password','sensitive-value','--api-key=hidden','https://user:secret@example.test'])
        self.assertNotIn('sensitive-value',str(result));self.assertNotIn('hidden',str(result));self.assertNotIn('user:secret',str(result))

    def test_A12_no_blind_retries(self):
        calls=[]
        original=phase1.execute
        def record(*a,**kw): calls.append(1); return original(*a,**kw)
        with patch('phase1.execute',side_effect=record):
            with self.assertRaises(RuntimeError): self.run_job(command=[sys.executable,'-c','raise SystemExit(7)'])
        self.assertEqual(len(calls),1)
        latest=state.read_json(phase1.job_root(self.run_id)/'latest.json')['attempt_id']
        record=state.read_json(phase1.job_root(self.run_id)/'attempts'/latest/'status.json')
        self.assertEqual(record['execution']['exit_code'],7)

    def test_A12_reuse_logging_failure(self):
        result,_=self.run_job()
        path=phase1.job_root(self.run_id)/'attempts'/result['attempt_id']; before=state.tree_hashes(path)
        original=phase1.event
        def fail(path,kind,**kw):
            if kind=='REUSE': raise OSError('injected reuse log failure')
            return original(path,kind,**kw)
        with patch('phase1.event',side_effect=fail):
            with self.assertRaisesRegex(OSError,'reuse log'): self.run_job()
        self.assertIsNone(self.accepted());self.assertEqual(before,state.tree_hashes(path))

    def test_A12_corrupt_manifest_cannot_downgrade_to_legacy(self):
        import argparse
        import review_cli
        import create_handoff
        phase1.manifest_path(self.run_id).write_text('{corrupt')
        with patch('review_cli._dispatch_streaming',side_effect=AssertionError('must not dispatch')):
            with self.assertRaises(json.JSONDecodeError):
                review_cli.cmd_run(argparse.Namespace(run_id=self.run_id,lane='00-intake-recovery'))
        with self.assertRaises(json.JSONDecodeError): run_process.mark_process(self.run_id,'00-intake-recovery','OK')
        with patch('sys.argv',['create_handoff.py','--run-id',self.run_id,'--process','02-evidence-pregather']):
            with self.assertRaises(json.JSONDecodeError): create_handoff.main()

    def test_A13_explicit_legacy_import(self):
        legacy=self.root/'legacy'; legacy.mkdir(); (legacy/'evidence.txt').write_text('preserve me')
        before=state.tree_hashes(legacy)
        run_process.init_run('imported')
        with self.assertRaises(state.Blocked): phase1.stage('imported',self.target,'fixture','goal',['Linux'],engagement_output=str(legacy))
        manifest=phase1.stage('imported',self.target,'fixture','goal',['Linux'],engagement_output=str(legacy),import_legacy=True)
        self.assertEqual(manifest['intake_config']['imports'][0]['hashes'],before)
        self.assertEqual(state.tree_hashes(legacy),before)
        self.assertTrue(Path(manifest['engagement_output']).is_relative_to(state.data_path('imported')))

    def test_A13_handoff_and_pipeline_isolation(self):
        result,_=self.run_job(); text=phase1.handoff(self.run_id)
        self.assertIn(result['attempt_id'],text)
        with self.assertRaises(ValueError): phase1.pipeline_out(self.run_id,'attempt',self.root/'scratch')
        good=phase1.job_root(self.run_id,'02-evidence-assembly')/'attempts/attempt/evidence'
        self.assertEqual(phase1.pipeline_out(self.run_id,'attempt',good),good)
        with self.assertRaisesRegex(state.Blocked,'planned'):
            phase1.pipeline_out(self.run_id,'attempt',good,reserve=True)
        self.assertFalse(good.exists())
        with self.assertRaises(ValueError): run_process.mark_process(self.run_id,'00-intake-recovery','OK')

    def test_A15_graph_and_status_consistency(self):
        self.assertEqual(job_graph.mermaid(job_graph.load_graph()),(ROOT.parent/'docs/design-parity/job-graph.mmd').read_text())
        result,_=self.run_job()
        status=state.read_json(state.run_path(self.run_id)/'run-status.json')
        lane=state.read_json(state.run_path(self.run_id)/'processes/00-intake-recovery/status.json')
        self.assertEqual(lane['status'],'OK'); self.assertEqual(lane['attempt_id'],result['attempt_id'])
        self.assertEqual(status['resume_from'],'02-evidence-pregather')
        self.assertEqual(status['phase1_status'],'OK')
        self.assertEqual(status['rerun_argv'][3],'handoff')

    def test_A15_executor_platform_boundary(self):
        path=phase1.manifest_path(self.run_id); manifest=state.read_json(path)
        manifest['intake_config']['executor_platform']='different-platform';state.atomic_json(path,manifest)
        with self.assertRaises(state.Blocked): self.run_job()

    def test_A15_recorded_resume_executes(self):
        with self.assertRaises(RuntimeError): self.run_job(command=[sys.executable,'-c','raise SystemExit(7)'])
        record=state.read_json(state.run_path(self.run_id)/'run-status.json')
        result=state.execute(record['rerun_argv'],self.root,self.logs('resume'),30,
                             env=dict(os.environ,APPSEC_RUNS_ROOT=str(state.RUNS),PYTHONDONTWRITEBYTECODE='1'))
        self.assertEqual(result['exit_code'],0)
        self.assertEqual(self.accepted()['status'],'OK')


if __name__ == '__main__':
    unittest.main(verbosity=2)
