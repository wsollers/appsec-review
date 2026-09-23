"""Bounded Linux/Dagster qualification against the live instance.

ADR-0011: runs on the POSIX host in the code location's environment
(`orchestrator/dagster/code-location.sh run -B appsec-review-process/qualify_dagster.py ...`), so it
uses the same DAGSTER_HOME/Postgres instance, run root and definitions as the jobs. It used to run
inside the retired code-server container.
"""
import argparse
import json
import os
import sys
from pathlib import Path
from execution_state import data_path, atomic_json, read_json, tree_hashes
import run_process
from phase1 import stage, accepted, job_root


def main():
    p=argparse.ArgumentParser(); p.add_argument('--qualification-run',required=True); p.add_argument('--resume-check',action='store_true')
    p.add_argument('--evidence-id',default='dagster')
    p.add_argument('--target',default=str(Path(__file__).resolve().parent.parent/'fixtures/targets/hello-autotools'),
                   help='host path of the target checkout (default: the hello-autotools fixture)')
    p.add_argument('--project',default='hello-autotools')
    p.add_argument('--platform',action='append',help='target platform (repeatable; default Linux)')
    args=p.parse_args(); out=data_path(args.qualification_run,'acceptance',args.evidence_id)
    out.mkdir(parents=True,exist_ok=True)
    sys.path.insert(0,os.environ.get('APPSEC_DEFINITIONS_DIR') or str(Path(__file__).resolve().parent.parent/'orchestrator/dagster'))
    target=str(Path(args.target).resolve(strict=True)); platforms=args.platform or ['Linux']
    from definitions import phase1_intake
    from dagster import DagsterInstance
    with DagsterInstance.get() as instance:
        if args.resume_check:
            before=read_json(out/'before-restart.json')
            after=[]
            for item in before['executions']:
                execution=instance.get_run_by_id(item['dagster_run_id'])
                if execution is None or execution.status.value != item['status']:
                    raise AssertionError('Dagster history did not survive restart')
                after.append({'dagster_run_id':execution.run_id,'status':execution.status.value})
            for item in before['accepted']:
                current=accepted(item['run_id'],fresh=False)
                if current != item['pointer']:
                    raise AssertionError('accepted evidence changed across restart')
            atomic_json(out/'after-restart.json',{'executions':after,'history_and_hashes_preserved':True})
            print(json.dumps({'restart_check':'PASS'})); return 0
        executions=[]; pointers=[]
        def engage(permissions=None):
            rid,_=run_process.get_or_create_run(None)
            stage(rid,target,args.project,'Bounded Phase 1 qualification; no builds or scanners',platforms,permissions=permissions,execution_environment='dagster-read-only-linux')
            return rid
        def dispatch(rid,force=False):
            result=phase1_intake.execute_in_process(instance=instance,raise_on_error=False,
                run_config={'resources':{'session':{'config':{'engagement_run_id':rid,'force':force}}}},
                tags={'engagement_run_id':rid,'qualification_run_id':args.qualification_run})
            record=instance.get_run_by_id(result.run_id)
            executions.append({'run_id':rid,'dagster_run_id':result.run_id,'status':record.status.value,
                               'steps':[{'event':e.event_type_value,'step':e.step_key} for e in result.all_events if e.step_key]})
            atomic_json(out/'executions.json',executions)
            return result
        first=engage(); a=dispatch(first)
        if not a.success: raise AssertionError('Dagster intake failed; see execution logs')
        pa=accepted(first,fresh=False); old=tree_hashes(job_root(first)/'attempts'/pa['attempt_id'])
        b=dispatch(first)
        if not b.success or accepted(first,fresh=False)['attempt_id'] != pa['attempt_id']:
            raise AssertionError('Dagster rerun did not reuse validated output')
        fresh=engage(); c=dispatch(fresh)
        if not c.success or accepted(fresh,fresh=False)['attempt_id'] == pa['attempt_id']:
            raise AssertionError('fresh run isolation failed')
        if tree_hashes(job_root(first)/'attempts'/pa['attempt_id']) != old:
            raise AssertionError('accepted attempt mutated')
        failure=engage(permissions=[]); d=dispatch(failure)
        if d.success or accepted(failure,fresh=False) is not None:
            raise AssertionError('pre-validation failure did not propagate')
        if any(e.step_key=='intake_work' and e.event_type_value=='STEP_START' for e in d.all_events):
            raise AssertionError('work started after failed pre-validation')
        for rid in (first,fresh): pointers.append({'run_id':rid,'pointer':accepted(rid,fresh=False)})
        atomic_json(out/'before-restart.json',{'executions':executions,'accepted':pointers,'target_runs':[first,fresh],'target':target,
                                              'failure_run':failure,'immutable_first_attempt':True})
        print(json.dumps({'dagster_qualification':'PASS','runs':[first,fresh,failure]}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
