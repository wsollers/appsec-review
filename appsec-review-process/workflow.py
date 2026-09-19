"""Immutable parallel preparation units. Dagster alone schedules their dependencies."""
from __future__ import annotations
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
import uuid

from execution_state import ROOT, Blocked, Lock, atomic_json, atomic_bytes, data_path, digest, execute, file_hash, identifier, now, read_json, tree_hashes, emergency
from phase1 import accepted, job_root, config_for
from job_graph import composition, load_graph

PLAN = ROOT/'workflow-plan.json'


def plan():
    value=read_json(PLAN)
    if value['branches'] != ['scope_check','native_plan_check','discovery_handoffs'] or value['retry_max_attempts'] != 1:
        raise Blocked('unsupported workflow plan')
    if value['max_concurrent_steps'] not in (1,2,3) or not 0 < value['worker_timeout_seconds'] <= 120:
        raise Blocked('invalid workflow bounds')
    expected={'workflow_intake':['workflow_config'],**{name:['workflow_intake'] for name in value['branches']},
              'workflow_publish':value['branches']}
    if value['dependencies']!=expected: raise Blocked('workflow plan and executable dependencies differ')
    return value


def root(run_id):
    return data_path(run_id,'workflows','engagement')


def intake_data(run_id, pointer):
    current=accepted(run_id,fresh=False)
    if not current or current != pointer:
        raise Blocked('upstream intake changed or is not accepted')
    return read_json(job_root(run_id)/'attempts'/identifier(pointer['attempt_id'])/'outputs/intake.json')


def branch_result(branch, data, templates):
    common={'schema':'appsec-review/preparation/1','branch':branch,'source_fingerprint':data['source_fingerprint'],
            'findings':[],'target_execution':False}
    if branch=='scope_check':
        if data['scope']['primary_selection_excludes_other_scope']:
            raise Blocked('primary build selection cannot exclude other scope')
        return {**common,'scope':data['scope'],'families':data['families'],'path_count':len(data['scope']['all_paths'])}
    if branch=='native_plan_check':
        if data['native']['build_status']!='NOT_EXECUTED' or data['native']['commands_attempted']:
            raise Blocked('preparation cannot claim target execution')
        return {**common,'native':data['native']}
    if branch=='discovery_handoffs':
        jobs=[]
        for selected in data['selected_jobs']:
            template=templates[selected['job']]
            jobs.append({'job':selected['job'],'status':'PLANNED_NOT_EXECUTED',
                         'applicability':selected['applicability'],'composition':template['composition'],
                         'inputs':template['inputs'],'output_files':template['outputs']['files'],
                         'output_root':'runs/<run_id>/data/jobs/'+selected['job']+'/<scope>/attempts/<attempt_id>',
                         'prerequisites':[] if selected['job']=='02-repository-partition-discovery' else ['02-repository-partition-discovery'],
                         'task_prompt':template.get('task_prompt'),
                         'scope_source':'accepted intake scope; refine only after partition discovery'})
        return {**common,'jobs':jobs,'next_job':'02-repository-partition-discovery'}
    raise Blocked('unknown preparation branch')


def templates_for(data):
    result={}
    for selected in data['selected_jobs']:
        template=read_json(ROOT/'registry/job-templates'/(identifier(selected['job'])+'.json'))
        composition(template)
        result[selected['job']]=template
    return result


def validate_branch(run_id, branch, pointer):
    base=data_path(run_id,'jobs','00-workflow-preparation',branch)
    latest=read_json(base/'latest.json')
    if pointer['attempt_id'] != latest['attempt_id'] or pointer['status']!='OK':
        raise Blocked('branch acceptance is not the latest successful attempt')
    attempt=data_path(run_id,'jobs','00-workflow-preparation',branch,'attempts',identifier(pointer['attempt_id']))
    if tree_hashes(attempt)!=pointer['hashes']:
        raise Blocked('branch artifacts changed')
    if read_json(attempt/'status.json')['status']!='OK':
        raise Blocked('branch did not finish')
    inputs=read_json(attempt/'inputs.json')
    expected=branch_result(branch,inputs['intake'],inputs['templates'])
    if read_json(attempt/'output.json')!=expected:
        raise Blocked('branch output failed semantic validation')
    return attempt


def run_branch(run_id, branch, pointer, dagster_id, force=False):
    if branch not in plan()['branches']: raise Blocked('unconfigured branch')
    base=data_path(run_id,'jobs','00-workflow-preparation',branch)
    with Lock(base/'job.lock'):
        data=intake_data(run_id,pointer)
        inputs={'intake':data,'templates':templates_for(data),'producer':pointer,
                'code':{name:file_hash(ROOT/name) for name in ('workflow.py','workflow-plan.json','dagster_workflow.py')},
                'validator':read_json(ROOT/'registry/job-templates/00-validation.json')['composition'],
                'coordinator':read_json(ROOT/'registry/job-templates/00-intake.json')['composition']}
        fingerprint=digest(inputs)
        if not force and (base/'accepted.json').exists():
            candidate=read_json(base/'accepted.json')
            if candidate.get('fingerprint')==fingerprint:
                try:
                    validate_branch(run_id,branch,candidate)
                    audit=data_path(run_id,'orchestration','dagster',dagster_id,branch+'-reuse.json')
                    atomic_json(audit,{'status':'OK','reused':True,'producer':candidate,'time':now()})
                    return candidate
                except (ValueError,Blocked,OSError,KeyError):
                    pass
        if (base/'latest.json').exists():
            previous=read_json(base/'latest.json')
            old=base/'attempts'/identifier(previous['attempt_id'])/'status.json'
            if old.exists() and read_json(old).get('status')=='RUNNING':
                atomic_json(old,{**read_json(old),'status':'FAILED','error':'INTERRUPTED_WORKER','ended_at':now()})
        attempt_id=uuid.uuid4().hex
        attempt=data_path(run_id,'jobs','00-workflow-preparation',branch,'attempts',attempt_id)
        attempt.mkdir(parents=True)
        status={'status':'RUNNING','branch':branch,'run_id':run_id,'attempt_id':attempt_id,
                'dagster_run_id':dagster_id,'started_at':now(),'pid':os.getpid(),'fingerprint':fingerprint}
        atomic_json(base/'accepted.json',{'status':'PENDING','attempt_id':attempt_id})
        atomic_json(base/'latest.json',{'attempt_id':attempt_id})
        try:
            atomic_json(attempt/'status.json',status)
            atomic_json(attempt/'inputs.json',inputs)
            atomic_json(attempt/'pre.json',{'status':'OK','upstream_attempt':pointer['attempt_id']})
            env={k:v for k,v in os.environ.items() if k.upper() in ('PATH','SYSTEMROOT','WINDIR','LANG','LC_ALL')}
            temporary=attempt/'tmp'; temporary.mkdir()
            env.update(PYTHONDONTWRITEBYTECODE='1',TMP=str(temporary),TEMP=str(temporary),TMPDIR=str(temporary))
            result=execute([sys.executable,'-B',str(ROOT/'workflow.py'),'worker',branch,str(attempt)],
                           attempt,attempt/'logs',plan()['worker_timeout_seconds'],env=env)
            if result.get('error') or result['exit_code']!=0: raise RuntimeError('preparation worker failed: '+json.dumps(result))
            expected=branch_result(branch,data,inputs['templates'])
            if read_json(attempt/'output.json')!=expected: raise Blocked('preparation result mismatch')
            intake_data(run_id,pointer)
            if inputs['code'] != {name:file_hash(ROOT/name) for name in inputs['code']}:
                raise Blocked('preparation code changed during work')
            atomic_json(attempt/'post.json',{'status':'OK','semantic_validation':'PASS'})
            status.update(status='OK',ended_at=now())
            atomic_json(attempt/'status.json',status)
            output={'status':'OK','branch':branch,'attempt_id':attempt_id,'fingerprint':fingerprint,
                    'upstream':pointer['fingerprint'],'hashes':tree_hashes(attempt)}
            atomic_json(base/'accepted.json',output)
            return output
        except BaseException as exc:
            try:
                status.update(status='FAILED',error=str(exc),ended_at=now())
                atomic_json(attempt/'status.json',status)
                atomic_json(base/'accepted.json',{'status':'FAILED','attempt_id':attempt_id})
            except BaseException as io: emergency(io)
            raise


def publish(run_id, dagster_id, pointer, branches):
    if {b['branch'] for b in branches}!=set(plan()['branches']) or len(branches)!=len(plan()['branches']):
        raise Blocked('all configured branches must finish exactly once')
    if accepted(run_id,fresh=True)!=pointer: raise Blocked('upstream changed before workflow publication')
    with ExitStack() as locks:
        for name in sorted(plan()['branches']):
            locks.enter_context(Lock(data_path(run_id,'jobs','00-workflow-preparation',name,'job.lock')))
        locks.enter_context(Lock(data_path(run_id,'publication.lock')))
        # Restaging or another producer can invalidate the pointer after the expensive freshness
        # check. Verify it again at the commit point, with branch publications also excluded.
        if accepted(run_id,fresh=False)!=pointer: raise Blocked('upstream changed at workflow commit')
        for branch in branches:
            if branch['upstream']!=pointer['fingerprint']: raise Blocked('mixed intake generations')
            validate_branch(run_id,branch['branch'],branch)
        current=read_json(root(run_id)/'status.json')
        if current['dagster_run_id']!=dagster_id: raise Blocked('workflow generation superseded')
        result={'status':'OK','run_id':run_id,'dagster_run_id':dagster_id,'intake':pointer,
                'branches':branches,'ended_at':now(),'next_job':'02-repository-partition-discovery',
                'downstream_execution':'PLANNED_NOT_EXECUTED'}
        atomic_json(root(run_id)/'attempts'/dagster_id/'result.json',result)
        atomic_json(root(run_id)/'status.json',result)
        atomic_json(root(run_id)/'accepted.json',result)
    return result


def inspect_status(run_id):
    current=read_json(root(run_id)/'status.json')
    result={'run_id':run_id,'status':current['status'],'dagster_run_id':current['dagster_run_id'],
            'url':'http://127.0.0.1:3000/runs/'+current['dagster_run_id'],
            'source_freshness':'checked at publication; not rechecked by this status command',
            'next_job':current.get('next_job'),'error':current.get('error')}
    if current['status']=='OK':
        try:
            pointer=read_json(root(run_id)/'accepted.json')
            if pointer!=current or accepted(run_id,fresh=False)!=pointer['intake']:
                raise Blocked('workflow acceptance or upstream intake changed')
            for branch in pointer['branches']: validate_branch(run_id,branch['branch'],branch)
        except (ValueError,Blocked,OSError,KeyError) as exc:
            result.update(status='BLOCKED',error=str(exc))
    return result


if __name__=='__main__':
    if len(sys.argv)!=4 or sys.argv[1]!='worker': raise SystemExit('expected worker BRANCH ATTEMPT')
    branch,attempt=sys.argv[2],Path(sys.argv[3])
    value=read_json(attempt/'inputs.json')
    atomic_json(attempt/'output.json',branch_result(branch,value['intake'],value['templates']))
    print('Prepared '+branch+'; no target execution.')
