"""Qualify the real Dagster queue, multiprocess branches and branch recovery."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import sys
import time
import uuid

from execution_state import ROOT, atomic_json, data_path, execute, read_json, file_hash, tree_hashes
from launch_job import launch, find_run, graphql, TERMINAL
from qualify_phase1 import code_identity, containers, legacy_identity


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id',required=True)
    args=parser.parse_args()
    out=data_path(args.run_id,'qualification','workflow-'+uuid.uuid4().hex[:8]);out.mkdir(parents=True)
    identity=code_identity()
    # workflow-plan.json is not a Phase 1 input; record its independent contract too.
    identity['workflow_plan_sha256']=file_hash(ROOT/'workflow-plan.json')
    legacy=legacy_identity(containers('lra-ingestion-harness'))
    fixture=out/'target'; fixture.mkdir()
    for n in range(100): (fixture/f'fixture{n}.py').write_text('# Static fixture; never executed.\n')
    linux_target='/runs/'+args.run_id+'/'+str(fixture.relative_to(data_path(args.run_id).parent)).replace('\\','/')
    # relative_to(run root) begins data/.
    create="""import sys,json;sys.path.insert(0,'/opt/process');import run_process,phase1
ids=[]
for target in [sys.argv[1]]*3+['/targets/freeciv21']:
 rid=run_process.new_run_id();run_process.init_run(rid);phase1.stage(rid,target,'workflow-qualification','Bounded Dagster workflow qualification',['Linux','Windows'],execution_environment='dagster-read-only-linux');ids.append(rid)
print(json.dumps(ids))"""
    result=execute(['docker','compose','-f','orchestrator/dagster/compose.yaml','exec','-T','code-server','python','-B','-c',create,linux_target],ROOT.parent,out/'create',120)
    if result['exit_code']!=0: raise RuntimeError('fixture staging failed: '+str(out/'create'))
    a,b,c,freeciv=json.loads((out/'create/stdout.log').read_text())
    requests=[]
    for rid,request in [(a,'queue-a'),(a,'queue-a-duplicate'),(b,'queue-b')]:
        requests.append(launch(rid,launch_id=request))
    samples=[]
    deadline=time.monotonic()+600
    while True:
        statuses=[find_run(r['launch_id'],r['run_id']) for r in requests]
        samples.append({'time':time.time(),'runs':statuses})
        atomic_json(out/'queue-samples.json',samples)
        active=[(requests[i]['run_id'],s) for i,s in enumerate(statuses) if s['status'] in ('STARTING','STARTED','CANCELING')]
        assert len(active)<=2,active
        assert len({rid for rid,_ in active})==len(active),active
        if all(s['status'] in TERMINAL for s in statuses): break
        if time.monotonic()>deadline: raise TimeoutError('queue qualification timeout; requests preserved')
        time.sleep(2)
    assert all(s['status']=='SUCCESS' for s in statuses),statuses
    assert any(sum(r['status']=='STARTED' for r in s['runs'])==2 for s in samples),'did not observe concurrent engagements'
    assert any(s['runs'][1]['status']=='QUEUED' for s in samples),'same-engagement request did not queue'
    print('Queue: two independent engagements overlap; duplicate waits. PASS',flush=True)
    query='query($id:ID!){runOrError(runId:$id){__typename ... on Run {runId status startTime endTime}}}'
    timing=[graphql(query,{'id':r['dagster_run_id']})['runOrError'] for r in requests]
    assert timing[1]['startTime']>=timing[0]['endTime'],timing
    atomic_json(out/'run-timing.json',timing)
    pointers=[]
    for branch in ('scope_check','native_plan_check','discovery_handoffs'):
        base=data_path(a,'jobs','00-workflow-preparation',branch)
        p=read_json(base/'accepted.json'); status=read_json(base/'attempts'/p['attempt_id']/'status.json')
        pointers.append({'branch':branch,'pointer':p,'status':status})
    assert len({p['status']['pid'] for p in pointers})==3,'branches did not use separate processes'
    starts=[datetime.fromisoformat(p['status']['started_at']).timestamp() for p in pointers]
    ends=[datetime.fromisoformat(p['status']['ended_at']).timestamp() for p in pointers]
    assert any(starts[i]<ends[j] and starts[j]<ends[i] for i in range(3) for j in range(i)), 'no branch overlap observed'
    atomic_json(out/'branch-overlap.json',pointers)
    print('Parallel preparation: distinct worker processes and overlapping attempts. PASS',flush=True)
    obstruction=data_path(c,'jobs','00-workflow-preparation','native_plan_check','attempts')
    obstruction.parent.mkdir(parents=True);obstruction.write_text('intentional qualification write obstruction')
    failed=launch(c,launch_id='branch-failure',wait=True)
    assert failed['status']=='FAILURE',failed
    assert read_json(data_path(c,'workflows','engagement','accepted.json'))['status']!='OK'
    siblings={name:read_json(data_path(c,'jobs','00-workflow-preparation',name,'accepted.json')) for name in ('scope_check','discovery_handoffs')}
    obstruction.rename(obstruction.with_name('attempts-obstruction-preserved.txt'))
    resumed=launch(c,launch_id='branch-recovery',wait=True)
    assert resumed['status']=='SUCCESS',resumed
    for name,pointer in siblings.items():
        assert read_json(data_path(c,'jobs','00-workflow-preparation',name,'accepted.json'))==pointer
    print('Branch failure blocks join; corrected rerun reuses successful siblings. PASS',flush=True)
    native=launch(freeciv,launch_id='freeciv-workflow',wait=True)
    assert native['status']=='SUCCESS',native
    print('Freeciv21 bounded workflow: PASS',flush=True)
    after=code_identity();after['workflow_plan_sha256']=file_hash(ROOT/'workflow-plan.json')
    assert identity==after,'code changed during qualification'
    assert legacy_identity(containers('lra-ingestion-harness'))==legacy,'legacy stack changed'
    atomic_json(out/'report.json',{'status':'PASS','tested_identity':identity,'engagement_runs':[a,b,c,freeciv],
                'requests':requests,'branch_failure':failed,'branch_recovery':resumed,'freeciv':native,
                'legacy_unchanged':True,'evidence':tree_hashes(out)})
    atomic_json(data_path(args.run_id,'qualification','latest.json'),{'status':'PASS','report':str(out/'report.json'),'sha256':file_hash(out/'report.json')})
    print(json.dumps({'status':'PASS','report':str(out/'report.json')}),flush=True)


if __name__=='__main__': main()
