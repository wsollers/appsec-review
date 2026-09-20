"""Actual-service build discovery and blocked full-graph qualification."""
import argparse
import json
from pathlib import Path
import sys
import uuid

from execution_state import ROOT, atomic_json, data_path, execute, read_json, tree_hashes
from launch_job import launch, graphql


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run-id',required=True)
    args=parser.parse_args()
    root=data_path(args.run_id,'qualification','build-'+uuid.uuid4().hex[:8])
    root.mkdir(parents=True)
    report={'status':'RUNNING','evidence':str(root)}
    atomic_json(root/'report.json',report)
    def command(label,argv):
        result=execute(argv,ROOT.parent,root/label,600)
        if result.get('error') or result['exit_code']!=0: raise RuntimeError(label+': '+str(result))
        return (root/label/'stdout.log').read_text(encoding='utf-8')
    docker=['docker','compose','-f','orchestrator/dagster/compose.yaml','exec','-T','code-server','python','-B']
    try:
        created=json.loads(command('create',docker+['/opt/process/run_process.py','--start']))
        run_id=created['run_id']; report['engagement_run_id']=run_id
        atomic_json(root/'report.json',report)
        command('stage',docker+['/opt/process/stage_artifacts.py','--run-id',run_id,'--project','freeciv21',
                    '--target','/targets/freeciv21','--business-goal','Bounded build discovery integration',
                    '--platform','Linux','--budget','probe','--execution-environment','dagster-read-only-linux'])
        first=launch(run_id,job='build_discovery',wait=True,timeout=600)
        atomic_json(root/'first-launch.json',first)
        assert first['status']=='SUCCESS',first
        base=data_path(run_id,'jobs','00-workflow-preparation','build_discovery')
        pointer=read_json(base/'accepted.json'); attempt=base/'attempts'/pointer['attempt_id']
        output=read_json(attempt/'output.json')
        assert output['primary_build_file']=='CMakeLists.txt'
        assert output['proposed_argv'] and output['declarations'] and output['observed_build_text']
        assert output['target_execution'] is False and output['build_status']=='NOT_EXECUTED'
        for name in ('stdout','stderr'): assert (attempt/'logs'/(name+'.log')).stat().st_size>0
        before=tree_hashes(attempt)
        second=launch(run_id,job='build_discovery',wait=True,timeout=600)
        atomic_json(root/'second-launch.json',second)
        assert second['status']=='SUCCESS'
        assert read_json(base/'accepted.json')==pointer and tree_hashes(attempt)==before
        blocked=launch(run_id,job='full_review',wait=True,timeout=600)
        atomic_json(root/'blocked-launch.json',blocked)
        assert blocked['status']=='FAILURE'
        # 02-repository-partition-discovery is no longer a blocked_op stub: it is discovery_gate's
        # validated hand-off gate (still implemented:false in the graph -- it does no analysis). With
        # no supplied partition map it records a BLOCKED attempt and an actionable hand-off under
        # data/jobs/, not a WORKER_NOT_IMPLEMENTED pre.json. The stubs downstream still do.
        gate=data_path(run_id,'jobs','02-repository-partition-discovery')
        attempt_status=read_json(gate/'attempts'/read_json(gate/'latest.json')['attempt_id']/'status.json')
        assert attempt_status['status']=='BLOCKED' and attempt_status['dagster_run_id']==blocked['dagster_run_id']
        assert 'HANDOFF_ISSUED' in attempt_status['cause']
        handoff=read_json(gate/'handoff.json')
        assert handoff['dagster_run_id']==blocked['dagster_run_id'] and handoff['expected_schema']=='repository-partition-map.schema.json'
        assert not data_path(run_id,'orchestration','dagster',blocked['dagster_run_id'],'02-repository-partition-discovery').exists()
        stubs=sorted(data_path(run_id,'orchestration','dagster',blocked['dagster_run_id']).glob('*/pre.json'))
        assert stubs and all(read_json(stub)['reason']=='WORKER_NOT_IMPLEMENTED' for stub in stubs)
        assert read_json(data_path(run_id,'workflows','engagement','status.json'))['status']=='FAILED'
        recovery=launch(run_id,job='build_discovery',wait=True,timeout=600)
        atomic_json(root/'recovery-launch.json',recovery)
        assert recovery['status']=='SUCCESS' and read_json(base/'accepted.json')==pointer
        report.update(status='PASS',checks=['Freeciv21 cited build plan','both streams','immutable reuse',
                       'full graph fails at unavailable worker','recovery reuses discovery'],
                      output=str(attempt/'output.json'),output_hashes=before,
                      resume_command=f'python -B appsec-review-process/launch_job.py --run-id {run_id} --job build_discovery --wait')
    except BaseException as exc:
        report.update(status='FAILED',error=str(exc))
        raise
    finally:
        atomic_json(root/'report.json',report)
        print(json.dumps(report,indent=2))


if __name__=='__main__': main()
