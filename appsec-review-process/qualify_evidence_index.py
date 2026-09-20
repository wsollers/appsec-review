"""Live Dagster + bounded Freeciv21 indexing and MCP qualification."""
import argparse
import json
import uuid
from execution_state import ROOT, atomic_json, data_path, execute, read_json, tree_hashes
from launch_job import launch


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run-id',required=True)
    p.add_argument('--engagement-run-id',help='resume the preserved engagement after fixing a blocker')
    args=p.parse_args()
    root=data_path(args.run_id,'qualification','evidence-'+uuid.uuid4().hex[:8]);root.mkdir(parents=True)
    report={'status':'RUNNING','owner_run_id':args.run_id}
    docker=['docker','compose','-f','orchestrator/dagster/compose.yaml','exec','-T','code-server','python','-B']
    def command(label,argv):
        result=execute(argv,ROOT.parent,root/label,600)
        if result.get('error') or result['exit_code']!=0:raise RuntimeError(label+': '+str(result))
        return (root/label/'stdout.log').read_text(encoding='utf-8')
    try:
        run_id=args.engagement_run_id or json.loads(command('create',docker+['/opt/process/run_process.py','--start']))['run_id']
        report['engagement_run_id']=run_id
        report['resume_command']=f'python -B appsec-review-process/qualify_evidence_index.py --run-id {args.run_id} --engagement-run-id {run_id}'
        atomic_json(root/'report.json',report)
        if not args.engagement_run_id:
            command('stage',docker+['/opt/process/stage_artifacts.py','--run-id',run_id,'--project','freeciv21',
                      '--target','/targets/freeciv21','--business-goal','Bounded evidence retrieval qualification',
                      '--platform','Linux','--budget','probe','--execution-environment','dagster-read-only-linux'])
        first=launch(run_id,job='evidence_index',wait=True,timeout=900)
        atomic_json(root/'first-launch.json',first)
        assert first['status']=='SUCCESS',first
        base=data_path(run_id,'jobs','02-evidence-index','whole')
        pointer=read_json(base/'accepted.json');attempt=base/'attempts'/pointer['attempt_id']
        manifest=read_json(attempt/'manifest.json');report['manifest']=manifest
        assert manifest['files']>1000 and manifest['chunks']>1000
        # V15: the worker's identity changed to add descriptive metrics; re-derive them here from
        # index.sqlite and objects/ rather than trusting the published member.
        from evidence_store import check_metrics
        metrics=check_metrics(attempt,True)
        assert metrics['snapshot']['files']==manifest['files'] and metrics['overall']['bytes']==manifest['snapshot_bytes']
        assert sum(row['files'] for row in metrics['by_scope'])==sum(row['files'] for row in metrics['by_language'])==manifest['files']
        report['metrics_sha256']=manifest['metrics_sha256']
        assert (attempt/'logs/stdout.log').stat().st_size and (attempt/'logs/stderr.log').stat().st_size
        before=tree_hashes(attempt)
        second=launch(run_id,job='evidence_index',wait=True,timeout=900)
        atomic_json(root/'second-launch.json',second)
        assert second['status']=='SUCCESS' and pointer==read_json(base/'accepted.json') and before==tree_hashes(attempt)
        assert check_metrics(attempt,True)==metrics
        search=json.loads(command('search',docker+['/opt/process/evidence_store.py','search','--run-id',run_id,'--text','CMAKE_EXPORT_COMPILE_COMMANDS']))
        assert search['results'] and all('sha256' in r and r['start_line']>=1 for r in search['results'])
        result=search['results'][0]
        citation=json.loads(command('read',docker+['/opt/process/evidence_store.py','read','--run-id',run_id,
                        '--path',result['path'],'--start',str(result['start_line']),'--limit','50']))
        assert citation['results'][0]['sha256']==result['sha256']
        command('similar',docker+['/opt/process/evidence_store.py','similar','--run-id',run_id,'--path','source/CMakeLists.txt'])
        command('mcp',docker+['/opt/process/tooling/probe_stdio.py','--out',f'/runs/{run_id}/data/tooling/evidence-mcp-'+uuid.uuid4().hex,
                '--mode','mcp','--timeout','180','--call-json',json.dumps({'name':'evidence_search','arguments':{'text':'Freeciv21','limit':2}}),
                '--','python','-B','/opt/process/evidence_mcp.py','--run-id',run_id])
        report.update(status='PASS',attempt_id=pointer['attempt_id'],dagster_runs=[first['dagster_run_id'],second['dagster_run_id']],
                      checks=['live Dagster success','immutable reuse','separate streams','FTS citations','snapshot read',
                              'ssdeep similarity query','MCP initialize/tools/list/tools/call',
                              'metrics re-derived from index.sqlite and objects'],
                      manifest_path=str(attempt/'manifest.json'))
    except BaseException as exc:
        report.update(status='FAILED',error=str(exc));raise
    finally:
        atomic_json(root/'report.json',report)
        print(json.dumps({'report':str(root/'report.json'), 'status':report['status'],
                          'engagement_run_id':report.get('engagement_run_id'),'resume_command':report.get('resume_command')},indent=2))


if __name__=='__main__':main()
