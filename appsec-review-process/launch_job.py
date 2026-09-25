"""Submit the engagement workflow to Dagster; never execute work in this client."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import time
import urllib.request
import uuid

from execution_state import Blocked, Lock, atomic_json, data_path, identifier, now, read_json, run_path

ENDPOINT = 'http://127.0.0.1:3000/graphql'
FIND = '''query($tags:[ExecutionTag!]!) {
  runsOrError(filter:{tags:$tags},limit:2) { __typename
    ... on Runs { results { runId status } } ... on PythonError { message }
  }
}'''
LAUNCH = '''mutation($params:ExecutionParams!) {
  launchRun(executionParams:$params) { __typename
    ... on LaunchRunSuccess { run { runId status } }
    ... on RunConfigValidationInvalid { errors { message } }
    ... on PythonError { message }
  }
}'''
TERMINAL = {'SUCCESS','FAILURE','CANCELED'}


def graphql(query, variables):
    request = urllib.request.Request(ENDPOINT, data=json.dumps({'query':query,'variables':variables}).encode(),
                                     headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request, timeout=20) as response:
        value = json.load(response)
    if value.get('errors') or not value.get('data'):
        raise RuntimeError('Dagster GraphQL error: '+json.dumps(value))
    return value['data']


def find_run(request_id, run_id):
    result = graphql(FIND, {'tags':[{'key':'appsec/request_id','value':request_id},
                                   {'key':'engagement_run_id','value':run_id}]})['runsOrError']
    if result['__typename'] != 'Runs':
        raise RuntimeError('Cannot query Dagster history: '+json.dumps(result))
    if len(result['results']) > 1:
        raise Blocked('multiple Dagster runs match this launch request; inspect history')
    return next(iter(result['results']), None)


def launch(run_id, force=False, launch_id=None, wait=False, timeout=600, job=None):
    run_id = identifier(run_id)
    manifest = read_json(run_path(run_id)/'inputs/artifact-manifest.json')
    if manifest.get('orchestration_version') != 1 or manifest.get('intake_config',{}).get('executor_platform') != 'posix':
        raise Blocked('Dagster requires a POSIX-staged run (ADR-0011: create and stage on the Linux/WSL host that runs the code location); preserve Windows-staged runs.')
    request_id = identifier(launch_id or str(uuid.uuid4()))
    root = data_path(run_id, 'orchestration', 'launches', request_id)
    root.mkdir(parents=True, exist_ok=True)
    previous=read_json(root/'request.json') if (root/'request.json').exists() else None
    job=job or (previous.get('job','phase1_intake') if previous else 'engagement_workflow')
    if job not in ('engagement_workflow','phase1_intake','build_discovery','build_execution','evidence_index','critical_findings_sarif','ossf_scorecard','repository_partition_discovery','dev_project_discovery','devops_project_discovery','sre_operations_topology','build_index','full_review'): raise Blocked('unsupported Dagster job')
    resume = [sys.executable,'-B',str(Path(__file__).resolve()),
              '--run-id',run_id,'--launch-id',request_id,'--job',job,'--wait'] + (['--force'] if force else [])
    with Lock(root/'request.lock'):
        path = root/'request.json'
        if path.exists():
            record = read_json(path)
            if record['force'] != force or record['run_id'] != run_id or record.get('job','phase1_intake') != job:
                raise Blocked('launch request configuration cannot change; use a new launch ID')
        else:
            record = {'run_id':run_id,'launch_id':request_id,'job':job,'force':force,'status':'PREPARED',
                      'created_at':now(),'resume_argv':resume}
            atomic_json(path,record)
        try:
            remote = find_run(request_id, run_id)
            if remote is None:
                if record['status'] != 'PREPARED':
                    raise Blocked('submission outcome is uncertain or history was removed; inspect Dagster before a new launch. No automatic resubmission.')
                record.update(status='SUBMITTING',updated_at=now())
                atomic_json(path,record)  # Durable intent precedes the external side effect.
                params = {'selector':{'repositoryLocationName':'appsec_review','repositoryName':'__repository__',
                                      'jobName':job},
                          'runConfigData':{'resources':{('session' if job=='phase1_intake' else 'workflow_settings'):{'config':{'engagement_run_id':run_id,'force':force}}}},
                          'executionMetadata':{'tags':[{'key':'appsec/request_id','value':request_id},
                                                       {'key':'engagement_run_id','value':run_id}]}}
                result = graphql(LAUNCH, {'params':params})['launchRun']
                if result['__typename'] != 'LaunchRunSuccess':
                    record.update(status='REJECTED',response=result)
                    atomic_json(path,record)
                    raise Blocked('Dagster rejected launch: '+json.dumps(result))
                remote = result['run']
            started = time.monotonic()
            while True:
                record.update(status=remote['status'],dagster_run_id=remote['runId'],updated_at=now(),
                              url='http://127.0.0.1:3000/runs/'+remote['runId'])
                record.pop('last_client_error',None)
                atomic_json(path,record)
                if not wait or remote['status'] in TERMINAL:
                    return record
                if time.monotonic()-started >= timeout:
                    raise TimeoutError('wait timed out; Dagster execution continues. Resume monitoring with resume_argv.')
                time.sleep(2)
                remote = find_run(request_id,run_id)
                if remote is None:
                    raise Blocked('Dagster run disappeared; no automatic resubmission')
        except BaseException as exc:
            record.update(last_client_error=type(exc).__name__+': '+str(exc),updated_at=now())
            atomic_json(path,record)
            print(json.dumps({'request':str(path),'status':record['status'],'resume_argv':resume}),file=sys.stderr)
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id',required=True)
    parser.add_argument('--force',action='store_true')
    parser.add_argument('--job',choices=['engagement_workflow','phase1_intake','build_discovery','build_execution','evidence_index','critical_findings_sarif','ossf_scorecard','repository_partition_discovery','dev_project_discovery','devops_project_discovery','sre_operations_topology','build_index','full_review'],help='default: engagement_workflow; reattachment preserves the original job')
    parser.add_argument('--launch-id',help='reattach to this existing launch without resubmitting')
    parser.add_argument('--wait',action='store_true')
    parser.add_argument('--timeout',type=int,default=600)
    args = parser.parse_args(argv)
    if args.timeout <= 0: parser.error('--timeout must be positive')
    try:
        result = launch(args.run_id,args.force,args.launch_id,args.wait,args.timeout,args.job)
        print(json.dumps(result,indent=2))
        return 0 if result['status'] not in {'FAILURE','CANCELED','REJECTED'} else 1
    except (Exception,KeyboardInterrupt) as exc:
        print(f'DAGSTER_LAUNCH_FAILED: {exc}',file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
