"""Submit the engagement workflow to Dagster; never execute work in this client."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import time
import urllib.request
import uuid

import dev_restart
from execution_state import ROOT, Blocked, Lock, atomic_json, data_path, identifier, now, read_json, run_path

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
BOUNDED_TRANSFORM_JOBS = {
    'native_memory_analysis': 'native_memory_analysis_work',
    'fuzz_target_triage': 'fuzz_target_triage_work',
    'owasp_validation_worklist': 'owasp_validation_worklist_work',
    'stig_srg_validation_worklist': 'stig_srg_validation_worklist_work',
    'deployment_hardening': 'deployment_hardening_work',
}
DEPENDENCY_JOBS = {
    'sbom_inventory': 'sbom_inventory_work',
    'sca_vulnerability_match': 'sca_vulnerability_match_work',
    'license_scan': 'license_scan_work',
    'dependency_lifecycle': 'dependency_lifecycle_work',
    'cve_reachability': 'cve_reachability_work',
}
VENDOR_EVIDENCE_JOBS = {
    'secrets_inventory': 'secrets_inventory_work',
    'iac_config_scan': 'iac_config_scan_work',
    'container_image_inventory': 'container_image_inventory_work',
    'binary_hardening': 'binary_hardening_work',
    'mobile_sast': 'mobile_sast_work',
}
CONTROL_JOBS = {
    'persona_tool_pool_dispatch':'persona_tool_pool_dispatch_work',
    'deterministic_pool_merge':'deterministic_pool_merge_work',
    'evidence_qualified_quorum':'evidence_qualified_quorum_work',
    'dynamic_rescope':'dynamic_rescope_work',
    'completeness_audit':'completeness_audit_work',
    'synthetic_hypothesis_resynthesis':'synthetic_hypothesis_resynthesis_work',
    'remediation_retest_feedback':'remediation_retest_feedback_work',
}
FINAL_PUBLICATION_JOBS = {'final_publication_gate':'final_publication_gate_work'}
ASSEMBLY_JOBS = {'full_review_input_assembly': 'full_review_input_assembly_standalone_work'}
FACTS_FILE_JOBS = {'owasp_join_report': 'owasp_join_report_standalone_work'}


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


def explain(run_id, mode='prod', force_jobs=()):
    """ADR-0024: print what a launch would do per job (REUSE / RERUN / REWIND and why) without
    submitting anything. Reads run-owned state only."""
    run_id = identifier(run_id)
    if not run_path(run_id).is_dir():
        raise Blocked('no such run: '+run_id)
    try:
        import job_executor
        item_explain = job_executor.explain_items
    except ImportError:
        item_explain = None
    return dev_restart.explain_run(run_path(run_id), read_json(ROOT/'job-graph.json'), ROOT, mode=mode,
                                   forced=force_jobs, item_explain=item_explain)


def launch(run_id, force=False, launch_id=None, wait=False, timeout=600, job=None,
           input_path=None, output_root=None, attempt_id=None, attempt_root=None, execution_root=None,
           mode='prod', force_jobs=()):
    run_id = identifier(run_id)
    if mode not in dev_restart.MODES:
        raise Blocked('unknown run mode '+repr(mode))
    force_jobs = sorted(set(force_jobs))
    if force_jobs and mode != 'dev':
        raise Blocked('--force <job> is a dev-mode restart control; in prod use --force for the whole launch')
    manifest = read_json(run_path(run_id)/'inputs/artifact-manifest.json')
    if manifest.get('orchestration_version') != 1 or manifest.get('intake_config',{}).get('executor_platform') != 'posix':
        raise Blocked('Dagster requires a POSIX-staged run (ADR-0011: create and stage on the Linux/WSL host that runs the code location); preserve Windows-staged runs.')
    request_id = identifier(launch_id or str(uuid.uuid4()))
    root = data_path(run_id, 'orchestration', 'launches', request_id)
    root.mkdir(parents=True, exist_ok=True)
    previous=read_json(root/'request.json') if (root/'request.json').exists() else None
    job=job or (previous.get('job','phase1_intake') if previous else 'engagement_workflow')
    if job not in ('engagement_workflow','phase1_intake','build_discovery','build_execution','evidence_index','critical_findings_sarif','ossf_scorecard','repository_partition_discovery','dev_project_discovery','devops_project_discovery','sre_operations_topology','build_index','build_classify','build_plan','build_resolution','build_configure','native_build','source_sast','codeql_sast','component_characterization','full_review_input_assembly','threat_model_dfd_stride','threat_model_reconciliation','synthesis_report','code_property_graph','ir_capture','ir_link','ir_facts','native_memory_analysis','fuzz_target_triage','owasp_component_routing','owasp_validation_worklist','owasp_join_report','stig_srg_validation_worklist','deployment_hardening','sbom_inventory','sca_vulnerability_match','license_scan','dependency_lifecycle','cve_reachability','secrets_inventory','iac_config_scan','container_image_inventory','binary_hardening','mobile_sast','persona_tool_pool_dispatch','deterministic_pool_merge','evidence_qualified_quorum','dynamic_rescope','completeness_audit','synthetic_hypothesis_resynthesis','remediation_retest_feedback','final_publication_gate','b13_harmless_container','full_review'): raise Blocked('unsupported Dagster job')
    bounded = job in BOUNDED_TRANSFORM_JOBS
    dependency = job in DEPENDENCY_JOBS
    vendor = job in VENDOR_EVIDENCE_JOBS
    control = job in CONTROL_JOBS
    final_publication = job in FINAL_PUBLICATION_JOBS
    assembly = job in ASSEMBLY_JOBS
    facts_file = job in FACTS_FILE_JOBS
    supplied = (input_path, output_root, attempt_id, attempt_root, execution_root)
    if bounded and not (input_path and output_root and attempt_id and not attempt_root and not execution_root):
        raise Blocked('bounded transform jobs require --input-path, --output-root and --attempt-id')
    if dependency and not (input_path and output_root and attempt_root and not attempt_id and not execution_root):
        raise Blocked('dependency jobs require --input-path, --output-root and --attempt-root')
    if vendor and not (input_path and output_root and attempt_root and execution_root and not attempt_id):
        raise Blocked('vendor evidence jobs require --input-path, --output-root, --attempt-root and --execution-root')
    if control and not (input_path and output_root and attempt_root and not attempt_id and not execution_root):
        raise Blocked('control jobs require --input-path, --output-root and --attempt-root')
    if final_publication and not (input_path and output_root and not attempt_id and not attempt_root and not execution_root):
        raise Blocked('final publication requires --input-path and --output-root')
    if assembly and any(supplied) and not (input_path and output_root and attempt_id and not attempt_root and not execution_root):
        raise Blocked('explicit full review input assembly requires --input-path, --output-root and --attempt-id')
    if facts_file and not (input_path and not output_root and not attempt_id and not attempt_root and not execution_root):
        raise Blocked('OWASP join report requires --input-path naming its dispatch facts file')
    if not bounded and not dependency and not vendor and not control and not final_publication and not assembly and not facts_file and any(supplied):
        raise Blocked('explicit lifecycle paths are only valid for config-driven jobs')
    if mode == 'dev' and job in FINAL_PUBLICATION_JOBS:
        raise Blocked('dev runs are never review deliverables; launch final publication in prod')
    resume = [sys.executable,'-B',str(Path(__file__).resolve()),
              '--run-id',run_id,'--launch-id',request_id,'--job',job,'--wait'] + (['--force'] if force else [])
    if mode == 'dev':
        resume += ['--mode','dev'] + [arg for name in force_jobs for arg in ('--force',name)]
    if bounded:
        resume += ['--input-path', input_path, '--output-root', output_root, '--attempt-id', attempt_id]
    if dependency:
        resume += ['--input-path', input_path, '--output-root', output_root, '--attempt-root', attempt_root]
    if vendor:
        resume += ['--input-path', input_path, '--output-root', output_root, '--attempt-root', attempt_root,
                   '--execution-root', execution_root]
    if control:
        resume += ['--input-path',input_path,'--output-root',output_root,'--attempt-root',attempt_root]
    if final_publication:
        resume += ['--input-path',input_path,'--output-root',output_root]
    if assembly and input_path:
        resume += ['--input-path', input_path, '--output-root', output_root, '--attempt-id', attempt_id]
    if facts_file:
        resume += ['--input-path', input_path]
    lifecycle_config = ({'input_path': input_path, 'output_root': output_root, 'attempt_id': attempt_id}
                        if bounded else {'input_path': input_path, 'output_root': output_root,
                                         'attempt_root': attempt_root} if dependency else
                        {'input_path': input_path, 'output_root': output_root, 'attempt_root': attempt_root,
                         'execution_root': execution_root} if vendor else
                        {'input_path':input_path,'output_root':output_root,'attempt_root':attempt_root} if control else
                        {'input_path':input_path,'output_root':output_root} if final_publication else
                        {'plan_path':input_path,'output_root':output_root,'attempt_id':attempt_id} if assembly and input_path else
                        {'facts_path':input_path} if facts_file else None)
    with Lock(root/'request.lock'):
        path = root/'request.json'
        if path.exists():
            record = read_json(path)
            if (record['force'] != force or record['run_id'] != run_id or
                    record.get('job','phase1_intake') != job or
                    record.get('mode','prod') != mode or record.get('force_jobs',[]) != force_jobs or
                    record.get('lifecycle_config', record.get('transform_config')) != lifecycle_config):
                raise Blocked('launch request configuration cannot change; use a new launch ID')
        else:
            record = {'run_id':run_id,'launch_id':request_id,'job':job,'force':force,'status':'PREPARED',
                      'created_at':now(),'resume_argv':resume}
            if bounded or dependency or vendor or control or final_publication or (assembly and lifecycle_config) or facts_file:
                record['lifecycle_config'] = lifecycle_config
            if mode == 'dev':
                record.update(mode='dev', evidence_grade=False, force_jobs=force_jobs)
            atomic_json(path,record)
        try:
            remote = find_run(request_id, run_id)
            if remote is None:
                if record['status'] != 'PREPARED':
                    raise Blocked('submission outcome is uncertain or history was removed; inspect Dagster before a new launch. No automatic resubmission.')
                record.update(status='SUBMITTING',updated_at=now())
                atomic_json(path,record)  # Durable intent precedes the external side effect.
                run_config = {'resources':{('session' if job=='phase1_intake' else 'workflow_settings'):{'config':{'engagement_run_id':run_id,'force':force}}}}
                if bounded:
                    run_config['ops'] = {BOUNDED_TRANSFORM_JOBS[job]: {'config': lifecycle_config}}
                if dependency:
                    run_config['ops'] = {DEPENDENCY_JOBS[job]: {'config': lifecycle_config}}
                if vendor:
                    run_config['ops'] = {VENDOR_EVIDENCE_JOBS[job]: {'config': lifecycle_config}}
                if control: run_config['ops']={CONTROL_JOBS[job]:{'config':lifecycle_config}}
                if final_publication: run_config['ops']={FINAL_PUBLICATION_JOBS[job]:{'config':lifecycle_config}}
                if assembly and lifecycle_config: run_config['ops']={ASSEMBLY_JOBS[job]:{'config':lifecycle_config}}
                if facts_file: run_config['ops']={FACTS_FILE_JOBS[job]:{'config':lifecycle_config}}
                params = {'selector':{'repositoryLocationName':'appsec_review','repositoryName':'__repository__',
                                      'jobName':job},
                          'runConfigData':run_config,
                          'executionMetadata':{'tags':[{'key':'appsec/request_id','value':request_id},
                                                       {'key':'engagement_run_id','value':run_id}]}}
                if mode == 'dev':
                    # The item executor refuses a run whose tag disagrees with its process mode.
                    params['executionMetadata']['tags'] += [
                        {'key':'appsec/run_mode','value':'dev'},
                        {'key':'appsec/force_jobs','value':','.join(force_jobs)}]
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
    parser.add_argument('--force',nargs='?',const=True,default=None,action='append',metavar='JOB',
                        help='rerun everything this launch touches; with a job id (dev mode, repeatable) '
                             'rerun only that job regardless of its inputs')
    parser.add_argument('--mode',choices=dev_restart.MODES,default=None,
                        help='default: $APPSEC_RUN_MODE, else prod. dev results are never evidence (ADR-0024)')
    parser.add_argument('--explain',action='store_true',
                        help='print REUSE/RERUN/REWIND and the cause per job; submit nothing')
    parser.add_argument('--job',choices=['engagement_workflow','phase1_intake','build_discovery','build_execution','evidence_index','critical_findings_sarif','ossf_scorecard','repository_partition_discovery','dev_project_discovery','devops_project_discovery','sre_operations_topology','build_index','build_classify','build_plan','build_resolution','build_configure','native_build','source_sast','codeql_sast','component_characterization','full_review_input_assembly','threat_model_dfd_stride','threat_model_reconciliation','synthesis_report','code_property_graph','ir_capture','ir_link','ir_facts','native_memory_analysis','fuzz_target_triage','owasp_component_routing','owasp_validation_worklist','owasp_join_report','stig_srg_validation_worklist','deployment_hardening','sbom_inventory','sca_vulnerability_match','license_scan','dependency_lifecycle','cve_reachability','secrets_inventory','iac_config_scan','container_image_inventory','binary_hardening','mobile_sast','persona_tool_pool_dispatch','deterministic_pool_merge','evidence_qualified_quorum','dynamic_rescope','completeness_audit','synthetic_hypothesis_resynthesis','remediation_retest_feedback','final_publication_gate','b13_harmless_container','full_review'],help='default: engagement_workflow; reattachment preserves the original job')
    parser.add_argument('--input-path')
    parser.add_argument('--output-root')
    parser.add_argument('--attempt-id')
    parser.add_argument('--attempt-root')
    parser.add_argument('--execution-root')
    parser.add_argument('--launch-id',help='reattach to this existing launch without resubmitting')
    parser.add_argument('--wait',action='store_true')
    parser.add_argument('--timeout',type=int,default=600)
    args = parser.parse_args(argv)
    if args.timeout <= 0: parser.error('--timeout must be positive')
    try:
        mode = args.mode or dev_restart.run_mode()
    except ValueError as exc:
        parser.error(str(exc))
    values = args.force or []
    force = any(value is True for value in values)
    force_jobs = [value for value in values if value is not True]
    if args.explain:
        try:
            print('\n'.join(explain(args.run_id, mode, force_jobs)))
            return 0
        except (Exception,KeyboardInterrupt) as exc:
            print(f'DAGSTER_EXPLAIN_FAILED: {exc}',file=sys.stderr)
            return 1
    if mode == 'dev':
        print('DEV MODE: results are not evidence and never reach a deliverable; the code location must '
              'run with APPSEC_RUN_MODE=dev (docs/dev-mode-restart.md)',file=sys.stderr)
    try:
        result = launch(args.run_id,force,args.launch_id,args.wait,args.timeout,args.job,
                        args.input_path,args.output_root,args.attempt_id,args.attempt_root,args.execution_root,
                        mode,force_jobs)
        print(json.dumps(result,indent=2))
        return 0 if result['status'] not in {'FAILURE','CANCELED','REJECTED'} else 1
    except (Exception,KeyboardInterrupt) as exc:
        print(f'DAGSTER_LAUNCH_FAILED: {exc}',file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
