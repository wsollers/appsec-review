"""Dagster multiprocessing graph. Each stateful unit owns its lock in one process."""
from pathlib import Path
from dagster import (DagsterRunStatus, DefaultSensorStatus, Failure, Field, MetadataValue, RetryPolicy, In, Out, Output,
                     failure_hook, job, multiprocess_executor, resource, run_failure_sensor, run_status_sensor)
from pipeline_log_dagster import op
from execution_state import Blocked, Lock, atomic_json, data_path, emergency, now, read_json, run_path
from phase1 import Session, config_for
import workflow
import build_execution as build_execution_worker
import build_classify as build_classify_worker
import build_plan as build_plan_worker
import build_resolution as build_resolution_worker
import build_configure as build_configure_worker
import native_build as native_build_worker
import source_sast as source_sast_worker
import codeql_sast as codeql_sast_worker
import reachability_engine_jobs
import treesitter_ast_job
import code_index_job
import lsp_xref_job
import evidence_index_derived
import language_census
import component_characterization as component_characterization_worker
import threat_model_core as threat_model_worker
import threat_model_reconciliation as threat_model_reconciliation_worker
import full_review_input_assembly as full_review_input_assembly_worker
import evidence_assembly as evidence_assembly_worker
import evidence_assembly_input
import evidence_assembly_runtime
import synthesis_report_worker
import bounded_transform_orchestration as bounded_transforms
import dependency_orchestration as dependency_jobs
import vendor_evidence_orchestration as vendor_evidence_jobs
import automatic_evidence_inputs
import analysis_feature_lifecycle
import control_lane_orchestration as control_lane_jobs
import build_index as build_index_worker
import b13_harmless as b13_harmless_worker
import discovery_gate
import automatic_discovery
import evidence_store
import critical_findings_sarif as critical_findings_sarif_worker
import ossf_scorecard as ossf_scorecard_worker
import owasp_dispatch
import owasp_join_publisher as owasp_join_publisher_worker
import owasp_workbench_lifecycle
import owasp_universe_jobs
import tunables
import ir_evidence as ir_evidence_worker
import joern_cpg as joern_cpg_worker
import api_collection_intelligence_ingest as api_collection_intelligence_worker
import binary_cfg as binary_cfg_worker
import binary_intelligence_ingest as binary_intelligence_worker
import binary_triage as binary_triage_worker
import debug_symbol_index as debug_symbol_index_worker
import doc_intelligence_ingest as doc_intelligence_worker
import native_sast as native_sast_worker
import operations_doc_ingest as operations_doc_worker
import standards_source_ingest as standards_source_worker
import standards_lifecycle
import claim_ledger
import hypothesis_discovery
import attack_chain_composition
import attack_chain_refutation
import poc_fix_worker
import persona_tool_pool_lifecycle
import control_feature_lifecycle
import test_coverage_ingest as test_coverage_worker
import test_execution as test_execution_worker
import test_intelligence_ingest as test_intelligence_worker
import test_result_ingest as test_result_worker
import remediation_proposal as remediation_proposal_worker
import claim_review_lifecycle as claim_review_worker
import claim_reviewer_pool
import resource_pools
import json
import os
import urllib.error
import urllib.request


# B15 resource pools. Pool ids, limits and the derivation live in resource_pools.py; this module
# only names, per op, the worker kind and permission kinds that decide its pool. An op that holds
# no pool records the explicit unassigned state, so no op is silently unlimited.
CPU_POOL=resource_pools.derive_pool('deterministic_python',(),memory_heavy=False)
MEMORY_POOL=resource_pools.derive_pool('deterministic_python',(),memory_heavy=True)
GATE_POOL=resource_pools.derive_pool('supplied_human_decision',(),memory_heavy=False)
PERSONA_POOL=resource_pools.derive_pool('persona',(),memory_heavy=False)
NETWORK_POOL=resource_pools.derive_pool('deterministic_python',('fixed-network-destination',),memory_heavy=False)
DOCKER_POOL=resource_pools.derive_pool('pinned_container',('target-execution',),memory_heavy=False)
OFFLINE_DOCKER_POOL=resource_pools.derive_pool('pinned_container',(),memory_heavy=False)
# Coordination ops reserve, check and publish under short locks; they must never wait on a work pool.
COORDINATION=resource_pools.unassigned('coordination_only')
NOT_IMPLEMENTED=resource_pools.unassigned('worker_not_implemented')


@resource(config_schema={'engagement_run_id':str,'force':bool})
def workflow_settings(context):
    return context.resource_config


def notify_discord(run_id, message):
    """Best-effort outbound alert for a workflow FAILED transition, added 2026-09-19 in direct
    response to the repo owner's "if this job fails it should alert me and terminate" ask.
    Configured via the DISCORD_WEBHOOK_URL environment variable on hal5000 -- if it is unset,
    this is a silent no-op and the prior disk-only status.json signal is all that happens, exactly
    as before this change. A notification failure must never mask or replace the real workflow
    failure it's trying to report, so any error here is swallowed (recorded via emergency()), never
    re-raised."""
    webhook = os.environ.get('DISCORD_WEBHOOK_URL')
    if not webhook:
        return
    payload = json.dumps({'content': 'AppSec Review workflow FAILED -- run ' + run_id + ': ' + message}).encode('utf-8')
    request = urllib.request.Request(webhook, data=payload, headers={'Content-Type': 'application/json'})
    try:
        urllib.request.urlopen(request, timeout=10)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        emergency(exc)


def fail_workflow(run_id, dagster_id, message):
    with Lock(data_path(run_id,'publication.lock')):
        path=workflow.root(run_id)/'status.json'
        if not path.exists(): return
        current=read_json(path)
        if current['dagster_run_id']!=dagster_id: return
        value={**current,'status':'FAILED','error':message,'ended_at':now()}
        atomic_json(workflow.root(run_id)/'attempts'/dagster_id/'failure.json',value)
        atomic_json(path,value)
        atomic_json(workflow.root(run_id)/'accepted.json',{'status':'FAILED','dagster_run_id':dagster_id})
        _mark_run_status_failed(run_id, dagster_id, message)
    notify_discord(run_id, message)


def _mark_run_status_failed(run_id, dagster_id, message):
    """run-status.json/.md are the operator's view; only phase1 wrote them, so a failed full_review still
    read READY / "Validated reuse; work not invoked" (run 20261001T032047Z-fd64eb). Best effort: the
    workflow status written above is the authority."""
    try:
        root=run_path(run_id)
        path=root/'run-status.json'
        data=read_json(path) if path.exists() else {}
        data.update(status='FAILED',workflow_status='FAILED',workflow_dagster_run_id=dagster_id,
                    last_message=message,updated_at=now())
        atomic_json(path,data)
        (root/'run-status.md').write_text(
            f"# AppSec run {run_id}\n\nStatus: FAILED\nWorkflow: Dagster run {dagster_id}\n"
            f"Intake: {data.get('phase1_status','')}\n\n{message}\n\n"
            "Failure detail: data/workflows/engagement/attempts/" + dagster_id + "/failure.json\n",
            encoding='utf-8')
    except (OSError, ValueError) as exc:
        emergency(exc)


@failure_hook(required_resource_keys={'workflow_settings'})
def workflow_failed(context):
    try:
        fail_workflow(context.resources.workflow_settings['engagement_run_id'],context.run_id,
                      context.op.name+': '+str(context.op_exception))
    except BaseException as exc:
        emergency(exc)
        raise


@op(required_resource_keys={'workflow_settings'},tags=COORDINATION)
def workflow_config(context):
    settings=context.resources.workflow_settings
    run_id=settings['engagement_run_id']
    config_for(run_id)
    if context.dagster_run.tags.get('engagement_run_id')!=run_id:
        raise Failure('engagement_run_id run tag must match config so the Dagster queue can serialize this engagement')
    with Lock(data_path(run_id,'publication.lock')):
        path=workflow.root(run_id)/'status.json'
        if path.exists():
            previous=read_json(path)
            old=context.instance.get_run_by_id(previous['dagster_run_id'])
            if old and not old.is_finished and old.run_id!=context.run_id:
                raise Failure('another workflow owns this engagement; wait for it to finish or cancel it')
            if previous['status']=='RUNNING':
                atomic_json(workflow.root(run_id)/'attempts'/previous['dagster_run_id']/'recovery.json',
                            {'status':'FAILED','cause':'INTERRUPTED_WORKFLOW','recovered_by':context.run_id,'time':now()})
        value={'status':'RUNNING','run_id':run_id,'dagster_run_id':context.run_id,'started_at':now()}
        atomic_json(workflow.root(run_id)/'accepted.json',{'status':'PENDING','dagster_run_id':context.run_id})
        atomic_json(path,value)
        atomic_json(workflow.root(run_id)/'attempts'/context.run_id/'config.json',
                    {'settings':settings,'plan':workflow.plan(),'staged':config_for(run_id)})
    return dict(settings)


@op(pool=CPU_POOL)
def workflow_intake(context, configured: dict):
    # Never share a live Session/OS lock between Dagster subprocesses.
    with Session(configured['engagement_run_id'],force=configured['force'],dagster_id=context.run_id,
                 observer=lambda stream,count:context.log.info('%s: %s bytes persisted',stream,count)) as session:
        session.configure(); session.prepare(); session.work()
        pointer=session.publish()
    return {**configured,'intake':pointer}


def branch_op(name, op_name=None):
    @op(name=op_name or name,pool=CPU_POOL)
    def prepared(context, intake: dict):
        pointer=workflow.run_branch(intake['engagement_run_id'],name,intake['intake'],context.run_id,intake['force'])
        path=data_path(intake['engagement_run_id'],'jobs','00-workflow-preparation',name,'attempts',pointer['attempt_id'])
        context.add_output_metadata({'output':MetadataValue.path(str(path/'output.json')),
                                     'stdout':MetadataValue.path(str(path/'logs/stdout.log')),
                                     'stderr':MetadataValue.path(str(path/'logs/stderr.log'))})
        return pointer
    return prepared


scope_check=branch_op('scope_check')
native_plan_check=branch_op('native_plan_check')
discovery_handoffs=branch_op('discovery_handoffs')


@op(tags=COORDINATION)
def workflow_publish(context, intake: dict, scope: dict, native: dict, handoffs: dict):
    result=workflow.publish(intake['engagement_run_id'],context.run_id,intake['intake'],[scope,native,handoffs])
    context.add_output_metadata({'workflow':MetadataValue.path(str(workflow.root(result['run_id'])/'accepted.json'))})
    return result


@job(resource_defs={'workflow_settings':workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent':workflow.plan()['max_concurrent_steps']}),
     hooks={workflow_failed},op_retry_policy=RetryPolicy(max_retries=0))
def engagement_workflow():
    intake=workflow_intake(workflow_config())
    workflow_publish(intake,scope_check(intake),native_plan_check(intake),discovery_handoffs(intake))


build_discovery_work=branch_op('build_discovery','build_discovery_work')


@op(tags=COORDINATION)
def build_discovery_publish(context, intake: dict, discovered: dict):
    run_id=intake['engagement_run_id']
    if discovered['upstream']!=intake['intake']['fingerprint']:
        raise Failure('mixed intake generations at build discovery publication')
    from phase1 import accepted
    if accepted(run_id,fresh=True)!=intake['intake']:
        raise Failure('source changed before build discovery publication')
    with Lock(data_path(run_id,'jobs','00-workflow-preparation','build_discovery','job.lock')):
        with Lock(data_path(run_id,'publication.lock')):
            workflow.validate_branch(run_id,'build_discovery',discovered)
            if accepted(run_id,fresh=False)!=intake['intake']:
                raise Failure('intake changed at build discovery publication')
            if read_json(workflow.root(run_id)/'status.json')['dagster_run_id']!=context.run_id:
                raise Failure('build discovery generation superseded')
            value={'status':'OK','run_id':run_id,'dagster_run_id':context.run_id,'intake':intake['intake'],
                   'branches':[discovered],'ended_at':now(),'next_job':'02-repository-partition-discovery',
                   'scope':'build discovery only; build not executed'}
            atomic_json(workflow.root(run_id)/'attempts'/context.run_id/'result.json',value)
            atomic_json(workflow.root(run_id)/'status.json',value)
            atomic_json(workflow.root(run_id)/'accepted.json',value)
    return value


@job(resource_defs={'workflow_settings':workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent':3}),
     hooks={workflow_failed},op_retry_policy=RetryPolicy(max_retries=0))
def build_discovery():
    intake=workflow_intake(workflow_config())
    build_discovery_publish(intake,build_discovery_work(intake))


@op(required_resource_keys={'workflow_settings'},tags=COORDINATION)
def build_execution_config(context):
    # Deliberately does NOT touch workflow.root(run_id)/status.json. That shared file's
    # RUNNING/OK lifecycle is owned by whichever of engagement_workflow/build_discovery last
    # published to it; build_execution is a separate, independently launchable job and must not
    # contend for or reset that ownership. It still enforces the same run-tag/config check.
    settings=context.resources.workflow_settings
    run_id=settings['engagement_run_id']
    config_for(run_id)
    if context.dagster_run.tags.get('engagement_run_id')!=run_id:
        raise Failure('engagement_run_id run tag must match config so the Dagster queue can serialize this engagement')
    return dict(settings)


@op(pool=DOCKER_POOL)
def build_execution_work(context, intake: dict):
    # This is the one op in the graph allowed to execute target-adjacent commands (a bounded
    # CMake configure inside audit-buildenv-cpp). See build_execution.py's module docstring for
    # why it owns its own immutable-attempt lifecycle instead of reusing workflow.run_branch.
    result=build_execution_worker.run(intake['engagement_run_id'],context.run_id,intake['force'])
    path=build_execution_worker.root(intake['engagement_run_id'])/'attempts'/result['attempt_id']
    context.add_output_metadata({'output':MetadataValue.path(str(path/'output.json')),
                                 'stdout':MetadataValue.path(str(path/'logs/stdout.log')),
                                 'stderr':MetadataValue.path(str(path/'logs/stderr.log'))})
    return result


@job(resource_defs={'workflow_settings':workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent':2}),
     hooks={workflow_failed},op_retry_policy=RetryPolicy(max_retries=0))
def build_execution():
    # Depends on build_discovery having already published an accepted branch for this run
    # (checked on disk by build_execution.discovered_plan, not by chaining Dagster ops together,
    # since build_discovery is its own independently launched job, not always run in this graph).
    intake=workflow_intake(build_execution_config())
    build_execution_work(intake)


@op(pool=MEMORY_POOL)
def evidence_index_work(context, intake: dict, discovered: dict):
    if discovered['upstream'] != intake['intake']['fingerprint']:
        raise Failure('mixed intake generations at evidence indexing')
    result = evidence_store.run(intake['engagement_run_id'], context.run_id, intake['force'])
    path = evidence_store.root(intake['engagement_run_id']) / 'attempts' / result['attempt_id']
    context.add_output_metadata({name: MetadataValue.path(str(path / relative)) for name, relative in
        [('manifest', 'manifest.json'), ('index', 'index.sqlite'), ('ssdeep', 'ssdeep.csv'),
         ('stdout', 'logs/stdout.log'), ('stderr', 'logs/stderr.log')]})
    return result


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 2}),
     op_retry_policy=RetryPolicy(max_retries=0))
def evidence_index():
    # Independent source branch; does not wait for native builds or reset aggregate status.
    intake = workflow_intake(build_execution_config())
    evidence_index_work(intake, build_discovery_work(intake))


@op(pool=CPU_POOL)
def critical_findings_sarif_work(context, configured: dict):
    result = critical_findings_sarif_worker.run(configured['engagement_run_id'], context.run_id,
                                                configured['force'])
    path = critical_findings_sarif_worker.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
    context.add_output_metadata({
        'sarif': MetadataValue.path(str(path / 'outputs/critical-findings.sarif')),
        'manifest': MetadataValue.path(str(path / 'manifest.json')),
        'stdout': MetadataValue.path(str(path / 'logs/stdout.log')),
        'stderr': MetadataValue.path(str(path / 'logs/stderr.log'))})
    return result


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def critical_findings_sarif():
    # This post-verification transform has a fixed run-owned input and does not mutate the
    # engagement preparation workflow's aggregate status.
    critical_findings_sarif_work(build_execution_config())


def run_ossf_scorecard(context, configured: dict):
    result = ossf_scorecard_worker.run(configured['engagement_run_id'], context.run_id,
                                       configured['force'])
    path = ossf_scorecard_worker.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
    context.add_output_metadata({
        'results': MetadataValue.path(str(path / 'outputs/scorecard-results.json')),
        'summary': MetadataValue.path(str(path / 'outputs/summary.md')),
        'manifest': MetadataValue.path(str(path / 'manifest.json')),
        'stdout': MetadataValue.path(str(path / 'logs/stdout.log')),
        'stderr': MetadataValue.path(str(path / 'logs/stderr.log'))})
    return result


@op(pool=NETWORK_POOL)
def ossf_scorecard_work(context, configured: dict):
    return run_ossf_scorecard(context, configured)


@op(name='job_02_ossf_scorecard', ins={'configured': In(dict), 'upstream': In(list)}, pool=NETWORK_POOL)
def ossf_scorecard_lifecycle_work(context, configured: dict, upstream: list):
    return run_ossf_scorecard(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def ossf_scorecard():
    # Published-result ingestion only. The worker enforces explicit network authorization and
    # records a SKIPPED receipt when no fixed project list is staged.
    ossf_scorecard_work(build_execution_config())


def blocked_op(name, node):
    @op(name='job_'+name.replace('-','_'),ins={'configured':In(dict),'upstream':In(list)},tags=NOT_IMPLEMENTED,
        description='BLOCKED: worker not implemented. Dependencies and failure are explicit.')
    def unavailable(context, configured, upstream):
        path=data_path(configured['engagement_run_id'],'orchestration','dagster',context.run_id,name)
        value={'status':'BLOCKED','job':name,'reason':'WORKER_NOT_IMPLEMENTED',
               'definition':node,'time':now(),'dependency_count':len(upstream),
               'resume_prerequisite':'Implement and qualify this worker before retrying.',
               'resume_command':'python -B appsec-review-process/launch_job.py --run-id '+configured['engagement_run_id']+' --job full_review --wait'}
        atomic_json(path/'pre.json',value)
        raise Failure(name+': WORKER_NOT_IMPLEMENTED; no downstream acceptance published',
                      metadata={'blocker':MetadataValue.path(str(path/'pre.json'))})
    return unavailable


def run_build_configure(context, configured):
    result = build_configure_worker.run(configured['engagement_run_id'], context.run_id,
                                        configured['force'])
    path = build_configure_worker.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
    context.add_output_metadata({'output': MetadataValue.path(str(path / build_configure_worker.RESULT)),
                                 'envelope': MetadataValue.path(str(path / 'result.json')),
                                 'attempt_id': result['attempt_id']})
    return result


@op(name='job_02_build_configure',ins={'configured':In(dict),'upstream':In(list)},pool=DOCKER_POOL)
def build_configure_work(context, configured, upstream):
    return run_build_configure(context, configured)


@op(pool=DOCKER_POOL)
def build_configure_standalone_work(context, configured):
    return run_build_configure(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def build_configure():
    build_configure_standalone_work(build_execution_config())


def run_native_build(context, configured):
    result = native_build_worker.run(configured['engagement_run_id'], context.run_id,
                                     configured['force'])
    path = native_build_worker.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
    context.add_output_metadata({'output': MetadataValue.path(str(path / native_build_worker.RESULT)),
                                 'envelope': MetadataValue.path(str(path / 'result.json')),
                                 'attempt_id': result['attempt_id']})
    return result


@op(name='job_02_native_build',ins={'configured':In(dict),'upstream':In(list)},pool=DOCKER_POOL)
def native_build_work(context, configured, upstream):
    """P42: never raises in the full review. A crash or BLOCKED returns NOT_PUBLISHED (as lane 14 does) for the
    SBOM's optional edge; native_build_published re-raises it for the required consumers."""
    try:
        return run_native_build(context, configured)
    except Exception as exc:
        context.log.warning(f'02-native-build did not publish ({type(exc).__name__}: {exc}); '
                            '02-sbom-inventory records the gap, required consumers are held')
        return {'job_id': '02-native-build', 'status': 'NOT_PUBLISHED', 'error': f'{type(exc).__name__}: {exc}'[:500]}


@op(name='job_02_native_build_published',ins={'native_build':In(dict)},tags=COORDINATION)
def native_build_published(context, native_build):
    if native_build.get('status')=='NOT_PUBLISHED':
        raise Failure('02-native-build did not publish: '+native_build['error'])
    return native_build


@op(pool=DOCKER_POOL)
def native_build_standalone_work(context, configured):
    return run_native_build(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def native_build():
    native_build_standalone_work(build_execution_config())


def run_source_sast(context, configured):
    result = source_sast_worker.run(configured['engagement_run_id'], context.run_id,
                                    configured['force'])
    path = source_sast_worker.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
    context.add_output_metadata({'output': MetadataValue.path(str(path / source_sast_worker.RESULT)),
                                 'envelope': MetadataValue.path(str(path / 'result.json')),
                                 'attempt_id': result['attempt_id']})
    return result


@op(name='job_02_source_sast',ins={'configured':In(dict),'upstream':In(list)},pool=DOCKER_POOL)
def source_sast_work(context, configured, upstream):
    return run_source_sast(context, configured)


@op(pool=DOCKER_POOL)
def source_sast_standalone_work(context, configured):
    return run_source_sast(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def source_sast():
    source_sast_standalone_work(build_execution_config())


def run_codeql_language(context, configured, language):
    # ADR-0023: one graph node per CodeQL language (02-codeql-<lang>), parallel in the Docker pool.
    result = codeql_sast_worker.run(configured['engagement_run_id'], context.run_id, language, configured['force'])
    path = codeql_sast_worker.root(configured['engagement_run_id'], language) / 'attempts' / result['attempt_id']
    context.add_output_metadata({'output': MetadataValue.path(str(path / codeql_sast_worker.RESULT)),
                                 'envelope': MetadataValue.path(str(path / 'result.json')),
                                 'attempt_id': result['attempt_id']})
    return result


def codeql_language_op(language):
    @op(name='job_' + codeql_sast_worker.job_id(language).replace('-', '_'),
        ins={'configured': In(dict), 'upstream': In(list)}, pool=DOCKER_POOL)
    def codeql_language_work(context, configured, upstream):
        return run_codeql_language(context, configured, language)
    return codeql_language_work


def codeql_language_standalone_op(language):
    @op(name='codeql_' + language + '_standalone_work', ins={'configured': In(dict)}, pool=DOCKER_POOL)
    def codeql_language_standalone_work(context, configured):
        return run_codeql_language(context, configured, language)
    return codeql_language_standalone_work


CODEQL_LANGUAGE_OPS = {language: codeql_language_op(language) for language in codeql_sast_worker.LANGUAGES}
CODEQL_STANDALONE_OPS = {language: codeql_language_standalone_op(language)
                         for language in codeql_sast_worker.LANGUAGES}


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 3}),
     op_retry_policy=RetryPolicy(max_retries=0))
def codeql_sast():
    # Every 02-codeql-<lang> node in parallel (bounded by the executor and the Docker pool).
    configured = build_execution_config()
    for language in codeql_sast_worker.LANGUAGES:
        CODEQL_STANDALONE_OPS[language](configured)


def run_common_python_worker(context, configured, worker):
    result = worker.run(configured['engagement_run_id'], context.run_id, configured['force'])
    attempt = worker.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
    context.add_output_metadata({
        'output': MetadataValue.path(str(attempt / worker.RESULT)),
        'envelope': MetadataValue.path(str(attempt / 'result.json')),
        'attempt_id': result['attempt_id']})
    return result


@op(name='job_01_component_characterization', ins={'configured': In(dict), 'upstream': In(list)}, pool=PERSONA_POOL)
def component_characterization_work(context, configured, upstream):
    return run_common_python_worker(context, configured, component_characterization_worker)


@op(pool=PERSONA_POOL)
def component_characterization_standalone_work(context, configured):
    return run_common_python_worker(context, configured, component_characterization_worker)


@job(resource_defs={'workflow_settings': workflow_settings}, executor_def=multiprocess_executor.configured({'max_concurrent': 1}), op_retry_policy=RetryPolicy(max_retries=0))
def component_characterization():
    component_characterization_standalone_work(build_execution_config())


@op(name='job_03_threat_model_dfd_stride', ins={'configured': In(dict), 'upstream': In(list)}, pool=PERSONA_POOL)
def threat_model_dfd_stride_work(context, configured, upstream):
    return run_common_python_worker(context, configured, threat_model_worker)


@op(pool=PERSONA_POOL)
def threat_model_dfd_stride_standalone_work(context, configured):
    return run_common_python_worker(context, configured, threat_model_worker)


@job(resource_defs={'workflow_settings': workflow_settings}, executor_def=multiprocess_executor.configured({'max_concurrent': 1}), op_retry_policy=RetryPolicy(max_retries=0))
def threat_model_dfd_stride():
    threat_model_dfd_stride_standalone_work(build_execution_config())


@op(name='job_03_threat_model_reconciliation', ins={'configured': In(dict), 'upstream': In(list)}, pool=CPU_POOL)
def threat_model_reconciliation_work(context, configured, upstream):
    return run_common_python_worker(context, configured, threat_model_reconciliation_worker)


@op(pool=CPU_POOL)
def threat_model_reconciliation_standalone_work(context, configured):
    return run_common_python_worker(context, configured, threat_model_reconciliation_worker)


@job(resource_defs={'workflow_settings': workflow_settings}, executor_def=multiprocess_executor.configured({'max_concurrent': 1}), op_retry_policy=RetryPolicy(max_retries=0))
def threat_model_reconciliation():
    threat_model_reconciliation_standalone_work(build_execution_config())


FULL_REVIEW_INPUT_CONFIG = {
    'plan_path': Field(str, is_required=False),
    'component_pointer': Field(str, is_required=False),
    'output_root': Field(str, is_required=False),
    'attempt_id': Field(str, is_required=False),
    'dispatch': Field(bool, is_required=False, default_value=True),
    'dispatch_root': Field(str, is_required=False),
}


def run_full_review_input_assembly(context, configured):
    started = now()
    root_path = run_path(configured['engagement_run_id'])
    attempt_id = context.op_config.get('attempt_id') or context.run_id
    output_root = Path(context.op_config.get('output_root') or
                       root_path / 'data/jobs/02-full-review-input-assembly')
    plan_value = context.op_config.get('plan_path')
    component_value = context.op_config.get('component_pointer')
    if plan_value and component_value:
        raise Failure('full review input assembly accepts a plan or component pointer, not both')
    if plan_value:
        plan_path = Path(plan_value)
    else:
        component_pointer = Path(component_value) if component_value else (
            root_path / 'data/jobs/01-component-characterization/accepted.json')
        plan_path = output_root / 'plans' / (attempt_id + '.json')
        plan_path.parent.mkdir(parents=True, exist_ok=True)
        full_review_input_assembly_worker.derive_plan(
            component_pointer, root_path, plan_path, run_id=configured['engagement_run_id'],
            generated_at=started)
    result = full_review_input_assembly_worker.assemble(
        plan_path, root_path, output_root, attempt_id=attempt_id,
        started_at=started, finished_at=now())
    attempt = output_root / 'attempts' / attempt_id
    # The standalone job can still request the legacy aggregate dispatcher.  In full_review each
    # planned feature owns its own Dagster node and accepted/skip receipt, so dispatching here would
    # execute analyzers outside their lifecycle nodes and create duplicate generations.
    if getattr(context, 'job_name', None) != 'full_review' and context.op_config.get('dispatch', True):
        dispatch_root = Path(context.op_config.get('dispatch_root') or
                             root_path / 'data/jobs/02-full-review-input-dispatch')
        dispatched = full_review_input_assembly_worker.dispatch(
            output_root, root_path, dispatch_root, attempt_id=attempt_id,
            dagster_run_id=context.run_id, started_at=started, finished_at=now())
        context.add_output_metadata({
            'dispatch': MetadataValue.path(str(dispatch_root / 'attempts' / attempt_id /
                                                'full-review-dispatch.json')),
            'dispatched': len(dispatched['results']), 'skipped_na': len(dispatched['skipped'])})
    context.add_output_metadata({'output': MetadataValue.path(str(attempt / full_review_input_assembly_worker.RESULT)),
        'envelope': MetadataValue.path(str(attempt / 'result.json')), 'attempt_id': attempt_id})
    return result


@op(name='job_02_full_review_input_assembly', ins={'configured': In(dict), 'upstream': In(list)}, config_schema=FULL_REVIEW_INPUT_CONFIG, pool=CPU_POOL)
def full_review_input_assembly_work(context, configured, upstream):
    return run_full_review_input_assembly(context, configured)


@op(config_schema=FULL_REVIEW_INPUT_CONFIG, pool=CPU_POOL)
def full_review_input_assembly_standalone_work(context, configured):
    return run_full_review_input_assembly(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings}, executor_def=multiprocess_executor.configured({'max_concurrent': 1}), op_retry_policy=RetryPolicy(max_retries=0))
def full_review_input_assembly():
    full_review_input_assembly_standalone_work(build_execution_config())


def run_synthesis_report(context, configured):
    run_root = run_path(configured['engagement_run_id'])
    result = synthesis_report_worker.run(run_root, configured['engagement_run_id'], context.run_id,
                                         configured['force'])
    attempt = synthesis_report_worker.root(run_root) / 'attempts' / result['attempt_id']
    context.add_output_metadata({'output': MetadataValue.path(str(attempt / 'report.json')),
        'html': MetadataValue.path(str(attempt / 'presentation/report.html')),
        'pdf': MetadataValue.path(str(attempt / 'presentation/report.pdf')),
        'latex': MetadataValue.path(str(attempt / 'presentation/report.tex')),
        'envelope': MetadataValue.path(str(attempt / 'result.json')), 'attempt_id': result['attempt_id']})
    return result


@op(name='job_10_synthesis_report', ins={'configured': In(dict), 'upstream': In(list)}, pool=CPU_POOL)
def synthesis_report_work(context, configured, upstream):
    return run_synthesis_report(context, configured)


@op(pool=CPU_POOL)
def synthesis_report_standalone_work(context, configured):
    return run_synthesis_report(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings}, executor_def=multiprocess_executor.configured({'max_concurrent': 1}), op_retry_policy=RetryPolicy(max_retries=0))
def synthesis_report():
    synthesis_report_standalone_work(build_execution_config())


def run_code_property_graph(context, configured):
    result = joern_cpg_worker.run(configured['engagement_run_id'], context.run_id,
                                  configured['force'])
    attempt = joern_cpg_worker.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
    context.add_output_metadata({
        'output': MetadataValue.path(str(attempt / joern_cpg_worker.RESULT)),
        'envelope': MetadataValue.path(str(attempt / 'result.json')),
        'attempt_id': result['attempt_id']})
    return result


@op(pool=OFFLINE_DOCKER_POOL)
def code_property_graph_work(context, configured, _intake):
    return run_code_property_graph(context, configured)


@op(pool=OFFLINE_DOCKER_POOL)
def code_property_graph_standalone_work(context, configured):
    return run_code_property_graph(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def code_property_graph():
    code_property_graph_standalone_work(build_execution_config())


def run_automatic_common_worker(context, configured, worker):
    """Run a worker whose complete input is derived from accepted run-owned state."""
    result = worker.run(configured['engagement_run_id'], context.run_id, configured['force'])
    base = worker.root(configured['engagement_run_id']) if hasattr(worker, 'root') else data_path(
        configured['engagement_run_id'], 'jobs', worker.JOB)
    attempt = base / 'attempts' / result['attempt_id']
    context.add_output_metadata({
        'output': MetadataValue.path(str(attempt / getattr(worker, 'RESULT', 'result.json'))),
        'envelope': MetadataValue.path(str(attempt / 'result.json')),
        'attempt_id': result['attempt_id']})
    return result


def automatic_common_lifecycle_op(job_id, worker, pool):
    @op(name='job_' + job_id.replace('-', '_'),
        ins={'configured': In(dict), 'upstream': In(list)}, pool=pool)
    def automatic_worker(context, configured, upstream):
        return run_automatic_common_worker(context, configured, worker)
    return automatic_worker


api_collection_intelligence_work = automatic_common_lifecycle_op(
    '02-api-collection-intelligence-ingest', api_collection_intelligence_worker, CPU_POOL)
doc_intelligence_work = automatic_common_lifecycle_op(
    '02-doc-intelligence-ingest', doc_intelligence_worker, OFFLINE_DOCKER_POOL)  # gap 7: PDF/DOCX conversion containers
test_intelligence_work = automatic_common_lifecycle_op(
    '02-test-intelligence-ingest', test_intelligence_worker, CPU_POOL)
operations_doc_work = automatic_common_lifecycle_op(
    '02-operations-doc-ingest', operations_doc_worker, CPU_POOL)
standards_source_work = automatic_common_lifecycle_op(
    '02-standards-source-ingest', standards_source_worker, CPU_POOL)
debug_symbol_index_work = automatic_common_lifecycle_op(
    '02-debug-symbol-index', debug_symbol_index_worker, OFFLINE_DOCKER_POOL)
binary_triage_work = automatic_common_lifecycle_op(
    '02-binary-triage', binary_triage_worker, OFFLINE_DOCKER_POOL)
binary_cfg_work = automatic_common_lifecycle_op(
    '02-binary-cfg', binary_cfg_worker, OFFLINE_DOCKER_POOL)
binary_intelligence_work = automatic_common_lifecycle_op(
    '02-binary-intelligence-ingest', binary_intelligence_worker, CPU_POOL)
test_execution_lifecycle_work = automatic_common_lifecycle_op(
    '02-test-execution', test_execution_worker, OFFLINE_DOCKER_POOL)
test_result_lifecycle_work = automatic_common_lifecycle_op(
    '02-test-result-ingest', test_result_worker, CPU_POOL)
test_coverage_lifecycle_work = automatic_common_lifecycle_op(
    '02-test-coverage-ingest', test_coverage_worker, CPU_POOL)
remediation_proposal_lifecycle_work = automatic_common_lifecycle_op(
    '11-remediation-proposal', remediation_proposal_worker, CPU_POOL)


def claim_review_lifecycle_op(stage):
    @op(name='job_' + stage.replace('-', '_'),
        ins={'configured': In(dict), 'upstream': In(list)}, pool=PERSONA_POOL)
    def review_stage(context, configured, upstream):
        pool_result = claim_reviewer_pool.run(
            configured['engagement_run_id'], context.run_id, stage,
            configured.get('force', False))
        result = claim_review_worker.run(
            configured['engagement_run_id'], context.run_id, stage,
            configured.get('force', False))
        attempt = claim_review_worker.root(
            configured['engagement_run_id'], stage) / 'attempts' / result['attempt_id']
        context.add_output_metadata({
            'output': MetadataValue.path(str(attempt / claim_review_worker.core.STAGES[stage][4])),
            'envelope': MetadataValue.path(str(attempt / 'result.json')),
            'reviewer_pool_attempt_id': pool_result['attempt_id'],
            'attempt_id': result['attempt_id']})
        return result
    return review_stage


red_team_lifecycle_work = claim_review_lifecycle_op('07-red-team-adversarial')
blue_team_lifecycle_work = claim_review_lifecycle_op('08-blue-team-refutation')
verification_lifecycle_work = claim_review_lifecycle_op('09-independent-verification')
scoring_lifecycle_work = claim_review_lifecycle_op('12-scoring-prioritization')


def analysis_feature_lifecycle_op(job_id):
    @op(name='job_' + job_id.replace('-', '_'),
        ins={'configured': In(dict), 'upstream': In(list)}, pool=CPU_POOL)
    def analysis_stage(context, configured, upstream):
        result = analysis_feature_lifecycle.run(
            configured['engagement_run_id'], context.run_id, job_id,
            configured.get('force', False))
        attempt = data_path(configured['engagement_run_id'], 'jobs', job_id,
                            'attempts', result['attempt_id'])
        context.add_output_metadata({
            'output': MetadataValue.path(str(attempt / analysis_feature_lifecycle.JOBS[job_id][1])),
            'envelope': MetadataValue.path(str(attempt / 'result.json')),
            'attempt_id': result['attempt_id']})
        return result
    return analysis_stage


native_memory_lifecycle_work = analysis_feature_lifecycle_op('05-native-memory')
def reachability_engine_op(engine, pool):
    # ADR-0023: 06-reachability-codeql / 06-reachability-ir publish the shared engine table.
    @op(name='job_' + reachability_engine_jobs.job_id(engine).replace('-', '_'),
        ins={'configured': In(dict), 'upstream': In(list)}, pool=pool)
    def reachability_engine_work(context, configured, upstream):
        run_id = configured['engagement_run_id']
        result = reachability_engine_jobs.run(run_id, context.run_id, engine, configured.get('force', False))
        attempt = reachability_engine_jobs.root(run_id, engine) / 'attempts' / result['attempt_id']
        context.add_output_metadata({'output': MetadataValue.path(str(attempt / reachability_engine_jobs.RESULT)),
                                     'envelope': MetadataValue.path(str(attempt / 'result.json')),
                                     'attempt_id': result['attempt_id']})
        return result
    return reachability_engine_work


def structural_index_op(job_id, worker, result_name, pool):
    # Brief U0: 02-treesitter-ast (pinned container) and 02-code-index (deterministic Python).
    @op(name='job_' + job_id.replace('-', '_'), ins={'configured': In(dict), 'upstream': In(list)}, pool=pool)
    def structural_index_work(context, configured, upstream):
        run_id = configured['engagement_run_id']
        result = worker.run(run_id, context.run_id, configured.get('force', False))
        attempt = worker.root(run_id) / 'attempts' / result['attempt_id']
        context.add_output_metadata({'output': MetadataValue.path(str(attempt / result_name)),
                                     'envelope': MetadataValue.path(str(attempt / 'result.json')),
                                     'attempt_id': result['attempt_id']})
        return result
    return structural_index_work


treesitter_ast_lifecycle_work = structural_index_op('02-treesitter-ast', treesitter_ast_job, treesitter_ast_job.RESULT,
                                                    OFFLINE_DOCKER_POOL)
code_index_lifecycle_work = structural_index_op('02-code-index', code_index_job, code_index_job.RESULT, CPU_POOL)
lsp_xref_lifecycle_work = structural_index_op('02-lsp-xref', lsp_xref_job, lsp_xref_job.RESULT, OFFLINE_DOCKER_POOL)
language_census_lifecycle_work = structural_index_op('02-language-census', language_census, language_census.RESULT,
                                                     CPU_POOL)
evidence_index_derived_lifecycle_work = structural_index_op('02-evidence-index-derived', evidence_index_derived,
                                                            evidence_index_derived.RESULT, CPU_POOL)
reachability_codeql_lifecycle_work = reachability_engine_op('codeql', DOCKER_POOL)
reachability_ir_lifecycle_work = reachability_engine_op('ir', CPU_POOL)
cve_reachability_lifecycle_work = analysis_feature_lifecycle_op('06-cve-reachability')
fuzz_triage_lifecycle_work = analysis_feature_lifecycle_op('13-fuzz-target-triage')


def standards_lifecycle_op(job_id, pool=CPU_POOL):
    @op(name='job_' + job_id.replace('-', '_'),
        ins={'configured': In(dict), 'upstream': In(list)}, pool=pool)
    def standards_stage(context, configured, upstream):
        result = standards_lifecycle.run(
            configured['engagement_run_id'], context.run_id, job_id,
            configured.get('force', False))
        context.add_output_metadata({
            'output': MetadataValue.path(str(data_path(
                configured['engagement_run_id'], 'jobs', job_id))),
            'attempt_id': result['attempt_id']})
        return result
    return standards_stage


owasp_worklist_lifecycle_work = standards_lifecycle_op('04-owasp-validation-worklist')
owasp_join_lifecycle_work = standards_lifecycle_op('04-asvs-masvs', PERSONA_POOL)
stig_worklist_lifecycle_work = standards_lifecycle_op('15-stig-srg-validation-worklist')
deployment_lifecycle_work = standards_lifecycle_op('15-deployment-hardening')


def claim_ledger_lifecycle_op():
    @op(name='job_claim_ledger_routing',
        ins={'configured': In(dict), 'upstream': In(list)}, pool=CPU_POOL)
    def claim_ledger_stage(context, configured, upstream):
        result = claim_ledger.run(
            configured['engagement_run_id'], context.run_id,
            configured.get('force', False))
        attempt = claim_ledger.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
        context.add_output_metadata({
            'output': MetadataValue.path(str(attempt / claim_ledger.LEDGER)),
            'envelope': MetadataValue.path(str(attempt / 'result.json')),
            'attempt_id': result['attempt_id']})
        return result
    return claim_ledger_stage


claim_ledger_lifecycle_work = claim_ledger_lifecycle_op()


def hypothesis_discovery_lifecycle_op():
    @op(name='job_07_hypothesis_discovery',
        ins={'configured': In(dict), 'upstream': In(list)}, pool=PERSONA_POOL)
    def hypothesis_discovery_stage(context, configured, upstream):
        result = hypothesis_discovery.run(
            configured['engagement_run_id'], context.run_id,
            configured.get('force', False))
        attempt = hypothesis_discovery.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
        context.add_output_metadata({
            'output': MetadataValue.path(str(attempt / hypothesis_discovery.RESULT)),
            'envelope': MetadataValue.path(str(attempt / 'result.json')),
            'attempt_id': result['attempt_id']})
        return result
    return hypothesis_discovery_stage


hypothesis_discovery_lifecycle_work = hypothesis_discovery_lifecycle_op()


def owasp_universe_lifecycle_op(job_id, pool):
    """ADR-0034: 04-owasp-candidate-search / -participation / -universe. owasp_universe_jobs imports
    the job modules only when a job runs. The universe raises
    Blocked over budget (nothing downstream runs); an accepted one is projected into the applicability
    request the worklist and T03-T06 read."""
    @op(name='job_' + job_id.replace('-', '_'), ins={'configured': In(dict), 'upstream': In(list)}, pool=pool)
    def owasp_universe_stage(context, configured, upstream):
        run_id, force = configured['engagement_run_id'], configured.get('force', False)
        if job_id == owasp_universe_jobs.UNIVERSE:
            result = owasp_universe_jobs.run_universe(run_id, context.run_id, force)
            context.add_output_metadata({'attempt_id': result['attempt_id'], 'reused': bool(result.get('reused')),
                                         'planned_validator_calls': result.get('planned_validator_calls', 0),
                                         'projection_attempt_id': result['projection']['attempt_id']})
            return result
        if job_id == owasp_universe_jobs.PARTICIPATION:
            result = owasp_universe_jobs.run_participation(run_id, context.run_id, force)
            output = 'owasp-participation.json'
        else:
            result = owasp_universe_jobs.run(job_id, run_id, context.run_id, force)
            output = owasp_universe_jobs.JOBS[job_id][1]
        attempt = owasp_universe_jobs.root(run_id, job_id) / 'attempts' / result['attempt_id']
        context.add_output_metadata({'output': MetadataValue.path(str(attempt / output)),
                                     'envelope': MetadataValue.path(str(attempt / 'result.json')),
                                     'attempt_id': result['attempt_id']})
        return result
    return owasp_universe_stage


owasp_candidate_search_lifecycle_work = owasp_universe_lifecycle_op('04-owasp-candidate-search', CPU_POOL)
owasp_participation_lifecycle_work = owasp_universe_lifecycle_op('04-owasp-participation', PERSONA_POOL)
owasp_universe_lifecycle_work = owasp_universe_lifecycle_op('04-owasp-universe', CPU_POOL)


def attack_chain_lifecycle_op(job_id, worker):
    """Lane 14 (ADR-0016) is an optional input of 10-synthesis-report: its own lifecycle records a
    FAILED/BLOCKED terminal, and this op then returns instead of raising so the report is never held."""
    @op(name='job_' + job_id.replace('-', '_'),
        ins={'configured': In(dict), 'upstream': In(list)}, pool=PERSONA_POOL)
    def attack_chain_stage(context, configured, upstream):
        try:
            result = worker.run(configured['engagement_run_id'], context.run_id, configured.get('force', False))
        except Exception as exc:
            context.log.warning(f'{job_id} did not publish ({type(exc).__name__}: {exc}); '
                                '10-synthesis-report records the lane as a gap')
            return {'job_id': job_id, 'status': 'NOT_PUBLISHED', 'error': f'{type(exc).__name__}: {exc}'[:500]}
        attempt = worker.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
        context.add_output_metadata({
            'output': MetadataValue.path(str(attempt / worker.RESULT)),
            'envelope': MetadataValue.path(str(attempt / 'result.json')),
            'attempt_id': result['attempt_id']})
        return result
    return attack_chain_stage


attack_chain_composition_lifecycle_work = attack_chain_lifecycle_op('14-attack-chain-composition', attack_chain_composition)
attack_chain_refutation_lifecycle_work = attack_chain_lifecycle_op('14-attack-chain-refutation', attack_chain_refutation)
# Lane 12b (brief F) is an optional input of 10 as well: a failed or blocked pool never holds the report.
poc_fix_lifecycle_work = attack_chain_lifecycle_op('12b-poc-and-fix', poc_fix_worker)


@op(name='job_persona_tool_pool_dispatch_lifecycle',
    ins={'configured': In(dict), 'upstream': In(list)}, pool=PERSONA_POOL)
def persona_tool_pool_lifecycle_work(context, configured, upstream):
    result = persona_tool_pool_lifecycle.run(
        configured['engagement_run_id'], context.run_id,
        configured.get('force', False))
    context.add_output_metadata({
        'output': MetadataValue.path(str(data_path(
            configured['engagement_run_id'], 'jobs', 'persona-tool-pool-dispatch', 'whole'))),
        'attempt_id': result['attempt_id']})
    return result


def control_feature_lifecycle_op(graph_job_id, worker_job_id=None):
    worker_job_id = worker_job_id or graph_job_id
    @op(name='job_' + graph_job_id.replace('-', '_') + '_lifecycle',
        ins={'configured': In(dict), 'upstream': In(list)}, pool=CPU_POOL)
    def control_stage(context, configured, upstream):
        result = control_feature_lifecycle.run(
            configured['engagement_run_id'], context.run_id, worker_job_id,
            configured.get('force', False))
        context.add_output_metadata({
            'output': MetadataValue.path(str(data_path(
                configured['engagement_run_id'], 'jobs', worker_job_id))),
            'attempt_id': result['attempt_id']})
        return result
    return control_stage


deterministic_pool_merge_lifecycle_work = control_feature_lifecycle_op('deterministic-pool-merge')
evidence_qualified_quorum_lifecycle_work = control_feature_lifecycle_op('evidence-qualified-quorum')
dynamic_rescope_lifecycle_work = control_feature_lifecycle_op('dynamic-rescope')
completeness_audit_lifecycle_work = control_feature_lifecycle_op('completeness-audit')
synthetic_resynthesis_lifecycle_work = control_feature_lifecycle_op('synthetic-hypothesis-resynthesis')
remediation_retest_feedback_lifecycle_work = control_feature_lifecycle_op('remediation-retest-feedback')
final_publication_preparation_lifecycle_work = control_feature_lifecycle_op(
    'final-publication-gate', 'final-publication-preparation')


@op(name='job_02_evidence_assembly', ins={'configured': In(dict), 'upstream': In(list)},
    pool=PERSONA_POOL)
def evidence_assembly_lifecycle_work(context, configured, upstream):
    run_id = configured['engagement_run_id']
    prepared = evidence_assembly_runtime.prepare(
        run_id, context.run_id, configured.get('force', False))
    run_root = run_path(run_id).absolute()
    supply_root = (evidence_assembly_worker.root(run_id) / 'supplies' /
                   prepared.expected_spec['attempt_id']).absolute()
    arguments = prepared.assembly_arguments()
    if not supply_root.exists():
        evidence_assembly_input.stage_supply(
            run_root, supply_root, run_id=run_id,
            source_snapshot_sha256=prepared.source_snapshot_sha256, **arguments)
    result = evidence_assembly_worker.run(
        run_id, context.run_id, supply_root=supply_root,
        source_snapshot_sha256=prepared.source_snapshot_sha256,
        force=configured.get('force', False), **arguments)
    attempt = evidence_assembly_worker.root(run_id) / 'attempts' / result['attempt_id']
    context.add_output_metadata({
        'output': MetadataValue.path(str(attempt / evidence_assembly_worker.RESULT)),
        'envelope': MetadataValue.path(str(attempt / 'result.json')),
        'supply': MetadataValue.path(str(supply_root)),
        'attempt_id': result['attempt_id']})
    return result


@op(name='job_02_native_sast', ins={'configured': In(dict), 'upstream': In(list)},
    pool=OFFLINE_DOCKER_POOL)
def native_sast_lifecycle_work(context, configured, upstream):
    run_id = configured['engagement_run_id']
    base = native_build_worker.root(run_id)
    pointer = read_json(base / 'accepted.json')
    result = native_sast_worker.run(run_id, context.run_id, native_build_root=base,
        native_build_fingerprint=pointer['fingerprint'], force=configured['force'])
    attempt = native_sast_worker.root(run_id) / 'attempts' / result['attempt_id']
    context.add_output_metadata({'output': MetadataValue.path(str(attempt / native_sast_worker.RESULT)),
        'envelope': MetadataValue.path(str(attempt / 'result.json')), 'attempt_id': result['attempt_id']})
    return result


def run_ir_evidence(context, configured, job_id):
    result = ir_evidence_worker.run_job(
        configured['engagement_run_id'], context.run_id, job_id, configured['force'])
    attempt = data_path(configured['engagement_run_id'], 'jobs', job_id,
                        'attempts', result['attempt_id'])
    context.add_output_metadata({
        'output': MetadataValue.path(str(attempt)),
        'envelope': MetadataValue.path(str(attempt / 'result.json')),
        'attempt_id': result['attempt_id']})
    return result


@op(pool=OFFLINE_DOCKER_POOL)
def ir_capture_work(context, configured, _native_build):
    return run_ir_evidence(context, configured, '02-ir-capture')


@op(pool=OFFLINE_DOCKER_POOL)
def ir_capture_standalone_work(context, configured):
    return run_ir_evidence(context, configured, '02-ir-capture')


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def ir_capture():
    ir_capture_standalone_work(build_execution_config())


@op(pool=OFFLINE_DOCKER_POOL)
def ir_link_work(context, configured, _capture):
    return run_ir_evidence(context, configured, '02-ir-link')


@op(pool=OFFLINE_DOCKER_POOL)
def ir_link_standalone_work(context, configured):
    return run_ir_evidence(context, configured, '02-ir-link')


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def ir_link():
    ir_link_standalone_work(build_execution_config())


@op(pool=OFFLINE_DOCKER_POOL)
def ir_facts_work(context, configured, _linked):
    return run_ir_evidence(context, configured, '02-ir-facts')


@op(pool=OFFLINE_DOCKER_POOL)
def ir_facts_standalone_work(context, configured):
    return run_ir_evidence(context, configured, '02-ir-facts')


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def ir_facts():
    ir_facts_standalone_work(build_execution_config())


BOUNDED_TRANSFORM_CONFIG = {'input_path': str, 'output_root': str, 'attempt_id': str}


def run_bounded_transform(context, configured, job_id):
    result = bounded_transforms.execute(
        job_id=job_id, run_id=configured['engagement_run_id'],
        input_path=context.op_config['input_path'], output_root=context.op_config['output_root'],
        attempt_id=context.op_config['attempt_id'])
    path = data_path(configured['engagement_run_id'], 'jobs', job_id,
                     'attempts', result['attempt_id'])
    context.add_output_metadata({
        'output': MetadataValue.path(str(path)),
        'envelope': MetadataValue.path(str(path / 'result.json')),
        'attempt_id': result['attempt_id']})
    return result


@op(config_schema=BOUNDED_TRANSFORM_CONFIG, pool=CPU_POOL)
def native_memory_analysis_work(context, configured):
    return run_bounded_transform(context, configured, '05-native-memory')


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def native_memory_analysis():
    native_memory_analysis_work(build_execution_config())


@op(config_schema=BOUNDED_TRANSFORM_CONFIG, pool=CPU_POOL)
def fuzz_target_triage_work(context, configured):
    return run_bounded_transform(context, configured, '13-fuzz-target-triage')


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def fuzz_target_triage():
    fuzz_target_triage_work(build_execution_config())


@op(config_schema=BOUNDED_TRANSFORM_CONFIG, pool=CPU_POOL)
def owasp_validation_worklist_work(context, configured):
    return run_bounded_transform(context, configured, '04-owasp-validation-worklist')


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def owasp_validation_worklist():
    owasp_validation_worklist_work(build_execution_config())


def owasp_validator_max_parallel():
    """ADR-0034: the 04-owasp-validator-cell tunable; run_dispatch caps it at pool_persona_llm_slots."""
    return tunables.value('04-owasp-validator-cell', 'max_parallel')


def run_owasp_validator_handoffs(context, configured):
    """T03 -> routing -> T04 -> T05 -> T06 from accepted run evidence (deterministic, no model)."""
    result = owasp_workbench_lifecycle.prepare_handoffs(
        configured['engagement_run_id'], context.run_id, configured.get('force', False))
    context.add_output_metadata({name: pointer.get('attempt_id') or '' for name, pointer in result.items()})
    return result['handoffs']


def run_owasp_validator_dispatch(context, configured):
    """T10: dispatch every static validator cell under the join's own facts, wait for all, and
    publish the accepted accounting (an EMPTY one when T06 produced no handoff)."""
    result = owasp_workbench_lifecycle.run_dispatch(
        configured['engagement_run_id'], context.run_id, configured.get('force', False),
        max_parallel=owasp_validator_max_parallel())
    context.add_output_metadata({
        'accounting': MetadataValue.path(str(owasp_dispatch._base(configured['engagement_run_id'])
                                             / 'attempts' / result['attempt_id'] / owasp_dispatch.ACCOUNTING_ARTIFACT)),
        'attempt_id': result['attempt_id'], 'reused': bool(result.get('reused'))})
    return result


@op(name='job_04_owasp_validator_handoffs', ins={'configured': In(dict), 'upstream': In(list)}, pool=CPU_POOL)
def owasp_validator_handoffs_work(context, configured, upstream):
    return run_owasp_validator_handoffs(context, configured)


@op(name='job_04_owasp_validator_dispatch', ins={'configured': In(dict), 'upstream': In(list)}, pool=PERSONA_POOL)
def owasp_validator_dispatch_work(context, configured, upstream):
    return run_owasp_validator_dispatch(context, configured)


OWASP_JOIN_CONFIG = {'facts_path': str}


def run_owasp_join_report(context, configured):
    raw = read_json(Path(context.op_config['facts_path']))
    required = {'registry_dir', 'allowed_models', 'invoker_id', 'source_snapshot_sha256', 'registry_ceiling'}
    if not isinstance(raw, dict) or set(raw) != required:
        raise Failure('OWASP join facts file must have the closed qualified shape')
    facts = owasp_dispatch.DispatchFacts(Path(raw['registry_dir']), tuple(raw['allowed_models']),
        raw['invoker_id'], raw['source_snapshot_sha256'], raw['registry_ceiling'])
    result = owasp_join_publisher_worker.run(configured['engagement_run_id'], context.run_id, facts,
                                             configured['force'])
    attempt = owasp_join_publisher_worker.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
    context.add_output_metadata({
        'matrix_manifest': MetadataValue.path(str(attempt / owasp_join_publisher_worker.MATRIX_MANIFEST)),
        'gaps': MetadataValue.path(str(attempt / 'owasp-coverage-gaps.json')),
        'routes': MetadataValue.path(str(attempt / 'owasp-candidate-promotion-routes.json')),
        'attempt_id': result['attempt_id']})
    return result


@op(name='job_04_asvs_masvs', ins={'configured': In(dict), 'upstream': In(list)}, config_schema=OWASP_JOIN_CONFIG, pool=CPU_POOL)
def owasp_join_report_work(context, configured, upstream):
    return run_owasp_join_report(context, configured)


@op(config_schema=OWASP_JOIN_CONFIG, pool=CPU_POOL)
def owasp_join_report_standalone_work(context, configured):
    return run_owasp_join_report(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings}, executor_def=multiprocess_executor.configured({'max_concurrent': 1}), op_retry_policy=RetryPolicy(max_retries=0))
def owasp_join_report():
    owasp_join_report_standalone_work(build_execution_config())


@op(config_schema=BOUNDED_TRANSFORM_CONFIG, pool=CPU_POOL)
def stig_srg_validation_worklist_work(context, configured):
    return run_bounded_transform(context, configured, '15-stig-srg-validation-worklist')


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def stig_srg_validation_worklist():
    stig_srg_validation_worklist_work(build_execution_config())


@op(config_schema=BOUNDED_TRANSFORM_CONFIG, pool=CPU_POOL)
def deployment_hardening_work(context, configured):
    return run_bounded_transform(context, configured, '15-deployment-hardening')


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def deployment_hardening():
    deployment_hardening_work(build_execution_config())


DEPENDENCY_CONFIG = {'input_path': str, 'output_root': str, 'attempt_root': str}


def run_dependency_job(context, configured, job_id):
    result = dependency_jobs.execute(
        job_id=job_id, run_id=configured['engagement_run_id'],
        input_path=context.op_config['input_path'], output_root=context.op_config['output_root'],
        attempt_root=context.op_config['attempt_root'])
    root = data_path(configured['engagement_run_id'], 'jobs', job_id)
    context.add_output_metadata({
        'output': MetadataValue.path(str(root)),
        'envelope': MetadataValue.path(str(root / 'attempts' / result['attempt_id'] / 'result.json')),
        'attempt_id': result['attempt_id']})
    return result


@op(config_schema=DEPENDENCY_CONFIG, pool=OFFLINE_DOCKER_POOL)
def sbom_inventory_work(context, configured):
    return run_dependency_job(context, configured, '02-sbom-inventory')


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def sbom_inventory():
    sbom_inventory_work(build_execution_config())


@op(config_schema=DEPENDENCY_CONFIG, pool=OFFLINE_DOCKER_POOL)
def sca_vulnerability_match_work(context, configured):
    return run_dependency_job(context, configured, '02-sca-vulnerability-match')


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def sca_vulnerability_match():
    sca_vulnerability_match_work(build_execution_config())


@op(config_schema=DEPENDENCY_CONFIG, pool=OFFLINE_DOCKER_POOL)
def license_scan_work(context, configured):
    return run_dependency_job(context, configured, '02-license-scan')


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def license_scan():
    license_scan_work(build_execution_config())


@op(config_schema=DEPENDENCY_CONFIG, pool=CPU_POOL)
def dependency_lifecycle_work(context, configured):
    return run_dependency_job(context, configured, '02-dependency-lifecycle')


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def dependency_lifecycle():
    dependency_lifecycle_work(build_execution_config())


@op(config_schema=DEPENDENCY_CONFIG, pool=CPU_POOL)
def cve_reachability_work(context, configured):
    return run_dependency_job(context, configured, '06-cve-reachability')


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def cve_reachability():
    cve_reachability_work(build_execution_config())


VENDOR_EVIDENCE_CONFIG = {
    'input_path': str, 'output_root': str, 'attempt_root': str, 'execution_root': str,
}


def run_vendor_evidence_job(context, configured, job_id):
    result = vendor_evidence_jobs.execute(
        job_id=job_id, run_id=configured['engagement_run_id'], dagster_run_id=context.run_id,
        input_path=context.op_config['input_path'], output_root=context.op_config['output_root'],
        attempt_root=context.op_config['attempt_root'], execution_root=context.op_config['execution_root'])
    root = data_path(configured['engagement_run_id'], 'jobs', job_id, 'whole')
    context.add_output_metadata({
        'output': MetadataValue.path(str(root)),
        'envelope': MetadataValue.path(str(root / 'attempts' / result['attempt_id'] / 'result.json')),
        'attempt_id': result['attempt_id']})
    return result


def run_automatic_evidence_job(context, configured, job_id):
    run_id = configured['engagement_run_id']
    request = automatic_evidence_inputs.prepare(run_id, job_id, context.run_id)
    if job_id in automatic_evidence_inputs.VENDOR_JOBS:
        result = vendor_evidence_jobs.execute(job_id=job_id, run_id=run_id,
            dagster_run_id=context.run_id, **request)
        base = data_path(run_id, 'jobs', job_id, 'whole')
    else:
        result = dependency_jobs.execute(job_id=job_id, run_id=run_id, **request)
        base = data_path(run_id, 'jobs', job_id)
    attempt = base / 'attempts' / result['attempt_id']
    context.add_output_metadata({
        'output': MetadataValue.path(str(base)),
        'envelope': MetadataValue.path(str(attempt / 'result.json')),
        'attempt_id': result['attempt_id'],
        'automatic_request': MetadataValue.path(request['input_path'])})
    return result


def automatic_evidence_lifecycle_op(job_id, pool):
    @op(name='job_' + job_id.replace('-', '_'),
        ins={'configured': In(dict), 'upstream': In(list)}, pool=pool)
    def automatic_evidence(context, configured, upstream):
        return run_automatic_evidence_job(context, configured, job_id)
    return automatic_evidence


def tolerant_automatic_evidence_op(job_id, pool):
    """P43 (the P42 pattern): never raises in the full review. A crash or BLOCKED returns NOT_PUBLISHED for the
    optional consumers (the SBOM records the gap); published_gate re-raises it for the required consumers."""
    @op(name='job_' + job_id.replace('-', '_'),
        ins={'configured': In(dict), 'upstream': In(list)}, pool=pool)
    def automatic_evidence(context, configured, upstream):
        try:
            return run_automatic_evidence_job(context, configured, job_id)
        except Exception as exc:
            context.log.warning(f'{job_id} did not publish ({type(exc).__name__}: {exc}); '
                                'optional consumers record the gap, required consumers are held')
            return {'job_id': job_id, 'status': 'NOT_PUBLISHED', 'error': f'{type(exc).__name__}: {exc}'[:500]}
    return automatic_evidence


def published_gate(job_id):
    @op(name='job_' + job_id.replace('-', '_') + '_published', ins={'result': In(dict)}, tags=COORDINATION)
    def published(context, result):
        if result.get('status') == 'NOT_PUBLISHED':
            raise Failure(f'{job_id} did not publish: ' + result['error'])
        return result
    return published


secrets_inventory_lifecycle_work = automatic_evidence_lifecycle_op('02-secrets-inventory', OFFLINE_DOCKER_POOL)
# P43: 02-sbom-inventory takes 02-iac-config-scan's base-image inventory over an optional edge.
iac_config_scan_lifecycle_work = tolerant_automatic_evidence_op('02-iac-config-scan', OFFLINE_DOCKER_POOL)
container_image_inventory_lifecycle_work = automatic_evidence_lifecycle_op('02-container-image-inventory', OFFLINE_DOCKER_POOL)
mobile_sast_lifecycle_work = automatic_evidence_lifecycle_op('02-mobile-sast', OFFLINE_DOCKER_POOL)
sbom_inventory_lifecycle_work = automatic_evidence_lifecycle_op('02-sbom-inventory', OFFLINE_DOCKER_POOL)
sca_vulnerability_match_lifecycle_work = automatic_evidence_lifecycle_op('02-sca-vulnerability-match', OFFLINE_DOCKER_POOL)
license_scan_lifecycle_work = automatic_evidence_lifecycle_op('02-license-scan', OFFLINE_DOCKER_POOL)
dependency_lifecycle_lifecycle_work = automatic_evidence_lifecycle_op('02-dependency-lifecycle', CPU_POOL)


@op(config_schema=VENDOR_EVIDENCE_CONFIG, pool=OFFLINE_DOCKER_POOL)
def secrets_inventory_work(context, configured):
    return run_vendor_evidence_job(context, configured, '02-secrets-inventory')


@job(resource_defs={'workflow_settings': workflow_settings}, executor_def=multiprocess_executor.configured({'max_concurrent': 1}), op_retry_policy=RetryPolicy(max_retries=0))
def secrets_inventory():
    secrets_inventory_work(build_execution_config())


@op(config_schema=VENDOR_EVIDENCE_CONFIG, pool=OFFLINE_DOCKER_POOL)
def iac_config_scan_work(context, configured):
    return run_vendor_evidence_job(context, configured, '02-iac-config-scan')


@job(resource_defs={'workflow_settings': workflow_settings}, executor_def=multiprocess_executor.configured({'max_concurrent': 1}), op_retry_policy=RetryPolicy(max_retries=0))
def iac_config_scan():
    iac_config_scan_work(build_execution_config())


@op(config_schema=VENDOR_EVIDENCE_CONFIG, pool=OFFLINE_DOCKER_POOL)
def container_image_inventory_work(context, configured):
    return run_vendor_evidence_job(context, configured, '02-container-image-inventory')


@job(resource_defs={'workflow_settings': workflow_settings}, executor_def=multiprocess_executor.configured({'max_concurrent': 1}), op_retry_policy=RetryPolicy(max_retries=0))
def container_image_inventory():
    container_image_inventory_work(build_execution_config())


@op(config_schema=VENDOR_EVIDENCE_CONFIG, pool=OFFLINE_DOCKER_POOL)
def binary_hardening_work(context, configured):
    return run_vendor_evidence_job(context, configured, '02-binary-hardening')


@job(resource_defs={'workflow_settings': workflow_settings}, executor_def=multiprocess_executor.configured({'max_concurrent': 1}), op_retry_policy=RetryPolicy(max_retries=0))
def binary_hardening():
    binary_hardening_work(build_execution_config())


@op(pool=OFFLINE_DOCKER_POOL)
def binary_hardening_lifecycle_work(context, configured, _native_build):
    result = vendor_evidence_jobs.execute_binary_from_native(
        run_id=configured['engagement_run_id'], dagster_run_id=context.run_id)
    base = data_path(configured['engagement_run_id'], 'jobs', '02-binary-hardening', 'whole')
    attempt = base / 'attempts' / result['attempt_id']
    context.add_output_metadata({
        'output': MetadataValue.path(str(base)),
        'envelope': MetadataValue.path(str(attempt / 'result.json')),
        'attempt_id': result['attempt_id'],
        'input_kind': 'accepted-native-build-binaries'})
    return result


@op(pool=OFFLINE_DOCKER_POOL)
def binary_component_cve_match_lifecycle_work(context, configured, _native_build):
    """cve-bin-tool over the accepted native-build binaries, against the database derived from the
    run's NVD snapshot (docs/proposals/vendor-prepass/blint-cve-bin-tool.md section 3b)."""
    import binary_component_cve_match
    result = binary_component_cve_match.execute(
        run_id=configured['engagement_run_id'], dagster_run_id=context.run_id)
    base = data_path(configured['engagement_run_id'], 'jobs', '02-binary-component-cve-match', 'whole')
    attempt = base / 'attempts' / result['attempt_id']
    context.add_output_metadata({
        'output': MetadataValue.path(str(base)),
        'envelope': MetadataValue.path(str(attempt / 'result.json')),
        'attempt_id': result['attempt_id'],
        'input_kind': 'accepted-native-build-binaries'})
    return result


@op(config_schema=VENDOR_EVIDENCE_CONFIG, pool=OFFLINE_DOCKER_POOL)
def mobile_sast_work(context, configured):
    return run_vendor_evidence_job(context, configured, '02-mobile-sast')


@job(resource_defs={'workflow_settings': workflow_settings}, executor_def=multiprocess_executor.configured({'max_concurrent': 1}), op_retry_policy=RetryPolicy(max_retries=0))
def mobile_sast():
    mobile_sast_work(build_execution_config())


CONTROL_CONFIG = {'input_path': str, 'output_root': str, 'attempt_root': str}
FINAL_PUBLICATION_CONFIG = {'input_path': str, 'output_root': str}

def run_control_job(context, configured, job_id, *, pool=False):
    runner = control_lane_jobs.execute_pool if pool else control_lane_jobs.execute
    result = runner(job_id=job_id, run_id=configured['engagement_run_id'], dagster_run_id=context.run_id,
        input_path=context.op_config['input_path'], output_root=context.op_config['output_root'],
        attempt_root=context.op_config['attempt_root'])
    context.add_output_metadata({'output': MetadataValue.path(context.op_config['output_root']),
                                 'attempt_id': result['attempt_id']})
    return result

def _control_op(name, job_id, *, pool=False):
    @op(name=name, config_schema=CONTROL_CONFIG, pool=PERSONA_POOL if job_id=='persona-tool-pool-dispatch' else CPU_POOL)
    def control(context, configured): return run_control_job(context, configured, job_id, pool=pool)
    return control

persona_tool_pool_dispatch_work=_control_op('persona_tool_pool_dispatch_work','persona-tool-pool-dispatch',pool=True)
deterministic_pool_merge_work=_control_op('deterministic_pool_merge_work','deterministic-pool-merge',pool=True)
evidence_qualified_quorum_work=_control_op('evidence_qualified_quorum_work','evidence-qualified-quorum')
dynamic_rescope_work=_control_op('dynamic_rescope_work','dynamic-rescope')
completeness_audit_work=_control_op('completeness_audit_work','completeness-audit')
synthetic_hypothesis_resynthesis_work=_control_op('synthetic_hypothesis_resynthesis_work','synthetic-hypothesis-resynthesis')
remediation_retest_feedback_work=_control_op('remediation_retest_feedback_work','remediation-retest-feedback')

@job(resource_defs={'workflow_settings': workflow_settings},executor_def=multiprocess_executor.configured({'max_concurrent':1}),op_retry_policy=RetryPolicy(max_retries=0))
def persona_tool_pool_dispatch(): persona_tool_pool_dispatch_work(build_execution_config())
@job(resource_defs={'workflow_settings': workflow_settings},executor_def=multiprocess_executor.configured({'max_concurrent':1}),op_retry_policy=RetryPolicy(max_retries=0))
def deterministic_pool_merge(): deterministic_pool_merge_work(build_execution_config())
@job(resource_defs={'workflow_settings': workflow_settings},executor_def=multiprocess_executor.configured({'max_concurrent':1}),op_retry_policy=RetryPolicy(max_retries=0))
def evidence_qualified_quorum(): evidence_qualified_quorum_work(build_execution_config())
@job(resource_defs={'workflow_settings': workflow_settings},executor_def=multiprocess_executor.configured({'max_concurrent':1}),op_retry_policy=RetryPolicy(max_retries=0))
def dynamic_rescope(): dynamic_rescope_work(build_execution_config())
@job(resource_defs={'workflow_settings': workflow_settings},executor_def=multiprocess_executor.configured({'max_concurrent':1}),op_retry_policy=RetryPolicy(max_retries=0))
def completeness_audit(): completeness_audit_work(build_execution_config())
@job(resource_defs={'workflow_settings': workflow_settings},executor_def=multiprocess_executor.configured({'max_concurrent':1}),op_retry_policy=RetryPolicy(max_retries=0))
def synthetic_hypothesis_resynthesis(): synthetic_hypothesis_resynthesis_work(build_execution_config())
@job(resource_defs={'workflow_settings': workflow_settings},executor_def=multiprocess_executor.configured({'max_concurrent':1}),op_retry_policy=RetryPolicy(max_retries=0))
def remediation_retest_feedback(): remediation_retest_feedback_work(build_execution_config())

@op(config_schema=FINAL_PUBLICATION_CONFIG, pool=CPU_POOL)
def final_publication_gate_work(context, configured):
    return control_lane_jobs.execute_final(run_id=configured['engagement_run_id'],dagster_run_id=context.run_id,
        input_path=context.op_config['input_path'],output_root=context.op_config['output_root'])
@job(resource_defs={'workflow_settings': workflow_settings},executor_def=multiprocess_executor.configured({'max_concurrent':1}),op_retry_policy=RetryPolicy(max_retries=0))
def final_publication_gate(): final_publication_gate_work(build_execution_config())


def run_repository_partition_discovery(context, configured):
    # Validated hand-off gate, not real analysis -- see discovery_gate.py's module docstring for
    # why this job cannot honestly be a deterministic worker. Accepts an out-of-band-supplied,
    # schema-valid repository-partition-map if present; otherwise issues an actionable hand-off
    # and fails clearly (never silently succeeds as a no-op).
    job = '02-repository-partition-discovery'
    result = automatic_discovery.run(configured['engagement_run_id'], context.run_id, job, configured['force'])
    path = discovery_gate.root(configured['engagement_run_id'], job) / 'attempts' / result['attempt_id']
    context.add_output_metadata({
        'output': MetadataValue.path(str(path / 'repository-partition-map.json')),
        'envelope': MetadataValue.path(str(path / 'result.json'))})
    return result


@op(pool=GATE_POOL)
def repository_partition_discovery_standalone_work(context, configured):
    return run_repository_partition_discovery(context, configured)


@op(name='job_02_repository_partition_discovery', ins={'configured': In(dict), 'upstream': In(list)}, pool=GATE_POOL)
def repository_partition_discovery_work(context, configured, upstream):
    return run_repository_partition_discovery(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def repository_partition_discovery():
    repository_partition_discovery_standalone_work(build_execution_config())


def run_dev_project_discovery(context, configured):
    # Same validated hand-off gate as run_repository_partition_discovery above, for the
    # project-discovery contract. The gate also requires an accepted partition map (the graph's
    # declared dependency) and checks citation freshness. See discovery_gate.py.
    job = '02-dev-project-discovery'
    result = automatic_discovery.run(configured['engagement_run_id'], context.run_id, job, configured['force'])
    path = discovery_gate.root(configured['engagement_run_id'], job) / 'attempts' / result['attempt_id']
    context.add_output_metadata({'output': MetadataValue.path(str(path / 'project-inventory.json')),
                                 'envelope': MetadataValue.path(str(path / 'result.json'))})
    return result


@op(pool=GATE_POOL)
def dev_project_discovery_standalone_work(context, configured):
    return run_dev_project_discovery(context, configured)


@op(name='job_02_dev_project_discovery', ins={'configured': In(dict), 'upstream': In(list)}, pool=GATE_POOL)
def dev_project_discovery_work(context, configured, upstream):
    return run_dev_project_discovery(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def dev_project_discovery():
    dev_project_discovery_standalone_work(build_execution_config())


def run_devops_project_discovery(context, configured):
    # Same validated hand-off gate, for the devops-persona reading of the project-discovery
    # contract (container/pipeline build definition). Requires the accepted partition map (the
    # graph's declared dependency) at the same source revision. See discovery_gate.py.
    job = '02-devops-project-discovery'
    result = automatic_discovery.run(configured['engagement_run_id'], context.run_id, job, configured['force'])
    path = discovery_gate.root(configured['engagement_run_id'], job) / 'attempts' / result['attempt_id']
    context.add_output_metadata({'output': MetadataValue.path(str(path / 'project-inventory.json')),
                                 'envelope': MetadataValue.path(str(path / 'result.json'))})
    return result


@op(pool=GATE_POOL)
def devops_project_discovery_standalone_work(context, configured):
    return run_devops_project_discovery(context, configured)


@op(name='job_02_devops_project_discovery', ins={'configured': In(dict), 'upstream': In(list)}, pool=GATE_POOL)
def devops_project_discovery_work(context, configured, upstream):
    return run_devops_project_discovery(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def devops_project_discovery():
    devops_project_discovery_standalone_work(build_execution_config())


def run_sre_operations_topology(context, configured):
    # Same validated hand-off gate, for the operations-topology contract. Requires the accepted
    # devops-project-discovery record (the graph's declared dependency) at the same source
    # revision -- operations topology is read off the containers/services devops discovery found.
    # See discovery_gate.py.
    job = '02-sre-operations-topology'
    result = automatic_discovery.run(configured['engagement_run_id'], context.run_id, job, configured['force'])
    path = discovery_gate.root(configured['engagement_run_id'], job) / 'attempts' / result['attempt_id']
    context.add_output_metadata({'output': MetadataValue.path(str(path / 'service-inventory.json')),
                                 'envelope': MetadataValue.path(str(path / 'result.json'))})
    return result


@op(pool=GATE_POOL)
def sre_operations_topology_standalone_work(context, configured):
    return run_sre_operations_topology(context, configured)


@op(name='job_02_sre_operations_topology', ins={'configured': In(dict), 'upstream': In(list)}, pool=GATE_POOL)
def sre_operations_topology_work(context, configured, upstream):
    return run_sre_operations_topology(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def sre_operations_topology():
    sre_operations_topology_standalone_work(build_execution_config())


def run_build_index(context, configured):
    # 02-build-index (ADR-0012 revision 1; TODO Phase 5g item 2): deterministic, in-process indexer on
    # the common worker-result envelope. Requires accepted intake, D01, D02 and D03 (the graph's
    # required edges); executes nothing from the target and assigns no class. See build_index.py.
    result = build_index_worker.run(configured['engagement_run_id'], context.run_id, configured['force'])
    path = build_index_worker.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
    context.add_output_metadata({
        'output': MetadataValue.path(str(path / 'build-index.json')),
        'summary': MetadataValue.path(str(path / 'build-index.md')),
        'envelope': MetadataValue.path(str(path / 'result.json'))})
    return result


@op(pool=CPU_POOL)
def build_index_standalone_work(context, configured):
    return run_build_index(context, configured)


@op(name='job_02_build_index', ins={'configured': In(dict), 'upstream': In(list)}, pool=CPU_POOL)
def build_index_work(context, configured, upstream):
    return run_build_index(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def build_index():
    build_index_standalone_work(build_execution_config())


def run_build_classify(context, configured):
    # 02-build-classify (ADR-0012 revision 2; TODO Phase 5g item 3): one live persona call
    # (claude-sonnet-5/medium) reads the checkout and the accepted build index, classifies every unit
    # and records where the index is wrong; published on the common envelope. See build_classify.py.
    result = build_classify_worker.run(configured['engagement_run_id'], context.run_id, configured['force'])
    path = build_classify_worker.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
    context.add_output_metadata({
        'output': MetadataValue.path(str(path / 'build-classification.json')),
        'summary': MetadataValue.path(str(path / 'build-classification-summary.md')),
        'envelope': MetadataValue.path(str(path / 'result.json'))})
    return result


@op(pool=PERSONA_POOL)
def build_classify_standalone_work(context, configured):
    return run_build_classify(context, configured)


@op(name='job_02_build_classify', ins={'configured': In(dict), 'upstream': In(list)}, pool=PERSONA_POOL)
def build_classify_work(context, configured, upstream):
    return run_build_classify(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def build_classify():
    build_classify_standalone_work(build_execution_config())


def run_build_plan(context, configured):
    # 02-build-plan (ADR-0012 revisions 2-3; TODO Phase 5g item 4): one live persona call (Haiku) per
    # build-set unit reads the checkout, the accepted index and classification, the buildenv catalog
    # and plan-unit.json; the compiler is fixed (our clang). Published on the common envelope.
    result = build_plan_worker.run(configured['engagement_run_id'], context.run_id, configured['force'])
    path = build_plan_worker.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
    context.add_output_metadata({
        'output': MetadataValue.path(str(path / 'build-plan.json')),
        'summary': MetadataValue.path(str(path / 'build-plan-summary.md')),
        'envelope': MetadataValue.path(str(path / 'result.json'))})
    return result


@op(pool=PERSONA_POOL)
def build_plan_standalone_work(context, configured):
    return run_build_plan(context, configured)


@op(name='job_02_build_plan', ins={'configured': In(dict), 'upstream': In(list)}, pool=PERSONA_POOL)
def build_plan_work(context, configured, upstream):
    return run_build_plan(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def build_plan():
    build_plan_standalone_work(build_execution_config())


def run_build_resolution(context, configured):
    result = build_resolution_worker.run(configured['engagement_run_id'], context.run_id,
                                         configured['force'])
    path = build_resolution_worker.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
    context.add_output_metadata({
        'output': MetadataValue.path(str(path / build_resolution_worker.RESULT)),
        'lock': MetadataValue.path(str(path / build_resolution_worker.LOCK_FILE)),
        'envelope': MetadataValue.path(str(path / 'result.json')),
        'attempt_id': result['attempt_id']})
    return result


@op(pool=DOCKER_POOL)
def build_resolution_standalone_work(context, configured):
    return run_build_resolution(context, configured)


@op(name='job_02_build_resolution', ins={'configured': In(dict), 'upstream': In(list)}, pool=DOCKER_POOL)
def build_resolution_work(context, configured, upstream):
    return run_build_resolution(context, configured)


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def build_resolution():
    build_resolution_standalone_work(build_execution_config())


@op(pool=resource_pools.derive_pool('pinned_container', (), memory_heavy=False))
def b13_harmless_container_work(context, configured):
    """Phase 3 qualification only: fixed harmless image/argv, not a lifecycle scanner."""
    result = b13_harmless_worker.run(configured['engagement_run_id'], context.run_id,
                                     configured['force'])
    path = b13_harmless_worker.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
    receipt = read_json(path / b13_harmless_worker.RECEIPT_FILE)
    context.add_output_metadata({
        'envelope': MetadataValue.path(str(path / 'result.json')),
        'qualification': MetadataValue.path(str(path / b13_harmless_worker.RECEIPT_FILE)),
        'image_reference': receipt['image_reference'],
        'expected_result_sha256': receipt['expected_result_sha256'],
        'attempt_id': result['attempt_id']})
    return result


@job(resource_defs={'workflow_settings': workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent': 1}),
     op_retry_policy=RetryPolicy(max_retries=0))
def b13_harmless_container():
    b13_harmless_container_work(build_execution_config())


# Construct the full graph from the same validated lifecycle contract as intake.
# Missing workers fail explicitly instead of succeeding as no-op placeholders.
from job_graph import load_graph
LIFECYCLE=load_graph()['jobs']
LIFECYCLE_OPS={name:blocked_op(name,node) for name,node in LIFECYCLE.items()
                if name not in ('00-intake','02-evidence-index','02-build-configure','02-native-build','02-source-sast',
                                 '01-component-characterization','02-full-review-input-assembly','03-threat-model-dfd-stride','03-threat-model-reconciliation','04-asvs-masvs','10-synthesis-report',
                                 '02-binary-hardening','02-binary-component-cve-match',
                                 '02-ir-capture','02-ir-link','02-ir-facts',
                                 '02-code-property-graph',
                                 '02-repository-partition-discovery','02-dev-project-discovery',
                                 '02-devops-project-discovery','02-sre-operations-topology',
                                 '02-build-index','02-build-classify','02-build-plan',
                                 '02-build-resolution','02-ossf-scorecard')}
LIFECYCLE_OPS['02-build-configure']=build_configure_work
LIFECYCLE_OPS['02-evidence-assembly']=evidence_assembly_lifecycle_work
LIFECYCLE_OPS['02-native-build']=native_build_work
LIFECYCLE_OPS['02-source-sast']=source_sast_work
LIFECYCLE_OPS['02-codeql-cpp']=CODEQL_LANGUAGE_OPS['cpp']
LIFECYCLE_OPS['02-codeql-csharp']=CODEQL_LANGUAGE_OPS['csharp']
LIFECYCLE_OPS['02-codeql-go']=CODEQL_LANGUAGE_OPS['go']
LIFECYCLE_OPS['02-codeql-java']=CODEQL_LANGUAGE_OPS['java']
LIFECYCLE_OPS['02-codeql-javascript']=CODEQL_LANGUAGE_OPS['javascript']
LIFECYCLE_OPS['02-codeql-python']=CODEQL_LANGUAGE_OPS['python']
LIFECYCLE_OPS['02-codeql-ruby']=CODEQL_LANGUAGE_OPS['ruby']
LIFECYCLE_OPS['02-codeql-rust']=CODEQL_LANGUAGE_OPS['rust']
LIFECYCLE_OPS['01-component-characterization']=component_characterization_work
LIFECYCLE_OPS['02-full-review-input-assembly']=full_review_input_assembly_work
LIFECYCLE_OPS['03-threat-model-dfd-stride']=threat_model_dfd_stride_work
LIFECYCLE_OPS['03-threat-model-reconciliation']=threat_model_reconciliation_work
LIFECYCLE_OPS['04-asvs-masvs']=owasp_join_lifecycle_work
LIFECYCLE_OPS['10-synthesis-report']=synthesis_report_work
LIFECYCLE_OPS['02-binary-hardening']=binary_hardening_lifecycle_work
LIFECYCLE_OPS['02-binary-component-cve-match']=binary_component_cve_match_lifecycle_work
LIFECYCLE_OPS['02-ir-capture']=ir_capture_work
LIFECYCLE_OPS['02-ir-link']=ir_link_work
LIFECYCLE_OPS['02-ir-facts']=ir_facts_work
LIFECYCLE_OPS['02-code-property-graph']=code_property_graph_work
LIFECYCLE_OPS['02-treesitter-ast']=treesitter_ast_lifecycle_work
LIFECYCLE_OPS['02-code-index']=code_index_lifecycle_work
LIFECYCLE_OPS['02-lsp-xref']=lsp_xref_lifecycle_work
LIFECYCLE_OPS['02-evidence-index-derived']=evidence_index_derived_lifecycle_work
LIFECYCLE_OPS['02-language-census']=language_census_lifecycle_work
LIFECYCLE_OPS['02-api-collection-intelligence-ingest']=api_collection_intelligence_work
LIFECYCLE_OPS['02-doc-intelligence-ingest']=doc_intelligence_work
LIFECYCLE_OPS['02-test-intelligence-ingest']=test_intelligence_work
LIFECYCLE_OPS['02-operations-doc-ingest']=operations_doc_work
LIFECYCLE_OPS['02-standards-source-ingest']=standards_source_work
LIFECYCLE_OPS['02-native-sast']=native_sast_lifecycle_work
LIFECYCLE_OPS['02-debug-symbol-index']=debug_symbol_index_work
LIFECYCLE_OPS['02-binary-triage']=binary_triage_work
LIFECYCLE_OPS['02-binary-cfg']=binary_cfg_work
LIFECYCLE_OPS['02-binary-intelligence-ingest']=binary_intelligence_work
LIFECYCLE_OPS['02-test-execution']=test_execution_lifecycle_work
LIFECYCLE_OPS['02-test-result-ingest']=test_result_lifecycle_work
LIFECYCLE_OPS['02-test-coverage-ingest']=test_coverage_lifecycle_work
LIFECYCLE_OPS['02-secrets-inventory']=secrets_inventory_lifecycle_work
LIFECYCLE_OPS['02-iac-config-scan']=iac_config_scan_lifecycle_work
LIFECYCLE_OPS['02-container-image-inventory']=container_image_inventory_lifecycle_work
LIFECYCLE_OPS['02-mobile-sast']=mobile_sast_lifecycle_work
LIFECYCLE_OPS['02-sbom-inventory']=sbom_inventory_lifecycle_work
LIFECYCLE_OPS['02-sca-vulnerability-match']=sca_vulnerability_match_lifecycle_work
LIFECYCLE_OPS['02-license-scan']=license_scan_lifecycle_work
LIFECYCLE_OPS['02-dependency-lifecycle']=dependency_lifecycle_lifecycle_work
LIFECYCLE_OPS['11-remediation-proposal']=remediation_proposal_lifecycle_work
LIFECYCLE_OPS['07-red-team-adversarial']=red_team_lifecycle_work
LIFECYCLE_OPS['08-blue-team-refutation']=blue_team_lifecycle_work
LIFECYCLE_OPS['09-independent-verification']=verification_lifecycle_work
LIFECYCLE_OPS['12-scoring-prioritization']=scoring_lifecycle_work
LIFECYCLE_OPS['05-native-memory']=native_memory_lifecycle_work
LIFECYCLE_OPS['06-reachability-codeql']=reachability_codeql_lifecycle_work
LIFECYCLE_OPS['06-reachability-ir']=reachability_ir_lifecycle_work
LIFECYCLE_OPS['06-cve-reachability']=cve_reachability_lifecycle_work
LIFECYCLE_OPS['13-fuzz-target-triage']=fuzz_triage_lifecycle_work
LIFECYCLE_OPS['04-owasp-candidate-search']=owasp_candidate_search_lifecycle_work
LIFECYCLE_OPS['04-owasp-participation']=owasp_participation_lifecycle_work
LIFECYCLE_OPS['04-owasp-universe']=owasp_universe_lifecycle_work
LIFECYCLE_OPS['04-owasp-validation-worklist']=owasp_worklist_lifecycle_work
LIFECYCLE_OPS['15-stig-srg-validation-worklist']=stig_worklist_lifecycle_work
LIFECYCLE_OPS['15-deployment-hardening']=deployment_lifecycle_work
LIFECYCLE_OPS['07-hypothesis-discovery']=hypothesis_discovery_lifecycle_work
LIFECYCLE_OPS['14-attack-chain-composition']=attack_chain_composition_lifecycle_work
LIFECYCLE_OPS['14-attack-chain-refutation']=attack_chain_refutation_lifecycle_work
LIFECYCLE_OPS['12b-poc-and-fix']=poc_fix_lifecycle_work
LIFECYCLE_OPS['claim-ledger-routing']=claim_ledger_lifecycle_work
LIFECYCLE_OPS['persona-tool-pool-dispatch']=persona_tool_pool_lifecycle_work
LIFECYCLE_OPS['deterministic-pool-merge']=deterministic_pool_merge_lifecycle_work
LIFECYCLE_OPS['evidence-qualified-quorum']=evidence_qualified_quorum_lifecycle_work
LIFECYCLE_OPS['dynamic-rescope']=dynamic_rescope_lifecycle_work
LIFECYCLE_OPS['completeness-audit']=completeness_audit_lifecycle_work
LIFECYCLE_OPS['synthetic-hypothesis-resynthesis']=synthetic_resynthesis_lifecycle_work
LIFECYCLE_OPS['remediation-retest-feedback']=remediation_retest_feedback_lifecycle_work
LIFECYCLE_OPS['final-publication-gate']=final_publication_preparation_lifecycle_work
LIFECYCLE_OPS['02-repository-partition-discovery']=repository_partition_discovery_work
LIFECYCLE_OPS['02-dev-project-discovery']=dev_project_discovery_work
LIFECYCLE_OPS['02-devops-project-discovery']=devops_project_discovery_work
LIFECYCLE_OPS['02-sre-operations-topology']=sre_operations_topology_work
LIFECYCLE_OPS['02-build-index']=build_index_work
LIFECYCLE_OPS['02-build-classify']=build_classify_work
LIFECYCLE_OPS['02-build-plan']=build_plan_work
LIFECYCLE_OPS['02-build-resolution']=build_resolution_work
LIFECYCLE_OPS['02-ossf-scorecard']=ossf_scorecard_lifecycle_work
# ADR-0025: a job with an item under items/ runs through the one generic executor op instead
# (its needs must equal its graph dependencies); without the item the legacy op above stays.
import job_executor
ITEM_JOBS=job_executor.register_item_ops(LIFECYCLE,LIFECYCLE_OPS,CPU_POOL)


# P42: a tolerant op returns NOT_PUBLISHED instead of raising; its optional consumers take that observation,
# its required consumers take the gate's output, so only they are held by a crashed or BLOCKED producer.
TOLERANT_OPS={'02-native-build':native_build_published,'02-iac-config-scan':published_gate('02-iac-config-scan')}


def published_inputs(job_id):
    """Gap 3: route a pass-through op's inputs. All published: 'ready' (the op runs). A required input that
    did not publish: 'missing' carries NOT_PUBLISHED and the op does not run (Dagster skips it)."""
    @op(name='job_'+job_id.replace('-','_')+'_inputs',ins={'upstream':In(list)},
        out={'ready':Out(list,is_required=False),'missing':Out(dict,is_required=False)},tags=COORDINATION)
    def inputs(upstream):
        absent=[]
        for row in upstream:
            if isinstance(row,dict) and row.get('status')=='NOT_PUBLISHED': absent.append(row.get('job_id','?'))
        if absent:
            yield Output({'job_id':job_id,'status':'NOT_PUBLISHED',
                          'error':'required input did not publish: '+', '.join(absent)},'missing')
        else:
            yield Output(upstream,'ready')
    return inputs


def pass_through_result(job_id):
    """The op's result, or the NOT_PUBLISHED pass-through when it did not run (fan-in of the one present)."""
    @op(name='job_'+job_id.replace('-','_')+'_result',ins={'results':In(list)},tags=COORDINATION)
    def result(results):
        return results[0]
    return result


# Gap 3: Dagster holds every op below a failed op, optional fan-in or not. The native evidence chain takes the
# native-build observation and passes NOT_PUBLISHED through instead of raising, so 02-code-index (whose edges
# to it are optional) still runs after a failed native build; published_gate holds their required consumers.
PASS_THROUGH_OPS={name:(published_inputs(name),pass_through_result(name),published_gate(name))
                  for name in ('02-binary-triage','02-debug-symbol-index','02-ir-capture','02-ir-link','02-ir-facts')}


def wire_lifecycle(configured, outputs, ops, discovered=None):
    """Compose ``ops`` in job-graph order onto ``outputs`` (job id -> output) inside a job body."""
    observed={}
    pending=dict(ops)
    while pending:
        if not any(all(d['job'] in outputs for d in LIFECYCLE[name]['dependencies'] if d.get('enabled',True))
                   for name in pending):
            raise ValueError('wire_lifecycle: no op has its dependencies wired: '+', '.join(sorted(pending)))
        for name in list(pending):
            deps=[d for d in LIFECYCLE[name]['dependencies'] if d.get('enabled',True)]
            if all(d['job'] in outputs for d in deps):
                upstream=[observed.get(d['job'],outputs[d['job']]) if d['kind']=='optional' else outputs[d['job']]
                          for d in deps]
                if name=='02-repository-partition-discovery': upstream.append(discovered)
                if name=='04-asvs-masvs':
                    # The join reads the accepted T10 accounting; produce T03-T06 and dispatch first.
                    handoffs=owasp_validator_handoffs_work(configured,list(upstream))
                    upstream.append(owasp_validator_dispatch_work(configured,[handoffs]))
                if name in PASS_THROUGH_OPS:
                    route,merge,gate=PASS_THROUGH_OPS[name]
                    ready,missing=route([observed.get(d['job'],outputs[d['job']]) for d in deps])
                    observed[name]=merge([pending.pop(name)(configured,ready),missing])
                    outputs[name]=gate(observed[name])
                    continue
                output=pending.pop(name)(configured,upstream)
                if name in TOLERANT_OPS: observed[name],output=output,TOLERANT_OPS[name](output)
                outputs[name]=output
    return outputs


@job(resource_defs={'workflow_settings':workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent':3}),
     hooks={workflow_failed},op_retry_policy=RetryPolicy(max_retries=0))
def full_review():
    configured=workflow_config()
    intake=workflow_intake(configured)
    discovered=build_discovery_work(intake)
    outputs={'00-intake':intake, '02-evidence-index': evidence_index_work(intake, discovered)}
    wire_lifecycle(configured,outputs,LIFECYCLE_OPS,discovered)



@run_failure_sensor(monitored_jobs=[engagement_workflow,build_discovery,build_execution,evidence_index,critical_findings_sarif,ossf_scorecard,repository_partition_discovery,dev_project_discovery,devops_project_discovery,sre_operations_topology,build_index,build_classify,build_plan,build_resolution,build_configure,native_build,source_sast,codeql_sast,component_characterization,full_review_input_assembly,threat_model_dfd_stride,threat_model_reconciliation,synthesis_report,code_property_graph,ir_capture,ir_link,ir_facts,native_memory_analysis,fuzz_target_triage,owasp_validation_worklist,owasp_join_report,stig_srg_validation_worklist,deployment_hardening,sbom_inventory,sca_vulnerability_match,license_scan,dependency_lifecycle,cve_reachability,secrets_inventory,iac_config_scan,container_image_inventory,binary_hardening,mobile_sast,persona_tool_pool_dispatch,deterministic_pool_merge,evidence_qualified_quorum,dynamic_rescope,completeness_audit,synthetic_hypothesis_resynthesis,remediation_retest_feedback,final_publication_gate,b13_harmless_container,full_review],default_status=DefaultSensorStatus.RUNNING)
def reconcile_workflow_failure(context):
    # Op hooks cannot run after abrupt worker loss. Dagster's durable terminal state wins.
    run=context.dagster_run
    settings=run.run_config['resources']['workflow_settings']['config']
    path=workflow.root(settings['engagement_run_id'])/'status.json'
    if path.exists() and read_json(path).get('status')!='FAILED':
        fail_workflow(settings['engagement_run_id'],run.run_id,'Dagster run failed; inspect event log and resume with a new launch')


@run_status_sensor(run_status=DagsterRunStatus.CANCELED,monitored_jobs=[engagement_workflow,build_discovery,build_execution,evidence_index,critical_findings_sarif,ossf_scorecard,repository_partition_discovery,dev_project_discovery,devops_project_discovery,sre_operations_topology,build_index,build_classify,build_plan,build_resolution,build_configure,native_build,source_sast,codeql_sast,component_characterization,full_review_input_assembly,threat_model_dfd_stride,threat_model_reconciliation,synthesis_report,code_property_graph,ir_capture,ir_link,ir_facts,native_memory_analysis,fuzz_target_triage,owasp_validation_worklist,owasp_join_report,stig_srg_validation_worklist,deployment_hardening,sbom_inventory,sca_vulnerability_match,license_scan,dependency_lifecycle,cve_reachability,secrets_inventory,iac_config_scan,container_image_inventory,binary_hardening,mobile_sast,persona_tool_pool_dispatch,deterministic_pool_merge,evidence_qualified_quorum,dynamic_rescope,completeness_audit,synthetic_hypothesis_resynthesis,remediation_retest_feedback,final_publication_gate,b13_harmless_container,full_review],
                   default_status=DefaultSensorStatus.RUNNING)
def reconcile_workflow_cancellation(context):
    run=context.dagster_run
    settings=run.run_config['resources']['workflow_settings']['config']
    fail_workflow(settings['engagement_run_id'],run.run_id,'Dagster run canceled; partial evidence preserved')
