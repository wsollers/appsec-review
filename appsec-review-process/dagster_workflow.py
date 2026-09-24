"""Dagster multiprocessing graph. Each stateful unit owns its lock in one process."""
from dagster import (DagsterRunStatus, DefaultSensorStatus, Failure, MetadataValue, RetryPolicy, In, failure_hook,
                     job, multiprocess_executor, op, resource, run_failure_sensor, run_status_sensor)
from execution_state import Blocked, Lock, atomic_json, data_path, emergency, now, read_json
from phase1 import Session, config_for
import workflow
import build_execution as build_execution_worker
import discovery_gate
import evidence_store
import critical_findings_sarif as critical_findings_sarif_worker
import ossf_scorecard as ossf_scorecard_worker
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
NETWORK_POOL=resource_pools.derive_pool('deterministic_python',('fixed-network-destination',),memory_heavy=False)
DOCKER_POOL=resource_pools.derive_pool('pinned_container',('target-execution',),memory_heavy=False)
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
    notify_discord(run_id, message)


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


@op(name='job_02_build_configure',ins={'configured':In(dict),'upstream':In(list)},pool=DOCKER_POOL)
def build_configure_work(context, configured, upstream):
    # Bridges job-graph.json's '02-build-configure' lifecycle node (planned_scope: "Isolated
    # configure and validated compile database") to build_execution.py's real, sandboxed
    # CMake+Ninja configure worker -- added 2026-09-19 after reconciling against the repo owner's
    # automated-pipeline ask. Before this, build_execution existed only as a separate, standalone
    # job that full_review's graph never called, so this exact lifecycle node fell through to
    # blocked_op above every time, identically to every other unimplemented worker.
    #
    # KNOWN, DELIBERATE GAP (documented in claude project TODO, 2026-09-19, not hidden here):
    # this node's real declared dependency per job-graph.json is '02-dev-project-discovery', not
    # build_discovery -- but '02-dev-project-discovery' (and its own dependency,
    # '02-repository-partition-discovery') are themselves unimplemented blocked_op stubs. Until
    # those are built, `upstream` (that lifecycle chain's output) can never actually arrive here in
    # a real full_review run -- reaching either of those still-blocked nodes first raises Failure
    # and halts the whole run before this op is ever invoked. This op is wired correctly for when
    # that upstream chain exists, but it does not yet make configure execute automatically inside
    # full_review. For now, exactly like the standalone `build_execution` job before it,
    # `discovered_plan()` reads build_discovery's accepted branch directly from disk (the only real
    # discovery evidence that currently exists) rather than from `upstream` -- `upstream` is
    # accepted per the shared blocked_op-compatible signature but intentionally unused here.
    result = build_execution_worker.run(configured['engagement_run_id'], context.run_id, configured['force'])
    path = build_execution_worker.root(configured['engagement_run_id']) / 'attempts' / result['attempt_id']
    context.add_output_metadata({'output': MetadataValue.path(str(path / 'output.json')),
                                 'stdout': MetadataValue.path(str(path / 'logs/stdout.log')),
                                 'stderr': MetadataValue.path(str(path / 'logs/stderr.log'))})
    return result


def run_repository_partition_discovery(context, configured):
    # Validated hand-off gate, not real analysis -- see discovery_gate.py's module docstring for
    # why this job cannot honestly be a deterministic worker. Accepts an out-of-band-supplied,
    # schema-valid repository-partition-map if present; otherwise issues an actionable hand-off
    # and fails clearly (never silently succeeds as a no-op).
    job = '02-repository-partition-discovery'
    result = discovery_gate.run(configured['engagement_run_id'], context.run_id, job, configured['force'])
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
    result = discovery_gate.run(configured['engagement_run_id'], context.run_id, job, configured['force'])
    path = discovery_gate.root(configured['engagement_run_id'], job) / 'attempts' / result['attempt_id']
    context.add_output_metadata({'output': MetadataValue.path(str(path / 'output.json'))})
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
    result = discovery_gate.run(configured['engagement_run_id'], context.run_id, job, configured['force'])
    path = discovery_gate.root(configured['engagement_run_id'], job) / 'attempts' / result['attempt_id']
    context.add_output_metadata({'output': MetadataValue.path(str(path / 'output.json'))})
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
    result = discovery_gate.run(configured['engagement_run_id'], context.run_id, job, configured['force'])
    path = discovery_gate.root(configured['engagement_run_id'], job) / 'attempts' / result['attempt_id']
    context.add_output_metadata({'output': MetadataValue.path(str(path / 'output.json'))})
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


# Construct the full graph from the same validated lifecycle contract as intake.
# Missing workers fail explicitly instead of succeeding as no-op placeholders.
from job_graph import load_graph
LIFECYCLE=load_graph()['jobs']
LIFECYCLE_OPS={name:blocked_op(name,node) for name,node in LIFECYCLE.items()
                if name not in ('00-intake','02-evidence-index','02-build-configure',
                                 '02-repository-partition-discovery','02-dev-project-discovery',
                                 '02-devops-project-discovery','02-sre-operations-topology',
                                 '02-ossf-scorecard')}
LIFECYCLE_OPS['02-build-configure']=build_configure_work
LIFECYCLE_OPS['02-repository-partition-discovery']=repository_partition_discovery_work
LIFECYCLE_OPS['02-dev-project-discovery']=dev_project_discovery_work
LIFECYCLE_OPS['02-devops-project-discovery']=devops_project_discovery_work
LIFECYCLE_OPS['02-sre-operations-topology']=sre_operations_topology_work
LIFECYCLE_OPS['02-ossf-scorecard']=ossf_scorecard_lifecycle_work


@job(resource_defs={'workflow_settings':workflow_settings},
     executor_def=multiprocess_executor.configured({'max_concurrent':3}),
     hooks={workflow_failed},op_retry_policy=RetryPolicy(max_retries=0))
def full_review():
    configured=workflow_config()
    intake=workflow_intake(configured)
    discovered=build_discovery_work(intake)
    outputs={'00-intake':intake, '02-evidence-index': evidence_index_work(intake, discovered)}
    pending=dict(LIFECYCLE_OPS)
    while pending:
        for name in list(pending):
            deps=[d['job'] for d in LIFECYCLE[name]['dependencies'] if d.get('enabled',True)]
            if all(dep in outputs for dep in deps):
                upstream=[outputs[dep] for dep in deps]
                if name=='02-repository-partition-discovery': upstream.append(discovered)
                outputs[name]=pending.pop(name)(configured,upstream)



@run_failure_sensor(monitored_jobs=[engagement_workflow,build_discovery,build_execution,evidence_index,critical_findings_sarif,ossf_scorecard,repository_partition_discovery,dev_project_discovery,devops_project_discovery,sre_operations_topology,full_review],default_status=DefaultSensorStatus.RUNNING)
def reconcile_workflow_failure(context):
    # Op hooks cannot run after abrupt worker loss. Dagster's durable terminal state wins.
    run=context.dagster_run
    settings=run.run_config['resources']['workflow_settings']['config']
    path=workflow.root(settings['engagement_run_id'])/'status.json'
    if path.exists() and read_json(path).get('status')!='FAILED':
        fail_workflow(settings['engagement_run_id'],run.run_id,'Dagster run failed; inspect event log and resume with a new launch')


@run_status_sensor(run_status=DagsterRunStatus.CANCELED,monitored_jobs=[engagement_workflow,build_discovery,build_execution,evidence_index,critical_findings_sarif,ossf_scorecard,repository_partition_discovery,dev_project_discovery,devops_project_discovery,sre_operations_topology,full_review],
                   default_status=DefaultSensorStatus.RUNNING)
def reconcile_workflow_cancellation(context):
    run=context.dagster_run
    settings=run.run_config['resources']['workflow_settings']['config']
    fail_workflow(settings['engagement_run_id'],run.run_id,'Dagster run canceled; partial evidence preserved')
