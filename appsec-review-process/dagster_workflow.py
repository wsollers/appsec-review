"""Dagster multiprocessing graph. Each stateful unit owns its lock in one process."""
from dagster import (DagsterRunStatus, DefaultSensorStatus, Failure, MetadataValue, RetryPolicy, failure_hook,
                     job, multiprocess_executor, op, resource, run_failure_sensor, run_status_sensor)
from execution_state import Blocked, Lock, atomic_json, data_path, emergency, now, read_json
from phase1 import Session, config_for
import workflow


@resource(config_schema={'engagement_run_id':str,'force':bool})
def workflow_settings(context):
    return context.resource_config


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


@failure_hook(required_resource_keys={'workflow_settings'})
def workflow_failed(context):
    try:
        fail_workflow(context.resources.workflow_settings['engagement_run_id'],context.run_id,
                      context.op.name+': '+str(context.op_exception))
    except BaseException as exc:
        emergency(exc)
        raise


@op(required_resource_keys={'workflow_settings'})
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


@op
def workflow_intake(context, configured: dict):
    # Never share a live Session/OS lock between Dagster subprocesses.
    with Session(configured['engagement_run_id'],force=configured['force'],dagster_id=context.run_id,
                 observer=lambda stream,count:context.log.info('%s: %s bytes persisted',stream,count)) as session:
        session.configure(); session.prepare(); session.work()
        pointer=session.publish()
    return {**configured,'intake':pointer}


def branch_op(name):
    @op(name=name)
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


@op
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


@run_failure_sensor(monitored_jobs=[engagement_workflow],default_status=DefaultSensorStatus.RUNNING)
def reconcile_workflow_failure(context):
    # Op hooks cannot run after abrupt worker loss. Dagster's durable terminal state wins.
    run=context.dagster_run
    settings=run.run_config['resources']['workflow_settings']['config']
    path=workflow.root(settings['engagement_run_id'])/'status.json'
    if path.exists() and read_json(path).get('status')!='FAILED':
        fail_workflow(settings['engagement_run_id'],run.run_id,'Dagster run failed; inspect event log and resume with a new launch')


@run_status_sensor(run_status=DagsterRunStatus.CANCELED,monitored_jobs=[engagement_workflow],
                   default_status=DefaultSensorStatus.RUNNING)
def reconcile_workflow_cancellation(context):
    run=context.dagster_run
    settings=run.run_config['resources']['workflow_settings']['config']
    fail_workflow(settings['engagement_run_id'],run.run_id,'Dagster run canceled; partial evidence preserved')
