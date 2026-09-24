"""Dagster owns config resolution, pre/work/post transitions and failure propagation.

Python workers perform bounded tasks; the original bootstrap smoke remains available.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

from dagster import (DefaultScheduleStatus, Definitions, Failure, job, op, resource,
                     in_process_executor, MetadataValue, RetryPolicy, ScheduleDefinition)

# ADR-0011: this file is loaded by a host-owned `dagster api grpc` code location, not a container.
# The process tree and run-data root resolve from the environment (code-location.sh sets both),
# falling back to this repository's own layout. The old container paths (/opt/process, /runs) are gone.
PROCESS_ROOT = Path(os.environ.get('APPSEC_PROCESS_ROOT')
                    or Path(__file__).resolve().parents[2] / 'appsec-review-process')
RUNS_ROOT = Path(os.environ.get('APPSEC_RUNS_ROOT') or PROCESS_ROOT / 'runs')

# B15: pool ids, limits and the explicit unassigned state come from resource_pools.py only.
sys.path.insert(0, str(PROCESS_ROOT))
import resource_pools


def write_json(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    os.replace(temporary, path)


def step_dir(context):
    # Dagster supplies the UUID; no user-controlled paths are accepted by this bootstrap.
    path = RUNS_ROOT / ('dagster-bootstrap-' + context.run_id) / 'data' / 'jobs' / context.op.name / 'attempts' / context.run_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def record(context, path, status, message, **details):
    from job_graph import composition
    from execution_state import ROOT, read_json
    template = read_json(ROOT / 'registry/job-templates/00-validation.json')
    composition(template)
    value = dict(run_id='dagster-bootstrap-' + context.run_id, dagster_run_id=context.run_id,
                 job_id=context.op.name, status=status, message=message,
                 attempt_id=context.run_id, composition=template['composition'],
                 timestamp=datetime.now(timezone.utc).isoformat(), **details)
    write_json(path / 'status.json', value)
    with (path / 'events.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(value) + '\n')
    context.log.info('%s: %s', status, message)


@op(tags=resource_pools.unassigned('bootstrap_diagnostic'))
def pre_validation(context):
    path = step_dir(context)
    try:
        (path / 'stdout.log').write_text('Run-owned data root is writable.\n', encoding='utf-8')
        (path / 'stderr.log').write_text('', encoding='utf-8')
        write_json(path / 'inputs.json', {'purpose': 'bootstrap smoke', 'target_execution': False})
        record(context, path, 'OK', 'Bootstrap prerequisites validated')
        return str(path)
    except Exception as exc:
        print(f'PRE_VALIDATION_FAILED: {exc}', file=sys.stderr, flush=True)
        raise


@op(config_schema={'fail_work': bool}, tags=resource_pools.unassigned('bootstrap_diagnostic'))
def smoke_work(context, validated_input: str):
    path = step_dir(context)
    try:
        if json.loads((Path(validated_input) / 'status.json').read_text())['status'] != 'OK':
            raise Failure('Pre-validation did not pass')
        command = [sys.executable, '-c',
                   "import sys; print('bootstrap stdout', flush=True); print('bootstrap stderr', file=sys.stderr, flush=True); sys.exit(" + ('7' if context.op_config['fail_work'] else '0') + ')']
        # Direct file handles avoid pipe deadlocks and unbounded buffering. The production
        # runner must additionally stream/redact arbitrary subprocess output into the UI.
        with (path / 'stdout.log').open('w') as stdout, (path / 'stderr.log').open('w') as stderr:
            result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=10, check=False)
        print((path / 'stdout.log').read_text(), end='', flush=True)
        print((path / 'stderr.log').read_text(), end='', file=sys.stderr, flush=True)
        if result.returncode:
            raise Failure(f'Smoke child exited {result.returncode}')
        output = path / 'output.json'
        write_json(output, {'bootstrap': True, 'validated_input': validated_input})
        record(context, path, 'OK', 'Smoke child completed', exit_code=result.returncode,
               output_sha256=hashlib.sha256(output.read_bytes()).hexdigest())
        return str(path)
    except Exception as exc:
        print(f'SMOKE_WORK_FAILED: {exc}', file=sys.stderr, flush=True)
        try:
            record(context, path, 'FAILED', str(exc))
        except Exception as logging_error:
            print(f'EMERGENCY_LOG_FAILURE: {logging_error}', file=sys.stderr, flush=True)
        raise


@op(tags=resource_pools.unassigned('bootstrap_diagnostic'))
def post_validation(context, work_output: str):
    path = step_dir(context)
    try:
        source = Path(work_output)
        output = source / 'output.json'
        data = json.loads(output.read_text())
        status = json.loads((source / 'status.json').read_text())
        if data.get('bootstrap') is not True or status['status'] != 'OK':
            raise Failure('Invalid smoke result')
        if hashlib.sha256(output.read_bytes()).hexdigest() != status['output_sha256']:
            raise Failure('Smoke output hash mismatch')
        for name in ('stdout.log', 'stderr.log'):
            if not (source / name).read_text().strip():
                raise Failure(f'Missing smoke stream: {name}')
        (path / 'stdout.log').write_text('Output shape, hash and both streams validated.\n', encoding='utf-8')
        (path / 'stderr.log').write_text('', encoding='utf-8')
        record(context, path, 'OK', 'Bootstrap post-validation passed', producer=work_output)
    except Exception as exc:
        print(f'POST_VALIDATION_FAILED: {exc}', file=sys.stderr, flush=True)
        try:
            record(context, path, 'FAILED', str(exc))
        except Exception as logging_error:
            print(f'EMERGENCY_LOG_FAILURE: {logging_error}', file=sys.stderr, flush=True)
        raise


@job(config={'ops': {'smoke_work': {'config': {'fail_work': False}}}})
def orchestration_smoke():
    post_validation(smoke_work(pre_validation()))


@op(tags=resource_pools.unassigned('bootstrap_diagnostic'))
def nop_op(context):
    # Plumbing proof for the host-owned code location (ADR-0011): no run data, no target, no Docker.
    print(f'nop: running in host code location, dagster run {context.run_id}', flush=True)
    print('nop: ending successfully', file=sys.stderr, flush=True)


@job
def nop():
    nop_op()


from phase1 import Session, sync_state, invalidate
from execution_state import atomic_json, data_path, digest, event, now, Blocked, emergency
from nvd_feed import sync as sync_nvd


def transition(context, name, work):
    session = context.resources.session
    root = data_path(session.run_id, 'orchestration', 'dagster', context.run_id)
    def record_stage(status, **extra):
        value = dict(run_id=session.run_id, dagster_run_id=context.run_id,
                     step=name, status=status, time=now(), **extra)
        atomic_json(root / (name + '.json'), value)
        event(root / 'events.jsonl', status, **{k:v for k,v in value.items() if k != 'status'})
    try:
        record_stage('RUNNING')
        result = work()
        record_stage('OK')
        return result
    except BaseException as exc:
        was_finished = session.finished
        session.fail(exc)
        try:
            # Configuration can fail before an attempt exists. Still expose a run-level failure.
            if was_finished or (not session.attempt and not session.audit):
                with session.publication():
                    if hasattr(session, 'graph'):
                        invalidate(session.run_id, session.graph, '00-intake', 'Dagster configuration failed')
                    sync_state(session.run_id, 'BLOCKED' if isinstance(exc, Blocked) else 'FAILED',
                               str(exc), dagster_id=context.run_id)
            record_stage('BLOCKED' if isinstance(exc, Blocked) else 'FAILED', error=str(exc))
        except BaseException as io:
            emergency(io)
        raise


@resource(config_schema={'engagement_run_id': str, 'force': bool})
def intake_session(context):
    # Lock ownership spans all three visible ops. In-process executor is intentional:
    # OS-held locks release on worker death, with no clock-based stale-lock stealing.
    config = context.resource_config
    with Session(config['engagement_run_id'], force=config['force'], dagster_id=context.run_id,
                 observer=lambda stream, count: context.log.info('%s: %s bytes persisted (raw stream kept in run storage)', stream, count)) as session:
        yield session


@op(required_resource_keys={'session'}, tags=resource_pools.unassigned('coordination_only'))
def intake_config(context):
    def gather():
        plan = context.resources.session.configure()
        path = data_path(context.resources.session.run_id, 'orchestration', 'dagster', context.run_id, 'resolved-config.json')
        atomic_json(path, plan)
        context.add_output_metadata({'config':MetadataValue.path(str(path)),
                                    'worker':plan['job']['execution']['worker'],
                                    'timeout_seconds':plan['job']['timeout_seconds']})
        return digest(plan)
    return transition(context, 'intake_config', gather)


@op(required_resource_keys={'session'}, tags=resource_pools.unassigned('coordination_only'))
def intake_pre_validation(context, configured: str):
    def validate():
        if digest(context.resources.session.configure()) != configured:
            raise Blocked('configuration changed after Dagster config resolution')
        result = context.resources.session.prepare()
        return result['attempt_id']
    return transition(context, 'intake_pre_validation', validate)


@op(required_resource_keys={'session'}, pool=resource_pools.derive_pool('deterministic_python', (), memory_heavy=False))
def intake_work(context, prepared: str):
    transition(context, 'intake_work', context.resources.session.work)
    session = context.resources.session
    attempt = session.attempt or (session.base / 'attempts' / prepared)
    context.add_output_metadata({'stdout':MetadataValue.path(str(attempt / 'logs/stdout.log')),
                                 'stderr':MetadataValue.path(str(attempt / 'logs/stderr.log')),
                                 'engagement_run_id':session.run_id,'attempt_id':prepared,'reused':session.reused})
    context.log.info('Engagement %s attempt %s work completed; reused=%s', context.resources.session.run_id, prepared, context.resources.session.reused)
    return prepared


@op(required_resource_keys={'session'}, tags=resource_pools.unassigned('coordination_only'))
def intake_post_validation(context, worked: str):
    result = transition(context, 'intake_post_validation', context.resources.session.publish)
    context.log.info('Accepted engagement %s attempt %s after post-validation', result['run_id'], worked)
    return result['attempt_id']


@job(resource_defs={'session': intake_session}, executor_def=in_process_executor,
     op_retry_policy=RetryPolicy(max_retries=0))
def phase1_intake():
    intake_post_validation(intake_work(intake_pre_validation(intake_config())))


@op(pool=resource_pools.derive_pool('deterministic_python', ('fixed-network-destination',), memory_heavy=False))
def nvd_sync_work(context):
    """Publish one immutable NVD snapshot outside every engagement run."""
    result = sync_nvd(coordinator_id=context.run_id)
    context.add_output_metadata({"snapshot_id": result["snapshot_id"],
                                 "cursor": result["cursor"]})
    return result["snapshot_id"]


@job(tags={"nvd_feed_id": "nvd"}, executor_def=in_process_executor,
     op_retry_policy=RetryPolicy(max_retries=0))
def nvd_reference_sync():
    nvd_sync_work()


nvd_reference_schedule = ScheduleDefinition(
    name="nvd_reference_schedule",
    job=nvd_reference_sync,
    cron_schedule="0 */2 * * *",
    execution_timezone="UTC",
    # On by default, as before. APPSEC_NVD_SCHEDULE=stopped in the ignored .env keeps a development
    # stack from calling the NVD API every two hours; any other value is refused, not guessed.
    default_status={'running': DefaultScheduleStatus.RUNNING, 'stopped': DefaultScheduleStatus.STOPPED}[
        os.environ.get('APPSEC_NVD_SCHEDULE', 'running')],
)


from dagster_workflow import engagement_workflow, build_discovery, build_execution, evidence_index, critical_findings_sarif, ossf_scorecard, repository_partition_discovery, dev_project_discovery, devops_project_discovery, sre_operations_topology, full_review, reconcile_workflow_failure, reconcile_workflow_cancellation

defs = Definitions(jobs=[orchestration_smoke, nop, phase1_intake, nvd_reference_sync,
                         engagement_workflow, build_discovery, build_execution,
                         evidence_index, critical_findings_sarif, ossf_scorecard,
                         repository_partition_discovery, dev_project_discovery,
                         devops_project_discovery, sre_operations_topology, full_review],
                   schedules=[nvd_reference_schedule],
                   sensors=[reconcile_workflow_failure, reconcile_workflow_cancellation,
                            resource_pools.build_guard_sensor()])
# A new op without a pool or an explicit unassigned record fails the code location load.
resource_pools.require_explicit_assignments(defs)
