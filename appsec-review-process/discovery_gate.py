"""Validated hand-off gate for the still-genuinely-unimplemented 02-*-discovery jobs.

02-repository-partition-discovery and 02-dev-project-discovery both require real analytical
judgment about *this specific target's* actual code -- partition boundaries, routing rationale,
confidence, overlap notes, relationships with a declared/inferred basis (see
schemas/repository-partition-map.schema.json). That is not something a deterministic script can
honestly produce, and fabricating those fields here would put false coverage/confidence claims
into a security review. So, unlike build_execution.py (which really does run a sandboxed CMake
configure), this module does not attempt the analysis itself.

It is a validated hand-off gate, following the project's existing "supplied artifact" precedent
(phase1.validate_supplied): a human or agent session does the actual analysis out-of-band and
drops a schema-conformant result at this job's supplied/result.json (path below). This gate
accepts it -- schema-validated, immutably recorded, same accepted.json/attempts/ shape as every
other job root in this codebase -- if present, or raises Blocked with a concrete, actionable
hand-off (a markdown note plus a machine-readable handoff.json) pointing at exactly what is
missing, instead of blocked_op's generic 'WORKER_NOT_IMPLEMENTED'.

Added 2026-09-19 to unblock 02-build-configure's real declared dependency chain
(02-build-configure -> 02-dev-project-discovery -> 02-repository-partition-discovery) without
inventing an in-Dagster LLM execution model or fabricating repository analysis. See the
'KNOWN, DELIBERATE GAP' comment on build_configure_work in dagster_workflow.py and
docs/build-discovery/build-discovery-integration.md's gap-status table for the full history.
"""
from pathlib import Path
import shutil
import uuid

from create_job_handoff import create_handoff, read_latest_handoff
from execution_state import (ROOT, Blocked, Lock, atomic_bytes, atomic_json, data_path, digest,
                             file_hash, now, read_json, run_path)
from publish_job_output import (common_pointer, coordinate_worker_lifecycle,
                                record_terminal_current, validate_published)
from schema_validate import validate_document
from worker_adapters import SuppliedHumanDecisionAdapter, WorkerRequest

# Job name -> dedicated result schema under schemas/.
SCHEMAS = {
    '02-repository-partition-discovery': 'repository-partition-map.schema.json',
    '02-dev-project-discovery': 'project-discovery.schema.json',
}

ADOPTED_JOB = '02-repository-partition-discovery'
CONSUMER_JOB = '02-dev-project-discovery'


def root(run_id, job):
    return data_path(run_id, 'jobs', job)


def supplied_path(run_id, job):
    return root(run_id, job) / 'supplied' / 'result.json'


def handoff_path(run_id, job):
    return root(run_id, job) / 'handoff.md'


def issue_handoff(run_id, job, dagster_id):
    """Write (or refresh) a concrete, actionable hand-off note for a human/agent to pick up."""
    schema = SCHEMAS.get(job)
    supplied = supplied_path(run_id, job)
    schema_line = (f'It must validate against `schemas/{schema}`.\n' if schema else
                   'No dedicated schema is shipped for this contract yet; the result must be a '
                   'non-empty JSON object.\n')
    text = (f'# Hand-off: {job}\n\n'
            f'Dagster run `{dagster_id}` reached `{job}` and found no '
            f'supplied result yet.\n\n'
            f'This job needs real analytical judgment about the target repository that this gate '
            f'cannot fabricate. A human or agent session must produce the result and write it to:\n\n'
            f'`{supplied}`\n\n{schema_line}\n'
            f'Once the file is in place, re-run the Dagster job that reached this gate for this '
            f'engagement (the standalone job, or `full_review`).\n')
    resolved_path, resolved = create_handoff(run_id, job, scope_id='handoff')
    atomic_json(handoff_path(run_id, job).with_suffix('.json'),
                {'job': job, 'dagster_run_id': dagster_id, 'issued_at': now(),
                 'expected_path': str(supplied), 'expected_schema': schema,
                 'resolved_handoff': str(resolved_path),
                 'resolved_handoff_sha256': file_hash(resolved_path),
                 'input_fingerprint': resolved['input_fingerprint']})
    path = handoff_path(run_id, job)
    atomic_bytes(path, text.encode('utf-8'))
    return path, resolved_path


def _legacy_run(run_id, dagster_id, job, force=False):
    """Keep the unadopted developer-discovery gate behavior unchanged except schema coverage."""
    base = root(run_id, job)
    supplied = supplied_path(run_id, job)
    if not supplied.exists():
        issue_handoff(run_id, job, dagster_id)
        raise Blocked(job + ': HANDOFF_ISSUED; awaiting a supplied, schema-valid result at ' + str(supplied))
    value = read_json(supplied)
    if not isinstance(value, dict) or not value:
        raise Blocked(job + ': supplied result is empty or not a JSON object')
    schema = SCHEMAS.get(job)
    if schema:
        errors = validate_document(value, schema)
        if errors:
            raise Blocked(job + ': supplied result failed schema validation: ' + '; '.join(errors))
    fingerprint = digest({'job': job, 'supplied_hash': file_hash(supplied)})
    if not force and (base / 'accepted.json').exists():
        candidate = read_json(base / 'accepted.json')
        if candidate.get('fingerprint') == fingerprint and candidate.get('status') == 'OK':
            atomic_json(data_path(run_id, 'orchestration', 'dagster', dagster_id, job + '-reuse.json'),
                        {'status': 'OK', 'reused': True, 'producer': candidate, 'time': now()})
            return candidate
    attempt_id = uuid.uuid4().hex
    attempt = base / 'attempts' / attempt_id
    attempt.mkdir(parents=True)
    atomic_json(attempt / 'inputs.json', {'supplied_path': str(supplied), 'fingerprint': fingerprint})
    atomic_json(attempt / 'output.json', value)
    accepted = {'status': 'OK', 'job': job, 'run_id': run_id, 'attempt_id': attempt_id,
                'dagster_run_id': dagster_id, 'fingerprint': fingerprint, 'accepted_at': now()}
    atomic_json(attempt / 'status.json', accepted)
    atomic_json(base / 'accepted.json', accepted)
    atomic_json(base / 'latest.json', {'attempt_id': attempt_id})
    return {**accepted, 'output': value}


def _partition_inputs(run_id, handoff, handoff_file, supplied):
    return {
        'job': ADOPTED_JOB,
        'handoff': {'path': handoff_file.relative_to(run_path(run_id)).as_posix(),
                    'sha256': file_hash(handoff_file),
                    'input_fingerprint': handoff['input_fingerprint']},
        'supplied': ({'path': str(supplied), 'sha256': file_hash(supplied)}
                     if supplied.is_file() else None),
        'code': {'discovery_gate.py': file_hash(Path(__file__)),
                 'create_job_handoff.py': file_hash(ROOT / 'create_job_handoff.py'),
                 'publish_job_output.py': file_hash(ROOT / 'publish_job_output.py'),
                 'validate_job_output.py': file_hash(ROOT / 'validate_job_output.py')},
    }


def _input_fingerprint(record):
    return 'sha256:' + digest(record)


def _validate_partition_payload(value):
    # Structural checks happen before copying; all cross-record/path/freshness semantics are owned
    # by validate_job_output's explicit repository-partition-map contract dispatch.
    return validate_document(value, SCHEMAS[ADOPTED_JOB])


def _validate_common(run_id, pointer):
    base = root(run_id, ADOPTED_JOB)
    handoff_file, handoff = read_latest_handoff(run_id, ADOPTED_JOB, 'handoff')
    record = _partition_inputs(run_id, handoff, handoff_file,
                               supplied_path(run_id, ADOPTED_JOB))
    record['run_id'] = run_id
    fingerprint = _input_fingerprint(record)
    attempt, _envelope = validate_published(
        base, pointer, fingerprint, expected_run_id=run_id, expected_job_id=ADOPTED_JOB,
        consumer_job_id=CONSUMER_JOB)
    payload = read_json(attempt / 'repository-partition-map.json')
    errors = _validate_partition_payload(payload)
    if errors:
        raise Blocked('repository partition result is invalid: ' + '; '.join(errors))
    return attempt


def _run_partition(run_id, dagster_id, force=False):
    base = root(run_id, ADOPTED_JOB)
    supplied = supplied_path(run_id, ADOPTED_JOB)
    resume = (f'python -B appsec-review-process/launch_job.py --run-id {run_id} '
              '--job full_review --wait')
    prepared = {}

    def derive_inputs():
        _handoff_note, handoff_file = issue_handoff(run_id, ADOPTED_JOB, dagster_id)
        handoff = read_json(handoff_file)
        record = _partition_inputs(run_id, handoff, handoff_file, supplied)
        record['run_id'] = run_id
        record['fingerprint'] = _input_fingerprint(record)
        prepared['record'] = record
        prepared['handoff'] = handoff
        return record

    def failure_inputs(exc):
        if 'record' in prepared:
            return prepared['record']
        return {
            'run_id': run_id,
            'job': ADOPTED_JOB,
            'preflight_error': f'{type(exc).__name__}: {exc}',
            'supplied': ({'path': str(supplied), 'sha256': file_hash(supplied)}
                         if supplied.is_file() and not supplied.is_symlink() else None),
            'code': {'discovery_gate.py': file_hash(Path(__file__)),
                     'publish_job_output.py': file_hash(ROOT / 'publish_job_output.py')},
        }

    def preflight_validate(_record):
        if not supplied.is_file() or supplied.is_symlink():
            raise Blocked(
                ADOPTED_JOB +
                ': HANDOFF_ISSUED; awaiting the bounded supplied result named by handoff.md')

    def post_validate(attempt, _envelope, record):
        if read_json(attempt / 'inputs.json') != record:
            raise Blocked('repository partition immutable attempt inputs changed')
        if _validate_partition_payload(read_json(attempt / 'repository-partition-map.json')):
            raise Blocked('accepted repository partition payload is invalid')

    def on_reuse(admitted):
        candidate, envelope = admitted['pointer'], admitted['envelope']
        atomic_json(data_path(run_id, 'orchestration', 'dagster', dagster_id,
                              ADOPTED_JOB + '-reuse.json'),
                    {'status': envelope['execution_status'], 'reused': True,
                     'publication_recovered': admitted['recovered_publication'],
                     'producer': candidate, 'time': now()})

    def execute_attempt(allocation, record, fingerprint):
        attempt_id = allocation['attempt_id']
        attempt = allocation['attempt']
        started = allocation['started_at']
        (attempt / 'supplied').mkdir()
        shutil.copyfile(supplied, attempt / 'supplied' / 'result.json')
        request = WorkerRequest(run_id, ADOPTED_JOB, attempt_id, attempt, record)
        value = dict(SuppliedHumanDecisionAdapter().execute(request))
        errors = _validate_partition_payload(value)
        if errors:
            raise ValueError('; '.join(errors))
        atomic_json(attempt / 'repository-partition-map.json', value)
        atomic_bytes(attempt / 'repository-partition-summary.md',
                     ('# Repository partition discovery\n\n'
                      'Validated supplied analysis. See `repository-partition-map.json` and the '
                      'immutable handoff identity in `inputs.json`.\n').encode('utf-8'))
        handoff = prepared['handoff']
        status = {'process': '02-evidence-pregather', 'status': 'OK', 'budget': 'standard',
                  'persona_id': 'developer-engineer', 'role_id': 'repository-partition-mapper',
                  'domain_id': 'repository-partitioning',
                  'tooling_profile_id': 'static-repo-project-inspector',
                  'artifacts_read': handoff['inputs'], 'run_id': run_id, 'job': ADOPTED_JOB,
                  'attempt_id': attempt_id, 'dagster_run_id': dagster_id,
                  'started_at': started, 'ended_at': now(), 'fingerprint': fingerprint}
        return record_terminal_current(
            base, attempt, run_id=run_id, job_id=ADOPTED_JOB,
            dagster_run_id=dagster_id, worker_kind='supplied_human_decision',
            output_contract='repository-partition-map', input_fingerprint=fingerprint,
            started_at=started, execution_status='OK',
            summary='Validated supplied repository partition analysis.', status_record=status,
            artifact_paths=['repository-partition-map.json',
                            'repository-partition-summary.md', 'status.json'],
            consumer_job_id=CONSUMER_JOB)

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=ADOPTED_JOB, dagster_run_id=dagster_id,
        worker_kind='supplied_human_decision', output_contract='repository-partition-map',
        resume_command=resume, derive_inputs=derive_inputs,
        fingerprint_inputs=lambda value: value.get('fingerprint') or _input_fingerprint(value),
        execute_attempt=execute_attempt, preflight_failure_inputs=failure_inputs,
        force=force, consumer_job_id=CONSUMER_JOB,
        preflight_validate=preflight_validate, post_validate=post_validate,
        on_reuse=on_reuse,
        blocked_summary='Repository partition preflight did not complete.',
        failed_summary='Supplied repository partition result was not accepted.')


def run(run_id, dagster_id, job, force=False):
    if job == ADOPTED_JOB:
        return _run_partition(run_id, dagster_id, force)
    base = root(run_id, job)
    with Lock(base / 'job.lock'):
        return _legacy_run(run_id, dagster_id, job, force)

def validate(run_id, job, pointer=None):
    pointer = pointer or read_json(root(run_id, job) / 'accepted.json')
    if job == ADOPTED_JOB and common_pointer(pointer):
        return _validate_common(run_id, pointer)
    if pointer.get('status') != 'OK':
        raise Blocked(job + ': result is not accepted')
    attempt = root(run_id, job) / 'attempts' / pointer['attempt_id']
    if not attempt.is_dir():
        raise Blocked(job + ': accepted attempt is missing')
    return attempt
