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
docs/build-discovery-integration.md's gap-status table for the full history.
"""
import uuid

from execution_state import Blocked, Lock, atomic_json, data_path, digest, file_hash, now, read_json
from schema_validate import validate_document

# Job name -> schema filename under schemas/, or None when no dedicated schema is shipped yet.
SCHEMAS = {
    '02-repository-partition-discovery': 'repository-partition-map.schema.json',
    # No dedicated schema exists under schemas/ for project-discovery as of 2026-09-19. Validated
    # structurally (non-empty JSON object) until one is authored; documented here, not hidden.
    '02-dev-project-discovery': None,
}


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
            f'Dagster run `{dagster_id}` reached `{job}` inside `full_review` and found no '
            f'supplied result yet.\n\n'
            f'This job needs real analytical judgment about the target repository that this gate '
            f'cannot fabricate. A human or agent session must produce the result and write it to:\n\n'
            f'`{supplied}`\n\n{schema_line}\n'
            f'Re-run `full_review` for this engagement once the file is in place.\n')
    atomic_json(handoff_path(run_id, job).with_suffix('.json'),
                {'job': job, 'dagster_run_id': dagster_id, 'issued_at': now(),
                 'expected_path': str(supplied), 'expected_schema': schema})
    path = handoff_path(run_id, job)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    return path


def run(run_id, dagster_id, job, force=False):
    base = root(run_id, job)
    with Lock(base / 'job.lock'):
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
