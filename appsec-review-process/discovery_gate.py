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
from datetime import datetime, timezone
from pathlib import Path
import shutil
import threading
import uuid

from create_job_handoff import create_handoff, read_latest_handoff
from execution_state import (ROOT, Blocked, Lock, atomic_bytes, atomic_json, data_path, digest,
                             file_hash, now, read_json, run_path)
from publish_job_output import (common_pointer, coordinate_worker_lifecycle,
                                record_terminal_current, validate_published)
from schema_validate import SchemaStore, validate_document
from worker_adapters import SuppliedHumanDecisionAdapter, WorkerRequest

# These four are only used by the automatic-dispatch path (_run_partition_automatic below); the
# existing supplied-record path (_run_partition) imports none of them. Imported at module load
# anyway (no lazy/local imports) since none of them import discovery_gate back -- checked
# 2026-09-24 -- and a missing/broken dependency for automatic mode should fail loudly the moment
# this module loads, not silently inside the one code path that happens to exercise it.
import intake
import model_version_registry as mvr
import persona_dispatch as pd
import persona_invocation as pi
import persona_prompt_assembly as ppa
import phase1
import review_cli as rc
from claude_cli_invoker import ClaudeCliInvoker

# Job name -> dedicated result schema under schemas/.
SCHEMAS = {
    '02-repository-partition-discovery': 'repository-partition-map.schema.json',
    '02-dev-project-discovery': 'project-discovery.schema.json',
    '02-devops-project-discovery': 'project-discovery.schema.json',
    '02-sre-operations-topology': 'operations-topology.schema.json',
}

ADOPTED_JOB = '02-repository-partition-discovery'
CONSUMER_JOB = '02-dev-project-discovery'

# The persona invocation's own run-scoped identity for the automatic-dispatch path (Phase 5b item
# 5). Deliberately short and opaque, NOT the job template/dagster job id (ADOPTED_JOB, 33 chars):
# persona_dispatch.build_request's own docstring documents the real bug this avoids --
# permission_capabilities.py's HIGH_ENTROPY_RE secret-scanner incidentally matches
# '02-repository-partition-discovery' when used as request.job_id, rejecting every permission
# decision before one is even reached. This constant is unrelated to ADOPTED_JOB's directory-naming
# convention (root(run_id, 'jobs', job)); it only ever appears inside the persona_invocation
# request/result identity, never as a job-tree path segment.
PERSONA_JOB_ID = 'd01-partition'
# Same reason and same shape for 02-dev-project-discovery's own persona invocation identity (D02,
# Phase 5c): short and opaque, never the 26-char template id, so it can never trip the secret
# scanner, and distinct from PERSONA_JOB_ID so the two jobs' run-scoped persona identities (and
# their llm-transcripts/ directories) can never collide inside one run.
DEV_PERSONA_JOB_ID = 'd02-devproject'
DEVOPS_JOB = '02-devops-project-discovery'
DEVOPS_PERSONA_JOB_ID = 'd03-devops'
# The chained project-discovery jobs that have an automatic persona-dispatch path, each with its own
# opaque persona invocation identity. Both read the accepted repository-partition-map.json as their
# upstream (UPSTREAM_JOB) and emit project-discovery.schema.json, which is what lets one code path
# serve both. 02-sre-operations-topology does neither (different upstream, different schema, its own
# claim builder) and is deliberately not listed.
AUTOMATIC_PROJECT_JOBS = {CONSUMER_JOB: DEV_PERSONA_JOB_ID, DEVOPS_JOB: DEVOPS_PERSONA_JOB_ID}

# Automatic-vs-supplied mode selection, scoped to (run_id, job) so it never needs
# dagster_workflow.py (Full protocol, AGENTS.md) to change discovery_gate.run()'s external
# signature: dagster_workflow.py calls run(run_id, dagster_id, job, force) identically for every
# discovery job today (confirmed 2026-09-24), and that call is out of scope for this fast-lane
# change. A run's dispatch mode instead lives in its own small opt-in data file, defaulting to
# 'supplied' for full backward compatibility -- an existing run, or one nobody has configured,
# behaves exactly as before.
DISPATCH_MODES = {'supplied', 'automatic'}


def dispatch_mode_path(run_id):
    return data_path(run_id, 'dispatch-mode.json')


def dispatch_mode(run_id, job):
    path = dispatch_mode_path(run_id)
    if not path.exists():
        return 'supplied'
    value = read_json(path)
    mode = (value.get(job) if isinstance(value, dict) else None) or 'supplied'
    if mode not in DISPATCH_MODES:
        raise Blocked(job + ': dispatch-mode.json names an unknown mode ' + repr(mode)
                      + ' (known: ' + ', '.join(sorted(DISPATCH_MODES)) + ')')
    return mode


def set_dispatch_mode(run_id, job, mode):
    """Opt one job into automatic (or explicitly back into supplied) dispatch for this run. Not
    called by any Full-protocol file; a human or a fast-lane script sets this before launching the
    job so `run()` picks the automatic-dispatch path without dagster_workflow.py ever knowing."""
    if mode not in DISPATCH_MODES:
        raise ValueError('unknown dispatch mode: ' + repr(mode) + ' (known: ' + ', '.join(sorted(DISPATCH_MODES)) + ')')
    path = dispatch_mode_path(run_id)
    value = read_json(path) if path.exists() else {}
    if not isinstance(value, dict):
        value = {}
    value[job] = mode
    atomic_json(path, value)
    return value

# Every other supplied-record gate's required upstream job: the same source_revision as the
# upstream's accepted result is required, plus that upstream must itself be accepted first.
# 02-dev-project-discovery and 02-devops-project-discovery both read the partition map directly
# (persona routing: developer-engineer vs devops-engineer partitions). 02-sre-operations-topology
# chains after 02-devops-project-discovery -- operations topology is read off the containers/
# services devops discovery already found, at the same revision.
UPSTREAM_JOB = {
    '02-dev-project-discovery': ADOPTED_JOB,
    '02-devops-project-discovery': ADOPTED_JOB,
    '02-sre-operations-topology': '02-devops-project-discovery',
}

# Job name -> the payload-shape validator (beyond schema) from validate_job_output.
_PAYLOAD_ERRORS = {
    '02-dev-project-discovery': 'project_discovery',
    '02-devops-project-discovery': 'project_discovery',
    '02-sre-operations-topology': 'operations_topology',
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


def _upstream_payload_filename(job):
    # The adopted partition gate writes its own dedicated artifact name; every other supplied
    # gate (this module's _legacy_run) writes the generic attempt/output.json shape.
    return 'repository-partition-map.json' if job == ADOPTED_JOB else 'output.json'


def _require_upstream_inputs(run_id, job, value):
    """Acceptance checks beyond the schema for every chained supplied-record gate (added
    2026-09-22 for 02-dev-project-discovery; generalized 2026-09-24 for
    02-devops-project-discovery and 02-sre-operations-topology).

    - The graph's declared dependency: an accepted upstream result for this run (UPSTREAM_JOB),
      at the same source revision as the supplied record.
    - The same content checks the adopted partition gate gets from validate_job_output: normalized
      repository paths, citation freshness against the staged target, no secret-like values and no
      finding/severity/runtime-state promotion.
    """
    import validate_job_output as vjo
    upstream = UPSTREAM_JOB[job]
    try:
        upstream_attempt = validate(run_id, upstream)
    except Blocked:
        raise
    except Exception as exc:
        raise Blocked(job + ': requires an accepted ' + upstream + ' result for this run first ('
                      + type(exc).__name__ + ')') from exc
    if upstream_attempt is None:
        raise Blocked(job + ': the accepted ' + upstream + ' result predates the common envelope; re-run it')
    upstream_value = read_json(upstream_attempt / _upstream_payload_filename(upstream))
    if value.get('source_revision') != upstream_value.get('source_revision'):
        raise Blocked(job + ': source_revision ' + str(value.get('source_revision'))
                      + ' does not match the accepted ' + upstream + ' (' + str(upstream_value.get('source_revision')) + ')')
    source_root, errors = vjo._source_root(run_path(run_id) / 'data', run_id)
    errors = list(errors)
    if source_root is not None:
        payload_kind = _PAYLOAD_ERRORS[job]
        if payload_kind == 'project_discovery':
            errors += vjo._project_discovery_errors(value, source_root)
        elif payload_kind == 'operations_topology':
            errors += vjo._operations_topology_errors(value, source_root)
    errors += vjo._secret_errors(value)
    errors += vjo._claim_promotion_errors(value, set(vjo.PROMOTION_FIELDS))
    if errors:
        raise Blocked(job + ': supplied result is invalid: ' + '; '.join(errors))


def _legacy_run(run_id, dagster_id, job, force=False):
    """Keep the unadopted developer-discovery gate behavior unchanged except schema coverage.

    The one addition (D02, generalized for D03): a run that opted a project-discovery job in
    ``AUTOMATIC_PROJECT_JOBS`` into automatic dispatch (``dispatch-mode.json``) is handed to
    ``_run_project_automatic`` before anything below runs. Every other job, and those jobs in the
    default ``supplied`` mode, take exactly the path they always did."""
    if job in AUTOMATIC_PROJECT_JOBS and dispatch_mode(run_id, job) == 'automatic':
        return _run_project_automatic(run_id, dagster_id, job, force)
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
    if job in UPSTREAM_JOB:
        _require_upstream_inputs(run_id, job, value)
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


def _backfill_citation_content_hashes(value, by_path):
    """Walks ``value`` exactly the way ``validate_job_output.py``'s own ``_walk_citations`` does
    (any dict key named ``evidence_citations`` holding a list of dicts, at any depth --
    partitions, their relationships, and coverage.category_checks all nest one), and for every
    ``source_type: source_file`` citation whose ``path`` resolves in ``by_path`` (this request's
    own pinned ``readable_inputs``, ``path`` -> bare-hex sha256), overwrites ``content_hash`` with
    that pinned value. Never fabricates a hash for a path that does not resolve -- an unresolved
    citation is left exactly as the persona wrote it, so independent re-validation (and
    ``validate_job_output.py``'s live citation-freshness check downstream) can legitimately reject
    it, per governing rule 2 ('a claim needs evidence that resolves'). **Why this exists (a real
    bug found live on hal5000, 2026-09-24, the same class as ``source_revision`` above):**
    ``content_hash`` is orchestrator-owned verification data -- the persona has no reliable way to
    compute a file's exact SHA-256 by hand, and its own guesses (when it attempted one at all)
    failed the freshness check's strict ``[0-9a-f]{64}`` format every time. The orchestrator
    already has the authoritative hash for every file it pinned into the request; trusting the
    model to reproduce it was never going to work reliably, so it is not asked to -- this function
    stamps the real value in, the same "caller owns provenance bookkeeping, the model owns
    evidence-derived content" split ``source_revision``'s fix above already draws."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key == 'evidence_citations' and isinstance(item, list):
                for citation in item:
                    if not isinstance(citation, dict) or citation.get('source_type') != 'source_file':
                        continue
                    sha256 = by_path.get(citation.get('path'))
                    if sha256:
                        citation['content_hash'] = sha256.split(':', 1)[-1]
            else:
                _backfill_citation_content_hashes(item, by_path)
    elif isinstance(value, list):
        for item in value:
            _backfill_citation_content_hashes(item, by_path)


def _validate_partition_payload(value):
    # Structural checks happen before copying; all cross-record/path/freshness semantics are owned
    # by validate_job_output's explicit repository-partition-map contract dispatch.
    return validate_document(value, SCHEMAS[ADOPTED_JOB])


def _validate_common(run_id, pointer):
    # The recomputed record must match whichever producer actually wrote the accepted attempt --
    # _run_partition's handoff-shaped record, or _run_partition_automatic's target/code-shaped
    # one -- or validate_published's own fingerprint check fails closed (never silently accepts a
    # supplied-path fingerprint against an automatic-path attempt, or vice versa).
    base = root(run_id, ADOPTED_JOB)
    if dispatch_mode(run_id, ADOPTED_JOB) == 'automatic':
        record = _automatic_partition_inputs(run_id)
    else:
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


def _automatic_target_root(run_id, job=ADOPTED_JOB):
    """The run's staged target checkout, sourced the same way validate_job_output.py's own
    citation-freshness check (`_source_root`) reads it -- `phase1.stage`'s manifest, never
    something this module invents. Raises Blocked (not a bare exception) so a missing/unstaged
    target surfaces as a normal preflight failure, exactly like the supplied path's missing-file
    check."""
    manifest = read_json(phase1.manifest_path(run_id))
    target = manifest.get('target') if isinstance(manifest, dict) else None
    repo_path = target.get('repo_path') if isinstance(target, dict) else None
    if not repo_path:
        raise Blocked(job + ': automatic dispatch requires a staged target '
                      '(phase1.stage) -- the run manifest has no target.repo_path')
    path = Path(repo_path)
    if not path.is_dir():
        raise Blocked(job + ': automatic dispatch target checkout is missing: ' + str(path))
    return path


def _automatic_partition_inputs(run_id):
    """The record automatic-mode dispatch fingerprints for reuse/tamper-evidence -- the target
    checkout's own content identity (never re-derived from an intermediate hand-off, since there
    is no hand-off in this path) plus the source of every module this path calls, mirroring
    _partition_inputs' 'code' block for the supplied path."""
    target_root = _automatic_target_root(run_id)
    identity = intake.source_identity(str(target_root))
    return {
        'job': ADOPTED_JOB,
        'mode': 'automatic',
        'target_root': str(target_root),
        'source_snapshot_sha256': 'sha256:' + identity['fingerprint'],
        'source_revision': identity.get('revision'),
        'code': {
            'discovery_gate.py': file_hash(Path(__file__)),
            'persona_dispatch.py': file_hash(ROOT / 'persona_dispatch.py'),
            'claude_cli_invoker.py': file_hash(ROOT / 'claude_cli_invoker.py'),
            'persona_invocation.py': file_hash(ROOT / 'persona_invocation.py'),
            'persona_prompt_assembly.py': file_hash(ROOT / 'persona_prompt_assembly.py'),
            'publish_job_output.py': file_hash(ROOT / 'publish_job_output.py'),
            'validate_job_output.py': file_hash(ROOT / 'validate_job_output.py'),
        },
    }


def _dispatch_partition_persona(run_id, dagster_id, allocation, record, fingerprint):
    """The automatic-dispatch execute_attempt body: builds one real persona invocation request,
    runs it through persona_invocation.run_invocation (B14's own validate/gate/invoke/re-derive/
    record adapter), and -- only on a genuinely OK completion -- materializes the two published
    artifacts at the SAME top-level attempt paths the supplied path already uses
    (attempt/repository-partition-map.json, attempt/repository-partition-summary.md), so
    _validate_common and every consumer job (02-dev-project-discovery, 02-devops-project-
    discovery) keep reading exactly the paths they already read; nothing about the accepted-
    pointer/consumer contract changes because the producer switched from a human hand-off to a
    live model call.

    A completed-but-not-OK persona_invocation result (the model's response failed schema/
    envelope validation, the invoker was unavailable, a budget/permission check failed, ...) is
    not a preflight error and not a value this function may quietly swallow: coordinate_worker_
    lifecycle's own contract (publish_job_output.py) only ever records a publishable terminal
    when execute_attempt returns normally (record_terminal_current requires execution_status in
    {OK, OK_WITH_GAPS, SKIPPED}); everything else must be represented by raising, so the
    coordinator's own terminal_for() records it as FAILED with the raised exception as cause --
    the exact path _run_partition's execute_attempt already uses for an invalid supplied payload
    (`raise ValueError(...)`). This function follows that established contract rather than
    inventing a second one.
    """
    attempt_id = allocation['attempt_id']
    attempt = allocation['attempt']
    started = allocation['started_at']
    target_root = Path(record['target_root'])
    source_snapshot_sha256 = record['source_snapshot_sha256']

    # Ensures a pinned model-versions record exists for this run; a no-op (loads the existing
    # pinned record unchanged) once the run's first automatic dispatch has resolved it, per
    # model_version_registry's own "a resumed run reuses exactly the versions its first run
    # resolved" contract.
    mvr.resolve_run_model_versions(run_id)

    store = SchemaStore()
    template = ppa.load_job_template(ADOPTED_JOB, store)
    budget_name = template.get('budget_default')
    resolved_model = rc.resolve_model(ADOPTED_JOB, budget_name)
    budget_usd = (rc.load_model_config().get('budget_max_usd_per_call') or {}).get(budget_name)

    def clock():
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    request = pd.build_request(
        ADOPTED_JOB, run_id=run_id, job_id=PERSONA_JOB_ID, attempt_id=attempt_id,
        target_root=target_root, source_snapshot_sha256=source_snapshot_sha256,
        now=clock(), store=store)
    model_identity = request['model']

    runtime = pi.PersonaRuntime(
        invoker=ClaudeCliInvoker(effort=resolved_model['effort'], budget_usd=budget_usd),
        registry_dir=pd.REGISTRY_DIR, prompt_root=ppa.PROMPT_ROOT,
        readable_roots={pd.DEFAULT_READABLE_ROOT: target_root},
        allowed_models=(model_identity,), source_snapshot_sha256=source_snapshot_sha256,
        registry_ceiling=None, clock=clock, cancel=threading.Event(), stop_grace_seconds=5)

    result = pi.run_invocation(
        runtime, run_id=run_id, job_id=PERSONA_JOB_ID, attempt_id=attempt_id,
        attempt_root=attempt, request=request)
    if result['execution_status'] != 'OK':
        raise RuntimeError(
            ADOPTED_JOB + ': persona dispatch did not complete OK (execution_status='
            + str(result.get('execution_status')) + ', cause=' + str(result.get('cause'))
            + ', outcome=' + str(result.get('outcome'))
            + '); see logs/persona under this attempt for the request/record/result triple')

    persona_output_root = attempt / Path(*request['output_root'].split('/'))
    partition_map = read_json(persona_output_root / 'repository-partition-map.json')
    # source_revision is orchestrator-owned provenance, not something the persona can know: D01's
    # readable_inputs deliberately exclude .git (persona_dispatch.py's _walk_target), the same
    # convention intake.source_identity's own exclusion follows, so the model has no VCS ref to
    # read at all. A real live dispatch confirmed this is not hypothetical: the model correctly
    # wrote "unknown (no VCS ref supplied ...)" rather than fabricate a revision it was never
    # given -- exactly the honest behavior governing rule 2 asks for -- but every downstream
    # consumer (citation-freshness checks, the SAT's own accept contract) expects this field to
    # equal the run's actual pinned revision. Overwritten here with the same authoritative value
    # _automatic_partition_inputs already computed from intake.source_identity (never trusted from
    # the model), the same "caller owns provenance bookkeeping, the model owns evidence-derived
    # content" split status.json's exclusion from the response envelope already draws.
    partition_map['source_revision'] = record['source_revision']
    # Same reasoning as source_revision just above, for a different field: every evidence
    # citation's content_hash must be the cited file's exact current SHA-256 (validate_job_
    # output.py's citation-freshness check, downstream of this gate), which the persona cannot
    # reliably reproduce by hand -- the orchestrator already has it, pinned per readable input.
    by_path = {entry['path']: entry['sha256'] for entry in request['readable_inputs']}
    _backfill_citation_content_hashes(partition_map, by_path)
    errors = _validate_partition_payload(partition_map)
    if errors:
        raise ValueError('persona dispatch result failed independent re-validation: '
                         + '; '.join(errors))
    summary_text = (persona_output_root / 'repository-partition-summary.md').read_text(encoding='utf-8')
    atomic_json(attempt / 'repository-partition-map.json', partition_map)
    atomic_bytes(attempt / 'repository-partition-summary.md', summary_text.encode('utf-8'))

    persona = request['persona']
    status = {'process': '02-evidence-pregather', 'status': 'OK', 'budget': budget_name,
              'persona_id': persona['persona_id'], 'role_id': persona['role_id'],
              'domain_id': persona['domain_id'], 'tooling_profile_id': persona['tooling_profile_id'],
              'artifacts_read': [entry['path'] for entry in request['readable_inputs']],
              'run_id': run_id, 'job': ADOPTED_JOB, 'attempt_id': attempt_id,
              'dagster_run_id': dagster_id, 'started_at': started, 'ended_at': now(),
              'fingerprint': fingerprint, 'dispatch_mode': 'automatic',
              'persona_job_id': PERSONA_JOB_ID, 'persona_result_sha256': result['result_sha256'],
              'model': dict(model_identity)}
    return record_terminal_current(
        root(run_id, ADOPTED_JOB), attempt, run_id=run_id, job_id=ADOPTED_JOB,
        dagster_run_id=dagster_id, worker_kind='persona',
        output_contract='repository-partition-map', input_fingerprint=fingerprint,
        started_at=started, execution_status='OK',
        summary='Live persona dispatch produced repository partition analysis.', status_record=status,
        artifact_paths=['repository-partition-map.json',
                        'repository-partition-summary.md', 'status.json'],
        consumer_job_id=CONSUMER_JOB)


def _run_partition_automatic(run_id, dagster_id, force=False):
    base = root(run_id, ADOPTED_JOB)
    resume = (f'python -B appsec-review-process/launch_job.py --run-id {run_id} '
              '--job full_review --wait')
    prepared = {}

    def derive_inputs():
        record = _automatic_partition_inputs(run_id)
        record['run_id'] = run_id
        record['fingerprint'] = _input_fingerprint(record)
        prepared['record'] = record
        return record

    def failure_inputs(exc):
        if 'record' in prepared:
            return prepared['record']
        return {
            'run_id': run_id, 'job': ADOPTED_JOB, 'mode': 'automatic',
            'preflight_error': f'{type(exc).__name__}: {exc}',
            'code': {'discovery_gate.py': file_hash(Path(__file__))},
        }

    def preflight_validate(record):
        target_root = Path(record['target_root'])
        if not target_root.is_dir():
            raise Blocked(ADOPTED_JOB + ': automatic dispatch target checkout is missing: '
                          + str(target_root))

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
        return _dispatch_partition_persona(run_id, dagster_id, allocation, record, fingerprint)

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=ADOPTED_JOB, dagster_run_id=dagster_id,
        worker_kind='persona', output_contract='repository-partition-map',
        resume_command=resume, derive_inputs=derive_inputs,
        fingerprint_inputs=lambda value: value.get('fingerprint') or _input_fingerprint(value),
        execute_attempt=execute_attempt, preflight_failure_inputs=failure_inputs,
        force=force, consumer_job_id=CONSUMER_JOB,
        preflight_validate=preflight_validate, post_validate=post_validate,
        on_reuse=on_reuse,
        blocked_summary='Repository partition automatic-dispatch preflight did not complete.',
        failed_summary='Automatic repository partition persona dispatch was not accepted.')


# ---- D02/D03: automatic persona dispatch for the project-discovery jobs (Phase 5c) ---------------
#
# One path serves 02-dev-project-discovery (D02) and 02-devops-project-discovery (D03), keyed by
# AUTOMATIC_PROJECT_JOBS. Deliberately NOT built on coordinate_worker_lifecycle/record_terminal_current
# the way D01's automatic path is: these jobs have never been on the common envelope (their accepted
# record is _legacy_run's small accepted.json/attempts/<id>/output.json shape, and its consumers --
# 02-build-configure, the SAT stage, validate() -- read exactly that). Moving it onto the envelope is
# a separate migration; this change only swaps the *source of the value*: a live persona call
# instead of a hand-supplied file, then the same schema check, the same upstream/citation-freshness
# checks (_require_upstream_inputs) and the same accepted-record shape as before. Nothing downstream
# has to change because the producer changed.

def _accepted_partition_map_path(run_id, job=CONSUMER_JOB):
    """(attempt dir, path of repository-partition-map.json) of the run's accepted D01 result,
    re-validated through ``validate`` -- never read straight off disk unchecked. ``job`` only names
    the asking job in a Blocked message."""
    try:
        attempt = validate(run_id, ADOPTED_JOB)
    except Blocked:
        raise
    except Exception as exc:
        raise Blocked(job + ': automatic dispatch requires an accepted ' + ADOPTED_JOB
                      + ' result for this run first (' + type(exc).__name__ + ')') from exc
    if attempt is None:
        raise Blocked(job + ': the accepted ' + ADOPTED_JOB + ' result predates the common '
                      'envelope; re-run it')
    path = attempt / _upstream_payload_filename(ADOPTED_JOB)
    if not path.is_file():
        raise Blocked(job + ': the accepted ' + ADOPTED_JOB + ' attempt has no ' + path.name)
    return attempt, path


def _automatic_project_inputs(run_id, job):
    """The record automatic-mode dispatch fingerprints for reuse/tamper-evidence: the target
    checkout's own content identity, the exact accepted partition map it was scoped by (so a
    changed or re-run upstream is a different input and never reuses an old result), and the source
    of every module this path calls."""
    target_root = _automatic_target_root(run_id, job)
    identity = intake.source_identity(str(target_root))
    upstream_attempt, map_path = _accepted_partition_map_path(run_id, job)
    return {
        'job': job,
        'mode': 'automatic',
        'target_root': str(target_root),
        'source_snapshot_sha256': 'sha256:' + identity['fingerprint'],
        'source_revision': identity.get('revision'),
        'upstream': {'job': ADOPTED_JOB, 'attempt_id': upstream_attempt.name,
                     'repository-partition-map.json': file_hash(map_path)},
        'code': {
            'discovery_gate.py': file_hash(Path(__file__)),
            'persona_dispatch.py': file_hash(ROOT / 'persona_dispatch.py'),
            'claude_cli_invoker.py': file_hash(ROOT / 'claude_cli_invoker.py'),
            'persona_invocation.py': file_hash(ROOT / 'persona_invocation.py'),
            'persona_prompt_assembly.py': file_hash(ROOT / 'persona_prompt_assembly.py'),
            'validate_job_output.py': file_hash(ROOT / 'validate_job_output.py'),
        },
    }


def _stage_upstream_partition_map(base, map_path, expected_sha256):
    """Copies the accepted partition map into a content-addressed directory of its own (the one
    directory the job's second readable root points at) and verifies the copy. The directory holds
    only this one file: persona_dispatch pins every regular file beneath an upstream root. An
    existing copy whose bytes no longer match is a tamper/corruption signal, not something to
    overwrite. ``base`` is the job's own root, so ``base.name`` is the job id."""
    directory = base / 'upstream' / expected_sha256[:16]
    target = directory / 'repository-partition-map.json'
    if not target.is_file():
        directory.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(map_path, target)
    if file_hash(target) != expected_sha256:
        raise Blocked(base.name + ': the staged upstream partition map does not match the accepted '
                      'partition map it was copied from')
    return directory


def _dispatch_project_persona(run_id, base, record):
    """One real persona invocation for the project-discovery job named by ``record['job']``
    (``AUTOMATIC_PROJECT_JOBS``). Returns ``(value, summary_text,
    facts)``; raises ``RuntimeError`` (like D01's ``_dispatch_partition_persona``) when the
    invocation did not complete OK -- nothing is ever published from a failed dispatch. The
    persona's own attempt tree (request/record/result triple, model output) is kept under
    ``persona-attempts/<id>/`` for review; it is not the published attempt.

    Orchestrator-owned fields (docs/lessons-learned-2026-09-24-d01-live-dispatch.md, lesson 2),
    overwritten after the model responds and never trusted from it: ``source_revision`` (a git ref
    the model cannot see, ``.git`` is not a readable input), every ``evidence_citations[].content_hash``
    (an exact SHA-256), and ``target`` (taken from the accepted partition map this job was scoped
    by, so the two records of one run cannot name different targets)."""
    job = record['job']
    persona_job_id = AUTOMATIC_PROJECT_JOBS[job]
    attempt_id = uuid.uuid4().hex
    persona_attempt = base / 'persona-attempts' / attempt_id
    persona_attempt.mkdir(parents=True)
    target_root = Path(record['target_root'])
    snapshot = record['source_snapshot_sha256']
    _upstream_attempt, map_path = _accepted_partition_map_path(run_id, job)
    upstream_dir = _stage_upstream_partition_map(
        base, map_path, record['upstream']['repository-partition-map.json'])

    mvr.resolve_run_model_versions(run_id)
    store = SchemaStore()
    template = ppa.load_job_template(job, store)
    budget_name = template.get('budget_default')
    resolved_model = rc.resolve_model(job, budget_name)
    budget_usd = (rc.load_model_config().get('budget_max_usd_per_call') or {}).get(budget_name)

    def clock():
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    request = pd.build_request(
        job, run_id=run_id, job_id=persona_job_id, attempt_id=attempt_id,
        target_root=target_root, source_snapshot_sha256=snapshot, now=clock(), store=store,
        upstream_root=upstream_dir)
    model_identity = request['model']
    runtime = pi.PersonaRuntime(
        invoker=ClaudeCliInvoker(effort=resolved_model['effort'], budget_usd=budget_usd),
        registry_dir=pd.REGISTRY_DIR, prompt_root=ppa.PROMPT_ROOT,
        readable_roots={pd.DEFAULT_READABLE_ROOT: target_root, pd.UPSTREAM_ROOT_ID: upstream_dir},
        allowed_models=(model_identity,), source_snapshot_sha256=snapshot,
        registry_ceiling=None, clock=clock, cancel=threading.Event(), stop_grace_seconds=5)
    result = pi.run_invocation(
        runtime, run_id=run_id, job_id=persona_job_id, attempt_id=attempt_id,
        attempt_root=persona_attempt, request=request)
    if result['execution_status'] != 'OK':
        raise RuntimeError(
            job + ': persona dispatch did not complete OK (execution_status='
            + str(result.get('execution_status')) + ', cause=' + str(result.get('cause'))
            + ', outcome=' + str(result.get('outcome')) + '); see persona-attempts/' + attempt_id
            + '/logs/persona for the request/record/result triple')

    output_root = persona_attempt / Path(*request['output_root'].split('/'))
    value = read_json(output_root / 'project-inventory.json')
    upstream_map = read_json(upstream_dir / 'repository-partition-map.json')
    value['source_revision'] = record['source_revision']
    if isinstance(upstream_map, dict) and isinstance(upstream_map.get('target'), str):
        value['target'] = upstream_map['target']
    by_path = {entry['path']: entry['sha256'] for entry in request['readable_inputs']
               if entry['root'] == pd.DEFAULT_READABLE_ROOT}
    _backfill_citation_content_hashes(value, by_path)
    summary_text = (output_root / 'project-discovery-summary.md').read_text(encoding='utf-8')
    facts = {'dispatch_mode': 'automatic', 'persona_job_id': persona_job_id,
             'persona_attempt_id': attempt_id, 'persona_result_sha256': result['result_sha256'],
             'model': dict(model_identity)}
    return value, summary_text, facts


def _run_project_automatic(run_id, dagster_id, job, force=False):
    if job not in AUTOMATIC_PROJECT_JOBS:
        raise Blocked(job + ': has no automatic persona dispatch path')
    base = root(run_id, job)
    record = _automatic_project_inputs(run_id, job)
    record['run_id'] = run_id
    fingerprint = _input_fingerprint(record)
    if not force and (base / 'accepted.json').exists():
        candidate = read_json(base / 'accepted.json')
        if candidate.get('fingerprint') == fingerprint and candidate.get('status') == 'OK':
            atomic_json(data_path(run_id, 'orchestration', 'dagster', dagster_id, job + '-reuse.json'),
                        {'status': 'OK', 'reused': True, 'producer': candidate, 'time': now()})
            return candidate
    value, summary_text, facts = _dispatch_project_persona(run_id, base, record)
    if not isinstance(value, dict) or not value:
        raise Blocked(job + ': persona dispatch result is empty or not a JSON object')
    errors = validate_document(value, SCHEMAS[job])
    if errors:
        raise Blocked(job + ': persona dispatch result failed schema validation: ' + '; '.join(errors))
    _require_upstream_inputs(run_id, job, value)
    attempt_id = uuid.uuid4().hex
    attempt = base / 'attempts' / attempt_id
    attempt.mkdir(parents=True)
    atomic_json(attempt / 'inputs.json', {**record, 'fingerprint': fingerprint})
    atomic_json(attempt / 'output.json', value)
    atomic_bytes(attempt / 'project-discovery-summary.md', summary_text.encode('utf-8'))
    accepted = {'status': 'OK', 'job': job, 'run_id': run_id, 'attempt_id': attempt_id,
                'dagster_run_id': dagster_id, 'fingerprint': fingerprint, 'accepted_at': now(),
                **facts}
    atomic_json(attempt / 'status.json', accepted)
    atomic_json(base / 'accepted.json', accepted)
    atomic_json(base / 'latest.json', {'attempt_id': attempt_id})
    return {**accepted, 'output': value}


def run(run_id, dagster_id, job, force=False):
    if job == ADOPTED_JOB:
        if dispatch_mode(run_id, job) == 'automatic':
            return _run_partition_automatic(run_id, dagster_id, force)
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
