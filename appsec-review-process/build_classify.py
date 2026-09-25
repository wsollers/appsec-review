"""02-build-classify: the model classifies every build unit and checks the index's work.

ADR-0012 Revision 1 decision 3 and Revision 2 (docs/processes/build-unit-classification.md). One
live persona call (`claude-sonnet-5`/`medium`, the job template's own pin) reads the whole target
checkout plus the accepted `build-index.json` (staged as an upstream artifact: scope, never
citable evidence) and returns `build-classification.json`: one class per index unit (or two or more
parts for a mixed unit), the index signals and checkout files each class rests on, and
`index_review`, where the model records what the deterministic index got wrong. Disagreements are
recorded, never applied.

The model owns the evidence-derived content. The orchestrator owns provenance and derivations and
overwrites them after the response (docs/lessons-learned-2026-09-24-d01-live-dispatch.md, lesson 2):
`source_revision`, `target`, `index` (the accepted index attempt and its sha256), `build_set` (the
units classed compiled-native, compiled-managed or transpiled) and every citation `content_hash`.

`check` is the deterministic validator (pure; fixture-tested). `run` / `validate` are the graph
node's worker on the common worker-result envelope (`persona`), modeled on D01's automatic path.
Status `OK`, or `OK_WITH_GAPS` when a unit is unclassified or `coverage_gaps` is non-empty; an
`index_review` item alone does not make a gap (William, 2026-09-25).
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import threading

import build_index
from claude_cli_invoker import ClaudeCliInvoker
import discovery_gate
from execution_state import (ROOT, Blocked, atomic_bytes, atomic_json, data_path, digest, file_hash,
                             identifier, now, read_json)
import model_version_registry as mvr
import persona_dispatch as pd
import persona_invocation as pi
import persona_prompt_assembly as ppa
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
import review_cli as rc
from schema_validate import SchemaStore, validate_document
import validate_job_output as vjo

JOB = '02-build-classify'
CONTRACT = 'build-classification'
# Short and opaque, like D01-D04's persona identities (permission_capabilities' secret scanner).
PERSONA_JOB_ID = 'b01-classify'
RESULT = 'build-classification.json'
SUMMARY = 'build-classification-summary.md'
UPSTREAM_NAME = 'build-index.json'
BUILD_SET_CLASSES = ('compiled-native', 'compiled-managed', 'transpiled')
PART_RE = re.compile(r'^(?P<base>(?:dir|file):\S+?)::(?P<part>[a-z0-9][a-z0-9-]*)$')
CODE_FILES = ('build_classify.py', 'build_index.py', 'discovery_gate.py', 'persona_dispatch.py',
              'persona_invocation.py', 'persona_prompt_assembly.py', 'claude_cli_invoker.py',
              'publish_job_output.py', 'validate_job_output.py',
              'registry/job-templates/02-build-classify.json',
              'registry/output-contracts/build-classification.json',
              '02-evidence-pregather/task-build-classify.md')


def root(run_id):
    return data_path(run_id, 'jobs', JOB)


# --- deterministic validation -----------------------------------------------------------------

def _under(path, base):
    return base == '.' or path == base or path.startswith(base + '/')


def _relative_path_error(value, allow_dot=False):
    if not isinstance(value, str) or not value:
        return 'must be a non-empty repository-relative path'
    if value == '.':
        return None if allow_dot else 'must name a path, not "."'
    if value.startswith('/') or re.match(r'^[A-Za-z]:', value) or '\\' in value:
        return 'must be repository-relative with forward slashes'
    if any(part in ('', '.', '..') for part in value.split('/')):
        return 'must be a normalized repository-relative path'
    return None


def derived_build_set(value):
    return sorted(u['unit_id'] for u in value.get('units', []) if u.get('class') in BUILD_SET_CLASSES)


def check(value, index, *, index_attempt_id, index_sha256, source_revision=None):
    """Errors (empty when valid) for a classification against the accepted index it read. Checks
    what the schema subset cannot: every index unit covered exactly once (as itself, or as two or
    more parts), part ids derived from their unit, roots inside their unit, signal ids resolving in
    the index, unclassified units named in coverage_gaps, the orchestrator-owned fields, and
    index_review paths and unit ids. Citation freshness is checked separately against the checkout
    (validate_job_output._citation_errors)."""
    errors = list(validate_document(value, 'build-classification.schema.json'))
    if errors:
        return errors
    if value['index'] != {'attempt_id': index_attempt_id, 'sha256': index_sha256}:
        errors.append('index does not name the accepted build index attempt and its sha256')
    if source_revision is not None and value['source_revision'] != source_revision:
        errors.append('source_revision is not the accepted revision')
    if value['source_revision'] != index.get('source_revision'):
        errors.append('source_revision differs from the index it classifies')
    index_units = {u['unit_id']: u for u in index.get('units', [])}
    signal_ids = {s['signal_id'] for s in index.get('signals', [])}
    entries = {}
    seen = set()
    for n, unit in enumerate(value['units']):
        where = f'units[{n}] {unit["unit_id"]}'
        uid, iuid = unit['unit_id'], unit['index_unit_id']
        if uid in seen:
            errors.append(where + ': unit_id repeats')
        seen.add(uid)
        if iuid not in index_units:
            errors.append(where + ': index_unit_id is not a unit of the accepted index')
            continue
        if uid != iuid:
            m = PART_RE.match(uid)
            if not m or m.group('base') != iuid:
                errors.append(where + ': a part id must be "<index_unit_id>::<part>" (lower-case letters, digits, hyphens)')
        entries.setdefault(iuid, []).append(unit)
        index_root = index_units[iuid]['root']
        root_error = _relative_path_error(unit['root'], allow_dot=True)
        if root_error:
            errors.append(where + ': root ' + root_error)
        elif uid == iuid and unit['root'] != index_root:
            errors.append(where + f': root {unit["root"]!r} is not the index unit root {index_root!r}')
        elif uid != iuid and not _under(unit['root'], index_root):
            errors.append(where + f': part root {unit["root"]!r} is outside the index unit root {index_root!r}')
        for sid in unit['signal_ids']:
            if sid not in signal_ids:
                errors.append(where + f': signal {sid} is not in the accepted index')
        if unit['class'] == 'unclassified' and not any(uid in gap for gap in value['coverage_gaps']):
            errors.append(where + ': an unclassified unit must be named in coverage_gaps')
    for iuid in index_units:
        got = entries.get(iuid, [])
        whole = [u for u in got if u['unit_id'] == iuid]
        parts = [u for u in got if u['unit_id'] != iuid]
        if not got:
            errors.append(f'index unit {iuid} is not classified')
        elif whole and parts:
            errors.append(f'index unit {iuid} is classified both whole and in parts')
        elif parts and len(parts) < 2:
            errors.append(f'index unit {iuid} is split into a single part (a split needs two or more)')
    if value['build_set'] != derived_build_set(value):
        errors.append('build_set is not exactly the units classed ' + ', '.join(BUILD_SET_CLASSES))
    for n, item in enumerate(value['index_review']):
        path_error = _relative_path_error(item['path'], allow_dot=True)
        if path_error:
            errors.append(f'index_review[{n}].path ' + path_error)
        if item.get('unit_id') is not None and item['unit_id'] not in index_units:
            errors.append(f'index_review[{n}].unit_id is not a unit of the accepted index')
    return errors


def finalize(value, *, index, index_attempt_id, index_sha256, source_revision, pinned):
    """Overwrite the orchestrator-owned fields in place (never trusted from the model)."""
    value['source_revision'] = source_revision
    if isinstance(index.get('target'), str) and index['target']:
        value['target'] = index['target']
    value['index'] = {'attempt_id': index_attempt_id, 'sha256': index_sha256}
    value['build_set'] = derived_build_set(value) if isinstance(value.get('units'), list) else []
    discovery_gate._backfill_citation_content_hashes(value, pinned)
    return value


def gaps_of(value):
    gaps = [str(g) for g in value.get('coverage_gaps', []) if str(g).strip()]
    for unit in value.get('units', []):
        if unit.get('class') == 'unclassified':
            gaps.append(f'Unit {unit["unit_id"]} could not be classified from the evidence.')
    return sorted(set(gaps))


# --- run-level worker -------------------------------------------------------------------------

def _code_hashes():
    return {name: file_hash(ROOT / name) for name in CODE_FILES} | {
        'schemas/build-classification.schema.json': file_hash(ROOT.parent / 'schemas' / 'build-classification.schema.json')}


def current_inputs(run_id):
    """The fingerprinted input record: the checkout, the accepted build index (re-validated end to
    end by build_index.validate, which also re-checks intake and every discovery upstream) pinned by
    hash, and the code that runs. The model version is pinned per run by model_version_registry."""
    target = build_index._target_root(run_id)
    index_attempt = build_index.validate(run_id)
    index_path = index_attempt / 'build-index.json'
    index = read_json(index_path)
    return {'job': JOB, 'target_root': str(target),
            'source_snapshot_sha256': 'sha256:' + index['source_fingerprint'],
            'source_revision': index['source_revision'],
            'upstream': {'job': build_index.JOB, 'attempt_id': index_attempt.name,
                         UPSTREAM_NAME: file_hash(index_path)},
            'code': _code_hashes()}


def _accepted_index(run_id, record):
    upstream = record['upstream']
    path = build_index.root(run_id) / 'attempts' / identifier(upstream['attempt_id']) / 'build-index.json'
    if not path.is_file() or file_hash(path) != upstream[UPSTREAM_NAME]:
        raise Blocked(f'{JOB}: the accepted build index changed since the attempt inputs were recorded')
    return path, read_json(path)


def dispatch(run_id, base, record, attempt_id):
    """One live persona invocation. Returns (value, summary_text, facts, pinned) where pinned maps
    each checkout path the model was shown to its sha256. Raises RuntimeError when the invocation
    did not complete OK: nothing is published from a failed dispatch. The persona's own attempt tree
    (request, record, result, model output) is kept under persona-attempts/<attempt_id>/."""
    index_path, _index = _accepted_index(run_id, record)
    upstream_dir = discovery_gate._stage_upstream_files(
        base, {UPSTREAM_NAME: (index_path, record['upstream'][UPSTREAM_NAME])})
    persona_attempt = base / 'persona-attempts' / attempt_id
    persona_attempt.mkdir(parents=True)
    target_root = Path(record['target_root'])
    snapshot = record['source_snapshot_sha256']

    mvr.resolve_run_model_versions(run_id)
    store = SchemaStore()
    template = ppa.load_job_template(JOB, store)
    budget_name = template.get('budget_default')
    resolved_model = rc.resolve_model(JOB, budget_name)
    budget_usd = (rc.load_model_config().get('budget_max_usd_per_call') or {}).get(budget_name)

    def clock():
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    request = pd.build_request(JOB, run_id=run_id, job_id=PERSONA_JOB_ID, attempt_id=attempt_id,
                               target_root=target_root, source_snapshot_sha256=snapshot, now=clock(),
                               store=store, upstream_root=upstream_dir)
    model_identity = request['model']
    runtime = pi.PersonaRuntime(
        invoker=ClaudeCliInvoker(effort=resolved_model['effort'], budget_usd=budget_usd),
        registry_dir=pd.REGISTRY_DIR, prompt_root=ppa.PROMPT_ROOT,
        readable_roots={pd.DEFAULT_READABLE_ROOT: target_root, pd.UPSTREAM_ROOT_ID: upstream_dir},
        allowed_models=(model_identity,), source_snapshot_sha256=snapshot,
        registry_ceiling=None, clock=clock, cancel=threading.Event(), stop_grace_seconds=5)
    result = pi.run_invocation(runtime, run_id=run_id, job_id=PERSONA_JOB_ID, attempt_id=attempt_id,
                               attempt_root=persona_attempt, request=request)
    if result['execution_status'] != 'OK':
        raise RuntimeError(
            f'{JOB}: persona dispatch did not complete OK (execution_status='
            f'{result.get("execution_status")}, cause={result.get("cause")}, '
            f'outcome={result.get("outcome")}); see persona-attempts/{attempt_id}/logs/persona')
    output_root = persona_attempt / Path(*request['output_root'].split('/'))
    value = read_json(output_root / RESULT)
    summary = (output_root / SUMMARY).read_text(encoding='utf-8')
    pinned = {e['path']: e['sha256'] for e in request['readable_inputs'] if e['root'] == pd.DEFAULT_READABLE_ROOT}
    facts = {'dispatch_mode': 'automatic', 'persona_job_id': PERSONA_JOB_ID, 'persona_attempt_id': attempt_id,
             'persona_result_sha256': result['result_sha256'], 'model': dict(model_identity)}
    return value, summary, facts, pinned


def _validate_attempt(run_id, attempt, record):
    if read_json(attempt / 'inputs.json') != record:
        raise Blocked(f'{JOB}: immutable attempt inputs changed')
    _path, index = _accepted_index(run_id, record)
    value = read_json(attempt / RESULT)
    errors = check(value, index, index_attempt_id=record['upstream']['attempt_id'],
                   index_sha256=record['upstream'][UPSTREAM_NAME], source_revision=record['source_revision'])
    errors += vjo._citation_errors(value, Path(record['target_root']))
    if errors:
        raise Blocked(f'{JOB}: classification is invalid: ' + '; '.join(errors[:20]))


def run(run_id, dagster_id, force=False):
    base = root(run_id)
    resume = f'python -B appsec-review-process/launch_job.py --run-id {run_id} --job build_classify --wait'

    def execute_attempt(allocation, record, fingerprint):
        attempt, attempt_id, started = allocation['attempt'], allocation['attempt_id'], allocation['started_at']
        _path, index = _accepted_index(run_id, record)
        value, summary, facts, pinned = dispatch(run_id, base, record, attempt_id)
        if not isinstance(value, dict):
            raise ValueError(f'{JOB}: the persona result is not a JSON object')
        finalize(value, index=index, index_attempt_id=record['upstream']['attempt_id'],
                 index_sha256=record['upstream'][UPSTREAM_NAME], source_revision=record['source_revision'],
                 pinned=pinned)
        errors = check(value, index, index_attempt_id=record['upstream']['attempt_id'],
                       index_sha256=record['upstream'][UPSTREAM_NAME], source_revision=record['source_revision'])
        errors += vjo._citation_errors(value, Path(record['target_root']))
        if errors:
            raise ValueError(f'{JOB}: persona result failed independent validation: ' + '; '.join(errors[:20]))
        atomic_json(attempt / RESULT, value)
        atomic_bytes(attempt / SUMMARY, summary.encode('utf-8'))
        if record['code'] != _code_hashes():
            raise Blocked(f'{JOB}: implementation changed during work')
        gaps = gaps_of(value)
        template = read_json(ROOT / 'registry' / 'job-templates' / f'{JOB}.json')
        composition = template['composition']
        status = {'process': '02-evidence-pregather', 'budget': template.get('budget_default'),
                  'persona_id': composition['persona_id'], 'role_id': composition['role_id'],
                  'domain_id': composition['domain_id'], 'tooling_profile_id': composition['tooling_profile_id'],
                  'artifacts_read': sorted(pinned) + [f'{build_index.JOB}:{UPSTREAM_NAME}'],
                  'source_revision': value['source_revision'], 'units': len(value['units']),
                  'build_set': value['build_set'], 'index_review': len(value['index_review']),
                  'run_id': run_id, 'job': JOB, 'attempt_id': attempt_id, 'dagster_run_id': dagster_id,
                  'started_at': started, 'fingerprint': fingerprint, **facts}
        classes = ', '.join(f'{u["unit_id"]}={u["class"]}' for u in value['units'])
        return record_terminal_current(
            base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id, worker_kind='persona',
            output_contract=CONTRACT, input_fingerprint=fingerprint, started_at=started,
            execution_status='OK_WITH_GAPS' if gaps else 'OK',
            summary=f'Build units classified: {classes}; {len(value["index_review"])} index disagreement(s).'[:1000],
            status_record=status, artifact_paths=[RESULT, SUMMARY, 'status.json'], gaps=gaps or None,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, record))

    def on_reuse(admitted):
        atomic_json(data_path(run_id, 'orchestration', 'dagster', dagster_id, JOB + '-reuse.json'),
                    {'status': admitted['envelope']['execution_status'], 'reused': True,
                     'publication_recovered': admitted['recovered_publication'],
                     'producer': admitted['pointer'], 'time': now()})

    def failure_inputs(exc):
        return {'run_id': run_id, 'job': JOB, 'preflight_error': f'{type(exc).__name__}: {exc}',
                'code': _code_hashes()}

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id, worker_kind='persona',
        output_contract=CONTRACT, resume_command=resume, derive_inputs=lambda: current_inputs(run_id),
        fingerprint_inputs=lambda value: 'sha256:' + digest(value), execute_attempt=execute_attempt,
        preflight_failure_inputs=failure_inputs, force=force,
        post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, attempt, record),
        on_reuse=on_reuse,
        blocked_summary='Build classification preflight did not complete (the build index is not accepted or stale).',
        failed_summary='Build classification was not published.')


def validate(run_id, pointer=None):
    """The accepted attempt directory, re-validated end to end (for 02-build-plan and the SAT)."""
    base = root(run_id)
    pointer = pointer or read_json(base / 'accepted.json')
    record = current_inputs(run_id)
    attempt, _envelope = validate_published(base, pointer, 'sha256:' + digest(record),
                                            expected_run_id=run_id, expected_job_id=JOB)
    _validate_attempt(run_id, attempt, record)
    return attempt


def validate_published_value(attempt_root, value, source_root, run_id):
    """validate_job_output's content check for this contract: locate the index the result names in
    the owning run, verify its hash, and run check and citation freshness."""
    errors = []
    index_ref = value.get('index') if isinstance(value, dict) else None
    if not isinstance(index_ref, dict):
        return ['build classification names no index']
    owner = vjo._owning_run_root(Path(attempt_root), run_id)
    if owner is None:
        return ['cannot locate the owning run for the build index']
    try:
        path = owner / 'data' / 'jobs' / build_index.JOB / 'attempts' / identifier(index_ref.get('attempt_id')) / 'build-index.json'
    except ValueError:
        return ['build classification names an invalid index attempt id']
    if not path.is_file() or file_hash(path) != index_ref.get('sha256'):
        return ['the build index this classification names is missing or changed']
    errors += check(value, read_json(path), index_attempt_id=index_ref['attempt_id'], index_sha256=index_ref['sha256'])
    errors += vjo._citation_errors(value, source_root)
    return errors


if __name__ == '__main__':
    import json
    import sys
    attempt = validate(sys.argv[1])  # usage: build_classify.py <run_id>
    print(json.dumps({'status': 'PASS', 'attempt': str(attempt)}))
