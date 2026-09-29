"""Generic executor for new-style pipeline items (ADR-0024 decision 8).

An item is a directory `items/<job-id>/` holding `item.json` (needs, argv worker, grants, params,
implementation files, declared outputs), `input.schema.json` and `output.schema.json`. One generic
Dagster op runs every item in three phases:

PRE      resolve each need from its producer's accepted output, validate the input document, pass it
         through the existing redaction filter on its way to the worker (only redaction metadata is
         recorded, never values), and compute input content/shape hashes and the fingerprint.
PROCESS  run the declared worker: an argv array (never a shell string) under the bounded process
         runner, with the declared grants. Host workers only: container grants are refused until an
         item needs them.
POST     validate the worker result against `output.schema.json`, write the coverage/gap record (a
         worker that did not run or did not finish is a gap, never "no findings"), write the receipt
         (status, resume_from, rerun_command, fingerprint, mode), run the optional pass-through
         normaliser (SARIF 2.1.0 / CycloneDX; no conversion), and publish through publish_job_output.

Prod: the fingerprint covers the input content, the upstream lineage (attempt ids), own and related
implementation files, params and the mode; reuse needs an identical fingerprint and a prod receipt.
Dev (APPSEC_RUN_MODE=dev): dev_restart decides from input content and shape and own files only, with
early cutoff and rewind of item producers. Dev receipts are never evidence.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import sys
from typing import Any, Iterable

import dev_restart as dr
from execution_state import (ROOT, Blocked, Lock, atomic_bytes, atomic_json, data_path, digest, execute,
                             file_hash, identifier, now, read_json, run_path)
from publish_job_output import (ACCEPTED_SCHEMA, coordinate_worker_lifecycle, record_terminal_current,
                                validate_published)
from schema_validate import SchemaStore, validate

ITEMS_ROOT = ROOT / 'items'
ITEM_SCHEMA = 'appsec-review/pipeline-item/1'
INPUT_SCHEMA = 'appsec-review/item-input/1'
RECORD_SCHEMA = 'appsec-review/item-inputs/1'
COVERAGE_SCHEMA = 'appsec-review/item-coverage/1'
WORKER_RESULT = 'worker-result.json'
PUBLISHABLE = ('OK', 'OK_WITH_GAPS', 'SKIPPED')
SHELLS = {'sh', 'bash', 'dash', 'zsh', 'ksh', 'fish', 'cmd', 'cmd.exe', 'powershell', 'pwsh',
          'powershell.exe', 'pwsh.exe'}
PLACEHOLDER = re.compile(r'\{([a-z_]+)\}')
ARGV_KEYS = {'python', 'item', 'job_id', 'run_id', 'attempt_id', 'input', 'output'}
NORMALISERS = {'sarif-2.1.0', 'cyclonedx'}


# --- items -------------------------------------------------------------------------------------

class Item:
    def __init__(self, root: Path, spec: dict[str, Any]):
        self.root, self.spec = Path(root), spec
        self.job_id = spec['job_id']

    def __getitem__(self, key):
        return self.spec[key]

    def get(self, key, default=None):
        return self.spec.get(key, default)

    def schema(self, name: str) -> dict[str, Any]:
        return read_json(self.root / name)


def item_ids(items_root: Path | None = None) -> list[str]:
    root = Path(items_root or ITEMS_ROOT)
    return sorted(p.parent.name for p in root.glob('*/item.json')) if root.is_dir() else []


def load_item(job_id: str, items_root: Path | None = None) -> Item | None:
    root = Path(items_root or ITEMS_ROOT) / job_id
    if not (root / 'item.json').is_file():
        return None
    item = Item(root, read_json(root / 'item.json'))
    errors = check_item(item)
    if errors:
        raise Blocked(f'{job_id}: item definition is invalid: ' + '; '.join(errors))
    return item


def check_item(item: Item) -> list[str]:
    """Structural rules the executor enforces before it will run anything."""
    spec, errors = item.spec, []
    if spec.get('schema') != ITEM_SCHEMA:
        errors.append(f'schema must be {ITEM_SCHEMA}')
    if spec.get('job_id') != item.root.name:
        errors.append('job_id must equal the item directory name')
    for key in ('output_contract', 'worker_kind'):
        if not isinstance(spec.get(key), str) or not spec[key]:
            errors.append(f'{key} is required')
    for name in ('input.schema.json', 'output.schema.json'):
        if not (item.root / name).is_file():
            errors.append(f'{name} is missing')
    needs = spec.get('needs')
    if not isinstance(needs, list) or not needs:
        errors.append('needs must list at least one upstream')
    else:
        names = [need.get('as') for need in needs if isinstance(need, dict)]
        if len(names) != len(needs) or len(set(names)) != len(names):
            errors.append('every need has a unique `as` name')
        for need in needs:
            if isinstance(need, dict) and need.get('resolve') not in RESOLVERS:
                errors.append(f"unknown resolver {need.get('resolve')!r}")
    worker = spec.get('worker') or {}
    argv = worker.get('argv')
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
        errors.append('worker.argv must be a non-empty array of strings (never a shell string)')
    else:
        if Path(argv[0]).name.lower() in SHELLS:
            errors.append('worker.argv must not start a shell')
        for arg in argv:
            unknown = set(PLACEHOLDER.findall(arg)) - ARGV_KEYS
            if unknown:
                errors.append(f'worker.argv uses unknown placeholder(s) {sorted(unknown)}')
    grants = worker.get('grants')
    if not isinstance(grants, dict) or 'container' not in grants or 'network' not in grants:
        errors.append('worker.grants must declare container and network')
    elif grants['container'] is not None or grants['network'] is not False:
        errors.append('only host workers without network are executable (container items: TODO brief I)')
    if not isinstance(worker.get('timeout_seconds'), int) or worker['timeout_seconds'] <= 0:
        errors.append('worker.timeout_seconds must be a positive integer')
    implementation = spec.get('implementation') or {}
    own = implementation.get('own')
    if not isinstance(own, list) or not own:
        errors.append('implementation.own must list the job\'s own files')
    for name in [*(own or []), *implementation.get('related', [])]:
        if not _code_path(item, name).is_file():
            errors.append(f'implementation file missing: {name}')
    outputs = spec.get('outputs') or {}
    artifacts = outputs.get('artifacts')
    if not isinstance(artifacts, list) or not artifacts or 'status.json' not in artifacts:
        errors.append('outputs.artifacts must list the published files, status.json included')
    elif any('/' in name or name in {'result.json', 'inputs.json', dr.RECEIPT_NAME, 'coverage.json'}
             for name in artifacts):
        errors.append('outputs.artifacts are flat names and may not shadow executor files')
    normalise = spec.get('normalise')
    if normalise is not None and (normalise.get('format') not in NORMALISERS or
                                  normalise.get('mode') != 'pass-through' or
                                  normalise.get('artifact') not in (artifacts or [])):
        errors.append('normalise is a pass-through of a declared artifact in SARIF 2.1.0 or CycloneDX')
    return errors


def _code_path(item: Item, name: str) -> Path:
    """Keys are process-root relative, `schemas/...` keys repository relative (as in every
    `_code_hashes`), and `items/<job>/...` keys name files in the item's own directory."""
    prefix = f'items/{item.job_id}/'
    if name.startswith(prefix):
        return item.root / name[len(prefix):]
    return (ROOT.parent if name.startswith('schemas/') else ROOT) / name


def _item_files(item: Item) -> list[str]:
    return sorted(f'items/{item.job_id}/{p.relative_to(item.root).as_posix()}' for p in item.root.rglob('*')
                  if p.is_file() and '__pycache__' not in p.parts)


def own_hashes(item: Item) -> dict[str, str]:
    """Rule 6: the item's own definition and implementation files."""
    names = sorted(set(item['implementation']['own']) | set(_item_files(item)))
    return {name: file_hash(_code_path(item, name)) for name in names}


def related_hashes(item: Item) -> dict[str, str]:
    """Files other jobs own that this item reads. Part of the prod fingerprint only."""
    return {name: file_hash(_code_path(item, name)) for name in sorted(item['implementation'].get('related', []))}


# --- PRE: resolvers ----------------------------------------------------------------------------

def _resolve_intake_source(run_id: str, need: dict[str, Any]):
    """The accepted, fresh intake: target, source binding and source inventory."""
    import phase1
    pointer = phase1.accepted(run_id, phase1.JOB, fresh=True)
    if pointer is None or pointer.get('status') != 'OK':
        raise Blocked('exact accepted intake is required')
    base = phase1.job_root(run_id, phase1.JOB, 'whole')
    attempt = base / 'attempts' / pointer['attempt_id']
    source = read_json(attempt / 'evidence/source.json')
    if source.get('fingerprint') != read_json(attempt / 'outputs/intake.json').get('source_fingerprint'):
        raise Blocked('intake source identity mismatch')
    target = Path(source['target'])
    if not target.is_absolute() or not target.is_dir() or target.is_symlink():
        raise Blocked('intake target is not a real absolute directory')
    binding = {'job_id': phase1.JOB, 'attempt_id': pointer['attempt_id'],
               'fingerprint': pointer['fingerprint'], 'source_fingerprint': source['fingerprint'],
               'source_revision': source['revision'],
               'pointer_sha256': 'sha256:' + file_hash(base / 'accepted.json')}
    document = {'target_path': str(target.resolve()), 'source': binding, 'source_files': source['files']}
    lineage = {'job': phase1.JOB, 'attempt_id': pointer['attempt_id'], 'fingerprint': pointer['fingerprint']}
    return document, lineage


def _resolve_accepted_artifacts(run_id: str, need: dict[str, Any]):
    """Named JSON artifacts of a producer's accepted common-envelope result, re-verified."""
    job = need['job']
    base = data_path(run_id, 'jobs', identifier(job))
    if not (base / 'accepted.json').is_file():
        raise Blocked(f'{job} has no accepted result')
    pointer = read_json(base / 'accepted.json')
    if pointer.get('schema') != ACCEPTED_SCHEMA or pointer.get('status') not in PUBLISHABLE:
        raise Blocked(f'{job} has no accepted result')
    attempt, _envelope = validate_published(base, pointer, pointer['fingerprint'], expected_run_id=run_id,
                                            expected_job_id=job)
    document = {name: read_json(attempt / name) for name in need['artifacts']}
    lineage = {'job': job, 'attempt_id': pointer['attempt_id'], 'fingerprint': pointer['fingerprint']}
    return document, lineage


RESOLVERS = {'intake-source': _resolve_intake_source, 'accepted-artifacts': _resolve_accepted_artifacts}


def _redact(name: str, document: Any) -> tuple[bytes, dict[str, Any]]:
    """Stream one input document through evidence_redaction on its way to the worker. Only the
    disposition and counts are recorded; the bytes the worker sees are the filtered ones."""
    import evidence_redaction as redaction
    data = (json.dumps(document, indent=2, sort_keys=True) + '\n').encode()
    outcome = redaction._process(data, f'input/{name}.json', redaction.DEFAULT_LIMITS)
    if outcome.disposition == 'withheld' or outcome.data is None:
        raise Blocked(f'input {name} was withheld by redaction ({outcome.withheld_reason}); nothing staged')
    counts = {kind: count for kind, count in sorted(outcome.counts.items()) if count}
    return outcome.data, {'input': name, 'disposition': outcome.disposition,
                          'parser_mode': outcome.parser_mode, 'counts': counts}


def prepare(item: Item, run_id: str, mode: str) -> dict[str, Any]:
    """PRE. Pure: reads run state and files, writes nothing."""
    needs, observed, lineage, redaction = {}, {}, {}, []
    for need in item['needs']:
        document, source = RESOLVERS[need['resolve']](run_id, need)
        staged, meta = _redact(need['as'], document)
        needs[need['as']] = json.loads(staged)
        observed[f"{need['job']}/{need['as']}"] = dr.observe_bytes(staged)
        lineage[need['as']] = source
        redaction.append(meta)
    input_doc = {'schema': INPUT_SCHEMA, 'run_id': run_id, 'job_id': item.job_id, 'needs': needs,
                 'params': item.get('params', {})}
    errors = validate(input_doc, item.schema('input.schema.json'), SchemaStore())
    if errors:
        raise Blocked(f'{item.job_id}: input fails input.schema.json: ' + '; '.join(errors[:10]))
    own = own_hashes(item)
    record = {'schema': RECORD_SCHEMA, 'run_id': run_id, 'job_id': item.job_id, 'mode': mode,
              'inputs': observed, 'own': own, 'params': item.get('params', {})}
    related = related_hashes(item)
    if mode == 'prod':
        # Prod keeps the legacy strictness: the upstream attempt and every related file pin it.
        record.update(lineage=lineage, related=related)
    return {'record': record, 'fingerprint': 'sha256:' + digest(record), 'input': input_doc,
            'lineage': lineage, 'redaction': redaction, 'related': related}


# --- decisions ---------------------------------------------------------------------------------

def root(run_id: str, job_id: str) -> Path:
    return data_path(run_id, 'jobs', identifier(job_id))


def accepted_receipt(run_id: str, job_id: str) -> tuple[dict | None, Path | None, dict | None]:
    """(pointer, attempt, receipt) of the job's accepted result, when it is a publishable one."""
    base = root(run_id, job_id)
    if not (base / 'accepted.json').is_file():
        return None, None, None
    pointer = read_json(base / 'accepted.json')
    if pointer.get('schema') != ACCEPTED_SCHEMA or pointer.get('status') not in PUBLISHABLE:
        return None, None, None
    attempt = base / 'attempts' / identifier(pointer['attempt_id'])
    receipt_path = attempt / dr.RECEIPT_NAME
    receipt = read_json(receipt_path) if receipt_path.is_file() else None
    if receipt is not None and (receipt.get('schema') != dr.RECEIPT_SCHEMA or receipt.get('job_id') != job_id):
        receipt = None
    return pointer, attempt, receipt


def _ledger(receipt: dict | None) -> dict | None:
    return {'inputs': receipt['inputs'], 'own': receipt['own'], 'outputs': receipt['outputs']} if receipt else None


def _reran_in(run_id: str, job_id: str, dagster_id: str) -> bool:
    _pointer, _attempt, receipt = accepted_receipt(run_id, job_id)
    return bool(receipt) and receipt.get('dagster_run_id') == dagster_id and \
        receipt.get('decision', {}).get('action') in (dr.RERUN, dr.REWIND)


def _rewind_producers(item: Item, prepared: dict, ledger: dict | None, items_root) -> dict[str, str]:
    """Rule 4 for this job: item producers whose published output shape differs from what this job
    recorded at its last accepted run."""
    if not ledger:
        return {}
    producers = {}
    for need in item['needs']:
        key = f"{need['job']}/{need['as']}"
        if load_item(need['job'], items_root) is None:
            continue  # a legacy producer's prod fingerprint covers its code: never stale
        if (ledger['inputs'].get(key) or {}).get('shape') != prepared['record']['inputs'][key]['shape']:
            producers[need['job']] = f'shape of {key} consumed by {item.job_id} changed'
    return producers


# --- PROCESS / POST ----------------------------------------------------------------------------

def _argv(item: Item, **values: str) -> list[str]:
    values = {'python': sys.executable, 'item': str(item.root), 'job_id': item.job_id, **values}
    return [PLACEHOLDER.sub(lambda m: values[m.group(1)], arg) for arg in item['worker']['argv']]


def _worker_env(mode: str) -> dict[str, str]:
    import execution_state
    env = {key: os.environ[key] for key in ('PATH', 'SYSTEMROOT', 'LANG', 'LC_ALL', 'TMPDIR', 'TEMP', 'TMP')
           if key in os.environ}
    env.update(PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE='1', APPSEC_RUN_MODE=mode,
               APPSEC_RUNS_ROOT=str(execution_state.RUNS))
    return env


def _normalise(item: Item, attempt: Path) -> dict[str, Any] | None:
    """Pass-through only: accept a tool's own SARIF 2.1.0 / CycloneDX document unchanged."""
    spec = item.get('normalise')
    if spec is None:
        return None
    path = attempt / spec['artifact']
    value = read_json(path)
    if spec['format'] == 'sarif-2.1.0':
        ok = isinstance(value, dict) and value.get('version') == '2.1.0' and isinstance(value.get('runs'), list)
    else:
        ok = isinstance(value, dict) and value.get('bomFormat') == 'CycloneDX' and isinstance(value.get('specVersion'), str)
    if not ok:
        raise Blocked(f"{item.job_id}: {spec['artifact']} is not {spec['format']}; no normaliser converts it")
    return {'format': spec['format'], 'mode': 'pass-through', 'artifact': spec['artifact'],
            'sha256': 'sha256:' + file_hash(path)}


def _rerun_command(run_id: str, job_id: str, mode: str) -> str:
    extra = f' --mode dev --force {job_id}' if mode == 'dev' else ' --force'
    return (f'python -B appsec-review-process/launch_job.py --run-id {run_id} --job full_review --wait'
            + extra)


def _receipt(item, *, run_id, dagster_id, attempt_id, mode, fingerprint, status, decision, prepared,
             outputs, resume_from, coverage, normalised=None) -> dict[str, Any]:
    return {'schema': dr.RECEIPT_SCHEMA, 'job_id': item.job_id, 'run_id': run_id,
            'dagster_run_id': dagster_id, 'attempt_id': attempt_id, 'status': status,
            'fingerprint': fingerprint, **dr.mode_fields(mode), 'decision': decision,
            'inputs': prepared['record']['inputs'], 'own': prepared['record']['own'],
            'related': prepared['related'], 'lineage': prepared['lineage'],
            'redaction': prepared['redaction'], 'outputs': outputs, 'coverage': coverage,
            'normalised': normalised, 'resume_from': resume_from,
            'rerun_command': _rerun_command(run_id, item.job_id, mode), 'recorded_at': now()}


def _execute(item: Item, run_id: str, dagster_id: str, mode: str, decision: dict, prepared: dict,
             allocation: dict, fingerprint: str) -> dict[str, Any]:
    attempt, attempt_id = allocation['attempt'], allocation['attempt_id']
    base = root(run_id, item.job_id)
    atomic_bytes(attempt / 'pre' / 'input.json',
                 (json.dumps(prepared['input'], indent=2, sort_keys=True) + '\n').encode())
    atomic_json(attempt / 'pre' / 'redaction.json', prepared['redaction'])
    out = attempt / 'out'
    out.mkdir()

    def fail(phase: str, cause: str, *, ran: bool) -> None:
        coverage = {'schema': COVERAGE_SCHEMA, 'job_id': item.job_id, 'tool_ran': ran, 'complete': False,
                    'execution_status': 'FAILED', 'gaps': [f'{phase}: {cause}'],
                    'rule': 'a tool that did not run or a partial scan is a gap, never "no findings"'}
        atomic_json(attempt / 'coverage.json', coverage)
        atomic_json(attempt / dr.RECEIPT_NAME, _receipt(
            item, run_id=run_id, dagster_id=dagster_id, attempt_id=attempt_id, mode=mode,
            fingerprint=fingerprint, status='FAILED', decision=decision, prepared=prepared, outputs={},
            resume_from=phase, coverage=coverage))
        raise RuntimeError(f'{item.job_id}: {phase} failed: {cause}')

    # PROCESS
    argv = _argv(item, run_id=run_id, attempt_id=attempt_id, input=str(attempt / 'pre' / 'input.json'),
                 output=str(out))
    command = execute(argv, ROOT, attempt / 'logs', item['worker']['timeout_seconds'], env=_worker_env(mode))
    if command.get('error') or command.get('exit_code') != 0:
        fail('process', command.get('error') or f"worker exit code {command.get('exit_code')}",
             ran=command.get('exit_code') is not None)
    # POST
    result_path = out / WORKER_RESULT
    if not result_path.is_file():
        fail('post', f'worker wrote no {WORKER_RESULT}', ran=True)
    result = read_json(result_path)
    errors = validate(result, item.schema('output.schema.json'), SchemaStore())
    errors += _worker_result_errors(result)
    if errors:
        fail('post', 'worker result fails output.schema.json: ' + '; '.join(errors[:10]), ran=True)
    declared = [name for name in item['outputs']['artifacts'] if name != 'status.json']
    missing = [name for name in declared if not (out / name).is_file()]
    if missing or sorted(result['artifacts']) != sorted(declared):
        fail('post', f'worker outputs do not match the declared artifacts (missing {missing})', ran=True)
    for name in declared:
        os.replace(out / name, attempt / name)
    gaps = sorted(set(result['gaps']))
    status = result['execution_status']
    if status == 'OK' and gaps:
        status = 'OK_WITH_GAPS'  # a gap is never hidden behind OK
    coverage = {'schema': COVERAGE_SCHEMA, 'job_id': item.job_id, 'tool_ran': status != 'SKIPPED',
                'complete': status == 'OK', 'execution_status': status, 'gaps': gaps,
                'skip_reason': result.get('skip_reason'),
                'rule': 'a tool that did not run or a partial scan is a gap, never "no findings"'}
    atomic_json(attempt / 'coverage.json', coverage)
    normalised = _normalise(item, attempt)
    outputs = {name: dr.observe_file(attempt / name) for name in declared}
    atomic_json(attempt / dr.RECEIPT_NAME, _receipt(
        item, run_id=run_id, dagster_id=dagster_id, attempt_id=attempt_id, mode=mode,
        fingerprint=fingerprint, status=status, decision=decision, prepared=prepared, outputs=outputs,
        resume_from=None, coverage=coverage, normalised=normalised))

    def pre_envelope(path: Path, _status: dict) -> None:
        for name, value in outputs.items():
            if dr.observe_file(path / name) != value:
                raise Blocked(f'{item.job_id}: {name} changed after POST validation')

    return record_terminal_current(
        base, attempt, run_id=run_id, job_id=item.job_id, dagster_run_id=dagster_id,
        worker_kind=item['worker_kind'], output_contract=item['output_contract'],
        input_fingerprint=fingerprint, started_at=allocation['started_at'], execution_status=status,
        summary=result['summary'][:1000], status_record=result['status'],
        artifact_paths=list(item['outputs']['artifacts']), gaps=gaps or None,
        skip_reason=result.get('skip_reason'), pre_envelope_validate=pre_envelope)


def _worker_result_errors(result: Any) -> list[str]:
    """What the executor itself needs from worker-result.json, whatever the item's schema allows."""
    if not isinstance(result, dict):
        return ['worker result is not an object']
    errors = []
    if result.get('execution_status') not in PUBLISHABLE:
        errors.append(f'execution_status must be one of {PUBLISHABLE}')
    if result.get('execution_status') == 'SKIPPED' and not isinstance(result.get('skip_reason'), str):
        errors.append('a SKIPPED result names its skip_reason')
    if not isinstance(result.get('gaps'), list) or not all(isinstance(g, str) for g in result.get('gaps', [])):
        errors.append('gaps must be an array of strings')
    if not isinstance(result.get('summary'), str) or not result.get('summary'):
        errors.append('summary is required')
    if not isinstance(result.get('status'), dict):
        errors.append('status facts must be an object')
    if not isinstance(result.get('artifacts'), list):
        errors.append('artifacts must list the files written')
    return errors


def _verify_reuse(item: Item, run_id: str, pointer: dict, attempt: Path, receipt: dict) -> None:
    base = root(run_id, item.job_id)
    validate_published(base, pointer, pointer['fingerprint'], expected_run_id=run_id,
                       expected_job_id=item.job_id, reuse=True)
    for name, value in receipt['outputs'].items():
        if dr.observe_file(attempt / name) != value:
            raise Blocked(f'{item.job_id}: reused {name} does not match its receipt')


def run_item(job_id: str, run_id: str, dagster_id: str, *, mode: str | None = None, force: bool = False,
             force_jobs: Iterable[str] = (), items_root: Path | None = None,
             rewind_cause: str | None = None) -> dict[str, Any]:
    """Run one item under the lifecycle lock. Returns the accepted pointer plus `decision`."""
    mode = mode or dr.run_mode()
    item = load_item(job_id, items_root)
    if item is None:
        raise Blocked(f'{job_id} is not an item')
    force_jobs = set(force_jobs)
    base = root(run_id, job_id)
    resume = _rerun_command(run_id, job_id, mode)
    pointer, attempt, receipt = accepted_receipt(run_id, job_id)

    holder: dict[str, Any] = {}
    if mode == 'dev':
        try:
            prepared = prepare(item, run_id, mode)
            ledger = _ledger(receipt)
            # Rule 4, transitive: a producer being rewound checks its own producers too.
            rewinds = _rewind_producers(item, prepared, ledger, items_root)
            for producer, cause in sorted(rewinds.items()):
                if not _reran_in(run_id, producer, dagster_id):
                    run_item(producer, run_id, dagster_id, mode=mode, force_jobs=force_jobs,
                             items_root=items_root, rewind_cause=cause)
            if rewinds:
                prepared = prepare(item, run_id, mode)
            fresh = [need['job'] for need in item['needs'] if _reran_in(run_id, need['job'], dagster_id)]
            decision = dr.decide(job_id, prepared['record'], ledger, forced=force or job_id in force_jobs,
                                 rewind_cause=rewind_cause, fresh=fresh)
        except Blocked as exc:
            # Recorded as a BLOCKED attempt below, exactly like a prod preflight failure.
            holder['error'], prepared, decision = exc, None, None
        if decision is not None and decision['action'] == dr.REUSE:
            with Lock(base / 'job.lock'):
                _verify_reuse(item, run_id, pointer, attempt, receipt)
                atomic_json(data_path(run_id, 'orchestration', 'dagster', dagster_id, job_id + '-reuse.json'),
                            {'status': pointer['status'], 'reused': True, 'mode': mode, 'decision': decision,
                             'producer': pointer, 'time': now()})
            return {**pointer, 'decision': decision}
        rerun = True
    else:
        # A prod run never reuses a dev result: it recomputes (post_validate below is the backstop).
        rerun = force or (receipt is not None and not dr.prod_may_reuse(receipt))
        decision = None
        prepared = None

    def derive():
        if 'error' in holder:
            raise holder['error']
        holder['prepared'] = prepared or prepare(item, run_id, mode)
        return holder['prepared']['record']

    def execute_attempt(allocation, _record, fingerprint):
        action = decision or dr._decision(job_id, dr.RERUN, [
            '--force' if force else 'the accepted result is not a prod receipt' if rerun else
            'prod fingerprint changed'])
        holder['decision'] = action
        return _execute(item, run_id, dagster_id, mode, action, holder['prepared'], allocation, fingerprint)

    def post_validate(reused_attempt, _envelope, _record):
        reused_receipt = read_json(reused_attempt / dr.RECEIPT_NAME)
        if not dr.prod_may_reuse(reused_receipt):
            raise Blocked(f'{job_id}: refusing to reuse a non-prod result in prod')
        for name, value in reused_receipt['outputs'].items():
            if dr.observe_file(reused_attempt / name) != value:
                raise Blocked(f'{job_id}: reused {name} does not match its receipt')

    def on_reuse(admitted):
        atomic_json(data_path(run_id, 'orchestration', 'dagster', dagster_id, job_id + '-reuse.json'),
                    {'status': admitted['envelope']['execution_status'], 'reused': True, 'mode': mode,
                     'publication_recovered': admitted['recovered_publication'],
                     'producer': admitted['pointer'], 'time': now()})
        holder['reused'] = True

    result = coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=job_id, dagster_run_id=dagster_id, worker_kind=item['worker_kind'],
        output_contract=item['output_contract'], resume_command=resume, derive_inputs=derive,
        fingerprint_inputs=lambda record: 'sha256:' + digest(record), execute_attempt=execute_attempt,
        preflight_failure_inputs=lambda exc: {'schema': RECORD_SCHEMA, 'run_id': run_id, 'job_id': job_id,
                                              'mode': mode, 'preflight_error': f'{type(exc).__name__}: {exc}'},
        force=rerun, post_validate=post_validate, on_reuse=on_reuse,
        blocked_summary=f'{job_id} item preflight did not complete.',
        failed_summary=f'{job_id} item did not publish.')
    if holder.get('reused'):
        return {**result, 'decision': dr._decision(job_id, dr.REUSE, ['prod fingerprint unchanged'])}
    return {**result, 'decision': holder['decision']}


# --- explain -----------------------------------------------------------------------------------

def explain_items(run_root: Path, upstream: dict[str, list[str]], *, mode: str, forced=(),
                  items_root: Path | None = None) -> list[dict[str, Any]]:
    """dev_restart.explain_run's item hook: the dev decision for each item from the run as it is now
    (no side effects), with rewinds and what prod would do on code alone."""
    run_id = Path(run_root).name
    if Path(run_root).absolute() != run_path(run_id).absolute():
        return []
    forced = set(forced)
    items = [job for job in dr.topological(upstream) if load_item(job, items_root) is not None]
    entries, ledgers = [], {}
    for job in items:
        item = load_item(job, items_root)
        _pointer, _attempt, receipt = accepted_receipt(run_id, job)
        ledgers[job] = _ledger(receipt)
        try:
            prepared = prepare(item, run_id, mode)
        except (Blocked, OSError, ValueError, KeyError) as exc:
            entries.append({'job': job, 'decision': dr._decision(job, dr.RERUN, [f'inputs not resolvable now: {exc}'])})
            continue
        recorded = None if receipt is None else {**receipt.get('own', {}), **receipt.get('related', {})}
        note = dr.prod_note(recorded, {**prepared['record']['own'], **prepared['related']})
        entries.append({'job': job, 'prepared': prepared, 'prod_note': note, 'receipt': receipt})
    rewinds: dict[str, str] = {}
    for entry in entries:
        job = entry['job']
        if 'prepared' not in entry:
            continue
        item = load_item(job, items_root)
        for producer, cause in _rewind_producers(item, entry['prepared'], ledgers[job], items_root).items():
            rewinds.setdefault(producer, cause)
    for entry in entries:
        job = entry['job']
        if 'prepared' in entry:
            entry['decision'] = dr.decide(job, entry['prepared']['record'], ledgers[job],
                                          forced=job in forced, rewind_cause=rewinds.get(job))
        entry.pop('prepared', None)
        entry.pop('receipt', None)
    return entries


# --- Dagster -----------------------------------------------------------------------------------

def run_tags(job_id: str, tags: dict[str, str], environ=None) -> tuple[str, list[str]]:
    """The launch's mode must be the code location's mode: a prod launch never runs dev semantics and
    a dev launch never silently produces evidence-grade results."""
    mode = dr.run_mode(environ)
    asked = tags.get('appsec/run_mode', 'prod')
    if asked != mode:
        raise Blocked(f'{job_id}: launch asked for {asked} but this code location runs in {mode} mode '
                      '(APPSEC_RUN_MODE); refusing')
    return mode, [name for name in tags.get('appsec/force_jobs', '').split(',') if name]


def dagster_item_op(job_id: str, pool: str | None = None):
    """The one generic op, registered per item job from job-graph.json like any lifecycle op."""
    from dagster import Failure, In, MetadataValue
    from pipeline_log_dagster import op

    @op(name='job_' + job_id.replace('-', '_'), ins={'configured': In(dict), 'upstream': In(list)},
        pool=pool, description=f'{job_id}: generic item executor (ADR-0024)')
    def item_work(context, configured, upstream):
        try:
            mode, force_jobs = run_tags(job_id, context.run.tags)
        except Blocked as exc:
            raise Failure(str(exc)) from None
        result = run_item(job_id, configured['engagement_run_id'], context.run_id, mode=mode,
                          force=configured.get('force', False), force_jobs=force_jobs)
        attempt = root(configured['engagement_run_id'], job_id) / 'attempts' / result['attempt_id']
        context.add_output_metadata({'envelope': MetadataValue.path(str(attempt / 'result.json')),
                                     'receipt': MetadataValue.path(str(attempt / dr.RECEIPT_NAME)),
                                     'attempt_id': result['attempt_id'], 'mode': mode,
                                     'decision': dr.explain_line(result['decision'])})
        return result
    return item_work


def register_item_ops(lifecycle: dict[str, Any], ops: dict[str, Any], pool: str | None = None,
                      items_root: Path | None = None) -> list[str]:
    """Replace the op of every job-graph job that has an item. An item's needs must be exactly its
    graph dependencies, so the graph stays the single source of wiring."""
    registered = []
    for job_id in item_ids(items_root):
        if job_id not in lifecycle:
            raise Blocked(f'item {job_id} is not a job in job-graph.json')
        item = load_item(job_id, items_root)
        deps = sorted(d['job'] for d in lifecycle[job_id]['dependencies'] if d.get('enabled', True))
        if sorted({need['job'] for need in item['needs']}) != deps:
            raise Blocked(f'item {job_id} needs {sorted({n["job"] for n in item["needs"]})} but the graph says {deps}')
        ops[job_id] = dagster_item_op(job_id, pool)
        registered.append(job_id)
    return registered


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Run one item outside Dagster (diagnostics).')
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--job', required=True)
    parser.add_argument('--dagster-id', default='manual')
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args()
    print(json.dumps(run_item(args.job, args.run_id, args.dagster_id, force=args.force), indent=2))
