"""Dev-mode restart policy (ADR-0025): decide REUSE / RERUN / REWIND from data, not from code hashes.

Production fingerprints stay the evidence rule and are not touched here: every legacy lifecycle keeps
its own inputs record and `_code_hashes` in both modes. This module is consulted only when
`APPSEC_RUN_MODE=dev`, by jobs that run through the generic item executor (`job_executor.py`), and by
`launch_job.py --explain`, which also predicts what each legacy job will do.

Rules (numbering follows docs/agent-briefs/I-dev-restart-and-executor.md; operator view in
docs/dev-mode-restart.md):
  2. every consumed input's content hash equals the job's last accepted run -> REUSE
  3. some input content changed but every shape is equal                      -> RERUN
  4. an input's SHAPE changed                                                -> REWIND: the producer
     of that input reruns first, then the pass continues forward. Applied to every job whose recorded
     input shape differs from what its producer has published now, so it is transitive by
     construction. Only item producers rewind: a legacy producer's full prod fingerprint already
     covers all of its code, so its published output is never stale and the consumer just reruns.
  5. early cutoff: a rerun whose output is byte-identical leaves every downstream content hash
     equal, so downstream jobs REUSE
  6. a job's own config, contract, schema, prompt and implementation files are inputs; SHARED_RUNTIME
     and other jobs' implementation files are not. `force` reruns one job regardless.

Guard rails: every dev receipt carries `mode: "dev"` and `evidence_grade: false`; a prod run never
reuses a dev-published result; `assert_deliverable` refuses a run whose accepted results include one.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
import hashlib
import json
import os
from pathlib import Path
from typing import Any

MODES = ('dev', 'prod')
MODE_ENV = 'APPSEC_RUN_MODE'
RECEIPT_SCHEMA = 'appsec-review/item-receipt/1'
RECEIPT_NAME = 'receipt.json'
REUSE, RERUN, REWIND = 'REUSE', 'RERUN', 'REWIND'
OPAQUE_SHAPE = 'opaque'  # non-JSON artifacts: content decides, shape never changes


def run_mode(environ: Mapping[str, str] | None = None) -> str:
    """The process run mode. Absent means prod; anything unrecognised fails closed."""
    value = (os.environ if environ is None else environ).get(MODE_ENV, '').strip().lower() or 'prod'
    if value not in MODES:
        raise ValueError(f'{MODE_ENV} must be one of {MODES}, not {value!r}')
    return value


def mode_fields(mode: str) -> dict[str, Any]:
    """The receipt fields every executor result carries. Only prod is evidence."""
    if mode not in MODES:
        raise ValueError(f'unknown run mode {mode!r}')
    return {'mode': mode, 'evidence_grade': mode == 'prod'}


def prod_may_reuse(receipt: Mapping[str, Any] | None) -> bool:
    """A prod run reuses only a prod, evidence-grade receipt; a dev result is recomputed."""
    return bool(receipt) and receipt.get('mode') == 'prod' and receipt.get('evidence_grade') is True


# --- hashing -----------------------------------------------------------------------------------

def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def content_hash(data: bytes) -> str:
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def shape_of(value: Any) -> Any:
    """Recursive JSON keys and value types, independent of values and of key order. An array's shape
    is the set of its distinct element shapes, so length and element order do not matter."""
    if isinstance(value, dict):
        return {'object': {str(key): shape_of(value[key]) for key in sorted(value, key=str)}}
    if isinstance(value, list):
        shapes = {_canonical(shape_of(item)): shape_of(item) for item in value}
        return {'array': [shapes[key] for key in sorted(shapes)]}
    if isinstance(value, bool):
        return 'boolean'
    if isinstance(value, (int, float)):
        return 'number'
    if isinstance(value, str):
        return 'string'
    if value is None:
        return 'null'
    raise TypeError(f'not a JSON value: {type(value).__name__}')


def shape_hash(value: Any) -> str:
    return content_hash(_canonical(shape_of(value)))


def observe_bytes(data: bytes) -> dict[str, str]:
    """Content and shape of one artifact. JSON (UTF-8, optional BOM) has a shape; anything else is
    opaque, so only its content can change."""
    try:
        value = json.loads(data.decode('utf-8-sig'))
    except (UnicodeDecodeError, ValueError):
        return {'content': content_hash(data), 'shape': OPAQUE_SHAPE}
    return {'content': content_hash(data), 'shape': shape_hash(value)}


def observe_file(path: Path) -> dict[str, str]:
    return observe_bytes(Path(path).read_bytes())


def observe_value(value: Any) -> dict[str, str]:
    """Content and shape of an in-memory JSON document, hashed in canonical form."""
    return {'content': content_hash(_canonical(value)), 'shape': shape_hash(value)}


# --- decisions ---------------------------------------------------------------------------------

def _changed(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    notes = []
    for key in sorted(set(before) | set(after)):
        if key not in after:
            notes.append(f'{key} removed')
        elif key not in before:
            notes.append(f'{key} added')
        elif before[key] != after[key]:
            notes.append(f'{key} changed')
    return notes


def producer_of(key: str) -> str:
    """Input keys are `<producer job>/<artifact>`."""
    return key.split('/', 1)[0]


def decide(job: str, current: Mapping[str, Any], ledger: Mapping[str, Any] | None, *,
           forced: bool = False, rewind_cause: str | None = None,
           fresh: Iterable[str] = ()) -> dict[str, Any]:
    """One job's dev decision.

    `current` and `ledger` hold `inputs` ({'<producer>/<artifact>': {'content', 'shape'}}) and `own`
    ({file: hash}, rule 6: own config/contract/schema/prompt/implementation only). `ledger` is the
    job's last accepted run; `fresh` names the producers that already reran in this pass.
    """
    fresh = set(fresh)
    if forced:
        return _decision(job, RERUN, ['--force'])
    if rewind_cause:
        return _decision(job, REWIND, [rewind_cause])
    if not ledger:
        return _decision(job, RERUN, ['no accepted run to reuse'])
    own = _changed(ledger.get('own', {}), current.get('own', {}))
    if own:
        return _decision(job, RERUN, ['own ' + note for note in own])
    before, after = ledger.get('inputs', {}), current.get('inputs', {})
    shape = [key for key in sorted(set(before) | set(after))
             if (before.get(key) or {}).get('shape') != (after.get(key) or {}).get('shape')]
    if shape:
        return _decision(job, RERUN, [f'input shape of {key} changed' + (
            f' ({producer_of(key)} reran in this pass)' if producer_of(key) in fresh else '')
            for key in shape])
    content = [key for key in sorted(after) if before[key]['content'] != after[key]['content']]
    if content:
        return _decision(job, RERUN, [f'input content of {key} changed' for key in content])
    cut = sorted({producer_of(key) for key in after} & fresh)
    if cut:
        return _decision(job, REUSE, [f'early cutoff: {name} reran with byte-identical output'
                                      for name in cut])
    return _decision(job, REUSE, ['inputs and own files unchanged'])


def _decision(job: str, action: str, causes: list[str]) -> dict[str, Any]:
    return {'job': job, 'action': action, 'causes': causes}


def plan_rewinds(order: list[str], ledgers: Mapping[str, Mapping[str, Any] | None],
                 published: Mapping[str, Mapping[str, Mapping[str, str]]],
                 rewindable: Callable[[str], bool]) -> dict[str, str]:
    """Rule 4 before any work runs: {producer: cause} for every rewindable producer whose published
    output shape differs from what a consumer recorded at its last accepted run. Every job is
    checked as a consumer, so a producer whose own input shape changed rewinds its producer too."""
    rewinds: dict[str, str] = {}
    for consumer in order:
        ledger = ledgers.get(consumer)
        if not ledger:
            continue
        for key, recorded in sorted(ledger.get('inputs', {}).items()):
            producer = producer_of(key)
            if producer in rewinds or not rewindable(producer):
                continue
            artifact = key.split('/', 1)[1] if '/' in key else key
            now_shape = (published.get(producer, {}).get(artifact) or {}).get('shape')
            if now_shape != recorded.get('shape'):
                rewinds[producer] = f'shape of {key} consumed by {consumer} changed'
    return rewinds


def rewind_points(rewinds: Mapping[str, str], upstream: Mapping[str, list[str]]) -> list[str]:
    """The rewound jobs with no rewound ancestor: where the pass restarts."""
    def ancestors(job: str, seen: set[str]) -> set[str]:
        for parent in upstream.get(job, []):
            if parent not in seen:
                seen.add(parent)
                ancestors(parent, seen)
        return seen
    return sorted(job for job in rewinds if not (ancestors(job, set()) & set(rewinds)))


def topological(upstream: Mapping[str, list[str]]) -> list[str]:
    """Deterministic topological order (ties by name); refuses cycles and unknown dependencies."""
    names = set(upstream)
    for job, parents in upstream.items():
        missing = set(parents) - names
        if missing:
            raise ValueError(f'{job} depends on unknown job(s): {sorted(missing)}')
    order, done = [], set()
    while len(order) < len(names):
        ready = sorted(job for job in names - done if set(upstream[job]) <= done)
        if not ready:
            raise ValueError('dependency cycle among: ' + ', '.join(sorted(names - done)))
        order.extend(ready)
        done.update(ready)
    return order


class Store:
    """What a pass reads and writes. job_executor supplies the run-backed implementation; tests use
    MemoryStore. `inputs(job)` is computed from what producers have published now."""
    def ledger(self, job: str) -> Mapping[str, Any] | None: raise NotImplementedError
    def published(self, job: str) -> Mapping[str, Mapping[str, str]]: raise NotImplementedError
    def inputs(self, job: str) -> dict[str, dict[str, str]]: raise NotImplementedError
    def own(self, job: str) -> dict[str, str]: raise NotImplementedError
    def rewindable(self, job: str) -> bool: return True


class MemoryStore(Store):
    """In-memory store for the policy tests: `outputs[job] = {artifact: bytes}`."""
    def __init__(self, upstream: Mapping[str, list[str]], own: Mapping[str, Mapping[str, str]] | None = None,
                 outputs: Mapping[str, Mapping[str, bytes]] | None = None,
                 ledgers: Mapping[str, Mapping[str, Any]] | None = None):
        self.upstream = {job: list(parents) for job, parents in upstream.items()}
        self.own_files = {job: dict((own or {}).get(job, {})) for job in upstream}
        self.outputs = {job: dict(value) for job, value in (outputs or {}).items()}
        self.ledgers = {job: value for job, value in (ledgers or {}).items()}

    def ledger(self, job): return self.ledgers.get(job)
    def own(self, job): return dict(self.own_files.get(job, {}))

    def published(self, job):
        return {name: observe_bytes(data) for name, data in self.outputs.get(job, {}).items()}

    def inputs(self, job):
        return {f'{parent}/{name}': value for parent in self.upstream[job]
                for name, value in self.published(parent).items()}

    def accept(self, job, inputs, own, outputs):
        self.outputs[job] = dict(outputs)
        self.ledgers[job] = {'inputs': inputs, 'own': own, 'outputs': self.published(job)}


def run_pass(store: Store, upstream: Mapping[str, list[str]],
             runner: Callable[[str, dict[str, Any]], Mapping[str, bytes]] | None = None, *,
             forced: Iterable[str] = ()) -> dict[str, Any]:
    """One dev pass in topological order. With `runner`, RERUN/REWIND jobs execute and publish
    (store.accept) before their consumers decide, so early cutoff falls out of content equality.
    Without it the result is the `--explain` prediction: a consumer of a pending rerun is shown as a
    provisional RERUN that becomes REUSE if the producer's output is byte-identical."""
    forced = set(forced)
    order = topological(upstream)
    rewinds = plan_rewinds(order, {job: store.ledger(job) for job in order},
                           {job: store.published(job) for job in order}, store.rewindable)
    fresh: set[str] = set()
    pending: set[str] = set()
    decisions = []
    for job in order:
        current = {'inputs': store.inputs(job), 'own': store.own(job)}
        decision = decide(job, current, store.ledger(job), forced=job in forced,
                          rewind_cause=rewinds.get(job), fresh=fresh)
        waiting = sorted(set(upstream[job]) & pending)
        if decision['action'] == REUSE and waiting:
            decision = _decision(job, RERUN, [f'provisional: {name} reruns first; REUSE if its '
                                              'output is byte-identical (early cutoff)' for name in waiting])
        if decision['action'] != REUSE:
            if runner is None:
                pending.add(job)
            else:
                outputs = runner(job, current)
                store.accept(job, current['inputs'], current['own'], outputs)
                fresh.add(job)
        decisions.append(decision)
    return {'order': order, 'decisions': decisions, 'rewinds': rewinds,
            'rewind_points': rewind_points(rewinds, upstream)}


# --- explain -----------------------------------------------------------------------------------

def explain_line(decision: Mapping[str, Any], prod_note: str | None = None) -> str:
    """One `--explain` line: `ACTION job: cause; cause [; prod would have ...]`."""
    text = f"{decision['action']:<6} {decision['job']}: " + '; '.join(decision['causes'])
    return text + (f'; {prod_note}' if prod_note else '')


def prod_note(recorded_code: Mapping[str, str] | None, current_code: Mapping[str, str]) -> str | None:
    """Why prod would invalidate (or not) on code alone: compares the code hashes the accepted
    attempt recorded with the files as they are now."""
    if recorded_code is None:
        return None
    notes = _changed(recorded_code, current_code)
    if not notes:
        return 'prod would also reuse on code'
    return 'prod would have invalidated because code hash of ' + ', '.join(notes)


PUBLISHABLE = ('OK', 'OK_WITH_GAPS', 'SKIPPED')


def _read(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def _file_hash(path: Path) -> str | None:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def function_source_hash(path: Path, name: str) -> str | None:
    """sha256 of the exact source of one top-level function, read without importing the module. A
    `<file>:<function>` code key narrows a fingerprint to the part of a large module that matters
    (brief N, D-13: build discovery hashes only dagster_workflow.py's branch_op). None if absent."""
    import ast
    try:
        text = Path(path).read_text(encoding='utf-8')
        tree = ast.parse(text)
    except (OSError, SyntaxError, UnicodeError, ValueError):
        return None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return hashlib.sha256(ast.get_source_segment(text, node).encode('utf-8')).hexdigest()
    return None


def current_code(recorded: Mapping[str, str], process_root: Path) -> dict[str, str | None]:
    """Re-hash the files an attempt recorded. Keys are process-root relative, `schemas/` keys are
    repository relative, as every `_code_hashes` writes them; a `<file>:<function>` key hashes that
    function's source. A missing file hashes to None."""
    process_root = Path(process_root)
    values = {}
    for key in recorded:
        base = process_root.parent if key.startswith('schemas/') else process_root
        if ':' in key:
            file_part, function = key.rsplit(':', 1)
            values[key] = function_source_hash(base / file_part, function)
        else:
            values[key] = _file_hash(base / key)
    return values


def accepted_attempt(jobs_root: Path, job: str) -> tuple[dict[str, Any] | None, Path | None]:
    """The job's accepted pointer (data/jobs/<job>/ or the phase-1 `whole` scope) and attempt dir."""
    for base in (Path(jobs_root) / job, Path(jobs_root) / job / 'whole'):
        path = base / 'accepted.json'
        if path.is_file():
            try:
                pointer = _read(path)
            except (OSError, ValueError):
                return None, None
            attempt = base / 'attempts' / str(pointer.get('attempt_id'))
            return pointer, attempt if attempt.is_dir() else None
    return None, None


def explain_legacy(job: str, jobs_root: Path, process_root: Path, upstream: list[str],
                   reruns: set[str], forced: bool) -> tuple[dict[str, Any], str | None]:
    """Predict a legacy lifecycle, which keeps its prod fingerprint in both modes: it reruns when its
    recorded code changed, when it has no publishable accepted result, or when any upstream job reruns
    (its inputs pin the upstream attempt, so it has no early cutoff)."""
    pointer, attempt = accepted_attempt(jobs_root, job)
    recorded = None
    if attempt is not None and (attempt / 'inputs.json').is_file():
        try:
            code = _read(attempt / 'inputs.json').get('code')
            recorded = code if isinstance(code, dict) else None
        except (OSError, ValueError, AttributeError):
            recorded = None
    reuse_path = attempt.parent.parent / 'reuse.json' if attempt is not None else None
    if recorded is None and reuse_path is not None and reuse_path.is_file():
        # A content-keyed producer (producer_reuse) records its code beside the accepted pointer.
        try:
            reuse = _read(reuse_path)
            code = reuse.get('inputs', {}).get('code') if reuse.get('attempt_id') == attempt.name else None
            recorded = code if isinstance(code, dict) else None
        except (OSError, ValueError, AttributeError):
            recorded = None
    note = prod_note(recorded, current_code(recorded, process_root)) if recorded is not None else None
    if forced:
        return _decision(job, RERUN, ['--force']), note
    if pointer is None or attempt is None:
        return _decision(job, RERUN, ['no accepted result']), note
    if pointer.get('status') not in PUBLISHABLE:
        return _decision(job, RERUN, [f"last attempt is {pointer.get('status')}"]), note
    if recorded is not None:
        changed = _changed(recorded, current_code(recorded, process_root))
        if changed:
            return _decision(job, RERUN, ['legacy fingerprint: code hash of ' + ', '.join(changed)]), None
    waiting = sorted(set(upstream) & reruns)
    if waiting:
        return _decision(job, RERUN, [f'upstream {name} reruns (legacy lifecycle pins the upstream '
                                      'attempt; no early cutoff)' for name in waiting]), note
    return _decision(job, REUSE, ['recorded code unchanged and no upstream rerun'
                                  + ('' if recorded is not None else ' (no code record to compare)')]), note


def explain_run(run_root: Path, graph: Mapping[str, Any], process_root: Path, *, mode: str,
                forced: Iterable[str] = (),
                item_explain: Callable[..., list[dict[str, Any]]] | None = None) -> list[str]:
    """`launch_job.py --explain`: one line per job in topological order. Item jobs (when
    `item_explain` is supplied by job_executor) follow the dev rules in dev mode; every other job is
    predicted from its own prod fingerprint record. The intake decides source freshness itself and is
    predicted from its pointer only."""
    upstream = {job: [dep['job'] for dep in node.get('dependencies', []) if dep.get('enabled', True)]
                for job, node in graph['jobs'].items()}
    forced = set(forced)
    unknown = forced - set(upstream)
    if unknown:
        raise ValueError(f'--force names unknown job(s): {sorted(unknown)}')
    jobs_root = Path(run_root) / 'data' / 'jobs'
    items = {}
    if item_explain is not None:
        items = {entry['job']: entry for entry in item_explain(run_root, upstream, mode=mode, forced=forced)}
    reruns: set[str] = set()
    lines = [f'# mode={mode} run={Path(run_root).name} jobs={len(upstream)}'
             + (' (dev: item jobs follow data rules 2-6; legacy jobs keep their prod fingerprint)'
                if mode == 'dev' else ' (prod: every job follows its own fingerprint)')]
    for job in topological(upstream):
        if job in items and mode == 'dev':
            decision, note = items[job]['decision'], items[job].get('prod_note')
            if decision['action'] == REUSE and set(upstream[job]) & reruns and not items[job].get('settled'):
                decision = _decision(job, RERUN, [f'provisional: {name} reruns first; REUSE if its output '
                                                  'is byte-identical (early cutoff)'
                                                  for name in sorted(set(upstream[job]) & reruns)])
        else:
            decision, note = explain_legacy(job, jobs_root, process_root, upstream[job], reruns, job in forced)
        if decision['action'] != REUSE:
            reruns.add(job)
        lines.append(explain_line(decision, note))
    return lines


# --- guard rails -------------------------------------------------------------------------------

def accepted_dev_results(run_root: Path) -> list[str]:
    """Every accepted attempt in the run whose receipt says it was produced in dev mode."""
    found = []
    jobs = Path(run_root) / 'data' / 'jobs'
    if not jobs.is_dir():
        return found
    for pointer_path in sorted(jobs.rglob('accepted.json')):
        try:
            pointer = json.loads(pointer_path.read_text(encoding='utf-8-sig'))
            attempt = pointer_path.parent / 'attempts' / str(pointer.get('attempt_id'))
            receipt_path = attempt / RECEIPT_NAME
            if not receipt_path.is_file():
                continue
            receipt = json.loads(receipt_path.read_text(encoding='utf-8-sig'))
        except (OSError, ValueError, AttributeError):
            continue
        if receipt.get('schema') == RECEIPT_SCHEMA and not prod_may_reuse(receipt):
            found.append(pointer_path.parent.relative_to(jobs).as_posix())
    return found


def assert_deliverable(run_root: Path, environ: Mapping[str, str] | None = None) -> None:
    """A review deliverable is never produced in, or from, a dev run."""
    from execution_state import Blocked
    if run_mode(environ) == 'dev':
        raise Blocked(f'{MODE_ENV}=dev: a dev process never publishes a review deliverable')
    dev = accepted_dev_results(run_root)
    if dev:
        raise Blocked('dev run results are not evidence; rerun in prod before publishing: '
                      + ', '.join(dev[:10]))
