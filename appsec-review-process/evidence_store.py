"""Immutable, run-owned source/evidence snapshots, ssdeep and SQLite FTS5.

Content is untrusted data. Nothing from the target is executed. SHA-256 is identity;
ssdeep is a retrieval hint, never proof of equivalence or vulnerability.
"""
from __future__ import annotations

import argparse
import csv
import ctypes
import hashlib
import json
import io
import os
from pathlib import Path
import sqlite3
import sys
import uuid

from execution_state import (ROOT, Blocked, Lock, atomic_bytes, atomic_json, beneath,
                             data_path, digest, execute, file_hash, identifier, now,
                             read_json, tree_hashes)
import phase1

LIMITS = {'max_files': 20000, 'max_file_bytes': 8 * 1024 * 1024,
          'max_total_bytes': 512 * 1024 * 1024, 'max_text_bytes': 2 * 1024 * 1024,
          'chunk_lines': 60, 'max_line_chars': 16384}
JOB = '02-evidence-index'
LOADED_WORKER_SHA256 = file_hash(Path(__file__))


class Fuzzy:
    def __init__(self):
        # The pinned Debian package supplies both the CLI and this ABI.
        self.lib = ctypes.CDLL('libfuzzy.so.2')
        self.lib.fuzzy_hash_buf.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p]
        self.lib.fuzzy_hash_buf.restype = ctypes.c_int
        self.lib.fuzzy_compare.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.lib.fuzzy_compare.restype = ctypes.c_int

    def hash(self, content):
        output = ctypes.create_string_buffer(148)
        if self.lib.fuzzy_hash_buf(content, len(content), output) != 0:
            raise RuntimeError('ssdeep hashing failed')
        return output.value.decode('ascii')

    def compare(self, left, right):
        score = self.lib.fuzzy_compare(left.encode('ascii'), right.encode('ascii'))
        if score < 0:
            raise ValueError('invalid ssdeep signature')
        return score


def root(run_id):
    return data_path(run_id, 'jobs', JOB, 'whole')


def inputs(run_id):
    if file_hash(ROOT / 'evidence_store.py') != LOADED_WORKER_SHA256:
        raise Blocked('index implementation changed in a running worker; start a new launch')
    from job_graph import composition
    template = read_json(ROOT / 'registry/job-templates/02-evidence-index.json')
    records = composition(template)
    upstream = phase1.accepted(run_id, fresh=True)
    if not upstream or upstream['status'] != 'OK':
        raise Blocked('fresh accepted intake required')
    producers = [{'kind': 'intake', 'pointer': upstream}]
    discovery = data_path(run_id, 'jobs', '00-workflow-preparation', 'build_discovery', 'accepted.json')
    if not discovery.exists():
        raise Blocked('accepted build discovery required; submit the evidence_index Dagster job')
    if discovery.exists():
        import workflow
        pointer = read_json(discovery)
        workflow.validate_branch(run_id, 'build_discovery', pointer)
        if pointer['upstream'] != upstream['fingerprint']:
            raise Blocked('build discovery belongs to another intake generation')
        producers.append({'kind': 'build_discovery', 'pointer': pointer})
    return {'producers': producers, 'limits': LIMITS, 'format': 1, 'template': template, 'composition': records,
            'worker_sha256': file_hash(ROOT / 'evidence_store.py'),
            'python': sys.version, 'sqlite': sqlite3.sqlite_version,
            'libfuzzy_sha256': file_hash(Path('/usr/lib/x86_64-linux-gnu/libfuzzy.so.2').resolve())}


def collect(run_id, attempt):
    if (attempt / 'index.sqlite').exists():
        raise Blocked('attempt already contains an index; allocate a new immutable attempt')
    plan = read_json(attempt / 'inputs.json')
    upstream = plan['producers'][0]['pointer']
    intake = phase1.job_root(run_id) / 'attempts' / upstream['attempt_id']
    source = read_json(intake / 'evidence/source.json')
    scope = read_json(intake / 'outputs/intake.json')['scope']
    excluded = set(scope['excluded_paths'])
    target = Path(source['target'])
    candidates, skipped = [], []
    for name, info in sorted(source['files'].items()):
        if name in excluded:
            skipped.append({'path': 'source/' + name, 'reason': 'excluded by accepted intake scope'})
            continue
        if info['kind'] != 'file':
            skipped.append({'path': 'source/' + name, 'reason': 'not a regular file'})
            continue
        candidates.append(('source/' + name, beneath(target, target / name), info['sha256'], info['bytes']))
    for producer in plan['producers']:
        pointer = producer['pointer']
        if producer['kind'] == 'intake':
            base = intake
            paths = ['outputs/intake.json', 'outputs/build-discovery.md']
        else:
            base = data_path(run_id, 'jobs', '00-workflow-preparation', 'build_discovery',
                             'attempts', pointer['attempt_id'])
            paths = ['output.json']
        for relative in paths:
            path = beneath(base, base / relative)
            candidates.append(('evidence/' + producer['kind'] + '/' + relative,
                               path, file_hash(path), path.stat().st_size))
    if len(candidates) > LIMITS['max_files']:
        raise Blocked('file budget exceeded; narrow the accepted source scope')
    fuzzy = Fuzzy()
    db = sqlite3.connect(attempt / 'index.sqlite')
    db.executescript('''PRAGMA journal_mode=DELETE; PRAGMA temp_store=MEMORY;
      CREATE TABLE files(path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL,
                         ssdeep TEXT NOT NULL, text_status TEXT NOT NULL);
      CREATE VIRTUAL TABLE chunks USING fts5(path UNINDEXED, sha256 UNINDEXED,
        start_line UNINDEXED, end_line UNINDEXED, content, tokenize='unicode61');''')
    total = chunks = 0
    signatures = io.StringIO()
    signatures.write('ssdeep,1.1--blocksize:hash:hash,filename\n')
    signature_writer = csv.writer(signatures, lineterminator='\n')
    try:
        for name, path, expected, size in candidates:
            if size > LIMITS['max_file_bytes']:
                skipped.append({'path': name, 'reason': 'file byte limit', 'bytes': size, 'sha256': expected})
                continue
            total += size
            if total > LIMITS['max_total_bytes']:
                raise Blocked('total snapshot byte budget exceeded')
            with path.open('rb') as stream:
                content = stream.read(LIMITS['max_file_bytes'] + 1)
            sha = hashlib.sha256(content).hexdigest()
            if len(content) != size or sha != expected:
                raise Blocked('source/evidence changed while collecting: ' + name)
            obj = attempt / 'objects' / sha
            if not obj.exists():
                atomic_bytes(obj, content)
            signature = fuzzy.hash(content)
            signature_writer.writerow([signature, name])
            status, text = 'indexed', None
            if b'\x00' in content:
                status = 'binary'
            elif size > LIMITS['max_text_bytes']:
                status = 'text byte limit'
            else:
                try:
                    text = content.decode('utf-8-sig')
                except UnicodeDecodeError:
                    status = 'not UTF-8'
                if text is not None and any(len(line) > LIMITS['max_line_chars'] for line in text.splitlines()):
                    status, text = 'line length limit', None
            db.execute('INSERT INTO files VALUES (?,?,?,?,?)', (name, sha, size, signature, status))
            if status == 'indexed':
                lines = text.splitlines()
                for start in range(0, len(lines), LIMITS['chunk_lines']):
                    end = min(len(lines), start + LIMITS['chunk_lines'])
                    db.execute('INSERT INTO chunks VALUES (?,?,?,?,?)', (name, sha, start + 1, end,
                                                                        '\n'.join(lines[start:end])))
                    chunks += 1
        db.commit()
        db.execute("INSERT INTO chunks(chunks) VALUES ('integrity-check')")
        db.commit()
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise Blocked('SQLite integrity check failed')
        counts = dict(db.execute('SELECT text_status, count(*) FROM files GROUP BY text_status'))
        atomic_bytes(attempt / 'ssdeep.csv', signatures.getvalue().encode('utf-8'))
        atomic_json(attempt / 'manifest.json', {'status': 'OK', 'source_fingerprint': source['fingerprint'],
                    'source_revision': source['revision'], 'files': sum(counts.values()), 'chunks': chunks,
                    'snapshot_bytes': total, 'text_status_counts': counts, 'excluded': skipped,
                    'untrusted_content': True, 'scope': 'source + accepted intake/build discovery outputs',
                    'producers': plan['producers'], 'limits': LIMITS})
        print(json.dumps({'files': sum(counts.values()), 'chunks': chunks, 'excluded': len(skipped)}))
        print('ssdeep hashes binary and text; full-text exclusions are recorded in files/manifest.', file=sys.stderr)
    finally:
        db.close()


def validate(run_id, pointer=None, fresh=True):
    base = root(run_id)
    pointer = pointer or read_json(base / 'accepted.json')
    if pointer.get('status') != 'OK' or read_json(base / 'latest.json')['attempt_id'] != pointer['attempt_id']:
        raise Blocked('no accepted latest index; rerun evidence_index')
    attempt = beneath(base, base / 'attempts' / identifier(pointer['attempt_id']))
    if tree_hashes(attempt) != pointer['hashes']:
        raise Blocked('index artifact integrity mismatch')
    if read_json(attempt / 'status.json')['status'] != 'OK':
        raise Blocked('index attempt is not successful')
    if fresh and digest(inputs(run_id)) != pointer['fingerprint']:
        raise Blocked('index is stale; rerun evidence_index')
    return pointer, attempt


def run(run_id, dagster_id, force=False):
    base = root(run_id)
    with Lock(base / 'job.lock'):
        # Retire interrupted attempts without changing their immutable partial evidence.
        if (base / 'latest.json').exists():
            latest = read_json(base / 'latest.json')
            old = base / 'attempts' / identifier(latest['attempt_id'])
            if not (old / 'status.json').exists() or read_json(old / 'status.json').get('status') == 'RUNNING':
                atomic_json(base / 'recoveries' / (uuid.uuid4().hex + '.json'),
                            {'attempt_id': latest['attempt_id'], 'reason': 'interrupted', 'time': now()})
        if not force and (base / 'accepted.json').exists():
            try:
                pointer, attempt = validate(run_id)
            except (Blocked, ValueError, OSError, KeyError):
                pass
            else:
                atomic_json(data_path(run_id, 'orchestration', 'dagster', identifier(dagster_id),
                                      'evidence-index-reuse.json'),
                            {'status': 'OK', 'producer': pointer, 'time': now()})
                return pointer
        attempt_id = uuid.uuid4().hex
        attempt = base / 'attempts' / attempt_id
        attempt.mkdir(parents=True)
        atomic_json(base / 'latest.json', {'attempt_id': attempt_id, 'dagster_run_id': dagster_id})
        atomic_json(base / 'accepted.json', {'status': 'PENDING', 'attempt_id': attempt_id})
        status = {'status': 'RUNNING', 'attempt_id': attempt_id, 'dagster_run_id': dagster_id,
                  'time': now(), 'resume_command': f'python -B appsec-review-process/launch_job.py --run-id {run_id} --job evidence_index --wait'}
        atomic_json(attempt / 'status.json', status)
        for phase in ('pre', 'post'):
            atomic_bytes(attempt / 'validation' / phase / 'stdout.log', b'')
            atomic_bytes(attempt / 'validation' / phase / 'stderr.log', b'')
        phase = 'pre'
        try:
            plan = inputs(run_id)
            atomic_json(attempt / 'inputs.json', plan)
            atomic_json(attempt / 'validation/pre.json', {'status': 'OK', 'fingerprint': digest(plan)})
            atomic_bytes(attempt / 'validation/pre/stdout.log', b'Fresh producers, role and tooling contract validated.\n')
            phase = 'work'
            temporary = attempt / 'tmp'
            temporary.mkdir()
            env = {k: v for k, v in os.environ.items() if k.upper() in ('PATH', 'SYSTEMROOT', 'WINDIR', 'LANG', 'LC_ALL')}
            env.update(APPSEC_RUNS_ROOT=str(data_path(run_id).parent.parent), PYTHONDONTWRITEBYTECODE='1',
                       PYTHONNOUSERSITE='1', TMP=str(temporary), TEMP=str(temporary), TMPDIR=str(temporary))
            outcome = execute([sys.executable, '-B', str(ROOT / 'evidence_store.py'), 'collect',
                               '--run-id', run_id, '--attempt', attempt_id], attempt, attempt / 'logs',
                              plan.get('template', {}).get('timeout_seconds', 600), env=env)
            if outcome.get('error') or outcome['exit_code'] != 0:
                raise Blocked('evidence collector failed: ' + json.dumps(outcome))
            phase = 'post'
            if inputs(run_id) != plan:
                raise Blocked('producer/config changed during indexing')
            manifest = read_json(attempt / 'manifest.json')
            if manifest['files'] == 0 or manifest['chunks'] == 0:
                raise Blocked('empty searchable corpus')
            atomic_json(attempt / 'validation/post.json', {'status': 'OK', 'files': manifest['files'],
                                                        'chunks': manifest['chunks']})
            atomic_bytes(attempt / 'validation/post/stdout.log', b'Fresh producers and nonempty integrity-checked corpus validated.\n')
            atomic_json(attempt / 'status.json', {**status, 'status': 'OK', 'ended_at': now()})
            pointer = {'status': 'OK', 'attempt_id': attempt_id, 'fingerprint': digest(plan),
                       'hashes': tree_hashes(attempt), 'run_id': run_id}
            with Lock(data_path(run_id, 'publication.lock')):
                if inputs(run_id) != plan:
                    raise Blocked('producer changed before publication')
                atomic_json(base / 'accepted.json', pointer)
            return pointer
        except BaseException as exc:
            atomic_json(attempt / 'validation/failure.json', {'status': 'FAILED', 'phase': phase, 'error': str(exc)})
            if phase in ('pre', 'post'):
                atomic_bytes(attempt / 'validation' / phase / 'stderr.log', (str(exc) + '\n').encode())
            atomic_json(attempt / 'status.json', {**status, 'status': 'FAILED', 'ended_at': now(), 'error': str(exc)})
            atomic_json(base / 'accepted.json', {'status': 'FAILED', 'attempt_id': attempt_id})
            raise


def query(run_id, action, text='', path='', limit=10, start=1, fresh=True):
    with Lock(root(run_id) / 'job.lock'):
        return _query(run_id, action, text, path, limit, start, fresh)


def _query(run_id, action, text='', path='', limit=10, start=1, fresh=True):
    if not 1 <= limit <= 50 or len(text) > 1000 or start < 1:
        raise ValueError('query bounds: limit 1..50, text <=1000 characters, start >=1')
    pointer, attempt = validate(run_id, fresh=fresh)
    db = sqlite3.connect((attempt / 'index.sqlite').as_uri() + '?mode=ro&immutable=1', uri=True)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA temp_store=MEMORY')
    # Bound FTS expressions and query work even for adversarial callers.
    budget = [0]
    def progress():
        budget[0] += 1
        return int(budget[0] > 10000)
    db.set_progress_handler(progress, 1000)
    try:
        if action == 'search':
            if not text.strip():
                raise ValueError('nonempty literal search required')
            # Literal terms joined by AND; caller text never becomes SQL or FTS operators.
            match = ' AND '.join('"' + word.replace('"', '""') + '"' for word in text.split())
            rows = [dict(row) for row in db.execute('''SELECT path,sha256,start_line,end_line,
              snippet(chunks,4,'[',']',' … ',32) AS excerpt FROM chunks
              WHERE chunks MATCH ? ORDER BY bm25(chunks),path,start_line LIMIT ?''', (match, limit))]
        elif action == 'read':
            row = db.execute('SELECT * FROM files WHERE path=?', (path,)).fetchone()
            if row is None:
                raise ValueError('path is not in the accepted index')
            if row['text_status'] != 'indexed':
                raise ValueError('not indexed text: ' + row['text_status'])
            lines = (attempt / 'objects' / row['sha256']).read_text(encoding='utf-8-sig').splitlines()
            if start > len(lines):
                raise ValueError('start line is beyond the file')
            excerpt = '\n'.join(lines[start-1:start-1+limit])
            if len(excerpt) > 65536:
                raise ValueError('read exceeds 64 KiB; request fewer lines')
            rows = [{'path': path, 'sha256': row['sha256'], 'start_line': start,
                     'end_line': min(len(lines), start + limit - 1), 'excerpt': excerpt}]
        elif action == 'similar':
            row = db.execute('SELECT sha256,ssdeep FROM files WHERE path=?', (path,)).fetchone()
            if row is None:
                raise ValueError('path is not in the accepted index')
            fuzzy = Fuzzy()
            rows = []
            for other in db.execute('SELECT path,sha256,ssdeep FROM files WHERE path<>?', (path,)):
                score = fuzzy.compare(row['ssdeep'], other['ssdeep'])
                if score or row['sha256'] == other['sha256']:
                    rows.append({'path': other['path'], 'sha256': other['sha256'], 'score': score,
                                 'exact': row['sha256'] == other['sha256']})
            rows = sorted(rows, key=lambda r: (-int(r['exact']), -r['score'], r['path']))[:limit]
        else:
            raise ValueError('unknown query action')
        if read_json(root(run_id) / 'accepted.json') != pointer:
            raise Blocked('index acceptance changed during retrieval; retry after producers complete')
        return {'run_id': run_id, 'attempt_id': pointer['attempt_id'], 'freshness_checked': fresh,
                'untrusted_content': True, 'results': rows}
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['collect', 'search', 'read', 'similar'])
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--attempt')
    parser.add_argument('--text', default='')
    parser.add_argument('--path', default='')
    parser.add_argument('--limit', type=int, default=10)
    parser.add_argument('--start', type=int, default=1)
    args = parser.parse_args()
    if args.action == 'collect':
        attempt = root(args.run_id) / 'attempts' / identifier(args.attempt)
        collect(args.run_id, beneath(data_path(args.run_id), attempt))
    else:
        print(json.dumps(query(args.run_id, args.action, args.text, args.path, args.limit, args.start), indent=2))


if __name__ == '__main__':
    main()
