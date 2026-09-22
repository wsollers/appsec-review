#!/usr/bin/env python3
"""Install a fixture's supplied discovery record into an engagement run.

    fixtures/supply_record.py --run-id <run_id> --job 02-repository-partition-discovery [--fixture hello-autotools]

Copies fixtures/supplied/<fixture>/<job>.json to the run's
data/jobs/<job>/supplied/result.json, the path the discovery gate names in its hand-off.

Fails closed: the run must exist and be staged, the staged target must be a git checkout whose HEAD
is exactly the record's source_revision (the analysis was written against that commit), and an
existing, different supplied file is never overwritten (supplied results are evidence).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parent.parent
RUNS = Path(os.environ.get('APPSEC_RUNS_ROOT') or REPO / 'appsec-review-process' / 'runs')


def fail(message: str) -> int:
    print(f'supply_record: {message}', file=sys.stderr)
    return 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--run-id', required=True)
    ap.add_argument('--job', required=True)
    ap.add_argument('--fixture', default='hello-autotools')
    args = ap.parse_args(argv)

    source = REPO / 'fixtures' / 'supplied' / args.fixture / f'{args.job}.json'
    if not source.is_file():
        return fail(f'no supplied record for {args.fixture}/{args.job} ({source})')
    record = json.loads(source.read_text(encoding='utf-8'))

    run = RUNS / args.run_id
    manifest_path = run / 'inputs' / 'artifact-manifest.json'
    if not manifest_path.is_file():
        return fail(f'run {args.run_id} is not staged ({manifest_path} missing)')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    target = (manifest.get('target') or {}).get('repo_path')
    if not target:
        return fail('staged manifest has no target.repo_path')

    revision = record.get('source_revision')
    head = subprocess.run(['git', '-C', target, 'rev-parse', 'HEAD'], capture_output=True, text=True)
    if head.returncode != 0:
        return fail(f'cannot read HEAD of staged target {target}: {head.stderr.strip()}')
    if head.stdout.strip() != revision:
        return fail(f'staged target is at {head.stdout.strip()}, record was written against {revision}')
    dirty = subprocess.run(['git', '-C', target, 'status', '--porcelain'], capture_output=True, text=True)
    if dirty.returncode != 0 or dirty.stdout.strip():
        return fail(f'staged target {target} has local modifications; citations would not match')

    dest = run / 'data' / 'jobs' / args.job / 'supplied' / 'result.json'
    data = source.read_bytes()
    if dest.exists():
        if hashlib.sha256(dest.read_bytes()).digest() == hashlib.sha256(data).digest():
            print(json.dumps({'status': 'already-supplied', 'path': str(dest)}))
            return 0
        return fail(f'{dest} already holds a different supplied result; refusing to overwrite evidence')
    dest.parent.mkdir(parents=True, exist_ok=True)
    temporary = dest.with_suffix('.tmp')
    temporary.write_bytes(data)
    os.replace(temporary, dest)
    print(json.dumps({'status': 'supplied', 'path': str(dest),
                      'sha256': hashlib.sha256(data).hexdigest(), 'source_revision': revision}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
