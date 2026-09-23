#!/usr/bin/env python3
"""Re-attest the Phase 1 implementation spec after maintenance edits (A01).

A01 accepts qualification only when the run's data/acceptance/prompt-vetting.json records the
SHA-256 of the spec as it is now. A review is only valid for the exact text it reviewed, so any
edit to phase-1-implementation-prompt.md (even a moved link) invalidates it. This tool is the
honest way to carry a review forward: it shows the diff between the reviewed revision and the
current file, and writes a new record only with an explicit, named approval of that diff. It never
rehashes blindly.

    attest_prompt.py --run-id <qualification_run> --reviewed-revision <git rev> --prior-sha256 <sha>
        # prints the diff and exits 2 (nothing written)
    attest_prompt.py ... --approved-by "<name>" --classification "<why the diff changes no requirement>" --approve
        # writes data/acceptance/prompt-vetting.json

--prior-sha256 is the prompt_sha256 of the earlier review record; the tool checks it equals the
spec's hash at --reviewed-revision, which proves the earlier review covered that exact commit.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from execution_state import ROOT, atomic_json, data_path, now

REPO = ROOT.parent
SPEC = 'appsec-review-process/phase-1-implementation-prompt.md'


def git(*args: str) -> str:
    return subprocess.run(['git', '-C', str(REPO), *args], check=True, capture_output=True, text=True).stdout


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--run-id', required=True)
    ap.add_argument('--reviewed-revision', required=True, help='git revision of the spec the earlier review covered')
    ap.add_argument('--prior-sha256', required=True, help='prompt_sha256 recorded by the earlier review')
    ap.add_argument('--prior-reviewer', default='', help='who performed the earlier review, as recorded')
    ap.add_argument('--approved-by', default='')
    ap.add_argument('--classification', default='')
    ap.add_argument('--approve', action='store_true')
    args = ap.parse_args(argv)

    if not data_path(args.run_id).parent.joinpath('run-status.json').exists():
        ap.error(f'run {args.run_id} does not exist')
    reviewed_bytes = subprocess.run(['git', '-C', str(REPO), 'show', f'{args.reviewed_revision}:{SPEC}'],
                                    check=True, capture_output=True).stdout
    reviewed_sha = hashlib.sha256(reviewed_bytes).hexdigest()
    if reviewed_sha != args.prior_sha256:
        print(f'attest_prompt: the spec at {args.reviewed_revision} hashes to {reviewed_sha}, not the prior '
              f'review\'s {args.prior_sha256}; that review did not cover this revision', file=sys.stderr)
        return 1
    current = (REPO / SPEC).read_bytes()
    current_sha = hashlib.sha256(current).hexdigest()
    diff = git('diff', '--no-color', '-U0', args.reviewed_revision, '--', SPEC).replace('\r', '')
    worktree_dirty = bool(git('status', '--porcelain', '--', SPEC).strip())
    print(f'reviewed: {args.reviewed_revision} ({reviewed_sha})\ncurrent:  working tree ({current_sha})'
          + (' -- UNCOMMITTED EDITS' if worktree_dirty else ''))
    print(diff or '(no textual difference)')
    if not args.approve:
        print('attest_prompt: nothing written. Review the diff above; re-run with --approved-by, '
              '--classification and --approve to record it.', file=sys.stderr)
        return 2
    if worktree_dirty:
        print('attest_prompt: refusing: the spec has uncommitted edits; commit them first', file=sys.stderr)
        return 1
    if not args.approved_by.strip() or not args.classification.strip():
        ap.error('--approve needs --approved-by and --classification')

    out = data_path(args.run_id, 'acceptance', 'prompt-vetting.json')
    if out.exists():
        existing = json.loads(out.read_text(encoding='utf-8'))
        if existing.get('prompt_sha256') == current_sha:
            print(json.dumps({'status': 'already-attested', 'path': str(out), 'prompt_sha256': current_sha}))
            return 0
        print(f'attest_prompt: {out} already records a different hash; refusing to overwrite a review record',
              file=sys.stderr)
        return 1
    lines = current.decode('utf-8').replace('\r\n', '\n').split('\n')
    record = {
        'reviewer': f'{args.approved_by} (re-attestation of a prior review; diff reviewed, full text not re-reviewed)',
        'date': now(),
        'prompt_sha256': current_sha,
        'base_revision': git('rev-parse', 'HEAD').strip(),
        'requirements': [{'line': n, 'requirement': text} for n, text in enumerate(lines, 1) if text.strip()],
        'findings': [],
        'requirement_blockers': [],
        'acceptance': 'Re-attested: carries the prior review forward across the diff below.',
        're_attestation': {
            'reviewed_revision': git('rev-parse', args.reviewed_revision).strip(),
            'reviewed_sha256': reviewed_sha,
            'prior_reviewer': args.prior_reviewer or None,
            'diff': diff,
            'classification': args.classification,
            'approved_by': args.approved_by,
        },
    }
    atomic_json(out, record)
    print(json.dumps({'status': 'attested', 'path': str(out), 'prompt_sha256': current_sha}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
