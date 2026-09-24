#!/usr/bin/env python3
"""Contract enforcement for the system acceptance test: verify what a command reads, verify what it wrote.

Every SAT command runs between a pre- and a post-contract (scripts/system-acceptance-test.sh,
run_step). A contract is JSON:

    {
      "inputs":  [ {"path": "{run}/inputs/artifact-manifest.json", "kind": "file",
                    "schema": "intake.schema.json",                       # optional, schemas/<name>
                    "equals": {"intake_config.executor_platform": "posix"}, # optional
                    "nonempty": ["run_id"]},                                # optional
                   {"path": "{run}/data/jobs/x/supplied/result.json", "kind": "absent"} ],
      "exit": 0,                                       # expected exit code (default 0)
      "writes": {"required": ["{run}/run-status.json"],   # each must match >= 1 changed path
                 "allowed":  ["{run}/data/**"],           # every added/modified path must match
                 "deletes":  []},                         # every deleted path must match
      "outputs": [ {"path": "{run}/data/jobs/00-intake/whole/attempts/*/outputs/intake.json",
                    "schema": "intake.schema.json", "min": 1} ]
    }

Placeholders: {run} (appsec-review-process/runs/<run_id>), {target} (fixtures/targets/<fixture>),
{fixture}, {run_id}. Patterns are repository-relative, fnmatch-style ("*" also crosses "/").

Ambient paths change without any SAT command (Dagster's own host storage, the scheduled NVD feed);
they are reported, never counted as a command's writes.

    sat_contract.py snapshot OUT --repo R [--hash-root DIR ...] [--exclude DIR ...]
    sat_contract.py pre  --repo R --contract C --vars V
    sat_contract.py post --repo R --contract C --vars V --before B --after A --exit N --report OUT

Standard library only; schema validation uses appsec-review-process/schema_validate.py (the
project's dependency-free validator), called here independently of the job under test.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
from pathlib import Path

AMBIENT = ['orchestrator/dagster/.host/**', 'data/feeds/nvd/**']
SKIP_DIRS = {'.git', '__pycache__', 'node_modules', '.pytest_cache'}


def render(value, variables):
    if isinstance(value, str):
        for k, v in variables.items():
            value = value.replace('{' + k + '}', v)
        return value
    if isinstance(value, list):
        return [render(x, variables) for x in value]
    if isinstance(value, dict):
        return {k: render(v, variables) for k, v in value.items()}
    return value


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def snapshot(repo: Path, hash_roots: list[str], excludes: list[str]) -> dict:
    """path -> [size, mtime_ns, sha256|None]; content hashes for files under the hash roots."""
    repo = repo.resolve()
    excl = {(repo / e).resolve() for e in excludes}
    roots = [(repo / r).resolve() for r in hash_roots]
    files = {}
    for dirpath, dirnames, filenames in os.walk(repo):
        d = Path(dirpath)
        dirnames[:] = [n for n in dirnames if n not in SKIP_DIRS and (d / n).resolve() not in excl]
        for name in filenames:
            p = d / name
            try:
                st = p.lstat()
            except FileNotFoundError:
                continue
            rel = p.relative_to(repo).as_posix()
            digest = None
            if p.is_file() and not p.is_symlink() and any(str(p.resolve()).startswith(str(r) + os.sep) for r in roots):
                try:
                    digest = sha256(p)
                except OSError:
                    digest = None
            files[rel] = [st.st_size, st.st_mtime_ns, digest]
    return files


def matches(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pat) for pat in patterns)


def dotted(value, key):
    for part in key.split('.'):
        if not isinstance(value, dict) or part not in value:
            return KeyError
        value = value[part]
    return value


def check_json(path: Path, spec: dict, repo: Path) -> list[str]:
    """Parse, schema-validate and apply equals/nonempty checks; returns problems."""
    problems = []
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except Exception as exc:
        return [f'{path.relative_to(repo)}: not valid JSON ({exc})']
    if spec.get('schema'):
        sys.path.insert(0, str(repo / 'appsec-review-process'))
        from schema_validate import validate_document
        errors = validate_document(value, spec['schema'])
        problems += [f'{path.relative_to(repo)}: schema {spec["schema"]}: {e}' for e in errors[:10]]
    for key, expected in (spec.get('equals') or {}).items():
        got = dotted(value, key)
        if got != expected:
            problems.append(f'{path.relative_to(repo)}: {key} = {got if got is not KeyError else "<missing>"!r}, expected {expected!r}')
    for key in spec.get('nonempty') or []:
        got = dotted(value, key)
        if got is KeyError or got in (None, '', [], {}):
            problems.append(f'{path.relative_to(repo)}: {key} is missing or empty')
    return problems


def resolve_glob(repo: Path, pattern: str) -> list[Path]:
    return sorted(p for p in repo.glob(pattern) if p.is_file())


def cmd_pre(args) -> int:
    repo = Path(args.repo).resolve()
    contract = render(json.loads(Path(args.contract).read_text()), json.loads(args.vars))
    problems, checked = [], []
    for spec in contract.get('inputs', []):
        kind = spec.get('kind', 'file')
        hits = resolve_glob(repo, spec['path']) if any(c in spec['path'] for c in '*?[') else [repo / spec['path']]
        if kind == 'absent':
            present = [h for h in hits if h.exists()]
            if present:
                problems.append(f'input must be absent: {present[0].relative_to(repo)}')
            checked.append({'path': spec['path'], 'kind': 'absent', 'ok': not present})
            continue
        if kind == 'dir':
            ok = (repo / spec['path']).is_dir()
            if not ok:
                problems.append(f'input directory missing: {spec["path"]}')
            checked.append({'path': spec['path'], 'kind': 'dir', 'ok': ok})
            continue
        existing = [h for h in hits if h.is_file()]
        if not existing:
            problems.append(f'input file missing: {spec["path"]}')
            checked.append({'path': spec['path'], 'kind': 'file', 'ok': False})
            continue
        for h in existing:
            p = check_json(h, spec, repo) if (spec.get('schema') or spec.get('equals') or spec.get('nonempty') or h.suffix == '.json') else []
            problems += p
            checked.append({'path': h.relative_to(repo).as_posix(), 'kind': 'file', 'sha256': sha256(h),
                            'schema': spec.get('schema'), 'ok': not p})
    print(json.dumps({'inputs': checked, 'problems': problems}))
    return 1 if problems else 0


def cmd_post(args) -> int:
    repo = Path(args.repo).resolve()
    contract = render(json.loads(Path(args.contract).read_text()), json.loads(args.vars))
    before = json.loads(Path(args.before).read_text())
    after = json.loads(Path(args.after).read_text())
    added = sorted(set(after) - set(before))
    deleted = sorted(set(before) - set(after))
    modified = sorted(p for p in set(after) & set(before) if after[p] != before[p])
    writes = contract.get('writes', {})
    allowed, required, deletes = writes.get('allowed', []), writes.get('required', []), writes.get('deletes', [])
    ambient = [p for p in added + modified + deleted if matches(p, AMBIENT)]
    changed = [p for p in added + modified if p not in ambient]
    gone = [p for p in deleted if p not in ambient]
    problems = []
    if args.exit != contract.get('exit', 0):
        problems.append(f'exit code {args.exit}, contract expects {contract.get("exit", 0)}')
    unexpected = [p for p in changed if not matches(p, allowed + required)]
    problems += [f'unexpected write: {p}' for p in unexpected]
    problems += [f'unexpected delete: {p}' for p in gone if not matches(p, deletes)]
    for pat in required:
        if not any(fnmatch.fnmatchcase(p, pat) for p in changed):
            problems.append(f'required write missing: {pat}')
    validated = []
    for spec in contract.get('outputs', []):
        hits = resolve_glob(repo, spec['path'])
        # Only artifacts this command wrote are judged as its outputs.
        hits = [h for h in hits if h.relative_to(repo).as_posix() in changed] if spec.get('written', True) else hits
        if len(hits) < spec.get('min', 1):
            problems.append(f'output missing: {spec["path"]} (found {len(hits)}, need {spec.get("min", 1)})')
        for h in hits:
            p = check_json(h, spec, repo) if h.suffix == '.json' or spec.get('schema') else []
            problems += p
            validated.append({'path': h.relative_to(repo).as_posix(), 'schema': spec.get('schema'), 'ok': not p})
    # 'written' and 'removed' are this command's own changes (ambient excluded); stages use these.
    report = {'exit': args.exit, 'written': changed, 'removed': gone, 'added': added, 'modified': modified,
              'deleted': deleted, 'ambient': ambient, 'outputs_validated': validated, 'problems': problems}
    Path(args.report).write_text(json.dumps(report, indent=1))
    print(json.dumps({'written': len(changed), 'deleted': len(gone), 'ambient': len(ambient),
                      'outputs_validated': len(validated), 'problems': problems}))
    return 1 if problems else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('snapshot'); s.add_argument('out'); s.add_argument('--repo', required=True)
    s.add_argument('--hash-root', action='append', default=[]); s.add_argument('--exclude', action='append', default=[])
    p = sub.add_parser('pre'); p.add_argument('--repo', required=True); p.add_argument('--contract', required=True); p.add_argument('--vars', required=True)
    q = sub.add_parser('post')
    for a in ('--repo', '--contract', '--vars', '--before', '--after', '--report'):
        q.add_argument(a, required=True)
    q.add_argument('--exit', type=int, required=True)
    args = ap.parse_args()
    if args.cmd == 'snapshot':
        Path(args.out).write_text(json.dumps(snapshot(Path(args.repo), args.hash_root, args.exclude)))
        return 0
    return cmd_pre(args) if args.cmd == 'pre' else cmd_post(args)


if __name__ == '__main__':
    sys.exit(main())
