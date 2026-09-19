#!/usr/bin/env python3
"""Stage an artifact manifest for a process run from an engagement output dir."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def existing(path: Path) -> str:
    return str(path) if path.exists() else ""


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def main() -> int:
    from phase1 import stage
    from execution_state import emergency
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run-id', required=True)
    ap.add_argument('--project', required=True)
    ap.add_argument('--target', required=True)
    ap.add_argument('--engagement-output', default='')
    ap.add_argument('--import-legacy', action='store_true')
    ap.add_argument('--compile-db', default='')
    ap.add_argument('--business-goal', required=True)
    ap.add_argument('--platform', action='append', required=True)
    ap.add_argument('--budget', choices=['probe','standard','full'], default='probe')
    ap.add_argument('--include', action='append')
    ap.add_argument('--exclude', action='append')
    ap.add_argument('--permission', action='append')
    ap.add_argument('--execution-environment', default='local-read-only')
    args = ap.parse_args()
    try:
        data = stage(args.run_id, args.target, args.project, args.business_goal, args.platform,
                     args.budget, args.include, args.exclude, args.permission, args.execution_environment,
                     args.engagement_output, args.import_legacy, args.compile_db)
        print(json.dumps({'run_id':args.run_id, 'data_root':data['data_root'], 'notes':data['notes']}))
        return 0
    except Exception as exc:
        emergency(exc)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
