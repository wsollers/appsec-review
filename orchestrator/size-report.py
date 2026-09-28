#!/usr/bin/env python3
"""Print what a run's target actually generated: every size observation, largest first.

usage: orchestrator/size-report.py <run_id> [--over]   (--over: only values above a former limit)
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "appsec-review-process" / "runs"


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    folder = ROOT / args[0] / "data" / "size-observations"
    rows = []
    for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
        try:
            rows.append(json.loads(path.read_text(encoding="utf-8")))
        except ValueError:
            continue
    if "--over" in sys.argv:
        rows = [r for r in rows if r.get("over_former_limit")]
    if not rows:
        print("no size observations yet")
        return 0
    rows.sort(key=lambda r: (r.get("job") or "", r.get("metric") or ""))
    print(f"{'job':<42} {'metric':<28} {'value':>12} {'former':>10}  extra")
    for r in rows:
        extra = {k: v for k, v in r.items() if k not in
                 {"run_id", "job", "metric", "value", "former_limit", "over_former_limit", "observed_at"}}
        flag = " *" if r.get("over_former_limit") else ""
        print(f"{str(r.get('job')):<42} {r['metric']:<28} {r['value']:>12} "
              f"{str(r.get('former_limit') or '-'):>10}{flag} {json.dumps(extra) if extra else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
