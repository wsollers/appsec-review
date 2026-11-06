from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .baseline import baseline_json, decode_baseline, prune
from .config import GateError, checked_file, load_config
from .runner import check, static_checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed offline development quality gates")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    subparsers = parser.add_subparsers(dest="command", required=True)
    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--base", default="HEAD")
    check_parser.add_argument("--full", action="store_true")
    modes = check_parser.add_mutually_exclusive_group()
    modes.add_argument("--static-only", action="store_true")
    modes.add_argument("--units-only", action="store_true")
    baseline_parser = subparsers.add_parser("baseline")
    operations = baseline_parser.add_mutually_exclusive_group(required=True)
    operations.add_argument("--initialize", action="store_true")
    operations.add_argument("--prune", action="store_true")
    baseline_parser.add_argument("--reason", required=True)
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve()
        config = load_config(root)
        if args.command == "check":
            report = check(root, config, base=args.base, full=args.full,
                           static_only=args.static_only, units_only=args.units_only)
            print(json.dumps(report, indent=2))
            return 0 if report["status"] == "PASS" else 1
        path = root / config.baseline
        if not args.reason.strip():
            raise GateError("configuration", "baseline requires a review reason")
        if args.initialize and path.exists():
            raise GateError("baseline-growth", "initialization never overwrites a baseline")
        findings, timing, count = static_checks(root, config)
        if args.prune:
            old = decode_baseline(checked_file(root, config.baseline).read_text(encoding="utf-8"))
            findings = prune(findings, old)
        contents = baseline_json(findings, args.reason)
        decode_baseline(contents)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8", newline="\n")
        print(json.dumps({"baseline_entries": len(findings), "modules_scanned": count, "seconds": timing}))
        return 0
    except (GateError, OSError, UnicodeError) as error:
        category = error.category if isinstance(error, GateError) else "input-error"
        print(json.dumps({"status": "ERROR", "category": category, "message": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
