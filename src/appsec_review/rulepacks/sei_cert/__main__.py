"""Command line for the SEI CERT rule pack.

    python -m appsec_review.rulepacks.sei_cert validate
    python -m appsec_review.rulepacks.sei_cert lock
    python -m appsec_review.rulepacks.sei_cert report [--check] [--evaluation DIR]
    python -m appsec_review.rulepacks.sei_cert evaluate --output test/tmp/sei-cert-evaluation
    python -m appsec_review.rulepacks.sei_cert verify-evaluation --output DIR
    python -m appsec_review.rulepacks.sei_cert source-index --checkout DIR --retrieved YYYY-MM-DD

Engines are located through APPSEC_REVIEW_SEMGREP / APPSEC_REVIEW_OPENGREP or PATH, and must match
the versions pinned in rules/sei-cert/pack.json.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from .evaluate import evaluate, verify_evaluation
from .pack import PACK_ROOT, load_pack, write_lock
from .report import render
from .sources import build_source_index
from .validate import validate

COVERAGE_REPORT = "COVERAGE.md"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m appsec_review.rulepacks.sei_cert")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate", help="validate rules, mappings, fixtures, and the content lock")
    commands.add_parser("lock", help="rewrite pack.lock.json from the current pack contents")
    report = commands.add_parser("report", help="regenerate COVERAGE.md")
    report.add_argument("--check", action="store_true", help="fail if COVERAGE.md is stale")
    report.add_argument("--evaluation", type=Path, help="render an evaluation directory to stdout")
    run = commands.add_parser("evaluate", help="run both engines over fixtures and multivuln")
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--multivuln-target", type=Path)
    run.add_argument("--skip-multivuln", action="store_true")
    verify = commands.add_parser("verify-evaluation", help="re-hash an evaluation's artifacts")
    verify.add_argument("--output", type=Path, required=True)
    source = commands.add_parser("source-index", help="rebuild the official source index from a checkout")
    source.add_argument("--checkout", type=Path, required=True)
    source.add_argument("--retrieved", required=True)
    args = parser.parse_args(argv)

    if args.command == "validate":
        errors = validate()
        for error in errors:
            print(error, file=sys.stderr)
        print("valid" if not errors else f"{len(errors)} validation error(s)")
        return 0 if not errors else 1
    if args.command == "lock":
        lock = write_lock()
        print(f"locked {len(lock['files'])} files; tree {lock['tree_sha256']}")
        return 0
    if args.command == "report":
        pack = load_pack()
        if args.evaluation is not None:
            evaluation = json.loads((args.evaluation / "evaluation.json").read_text(encoding="utf-8"))
            sys.stdout.write(render(pack, evaluation))
            return 0
        text = render(pack)
        path = PACK_ROOT / COVERAGE_REPORT
        if args.check:
            current = path.read_text(encoding="utf-8") if path.is_file() else ""
            if current != text:
                print(f"{path} is stale; run the report command and the lock command", file=sys.stderr)
                return 1
            return 0
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
        return 0
    if args.command == "evaluate":
        result = evaluate(args.output, multivuln_target=args.multivuln_target,
                          include_multivuln=not args.skip_multivuln)
        for failure in result["failures"]:
            print(failure, file=sys.stderr)
        print(f"{result['status']}: evaluation written to {args.output}")
        return 0 if result["status"] == "PASSED" else 1
    if args.command == "verify-evaluation":
        errors = verify_evaluation(args.output)
        for error in errors:
            print(error, file=sys.stderr)
        print("verified" if not errors else f"{len(errors)} problem(s)")
        return 0 if not errors else 1
    if args.command == "source-index":
        index = build_source_index(args.checkout, retrieved=args.retrieved)
        target = PACK_ROOT / load_pack().manifest["source_index"]
        target.write_text(json.dumps(index, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"wrote {target} with {len(index['entries'])} entries")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
