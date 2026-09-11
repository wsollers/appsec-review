#!/usr/bin/env python3
"""
php_parse_coverage.py — independent parse-coverage ledger for PHP source.

Remediation for finding S6-1 (Adversarial Process Review, 2026-09-01):
against PHP 5-era vendor syntax (e.g. the `$secret{0}` curly-brace string
offset, removed since PHP 8.0) running under this toolbox's PHP 8.x tooling,
PHPStan hard-errors with "Result is incomplete because of severe errors" and
never analyzes the rest of that file's content (fail-open on parse failure -
a count-only consumer reads that as "1 error", not "1 file never analyzed").
Psalm keeps going but drops the broken file's own findings. Only Semgrep
(tree-sitter error recovery) reliably keeps matching sinks in a file that
doesn't fully parse - which is why it should be treated as the PRIMARY PHP
SAST pass here (sast-multi-semgrep, p/php config), with PHPStan/Psalm as
secondary/supplementary passes whose "0 findings" on a given file is NOT
evidence that file was analyzed.

This script is independent of all three of those tools: it runs `php -l`
(the interpreter's own syntax check, not a linter with its own opinions)
against every .php file in the target tree and records, per file, whether it
parses at all under the container's PHP version. Cross-reference the
NOT_ANALYZED list here against psalm.json / phpstan.json's own file lists
before treating either tool's silence on a file as "clean".

Usage:
    python3 php_parse_coverage.py /workspace -o /evidence/sast-php/parse-coverage.json
"""
import argparse
import json
import os
import subprocess
import sys


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", help="Directory to walk for .php files")
    ap.add_argument("-o", "--out", required=True, help="Output JSON path")
    ap.add_argument("--php-bin", default="php", help="php CLI to use for -l (default: php on PATH)")
    args = ap.parse_args()

    php_files = []
    for dirpath, dirnames, filenames in os.walk(args.root):
        # Skip the usual noise the rest of the toolbox already excludes.
        dirnames[:] = [d for d in dirnames if d not in (".git", "vendor", "node_modules")]
        for fname in filenames:
            if fname.lower().endswith(".php"):
                php_files.append(os.path.join(dirpath, fname))

    results = []
    parsed_ok = 0
    parse_failed = 0

    for path in sorted(php_files):
        try:
            proc = subprocess.run(
                [args.php_bin, "-l", path],
                capture_output=True, text=True, timeout=30,
            )
            ok = proc.returncode == 0
            message = (proc.stdout or proc.stderr or "").strip()
        except subprocess.TimeoutExpired:
            ok = False
            message = "php -l timed out after 30s"
        except OSError as e:
            ok = False
            message = f"could not invoke php -l: {e}"

        rel = os.path.relpath(path, args.root)
        results.append({
            "file": rel,
            "status": "PARSED" if ok else "NOT_ANALYZED",
            "detail": message,
        })
        if ok:
            parsed_ok += 1
        else:
            parse_failed += 1

    summary = {
        "total_php_files": len(php_files),
        "parsed_ok": parsed_ok,
        "not_analyzed": parse_failed,
        "note": (
            "PARSED here means php -l accepted the file's syntax under this "
            "container's PHP version - it says nothing about PHPStan/Psalm/"
            "PHPCS's own internal parsing, which can still diverge (PHPStan "
            "in particular has been observed to hard-error and skip a file "
            "that php -l itself accepts, and vice versa for old constructs "
            "php -l is lenient about). Treat NOT_ANALYZED files as having "
            "zero SAST coverage from any tool in this pipeline except "
            "Semgrep, and prioritize a manual look or a legacy-PHP-version "
            "toolchain pass for them."
        ),
        "results": results,
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"PHP parse coverage: {parsed_ok}/{len(php_files)} files parsed, "
          f"{parse_failed} NOT_ANALYZED. Written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
