#!/bin/bash
# run-dockerfile-lint.sh — static, baked-into-image replacement for the
# dockerfile-lint step's former inline "bash -lc <compound string>" Cmd.
#
# 2026-09-10 fix (confirmed live against a real fsh-server run's
# dockerfile-lint.stderr.log — not guessed): the previous inline compound
# string (a single PowerShell string literal containing a
# `while IFS= read -r -d "" f; do ... done < <(find ... -print0)`
# process-substitution pipeline, including a literal `-d ""` empty
# delimiter and nested double-quotes) did not survive the
# PowerShell-to-docker.exe argv marshalling intact. The real, observed
# failure was:
#     f;: -c: line 1: unexpected EOF while looking for matching `"'
#     f;: -c: line 2: syntax error: unexpected end of file
# i.e. bash received only a truncated/corrupted fragment of the intended
# command (starting mid-string at "f;"), not any error the script's own
# logic would ever produce. This is the SAME class of bug already
# root-caused and fixed for joern-parse, ast-grep-scan, and sast-php
# elsewhere in this toolbox (see those steps' own long Notes in
# Invoke-VendorAuditPrePass.ps1) — a compound string assembled via
# PowerShell concatenation/interpolation, passed through
# `& docker @dockerArgs` array-splatting, does not reliably survive intact,
# especially with embedded empty-string literals and nested quoting.
#
# Fix, consistent with every prior instance of this bug: move the whole
# thing into a static script file baked into the image (this file) and
# invoke it with a two-literal-element Cmd array
# (`@("bash", "/opt/scripts/run-dockerfile-lint.sh")`) in the orchestrator —
# no string concatenation, no shell re-parsing anywhere in the
# PowerShell-to-docker.exe path, ever again.
#
# Behavior is otherwise unchanged from the original inline command: walk
# /workspace for every Dockerfile*-named file, run `hadolint --no-fail`
# against each one, and write everything to hadolint.txt. This file is
# always created (even empty, on a Dockerfile-free repo) — that is a
# legitimate outcome, not a failure; do not add an emptiness check against
# it upstream.
set -u

out=/evidence/iac-docker/hadolint.txt
: > "$out"

while IFS= read -r -d "" f; do
  printf '=== %s ===\n' "$f" >> "$out"
  hadolint --no-fail "$f" >> "$out" 2>&1
done < <(find /workspace -iname "Dockerfile*" -type f -print0)

exit 0
