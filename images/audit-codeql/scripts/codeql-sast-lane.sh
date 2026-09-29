#!/usr/bin/env bash
# codeql-sast-lane.sh LANGUAGE BUILD_MODE SUITE THREADS RAM_MB
#
# One 02-codeql-sast language lane (appsec-review-process/codeql_sast.py): create a CodeQL
# database from the read-only /workspace with the given build mode, analyze it with one pinned
# bundled suite, write /scratch/codeql.sarif, then drop the database. Offline: the bundle ships
# the query packs; nothing is downloaded. Any failure exits non-zero and the worker records a
# coverage gap for that language (ADR-0013). No license gate (William, 2026-09-28).
set -euo pipefail
[ "$#" -eq 5 ] || { echo "usage: $0 LANGUAGE BUILD_MODE SUITE THREADS RAM_MB" >&2; exit 2; }
language=$1; mode=$2; suite=$3; threads=$4; ram=$5
export HOME=/tmp
codeql=/opt/codeql/codeql
"$codeql" version --format=terse
"$codeql" database create /scratch/db --language="$language" --source-root=/workspace \
  --build-mode="$mode" --threads="$threads" --ram="$ram" --overwrite
"$codeql" database analyze /scratch/db "$suite" --format=sarif-latest \
  --output=/scratch/codeql.sarif --threads="$threads" --ram="$ram"
rm -rf /scratch/db
