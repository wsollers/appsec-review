#!/usr/bin/env bash
# codeql-sast-lane.sh LANGUAGE BUILD_MODE SUITE THREADS RAM_MB [COMPILE_COMMANDS [GRAPH_PACK]]
#
# One 02-codeql-sast lane (appsec-review-process/codeql_sast.py), offline (the bundle ships the
# query packs; nothing is downloaded). Any failure exits non-zero and the worker records a coverage
# gap for that lane (ADR-0013). No license gate (William, 2026-09-28).
#
# BUILD_MODE none    database create --build-mode none from the read-only /workspace (audit-codeql).
# BUILD_MODE traced  cpp only, audit-codeql-native: CodeQL traces replay_compile_commands.py, which
#                    re-runs the accepted native build's adapted compile database (compiler
#                    invocations only; no target build script runs). Replay counts go to
#                    /scratch/replay.json. With GRAPH_PACK, the appsec/cpp-graph-queries table
#                    queries also run and are decoded to /scratch/graph/<Query>.csv (brief E);
#                    a graph query failure is logged and does not fail the lane.
# Then the SUITE is analyzed to /scratch/codeql.sarif and the database is dropped.
set -euo pipefail
usage() { echo "usage: $0 LANGUAGE none|traced SUITE THREADS RAM_MB [COMPILE_COMMANDS [GRAPH_PACK]]" >&2; exit 2; }
[ "$#" -ge 5 ] && [ "$#" -le 7 ] || usage
language=$1; mode=$2; suite=$3; threads=$4; ram=$5
case "$mode" in
  none) [ "$#" -eq 5 ] || usage ;;
  traced) [ "$language" = cpp ] && [ "$#" -ge 6 ] || usage ;;
  *) usage ;;
esac
export HOME=/tmp
codeql=/opt/codeql/codeql
"$codeql" version --format=terse
case "$mode" in
  none)
    "$codeql" database create /scratch/db --language="$language" --source-root=/workspace \
      --build-mode=none --threads="$threads" --ram="$ram" --overwrite
    ;;
  traced)
    compile_commands=$6
    [ -f "$compile_commands" ] || { echo "compile database not found: $compile_commands" >&2; exit 2; }
    "$codeql" database create /scratch/db --language=cpp --source-root=/workspace \
      --command="python3 /opt/scripts/replay_compile_commands.py $compile_commands --stats /scratch/replay.json" \
      --threads="$threads" --ram="$ram" --overwrite
    ;;
esac
"$codeql" database analyze /scratch/db "$suite" --format=sarif-latest \
  --output=/scratch/codeql.sarif --threads="$threads" --ram="$ram"
if [ "$mode" = traced ] && [ "$#" -eq 7 ]; then
  pack=$7
  mkdir -p /scratch/graph
  for query in CallEdges EntryPoints FlowSources; do
    if "$codeql" query run --database=/scratch/db --additional-packs=/opt/codeql/qlpacks \
         --threads="$threads" --ram="$ram" --output="/scratch/graph/$query.bqrs" "$pack/$query.ql" \
         > "/scratch/graph/$query.log" 2>&1 \
       && "$codeql" bqrs decode --format=csv --output="/scratch/graph/$query.csv" "/scratch/graph/$query.bqrs" \
         >> "/scratch/graph/$query.log" 2>&1; then
      echo "graph $query: ok"
    else
      echo "graph $query: failed (see /scratch/graph/$query.log)" >&2
      rm -f "/scratch/graph/$query.csv"
    fi
    rm -f "/scratch/graph/$query.bqrs"
  done
fi
rm -rf /scratch/db
