#!/usr/bin/env bash
# codeql-sast-lane.sh LANGUAGE BUILD_MODE SUITE THREADS RAM_MB KEEP_DB [COMPILE_COMMANDS [GRAPH_PACK]]
#
# One 02-codeql-<lang> lane (appsec-review-process/codeql_sast.py), offline (the bundle ships the
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
# Then the SUITE is analyzed to /scratch/codeql.sarif. KEEP_DB keep-db leaves the finalized
# database at /scratch/db for the worker to retain (ADR-0023: the reachability engines reuse it and
# never rebuild); drop-db removes it.
set -euo pipefail
usage() { echo "usage: $0 LANGUAGE none|traced|autobuild SUITE THREADS RAM_MB keep-db|drop-db [COMPILE_COMMANDS [GRAPH_PACK] | online|offline (autobuild)]" >&2; exit 2; }
[ "$#" -ge 6 ] && [ "$#" -le 8 ] || usage
language=$1; mode=$2; suite=$3; threads=$4; ram=$5; keep=$6
case "$keep" in keep-db|drop-db) ;; *) usage ;; esac
case "$mode" in
  none) [ "$#" -eq 6 ] || usage ;;
  traced) [ "$language" = cpp ] && [ "$#" -ge 7 ] || usage ;;
  autobuild) [ "$language" = go ] && { [ "$#" -eq 6 ] || { [ "$#" -eq 7 ] && case "$7" in online|offline) true ;; *) false ;; esac; }; } || usage ;;
  *) usage ;;
esac
export HOME=/tmp
codeql=/opt/codeql/codeql
"$codeql" version --format=terse
case "$mode" in
  autobuild)
    # Go only (no build-mode none). Offline: no module proxy, no toolchain download, no cgo; the build
    # cache lives in scratch (/tmp is noexec) and is removed afterwards. A module whose dependencies
    # are neither vendored nor in the standard library does not resolve: a recorded gap.
    # Optional 7th argument: online (D-29: the job runs with network, modules come from the default proxy)
    # or offline (default; GOPROXY=off, as the smokes run it).
    export GOTOOLCHAIN=local GOFLAGS=-buildvcs=false CGO_ENABLED=0 \
           GOCACHE=/scratch/.go/cache GOPATH=/scratch/.go/path GOTMPDIR=/scratch/.go/tmp
    if [ "${7:-offline}" = offline ]; then export GOPROXY=off GOSUMDB=off; fi
    mkdir -p "$GOCACHE" "$GOPATH" "$GOTMPDIR"
    "$codeql" database create /scratch/db --language=go --source-root=/workspace \
      --build-mode=autobuild --threads="$threads" --ram="$ram" --overwrite
    chmod -R u+w /scratch/.go 2>/dev/null || true; rm -rf /scratch/.go   # the module cache is read-only
    ;;
  none)
    "$codeql" database create /scratch/db --language="$language" --source-root=/workspace \
      --build-mode=none --threads="$threads" --ram="$ram" --overwrite
    ;;
  traced)
    compile_commands=$7
    [ -f "$compile_commands" ] || { echo "compile database not found: $compile_commands" >&2; exit 2; }
    "$codeql" database create /scratch/db --language=cpp --source-root=/workspace \
      --command="python3 /opt/scripts/replay_compile_commands.py $compile_commands --stats /scratch/replay.json" \
      --threads="$threads" --ram="$ram" --overwrite
    ;;
esac
"$codeql" database analyze /scratch/db "$suite" --format=sarif-latest \
  --output=/scratch/codeql.sarif --threads="$threads" --ram="$ram"
if [ "$mode" = traced ] && [ "$#" -eq 8 ]; then
  pack=$8
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
if [ "$keep" = drop-db ]; then rm -rf /scratch/db; fi
