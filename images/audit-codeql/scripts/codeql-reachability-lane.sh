#!/usr/bin/env bash
# codeql-reachability-lane.sh LANGUAGE THREADS RAM_MB
#
# One 06-reachability-codeql language (appsec-review-process/reachability_engine_jobs.py, ADR-0023),
# offline. Mounts (read-only): /inputs/codeql-db (the database a 02-codeql-<lang> node retained,
# re-hashed by the worker before the run), /inputs/pack (data/codeql-reachability/<lang>, pinned
# pack appsec/<lang>-reachability) and /inputs/symbols (the generated data-extension pack
# appsec/<lang>-reachability-symbols: advisory symbols as rows, never as QL text). The database is
# copied into /scratch/db (query evaluation writes caches next to it), each table query is run and
# decoded to /scratch/graph/<Query>.csv, and the copy is removed. A query that fails is logged and
# leaves no CSV (the worker records a gap); only a failed database copy fails the lane.
set -euo pipefail
usage() { echo "usage: $0 LANGUAGE THREADS RAM_MB" >&2; exit 2; }
[ "$#" -eq 3 ] || usage
language=$1; threads=$2; ram=$3
case "$language" in go|java|csharp|javascript|python) ;; *) usage ;; esac
export HOME=/tmp
codeql=/opt/codeql/codeql
"$codeql" version --format=terse
[ -f /inputs/codeql-db/codeql-database.yml ] || { echo "no CodeQL database at /inputs/codeql-db" >&2; exit 2; }
cp -R /inputs/codeql-db /scratch/db
mkdir -p /scratch/graph
for query in CallEdges EntryPoints Reachability TaintReach; do
  if "$codeql" query run --database=/scratch/db \
       --additional-packs=/inputs/pack:/inputs/symbols:/opt/codeql/qlpacks \
       --model-packs="appsec/$language-reachability-symbols" --threads="$threads" --ram="$ram" \
       --output="/scratch/graph/$query.bqrs" "/inputs/pack/$query.ql" > "/scratch/graph/$query.log" 2>&1 \
     && "$codeql" bqrs decode --format=csv --output="/scratch/graph/$query.csv" "/scratch/graph/$query.bqrs" \
       >> "/scratch/graph/$query.log" 2>&1; then
    echo "reachability $query: ok"
  else
    echo "reachability $query: failed (see /scratch/graph/$query.log)" >&2
    rm -f "/scratch/graph/$query.csv"
  fi
  rm -f "/scratch/graph/$query.bqrs"
done
rm -rf /scratch/db
