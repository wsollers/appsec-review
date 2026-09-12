#!/usr/bin/env bash
# run-codeql.sh — create CodeQL databases and run security-extended suites, offline.
#
#   run-codeql.sh --langs cpp,javascript,python [--suite security-extended|security-and-quality|default]
#                 [--traced-cpp /scratch/compile_commands.json] [--threads N] [--ram MB]
#
# Env (required): CODEQL_LICENSE_BASIS = oss | academic | ghas   (see Dockerfile header)
# Input : /workspace (read-only source root)
# Output: /scratch/codeql/{db-<lang>/, <lang>.sarif, <lang>.csv, run-manifest.json, *.log}
#
# C/C++: --build-mode none by default (no compiler needed; lower fidelity: no build-driven
# macro/template resolution). --traced-cpp <compile_commands.json> instead replays the
# audit-native compile DB under CodeQL's tracer with clang-cl ("preliminary" support per
# CodeQL docs) — an experiment, and it needs the MSVC headers mounted at /msvc plus a
# clang-cl on PATH, i.e. it only works in an image that has both. Records which mode ran.
set -euo pipefail
LANGS=""; SUITE="security-extended"; TRACED=""; THREADS=$(nproc); RAM=""
while [ $# -gt 0 ]; do case "$1" in
  --langs) LANGS=$2; shift 2;; --suite) SUITE=$2; shift 2;; --traced-cpp) TRACED=$2; shift 2;;
  --threads) THREADS=$2; shift 2;; --ram) RAM=$2; shift 2;; *) echo "unknown arg $1"; exit 2;; esac; done
[ -n "$LANGS" ] || { echo "--langs required (comma list: cpp,csharp,go,java,javascript,python,ruby,swift)"; exit 2; }
case "${CODEQL_LICENSE_BASIS:-}" in
  oss|academic|ghas) ;;
  *) echo "REFUSING: CODEQL_LICENSE_BASIS must be oss|academic|ghas (CodeQL CLI license). Set it per engagement."; exit 3;;
esac
OUT=/scratch/codeql; mkdir -p "$OUT"; cd "$OUT"
RAMOPT=(); [ -n "$RAM" ] && RAMOPT=(--ram "$RAM")
SRC_HASH=$(cd /workspace && find . -type f -not -path './.git/*' -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
echo "{\"codeql\": $(codeql version --format=json), \"bundle\": \"${CODEQL_BUNDLE:-?}\", \"license_basis\": \"$CODEQL_LICENSE_BASIS\", \"suite\": \"$SUITE\", \"source_tree_sha256\": \"$SRC_HASH\", \"languages\": {}, \"started_utc\": \"$(date -u +%FT%TZ)\"}" > run-manifest.json

for L in ${LANGS//,/ }; do
  DB="$OUT/db-$L"; rm -rf "$DB"
  echo "== $L: database create"
  MODE="none"
  case "$L" in
    cpp|c-cpp)
      if [ -n "$TRACED" ]; then
        MODE="traced-clang-cl"
        codeql database create "$DB" --language=cpp --source-root=/workspace --threads="$THREADS" "${RAMOPT[@]}" \
          --command="python3 /opt/scripts/replay_compile_commands.py $TRACED" > "create-$L.log" 2>&1
      else
        codeql database create "$DB" --language=cpp --source-root=/workspace --build-mode=none --threads="$THREADS" "${RAMOPT[@]}" > "create-$L.log" 2>&1
      fi;;
    java|csharp)
      codeql database create "$DB" --language="$L" --source-root=/workspace --build-mode=none --threads="$THREADS" "${RAMOPT[@]}" > "create-$L.log" 2>&1;;
    *)  # javascript, python, ruby, go(buildless), swift
      MODE="interpreted-or-buildless"
      codeql database create "$DB" --language="$L" --source-root=/workspace --threads="$THREADS" "${RAMOPT[@]}" > "create-$L.log" 2>&1;;
  esac
  FILES=$(codeql database print-baseline "$DB" 2>/dev/null | grep -oE '[0-9]+ files' | head -1 || echo "?")
  echo "   db ok ($FILES); analyze: codeql/$L-queries:codeql-suites/$L-$SUITE.qls"
  codeql database analyze "$DB" "codeql/$L-queries:codeql-suites/$L-$SUITE.qls" \
      --format=sarif-latest --output="$L.sarif" --threads="$THREADS" "${RAMOPT[@]}" --sarif-add-baseline-file-info > "analyze-$L.log" 2>&1
  codeql database analyze "$DB" "codeql/$L-queries:codeql-suites/$L-$SUITE.qls" --format=csv --output="$L.csv" --threads="$THREADS" "${RAMOPT[@]}" --rerun >> "analyze-$L.log" 2>&1 || true
  N=$(python3 -c "import json; print(sum(len(r['results']) for r in json.load(open('$L.sarif'))['runs']))")
  PACK=$(codeql resolve qlpacks --format=json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('codeql/$L-queries',['?'])[0])" || echo "?")
  echo "   findings: $N -> $L.sarif / $L.csv  (pack codeql/$L-queries @ $PACK, extraction mode: $MODE)"
  python3 - "$L" "$MODE" "$N" "$PACK" <<'PY'
import json, sys
m = json.load(open("run-manifest.json")); l, mode, n, pack = sys.argv[1:]
m["languages"][l] = {"extraction_mode": mode, "findings": int(n), "query_pack": f"codeql/{l}-queries", "pack_path": pack, "db": f"db-{l}"}
json.dump(m, open("run-manifest.json", "w"), indent=1)
PY
done
echo "done -> $OUT (run-manifest.json records license basis, suite, source hash, per-language extraction mode)"
