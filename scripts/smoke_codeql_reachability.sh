#!/usr/bin/env bash
# smoke_codeql_reachability.sh [LANG ...]   (from the repo root on the WSL host, Docker required)
#
# Compiles and runs brief E's CodeQL reachability packs (data/codeql-reachability/<lang>, ADR-0022)
# in the pinned audit-codeql image against the fixtures in data/codeql-reachability/fixtures/<lang>,
# then decodes the CSVs with dep_reachability_engines and checks that the fixture's vulnerable call
# is REACHABLE. Default languages: go java csharp javascript python.
#
# Each container runs one argv from `dep_reachability_codeql.py plan` (no shell), with no network,
# the fixture, the pack and the generated symbols model pack mounted read-only, and only
# scratch/codeql-reachability-smoke/<lang>/scratch writable. One line per check: PASS, FAIL or SKIP;
# exit status 1 if any check FAILs. Logs: scratch/codeql-reachability-smoke/<lang>/step-NN.log.
set -uo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
image=${CODEQL_IMAGE:-audit-codeql:local}
langs=("$@")
[ ${#langs[@]} -gt 0 ] || langs=(go java csharp javascript python)
py=$(command -v python3)
failures=0
report() {  # STATUS NAME DETAIL
  printf '%-4s %-40s %s\n' "$1" "$2" "$3"
  [ "$1" = FAIL ] && failures=$((failures + 1))
  return 0
}

if "$py" "$repo/appsec-review-process/dep_reachability_codeql.py" check >/dev/null; then
  report PASS "pack pins" "$("$py" "$repo/appsec-review-process/dep_reachability_codeql.py" check)"
else
  report FAIL "pack pins" "dep_reachability_codeql.py check failed"
fi

for lang in "${langs[@]}"; do
  # Go is extracted with --build-mode=autobuild, which needs a Go toolchain; audit-codeql has none yet
  # (TODO: 02-codeql-go). Until it does, Go is a known gap, reported as SKIP like
  # smoke_codeql_per_language.sh does, not as a failure (zarathustra, 2026-10-01).
  if [ "$lang" = go ] && ! docker run --rm --network none --entrypoint /bin/sh "$image" -c 'command -v go' >/dev/null 2>&1; then
    report SKIP "$lang reachability" "no Go toolchain in $image: Go needs autobuild (TODO 02-codeql-go)"
    continue
  fi
  out="$repo/scratch/codeql-reachability-smoke/$lang"
  rm -rf "$out"; mkdir -p "$out/scratch/graph" "$out/symbols"
  fixture="$repo/data/codeql-reachability/fixtures/$lang"
  if ! "$py" "$repo/appsec-review-process/dep_reachability_codeql.py" symbols --language "$lang" \
       --symbols "$fixture/symbols.json" --out "$out/symbols" 2>"$out/symbols.log"; then
    report FAIL "$lang symbols pack" "see $out/symbols.log"; continue
  fi
  # one NUL-separated argv file per container step (bash variables cannot hold NUL)
  "$py" "$repo/appsec-review-process/dep_reachability_codeql.py" plan --language "$lang" \
    | "$py" -c 'import json,sys
for i, s in enumerate(json.load(sys.stdin)["steps"], 1):
    open(sys.argv[1] + "/step-%02d.argv" % i, "w").write("\0".join(s) + "\0")' "$out"
  step=0; ok=1
  for file in "$out"/step-*.argv; do
    step=$((step + 1))
    mapfile -d '' -t argv < "$file"
    if ! docker run --rm --network none --user "$(id -u):$(id -g)" --env HOME=/tmp \
         --mount "type=bind,source=$fixture,target=/workspace,readonly" \
         --mount "type=bind,source=$repo/data/codeql-reachability/$lang,target=/inputs/pack,readonly" \
         --mount "type=bind,source=$out/symbols,target=/inputs/symbols,readonly" \
         --mount "type=bind,source=$out/scratch,target=/scratch" \
         --entrypoint "${argv[0]}" "$image" "${argv[@]:1}" > "${file%.argv}.log" 2>&1; then
      report FAIL "$lang step $step" "${argv[1]} ${argv[2]}: see ${file%.argv}.log"
      ok=0
      [ "$step" -eq 1 ] && break
    fi
  done
  [ "$ok" -eq 1 ] && report PASS "$lang queries" "$((step - 1)) container step(s) after database create"
  "$py" - "$repo" "$lang" "$out/scratch/graph" "$fixture/symbols.json" <<'PY' || failures=$((failures + 1))
import json, sys
from pathlib import Path
repo, lang, graph, symbols = sys.argv[1], sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])
sys.path.insert(0, str(Path(repo) / "appsec-review-process"))
import dep_reachability_engines as e
tables, gaps = e.load_codeql_dirs({lang: graph})
for gap in gaps.get(lang, []):
    print(f"FAIL {lang + ' table':40s} {gap}")
rows = [dict(row, source="reviewed-map") for row in json.loads(symbols.read_text())]
found = e.CodeqlEngine(tables, gaps).assess(e.Query("VM-000001", lang, rows[0]["package"], rows))
status = "PASS" if found["state"] == "reachable" and not gaps.get(lang) else "FAIL"
print(f"{status} {lang + ' reachability':40s} {found['state']}: {found['reason']}")
sys.exit(0 if status == "PASS" else 1)
PY
done
[ "$failures" -eq 0 ] || { echo "$failures check(s) failed"; exit 1; }
echo "all checks passed"
