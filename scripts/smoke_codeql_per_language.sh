#!/usr/bin/env bash
# smoke_codeql_per_language.sh [LANG ...]   (from the repo root on the WSL host, Docker required)
#
# Brief G (ADR-0023) smoke for the rebuilt audit-codeql image: per language, the 02-codeql-<lang>
# lane keeps its database (keep-db), then the 06-reachability-codeql lane runs the pinned pack
# against that retained database and the decoded tables must make the fixture's vulnerable call
# REACHABLE. Fixtures: data/codeql-reachability/fixtures/<lang>. Default languages:
# java csharp javascript python go (Go runs --build-mode autobuild offline on the image's Go toolchain).
#
# Every container runs with --network none, the fixture / database / packs mounted read-only and
# only scratch/codeql-per-language-smoke/<lang>/<step>/scratch writable, like the B13 requests the
# workers build. One line per check: PASS, FAIL or SKIP; exit status 1 if any check FAILs.
#
#   docker build -t audit-codeql:local images/audit-codeql     # picks up both lane scripts
#   scripts/smoke_codeql_per_language.sh
#   scripts/smoke_codeql_per_language.sh python java
set -uo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
image=${CODEQL_IMAGE:-audit-codeql:local}
langs=("$@")
[ ${#langs[@]} -gt 0 ] || langs=(java csharp javascript python go)
py=$(command -v python3)
failures=0
report() {  # STATUS NAME DETAIL
  printf '%-4s %-40s %s\n' "$1" "$2" "$3"
  [ "$1" = FAIL ] && failures=$((failures + 1))
  return 0
}
run() {  # SCRATCH LOG ENTRYPOINT ARGS... (mounts come from the MOUNTS array)
  local scratch=$1 log=$2 entry=$3; shift 3
  mkdir -p "$scratch"
  docker run --rm --network none --read-only --tmpfs /tmp:rw,size=1g --user "$(id -u):$(id -g)" \
    --env HOME=/tmp "${MOUNTS[@]}" --mount "type=bind,source=$scratch,target=/scratch" \
    --entrypoint "$entry" "$image" "$@" > "$log" 2>&1
}

for script in codeql-sast-lane.sh codeql-reachability-lane.sh; do
  if docker run --rm --network none --entrypoint /bin/sh "$image" -c "test -x /opt/scripts/$script"; then
    report PASS "image has $script" "$image"
  else
    report FAIL "image has $script" "rebuild: docker build -t audit-codeql:local images/audit-codeql"
  fi
done

for lang in "${langs[@]}"; do
  out="$repo/scratch/codeql-per-language-smoke/$lang"
  rm -rf "$out"; mkdir -p "$out"
  fixture="$repo/data/codeql-reachability/fixtures/$lang"
  mode=none
  [ "$lang" = go ] && mode=autobuild   # Go has no build-mode none: offline autobuild on the image's Go toolchain
  suite="codeql/$lang-queries:codeql-suites/$lang-security-extended.qls"
  MOUNTS=(--mount "type=bind,source=$fixture,target=/workspace,readonly")
  if run "$out/sast/scratch" "$out/sast.log" /opt/scripts/codeql-sast-lane.sh "$lang" "$mode" "$suite" 2 2048 keep-db \
     && [ -s "$out/sast/scratch/codeql.sarif" ] && [ -f "$out/sast/scratch/db/codeql-database.yml" ]; then
    report PASS "$lang 02-codeql lane (keep-db)" "SARIF and retained database"
  else
    report FAIL "$lang 02-codeql lane (keep-db)" "see $out/sast.log"; continue
  fi
  "$py" - "$repo" "$out/sast/scratch/db" <<'PY' && report PASS "$lang database pointer" "tree hash computed" \
    || report FAIL "$lang database pointer" "database_tree refused the retained database"
import sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "appsec-review-process"))
import codeql_sast
sys.exit(0 if codeql_sast.database_tree(Path(sys.argv[2])) else 1)
PY
  mkdir -p "$out/symbols"
  if ! "$py" "$repo/appsec-review-process/dep_reachability_codeql.py" symbols --language "$lang" \
       --symbols "$fixture/symbols.json" --out "$out/symbols" 2>"$out/symbols.log"; then
    report FAIL "$lang symbols pack" "see $out/symbols.log"; continue
  fi
  MOUNTS=(--mount "type=bind,source=$out/sast/scratch/db,target=/inputs/codeql-db,readonly"
          --mount "type=bind,source=$repo/data/codeql-reachability/$lang,target=/inputs/pack,readonly"
          --mount "type=bind,source=$out/symbols,target=/inputs/symbols,readonly")
  if run "$out/reach/scratch" "$out/reach.log" /opt/scripts/codeql-reachability-lane.sh "$lang" 2 2048; then
    report PASS "$lang 06-reachability lane" "$(grep -c ': ok' "$out/reach.log") of 4 queries ok"
  else
    report FAIL "$lang 06-reachability lane" "see $out/reach.log"; continue
  fi
  [ -e "$out/reach/scratch/db" ] && report FAIL "$lang database copy removed" "/scratch/db left behind"
  "$py" - "$repo" "$lang" "$out/reach/scratch/graph" "$fixture/symbols.json" <<'PY' || failures=$((failures + 1))
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
