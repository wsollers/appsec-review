#!/usr/bin/env bash
# smoke_entry_exports.sh   (from the repo root on the WSL host, Docker required)
#
# Qualifies exported-symbol entry points for reachability (brief Q3, docs/reachability-entry-points.md
# source 2) before William decides whether to flip `reachability_export_entries` on:
#
#   1. builds images/test/entry-exports/libentry.cpp as a shared library (-fvisibility=hidden) in the
#      pinned audit-buildenv-cpp image (no network, read-only workspace, scratch writable);
#   2. runs the pinned `binary-summary` tool in audit-binary-analysis on it (the same tool
#      02-binary-triage runs), which records the `dynamic_exports` table from .dynsym;
#   3. on the host, joins that table to the fixture's canned CPG records with
#      appsec-review-process/entry_exports.py and assesses two locations.
#
# Checks: the table is complete and names a shared library; entry_parse is REACHABLE through an
# `exported-symbol` root; the static and hidden functions are neither exported nor roots; the two
# fx::overload exports are `ambiguous-export` escapes and no entry; line 19 (only a hidden function
# calls it) is not REACHABLE; the tunable still defaults off. One line per check: PASS or FAIL;
# exit status 1 if any check FAILs. Output: scratch/entry-exports-smoke/.
#
# Images: BUILD_IMAGE (default audit-buildenv-cpp:local), BINARY_IMAGE (default audit-binary-analysis:local).
set -uo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build_image=${BUILD_IMAGE:-audit-buildenv-cpp:local}
binary_image=${BINARY_IMAGE:-audit-binary-analysis:local}
out="$repo/scratch/entry-exports-smoke"
fixture=images/test/entry-exports
py=$(command -v python3)
failures=0
report() {  # STATUS NAME DETAIL
  printf '%-4s %-40s %s\n' "$1" "$2" "$3"
  [ "$1" = FAIL ] && failures=$((failures + 1))
  return 0
}

rm -rf "$out"; mkdir -p "$out"
if bash "$repo/images/audit-buildenv-common/run.sh" "$build_image" "$repo" "$out" -- \
     g++ -shared -fPIC -O0 -g -fvisibility=hidden -o /scratch/libentry.so "/workspace/$fixture/libentry.cpp" \
     > "$out/build.log" 2>&1 && [ -s "$out/libentry.so" ]; then
  report PASS "build libentry.so" "$build_image"
else
  report FAIL "build libentry.so" "see $out/build.log"
  exit 1
fi

if bash "$repo/images/audit-buildenv-common/run.sh" "$binary_image" "$repo" "$out" -- \
     bash -c 'binary-summary /scratch/libentry.so > /scratch/summary.json' > "$out/summary.log" 2>&1 \
     && [ -s "$out/summary.json" ]; then
  report PASS "binary-summary" "$binary_image"
else
  report FAIL "binary-summary" "see $out/summary.log"
  exit 1
fi

if ! "$py" "$repo/appsec-review-process/entry_exports.py" smoke --summary "$out/summary.json" \
     --records "$repo/$fixture/cpg-records.jsonl" \
     --target src/libentry.cpp:9 --target src/libentry.cpp:19 > "$out/join.json" 2> "$out/join.log"; then
  report FAIL "entry_exports.py smoke" "see $out/join.log"
  exit 1
fi

while IFS='|' read -r status name detail; do
  report "$status" "$name" "$detail"
done < <("$py" - "$out/join.json" "$repo/appsec-review-process" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
sys.path.insert(0, sys.argv[2])
table, roots, escapes = data["table"], data["roots"], data["escapes"]
exported = {row["demangled"] or row["symbol"] for row in table["exports"]}
root_names = {name.split(":", 1)[0] for name in roots}
reach, hidden = data["assessments"]["src/libentry.cpp:9"], data["assessments"]["src/libentry.cpp:19"]
def check(name, ok, detail):
    print(f"{'PASS' if ok else 'FAIL'}|{name}|{detail}")
check("export table complete", table["complete"] and table["artifact_kind"] == "shared-library",
      f"kind={table['artifact_kind']} complete={table['complete']} gaps={table['gaps']}")
check("entry_parse exported", "entry_parse" in exported, ", ".join(sorted(exported)))
check("entry_parse REACHABLE via export",
      reach["state"] == "REACHABLE" and reach.get("entry_point", {}).get("label") == "exported-symbol"
      and reach["entry_point"].get("symbol") == "entry_parse", reach["reason"])
banned = {"helper_static", "sink_copy", "helper_hidden", "only_from_hidden"}
check("static/hidden not exported", not (banned & {name.split("(")[0] for name in exported}), "")
check("static/hidden not roots", not (banned & root_names), ", ".join(sorted(root_names)))
check("fx::overload ambiguous, no entry",
      "fx.overload" not in root_names and
      sum(1 for item in escapes if item["reason"] == "ambiguous-export") == 2,
      f"{len(escapes)} escape(s)")
check("hidden-only callee not REACHABLE", hidden["state"] != "REACHABLE", f"{hidden['state']}: {hidden['reason']}")
import entry_exports
check("tunables default off", not entry_exports.enabled("reachability_export_entries")
      and not entry_exports.enabled("reachability_codeql_entries"), "registry/tunables.json")
PY
)

echo "entry-exports smoke: $failures failure(s); evidence in $out"
[ "$failures" -eq 0 ]
