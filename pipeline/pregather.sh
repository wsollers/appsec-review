#!/usr/bin/env bash
# pregather.sh — Phase 1: mechanical evidence gathering for a native C/C++ target. No LLM.
#
#   pipeline/pregather.sh --target <source-root> --scratch <dir> --project <name>
#        [--msvc <dir>]            Windows (vcxproj) target: converter + clang-cl; omit for a native Linux build
#        [--compile-db <path>]     use an existing compile_commands.json (cmake/bear/UBT) instead of the converter
#        [--codeql]                also build a traced CodeQL database + run the mythos pack
#        [--csa]                   also run CSA (CTU + taint config)
#
# Produces under <scratch>/: compile_commands.json, compile-command-audit.seed.json, feasibility.json,
# feasibility-ir.json, ir/, linked/<module>.bc, ir-facts-<module>.json, [csa/], [codeql/mythos.sarif],
# pregather-manifest.json (what ran, image digests, hashes). Everything here is input to assemble.py.
# PowerShell twin: pregather.ps1 (same flags). Logic lives in the container scripts; this is a driver.
set -euo pipefail
TARGET=""; SCRATCH=""; PROJECT=""; MSVC="-"; CDB=""; DO_CODEQL=0; DO_CSA=0
while [ $# -gt 0 ]; do case "$1" in
  --target) TARGET=$2; shift 2;; --scratch) SCRATCH=$2; shift 2;; --project) PROJECT=$2; shift 2;;
  --msvc) MSVC=$2; shift 2;; --compile-db) CDB=$2; shift 2;; --codeql) DO_CODEQL=1; shift;; --csa) DO_CSA=1; shift;;
  *) echo "unknown arg $1"; exit 2;; esac; done
[ -n "$TARGET" ] && [ -n "$SCRATCH" ] && [ -n "$PROJECT" ] || { echo "--target, --scratch, --project required"; exit 2; }
HERE=$(cd "$(dirname "$0")/.." && pwd); RUN="$HERE/images/audit-native/run.sh"
mkdir -p "$SCRATCH"; LOG="$SCRATCH/pregather.log"; exec > >(tee -a "$LOG") 2>&1
step() { echo; echo "#### [$1] $(date +%T)"; }
R() { "$RUN" "$TARGET" "$MSVC" "$SCRATCH" -- "$@"; }

step "compile database"
if [ -n "$CDB" ]; then
  # normalise to container paths: the DB was produced on the host for <TARGET>; rewrite that prefix to /workspace
  python3 - "$CDB" "$(realpath "$TARGET")" "$SCRATCH/compile_commands.json" "$PROJECT" <<'PY'
import json, sys
src, root, out, proj = sys.argv[1:]
db = json.load(open(src)); n = 0
for e in db:
    e["project"] = e.get("project", proj)
    for k in ("directory", "file", "output"):
        if k in e and e[k].startswith(root): e[k] = "/workspace" + e[k][len(root):]
    if "arguments" in e: e["arguments"] = ["/workspace" + a[len(root):] if a.startswith(root) else a for a in e["arguments"]]
    if "command" in e: e["command"] = e["command"].replace(root, "/workspace")
    n += 1
json.dump(db, open(out, "w"), indent=1); print(f"{n} entries rewritten -> {out}")
PY
else
  R /opt/scripts/vcxproj_to_compile_commands.py --root /workspace --config Release --platform x64 \
    --msvc-root /msvc --out /scratch/compile_commands.json --audit /scratch/compile-command-audit.seed.json
fi

step "feasibility gate"
R /opt/scripts/compile_feasibility_gate.py --compile-commands /scratch/compile_commands.json --out /scratch/feasibility.json
step "emit IR"
rm -rf "$SCRATCH/ir" "$SCRATCH/linked"
R /opt/scripts/compile_feasibility_gate.py --compile-commands /scratch/compile_commands.json --out /scratch/feasibility-ir.json --emit-ir --ir-dir /scratch/ir
step "link per project"
R /opt/scripts/link_ir.py --feasibility /scratch/feasibility-ir.json --out /scratch/linked
step "ir-facts"
for m in "$SCRATCH"/linked/*.bc; do n=$(basename "$m" .bc); R /opt/ir-facts/ir-facts "/scratch/linked/$n.bc" -o "/scratch/ir-facts-$n.json" 2>&1 | tail -1; done
if [ "$DO_CSA" = 1 ]; then step "CSA (CTU + taint)"
  R /opt/scripts/run_csa.py --compile-commands /scratch/compile_commands.json --out /scratch/csa --ctu --alpha
fi
if [ "$DO_CODEQL" = 1 ]; then step "CodeQL traced DB + mythos pack"
  AUDIT_NATIVE_IMAGE=${AUDIT_CODEQL_IMAGE:-audit-codeql-native:local} "$RUN" "$TARGET" "$MSVC" "$SCRATCH" -- \
    /opt/scripts/run-codeql.sh --langs cpp --traced-cpp /scratch/compile_commands.json --ram "${CODEQL_RAM:-12000}"
  AUDIT_NATIVE_IMAGE=${AUDIT_CODEQL_IMAGE:-audit-codeql-native:local} "$RUN" "$HERE" - "$SCRATCH" -- bash -c \
    "cd /scratch/codeql && rm -f db-cpp/db-cpp/default/cache/.lock && codeql database analyze db-cpp /workspace/queries/mythos-cpp \
     --additional-packs=/opt/codeql/qlpacks --format=sarif-latest --output=mythos.sarif --threads=4 --ram=${CODEQL_RAM:-12000} --rerun 2>&1 | grep -iE 'error' || true"
fi
step "manifest"
python3 "$HERE/pipeline/manifest.py" "$SCRATCH" "$PROJECT" "$TARGET"
echo "pregather complete -> $SCRATCH (log: $LOG)"
