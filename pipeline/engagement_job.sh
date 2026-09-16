#!/usr/bin/env bash
# engagement_job.sh -- end-to-end evidence job for an appsec engagement.
#
# Runs broad static evidence first, then native build-backed evidence, then assembles
# a constrained LLM input package.
set -euo pipefail

PROJECT=""
TARGET=""
OUT=""
COMPILE_DB=""
MSVC="-"
STATIC_IMAGE="${STATIC_IMAGE:-vendor-audit-toolbox:latest}"
RUN_STATIC=1
RUN_NATIVE=1
RUN_CODEQL=1
RUN_CSA=1
STATIC_STEPS=""

usage() {
  cat <<'EOF'
Usage:
  pipeline/engagement_job.sh --project NAME --target PATH --out DIR [options]

Options:
  --compile-db PATH       Existing compile_commands.json for native targets.
  --msvc PATH|-           MSVC mount for Windows targets; default "-".
  --static-image TAG      Static toolbox image; default vendor-audit-toolbox:latest.
  --static-steps a,b,c    Optional subset for Invoke-VendorAuditPrePass.ps1.
  --skip-static           Do not run Semgrep/gitleaks/trivy/BinSkim/etc pre-pass.
  --skip-native           Do not run native pregather/IR/CSA/CodeQL.
  --no-codeql             Skip native CodeQL.
  --no-csa                Skip native CSA/CTU.

Outputs:
  DIR/static-evidence/
  DIR/native-scratch/
  DIR/llm/native-bundle.json
  DIR/llm/native-bundle.md
  DIR/llm/correlated-findings.json
  DIR/llm/correlated-findings.md
  DIR/llm/retrieval-plan.json
  DIR/llm/retrieval-plan.md
  DIR/llm/coverage-ledger.json
  DIR/llm/ENGAGEMENT_LLM_INPUT.md
  DIR/job-status.json
  DIR/job-status.md
  DIR/job-manifest.jsonl
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="$2"; shift 2;;
    --target) TARGET="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --compile-db) COMPILE_DB="$2"; shift 2;;
    --msvc) MSVC="$2"; shift 2;;
    --static-image) STATIC_IMAGE="$2"; shift 2;;
    --static-steps) STATIC_STEPS="$2"; shift 2;;
    --skip-static) RUN_STATIC=0; shift;;
    --skip-native) RUN_NATIVE=0; shift;;
    --no-codeql) RUN_CODEQL=0; shift;;
    --no-csa) RUN_CSA=0; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 2;;
  esac
done

[[ -n "$PROJECT" && -n "$TARGET" && -n "$OUT" ]] || { usage; exit 2; }

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARGET=$(realpath "$TARGET")
OUT=$(mkdir -p "$OUT" && cd "$OUT" && pwd)
STATIC_EVIDENCE="$OUT/static-evidence"
NATIVE_SCRATCH="$OUT/native-scratch"
LLM_DIR="$OUT/llm"
LOG_DIR="$OUT/logs"
MANIFEST="$OUT/job-manifest.jsonl"
mkdir -p "$STATIC_EVIDENCE" "$NATIVE_SCRATCH" "$LLM_DIR" "$LOG_DIR"
: > "$MANIFEST"

json_escape() {
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

run_step() {
  local name="$1"; shift
  local log="$LOG_DIR/$name.log"
  echo
  echo "#### [$name] $(date -Is)"
  local start end rc
  start=$(date +%s)
  set +e
  "$@" > >(tee "$log") 2>&1
  rc=$?
  set -e
  end=$(date +%s)
  printf '{"step":%s,"exit_code":%s,"seconds":%s,"log":%s}\n' \
    "$(json_escape "$name")" "$rc" "$((end-start))" "$(json_escape "$log")" >> "$MANIFEST"
  return "$rc"
}

if [[ "$RUN_STATIC" == 1 ]]; then
  PWSH_BIN=""
  if command -v pwsh >/dev/null 2>&1; then
    PWSH_BIN="pwsh"
  elif command -v pwsh.exe >/dev/null 2>&1; then
    PWSH_BIN="pwsh.exe"
  fi
  if [[ -n "$PWSH_BIN" ]]; then
    static_args=("-NoProfile" "-File" "$ROOT/scripts/Invoke-VendorAuditPrePass.ps1" "$TARGET" "$STATIC_EVIDENCE" "-ImageTag" "$STATIC_IMAGE" "-CleanEvidence")
    if [[ -n "$STATIC_STEPS" ]]; then
      static_args+=("-Steps" "$STATIC_STEPS")
    fi
    run_step "static-prepass" "$PWSH_BIN" "${static_args[@]}" || true
  else
    echo "WARNING: pwsh/pwsh.exe not found; skipping static pre-pass" | tee "$LOG_DIR/static-prepass.log"
    printf '{"step":"static-prepass","exit_code":127,"seconds":0,"log":%s,"note":"pwsh/pwsh.exe not found"}\n' "$(json_escape "$LOG_DIR/static-prepass.log")" >> "$MANIFEST"
  fi
  run_step "static-summary" python3 "$ROOT/scripts/summarize_evidence.py" "$STATIC_EVIDENCE" -o "$STATIC_EVIDENCE/SUMMARY.md" || true
fi

if [[ "$RUN_NATIVE" == 1 ]]; then
  pregather_args=("--target" "$TARGET" "--scratch" "$NATIVE_SCRATCH" "--project" "$PROJECT" "--msvc" "$MSVC")
  if [[ -n "$COMPILE_DB" ]]; then
    pregather_args+=("--compile-db" "$(realpath "$COMPILE_DB")")
  fi
  [[ "$RUN_CODEQL" == 1 ]] && pregather_args+=("--codeql")
  [[ "$RUN_CSA" == 1 ]] && pregather_args+=("--csa")
  run_step "native-pregather" "$ROOT/pipeline/pregather.sh" "${pregather_args[@]}" || true
  run_step "native-assemble" python3 "$ROOT/pipeline/assemble.py" --scratch "$NATIVE_SCRATCH" --out "$LLM_DIR/native-bundle.json" --repo "$ROOT" || true
fi

run_step "correlate-findings" python3 "$ROOT/pipeline/correlate_findings.py" \
  --static-evidence "$STATIC_EVIDENCE" \
  --native-scratch "$NATIVE_SCRATCH" \
  --bundle "$LLM_DIR/native-bundle.json" \
  --out "$LLM_DIR/correlated-findings.json" || true

run_step "retrieval-plan" python3 "$ROOT/pipeline/generate_retrieval_plan.py" \
  --static-evidence "$STATIC_EVIDENCE" \
  --native-scratch "$NATIVE_SCRATCH" \
  --correlated-findings "$LLM_DIR/correlated-findings.json" \
  --out "$LLM_DIR/retrieval-plan.json" || true

run_step "llm-input" python3 "$ROOT/pipeline/build_llm_input.py" \
  --project "$PROJECT" \
  --target "$TARGET" \
  --static-evidence "$STATIC_EVIDENCE" \
  --native-scratch "$NATIVE_SCRATCH" \
  --bundle "$LLM_DIR/native-bundle.json" \
  --correlated-findings "$LLM_DIR/correlated-findings.json" \
  --retrieval-plan "$LLM_DIR/retrieval-plan.json" \
  --out-dir "$LLM_DIR" || true

status_args=(
  "--manifest" "$MANIFEST"
  "--out" "$OUT"
  "--static-evidence" "$STATIC_EVIDENCE"
  "--native-scratch" "$NATIVE_SCRATCH"
  "--llm-dir" "$LLM_DIR"
)
[[ "$RUN_STATIC" == 1 ]] && status_args+=("--static-enabled")
[[ "$RUN_NATIVE" == 1 ]] && status_args+=("--native-enabled")
[[ "$RUN_NATIVE" == 1 && "$RUN_CODEQL" == 1 ]] && status_args+=("--codeql-enabled")

echo
echo "#### [job-status] $(date -Is)"
set +e
python3 "$ROOT/pipeline/job_status.py" "${status_args[@]}" | tee "$LOG_DIR/job-status.log"
STATUS_RC=${PIPESTATUS[0]}
set -e

echo
if [[ "$STATUS_RC" == 0 ]]; then
  echo "Engagement job complete: OK."
else
  echo "Engagement job complete: DEGRADED. See $OUT/job-status.md"
fi
echo "Manifest: $MANIFEST"
echo "LLM input: $LLM_DIR/ENGAGEMENT_LLM_INPUT.md"
exit "$STATUS_RC"
