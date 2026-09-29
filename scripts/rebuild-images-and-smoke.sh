#!/usr/bin/env bash
# rebuild-images-and-smoke.sh   (run from the appsec-review repo root in WSL, Docker required)
#
# Rebuilds audit-codeql, audit-codeql-native, audit-binary-analysis and audit-native (plus the two
# images they need first), then runs the smoke tests that prove them. One PASS/FAIL line per step,
# a summary at the end, exit status 1 if any step failed. Every step's full output goes to
# scratch/rebuild-<timestamp>/<step>.log
#
# Order (image_build.py BLOCKS a build whose required image is missing):
#   audit-lsp-vendor -> audit-native -> audit-binary-analysis -> audit-codeql -> audit-codeql-native
#
# Options (environment variables):
#   DRY_RUN=1        print the commands, run nothing
#   NO_CACHE=1       docker build --no-cache for every image (slow; default uses the layer cache)
#   FORCE=1          rebuild even when the fingerprint is unchanged (default: REUSED is fine)
#   WITH_BUILDENV=1  also rebuild audit-buildenv-cpp (it extends audit-native:local) and lang-server smoke it
#   REGISTER=1       regenerate the B16 image records after the builds. OFF by default: this changes
#                    fingerprints of jobs that use these images, so do it only when no run is live
#                    (wait for the hello-autotools baseline to finish).
#   SKIP_SMOKE=1     build only
#   WINE_VERSION=V   pass --build-arg WINE_VERSION=V to audit-binary-analysis (see the hint printed on failure)
#
# Run it detached so a dropped terminal does not kill a 3-hour build:
#   nohup bash rebuild-images-and-smoke.sh > rebuild.out 2>&1 &   then   tail -f rebuild.out
set -uo pipefail

if [[ ! -f images/image_build.py || ! -d appsec-review-process ]]; then
  echo "Run this from the appsec-review repo root (images/image_build.py not found)." >&2
  exit 2
fi
if [[ "${DRY_RUN:-0}" != "1" ]] && ! docker info >/dev/null 2>&1; then
  echo "Docker is not reachable from this shell (docker info failed)." >&2
  exit 2
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
LOGDIR="scratch/rebuild-${TS}"
mkdir -p "$LOGDIR"
declare -a NAMES=() RESULTS=() SECS=()
declare -A FAILED=()

BUILD_FLAGS=()
[[ "${NO_CACHE:-0}" == "1" ]] && BUILD_FLAGS+=(--no-cache)
[[ "${FORCE:-0}" == "1" ]] && BUILD_FLAGS+=(--force)

# step NAME [--needs IMAGE_ID ...] -- COMMAND...
step() {
  local name="$1"; shift
  local needs=()
  if [[ "${1:-}" == "--needs" ]]; then
    shift
    while [[ "$1" != "--" ]]; do needs+=("$1"); shift; done
  fi
  shift  # the --
  local dep
  for dep in "${needs[@]}"; do
    if [[ -n "${FAILED[$dep]:-}" ]]; then
      NAMES+=("$name"); RESULTS+=("SKIP (needs $dep)"); SECS+=(0)
      echo "SKIP  $name  (needs $dep, which failed)"
      FAILED["$name"]=1
      return 0
    fi
  done
  local log="$LOGDIR/${name}.log" start end rc
  echo "START $name   -> $log"
  echo "      $*"
  start=$(date +%s)
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    rc=0
  else
    "$@" >"$log" 2>&1
    rc=$?
  fi
  end=$(date +%s)
  NAMES+=("$name"); SECS+=($((end - start)))
  if [[ $rc -eq 0 ]]; then
    RESULTS+=("PASS"); echo "PASS  $name  ($((end - start))s)"
  else
    RESULTS+=("FAIL (exit $rc)"); FAILED["$name"]=1
    echo "FAIL  $name  (exit $rc, $((end - start))s)  last lines of $log:"
    tail -n 15 "$log" | sed 's/^/      | /'
  fi
  return 0
}

echo "== appsec-review image rebuild + smoke, ${TS}"
echo "== repo: $(pwd)   branch: $(git branch --show-current 2>/dev/null)   head: $(git rev-parse --short HEAD 2>/dev/null)"
echo "== logs: ${LOGDIR}"

# ---- 1. builds ---------------------------------------------------------------------------------
BUILD="python3 -B images/image_build.py build"
step build-audit-lsp-vendor       -- $BUILD audit-lsp-vendor       "${BUILD_FLAGS[@]}"
step build-audit-native           -- $BUILD audit-native           "${BUILD_FLAGS[@]}"

WINE_ARGS=()
[[ -n "${WINE_VERSION:-}" ]] && WINE_ARGS=(--build-arg "WINE_VERSION=${WINE_VERSION}")
step build-audit-binary-analysis  -- $BUILD audit-binary-analysis  "${BUILD_FLAGS[@]}" "${WINE_ARGS[@]}"

step build-audit-codeql           --needs build-audit-lsp-vendor -- \
  $BUILD audit-codeql "${BUILD_FLAGS[@]}"
step build-audit-codeql-native    --needs build-audit-lsp-vendor build-audit-native -- \
  $BUILD audit-codeql-native "${BUILD_FLAGS[@]}"

if [[ "${WITH_BUILDENV:-0}" == "1" ]]; then
  step build-audit-buildenv-cpp   --needs build-audit-lsp-vendor build-audit-native -- \
    $BUILD audit-buildenv-cpp "${BUILD_FLAGS[@]}"
fi

# ---- 2. image records (opt-in) ----------------------------------------------------------------
if [[ "${REGISTER:-0}" == "1" ]]; then
  step register-image-records -- python3 -B images/registry_records.py generate
  step check-image-records    --needs register-image-records -- python3 -B images/registry_records.py check
else
  echo "NOTE  image records NOT regenerated (REGISTER=1 to do it). Every 02-codeql-<lang> node stays an"
  echo "      UNAVAILABLE gap until you do. Do it only when no review run is live."
fi

# ---- 3. smoke tests ---------------------------------------------------------------------------
if [[ "${SKIP_SMOKE:-0}" != "1" ]]; then
  step smoke-reverse-audit-binary-analysis --needs build-audit-binary-analysis -- \
    bash scripts/smoke_reverse_tools.sh --docker audit-binary-analysis
  step smoke-reverse-audit-native          --needs build-audit-native -- \
    bash scripts/smoke_reverse_tools.sh --docker audit-native
  step smoke-codeql-per-language           --needs build-audit-codeql -- \
    bash scripts/smoke_codeql_per_language.sh
  step smoke-codeql-reachability           --needs build-audit-codeql -- \
    bash scripts/smoke_codeql_reachability.sh
  if [[ "${WITH_BUILDENV:-0}" == "1" ]]; then
    step smoke-lang-servers-cpp            --needs build-audit-buildenv-cpp -- \
      bash scripts/smoke_lang_servers.sh --docker audit-buildenv-cpp
  fi
fi

# ---- 4. summary -------------------------------------------------------------------------------
echo
echo "================ SUMMARY (${LOGDIR}) ================"
printf '%-42s %-22s %s\n' STEP RESULT SECONDS
bad=0
for i in "${!NAMES[@]}"; do
  printf '%-42s %-22s %s\n' "${NAMES[$i]}" "${RESULTS[$i]}" "${SECS[$i]}"
  [[ "${RESULTS[$i]}" == PASS ]] || bad=1
done

if [[ -n "${FAILED[build-audit-binary-analysis]:-}" ]] && grep -qi "wine" "$LOGDIR/build-audit-binary-analysis.log" 2>/dev/null; then
  cat <<'EOF'

HINT  audit-binary-analysis: the apt pin wine=8.0~repack-4 is unverified. Find the real version:
        docker run --rm debian:bookworm-slim bash -c 'apt-get update -qq && apt-cache policy wine'
      then rerun with   WINE_VERSION=<that version> bash rebuild-images-and-smoke.sh
      and update WINE_VERSION in images/audit-binary-analysis/Dockerfile and scripts/smoke_reverse_tools.sh.
EOF
fi

cat <<'EOF'

MANUAL CHECKS (not automated):
  - Ghidra zip sha256 93a5d11a... in images/audit-binary-analysis and images/audit-native against the hash in the
    Ghidra 12.1.3 release notes.
  - If a CodeQL reachability smoke reports a QL compile error, the packs under data/codeql-reachability/ were
    never compiled before this run: send me logs/step-NN.log from scratch/codeql-reachability-smoke/<lang>/.
  - Go stays a gap (no offline build); the per-language smoke reports it as SKIP, not FAIL.
EOF

[[ $bad -eq 0 ]] && echo "ALL STEPS PASSED" || echo "SOME STEPS FAILED (see logs above)"
exit $bad
