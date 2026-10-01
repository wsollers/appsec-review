#!/usr/bin/env bash
# rebuild-images-and-smoke.sh   (run from the appsec-review repo root in WSL, Docker required)   v3
#
# Rebuilds audit-lsp-vendor, audit-native, audit-binary-analysis, audit-codeql and audit-codeql-native, then runs
# the smoke tests. One PASS/FAIL line per step and a summary. EVERY failure prints the real error lines, and at
# the end a diagnostics bundle is written to scratch/rebuild-<timestamp>/diagnostics.tgz: send me that one file.
#
# Order (image_build.py BLOCKS a build whose required image is missing):
#   audit-lsp-vendor -> audit-native -> audit-binary-analysis -> audit-codeql -> audit-codeql-native
#
# Options (environment variables):
#   DRY_RUN=1        print the commands, run nothing
#   NO_CACHE=1       docker build --no-cache
#   FORCE=1          rebuild and re-smoke even when nothing changed. Default: an image whose fingerprint is
#                    unchanged and which still exists is SKIPPED (image_build.py says REUSED), and a smoke
#                    test that already passed against that exact image id is SKIPPED too (stamps in
#                    scratch/.smoke-ok/). NO_CACHE=1 also rebuilds.
#   WITH_BUILDENV=1  also rebuild audit-buildenv-cpp and run the lang-server smoke
#   REGISTER=1       regenerate the B16 image records afterwards (OFF by default: it changes job fingerprints;
#                    do it after briefs L, O and K are merged, before the hello-autotools rerun)
#   SKIP_SMOKE=1     build only
#   ONLY="a b"       run only these build steps (image ids), e.g. ONLY="audit-lsp-vendor"
#   WINE_VERSION=V   force --build-arg WINE_VERSION=V for audit-binary-analysis (default: auto-detect, see below)
#   KEEP_GOING=0     stop at the first failed step (default 1: continue with steps that do not depend on it)
#
# Run it detached so a dropped terminal does not kill a long build:
#   nohup bash scripts/rebuild-images-and-smoke.sh > rebuild.out 2>&1 &     then    tail -f rebuild.out
set -uo pipefail

if [[ ! -f images/image_build.py || ! -d appsec-review-process ]]; then
  echo "Run this from the appsec-review repo root (images/image_build.py not found)." >&2; exit 2
fi
if [[ "${DRY_RUN:-0}" != "1" ]] && ! docker info >/dev/null 2>&1; then
  echo "Docker is not reachable from this shell (docker info failed)." >&2; exit 2
fi

export BUILDKIT_PROGRESS=plain          # full, non-collapsed build output in the logs
TS="$(date -u +%Y%m%dT%H%M%SZ)"
LOGDIR="scratch/rebuild-${TS}"
mkdir -p "$LOGDIR"
declare -a NAMES=() RESULTS=() SECS=()
declare -A FAILED=()
BUILD_FLAGS=()
[[ "${NO_CACHE:-0}" == "1" ]] && BUILD_FLAGS+=(--no-cache)
[[ "${FORCE:-0}" == "1" ]] && BUILD_FLAGS+=(--force)

selected() { [[ -z "${ONLY:-}" ]] || [[ " ${ONLY} " == *" $1 "* ]]; }

# Print the lines that explain a failure: real error markers with context, then the tail.
explain_failure() {
  local log="$1"
  echo "      ---- error lines ----"
  grep -n -i -E "^ERROR|error:|E: |fatal|failed|not found|no such|sha256|checksum|mismatch|denied|timed out|unauthorized|toomanyrequests|no space|manifest unknown|could not resolve|connection (refused|reset)" "$log" \
    | grep -v -E "^[0-9]+:\+ " | tail -n 20 | cut -c1-240 | sed 's/^/      | /'
  echo "      ---- last 25 lines ----"
  tail -n 25 "$log" | cut -c1-240 | sed 's/^/      | /'
}

# step NAME [--needs STEP ...] -- COMMAND...
step() {
  local name="$1"; shift
  local needs=()
  if [[ "${1:-}" == "--needs" ]]; then
    shift; while [[ "$1" != "--" ]]; do needs+=("$1"); shift; done
  fi
  shift
  local dep
  for dep in "${needs[@]}"; do
    if [[ -n "${FAILED[$dep]:-}" ]]; then
      NAMES+=("$name"); RESULTS+=("SKIP (needs $dep)"); SECS+=(0)
      echo "SKIP  $name  (needs $dep, which failed)"; FAILED["$name"]=1; return 0
    fi
  done
  local log="$LOGDIR/${name}.log" start end rc
  echo "START $name   -> $log"; echo "      $*"
  start=$(date +%s)
  if [[ "${DRY_RUN:-0}" == "1" ]]; then rc=0; else "$@" >"$log" 2>&1; rc=$?; fi
  end=$(date +%s); NAMES+=("$name"); SECS+=($((end - start)))
  if [[ $rc -eq 0 && "${DRY_RUN:-0}" != "1" && "$name" == build-* ]] && grep -q "^REUSED" "$log"; then
    RESULTS+=("SKIP (already built)"); echo "SKIP  $name  (already built, fingerprint unchanged)"
  elif [[ $rc -eq 0 ]]; then
    RESULTS+=("PASS"); echo "PASS  $name  ($((end - start))s)"
  else
    RESULTS+=("FAIL (exit $rc)"); FAILED["$name"]=1
    echo "FAIL  $name  (exit $rc, $((end - start))s)"
    explain_failure "$log"
    if [[ "${KEEP_GOING:-1}" == "0" ]]; then echo "KEEP_GOING=0: stopping."; finish; fi
  fi
  return 0
}

# ---- diagnostics bundle ------------------------------------------------------------------------
collect_diagnostics() {
  local d="$LOGDIR/diag"; mkdir -p "$d"
  { echo "== date"; date -u; echo "== uname"; uname -a; echo "== docker version"; docker version 2>&1 | head -30
    echo "== docker info (head)"; docker info 2>&1 | head -40; echo "== df -h ."; df -h . 2>&1
    echo "== docker system df"; docker system df 2>&1; echo "== git"; git rev-parse --short HEAD 2>&1; git branch --show-current 2>&1
    echo "== images"; docker images --format '{{.Repository}}:{{.Tag}}  {{.ID}}  {{.Size}}  {{.CreatedSince}}' 2>&1 | grep -E "audit|lsp|codeql" ; } > "$d/environment.txt" 2>&1
  # image_build.py keeps its own attempt records and full docker logs
  for id in audit-lsp-vendor audit-native audit-binary-analysis audit-codeql audit-codeql-native audit-buildenv-cpp; do
    local s="images/.build-state/$id"
    if [[ -d "$s" ]]; then
      mkdir -p "$d/state/$id"
      cp "$s/latest.json" "$d/state/$id/" 2>/dev/null || true
      local a; a=$(ls -1dt "$s"/attempts/*/ 2>/dev/null | head -1)
      [[ -n "$a" ]] && cp -r "$a" "$d/state/$id/last-attempt" 2>/dev/null || true
    fi
  done
  cp -r scratch/reverse-smoke "$d/reverse-smoke" 2>/dev/null || true
  cp -r scratch/codeql-per-language-smoke "$d/codeql-per-language-smoke" 2>/dev/null || true
  cp -r scratch/codeql-reachability-smoke "$d/codeql-reachability-smoke" 2>/dev/null || true
  tar czf "$LOGDIR/diagnostics.tgz" -C "$LOGDIR" . --exclude=diagnostics.tgz 2>/dev/null
  echo "DIAGNOSTICS: $(pwd)/$LOGDIR/diagnostics.tgz  ($(du -h "$LOGDIR/diagnostics.tgz" | cut -f1))"
}

finish() {
  echo; echo "================ SUMMARY (${LOGDIR}) ================"
  printf '%-42s %-30s %s\n' STEP RESULT SECONDS
  local bad=0 i
  for i in "${!NAMES[@]}"; do
    printf '%-42s %-30s %s\n' "${NAMES[$i]}" "${RESULTS[$i]}" "${SECS[$i]}"
    [[ "${RESULTS[$i]}" == PASS || "${RESULTS[$i]}" == SKIP* ]] || bad=1
  done
  cat <<'EOF'

MANUAL CHECKS (not automated):
  - Ghidra zip sha256 93a5d11a... against the hash in the Ghidra 12.1.3 release notes.
  - Go stays a gap (no offline build); the per-language smoke reports it as SKIP, not FAIL.
  - A QL compile error in a CodeQL reachability smoke means the packs under data/codeql-reachability/ (never
    compiled before) need a fix: the diagnostics bundle includes those logs.
EOF
  if [[ "${DRY_RUN:-0}" != "1" ]]; then collect_diagnostics; fi
  [[ $bad -eq 0 ]] && echo "ALL STEPS PASSED" || echo "SOME STEPS FAILED: send me diagnostics.tgz"
  exit $bad
}

echo "== appsec-review image rebuild + smoke v2, ${TS}"
echo "== repo: $(pwd)   branch: $(git branch --show-current 2>/dev/null)   head: $(git rev-parse --short HEAD 2>/dev/null)"
echo "== logs: ${LOGDIR}"

# ---- 0. preflight: the causes of most first-build failures ---------------------------------------
preflight() {
  local rc=0
  echo "disk:"; df -h . | tail -1
  local free_gb; free_gb=$(df -Pk . | awk 'NR==2 {printf "%d", $4/1024/1024}')
  if [[ "$free_gb" -lt 40 ]]; then echo "WARN: only ${free_gb} GB free here; these images need about 40 GB (Ghidra, JDK, Wine, CodeQL bundle)"; rc=1; fi
  echo "docker root:"; docker info 2>/dev/null | grep -E "Docker Root Dir|Storage Driver" | head -2
  for u in https://registry-1.docker.io/v2/ https://github.com https://storage.googleapis.com https://static.crates.io https://pypi.org https://files.pythonhosted.org; do
    if curl -sS -m 15 -o /dev/null -w "%{http_code}" "$u" 2>/dev/null | grep -qE "^[1-4][0-9][0-9]$"; then echo "reach OK   $u"
    else echo "reach FAIL $u"; rc=1; fi
  done
  # base images by name: unpinned or moved bases are a common failure
  for img in debian:bookworm-slim ubuntu:24.04 fkiecad/cwe_checker:latest; do
    if docker manifest inspect "$img" >/dev/null 2>&1; then echo "base OK    $img"; else echo "base FAIL  $img (cannot be pulled)"; rc=1; fi
  done
  return $rc
}
if [[ "${DRY_RUN:-0}" == "1" ]]; then echo "preflight skipped (dry run)"; else
  preflight 2>&1 | tee "$LOGDIR/preflight.log"; echo "== preflight above (WARN/FAIL lines are the usual suspects if a build fails)"
fi

# ---- Wine version: use what the distro actually offers ---------------------------------------------
WINE_ARGS=()
if [[ -n "${WINE_VERSION:-}" ]]; then
  WINE_ARGS=(--build-arg "WINE_VERSION=${WINE_VERSION}"); echo "WINE_VERSION forced: ${WINE_VERSION}"
elif [[ "${DRY_RUN:-0}" != "1" ]] && selected audit-binary-analysis; then
  want=$(sed -n 's/^ARG WINE_VERSION=//p' images/audit-binary-analysis/Dockerfile | head -1)
  have=$(docker run --rm debian:bookworm-slim bash -c 'dpkg --add-architecture i386; apt-get update -qq >/dev/null 2>&1; apt-cache policy wine | sed -n "s/^ *Candidate: //p"' 2>/dev/null | head -1)
  echo "wine: Dockerfile pins '${want}', debian:bookworm-slim offers '${have:-unknown}'"
  if [[ -n "$have" && "$have" != "$want" ]]; then
    WINE_ARGS=(--build-arg "WINE_VERSION=${have}")
    echo "wine: using ${have}. If the smoke then reports wine-version FAIL, update WINE_VERSION in the Dockerfile and scripts/smoke_reverse_tools.sh to match."
  fi
fi

# ---- 1. builds ---------------------------------------------------------------------------------
BUILD="python3 -B images/image_build.py build"
selected audit-lsp-vendor      && step build-audit-lsp-vendor      -- $BUILD audit-lsp-vendor "${BUILD_FLAGS[@]}"
selected audit-native          && step build-audit-native          -- $BUILD audit-native "${BUILD_FLAGS[@]}"
selected audit-binary-analysis && step build-audit-binary-analysis -- $BUILD audit-binary-analysis "${BUILD_FLAGS[@]}" "${WINE_ARGS[@]}"
selected audit-codeql          && step build-audit-codeql          --needs build-audit-lsp-vendor -- $BUILD audit-codeql "${BUILD_FLAGS[@]}"
selected audit-codeql-native   && step build-audit-codeql-native   --needs build-audit-lsp-vendor build-audit-native -- $BUILD audit-codeql-native "${BUILD_FLAGS[@]}"
if [[ "${WITH_BUILDENV:-0}" == "1" ]]; then
  step build-audit-buildenv-cpp --needs build-audit-lsp-vendor build-audit-native -- $BUILD audit-buildenv-cpp "${BUILD_FLAGS[@]}"
fi

# ---- 2. image records (opt-in) ------------------------------------------------------------------
if [[ "${REGISTER:-0}" == "1" ]]; then
  step register-image-records -- python3 -B images/registry_records.py generate
  step check-image-records --needs register-image-records -- python3 -B images/registry_records.py check
else
  echo "NOTE  image records NOT regenerated (REGISTER=1). Every 02-codeql-<lang> node stays an UNAVAILABLE gap until you do."
fi

# smoke NAME IMAGE SCRIPT-FILE -- COMMAND...: skip when this smoke already passed against this exact image id
STAMPS="scratch/.smoke-ok"; mkdir -p "$STAMPS"
smoke() {
  local name="$1" image="$2" script="$3"; shift 3; shift   # drop the --
  local iid sh key
  iid=$(docker image inspect --format "{{.Id}}" "${image}:local" 2>/dev/null | sed 's/^sha256://' | cut -c1-16)
  sh=$(sha256sum "$script" 2>/dev/null | cut -c1-12)
  key="$STAMPS/${name}-${iid}-${sh}"
  if [[ "${FORCE:-0}" != "1" && "${DRY_RUN:-0}" != "1" && -n "$iid" && -f "$key" ]]; then
    NAMES+=("$name"); RESULTS+=("SKIP (already passed)"); SECS+=(0)
    echo "SKIP  $name  (passed before against image ${iid})"; return 0
  fi
  step "$name" "${SMOKE_NEEDS[@]}" -- "$@"
  if [[ "${RESULTS[-1]}" == PASS && -n "$iid" ]]; then touch "$key"; fi
}

# ---- 3. smoke tests -----------------------------------------------------------------------------
if [[ "${SKIP_SMOKE:-0}" != "1" ]]; then
  SMOKE_NEEDS=(--needs build-audit-binary-analysis)
  smoke smoke-reverse-audit-binary-analysis audit-binary-analysis scripts/smoke_reverse_tools.sh -- bash scripts/smoke_reverse_tools.sh --docker audit-binary-analysis
  SMOKE_NEEDS=(--needs build-audit-native)
  smoke smoke-reverse-audit-native audit-native scripts/smoke_reverse_tools.sh -- bash scripts/smoke_reverse_tools.sh --docker audit-native
  SMOKE_NEEDS=(--needs build-audit-codeql)
  smoke smoke-codeql-per-language audit-codeql scripts/smoke_codeql_per_language.sh -- bash scripts/smoke_codeql_per_language.sh
  smoke smoke-codeql-reachability audit-codeql scripts/smoke_codeql_reachability.sh -- bash scripts/smoke_codeql_reachability.sh
  if [[ "${WITH_BUILDENV:-0}" == "1" ]]; then
    SMOKE_NEEDS=(--needs build-audit-buildenv-cpp)
    smoke smoke-lang-servers-cpp audit-buildenv-cpp scripts/smoke_lang_servers.sh -- bash scripts/smoke_lang_servers.sh --docker audit-buildenv-cpp
  fi
fi

finish
