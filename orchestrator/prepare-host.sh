#!/usr/bin/env bash
# Get this host ready to run full_review on the ADR-0013 targets. Idempotent: each step checks first
# and only acts when something is missing. Safe to re-run.
#
#   orchestrator/prepare-host.sh              do every required step
#   orchestrator/prepare-host.sh --check      report what is missing; change nothing
#   orchestrator/prepare-host.sh --buildenvs  also build the per-language build images
#                                             (audit-buildenv-*), expected for appsec-multi-vuln
#   orchestrator/prepare-host.sh --no-claude  skip the Claude CLI login probe
#
# Steps (host layouts: docs/processes/host-layouts.md):
#   0. host packages: python3.12 + venv, git, libfuzzy2, jq, docker group (reported; install needs sudo)
#   1. offline Grype/OSV snapshots resolve within the 14-day ceiling (sync is separate; see TODO.md)
#   2. Dagster stack (compose project appsec-review) is up
#   3. every image the B13 registry needs has a current successful build here (builds missing or stale ones)
#   4. B16 registry records generate and match Docker
#   5. the host code location is running (started in the background if not) and reloaded
#   6. the four targets are cloned at their pinned commits (fixtures/populate-targets.sh)
#   7. the Claude CLI answers (persona jobs use its subscription login)
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
CHECK=0; BUILDENVS=0; CLAUDE=1
for arg in "$@"; do
    case "$arg" in
        --check) CHECK=1 ;;
        --buildenvs) BUILDENVS=1 ;;
        --no-claude) CLAUDE=0 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

REG="$REPO/appsec-review-process/offline/dependency-snapshots"
MAX_AGE=1209600
LOG_DIR="$REPO/orchestrator/dagster/.host"
CL_LOG="$LOG_DIR/code-location.log"
FAILED=()
ok()   { printf '  \033[32mOK\033[0m    %s\n' "$*"; }
todo() { printf '  \033[33mTODO\033[0m  %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "${*:2}"; FAILED+=("$1"); }
step() { printf '\n== %s\n' "$*"; }

# ---- 0. host packages -----------------------------------------------------------------------------
step "0. host packages"
command -v python3.12 >/dev/null && python3.12 -c 'import ensurepip' 2>/dev/null \
    && ok "python3.12 with venv" || bad "python" "python3.12 or python3.12-venv missing: sudo apt install python3.12-venv"
command -v git >/dev/null && ok "$(git --version)" || bad "git" "git missing: sudo apt install git"
ldconfig -p 2>/dev/null | grep -q 'libfuzzy.so.2' && ok "libfuzzy2" \
    || bad "libfuzzy" "libfuzzy.so.2 missing (evidence index needs it): sudo apt install libfuzzy2"
command -v jq >/dev/null && ok "jq $(jq --version)" \
    || bad "jq" "jq missing (model jobs query JSON inputs through input_jq): sudo apt install jq"
id -nG | tr ' ' '\n' | grep -qx docker && ok "$(id -un) in docker group" \
    || bad "docker-group" "$(id -un) not in the docker group: sudo usermod -aG docker $(id -un), then log in again"

# ---- 1. offline vulnerability snapshots -----------------------------------------------------------
step "1. offline Grype/OSV snapshots (ceiling ${MAX_AGE}s)"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
for kind in grype-db osv; do
    out="$(python3 -B appsec-review-process/dependency_snapshot_registry.py resolve --kind "$kind" \
        --registry-root "$REG" --max-age-seconds "$MAX_AGE" --now "$NOW" 2>&1)"
    if [[ $? -eq 0 ]]; then
        ok "$kind $(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d["snapshot_id"], "age", d["age_seconds"]//3600, "h")' "$out")"
    else
        bad "snapshot-$kind" "$kind: $out (re-sync with appsec-review-process/dependency_snapshot_sync.py)"
    fi
done

# ---- 2. Dagster stack ------------------------------------------------------------------------------
step "2. Dagster stack"
running="$(docker compose -p appsec-review ps --status running --format '{{.Service}}' 2>/dev/null | sort | tr '\n' ' ')"
if [[ "$running" == *daemon* && "$running" == *postgres* && "$running" == *webserver* ]]; then
    ok "running: $running"
elif [[ $CHECK -eq 1 ]]; then
    todo "stack not fully up (running: ${running:-none})"
else
    docker compose -p appsec-review -f orchestrator/dagster/compose.yaml up -d && ok "stack started" \
        || bad "stack" "docker compose up failed"
fi

# ---- 3. images -------------------------------------------------------------------------------------
step "3. images needed by the B13 registry"
# Build-only images (audit-lsp-vendor) come first: the compiler images mount them at build time.
mapfile -t REQUIRED < <(python3 -B -c 'import sys; sys.path.insert(0, "images"); import registry_records as r; print("\n".join(r.BUILD_ONLY_IMAGE_IDS + r.STEP4_IMAGE_IDS))')
if [[ $BUILDENVS -eq 1 ]]; then
    for d in images/audit-buildenv-*/; do [[ -f "$d/image.json" ]] && REQUIRED+=("$(basename "$d")"); done
fi
# Missing: no successful build, or its inputs changed since (the same fingerprint check step 4 makes).
missing_images() {
    python3 -B - "${REQUIRED[@]}" <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, "images")
try:
    import image_build
    builds = image_build.load_builds(Path("images"))
except Exception:   # cannot tell: report every image, so nothing passes as current by accident
    builds = {}
for image_id in sys.argv[1:]:
    latest = Path("images/.build-state", image_id, "latest.json")
    try:
        stale = image_build.fingerprint(builds[image_id])[0] != json.loads(latest.read_text())["fingerprint"]
    except Exception:
        stale = True
    if stale:
        print(image_id)
PY
}
mapfile -t MISSING < <(missing_images)
if [[ ${#MISSING[@]} -eq 0 ]]; then
    ok "all ${#REQUIRED[@]} images have a current successful build"
elif [[ $CHECK -eq 1 ]]; then
    todo "missing or stale builds: ${MISSING[*]}"
else
    # A build that needs another image first reports BLOCKED; keep passing until nothing moves.
    while :; do
        before=${#MISSING[@]}
        for id in "${MISSING[@]}"; do
            echo "  building $id ..."
            python3 -B images/image_build.py build "$id" 2>&1 | tail -3 | sed 's/^/    /'
        done
        mapfile -t MISSING < <(missing_images)
        [[ ${#MISSING[@]} -eq 0 || ${#MISSING[@]} -eq $before ]] && break
    done
    if [[ ${#MISSING[@]} -eq 0 ]]; then ok "all ${#REQUIRED[@]} images built"
    else bad "images" "still missing: ${MISSING[*]} (see images/.build-state/<id>/attempts/*/logs)"; fi
fi

# ---- 4. registry records ---------------------------------------------------------------------------
step "4. B16 registry records"
if [[ $CHECK -eq 0 ]]; then
    python3 -B images/registry_records.py generate >/dev/null 2>&1 || true
fi
if out="$(python3 -B images/registry_records.py check 2>&1)"; then
    ok "$(echo "$out" | tail -1)"
elif [[ $CHECK -eq 1 ]]; then
    todo "$(echo "$out" | tail -1)"
else
    bad "registry" "$(echo "$out" | tail -1)"
fi

# ---- 5. code location ------------------------------------------------------------------------------
step "5. host code location"
cl_up() { orchestrator/dagster/code-location.sh check >/dev/null 2>&1; }
if cl_up; then
    ok "running"
    [[ $CHECK -eq 0 ]] && { orchestrator/dagster/code-location.sh reload 2>&1 | tail -1 | sed 's/^/  /'; }
elif [[ $CHECK -eq 1 ]]; then
    todo "not running"
elif [[ " ${FAILED[*]} " == *" images "* || " ${FAILED[*]} " == *" registry "* ]]; then
    bad "code-location" "not started: fix images/registry first (records are generated at start)"
else
    mkdir -p "$LOG_DIR"
    echo "  starting in the background; log: $CL_LOG"
    setsid nohup orchestrator/dagster/code-location.sh start >"$CL_LOG" 2>&1 < /dev/null &
    for _ in $(seq 1 60); do cl_up && break; sleep 5; done
    if cl_up; then
        ok "started (pid $(pgrep -f 'dagster code-server start' | head -1))"
        orchestrator/dagster/code-location.sh reload 2>&1 | tail -1 | sed 's/^/  /'
    else
        bad "code-location" "did not come up within 5 minutes; tail $CL_LOG"
    fi
fi

# ---- 6. targets ------------------------------------------------------------------------------------
step "6. targets"
if [[ $CHECK -eq 1 ]]; then
    for t in hello-autotools appsec-multi-vuln freeciv21 doom3-bfg; do
        if [[ -d "fixtures/targets/$t/.git" ]]; then ok "$t ($(git -C "fixtures/targets/$t" rev-parse --short HEAD))"
        else todo "$t not cloned"; fi
    done
else
    fixtures/populate-targets.sh 2>&1 | sed 's/^/  /'
    [[ ${PIPESTATUS[0]} -eq 0 ]] && ok "all targets at their pinned commits" || bad "targets" "populate-targets.sh reported a problem"
fi

# ---- 7. Claude CLI ---------------------------------------------------------------------------------
step "7. Claude CLI"
if [[ $CLAUDE -eq 0 ]]; then
    todo "skipped (--no-claude)"
elif ! command -v claude >/dev/null; then
    bad "claude" "claude CLI not on PATH"
elif reply="$(timeout 90 claude -p --model haiku 'Reply with the single word READY.' 2>&1)" && [[ "$reply" == *READY* ]]; then
    ok "$(claude --version 2>/dev/null | head -1) answers"
else
    bad "claude" "no answer from claude -p: ${reply:0:200} (log in with: claude)"
fi

# ---- summary ---------------------------------------------------------------------------------------
echo
if [[ ${#FAILED[@]} -eq 0 ]]; then
    [[ $CHECK -eq 1 ]] && echo "check done (TODO lines are what a normal run would do)." \
                       || echo "host ready: stage a run and launch full_review (appsec-review-process/TODO.md)."
    exit 0
fi
echo "not ready: ${FAILED[*]}"
exit 1
