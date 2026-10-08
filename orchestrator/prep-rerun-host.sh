#!/usr/bin/env bash
# Prepare a run host for the hello-autotools re-run after the 2026-10-03 gap punch list
# (docs/report-path/happy-path-operator-guide.md). Wraps the repo's own tools in
# order; safe to re-run, each step only acts when something is missing or stale.
#
#   orchestrator/prep-rerun-host.sh               do everything
#   orchestrator/prep-rerun-host.sh --check       report what is missing; change nothing
#   orchestrator/prep-rerun-host.sh --skip-osv    skip the OSV feed download (E1, large, network)
#   orchestrator/prep-rerun-host.sh --no-claude   skip the Claude CLI login probe
#   orchestrator/prep-rerun-host.sh --publish     hal5000 only: publish the rebuilt images afterwards
#
# Steps:
#   1. update this checkout to origin/main (fast-forward only; a dirty or diverged tree stops here)
#   2. orchestrator/prepare-host.sh: packages, snapshots, Dagster stack, image rebuilds
#      (audit-binary-analysis = E3, audit-native, audit-buildenv-cpp*, audit-codeql-native = E2,
#      tool-shellcheck), B16 records, code location, targets at their pins, base-image cache (6b)
#   3. OSV feed (E1): osv_feed.py sync + verify into APPSEC_OSV_ROOT (default data/feeds/osv), now
#      including the Debian and Alpine ecosystems
#  3b. embedding model: semantic_recall_index.py fetch-model at the committed pin, then model-status
#   4. reload the code location so it sees the new feed and records; check the B16 records
#   5. final prepare-host.sh --check, then print the commands that start the re-run
# Log: orchestrator/dagster/.host/prep-rerun-<UTC time>.log
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO" || exit 1
CHECK=0; OSV=1; PUBLISH=0; HOST_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --check) CHECK=1 ;;
        --skip-osv) OSV=0 ;;
        --no-claude) HOST_ARGS+=(--no-claude) ;;
        --publish) PUBLISH=1 ;;
        -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

LOG_DIR="$REPO/orchestrator/dagster/.host"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/prep-rerun-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$LOG") 2>&1
FAILED=()
ok()   { printf '  \033[32mOK\033[0m    %s\n' "$*"; }
todo() { printf '  \033[33mTODO\033[0m  %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "${*:2}"; FAILED+=("$1"); }
step() { printf '\n== %s\n' "$*"; }
OSV_ROOT="${APPSEC_OSV_ROOT:-$REPO/data/feeds/osv}"

# ---- 1. checkout -----------------------------------------------------------------------------------
step "1. checkout at origin/main"
git fetch -q origin main || bad "git" "git fetch origin main failed (network or credentials)"
branch="$(git rev-parse --abbrev-ref HEAD)"
behind="$(git rev-list --count HEAD..origin/main 2>/dev/null || echo '?')"
if [[ "$branch" != "main" ]]; then
    bad "git" "on branch $branch, not main: git switch main"
elif [[ "$behind" == "0" ]]; then
    ok "main at $(git rev-parse --short HEAD), up to date"
elif [[ $CHECK -eq 1 ]]; then
    todo "main is $behind commit(s) behind origin/main: git pull --ff-only"
elif [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    bad "git" "local changes to tracked files; commit or stash them, then re-run (git status)"
elif git merge -q --ff-only origin/main; then
    ok "main fast-forwarded to $(git rev-parse --short HEAD) ($behind commit(s))"
    # This script may itself have changed: run the new version.
    exec "$REPO/orchestrator/prep-rerun-host.sh" "$@"
else
    bad "git" "main has diverged from origin/main; resolve by hand"
fi
if [[ " ${FAILED[*]} " == *" git "* && $CHECK -eq 0 ]]; then
    echo; echo "stopped: fix the checkout first (log: $LOG)"; exit 1
fi

# ---- 2. host preparation ---------------------------------------------------------------------------
step "2. orchestrator/prepare-host.sh $([[ $CHECK -eq 1 ]] && echo --check) ${HOST_ARGS[*]:-}"
if [[ $CHECK -eq 1 ]]; then
    orchestrator/prepare-host.sh --check "${HOST_ARGS[@]}" | sed 's/^/  /'
else
    echo "  image rebuilds can take a long time on the first pass; output follows"
    HOST_OUT="$(mktemp)"
    orchestrator/prepare-host.sh "${HOST_ARGS[@]}" 2>&1 | tee "$HOST_OUT" | sed 's/^/  /'
    if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
        ok "prepare-host.sh finished"
    else
        bad "prepare-host" "prepare-host.sh reported problems (FAIL lines above); fix them and re-run this script"
        # For images that failed to build, show the end of the latest attempt's logs.
        for id in $(sed -n 's/.*still missing: \([^(]*\).*/\1/p' "$HOST_OUT"); do
            latest="$(ls -td "images/.build-state/$id/attempts"/*/ 2>/dev/null | head -1)"
            [[ -n "$latest" ]] || { echo "  -- $id: no build attempt recorded"; continue; }
            echo "  -- $id: last lines of ${latest}logs/"
            for f in "${latest}logs/stderr.log" "${latest}logs/stdout.log" "${latest}logs/prebuild.log"; do
                [[ -s "$f" ]] && { echo "     $(basename "$f"):"; tail -n 25 "$f" | sed 's/^/       /'; }
            done
        done
    fi
    rm -f "$HOST_OUT"
fi

# ---- 3. OSV feed (E1) ------------------------------------------------------------------------------
step "3. OSV feed in $OSV_ROOT (E1)"
if [[ $OSV -eq 0 ]]; then
    todo "skipped (--skip-osv): reachability rows that need OSV stay gaps"
elif [[ $CHECK -eq 1 ]]; then
    if out="$(python3 -B appsec-review-process/osv_feed.py verify --root "$OSV_ROOT" 2>&1)"; then ok "$(echo "$out" | tail -1)"
    else todo "no verified feed: $(echo "$out" | tail -1)"; fi
else
    echo "  downloading the OSV ecosystems (several GB, network) ..."
    # sync takes the feed lock under a coordinator identity (Dagster passes its run id); a manual sync names itself.
    if python3 -B appsec-review-process/osv_feed.py sync --root "$OSV_ROOT" \
            --coordinator-id "prep-rerun-$(hostname -s)-$(date -u +%Y%m%dT%H%M%SZ)" 2>&1 | tail -5 | sed 's/^/    /' \
        && out="$(python3 -B appsec-review-process/osv_feed.py verify --root "$OSV_ROOT" 2>&1)"; then
        ok "feed verified: $(echo "$out" | tail -1)"
    else
        bad "osv" "osv_feed.py sync/verify failed (above); the previous good snapshot, if any, is kept"
    fi
fi

# ---- 3b. embedding model for 02-semantic-recall-index --------------------------------------------
step "3b. embedding model (02-semantic-recall-index)"
SRI=appsec-review-process/semantic_recall_index.py
if out="$(python3 -B "$SRI" model-status 2>&1)"; then
    ok "model present and matches its pin"
elif [[ $CHECK -eq 1 ]]; then
    todo "model missing or unpinned: $(echo "$out" | tail -1)"
elif python3 -B "$SRI" fetch-model 2>&1 | tail -3 | sed 's/^/    /' && python3 -B "$SRI" model-status >/dev/null 2>&1; then
    ok "model fetched at the pinned revision and verified"
else
    bad "embedding-model" "fetch-model failed (above); semantic recall stays a gap until the pinned model is present"
fi

# ---- 4. code location and registry records ---------------------------------------------------------
step "4. code location and B16 records"
if orchestrator/dagster/code-location.sh check >/dev/null 2>&1; then
    if [[ $CHECK -eq 0 ]]; then
        orchestrator/dagster/code-location.sh reload 2>&1 | tail -1 | sed 's/^/  /'
    fi
    ok "code location running"
else
    if [[ $CHECK -eq 1 ]]; then todo "code location not running (prepare-host.sh step 5 starts it)"
    else bad "code-location" "not running: see orchestrator/dagster/.host/code-location.log"; fi
fi
if out="$(python3 -B images/registry_records.py check 2>&1)"; then ok "$(echo "$out" | tail -1)"
elif [[ $CHECK -eq 1 ]]; then todo "$(echo "$out" | tail -1)"
else bad "registry" "$(echo "$out" | tail -1)"; fi

# ---- optional: publish images (hal5000) ------------------------------------------------------------
if [[ $PUBLISH -eq 1 && $CHECK -eq 0 ]]; then
    step "publish rebuilt images (ADR-0033)"
    if python3 -B images/image_build.py publish --all 2>&1 | tail -5 | sed 's/^/    /'; then
        ok "published; commit images/published.lock.json so other hosts load them"
    else
        bad "publish" "image_build.py publish --all failed (above)"
    fi
fi

# ---- 5. final check and next commands --------------------------------------------------------------
step "5. final check"
orchestrator/prepare-host.sh --check "${HOST_ARGS[@]}" | grep -E 'TODO|FAIL|not ready|check done' | sed 's/^/  /'
echo
if [[ ${#FAILED[@]} -eq 0 ]]; then
    if [[ $CHECK -eq 1 ]]; then
        echo "check done (TODO lines are what a normal run of this script would do). Log: $LOG"
    else
        cat <<'NEXT'
Host ready. Start the run (docs/report-path/happy-path-operator-guide.md):

  RUN_ID=$(orchestrator/stage-run.sh hello-autotools)
  python3 appsec-review-process/launch_job.py --run-id "$RUN_ID" --job full_review --wait
  # when it stops at the test gate (02-native-build accepted):
  python3 -B appsec-review-process/test_evidence.py stage-control "$RUN_ID"
  python3 appsec-review-process/launch_job.py --run-id "$RUN_ID" --job full_review --wait
  python3 orchestrator/run-status.py "$RUN_ID" --failed
NEXT
        echo "Log: $LOG"
    fi
    exit 0
fi
echo "not ready: ${FAILED[*]} (log: $LOG)"
exit 1
