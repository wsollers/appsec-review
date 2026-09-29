#!/usr/bin/env bash
# update-host.sh   (run on zarathustra, or any host, from anywhere inside the appsec-review clone)
#
# Brings this host up to date with origin/main and makes it ready to run:
#   1. git: fetch, fast-forward main (refuses to touch local tracked changes; see STASH), prune dead worktrees
#   2. host packages: reports python3.12, libfuzzy2, jq, docker group, docker reachable, buildx
#   3. images (only with REBUILD=1): scripts/rebuild-images-and-smoke.sh
#   4. orchestrator/prepare-host.sh: snapshots, Dagster stack, missing images, image records,
#      code location started/reloaded, target clones, Claude CLI probe
#   5. MITRE ATT&CK/CAPEC/CWE feed sync + verify (skipped with MITRE=0; needs network to GitHub and cwe.mitre.org)
#   6. quick consistency checks (job catalog, design parity views, tunables)
#   7. summary, and what still needs a human
#
# Options (environment variables):
#   STASH=1        stash local tracked changes first (default: stop and list them)
#   BRANCH=name    update this branch instead of main (default main)
#   REBUILD=1      also rebuild the audit images (long; runs detached logging to scratch/)
#   REGISTER=1     with REBUILD=1: regenerate the B16 image records afterwards (changes job fingerprints)
#   BUILDENVS=1    pass --buildenvs to prepare-host.sh (per-language build images)
#   MITRE=0        skip the MITRE feed sync
#   NO_CLAUDE=1    skip the Claude CLI probe
#   CHECK_ONLY=1   report only: fetch and compare, run prepare-host.sh --check, change nothing else
#
#   bash scripts/update-host.sh                       normal update
#   REBUILD=1 REGISTER=1 bash scripts/update-host.sh  update and rebuild images (after image scripts changed)
#   nohup env REBUILD=1 bash scripts/update-host.sh > update.out 2>&1 &   then   tail -f update.out
set -uo pipefail

REPO="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null)" || { echo "not inside a git clone" >&2; exit 2; }
cd "$REPO"
BRANCH="${BRANCH:-main}"
RESULTS=(); MANUAL=()
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mOK\033[0m    %s\n' "$*"; RESULTS+=("OK    $*"); }
warn() { printf '  \033[33mWARN\033[0m  %s\n' "$*"; RESULTS+=("WARN  $*"); }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; RESULTS+=("FAIL  $*"); }
need() { MANUAL+=("$*"); }

# ---------------------------------------------------------------- 1. git
step "1. git ($REPO, branch $BRANCH)"
if ! git fetch --prune origin 2>&1 | tail -3; then fail "git fetch failed (network or credentials)"; fi
dirty="$(git status --porcelain --untracked-files=no)"
if [[ -n "$dirty" ]]; then
  if [[ "${STASH:-0}" == "1" ]]; then
    git stash push -m "update-host $(date -u +%Y%m%dT%H%M%SZ)" >/dev/null && ok "stashed local tracked changes (git stash list)"
    need "local changes were stashed: review with 'git stash list' and 'git stash show -p'"
  else
    fail "local tracked changes; rerun with STASH=1 or commit them first"
    printf '%s\n' "$dirty" | head -20 | sed 's/^/        /'
    exit 1
  fi
fi
current="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$current" != "$BRANCH" ]]; then git checkout "$BRANCH" 2>&1 | tail -2; fi
before="$(git rev-parse --short HEAD)"
if [[ "${CHECK_ONLY:-0}" == "1" ]]; then
  behind="$(git rev-list --count HEAD..origin/$BRANCH 2>/dev/null || echo '?')"
  echo "  $BRANCH is at $before, $behind commit(s) behind origin/$BRANCH"
else
  if git merge --ff-only "origin/$BRANCH" 2>&1 | tail -2; then
    after="$(git rev-parse --short HEAD)"
    if [[ "$before" == "$after" ]]; then ok "already at origin/$BRANCH ($after)"; else ok "$BRANCH $before -> $after"; git log --oneline "$before..$after" | head -25 | sed 's/^/        /'; fi
  else
    fail "cannot fast-forward $BRANCH (local commits diverge from origin). Inspect: git log --oneline origin/$BRANCH..$BRANCH"
    exit 1
  fi
  git worktree prune && ok "pruned dead worktrees"
fi
git submodule update --init --recursive >/dev/null 2>&1 || true

# ---------------------------------------------------------------- 2. host packages
step "2. host packages"
if command -v python3.12 >/dev/null 2>&1; then ok "python3.12 present"; else fail "python3.12 missing (the suite needs >= 3.11)"; need "sudo apt install python3.12 python3.12-venv"; fi
for tool in git jq; do command -v "$tool" >/dev/null 2>&1 && ok "$tool present" || { warn "$tool missing"; need "sudo apt install $tool"; }; done
if ldconfig -p 2>/dev/null | grep -q libfuzzy.so.2; then ok "libfuzzy2 present"; else fail "libfuzzy2 missing (the evidence index needs it)"; need "sudo apt install libfuzzy2"; fi
if id -nG | tr ' ' '\n' | grep -qx docker; then ok "user is in the docker group"; else warn "user not in the docker group"; need "sudo usermod -aG docker \$USER, then log out and in"; fi
DOCKER_OK=0
if docker info >/dev/null 2>&1; then DOCKER_OK=1; ok "docker reachable"; else fail "docker not reachable (docker info failed)"; need "start Docker: sudo systemctl start docker"; fi
if [[ $DOCKER_OK == 1 ]]; then
  if docker buildx version >/dev/null 2>&1; then ok "docker buildx works"; else fail "docker buildx missing or broken (BuildKit builds fail)"; need "install buildx: see docs/processes/host-layouts.md or the buildx release binary into ~/.docker/cli-plugins/"; fi
fi

if [[ "${CHECK_ONLY:-0}" == "1" ]]; then
  step "prepare-host.sh --check"
  bash orchestrator/prepare-host.sh --check 2>&1 | tail -40
  exit 0
fi

# ---------------------------------------------------------------- 3. images
if [[ "${REBUILD:-0}" == "1" ]]; then
  step "3. rebuild audit images (long; log in scratch/)"
  if [[ $DOCKER_OK != 1 ]]; then fail "skipped: docker not reachable"; else
    mkdir -p scratch
    log="scratch/update-host-rebuild-$(date -u +%Y%m%dT%H%M%SZ).log"
    if WITH_BUILDENV=1 REGISTER="${REGISTER:-0}" bash scripts/rebuild-images-and-smoke.sh >"$log" 2>&1; then ok "images rebuilt and smokes passed (log $log)"; else
      fail "image rebuild or smoke failed; see $log and the newest scratch/rebuild-*/diagnostics.tgz"; need "send scratch/rebuild-*/diagnostics.tgz"; fi
  fi
else
  step "3. images: skipped (set REBUILD=1 after image scripts change, e.g. audit-binary-analysis)"
fi

# ---------------------------------------------------------------- 4. prepare-host
step "4. prepare-host.sh"
args=()
[[ "${BUILDENVS:-0}" == "1" ]] && args+=(--buildenvs)
[[ "${NO_CLAUDE:-0}" == "1" ]] && args+=(--no-claude)
if bash orchestrator/prepare-host.sh "${args[@]}"; then ok "prepare-host.sh finished"; else fail "prepare-host.sh reported failures (read its output above)"; fi

# ---------------------------------------------------------------- 5. MITRE feed
if [[ "${MITRE:-1}" == "1" ]]; then
  step "5. MITRE ATT&CK / CAPEC / CWE feed"
  PY=python3.12; command -v "$PY" >/dev/null 2>&1 || PY=python3
  if "$PY" appsec-review-process/mitre_feed.py sync 2>&1 | tail -12; then
    if "$PY" appsec-review-process/mitre_feed.py verify 2>&1 | tail -6; then ok "MITRE feed synced and verified"; else fail "MITRE verify failed"; fi
  else
    fail "MITRE sync failed (network to GitHub or cwe.mitre.org?); a stale snapshot only records a gap and never blocks a run"
  fi
  need "first CWE sync: copy the CWE zip sha256 the smoke prints into the pin (bash scripts/smoke_mitre_feed.sh)"
else
  step "5. MITRE feed: skipped (MITRE=0)"
fi

# ---------------------------------------------------------------- 6. consistency
step "6. consistency checks"
PY=python3.12; command -v "$PY" >/dev/null 2>&1 || PY=python3
"$PY" docs/processes/job_catalog.py --check >/dev/null 2>&1 && ok "job catalog current" || fail "job catalog stale or check failed (python docs/processes/job_catalog.py --check)"
(cd appsec-review-process && "$PY" validate_design_parity.py --check-generated-views >/dev/null 2>&1) && ok "design-parity generated views current" || fail "design-parity views stale"
(cd appsec-review-process && "$PY" tunables.py check >/dev/null 2>&1) && ok "tunables doc current" || fail "tunables check failed"

# ---------------------------------------------------------------- 7. summary
step "7. summary (HEAD $(git rev-parse --short HEAD))"
printf '%s\n' "${RESULTS[@]}"
if ((${#MANUAL[@]})); then printf '\nStill needs a human:\n'; printf '  - %s\n' "${MANUAL[@]}"; fi
printf '\nNext: python3 orchestrator/run-status.py <run-id>   |   docs/processes/host-layouts.md\n'
printf '%s\n' "${RESULTS[@]}" | grep -q '^FAIL' && exit 1 || exit 0
