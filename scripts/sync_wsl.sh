#!/usr/bin/env bash
# sync_wsl.sh [BRANCH]      default: main
#
# Points a host clone (hal5000 WSL: ~/projects/appsec-review, docs/processes/host-layouts.md) at
# origin/BRANCH exactly, for building images or running targets from the current remote head.
# Local changes (tracked and untracked) are stashed first, never discarded: `git stash list` shows
# them and `git stash pop` restores them. Ignored paths (scratch/, images/.build-state/, downloads/)
# are left alone. Works on the clone this script lives in; set APPSEC_REPO to sync another one.
set -euo pipefail
REPO=${APPSEC_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
BRANCH=${1:-main}
cd "$REPO"

git fetch --prune origin
git rev-parse --verify --quiet "origin/$BRANCH" >/dev/null || { echo "no origin/$BRANCH" >&2; exit 1; }

if [ -n "$(git status --porcelain)" ]; then
  git stash push --include-untracked -m "sync_wsl $(date -u +%Y-%m-%dT%H:%M:%SZ) before $BRANCH"
  echo "local changes stashed: git stash list"
fi

git checkout -B "$BRANCH" "origin/$BRANCH"   # creates the branch or resets it to the remote head
git branch --set-upstream-to="origin/$BRANCH" "$BRANCH" >/dev/null
git worktree prune

echo "== $REPO now at:"
git log --oneline -1
git status -sb | head -1
