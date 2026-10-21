#!/usr/bin/env bash
# Shared helpers for the operator scripts in scripts/. Source this file; do not execute it.
# The real logic lives in deploy/dagster/bin/ops.py (typed, unit-tested); the scripts only locate
# the repository and a suitable Python, then hand over their arguments unchanged.
# shellcheck shell=bash

OPS_LIB_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd -P)"
OPS_ROOT="$(cd "$OPS_LIB_DIR/../.." && pwd -P)"

# True when "$1" is a Python 3.11 or newer interpreter (tomllib is required).
ops_python_ok() {
  "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1
}

# Print the interpreter to use: $APPSEC_PYTHON, this checkout's .venv, the main checkout's .venv
# (when this is a git worktree), then python3/python from PATH.
ops_find_python() {
  local candidate common
  if [ -n "${APPSEC_PYTHON:-}" ]; then
    printf '%s\n' "$APPSEC_PYTHON"
    return 0
  fi
  candidate="$OPS_ROOT/.venv/bin/python"
  if [ -x "$candidate" ] && ops_python_ok "$candidate"; then
    printf '%s\n' "$candidate"
    return 0
  fi
  if common="$(git -C "$OPS_ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)"; then
    candidate="$(dirname "$common")/.venv/bin/python"
    if [ -x "$candidate" ] && ops_python_ok "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && ops_python_ok "$candidate"; then
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}

# ops_main SUBCOMMAND ARGS...: run one ops.py subcommand and exit with its status.
ops_main() {
  local name="$1" python
  shift
  if ! python="$(ops_find_python)"; then
    echo "error: no Python 3.11+ found; create .venv or set APPSEC_PYTHON" >&2
    exit 1
  fi
  exec "$python" "$OPS_ROOT/deploy/dagster/bin/ops.py" "$name" "$@"
}
