#!/usr/bin/env bash
# ADR-0011: host-owned Dagster code location. Ops run as host processes with the host's own Docker;
# webserver/daemon (compose.yaml) reach this server at host.docker.internal:4000.
#
#   code-location.sh prepare   create/refresh the host venv and DAGSTER_HOME, then exit
#   code-location.sh start     prepare, then run `dagster api grpc` in the foreground
#   code-location.sh check     gRPC health check against the running server
#
# Native Linux or WSL (code-location.ps1 runs this under WSL on a Windows host). Runs as the
# invoking user: run data are written by the host user directly, not through a container mount.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PORT=4000   # fixed: workspace.yaml names this port
BIND="${APPSEC_GRPC_BIND:-0.0.0.0}"
VENV="${APPSEC_VENV:-$HOME/.venvs/appsec-review-dagster}"
# requirements.lock.txt is resolved for the image's Python (3.12, Dockerfile); other minors fail to
# resolve it (e.g. websockets==17.1 has no 3.10 build), so the host venv must match.
PYTHON="${APPSEC_PYTHON:-python3.12}"

# Shared with compose: the instance password and optional NVD settings. CRLF-safe; only
# KEY=VALUE lines with the keys below are read, nothing is eval'd.
if [[ ! -f "$HERE/.env" ]]; then
    echo "code-location: $HERE/.env missing; run: python orchestrator/dagster/setup.py" >&2; exit 2
fi
while IFS='=' read -r key value; do
    value="${value%$'\r'}"
    case "$key" in
        DAGSTER_POSTGRES_PASSWORD|NVD_API_KEY|APPSEC_NVD_SCHEDULE|APPSEC_PG_PORT)
            [[ -n "${!key:-}" ]] || export "$key=$value" ;;
    esac
done < "$HERE/.env"

export DAGSTER_HOME="$HERE/.host/home"
export DAGSTER_PG_HOST="${DAGSTER_PG_HOST:-127.0.0.1}"
export DAGSTER_PG_PORT="${APPSEC_PG_PORT:-55432}"
export DAGSTER_COMPUTE_LOG_DIR="$HERE/.host/compute-logs"
export DAGSTER_ARTIFACT_DIR="$HERE/.host/artifacts"
export APPSEC_PROCESS_ROOT="$REPO/appsec-review-process"
export APPSEC_RUNS_ROOT="$REPO/appsec-review-process/runs"
export APPSEC_NVD_ROOT="$REPO/data/feeds/nvd"
export APPSEC_ORCHESTRATOR_ROOT="$HERE"
export APPSEC_DEFINITIONS_DIR="$HERE"
export PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

prepare() {
    mkdir -p "$DAGSTER_HOME" "$DAGSTER_COMPUTE_LOG_DIR" "$DAGSTER_ARTIFACT_DIR" "$APPSEC_RUNS_ROOT"
    # Copied on every start so the host instance never drifts from the tracked file.
    cp "$HERE/dagster.yaml" "$DAGSTER_HOME/dagster.yaml"
    local stamp="$VENV/.appsec-requirements.sha256" want
    want="$(cat "$HERE/requirements.txt" "$HERE/requirements.lock.txt" | sha256sum | cut -d' ' -f1)"
    if [[ ! -x "$VENV/bin/dagster" || "$(cat "$stamp" 2>/dev/null)" != "$want" ]]; then
        echo "code-location: installing pinned Dagster into $VENV" >&2
        if ! "$PYTHON" -c 'import sys; sys.exit(sys.version_info[:2] != (3, 12))' 2>/dev/null; then
            echo "code-location: need Python 3.12 to match requirements.lock.txt; set APPSEC_PYTHON" \
                 "(e.g. sudo apt install python3.12-venv, or uv python install 3.12)" >&2; exit 2
        fi
        if ! "$PYTHON" -c 'import ensurepip' 2>/dev/null; then
            echo "code-location: $PYTHON has no ensurepip; on Ubuntu: sudo apt install python3.12-venv" >&2; exit 2
        fi
        # --clear: a half-built venv from an earlier failed attempt is rebuilt, not reused.
        "$PYTHON" -m venv --clear "$VENV"
        "$VENV/bin/pip" install --quiet --no-cache-dir -r "$HERE/requirements.txt" -c "$HERE/requirements.lock.txt"
        "$VENV/bin/pip" check
        echo "$want" > "$stamp"
    fi
}

case "${1:-start}" in
    prepare) prepare ;;
    start)
        prepare
        echo "code-location: dagster api grpc on $BIND:$PORT, runs under $APPSEC_RUNS_ROOT" >&2
        exec "$VENV/bin/dagster" api grpc -h "$BIND" -p "$PORT" \
            -f "$HERE/definitions.py" -d "$REPO" --location-name appsec_review ;;
    check) exec timeout 20 "$VENV/bin/dagster" api grpc-health-check -p "$PORT" ;;
    *) echo "usage: $0 [prepare|start|check]" >&2; exit 2 ;;
esac
