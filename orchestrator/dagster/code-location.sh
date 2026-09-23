#!/usr/bin/env bash
# ADR-0011: host-owned Dagster code location. Ops run as host processes with the host's own Docker;
# webserver/daemon (compose.yaml) reach this server at host.docker.internal:4000, which compose maps
# to APPSEC_CODE_LOCATION_HOST (set here under WSL NAT) or Docker's host-gateway.
#
#   code-location.sh prepare   create/refresh the host venv and DAGSTER_HOME, then exit
#   code-location.sh start     prepare, then run `dagster api grpc` in the foreground
#   code-location.sh check     gRPC health check against the running server
#   code-location.sh reload    tell the webserver to reload this code location (run after every
#                              start/restart: until then it launches from its old job list and a
#                              new job is rejected with PipelineNotFoundError)
#
# Native Linux or WSL (code-location.ps1 runs this under WSL on a Windows host). Runs as the
# invoking user: run data are written by the host user directly, not through a container mount.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PORT=4000   # fixed: workspace.yaml names this port
BIND="${APPSEC_GRPC_BIND:-}"   # resolved below: WSL NAT -> the distro's own IP, else 0.0.0.0
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

# Where the containers find this server. Under WSL 2 NAT networking, Docker Desktop's host-gateway
# is the Windows host, which WSL does not forward this port to (verified 2026-09-22 on hal5000:
# refused); the distro's own IP is reachable from the containers because Docker Desktop runs in the
# same WSL VM. That IP changes on every WSL restart, so it is re-read on each start and written to
# .env as APPSEC_CODE_LOCATION_HOST, which compose.yaml maps host.docker.internal to.
wsl_nat_ip() {
    [[ -r /proc/sys/fs/binfmt_misc/WSLInterop || -n "${WSL_DISTRO_NAME:-}" ]] || return 1
    [[ "$(wslinfo --networking-mode 2>/dev/null)" == "nat" ]] || return 1
    ip -4 -o addr show dev eth0 2>/dev/null | awk '{split($4, a, "/"); print a[1]; exit}'
}
sync_env_host() {   # rewrite only this script's own key; every other .env line is left alone
    local value="$1" current
    current="$(sed -n 's/^APPSEC_CODE_LOCATION_HOST=//p' "$HERE/.env" | tr -d '\r')"
    [[ "$current" == "$value" ]] && return 0
    if [[ -n "$current" ]]; then
        sed -i "s/^APPSEC_CODE_LOCATION_HOST=.*/APPSEC_CODE_LOCATION_HOST=$value/" "$HERE/.env"
    else
        [[ -z "$(tail -c1 "$HERE/.env")" ]] || echo >> "$HERE/.env"
        echo "APPSEC_CODE_LOCATION_HOST=$value" >> "$HERE/.env"
    fi
    echo "code-location: APPSEC_CODE_LOCATION_HOST ${current:-(unset)} -> $value; recreate the containers:" \
         "docker compose -f $HERE/compose.yaml up -d webserver daemon" >&2
}
if WSL_IP="$(wsl_nat_ip)" && [[ -n "$WSL_IP" ]]; then
    BIND="${BIND:-$WSL_IP}"
    sync_env_host "$WSL_IP"
fi
BIND="${BIND:-0.0.0.0}"
CHECK_HOST="$BIND"; [[ "$BIND" == "0.0.0.0" ]] && CHECK_HOST=127.0.0.1

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
    if ! mkdir -p "$DAGSTER_HOME" "$DAGSTER_COMPUTE_LOG_DIR" "$DAGSTER_ARTIFACT_DIR" "$APPSEC_RUNS_ROOT" \
         || [[ ! -w "$DAGSTER_HOME" || ! -w "$DAGSTER_COMPUTE_LOG_DIR" ]]; then
        # Usually `compose up` ran before setup.py and Docker created the bind source as root.
        echo "code-location: $HERE/.host is not writable by $(id -un); fix with:" \
             "sudo chown -R $(id -u):$(id -g) '$HERE/.host'" >&2; exit 2
    fi
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
        # Workers now run here, not in the image, so host prerequisites the image used to pin are checked.
        command -v git >/dev/null || echo "code-location: WARNING git not found; intake needs it" >&2
        "$VENV/bin/python" -c "import ctypes; ctypes.CDLL('libfuzzy.so.2')" 2>/dev/null \
            || echo "code-location: WARNING libfuzzy.so.2 not found; evidence_index needs it (Ubuntu: sudo apt install libfuzzy2)" >&2
        echo "code-location: dagster api grpc on $BIND:$PORT, runs under $APPSEC_RUNS_ROOT" >&2
        echo "code-location: once it reports Started, run '$0 reload' so the webserver picks up the current jobs" >&2
        exec "$VENV/bin/dagster" api grpc -h "$BIND" -p "$PORT" \
            -f "$HERE/definitions.py" -d "$REPO" --location-name appsec_review ;;
    check) exec timeout 20 "$VENV/bin/dagster" api grpc-health-check -h "$CHECK_HOST" -p "$PORT" ;;
    reload)
        exec "$VENV/bin/python" - <<'PY'
import json, sys, urllib.request
query = 'mutation { reloadRepositoryLocation(repositoryLocationName: "appsec_review") { __typename ... on WorkspaceLocationEntry { loadStatus } ... on PythonError { message } } }'
request = urllib.request.Request('http://127.0.0.1:3000/graphql', data=json.dumps({'query': query}).encode(),
                                 headers={'Content-Type': 'application/json'})
try:
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.load(response)['data']['reloadRepositoryLocation']
except Exception as exc:
    sys.exit(f'code-location: webserver reload failed ({exc}); is the stack up on 127.0.0.1:3000?')
print('code-location: webserver reload ->', json.dumps(result))
sys.exit(0 if result.get('__typename') == 'WorkspaceLocationEntry' else 1)
PY
        ;;
    *) echo "usage: $0 [prepare|start|check|reload]" >&2; exit 2 ;;
esac
