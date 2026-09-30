#!/usr/bin/env bash
# run.sh - shared hostile-build wrapper for language build/LSP/MCP containers.
#
# Usage:
#   run.sh <image> <workspace> <scratch> -- <command...>
#
# Runtime defaults match audit-native's isolation model: no network, read-only
# workspace, writable scratch, dropped caps, no-new-privileges, and bounded
# resources. Set ALLOW_NETWORK=1 only for explicitly authorized dependency
# restore or language-server bootstrap work. Set DEBUG_CAPS=1 only when an
# approved debugging task needs ptrace/seccomp support.
set -euo pipefail
IMAGE=${1:?image}; WS=${2:?workspace}; SCR=${3:?scratch}; shift 3
[ "${1:-}" = "--" ] && shift
mkdir -p "$SCR"
NETWORK_ARG=(--network none)
if [ "${ALLOW_NETWORK:-0}" = "1" ]; then
  NETWORK_ARG=(--network bridge)
fi
DEBUG_ARGS=()
if [ "${DEBUG_CAPS:-0}" = "1" ]; then
  DEBUG_ARGS=(--cap-add SYS_PTRACE --security-opt seccomp=unconfined)
fi
exec docker run --rm \
  --user "$(id -u):$(id -g)" \
  "${NETWORK_ARG[@]}" \
  --hostname audit-buildenv --add-host audit-buildenv:127.0.0.1 \
  --read-only \
  --cap-drop ALL \
  "${DEBUG_ARGS[@]}" \
  --security-opt no-new-privileges \
  --pids-limit "${PIDS_LIMIT:-2048}" \
  --memory "${MEM_LIMIT:-12g}" --memory-swap "${MEM_LIMIT:-12g}" \
  --cpus "${CPU_LIMIT:-8}" \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=4g \
  --tmpfs /tmp/home:rw,exec,nosuid,nodev,size=1g \
  -v "$(realpath "$WS"):/workspace:ro" \
  -v "$(realpath "$SCR"):/scratch:rw" \
  -e HOME=/tmp/home \
  -e USER=audit-worker \
  -e LOGNAME=audit-worker \
  -e XDG_CACHE_HOME=/scratch/.cache \
  -e npm_config_cache=/scratch/.npm \
  -e PIP_CACHE_DIR=/scratch/.pip-cache \
  "$IMAGE" "$@"
