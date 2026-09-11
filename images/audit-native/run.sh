#!/usr/bin/env bash
# run.sh — host-side wrapper enforcing the hostile-build boundary (design §2.2)
# for one audit-native step. The orchestrator calls this with a static argv.
#
#   run.sh <workspace> <msvc-dir|-> <scratch> -- <command...>
#
# Every flag below is the boundary. Do not add --privileged, a docker socket,
# host home, or --network anything-other-than-none.
set -euo pipefail
WS=${1:?workspace}; MSVC=${2:?msvc dir or -}; SCR=${3:?scratch}; shift 3
[ "${1:-}" = "--" ] && shift
IMAGE=${AUDIT_NATIVE_IMAGE:-audit-native:local}
MSVC_MOUNT=()
[ "$MSVC" != "-" ] && MSVC_MOUNT=(-v "$(realpath "$MSVC"):/msvc:ro")
mkdir -p "$SCR"
exec docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit "${PIDS_LIMIT:-2048}" \
  --memory "${MEM_LIMIT:-16g}" --memory-swap "${MEM_LIMIT:-16g}" \
  --cpus "${CPU_LIMIT:-8}" \
  --tmpfs /tmp:rw,nosuid,nodev,size=4g \
  --tmpfs /home/worker:rw,nosuid,nodev,size=1g \
  -v "$(realpath "$WS"):/workspace:ro" \
  "${MSVC_MOUNT[@]}" \
  -v "$(realpath "$SCR"):/scratch:rw" \
  -e HOME=/home/worker \
  "$IMAGE" "$@"
