#!/usr/bin/env bash
# run.sh — host-side wrapper enforcing the hostile-build boundary (design §2.2)
# for one audit-native step. The orchestrator calls this with a static argv.
#
#   run.sh <workspace> <msvc-dir|-> <scratch> -- <command...>
#
# Every flag below is the boundary. Do not add --privileged, a docker socket,
# host home, or --network anything-other-than-none.
#
# /tmp is noexec on purpose (Docker's tmpfs default, made explicit): a hostile
# build must not be able to drop and run binaries there. Joern's zstd-jni needs
# to dlopen a .so it extracts into java.io.tmpdir, so the JVM — and only the
# JVM — gets a small separate exec-allowed tmpfs at /tmp/jvm via
# JAVA_TOOL_OPTIONS (which reaches joern-parse's c2cpg subprocess too).
# --add-host: with --network none the container's own hostname doesn't resolve,
# which log4j treats as an error on every JVM start.
set -euo pipefail
WS=${1:?workspace}; MSVC=${2:?msvc dir or -}; SCR=${3:?scratch}; shift 3
[ "${1:-}" = "--" ] && shift
IMAGE=${AUDIT_NATIVE_IMAGE:-audit-native:local}
MSVC_MOUNT=()
[ "$MSVC" != "-" ] && MSVC_MOUNT=(-v "$(realpath "$MSVC"):/msvc:ro")
mkdir -p "$SCR"
# --user: run as the invoking host user so /scratch (a bind mount) is writable.
exec docker run --rm \
  --user "$(id -u):$(id -g)" \
  --network none \
  --hostname audit-native --add-host audit-native:127.0.0.1 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit "${PIDS_LIMIT:-2048}" \
  --memory "${MEM_LIMIT:-16g}" --memory-swap "${MEM_LIMIT:-16g}" \
  --cpus "${CPU_LIMIT:-8}" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=4g \
  --tmpfs /tmp/home:rw,noexec,nosuid,nodev,size=1g \
  --tmpfs /tmp/jvm:rw,exec,nosuid,nodev,size=512m \
  -v "$(realpath "$WS"):/workspace:ro" \
  "${MSVC_MOUNT[@]}" \
  -v "$(realpath "$SCR"):/scratch:rw" \
  -e HOME=/tmp/home \
  -e JAVA_TOOL_OPTIONS=-Djava.io.tmpdir=/tmp/jvm \
  "$IMAGE" "$@"
