#!/usr/bin/env bash
# Build language build/LSP/MCP worker images and binary-analysis workers.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ONLY="cpp,java,go,typescript,php,dotnet,python,rust,binary"
NO_CACHE=0
DOCKER_CONTEXT_NAME="${DOCKER_CONTEXT:-}"

usage() {
  cat <<'EOF'
Usage: scripts/build-language-buildenv-images.sh [options]

Options:
  --only NAMES    Comma-separated subset of: cpp,java,go,typescript,php,dotnet,python,rust,binary
  --no-cache      Pass --no-cache to docker build.
  --context NAME  Docker context override for this invocation only.
  -h, --help      Show this help.

Notes:
  cpp depends on audit-native:local. Build it first with:
    scripts/build-audit-images.sh --only native
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --only) ONLY="$2"; shift 2;;
    --no-cache) NO_CACHE=1; shift;;
    --context) DOCKER_CONTEXT_NAME="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "unknown option: $1" >&2; usage; exit 2;;
  esac
done

IFS=',' read -r -a SELECTED <<< "$ONLY"
want() {
  local name="$1"
  for s in "${SELECTED[@]}"; do [[ "$s" == "$name" ]] && return 0; done
  return 1
}

NOCACHE_ARGS=()
[[ "$NO_CACHE" == 1 ]] && NOCACHE_ARGS=(--no-cache)
DOCKER_CTX_ARGS=()
[[ -n "$DOCKER_CONTEXT_NAME" ]] && DOCKER_CTX_ARGS=(--context "$DOCKER_CONTEXT_NAME")

docker "${DOCKER_CTX_ARGS[@]}" info >/dev/null

RESULTS=()
FAILED=0
build_one() {
  local name="$1" tag="$2" dir="$3"
  echo ""
  echo "=== Building $name -> $tag ==="
  local start
  start=$(date +%s)
  if docker "${DOCKER_CTX_ARGS[@]}" build --progress=plain "${NOCACHE_ARGS[@]}" -t "$tag" "$REPO_ROOT/images/$dir"; then
    RESULTS+=("OK   $name -> $tag ($(( $(date +%s) - start ))s)")
  else
    RESULTS+=("FAIL $name -> $tag ($(( $(date +%s) - start ))s)")
    FAILED=1
  fi
}

want cpp && build_one cpp audit-buildenv-cpp:local audit-buildenv-cpp
want java && build_one java audit-buildenv-java:local audit-buildenv-java
want go && build_one go audit-buildenv-go:local audit-buildenv-go
want typescript && build_one typescript audit-buildenv-typescript:local audit-buildenv-typescript
want php && build_one php audit-buildenv-php:local audit-buildenv-php
want dotnet && build_one dotnet audit-buildenv-dotnet:local audit-buildenv-dotnet
want python && build_one python audit-buildenv-python:local audit-buildenv-python
want rust && build_one rust audit-buildenv-rust:local audit-buildenv-rust
want binary && build_one binary audit-binary-analysis:local audit-binary-analysis

echo ""
echo "=== Summary ==="
for r in "${RESULTS[@]}"; do echo "$r"; done
exit "$FAILED"
