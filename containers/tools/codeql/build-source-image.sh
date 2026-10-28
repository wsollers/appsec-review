#!/usr/bin/env bash
# Build the licensed CodeQL source image (audit-codeql:custom-2.27.0) from this repository's
# Dockerfiles on any Linux or WSL Docker host. Run from anywhere; see README.md in this directory.
#
#   containers/tools/codeql/build-source-image.sh
#
# Downloads are pinned by SHA-256 and staged in the ignored containers/tools/codeql/downloads/;
# every docker build runs with --network=none. Override tags with CODEQL_LOCAL_TAG and
# CODEQL_CUSTOM_TAG (for example to build a scratch copy beside the pinned one).
set -euo pipefail

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../../.." && pwd)
DOCKER=${APPSEC_DOCKER_BIN:-docker}
STAGE="$HERE/downloads"
LOCAL_TAG=${CODEQL_LOCAL_TAG:-audit-codeql:local}
CUSTOM_TAG=${CODEQL_CUSTOM_TAG:-audit-codeql:custom-2.27.0}
BASE_TAG=appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1

BUNDLE_URL=https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.0/codeql-bundle-linux64.tar.gz
BUNDLE_SHA256=8e870433e5c80d0e916c3c1aa9005fc88aab990bcdcc649fade9dfc4d7e94305
STANDARDS_URL=https://github.com/github/codeql-coding-standards/releases/download/v2.62.0/coding-standards-codeql-packs.zip
STANDARDS_SHA256=775e34cb36e522c30f3c4381c0758a7fbe29e6c9a5428eb6c9ad67ebd145cb0b

fetch() {
  local url=$1 sha=$2 out=$3
  if [ -f "$out" ] && echo "$sha  $out" | sha256sum -c --status -; then
    return
  fi
  curl -fL --retry 3 --proto '=https' -o "$out.part" "$url"
  echo "$sha  $out.part" | sha256sum -c -
  mv "$out.part" "$out"
}

mkdir -p "$STAGE"
fetch "$BUNDLE_URL" "$BUNDLE_SHA256" "$STAGE/codeql-bundle-linux64.tar.gz"
fetch "$STANDARDS_URL" "$STANDARDS_SHA256" "$STAGE/coding-standards-codeql-packs.zip"

if ! "$DOCKER" image inspect "$BASE_TAG" >/dev/null 2>&1; then
  "$ROOT/containers/build-all.sh" build buildenv-native-toolchain
fi

"$DOCKER" build --network=none --pull=false \
  --file "$HERE/Dockerfile.bundle" --build-arg "BASE_IMAGE=$BASE_TAG" \
  --tag "$LOCAL_TAG" "$STAGE"
"$DOCKER" build --network=none --pull=false \
  --file "$HERE/Dockerfile.custom-source" --build-arg "CODEQL_SOURCE_IMAGE=$LOCAL_TAG" \
  --tag "$CUSTOM_TAG" "$STAGE"

if [ "${CODEQL_KEEP_DOWNLOADS:-0}" != 1 ]; then
  rm -rf "$STAGE"
fi
echo "$CUSTOM_TAG $("$DOCKER" image inspect "$CUSTOM_TAG" --format '{{.Id}}')"
