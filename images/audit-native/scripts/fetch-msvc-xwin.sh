#!/usr/bin/env bash
# fetch-msvc-xwin.sh — populate the MSVC CRT + Windows SDK volume using xwin.
#
# RUN THIS ON A NETWORKED HOST, NOT INSIDE THE ISOLATED WORKER. The worker has
# no network. The resulting directory is a LICENSED INPUT (Microsoft's VS
# license terms apply); it is mounted read-only at /msvc and its hash is
# recorded in build-isolation-manifest.json. Never bake it into an image.
#
# Pin the manifest version so two runs get identical headers.
#   usage: fetch-msvc-xwin.sh <dest-dir> [manifest-version] [arch]
#   e.g.   fetch-msvc-xwin.sh ./msvc 17 x86_64,x86
set -euo pipefail
DEST=${1:?dest dir}; MANIFEST=${2:-17}; ARCH=${3:-x86_64,x86}
mkdir -p "$DEST"
xwin --accept-license --manifest-version "$MANIFEST" --arch "$ARCH" --cache-dir "$DEST/.xwin-cache" \
     splat --output "$DEST" --include-debug-libs --preserve-ms-arch-notation
# record provenance next to the tree
{
  echo "xwin_version: $(xwin --version)"
  echo "manifest_version: $MANIFEST"
  echo "arch: $ARCH"
  echo "fetched_utc: $(date -u +%FT%TZ)"
  echo "tree_sha256: $(cd "$DEST" && find crt sdk -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)"
} > "$DEST/PROVENANCE.txt"
rm -rf "$DEST/.xwin-cache"
cat "$DEST/PROVENANCE.txt"
