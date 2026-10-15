#!/usr/bin/env bash
# Acquire the .deb closure for tool-native-cpp into downloads/native-cpp-debs.tar.
#
# The closure is resolved inside the image's own pinned base, so it is exactly the set of packages
# the offline `apt-get install --no-download` in the Dockerfile needs on top of that base. APT
# verifies the signed Release metadata and every package hash while downloading. The tar is written
# deterministically (sorted names, fixed mtime and ownership) and a manifest of every package,
# version and SHA-256 is written next to it. Record the tar's size and SHA-256 in assets.lock.json
# and commit the manifest as packages.manifest after acquiring.
#
# Usage: containers/tools/native-cpp/acquire_assets.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
base="$(sed -n 's/^FROM \(ubuntu:24.04@sha256:[0-9a-f]\{64\}\) AS build$/\1/p' "$here/Dockerfile")"
[[ -n "$base" ]] || { echo "pinned ubuntu base not found in Dockerfile" >&2; exit 1; }
packages="clang-18 cmake bear"
mkdir -p "$here/downloads"

docker run --rm --pull=missing -e DEBIAN_FRONTEND=noninteractive -e PACKAGES="$packages" \
  -v "$here/downloads:/out" "$base" bash -euo pipefail -c '
    apt-get update -qq
    apt-get install -y -qq --download-only $PACKAGES >/dev/null
    cd /var/cache/apt/archives
    ls *.deb >/dev/null
    tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu \
        -cf /out/native-cpp-debs.tar.partial $(ls *.deb | LC_ALL=C sort)
    for deb in $(ls *.deb | LC_ALL=C sort); do
      printf "%s=%s %s %s\n" "$(dpkg-deb -f "$deb" Package)" "$(dpkg-deb -f "$deb" Version)" \
        "$(sha256sum "$deb" | cut -d" " -f1)" "$deb"
    done > /out/packages.manifest
    mv /out/native-cpp-debs.tar.partial /out/native-cpp-debs.tar
    chown "$(stat -c %u:%g /out)" /out/native-cpp-debs.tar /out/packages.manifest
  '

tar_path="$here/downloads/native-cpp-debs.tar"
echo "packages: $(wc -l < "$here/downloads/packages.manifest")"
echo "bytes:    $(stat -c %s "$tar_path")"
echo "sha256:   $(sha256sum "$tar_path" | cut -d' ' -f1)"
