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
# clang-18, cmake and bear drive the replays. The PHP and Python development headers are the ones
# containers/buildenv/php and containers/buildenv/python install, at the same pinned versions, so a
# phpize or setuptools compile captured there replays here against the same absolute include paths
# (/usr/include/php/20230831/..., /usr/include/python3.12). Keep these pins equal to those images';
# python3-dev pulls python3.12-dev and libpython3.12-dev, which carry Python.h and pyconfig.h.
php_version="8.3.6-0ubuntu0.24.04.11"
python_version="3.12.3-0ubuntu2.1"
packages="clang-18 cmake bear"
packages+=" php8.3-cli=$php_version php8.3-dev=$php_version"
packages+=" python3-dev=$python_version"
# Resolve against the Ubuntu snapshot service, not the live archive: noble-updates and noble-security
# supersede packages, and an exact version pinned below stops existing there within weeks (first seen
# 2026-11-09, "Version ... was not found"). The snapshot is immutable, so the pinned versions always
# resolve and the tar's hash stays what assets.lock.json records. The same snapshot buildenv-native-toolchain pins, so the closure and the toolchain agree.
snapshot="20261015T070000Z"
mkdir -p "$here/downloads"

# The bare base carries no CA bundle and the snapshot service is HTTPS only; lend it the host's trust
# roots read-only (the toolchain Dockerfile does the same by copying the bundle from a pinned image).
ca_bundle="${APPSEC_CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}"
[[ -r "$ca_bundle" ]] || { echo "CA bundle not readable: $ca_bundle (set APPSEC_CA_BUNDLE)" >&2; exit 1; }
docker run --rm --pull=missing -e DEBIAN_FRONTEND=noninteractive -e PACKAGES="$packages" -e SNAPSHOT="$snapshot" \
  -v "$ca_bundle:/etc/ssl/certs/ca-certificates.crt:ro" \
  -v "$here/downloads:/out" "$base" bash -euo pipefail -c '
    printf "APT::Snapshot \"%s\";\n" "$SNAPSHOT" > /etc/apt/apt.conf.d/50snapshot
    apt-get -o APT::Update::Error-Mode=any update -qq
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
