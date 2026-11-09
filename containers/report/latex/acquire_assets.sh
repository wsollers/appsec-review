#!/usr/bin/env bash
# Acquire the .deb closure for tool-report-latex into downloads/report-latex-debs.tar.
#
# Same method as containers/tools/native-cpp/acquire_assets.sh: the closure is resolved inside the
# Dockerfile's own pinned Ubuntu base, so it is exactly the set of packages the offline
# `apt-get install --no-download` needs. APT verifies the signed Release metadata and every package
# hash while downloading. The tar is written deterministically (sorted names, fixed mtime and
# ownership) and a manifest of every package, version and SHA-256 is written next to it. Record the
# tar's size and SHA-256 in assets.lock.json and commit the manifest as packages.manifest after
# acquiring.
#
# Usage: containers/report/latex/acquire_assets.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
base="$(sed -n 's/^FROM \(ubuntu:24.04@sha256:[0-9a-f]\{64\}\) AS build$/\1/p' "$here/Dockerfile")"
[[ -n "$base" ]] || { echo "pinned ubuntu base not found in Dockerfile" >&2; exit 1; }
# texlive-xetex pulls texlive-latex-base/-recommended/-extra and texlive-pictures (tcolorbox, pgf,
# fontspec, fvextra, microtype, hyperref, booktabs, longtable); texlive-fonts-recommended adds the
# pzdr font metrics that hyperref loads under XeTeX. The fonts-extra collection is not used.
packages="texlive-xetex=2023.20240207-1 texlive-fonts-recommended=2023.20240207-1 fonts-inter=4.0+ds-1 fonts-jetbrains-mono=2.304+ds-4"
packages+=" poppler-utils=24.02.0-1ubuntu9.10"
# Resolve against the Ubuntu snapshot service, not the live archive: noble-updates and noble-security
# supersede packages, and an exact version pinned below stops existing there within weeks (first seen
# 2026-11-09, "Version ... was not found"). The snapshot is immutable, so the pinned versions always
# resolve and the tar's hash stays what assets.lock.json records. The day the lock was acquired (lock version ubuntu-24.04-2026-10-21).
snapshot="20261021T235959Z"
mkdir -p "$here/downloads"

docker run --rm --pull=missing -e DEBIAN_FRONTEND=noninteractive -e PACKAGES="$packages" -e SNAPSHOT="$snapshot" \
  -v "$here/downloads:/out" "$base" bash -euo pipefail -c '
    printf "APT::Snapshot \"%s\";\n" "$SNAPSHOT" > /etc/apt/apt.conf.d/50snapshot
    apt-get -o APT::Update::Error-Mode=any update -qq
    apt-get install -y -qq --no-install-recommends --download-only $PACKAGES >/dev/null
    cd /var/cache/apt/archives
    ls *.deb >/dev/null
    tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu \
        -cf /out/report-latex-debs.tar.partial $(ls *.deb | LC_ALL=C sort)
    for deb in $(ls *.deb | LC_ALL=C sort); do
      printf "%s=%s %s %s\n" "$(dpkg-deb -f "$deb" Package)" "$(dpkg-deb -f "$deb" Version)" \
        "$(sha256sum "$deb" | cut -d" " -f1)" "$deb"
    done > /out/packages.manifest
    mv /out/report-latex-debs.tar.partial /out/report-latex-debs.tar
    chown "$(stat -c %u:%g /out)" /out/report-latex-debs.tar /out/packages.manifest
  '

tar_path="$here/downloads/report-latex-debs.tar"
echo "packages: $(wc -l < "$here/downloads/packages.manifest")"
echo "bytes:    $(stat -c %s "$tar_path")"
echo "sha256:   $(sha256sum "$tar_path" | cut -d' ' -f1)"
