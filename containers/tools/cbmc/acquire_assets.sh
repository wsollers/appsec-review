#!/usr/bin/env bash
# Called after build.py fetches and verifies cbmc.deb. Resolve its dependencies against the
# same pinned Ubuntu base used by the offline Dockerfile, without installing them on the host.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
base="$(sed -n 's/^FROM \(ubuntu:24.04@sha256:[0-9a-f]\{64\}\)$/\1/p' "$here/Dockerfile")"
[[ -n "$base" ]] || { echo "pinned Ubuntu base not found in Dockerfile" >&2; exit 1; }
[[ -f "$here/downloads/cbmc.deb" ]] || {
  echo "cbmc.deb is missing; use python3 containers/build.py fetch tool-cbmc" >&2
  exit 1
}
ca_bundle="${APPSEC_CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}"
[[ -r "$ca_bundle" ]] || { echo "CA bundle not readable: $ca_bundle" >&2; exit 1; }

docker run --rm --pull=missing --platform linux/amd64 --cpus 2 --memory 1g --pids-limit 256 \
  -e DEBIAN_FRONTEND=noninteractive -e SNAPSHOT=20261015T070000Z \
  -v "$ca_bundle:/etc/ssl/certs/ca-certificates.crt:ro" \
  -v "$here/downloads/cbmc.deb:/inputs/cbmc.deb:ro" \
  -v "$here/downloads:/out" "$base" bash -euo pipefail -c '
    printf "APT::Snapshot \"%s\";\n" "$SNAPSHOT" > /etc/apt/apt.conf.d/50snapshot
    apt-get -o APT::Update::Error-Mode=any update -qq
    apt-get install -y -qq --download-only --no-install-recommends \
      /inputs/cbmc.deb g++ make cmake ninja-build pkg-config python3 >/dev/null
    cd /var/cache/apt/archives
    debs=(*.deb)
    [[ -f "${debs[0]}" ]]
    tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu \
      -cf /out/cbmc-debs.tar.partial "${debs[@]}"
    for deb in "${debs[@]}"; do
      printf "%s=%s %s %s\n" "$(dpkg-deb -f "$deb" Package)" "$(dpkg-deb -f "$deb" Version)" \
        "$(sha256sum "$deb" | cut -d" " -f1)" "$deb"
    done > /out/packages.manifest
    mv /out/cbmc-debs.tar.partial /out/cbmc-debs.tar
    chown "$(stat -c %u:%g /out)" /out/cbmc-debs.tar /out/packages.manifest
  '
echo "packages: $(wc -l < "$here/downloads/packages.manifest")"
echo "bytes:    $(stat -c %s "$here/downloads/cbmc-debs.tar")"
echo "sha256:   $(sha256sum "$here/downloads/cbmc-debs.tar" | cut -d' ' -f1)"
