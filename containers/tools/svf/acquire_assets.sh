#!/usr/bin/env bash
# Acquire the pinned SVF build inputs into the ignored downloads/ cache.
#
# 1. Release archives: SVF-3.3 source, the RTTI-enabled LLVM 21.1.0 distribution SVF-3.3's build.sh
#    names, and Z3 4.8.8. Each is fetched once; its SHA-256 and byte size must equal
#    assets.lock.json, otherwise the file is deleted and the script fails.
# 2. Build-only development headers (zlib, zstd, libxml2) that LLVM 21's CMake package requires.
#    The closure is resolved inside the tool-native-cpp image the Dockerfile builds on, so it is
#    exactly what the offline `apt-get install --no-download` there needs. APT verifies the signed
#    Release metadata and every package hash; the tar is deterministic, and every package, version
#    and SHA-256 is written to packages.manifest. Record the tar's size and SHA-256 in the lock.
#
# With --print, the hashes of files already present are printed instead of verified, for recording a
# deliberate version bump.
#
# Usage: containers/tools/svf/acquire_assets.sh [--print]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$here/downloads"

if [[ ! -f "$here/downloads/svf-build-debs.tar" ]]; then
  docker run --rm --network bridge --user 0 -e DEBIAN_FRONTEND=noninteractive \
    -v "$here/downloads:/out" appsec-review/tool-native-cpp:1.0.0 bash -euo pipefail -c '
      apt-get update -qq
      apt-get install -y -qq --download-only zlib1g-dev libzstd-dev libxml2-dev >/dev/null
      cd /var/cache/apt/archives
      tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu \
          -cf /out/svf-build-debs.tar.partial $(ls *.deb | LC_ALL=C sort)
      for deb in $(ls *.deb | LC_ALL=C sort); do
        printf "%s=%s %s %s\n" "$(dpkg-deb -f "$deb" Package)" "$(dpkg-deb -f "$deb" Version)" \
          "$(sha256sum "$deb" | cut -d" " -f1)" "$deb"
      done > /out/packages.manifest
      mv /out/svf-build-debs.tar.partial /out/svf-build-debs.tar
      chown "$(stat -c %u:%g /out)" /out/svf-build-debs.tar /out/packages.manifest
    '
fi

python3 - "$here/assets.lock.json" "$here" "${1:-}" <<'PY'
import hashlib, json, pathlib, subprocess, sys

lock, here, mode = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
for item in json.loads(lock.read_text(encoding="utf-8"))["artifacts"]:
    path = here / item["path"]
    if not path.is_file():
        if mode == "--print" or not item["url"].endswith((".tar.gz", ".zip")):
            print(f"missing {item['path']}")
            continue
        partial = path.with_suffix(path.suffix + ".partial")
        subprocess.run(["curl", "-fsSL", "--retry", "3", "-o", str(partial), item["url"]], check=True)
        partial.replace(path)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    size, sha = path.stat().st_size, digest.hexdigest()
    if mode == "--print":
        print(f"{item['path']} bytes={size} sha256={sha}")
        continue
    if sha != item["sha256"] or size != item["bytes"]:
        path.unlink()
        sys.exit(f"{item['path']}: got {size} bytes sha256 {sha}; lock requires {item['bytes']} {item['sha256']}")
    print(f"verified {item['path']}")
PY
