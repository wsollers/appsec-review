#!/usr/bin/env bash
# Acquire the hash-locked wheels and grammar libraries for tool-tree-sitter into downloads/.
#
# This is the procedure README.md describes, as one command: inside the image's own digest-pinned
# base, download the two exact wheels assets.lock.json names into downloads/wheels (pip verifies the
# recorded SHA-256), install them, and run acquire_assets.py with /out bound to downloads so the
# language pack writes one prebuilt .so per locked grammar into downloads/parsers-linux. The build
# never uses the network; verify_assets.py inside the Dockerfile rejects any byte that differs from
# the lock. Idempotent: existing current files are left alone by the launcher, which only calls this
# when something under downloads/ is missing or mismatched.
#
# Usage: containers/tools/tree-sitter/acquire_assets.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock="$here/assets.lock.json"
base="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["base"])' "$lock")"
read -r ts_version ts_sha lp_version lp_sha < <(python3 - "$lock" <<'PY'
import json, sys
lock = json.load(open(sys.argv[1]))
print(lock["tree_sitter"]["version"], lock["tree_sitter"]["wheel_sha256"],
      lock["language_pack"]["version"], lock["language_pack"]["wheel_sha256"])
PY
)
mkdir -p "$here/downloads/wheels" "$here/downloads/parsers-linux"
docker run --rm --pull=missing \
  -e TS_VERSION="$ts_version" -e TS_SHA="$ts_sha" -e LP_VERSION="$lp_version" -e LP_SHA="$lp_sha" \
  -v "$here/downloads:/out" -v "$here/acquire_assets.py:/acquire_assets.py:ro" "$base" bash -euo pipefail -c '
    printf "tree-sitter==%s --hash=sha256:%s\ntree-sitter-language-pack==%s --hash=sha256:%s\n" \
        "$TS_VERSION" "$TS_SHA" "$LP_VERSION" "$LP_SHA" > /tmp/requirements.txt
    pip download --quiet --no-deps --only-binary=:all: --require-hashes \
        --platform manylinux_2_34_x86_64 --platform manylinux2014_x86_64 --platform manylinux_2_28_x86_64 \
        --python-version 3.12 --implementation cp --dest /out/wheels -r /tmp/requirements.txt
    pip install --quiet --no-index --no-deps --find-links=/out/wheels \
        "tree-sitter==$TS_VERSION" "tree-sitter-language-pack==$LP_VERSION"
    rm -rf /out/parsers-linux/*
    python /acquire_assets.py
    chown -R "$(stat -c %u:%g /out)" /out/wheels /out/parsers-linux
  '
echo "wheels:   $(ls "$here/downloads/wheels" | wc -l)"
echo "grammars: $(ls "$here/downloads/parsers-linux" | wc -l)"
