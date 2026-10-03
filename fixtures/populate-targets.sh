#!/usr/bin/env bash
# Populate fixtures/targets/ with the pinned fixture targets. Targets are cloned in, never committed
# (fixtures/targets/ is gitignored), the same way a real engagement target arrives.
#
#   fixtures/populate-targets.sh              populate every fixture below
#   fixtures/populate-targets.sh <name>...    populate only the named fixtures
#
# Idempotent: an existing clone is verified (origin URL, clean tree) and moved to the pinned commit.
# Fails closed: a wrong origin or local modifications are reported and left untouched, never reset.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/targets"

# name|origin|pinned commit (full SHA; bump deliberately when the fixture changes)
FIXTURES=(
    "hello-autotools|https://github.com/wsollers/hello-autotools.git|632522b6801caa5810f0c6bf71bf3783c90068ac"
    "appsec-multi-vuln|https://github.com/wsollers/appsec-multi-vuln.git|7a0ce333e098e1ffb7f23fa11c9fc2c032f6dac0"
    "freeciv21|https://github.com/longturn/freeciv21.git|0ce1c60acf1140d6c5c5a5cd6bef2507bd072319"
    "doom3-bfg|https://github.com/id-Software/DOOM-3-BFG.git|1caba1979589971b5ed44e315d9ead30b278d8b4"
)

populate() {
    local name="$1" url="$2" commit="$3" dest="$ROOT/$1"
    if [[ ! -e "$dest" ]]; then
        echo "$name: cloning $url" >&2
        git clone --quiet "$url" "$dest"
    elif [[ ! -d "$dest/.git" ]]; then
        echo "$name: $dest exists but is not a git clone; move it aside and re-run" >&2; return 1
    else
        local have; have="$(git -C "$dest" remote get-url origin)"
        if [[ "$have" != "$url" ]]; then
            echo "$name: origin is $have, expected $url; refusing to touch it" >&2; return 1
        fi
        if [[ -n "$(git -C "$dest" status --porcelain --untracked-files=all)" ]]; then
            echo "$name: local modifications in $dest; refusing to touch it (inspect, then clean or re-clone)" >&2
            return 1
        fi
        git -C "$dest" fetch --quiet origin
    fi
    git -C "$dest" -c advice.detachedHead=false checkout --quiet "$commit"
    local head; head="$(git -C "$dest" rev-parse HEAD)"
    [[ "$head" == "$commit" ]] || { echo "$name: HEAD is $head, expected $commit" >&2; return 1; }
    echo "$name: $dest at ${commit:0:7}"
}

mkdir -p "$ROOT"
status=0; matched=0
for entry in "${FIXTURES[@]}"; do
    IFS='|' read -r name url commit <<< "$entry"
    if [[ $# -gt 0 ]]; then
        wanted=0; for arg in "$@"; do [[ "$arg" == "$name" ]] && wanted=1; done
        [[ $wanted == 1 ]] || continue
    fi
    matched=$((matched + 1))
    populate "$name" "$url" "$commit" || status=1
done
[[ $# -eq 0 || $matched -eq $# ]] || { echo "unknown fixture name in: $*" >&2; status=1; }
exit $status
