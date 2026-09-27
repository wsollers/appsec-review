#!/usr/bin/env bash
# Render the report inside images/audit-report (pinned TeX Live, adapted from lra-governance).
#   bash pipeline/report/render-in-docker.sh [examples/hello-autotools.review.json]
#   SOURCE_ROOT=../hello-autotools bash pipeline/report/render-in-docker.sh   # snippets from a checkout
#   ENGINE=lualatex SKIP_BUILD=1 bash pipeline/report/render-in-docker.sh      # pdf (default) | lualatex | xelatex
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
image="${IMAGE:-audit-report:local}"
data="${1:-examples/hello-autotools.review.json}"
engine="${ENGINE:-pdf}"

if [ -z "${SKIP_BUILD:-}" ]; then
  docker build -t "$image" "$repo/images/audit-report"
fi
mkdir -p "$here/build"

run=(docker run --rm --network none --read-only --tmpfs /tmp:rw,exec,size=512m
     --cap-drop ALL --security-opt no-new-privileges
     -u "$(id -u):$(id -g)"
     -v "$here:/report:ro" -v "$here/build:/out" -w /out)
extra=()
if [ -n "${SOURCE_ROOT:-}" ]; then
  run+=(-v "$(cd "$SOURCE_ROOT" && pwd):/source:ro")
  extra+=(--source-root /source)
fi

"${run[@]}" "$image" python3 -B /report/render.py "/report/$data" --out /out --pdf --engine "$engine" "${extra[@]}"
echo "PDF: $here/build/report.pdf"
