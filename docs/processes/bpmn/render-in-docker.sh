#!/usr/bin/env bash
# Render BPMN files to SVG + PNG inside images/docs-render (bpmn-js + headless Chromium), so the host
# needs only Docker. render.cjs and the models are mounted read-only; output goes to the out directory.
#   bash docs/processes/bpmn/render-in-docker.sh                      # every job card -> cards/render/
#   bash docs/processes/bpmn/render-in-docker.sh pre-submission.bpmn render-new
#   SKIP_BUILD=1 bash docs/processes/bpmn/render-in-docker.sh         # reuse docs-render:local
# Paths are relative to docs/processes/bpmn.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
image="${IMAGE:-docs-render:local}"

if [ -z "${SKIP_BUILD:-}" ]; then
  docker build -t "$image" "$repo/images/docs-render"
fi

if [ $# -eq 0 ]; then
  models=(cards/*.bpmn); out="cards/render"
else
  models=("$1"); out="${2:-render-new}"
fi
mkdir -p "$here/$out"

for model in "${models[@]}"; do
  docker run --rm --network none --read-only --tmpfs /tmp:rw,exec,size=512m --shm-size 256m \
    --cap-drop ALL --security-opt no-new-privileges -u "$(id -u):$(id -g)" \
    -v "$here:/bpmn:ro" -v "$here/$out:/out" -w /bpmn \
    "$image" node /bpmn/render.cjs "/bpmn/$model" /out
done
echo "rendered ${#models[@]} model(s) to $here/$out"
