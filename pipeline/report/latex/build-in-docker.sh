#!/usr/bin/env bash
# Compile the LaTeX document templates in images/audit-report.
#   bash pipeline/report/latex/build-in-docker.sh                 # all *.tex here -> pipeline/report/build/latex/
#   bash pipeline/report/latex/build-in-docker.sh design-doc.tex  # one document
#   ENGINE=lualatex SKIP_BUILD=1 bash pipeline/report/latex/build-in-docker.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd -P)"
repo="$(cd "$here/../../.." && pwd -P)"
image="${IMAGE:-audit-report:local}"
engine="${ENGINE:-pdf}"
out="$here/../build/latex"

if [ -z "${SKIP_BUILD:-}" ]; then
  docker build -t "$image" "$repo/images/audit-report"
fi
mkdir -p "$out"
docs=("$@"); [ ${#docs[@]} -eq 0 ] && docs=($(cd "$here" && ls *.tex))

for d in "${docs[@]}"; do
  docker run --rm --network none --read-only --tmpfs /tmp:rw,exec,size=512m \
    --cap-drop ALL --security-opt no-new-privileges -u "$(id -u):$(id -g)" \
    -v "$here:/src:ro" -v "$out:/out" -w /out -e TEXINPUTS=/src//: \
    "$image" latexmk "-$engine" -interaction=nonstopmode -halt-on-error -quiet -outdir=/out "/src/$d"
  echo "PDF: $out/${d%.tex}.pdf"
done
