#!/bin/sh
# tool-report-latex entry point: render one LaTeX report to a reproducible PDF.
#
# Contract (the standard runtime boundary of containers/runtime-policy.toml applies):
#   /template  read-only  the report class (appsec-report.cls) and any files it loads
#   /input     read-only  report.tex and the files it \input's; optional source-date-epoch
#   /scratch   writable   build directory; report.pdf, report.pdfinfo.txt, report.txt and
#                         report.log are left here for the caller to copy out
#
# The PDF is reproducible: SOURCE_DATE_EPOCH and FORCE_SOURCE_DATE pin the creation date and the
# document id, there is no shell escape and no network. Usage:
#   render-pdf [--version] [INPUT_DIR [TEMPLATE_DIR]]
set -eu
# Files left in a bind-mounted scratch directory must stay removable by the host user.
umask 000

if [ "${1:-}" = "--version" ]; then
    echo "tool-report-latex ${TOOL_VERSION:-unknown} $(xelatex --version | head -n 1)"
    exit 0
fi

input="${1:-/input}"
template="${2:-/template}"
out="${SCRATCH_DIR:-/scratch}"
[ -f "$input/report.tex" ] || { echo "render-pdf: $input/report.tex is missing" >&2; exit 2; }
[ -f "$template/appsec-report.cls" ] || { echo "render-pdf: $template/appsec-report.cls is missing" >&2; exit 2; }

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    if [ -f "$input/source-date-epoch" ]; then
        SOURCE_DATE_EPOCH="$(tr -cd '0-9' < "$input/source-date-epoch")"
    fi
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
fi
export SOURCE_DATE_EPOCH FORCE_SOURCE_DATE=1
export TEXINPUTS="$template//:$input//:"
# Caches go to the /tmp tmpfs so nothing but the build and its outputs is left in a bind-mounted scratch.
export XDG_CACHE_HOME="${TMPDIR:-/tmp}/cache" TEXMFVAR="${TMPDIR:-/tmp}/texmf-var" TEXMFCONFIG="${TMPDIR:-/tmp}/texmf-config" TEXMFHOME="${TMPDIR:-/tmp}/texmf"
export SOURCE_DATE_EPOCH

work="$out/build"
mkdir -p "$work" "$XDG_CACHE_HOME" "$TEXMFVAR" "$TEXMFCONFIG"
cp -R "$input/." "$work/"
cd "$work"

pass=1
while [ "$pass" -le 3 ]; do
    if ! xelatex -interaction=nonstopmode -halt-on-error -file-line-error -no-shell-escape \
            -output-directory "$work" report.tex > "$work/pass-$pass.log" 2>&1; then
        tail -n 60 "$work/pass-$pass.log" >&2
        cp "$work/pass-$pass.log" "$out/report.log" 2>/dev/null || true
        echo "render-pdf: xelatex failed on pass $pass" >&2
        exit 1
    fi
    cp "$work/report.log" "$out/report.log"
    # Stop once cross references and the page count are stable.
    if ! grep -q "Rerun to get\|Label(s) may have changed" "$work/report.log"; then
        break
    fi
    pass=$((pass + 1))
done

cp "$work/report.pdf" "$out/report.pdf"
pdfinfo "$out/report.pdf" > "$out/report.pdfinfo.txt"
pdftotext -layout "$out/report.pdf" "$out/report.txt"
cat "$out/report.pdfinfo.txt"
grep -c "Overfull" "$out/report.log" | sed 's/^/overfull-boxes: /' || true
echo "render-pdf: wrote $out/report.pdf after $pass pass(es)"
