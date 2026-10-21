#!/usr/bin/env bash
# Render the report of a finished review run to PDF or to a single-page HTML file.
#
#   scripts/render-report.sh --run <run-id|run-dir> [--format pdf|html] [options]
#
# html  runs only the Python renderer (stdlib, no Docker).
# pdf   renders report.tex with the Python renderer, then compiles it in the tool-report-latex image
#       under the standard runtime boundary (no network, read-only root, all capabilities dropped,
#       non-root, template and input mounted read-only, one writable scratch directory).
#
# Works from any current directory. The run directory is only read. Exit status: 0 success,
# 1 render failure, 2 usage error or a missing prerequisite (Python, Docker, the image).
set -euo pipefail

readonly DEFAULT_IMAGE="appsec-review/tool-report-latex:1.0.0"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$script_dir/.." && pwd)"

usage() {
  cat <<EOF
Usage: scripts/render-report.sh --run <run-id|run-dir> [options]

Render the report of a review run to PDF or single-page HTML.

Required:
  --run <id|dir>         run id (looked up in --runs-dir) or a run directory

Options:
  --format pdf|html      output format (default: pdf)
  --runs-dir <dir>       directory holding run directories (default: <repo>/runs)
  --output-dir <dir>     where <run-id>.pdf / <run-id>.html is written
                         (default: <repo>/runs/reports, which git ignores)
  --limit <n>            render only the first n packages (a bounded sample)
  --package <id>         render only packages whose id starts with or contains <id> (repeatable)
  --max-cells <n>        interchanges drawn per package (default: 6)
  --image <tag>          report image for pdf (default: $DEFAULT_IMAGE)
  --keep-work            keep the staging directory (report.tex, build log) next to the output
  -h, --help             show this help

Environment:
  APPSEC_PYTHON          Python 3.11+ interpreter to use (default: <repo>/.venv, then python3)
  APPSEC_DOCKER_BIN      Docker-compatible client (default: docker)

Examples:
  scripts/render-report.sh --run 2026-10-21-0007 --format html
  scripts/render-report.sh --run 2026-10-21-0007 --format pdf --limit 3 --output-dir /tmp/reports

The pdf format needs the image: containers/build-all.sh build tool-report-latex
EOF
}

die() { echo "render-report: $*" >&2; exit "${2:-2}"; }

run="" format="pdf" runs_dir="$repo/runs" output_dir="" limit="" max_cells="" image="$DEFAULT_IMAGE" keep_work=0
packages=()

need_value() { [[ $# -ge 2 && -n "${2:-}" ]] || die "option $1 needs a value"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --run|--format|--runs-dir|--output-dir|--limit|--package|--max-cells|--image)
      need_value "$@"
      case "$1" in
        --run) run="$2" ;;
        --format) format="$2" ;;
        --runs-dir) runs_dir="$2" ;;
        --output-dir) output_dir="$2" ;;
        --limit) limit="$2" ;;
        --package) packages+=("$2") ;;
        --max-cells) max_cells="$2" ;;
        --image) image="$2" ;;
      esac
      shift 2 ;;
    --run=*|--format=*|--runs-dir=*|--output-dir=*|--limit=*|--package=*|--max-cells=*|--image=*)
      set -- "${1%%=*}" "${1#*=}" "${@:2}" ;;
    --keep-work) keep_work=1; shift ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

[[ -n "$run" ]] || { usage >&2; die "--run is required"; }
case "$format" in pdf|html) ;; *) die "--format must be pdf or html, not '$format'" ;; esac
[[ -z "$limit" || "$limit" =~ ^[1-9][0-9]*$ ]] || die "--limit must be a positive integer"
[[ -z "$max_cells" || "$max_cells" =~ ^[1-9][0-9]*$ ]] || die "--max-cells must be a positive integer"
[[ -n "$output_dir" ]] || output_dir="$repo/runs/reports"

# -- Python -----------------------------------------------------------------------------------------
python_bin="${APPSEC_PYTHON:-}"
if [[ -z "$python_bin" ]]; then
  for candidate in "$repo/.venv/bin/python" "$repo/.venv/Scripts/python.exe" python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then python_bin="$candidate"; break; fi
  done
fi
[[ -n "$python_bin" ]] || die "no Python interpreter found; set APPSEC_PYTHON"
export PYTHONPATH="$repo/src${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

# -- Run directory ----------------------------------------------------------------------------------
if [[ -d "$run/data" ]]; then
  run_dir="$(cd "$run" && pwd)"
elif [[ -d "$runs_dir/$run/data" ]]; then
  run_dir="$(cd "$runs_dir/$run" && pwd)"
else
  die "run '$run' not found: neither '$run/data' nor '$runs_dir/$run/data' is a directory"
fi
run_id="$(basename "$run_dir")"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

render_args=(--run "$run_dir")
[[ -z "$limit" ]] || render_args+=(--limit "$limit")
[[ -z "$max_cells" ]] || render_args+=(--max-cells "$max_cells")
for package in ${packages[@]+"${packages[@]}"}; do render_args+=(--package "$package"); done

# -- HTML -------------------------------------------------------------------------------------------
if [[ "$format" == html ]]; then
  stage="$(mktemp -d "$output_dir/.render-$run_id.XXXXXX")"
  trap 'rm -rf -- "$stage"' EXIT
  "$python_bin" -m appsec_review.reporting render "${render_args[@]}" --format html --out "$stage" >/dev/null \
    || die "the HTML renderer failed" 1
  mv -f -- "$stage/report.html" "$output_dir/$run_id.html"
  echo "$output_dir/$run_id.html"
  exit 0
fi

# -- PDF --------------------------------------------------------------------------------------------
docker_bin="${APPSEC_DOCKER_BIN:-docker}"
command -v "$docker_bin" >/dev/null 2>&1 || die "Docker is required for --format pdf but '$docker_bin' was not found. Install Docker, or use --format html"
if ! "$docker_bin" image inspect "$image" >/dev/null 2>&1; then
  die "the report image '$image' is not available locally (or the Docker daemon is not running). Build it with: containers/build-all.sh build tool-report-latex"
fi
template_dir="$repo/containers/report/latex/template"
[[ -f "$template_dir/appsec-report.cls" ]] || die "template not found at $template_dir"

stage="$(mktemp -d "$output_dir/.render-$run_id.XXXXXX")"
container="appsec-report-$$"
cleanup() {
  "$docker_bin" rm -f "$container" >/dev/null 2>&1 || true
  if [[ "$keep_work" -eq 0 ]]; then rm -rf -- "$stage"; else echo "render-report: kept $stage" >&2; fi
}
trap cleanup EXIT
mkdir -p "$stage/input" "$stage/scratch"
chmod 0777 "$stage/scratch"

"$python_bin" -m appsec_review.reporting render "${render_args[@]}" --format tex --out "$stage/input" >/dev/null \
  || die "the LaTeX renderer failed" 1

host_path() {  # Docker Desktop on Windows needs Windows-style paths from Git Bash / MSYS.
  if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}
mounts=(--mount "type=bind,src=$(host_path "$template_dir"),dst=/template,readonly"
        --mount "type=bind,src=$(host_path "$stage/input"),dst=/input,readonly"
        --mount "type=bind,src=$(host_path "$stage/scratch"),dst=/scratch")
for path in "$template_dir" "$stage"; do
  [[ "$path" != *,* ]] || die "a path containing a comma cannot be bind-mounted: $path"
done

limit_cmd=()
if command -v timeout >/dev/null 2>&1; then limit_cmd=(timeout 600); fi
set +e
MSYS_NO_PATHCONV=1 ${limit_cmd[@]+"${limit_cmd[@]}"} "$docker_bin" run --rm --name "$container" \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --user 10001:10001 --pids-limit 256 --memory 1g --cpus 2 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=128m \
  "${mounts[@]}" "$image" /opt/tool/bin/render-pdf > "$stage/render.out" 2> "$stage/render.err"
status=$?
set -e
if [[ $status -ne 0 || ! -f "$stage/scratch/report.pdf" ]]; then
  echo "render-report: PDF rendering failed (exit $status)" >&2
  tail -n 40 "$stage/render.err" >&2 || true
  [[ -f "$stage/scratch/report.log" ]] && { echo "--- last lines of the TeX log ---" >&2; tail -n 40 "$stage/scratch/report.log" >&2; }
  keep_work=1
  exit 1
fi
cp -f -- "$stage/scratch/report.pdf" "$output_dir/$run_id.pdf"
echo "$output_dir/$run_id.pdf"
