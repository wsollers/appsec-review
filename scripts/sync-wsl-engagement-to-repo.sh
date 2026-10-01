#!/usr/bin/env bash
# Copy a WSL-run engagement back into this repo's ignored target/scratch layout.
#
# Intended use:
#   - run heavy Docker/native collection in WSL
#   - clone or mirror the reviewed source into <repo>/targets/<name>
#   - copy generated artifacts into <repo>/scratch/<name>-engagement
#   - optionally restage an appsec-review-process run manifest against repo-local paths
set -euo pipefail

PROJECT=""
TARGET_NAME=""
SOURCE_URL=""
SOURCE_REF=""
SOURCE_DIR=""
ENGAGEMENT_DIR=""
OUT_NAME=""
REPO_ROOT=""
RUN_ID=""
COMPILE_DB_REL="build/compile_commands.json"
BUSINESS_GOAL=""
PLATFORMS=("wsl" "docker")
NO_DELETE=0

usage() {
  cat <<'EOF'
Usage:
  scripts/sync-wsl-engagement-to-repo.sh --project NAME --engagement-dir PATH [options]

Required:
  --project NAME             Project label, e.g. eastl.
  --engagement-dir PATH      WSL/Linux engagement output to copy from.

Source options, choose at least one if targets/NAME does not already exist:
  --source-url URL           Git URL to clone into targets/NAME.
  --source-ref REF           Optional branch/tag/commit to checkout after clone/fetch.
  --source-dir PATH          Existing WSL/Linux source tree to copy into targets/NAME.
  --target-name NAME         Directory name under targets/. Defaults to --project.

Output options:
  --repo-root PATH           Appsec-review repo root. Defaults to git top-level or cwd.
  --out-name NAME            Directory name under scratch/. Defaults to NAME-engagement.
  --compile-db-rel PATH      Compile DB path relative to target. Default: build/compile_commands.json.
  --no-delete                Do not delete stale files in the destination scratch output.

Process manifest options:
  --run-id ID                Restage appsec-review-process inputs for this run id.
  --business-goal TEXT       Business goal written into the artifact manifest.
  --platform VALUE           Add a platform label. May be repeated. Defaults: wsl,docker.

Examples:
  scripts/sync-wsl-engagement-to-repo.sh \
    --project eastl \
    --source-url https://github.com/electronicarts/EASTL.git \
    --source-ref master \
    --engagement-dir ~/scratch/eastl-engagement \
    --run-id 20260917T022435Z-25d75d \
    --business-goal "Probe EASTL before the large game repo."

  scripts/sync-wsl-engagement-to-repo.sh \
    --project eastl \
    --source-dir ~/targets/eastl \
    --engagement-dir ~/scratch/eastl-engagement
EOF
}

die() {
  echo "error: $*" >&2
  exit 2
}

abs_path() {
  local p="$1"
  if [[ -e "$p" || -d "$(dirname "$p")" ]]; then
    realpath -m "$p"
  else
    python3 - "$p" <<'PY'
import os, sys
print(os.path.abspath(sys.argv[1]))
PY
  fi
}

is_under() {
  local child parent
  child="$(abs_path "$1")"
  parent="$(abs_path "$2")"
  [[ "$child" == "$parent" || "$child" == "$parent"/* ]]
}

copy_tree() {
  local src="$1" dst="$2" delete_arg=()
  [[ -d "$src" ]] || die "source directory does not exist: $src"
  mkdir -p "$dst"
  if [[ "$NO_DELETE" != 1 ]]; then
    delete_arg=(--delete)
  fi
  if command -v rsync >/dev/null 2>&1; then
    rsync -a "${delete_arg[@]}" "$src"/ "$dst"/
  else
    if [[ "$NO_DELETE" != 1 ]]; then
      find "$dst" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    fi
    cp -a "$src"/. "$dst"/
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="$2"; shift 2;;
    --target-name) TARGET_NAME="$2"; shift 2;;
    --source-url) SOURCE_URL="$2"; shift 2;;
    --source-ref) SOURCE_REF="$2"; shift 2;;
    --source-dir) SOURCE_DIR="$2"; shift 2;;
    --engagement-dir) ENGAGEMENT_DIR="$2"; shift 2;;
    --repo-root) REPO_ROOT="$2"; shift 2;;
    --out-name) OUT_NAME="$2"; shift 2;;
    --compile-db-rel) COMPILE_DB_REL="$2"; shift 2;;
    --run-id) RUN_ID="$2"; shift 2;;
    --business-goal) BUSINESS_GOAL="$2"; shift 2;;
    --platform) PLATFORMS+=("$2"); shift 2;;
    --no-delete) NO_DELETE=1; shift;;
    -h|--help) usage; exit 0;;
    *) die "unknown argument: $1";;
  esac
done

[[ -n "$PROJECT" ]] || die "--project is required"
[[ -n "$ENGAGEMENT_DIR" ]] || die "--engagement-dir is required"

if [[ -z "$REPO_ROOT" ]]; then
  REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
fi
REPO_ROOT="$(abs_path "$REPO_ROOT")"
[[ -d "$REPO_ROOT" ]] || die "repo root does not exist: $REPO_ROOT"
[[ -d "$REPO_ROOT/appsec-review-process" ]] || die "repo root does not look like appsec-review: $REPO_ROOT"

TARGET_NAME="${TARGET_NAME:-$PROJECT}"
OUT_NAME="${OUT_NAME:-$PROJECT-engagement}"
TARGET_ROOT="$REPO_ROOT/targets"
SCRATCH_ROOT="$REPO_ROOT/scratch"
TARGET_DIR="$TARGET_ROOT/$TARGET_NAME"
OUT_DIR="$SCRATCH_ROOT/$OUT_NAME"
ENGAGEMENT_DIR="$(abs_path "$ENGAGEMENT_DIR")"

mkdir -p "$TARGET_ROOT" "$SCRATCH_ROOT"
is_under "$TARGET_DIR" "$TARGET_ROOT" || die "target destination escaped targets/: $TARGET_DIR"
is_under "$OUT_DIR" "$SCRATCH_ROOT" || die "scratch destination escaped scratch/: $OUT_DIR"

if [[ ! -d "$TARGET_DIR" ]]; then
  if [[ -n "$SOURCE_URL" ]]; then
    git clone "$SOURCE_URL" "$TARGET_DIR"
  elif [[ -n "$SOURCE_DIR" ]]; then
    copy_tree "$(abs_path "$SOURCE_DIR")" "$TARGET_DIR"
  else
    die "$TARGET_DIR does not exist; pass --source-url or --source-dir"
  fi
elif [[ -n "$SOURCE_URL" ]]; then
  [[ -d "$TARGET_DIR/.git" ]] || die "$TARGET_DIR exists but is not a git checkout"
  git -C "$TARGET_DIR" fetch --tags --prune
fi

if [[ -n "$SOURCE_REF" ]]; then
  [[ -d "$TARGET_DIR/.git" ]] || die "--source-ref requires a git checkout at $TARGET_DIR"
  git -C "$TARGET_DIR" checkout "$SOURCE_REF"
fi

copy_tree "$ENGAGEMENT_DIR" "$OUT_DIR"

COMPILE_DB="$TARGET_DIR/$COMPILE_DB_REL"
if [[ ! -f "$COMPILE_DB" ]]; then
  echo "warning: compile database not found at $COMPILE_DB" >&2
fi

if [[ -n "$RUN_ID" ]]; then
  stage_args=(
    "$REPO_ROOT/appsec-review-process/stage_artifacts.py"
    --run-id "$RUN_ID"
    --project "$PROJECT"
    --target "$TARGET_DIR"
    --engagement-output "$OUT_DIR"
    --business-goal "$BUSINESS_GOAL"
  )
  if [[ -f "$COMPILE_DB" ]]; then
    stage_args+=(--compile-db "$COMPILE_DB")
  fi
  for platform in "${PLATFORMS[@]}"; do
    stage_args+=(--platform "$platform")
  done
  python3 "${stage_args[@]}"
fi

cat <<EOF
synced engagement artifacts
  target:     $TARGET_DIR
  artifacts:  $OUT_DIR
  compile DB: $COMPILE_DB
EOF
