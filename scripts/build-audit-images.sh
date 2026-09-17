#!/usr/bin/env bash
# build-audit-images.sh — build every pinned appsec-review Docker image from one
# entrypoint. Bash twin of Build-AuditImages.ps1; run this one from WSL/Linux
# for the performance reasons documented in the repo README (WSL ext4, not
# /mnt/c or /mnt/f). Typical WSL checkout: ~/projects/appsec-review.
#
# Builds, in order:
#   audit-static     vendor-audit-toolbox:latest   (repo-root context; COPYs scripts/)
#   audit-native     audit-native:local             (self-contained; slow — SVF build)
#   audit-codeql     audit-codeql:local             (needs a pre-downloaded CodeQL bundle;
#                                                     auto-downloaded unless --skip-codeql)
#   audit-iac        audit-iac:local                (self-contained)
#   audit-container  audit-container:local          (repo-root context; COPYs scripts/run-dockerfile-lint.sh)
#   audit-report     audit-report:local             (self-contained)
#
# scancode-toolkit:local is deliberately NOT built here — it has its own
# dedicated build path (scripts/Build-ScanCodeImage.ps1) because there is no
# publishable upstream image to pull; see that script and images/audit-static's
# Dockerfile header for why.
#
# Usage:
#   scripts/build-audit-images.sh [options]
#
# Options:
#   --only NAMES         Comma-separated subset of: static,native,codeql,iac,container,report
#                         Default: all of them.
#   --no-cache            Pass --no-cache to every docker build.
#   --skip-codeql          Skip audit-codeql entirely (no bundle download, no build).
#   --codeql-bundle-version V   CodeQL bundle release tag to download if missing.
#                                Default: codeql-bundle-v2.27.0 (matches images/audit-codeql/README.md).
#   --static-tag TAG       Tag for audit-static. Default: vendor-audit-toolbox:latest
#                           (the default $IMAGE_TAG every orchestrator script expects).
#   -h, --help             Show this help.
#
# Examples:
#   scripts/build-audit-images.sh
#   scripts/build-audit-images.sh --only iac,container --no-cache
#   scripts/build-audit-images.sh --skip-codeql

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ONLY="static,native,codeql,iac,container,report"
NO_CACHE=0
SKIP_CODEQL=0
CODEQL_BUNDLE_VERSION="codeql-bundle-v2.27.0"
STATIC_TAG="vendor-audit-toolbox:latest"

usage() {
  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --only) ONLY="$2"; shift 2;;
    --no-cache) NO_CACHE=1; shift;;
    --skip-codeql) SKIP_CODEQL=1; shift;;
    --codeql-bundle-version) CODEQL_BUNDLE_VERSION="$2"; shift 2;;
    --static-tag) STATIC_TAG="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "unknown option: $1" >&2; usage; exit 2;;
  esac
done

IFS=',' read -r -a SELECTED <<< "$ONLY"
want() {
  local name="$1"
  for s in "${SELECTED[@]}"; do [[ "$s" == "$name" ]] && return 0; done
  return 1
}

NOCACHE_ARGS=()
[[ "$NO_CACHE" == 1 ]] && NOCACHE_ARGS=(--no-cache)

echo "Repo root: $REPO_ROOT"
docker info >/dev/null || { echo "docker is not available/running" >&2; exit 1; }

# Preflight: audit-static and audit-container both COPY from repo-root scripts/;
# fail loudly here rather than letting docker build fail with an opaque
# "file not found" partway through a long build.
preflight_scripts() {
  local missing=0
  for f in \
    scripts/build_symbol_index.py scripts/md_to_sarif.py scripts/build_semantic_index.py \
    scripts/query_semantic_index.py scripts/scrub_evidence.py scripts/php_parse_coverage.py \
    scripts/run-sast-php.sh scripts/run-semantic-index-batched.sh scripts/run-dockerfile-lint.sh
  do
    if [[ ! -f "$REPO_ROOT/$f" ]]; then
      echo "MISSING: $f (expected by images/audit-static or images/audit-container COPY)" >&2
      missing=1
    fi
  done
  [[ "$missing" == 0 ]] || exit 1
}
preflight_scripts

RESULTS=()
build_one() {
  local name="$1" tag="$2" dockerfile="$3" context="$4"
  echo ""
  echo "=== Building $name -> $tag ==="
  local start
  start=$(date +%s)
  if docker build --progress=plain "${NOCACHE_ARGS[@]}" -t "$tag" -f "$dockerfile" "$context"; then
    local dur=$(( $(date +%s) - start ))
    RESULTS+=("OK   $name -> $tag (${dur}s)")
  else
    local dur=$(( $(date +%s) - start ))
    RESULTS+=("FAIL $name -> $tag (${dur}s)")
    echo "Build failed: $name. If a tool install step failed, that tool's version pin most" >&2
    echo "likely drifted (an unpinned go/pip/curl install pulling something new) — see the" >&2
    echo "Dockerfile's own version-pinning header." >&2
    return 1
  fi
}

FAILED=0

if want static; then
  build_one "audit-static" "$STATIC_TAG" "$REPO_ROOT/images/audit-static/Dockerfile" "$REPO_ROOT" || FAILED=1
fi

if want native; then
  echo ""
  echo "audit-native build includes an SVF build from source — expect several minutes."
  build_one "audit-native" "audit-native:local" "$REPO_ROOT/images/audit-native/Dockerfile" "$REPO_ROOT/images/audit-native" || FAILED=1
fi

if want codeql; then
  if [[ "$SKIP_CODEQL" == 1 ]]; then
    echo ""
    echo "=== Skipping audit-codeql (--skip-codeql) ==="
    RESULTS+=("SKIP audit-codeql (--skip-codeql)")
  else
    BUNDLE="$REPO_ROOT/images/audit-codeql/codeql-bundle-linux64.tar.zst"
    if [[ ! -f "$BUNDLE" ]]; then
      echo ""
      echo "=== Downloading CodeQL bundle ($CODEQL_BUNDLE_VERSION) — audit-codeql needs this before build ==="
      curl -L -C - -o "$BUNDLE" \
        "https://github.com/github/codeql-action/releases/download/${CODEQL_BUNDLE_VERSION}/codeql-bundle-linux64.tar.zst"
    fi
    build_one "audit-codeql" "audit-codeql:local" "$REPO_ROOT/images/audit-codeql/Dockerfile" "$REPO_ROOT/images/audit-codeql" || FAILED=1
  fi
fi

if want iac; then
  build_one "audit-iac" "audit-iac:local" "$REPO_ROOT/images/audit-iac/Dockerfile" "$REPO_ROOT/images/audit-iac" || FAILED=1
fi

if want container; then
  build_one "audit-container" "audit-container:local" "$REPO_ROOT/images/audit-container/Dockerfile" "$REPO_ROOT" || FAILED=1
fi

if want report; then
  build_one "audit-report" "audit-report:local" "$REPO_ROOT/images/audit-report/Dockerfile" "$REPO_ROOT/images/audit-report" || FAILED=1
fi

echo ""
echo "=== Summary ==="
for r in "${RESULTS[@]}"; do echo "$r"; done

exit "$FAILED"
