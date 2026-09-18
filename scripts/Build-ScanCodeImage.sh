#!/usr/bin/env bash
# Build-ScanCodeImage.sh — bash twin of Build-ScanCodeImage.ps1.
#
# One-time (or standalone) build of a local scancode-toolkit:local Docker
# image, used by the "scancode" step in Invoke-VendorAuditPrePass.sh /
# Invoke-VendorAuditPrePass.ps1. Build-AuditImages.ps1 / build-audit-images.sh
# now build this automatically as part of their normal "scancode" step (added
# 2026-09-18) -- use this script instead only if you want to (re)build just
# this one image without running the full image-build pass.
#
# There is no published ghcr.io/aboutcode-org/scancode-toolkit image to pull
# (confirmed directly: an anonymous `docker manifest inspect` against that
# path returns "denied", and ScanCode Toolkit's own docs -- Install ScanCode
# using docker -- say explicitly to clone the repo and `docker build` it
# yourself). This script does exactly that.
#
# Usage:
#   scripts/Build-ScanCodeImage.sh [--tag TAG] [--clone-dir DIR]
#
# Options:
#   --tag TAG         Local image tag to build. Must match the Image value the
#                      "scancode" step in Invoke-VendorAuditPrePass.sh/.ps1
#                      references. Default: scancode-toolkit:local.
#   --clone-dir DIR    Where to clone the scancode-toolkit source. Reused as-is
#                       on later runs (delete it to re-clone fresh). Default:
#                       a scancode-toolkit-src subfolder next to this script.
#   -h, --help          Show this help.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAG="scancode-toolkit:local"
CLONE_DIR="$SCRIPT_DIR/scancode-toolkit-src"

usage() { sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="$2"; shift 2;;
    --clone-dir) CLONE_DIR="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "unknown option: $1" >&2; usage; exit 2;;
  esac
done

if ! command -v git >/dev/null 2>&1; then
  echo "git is required to clone the ScanCode Toolkit source - install it and retry." >&2
  exit 1
fi

if [[ ! -d "$CLONE_DIR" ]]; then
  echo "Cloning aboutcode-org/scancode-toolkit into $CLONE_DIR ..."
  git clone --depth 1 "https://github.com/aboutcode-org/scancode-toolkit.git" "$CLONE_DIR"
else
  echo "$CLONE_DIR already exists - using it as-is (delete it first to re-clone fresh)."
fi

echo "Building $TAG from ScanCode Toolkit's own Dockerfile ..."
echo "This is a separate, fairly heavy multi-stage build (its own Python env, native deps) - expect several minutes."

docker build --progress=plain --tag "$TAG" "$CLONE_DIR"

echo "Built $TAG"
echo "Sanity check:"
docker run --rm "$TAG" --help | head -5
echo ""
echo "The scancode step in Invoke-VendorAuditPrePass.sh/.ps1 will now find this image by name."
