#!/usr/bin/env bash
# scripts/stack-rebuild.sh - see `scripts/stack-rebuild.sh --help` and docs/operations/operator-scripts.md.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/lib/common.sh"
ops_main stack-rebuild "$@"
