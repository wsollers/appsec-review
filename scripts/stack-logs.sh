#!/usr/bin/env bash
# scripts/stack-logs.sh - see `scripts/stack-logs.sh --help` and docs/operations/operator-scripts.md.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/lib/common.sh"
ops_main stack-logs "$@"
