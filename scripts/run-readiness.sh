#!/usr/bin/env bash
# scripts/run-readiness.sh - see `scripts/run-readiness.sh --help` and docs/operations/run-readiness.md.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/lib/common.sh"
ops_main run-readiness "$@"
