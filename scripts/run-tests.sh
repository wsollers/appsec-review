#!/usr/bin/env bash
# scripts/run-tests.sh - see `scripts/run-tests.sh --help` and docs/operations/operator-scripts.md.
set -euo pipefail
# Only acceptance bypasses deployment selection; legacy suites keep their existing environment.
for argument in "$@"; do
    if [[ "$argument" == "--acceptance" || "$argument" == --acceptance=* ]]; then
        while IFS= read -r name; do unset "$name"; done < <(compgen -v APPSEC_NATIVE_)
        break
    fi
done
# shellcheck source=lib/common.sh
. "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/lib/common.sh"
ops_main run-tests "$@"
