#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/lib/common.sh"
python="$(ops_find_python)" || { echo "error: Python 3.11+ is required" >&2; exit 1; }
exec "$python" "$OPS_ROOT/scripts/generate-docs.py" "$@"
