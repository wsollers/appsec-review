#!/usr/bin/env bash
# scripts/compile-codeql-queries.sh - compile the CodeQL queries that need compiling into the shared
# compile cache review runs mount. Thin wrapper over `containers/build.py query-packs --warm`; see
# `--help` and docs/operations/codeql-analysis.md#compiling-codeql-queries.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/lib/common.sh"

usage() {
  cat <<'EOF'
usage: scripts/compile-codeql-queries.sh [--language LANG]... [--ram MB] [--threads N]
                                         [--dry-run] [--allow-concurrent] [PACK-ID ...]

Compile, one pack at a time, every CodeQL pack registered with `warm = true` in rules/registry.toml
(the repository-authored graph-export packs under rules/codeql-graph-export/<lang>/) into the
shared compile-cache volume review runs mount. The image's standard query packs and the licensed
CERT pack ship precompiled .qlx and are skipped on purpose. Already-cached queries are cache hits,
so a repeat run takes seconds per pack.

Run it after the CodeQL image/release changes or after any change to graph-export QL, before
starting review runs.

options:
  --language LANG     only these languages (repeatable or comma-separated: cpp,java,csharp,
                      javascript,python,ruby,go,rust)
  --ram MB            codeql query compile --ram (default 7000; ~3000 thrashes the GC)
  --threads N         codeql query compile --threads (default 8)
  --dry-run           print the packs and docker commands, compile nothing
  --allow-concurrent  start even if another CodeQL compile container is running (risks OOM)
  PACK-ID             only these registry pack ids (e.g. graph-export-go)
  -h, --help          this help

Exit codes: 0 compiled (or cache hit), 1 a pack failed, 2 usage error, 3 refused because another
compile is running. PowerShell twin: scripts/compile-codeql-queries.ps1 (runs this script in WSL).
EOF
}

for argument in "$@"; do
  case "$argument" in
    -h|--help) usage; exit 0 ;;
  esac
done

if ! python="$(ops_find_python)"; then
  echo "error: no Python 3.11+ found; create .venv or set APPSEC_PYTHON" >&2
  exit 1
fi
cd "$OPS_ROOT"
exec "$python" "$OPS_ROOT/containers/build.py" query-packs --warm "$@"
