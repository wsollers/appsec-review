#!/usr/bin/env bash
# Language-server, tree-sitter and CodeQL smoke for every compiler image (docs/language-servers.md §8).
# Each image runs scripts/smoke_lang_servers.sh inside the sealed buildenv boundary (no network,
# read-only repo at /workspace). Pass image ids to limit the set. The older initialize-only probe
# (lsp-smoke.py) is still used by Run-LspSmoke.ps1.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGES=("$@")
[ ${#IMAGES[@]} -gt 0 ] || IMAGES=(audit-buildenv-cpp audit-buildenv-cpp-resolute audit-buildenv-dotnet
  audit-buildenv-go audit-buildenv-java audit-buildenv-php audit-buildenv-python audit-buildenv-rust
  audit-buildenv-typescript audit-codeql audit-codeql-native)
failed=()
for image in "${IMAGES[@]}"; do
  "$ROOT/scripts/smoke_lang_servers.sh" --docker "$image" || failed+=("$image")
done
[ ${#failed[@]} -eq 0 ] && echo "all language tooling smokes passed" && exit 0
echo "FAILED: ${failed[*]}" >&2
exit 1
