#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNNER="$ROOT/images/audit-buildenv-common/run.sh"
PROBE="$ROOT/images/test/lsp-smoke.py"
SCRATCH="$ROOT/scratch/buildenv-lsp-smoke"

"$RUNNER" audit-buildenv-cpp:local "$ROOT/images/test" "$SCRATCH/cpp" -- bash -lc \
  'python3 /workspace/lsp-smoke.py --name clangd --root /workspace/cpp -- clangd'

"$RUNNER" audit-buildenv-java:local "$ROOT/images/test" "$SCRATCH/java" -- bash -lc \
  'JAVA_TOOL_OPTIONS=-Duser.home=/tmp/home python3 /workspace/lsp-smoke.py --name jdtls --root /workspace/java --timeout 60 -- jdtls -data /scratch/jdtls-workspace'

"$RUNNER" audit-buildenv-go:local "$ROOT/images/test" "$SCRATCH/go" -- bash -lc \
  'python3 /workspace/lsp-smoke.py --name gopls --root /workspace/go -- gopls serve'

"$RUNNER" audit-buildenv-typescript:local "$ROOT/images/test" "$SCRATCH/typescript" -- bash -lc \
  'python3 /workspace/lsp-smoke.py --name typescript-language-server --root /workspace/typescript --initialization-options-json '"'"'{"tsserver":{"path":"/usr/local/lib/node_modules/vscode-langservers-extracted/node_modules/typescript/lib/tsserver.js"}}'"'"' -- typescript-language-server --stdio'

"$RUNNER" audit-buildenv-typescript:local "$ROOT/images/test" "$SCRATCH/typescript-json" -- bash -lc \
  'python3 /workspace/lsp-smoke.py --name vscode-json-language-server --root /workspace/typescript -- vscode-json-language-server --stdio'

"$RUNNER" audit-buildenv-php:local "$ROOT/images/test" "$SCRATCH/php" -- bash -lc \
  'python3 /workspace/lsp-smoke.py --name phpactor --root /workspace/php -- phpactor language-server'

"$RUNNER" audit-buildenv-dotnet:local "$ROOT/images/test" "$SCRATCH/dotnet" -- bash -lc \
  'python3 /workspace/lsp-smoke.py --name csharp-ls --root /workspace/dotnet -- csharp-ls'

"$RUNNER" audit-buildenv-python:local "$ROOT/images/test" "$SCRATCH/python-pylsp" -- bash -lc \
  'python /workspace/lsp-smoke.py --name pylsp --root /workspace/python -- pylsp'

"$RUNNER" audit-buildenv-python:local "$ROOT/images/test" "$SCRATCH/python-basedpyright" -- bash -lc \
  'python /workspace/lsp-smoke.py --name basedpyright --root /workspace/python -- basedpyright-langserver --stdio'

"$RUNNER" audit-buildenv-rust:local "$ROOT/images/test" "$SCRATCH/rust" -- bash -lc \
  'python3 /workspace/lsp-smoke.py --name rust-analyzer --root /workspace/rust -- rust-analyzer'
