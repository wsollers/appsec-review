[CmdletBinding()]
param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).ProviderPath
)

$ErrorActionPreference = "Stop"
$runner = Join-Path $Root "images/audit-buildenv-common/run.ps1"
$scratch = Join-Path $Root "scratch/buildenv-lsp-smoke"

$testRoot = Join-Path $Root "images/test"
& $runner audit-buildenv-cpp:local $testRoot (Join-Path $scratch "cpp") -- bash -lc 'python3 /workspace/lsp-smoke.py --name clangd --root /workspace/cpp -- clangd'
& $runner audit-buildenv-java:local $testRoot (Join-Path $scratch "java") -- bash -lc 'JAVA_TOOL_OPTIONS=-Duser.home=/tmp/home python3 /workspace/lsp-smoke.py --name jdtls --root /workspace/java --timeout 60 -- jdtls -data /scratch/jdtls-workspace'
& $runner audit-buildenv-go:local $testRoot (Join-Path $scratch "go") -- bash -lc 'python3 /workspace/lsp-smoke.py --name gopls --root /workspace/go -- gopls serve'
& $runner audit-buildenv-typescript:local $testRoot (Join-Path $scratch "typescript") -- bash -lc 'python3 /workspace/lsp-smoke.py --name typescript-language-server --root /workspace/typescript --initialization-options-json ''{"tsserver":{"path":"/usr/local/lib/node_modules/vscode-langservers-extracted/node_modules/typescript/lib/tsserver.js"}}'' -- typescript-language-server --stdio'
& $runner audit-buildenv-typescript:local $testRoot (Join-Path $scratch "typescript-json") -- bash -lc 'python3 /workspace/lsp-smoke.py --name vscode-json-language-server --root /workspace/typescript -- vscode-json-language-server --stdio'
& $runner audit-buildenv-php:local $testRoot (Join-Path $scratch "php") -- bash -lc 'python3 /workspace/lsp-smoke.py --name phpactor --root /workspace/php -- phpactor language-server'
& $runner audit-buildenv-dotnet:local $testRoot (Join-Path $scratch "dotnet") -- bash -lc 'python3 /workspace/lsp-smoke.py --name csharp-ls --root /workspace/dotnet -- csharp-ls'
& $runner audit-buildenv-python:local $testRoot (Join-Path $scratch "python-pylsp") -- bash -lc 'python /workspace/lsp-smoke.py --name pylsp --root /workspace/python -- pylsp'
& $runner audit-buildenv-python:local $testRoot (Join-Path $scratch "python-basedpyright") -- bash -lc 'python /workspace/lsp-smoke.py --name basedpyright --root /workspace/python -- basedpyright-langserver --stdio'
& $runner audit-buildenv-rust:local $testRoot (Join-Path $scratch "rust") -- bash -lc 'python3 /workspace/lsp-smoke.py --name rust-analyzer --root /workspace/rust -- rust-analyzer'
