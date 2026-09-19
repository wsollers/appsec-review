[CmdletBinding()]
param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).ProviderPath
)

$ErrorActionPreference = "Stop"
$runner = Join-Path $Root "images/audit-buildenv-common/run.ps1"
$scratch = Join-Path $Root "scratch/buildenv-smoke"

& $runner audit-buildenv-cpp:local (Join-Path $Root "images/test/cpp") (Join-Path $scratch "cpp") -- bash -lc 'cmake -S /workspace -B /scratch/build && cmake --build /scratch/build && /scratch/build/hello-cpp'
& $runner audit-buildenv-java:local (Join-Path $Root "images/test/java") (Join-Path $scratch "java") -- bash -lc 'mkdir -p /scratch/classes && javac -d /scratch/classes $(find /workspace/src/main/java -name "*.java") && java -cp /scratch/classes com.example.Hello'
& $runner audit-buildenv-go:local (Join-Path $Root "images/test/go") (Join-Path $scratch "go") -- bash -lc 'cd /workspace && go test ./... && go run .'
& $runner audit-buildenv-typescript:local (Join-Path $Root "images/test/typescript") (Join-Path $scratch "typescript") -- bash -lc 'tsc -p /workspace --noEmit && node /workspace/src/hello.js'
& $runner audit-buildenv-php:local (Join-Path $Root "images/test/php") (Join-Path $scratch "php") -- bash -lc 'php /workspace/hello.php'
& $runner audit-buildenv-dotnet:local (Join-Path $Root "images/test/dotnet") (Join-Path $scratch "dotnet") -- bash -lc 'dotnet build /workspace/HelloDotnet.csproj -p:BaseIntermediateOutputPath=/scratch/obj/ -p:OutputPath=/scratch/out/ && dotnet /scratch/out/HelloDotnet.dll'
& $runner audit-buildenv-python:local (Join-Path $Root "images/test/python") (Join-Path $scratch "python") -- bash -lc 'PYTHONPATH=/workspace python -m pytest -q -o cache_dir=/scratch/.pytest_cache /workspace'
& $runner audit-buildenv-rust:local (Join-Path $Root "images/test/rust") (Join-Path $scratch "rust") -- bash -lc 'cd /workspace && cargo test --target-dir /scratch/target && cargo run --target-dir /scratch/target'
