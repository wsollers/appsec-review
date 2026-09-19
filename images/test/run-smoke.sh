#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNNER="$ROOT/images/audit-buildenv-common/run.sh"
SCRATCH="$ROOT/scratch/buildenv-smoke"

"$RUNNER" audit-buildenv-cpp:local "$ROOT/images/test/cpp" "$SCRATCH/cpp" -- bash -lc \
  'cmake -S /workspace -B /scratch/build && cmake --build /scratch/build && /scratch/build/hello-cpp'

"$RUNNER" audit-buildenv-java:local "$ROOT/images/test/java" "$SCRATCH/java" -- bash -lc \
  'mkdir -p /scratch/classes && javac -d /scratch/classes $(find /workspace/src/main/java -name "*.java") && java -cp /scratch/classes com.example.Hello'

"$RUNNER" audit-buildenv-go:local "$ROOT/images/test/go" "$SCRATCH/go" -- bash -lc \
  'cd /workspace && go test ./... && go run .'

"$RUNNER" audit-buildenv-typescript:local "$ROOT/images/test/typescript" "$SCRATCH/typescript" -- bash -lc \
  'tsc -p /workspace --noEmit && node /workspace/src/hello.js'

"$RUNNER" audit-buildenv-php:local "$ROOT/images/test/php" "$SCRATCH/php" -- bash -lc \
  'php /workspace/hello.php'

"$RUNNER" audit-buildenv-dotnet:local "$ROOT/images/test/dotnet" "$SCRATCH/dotnet" -- bash -lc \
  'dotnet build /workspace/HelloDotnet.csproj -p:BaseIntermediateOutputPath=/scratch/obj/ -p:OutputPath=/scratch/out/ && dotnet /scratch/out/HelloDotnet.dll'

"$RUNNER" audit-buildenv-python:local "$ROOT/images/test/python" "$SCRATCH/python" -- bash -lc \
  'PYTHONPATH=/workspace python -m pytest -q -o cache_dir=/scratch/.pytest_cache /workspace'

"$RUNNER" audit-buildenv-rust:local "$ROOT/images/test/rust" "$SCRATCH/rust" -- bash -lc \
  'cd /workspace && cargo test --target-dir /scratch/target && cargo run --target-dir /scratch/target'
