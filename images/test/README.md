# Build Environment Smoke Tests

This directory contains tiny no-dependency projects for smoke-testing the language build/LSP/MCP
images and the binary-analysis image.

Build the images first:

```bash
scripts/build-language-buildenv-images.sh
```

Run all smoke tests from the repo root:

```bash
images/test/run-smoke.sh
```

Or run individual smoke tests:

```bash
images/audit-buildenv-common/run.sh audit-buildenv-cpp:local images/test/cpp scratch/buildenv-smoke/cpp -- bash -lc 'cmake -S /workspace -B /scratch/build && cmake --build /scratch/build && /scratch/build/hello-cpp'
images/audit-buildenv-common/run.sh audit-buildenv-java:local images/test/java scratch/buildenv-smoke/java -- bash -lc 'mkdir -p /scratch/classes && javac -d /scratch/classes $(find /workspace/src/main/java -name "*.java") && java -cp /scratch/classes com.example.Hello'
images/audit-buildenv-common/run.sh audit-buildenv-go:local images/test/go scratch/buildenv-smoke/go -- bash -lc 'cd /workspace && go test ./... && go run .'
images/audit-buildenv-common/run.sh audit-buildenv-typescript:local images/test/typescript scratch/buildenv-smoke/typescript -- bash -lc 'tsc -p /workspace --noEmit && node /workspace/src/hello.js'
images/audit-buildenv-common/run.sh audit-buildenv-php:local images/test/php scratch/buildenv-smoke/php -- bash -lc 'php /workspace/hello.php'
images/audit-buildenv-common/run.sh audit-buildenv-dotnet:local images/test/dotnet scratch/buildenv-smoke/dotnet -- bash -lc 'dotnet build /workspace/HelloDotnet.csproj -p:BaseIntermediateOutputPath=/scratch/obj/ -p:OutputPath=/scratch/out/ && dotnet /scratch/out/HelloDotnet.dll'
images/audit-buildenv-common/run.sh audit-buildenv-python:local images/test/python scratch/buildenv-smoke/python -- bash -lc 'PYTHONPATH=/workspace python -m pytest -q -o cache_dir=/scratch/.pytest_cache /workspace'
images/audit-buildenv-common/run.sh audit-buildenv-rust:local images/test/rust scratch/buildenv-smoke/rust -- bash -lc 'cd /workspace && cargo test --target-dir /scratch/target && cargo run --target-dir /scratch/target'
```

Run LSP initialization smoke tests from the repo root:

```bash
images/test/run-lsp-smoke.sh
```

Run the binary-analysis smoke test from the repo root:

```bash
images/test/run-binary-smoke.sh
```

The binary smoke test compiles a tiny debug-enabled C program and checks the expanded binary worker
surface, including Ghidra, RetDec, angr imports, cwe_checker/check_cwe, FLOSS, DIE, Syft, Grype,
Trivy, ssdeep/TLSH, QEMU user emulation, apktool, JADX, ILSpy, and Frida command availability.

PowerShell all-in-one:

```powershell
.\images\test\Run-Smoke.ps1
```

PowerShell LSP smoke:

```powershell
.\images\test\Run-LspSmoke.ps1
```

PowerShell binary-analysis smoke:

```powershell
.\images\test\Run-BinarySmoke.ps1
```

PowerShell individual example:

```powershell
.\images\audit-buildenv-common\run.ps1 audit-buildenv-python:local images\test\python scratch\buildenv-smoke\python -- bash -lc 'PYTHONPATH=/workspace python -m pytest -q -o cache_dir=/scratch/.pytest_cache /workspace'
```

These fixtures avoid dependency restore. Keep them small and deterministic.
