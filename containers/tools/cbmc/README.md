---
title: "Reusable CBMC tooling image"
kind: "operations"
subsystem: "images and deployment"
status: "current"
jobs: []
last reconciled: "ea03df9695991eafe37065717624278af845a74c"
---
# Reusable CBMC tooling image

`appsec-review/tool-cbmc:6.11.0` packages the upstream CBMC 6.11.0 Ubuntu 24.04
**linux/amd64** release. It needs no application-security pipeline, credentials, services,
or repository checkout at runtime. Mount another project's sources and harnesses read-only
and put GOTO binaries, traces and other generated files in a separate writable directory.

The catalog entry is enabled for review hosts; its static scanner adapter remains disabled
because [`job_cbmc_analysis`](../../../docs/operations/job_cbmc_analysis.md) owns bounded execution.
Ordinary image provisioning and image-pin checks include it. Standalone use remains independent
of that job. Neither path adds finding promotion, solver-based dismissal, or Lean proof authority. The separate
[formal-verification decision](../../../docs/formal-verification/design-review-2026-11-07.md)
is unchanged: bounded results and solver witnesses are conditional on the harness,
assumptions, selected properties, model and unwind bounds, not unconditional proofs about
the original program. CBMC consumes C/C++ or its own GOTO representation, not arbitrary
ELF/PE machine code or debug symbols.

## Contents

- The complete upstream Debian package, including `cbmc`, `goto-cc`, `goto-gcc`,
  `goto-instrument`, `goto-analyzer`, `goto-diff`, `goto-harness` and `symtab2gb`.
- CBMC's bundled MiniSAT backend; no separate solver installation or network service is needed.
- GCC/G++ 13.3, C/C++ headers, binutils, Make 4.3, CMake 3.28, Ninja 1.11,
  pkg-config and Python 3.12, with their complete Debian dependency closure.

The upstream package also contains JBMC executables, but this image does not install a JDK
or claim Java validation. Optional external SMT solvers and `cbmc-viewer` are not installed.
The C++ frontend does not support every modern C++ feature or library; unsupported input
is a coverage gap, not verification success.
In the pinned release, aggregate initialization of a struct with a member function
(`Counter counter = {2};`) triggered `struct member must not be of code type` in
`goto-cc`. The C++ smoke uses an explicit constructor instead. This is an observed upstream
frontend limitation, not a reason to change a project's source or suppress an engine failure.

## Build

From the repository root on Linux/WSL, with Python 3.11+ and Docker:

```bash
python3 containers/build.py --validate-only
python3 containers/build.py build tool-cbmc
```

Only this image is selected; it does not rebuild the shared native toolchain or Dagster.
The builder fetches the official release and licenses, verifies exact size and SHA-256,
and runs [`acquire_assets.sh`](acquire_assets.sh) if the dependency cache is absent.
Acquisition uses signed Ubuntu snapshot `20261015T070000Z` in the digest-pinned base.
Its 85-package closure is recorded in [`packages.manifest`](packages.manifest) and
[`assets.lock.json`](assets.lock.json). Nothing is installed into the host OS.
The Docker build installs exclusively from these verified local inputs with networking disabled.
Acquisition and base-image resolution can use the network.

For a direct Docker build, first populate and verify the cache through the same builder:

```bash
python3 containers/build.py fetch tool-cbmc
docker build --platform linux/amd64 --network none --pull=false \
  --provenance=false --sbom=false \
  --build-arg TOOL_VERSION=6.11.0 \
  -t appsec-review/tool-cbmc:6.11.0 containers/tools/cbmc
```

The resulting image can be loaded/tagged for other projects without this repository.
Publishing it is a separate operator action. Record the resulting host image ID or registry
digest when reproducibly identifying a run; a recipe tag alone is not an immutable binding.

## Use with another project

Run this from the other project's root, replacing `harness.c` with its intended harness:

```bash
mkdir -p cbmc-output
status=0
docker run --rm --init --network none --read-only \
  --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
  --cpus 2 --memory 1g --pids-limit 256 \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m \
  --mount "type=bind,src=$PWD,dst=/workspace,readonly" \
  --mount "type=bind,src=$PWD/cbmc-output,dst=/scratch" \
  appsec-review/tool-cbmc:6.11.0 \
  timeout --signal=TERM --kill-after=5s 600s \
  cbmc /workspace/harness.c --unwind 16 --unwinding-assertions \
    --bounds-check --pointer-check --signed-overflow-check --trace --json-ui \
  > cbmc-output/result.json || status=$?
printf 'CBMC/container exit status: %s\n' "$status"
```

The image has no entrypoint and defaults to `cbmc --help`. Substitute a command such as
`goto-cc /workspace/harness.c -o /scratch/harness.goto`, then run CBMC over that GOTO
binary with the same mounts. Invoke `goto-instrument` directly for transformations.
For a trusted multi-file build, use a writable scratch copy or out-of-source build and
`goto-gcc`/`goto-cc`; do not run untrusted project build scripts on the host. Project-specific
headers, build dependencies and assumptions remain the caller's responsibility.

CBMC exit **0** means the selected properties succeeded under the supplied model and bounds;
**10** means verification failed (inspect the individual properties and traces).
Unwinding failures also need interpretation: they do not by themselves prove a program bug.
Other exit codes, timeout **124**, killed/OOM processes and malformed or incomplete JSON are
errors or inconclusive coverage, never a clean result. Preserve the command, inputs,
image identity, JSON terminal status and individual property results together.
The direct example bounds time and container resources; a caller capturing large traces must
also bound its output storage. `tool.toml` declares the repository executor's output budget,
but Docker does not enforce that metadata for a standalone invocation.

## Explicit image checks

These manual container checks are separate from unit tests and do not run a target review:

```bash
python3 containers/build.py smoke --functional tool-cbmc
python3 containers/build.py security tool-cbmc
```

The functional fixture checks a safe bounded C harness, its failing twin with a nonempty
counterexample trace, and C/C++ preprocessing, GOTO compilation and instrumentation.
It validates exit codes, structured terminal/property statuses and trace presence, not just
version strings. Fixtures and the checker are mounted, never baked into the tooling image.
Outputs stay under the builder's `runs/container-builds/` directory.

## Updating and licensing

Select an exact upstream release and architecture; update the release/license entries in
`assets.lock.json`, the version in `Dockerfile`, `tool.toml` and `catalog.toml`. Reacquire the
dependency closure, record its observed size/SHA-256 and generated `packages.manifest`, then
build and explicitly check the image. Never relock different bytes merely to silence a failure.

CBMC uses BSD-4-Clause and MiniSAT uses MIT. Their unmodified license notices are installed
under `/usr/share/doc/cbmc/`; Ubuntu dependencies retain `/usr/share/doc/*/copyright`.
Redistribution must satisfy each included component's terms, including the CBMC acknowledgement:

> This product includes software developed by Daniel Kroening, Edmund Clarke,
> Computer Science Department, University of Oxford,
> Computer Science Department, Carnegie Mellon University.
