# Generic language-build operations

`job_language_build` consumes only the accepted, hash-verified `job_project_build` handoff. The
current execution implementation is the Linux native family; accepted Rust, Go, Java, Node,
.NET, Python, PHP, and WASM dispatches remain explicit gaps until equivalent executors are added.
Native CMake dispatches use the validated deterministic marker recipe; model-proposed package or
command drift cannot change that accepted execution contract.

For every native unit the job revalidates the target snapshot, successful probe identity, recipe,
dependency hashes, build-unit root, derived image identity, and dependency edges. It then copies
the bounded source root into `runs/<run-id>/data/build/native/units/<build-unit-id>/workspace/` and
executes the accepted configure/build argv without a shell. The pinned container has no network,
runs non-root with dropped capabilities and `no-new-privileges`, has a read-only root, and receives
central CPU, memory, PID, timeout, tmpfs, and output limits. Target binaries and tests are never run.

Receipts catalog generated sources, compile databases, objects, static/shared libraries,
executables, LLVM bitcode/IR, debug data, and link maps. Loader dependencies remain an explicit gap
until a pinned parser is available. Exact recipe and compiler/linker argv are retained only under
the unit's `protected-commands/` directory; searchable records retain argv hashes, sanitized
environment facts, resolved inputs/outputs, artifact hashes, and mapping confidence. A complete
workspace manifest protects the handoff consumed by later language-specific analysis.

Build-unit dependencies execute in topological layers. A failed dependency blocks its dependents,
but unrelated units continue in the configured worker pool. A checkpoint is reusable only when its
target snapshot, recipe, dependency hashes, image, executor/capture identity, toolchain, probe, and
upstream handoff are unchanged and every retained artifact still verifies.

Inspect `data/logs/pipeline.jsonl` for `LANGUAGE_BUILD_STARTED`, `BUILD_COMMAND_COMPLETED`,
`LANGUAGE_BUILD_COMPLETED`, and `LANGUAGE_BUILD_REUSED`. Events intentionally contain identities,
counts, dispositions, gap counts, and durations—not command text or environment values.

## Live acceptance

Dagster run `3f7cc512-6736-4e53-a067-c1d4e78d8fd9` (application run
`2026-10-08-0060`) completed all 232 orchestration steps successfully against
`targets/appsec-multi-vuln`. Its native CMake unit completed both accepted commands and retained 19
artifacts, protected command provenance, four link relationships, and the exact derived image
identity. The dynamic C++ consumer retained all seven logical branch indexes and all 31 physical
shards; post-build retained one build-security shard for the discovered native unit. Known missing
loader parsing, CodeQL/Joern assets, and non-native executors remain explicit gaps. The hash-bearing
record is `deploy/dagster/verification/wave1-live-acceptance.json`.
