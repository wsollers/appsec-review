---
title: "WebAssembly output-family build operations"
kind: "operations"
subsystem: "target acquisition and build"
status: "current"
jobs: ["job_cpp_compiled_analysis", "job_language_build", "job_project_build"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# WebAssembly output-family build operations

The WebAssembly lane in `job_language_build` consumes only the accepted, hash-verified
`job_project_build` dispatch and matching image-preparation identities. It does not require an
old successful probe for every prepared unit, discover a WebAssembly source
language or publish a separate handoff. Instead, centrally configured
producer rules select accepted Rust, native C/C++, Node/AssemblyScript, WAT, or other explicitly
enabled source-family recipes whose commands and outputs establish WebAssembly intent.

Selected units run serially in the global dependency-aware iteration controller, using its shared
target/install workspace and verified product interfaces. Network selection follows the source
family: native production selects `none`, other families `bridge`; the standalone adapter's
executor default is `bridge`. The root filesystem is read-only, not the run-owned build workspace.
See [the canonical language-build process](job_language_build.md#process). The executor may add diagnostic-only verbosity flags to accepted build
drivers (`cargo`, CMake, Make, or Ninja); it never adds target execution or tests and never
instantiates a produced module or component.

Receipts retain exact argv and sanitized environment values in protected run-owned files. Stdout,
stderr, and useful truncation tails are separate protected artifacts with SHA-256, retained and
observed byte counts, configured limits, timeout/exit status, duration, image identity, and attempt
identity. Retrieval and central logs receive only tool names, roles, hashes, dispositions, bounded
artifact facts, and explicit gaps. Verbose producer streams are parsed only for tool invocations
that actually appeared; missing nested compiler or linker provenance is a gap. A unit whose
accepted plan lists `native_components` (a `build.sh` or clang `--target=wasm32` producer) runs
every command under the standardized execution capture instead (`wasm.py`), and its receipt adds
`family = "wasm"`, `native_components`, a `native_compile_database` built from the observed
compiler execs, and capture-derived invocation rows; `job_cpp_compiled_analysis` then consumes
those compiles. Both the `rust` and `wasm` profiles run in `audit-buildenv-rust-wasm`, whose
C-to-wasm32 clang comes from the shared native toolchain. Produced WebAssembly modules are not
ELF/PE/Mach-O and are not inspected by the post-build hardening assessment.

The artifact catalog recognizes modules, components, WAT, source maps and debug metadata,
JavaScript/TypeScript bindings, WIT/WAI interface metadata, native side modules, libraries,
packages, intermediates, and generated sources. Workspace manifests and retained artifact hashes
are verified before checkpoint reuse. A changed target snapshot, recipe, dependency identity,
derived image, preparation identity, producer selection, toolchain, capture contract, limit,
upstream handoff or exact product interface invalidates the affected checkpoint and dependent
nodes. Shared-workspace execution uses controller product checkpoints rather than the adapter's
private-workspace cache.

Checkpoint lookup and publication also require operator-owned `platform`, `validation`,
`build_toolchain`, and `wasm_instrumentation` release IDs in `[review_policy.releases]`.
These are opaque declarations, not hashes of installed code, images, or supplied tools.
Missing declarations emit `missing_release_identity` and disable checkpoint reuse and caching;
execution does not fall back to fingerprinting platform payloads. Relevant release changes and
the frozen assurance policy participate in the checkpoint identity. Checkpoints are private to
the current run; they are not a cross-run import mechanism. Target outputs and execution evidence
retain their content hashes in both assurance modes.

Producer failures retain `FAILED` or `BLOCKED` receipts; siblings can continue when a prepared
receipt and confirmed cleanup permit rollback. A refusal before that boundary can stop the
controller, as tracked by [T-092](../TODO.md#t-092-decide-whether-a-refused-build-command-fails-one-unit-or-the-whole-language-build).
Path,
hash, configuration, accepted-handoff, manifest, and checkpoint-integrity failures stop publication.
`NOT_APPLICABLE` means no accepted recipe matched a configured WebAssembly producer; it is not a
clean-build claim.

The accepted language-build handoff composes its sanitized evidence into the shared `build`
retrieval shard. Operators can query module,
artifact, and tool-hash evidence through the normal retrieval/MCP interface; raw argv and streams
are never indexed or returned.
