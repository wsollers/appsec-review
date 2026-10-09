# WebAssembly output-family build operations

The WebAssembly lane in `job_language_build` consumes only the accepted, hash-verified
`job_project_build` dispatch and probe receipts. It does not discover a WebAssembly source
language or publish a separate handoff. Instead, centrally configured
producer rules select accepted Rust, native C/C++, Node/AssemblyScript, WAT, or other explicitly
enabled source-family recipes whose commands and outputs establish WebAssembly intent.

Each selected unit runs in dependency order through the same pinned, non-root, dependency-egress,
read-only container boundary used by project-build probing. Independent ready units share the
configured worker pool. The executor may add diagnostic-only verbosity flags to accepted build
drivers (`cargo`, CMake, Make, or Ninja); it never adds target execution or tests and never
instantiates a produced module or component.

Receipts retain exact argv and sanitized environment values in protected run-owned files. Stdout,
stderr, and useful truncation tails are separate protected artifacts with SHA-256, retained and
observed byte counts, configured limits, timeout/exit status, duration, image identity, and attempt
identity. Retrieval and central logs receive only tool names, roles, hashes, dispositions, bounded
artifact facts, and explicit gaps. Verbose producer streams are parsed only for tool invocations
that actually appeared; missing nested compiler or linker provenance is a gap.

The artifact catalog recognizes modules, components, WAT, source maps and debug metadata,
JavaScript/TypeScript bindings, WIT/WAI interface metadata, native side modules, libraries,
packages, intermediates, and generated sources. Workspace manifests and retained artifact hashes
are verified before checkpoint reuse. A changed target snapshot, recipe, dependency identity,
derived image, probe, producer selection, toolchain, capture contract, limit, upstream handoff, or
upstream build fingerprint invalidates only the affected checkpoint.

Producer failures publish `FAILED` or `BLOCKED` receipts and preserve successful siblings. Path,
hash, configuration, accepted-handoff, manifest, and checkpoint-integrity failures stop publication.
`NOT_APPLICABLE` means no accepted recipe matched a configured WebAssembly producer; it is not a
clean-build claim.

The accepted language-build handoff composes its sanitized evidence into the shared `build`
retrieval shard. Operators can query module,
artifact, and tool-hash evidence through the normal retrieval/MCP interface; raw argv and streams
are never indexed or returned.
