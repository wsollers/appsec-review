# Produced-artifact security analysis

`job_artifact_security_analysis` consumes the accepted `job_language_build` publication and the
accepted, hash-verified `job_artifact_indexing` handoff derived from it. The two handoffs must bind
the same language-build identity and target snapshot. It never walks the target tree to find
outputs. Every analyzed object must have an accepted run-relative path, SHA-256, byte count, build
unit, and producer identity. A changed path, file, handoff, or index manifest is a framework-integrity
failure and stops publication.

The job classifies files from bounded magic bytes plus accepted producer metadata. A filename or
extension is never sufficient. Supported families include ELF and native objects/libraries,
PE/COFF and managed assemblies, JVM class and archive outputs, Node/Python/PHP packages and
generated bundles, WebAssembly modules, and bounded archives. Archive inspection reads directory
metadata without extracting or executing members. Traversal, absolute paths, links, excessive
member count or size, expansion ratios, corrupt containers, and unsupported formats become precise
coverage gaps.

## Units, recovery, and invalidation

Dagster exposes independent inventory, native, JVM, package, WebAssembly, SpotBugs, BLint, Syft,
Grype, and OSV capability units. Below that graph, each artifact/capability pair has a content-addressed shard
fingerprinted by:

- accepted artifact hash and detected format;
- producer/build identity and accepted language-build handoff;
- scanner, image, rules, parser, normalizer, and schema identities;
- the required upstream build-index manifest; and
- analysis limits from central configuration.

An interrupted attempt can reuse only shards whose fingerprints and raw artifact hashes still
match. Changing one artifact or scanner identity invalidates its dependent shards without forcing
unrelated siblings to rerun. Scanner failure is isolated to that artifact/capability pair; successful
siblings remain publishable with the failure represented as a gap. Upstream identity changes are not
recoverable scanner failures and stop the job.

Use `appsec-review plan-resume --run-id <id> --target <path>` before a consequential resume. Do not
delete locks, edit pointers, or modify accepted files to force reuse.

## Evidence and retrieval

For every attempted scan, stdout and stderr are retained under the immutable application attempt
with SHA-256, source byte count, capture limit, truncation state, optional tail identity, exit status,
timeout, duration, artifact identity, tool/image/rule identity, and attempt identity. Retrieval stores
only bounded sanitized observation records. The accepted observations manifest verifies both the new
SQLite shard and the upstream build-index manifest, so every indexed observation resolves back to
exact run-owned raw artifacts.

Built-in parsers provide bounded inventory and structural metadata. Tool-dependent coverage is
explicit: unavailable BLint, Syft, Grype, OSV, native-symbol/hardening, JVM bytecode, or full WASM
policy tooling is recorded as a gap, never as a clean result. Tool output is evidence only and is not
an adjudicated finding.

For live acceptance, follow `deploy/dagster/README.md`, build the pinned scanner images, start a fresh
Dagster run against an applicable target, and retain its new verification receipt. Historical,
canceled, partial, fake-executor, or stale runs do not establish acceptance.
