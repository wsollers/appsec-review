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

Pinned scanners run only on the inputs `appsec_review.tool_inputs` declares for them: BLint on
ELF, PE/.NET, COFF, Mach-O, and Android packages; SpotBugs on JVM classes and on archives that
contain `.class` members; osv-scanner on lockfiles and manifests it extracts offline (by file name,
`OSV_LOCKFILE_ECOSYSTEMS`); Syft and Grype on any produced artifact. An artifact outside a
scanner's support is never launched and is counted per capability in `not_applicable_inputs` as
`SKIPPED_NA`, not as a gap. Classification reads bounded member names: a jar holding only
`classes.dex` is `dex-archive` and a jar with no `.class` member is `jvm-resource-archive`, so
neither reaches SpotBugs (which would exit 1 with "No files to analyze could be opened"). Unix `ar`
archives (`.a` static libraries, Rust `.rlib`) are `ar-archive`: their members are listed from GNU,
BSD, and thin headers without extraction instead of being reported as corrupt.

BLint 3.4.0 has no JSON stdout: with `--reports /scratch` it writes `findings.json` (only when there
are findings), `reviews.json`, and one `<name>-metadata.json` per binary it analyzed.
`appsec_review.blint_report` assembles those into `blint-report.json`; a supported binary with no
metadata report is a gap ("blint produced no per-binary analysis report"), never a clean result.

osv-scanner 1.9.2 is invoked as `scan --experimental-offline --lockfile /target/<name>`: it selects
an extractor by file name and has no extractor for jars, wheels, Go/Rust binaries, objects, or
package metadata such as `PKG-INFO` or `composer.json` when handed the file. Every ecosystem in the
verified OSV snapshot is bind-mounted read-only at `/database/osv-scanner/<ecosystem>/all.zip`. A
lockfile whose ecosystem the snapshot lacks is not launched and records the gap "offline OSV
snapshot lacks ecosystem <X>"; the same text replaces osv-scanner's exit-127 "could not find local
databases" report. Its exit-128 "No package sources found" report (an empty lockfile) is accepted as
`SKIPPED_NA`; any other non-zero exit is a gap carrying the last bounded stderr line, as are
timeouts and truncation.

## Units, recovery, and invalidation

Dagster exposes independent inventory, native, JVM, package, WebAssembly, SpotBugs, BLint, Syft,
Grype, and OSV capability units. Below that graph, each artifact/capability pair has a content-addressed shard
fingerprinted by:

- accepted artifact hash and detected format;
- producer/build identity and accepted language-build handoff;
- scanner, image, rules, parser, normalizer, and schema identities;
- the required upstream build-index manifest; and
- analysis limits from central configuration.

The repository default sets `[tools].disable_grype = true`. In that state the Grype unit does not
resolve an image, database, or runner and publishes `NOT_APPLICABLE` with a
`CONFIGURED_DISABLED` coverage gap. Set the typed Boolean to `false` to restore the ordinary
hash-verified scanner contract; this does not affect successful sibling evidence.

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
