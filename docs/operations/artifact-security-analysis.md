# Produced-artifact security analysis

`job_artifact_security_analysis` consumes the accepted `job_language_build` publication and the
accepted, hash-verified `job_artifact_indexing` handoff derived from it. The two handoffs must bind
the same language-build identity and target snapshot. It never walks the target tree to find
outputs. Every analyzed object must have an accepted run-relative path, SHA-256, byte count and
producer identity. Build outputs additionally bind a build unit; prebuilt target artifacts instead
bind their target-intake catalog handoff and exact target-relative path, without claiming a build
occurred. Unknown delivery status remains a coverage gap, not exclusion from conservative analysis.
A changed path, file, handoff, or index manifest is a framework-integrity
failure and stops publication.

Prebuilt objects retain content-addressed storage, but scanner invocation mounts only the selected
object read-only under its original basename in an otherwise empty target directory. This preserves
filename-sensitive tool behavior without copying payloads or mounting the whole shared object store.

The job classifies files from bounded magic bytes plus accepted producer metadata. A filename or
extension never classifies executable, object, or archive content. Supported families include ELF
and native objects/libraries, PE/COFF and managed assemblies, JVM class and archive outputs,
Node/Python/PHP packages and generated bundles, WebAssembly modules, and bounded archives. Media and
asset files are classified into family `media-asset` with a category-prefixed format (`image-png`,
`audio-ogg`, `font-truetype`, `model-fbx`, `texture-dds`, ...) from the typed declarations in
`appsec_review.media_assets`: by content first, and by suffix only when the bytes matched no other
format and the suffix names a media format and nothing else. Ambiguous suffixes (`.obj`, `.mod`,
`.ts`, `.pak`, `.bin`, ...) are never a fallback; a Wavefront `.obj` is recognized only from its
geometry directives, so an ELF or COFF `.obj` stays a native object. Archive inspection reads directory
metadata without extracting or executing members. Traversal, absolute paths, links, excessive
member count or size, expansion ratios, corrupt containers, and unsupported formats become precise
coverage gaps.

Pinned scanners run only on the inputs `appsec_review.tool_inputs` declares for them: BLint on
ELF, PE/.NET, COFF, Mach-O, and Android packages; SpotBugs on JVM classes and on archives that
contain `.class` members; osv-scanner on lockfiles and manifests it extracts offline (by file name,
`OSV_LOCKFILE_ECOSYSTEMS`); Syft and Grype on any produced artifact except media and asset files
(images, audio, video, fonts, 3D models, textures, game data), in which a package cataloger finds
nothing. That exclusion is a denylist of positively recognized formats rather than an allowlist,
because Syft also catalogs by file name and embedded content that classify as `unknown`. An artifact
outside a scanner's support is never launched and is counted per capability in
`not_applicable_inputs` as `SKIPPED_NA`, not as a gap; its row in that capability's
`scope_dispositions` also carries `format`, `input_disposition: SKIPPED_NA`,
`input_reason_code: INPUT_FORMAT_UNSUPPORTED`, and `input_reason`. A skipped artifact is never
evidence that it is clean. Classification reads bounded member names: a jar holding only
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
package metadata such as `PKG-INFO` or `composer.json` when handed the file. Only the lockfile's own
ecosystem from the verified OSV snapshot is bind-mounted read-only at
`/database/osv-scanner/<ecosystem>/all.zip`, because offline mode loads every mounted database
whole, and the container runs under `jobs.job_artifact_security_analysis.settings.osv_memory`
(default `3g`) instead of the uniform 1g scanner limit (npm's database alone is 368 MB of JSON). A
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
only bounded sanitized observation records. The accepted observations manifest verifies the new
SQLite shard and the upstream artifact-index manifest, and retains the upstream index entries alongside
its observations. Standalone retrieval therefore keeps the artifact inventory, including distinct
target paths with identical bytes, available after security analysis. Observations resolve back to
exact run-owned raw artifacts without inventing source-line locations for binary inputs.

The [interchange upgrade](../architecture/job-interchange.md) adds common observation metadata
and native-result references to this scanner lane. The integration keeps
`appsec-review/artifact-security-record/2` and the existing observation `/1` schema, with additive
common/provenance metadata; finding normalization moves to `/2`, artifact parsers to `/3`, and
artifact normalization to `/2` for retained parser-input semantics. Keep original scanner result
identity, parser, retained byte count/hash, selector, and
completeness alongside domain-specific artifact/package fields. A synthesized BLint report or
partitioned result must not replace the original report/invocation provenance. Duplicate
observation-to-native-result references remain visible even when the file bytes are stored once.
Only safe metadata enters indexes; retained scanner bodies remain protected run artifacts.
Missing provenance or bounded/truncated capture is a named gap, not a clean artifact verdict.

Parser-input retention is separate from diagnostic head/tail capture. The integrating typed setting
`jobs.job_artifact_security_analysis.settings.parser_input_limit_bytes` defaults to 67,108,864
bytes and must be positive. Retain the full native input within that bound so the parser and result
selector refer to the same bytes; `stream_limit_bytes` bounds diagnostic streams instead.
Exceeding the parser-input bound requires explicit partial coverage/truncation rather than parsing
an unrecorded complete report while citing a truncated diagnostic copy.

Built-in parsers provide bounded inventory and structural metadata. Tool-dependent coverage is
explicit: unavailable BLint, Syft, Grype, OSV, native-symbol/hardening, JVM bytecode, or full WASM
policy tooling is recorded as a gap, never as a clean result. Tool output is evidence only and is not
an adjudicated finding.

For live acceptance, follow `deploy/dagster/README.md`, build the pinned scanner images, start a fresh
Dagster run against an applicable target, and retain its new verification receipt. Historical,
canceled, partial, fake-executor, or stale runs do not establish acceptance.
