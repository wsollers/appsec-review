# Produced-artifact indexing

`job_artifact_indexing` is the repository-independent boundary between accepted language builds and
artifact consumers. It reads the accepted, hash-verified `job_language_build` handoff, its
workspace manifests and declared outputs, plus the accepted `job_target_catalog` target-artifact
intake. It never discovers authority by scanning the target tree.

Bounded NUL-containing target files are retained separately from the text inventory as
`appsec-review/target-artifact-intake/1` records. They share the inventory's file/byte bounds,
retain their target-relative paths and run-owned byte references, and have `target-intake` origin,
unknown delivery status and an explicit delivery-status gap. A separate `catalog-target-intake`
shard publishes them without a build-unit identity, image, invented build command or successful
build receipt. Empty language-build receipts do not remove these target inputs. Missing or legacy
target intake remains a named coverage gap. Supplied-looking paths inside the customer target are
not exclusions; platform roles or references outside the accepted object store are rejected before
payload verification.

The job publishes immutable `artifacts` SQLite/FTS shards in three independently fingerprinted
groups:

- catalog shards per build unit and canonical artifact family (`catalog-<build_unit_id>-<family>`),
  plus the `catalog-target-intake` shard;
- archive-member shards per build unit, in bounded batches (`members-<build_unit_id>-<NNNN>`); and
- relationship shards per build unit, in bounded batches (`relations-<build_unit_id>-<NNNN>`).

### Build-unit batch shards

The accepted language-build receipt is the reuse and invalidation unit for the member and
relationship indexes. Each step sorts the unit's artifacts it indexes (package artifacts for
members, every validated artifact for relationships) by `(workspace_path, sha256)` and packs
them into deterministic batches. A batch closes before it would exceed `MAX_ARTIFACTS_PER_SHARD`
(5,000 artifacts) or `MAX_ROWS_PER_SHARD` (100,000 relations plus entities). An artifact that alone
exceeds the row bound gets its own shard. `<NNNN>` is the zero-based, four-digit batch number
within the unit (`0000` first). A shard ID outside `[A-Za-z0-9_.-]{1,128}` is an integrity
failure. Earlier releases published one member shard per package artifact and one relationship
shard per artifact; the `members-` and `relations-` prefixes are unchanged.

Per-artifact and per-invocation detail stays in rows, not shards: relations, one coverage row per
artifact keyed by its `workspace_path`, and that artifact's gaps. A shard's `IndexIdentity` gaps
are the union of its artifacts' gaps. Its producer mapping records `job`, `unit`, `family`,
`build_unit_id`, `batch` and `batch_count`.

Member and relationship fingerprints bind the shard layout `build-unit-batch/1` and both batch
limits, besides the receipt, the batch's artifacts and their upstream manifests. Older
per-artifact shards therefore never satisfy a new fingerprint: the first run after an upgrade
rebuilds these two groups once. Catalog shards keep their previous layout and fingerprints.

The accepted composite manifest retains the previously accepted physical indexes and replaces the
prior `artifacts` shard set atomically. Catalog fingerprints contain no scanner, retrieval transport,
or MCP identity. A scanner change therefore invalidates only its observation shards, and an MCP
change invalidates no physical shard.

## Recovery and integrity

Restart the same application run normally. A completed shard whose deterministic path, SQLite
integrity, metadata, and hash still verify is reused; this includes every completed batch shard of
a partially indexed build unit. A stale or corrupt shard is an integrity failure and stops
publication; it is never silently overwritten. Changing one artifact changes its family catalog
shard and the member and relationship batch shards of its build unit without invalidating
unrelated build units or artifact families.

An unavailable, failed, empty, truncated, or ambiguously mapped producer remains an explicit
coverage gap. Raw artifact bytes, protected command arguments, and stdout/stderr never enter the
SQLite/FTS payloads. The accepted summary and composite manifest are run-owned artifacts bound to
the accepted job handoff.

Every shard uses the common `IndexBuilder` durability contract described in
[review-data indexing](review-data-indexing.md#index-shard-durability): a step returns a shard
identity only after the shard is durable, hashed, linked into the shared object store and
registered for custody.

## Throughput

Shard count, `fsync` count and hash count scale with build units and batches, not with artifact
count. The relationship step indexes a receipt's tool invocations by output path once, so
attributing one artifact no longer scans every invocation of its unit. Fewer shards also make the
`acceptance.publish_handoff` manifest verification cheaper, and they make retrieval cheaper,
because retrieval opens every shard listed in the accepted manifest.

The motivating evidence is Dagster run `4824e750-9c47-4c28-bd64-aaeeee3652b0`. It spent 45.2
minutes in `index.relationships`, writing 8,225 per-artifact shards (3.78 GB of writes) for less
than 1 MB of target source.

Known limitation: an artifact that no invocation or producer-supplied relationship uniquely
attributes still receives a 0.25-confidence `GENERATED_FROM` edge to every command of its unit.
That is O(outputs × commands) rows for weakly attributed units; batching bounds the rows per
shard, not the total. Reducing these edges is a pending follow-up.

### Deferred: parallel build units

Build units and their batches are indexed sequentially. A future bounded worker pool across build
units must run each task under `contextvars.copy_context().run(...)`, as
`storage.shared.PublicationThreadPoolExecutor` does. The attempt owner, the validation scope and
operation spans are `ContextVar` values: in a bare thread the owner is absent, so
`IndexBuilder.build()` would skip custody registration and lose work telemetry without failing.
Such a pool may index different completed receipts in parallel, never the batches of one receipt,
and must sort results by `(build_unit_id, family, batch)` before publication, so handoffs stay
deterministic.

## Node retention policy

The Node language build publishes a deliberately small review set. A successful build always
retains each in-workspace `package.json` and the selected npm, pnpm, or Yarn resolution metadata
(`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, or Yarn Plug'n'Play
loader metadata). These files are retained even when unchanged because they define package entry
points, dependency intent, exact resolutions, and integrity values. npm documents that a normal
lockfile represents the dependency tree without requiring `node_modules`. Its hidden
`node_modules/.package-lock.json` instead records what an install actually wrote. When a recipe's
own install leaves one in the workspace, it is retained as `resolved-dependency-metadata` with role
`installed-dependency-record`, and it is the only basis for summarizing that installed tree (see
below). See the [Node package contract](https://nodejs.org/api/packages.html),
[npm lockfile format](https://docs.npmjs.com/cli/v7/configuring-npm/package-lock-json/),
[pnpm lockfile configuration](https://pnpm.io/settings#lockfile), and
[Yarn install model](https://yarnpkg.com/cli/install).

The produced-file set is:

- emitted `.js`, `.cjs`, and `.mjs` code (and other emitted Node build code already recognized by
  the language build), bundles, and bundle assets;
- ECMA-426 source maps, with bounded declared-source identities when the referenced source remains
  inside the immutable workspace;
- compiled `.node` addons and separately emitted native symbols (`.pdb`, `.debug`, `.dwo`, `.dwp`,
  `.sym`, and `.node.map`) only when a same-build `.node` companion binds their identity;
- generated `.d.ts`, `.d.mts`, and `.d.cts` declarations, because declarations define the API shape
  that TypeScript consumers resolve even though they contain no implementation;
- produced `.tgz`/`.zip` package archives and adjacent integrity sidecars whose basename identifies
  a retained archive; and
- only the well-known coverage and execution-profile exchange files owned by the dedicated
  coverage/profile ingestion contracts.

This selection follows Node's treatment of `.js`/`.cjs`/`.mjs`, package manifests, and loadable
`.node` addons; [Node's source-map API](https://nodejs.org/api/module.html#source-map-support) and
the [ECMA-426 format](https://ecma-international.org/publications-and-standards/standards/ecma-426/);
the [Node addon contract](https://nodejs.org/api/addons.html); and TypeScript's documented
[declaration-to-runtime correspondence](https://www.typescriptlang.org/docs/handbook/modules/theory.html#the-role-of-declaration-files).
Package archives are retained because `npm pack` creates the publishable tarball
([npm pack](https://docs.npmjs.com/cli/v7/commands/npm-pack/)); bounded `npm pack --json` integrity
and shasum fields, plus adjacent checksums, bind separately produced integrity evidence to that
exact retained archive without retaining raw command output. Separate native debug data is useful
only with its binary identity; GDB documents the debug-link/build-ID relationship in
[Separate Debug Files](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html).

The collector walks the whole workspace without following symlinks, and directory names establish
no scope. It enters a `node_modules` tree that a recipe's own install wrote. Files of a recognized
kind there are kept even when unchanged, unless npm's installer record covers them or a named
`[build_outputs]` exclusion removes them; the shipped `node-bundler-cache` rule removes
`node_modules/.cache` and `node_modules/.vite`. Each verified
installed package becomes one supply-chain `package-metadata` row that carries its file and byte
counts. Its native addons, shared libraries, native symbols and package archives keep their own
rows, and the rest of the package is summarized in one `dependency-content-summarized` gap per
record. Files that the record does not cover stay per-file with named gaps. The full contract,
bounds and gap texts are in [installed npm dependencies](language-build.md). Apart from those
dependency rows, the collector does not retain object files, generic native libraries, logs,
arbitrary checksum files, unchanged source modules, or other redundant intermediates. Only npm
installer records are used. Yarn's own guidance identifies `.yarn/cache` as a package cache and
`.yarn/install-state.gz` as an optimization, and pnpm and Yarn trees are not summarized
([Yarn cache configuration](https://yarnpkg.com/configuration/yarnrc/#cacheFolder),
[Yarn project files](https://yarnpkg.com/getting-started/qa#which-files-should-be-gitignored)).

Every retained entry carries its run-owned path, workspace path, SHA-256, byte size, build-unit
identity, exact-path mapping, and accepted-input/build-output origin. Source maps retain bounded
source identities; package integrity sidecars retain the corresponding archive path and hash.
Catalog publication revalidates those identities against the immutable workspace manifest. The
relationship index maps an artifact to its producing command through a tool invocation that names
it as an output (same workspace path and SHA-256): the invocation's own `parent_command_id`, which
captured rows carry, or else a unique match of its protected argument hash. An artifact that no
invocation or producer-supplied relationship attributes gets explicit ambiguous relations
(confidence 0.25) to every command of its unit and a `producing action mapping is ambiguous`
coverage gap.

Bounds are fail-visible: source maps are limited to 16 MiB and 4,096 declared sources; package and
dependency metadata to 64 MiB per file; other retained artifacts to 512 MiB per file; the central
configured artifact-count bound remains authoritative. Oversized or truncated coverage is reported
as a gap, never interpreted as proof that the omitted material is safe.

## Telemetry

The catalog, member and relationship units run inside operation spans. Each declares
`expect_work("artifacts_processed", n)` up front and counts `artifacts_processed` and
`receipts_processed` per item; the relationship unit also counts `invocations_scanned` once per
receipt, for the tool invocations it indexes by output path, so the count grows with invocations,
not with artifacts × invocations. Shard builds count `shards_built`, `entities_written` and
`relations_written`; a verified reused shard counts `shards_reused`. A shard build records, in
order, `index.prepare`, `index.sqlite_write`, `storage.fsync` (its one `timed_fsync`, also counted
in `fsync_calls`), `index.digest`, `index.publish`, `index.link` and `index.custody_bind`. Shard
lock waits record `index.lock_wait` and reuse verification `index.reuse_verify`; `storage.copy`
appears only when adoption falls back to a cross-filesystem copy. `IndexBuilder.build` runs no
`VACUUM`, so `index.sqlite_vacuum` is never recorded. A long unit
writes `OPERATION_PROGRESS` with these counters
while it runs. To investigate a slow unit, follow
[diagnosing a slow or stuck step](metrics.md#diagnosing-a-slow-or-stuck-step).
