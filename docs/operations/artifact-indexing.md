# Produced-artifact indexing

`job_artifact_indexing` is the repository-independent boundary between accepted language builds and
artifact consumers. It reads only the accepted, hash-verified `job_language_build` handoff, its
workspace manifests, and its declared produced artifacts. It never discovers authority by scanning
the target tree.

The job publishes immutable `artifacts` SQLite/FTS shards in three independently fingerprinted
groups:

- catalog shards per build unit and canonical artifact family;
- archive-member shards per package artifact and extractor identity; and
- relationship shards per artifact.

The accepted composite manifest retains the previously accepted physical indexes and replaces the
prior `artifacts` shard set atomically. Catalog fingerprints contain no scanner, retrieval transport,
or MCP identity. A scanner change therefore invalidates only its observation shards, and an MCP
change invalidates no physical shard.

## Recovery and integrity

Restart the same application run normally. A completed shard whose deterministic path, SQLite
integrity, metadata, and hash still verify is reused. A stale or corrupt shard is an integrity
failure and stops publication; it is never silently overwritten. Changing one artifact changes its
family catalog shard and its artifact-specific member or relationship shards without invalidating
unrelated build units or artifact families.

An unavailable, failed, empty, truncated, or ambiguously mapped producer remains an explicit
coverage gap. Raw artifact bytes, protected command arguments, and stdout/stderr never enter the
SQLite/FTS payloads. The accepted summary and composite manifest are run-owned artifacts bound to
the accepted job handoff.

## Node retention policy

The Node language build publishes a deliberately small review set. A successful build always
retains each in-workspace `package.json` and the selected npm, pnpm, or Yarn resolution metadata
(`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, or Yarn Plug'n'Play
loader metadata). These files are retained even when unchanged because they define package entry
points, dependency intent, exact resolutions, and integrity values. npm documents that a normal
lockfile represents the dependency tree without requiring `node_modules`; its hidden
`node_modules/.package-lock.json` is only an installation optimization and is deliberately not
retained. See the [Node package contract](https://nodejs.org/api/packages.html),
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

The collector does not enter `node_modules`, package-manager stores, `.yarn/cache`, generic build
caches, or transient temporary directories. It does not retain object files, generic native
libraries, logs, arbitrary checksum files, unchanged source modules, or other redundant
intermediates. Dependency trees are represented by their manifests and lock metadata rather than
thousands of mutable installed files. Yarn's own guidance identifies `.yarn/cache` as a package
cache and `.yarn/install-state.gz` as an optimization
([Yarn cache configuration](https://yarnpkg.com/configuration/yarnrc/#cacheFolder),
[Yarn project files](https://yarnpkg.com/getting-started/qa#which-files-should-be-gitignored)).

Every retained entry carries its run-owned path, workspace path, SHA-256, byte size, build-unit
identity, exact-path mapping, and accepted-input/build-output origin. Source maps retain bounded
source identities; package integrity sidecars retain the corresponding archive path and hash.
Catalog publication revalidates those identities against the immutable workspace manifest. The
relationship index maps a tool invocation to a producing command only when its protected argument
hash uniquely matches; otherwise it publishes explicit ambiguous relations and a coverage gap.

Bounds are fail-visible: source maps are limited to 16 MiB and 4,096 declared sources; package and
dependency metadata to 64 MiB per file; other retained artifacts to 512 MiB per file; the central
configured artifact-count bound remains authoritative. Oversized or truncated coverage is reported
as a gap, never interpreted as proof that the omitted material is safe.
