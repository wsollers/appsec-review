# Cross-language CodeQL analysis

`job_codeql_analysis` is the sole CodeQL producer. It runs after the accepted target catalog,
language build, artifact index, artifact-security analysis, C++ compiled analysis, post-build
assessment, static-evidence, and tree-sitter handoffs in Dagster's `wave1_review`. The job never
discovers a second target snapshot: it plans from accepted artifacts and verifies every source hash
before use.

## Supported coverage

The pinned Linux x86-64 runtime is inventoried live before planning. C/C++, Go, Java/Kotlin, and
C# use `manual` databases and replay the exact protected configure/build argv captured by
`job_language_build`. JavaScript/TypeScript and Python use `none` databases. Rust uses the pinned
source/no-build extractor; missing Cargo manifests or lockfiles are explicit coverage gaps.
GitHub Actions is analyzed only when accepted `.github/workflows/*.yml` or `.yaml` files exist.

Visual Basic and F# are not implied by C# coverage. PHP and raw WebAssembly are recorded as
`NOT_APPLICABLE`. Ruby and Swift remain explicit gaps until an accepted executor/platform exists.

## Runtime and checkpoints

The licensed base image is operator-provided. No proprietary payload is committed. The configured
`audit-codeql:custom-2.27.0` source image adds the release-pinned CERT C++ coding-standards pack to
that base. The reviewed asset lock pins the CLI, license, complete extractor trees,
TypeScript/Rust analyzer prerequisites, default query packs, custom query trees, pack locks, and
suites. A derived image layers that payload onto each accepted build image and runs as a distinct
non-root user with no network,
read-only root filesystem, dropped capabilities, bounded memory/CPU/PIDs, and bounded head/tail
logs.

Database and query checkpoints are separate. Each applicable scope runs a `default` query profile;
C/C++ also runs the discovered `cert-cpp` custom profile. The C/C++ default profile uses
`cpp-code-scanning.qls`, while the custom profile uses `cert-cpp-default.qls`. Database identities
exclude all query inputs, so a query-suite change reuses a verified database while a build recipe,
dependency, environment,
extractor, source, runtime, or database-limit change invalidates it. Databases and SARIF are
run-owned and retained beneath `runs/<run-id>/data/codeql/scopes/<scope-id>/`; profile-specific
query artifacts live under `queries/<profile-id>/`.

Ordinary producer failures are accepted as scope-local coverage gaps. A sibling scope continues.
Changed accepted handoffs, source bytes, protected argv, image identities, database manifests,
checkpoints, or SARIF identities are framework-integrity failures and stop publication.

## Evidence and retrieval

SARIF 2.1 results, rule metadata, severities, fingerprints, suppressions, baseline state, locations,
and code-flow steps are normalized into immutable `observations` shards. Exact path matches are
distinguished from suffix matches; ambiguity and unmapped locations remain gaps. The publisher
composes its manifest onto the current accepted manifest rather than replacing upstream evidence.

Use the `query_codeql` MCP tool to filter accepted observations by language, original source
language, scope, build unit, rule, severity, path, or CodeQL shard.

## Acceptance checklist

For a fresh `appsec-multi-vuln` run, verify:

1. the live extractor inventory matches `containers/tools/codeql/assets.lock.json`;
2. every applicable scope reports separate database and per-profile query identities;
3. every successful C/C++ database reports both `default` and `cert-cpp` query profiles;
4. each supported language present has a real database and query execution or a precise gap;
5. the accepted manifest contains profile-specific `codeql-*` observation shards;
6. `query_codeql` returns the same accepted observations; and
7. deployment verification reports per-language and per-profile execution, SARIF, observation,
   and gap counts.
