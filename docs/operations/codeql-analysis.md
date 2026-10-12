# Cross-language CodeQL analysis

`job_codeql_analysis` is the sole CodeQL producer. It runs after the accepted target catalog,
language build, artifact index, artifact-security analysis, C++ compiled analysis, post-build
assessment, static-evidence, and tree-sitter handoffs in Dagster's `wave1_review`. The job never
discovers a second target snapshot: it plans from accepted artifacts and verifies every source hash
before use.

## Supported coverage

The pinned Linux x86-64 runtime is inventoried live before planning. C/C++, Go, Java/Kotlin, and
C# are centrally configured as `build` and use `manual` executor databases that replay the exact
protected configure/build argv captured by `job_language_build`. JavaScript/TypeScript and Python
are configured as `source` and use `none` executor databases. Rust uses the pinned
source/no-build extractor layered onto the accepted Rust build image so the semantic analyzer can
load Cargo metadata without replaying or executing the target build; missing Cargo manifests,
lockfiles, accepted Rust images, or semantic-analyzer coverage are explicit gaps.
GitHub Actions is analyzed only when accepted `.github/workflows/*.yml` or `.yaml` files exist.

The job-level typed default is `auto`, with fixed per-language overrides in the checked-in TOML that
preserve the behavior above. Valid configuration values are `build`, `source`, `auto`, and
`disabled`. Legacy `manual` and `none` input values normalize one way to `build` and `source`, so
the immutable resolved configuration uses only the canonical vocabulary. The deterministic
evaluator selects `build` only when the accepted descriptor and materialized build receipt declare
the build capability; it selects `source` only for a declared source/no-build capability.
`disabled` records `SKIPPED_POLICY`, unsupported languages with positive accepted evidence record
`SKIPPED_NA`, and missing extractors, replayable commands, toolchains, databases, SARIF, or required
evidence remain `GAP`.

Auxiliary build evidence such as package-catalog commands is never replayed as compilation. When
the accepted producer labels commands, CodeQL selects only the ordered `configure` and `build`
commands and requires their role sequence and arity to match the accepted recipe. A roleless
command inventory is usable only when its complete ordered sequence has exactly the recipe's
configure/build arity; the roles are then derived from that immutable recipe order. Extra, missing,
or mixed-role inventories are rejected as gaps instead of guessed. Replay uses the protected argv,
working directory, and environment that the accepted build actually executed, not reconstructed
recipe text.

Visual Basic and F# are not implied by C# coverage. PHP and raw WebAssembly are recorded as
`SKIPPED_NA`. Ruby and Swift remain explicit gaps until an accepted executor/platform exists.

## Runtime and checkpoints

The licensed base image is operator-provided. No proprietary payload is committed. The configured
`audit-codeql:custom-2.27.0` source image adds the release-pinned CERT C++ coding-standards pack to
that base. The reviewed asset lock pins the CLI, license, complete extractor trees,
TypeScript/Rust analyzer prerequisites, default query packs, custom query trees, pack locks, and
suites. `jobs.job_codeql_analysis.settings.asset_lock_sha256` in `appsec-review.toml` must equal
the SHA-256 of `containers/tools/codeql/assets.lock.json`, and each configured query, additional,
and custom suite must equal its locked entry; otherwise planning stops with a framework-integrity
failure. Any change to the lock therefore updates `asset_lock_sha256` in the same change. A
derived image layers that payload onto each accepted build image and runs as a distinct non-root
user on Docker's bridge network so manual builds can restore declared dependencies,
read-only root filesystem, dropped capabilities, bounded memory/CPU/PIDs, and bounded head/tail
logs.

Database and query checkpoints are separate. Each applicable scope runs a `default` query profile;
C# and Rust also run independently hash-pinned `security-extended` profiles, and C/C++ runs the
discovered `cert-cpp` custom profile. `appsec-review.toml` also configures a Go `security-extended`
additional query that the asset lock does not contain, so Go scopes fail the additional-suite
equality check until the lock and configuration agree. The C/C++ default profile uses
`cpp-code-scanning.qls`, while the custom profile uses `cert-cpp-default.qls`. Database identities
exclude all query inputs, so a query-suite change reuses a verified database while a build recipe,
dependency, environment,
extractor, source, runtime, or database-limit change invalidates it. Databases and SARIF are
run-owned and retained beneath `runs/<run-id>/data/codeql/scopes/<scope-id>/`; profile-specific
query artifacts live under `queries/<profile-id>/`.

Ordinary producer failures are accepted as scope-local coverage gaps. A sibling scope continues.
Changed accepted handoffs, source bytes, protected argv, image identities, database manifests,
checkpoints, or SARIF identities are framework-integrity failures and stop publication.

## Graph export step

The `export` step (unit `export.scopes`) runs the repository-owned, hash-pinned graph export pack
on each successful database. It depends on `database.scopes` only, so query and export failures
never invalidate each other. Its design is
[code-graph precomputation](../architecture/code-graph-precomputation.md) section 7. Only C/C++
has a pack in this change. Every other language records the export disposition `NOT_APPLICABLE`
with the reason "no hash-pinned CodeQL graph export pack for `<language>`". This is a named
disposition, not a failure and not a clean result.

Configuration lives in `appsec-review.toml`:

- `[jobs.job_codeql_analysis.settings.export_queries]` sets `enabled`, `row_limit` (rows decoded
  per export query), `max_bytes` (total export bytes per scope) and `timeout_seconds` (the runner
  `export` action). The defaults equal the `GraphSettings` contract: 200000, 268435456 and 1800.
- `[[jobs.job_codeql_analysis.settings.languages.cpp.export_queries]]` must equal
  `export_query_packs.cpp` in `containers/tools/codeql/assets.lock.json` field for field. At most
  one pack is allowed per language, and only `cpp` may declare one. Planning stops with a
  framework-integrity failure when any language's block differs from its lock entry. The export
  unit then rechecks the asset-lock hash, the pack tree hash and file count, `qlpack.yml`, the
  suite, `columns.json` and `catalog.json` in the repository before it runs anything.

For each exportable scope, the job stages scratch under `data/codeql/scopes/<scope-id>/export/`.
The scratch holds a disposable database copy, the pack, `columns.json` and the asset lock. The
runner verifies them against the lock again, inside a `--network none` container, and writes
`exports/<query_id>.json` plus `exports/export-manifest.json`. The scratch is then deleted.
`load_graph_exports` re-verifies the directory against its manifest and the export contract. The
manifest's language, pack identity and bounds must equal the configuration.

The export checkpoint is `export-checkpoint.json`
(`appsec-review/codeql-export-checkpoint/1`). Its identity binds the database identity and tree,
the export pack entry without the catalog, the manifest schema, the bounds and the runner hash.
A database, pack, bound or runner change reruns the export only. A query-suite or catalog change
does not. On reuse the exports are re-verified, and a changed, extra or missing export file is a
framework-integrity failure. A timeout, a non-zero exit or an invalid fresh export is a scope gap.
A failed database is the gap "export skipped because database creation failed". A truncated query
is a named gap. Any of these gaps makes the step's `terminal_status` `COMPLETED_WITH_GAPS`, while
sibling scopes keep their exports.

Raw exports are the `codeql_graph_export` dataset (`artifact_only`). Their rows hold CodeQL
internal ids and are never served; `job_code_graph_index` normalizes them. Consumers find them in
the accepted handoff in three places:

- `outputs["export.scopes"].artifact` points to `artifacts/codeql/graph-exports.json`
  (`appsec-review/codeql-graph-exports/1`), with one record per scope.
- The `graph_exports` list in the acceptance summary (`outputs["acceptance.publish_handoff"].artifact`)
  holds the same records.
- Every export manifest and file appears with its SHA-256 in the handoff `artifacts`.

A succeeded record carries `export_status`, `export_identity`, `export_reused`, `export_pack`,
`export_manifest` and `export_files`, each `{path, sha256, size_bytes}`, plus row counts and
`truncated_queries`. Other records carry `export_status` (`FAILED`, `SKIPPED` or
`NOT_APPLICABLE`) and the gaps or reason.

## Evidence and retrieval

SARIF 2.1 results, rule metadata, severities, fingerprints, suppressions, baseline state, locations,
and code-flow steps are normalized into immutable `observations` shards. Each step records its
SARIF `code_flow` index (normalizer `appsec-review/codeql-sarif-normalizer/2`), so alternative paths
for one result stay separable; `job_review_prioritization` keeps the shortest flow per source and
sink as a verified semantic path. Exact path matches are
distinguished from suffix matches; ambiguity and unmapped locations remain gaps. The publisher
composes its manifest onto the current accepted manifest rather than replacing upstream evidence.

Use the `query_codeql` MCP tool to filter accepted observations by language, original source
language, scope, build unit, rule, severity, path, or CodeQL shard.

## Acceptance checklist

For a fresh `appsec-multi-vuln` run, verify:

1. the live extractor inventory matches `containers/tools/codeql/assets.lock.json`;
2. every applicable scope reports separate database and per-profile query identities;
3. every successful C/C++ database reports both `default` and `cert-cpp` query profiles;
4. every successful C# and Rust database reports both `default` and `security-extended` profiles;
5. each supported language present has a real database and query execution or a precise gap;
6. the accepted manifest contains profile-specific `codeql-*` observation shards;
7. `query_codeql` returns the same accepted observations; and
8. deployment verification reports per-language and per-profile execution, SARIF, observation,
   and gap counts.

## Live acceptance

The current pre-Dagster Rust fixture gate creates a real source/no-build database in the derived
Rust/CodeQL image, confirms successful semantic extraction of the fixture source, and executes both
the default `rust-security-and-quality` suite and `rust-security-extended`. Both runs retain SARIF
and normalized observation files with verified hashes. The benign fixture currently produces zero
observations; this is a verified zero-result execution, not evidence that an arbitrary Rust target
is clean. Rust compiler-native AST and IR coverage are outside CodeQL and remain unsupported.

The current bounded acceptance report is
`deploy/dagster/verification/codeql-cross-language-live-acceptance.json`. Dagster run
`0958c6ff-907d-43fc-b82a-004243f3a573` executed all seven selected steps successfully for
application run `2026-10-09-0007` and reused accepted CodeQL attempt `attempt_0006`. The producer
execution for that attempt was Dagster run `e596f2f0-3b47-4263-973e-e0bc0362fe5a`. It records
37 profile scopes,
30 successful database/query executions, 37 resolved observation shards, 30 normalized
observations, and 26 explicit gaps. The successful scopes comprise Actions 1/1, C/C++ 2/2,
Java/Kotlin 7/7, JavaScript/TypeScript 12/12, and Python 8/8. All seven Go scopes truthfully failed
database creation because the exact accepted recipes only downloaded modules and never compiled
source. C# and Rust remain planning gaps for unavailable accepted .NET environments and missing
Cargo locks, while PHP and raw WebAssembly are `NOT_APPLICABLE`.

The producer retry reused 29 previously successful database/query checkpoints and executed the
formerly blocked Java scope after bounded derived-image locking was fixed; the final exact-tree run
then verified whole-job reuse. `query_codeql`
resolved Java and JavaScript findings from accepted manifest
`cc436fe9611a8182b7de4073c95995c738998e8de89ceb96ac09b5990e195b57`, including normalized
code-flow-bearing observations.
