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
and Ruby are configured as `source` and use `none` executor databases. Rust uses the pinned
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
evidence remain `GAP`. Any `GAP` decision, or any scope that did not succeed, makes the published
`acceptance.publish_handoff` `terminal_status` and the job `COMPLETED_WITH_GAPS`; an empty CodeQL
result is `SUCCEEDED` only when every planned language and project was analyzed.

Auxiliary build evidence such as package-catalog commands is never replayed as compilation. When
the accepted producer labels commands, CodeQL selects only the ordered `configure` and `build`
commands and requires their role sequence and arity to match the accepted recipe. A roleless
command inventory is usable only when its complete ordered sequence has exactly the recipe's
configure/build arity; the roles are then derived from that immutable recipe order. Extra, missing,
or mixed-role inventories are rejected as gaps instead of guessed. Replay uses the protected argv,
working directory, and environment that the accepted build actually executed, not reconstructed
recipe text.

Visual Basic and F# are not implied by C# coverage. PHP and raw WebAssembly are recorded as
`SKIPPED_NA`. Swift remains an explicit platform gap. Ruby source analysis is accepted only when
the live pinned runtime reports the Ruby extractor and the locked official Ruby query pack; a
missing extractor or pack is a coverage gap, never clean Ruby coverage.

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

Both derived-image build paths normalize bundled payload permissions with `chmod -R a+rX` before
selecting the non-root runtime UID. This preserves precompiled query contents while making
owner-only upstream `.qlx` files readable across UIDs; otherwise CodeQL falls back to compilation
after `AccessDeniedException`, potentially exhausting query memory or time limits. A Dockerfile
change invalidates the derived-image cache identity without changing the pinned source payload.
The live `precompiled_queries` regression in `tests/test_live_codeql_toolchains.py` checks both
image paths as non-root users, not as the build-time root user.

Database and query checkpoints are separate. Each applicable scope runs a `default` query profile;
Go, C# and Rust also run independently hash-pinned `security-extended` profiles (each configured
under `languages.<language>.additional_queries` and present with the same suite hash in
`containers/tools/codeql/assets.lock.json`), and C/C++ runs the discovered `cert-cpp` custom
profile. The C/C++ default profile uses
`cpp-code-scanning.qls`, while the custom profile uses `cert-cpp-default.qls`. Database identities
exclude all query inputs, so a query-suite change reuses a verified database while a build recipe,
dependency, environment,
extractor, source, runtime, or database-limit change invalidates it. Databases and SARIF are
run-owned and retained beneath `runs/<run-id>/data/codeql/scopes/<scope-id>/`; profile-specific
query artifacts live under `queries/<profile-id>/`.

Normalization can rerun with a mixture of reused and fresh query scopes. The shared SQLite
index builder constructs each candidate shard in a private temporary directory and reuses an
existing shard only when its complete bytes match the candidate's SHA-256. It does not overwrite
or delete existing indexes, including shards left by a partially completed normalization step.
Different content at the same identity, corrupt files, and symlinks fail publication explicitly.
New shards are published with an atomic, non-replacing hard link on the same filesystem
(supported by native WSL ext4 and Windows NTFS); an unsupported filesystem fails rather than
falling back to overwrite. Temporary files belong to one builder and are cleaned on success or
failure. Regression tests cover repeated and mixed-scope normalization, integrity rejection, and
concurrent publication in `tests/test_codeql_analysis.py` and `tests/test_retrieval_core.py`.
Byte comparison includes SQLite's serialized format, so replay retained shards with the pinned
deployment runtime; a host Python using a different SQLite version can produce different bytes
for the same logical records and is not a valid byte-identical recovery check.

Ordinary producer failures are accepted as scope-local coverage gaps. A sibling scope continues.
Changed accepted handoffs, source bytes, protected argv, image identities, database manifests,
checkpoints, or SARIF identities are framework-integrity failures and stop publication.

Source-mode workspace staging copies only manifest-pinned regular files at their canonical paths.
Relative npm file aliases and workspace-directory aliases (for example,
`node_modules/@northwinds/frontend -> ../../frontend`) are validated and omitted, not followed or
recreated. Directory targets must be inside the workspace, not ancestors of the link, and contain
manifest-backed files; the complete file inventory and hashes must still match. Absolute links
remain rejected except the existing exact container-owned `/opt/project/.../node_modules` alias.
Escaping, dangling, cyclic, and unpinned links still fail; manifest paths cannot traverse aliases.
Integrity errors identify the scope and offending link. No target or retained build workspace is
modified. Regression coverage lives in `tests/test_codeql_analysis.py`.

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
`NOT_APPLICABLE`) and the gaps or reason. The plan is `outputs["plan.inventory"].plan` in the
handoff's `result.json`; `job_code_graph_index` reads the plan and `export.scopes` only through
those handoff-bound identities, and checks the catalog it normalizes with against this job's
configured `catalog_sha256` pin.

Verification status: the export step runs offline in `tests/test_codeql_export_step.py` and, inside
the real job with an injected executor, in `tests/integration/test_code_graph_end_to_end.py`. Both
play back hand-authored recordings. The pack has compiled and run in the pinned image against the
calibration database (`tests/live/test_codeql_pack_shapes.py`);
`tests/live/test_codeql_graph_export_live.py` and `tests/live/test_code_graph_live.py` remain the
operator tiers that refresh and verify the recordings.

### Query precompilation

Compiling the export pack is the slow part of a first export: a cold `codeql query compile
--threads 8` over the nine export queries took 599 s through `build.py query-packs --warm` and
1053 s through the runner's `compile` action (`--ram 8192`, run alongside other host load) on
Zarathustra (the first query, `CallSites`, takes the longest at 10 minutes because it compiles the
shared libraries; the smallest, `Seeds` and `Neighborhood`, about a minute), and 25-33 s when the
compile cache is warm. After the payload was rebuilt as `sha256:4e6f3afa...2bee` the volume
`appsec-codeql-compile-6152bec784c6efd0` compiled cold in 735 s (two duplicate `--warm` runs shared
the volume and the host load stayed near 12, so this is an upper bound) and then warm in 25 s. An earlier measurement of seven queries took 887 s, and compiling the first
query and then the rest in separate concurrent processes was slower (1144 s: 522 s, then about 10
minutes of contended processes), so the `compile` action uses a single multi-threaded invocation. Evaluation does not recompile: the seeded export binds `exportScope` and
`exportSeed` with `--external` at evaluation time, so compiled queries are independent of the
project, the database and the scope.

- **Cache.** `$HOME/.codeql/compile-cache` is persisted in the docker volume
  `appsec-codeql-compile-<sha256(key)[:16]>`, mounted at `/codeql-cache` and linked by the runner.
  The key is the pinned CodeQL payload image (`image.source_image_id`), not the derived project
  image, so every project image and every runner-script edit shares one warm cache. A new CodeQL
  payload starts cold by design.
  Entries are readable only by the uid that wrote them, so `build.py query-packs --warm` runs as
  the same uid the job does (the host process owner, `application_runtime_user`), and both
  re-assert ownership of the volume recursively before use. A cache written as a different uid is
  a silent miss: the job recompiled from cold (1053 s) against a volume warmed as uid 10001.
- **`compile` action.** `codeql_runner.py compile` compiles the whole pack with
  `codeql query compile --threads` into the cache and writes nothing else. It has its own
  timeout, CPU and memory limits (`compile_timeout_seconds` 3600, `compile_threads` 8,
  `compile_ram_mb` 8192 in `[codeql_analysis.export_queries]`) so a cold compile does not consume
  the export timeout or the two-thread evaluation cap. These settings do not enter the export
  identity.
- **Job behaviour.** `job_codeql_analysis` runs the `compile` action once per pack identity per
  process (per-key lock, in-memory memo) before the first export action. A compile that fails or
  times out makes that export `FAILED` with a named gap; it is never read as "no flows".
  Events use tool id `codeql-graph-export-compile`.
- **Warming ahead of time.** `python containers/build.py query-packs` type-checks the registered
  packs (`--check-only`, no cache). `python containers/build.py query-packs --warm` performs the
  real compile into the same volume, for packs registered with `warm = true` in
  `rules/registry.toml` (currently `graph-export-cpp`). Run it once per host and after a CodeQL
  payload change. The cache is per host, so a fresh host pays the cold cost on its first export
  unless it has been warmed.
- **Other CodeQL packs.** `cert-cpp-coding-standards` is type-checked, not warmed (its 117 queries
  took 48 min 36 s with `--check-only` on the rebuilt payload, so the registry gives it a 7200 s
  timeout); registering it with `warm = true` would add that cost to every payload rebuild; it was
  left off. Its dependencies ship inside the
  `cert-cpp-coding-standards.tgz` member of the licensed zip, so the image needs no other member
  packs.
- **Detecting a cold cache.** A compile event longer than a couple of minutes, or an export that
  fails with a compile timeout, means the volume was empty or the payload changed.

### Seeded export

By default the export is seeded from finding locations instead of running over the whole program
([design](../architecture/seeded-codeql-neighborhoods.md)). Additional `export_queries` settings:

- `mode`: `seeded` (default) or `whole_program`.
- `seed_depth`: call-graph steps (callers and callees) from each seed function; default 3,
  `0` exports the seed functions only, capped by `max_seed_depth` (8).
- `seed_limit`: maximum distinct seeds per scope (default 200); the overflow is a named gap.

Seeds are the locations of `tool_observation` entities from `job_evidence_collection`. The job
writes `scope.csv` and `seeds.csv` next to the staged database and the runner binds them with
`--external`. Mode, depth, limit and the seed set are part of the export identity, so changing any
reruns the export. A scope with no resolvable seed does not run the export; it is `partial` with the
gap "seeded export skipped". Each export record carries a `seeded` section with the seed ledger
(`resolved`, `unresolved`, `file_not_in_database`, `over_limit`), the neighborhood function count
and the per-depth histogram. `job_code_graph_index` publishes one database card per scope; models
list the cards with `list_codeql_databases` and expand one with `query_codeql_neighborhood`.

## Evidence and retrieval

SARIF 2.1 results, rule metadata, severities, fingerprints, suppressions, baseline state, locations,
and code-flow steps are normalized into immutable `observations` shards. Each step records its
SARIF `code_flow` index (normalizer `appsec-review/codeql-sarif-normalizer/2`), so alternative paths
for one result stay separable; `job_review_prioritization` keeps the shortest flow per source and
sink as a verified semantic path. Exact path matches are
distinguished from suffix matches; ambiguity and unmapped locations remain gaps. The publisher's
manifest lists this job's own observation shards and references the current accepted manifest and
the accepted sibling manifests as verified `upstream_manifests`; it does not copy their shards into
its own list. Later publishers compose onto it, and shards it dropped from the accepted list are
restored from their producers' accepted handoffs by `job_code_graph_index` (clangd, IR and AST
shards) and `job_review_data_indexing` (every producer).

Use the `query_codeql` MCP tool to filter accepted observations by language, original source
language, scope, build unit, rule, severity, path, or CodeQL shard.

## Acceptance checklist

For a fresh `appsec-multi-vuln` run, verify:

1. the live extractor inventory matches `containers/tools/codeql/assets.lock.json`;
2. every applicable scope reports separate database and per-profile query identities;
3. every successful C/C++ database reports both `default` and `cert-cpp` query profiles;
4. every successful Go, C# and Rust database reports both `default` and `security-extended` profiles;
5. each supported language present has a real database and query execution or a precise gap;
6. the accepted manifest contains profile-specific `codeql-*` observation shards;
7. `query_codeql` returns the same accepted observations; and
8. deployment verification reports per-language and per-profile execution, SARIF, observation,
   and gap counts; and
9. every successful C/C++ database has a `SUCCEEDED` graph export whose manifest is bound to the
   handoff, every other language reports `NOT_APPLICABLE`, and `tests/live/test_code_graph_live.py`
   passes (not yet run).

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
