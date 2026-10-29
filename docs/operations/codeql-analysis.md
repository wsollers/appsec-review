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
that base. The supplied asset lock describes CLI/extractor/query capabilities; the customer review
does not hash the lock, license, installed trees or supplied packs. Runtime reuse instead requires
operator-declared component releases under `[review_policy.releases]`. Missing declarations disable
reuse rather than trigger payload hashing. Configuration and capability incompatibilities still
fail explicitly. Required image layering uses the separately configured
[bounded builder](performance-assurance.md#scheduling-and-limits); an unavailable backend cannot
be replaced by an uncustomized base image. A derived image layers that payload onto each accepted build image and runs as a distinct non-root
user on Docker's bridge network so manual builds can restore declared dependencies,
read-only root filesystem, dropped capabilities, bounded memory/CPU/PIDs, and bounded head/tail
logs.

### Explicit preinstalled runtimes

An operator may configure `jobs.job_codeql_analysis.settings.preinstalled_runtimes` as an array
of at most 128 exact declarations. With the array absent or empty, the bounded-layer preparation
path is unchanged and `preinstalled_undeclared` has no effect. Once any declaration exists,
resolution of a requested (build environment image, effective user) pair follows these rules:

- **Declared environment.** When at least one declaration names the requested `build_image_id`,
  exactly one of those declarations must match the effective user, and it is used. Missing,
  duplicate or conflicting mappings for a declared environment fail with
  `CodeQL preinstalled runtime requires one exact environment/user declaration` rather than using
  a different tag or silently preparing a layer; `preinstalled_undeclared` never applies to it.
- **Wholly undeclared environment.** When no declaration names the requested `build_image_id`,
  the string setting `jobs.job_codeql_analysis.settings.preinstalled_undeclared` decides:
  - `"fail"` (the typed default) refuses it with the same error (preinstalled-only resolution);
  - `"derive"` uses the bounded derived-image path: `containers/tools/codeql/Dockerfile` layers the
    pinned `/opt/codeql` payload and `codeql_runner.py` onto the accepted build image and runs as
    its non-root runtime user. This needs the commissioned
    [bounded image builder](performance-assurance.md#scheduling-and-limits) and costs build time
    and image disk on first use of each environment/user pair. Later resolutions reuse that image
    only when `review_policy.releases` declares `codeql` and `codeql_runner`.

Any other value is a configuration error. The shipped `appsec-review.toml` sets
`preinstalled_undeclared = "derive"`: the source (inventory) image and the native C/C++ image
use their declared preinstalled runtimes, and every other build profile, including per-run
customized project images produced by `job_project_build` image repair (whose IDs cannot be
declared statically), derives. `CODEQL_RUNTIME_RESOLVED` records which path each scope took as
`preparation_kind = "preinstalled"` or `"derived"`, with `image_build_performed` and
`checkpoint_reused`.

The setting is frozen with the rest of the resolved run configuration. A frozen configuration
that predates the key resolves to the `"fail"` default, so resuming such a run keeps refusing
undeclared environments; for example run `2026-10-29-0002`, which faulted on undeclared
environments, cannot be resumed into `"derive"`. Start a fresh run to apply the shipped policy.

Each declaration has six required string fields: `source_image_id`, `build_image_id`,
`runtime_image_id`, `runtime_user`, `codeql_release_id`, and `runner_release_id`. The only optional
field is `runner_source`, either `image` (default) or `application`. All image fields
are full immutable `sha256:` image IDs. The source ID must match the configured licensed source;
both release IDs must match the frozen `[review_policy.releases]` values `codeql` and
`codeql_runner`. The user is a non-root numeric `UID:GID` and must match the effective application
user. Selection uses the existing `application_runtime_user` translation of the caller's nominal
user before requiring an explicit matching declaration. On an ordinary host running as `1000:1000`,
nominal source/build users such as `10001:10001` therefore require a declaration for `1000:1000`;
no source/build profile override is needed. The selected effective user is bound into runtime,
database and predecessor identities; execution rejects subsequent user drift. This does not
change legacy derived-image identity semantics.

The following is a shape example, not an enabled or usable image declaration. Replace the
placeholders with operator-approved installed IDs/releases and the actual application UID/GID:

```toml
[review_policy.releases]
codeql = "operator-codeql-release"
codeql_runner = "operator-runner-release"

[jobs.job_codeql_analysis.settings]
# "fail" (default) or "derive"; applies only to environments no declaration names.
preinstalled_undeclared = "fail"

[[jobs.job_codeql_analysis.settings.preinstalled_runtimes]]
source_image_id = "sha256:<64-hex-source-id>"
build_image_id = "sha256:<same-source-id-for-inventory>"
runtime_image_id = "sha256:<64-hex-installed-source-runtime-id>"
runtime_user = "1000:1000"
codeql_release_id = "operator-codeql-release"
runner_release_id = "operator-runner-release"
runner_source = "application"

[[jobs.job_codeql_analysis.settings.preinstalled_runtimes]]
source_image_id = "sha256:<64-hex-source-id>"
build_image_id = "sha256:<64-hex-accepted-build-environment-id>"
runtime_image_id = "sha256:<64-hex-installed-compatible-build-runtime-id>"
runtime_user = "1000:1000"
codeql_release_id = "operator-codeql-release"
runner_release_id = "operator-runner-release"
runner_source = "application"
```

The second mapping must match the image in the actual accepted build receipt and the effective
application user selected from its nominal user, including its dependency
environment; a generic C++ image is not authorization for a different dependency-bearing image.
Under `preinstalled_undeclared = "fail"`, inventory needs the source-environment mapping and every
additional accepted environment needs its own entry. Under `"derive"`, an environment without any
entry derives its runtime instead; an entry for the image but not the effective user still fails.
A source-only runtime does not establish compiled CodeQL coverage.

Resolution inspects source/build tag bindings and the selected runtime by immutable ID each
time, and execution independently inspects that ID again. It does not scan installed payloads,
read an old image manifest to establish trust, pull/tag/build images, or bypass execution
reservations, target verification, protected build replay or cleanup. The operator declaration
asserts runtime compatibility and installed release provenance; tool inventory and real
compilation/query failures remain visible rather than being assumed successful from that assertion.
With `runner_source = "image"`, the image must already supply the compatible
`/opt/appsec/codeql_runner.py`: capability-only
inventory with platform-payload verification excluded; protected manual replay and source-only
mode separation; staged database export/query handling; and, when enabled, compile/export actions
with availability-only checks on supplied packs. Customer-generated databases, command identities
and BQRS/SARIF outputs remain verified. The interpreter, CLI, extractors, query packs and precompiled
queries must be usable by the declared non-root user on the existing constrained filesystem.
An old schema2 image is not presumed compatible. An unknown installed runner is an unmet operator
prerequisite, even when the image ID is present; this declaration neither installs nor repairs it.

For ordinary (non-native) execution, `runner_source = "application"` instead mounts the current
application's fixed `containers/tools/codeql/codeql_runner.py` read-only at
`/opt/appsec/codeql_runner.py`. The existing application-asset lookup supports both the trusted
source checkout and installed deployment layout; existing host-bind translation selects the
engine-visible path. A containerized application must already expose that asset through a host
mount; an image-only application asset cannot be translated and fails explicitly.
There is no configurable host path, target-selected wrapper, copying into
target/evidence, payload hash or fallback to the image wrapper. Missing, symlinked or escaping
assets fail before tool launch. Keep that application release and its declared `codeql_runner`
release frozen throughout the run; this is operator provenance, not detection of undeclared edits.
The image still supplies its pinned CodeQL/tools/dependency environment and interpreter, while
provenance explicitly identifies the application-supplied wrapper instead of claiming it lives in
the image. Changing the runner-source mode changes runtime/database identity; execution also
rejects a declaration that no longer matches its resolved image record.

Application-supplied wrappers are explicitly unsupported in native execution in this slice.
The option does not widen broker mount grants or bypass them. Native preinstalled runtimes with
the default image-supplied wrapper retain their existing operator-grant requirements.

Distinct `appsec-review/codeql-preinstalled-image/1` records under metadata
`codeql-preinstalled-images/` and run-owned scope `image.json` identify `preinstalled = true`,
`image_build_performed = false`, `reused = false`, `runner_source`, and no builder receipt. Repeated selection is
still not a cache hit or saved build. The selected runtime ID participates in that environment's
database identity; changing it invalidates the database and downstream work without invalidating
unrelated environment mappings. Legacy derived manifests are neither upgraded nor adopted.

The `codeql.runtime_resolution` span measures selection time, including failures.
`CODEQL_RUNTIME_RESOLVED` records preinstalled/derived provenance, runner source/release, nominal
and effective users, and whether a build occurred. Tool receipts also record runner source/release.
Successful preinstalled spans report `preinstalled_runtimes = 1` and `builder_launches = 0`;
actual database/query work and its reuse remain separately measured. This support does not
provision images, license CodeQL, fill missing target dependencies or authorize a review launch.

Both derived-image build paths normalize bundled payload permissions with `chmod -R a+rX` before
selecting the non-root runtime UID. This preserves precompiled query contents while making
owner-only upstream `.qlx` files readable across UIDs; otherwise CodeQL falls back to compilation
after `AccessDeniedException`, potentially exhausting query memory or time limits. A Dockerfile
change requires the operator to update its declared component release; review execution does not
fingerprint that Dockerfile.
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

A different query release requires a new frozen run, not an edit to an existing configuration.
The explicitly authorized [predecessor DB path](performance-assurance.md#explicit-predecessor-database-reuse)
re-admits only selected compatible databases into new-run custody. Current queries then run under
the new declaration. This is not a global cache or permission to import retained operational data.

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

The export action inside `execution.scopes` runs the supplied graph export pack
on each successful database without fingerprinting supplied pack files. Each database immediately
makes its queries and export eligible, and query/export failures do not invalidate one another.
The job-level topology is planning, ready-scope execution, then acceptance. Resource admission
still applies; [current conservative limits](performance-assurance.md#scheduling-and-limits)
do not permit two ordinary actions to overlap. Its design is
[code-graph precomputation](../architecture/code-graph-precomputation.md) section 7. C/C++, C#,
Go, Java/Kotlin, JavaScript/TypeScript, Python, Ruby and Rust have pinned packs. Every other
language (Swift, Actions, and any language without a pin) records the export disposition
`NOT_APPLICABLE` with the reason "no hash-pinned CodeQL graph export pack for `<language>`". This
is a named disposition, not a failure and not a clean result. An export that did not finish
`SUCCEEDED` or `NOT_APPLICABLE`, or that carries a gap, keeps the job's terminal status at
`COMPLETED_WITH_GAPS` (`publication_status`).

Configuration lives in `appsec-review.toml`:

- `[jobs.job_codeql_analysis.settings.export_queries]` sets `enabled`, `row_limit` (rows decoded
  per export query), `max_bytes` (total export bytes per scope) and `timeout_seconds` (the runner
  `export` action). The defaults equal the `GraphSettings` contract: 200000, 268435456 and 1800.
- `[[jobs.job_codeql_analysis.settings.languages.<language>.export_queries]]` must equal
  `export_query_packs.<language>` in `containers/tools/codeql/assets.lock.json` field for field.
  At most one pack is allowed per language. `cpp`, `csharp`, `go`, `java`, `javascript`, `python`,
  `ruby` and `rust` declare one; `swift` has a pack but no pin, because CodeQL extracts Swift only
  on macOS, so its scopes take the "no hash-pinned pack" disposition. Planning stops with a
  framework-integrity failure when any language's block differs from its lock entry. Runtime
  reads the declared pack, column and catalog contracts for execution; it does not fingerprint
  the supplied lock, pack tree, suite or runner. Relevant operator release declarations determine
  reuse, and missing declarations disable it.

For each exportable scope, the job stages scratch under `data/codeql/scopes/<scope-id>/export/`.
The scratch holds a disposable database copy, the pack, `columns.json` and the asset lock. The
runner checks declared execution compatibility, not supplied payload integrity, inside a
`--network none` container and writes
`exports/<query_id>.json` plus `exports/export-manifest.json`. The scratch is then deleted.
`load_graph_exports` re-verifies the directory against its manifest and the export contract. The
manifest's language, pack identity and bounds must equal the configuration.

The export checkpoint is `export-checkpoint.json`
(`appsec-review/codeql-export-checkpoint/1`). Its identity binds the database identity and tree,
the effective export contract, the manifest schema, the bounds and declared export/runner releases.
A database, declared pack release, bound or declared runner release change reruns the export only. A query-suite or catalog change
does not. On reuse the exports are re-verified, and a changed, extra or missing export file is a
framework-integrity failure. A timeout, a non-zero exit or an invalid fresh export is a scope gap.
A failed database is the gap "export skipped because database creation failed". A truncated query
is a named gap. Any of these gaps makes the execution step, acceptance publication and job
`COMPLETED_WITH_GAPS`, while sibling scopes keep their exports. The execution output publishes
per-scope export dispositions; a failed export prevents accepted-attempt reuse on resume. Successful
bounded exports with named limitations, and policy skips such as a scope with no seeds, do not
become retriable failures solely because they carry a gap.

Raw exports are the `codeql_graph_export` dataset (`artifact_only`). Their rows hold CodeQL
internal ids and are never served; `job_code_graph_index` normalizes them. Consumers find them in
the accepted handoff in three places:

- `outputs["execution.scopes"].graph_export_artifact` points to `artifacts/codeql/graph-exports.json`
  (`appsec-review/codeql-graph-exports/1`), with one record per scope. The handoff preserves this
  reference and binds its path and SHA-256 in `artifacts`. Readers also accept the legacy
  `outputs["export.scopes"].artifact` reference.
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
play back recordings: the C/C++ native recording is copied from a live export, and the per-language
synthetic recordings are hand-authored. Every pack except Swift has compiled and run in
`audit-codeql:custom-2.27.0` built from this repository on a Linux (WSL 2) Docker host; the
per-language live results are in
[`rules/codeql-graph-export/README.md`](../../rules/codeql-graph-export/README.md#live-verification).
`tests/live/test_codeql_graph_export_live.py`, `tests/live/test_codeql_graph_export_<language>_live.py`
and `tests/live/test_code_graph_live.py` are the operator tiers that refresh and verify the
recordings; the JavaScript/TypeScript tier runs in the `node` build profile because the TypeScript
extractor needs Node.js. The native fixture has no sources or sinks,
so `test_codeql_graph_export_live.py` also compiles the synthetic fixture
(`tests/fixtures/graph/codeql_export/synthetic/source/synthetic.cpp`) and requires the live export to
meet every row in its `expected-facts.json` (two paths to one sink, dominating, non-dominating and
macro guards, unknown ranges, sign-changing conversions, virtual and unresolved dispatch). The
offline `tests/graph/test_synthetic_export_expectations.py` holds the hand-authored recording to the
same file.

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
  `appsec-codeql-compile-<sha256(declarations)[:24]>`, mounted at `/codeql-cache` and linked by
  the runner. Its namespace is the declared CodeQL release and the runtime user (the runner
  release is not part of it: the runner contributes nothing to compiled QL), so it is shared
  across runs and queries recompile only when the CodeQL distribution or the query bytes change
  (CodeQL's cache is content addressed by query and library bytes).
  Native mode keeps its cache directory under the run. Missing component declarations disable
  cache use explicitly.
  Initialization is single-flight under a process-safe per-volume lock. Only the volume root
  is chowned; existing cache contents are not recursively traversed. A Docker volume creation
  timestamp binds the initialization record so a recreated volume is initialized again.
  Initialization helpers are named, CPU/memory/PID bounded and tracked by the action's resource
  lease. Unconfirmed container death quarantines the lease; initialization failure is a named
  action failure, not a silent cold-cache fallback.
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
- **Platform warm compile.** `scripts/compile-codeql-queries.sh` (a wrapper over
  `python containers/build.py query-packs --warm`) compiles every
  warm-registered pack into the same volume review runs mount (the name is derived from the
  declared CodeQL release in `appsec-review.toml` and the uid that reads it), so after a CodeQL
  release change one warm step, not the first review run, pays the cold compile. Its checks are
  platform maintenance and never count as customer-review assurance. See
  [Compiling CodeQL queries](#compiling-codeql-queries).
- **Cache sharing trade-off.** The job's compilation cache is shared by every run of the same
  user and declared releases. It holds only compiled QL derived from repository-owned packs and
  the image's libraries (evaluation binds the scope and seeds with `--external`, so no project
  data enters it), but it is writable state that outlives a run.
- **Other CodeQL packs.** `cert-cpp-coding-standards` is type-checked, not warmed: every one of its
  117 queries ships a precompiled `.qlx` in the image (checked in `audit-codeql:custom-2.27.0`),
  which `database analyze` loads, so the registry sets `warm = false` with a `warm_skip_reason`.
  Its `--check-only` verification took 48 min 36 s on the rebuilt payload, so the registry gives it
  a 7200 s timeout. Its dependencies ship inside the
  `cert-cpp-coding-standards.tgz` member of the licensed zip, so the image needs no other member
  packs.
- **Detecting a cold cache.** A compile event longer than a couple of minutes, or an export that
  fails with a compile timeout, means the volume was empty or the payload changed.

### Compiling CodeQL queries

Run `scripts/compile-codeql-queries.sh` (Windows: `scripts\compile-codeql-queries.ps1`) on the
review host before starting review runs whenever:

- the CodeQL image or `review_policy.releases.codeql` changes: the compile-cache volume name is
  derived from the release and the runtime uid, so a new release starts with an empty volume;
- any QL, `qlpack.yml` or suite under `rules/codeql-graph-export/<language>/` changes (also re-pin
  the pack as described in
  [Changing the pack or catalog](../../rules/codeql-graph-export/README.md#changing-the-pack-or-catalog));
- the cache volume was removed or recreated.

What it compiles, and what it skips on purpose:

- **Compiled:** every CodeQL pack registered with `warm = true` in `rules/registry.toml`, which is
  the repository-authored graph-export packs (`cpp`, `java`, `csharp`, `javascript`, `python`,
  `ruby`, `go`, `rust`). Each takes about 2-4 minutes cold at a 7 GB budget. `swift` is deferred
  because CodeQL cannot extract Swift on Linux.
- **Skipped:** the standard query packs in the image (`/opt/codeql/qlpacks/codeql/*-queries`) and
  the licensed CERT pack (`/opt/codeql/custom-queries/cert-cpp`) ship precompiled `.qlx` files, and
  `codeql database analyze` loads those (`Loaded .../Xxe.qlx`, zero compiles). Never warm them:
  compiling the C/C++ analyze suites took 2.8 hours and produced nothing analyze uses.
- Non-CodeQL packs are skipped; they have nothing to compile.

The compile is idempotent: CodeQL's cache is content addressed, so a pack already in the volume is
a cache hit and takes seconds.

Memory: the review host runs these containers in one cgroup
(`appsecreview.slice/appsecreview-actions.slice`, `memory.max` 10 GB) shared with other sessions.
Two compiles at 6-7 GB each are OOM-killed, and a 3 GB budget thrashes the garbage collector. The
script therefore compiles one pack at a time with `--ram 7000 --threads 8` by default, and refuses
(exit 3) while another compile container (`appsec-review-warm-*` or `warm-*`) is running unless
`--allow-concurrent` is given.

```bash
scripts/compile-codeql-queries.sh --dry-run              # list the packs and docker commands
scripts/compile-codeql-queries.sh                        # compile everything that needs it
scripts/compile-codeql-queries.sh --language go,java     # only some languages
scripts/compile-codeql-queries.sh --ram 6000 --threads 4 graph-export-cpp
```

```powershell
.\scripts\compile-codeql-queries.ps1 -DryRun
.\scripts\compile-codeql-queries.ps1 -Language go,java -Ram 7000 -Threads 8
```

Everything runs on Linux Docker. On Windows the PowerShell twin always runs the bash script inside
WSL (`-Distro`, else the distribution of a `\\wsl.localhost\<distro>\` checkout, else the WSL
default); Windows-native Docker is not supported. Under `pwsh` on Linux it runs the bash script
directly. Per-pack logs go to `runs/container-builds/<timestamp>-packs-<pid>/logs/<pack>.warm.log`.
Exit codes: `0` compiled or cached, `1` a pack failed, `2` usage error, `3` refused because another
compile is running.

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

## Execution telemetry

Every CodeQL action emits a telemetry event with `action` (`database`, `analyze`, `compile`,
`export`), `language`, `source_languages`, `build_mode`, scope and build unit, and the query pack
identity (`query_pack`/`query_pack_version`/`query_suite` for analysis, `export_pack`/
`export_pack_version`/`query_suite` for graph export). Fresh executions emit
`TOOL_INVOCATION_STARTED`/`COMPLETED` with `disposition`, `duration_ms`, `timed_out`,
`result_count`, `gap_count`, `truncated`, and the hash identity of the execution receipt. Reused
checkpoints emit `checkpoint_reused=true` and count as `REUSED`. An analyze or export skipped
because its database failed (or a seeded export without seeds) emits `CODEQL_ACTION_SKIPPED`; a
producer exception emits `CODEQL_ACTION_FAILED` with the same identity, so neither is dropped.
Languages and packs are read from scope and configuration, never enumerated, so new export packs
are covered automatically. `appsec-review metrics` aggregates these into the `codeql` section of
the run summary ([review metrics](metrics.md)).

Per-query metrics are written beside each execution receipt as
`executions/<action>/query-metrics.json` (`appsec-review/codeql-query-metrics/1`) and referenced by
hash from the event's `query_metrics` field, or a `query_metrics_gap` reason:

| Action | Source | Per-query data | Limits |
| --- | --- | --- | --- |
| analyze | Runner `query-timings.json` (`appsec-review/codeql-query-timings/1`), parsed from `database analyze` progress lines (`[N/M eval T] Evaluation done`, `Found in cache`), plus accepted SARIF | evaluation ms per query path (cache hits are `REUSED`); result count per rule id | runtimes are keyed by query path and result counts by rule id, which are not joined; at most 5000 timing rows; a failed or timed-out analyze, or an older runner, yields a named gap |
| export | Accepted `export-manifest.json` | `evaluate_ms + decode_ms`, row and exported counts, truncation per query id | a manifest row without `evaluate_ms` is a named gap |
| compile | Runner compile summary on stdout (`appsec-review/codeql-compile/1`) | compile ms per query file | cache hits report no time and are named as a gap |
| database | — | not applicable | — |

The analyze timing source needs a runner that writes `query-timings.json`. The declared runner
release `review_policy.releases.codeql_runner = "appsec-codeql-runner-89568569"` does: derived
images copy the repository's `codeql_runner.py`, and the shipped `preinstalled_runtimes` declare
`runner_source = "application"` with that release; environments they do not name derive under the
shipped `preinstalled_undeclared = "derive"`. A runtime that still carries an older runner yields
analyze rows with the gap "runner wrote no query-timings.json". If an exception escapes after an action's
`COMPLETED` event, the isolated wrapper also emits `CODEQL_ACTION_FAILED`, so that action is counted
twice.

## Evidence and retrieval

SARIF 2.1 results, rule metadata, severities, fingerprints, suppressions, baseline state, locations,
and code-flow steps are normalized into immutable `observations` shards. Each step records its
SARIF `code_flow` index (normalizer `appsec-review/codeql-sarif-normalizer/3`), so alternative paths
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

The [interchange provenance upgrade](../architecture/job-interchange.md) retains the original SARIF
file and resolves each normalized observation to its original RFC 6901 result pointer, parser,
execution receipt, and retained byte identity. Common metadata supplements SARIF rules, flows,
suppressions, fingerprints, and source locations rather than replacing them. The normalizer upgrade
uses `appsec-review/codeql-sarif-normalizer/3`; historical results retain their recorded version.
Database and query checkpoint schema/identity are unchanged. A normalizer/provenance-only
change invalidates derived observations, not an otherwise valid CodeQL database checkpoint.
SARIF ingestion is not a new external exporter, and raw SARIF bodies are not added to inference.

When a failed action left bounded SARIF, it is retained as incomplete diagnostic evidence with no
normalized finding observations; an oversized failed report is an explicit native-output gap.
Missing query execution receipts and unresolved source locations produce provenance gaps.
Source locations are safely resolved and checked against accepted hashes, not trusted from a
scanner-supplied path.

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
9. every successful database of a language with a pinned graph-export pack has a `SUCCEEDED`
   graph export whose manifest is bound to the handoff, every other language reports
   `NOT_APPLICABLE`, and `tests/live/test_code_graph_live.py` passes (not yet run).

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
