# Jobs and runtime

## Wave 1 resumability

An ordered application graph sits above the existing semantic `JobRunner`. Each successful attempt
publishes `handoff.json` inside its immutable attempt directory and updates the job's small
`latest.json` pointer only after output validation. The handoff binds result artifacts, upstream
handoff hashes, resolved and job-local configuration hashes, target fingerprint, implementation,
schema, validator, tool identity, timestamps, and resolving paths.

The generic resume planner walks jobs in graph order. Once a job cannot be reused, it schedules that
job and invalidates the transitive downstream closure. It never treats time as proof of freshness.
The graph holds a kernel-backed per-run claim lock across planning and execution so two resume
processes cannot claim the same run concurrently.

The direct CLI currently exercises this mechanism with an eleven-job linear review graph from
`job_review_intake` through `job_evidence_collection`. Dagster builds the broader, branched
`wave1_review` topology from the registered and configured jobs, including CI configuration,
tree-sitter, post-build, and OWASP branches that are not in the direct graph. Both surfaces use the
same semantic registry and accepted-handoff format. The exact operator-visible distinction is
documented in [`../operations/wave1-review.md`](../operations/wave1-review.md).

Each orchestrated graph launch also publishes an immutable run-level orchestration receipt. This
keeps the current Dagster run linked to the application run even when every job is reused and the
accepted job receipts correctly remain linked to their original launch.

## Global events

Every job and unit event is mirrored through one process-safe writer to
`runs/<run-id>/data/logs/pipeline.jsonl`, while attempt-local event logs remain available. Sequence
allocation and append occur under the same kernel lock. Records have bounded/redacted details, and a
torn final line is truncated under that lock before the next append, preserving a readable total
order after a writer crash.

The runtime composes each job from one handler and explicit input/output validator lists. Specific
jobs do not subclass the runtime and cannot replace its attempt, status, logging, or publication
lifecycle.

```text
src/appsec_review/
  runtime/       composed Job, registry, runner and context
  config/        typed TOML loading
  observability/ structured execution events
  storage/       atomic writes, run allocation and locks
  jobs/
    job_third_party_data_sync/
      steps/
        nvd_sync/
```

Stable hierarchy is `job -> step -> task`. Every identifier is a descriptive lowercase snake-case
name. Add step or task modules only when the work actually has independently validated or
dispatchable units; do not make empty structural classes.

Configuration uses nested stable ids:

```toml
[jobs.job_third_party_data_sync]
name = "third_party_data_sync"

[jobs.job_third_party_data_sync.schedule]
enabled = true
cron = "0 0 * * *"
timezone = "UTC"

[jobs.job_third_party_data_sync.steps.nvd_sync.tasks.fetch]
workers = 1
```

Step/task overrides use
`[jobs.<job_name>.steps.<step_name>.tasks.<task_name>]`; for example, the NVD step declares
`fetch`, `process`, and `publish` tasks.

## Processing-mode configuration reference

Three independently typed controls are resolved by the central TOML loader:

```toml
[build_capture]
mode = "required" # required | auto | disabled

[jobs.job_language_build.settings]
compiler_artifact_collection_mode = "required" # required | auto | disabled

[jobs.job_language_build.settings.compiler_artifact_collection_overrides]
native = "required"
go = "required"
dotnet = "required"
rust = "required"

[jobs.job_codeql_analysis.settings]
enabled = true
execution_mode = "auto" # build | source | auto | disabled

[jobs.job_codeql_analysis.settings.languages.cpp]
enabled = true
mode = "build" # build | source | auto | disabled
```

`build_capture.mode` defaults to `required`. Only `job_project_build` and
`job_language_build` may override it through their existing `settings.build_capture` table; all
other job targets are rejected. `compiler_artifact_collection_mode` defaults to `required`, and
its override table accepts only the configured language-build families: `native`, `go`, `dotnet`,
`node`, `python`, `rust`, `php`, `java`, and `wasm`. An omitted family inherits the default.

CodeQL `execution_mode` defaults to `auto`; each of the fixed CodeQL language entries can override
it with `build`, `source`, `auto`, or `disabled`. The checked-in configuration preserves verified
behavior explicitly: C/C++, Go, Java/Kotlin, and C# use `build`, while JavaScript/TypeScript,
Python, Rust, and Actions use `source`. The old per-language spellings normalize only at load time:
`manual` becomes `build` and `none` becomes `source`. The typed object and resolved configuration
never retain the legacy spelling. A legacy `enabled` Boolean that conflicts with `disabled` is
rejected rather than guessed.

Every run retains both the exact source TOML and canonical `resolved.json` under
`runs/<run-id>/data/configuration/`. The version 2 configuration manifest hashes both. Canonical
JSON and its SHA-256 include defaults, overrides, and normalized CodeQL values; accepted handoffs,
job configuration hashes, and resume planning use the resolved hash. Changing any processing mode
therefore invalidates reuse deterministically.

The generic deterministic evaluator makes these controls operational. Its immutable decision binds
resolved policy and configuration hash to the accepted project/language identity, bounded facts,
selected capability, descriptor source path/hash identities, reason code, and one of `SUCCEEDED`,
`SKIPPED_NA`, `SKIPPED_POLICY`, or `GAP`. Decisions are retained in project-build,
language-build, and CodeQL artifacts and handoffs. They are checkpoint inputs, participate in
resume invalidation, and feed completeness accounting; `GAP` is retriable and blocks clean claims,
while either skip remains explicit without becoming a gap or evidence of security.

## NVD synchronization

`job_third_party_data_sync.nvd_sync` is a standalone, network-enabled reference publisher. It bootstraps from the official
NVD CVE 2.0 yearly feeds and then consumes bounded CVE API last-modified windows. Raw source bytes
and a compact CVE metadata JSONL projection are stored as content-addressed gzip blobs. An immutable
manifest links each snapshot to its parent; `current.json` advances only after complete validation.

The schedule declaration is midnight UTC. Direct CLI invocations enter `JobRunner` with an explicit
trigger:

```powershell
python -m appsec_review run job_third_party_data_sync --trigger manual
python -m appsec_review run job_third_party_data_sync --trigger schedule
```

The application runtime exposes a typed `ExecutionPlan` and safe lifecycle methods to begin an
attempt, execute or reuse one unit, and finalize its validated handoff. Dagster consumes that plan
and displays the actual dependency graph. Intake and catalog tasks are visible nodes; every evidence
producer is a `scan -> normalize -> index` branch; Syft is a real prerequisite of Grype; final
manifest assembly depends on every producer-owned index shard; handoff publication depends on the
verified manifest. There is no whole-job dispatch op.

Dagster owns dependency scheduling, multiprocess concurrency, pools, node visibility, and selected
re-execution. The application remains authoritative for run/attempt allocation, immutable
configuration binding, handlers and validator lists, checkpoints, receipts, hashes, source identity,
coverage gaps, shard validation, the accepted manifest pointer, the central log, and accepted
handoffs. TOML controls the multiprocess executor and concurrency bounds.

Dagster run UUIDs and application run ids are separate identities. The adapter passes the Dagster
UUID into `JobRunner` as orchestration correlation, and the runner records it in terminal
`status.json`. After a successful return, the adapter adds the application run and attempt ids to
the Dagster run tags. This creates a checked bidirectional trace without allowing Dagster to write
application receipts or allocate application ids.

Deployment layout and exact operator commands are documented in
[`deploy/dagster/README.md`](../../deploy/dagster/README.md). The process-safe central log and
immutable publication checks remain coherent across Dagster worker processes. Direct
`JobRunner.run` remains available for fast runtime tests and controlled application execution;
integration and acceptance tests use the Dagster DAG.

## Inference entry point and model preflight

`appsec_review.inference.infer` is the only path from the application to a language model. A job
builds a `ModelRequest` naming its configured provider and model and calls `infer`; the inference
package resolves the provider to one transport function (`anthropic-api` or `claude-cli`). Jobs
receive `infer` as a parameter from the registry and never import a provider module, an SDK, or a
provider endpoint. A test fails if any module outside the inference package does.

Every review graph starts with `job_review_intake`, whose first step is `model_preflight`:

- `resolve_models` reads the run's frozen configuration and collects every provider/model pair any
  job's settings name, including jobs whose model is disabled and nested model tables.
- `verify_models` asks each named provider once, through `inference.check_models`, whether it serves
  each model. API providers return their model listing and resolve aliases by lookup; the Claude CLI
  has no listing, so each model is confirmed by one minimal call that the model itself must answer.

The provider listings, per-model results, and provider errors are written to
`model-preflight.json` before any decision. If one configured model is unavailable, its provider
cannot be reached or authenticated, or its provider has no inference transport, `verify_models`
fails, the intake handoff is not published, and no later job in the review can start. A job
instance built outside the registry has no check wired and reports `NOT_APPLICABLE` rather than
claiming the models were confirmed. `jobs.job_review_intake.settings.model_preflight.timeout_seconds`
bounds each provider request or probe.

## Target analysis planning

`job_target_analysis_plan` is the semantic boundary between the accepted target catalog and costly
producer branches. It consumes only hash-verified catalog artifacts and accepted index identities;
it never walks the target during inference and never builds or executes target code. Its bounded
summary groups large trees by prefix and component while preserving exact target-relative path and
hash identities for every accepted scope.

Deterministic rules select mandatory baseline coverage, language-specific scanners, dependency
managers, and generic build units first. Units come from accepted project descriptors or a bounded
source-only fallback for directly compiled languages; their stable identities never include fixture
names or fixed repository layouts. A centrally configured model resolves how each unit should be
built from a bounded descriptor package. It returns one typed recipe per unit, including the
throwaway-image profile, declared dependencies, environment, argv arrays, and expected outputs.

Model proposals are untrusted, versioned data. Every identity and path must resolve against the
accepted catalog. Validators reject unknown executables, shell syntax, secret environment keys,
absolute or escaping paths, package/tool installers, tests, and target execution. The model cannot
invent a build unit or authorize execution; a later build job may execute only an accepted recipe
inside its matching image profile. Disabled, unavailable, failed, invalid, or contradictory model
assistance publishes an explicit build-planning gap and leaves recipes absent.

`job_project_build` resolves native CMake recipes deterministically from an accepted
`CMakeLists.txt` marker. That narrow policy takes precedence over model-proposed CMake commands,
is validated by the same recipe allowlist, and is marked `deterministic-cmake-marker`; it does not
generalize to ambiguous build systems. Project-build execution first probes the default pinned
family image. A failed probe may trigger at least three centrally bounded inference-guided image
repairs. The repair schema permits only a validated complete apt package set; commands and all
other recipe fields remain immutable. A successful repair promotes the exact Dockerfile, derived
image digest, and repaired operational recipe into a cache keyed by the original recipe identity,
so unchanged recipes reuse the accepted image while changed recipes return to the default probe.

The accepted plan is an immutable run artifact and an `analysis/target-analysis-plan` retrieval
shard. Its manifest composes the catalog shards rather than replacing them. Evidence producers read
the accepted plan, execute only selected scanner scopes, and publish explicit `NOT_APPLICABLE`
dispositions for unselected families. Because the planner is a real job in the Dagster graph,
catalog changes invalidate the plan and downstream producers while unrelated upstream work can be
reused.

## Generic language-build execution

`job_language_build` is the execution boundary after project-build probing. It hash-verifies the
accepted dispatch, probe receipt, recipe, dependency files, source snapshot, and exact derived
image before executing accepted argv in a fresh run-owned workspace. Native builds, Rust/Cargo, JVM Java/Kotlin
projects, Go modules and
workspaces, manifest-declared Node/JavaScript/TypeScript projects, and Linux-capable .NET SDK projects
are implemented; Windows-only and .NET Framework units publish
explicit platform gaps. Families without an executor publish a named unsupported gap. Build dependencies form topological layers, while unrelated units share the configured
worker pool. Receipts bind command, compile-database, link, artifact, workspace-manifest, image,
and checkpoint identities. The Go capture derives actual compiler/assembler/linker/cgo/package
invocations from the toolchain trace and catalogs package relationships and build IDs.
The Rust capture binds Cargo metadata and accepted workspace/package/target/profile/feature choices
to protected rustc/linker/archiver/build-script provenance, Rust artifact identities, and exact
package dependency relationships without executing examples, benchmarks, tests, or binaries.
The Node capture binds npm, pnpm, or Yarn to its accepted dependency identity, executes lifecycle
scripts as untrusted build code with dependency egress available, catalogs generated/bundled/package/native outputs and
source maps, and records only actually observed or successful package-script tool provenance.
Exact argv remains in protected run-owned artifacts; central logs and
retrieval-visible records contain hashes and sanitized facts only. See
[`../operations/language-build.md`](../operations/language-build.md).

The JVM family is an independent DAG branch. Maven and Gradle wrapper recipe names resolve to the
pinned system tools without trusting target wrapper payloads. Mixed Java/Kotlin units share their
accepted topology and dependency layers. The adapter catalogs generated sources/resources,
classes, JVM metadata, and JAR/WAR/EAR packages, and publishes sanitized command/artifact entities
to the composable `build` index while exact argv and streams remain protected.

Python is a first-class parallel family node rather than a repository-specific lane. It consumes
the same accepted dispatch/probe contract, binds checkpoints to declared dependency inputs and typed
network policy, executes packaging hooks only inside the generic sandbox, and publishes wheel,
sdist, metadata, generated-source, bytecode, native-extension, invocation, and package-relationship
evidence through the shared receipt and retrieval contracts.

## WebAssembly output-family execution

The `job_language_build` WebAssembly lane is an output-family adapter alongside its generic
source-family lanes. It selects accepted source-family recipes by typed producer rules rather than treating WebAssembly as
one source language. Rust wasm targets, Emscripten, WASI SDK/Clang, AssemblyScript, WAT tooling, and
additional explicit producers therefore reuse catalog discovery, recipe validation, derived images,
probe receipts, dependency topology, execution isolation, and immutable handoffs.

The adapter adds bounded diagnostic verbosity where supported, retains protected command streams
and argv, catalogs WebAssembly modules/components plus bindings and interface/debug/package
artifacts, and publishes sanitized command/artifact entities into the shared composable `build` shard. It
never instantiates produced modules. Producer failures are receipt gaps; accepted-input, path,
configuration, hash, checkpoint, and manifest failures stop publication. See
[`../operations/wasm-build.md`](../operations/wasm-build.md).

## C/C++ compiled-analysis lane

`job_cpp_compiled_analysis` consumes successful native receipts from the accepted generic
language-build handoff. It does not configure or compile projects. Its graph is repository-independent:
one task per stage batches an arbitrary project
set while retaining per-project checkpoints, terminal states, and shard identities. Once a project
catalog is terminal, compiled indexing, Clang AST, LLVM IR, Infer, Joern, and binary/symbol branches
can be produced without encoding project names or counts in the graph.

`job_codeql_analysis` is a separate cross-language consumer of the accepted catalog, language-build,
artifact-index, and C++ handoffs. It owns C/C++, Go, Java/Kotlin, C#, JavaScript/TypeScript, Python,
Rust, and GitHub Actions database/query/SARIF production and publishes one composed accepted view.

The generic native build container executes untrusted build logic but never target binaries or tests.
The C++ analysis container only replays bounded compile units for analysis. Application code validates
workspace manifests, compile commands, and artifacts; converts tool failures to explicit gaps; and
retains framework integrity failures as hard failures. See
[`../operations/cpp-compiled-analysis.md`](../operations/cpp-compiled-analysis.md).

## Post-build security assessment

`job_post_build_security_assessment` runs after the accepted C/C++ compiled-analysis handoff and
before the CodeQL and OWASP joins. Static evidence collection is a sibling branch and does not wait
for this job. The assessment reads the accepted handoff and manifest rather than walking the target.
A dynamic project set reuses the generic build's protected exact argv artifacts plus redacted
indexed command summaries, inspects produced files as bytes without executing them, applies
platform-aware deterministic hardening rules, validates bounded model observations against exact
command or artifact identities, and publishes independently fingerprinted `build_security` shards.

The fingerprint for each shard binds its protected command artifacts, produced-binary hashes,
tool/image identity, rule version, parser and normalizer versions, model/guidance identity, and
upstream manifest. A changed translation unit therefore invalidates its case and dependent linked
artifacts without invalidating unrelated case shards. Missing action timing, link maps, loader
metadata, unsupported formats, unavailable model/tooling, truncation, and parser limitations are
coverage gaps rather than clean results. Exact command text is never written to the central log or
retrieval databases. Operational details are in
[`../operations/post-build-security-assessment.md`](../operations/post-build-security-assessment.md).
