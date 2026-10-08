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

Wave 1 exercises this mechanism with `job_review_intake` followed by `job_target_catalog`. Both are
registered through the same semantic registry used by the generic Dagster adapter. Later review jobs
extend the ordered graph without changing the accepted-handoff format.

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

The accepted plan is an immutable run artifact and an `analysis/target-analysis-plan` retrieval
shard. Its manifest composes the catalog shards rather than replacing them. Evidence producers read
the accepted plan, execute only selected scanner scopes, and publish explicit `NOT_APPLICABLE`
dispositions for unselected families. Because the planner is a real job in the Dagster graph,
catalog changes invalidate the plan and downstream producers while unrelated upstream work can be
reused.

## C/C++ compiled-analysis lane

`job_cpp_compiled_analysis` follows the accepted plan and discovers native projects from accepted
build actions. Its graph is repository-independent: one task per stage batches an arbitrary project
set while retaining per-project checkpoints, terminal states, and shard identities. Once a project
catalog is terminal, compiled indexing, Clang AST, LLVM IR, Infer, CodeQL, Joern, and binary/symbol branches
can be produced without encoding project names or counts in the graph.

The native container executes untrusted build logic but never target binaries or tests. Application
code validates compile commands and artifacts, converts tool failures to explicit gaps, and retains
framework integrity failures as hard failures. See
[`../operations/cpp-compiled-analysis.md`](../operations/cpp-compiled-analysis.md).

## Post-build security assessment

`job_post_build_security_assessment` runs after the accepted C/C++ compiled-analysis handoff and
before evidence-package assembly. It reads the accepted handoff and manifest rather than walking
the target. Thirteen independent case paths capture protected exact argv artifacts plus redacted
indexed command summaries across thirteen accepted cases, inspect produced files as bytes without executing them, apply
platform-aware deterministic hardening rules, validate bounded model observations against exact
command or artifact identities, and publish independently fingerprinted `build_security` shards.

The fingerprint for each shard binds its protected command artifacts, produced-binary hashes,
tool/image identity, rule version, parser and normalizer versions, model/guidance identity, and
upstream manifest. A changed translation unit therefore invalidates its case and dependent linked
artifacts without invalidating unrelated case shards. Missing action timing, link maps, loader
metadata, unsupported formats, unavailable model/tooling, truncation, and parser limitations are
coverage gaps rather than clean results. Exact command text is never written to the central log or
retrieval databases. Operational details are in
[`../operations/post-build-security-assessment.md`](../operations/post-build-security-assessment.md).
