# Implementation prompt: stateful engagement intake and job orchestration

Status: implementation specification; Phase 1 is not accepted by publication of this prompt.
Phase 1 means engagement intake/recovery (`00-intake-recovery`), not registry Phase 1 in the
older composable implementation plan. Dagster bootstrap is the first enabling task.

## Objective and governing reads

Implement reliable, repeatable intake and its handoff to pregather. Use Dagster for visual job
dependencies, execution state, and logs while retaining the existing lane lifecycle. Every run
owns its evidence, extracted data, build products, attempts, and validation results. A fresh run
must start clean without deleting another run or accidentally consuming its evidence.

Read `initiate.md`, `environment.md`, `artifacts.md`, `budget-policy.md`,
`manual-orchestration-runbook.md`, `process-manifest.json`, `00-intake-recovery/{config,prompt}.md`,
`registry/AUTHORING-TEMPLATE.md`, `registry/job-templates/`, `tooling/buildenv-catalog.json`,
`../docs/decisions/ADR-0002-orchestrator-in-python.md`,
`../docs/engagement-job-flow.md`, and `../docs/run-data-and-job-execution.md`.
Inspect `run_process.py`, `stage_artifacts.py`, `create_handoff.py`, `validate_lane_output.py`,
`review_cli.py`, and the engagement pipeline before changing contracts. Preserve unrelated edits.

## Task 0: vet this prompt before implementation

Produce a review matrix mapping every requirement below to implementation files, tests, and evidence.
Check it against the actual code, registry, schema-validator capabilities, user requirements, and
the dependency graph. Identify ambiguous requirements, cyclic dependencies, impossible acceptance
conditions, missing personas/roles, and migration conflicts. Resolve routine issues and record
revisions; request clarification only for a material unresolved decision. Record reviewer identity,
prompt hash, date, findings, disposition, and remaining blockers in a run-scoped vetting report.
Never claim independent review if only self-review occurred. Re-vet substantive prompt changes.
The implementation may not pass acceptance with unresolved requirement blockers.

## Task 1: establish or complete the local Dagster foundation

Inspect Docker before acting. The prior stack belonged to `lra-ingestion-harness`; it was stopped
on 2026-09-19 without removing its containers or volumes. Do not restart or delete it as part of
this engagement. Inspect the repository's new Dagster bootstrap before adding duplicate services.

Use repository-owned Compose/configuration, a distinct project/network, persistent metadata and
compute-log storage, and a web UI bound to localhost. Pin compatible dependency versions. Include
health checks, bounded log rotation, graceful stop, restart instructions, and a deterministic
pre-validation -> work -> post-validation smoke graph. Prove history survives a container restart.
Never mount the Docker socket or host credentials into target-analysis workers. Keep target data
read-only; use the established isolated scanner wrappers or a documented bounded worker adapter.
Dagster visualizes a code-defined graph; do not promise a drag-and-drop workflow editor.

## Task 2: fix intake scope and build discovery

- Record business goal, target identity, revision and dirty/untracked-input fingerprint, platforms,
  scope includes/excludes, budget, execution environment, and already granted action permissions.
- Discover all relevant language/workspace/build/deployment families. Compile-database and
  link-recipe planning applies only to native scopes. Non-native and IaC-only targets must pass
  intake without a compile database. Missing native coverage blocks only dependent native work.
- Preserve the whole engagement scope. Choosing a primary native build does not exclude other
  clients, servers, APIs, IaC, CI/CD, or SRE artifacts. Record unavailable submodules and paths.
- Plan `02-repository-partition-discovery` and subsequent specialist discovery. Intake supplies
  inventory and scope; it does not depend on the partition map it is scheduling. Reuse a prior
  map/build plan only through a validated provenance-bearing import.
- Separate readiness to collect evidence from post-pregather completeness. Missing scanner outputs
  are expected before pregather; corrupt or inconsistent supplied artifacts are never silently OK.
- Extend staged manifests to include scope, source identity, run-owned data root, build-discovery
  references, selected jobs, partition and specialist artifacts, hashes, and producer attempt IDs.
  Restaging preserves existing run state and explicitly invalidates stale derived references.

## Task 3: implement durable run and attempt ownership

Follow `../docs/run-data-and-job-execution.md`. Resolve all engagement data below
`appsec-review-process/runs/<run_id>/data/`. Keep immutable per-attempt evidence/build/extraction
directories and an atomically published manifest selecting accepted outputs. No job may consume
another run's data by searching a shared project directory or choosing the newest file.

Integrate CLI, Dagster, staging, handoff generation, and pipeline `--out` handling through one
Python execution/state adapter. Map the stable engagement run ID to each Dagster execution ID
and job attempt ID. Preserve old runs read-only with explicit import/migration; do not bulk move
or delete legacy `scratch/<project>-engagement` data. Compatibility exports are conveniences,
never authoritative input discovery.

Identical accepted inputs/config/code may be reused only after hash and contract validation.
Reuse does not invoke tools or LLMs again. Forced reruns create new attempts. Changed input,
prompt, schema, tool image, or configuration creates a new attempt and invalidates dependent
acceptance. Preserve old data for audit. Interrupted attempts cannot become cache hits.
Use per-job/scope locking and atomic commits; validate IDs and paths including traversal and
symlink escape. Capture a stable source snapshot or detect changes during execution and reject
mixed-revision output. Document stale lock and crash recovery without unsafe lock stealing.

## Task 4: jobs, roles, dependencies, and validation

Configure every job with persona, role, domain, tooling profile, output contract, budget, explicit
inputs, applicability, retry policy, timeout, and output namespace. Reuse registry records when
appropriate; define missing coordinator and validation responsibilities. Deterministic validation
jobs still need an auditable registry composition; a persona assignment does not require an LLM.
Developer, DevOps, and SRE assignments may overlap but must have an explicit coordinating reviewer.

Use one machine-readable dependency graph to drive scheduling and diagram checks/generation.
Respect `process-manifest.json`; validate lane order separately from intra-lane job edges.
Detect missing job references, cycles, incompatible contracts, and duplicate output namespaces
before dispatch. Required, optional, and not-applicable dependencies need different semantics.
An upstream skip satisfies a dependency only if the consumer explicitly permits its reason.
Never treat a missing required result or failed optional enabled job as silent success.

Every work job has visible pre-validation and post-validation jobs. Pre-validation checks source
identity, input hashes, dependency acceptance, composition, configuration, permissions, and output
isolation. Post-validation checks schema AND semantic rules, produced file hashes, citations,
source consistency, completeness, claim limits, and final status. Only validated output is
published. Validation failures block dependent jobs even if the work process exited zero.
Validators use a small trusted bootstrap contract rather than recursively scheduling validators
for validators. They receive the same failure/logging envelope as other jobs.

The intended order is intake acceptance -> file inventory/partition discovery -> applicable
developer/DevOps/SRE discovery and collection -> validated evidence assembly -> component
characterization -> existing specialist lanes. Independent jobs may overlap only when declared
inputs and output namespaces permit it. Component characterization is not a prerequisite for
initial partition discovery. Do not falsely mark unwired downstream jobs as implemented.

## Task 5: robust errors, streams, and recovery

Use argv arrays, no interpolated shell commands. Capture stdout and stderr separately, stream
both without deadlocks or unbounded memory, and persist structured timestamped events. Record
run/job/attempt/Dagster IDs, command with secrets redacted, working directory, tool/image version,
start/end/duration, exit code or signal, timeout, validation outcome, and exact resume command.
An stderr message alone is not failure; zero exit alone is not success. Tool-specific finding
exit codes require documented interpretation and valid artifacts. Preserve partial evidence.

Handle startup failure, tool absence, timeout, cancellation, child-process cleanup, malformed
JSON, permission/disk/write failure, lost workers, and logging failure. Propagate terminal
`OK`, `FAILED`, `BLOCKED`, or justified `SKIPPED` to job/lane/run state and Dagster. Explicitly
map transient execution states and cancellations; never swallow exceptions. Logging/state-write
failure must fail closed and emit an emergency stderr diagnostic, with recovery recorded when
storage returns. Bound retries to explicitly transient failures; never blindly retry target
execution with side effects. Keep raw logs in ignored run storage, redact UI/export views.

## Acceptance requirements

Attach commands, exit codes, artifact paths and hashes to every row. Tests must exercise behavior,
not merely assert the presence of configuration strings. A bootstrap smoke is not Phase 1 acceptance.

| ID | Required evidence |
|---|---|
| A01 | Prompt vetting report covers every requirement; no unresolved blockers; current prompt hash recorded. |
| A02 | Repo-owned Dagster services healthy; graph, separate streams and history visible; restart preserves history/data; old stack untouched after its authorized stop. |
| A03 | Every implemented job resolves all five registry composition IDs; semantic compatibility and bad references tested. |
| A04 | Native, non-native, IaC-only and mixed fixtures prove conditional build requirements and scope preservation. |
| A05 | Initial intake passes without scanner outputs; post-pregather missing/corrupt required artifacts fail. |
| A06 | All evidence, extracted files, builds and attempt logs resolve under the owning run's data root; traversal/symlink escapes rejected; two runs cannot overwrite or implicitly consume each other. |
| A07 | Same run and fingerprint rerun reuses validated output without invoking work; force rerun makes a distinct immutable attempt; prior accepted bytes stay unchanged. |
| A08 | Source/dirty input/prompt/schema/tool/config changes invalidate appropriate outputs and descendants; tampering, partial and stale artifacts are rejected. |
| A09 | Crash/restart and concurrent duplicate dispatch tests prove locks, atomic publication and recovery; interrupted work never appears accepted. |
| A10 | Pre-validation blocks work; post-validation blocks consumers; cycles, missing dependencies and incompatible skip reasons fail. |
| A11 | Large concurrent stdout/stderr, stderr-only success, nonzero exit, zero-exit malformed output, startup error, timeout and cancellation all preserve diagnostics and produce correct statuses. |
| A12 | Simulated disk/permission/logging failures fail closed with emergency diagnostics; child processes are cleaned up; retries are bounded and auditable. |
| A13 | Legacy CLI/handoff/status interfaces remain usable through explicit compatibility; legacy data are preserved and imports record origin/hash. |
| A14 | A bounded Freeciv21 intake run records actual source identity, native plan, complete scope caveats and pregather job plan; rerun and fresh-run isolation are demonstrated. Do not claim unexecuted builds succeeded. |
| A15 | Machine graph, Mermaid, registry and process order agree; all Phase 1 statuses and resume points are consistent in CLI, files and Dagster. |
| A16 | Acceptance report lists PASS/FAIL/BLOCKED per requirement, exact tested revision and limitations. Only all required PASS results permit Phase 1 ACCEPTED. |

## Acceptance and documentation closeout

Do not self-declare acceptance because code exists or the UI starts. Store the evidence-backed
acceptance report with its run. Once A01-A16 pass, record Phase 1 acceptance and update README,
intake config/prompt, initiation/recovery guidance, artifacts policy, staging examples, runbook,
registry role/persona assignments, implementation plan, TODO, and the maintained Mermaid flow.
Update obsolete shared-scratch examples for new runs and retain clearly labeled legacy examples.
Keep actual implementation status distinct from future design. If a gate fails, document the
failure and next command; retain all attempts and do not advance dependent engagement work.

Deliver the implementation, tests, run-scoped vetting/acceptance evidence, reproducible local
startup/stop/resume commands, and the revised documentation. Do not launch a full security review
or unbounded scanner run merely to test intake.
