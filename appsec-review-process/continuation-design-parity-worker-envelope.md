# Continuation Prompt — Design Parity Workstream B, Batch 9

Continue the executable Mythos design-parity backlog from the Workstream B Batch 8 checkpoint
completed on 2026-09-19. Preserve unrelated work. Read `AGENTS.md`, the process reader skill, and
the current authoritative docs before editing.

## Completed checkpoint

Workstream B Batch 8 is complete within the requested boundary:

- `deterministic_child.py` defines `appsec-review/deterministic-child/1.0` for one explicit
  absolute executable and fixed argv prefix. It accepts no shell string, rejects known shell
  executables, requires an explicit environment and run-owned log root, and caps each configured
  retained stream at 16 MiB.
- The runner drains stdout and stderr concurrently while retaining only the caller's bounded byte
  limits. Its durable metadata records observed, written, and dropped byte counts and whether each
  stream was truncated.
- Timeout, cooperative cancellation, process exit/signal, startup failure, stream logging failure,
  and wall duration are explicit. The Windows Job Object or POSIX process session is closed on
  every exit path, including after the direct child exits, so surviving descendants are killed.
- `KeyboardInterrupt` and `SystemExit` are persisted and then re-raised with their original type;
  the existing lifecycle coordinator therefore retains its `CANCELED` mapping.
- `02-ossf-scorecard` is the only adopter. Its immutable input fingerprint now pins the child
  contract, one-MiB stdout/stderr limits, child runner, process gate, and process-tree code.
- Supplied `02-repository-partition-discovery` has no child process and was not routed through this
  adapter. No other worker was migrated.

## Exact Batch 8 files

Batch 8 changed exactly these 10 paths. Eight were already inside the Batch 7 boundary and two are
new paths:

- `appsec-review-process/TODO.md`
- `appsec-review-process/continuation-design-parity-worker-envelope.md`
- `appsec-review-process/deterministic_child.py` (new)
- `appsec-review-process/ossf_scorecard.py`
- `appsec-review-process/qualify_worker_adoption.py`
- `appsec-review-process/tests/test_deterministic_child.py` (new)
- `appsec-review-process/tests/test_ossf_scorecard.py`
- `docs/design-parity-completion-plan.md`
- `docs/run-data-and-job-execution.md`
- `docs/worker-result-envelope.md`

The dirty-worktree boundary is exactly 45 paths. Do not reset, clean, stash, checkout, or broadly
rewrite any of them. Preserve later unrelated changes.

## Qualification completed

- Windows focused tests: 77 passed — the Batch 7 set of 71 plus six deterministic-child cases.
- Linux focused tests: the same 77 passed in the code-server with
  `PYTHONDONTWRITEBYTECODE=1`.
- The seven Linux Dagster repository/registration tests passed.
- Deterministic-child tests cover fixed-prefix/shell rejection, simultaneous 2-MiB stdout/stderr
  pressure with 32-KiB retained limits, timeout and cancellation descendant cleanup, abnormal child
  loss, injected log-write failure, and persisted `KeyboardInterrupt` propagation.
- `python -B -m py_compile` passed for the child runner, Scorecard worker, qualification script,
  and focused tests.
- `python -B appsec-review-process/validate_design_parity.py` — PASS, 42 jobs / 15 capabilities.
- `python -B appsec-review-process/qualify_phase1.py --check-contracts` — PASS,
  83 registry records / 42 graph jobs / 15 parity capabilities.
- `git diff --check` — PASS; Windows line-ending conversion warnings remain non-failures.
- Live qualification owner run remains `20260919T205313Z-409a32`.
- Batch 8 live engagement runs: `batch8-scorecard-d0c19ecb1c` and
  `batch8-partition-d8a7c4258e`.
- Batch 8 Dagster run IDs, in order:
  `ace81c8e-e3e3-4ea4-b24d-d2929215636d`,
  `1c1dbb19-76bb-4824-9dc1-f1ebb3e1c343`,
  `7a68ed60-b43c-41fa-bb88-a49bb813bb83`,
  `794510d5-43b1-4aa4-b50b-bc09fb41e2f6`,
  `dc4073b0-075c-4de2-9cbf-a7bf3b2f10c1`,
  `584fb3df-45cb-4b91-8d8b-06af521611f0`,
  `87f5ee0d-cbeb-416d-989a-de77c12b7364`,
  `86695ab4-3865-465e-bcff-681c98c2ad18`, and
  `c6a3b778-5430-4ca4-8c7c-e5d06e269483`.
- Batch 8 attempts: Scorecard `6a032f771f9d4f30880d98b3e7bae9fd`; partition initial
  `4a6460056e464e6f92858179bd592ee4`; deliberately interrupted
  `531c75d2e1ac45ebab01664dfe40e000`; post-interruption
  `980a3e85675b4986b8ad86d9a64a84d8`; invalid newer
  `87f4d89efca641c8a4a31366e4989aac`; recovered fresh
  `a5d2a3c24e1847c79169d865a195bdb0`.
- The live Scorecard attempt executed `/usr/local/bin/python3.12 -B
  /opt/process/ossf_scorecard.py worker ...`, returned zero, retained 53 stdout bytes and zero
  stderr bytes under one-MiB limits, and published a common current envelope.
- Authoritative ignored evidence:
  `runs/20260919T205313Z-409a32/data/qualification/worker-adoption-dc8cd2ba/report.json`;
  SHA-256 `d700c15a4a4419262903b26d82489357ebd8e86d2cf5510cb139095463e5f853`.
  The report pins the child runner, process-tree/gate implementation, qualification script,
  focused tests, lifecycle coordinator, handoff, validator, workers, contracts, and schemas.

## Known discrepancies and boundaries

- The child runner is an execution sub-contract, not an arbitrary worker controller. It does not
  construct payloads, interpret contracts, supervise containers, assign resource pools, or publish
  worker results.
- The explicit cancellation event produces a canceled diagnostic result for its caller to map;
  `KeyboardInterrupt`/`SystemExit` propagate directly. Abrupt parent loss relies on the inherited
  Windows Job Object or POSIX process-gate watchdog. The live API request is too short for stable
  service-level cancellation injection, so cancellation/tree faults are cross-platform focused
  tests rather than live Dagster faults.
- Bounded retention applies to stdout and stderr. `events.jsonl` and `command.json` contain bounded
  per-run metadata, while worker output artifacts retain their own contract-specific limits.
- The success transition remains fail-closed but spans individually atomic attempt-status,
  result-envelope, and accepted-pointer replacements under the common per-job lock. Recovery is
  explicit for the durable-envelope/`PENDING` boundary; it is not a multi-file transaction.
- If terminal recording itself fails, the coordinator annotates and re-raises the original callback
  exception. Durable evidence failure therefore remains visible but cannot replace the original
  Dagster failure/cancellation type.
- Historical attempts and handoffs were not rewritten. Intake, evidence index, SARIF, build
  workers, developer discovery, and all other lifecycle jobs retain their previous formats.
- Pinned-container, persona, pool-coordinator, and join/controller adapters remain unsupported.
  Resource pools, persona fan-out, pool waiters/mergers, claim-ledger loops, standards workers, and
  Workstream G decisions remain out of scope.

## Next bounded batch

A reasonable Batch 9 is one separate deterministic-worker adoption for
`10-critical-findings-sarif`:

1. Preserve its fixed-input format-transform semantics while adopting the common lifecycle,
   terminal envelope, publication/reuse boundary, and deterministic-child contract.
2. Define the exact consumer edge and contract-specific validator before changing publication.
3. Re-run its existing semantic-parity fixture plus the common lifecycle and child fault cases on
   Windows and Linux.
4. Qualify one bounded live Dagster success, reuse, newer-failure blocking, and recovery sequence if
   the worker's executable identities change.
5. Stop after that one worker. Do not adopt developer discovery or implement pinned containers,
   persona dispatch, resource pools, waiters/mergers, claim-ledger loops, standards workers, or
   Workstream G decisions in that batch.

If SARIF cannot preserve its strict fixed-input/finding-validation boundary under the common
envelope, record the gap and leave it on its existing implementation rather than broadening the
batch.

## Batch 9 result — `10-critical-findings-sarif` common-runtime adoption

Implemented on branch `claude/b09-sarif-common-runtime` within the requested boundary.

- `critical_findings_sarif.py` keeps its strict fixed-input Markdown-to-SARIF semantics unchanged
  and its standalone Dagster job unbound from synthesis. Only the execution wrapper moved: it now
  calls `coordinate_worker_lifecycle`, allocates and recovers attempts through
  `publish_job_output.py`, persists the v1.0 `result.json` envelope, publishes through the
  read-only validator, and executes its bounded child under
  `appsec-review/deterministic-child/1.0` with one-MiB retained stdout/stderr limits.
- The immutable input fingerprint now pins the output contract, worker kind, the child contract and
  stream limits, and the hashes of `deterministic_child.py`, `execution_state.py`,
  `process_gate.py`, `publish_job_output.py`, `validate_job_output.py`, `worker_result.py`, the job
  template and the output contract. The worker's executable identity therefore changed.
- `registry/output-contracts/critical-findings-sarif.json` declares
  `outputs/critical-findings.sarif` as its single result artifact against the new
  `schemas/critical-findings-sarif.schema.json`. It deliberately declares no `claim_class`: the
  three trusted claim-class policies forbid finding/severity promotion, which is not a meaningful
  surface for a transform whose whole purpose is republishing an upstream verification decision.
  The strict fixed-input boundary, not a claim class, is what keeps it from verifying anything.
- Pre-migration accepted pointers remain integrity-readable through `_validate_legacy`; they are
  never reused as current. No historical attempt was rewritten.
- `publish_job_output.py`, `validate_job_output.py`, `worker_result.py` and
  `deterministic_child.py` are unchanged except for one docstring count in the coordinator. No
  generic defect was found in them.
- `qualify_sarif_adoption.py` is the narrowly separate live sequence: prepare, success, reuse,
  pending-publication recovery, interrupted allocation, invalid newer attempt, and recovery.

### Batch 9 files

- `appsec-review-process/critical_findings_sarif.py`
- `appsec-review-process/tests/test_critical_findings_sarif.py`
- `appsec-review-process/qualify_sarif_adoption.py` (new)
- `appsec-review-process/registry/output-contracts/critical-findings-sarif.json`
- `schemas/critical-findings-sarif.schema.json` (new)
- `appsec-review-process/publish_job_output.py` (docstring only)
- `appsec-review-process/TODO.md`
- `appsec-review-process/continuation-design-parity-worker-envelope.md`
- `docs/critical-findings-sarif-job.md`
- `docs/worker-result-envelope.md`
- `docs/run-data-and-job-execution.md`
- `docs/design-parity-completion-plan.md`

### Batch 9 qualification state

- Linux focused tests with `PYTHONDONTWRITEBYTECODE=1`: 13 SARIF cases, 19 worker-adoption cases,
  and 6 deterministic-child cases passed.
- `python -B -m py_compile` passed for every changed Python file.
- `python -B appsec-review-process/validate_design_parity.py` — PASS, 42 jobs / 15 capabilities.
- `python -B appsec-review-process/qualify_phase1.py --check-contracts` — PASS, 83 registry
  records / 42 graph jobs / 15 parity capabilities.
- `git diff --check` — PASS.
- **Not performed, not faked:** the bounded live Dagster success/reuse/newer-failure/recovery
  sequence and the Windows focused run. The implementation environment had no Docker daemon, no
  Dagster service and no `/targets`, so no run IDs, attempt IDs, evidence hashes or success files
  exist for them. B09 stays open until a host with the stack runs
  `python -B appsec-review-process/qualify_sarif_adoption.py --run-id <owner_run_id>` after
  confirming no Dagster run is active, and records the report path and SHA-256 under the owning
  ignored run.
