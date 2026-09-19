# Phase 1 acceptance

**ACCEPTED on 2026-09-19: A01-A16 PASS.** Qualification is a Codex self-review, not an independent review.

Subsequent change: the normal CLI now submits to the Dagster service, and configuration resolution
is an explicit fourth op. See [Dagster launcher verification](dagster-launching.md#verification)
for the follow-up's exact code identity, 40 host/44 Linux tests and actual service-launch evidence.
The original A01-A16 baseline and its hashes below remain preserved unchanged.

The later [Dagster workflow migration](dagster-workflow.md) adds queued engagement concurrency,
parallel preparation, a validated join and branch recovery. Its separate qualification records
the migration's tested identity and evidence; it does not claim downstream scanners are implemented.

The [recorded acceptance report](../appsec-review-process/runs/20260919T104300Z-ba7b4c/data/acceptance/q-eeb8b07a/acceptance.md)
and [machine-readable evidence](../appsec-review-process/runs/20260919T104300Z-ba7b4c/data/acceptance/q-eeb8b07a/acceptance.json)
contain each gate's commands, exit codes, artifact paths, hashes and resume command. Evidence is
ignored local run data; these links require the qualification workspace or its preserved run archive.
Earlier unsuccessful qualification batches remain preserved and are not acceptance evidence.

Tested code is base revision `0228e2182ce0eba51950931d9b57c010da571022` plus the exact working-file
hashes in [tested-identity.json](../appsec-review-process/runs/20260919T104300Z-ba7b4c/data/acceptance/q-eeb8b07a/tested-identity.json).
The implementation was unchanged during qualification. The final
[prompt review matrix](../appsec-review-process/runs/20260919T104300Z-ba7b4c/data/acceptance/q-eeb8b07a/prompt-vetting.json)
records the prompt hash, every nonblank requirement line, coverage and no unresolved blockers.

| Gates | Verified behavior |
|---|---|
| A01-A03 | Current prompt vetted; four repo-owned Dagster services healthy; persistent history and data; 66 registry records validated. |
| A04-A06 | Native, non-native, IaC and mixed intake; initial versus post-pregather validation; run ownership and path containment. |
| A07-A10 | Validated reuse, immutable forced attempts, freshness, locks, crash recovery, atomic publication and explicit blocking dependencies. |
| A11-A13 | Separate large streams, failure/cancellation propagation, child cleanup, logging failures, bounded retry and explicit legacy compatibility. |
| A14-A16 | Bounded Freeciv21 intake/reuse/isolation; graph and resume consistency; evidence-backed acceptance with exact code identity. |

All 36 behavioral tests passed on Windows and Linux (72 test executions). Actual Dagster runs
demonstrated fresh intake, same-run reuse, second-run isolation and pre-validation failure blocking.
The webserver's GraphQL graph exposed the pre/work/post dependencies; this was an API verification,
not a manual browser inspection. Restart preserved history and accepted artifact hashes. The four
stopped legacy containers, their state and mounts matched the original snapshot.

Freeciv21 source revision was `0ce1c60acf1140d6c5c5a5cd6bef2507bd072319`, with 6,210 inventoried
paths. Intake recorded the native CMake plan, source hashes, whole-repository scope and platform
link caveats. No target build, scanner, full security review or LLM was executed. Partition discovery,
specialist collection and subsequent lanes remain planned; new-run downstream dispatch is blocked.

Run locks are bound to one executor OS. Keep source quiescent: boundary hashing cannot detect a
transient edit reverted between checks. Recovery is explicit, with one attempt per invocation.
Run evidence and logs belong under `runs/<run_id>/data/`; persistent Dagster service metadata and
compute logs use dedicated project volumes.

Use the [operations guide](phase-1-operations.md) for staging, execution, reuse, recovery and legacy
imports. The [job flow](engagement-job-flow.md) links the checked machine graph and Mermaid.
Documentation closeout hashes are recorded separately in the qualification's
`documentation-closeout.json`; documentation updates do not alter the tested implementation.
