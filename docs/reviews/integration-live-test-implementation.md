# Bounded integration and live acceptance

Implementation record for the approved integration/live coverage plan, based on `fcac4306`.
The original audits and approval plan are retained in the coordinating session's Library.

## Shared decisions

1. Acceptance state lives only under a unique `test/tmp/acceptance/<invocation>/<lane>/`.
   Fixture runs, admission ledgers, caches and metrics must never use production `runs/`.
   Redirected scratch directories are rejected.
2. Reuse production `PipelineLog`, `EventLog` and operation spans for telemetry. The driver
   stream, fixture job streams, results and elapsed/resource metrics remain test-owned.
   Acceptance uses an explicit namespace, not production metrics destinations.
3. Each lane declares exact selections, prerequisites, per-case/suite deadlines and at most
   two workers. Missing required coverage is failure, not successful skipped acceptance.
4. Hermetic lanes may run alongside reviews: no production service commands, target access,
   production ledger/cache mutation, shared Docker cleanup or automatic acquisition.
   Optional real-tool lanes need private mounts/state, explicit capability selection and
   resource limits. They never restart the review stack.
5. Timing claims require actual timed lane executions with commit, result, prerequisites,
   cleanup and metrics artifacts. Targets are initially unmeasured, not guarantees.
6. External inference, cold builds and native commissioning remain separately authorized.
   Unavailable features/platforms retain named deferrals rather than fabricated coverage.
7. Agent chunks import `appsec_review.acceptance.lanes` without editing its shared contract.
   The coordinator owns integration and changes to this contract.

## Partition and verification

The shared contract is implemented first. Isolated agents then own runner/telemetry,
authentic PoC/oracle seams, and process/review integration. Following chunks cover signal
jobs and tool/graph boundaries. No agent pushes or changes production host state.

Per-lane measurements, merged commits, reconciliations and outstanding host-dependent
obligations are recorded here as chunks arrive. No passing lane or runtime claim is made
by this initial contract.

## Initial measured slices

The shared-contract tests passed three portable cases in 2.04 seconds (4.47 seconds wall);
the actual directory-symlink case was unavailable without Windows symlink privileges.
It is not counted as demonstrated symlink coverage.

The coordinator added an accepted signal-job slice: real intake/catalog, artifact indexing,
all four coverage formats, populated profile indexing and immutable publication. Recorded
build receipts replace the external compiler boundary. A companion case mutates a profile
and requires `ProfileIntegrityError`, no accepted publication, and a production-schema
failure event identifying `normalize.profile_data`.

The two signal cases plus the existing mixed-language artifact-index regression passed:
3 tests in 116.19 seconds, 118.10 seconds including interpreter startup, under a real
240-second subprocess watchdog. The signal cases individually assert a 120-second limit;
the bounded runner adds enforced per-case deadlines when integrated. Fixture job logs and
driver operation spans remain beneath their own `test/tmp/acceptance/` invocation roots.

An existing broad four-package review-to-report baseline did not finish in several minutes
and its owned process tree was stopped. It is not a passing result or a quick-lane candidate
without reduction. No production service, ledger, target, cache or metrics path was changed.
