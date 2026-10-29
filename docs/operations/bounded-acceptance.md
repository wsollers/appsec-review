# Bounded integration acceptance

This is the operator guide for the explicit acceptance profiles exposed by `run-tests`.
For the producer/consumer design, see [bounded acceptance architecture](../architecture/bounded-acceptance.md).
For revision-specific measurements and remaining work, see the
[implementation record](../reviews/integration-live-test-implementation.md).
These profiles are separate from the existing stepwise corpus and deployed-review acceptance tools.

**Current status: not green.** Producer detachment is implemented and the complete CI chain
reaches a passing private oracle consumer, but review still has one stage deadline failure
and two blocked consumers; signals passed only with two opted-in workers. See
[current measured status](#current-staged-status-not-green), not historical profile passes,
before assessing coverage or budgets.

## What a passing profile means

A profile selects connected application behavior, with exact pytest nodes declared in
[`tests/acceptance_inventory.json`](../../tests/acceptance_inventory.json). Real producers,
validators, accepted handoffs and consumers run; external model/compiler/feed boundaries may
be scripted or recorded as declared by the obligation. This is stronger than independently
passing mocked units, but does not prove that the substituted service or tool currently works.

The inventory records obligations, gap IDs, boundaries, variants, prerequisites, substitutions,
deferrals and node selections. Its catalog snapshots detect added/removed jobs, MCP tools and
provider families/transports. **Catalog membership is not execution evidence.** An obligation
is demonstrated only by a successful recorded execution of all its selected cases on the
identified revision. Deferred features remain unverified.

Acceptance is always strict. Unlike legacy `run-tests` suites, it does not forgive entries in
`scripts/known-failures.txt`. Missing prerequisites, incomplete/unexpected collection, empty
collection, duplicate collected nodes, failure, skip, xfail, xpass, interruption, timeout,
unexecuted requirements and unconfirmed process cleanup cannot make a profile pass.
Parameterized selections must collect and pass every matching parameter case.

## Select and inspect a profile

Use the checkout's own Python 3.11+ virtual environment with its test dependencies installed.
Acceptance refuses a virtual environment borrowed from another checkout. Process cases also
require the pinned Dagster host dependencies, including when those cases are selected by `quick`.
Follow repository host policy: use Linux or a Linux-filesystem WSL checkout by default; native
Windows execution requires explicit permission.

```powershell
.\scripts\run-tests.ps1 -Acceptance quick -Workers 1 -DryRun
.\scripts\run-tests.ps1 -Acceptance signals -Workers 1
.\scripts\run-tests.ps1 -Acceptance review -Workers 1
```

```bash
scripts/run-tests.sh --acceptance quick --workers 1 --dry-run
scripts/run-tests.sh --acceptance signals --workers 1
scripts/run-tests.sh --acceptance review --workers 1
```

Remove `-DryRun` / `--dry-run` to execute the inspected selection. Dry run prints JSON containing
`profile`, `nodes`, `workers`, `deadline_seconds`, `case_deadline_seconds`, `strict` and
`implemented`; it neither establishes prerequisite availability nor demonstrates coverage.

| Hermetic profile | Connected selection | Suite cap |
| --- | --- | --- |
| `quick` | Representative harness/isolation, signals/dependencies, graph/helper, process recovery/MCP, controls/TLS, authentic review and current-report oracle obligations | 720 s |
| `signals` | Real catalog/artifact/coverage/profile flows, signal-integrity negative and dependency/exposure/cache flows | 240 s |
| `graphs` | Source-resolving recorded graph consumers, same-row semantic matching and real local SQLite helper CLI, including bad inputs | 180 s |
| `process` | Actual local/Dagster workers, configuration/refusal, failure/recovery, all submission barriers, MCP integrity, record/replay and failure sensor | 480 s |
| `process-linux` | Linux guardian/process-tree and Unix listener/peer-credential obligations | 180 s |
| `process-windows` | Actual PowerShell dispatch with an invocation-owned compiled transport | 60 s |
| `controls` | Explicit OWASP qualification with document/catalog context and accepted Workbench retrieval; loopback HTTPS, including negative matrix | 240 s |
| `review` | 13 core staged cases: native prepare/review/PoC and empty/corrupt consumers; CI prepare/review/gate/report and representative current-report reader | 600 s |
| `review-exhaustive` | 24 staged cases retaining full current-report integrity, same-length tampering, benign/blocked and core vectors; uncalibrated | 600 s |
| `consumers` | Real triage/admission, next-round referral repair/deduplication/convergence and accepted report HTML/LaTeX rendering | 360 s |

This table summarizes the inventory, not a promise that every profile has passed. `quick` is
representative, not the union of all hermetic profiles. Inventory revision `09cbf227` keeps the
negative matrices in explicit full profiles instead of removing variants: signal integrity in
`signals`, helper bad inputs/graph-matcher negatives in `graphs`, TLS negatives in `controls`,
and submission barriers/MCP integrity/invalid process profile/record-replay-sensor in `process`.
Empty/corrupt variants remain in core `review`; full integrity and benign/blocked variants
remain in `review-exhaustive`, not removed to force a pass. The three consumer nodes are
enrolled in `consumers`, not `quick`. OS-specific cases have their own selections.
Inspect the inventory at the commit under test for the exact selection; collection supplies
the actual case count, not a fixed count copied from an older quick result. At `58387690`,
quick has 35 selectors resolving to 38 cases; staged producer phases count in that denominator.

The selectable `tools`, `deployed`, `provider`, `guidance`, `codeql-warm` and `native` profiles
currently have no executable obligations. Actual invocation fails with `profile_not_implemented`;
dry run reports `implemented: false`. Their declared prerequisites and ceilings are reservation
metadata, not working live lanes. They do not download tools, warm CodeQL, fall back to a live
provider, discover credentials or authorize deployment/native access.

## Deadlines and concurrency

- Serial execution is the default and the recommended calibration mode. `--workers 2`
  (`-Workers 2`) is the maximum; it schedules isolated case subprocesses, not `pytest -n auto`.
- An ordinary case has a 60-second hard cap. Explicit obligation exceptions are 15 seconds for
  loopback feed transport, 30 seconds for the helper CLI, and 120 seconds for declared
  signals/dependency, controls, review/oracle, consumer and process-startup/replay obligations.
  `process` has a 120-second profile case ceiling to account for current-main startup and
  cleanup; obligations still marked 60 seconds retain that cap. Profile-level 120-second
  maxima do not silently grant every case that allowance.
- `quick` targets less than ten minutes, with a hard twelve-minute suite ceiling. This is a
  design target pending final integrated public-driver calibration, not an achieved benchmark.
- `--deadline` / `-Deadline` and `--case-deadline` / `-CaseDeadline` can only lower declared
  ceilings. Three seconds are reserved **inside** a supervised process deadline for cleanup.
  Interpreter/plugin startup, fixtures, custody prechecks/copy/checkpoint/seal, case execution
  and owned-process cleanup count toward its cap; collection and driver setup also consume
  the suite budget. Staging is not unmetered setup or an increased cap.
- Legacy suite arguments, arbitrary pytest selections, `--parallel` and `--background` cannot
  be combined with acceptance. Do not bypass the public driver to claim its budget passed.

Storage/process isolation allows hermetic acceptance alongside an ongoing review without using
its run storage or restarting services. It does **not** guarantee zero shared CPU, memory, disk
or I/O contention. Check host load and coordinate before running; use serial execution and
report load-related limitations rather than promising production performance isolation.

## Staged producer/reader process

The inventory declares dependency-ready producer phases, not a preaccepted output cache.
Native-positive runs prepare -> review -> PoC; native-empty ends after review; CI variants
run prepare -> review -> gate -> report. Each phase runs real application jobs at the
scripted external boundary. A failed/incomplete predecessor leaves descendants explicitly
blocked and unexecuted; they still fail profile adequacy.

Prepare declares frozen target/configuration/overlay/fixture inputs. The supervisor captures
their actual bytes and verifies those inputs plus predecessor checkpoints around subsequent
phases. Only after a successful producer exits with confirmed owned cleanup can the
supervisor checkpoint its tree; the terminal phase publishes an invocation-specific seal
outside the producer tree. Schema **`appsec-review/acceptance-invocation-seed/1`** is distinct
from the operator `appsec-review/acceptance-seed/1` format; neither is interchangeable.

Consumers verify the exact invocation/variant/commit/source/tree binding and receive fresh
ordinary private copies with byte/path/hash/mode verification and materialization receipts.
Only reader run/runs loci relocate: authenticated source/configuration paths remain frozen.
Mutation vectors get independent copies and production validation scopes, not rewritten
accepted bytes or cached proof shared across attempts.

Consumer execution writes its own `consumer-telemetry/<uuid>/telemetry-origin.json`
sidecar (`appsec-review/acceptance-consumer-telemetry/1`). It names current event/metric paths
and labels retained copied producer telemetry `execution_evidence: false`. Retained producer
history must not be counted as freshly executed consumer work.

Custody still requires bounded ordinary files with `st_nlink == 1` for checkpoints, seals and
private copies. Implemented `detach_producer_outputs` requires successful kernel-owned cleanup,
accounts every device/inode/link-count group within one run's registered named/content-addressed
OUTPUTS, and verifies exact production bindings. External/unaccounted, unclassified, cross-run
and immutable groups fail. Exclusive copies are hashed, fsynced, mode-preserved and replaced;
strict ordinary snapshot and frozen-input checks then precede checkpoint/seal. There are no
retries or usable checkpoints/seals after failed, partial or deadline operations.

The receipt schema is `appsec-review/acceptance-producer-detachment/1`, with
`acceptance.stage.producer_publication` spans. The guard permits real mutable producer links,
not sealed/private-reader or immutable-input links. Only verified anonymous stdio PIPE
wrapping is distinguished from filesystem descriptor mutations: unresolved/off-root/immutable
filesystem writes still fail. The Windows completion todo remains open until the complete
timed review passes; partial Windows detachment/CI-reader proof is not that completion gate.

## Artifacts and telemetry

Each invocation creates only a unique
`test/tmp/acceptance/acceptance-<uuid>/<profile>/` workspace:

| Path below that workspace | Purpose |
| --- | --- |
| `owner.json` | Invocation, repository, lane and private runs-directory identity |
| `result.json` | Strict suite result, coverage accounting, provenance, budgets and artifact references |
| `driver/` | Production-format `PipelineLog`, `events.jsonl` and acceptance operation spans |
| `runs/` | Real fixture job attempts, accepted handoffs, indices, logs and other run-owned evidence |
| `processes/collection/` | Collection log, pytest outcome, exit/gate records and supervisor result |
| `processes/case-<ordinal>/`, `p/case-<ordinal>/` | Ordinary/staged process records and private cache/base-temp; staged HOME/TEMP/DAGSTER_HOME are process-specific |
| `source-identities.json` | Exact staged Python/helper, schema, pipeline, selected/static/configuration byte identities |
| `stages/<variant>/` | Invocation-owned authentic producer chain and frozen inputs |
| `custody/<variant>/` | Immutable-input receipts, predecessor checkpoints and terminal invocation seal |
| `custody/<variant>/case-<ordinal>.publication.json` | Verified producer OUTPUT detachment accounting, outcome and copy/replacement counts |
| `consumers/case-<ordinal>/` and sibling `.custody.json` | Fresh verified reader copy and materialization receipt |
| `consumers/.../consumer-telemetry/<uuid>/` | Current consumer streams and `telemetry-origin.json`; copied producer history stays separate |
| `home/`, `temporary/`, `dagster/` | Private HOME/profile, TEMP/TMP/TMPDIR and DAGSTER_HOME |

The public command prints `acceptance: PASSED|FAILED; <N> cases; <seconds>s` and the path to
`result.json`. Exit 0 requires all selected obligations to pass with confirmed cleanup;
execution failures return 1, while invalid options/profile/deadline selections return 2.

`appsec-review/acceptance-result/1` records the tested commit, dirty-working-tree flag,
inventory SHA-256, source-file SHA-256 identities, Python versions, selected/collected nodes,
selected/executed/failed/skipped/blocked/unexecuted obligations, executed/unexecuted nodes,
prerequisites, case outcomes, cleanup
and `coverage_status`. From parent correction `19c7c000`, source identities also record the
two allowed pinned static taxonomy inputs. Staged provenance now includes all Python under
`src/`, the local helper import closure, selected tests/driver/configuration, and every file
under `docs/schemas/` and `pipeline/`, checked before/after phases and at suite completion.
This is byte provenance for those declared inputs, not every external dependency or arbitrary
host state. A dirty result must not be described as testing only the named commit.

From `09cbf227`, each supervised process also records `static_input_identities`. A mismatch
against the suite's source identities fails that case as `static_reference_changed_during_suite`,
even when pytest otherwise succeeded. Hash pinning is checked at the documented validation
boundaries; it is not a hostile-code or arbitrary-host-mutation guarantee.

Each supervised process retains `pytest.log`, `pytest.json` and `supervisor.json`. Preserve
these alongside the result when reporting a failure; read the named node's log instead of
substituting an unrelated green unit result. Cases retain setup/call/teardown phase durations;
the supervisor records elapsed time and cleanup duration. The suite's
`setup_duration_seconds`, when present, ends before supervised collection, not after all fixture
setup. If a prior measurement did not capture setup time, report it as unavailable.

Telemetry reuses production `PipelineLog`, `EventLog` and `operation_span` formats, but **only**
under these test-owned roots, with acceptance namespace/invocation correlation. It is not
copied into production metrics destinations. Operation spans report wall duration and
`os.times()` process CPU deltas. Child CPU and span-attributable peak RSS remain null with
explicit reasons; Linux `/proc/self/io` supplies I/O deltas where available, otherwise I/O is
null with `proc_io_unavailable`. Missing or interrupted measurements keep their unavailable
reason; never reinterpret nulls as zero resource consumption.

## Isolation, supervision and fixture discipline

The driver strips inherited deployment selection, credentials, SDK endpoints and pytest/plugin
overrides, and supplies private home/temp/Dagster paths. The plugin guards Python file access,
mutation, network use and child execution: no repository `targets/`, production `runs/` or
mutable production `data/`, no external network (only loopback/owned local sockets), no
production service commands, and no shared Docker cleanup. Parent correction `19c7c000`
permits reads of exactly `data/reference/taxonomy/vocabulary.json` and
`data/reference/taxonomy/crosswalk.json`, pinned by the supervisor and hash-validated before
guard installation. It permits no mutation of those files and no other protected-data access.
Descriptor flags `O_TRUNC` and `O_APPEND`, as well as writable/create modes, count as mutation.
Redirected scratch roots and paths escaping the invocation are rejected. The guard catches
accidental regressions; it is **not a hostile-code sandbox** or proof that arbitrary native
code cannot access the host.

The supervisor opens the execution gate only after ownership is established. Windows uses a
private kill-on-close Job Object without breakaway. Linux uses a subreaper with verified
process identities and descendant cleanup, including adopted descendants; this path and the
Linux guardian/peer-credential cases have not been executed in the Windows evidence recorded
here. A case that exits with leftover descendants fails even if the assertions passed.
Cleanup kills only the invocation-owned tree, never processes selected by executable name.

For new fixtures:

1. Use `LaneWorkspace` and private `runs_dir`; nested acceptance helpers inherit the outer root.
2. Keep child working directories short on Windows, but still inside the owned root. Deep nested
   fixture paths can exceed Win32/process-tool path limits.
3. Do not launch child `git`. The supervisor resolves HEAD before the guarded test process and
   exports `APPSEC_ACCEPTANCE_TESTED_COMMIT`; use it rather than widening the executable guard.
4. Use application producers and certified validators at real joins. Write framework
   `handoff/2` fixture envelopes through `tests.handoff_fixture.write_fixture_handoff`; do not
   replace the current review `/3` or gate/report `/2` domain contracts to make an integration pass.
   Freeze the actual configuration before synthetic upstream handoffs, and bind their
   explicitly claimed upstream digest. Declare tiny selections such as one lead package and
   no hunt in the test configuration, rather than weakening validation.
5. Add exact inventory nodes, budgets, substitutions and named deferrals. Preserve substantive
   existing unit/job coverage; deleting failing tests does not establish integration adequacy.
6. Give each oracle evaluation a fresh production `validation_scope`, especially after
   restoring or tampering with accepted bytes. Batch unchanged negative expected identities
   in a single evaluation where appropriate; do not cache validation across mutations.

## Remaining commissioning

Current results do not authorize or demonstrate actual WSL dispatch, native containers/daemon
compatibility, provider access, cold builds, current CodeQL exports, Lua/native-variant
compatibility or a full language/runtime matrix. The unknown original producer of a recorded
feed is not a real live-computation claim. The application has real OWASP assessment mode;
the bounded controls case deliberately selects `QUALIFICATION`, disables inference and pins
five tiny abridged catalogs. It exercises authentic document/catalog context and accepted
Workbench retrieval, with non-lead-eligible qualification-only rows, not genuine assessment.
Genuine assessment, positive assessment/source binding, precomputed control facts and the
review join remain unverified. The pinned Dagster run object lacks `create_timestamp`, so
queue-delay timing is unavailable.

## Historical pre-staging evidence

At `06a4ea6c`, three triage/referral/presentation nodes passed through the real
`supervised_pytest` and `tests.acceptance_plugin` boundary in 225.664 seconds, with all owned
Windows trees cleaned up. Each used a measured 120-second real-job exception and the serial
group had a 360-second cap. This was an exact-node supervised execution, **not** a named
inventory/profile CLI run. Revision `09cbf227` enrolled those nodes in `consumers`; the later
actual named public pass at `1ff86556` is recorded below. The earlier exact-node result is
historical, not a substitute for that named proof or for final integrated calibration.

These cases prove bounded triage/admission, next-round referral deduplication/foreign-anchor
repair/convergence and authentic accepted gate/report HTML/LaTeX rendering. They do not prove
specialist dispatch/resolution, referral/active-claim saturation, cross-package/lane referrals,
actual concurrent review execution, or stale/historical renderer selection and tamper
rejection. `unresolved_specialist_referral:ci_cd_pipeline` remains a gap rather than fabricated
specialist resolution. The implementation record retains exact nodes, commit, timings,
artifacts and these limitations; do not treat direct tests or guarded exact-node results as a
passing named public profile.

Pre-staging candidate/oracle follow-up `b72e79a9` passed the minimal native candidate case but
timed out the exhaustive current-report oracle before its fixture returned. No oracle
assertion was reached. This historical failure was not accepted report proof; intermediate
validated/completed job events cannot substitute for accepted final output.
A separate direct matrix check without the audit plugin also timed out after the report
fixture completed and oracle evaluation began. This is not merely guard overhead.
The current staged core CI oracle now passes with separately budgeted authentic producers.
That does not establish the full `review-exhaustive` matrix or a green `review`/`quick`;
splitting assertions alone is not evidence that every fresh public fixture fits.

## Current staged status: not green

At exact parent `d6042ab9c13e86c8045560bdebc09a68544d272a`:

- Public `scripts\run-tests.ps1 -Acceptance review -Workers 2` **failed** in 530.257 seconds
  under the 600-second suite cap: 10/13 passed, native-positive PoC timed out, candidate and
  corruption consumers were correctly blocked. Pytest passed that producer's assertions in
  54.28 seconds, but its total stage took 120.023 seconds and expired during final sealed-input
  postcheck; its seal was invalidated. Root:
  `test/tmp/acceptance/acceptance-a59d77fffc7447658af064fbb8ff67c9/review/`.
- Native-positive, native-empty and CI review detached 38 files each (114 total) with bytes,
  modes and bindings preserved. Native-empty's sealed private consumer passed in 56.403
  seconds. The actual CI prepare -> review -> gate -> report -> sealed private current-report
  oracle chain completed; its consumer passed in 101.245 seconds with reader-only relocation,
  fresh telemetry and no accepted hash/path/configuration rewrite.
- Public `process-windows` passed 1/1 in 17.898 seconds (60-second cap), one worker, at
  `acceptance-fd7907ac0051437987dbd4a07fc0987c/process-windows/` below `test/tmp/acceptance/`.
  This is actual PowerShell with a compiled owned WSL shim, **not actual WSL**. Earlier
  `992058ae` failed in 8.905 seconds on stdin PIPE classification; the source fix is disclosed,
  not a retry-to-green claim. Combined native Windows validation: 89 passed, one host skip,
  141.73 seconds.
- Other named public passes remain revision-scoped: graphs 22/22 in 57.756 seconds and
  controls 8/8 in 70.770 seconds at `f4a04b29`; consumers 3/3 in 111.330 seconds at `992058ae`;
  signals 3/3 in 145.353 seconds at `58387690`. These used two workers, met case caps and
  confirmed cleanup zero / no production services touched; they are not final-source warm
  proofs or serial-default signals proof.
- Repeated immutable verification currently hashes the entire mutable tree. Equivalent fresh
  immutable-subtree-only verification is assigned for optimization, not integrated in `d6042ab9`:
  no cap change, cross-call cache or omission of whole checkpoint/seal/detachment checks.
- Windows completion remains open; no full quick, exhaustive or three-warm proof exists.
  Incoming Linux commissioning units cannot collect on native Windows (`fcntl` absent);
  this is a separate host gap with no workaround. Parent docs/inventory validation had
  6 passes and one failure in 7.18 seconds: two pre-existing missing target README/project-
  matrix links in unchanged `build-environments-and-execution-capture.md`, not repaired here.
- Windows `WinError 5` remains unexplained: a bounded ten-transaction probe (4.055 seconds)
  did not explain it. Genuine assessment/source-bound review, Linux guardian, actual WSL,
  tool/provider/CodeQL/native compatibility, specialist/renderer-selection/saturation/cross-lane
  consumer cases and unselected record/replay/sensor variant matrices remain gaps.

No production runs/services were inspected or mutated. Path/process/metrics isolation is not
zero CPU/I/O contention. Default workers remain one, maximum two; all existing caps are
unchanged. Detachment is implemented with real Windows publication and CI-reader proof, but
the explicit Windows full-review completion todo remains open.

## Historical non-staged profile results

The documentation snapshot includes exact parent
`1ff865561cc79171d56e389ead1c961975234a11` and frozen main `a8883acc`. Evidence below is
still scoped to each tested revision, not retrospectively to every later merge.

- **Named process profile:** the actual
  `scripts\run-tests.ps1 -Acceptance process -Workers 1` passed 13/13 in 340.136 seconds at
  `16a520f4e70c8d1699dda7401a729d7c93515fe4`, with zero remaining owned processes.
  Result: `test/tmp/acceptance/acceptance-ef2e537e8e5d49c0bcda6a12522c41bc/process/result.json`.
  This is named-profile proof, unlike earlier nested/exact-node measurements; it does not
  include the Linux guardian/peer-credential requirements.
- **Named consumers profile:** the actual
  `scripts\run-tests.ps1 -Acceptance consumers -Workers 1` passed 3/3 in 207.438 seconds at
  `1ff865561cc79171d56e389ead1c961975234a11`. The public driver requires confirmed owned
  cleanup to pass. Result:
  `test/tmp/acceptance/acceptance-e809aa5c094a4ab8a620d07f602c6044/consumers/result.json`.
  This supersedes pending named-profile verification, not the remaining specialist,
  renderer-selection, saturation and cross-lane gaps. No production reviews were inspected
  or touched; it is not actual concurrent-production-review evidence.
- **Exact guarded dependency case:** at `1ff86556`, 1/1 passed in 83.9186626 seconds with
  cleanup zero, including both actual job attempts, cache reuse, immutable indices and exposure
  assertions. Its isolated root is
  `test/tmp/acceptance/acceptance-de13d4f4443446f7a0de7bc235d4e812/dependency-final-public/`.
  `outcome.json` retains the supervisor receipt and `verified-summary.json` discloses a
  wrapper-only error: the ad-hoc wrapper incorrectly expected supervisor outcome `passed`
  instead of successful `completed` and exited 1. The raw pytest pass (81.8 seconds) and
  supervisor receipt were validated without rerunning; neither the wrapper error nor the
  corrected interpretation is hidden.
- **Signals budget remains unproved:** separate signal-positive/corruption/dependency
  measurements total 102.625 + 56.574 + 83.919 = 243.118 seconds **before collection**,
  above the declared 240-second serial signals ceiling. This is a projection from separate
  runs, not an actual new integrated failure or a permitted deadline increase.
- **Overall not green:** quick remains red; the authentic oracle fixture still exhausts the
  117-second execution allowance before its matrix. Windows `WinError 5`, genuine assessment,
  and live/provider/native/Linux validation remain gaps. The process/consumers profile passes
  do not make quick, the full oracle matrix, serial signals scheduling or all consumer
  capabilities green.

At that historical checkpoint, planner `81ada94f` had produced only a read-only
`staged-authentic-producer/private-verified-materialization` proposal.
The producer/reader machinery is now integrated as described above; its remaining stage
deadline failure is not fixed by that historical proposal or by treating it as a validation-cache
shortcut or cap waiver. Output detachment is now implemented and partially Windows-proven;
the final timed review gate remains not green.
