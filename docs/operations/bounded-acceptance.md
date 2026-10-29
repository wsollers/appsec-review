# Bounded integration acceptance

This is the operator guide for the explicit acceptance profiles exposed by `run-tests`.
For the producer/consumer design, see [bounded acceptance architecture](../architecture/bounded-acceptance.md).
For revision-specific measurements and remaining work, see the
[implementation record](../reviews/integration-live-test-implementation.md).
These profiles are separate from the existing stepwise corpus and deployed-review acceptance tools.

**Current status: approved bounded exhaustive series qualified at `856300ca`.** All three
fresh sequential members passed: 35 executed cases / 31 unique, within every profile/case
cap, in 18 minutes 58.249 seconds wrapper wall time. This is not a monolithic
`review-exhaustive` pass, new-revision quick warm proof, or platform/provider-wide clearance.
See [qualified series](#qualified-series-at-856300ca) and
[revision-bound calibration](#current-measured-status) before assessing coverage or budgets.

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
| `review-report-integrity` | Four fresh CI-positive producer phases plus eight independent integrity vectors | 600 s |
| `review-outcomes` | Complete CI-benign and CI-blocked chains: four phases and one private consumer each | 600 s |
| `review-exhaustive` | 31 staged cases retaining every integrity/benign/blocked/core vector; monolithic selection is not qualified | 600 s |
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

### Approved bounded exhaustive series

The user selected **Approve bounded exhaustive series (Recommended)**. The following
selection contract is implemented and qualified at frozen
`856300cafdc1a4693608d24e93586cb88a7fb2bc`, including main `a31d4249`. Approval alone was not
proof: the first `086ded0a` attempt failed; the corrected-source results are recorded below.

| Required member | Approved selection | Cases | Suite cap |
| --- | --- | --- | --- |
| `review` | Existing native/core CI review selection, unchanged | 13 | 600 s |
| `review-report-integrity` | Fresh CI-positive prepare/review/gate/report plus eight independent integrity vectors | 12 | 600 s |
| `review-outcomes` | Complete CI-benign and CI-blocked chains: four producer/report phases and one private consumer each | 10 | 600 s |

Use the existing public PowerShell/Bash forms with each exact member as **sequential fresh
invocations**, not a new umbrella CLI or one enlarged profile. Record the actual chosen
order; do not run members concurrently. The qualified order was `review-report-integrity`,
`review-outcomes`, then `review`, each at `856300ca` with a fresh invocation. The failed
`086ded0a` attempt stopped after integrity; its unchanged retry was forbidden, not a way to
manufacture passing proof.
Each member permits at most two workers; the global default stays one.
The eight new integrity consumers have ordinary 60-second caps; producer/job phases retain
their existing declared 60/120-second caps and cleanup reserves. No API, custody, scheduler
or production behavior change is part of this approved selection.

The approved exhaustive-only node is
`tests/integration/test_current_report_integrity_cases.py::test_current_report_integrity_vector[ID]`,
with exactly these eight IDs:

- `identity-state-bucket`
- `missing-current`
- `orphan-hit`
- `report-tamper`
- `manifest-tamper`
- `finding-tamper`
- `handoff-tamper`
- `same-length-report-tamper`

All original vectors remain required. Replacing the one combined integrity case with eight
makes the monolithic `review-exhaustive` selection **31 cases**, not a series alias:
it retains its 600-second cap and remains **not qualified**. Its historical 24-case,
599.621-second failure is preserved below. Quick and core review nodes are unchanged.

The qualified series executed **35 cases across three fresh invocations / 31 unique cases** because
four CI-positive producer phases repeat. Each invocation must produce its own authenticated
seed; cross-invocation seed reuse is forbidden. Required series accounting identifies the
exact ordered members, frozen source/environment and each full source-identity closure,
distinct invocation IDs, selected/collected/executed cases, result paths and each final
`result.json` SHA-256. Retain per-member caps, outcomes, resources and cleanup plus measured
aggregate elapsed time and summed member durations. No member may disappear from the
aggregate or be satisfied by historical output.

The planning estimate was about 18–20 minutes, with three profile caps summing to 30 minutes.
The measured qualified wrapper took 18 minutes 58.249 seconds; this is three bounded profiles,
not a new 600-second exhaustive benchmark. Historical `a4ce5459` quick/portable passes remain
their original-revision proof, not new `856300ca` warm runs or portable-profile results.

### First series qualification: failed, not complete

At exact source `086ded0afdbc82abd1be6da3acaa8f4e3b3e9129`, actual public
`scripts\run-tests.ps1 -Acceptance review-report-integrity -Workers 2` **failed with 10/12
passing in 429.065 seconds**. `identity-state-bucket` and `orphan-hit` reached their ordinary
60-second case execution deadlines at **58.663 / 58.740 seconds**; all other six vectors and
four real producers passed. Receipt times below the total cap do not erase execution
timeouts/cleanup reserves. Owned cleanup confirmed zero survivors and
`production_services_touched=false`.

Evidence:
`test/tmp/acceptance/acceptance-82a8878f33e545cda8a45f596c4d6885/review-report-integrity/result.json`.
The series stopped on failure; outcomes and review did not run at that source. This is not
35 executed cases, a measured 18–20-minute aggregate or a complete/passing series. The
correction below changes only redundant fixture seed verification; it is not a new identity-
oracle batching change, cap increase or passing result.

### Corrected source and guard-preflight reuse

Exact source `856300cafdc1a4693608d24e93586cb88a7fb2bc` includes main `a31d4249` and fix
`1e0c6996`. The identity oracle was **already batched**. The two heavy fixtures redundantly
scanned the original seed after the same-process guard had freshly verified its seal and
the whole private copy, then installed the immutable-seed guard. The fix removes **only that
duplicate seed scan** (about 6.7–6.9 seconds), requiring matching completed guard preflight,
workspace and invocation. All driver/guard byte proofs and production validation remain.

Five persistent fail-closed guard-reuse unit cases were added in existing
`tests/test_acceptance_review_stages.py`. Combined focused validation passed 34 units in
12.75 seconds; eight exact integrity nodes collected in 1.77 seconds. Those focused results
were not substitutes for the subsequent public qualification. All eight vectors and
60-second ordinary caps remain unchanged.

### Qualified series at `856300ca`

All three public members ran sequentially at the same frozen source/environment with two
workers per member:

| Actual order/member | Result | Profile timer | Evidence root below `test/tmp/acceptance/` |
| --- | --- | --- | --- |
| 1. `review-report-integrity` | **12/12 passed** | 430.0222257 s | `acceptance-e2ef45f64cd4477bbbb51b7a299b562b/review-report-integrity/` |
| 2. `review-outcomes` | **10/10 passed** | 223.4540428 s | `acceptance-eaf48cbd258346b6a3cad0511175f475/review-outcomes/` |
| 3. `review` | **13/13 passed** | 478.4067317 s | `acceptance-772c70e8de804a85adb76dc1e2d941cc/review/` |

The full receipt is
`test/tmp/acceptance/series-0407a57ef3af4e57a449dcf5bbb8e115/series.json`; it retains exact
member result paths and hashes. Profile timers sum to **1131.883 seconds**; independently
measured sequential wrapper wall time is **1138.249 seconds = 18 minutes 58.249 seconds**.
Do not label the timer sum as wrapper time or infer unavailable setup breakdowns from it.

All 600-second profile caps and individual 60/120-second caps passed. Collection and case
cleanup confirmed `remaining_processes=0`; `production_services_touched=false`. Shared source
identities agree, every member manifest/source is bound to `856300ca`, invocation IDs are
distinct and no artifacts/seeds were reused between members. The 35 executions include
four repeated CI-positive producers, giving 31 unique cases.

The coordinator also reconciled eight distinct integrity copy roots with one new telemetry
lane each, both heavy-vector preflight spans against actual pytest guard receipts, seven
mutation outcomes and source/private hashes including the same-length proof. These are
authentic private consumers, not copied producer history counted as fresh execution.
Monolithic 31-case `review-exhaustive` remains **unqualified**; there are no new quick warm,
Linux/actual-WSL, tool/provider/CodeQL/native or genuine assessment claims.

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
  signals/dependency, controls, review/oracle, consumer and tagged-worker startup/resume obligations.
  `process` has a 120-second profile case ceiling to account for current-main startup and
  cleanup; obligations still marked 60 seconds retain that cap. Profile-level 120-second
  maxima do not silently grant every case that allowance. The lifecycle helper accepts only
  explicit 60/120-second budgets: tagged workers use 120, other helper cases retain 60.
  Its five-second internal reserve/receipt now reflect the selected cap; the outer existing
  exception and 480-second process aggregate are unchanged, not globally increased.
- `quick` targets less than ten minutes, with a hard twelve-minute suite ceiling. All three
  frozen-source two-worker warm runs meet the target: 559.626 / 551.899 / 567.917 seconds.
  That runtime goal is demonstrated for two workers, not the serial default or exhaustive
  coverage.
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
filesystem writes still fail. The timed Windows core-review pass completes its scoped
verification todo, not Linux/actual-WSL coverage or general Windows failure reliability.

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

The sequential series wrapper also retains a separate
`test/tmp/acceptance/series-<uuid>/series.json` aggregate receipt with member result paths/
hashes, source/invocation identities and measured accounting. It is not a shared producer seed
or a replacement for any member's artifacts.

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
The current staged core review now passes with separately budgeted authentic producers.
The separate three-warm quick results below establish that bounded two-worker runtime goal,
not the full `review-exhaustive` matrix. Splitting assertions alone is not evidence that every
fresh public fixture fits.

## Current measured status

The approved series is qualified at `856300ca` as recorded above. The following calibration
facts remain historical and are not retargeted to that newer source.

The historical passing source checkpoint is `a4ce5459ab51727cb3793c0425894a7f56fc21dc`, including
custody optimization `881b8709` and helper-budget correction `85d39172`.

- Optimized public `scripts\run-tests.ps1 -Acceptance review -Workers 2` **passed 13/13 in
  469.729 seconds** under 600, with all individual 60/120-second caps met. Three real review
  producers detached 114 output files; native candidate, fresh corruption/empty and CI
  review/gate/report/oracle private consumers naturally passed with no binding rewrites.
  Cleanup confirmed zero survivors and `production_services_touched` was false. Root:
  `test/tmp/acceptance/acceptance-13846b2ca1fc4685ae71ac1e43796e44/review/`.
- The Windows verification todo is **done for that demonstrated scope**, not Linux, actual
  WSL or general `WinError 5` reliability.
- Frozen source/environment `a4ce5459`, actual public quick with two workers:
  warm 1 **passed 38/38 in 559.626 seconds**, root
  `test/tmp/acceptance/acceptance-59628deb115e419e8edbca858eb536a8/quick/`;
  warm 2 **passed 38/38 in 551.899 seconds**, root
  `test/tmp/acceptance/acceptance-8206b2c4d27b4e1990a7dba1cb10ed17/quick/`;
  warm 3 **passed 38/38 in 567.917 seconds**, root
  `test/tmp/acceptance/acceptance-adc9cf098cca48b28ae2780803973906/quick/`.
  All three have identical full source-identity closure, distinct invocation IDs, every case
  cap satisfied, owned cleanup zero and no production services touched. This completes
  three-warm quick runtime calibration for two workers, not default-serial timing.
- First public `review-exhaustive -Workers 2` at the same `a4ce5459` **failed** 24 selected
  cases in **599.621 seconds**: 20 passed, `current-report-integrity` hit its own deadline
  (118.444-second receipt, below 120 total), `ci-blocked-gate` had only 9.059 seconds before
  the 600-second suite end, and `ci-blocked-report` / `review-blocked` were correctly blocked.
  All native, CI-positive oracle and CI-benign full paths passed; CI-blocked prepare/review
  passed. The budget-stopped gate is uncompleted coverage, not a semantic gate failure or a
  passing gate claim. Root:
  `test/tmp/acceptance/acceptance-decde16e3a6141daaddf5522aa918449/review-exhaustive/`.
  The bounded series above is now user-approved and its first selection implemented, but
  the initial `086ded0a` integrity qualification failed as recorded above. The corrected
  `856300ca` series subsequently passed; neither approval nor that series qualifies the
  monolithic profile.
- At `d6042ab9`, full portable `process` failed twice with 12/13 passing: two workers in
  191.015 seconds and one worker in 353.493 seconds. Tagged workers hit the helper's inner 55-second execution/
  60-second receipt cap on fresh resume despite the existing outer 120-second exception.
  `85d39172` aligns only that helper call to 120; six new units passed in 4.44 seconds.
  At unchanged `a4ce5459`, actual public `scripts\run-tests.ps1 -Acceptance process -Workers 1`
  now **passed 13/13 in 351.471 seconds**, under 480 with all individual caps met. Root:
  `test/tmp/acceptance/acceptance-be7d2d44ad7d48669710a5f76490035d/process/`.
  This closes post-correction named portable proof, not Linux/actual-WSL coverage. Prior
  serial/parallel failures, Windows PIPE failure/fix and staged PoC deadline failure stay recorded.
- Other named public passes remain revision-scoped: graphs 22/22 in 57.756 seconds and
  controls 8/8 in 70.770 seconds at `f4a04b29`; consumers 3/3 in 111.330 seconds at `992058ae`;
  signals 3/3 in 145.353 seconds at `58387690`. These used two workers, met case caps and
  confirmed cleanup zero / no production services touched; they are not final-source warm
  proofs or serial-default signals proof.
- Fresh immutable capture now traverses/hashes the declared union once per scope with full
  limits and missing/extra/same-size checking; mutable outputs are not rehashed for each
  immutable check. Whole producer inspection/checkpoint/seal/full source checks remain.
  Combined validation: 104 passed, four host-facility skips, 235.17 seconds, not full coverage.
- Exhaustive adequacy still blocks full handoff; scoped Windows, three-warm quick and
  corrected named portable completion facts remain true despite that outstanding gate.
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
unchanged. Scoped Windows review verification is complete; it does not waive the remaining
calibration/profile gates or establish default-serial timing.

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
- **At that historical checkpoint, overall not green:** quick was red; the authentic oracle
  fixture exhausted the 117-second execution allowance before its matrix. Windows `WinError 5`,
  genuine assessment,
  and live/provider/native/Linux validation remain gaps. The process/consumers profile passes
  do not make quick, the full oracle matrix, serial signals scheduling or all consumer
  capabilities green.

At that historical checkpoint, planner `81ada94f` had produced only a read-only
`staged-authentic-producer/private-verified-materialization` proposal.
The producer/reader machinery and fresh immutable-union optimization are now integrated;
the timed Windows core-review gate passes. The historical proposal supplies neither a
validation-cache shortcut nor a cap waiver. The approved exhaustive series now has passing
member/aggregate calibration at `856300ca`; monolithic and platform/provider gaps remain
outside that qualified scope.
