# Bounded integration and live acceptance

Implementation record for the approved integration/live coverage plan, based on `fcac4306`.
The original audits and approval plan are retained in the coordinating session's Library.

Operator instructions are in [bounded integration acceptance](../operations/bounded-acceptance.md);
the [architecture](../architecture/bounded-acceptance.md) describes the authentic seams and
current-report oracle. This is a revision-bound implementation/evidence record, not a claim that
all inventory members or optional live profiles have executed.

## Current reconciliation checkpoint

The approved bounded exhaustive series is **qualified** at exact tested source
`856300cafdc1a4693608d24e93586cb88a7fb2bc`, including main `a31d4249`. Integrity 12/12,
outcomes 10/10 and review 13/13 passed sequentially with two workers in three fresh
invocations: **35 executed / 31 unique cases**, all case/profile caps met, in
**1138.249 seconds wrapper wall time (18 minutes 58.249 seconds)**. Exact member results,
source/invocation identities and result hashes are retained in the series receipt below.

The documentation change is based on `dba23ad649389a708d6b94fab347e5784d5a23d0`; that is
not the tested runtime revision. Historical
`a4ce5459ab51727cb3793c0425894a7f56fc21dc` retains its scoped Windows review completion,
three under-ten-minute two-worker quick warm passes and corrected one-worker portable pass.
No new warm or platform/provider results are claimed at `856300ca`. Earlier monolithic and
`086ded0a` integrity failures remain recorded. Monolithic 31-case `review-exhaustive` is
**unqualified**, not an alias for the qualified series. Every result remains revision-bound.

### Actually integrated staged contract

The public driver schedules only dependency-ready producer phases. Prepare freezes actual
configuration/overlay, target and fixture inputs; subsequent producers verify immutable-input
receipts and predecessor tree checkpoints. A terminal producer is sealed by the supervisor
only after successful process exit and confirmed owned cleanup. The protocol is invocation
specific: `appsec-review/acceptance-invocation-seed/1`, **not** the operator
`appsec-review/acceptance-seed/1`.

The source manifest binds all staged Python under `src/`, the local helper import closure,
selected tests/driver/configuration/static inputs, all `docs/schemas/` files and all `pipeline/`
bytes. Consumers verify exact invocation/variant/commit/source/tree identities and receive
fresh ordinary private copies with materialization receipts. Reader run/runs loci relocate
without rewriting authenticated source/configuration paths, accepted bytes or hashes.
Mutation vectors get independent copies and production validation scopes.

Consumer execution writes separate current private streams and a
`appsec-review/acceptance-consumer-telemetry/1` origin sidecar. Retained copied producer
history is explicitly `execution_evidence: false`, not freshly executed consumer work.
Blocked descendants remain failed/unexecuted coverage, never successful skips.

At `856300ca`, core `review` selects 13 staged cases, report-integrity 12 and outcomes 10;
monolithic `review-exhaustive` retains all 31 unique integrity/benign/blocked/core cases and
is not qualified. Its earlier 24-case attempt failed as detailed below. Quick retains 35 selectors
resolving to 38 cases including prerequisites. Caps are unchanged: quick 720 seconds,
review/exhaustive 600, signals 240; ordinary/declared per-case caps and cleanup reserves still
apply. Default workers are one, maximum two.

### Implemented producer OUTPUT detachment

The approved correction is implemented by `custody.detach_producer_outputs`: successful
kernel-owned cleanup must precede publication, and every device/inode/link-count group must
be fully accounted within one run's registered named/content-addressed outputs. Exact
production bindings are freshly validated; external/unaccounted, unclassified, cross-run
and immutable groups fail. Exclusive copies are hashed, fsynced, mode-preserved and replaced.
Strict ordinary-tree snapshots and frozen inputs must still pass before checkpoint/seal.
Failure, partial work or a deadline leaves no usable checkpoint/seal; there are no retries.

The sidecar schema is `appsec-review/acceptance-producer-detachment/1`, with
`acceptance.stage.producer_publication` spans. Only mutable producer link locations are
allowed by the guard. Verified anonymous stdio PIPE wrapping is distinct from filesystem
descriptor mutation; unresolved/off-root/immutable filesystem mutations remain denied.
The ordinary checkpoint/seal/private-copy policy is not relaxed.

### Optimized public Windows review and frozen warm checkpoint

The actual public `scripts\run-tests.ps1 -Acceptance review -Workers 2` at frozen `a4ce5459`
**passed 13/13 in 469.729 seconds**, under 600, with every individual 60/120-second cap met. Three real review
producers detached **114 output files**. Native candidate, fresh corruption, empty and CI
review -> gate -> report -> oracle private consumers naturally passed with no binding
rewrites, zero surviving owned processes and `production_services_touched=false`. Root:
`test/tmp/acceptance/acceptance-13846b2ca1fc4685ae71ac1e43796e44/review/`.

The Windows verification todo is **done for that demonstrated publication/staged-review
scope**. It does not establish Linux, actual WSL or general Windows `WinError 5` reliability.

Source and environment were frozen at exact `a4ce5459` for three public quick warm runs,
each with two workers:

| Warm run | Actual result | Evidence root below `test/tmp/acceptance/` |
| --- | --- | --- |
| 1 | **Passed 38/38**, 559.626 s | `acceptance-59628deb115e419e8edbca858eb536a8/quick/` |
| 2 | **Passed 38/38**, 551.899 s | `acceptance-8206b2c4d27b4e1990a7dba1cb10ed17/quick/` |
| 3 | **Passed 38/38**, 567.917 s | `acceptance-adc9cf098cca48b28ae2780803973906/quick/` |

All three measured runs have identical full source-identity closure and distinct invocation
IDs. Every case cap passed, owned cleanup confirmed zero survivors, and no production services
were touched. The under-ten-minute runtime target and twelve-minute ceiling are genuinely
demonstrated for **two workers**, not the serial default, exhaustive coverage or a final handoff.
Combined focused validation reported **104 passed, four host-facility skips, 235.17 seconds**;
those skips remain gaps, not executed coverage.

### First public exhaustive result at the same `a4ce5459`

`scripts\run-tests.ps1 -Acceptance review-exhaustive -Workers 2` **failed** 24 selected
cases in **599.621 seconds**: 20 passed, two deadline-stopped cases and two correctly blocked
descendants. Root:
`test/tmp/acceptance/acceptance-decde16e3a6141daaddf5522aa918449/review-exhaustive/`.

- `current-report-integrity` hit its own hard deadline; its receipt was **118.444 seconds**,
  below 120 total. Being below the outer total ceiling does not erase the execution timeout.
- `ci-blocked-gate` had only **9.059 seconds** before the 600-second suite end.
  `ci-blocked-report` and `review-blocked` were consequently blocked, not executed coverage.
  This is no semantic failure claim for the budget-stopped gate and no evidence it passed.
- All native, CI-positive oracle and CI-benign full paths passed; CI-blocked prepare and
  review passed. Those passes do not satisfy the missing integrity/gate/report/consumer work.

That failure is not erased by the subsequently qualified bounded series below. The historical
scoped Windows/three-warm facts remain true; the monolithic profile stays unqualified.

### Approved bounded exhaustive series

The user selected verbatim **Approve bounded exhaustive series (Recommended)**. This
approves eight independent exhaustive-only integrity cases plus these sequential members:

| Member | Required selection | Cases | Timing status |
| --- | --- | --- | --- |
| `review` | Existing native/core selection unchanged | 13 | Passed at `856300ca`, 478.4067317 s |
| `review-report-integrity` | Fresh CI-positive prepare/review/gate/report plus eight vectors | 12 | Passed at `856300ca`, 430.0222257 s |
| `review-outcomes` | Complete CI-benign and CI-blocked chains, four phases plus one consumer each | 10 | Passed at `856300ca`, 223.4540428 s |

Each member remains capped at 600 seconds with at most two workers. New integrity consumers
retain ordinary 60-second caps; existing declared producer/job 60/120-second caps and cleanup
reserves remain. The approval estimate was **18–20 minutes aggregate**; the measured qualified
wrapper took 18 minutes 58.249 seconds. The three caps sum to 30 minutes. This is not a new
600-second exhaustive benchmark.

The exhaustive-only node in the new selection is
`tests/integration/test_current_report_integrity_cases.py::test_current_report_integrity_vector[ID]`;
the [operator contract](../operations/bounded-acceptance.md#approved-bounded-exhaustive-series)
lists all eight exact IDs. Replacing the combined integrity case with eight preserves every
original vector and makes the monolithic selection 31 cases, still capped at 600 and
not qualified. Its old 24-case/599.621-second result above remains unchanged.

The qualified series executed **35 cases across three fresh invocations / 31 unique cases**,
with four CI-positive producer phases deliberately repeated.
No cross-invocation seeds are permitted.
Required completion accounting retains exact ordered members, frozen source/environment,
each full source-identity closure, distinct invocation IDs, exact selected/collected/executed
cases, per-member result paths/SHA-256 hashes, caps/outcomes/cleanup/resources and measured
aggregate plus member durations. Historical results cannot substitute for any member.

Only test-module/inventory changes are assigned: no API, custody, scheduler or production
changes. This documentation change remains based on `dba23ad6`; the runtime qualification
below is explicitly bound to tested source `856300ca`, not this older checkout.
Quick/review nodes are unchanged by this design; the historical three quick warm
passes at `a4ce5459` are not new-revision evidence.

### Failed first integrity qualification at `086ded0a`

At exact source `086ded0afdbc82abd1be6da3acaa8f4e3b3e9129`, actual public
`scripts\run-tests.ps1 -Acceptance review-report-integrity -Workers 2` **failed with 10/12
passing in 429.065 seconds**. Ordinary 60-second execution deadlines stopped
`identity-state-bucket` at **58.663 seconds** and `orphan-hit` at **58.740 seconds**.
All six other vectors and four real producers passed. Cleanup confirmed zero survivors;
`production_services_touched=false`. Evidence:
`test/tmp/acceptance/acceptance-82a8878f33e545cda8a45f596c4d6885/review-report-integrity/result.json`.

The sequential qualification started with integrity and **stopped on failure**. Outcomes and
review were not run at that source. This does not establish 35 measured cases, an 18–20-minute
aggregate, or a passing/complete series. The first failed member's duration is not a qualified
runtime for the planning estimate. An unchanged retry is forbidden; the correction below
removes only redundant fixture seed verification within the approved eight-case/60-second
design, not repeated identity-oracle computation. At that checkpoint no revised passing
measurements were available; the corrected-source qualification below does not erase this failure.

After that stopped run, the coordinator incorporated frozen main `a31d4249` as
`59f6a0e719f1d0c5a809936350d311f1535cae7d`: private-containerd/opt-in-ptrace changes, with no
reported harness overlap. That later merge is **not** the source of the `086ded0a` receipt
and supplies no series qualification evidence by itself. The qualified corrected source is
`856300ca` below; this documentation change remains based on `dba23ad6`.

### Corrected frozen source `856300ca`

The next frozen implementation is exact `856300cafdc1a4693608d24e93586cb88a7fb2bc`, including
main `a31d4249` and fix `1e0c6996`. The identity oracle was **already batched**. The new
module's two heavy fixtures redundantly verified the original seed after the same-process
guard had freshly verified the seal and whole private copy and installed the immutable-seed
guard. `1e0c6996` removes only that redundant seed scan (about 6.7–6.9 seconds), requiring
matching completed guard preflight, workspace and invocation. It leaves all driver/guard
byte proofs and production validation untouched; it is not new oracle batching or a cap/vector
change.

Five persistent fail-closed guard-reuse unit cases were added to existing
`tests/test_acceptance_review_stages.py`. Combined focused validation: **34 passed,
12.75 seconds**; all **eight exact nodes collected in 1.77 seconds**. These are unit/
collection results, not substitutes for public profile qualification. The same three
profiles subsequently passed sequentially at this corrected frozen source as recorded
below; the failed `086ded0a` qualification remains historical, not silently deleted.

Separately, the incoming `a31d4249` native-unit command stopped with **two collection errors
in 2.09 seconds**, both missing `fcntl` on native Windows. That explicit host gap is not part
of the 34-unit passing scope and has no workaround here. No parent/source checkout was moved
to produce this documentation change.

### Qualified complete series at `856300ca`

The public profile invocations ran in this sequential order, each with two workers and its
own fresh invocation at the same frozen source/environment:

| Actual member order | Result | Profile timer | Evidence root below `test/tmp/acceptance/` |
| --- | --- | --- | --- |
| 1. `review-report-integrity` | **12/12 passed** | **430.0222257 s** | `acceptance-e2ef45f64cd4477bbbb51b7a299b562b/review-report-integrity/` |
| 2. `review-outcomes` | **10/10 passed** | **223.4540428 s** | `acceptance-eaf48cbd258346b6a3cad0511175f475/review-outcomes/` |
| 3. `review` | **13/13 passed** | **478.4067317 s** | `acceptance-772c70e8de804a85adb76dc1e2d941cc/review/` |

Full series receipt:
`test/tmp/acceptance/series-0407a57ef3af4e57a449dcf5bbb8e115/series.json`.
It retains exact member result paths and hashes. The profile timer sum is **1131.883 seconds**;
measured sequential wrapper wall time is independently **1138.249 seconds
(18 minutes 58.249 seconds)**. These are different measurements, not inferred fixture/setup
breakdowns.

All three 600-second profile caps and every individual 60/120-second cap passed. Collection
and case cleanup confirmed **`remaining_processes=0`**; **`production_services_touched=false`**.
Shared source identities agree; each member manifest/source is bound to
`856300cafdc1a4693608d24e93586cb88a7fb2bc`. Invocation IDs are distinct and no artifacts/seeds
were reused across members. The 35 executed cases / 31 unique cases include four repeated
CI-positive producers; no historical `a4ce5459` pass was substituted for a member.

The eight integrity-vector durations were **52.365 / 46.545 / 54.153 / 48.569 / 50.167 /
55.410 / 46.961 / 44.564 seconds**; exact node mappings remain in the member result.
The coordinator independently reconciled eight distinct private copy roots, one new
consumer-telemetry lane per vector, both heavy-vector preflight spans against actual pytest
guard receipts, seven mutation outcomes, source/private hashes and the same-length proof.
The guard reuse was therefore observed in the real public route, not merely assumed from
unit/collection results. Driver/guard byte proofs and production validation remain intact.

This qualifies the **approved bounded series only**. Monolithic 31-case `review-exhaustive`
remains unqualified; the old 24-case failure and first `086ded0a` split failure remain above.
Historical quick three-warm and portable results stay at `a4ce5459`. There are no new warm,
Linux/actual-WSL, tool/provider/CodeQL/native compatibility or genuine assessment results.

### Implemented fresh immutable-union optimization

`881b8709` changes immutable capture to fresh traversal/hashing of the declared union once
per scope, including the declaration. Overlapping paths count once; full ordinary-file,
depth/entry/file/byte/deadline limits and missing/extra/same-size checking remain. Mutable
outputs are not hashed for every immutable check. Whole producer inspection, checkpoints,
seals and full source checks remain unchanged. There is no cross-call proof cache, weakened
seal or cap increase.

### Portable process failures and helper-budget correction

At `d6042ab9`, full named portable `process` failed twice with **12/13 passing**: two workers
took **191.015 seconds**, one worker **353.493 seconds**. Both tagged-worker failures hit
the helper's inner 55-second execution/60-second receipt cap on fresh resume even though
inventory/supervisor already declared its 120-second exception.

`85d39172` fixes that mismatch: `case(name, deadline_seconds=60)` accepts only 60/120, and
tagged workers explicitly select 120; remaining helper cases retain 60. The helper reserves
five seconds and records the selected cap. Outer 120-second exception and aggregate
480-second process ceiling are unchanged, not increased globally. Six new units passed in
4.44 seconds. All three actual quick warm runs passed the config/worker/resume obligation.

The actual public `scripts\run-tests.ps1 -Acceptance process -Workers 1` at unchanged
`a4ce5459` subsequently **passed 13/13 in 351.471 seconds**, below its 480-second profile cap,
with all individual caps met. Root:
`test/tmp/acceptance/acceptance-be7d2d44ad7d48669710a5f76490035d/process/`.
This closes post-budget-correction named portable proof without erasing either prior failed
run or claiming Linux/actual-WSL execution. Source and environment remained unchanged.

### Earlier partial public review at `d6042ab9`

`scripts\run-tests.ps1 -Acceptance review -Workers 2` **failed**: 10/13 passed, one
native-positive PoC producer timed out and two consumers were correctly blocked. The whole
profile took **530.257 seconds**, under 600 seconds, but a passing suite clock does not
override a failed case cap. Evidence root:
`test/tmp/acceptance/acceptance-a59d77fffc7447658af064fbb8ff67c9/review/`.

- Native-positive, native-empty and CI review each detached **38 files**, 114 total,
  preserving bytes, modes and bindings.
- Native-empty's sealed private consumer passed in **56.403 seconds**.
- The full actual CI prepare -> review -> gate -> report -> sealed private current-report
  oracle chain completed; its consumer passed in **101.245 seconds**. Reader-only relocation
  and fresh telemetry occurred naturally, without accepted hash/path/configuration rewrites.
- Native-positive PoC pytest passed in **54.28 seconds**, but the total stage took
  **120.023 seconds**, exceeding 120 during the final sealed-input postcheck. Its seal was
  invalidated and candidate/corruption consumers remained blocked, not executed coverage.

Owned cleanup confirmed zero survivors and `production_services_touched` was false.
At that revision the Windows completion todo was still open despite genuine detachment and
CI consumer proof. Repeated immutable verification hashed the entire mutable tree; the
later integrated `881b8709` optimization and passing core review above supersede that blocker,
not the recorded failure itself.

### Other revision-bound public and focused results

| Route / revision | Actual result | Boundary |
| --- | --- | --- |
| `process-windows`, `d6042ab9`, workers 1 | **Passed 1/1**, 17.898 s, cap 60 s | Actual PowerShell with a compiled invocation-owned WSL shim, **not real WSL** |
| `graphs`, `f4a04b29`, workers 2 | **Passed 22/22**, 57.756 s | Named public profile |
| `controls`, `f4a04b29`, workers 2 | **Passed 8/8**, 70.770 s | Named public qualification profile, not genuine assessment/source-bound review |
| `consumers`, `992058ae`, workers 2 | **Passed 3/3**, 111.330 s | Named public profile, not exhaustive consumer/replay coverage |
| `signals`, `58387690`, workers 2 | **Passed 3/3**, 145.353 s | Below 240 s for this two-worker invocation, not serial proof |

These runs confirmed case caps, cleanup zero and no production services touched; they are
not final-source frozen warm proofs. Windows evidence root:
`test/tmp/acceptance/acceptance-fd7907ac0051437987dbd4a07fc0987c/process-windows/`.
The earlier `process-windows` attempt at `992058ae` **failed in 8.905 seconds** because stdin
PIPE was misclassified. The subsequent result follows an actual source correction, not an
undisclosed retry-to-green.

Combined native Windows validation at `d6042ab9` reported **89 passed, one host
skip in 141.73 seconds**, not a full acceptance/warm-suite result. Incoming frozen-main Linux
commissioning focused units cannot collect on native Windows because `fcntl` is absent;
this is a separate host gap, not a detachment regression or permission for a workaround.
Parent docs/inventory validation reported **6 passed, one failure in 7.18 seconds**: two
missing target README/project-matrix links in unchanged
`docs/architecture/build-environments-and-execution-capture.md`, confirmed pre-existing
before the documentation merge. That unrelated document and user targets remain untouched.

Windows `WinError 5` remains unexplained: a bounded ten-transaction probe completed in
4.055 seconds without explaining it. Genuine assessment/source-bound review, Linux guardian,
actual WSL/tool/provider/CodeQL/native validation, specialist/renderer-selection/saturation/
cross-lane consumers and unselected record/replay/sensor variant matrices remain gaps.
No production runs/services were inspected or mutated. Path/process/metrics isolation does
not guarantee zero shared CPU/I/O contention.

### Earlier pre-detachment failure at `58387690`

| Public route | Actual result | Evidence |
| --- | --- | --- |
| `scripts\run-tests.ps1 -Acceptance review -Workers 2` | **Failed**, 13 selected, 24.4064413 s: 3 prepare failures, 10 correctly blocked descendants | `test/tmp/acceptance/acceptance-88a0d85707f7442f80d2765174e3f3c2/review/result.json` |
| `scripts\run-tests.ps1 -Acceptance signals -Workers 2` | **Passed 3/3**, 145.353 s, below 240 s | `test/tmp/acceptance/acceptance-cb32192d91924fdbb4d3bc5d6e8259e1/signals/result.json` |

Review failed on real `IndexBuilder` atomic `os.link` publication denied by the staged guard.
Owned cleanup confirmed zero survivors and `production_services_touched` was false. No
descendant consumer executed or established a staged chain. The signals pass resolves the
timing concern for this measured **two-worker** invocation only; serial-default feasibility
is not proved, and the earlier projected serial sum is not an actual integrated failure.

Integrated runner/custody validation reported **79 passed, one skip, two failures in
344.73 seconds**. Both failures were corrected by `58387690`; affected/core/fixture/inventory
validation then reported **72 passed, one host skip in 56.53 seconds**. These are distinct
runs, not a new single full-suite green result. Linux guardian, actual WSL/tool/provider/
CodeQL/native validation, genuine assessment/source-bound review, specialist/renderer-selection/
saturation/cross-lane consumer cases and unselected record/replay/sensor variant matrices
remain named gaps.

Legitimate named/content-addressed aliases also conflicted with strict single-link custody,
so merely allowing `os.link` could not fix that historical failure. The later user-approved
OUTPUT-only detachment above addresses it without relaxing ordinary checkpoints/seals/copies.
It supplies no budget waiver, shared main landing, restart, push or production service/build
authorization.

## Historical pre-staging reconciliation

Framework fixtures now use `tests.handoff_fixture.write_fixture_handoff` for `handoff/2`.
The current review domain is `/3`, while gate/report domains remain `/2`; these are independent
of the framework envelope version. The final-report job is gate-only,
with no OpenVEX fan-in. The current-report oracle delegates to certified `load_accepted_gate`
and source-resolving current accepted-manifest validation; scanner hits or orphan/historical
shards cannot establish final survival. PoC planning consumes the direct accepted review and
strict candidate eligibility, and does not dispatch compilers/models without an accepted build.

### Latest-main source transition remains in progress

The coordinator is correcting shared fixtures, not production behavior: framework `handoff/2`
requires the actual configuration to be frozen before synthetic upstream handoffs and an
explicitly claimed upstream digest. The native candidate chain follows the current direct
review -> PoC dependency without a prerequisite gate; the CI oracle keeps the actual
review -> gate -> report chain.

Bounding the fixture to one explicitly configured lead package and no hunt is a valid tiny
selection, not permission to weaken contracts. Oracle evaluation uses a fresh per-call
production `validation_scope`, with no cached validation across tamper attempts; unchanged
negative expected identities can be batched in one evaluation.

This transition has no final latest-main pass at this update. Earlier measurements remain
revision-scoped; fixture corrections and reduced work alone do not complete public calibration.

W5's interim public W0-supervised attempt exposed a shared guard/source incompatibility after
`bfe7f38b`: `tests/acceptance_plugin.py` rejected all reads beneath repository `data/`, while
the real review job's `_taxonomy` reads tracked
`data/reference/taxonomy/vocabulary.json`. All three new consumer nodes therefore failed at
`packages.assemble_lead_packages` with `PermissionError`; owned cleanup is confirmed with zero
remaining processes. This was a shared runner-policy blocker, not evidence that the consumer
joins passed or that production mutable-data access should be enabled. The narrow `19c7c000`
correction below distinguishes pinned read-only application taxonomy from production mutable
state; copying/substituting the taxonomy or weakening the guard is not an acceptance result.

Direct W5 triage/referral executions were reported passing at approximately 45 seconds, and
publication reached the real accepted report/render path at approximately 112 seconds before
final assertion refinement. These are interim direct-test observations, not final public
verification; exact revision, artifacts and a passing post-correction run remain outstanding.

### Latest public quick result and correction

On parent revision `6265bbc7`, the actual public command was:

```powershell
.\scripts\run-tests.ps1 -Acceptance quick -Workers 1
```

The profile **failed**, with 39 of 45 cases passing in **717.061 seconds** and owned cleanup
confirmed. The coordinator's result is
`test/tmp/acceptance/acceptance-b2fbda7335ba4a36bab652567da7452b/quick/result.json`.
This is the result location in the execution checkout, not a committed artifact or a result
regenerated by the documentation agent.

| Unsuccessful case | Observed failure |
| --- | --- |
| Full signal lifecycle | Timed out at 117 seconds of execution budget |
| Dependency lifecycle | `WinError 5` during atomic status replacement |
| Tagged multiprocess worker | Assertions passed in 54.88 seconds, but process overhead exhausted the 57-second execution allowance before the reserved cleanup window |
| Control evidence | Stale fixture configuration selected production OWASP catalogs |
| Native candidate | Guard rejected the required tracked taxonomy read |
| Current-report oracle | Only 5.48 seconds of suite budget remained; the oracle was starved |

These are six acceptance failures, even where an assertion body passed or cleanup succeeded.
The elapsed suite remained below twelve minutes, but that does not make it green or establish
the under-ten-minute target.

Parent correction `19c7c000` admits only supervisor-hash-pinned read-only
`data/reference/taxonomy/vocabulary.json` and `data/reference/taxonomy/crosswalk.json`.
The child validates those identities before installing the audit hook, and the result records
their source hashes. Mutations and all other protected data remain denied. Control fixtures
now explicitly select and re-pin all five tiny abridged OWASP catalogs instead of inheriting
the newly expanded production catalogs. Guard/inventory focused validation passed 7 tests in
8.81 seconds; it is not a whole-profile result. At that checkpoint W5 was instructed to merge
the correction and rerun. Its later final exact-node and named consumers CLI results are
recorded below; neither was available at that earlier checkpoint.
Whole-quick verification remains outstanding.

The coordinating session obtained explicit native Windows authorization. That authorization
does not commission Linux, WSL, native containers or other sessions; Linux remains unverified.

### W5 final bounded consumer handoff

Consumer tip `06a4ea6c3ba2a572b3701d9977df76a896e4bf9e` contains parent `19c7c000`
(and `6265bbc7` / `bfe7f38b`). Its sole file difference from that parent is the new
`tests/integration/test_review_consumer_acceptance.py`. The implementation commits are
`67d83bc40c7360a2fca5566fc8d69da5765f2e38` and
`06a4ea6c3ba2a572b3701d9977df76a896e4bf9e`; merge `e81f8f5a` incorporates the parent guard.
This handoff changes no production code, schemas, shared helpers, runner or inventory.

The final direct execution passed all three nodes in 181.27 seconds pytest / 183.725 seconds
subprocess wall. The final **exact-node supervised** execution used the real public
`supervised_pytest` and `tests.acceptance_plugin` boundary and passed 3/3 in 225.664 seconds.
It was serial (one worker), with a 360-second group cap and an explicitly measured 120-second
real-job exception for each case, including a three-second cleanup reserve. Every Windows Job
Object cleanup confirmed zero remaining owned processes. The direct child also exited; no
services were started.

All node names below have prefix `tests/integration/test_review_consumer_acceptance.py::`.

| Exact node suffix | Direct call time | Supervised wall / pytest time |
| --- | --- | --- |
| `test_triage_assessment_orders_admits_and_binds_real_review_handoff` | 45.09 s | 56.455 / 52.265 s |
| `test_authentic_publication_renders_counts_states_gaps_and_provenance` | 95.71 s | 114.521 / 110.380 s |
| `test_worker_referral_deduplicates_next_round_after_foreign_repair` | 36.40 s | 53.864 / 49.779 s |

This is **not a named inventory/profile CLI run**. Parent `09cbf227` subsequently enrolls these
three nodes in `consumers`; the later named public pass at `1ff86556` is recorded separately
below. Final integrated calibration remains incomplete. Earlier larger consumer fixtures hit
execution cutoffs despite confirmed cleanup; the final CI-only reduction removes unrelated
build/component/reference shards and all feeds, retains source/CI observations and leaves
missing facts as gaps. It uses the existing typed synthetic accepted-index producer fixture
and scripts only the external inference callable. All real job units, schemas, index-to-review
consumption, gate/report publication and hash-bound outputs remain; no accepted review, gate
or report output is injected.

Artifacts are retained in the isolated `test/tmp/agent-worktrees/consumers/` checkout, at these
paths relative to that checkout:

- Public-boundary root:
  `test/tmp/acceptance/acceptance-d751c3b1b0f74f65ac78ed2140e9a269/consumer-verified-public/`.
  `handoff.json` and `consumer-result.json` retain full node/results/resources/cleanup and log
  paths; `publication/report.html` and `publication/report.tex` retain the rendered output.
  Driver streams are `driver/events.jsonl` and `driver/data/logs/pipeline.jsonl`.
- The same root's `runs/2026-10-28-0301`, `runs/2026-10-28-0302` and
  `runs/2026-10-28-0303` each retain `data/telemetry/summary.json`, verified as
  `appsec-review/run-metrics/5`.
- Direct root:
  `test/tmp/acceptance/acceptance-c6aa9951898b418eadf0c3e5fb78f962/consumer-final-direct/`,
  retaining `consumer-result.json` and `pytest.log`.

The remaining consumer limits are substantive:

- The renderer consumes one authentic hash-bound current publication. Its
  `reporting.sources.RunReader` still selects globs rather than using a current-accepted
  renderer API; stale/historical-render selection and tamper rejection are unverified.
- Referral transport to the next round, deduplication, foreign-anchor validation/repair and
  convergence are demonstrated. Dedicated specialist dispatch/resolution is not:
  `unresolved_specialist_referral:ci_cd_pipeline` remains explicit.
- Request-count/active-claim saturation, cross-package/lane referrals, actual concurrent review
  execution and optional live/native/provider/CodeQL capabilities are not established.
- Three bounded nodes do not make all W5 obligations, any named profile or the whole quick
  lane exhaustive or verified.

### Current qualification and tiny-signal corrections

W3 `e50b5a3e` passed the real supervised controls case in 65.490 seconds with zero remaining
owned children; focused configuration validation was reported at 2.48 seconds. The fixture
explicitly selects `QUALIFICATION`, disables inference, pins five tiny abridged catalogs and
uses authentic accepted document/catalog context through Workbench retrieval. Qualification
rows remain non-lead-eligible with `fixture_only` / `qualification_only` dispositions and
missing-evidence gaps. Current application code has real assessment mode; the earlier
description that the configured producer lacks an assessment hook is obsolete. Genuine
assessment, positive assessment/source binding, precomputed control facts and the review join
remain unverified by this lane.

At `5d7a35c4`, the exact-node supervised full signal positive passed in 99.837 seconds including
cleanup. The bounded fixture uses tiny native receipts and one missing-signal-family receipt,
retains the real catalog and artifact producers, and avoids unrelated intake work. An earlier
whole `signals` attempt at `b9e55009` failed in 80.607 seconds because it omitted the required
catalog; the correction retains that producer rather than supplying accepted catalog output.
The later exact-node pass is not proof that the full signals profile passed.

### Later public review and Windows filesystem failures

The public `review` profile at `5d7a35c4` **failed** after six cases in 593.872 seconds:

| Case | Supervised outcome |
| --- | --- |
| Native candidate / direct review-to-PoC | Timeout, 117.022 s |
| Current-report oracle | Timeout, 117.021 s |
| Explicit empty candidates | Passed, 71.472 s |
| Corrupt review | Passed, 70.298 s |
| Benign report | Passed, 106.284 s |
| Blocked report | Passed, 107.337 s |

These timings remain revision-bound. The candidate/oracle tiny-fixture performance follow-up
is separate work; four passing cases do not make this profile pass.

Intermittent Windows `WinError 5` also occurred while renaming an owned TLS stage directory.
The coordinator retained that failure at
`test/tmp/acceptance/acceptance-28503037d3224b5296fb4b848fd86851/controls/result.json`.
No retry-to-green, production-directory workaround or reliable whole-controls green claim is
made from that result.

### Final declared inventory and harness checkpoint

Parent `09cbf227` keeps the representative quick ceiling at 720 seconds and moves exhaustive
negative variants into explicit full profiles without deleting coverage: `signals` retains
signal integrity; `graphs` retains bad helper inputs; `controls` retains TLS negatives;
`process` retains other submission barriers, MCP integrity and invalid-profile refusal.
The `consumers` profile enrolls the three W5 nodes with a 360-second suite ceiling and
120-second per-node exceptions. `process` is now 480 seconds with a 120-second case ceiling
and explicit startup/replay exceptions; still-ordinary obligations retain their 60-second caps.
Signals/controls/graphs/review remain 240/240/180/600 seconds. Serial remains default; at most
two workers are opt-in. The collected result, not an estimated quick count, supplies the
execution denominator.

Each process now records `static_input_identities`; mismatch against the suite's source
identities fails the case even when pytest succeeded. The guard also treats descriptor
`O_TRUNC` and `O_APPEND` as mutation. The changed harness/inventory/lanes focused unit set
passed 42 tests with one host-symlink skip in 59.27 seconds, using base-temp
`test/tmp/acceptance-final-harness-unit`. That host capability remains a named gap; this is
not a passing acceptance profile or a reason to ignore required skips.

### Candidate/oracle performance follow-up: partial result, not a green review

W5 follow-up `b72e79a9bfb1511fe6a73ee0d5d8949d82c5d8ed`, based on merge `1e47a65b`
containing parent `5d7a35c4` and preserving `06a4ea6c`, changes only the two assigned
candidate/oracle test files. It changes no shared helper, guard, inventory, schema, durability
rule or cap. One distinct minimal-fixture attempt used the real supervisor/audit plugin,
serial execution, 120 seconds per node including a three-second cleanup reserve, and a
360-second group allowance.

- `test_real_review_and_poc_planning_use_authoritative_contracts` passed in 112.285527 seconds
  supervised wall / 108.840833 seconds pytest span (109.99 seconds pytest console). It uses
  one native lead, real graph/source references, an explicit strict high/critical risk
  assertion and direct accepted review -> actual no-build PoC planning. No model/compiler
  execution is dispatched by PoC planning.
- `test_current_report_bound_oracle_matrix` timed out at 117.024162 seconds before its fixture
  returned; **no oracle assertion was reached**. The CI-only fixture completed review in
  42.663572 seconds and gate in 39.910998 seconds. Report finalization emitted
  `HANDOFF_VALIDATED` and `JOB_COMPLETED_WITH_GAPS`, but had not emitted `HANDOFF_ACCEPTED`
  before timeout. Intermediate lifecycle events are not accepted report/oracle proof.
- The group took 229.923300 seconds. Both Windows Job Object cleanups confirmed zero
  remaining owned processes. The artifact in the consumer checkout is
  `test/tmp/acceptance/acceptance-4dc38d6786e040108b39bc3d2401944c/review-reconciled-public/result.json`,
  with process logs/outcomes/supervisor records and production metrics version 5 retained
  under the same root. Final `handoff.json` is persisted beside that result.

A separate bounded direct functional matrix check, without the audit plugin, also timed out
at 117.014358 seconds with zero remaining owned processes. Its real review took 42.479609
seconds and gate 34.818231 seconds; the report fixture completed at 104.102093 seconds. The
batched positive/four-negative/orphan oracle evaluation then started but did not complete
within the cap. This rules out describing the current failure as merely audit-plugin
overhead; rewritten oracle/mutation coverage remains unverified even directly. Its record is
`test/tmp/acceptance/acceptance-2f80d7ea53b140fb9216cccf89d7ec8f/review-matrix-direct/direct-result.json`
in the consumer checkout.

The pure producer-contract test passed in 1.86 seconds, and 14 owned nodes collected in 4.13
seconds; collection is not execution. The affected empty/corruption/benign/blocked nodes were
not rerun on this follow-up revision, so their earlier results remain bound to their earlier
source. The completed `06a4ea6c` consumer file is byte-unchanged. No further runs, increased
caps, integrity weakening, cross-call validation-cache sharing or shared-helper changes are
claimed by this handoff.

The exhaustive oracle remains unverified under its 120-second cap. Representative/exhaustive
obligation splitting needs real authenticated prerequisite producer artifacts with explicit
separate budgets, or parent-owned publication/harness performance work first. Merely splitting
assertions cannot fix a fresh public fixture that alone exhausts the execution allowance.
This result is neither a cap escalation nor retry-to-green evidence.

### Frozen main and corrected native/dependency seams

The latest frozen main is `a8883acc`, atop `493d75eb`; its capacity-overlay behavior no
longer overrides review teams to three. Production and Copilot production retain seven
teams, while the overlay selects four I/O and four scanner slots. This is configuration
provenance, not a production-stack change made by acceptance. Tiny explicitly configured
test teams do not describe production capacity.

Parent `1ff86556` contains these directly related corrections:

- Production `75383329` classifies `native_artifacts` as source inventory instead of treating
  source display paths as declared run references. Nested `evidence_source.artifact` and
  explicit `run_path` references remain collected and validated.
- Fixture `67944818` binds workspace manifests and protected compile-command artifacts as
  direct accepted handoff members, retaining production membership validation.
- Package-local fixture `e9b336e8` separates dependency roots and uses a static QA archive
  rather than SONAME evidence, avoiding accidental sibling production exposure.

Focused native/interchange/selected-overlay unit validation passed 7 tests in 9.73 seconds.
This is not native-container, daemon or compiler compatibility proof.

### Named process/consumers passes and exact dependency pass

At `16a520f4e70c8d1699dda7401a729d7c93515fe4`, the actual public command
`scripts\run-tests.ps1 -Acceptance process -Workers 1` passed **13/13 in 340.136 seconds**.
The profile was genuinely enrolled and selected through the named public CLI; all owned
cleanup confirmed zero remaining processes. The coordinator's result is
`test/tmp/acceptance/acceptance-ef2e537e8e5d49c0bcda6a12522c41bc/process/result.json`.
This proves that process selection on its tested revision, not every later merge or either
Linux-specific guardian/peer-credential requirement.

At exact parent `1ff865561cc79171d56e389ead1c961975234a11`, the actual public command
`scripts\run-tests.ps1 -Acceptance consumers -Workers 1` passed **3/3 in 207.438 seconds**.
The result is
`test/tmp/acceptance/acceptance-e809aa5c094a4ab8a620d07f602c6044/consumers/result.json`.
The public supervisor requires confirmed owned cleanup for a pass. No production reviews
were inspected or touched. This is the named-profile proof that was previously pending;
the older 225.664-second exact-node result remains historical. It is not exhaustive W5,
specialist resolution, stale/historical renderer selection or actual concurrent-review proof.

At `1ff865561cc79171d56e389ead1c961975234a11`, the final guarded dependency exact node
passed **1/1 in 83.9186626 seconds**, cleanup zero. Both real job attempts, fresh-cache reuse,
immutable-index preservation and package-local exposure assertions passed. The root is
`test/tmp/acceptance/acceptance-de13d4f4443446f7a0de7bc235d4e812/dependency-final-public/`;
`outcome.json` retains the supervisor receipt and `verified-summary.json` discloses a
wrapper-only error. The outer ad-hoc wrapper wrongly compared outcome to `passed` rather
than the supervisor's successful `completed`, so it exited 1. The raw pytest pass (81.8
seconds) and actual receipt were validated without a rerun. This is a validated exact-node
pass with a disclosed wrapper error, not a successful named signals profile.

The separately measured signal-positive/corruption/dependency times are
102.625 + 56.574 + 83.919 = **243.118 seconds before collection**, above the 240-second
serial signals ceiling. This is a projected over-cap sum of separate measurements, not an
actual new integrated failure or proof that the full profile fits. Windows `WinError 5`
remains unresolved; genuine assessment and actual live/provider/native/Linux validation
remain gaps. No quick/oracle cap waiver is claimed.

At that historical checkpoint, planner `81ada94f` had produced a read-only
`staged-authentic-producer/private-verified-materialization` proposal.
It was not yet implemented and could not be cited as accepted prerequisite reuse, timing
proof or permission to share validation caches. The staged machinery has since been integrated,
as recorded at the top; output detachment is now implemented with actual Windows
publisher/CI-reader evidence and a later optimized core-review pass. The historical named
consumers pass does not replace the unresolved exhaustive gate.

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

The dependency-job slice runs real accepted input loading, native metadata/link normalization,
repository deduplication, Scorecard response retention, exposure indexing and immutable
publication twice. Compiler/SBOM input and HTTP response are explicit recorded boundaries;
this is not evidence that current compiler, Syft or public Scorecard services work. Two
native dependencies share one repository/request; DEBUG versus runtime evidence resolves to
PROD without losing either source, while the separate QA dependency remains QA. A second
accepted attempt uses the private fresh cache without another request and preserves the
first index bytes.

That second attempt reproduced a production defect: index fingerprints included upstream
handoffs but omitted changing Scorecard/provenance/cache context, causing an immutable-shard
conflict. The fingerprint now also binds the exact normalized dependency, Scorecard and gap
content. The new case passed in a combined 28.70-second run (30.52 seconds wall); that run
also passed 25 existing dependency cases. One existing integrity-error wording assertion
failed identically with the pre-change dependency implementation: it expects `index integrity
mismatch` while the shared verifier returns `target evidence integrity mismatch`. This is a
named baseline failure, not a passing suite or a reason to weaken acceptance.

The real MCP subprocess workstream found malformed-first-message session termination and
stale request-id reuse. Focused regressions reproduced both before the correction; the
protocol now returns a null-id JSON-RPC parse error and continues. A separate owned-process
test confirms review-style heartbeat events remain in a disjoint stream while acceptance
events are written. It passed in 1.91 seconds (3.67 seconds wall). This demonstrates local
process/storage isolation, not zero CPU/I/O contention with a production review.

## Integrated seams and narrow corrections

- **W0 public execution:** `run-tests --acceptance <profile>` reads exact inventory obligations,
  supervises collection and individual cases, always applies strict adequacy, and emits a
  revision/source-bound result. The ordinary 60-second case cap has explicit 15/30/120-second
  obligation exceptions. The quick target is under ten minutes with a hard twelve-minute cap,
  not a completed final calibration.
- **W2 local execution:** real Dagster multiprocess configuration, worker death/resume,
  durable submission/reconciliation, MCP stdio discovery/error recovery, record/replay and
  sensor paths have bounded selections. The supervisor uses Windows Job Objects or Linux
  subreaper/identity-based cleanup; Linux-specific execution is not proven on Windows.
- **W3 controls/feeds:** configured source/standards normalization and loopback TLS use real
  application normalization/publication. The bounded control producer explicitly uses
  qualification, not genuine assessment; positive assessment/source binding, precomputed facts
  and the review join remain unverified. Valid JSON with a truncated HTTPS `Content-Length`
  is now rejected rather than accepted as a complete response.
- **W4 graphs/helpers:** source-resolving recorded graph rows reach actual semantic consumers;
  safe/unguarded, same-row and vacuous-subject negatives are explicit. The SQLite helper is an
  actual local CLI. This does not establish current CodeQL/graph-engine compatibility.
- **Authentic review/oracle:** real accepted review/gate/PoC planning and current final-report
  authority replace synthetic cross-contract assumptions. Benign/blocked publication and
  corrupted/stale accepted bytes are distinct from raw scanner detection.

The narrow production corrections observed by these seams are MCP malformed-first-message
parse-first/null-id recovery (without stale-id reuse), dependency context fingerprinting and
truncated HTTPS response rejection. Other work was not removed merely to turn the selection
green: the detailed PoC unit/job tests remain present.

## Revision-specific measurements

These are different evidence classes. A focused pytest result, a guarded nested-plugin run
and a public W0 invocation are not interchangeable. Times are stated at the scope actually
reported; setup duration is unavailable unless captured separately.

| Revision / scope | Recorded outcome | Limitation |
| --- | --- | --- |
| `bbcbf0b1`, public `signals` | 3/3 passed, 161.535 s | Public-driver evidence for that revision only; not latest-main quick calibration |
| Before latest-main merge, direct authentic review/oracle | 13 passed, reported 304.33 s | Direct test timing, not public W0; exact tested revision/setup duration not supplied in this handoff |
| `ec653020`, W4 focused tests | 40 passed, 18.09 s wall | Focused tests, not public W0 |
| `ec653020`, W4 local audit | 22 passed, 15.15 s wall | Local audit, not public W0 |
| Earlier W3 public controls/feed selection | 6 passed, 110.830 s | Control body 87.355 s; feed bodies below 1 s; older selection/revision |
| `495f4300`, public TLS selection after truncation fix | 7 passed, 27.654 s | TLS cases only, not a final integrated profile |
| `495f4300`, related focused tests | 15 passed, reported 5.99 s | Focused test timing, not public W0 |
| `ec48a7c0`, W2 nested Windows warm runs with exact extracted W0 guard/plugin | 14/14 selected cases passed in each of 216.859 / 218.118 / 214.753 s, cleanup confirmed | Three guarded nested runs, not integrated public-driver calibration |
| Same W2 measurements | Maximum tagged case 52.435 s including cleanup, below its 60 s cap | Does not establish every new integrated case's budget |
| Latest-main reconciliation, first public `review` attempt | 6 cases failed, 49.071 s | Active coordinator debugging; neither a passing profile nor a final diagnosis |
| `6265bbc7`, public `quick` | Failed: 39/45 cases passed, 717.061 s, cleanup confirmed | Six failures detailed above; not a whole-profile green result |
| `19c7c000`, guard/inventory focused validation | 7 passed, reported 8.81 s | Narrow correction validation only; later W5 exact-node result below, whole quick still pending |
| `06a4ea6c`, W5 final direct tests | 3 passed, 181.27 s pytest / 183.725 s wall | Direct execution, not a named profile |
| `06a4ea6c`, W5 exact-node supervisor/plugin | 3/3 passed, 225.664 s group, all owned trees empty after cleanup | Actual guarded boundary, but not a named profile CLI run; later `consumers` enrollment does not retroactively change that |
| `e50b5a3e`, W3 explicit qualification | Supervised pass, 65.490 s, cleanup zero; configuration validation reported 2.48 s | Qualification only, not genuine assessment or the full controls profile |
| `b9e55009`, public `signals` | Failed, 80.607 s, required catalog missing | Producer omission corrected later; not a passing baseline |
| `5d7a35c4`, exact-node signal positive | Passed, 99.837 s including cleanup | Real catalog retained; not a whole signals profile pass |
| `5d7a35c4`, public `review` | Failed, six cases, 593.872 s | Candidate/oracle timed out; four other cases passed |
| `09cbf227`, focused harness/inventory/lanes units | 42 passed, one host-symlink skip, 59.27 s | Direct unit validation; symlink capability and public calibration remain gaps |
| `b72e79a9`, exact-node candidate/oracle follow-up | Candidate passed 112.285527 s; oracle timed out 117.024162 s; group 229.923300 s, both cleanups zero | No oracle assertion reached; not a green review profile |
| `b72e79a9`, bounded direct functional matrix | Timeout 117.014358 s, cleanup zero; report fixture completed 104.102093 s | Audit plugin absent; oracle evaluation started but did not complete, so not merely guard overhead |
| `16a520f4`, named public `process` | 13/13 passed, 340.136 s, cleanup zero | Real profile CLI proof on that revision; Linux-specific requirements unexecuted |
| `1ff86556`, named public `consumers` | 3/3 passed, 207.438 s, public cleanup requirement satisfied | Named profile proof on that revision, not exhaustive W5 or concurrent production review |
| `1ff86556`, final guarded dependency exact node | 1/1 passed, 83.9186626 s, cleanup zero; raw pytest 81.8 s | Wrapper-only exit 1 disclosed and receipt verified without rerun; not whole signals |
| Focused native/interchange/selected-overlay units | 7 passed, reported 9.73 s | Focused unit scope only |
| Separate signal-positive/corruption/dependency measurements | 102.625 + 56.574 + 83.919 = 243.118 s before collection | Projected above serial signals 240 s; not an actual new integrated failure |

Final result paths, exact calibration revision, working-tree/source identities, per-case budgets,
collection/setup overhead and cleanup must come from the corresponding public driver's
`result.json` and referenced process artifacts before updating the integrated budget claim.
Do not reconstruct unavailable setup metrics by subtracting unrelated test-body timings.

## Named remaining gaps and baseline failures

- Linux guardian and peer-credential cases are implemented but unexecuted in the Windows
  measurements; actual WSL dispatch is also unexecuted. Windows PowerShell with a private
  transport is not WSL/native compatibility evidence.
- The pinned `DagsterRun` lacks `create_timestamp`; queue-delay timing is unavailable.
- Actual native containers/daemon/provider compatibility, cold builds, current CodeQL,
  Lua/native variants and the full runtime/language matrix have not been authorized/executed.
  The `tools`, `deployed`, `provider`, `guidance`, `codeql-warm` and `native` public profiles
  deliberately fail as unimplemented, not successfully skipped.
- Genuine OWASP assessment, positive assessment/source binding, precomputed facts and the
  review join remain unverified by the bounded qualification lane. Unknown original
  recorded-feed production cannot be claimed as a real live computation.
- Three bounded W5 triage/referral/presentation nodes have exact-node guarded evidence above
  and a later named `consumers` profile pass. The listed specialist, renderer-selection,
  saturation and cross-lane obligations remain unverified; separate historical quick warm
  evidence does not widen those three consumer obligations.
- Historical `b72e79a9` passed the tiny candidate but timed out the all-in-one oracle.
  At `d6042ab9`, native-positive PoC timed out and blocked candidate/corruption consumers.
  The optimized Windows review now passes 13/13, and all three frozen quick warm runs pass
  38/38 under ten minutes with two workers; corrected named portable process passes 13/13.
  The first split integrity qualification at `086ded0a` also failed. The approved bounded
  series subsequently qualified at `856300ca`; monolithic `review-exhaustive` and named
  platform/provider/assessment gaps remain outside that proof.
- Two existing ELF catalog tests assert an exact gap count and fail after the new
  `delivery_fact_unavailable` gap. The dependency verifier error-wording discrepancy described
  above is also baseline. Neither is silently converted into passing acceptance.

The acceptance guard is a regression guard, not a hostile-code sandbox. Fixture subprocesses
must use invocation-owned, short Windows working directories and must not run child git; the
supervisor exports `APPSEC_ACCEPTANCE_TESTED_COMMIT`. All state and production-format telemetry
remain in unique `test/tmp/acceptance/` roots with separate private runs/driver/HOME/TEMP and
DAGSTER_HOME. No target, production run/data tree or production service is needed. This permits
concurrent process/storage isolation but makes no zero-contention CPU/I/O guarantee; serial is
the default and host load still affects calibration.
