# Wait-all rendezvous and terminal-instance manifest

## Status

Backlog batch C02. `appsec-review-process/pool_rendezvous.py` implements
`appsec-review/pool-rendezvous-manifest/1.0` and the classification rule
`appsec-review/pool-instance-classification/1.0`. It launches every expected instance of one
verified C01 expansion through the real B13 and B14 adapters (`worker_adapters`), waits for all of
them, and publishes one terminal-instance manifest. Nothing here is a Dagster op, a lifecycle job,
a merge or a quorum, and no graph, launcher or `owasp_*.py` module uses it yet. The order
decided on 2026-09-20 is B13, B14, B15, C01, C02, T10; C03 (typed merges) and T10 (OWASP validator
dispatch) build on the manifest written here.

Qualification: **unit level** (`IMPLEMENTED_NOT_QUALIFIED`). Three things are NOT done and each
has its own section below: no Dagster op runs the rendezvous ("Capability record"), at most one
engagement runs at a time, while rendezvous inside it may be concurrent and each sees only itself
("Constraint: one engagement at a time"), and a reviewer's
producers and chain independence are not built ("Not done: producers and chain independence").
Schema ids stay `1.0` although the instance record gained `state_reason` and the reader's return
type changed in the review of PR #35: nothing of C02 is released or consumed, as with C01.

```text
verified expansion --> launch (bounded threads) --> wait (condition) --> classify from DISK --> publish, last
   (C01, re-derived)    real adapters, B15 caps      worker end, cancel,    adapter's own verifier    exclusive create,
                                                     deadline wake it       classify_instance         all bytes or none
```

## Calls

| Call | What it does |
|---|---|
| `run_rendezvous(pool_root, *, expected_spec, context, runtime)` | verifies the expansion, launches, waits, publishes once; returns the frozen manifest |
| `verify_manifest(pool_root, *, expected_spec, context, rendezvous_parent)` | read-only; re-derives the manifest from the expected specification, the expansion and the attempts on disk; returns fixed-text errors |
| `load_verified_manifest(...)` (same arguments) | a frozen `VerifiedManifest`: the manifest parsed from the very bytes that were verified, the plan, and per instance the adapter result that verification obtained (see "Reading a rendezvous") |
| `classify_instance(plan, index, *, pool_root, context, observation)` | THE rule: one instance's manifest entry |
| `derive_manifest(plan, *, pool_root, context, observations)` | the whole manifest for one observation per instance |
| `adapter_runtimes(plan, context, runtime)` | the B13/B14 runtimes of exactly the kinds the expansion has, built by the context |
| `expansion_errors(pool_root, *, expected_spec, context)` | C01's check with the one tolerance described under Verification |
| `pool_outcome(states)` | the pool-level outcome |

No argument is optional.

### The context is the single carrier of host facts

B13's verifier builds the one docker argv a run of a request can have, so it requires
`host_flavor`, `docker_host`, `docker_executable` and `container_user`; B14's requires the registry,
prompt root, readable roots, allowed models, snapshot and ceiling. Since the review of PRs #34/#35
(Q3) **all of them are `PoolContext` fields** (`docs/pool-specification.md`), and this module keeps
no second copy:

- the coordinator builds both adapter runtimes with `context.container_runtime(clock=, cancel=)` and
  `context.persona_runtime(invoker=, clock=, cancel=, stop_grace_seconds=)`, so an instance cannot
  run under one registry, image directory, snapshot, docker executable or container user and be
  verified under another. A ready-made adapter runtime cannot be handed in;
- the coordinator and every reader call the adapters' verifiers with
  `context.container_verification_arguments()` / `context.persona_verification_arguments()`.

A later process (C03) therefore re-supplies exactly the `PoolContext` of the run and nothing beside
it. With another `docker_executable` or `container_user` than the launch used, exactly the container
instances stop verifying. A context without the container facts (`None`, allowed by C01 for a
persona-only caller) is refused by every call here for an expansion that has pinned-container
instances. Nothing is defaulted (`container_execution.host_defaults()` is not called here) and
nothing is read from an attempt.

### Runtime

`RendezvousRuntime` is a frozen dataclass with no defaulted field. It holds only what exists while
something is launched (C01's `CONTAINER_LAUNCH_ONLY_FIELDS` / `PERSONA_LAUNCH_ONLY_FIELDS`) and the
rendezvous' own bounds; a test proves it shares no field with `PoolContext`.

| Field | Meaning |
|---|---|
| `rendezvous_parent` | run-owned directory for manifests; absolute, real, one spelling; may not be, contain or lie beneath `context.pool_parent` (device and inode), so no worker of any pool below that parent can reach a manifest |
| `invoker` | the B14 invoker; must be the one `context.invoker_id` names. `None` only when the expansion has no persona instance |
| `clock` | the adapters' clock (a callable returning a UTC timestamp) |
| `stop_grace_seconds` | B14's stop grace after a cancel |
| `cancel` | a `PoolCancel`; the one cancel event both adapter runtimes are built with |
| `max_parallel` | 1..`MAX_PARALLEL` instances in flight, whatever their kind |
| `wait_limit_seconds` | can only narrow the specification's `rendezvous_timeout_seconds`: the wait lasts `min` of the two |
| `drain_seconds` | 0..180: how long launched workers get to wind down after the wait ended |

The runtimes are built before the lock is taken and before anything is created; a refusal there is
C01's `PoolSpecError` (missing container facts, an invoker that is not the context's, a clock or stop
grace the adapter refuses) and launches nothing.

## Layout

```text
<context.pool_parent>/<pool directory>/           C01's pool root; unchanged by this module
    instances/<instance id>/                       written by that instance's adapter only
<runtime.rendezvous_parent>/
    <pool directory>.lock                          coordinator lock (kernel-released on death; never deleted)
    <pool directory>/                              rendezvous root, mode 0700
        terminal-instances.json                    the manifest: created exclusively, last, never replaced
```

Nothing is written into the pool root (C01's verifier requires exactly its four entries) or into
an instance root (B14 treats a change outside its output root as `OUTPUT_ESCAPE`). The rendezvous
root is named by the bare 32-hex pool directory, which survives the V06 redactor as a path.

## Terminal states

Closed vocabulary of **eleven** states (`STATES`). Exactly the first five adopt an adapter result.

| State | Meaning | Source |
|---|---|---|
| `succeeded` | verified adapter result, `OK`, and nothing of that attempt may still be writing (`invoker_stopped` / `container_removed` is `true`) | disk |
| `failed` | verified result, `FAILED`, any cause but `TIMEOUT` | disk |
| `blocked` | verified result, `BLOCKED` | disk |
| `canceled` | verified result, `CANCELED` | disk |
| `instance_timed_out` | verified result, `FAILED` with cause `TIMEOUT`: the instance's own timeout | disk |
| `rendezvous_timed_out` | launched, and the wait ended before it reported. Whatever is or later appears in its root is **not adopted**; `worker_stopped` says whether its thread was gone after the drain | coordinator |
| `crashed` | the root holds attempt evidence but no adapter result file: worker lost, adapter could not persist, coordinator died mid-attempt, or something was planted in the root | disk |
| `invalid` | evidence that cannot be adopted: the adapter's verifier refuses the result, the root is no longer a private real directory, evidence sits in a root this coordinator never launched into, or an `OK` whose writer is not known to have stopped | disk |
| `not_launched_canceled` | the pool was canceled before this instance was launched; its root is empty | coordinator + disk |
| `not_launched_rendezvous_timeout` | the wait ended before this instance was launched; its root is empty | coordinator + disk |
| `missing` | no attempt evidence at all: the root is gone, a worker reported and left nothing, or its thread could not be started | disk |

### State reasons

`invalid` merges five causes and `missing` three, and C03/C04 will want to tell them apart, so every
entry carries a required `state_reason` from a closed enum (`STATE_REASONS`; which reasons a state
may have is `REASONS_BY_STATE`, tied to the schema's enum by a test). (Review of PR #35, Q4:
coordinator's recommendation, owner to confirm.)

| State | `state_reason` | Decided by |
|---|---|---|
| the five result states | `verified_adapter_result` | disk |
| `rendezvous_timed_out` | `worker_stopped_after_the_wait_ended` / `worker_still_running_after_the_drain` (the same fact as `worker_stopped`) | coordinator |
| `crashed` | `attempt_evidence_without_adapter_result` | disk |
| `invalid` | `adapter_verifier_refused_the_result` | disk |
| `invalid` | `instance_root_not_a_private_directory` | disk |
| `invalid` | `evidence_nobody_launched` (unlaunched or unstartable, and the root is not empty) | coordinator + disk |
| `invalid` | `ok_result_whose_writer_has_not_stopped` | disk |
| `invalid` | `adapter_status_not_classifiable` (a verified result whose status is none of the adapters' four; unreachable while their enums hold) | disk |
| `not_launched_canceled` | `pool_canceled_before_launch` | coordinator + disk |
| `not_launched_rendezvous_timeout` | `wait_ended_before_launch` | coordinator + disk |
| `missing` | `instance_root_absent` | disk |
| `missing` | `adapter_left_no_evidence` (the worker ran and the root is still empty) | coordinator + disk |
| `missing` | `worker_thread_not_started` (the interpreter refused the thread, or it never ran) | coordinator + disk |

The verifier re-derives the whole entry, reason included, so a reason the disk decides cannot be
resealed to another. What only the coordinator saw is **bounded**, not proven: for an empty root the
verifier accepts `adapter_left_no_evidence` or `worker_thread_not_started` (and the two
`not_launched_*` states), for `rendezvous_timed_out` either of its two reasons, and nothing else.

**A worker that never began is never `rendezvous_timed_out`.** A worker thread is registered before
it is started and passes a launch gate under the waiter's lock before it touches its adapter. When
the wait ends, or when an interrupt lands between taking an instance off the pending list and
starting its thread, whatever has not passed the gate is recorded as not launched
(`not_launched_canceled` for a cancel or an interrupt, `not_launched_rendezvous_timeout` for the
deadline) under that same lock, and a thread that reaches the gate afterwards launches nothing. So
`worker_stopped: false` is only ever said about a worker that really began.

"Verified" means the adapter's own `load_verified_result` passes for that instance's ids and the
request the expected specification derives (`container_execution`, `persona_invocation`). **Any
exception from an adapter's verifier is a refusal** (`invalid`), a `TypeError` from a changed
adapter signature included: it never propagates out of the coordinator or the verifier, never
passes, and its text is never kept. This happened for real when B13's verifier gained required
arguments: every container instance became `invalid` and no pool was `COMPLETE`. A value
an adapter returned and a worker thread's report are never read for state: a worker that returns
`OK` and leaves nothing on disk is `missing`. `adapter_status` and `adapter_cause` are the verified
result's `execution_status` and `cause`; `result_file` is `{path, sha256, bytes}` of the adopted
`invocation-result.json` or `container-result.json`. B14's `invoker_stopped: false` (a stuck
invoker) is carried through; B14 only records it on `TIMEOUT` and `CANCELED`, so its later output
is never part of a success.

### The one rule

`classify_instance` is called by the coordinator (before publication) and by the verifier, and
nothing else decides. It is a pure function of the expansion, the disk now, and one of six
coordinator observations (`OBSERVATIONS`; `_entry`'s docstring has the same table with reasons):

| Observation | Disk | State |
|---|---|---|
| any | instance root absent | `missing` |
| unreported (thread stopped / still running) | anything | `rendezvous_timed_out` |
| unlaunched (cancel / timeout) | root empty | `not_launched_canceled` / `not_launched_rendezvous_timeout` |
| unstartable (no worker thread) | root empty | `missing` |
| unlaunched or unstartable | root not empty | `invalid` |
| reported | root is not a private real directory | `invalid` |
| reported | root empty | `missing` |
| reported | evidence, no result file | `crashed` |
| reported | result file, verifier refuses | `invalid` |
| reported | verified result | by status and cause |

"Reported" means the attempt ended before the wait ended, **or its evidence already existed when
the coordinator started** (restart). The observation is not published; it selects the state.

## Pool outcome

`pool_outcome(states)` is a pure function of the instance states, in this precedence:

| Outcome | Rule |
|---|---|
| `EMPTY` | no instance. The manifest carries `expansion_state: "EMPTY"` and the `empty_pool_reason`. Not a result set |
| `COMPLETE` | every instance `succeeded`. The only whole result set |
| `CANCELED` | any instance `canceled` or `not_launched_canceled` |
| `FAILED` | no instance `succeeded` |
| `DEGRADED` | some succeeded and some did not |

Nothing is dropped or flattened: every instance keeps its kind, group, ordinal, resource pool,
state, cause and result pointer, and `counts` has one integer per state that sum to `instances`.

## Waiting

The coordinator thread waits on one `threading.Condition`. Three things wake it: a worker thread
ending (it notifies in its `finally`), the pool cancel (`PoolCancel` is a `threading.Event`, which
the adapters require and poll, whose `set()` also notifies subscribed waiters), and the deadline
(the wait's own timeout). There is no sleep and no state poll.

| Number | Value | Why |
|---|---|---|
| `LIVENESS_BACKSTOP_SECONDS` | 5.0 | upper bound of one `Condition.wait`. Not how state is observed: it bounds how long a lost wake-up could go unnoticed, namely a worker thread that died without running its `finally`. On wake-up the only work is a constant-time `is_alive` check; at most 12 idle wake-ups a minute. A test asserts that nothing wakes the waiter during an idle half second and that a whole pool costs fewer waits than worker events |
| `MAX_PARALLEL` | `resource_pools.AGGREGATE_STEP_CEILING` (6) | the most steps B15's merged limits allow one host at once; a runtime may ask for less, never more |
| `DRAIN_BOUNDS` | 0..180 s | after the wait ended. B14's stop grace is at most 60 s and B13 removes a container with at most two 60 s control calls, so more buys nothing |
| effective wait | `min(rendezvous_timeout_seconds, wait_limit_seconds)` | the runtime can only narrow the recorded timeout |

The adapters' own intervals are theirs (B14 joins its invoker thread in 20 ms slices; the child
runner polls its cancel event).

### Concurrency

In flight at once: at most `max_parallel` instances; persona instances at most
`min(totals.persona_slot_request, LIMITS[persona_llm])`; per derived resource pool at most
`resource_pools.LIMITS[pool]` (so tool instances run one at a time today). These are in-process
caps that, **within one rendezvous**, can only be at or below B15's. No limit is raised here. They
do not see any other rendezvous, in the same run or another: see "Constraint: one engagement at a time".

Threads: one daemon thread per launched instance, named `pool-instance-<n>`. An instance is
launched only into the still empty, real directory the expansion created.

## Constraint: one engagement at a time

**Owner decision 2026-09-21** (review of PR #35, Q2, clarified the same day): **one engagement at a
time for now.** The review processes themselves are not concurrent: two engagements never run
together, so there are never two OWASP pools at once. **Inside one engagement, concurrency is fine:**
a flow that forks branches A and B may have each start its own pool -- an OWASP review in A, a
red/blue-team pool in B -- and those rendezvous run at the same time.

What that does and does not give:

- The caps in this module are counters inside one Python process, and forked branches of one Dagster
  run are separate step processes. **A rendezvous sees only itself.** The op that calls
  `run_rendezvous` is `resource_pools.unassigned('coordination_only')`: it holds no Dagster pool
  slot, and the instances it launches are threads, not pooled ops.
- So B15's numbers bound EACH rendezvous, not the host. With k rendezvous running concurrently inside
  the engagement, the host can see up to k containers although B15 limits `docker` to 1, and up to
  3k persona invocations although `persona_llm` is limited to 3. k is bounded by the executor's
  steps per run (`workflow-plan.json` `max_concurrent_steps`, 3). One engagement at a time removes
  the multiplication by engagements; it does not remove k.
- B15's `persona_slot_request` is a per-RUN bound (ADR-0008 Decision 6); here it is applied per
  pool, so two pools of one run each take it.
- B15's live-qualified behaviour -- a cancelled or failed run releases its slots, queued steps wait
  their turn, a slot is returned when the step's process ends -- **does not apply to these
  instances**. What applies instead is this module's own cancel, drain and restart handling.

Enforcing the decision is for the op's author (T10): the job that contains a rendezvous op gets a
run-level tag and a tag concurrency limit of 1 in the run coordinator's configuration, so a second
engagement's review run queues. A run-level limit does not restrict the rendezvous ops INSIDE the
run, which is the intent. That op, that tag and that limit do not exist yet, and T10 does not merge
without them. Until then this is an operating rule, not an enforced one: the run queue still admits
two runs of two engagements (`max_concurrent_runs: 2`, one per engagement), which is what
`qualify_workflow.py` asserts. Nothing in this module can enforce it across processes (the per-pool
lock only excludes a second coordinator of the SAME pool).

The aggregate across concurrent rendezvous of one engagement stays open as the parity gap
`in_process_caps_do_not_see_other_rendezvous`. It closes when instances are launched as dynamically
mapped POOLED ops with C02 as the collector (the target design; it changes this module's launch
API, not its manifest): B15's pools then count across branches natively, and B15's cancellation and
slot-release behaviour applies. `docs/resource-pools.md` states this under Limitations.

## Cancel, timeout, late finish

- **Pool cancel.** Setting `runtime.cancel` stops launches at once (pending instances become
  `not_launched_canceled`) and reaches every running adapter, because it is the adapters' own
  cancel event. The wait continues until they have reported or the deadline passes; B13 and B14
  write `CANCELED` results, which are verified and adopted as `canceled`.
- **Interrupt.** From the moment anything may have been launched until the manifest is published --
  the wait, closing the ledger, the drain, derivation, validation and publication -- a
  `KeyboardInterrupt` or `SystemExit` in the coordinator is **held**: it sets the pool cancel, the
  step it landed in is entered again (every step is resumable: nothing is launched twice, the
  ledger closes once, the drain keeps its one deadline, publication links nothing twice), and the
  first one is re-raised after publication. A second interrupt also cuts the drain short; the
  manifest is still published, with whatever had not stopped as `worker_stopped: false`. An
  interrupted rendezvous therefore never leaves a pool unpublished for a later run to adopt a late
  result from (review of PR #35, F1). Two bounds: an interrupt BEFORE the first launch (expansion
  check, lock, restart scan) propagates at once, because nothing was launched; and after
  `MAX_HELD_INTERRUPTS` (32) held interrupts the next one is given back although nothing was
  published, so a caller that raises forever cannot hang the coordinator.
- **Rendezvous timeout.** At the deadline the ledger is closed: what has not reported is
  `rendezvous_timed_out` or `not_launched_rendezvous_timeout`, for good. The coordinator then sets
  the cancel event (it stops what it no longer waits for) and drains for `drain_seconds`.
- **Late finish.** A worker that ends after the ledger closed cannot report (`TerminalLedger`
  refuses it). Its result may well be valid on disk, even `OK`; the manifest says
  `rendezvous_timed_out` with no `result_file`, the manifest is never replaced, and a later
  `run_rendezvous` fails closed. `worker_stopped: false` tells T10 that something may still write
  into that (not adopted) root.

## Publication

The manifest is derived after the wait, checked with the verifier's own acceptance rule
(`manifest_errors`), and published by writing a complete temporary file, `fsync`, and
`os.link(temporary, final)`: all of the bytes or none, and never over an existing manifest. A crash
before the link leaves no manifest. Tests prove that the rendezvous root is empty while any
instance is still running and that publication happens once, after every result is on disk.

## Restart and duplicate terminal

`run_rendezvous` takes the pool's lock (`execution_state.Lock`, kernel-released when a coordinator
dies). A second coordinator while the first is alive gets `RendezvousBusyError` and launches
nothing. After publication every call gets `RendezvousPublishedError`; the file is not touched.

Under the lock a restarted coordinator:

1. clears its predecessor's unpublished temporary file, or finishes a publication that was killed
   between the link and the unlink; anything else in the rendezvous root is refused;
2. classifies every instance root that already holds anything from disk and **never launches into
   it**: a verified attempt is adopted with its state, a half-written one is `crashed`. For a
   crashed tool instance it force-removes the run-owned container a dead coordinator may have left
   (best effort, not recorded);
3. launches only the instances whose root is still empty, then waits and publishes as usual.

`TerminalLedger` refuses a report for an unknown instance, a second report for one instance (the
first stands) and any report after the wait ended. A report carries no state.

### Timestamps and determinism

The manifest has **no timestamp, no host path, no container name and no free text**. The adapters'
timestamps stay inside their own result files, which the manifest binds by hash. One set of on-disk
facts and observations therefore derives one byte sequence: a test runs the same specification in
two directories, kills one coordinator's work after two instances, and compares the published
bytes; another kills a real coordinator process (SIGKILL) and proves the restart's bytes equal
`derive_manifest` over the disk.

## Verification

`verify_manifest` first runs C01's `check_expansion` ONCE and uses the plan that check derived. It
tolerates exactly the findings whose code is in `pool_specification.INSTANCE_ROOT_DAMAGE_CODES`
(`instance_root_missing`, `instance_root_not_a_private_directory`): damage to ONE EXPECTED instance
root, which the classification rule records as that instance being `missing` or `invalid`. Findings
are selected by code, never by message text. Every other finding refuses the manifest exactly as it
makes `run_rendezvous` refuse the pool -- in particular an unexpected extra entry under
`instances/` (`instance_root_unexpected`), an `instances` that is not a real directory
(`instances_not_a_directory`) and two roots that are one directory (`instance_roots_shared`): no
classification rule covers those, so they are nobody's instance outcome (review of PR #35, F2; a
test walks C01's whole code list).
Then the rendezvous root must be a real directory holding exactly the
manifest, a regular, singly linked, bounded file read without crossing a link and parsed with
`parse_document` (no repeated key). Then, per instance, the recorded entry must equal what
`classify_instance` derives **now** for one of the six observations, and the whole file must be
the bytes `derive_manifest` derives for those observations. No hash in the manifest is an input:
every adopted result is re-verified by its adapter's verifier, which reads every file it hashes, so
a producer who edits one file and reseals every hash is refused. Messages are fixed text.

## Differences from design-v3 5.5 and the task text

| Source | Says | Here |
|---|---|---|
| design-v3 5.5 (proposed) | the waiter polls with `time.sleep(N)` | condition based, no sleep; TODO C02 and the parity plan both say "non-busy", and they win |
| design-v3 5.5 | the launcher launches, the waiter reads a job manifest of output paths | one module launches and waits; "terminal" is the adapter's verifier, not a path appearing |
| design-v3 5.5 | bounded by the job's `timeout_seconds` | `rendezvous_timeout_seconds`, which a runtime may narrow but not widen |
| C01 doc, "What C02 needs" | launch in the Dagster pool `resource_pool` | in-process caps at or below B15's; Dagster pools remain the integrator's |
| ADR-0009 / T10 | a `skipped` cell | no adapter emits `SKIPPED`; a pool that has nothing to do is `EMPTY` with a reason, and an instance that did not run is `not_launched_*` |

## Limitations

- Nothing is signed. The verifier proves that the manifest agrees with the disk and the expected
  specification, not which observation the coordinator made. Whoever can rewrite the manifest can
  claim any entry the rule derives for *some* observation: for a verified attempt that is its true
  state, `rendezvous_timed_out` or `invalid` (a downgrade that adopts nothing), and for a
  late-finished attempt also its now-valid result. Never another instance's result and never a
  success without a verified result. Exclusive creation and the lock are what keep the published
  file as the coordinator wrote it.
- Verification reads the disk **now**. An adopted attempt that changes or disappears after
  publication makes the whole manifest unverifiable (fail closed), including a stuck invoker's late
  write if B14's verifier ever starts to look at a canceled attempt's output root.
- A process killed between `os.link` and the unlink leaves a complete manifest with two names; the
  verifier refuses it until any later `run_rendezvous` call finishes that publication.
- Threads cannot be killed. A worker that ignores cancel stays alive as a daemon thread after
  publication; its root is never adopted, and the manifest says `worker_stopped: false`.
- The restart's container removal is best effort and is not recorded.
- A coordinator that dies after the deadline but before publication forgets that deadline: the
  restart adopts what is verified on disk. Only a published manifest makes "late" final.
- In-process caps do not see other rendezvous; see "Constraint: one engagement at a time".
- An interrupt before the first launch publishes nothing (nothing was launched); see Interrupt.
- Windows: `os.link` needs NTFS; path rules are the adapters'.

## Reading a rendezvous

`load_verified_manifest` returns a frozen `VerifiedManifest`:

| Attribute | Value |
|---|---|
| `manifest` | the manifest, deeply immutable, parsed from the very bytes that were verified |
| `plan` | C01's `ExpansionPlan` the manifest was verified against (one derivation) |
| `instances` | one frozen `VerifiedInstance(instance, record, result)` per expected instance, in order: C01's `PlannedInstance` (ids, request, `attempt_root_path`), the manifest record, and -- exactly for the five result states -- the adapter result that the adapter's own verifier returned during this verification, whose canonical bytes `record["result_file"]` pins; `None` otherwise. `.state` is the record's state |
| `outcome`, `in_state(state)` | the pool outcome; the instances in one state |

A consumer calls no adapter verifier and re-supplies no host fact beside the `PoolContext`. It is
a cache of ONE verification, never an authority: a consumer that needs the facts later calls
`load_verified_manifest` again.

**Read a pool through this reader, not through `pool_specification.load_verified_expansion`.** C01's
loader refuses any pool root with a deleted or replaced instance root -- which is exactly the pool
whose manifest honestly records a `missing` or `invalid` instance. The reader here tolerates that one
kind of damage and nothing else (see Verification) and hands over the plan.

The first ten lines C03 would write (`test_the_first_ten_lines_of_c03_against_the_reader` runs
exactly these, over a pool with a `missing` instance):

```python
verified = pr.load_verified_manifest(pool_root, expected_spec=spec, context=context,
                                     rendezvous_parent=parent)
if verified.outcome not in (pr.COMPLETE, pr.DEGRADED):
    raise NothingToMerge(verified.outcome)
candidates = []
for item in verified.in_state(pr.SUCCEEDED):
    attempt_root = item.instance.attempt_root_path(pool_root)
    for output in item.result["outputs"]:
        candidates.append((item.instance.instance_id, item.result["persona_id"], item.result["model"],
                           attempt_root / item.result["output_root"] / output["path"], output["sha256"]))
absent = [(item.instance.instance_id, item.record["state_reason"]) for item in verified.in_state(pr.MISSING)]
```

## Not done: producers and chain independence

Owner decision of 2026-09-21 (recorded under C02 in `TODO.md`): C02 builds a reviewer's `producers`
from verified results and owns chain independence over every ancestor. **This PR does not implement
it**, and nothing here should be read as if it did:

- no call builds a reviewer request's `producers` / `producer_result` inputs from the verified
  results of an earlier pool. Reviewer requests are fixed at C01 expansion, before any producer of
  the same wave has run, and one `run_rendezvous` runs one pool;
- nothing walks a result's own `producers` to its ancestors, so "this reviewer is independent of
  every producer in its chain" (B14's independence rule, applied transitively) is not checked
  across pools.

Where it would live: a helper over `load_verified_manifest` (for example
`producer_pins(verified)` and `chain_independence_errors(verified, ancestors)`), which emits one
producer pin per `succeeded` instance and walks each result's own `producers`. The manifest carries
no persona or model identity per instance, so the helper must read them from the verified RESULT
FILES (`VerifiedInstance.result`: `persona_id`, `model`, `invoker_id`, `result_sha256`), which the
reader now hands over; for ancestors in other pools it needs those pools' verified manifests as
well. A second-wave pool's specification would then be expanded only after the first wave's
manifest is verified. Tracked as C02b / inside T10; parity gap `chain_independence_not_implemented`.

## Capability record

The parity capability `wait-all-rendezvous` lives in
`appsec-review-process/design-parity-manifest.json` (generated views: `docs/design-parity-report.md`
and the views `validate_design_parity.py --write-generated-views` writes), updated in this PR:

| Field | Value |
|---|---|
| readiness | `missing_prerequisites` -- no Dagster op consumes the rendezvous |
| execution mode | unchanged |
| qualification level | `unit`; references are `tests/test_pool_rendezvous.py`, `tests/test_pool_rendezvous_cross_slice.py`, `tests/test_pool_rendezvous_live.py` |
| gaps removed | `waiter_missing`, `terminal_instance_manifest_missing` |
| gaps stated | `no_dagster_op_runs_the_rendezvous`, `chain_independence_not_implemented`, `in_process_caps_do_not_see_other_rendezvous` |
| next prerequisite | C03 (typed merges) / T10 (OWASP validator dispatch) |

## What T10 and C03 need

- Expand one pool per wave with C01, then `run_rendezvous`, from an op tagged
  `resource_pools.unassigned('coordination_only')`, in a job limited to one run at a time
  ("Constraint: one engagement at a time"). Afterwards, and in any later process, read only
  through `load_verified_manifest` with the run's `PoolContext`. A `RendezvousError` there means
  **no instance of that pool may be treated as assessed**.
- Invariants a consumer may rely on: `instances` is the expansion's list, same ids, same order,
  each once; `counts` sum to `instances`; `outcome == pool_outcome(states)`; `result_file` is
  non-null exactly for `RESULT_STATES`; only `succeeded` has `adapter_status == "OK"`;
  `state_reason` is one of `REASONS_BY_STATE[state]`.
- Mapping a T06 handoff batch: one persona group per handoff (or `count: n` for n independent
  validators of one handoff), the handoff as a readable input with role `handoff` (C01). Keep
  `group_id` and `ordinal` to map an instance back to its handoff and rows.
- `not_assessed`: every applicable row of a handoff whose instance is not `succeeded` is
  `not_assessed`, with the instance's `state`, `state_reason`, `adapter_status` and `adapter_cause`
  as failure provenance (ADR-0009). A `succeeded` instance only says the adapter's checks passed;
  T07's validator-result validation still decides whether its output is a valid result. `EMPTY` is a
  coverage statement with its reason, never an assessed set. A newer failed attempt is a new
  specification `attempt_id`, hence a new pool root and a new manifest: there is nothing here that
  could fall back to an older one.
- For a `succeeded` instance use `VerifiedInstance.result` (or the adapter's `to_worker_envelope`
  with the context's verification arguments); the manifest's `result_file.sha256` pins its bytes.
