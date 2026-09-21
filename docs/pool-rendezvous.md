# Wait-all rendezvous and terminal-instance manifest

## Status

Backlog batch C02. `appsec-review-process/pool_rendezvous.py` implements
`appsec-review/pool-rendezvous-manifest/1.0` and the classification rule
`appsec-review/pool-instance-classification/1.0`. It launches every expected instance of one
verified C01 expansion through the real B13 and B14 adapters (`worker_adapters`), waits for all of
them, and publishes one terminal-instance manifest. Nothing here is a Dagster op, a lifecycle job,
a merge or a quorum, and no graph, manifest, launcher or `owasp_*.py` module uses it yet. The order
decided on 2026-09-20 is B13, B14, B15, C01, C02, T10; C03 (typed merges) and T10 (OWASP validator
dispatch) build on the manifest written here.

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
| `load_verified_manifest(...)` (same arguments) | the frozen manifest, parsed from the very bytes that were verified |
| `classify_instance(plan, index, *, pool_root, context, observation)` | THE rule: one instance's manifest entry |
| `derive_manifest(plan, *, pool_root, context, observations)` | the whole manifest for one observation per instance |
| `pool_outcome(states)` | the pool-level outcome |

No argument is optional. `RendezvousRuntime` is a frozen dataclass with no defaulted field:

| Field | Meaning |
|---|---|
| `rendezvous_parent` | run-owned directory for manifests; absolute, real, one spelling; may not be, contain or lie beneath `context.pool_parent` (device and inode), so no worker of any pool below that parent can reach a manifest |
| `container_runtime`, `persona_runtime` | the B13 `ContainerRuntime` and B14 `PersonaRuntime`; one may be `None` only when the expansion has no instance of that kind |
| `cancel` | a `PoolCancel`; both adapter runtimes must carry this same object |
| `max_parallel` | 1..`MAX_PARALLEL` instances in flight, whatever their kind |
| `wait_limit_seconds` | can only narrow the specification's `rendezvous_timeout_seconds`: the wait lasts `min` of the two |
| `drain_seconds` | 0..180: how long launched workers get to wind down after the wait ended |

Every adapter-runtime fact the verifier later takes from the `PoolContext` must equal the
context's before anything is launched (`images_dir`, `host_flavor`, `docker_host`,
`source_snapshot_sha256`, `registry_ceiling`; `registry_dir`, `prompt_root`, `readable_roots`,
`allowed_models`, the invoker id). An instance therefore cannot run under one registry, image
directory or snapshot and be verified under another. A refusal names exactly the field.

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

Closed vocabulary (`STATES`). Exactly the first five adopt an adapter result.

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
| `missing` | no attempt evidence at all: the root is gone, or a worker reported and left nothing | disk |

"Verified" means the adapter's own `load_verified_result` passes for that instance's ids and the
request the expected specification derives (`container_execution`, `persona_invocation`). A value
an adapter returned and a worker thread's report are never read for state: a worker that returns
`OK` and leaves nothing on disk is `missing`. `adapter_status` and `adapter_cause` are the verified
result's `execution_status` and `cause`; `result_file` is `{path, sha256, bytes}` of the adopted
`invocation-result.json` or `container-result.json`. B14's `invoker_stopped: false` (a stuck
invoker) is carried through; B14 only records it on `TIMEOUT` and `CANCELED`, so its later output
is never part of a success.

### The one rule

`classify_instance` is called by the coordinator (before publication) and by the verifier, and
nothing else decides. It is a pure function of the expansion, the disk now, and one of five
coordinator observations:

| Observation | Disk | State |
|---|---|---|
| any | instance root absent | `missing` |
| unreported (thread stopped / still running) | anything | `rendezvous_timed_out` |
| unlaunched (cancel / timeout) | root empty | `not_launched_canceled` / `not_launched_rendezvous_timeout` |
| unlaunched | root not empty | `invalid` |
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
caps that can only be at or below B15's. **They do not replace Dagster pools**: the op that calls
`run_rendezvous` is `resource_pools.unassigned('coordination_only')`, holds no work-pool slot
while waiting, and an integrator that needs cross-run enforcement launches instances as pooled ops
instead. No limit is raised here.

Threads: one daemon thread per launched instance, named `pool-instance-<n>`. An instance is
launched only into the still empty, real directory the expansion created.

## Cancel, timeout, late finish

- **Pool cancel.** Setting `runtime.cancel` stops launches at once (pending instances become
  `not_launched_canceled`) and reaches every running adapter, because it is the adapters' own
  cancel event. The wait continues until they have reported or the deadline passes; B13 and B14
  write `CANCELED` results, which are verified and adopted as `canceled`. `KeyboardInterrupt` or
  `SystemExit` in the coordinator is treated as a cancel and re-raised after publication.
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

`verify_manifest` first runs C01's `verify_expansion`, tolerating only its two findings about a
damaged `instances/` directory (those instances are `missing` or `invalid` by the rule above; a
test pins C01's exact words). Then the rendezvous root must be a real directory holding exactly the
manifest, a regular, singly linked, bounded file read without crossing a link and parsed with
`parse_document` (no repeated key). Then, per instance, the recorded entry must equal what
`classify_instance` derives **now** for one of the five observations, and the whole file must be
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
- In-process caps do not see other runs; see Concurrency.
- Windows: `os.link` needs NTFS; path rules are the adapters'.

## What T10 and C03 need

- Expand one pool per wave with C01, then `run_rendezvous`, from an op tagged
  `resource_pools.unassigned('coordination_only')`. Afterwards, and in any later process, read only
  through `load_verified_manifest`. A `RendezvousError` there means **no instance of that pool may
  be treated as assessed**.
- Invariants a consumer may rely on: `instances` is the expansion's list, same ids, same order,
  each once; `counts` sum to `instances`; `outcome == pool_outcome(states)`; `result_file` is
  non-null exactly for `RESULT_STATES`; only `succeeded` has `adapter_status == "OK"`.
- Mapping a T06 handoff batch: one persona group per handoff (or `count: n` for n independent
  validators of one handoff), the handoff as a readable input with role `handoff` (C01). Keep
  `group_id` and `ordinal` to map an instance back to its handoff and rows.
- `not_assessed`: every applicable row of a handoff whose instance is not `succeeded` is
  `not_assessed`, with the instance's `state`, `adapter_status` and `adapter_cause` as failure
  provenance (ADR-0009). A `succeeded` instance only says the adapter's checks passed; T07's
  validator-result validation still decides whether its output is a valid result. `EMPTY` is a
  coverage statement with its reason, never an assessed set. A newer failed attempt is a new
  specification `attempt_id`, hence a new pool root and a new manifest: there is nothing here that
  could fall back to an older one.
- For a `succeeded` instance read the result with the adapter's `load_verified_result` or
  `to_worker_envelope`; the manifest's `result_file.sha256` must match what is read.
- The parity capability record for `wait-all-rendezvous` is an integrator follow-up (PR 30 owns
  `design-parity-manifest.json`).
