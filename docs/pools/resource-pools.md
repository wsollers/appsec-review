# Dedicated resource pools (B15)

Backlog batch B15. Six named Dagster pools bound how much CPU, memory, Docker, network,
persona/LLM and dynamic-analysis work runs at once across every run and engagement. The run queue
(two runs, one run per engagement, one NVD sync) and every executor `max_concurrent` are unchanged
and stay the outer limits: a pool can only make a ready step wait, it can never start one that the
queue or the executor would not.

Single source of truth: [`appsec-review-process/resource_pools.py`](../../appsec-review-process/resource_pools.py).
`dagster_workflow.py` and `orchestrator/dagster/definitions.py` take every `pool=` value from it;
no pool id or limit is a constant anywhere else. A test ties the tables on this page to the module.

The parity manifest names the six pools and assigns the six jobs that have workers (`00-intake`,
`02-repository-partition-discovery`, `02-dev-project-discovery` cpu; `02-ossf-scorecard` network;
`02-build-configure` docker; `02-evidence-index` memory); every other job stays `unassigned` and is
reported as a gap. The capability `dedicated-resource-pools` is `implemented_not_qualified`: the
live service qualification below was run on 2026-09-21 except its worker-loss step.

## Pools

| Pool | Limit | Work | Why this number |
|---|---|---|---|
| `cpu` | 3 | deterministic Python work: intake, preparation branches, build discovery, gates | equals workflow-plan.json max_concurrent_steps, the fan-out one run is already allowed; 1 would serialize the qualified parallel preparation branches; today two runs may use 6 |
| `memory` | 1 | memory-heavy deterministic work: the evidence index | no memory measurement exists; today two engagements may index at once, so 1 is tighter |
| `docker` | 1 | pinned-container and target-execution work: the sandboxed configure | no Docker load measurement exists; today two engagements may configure at once |
| `network` | 1 | fixed-destination network work: Scorecard ingestion, the NVD feed sync | no provider rate measurement exists; today a Scorecard step and the NVD sync may overlap |
| `persona_llm` | 3 | persona / model invocations | ADR-0008 Decision 6 deep class needs 3 concurrent cells; 3 does not exceed the executor cap of 3 steps per run and is half of today's aggregate of 6; no persona op exists yet |
| `dynamic_analysis` | 1 | dynamic testing and debugger/ptrace work | no dynamic worker exists and nothing is measured; 1 |

Before B15 the only bound was two runs times at most three steps, six step processes of any kind.
Every limit above is at most three and below six, so no limit is looser than what was already
permitted; `resource_pools.constant_errors()` refuses a limit above that ceiling.

**No limit may be raised without load evidence.** A change to any number in the table needs a
recorded measurement for that resource (CPU and memory saturation of the host, Docker daemon
behaviour, provider rate limits, model-rate errors) at the current limit and at the proposed one,
referenced from the commit that changes `resource_pools.py`, followed by a new live qualification.
The run queue and executor caps are not pool limits and are out of scope for such a change.

## The unassigned state

`unassigned` is a recorded value, never the absence of one. An op records it with
`tags=resource_pools.unassigned(<reason>)`; the closed reasons are:

- `coordination_only`: config, reservation and publication ops. They hold short locks and must
  never wait on a work pool. They include every job's root op on purpose: with a pooled root op
  Dagster's run coordinator would keep the whole run in the queue while that pool is full.
- `worker_not_implemented`: the `blocked_op` lifecycle stubs. Their worker kind and permissions
  do not exist yet, so no pool can be derived.
- `bootstrap_diagnostic`: the `orchestration_smoke` ops.

An op with neither a pool nor this record is an error: `resource_pools.require_explicit_assignments`
runs at the end of `definitions.py`, so the code location fails to load and nothing can launch.
An unknown pool id, a pool together with an unassigned record, and an unknown reason are errors
too. Unassigned ops are listed in every pool-state document, and the parity validator reports
every manifest job whose `resource_pool` is `unassigned` as a gap. In Dagster 1.13.21 an op without
a pool never claims a slot, whatever the default limit is, so an unassigned op is bounded only by
the run queue and its executor cap; that is the behaviour before B15.

## Deriving a pool

`resource_pools.derive_pool(worker_kind, granted_kinds, *, memory_heavy)` is pure and total over the
known vocabulary; all three arguments are required. An unknown worker kind (including the future
`pool_coordinator` and `join_controller` modes), an unknown permission kind, a legacy permission
string such as `network:api.scorecard.dev`, or a string where a list belongs raises
`PoolAssignmentError`. It never returns `unassigned`.

| Worker kind | Pool |
|---|---|
| `deterministic_python` | `cpu` (`memory` when `memory_heavy`) |
| `supplied_human_decision` | `cpu` (`memory` when `memory_heavy`) |
| `pinned_container` | `docker` |
| `persona` | `persona_llm` |

| Granted permission kind | Pool |
|---|---|
| `fixed-network-destination` | `network` |
| `package-restore` | `network` |
| `dynamic-testing` | `dynamic_analysis` |
| `debugger-ptrace` | `dynamic_analysis` |
| `target-execution` | `docker` |
| `credential-use` | none |
| `target-mutation` | none |

A Dagster op holds exactly one pool. When the worker kind and the grants point at several, the
first of this fixed precedence wins, most restrictive and specific first:

`dynamic_analysis` > `docker` > `persona_llm` > `network` > `memory` > `cpu`

`persona_llm` ranks above `network` deliberately: a persona's fixed network destination is its model
provider, and the model rate is what the persona pool meters. A persona granted `target-execution`
or a dynamic kind still goes to the stricter pool. Consequence: an op that uses two resources is
metered on one; a container that also restores packages holds a `docker` slot and no `network` slot.

Until registry templates carry B11 permission requirements (permission-capabilities follow-up 1),
`dagster_workflow.py` names the worker kind and permission kinds per op in its own `*_POOL` lines.

### Persona budget classes (ADR-0008 Decision 6)

| Budget class | Concurrent persona cells |
|---|---|
| `probe` | 1 |
| `standard` | 2 |
| `deep` | 3 |

`resource_pools.persona_slot_request(budget_class)` is the only place these numbers live. A class is
the number of `persona_llm` slots one run may hold at once; the pool limit is global, so a `deep` run
and a `probe` run contend for the same three slots. A class that would exceed the pool limit raises;
the limit is never raised to fit a class.

## What Dagster 1.13.21 does

Confirmed against the package installed in the code-server image, not from documentation:

- `@op(pool=...)`. Any non-whitespace name is valid. Both the multiprocess and the in-process
  executor claim a slot before starting a step (`InstanceConcurrencyContext.claim`) and free it on
  step success, failure, retry and when a step process dies.
- **Per-pool limits live in the event-log storage**, tables `concurrency_limits`,
  `concurrency_slots` and `pending_steps` (Postgres here), written by
  `event_log_storage.set_concurrency_slots`, which is also what `dagster instance concurrency set`
  and the UI call. They are not in `dagster.yaml`.
- The only YAML part is the default for a *named* pool that has no stored limit. With no default
  such a pool is unlimited; with one, Dagster creates the pool row on first use
  (`using_default_limit`). `concurrency.pools.default_limit` cannot be used here: any
  `concurrency.pools` or `concurrency.runs` block makes Dagster reject `max_concurrent_runs` and
  `tag_concurrency_limits` under `run_coordinator`. The older key
  `concurrency.default_op_concurrency_limit` has the same effect without that conflict.
- Granularity is `op` when unset: the run coordinator only holds back a queued run whose *root*
  ops are all in full pools (no job here has a pooled root op except `nvd_reference_sync`), and
  steps wait individually. Waiting steps are served by priority, then first come first served.
- A run worker that is killed cannot free its slots. The daemon frees the slots of finished runs
  only when `run_monitoring.free_slots_after_run_end_seconds` is set.
- The temporary SQLite instance used by the tests supports pool slots; the in-memory ephemeral
  instance does not, and `resource_pools` refuses it.

## Where the limits are applied, and restart

`orchestrator/dagster/dagster.yaml` carries two lines, mounted read-only into every service:

```yaml
concurrency:
  default_op_concurrency_limit: 1
run_monitoring:
  free_slots_after_run_end_seconds: 120
```

The first is the fail-closed floor: on a fresh or wiped Postgres volume, or for a mistyped pool,
a named pool gets one slot, never no limit. The second returns slots leaked by a lost run worker
120 seconds after run monitoring marks the run finished (above the 30 second stop grace, cancel
timeout and poll interval combined).

The explicit limits are written by `resource_pools.apply_limits(instance)`, which is idempotent,
sets exact values (it lowers a raised limit as well as raising a defaulted one) and never deletes
a pool. The `resource_pool_guard` sensor registered in `definitions.py` calls it on its first tick
after the daemon starts and every 30 seconds, then runs `verify_instance`; its tick fails, visibly in the UI
and the daemon log, while the instance disagrees with the module (an undeclared pool, a changed run
queue limit, a missing floor). Nobody has to click anything.

Restart behaviour follows from where things live. Limits and claimed slots are rows in Postgres
(`postgres-data` volume): they survive a restart of the daemon, webserver and code-server.
`docker compose down -v` removes them; the floor holds until the guard's first tick rewrites them.
A sensor can be switched off in the UI; then limits stop being corrected but keep their stored
values, and `resource_pools.py verify` still reports drift.

## Operator commands

Run inside the code-server (`docker compose -f orchestrator/dagster/compose.yaml exec -T code-server ...`):

```text
python -B /opt/process/resource_pools.py table          # declared pools; needs no Dagster
python -B /opt/process/resource_pools.py verify         # read-only; exit 2 on any drift
python -B /opt/process/resource_pools.py apply          # idempotent write, then verify
python -B /opt/process/resource_pools.py state --out <new file> --run-id <dagster run id> ...
python -B /opt/process/resource_pools.py verify-state <file>
```

`state` writes a `resource-pool-state` document (`appsec-review/resource-pool-state/1.1`; no 1.0
document exists outside tests -- the id was raised when the required `pooled_steps_recorded` field
was added, because a changed shape gets a new id; a 1.0 document fails the schema)
([schema](../../schemas/resource-pool-state.schema.json)): declared and observed limits, the floor,
the outer limits, every op's pool or unassigned reason, and for the named runs each pooled step's
start and end with the largest observed overlap per pool. It refuses to overwrite and refuses a
run id given twice. Steps without a pool are not recorded, so a recorded step always names a
declared pool. `pooled_steps_recorded` is true only when at least one named run recorded at least
one pooled step: **a `PASS` with `pooled_steps_recorded: false` (for example `state` without
`--run-id`) shows the limits and assignments only and is not contention evidence.** `state` exits
2 when runs were named and none of them recorded a pooled step.

The document's `errors` (result `FAIL`) are faults of the observed system: a pool that is
`MISSING`, `DEFAULTED` or `DRIFT`, an undeclared pool, a changed floor or outer limit, a Dagster
release other than the pinned 1.13.21, more claimed slots than the declared limit, a recorded step
that names an undeclared pool, an overlap above a limit, pooled steps of two runs of one engagement
that overlap, an op assignment error, and no inspected op at all.

`verify-state` re-reads the bytes and reports a problem when the document is not what this code
would have written: JSON with a repeated key or a non-finite number (`1e999` as well as `NaN` and
`Infinity`), a schema failure, a wrong `state_sha256`, a `declaration_sha256` that is not the hash
of the `resource_pools.py` doing the verification (verify with the commit that produced the
document), expected values that are not the declared ones, a pool state that does not follow from
the observed limit, a negative slot, pending-step or step time, a step that ends before it starts,
a (job, op) listed twice across pooled and unassigned, a Dagster run id or a step key listed twice,
foreign pools that are not a sorted list of distinct undeclared pools, and `pooled_steps_recorded`,
overlaps, errors or a result that do not follow from the rest. It returns fixed strings and never
echoes a value read from the document. Not bound, because nothing on disk determines them:
`generated_at`, the job, op and run identifiers, a run's `status` (a failed or canceled run is
valid evidence for failure injection) and the step times themselves. `state_sha256` is an integrity
check, not an authenticator.

Stuck slot: `dagster instance concurrency get --all` shows holders; a slot held by a finished run
is freed by the daemon after 120 seconds, or at once with the UI's "free slots for run".

## Live service qualification (run 2026-09-21; step 8 still owed)

B15 changes Dagster registration (a sensor, op pools, a load-time check) and `dagster.yaml`, so it
needs the bounded live qualification that `TODO.md` requires. `dagster.yaml` and `definitions.py`
are part of every job's runtime fingerprint (as is any new `schemas/*.schema.json`): accepted
pointers become non-current and the first run of each engagement re-executes instead of reusing.

1. Idle check: `docker compose -f orchestrator/dagster/compose.yaml ps`, and no `STARTED` or
   `QUEUED` run in the UI. Record `docker image inspect appsec-review-dagster:local --format '{{.Id}}'`
   and the commit under test.
2. Restart the stack from the checkout under test so the mounted `dagster.yaml`, `definitions.py`
   and `/opt/process` are this branch (`up -d`; rebuild only if the image must carry the same files).
   All four services healthy; the code location loads (a load error here means an op without a
   pool state).
3. Within a minute the `resource_pool_guard` sensor shows a successful tick
   (`resource pools verified; corrected=6` the first time on this storage, `corrected=0` after).
   Then `exec -T code-server python -B /opt/process/resource_pools.py verify` exits 0 and the UI's
   Deployment > Concurrency page lists the six pools with 3/1/1/1/3/1.
4. Per-pool limit and fairness, memory pool: stage two Linux-owned engagements (A, B) as in
   `docs/dagster/dagster-launching.md`, run `engagement_workflow` for both, then launch
   `--job evidence_index` for A and for B at the same time. Both runs are `STARTED` together
   (run queue 2), but only one `evidence_index_work` step runs; the other shows Dagster's
   pool-blocked message and starts when the first ends.
5. CPU pool: launch `engagement_workflow --force` for A and B at the same time. At most three
   `cpu` steps run across both runs; within a run the branches still overlap
   (`qualify_workflow.py` still passes its branch-overlap and queue assertions).
6. Unchanged engagement serialization: submit a second job for A while A runs; it stays `QUEUED`
   until A's run ends, with or without free pool slots.
7. Cancellation: while B waits for the memory slot in step 4 (or holds it), terminate B from the
   UI. B becomes `CANCELED`, the `reconcile_workflow_cancellation` sensor marks the workflow
   `FAILED`, `verify` shows no slot held by B, and the next waiting step proceeds.
8. Failure injection, lost run worker: during a pooled step, find the run worker with
   `exec code-server ps -ef` and `kill -9` it and its step child (killing a whole service is too
   broad; an orphaned step child would otherwise keep working without a slot record). The slot
   stays claimed; run monitoring fails the run; about 120 seconds after that the daemon log shows
   `Freed ... slots for run ...` and the next step proceeds.
9. Restart: with one pooled step running and one waiting, `docker compose restart daemon webserver`.
   Limits are unchanged (`verify` exit 0), the running step finishes, the waiting step gets its
   slot, no slot is leaked. Then `docker compose restart code-server` when idle and re-check 3.
10. Drift: set the docker pool to 5 in the UI; within 30 seconds the guard logs the correction and
    `verify` exits 0 again. Add a pool `gpu` in the UI; the guard tick fails visibly; delete it.
11. Evidence: `resource_pools.py state --out /runs/<A>/data/qualification/resource-pools-<id>/resource-pool-state.json --run-id <each Dagster run id>`
    (result `PASS`, `pooled_steps_recorded` true, overlaps within limits), then `verify-state` on the
    host copy from the same commit (no problems). A `PASS` without `pooled_steps_recorded` is not
    qualification evidence. Record the
    engagement and Dagster run ids, attempt ids, the state document path and its `file_sha256`,
    the image id, the commit, the injected failures and the observed recovery.

### Record of the 2026-09-21 run

Run by the coordinator on the owner's instruction, on the Linux host, with the shared stack restarted
from this branch at commit `4cfa2f5` (image `sha256:0373f1c871f472e02f5e452f45e3644517ce5d2c9a21890232f9c035b57fed5d`,
Dagster 1.13.21, Postgres storage) and returned to the main checkout afterwards. UI actions were
made through the same GraphQL mutations the UI calls (`terminateRun`, `setConcurrencyLimit`,
`deleteConcurrencyLimit`). Engagements: A `20260921T081929Z-ce1886`, B `20260921T081930Z-939b69`.

| Step | Result | Observation |
|---|---|---|
| 1 | PASS | four services healthy, no `STARTED`/`QUEUED` run |
| 2 | PASS | `/opt/process` mounted from this branch; code location `LOADED` (so every op of the 51-node graph has a pool or an unassigned record) |
| 3 | PASS | guard tick `corrected=6`, then `corrected=0`; `verify` exit 0 with 3/1/1/1/3/1 |
| 4 | PASS | `evidence_index` for A and B (`1ed199d5`, `404f210e`): both runs `STARTED`, one `evidence_index_work` claimed, the other pending until the first ended (97 samples) |
| 5 | PASS | `engagement_workflow --force` for A and B (`cbf2b330`, `651ce7d2`): at most 3 `cpu` claims across both runs, both runs holding `cpu` together, two `cpu` steps inside one run. `qualify_workflow.py` PASS on this stack (report sha256 `11f84caa61afb00f67695dda6f752b103a37e71eedb22bdda5d86e99e69f3a15`) |
| 6 | PASS | a second job for A (`997c86aa`) stayed `QUEUED` for the whole of A's run (`e18e0db7`) and started when it ended |
| 7 | PASS, with a finding | B (`679bd3ca`) terminated while waiting for `memory`: `CANCELED`, its pending claim gone, the next step proceeded. A workflow-owning run (`80c042cd`) terminated while HOLDING a `cpu` slot: `CANCELED`, `reconcile_workflow_cancellation` marked the workflow `FAILED` within 10 s -- **but the slot stayed claimed for about 150 s**, until the daemon's free-slots pass. See below |
| 8 | **NOT RUN** | `kill -9` of the run worker and its step child inside the shared code-server was refused by the coordinator session's permission system. The pids were identified; nothing was killed. Owed by the owner |
| 9 | PASS | `restart daemon webserver` with one `memory` step running (`6f869abb`) and one waiting (`bfc21b69`): limits unchanged, the running step finished, the waiter got the slot, nothing leaked. `restart code-server` when idle: `verify` exit 0 |
| 10 | PASS | `docker` set to 5: `verify` reported the drift, the guard corrected it within 40 s. Pool `gpu` added: the guard tick was a visible `FAILURE` and `verify` named it; deleted: next tick clean |
| 11 | PASS | `runs/20260921T081929Z-ce1886/data/qualification/resource-pools-20260921T084124Z/resource-pool-state.json`, `file_sha256` `813b4ae44379775df506511d8c52479f74106606992aa0e701ac6bf55041b27a`: result `PASS`, `pooled_steps_recorded` true, 14 runs, largest overlap `cpu` 3 of 3 and `memory` 1 of 1; `verify-state` on the host copy from the same commit: no problems |

Only `cpu` and `memory` have pooled ops that a bounded run reaches on this host; `docker`, `network`,
`persona_llm` and `dynamic_analysis` were verified as limits, not under contention.

**Finding (step 7): a terminated run that holds a slot does not free it at once.** In the test
suite a `SIGINT`ed run worker frees its slot. On the live service `terminateRun` ended the run
`CANCELED` with its `cpu` slot still recorded as claimed; it was returned about 150 seconds later
by `run_monitoring.free_slots_after_run_end_seconds` (120 s plus the monitoring interval). That is
the same path as a lost run worker. Consequence: on a limit-1 pool, cancelling the run that holds
the slot can delay the next step by up to about two and a half minutes. It is not a deadlock, and
it is why `free_slots_after_run_end_seconds` must stay set. Until step 8 is run, this is also the
only live evidence that the free-slots pass returns a leaked slot.

## Tests

`tests/test_resource_pools.py` is pure and runs anywhere; it includes the `verify_state_file`
tamper tests (every leaf edited alone with a consistent reseal, every key removed, repeated keys,
overflowing numbers; the leaves that may change are an explicit, justified list) and the ties
between this page and the module. `tests/test_resource_pools_dagster.py`
needs Dagster, skips only when Dagster is not importable, and runs in the code-server against a
temporary SQLite instance built from the repository's own `dagster.yaml` sections. It proves: each
pool admits its limit and not one more with limit+1 contenders; a saturated pool does not delay
another pool; the executor cap still binds below a pool limit; an unapplied pool gets the floor;
two engagements take turns on one pool; failed, killed and canceled work releases its slot (on the live service a terminated run's slot
came back only through the free-slots pass: see the 2026-09-21 record); a
killed run worker leaks its slot until run monitoring frees it; limits survive an instance
re-open; drift is reported and corrected; silent or malformed op states are errors.

Not covered by tests, and the subject of live qualification: the run-queue daemon (two runs, one
per engagement) together with pools, Postgres storage, the guard sensor under the real daemon, and
restart of the real services.

## Limitations

- One pool per op (Dagster). Secondary resource use is not metered.
- Pool lanes are outside these pools for now. `pool_rendezvous.run_rendezvous` (C02) launches its
  instances as threads inside one `unassigned('coordination_only')` op, so its containers and
  persona invocations claim no slot here, and its own caps see only that one rendezvous. **Owner
  decision 2026-09-21: one engagement at a time for now** -- review processes are not concurrent --
  while forked branches INSIDE an engagement may each run a rendezvous at the same time. The limits
  on this page therefore bound each rendezvous, not the host: k concurrent rendezvous can run k
  containers and 3k persona invocations. The job whose op calls `run_rendezvous` (T10) must carry a
  run-level tag with a tag concurrency limit of 1; the aggregate inside an engagement closes when
  instances are launched as dynamically mapped pooled ops ([pool rendezvous](../rendezvous/pool-rendezvous.md),
  "Constraint: one engagement at a time").
- Pools count steps, not bytes or cores; `memory` 1 means one memory-heavy step, not a quota.
- Waiting is first come first served within a priority, not proportional between engagements.
  An engagement that asks first with many ready steps is served first for all of them.
- A waiting step re-checks its claim with a back-off of a second or more, so a freed slot is not
  taken instantly.
- The guard corrects drift within its interval, not before the first step after a wipe; the floor
  covers that window. The guard can be stopped from the UI.
- The manifest's per-job pool is not yet cross-checked against the op's pool; the validator checks
  the pool vocabulary only.
