# Dedicated resource pools (B15)

Backlog batch B15. Six named Dagster pools bound how much CPU, memory, Docker, network,
persona/LLM and dynamic-analysis work runs at once across every run and engagement. The run queue
(two runs, one run per engagement, one NVD sync) and every executor `max_concurrent` are unchanged
and stay the outer limits: a pool can only make a ready step wait, it can never start one that the
queue or the executor would not.

Single source of truth: [`appsec-review-process/resource_pools.py`](../appsec-review-process/resource_pools.py).
`dagster_workflow.py` and `orchestrator/dagster/definitions.py` take every `pool=` value from it;
no pool id or limit is a constant anywhere else. A test ties the tables on this page to the module.

Not done in B15 (shared surfaces owned by another open change): the parity manifest still records
`resource_pools: []` and every job as `unassigned`; the manifest, generated views and `TODO.md`
are updated in a follow-up. Live service qualification is a separate, owner-run step (below).

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
| `supplied_human_decision` | `cpu` |
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

`state` writes a `resource-pool-state` document
([schema](../schemas/resource-pool-state.schema.json)): declared and observed limits, the floor,
the outer limits, every op's pool or unassigned reason, and for the named runs each pooled step's
start and end with the largest observed overlap per pool. It refuses to overwrite. `verify-state`
re-reads the bytes, checks the schema and `state_sha256`, and re-derives the pool states, the
overlaps, the errors and the result; it also fails a document in which pooled steps of two runs of
one engagement overlap. `state_sha256` is an integrity check, not an authenticator.

Stuck slot: `dagster instance concurrency get --all` shows holders; a slot held by a finished run
is freed by the daemon after 120 seconds, or at once with the UI's "free slots for run".

## Tests

`tests/test_resource_pools.py` is pure and runs anywhere. `tests/test_resource_pools_dagster.py`
needs Dagster, skips only when Dagster is not importable, and runs in the code-server against a
temporary SQLite instance built from the repository's own `dagster.yaml` sections. It proves: each
pool admits its limit and not one more with limit+1 contenders; a saturated pool does not delay
another pool; the executor cap still binds below a pool limit; an unapplied pool gets the floor;
two engagements take turns on one pool; failed, killed and canceled work releases its slot; a
killed run worker leaks its slot until run monitoring frees it; limits survive an instance
re-open; drift is reported and corrected; silent or malformed op states are errors.

Not covered by tests, and the subject of live qualification: the run-queue daemon (two runs, one
per engagement) together with pools, Postgres storage, the guard sensor under the real daemon, and
restart of the real services.

## Limitations

- One pool per op (Dagster). Secondary resource use is not metered.
- Pools count steps, not bytes or cores; `memory` 1 means one memory-heavy step, not a quota.
- Waiting is first come first served within a priority, not proportional between engagements.
  An engagement that asks first with many ready steps is served first for all of them.
- A waiting step re-checks its claim with a back-off of a second or more, so a freed slot is not
  taken instantly.
- The guard corrects drift within its interval, not before the first step after a wipe; the floor
  covers that window. The guard can be stopped from the UI.
- The manifest's per-job pool is not yet cross-checked against the op's pool; the validator checks
  the pool vocabulary only.
