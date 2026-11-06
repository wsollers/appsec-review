# Operational status, cost provenance, quality trends and retention

These are derived operator facilities, not a replacement scheduler, recovery controller,
evidence authority or billing service. No model, service, collector or deployment is started
implicitly. Existing `status`/`watch` commands remain available.

## Bounded status and event following

From an installed checkout, with its own Python environment:

```sh
.venv/bin/python -m appsec_review.observability.operator runs/<run-id>
.venv/bin/python -m appsec_review.observability.operator runs/<run-id> \
  --watch --pages 4 --checkpoint test/tmp/operator-checkpoint.json
.venv/bin/python deploy/dagster/bin/run_report.py --max-runs 100
```

The first two commands are offline. `--dispatches FILE` supplies a recorded array of Dagster
run results; only `run_report.py` explicitly queries its configured Dagster URL. Its existing
`operator-performance-report/1` keys remain, with a versioned `operator-join/1` extension.
The legacy `stale` array now means progress is unconfirmed, **not that a process is dead**;
an old `STARTED` dispatch remains running. Unknown/missing process evidence never proves death.

`OperatorFollower` joins run lifecycle, job attempts (including retries), dispatches, progress,
declared/reused gaps, failure categories, receipt hashes and resource cleanup ownership.
Operational success is separate from coverage. Even `no_declared_gaps` is not a claim of
complete analysis. A conflicting application/orchestrator lifecycle is named explicitly.
The status view never authorizes reuse: runtime receipt validation is still required.
At most 16 execution receipts of at most 1 MiB each are verified per snapshot through the
existing run-artifact verifier. Unsupported receipts are named gaps, not inferred successes.

`PipelineLog.follow()` accepts a serializable byte/sequence cursor and returns at most the
configured record/byte page. Complete corrupt records fail; a torn final line does not advance
the cursor. Inode changes, truncation and changed accepted-boundary bytes explicitly reset it.
This is an append-stream cursor, not a forensic proof that every historical byte is immutable.
Checkpoint the derived state **with** the cursor; a cursor alone is not an aggregate.
Checkpoints retain alert deduplication across restarts. They are derived local state, not evidence.

Only replaceable span progress samples are coalesced. Counts remain cumulative. All other
records are retained until the explicit capacity bound (default 10,000); reaching it stops
consumption without advancing the cursor or silently discarding lifecycle records. A backlog,
torn tail or capacity stop makes completion unknown. Increase `--pages`/`--capacity` deliberately
or use the existing completed-run report; this is not unlimited event compaction.

Progress/cleanup alerts are local output records, deduplicated by run generation and ownership.
They do not send external notifications. `snapshot()` exposes `stale_seconds`,
`alert_after_seconds` and `max_alerts`; the watch interval does not change lifecycle durability.
Every critical central event retains synchronous fsync. Oversized critical records fail
explicitly; oversized progress retains its span/sequence plus an explicit truncation marker.
Existing operation spans measure `telemetry.lock_wait`, `telemetry.fsync` and
`telemetry.aggregate`; outside an active span those measurements are unavailable, not zero.

## Execution and cost accounting

Execution summaries distinguish timeout (including historical `TimeoutExpired` errors),
OOM **only when reported**, nonzero exit, cancellation, reuse and unknown. Hash-bound diagnostics
never include stderr, stdout, prompts, source, exception messages, mounts or command lines.
The receipt adapter accepts `container-execution/1` and `tree-sitter-invocation/1`.

`run-metrics/7` retains its existing fields and adds `cost-provenance/1`. Legacy `model_tokens`
is a compatibility field; use the extension's nullable usage and completeness status when
unknown usage matters. Dispatch correlation accepts both `model_invocation_id` and historical
`invocation_id`. Conflicting terminal records remain accounting gaps even when the legacy
aggregation de-duplicates them.

The extension distinguishes:

- `provider_reported`: an event records `provider_charge` with `source: provider_reported`,
  a finite nonnegative `amount` and three-letter `currency`. This is reported provider data,
  not an independently verified invoice. Existing scalar `cost` without provenance stays unknown.
- `api_estimate`: explicit `--prices FILE` opts into a versioned table. No built-in prices,
  price lookup, billing API or dependency is introduced.
- `subscription`: usage may be known, but no per-call dollars are invented.
- `unknown`: missing, invalid, incomplete or conflicting usage/charge records stay unknown.
- `reused`: replay/cache/reuse creates no new dispatch charge; historical token usage is not
  charged again. Provider cache-token discounts on an actual dispatch are a separate concept.

Example **synthetic** price table (not a current provider price):

```json
{
  "schema": "appsec-review/api-prices/1",
  "version": "synthetic-example-1",
  "rates": {
    "provider/model": {
      "currency": "USD",
      "cache_semantics": "included_in_input",
      "input_per_million": "1",
      "output_per_million": "2",
      "cache_per_million": "0.5"
    }
  }
}
```

Prices require all three token counters and explicit cache semantics. Reported and estimated
amounts are never combined, nor are currencies. Per-job totals are partitions of the per-run
calls. Optional finding links allocate one dispatch over distinct findings using an explicit
equal-share rational fraction; this is analytical allocation, not a second billing total.
Retries with distinct invocation IDs remain distinct work; duplicate completions do not.

## Revision-bound quality observations

`quality.evaluation_trend` calls the existing `review.evaluation.score`; it does not invent a
new per-case evaluator or change guidance. `quality.acceptance_trend` adapts the existing
CASTLE scoring report for one producer. Artifacts bind source-report hash, corpus, configuration,
prompt bundle set, model identity and implementation commit. Missing identities stay `null`.
Supply implementation/model identities from the actual run/fixture provenance; they are
operator-supplied annotations where the original evaluator did not retain them.

```sh
.venv/bin/python -m appsec_review.observability.quality \
  --report <recorded-report.json> --cases <recorded-cases.json> --variant full \
  --implementation-sha <40-hex-tested-commit> --model-sha256 <64-hex-model-config-hash> \
  --output <quality-artifact-directory>
```

Artifacts are content-addressed and immutable; an identical publication reports `duplicate`.
Comparison requires the same corpus, prompt/model/config identities, role, variant and case
count. Otherwise it reports `incomparable`. Missing results and empty denominators are explicit.
Evaluation precision is **case-resolution precision**, not production finding precision.
Single-turn evaluation has no retrieval-failure measurement; it stays unavailable rather than
zero. Acceptance results do not supply abstention, token or retrieval metrics.

`tests/fixtures/operations-quality.json` is a pinned **synthetic assessed-row** fixture, not a
live model result. Its zero-regression thresholds cover precision, recall, justified abstention
and unsupported conclusions. The existing opt-in live path remains separate:

```sh
# MANUAL ONLY: configured model credentials, budgets, guidance and a new run-owned output required.
.venv/bin/python -m appsec_review.review.evaluation --root . \
  --cases tests/fixtures/review_guidance/cases.json --role independent_verifier \
  --variant paired --live --output runs/<new-evaluation-run>
```

This package does not run that command. Live results must be source-verified; passing fixture
thresholds is not evidence of production quality.

## Conservative retention boundary

Deletion is supported only for explicitly **sealed offline stores** under exclusive POSIX
ownership, not active `runs/`, normal legacy run roots or build workspaces. Ordinary runtime
stores return a named hold. There is no automatic enrollment, sealing, migration or production
cleanup command. This narrow boundary is intentional: existing live writers do not all share a
durable-artifact deletion lock, so general live-run deletion cannot currently be proved safe.

A `retention-catalog.json` with schema `appsec-review/retention-catalog/1` asserts
`custody: sealed_offline`, an operator owner, a complete `runs` map and a complete `objects` list.
Each run declares `state` (`terminal`, `active`, `held`), `leases` and `repair_hold`. Each object
declares normalized `path`, `run_id`, content `sha256`, `role`, Boolean `retain` and complete
cross-run `references`. Missing ownership/reference information holds the entire store.
The operator must have removed the store from all runtime writers before making this assertion.
All cooperating offline claims and catalog changes must take the same `.retention.lock`.

Accepted receipts, audit roots, configuration, logs, build workspaces, active/leased/held runs
and their transitive dependencies are retained. Known authoritative `data/jobs`, `data/build`,
`data/logs`, `data/configuration`, `data/guidance` and `data/orchestration` paths are protected
even if mislabelled. Reachability handles cycles and shared/cross-run objects once.
No dependency is deleted because it is old. Only unreferenced catalogued artifact **files**
can be removed; run directories and the existing build-workspace retention API are untouched.

Planning bounds: 1,000 roots, 10,000 objects, 20,000 directory entries, 16 MiB per object and
64 MiB total object verification. Unknown files/roots, symlinks, hardlinks, nonregular files,
permissive ownership, changed content and unsupported schemas cause holds.

```sh
# MANUAL ONLY: choose a disposable, privately owned, already sealed offline fixture.
.venv/bin/python -m appsec_review.observability.retention <sealed-store>
```

Save the returned inner `plan` object outside the store. A later explicit apply uses that exact
plan, rechecks ownership/content/claims under the OS-backed lock and journals each unlink:

```sh
.venv/bin/python -m appsec_review.observability.retention <sealed-store> \
  --plan <saved-inner-plan.json> --apply
```

Interrupted deletion resumes only with its original plan/journal. The same plan is idempotent;
a changed catalog or concurrent claim refuses deletion. Existing production runs were neither
deleted nor migrated during development.

## Optional OTLP adapter

`BoundedOTLP(exporter, enabled=False)` is an injected OTLP/HTTP JSON adapter, with no network
transport or collector provisioned. It exports only allowlisted categories and hashed
identifiers. A full queue returns `backpressure_retry_same_event`; the caller must not advance
its input cursor. Export failure retains the queue and returns an error class without exception
text. Delivery is at-least-once; receivers can deduplicate the hashed event identity.
This adapter runs independently of review execution and never becomes evidence authority.

## Deployment boundary

The changed observability modules are application Python code, not newly mounted job scripts.
No script mount was added and no running application was reloaded or rebuilt. A later deployment
must use the existing signed application-image lifecycle for these baked-in modules; changing
the checkout alone does not update a running image. Unrelated tooling images need no rebuild.

## Manual integration and acceptance commands (NOT RUN for this package)

Use this checkout's own Linux environment, installed with `.[test]`. Integration requires an
already running **isolated** Dagster instance and OTLP/HTTP logs collector. Never use customer
or production endpoints. The tests do not start services:

```sh
APPSEC_OPERATIONS_ISOLATED_SERVICES=1 \
APPSEC_OPERATIONS_DAGSTER_URL=http://127.0.0.1:<isolated-port>/graphql \
APPSEC_OPERATIONS_OTLP_URL=http://127.0.0.1:<isolated-port>/v1/logs \
.venv/bin/python -m pytest -q tests/integration/test_operations_package.py \
  --basetemp=test/tmp/operations-integration

.venv/bin/python -m pytest -q tests/acceptance/test_operations_package.py \
  --basetemp=test/tmp/operations-acceptance
```

The separate suites combine real writers/readers, interrupted logs/restarts, pinned recorded
quality observations and disposable multi-run retention with shared evidence and holds.
Default collection excludes `tests/integration` and `tests/acceptance`; these explicit commands
are manual opt-ins. Unit results do not establish either suite has passed.
