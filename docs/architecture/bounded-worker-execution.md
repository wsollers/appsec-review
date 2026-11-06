# Shared bounded model execution

`src/appsec_review/inference/execution.py` supplies **mechanics, not an agent framework**.
Each job still constructs its own request, authorizes its own retrieval, validates its own final
answer, and decides whether that answer is a finding, abstention, unresolved obligation or gap.
The engine does not grant tools, load guidance, choose personas, run commands, or change a
claim's state. Deterministic scoring and attack-chain helpers remain deterministic.

## Stable interfaces

`Infer(request, *, timeout_seconds) -> ModelResult`, `ModelRequest`, and `ReviewModelRequest`
remain the transport interfaces. Provider authentication, SDK setup, tool denial and process
cleanup stay inside provider modules. Test doubles replace this boundary, not the shared loop.

An `Execution` bounds one sequential conversation:

```python
execution = Execution(
    timeout_seconds=profile.timeout_seconds,
    max_calls=call_limit,
    context=CallContext(run_root, run_id, job_id, attempt_id, step_id, task_id),
)
result = execution.call(infer, request, timeout_seconds=profile.timeout_seconds)
```

The optional context defaults to the current immutable job publication scope. Explicit contexts
also support bounded `package_id`, `lane`, `batch_id`, `build_unit_id` and `case_id` correlations.
A legacy `ModelRequest` adapter can pass its exact bundle pin as `guidance_sha256`; otherwise the
summary's valid `guidance_bundle_sha256`, or a digest of the exact guidance content, identifies
the guidance. No free-form correlation dictionary reaches general telemetry.

The engine shares a monotonic deadline across turns and retry waits. It checks cancellation
before admission and after the transport returns, limits physical calls, bounds serialized input
(including transcript) and output, optionally bounds cumulative output bytes, normalizes usage,
and retains an immutable `CallReceipt`. Optional `CallAccounting.reserve/settle` hooks admit
before the start event and settle in `finally`, including cancellation and rejected output.
Admission refusal is not reported as a physical provider call.

`RetryPolicy` holds finite attempts, the timeout/provider/schema switches and the configured
backoff schedule. `Execution.retry` checks the category, waits in cancellation-aware slices no
longer than 100 ms, and cannot extend the conversation deadline. Once the schedule is exhausted,
its final delay is reused; an empty schedule means no delay. First-error mode permits one attempt.
Adapters may retain a stricter repair policy; remediation's invalid final remains terminal.

Cancellation is cooperative. A synchronous arbitrary Python callback cannot safely be preempted
by abandoning a thread. The `Infer` contract requires a transport to honor the supplied timeout,
finish or positively diagnose cleanup, and never return a success while cleanup is unconfirmed.
Provider implementations, rather than an extra runtime supervisor, own process/SDK cancellation.

## Failure and usage contracts

`inference.errors` defines the closed categories `timeout`, `cancelled`, `provider`, `schema`,
`budget`, and `contract`. `ProviderError` explicitly says whether a failure is transient.
`ModelOutputError` is a schema/decoding failure, `ModelTimeout` is a real `TimeoutError`, and
`ModelCancelled` preserves cancellation control flow. A programming exception is not inferred to
be a provider outage. Unexpected application/integrity errors retain evidence and propagate.

`inference.usage.Usage` keeps input, output and cache reports independently. Missing, negative,
boolean and noninteger token values become **unknown (`None`)**, not zero. A known partial sum
must not be presented as a complete actual total. Token-derived byte estimates are bounds on
serialized material, not measured tokenizer usage.

`ModelResult.usage_source` is `provider` or `replay`. Replay preserves historical reported values
with their provenance but adds no new billable tokens. Cache tokens are separate reports, not
silently subtracted from input tokens. Unknown-usage reasons include `provider_usage_missing`,
`invalid_provider_usage`, `no_provider_response`, and `recorded_replay`.

Budget snapshot `input_tokens`/`output_tokens`/`cache_tokens` retain backward-compatible **known
subtotals**; use `actual_input_tokens`/`actual_output_tokens`/`actual_cache_tokens` for complete
actual totals, which are null while reports or live reservations leave them unknown. Native SBOM
integer publication counters likewise remain known subtotals; its `usage_totals` and
`known_usage_subtotals` qualify the complete versus partial figures explicitly. Reused cell
receipt counts describe the historical receipt, not a new dispatch; `reused`/`reuse_source`,
the run budget and physical model-call events distinguish that reuse from new spend.

## Run budget admission and settlement

The inference-review job opens `JobBudget.for_run(run_root, limits)`, not a fresh counter file
per runtime attempt. Its canonical ledger is
`data/jobs/job_inference_security_review/budget/budget.json`.

```python
reservation = budget.reserve_call(
    owner_id=owner_id,
    input_tokens=request.max_input_tokens,
    output_tokens=request.max_output_tokens,
    replay=False,
)
# None means do not launch.
budget.settle_call(reservation, usage=usage, dispatched=True)
```

Under the existing kernel lock, admission includes known spend, conservative unknown-spend
liabilities, and all in-flight reservations. It reserves one turn and the requested input/output
maxima before dispatch. A response settles actual reported usage even when the provider exceeds
those maxima. Unused reservations are released. A failed/cancelled dispatched call has unknown
possible spend: it releases its live reservation but retains a conservative admission liability.
An undispatched call is settled with `usage=None, dispatched=False`.

Settlement identities are immutable and idempotent; conflicting repeated settlement is an
integrity error. Replay is accounted separately. These are **launch limits, not hard billed-cost
guarantees**: a provider may overrun, or fail without reporting its spend. Exhausted work keeps
named budget gaps rather than looking clean.

An exhausted budget does not forbid revalidating an existing immutable receipt. Already-selected
team work can reconstruct prior claims in a no-new-calls context; it cannot use that path to
bypass fresh team or call admission. This preserves completed findings across an interrupted
attempt without resetting the cumulative budget.

`reconcile_owner(owner_id, cessation_evidence=..., dispatched=True)` handles positively stopped
abandoned ownership. Age alone never reclaims it. The evidence string must identify immutable
run-owned evidence proving cessation; the budget validates the bounded string, and the lifecycle
caller is responsible for verifying the evidence. `dispatched=False` requires proof that *every*
remaining reservation for that owner was never dispatched.

## Active timing and compatibility

New review-job budgets select `new_timing_mode="active_v2"`. Other callers of `for_run` retain
the explicit default `wall_clock_v1`. Existing or imported wall-clock budgets never silently
switch semantics.

`resume_execution(owner_id)` opens an active owner; `pause_execution(owner_id,
cessation_evidence=...)` closes only that owner and requires it to have no live reservations.
Overlapping owners contribute the union of their active intervals, not the sum. Reusing an
already-closed owner is invalid: a new immutable invocation needs a new identity.

The review adapter uses an attempt/cell/invocation owner around bounded cell execution, including
retrieval and backoff. Normal completion/reuse closes that interval against the verified terminal
cell receipt. Time between such intervals, including a repair pause, is excluded. An interrupted
or integrity-failed invocation remains conservatively open until its lifecycle owner establishes
cessation and reconciles it. This is budget accounting, not a replacement runtime state machine.
Spend and all earlier receipts remain cumulative through pause/resume.

Budget v1 imports retain their original counters and wall-clock origin. Previous attempt-local
ledgers are imported once with pinned identities; ambiguous or changed historical inputs fail
explicitly. Historical usage quality is `legacy_unverified`, since old zero-filled counters
cannot prove complete billed usage. The snapshot exposes selected elapsed time, cumulative
active time, active owners, live reservations and reserved amounts separately.

Review-cell executor `/3` fingerprints the changed mechanics, so older semantic behavior is not
silently reused. Old cell receipt bytes are never rewritten. The blue-only memo remains a
revalidated pointer to immutable same-run results; verifiers and judges do not share that memo.
Garnet outages remain optional-cache misses with visible diagnostics.

## Recording, replay and telemetry

Recording v2 stores closed, bounded error envelopes instead of recreating arbitrary exception
classes. It preserves timeout/cancellation/provider/schema/contract semantics and safe bounded
diagnostics. No replay path imports an exception class named by a recording or executes a
recorded command. Legacy v1 successful responses remain readable; legacy v1 errors are explicitly
rejected because their lost semantics cannot be recovered safely.

Recordings use `<job>/<request-key>.<sequence>.json`; repeated identical calls reserve their
ordinal at admission, not completion. Copy `recording-root.json` **with** the job directories
when replaying elsewhere. Malformed envelopes, mismatched roots/requests and replay misses are
explicit integrity failures, never an invitation to call a live provider.

Shared hash-only execution receipts live under
`data/inference-executions/<job-attempt-digest>/<execution-id>/<sequence>.json`.
Existing specialized receipts retain the semantic result, retrieval provenance and final
validation decisions. General `MODEL_CALL_STARTED`/`MODEL_CALL_COMPLETED` events use the existing
`PipelineLog`/`emit_model_event` contract with request/guidance/attempt identities, retry number
and closed reason, requested and reported provider/model, usage availability, and failure
category/code. Terminal statuses include `SUCCEEDED`, `FAILED`, `TIMED_OUT`, and `CANCELLED`.
Prompts, model answers, source text, exception messages and secrets do not enter these events.

## Verification boundaries

The package's deterministic unit coverage and exact commands/results are recorded in
[`../tasks/2026-11-06-bounded-worker-execution.md`](../tasks/2026-11-06-bounded-worker-execution.md).
The new suites under `tests/integration` and `tests/acceptance` are explicit manual checks,
excluded from implicit unit collection. They were **written, not run** for this package.
No passing unit result establishes live provider cancellation, a live review, deployment,
integration or acceptance success.
