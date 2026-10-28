# Review metrics

Run `appsec-review metrics --run-id <id>` after or during a review. The command deterministically
rebuilds `runs/<run-id>/data/telemetry/summary.json` and prints the same document. It does not scan
the target repository. All review-scope values resolve through receipt paths and SHA-256 identities
recorded in the run telemetry stream.

Use `review.source_by_language`, `review.projects`, `review.build_units`, and `review.artifacts` for
scope and throughput. Artifact `reference_*` values answer how much work build units reference;
`deduplicated_*` values answer how many distinct content objects were produced. Do not substitute
one for the other when artifacts are shared.

Use `review.codeql_timings.groups` for like-for-like scope comparisons and the `aggregate`,
`by_language`, `by_project`, and `by_profile` views for rollups. `summed_work_ms` includes concurrent
producer work; `wall_span_ms` merges overlapping intervals. Reused checkpoints are visible as
reused work with zero elapsed producer duration.
That zero describes avoided producer execution only. Read `resource_spans` and
`resource_admissions` for cache verification, staging, preparation and admission delay.
Scope/profile, resource lease and tool invocation identifiers correlate concurrent work;
inclusive process resource samples must not be added across overlapping spans.

Pipeline appends still validate the bounded tail and contiguous sequence under the process lock.
Decoded sequence values are cached for at most 256 exact record byte strings (at most 16 MiB of
record bytes), not by path, timestamp or file size. Changed bytes must be decoded again; tail
ordering, complete-record corruption checks, torn-write recovery and durable flushes are unchanged.

`work_counters` contains measured logical hash/copy work, not physical disk occupancy.
`platform_work` reports explicit instrumented zeros separately from missing counters, which
remain null with a reason. Platform exclusion is unconditional in both assurance modes; absent
measurements are not proof that an uninstrumented boundary did no work. Child resources,
peak RSS, model usage and costs remain null when their attribution or provider data is unavailable.
`lifecycle_accounting = "partial"` and `lifecycle_gaps` expose unmatched/conflicting terminals
rather than manufacturing durations. Raw versus deduplicated event counts are reported separately.

For comparison and interpretation limits, see
[performance and customer-evidence assurance](performance-assurance.md#metrics-and-comparison).
The fixture comparisons preserve semantic package membership, resolving evidence and gaps,
alternate trial order and report individual samples plus medians. The operation-telemetry
comparison disables only added operation spans/counters/resource sampling, retaining ordinary
lifecycle logs and evidence validation in both conditions. Its five-percent threshold and the
strict/managed comparison's reduction threshold are reported outcomes, not assumed passes or
production performance claims.

Treat every entry in `review.gaps`, every nonzero `source_gap_count`, and every build or CodeQL gap
as missing coverage. A missing, changed, escaped, or malformed receipt is an integrity gap and is
never evidence that the corresponding scope is clean. `finding_states` counts only authoritative
finding transitions; scanner observations and CodeQL SARIF result counts are not confirmed defects
or vulnerabilities.

## Completion rollout tracking (pending integration)

The [completion telemetry contract](../architecture/telemetry.md#evidence-completion-tracking-commissioned)
requires PoC, chain, remediation, dossier and final-publication tracking from their first
implementation. The existing `metrics` command and summary path remain the operating surface;
no separate backend is needed. Integration `b702eb7` adds `completion` to `run-metrics/3`, with
`completion-process-metrics/1` semantics. This is observational attempted-work accounting, not
accepted findings or runtime proof. Checkpoint `18eae9f` adds actual status/capability/flag
parity and nonadditive limits; final producer instrumentation is still being reconciled.

Use `completion.lanes.<lane>.observed` and `.events.<event>` for the seven fixed lane buckets
listed in [telemetry architecture](../architecture/telemetry.md#evidence-completion-tracking-commissioned).
Each event reports `count`, allowlisted `counters`/`outcomes`, fixed `flags`/`dimensions`,
`limits`, `unavailable_token_measurements` and `duration_ms.{count,p50,p95,max,summed_work}`.
Configured dossier/source/evidence limits are observed `{min,max}` ranges, **never sums**.
Capability attachment/gap/omission counts, enabled/disposition maps, explicit manual admission,
render/adapter-attempt flags and fixed kind/role/adapter dimensions are retained where emitted.
`unavailable_token_measurements` counts explicit-null token fields;
`counters.usage_unavailable_count` counts producer-reported missing-usage turns instead.
Neither means a missing field was measured as zero. An unobserved lane is not an observed zero.
`measurement_gap_count` and bounded `measurement_gaps` identify invalid emitted readings; they
do not independently prove all expected candidates/stages were measured.

Operators must be able to follow stage and candidate progress, terminal dispositions, caps,
coverage/integrity gaps, retry/reuse, adapter/render failures and durations. Correlate individual
outcomes by run/attempt and accepted artifact identities, while grouping rollups by bounded
lane/stage/status/error class. Compare accepted candidate/attachment manifests with event totals:
raw lifecycle volume is not the number of unique eligible findings, proposals or rendered PDFs.
Report missing/duplicate/conflicting process coverage explicitly rather than hiding it in success
counts. Model usage applies only where actually emitted; missing provider tokens/cache/cost data
must remain unavailable, not zero. Remediation follow-up `e769645f` now preserves per-dimension
unknown totals as null, genuine measured zero and unavailable-turn metadata. An invocation with
no completed turns has null totals and an unavailable flag even though its unavailable-turn count
is zero. Generic lifecycle events do not substitute for
missing candidate/outcome instrumentation in the other pending producers.

Check frozen run settings before interpreting an absent lane. The
[new-run rollout decision](../architecture/evidence-completion-and-remediation.md#11-parallel-implementation-decisions)
does not enable producers in old immutable configurations. Automatic validation and compile-only
PoC still record no runtime execution; no throughput or successful build metric establishes
reproduction, a passing negative control or a fixed finding. Neither stream nor its metrics may
include raw source, patches, PoC payloads, prompts or credentials.
