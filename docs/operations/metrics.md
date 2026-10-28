# Review metrics

Run `appsec-review metrics --run-id <id>` after or during a review. The command deterministically
rebuilds `runs/<run-id>/data/telemetry/summary.json` and prints the same document. It does not scan
the target repository. All review-scope values resolve through receipt paths and SHA-256 identities
recorded in the run telemetry stream.

The integrating [job interchange telemetry](../architecture/telemetry.md#interchange-instrumentation)
adds a receipt-verified `interchange` section (`appsec-review/interchange-metrics/1`) in
`appsec-review/run-metrics/5`. It separates handoff admission, execution, coverage, native retention,
and observation provenance. Until that integration is deployed, existing `/4` summaries lack this
section; absence is not zero provenance work. Do not copy claimed event counts into reports:
retention/provenance receipt bytes and computations must verify first. Duplicate publication/receipt
identities must not inflate totals, and reused results must not count as fresh scanner execution.

The new section groups handoff `accepted`, `rejected`, `validated`, unit/retry counts,
`coverage_dispositions`, `execution_statuses`, `producer_gap_codes`, and validation `duration_ms`.
`native_outputs` distinguishes reference count from distinct artifact count/bytes, retained
completeness/truncation, and native result count. `observations` distinguishes observation count,
native-reference count, and complete/incomplete/truncated batches. Registered job IDs bound
`by_job`; closed `integrity_gap_codes` classify failures without path/rule/message labels.
Read each section's `accounting_complete`: a null count with an integrity gap is not a measured zero.

Observation `provenance_complete_count` and `provenance_incomplete_count` partition observation
counts by receipt completeness; `provenance_gap_count` is the receipt-computed sum of common
`gap_ids`, not an adjudicated finding count. Root `duplicate_events` identifies duplicate event
identities. Receipt references are `HANDOFF_*.handoff_reference`,
`NATIVE_OUTPUT_RETAINED.retention_receipt`, and
`OBSERVATION_PROVENANCE_VALIDATED.provenance_receipt`; metrics verify those artifacts before
using their computations.

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

The upgraded summary schema is `appsec-review/run-metrics/5` (historical summaries use `/4`).
Use the top-level `codeql` section for CodeQL
execution telemetry: `by_query_pack`, `by_language`, `by_query_pack_language` (pack, then language)
and `by_source_language` each report `count`, `statuses` (`SUCCEEDED`, `FAILED`, `TIMED_OUT`,
`SKIPPED`, `REUSED`, zeroes included), `runtime_ms` (`total`, `min`, `max`, `p50`, `p95` over fresh
executions plus `measured_count`/`unmeasured_count`), `result_count`, `gap_count`,
`truncated_count`, and a `by_action` breakdown. Database creation is grouped under the pack
`(database creation)`. `by_query` holds per-query and per-rule rows, `executions` one row per
action with its `per_query` status, and `gaps` names every missing per-query source or unmeasured
runtime. Sources and limits are described in
[CodeQL execution telemetry](codeql-analysis.md#execution-telemetry).

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

## Interchange troubleshooting

For `HANDOFF_REJECTED`, inspect the hash-bound diagnostic handoff and detailed outcomes when
available. Separate framework `execution_status` from `status` admission and `coverage.disposition`;
an accepted partial publication is not a failed runtime, and successful execution need not provide
complete coverage. Read unit status/result references and gap codes before retrying.

A missing, changed, escaped, or malformed handoff, outcomes file, native artifact, retention receipt,
or provenance receipt is an integrity gap. Preserve it for diagnosis and rerun the affected
producer; never repair accepted JSON or reset its pointer. A count disagreement is likewise not
permission to trust the larger number. If receipt metadata is available but its raw report is
protected, use authorized run-artifact access, not an inference retrieval bypass.

For `handoff_schema_changed`, preserve the `/1` attempt and use `plan-resume`/`resume` to produce
new `/2` publications and dependent indexes. For scanner failure, missing output, parser failure,
or truncation, fix the named prerequisite or bound and rerun the affected unit; retain unrelated
verified checkpoints. Disabled, not-applicable, empty, failed, and inventory-only coverage never
establish a security-negative result.
