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
