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

The summary schema is `appsec-review/run-metrics/4`. Use the top-level `codeql` section for CodeQL
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

## OpenVEX metrics

Implemented at `5d2d1a44eaae5cc5939d36fa463036185d3ece13`. The additive `openvex`
section has semantics `appsec-review/openvex-metrics/1` in the existing run-owned summary,
preserving OWASP/review-flow metrics. No Prometheus, exporter SDK or network endpoint is
added. See the [operator guide](openvex-export.md)
for eligibility, outcomes and protected output handling.

| Field | Meaning |
| --- | --- |
| `openvex_export_attempts_total` | Terminal fresh attempts by `outcome`: `exported`, `exported_with_gaps`, `no_statements`, `failed`, reconciled against runtime terminals. |
| `openvex_export_reuses_total` | Deduplicated runtime `JOB_REUSED`, without a fresh attempt, duration or document-size sample. |
| `openvex_export_failures_total` | Failures by closed `phase` and `reason`, including pre-domain admission failure from runtime `JOB_FAILED`. |
| `openvex_export_statements_total` | Accepted fresh statements only, with `status = affected`; explicit zero for accepted empty results. |
| `openvex_export_findings_total` | Every gate package once per accepted fresh result, by `disposition = included/excluded` and `reason = included/gate_verification_backlog/gate_withheld`. |
| `openvex_export_document_bytes_total` | Actual canonical document bytes from accepted fresh nonempty results. |
| `openvex_export_duration_seconds` | Measured fresh wall-duration histogram by terminal outcome; failures included when measurable. |
| `openvex_export_phase_duration_seconds` | Fresh operation-duration histograms by phase; inclusive measurements are not necessarily exclusive work. |
| `openvex_export_document_bytes` | Accepted fresh nonempty document-size histogram. |

Phases are `load`, `assemble`, `validate`, `accept`; operation stages are
`openvex.verify_inputs`, `openvex.assemble`, `openvex.validate`, `openvex.accept`.
Failure reasons are restricted to `configuration_invalid`, `input_missing`, `input_stale`,
`input_tampered`, `identity_conflict`, `schema_invalid`, `semantic_invalid`, `bound_exceeded`,
`timed_out`, `io_error`, `internal_error`. Diagnostics must not become unbounded labels.

Duration buckets in seconds are
`0.01, 0.05, 0.1, 0.5, 1, 5, 15, 30, 60, 120, +Inf`;
document-size buckets in bytes are
`1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 33554432, +Inf`.
Histogram JSON contains cumulative fixed buckets, `count`, `sum` and measured/unmeasured
counts. With no measured samples, `sum` is null, not zero; a measured zero is a valid sample.
Reuse, crashes or missing measurements do not supply fake zero durations.
Accepted `no_statements` contributes explicit zero statement/document-byte totals but no
document-size sample, because no document exists.

The section also exposes `configured_enabled`, `latest_state`, `latest_accepted`,
`accepted_fresh_output_count`, zero-filled exclusions in accepted counts and telemetry
`gaps`/`conflicts`, plus `accounting_complete`. `disabled` and
`not_run` are not successful attempts. Missing/unreadable accepted artifacts yield null
accepted counts with a named gap, not zeros. Read counts from bounded, hash-verified
accepted results, not just emitted events; distinguish cumulative work from latest output.

Events are `OPENVEX_EXPORT_STARTED`,
`OPENVEX_INPUTS_VERIFIED`, `OPENVEX_EXPORT_ACCOUNTED`, `OPENVEX_EXPORT_COMPLETED`
and `OPENVEX_EXPORT_FAILED`. A completed domain event followed by failed runner
finalization must not increment accepted statements/bytes. Domain outcome, runtime success
and `HANDOFF_ACCEPTED` are reconciled; semantic counts require the full accepted-export
reader, which rehashes immutable inputs and runtime-declared artifacts and proves canonical
reassembly. Later tamper can preserve a known execution outcome/attempt count while making its
semantic contribution unavailable. If no verifiable accepted output remains, statement,
finding and document-byte totals are null, with named gaps rather than false zeros.

Attempts correlate by run/job/attempt and domain `invocation_id`; semantic totals deduplicate
accepted handoff digests. Reuse correlation prefers `invocation_id`, then `dagster_run_id`,
then stable `event_id`, distinguishing real repeated invocations from duplicate records.
Missing/conflicting terminals, phase measurements or acceptance produce explicit gaps/conflicts.
`attempts` holds correlation details, while `duplicate_lifecycle_records` records deduplication.
Timing stays in logs/receipts/summary, outside deterministic document/manifest/result bytes.

The ordinary runtime metrics snapshot is written **before** `HANDOFF_ACCEPTED`. The report
tail's later snapshot, or an explicit `appsec-review metrics --run-id <id>`, refreshes accepted
semantic totals after acceptance. An initial missing-acceptance gap/null total is not an
accepted empty export. No runtime sequencing changes or background metrics service are added.
The metrics consumer records unreadable latest output as `latest_state = stale` with a
`latest_accepted_output_unavailable` gap; the final-report consumer instead fails on corrupt
accepted artifacts. Neither behavior establishes a clean result.

No finding/claim/product/run IDs, hashes, filesystem paths, repository/issuer/action text,
source, credentials or model/error strings are permitted as metric labels. Run/job/attempt/
span identifiers are structured log correlation only. Counts cannot establish handoff
acceptance, issuer authority, exploit execution, absence of vulnerabilities or shipping approval.
