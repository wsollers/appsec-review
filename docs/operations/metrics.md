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

## Completion rollout tracking (pending integration)

The [completion telemetry contract](../architecture/telemetry.md#evidence-completion-tracking-commissioned)
requires PoC, chain, remediation, dossier and final-publication tracking from their first
implementation. The existing `metrics` command and summary path remain the operating surface;
no separate backend is needed. Integration `b702eb7` adds `completion` to `run-metrics/3`, with
`completion-process-metrics/1` semantics. This is observational attempted-work accounting, not
accepted findings or runtime proof. Checkpoint `18eae9f` adds actual status/capability/flag
parity and nonadditive limits; final `dd9c9ad` adds real chain/PoC/gate/report events.
Source support is not proof every candidate or model-usage dimension was measured.

Use `completion.lanes.<lane>.observed` and `.events.<event>` for the seven fixed lane buckets
listed in [telemetry architecture](../architecture/telemetry.md#evidence-completion-tracking-commissioned).
Each event reports `count`, allowlisted `counters`/`outcomes`, fixed `flags`/`dimensions`,
`limits`, `unavailable_token_measurements` and `duration_ms.{count,p50,p95,max,summed_work}`.
Configured dossier/source/evidence limits are observed `{min,max}` ranges, **never sums**.
Capability attachment/gap/omission counts, enabled/disposition maps, explicit manual admission,
render/adapter-attempt flags and fixed kind/role/adapter dimensions are retained where emitted.
`FINAL_REPORT_ASSEMBLED.counters.certified_outcome_counts.<capability>` counts the gate-certified
attachment rows reported for each fixed capability. These are counts, not dispositions or unique
findings, and do not establish reproduction or a fixed finding.
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
is zero. Generic lifecycle events do not substitute for missing candidate/outcome measurements.
Checkpoint `0ece65d3` includes chain `not_launched` outcomes and a real `CellStatus`-shaped map
regression, resolving that aggregate allowlist gap. These remain attempted-work observations,
not accepted evidence or proof that no challenge was omitted.

Generation unit tests cover the persisted summary, deterministic replay, stale-cache replacement
and unchanged source-log bytes, not just the in-memory aggregate. They also verify that newly
appended producer events update the summary without recounting old events. Full all-lane
acceptance additionally checks actual producer events through persisted
`data/telemetry/summary.json`; track that separately in the
[implementation record](../reviews/evidence-completion-documentation-inventory.md).

Check frozen run settings before interpreting an absent lane. The
[new-run rollout decision](../architecture/evidence-completion-and-remediation.md#11-parallel-implementation-decisions)
does not enable producers in old immutable configurations. Automatic validation and compile-only
PoC still record no runtime execution; no throughput or successful build metric establishes
reproduction, a passing negative control or a fixed finding. Neither stream nor its metrics may
include raw source, patches, PoC payloads, prompts or credentials.
## Planned OpenVEX metrics

**Design only; not implemented at baseline `b7c31ba23af840f14cc919d56b8c557ffdb2d010`.**
The [OpenVEX design](../architecture/openvex-export.md#12-first-class-telemetry-and-metrics)
specifies an additive `openvex` section with semantics `appsec-review/openvex-metrics/1`
in the existing run-owned summary, preserving OWASP/review-flow metrics. No Prometheus,
exporter SDK or network endpoint is planned. See the [draft operator guide](openvex-export.md)
for eligibility, outcomes and protected output handling.

| Planned field | Meaning |
| --- | --- |
| `openvex_export_attempts_total` | Terminal fresh attempts by `outcome`: `exported`, `exported_with_gaps`, `no_statements`, `failed`, reconciled against runtime terminals. |
| `openvex_export_reuses_total` | Runtime `JOB_REUSED`, without a new duration sample. |
| `openvex_export_failures_total` | Failures by closed `phase` and `reason`, including pre-domain admission failure from runtime `JOB_FAILED`. |
| `openvex_export_statements_total` | Accepted fresh statements only, with `status = affected`; explicit zero for accepted empty results. |
| `openvex_export_findings_total` | Every gate package once per accepted fresh result, by `disposition = included/excluded` and `reason = included/gate_verification_backlog/gate_withheld`. |
| `openvex_export_document_bytes_total` | Actual canonical document bytes from accepted fresh nonempty results. |
| `openvex_export_duration_seconds` | Measured fresh wall-duration histogram by terminal outcome; failures included when measurable. |
| `openvex_export_phase_duration_seconds` | Fresh operation-duration histograms by phase; inclusive measurements are not necessarily exclusive work. |
| `openvex_export_document_bytes` | Accepted fresh nonempty document-size histogram. |

Planned phases are `load`, `assemble`, `validate`, `accept`; operation stages are
`openvex.verify_inputs`, `openvex.assemble`, `openvex.validate`, `openvex.accept`.
Failure reasons are restricted to `configuration_invalid`, `input_missing`, `input_stale`,
`input_tampered`, `identity_conflict`, `schema_invalid`, `semantic_invalid`, `bound_exceeded`,
`timed_out`, `io_error`, `internal_error`. Diagnostics must not become unbounded labels.

Duration buckets in seconds are
`0.01, 0.05, 0.1, 0.5, 1, 5, 15, 30, 60, 120, +Inf`;
document-size buckets in bytes are
`1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 33554432, +Inf`.
Histogram JSON contains cumulative fixed buckets, `count`, `sum` and measured/unmeasured
counts. Reuse, crashes or missing measurements do not supply fake zero durations.

The section is also intended to expose `configured_enabled`, `latest_state`, latest
accepted counts, zero-filled exclusions and telemetry gaps/conflicts. `disabled` and
`not_run` are not successful attempts. Missing/unreadable accepted artifacts yield null
accepted counts with a named gap, not zeros. Read counts from bounded, hash-verified
accepted results, not just emitted events; distinguish cumulative work from latest output.

The event sequence is designed around `OPENVEX_EXPORT_STARTED`,
`OPENVEX_INPUTS_VERIFIED`, `OPENVEX_EXPORT_ACCOUNTED`, `OPENVEX_EXPORT_COMPLETED`
and `OPENVEX_EXPORT_FAILED`. A completed domain event followed by failed runner
finalization must not increment accepted statements/bytes. Lifecycle deduplication uses
`(run_id, job_id, attempt_id, invocation_id)`; semantic totals deduplicate accepted handoff
digests. Missing/conflicting terminal records are telemetry gaps, not fabricated success.
Timing stays in logs/receipts/summary, outside deterministic document/manifest/result bytes.

No finding/claim/product/run IDs, hashes, filesystem paths, repository/issuer/action text,
source, credentials or model/error strings are permitted as metric labels. Run/job/attempt/
span identifiers are structured log correlation only. Counts cannot establish handoff
acceptance, issuer authority, exploit execution, absence of vulnerabilities or shipping approval.
