# Telemetry and derived metrics

`runs/<run-id>/data/logs/pipeline.jsonl` is the canonical append-only event stream. Every record uses
`appsec-review/telemetry-event/1`, a contiguous sequence, stable event identity, UTC timestamp, and
run/job/attempt/step/task correlation. Details may add Dagster run/node, producer/tool invocation,
index shard, MCP session/invocation, model invocation, or finding-package identities.

The writer is process-safe and crash-recovering. It bounds depth, collection size, strings, and total
record bytes. Credentials, secret-like values, prompts, responses, raw model output, source text,
and query text are redacted. Telemetry uses request, guidance, reason, evidence, and artifact hashes.
Where a job explicitly needs raw provider or tool output for diagnosis, it stores bounded bytes as a
run-owned task artifact with access inherited from the run; those bytes are never copied into this
central event stream, and credentials remain prohibited.

Lifecycle families are:

- `RUN_*`, `GRAPH_*`, `JOB_*`, `STEP_*`, and `TASK_*` start and terminal events, including duration,
  reuse, disposition, and `COMPLETED_WITH_GAPS` where applicable.
- `TOOL_INVOCATION_STARTED/COMPLETED` for scanners and external tools, with immutable tool identity,
  retry, duration, result/gap counts, truncation, disposition, and error class.
- `MCP_TOOL_STARTED/COMPLETED` for transport calls and `RETRIEVAL_SUBOP_COMPLETED` for child spans.
- `MODEL_CALL_STARTED/COMPLETED` around inference calls (currently emitted by target analysis
  planning, project-build image repair, post-build security assessment, OWASP worker/independent
  assessment, and lead/hunt red/blue/verifier/judge cells), with
  provider/model/reasoning identities, guidance and request hashes, token/cache counts, duration,
  retry, status, and error class.
- `DAGSTER_QUEUE_DELAY`, written by the Dagster adapter when it claims a job attempt, with the
  Dagster run id and the delay in milliseconds since that Dagster run was created.
- `PROJECT_IMAGE_BUILD_STARTED`, `PROJECT_IMAGE_BUILT|REUSED|BUILD_FAILED`, and
  `BUILD_PROBE_REUSED` record project-image and cross-run probe decisions by recipe and image
  identity. `PROJECT_IMAGE_REPAIR_ACCEPTED|FAILED|REUSED` records bounded repair disposition and
  identities without Dockerfile, package, diagnostic, or model-response text. Probe compiler/linker
  commands use the ordinary `TOOL_INVOCATION_*` lifecycle.
- `LANGUAGE_STATIC_WORKFLOW_DISPATCHED` and `LANGUAGE_BUILD_WORKFLOW_DISPATCHED` record bounded
  routing decisions. They carry identities and counts, not raw commands, source, or model content.
- `FINDING_TRANSITION` for `NONE -> CANDIDATE -> CONFIRMED|REFUTED`. It carries the immutable finding
  package, evidence identities/count, actor class, and reason/evidence hash. Scanner observations are
  evidence records; they are never counted as confirmed findings without a valid transition.
- `REVIEW_SCOPE_CATALOGED`, `LANGUAGE_BUILDS_RECORDED`, and `CODEQL_SCOPES_RECORDED` point to
  immutable, hash-verified run receipts. They make workload, build, artifact, and missing-producer
  scope available to the metrics derivation without copying mutable aggregate counters into events.

## Interchange instrumentation

The [interchange upgrade](job-interchange.md) adds `HANDOFF_VALIDATED` and `HANDOFF_REJECTED`
alongside `HANDOFF_ACCEPTED`. Each event binds `handoff_reference`
(`path`, `sha256`, `size_bytes`), `duration_ms`, `execution_status`, `admission_status`,
`coverage_disposition`, `unit_count`, `gap_count`, and `retry_required`.
A rejection may use a null handoff reference only when a safe diagnostic publication is unavailable.
Accepted events retain `handoff_path`, `handoff_sha256`, and `completion_status` for existing
consumers. The event's completion status is bounded to known runtime terminals or `UNKNOWN`;
native producer status remains in receipt accounting, not arbitrary telemetry labels.
Validation events describe publication work, not repeated validation on checkpoint reuse.

`NATIVE_OUTPUT_RETAINED.retention_receipt` and
`OBSERVATION_PROVENANCE_VALIDATED.provenance_receipt` bind immutable retention/provenance
receipts; handoff events use `handoff_reference`. They describe retained bytes and resolving
observation references, not scanner-origin attestation or vulnerability confirmation.
Events carry bounded identities, durations, counts, and hashes,
never raw reports, source, argv, secrets, or per-result message text. The fixed work-counter names
are `handoff_validations`, `native_output_references`, `native_output_bytes`,
`observation_references`, and `provenance_gaps`; paths, rule IDs, gap reasons, and arbitrary producer
status strings must not become unbounded counter labels.
Native retention/provenance events take run/job/attempt identity explicitly from the publication
owner. Native reference/byte work counters also measure verified reuse consumption; they describe
logical reference processing, not fresh scanner execution or physical retained occupancy.

The metrics contract is `appsec-review/run-metrics/5`, adding `interchange` with schema
`appsec-review/interchange-metrics/1`. It derives publication/receipt identities and verifies the
referenced bytes and retention/provenance computation instead of trusting event-supplied counts.
Missing or tampered receipts are named integrity gaps, not zero work. Repeated publication/receipt
events deduplicate by identity, while reused evidence is not counted as fresh scanner work.
The closed groups are `handoffs`, `native_outputs`, `observations`, registered-job-only `by_job`,
and `integrity_gap_codes`. Section `accounting_complete` distinguishes measured accounting from
missing evidence; invalid/missing receipts yield null affected totals, not invented zeros. Rollups retain
coverage/execution/gap-code dimensions but never rule/path/hash/package/message labels.
Observation rollups also distinguish `provenance_complete_count` from
`provenance_incomplete_count` using receipt completeness, and `provenance_gap_count` sums common
observation `gap_ids` from the receipt computation. `interchange.duplicate_events` reports repeated
event identities without inflating the verified publication or receipt totals.
Handoff `duration_ms` has `count`, `sum`, `p50`, `p95`, and `max`, once per publication rather than
once per validated/accepted event. This is publication timing, not scanner runtime.
Interchange processing is bounded to 100,000 relevant events; exceeding it produces
`accounting_bound_exceeded` and incomplete affected accounting. The receipt is authoritative,
not the presence of a summary field. Integrated source and offline tests do not establish that a
deployed runtime has been rebuilt or accepted.

## Existing derived views

`appsec-review metrics --run-id <id>` deterministically rebuilds and persists
`data/telemetry/summary.json` using `appsec-review/run-metrics/5`
(historical summaries use `/4`). It separates end-to-end wall time, per-job wall spans, summed
concurrent task time, queue delay, completed and still-running work, reuse, processed counts/bytes,
critical-path candidates, and bounded p50/p95/max rankings by stable operation identity. The JSONL
events remain authoritative; the summary is a regenerable operator view.
The [end-of-review telemetry report](../operations/telemetry-report.md) renders both, read-only,
into one LaTeX/PDF rollup per run.

The additive `project_image_builds` view reports preparation starts, fresh builds,
reuse, failures and failures by language family. Image preparation is paired by
`build_unit_id`, including `PROJECT_IMAGE_BUILT`, `PROJECT_IMAGE_REUSED` and
accepted-repair reuse as terminals; unrelated repair failures do not close that
phase. A handled `PROJECT_IMAGE_BUILD_FAILED` is a nested preparation gap, not a
failed Dagster step or `TASK_FAILED`. Concurrent starts/terminals need not be
adjacent. Ordinary split task failures separately close FAILED step/attempt state;
new-contract terminal Dagster failure recording supplies graph/run terminal events
when success-only finalizers are skipped. Historical events are not rewritten.

The additive `owasp` section resolves `OWASP_ASSESSMENT_RECORDED` to the hash-verified workbench
report. It retains each publication attempt and the latest coverage denominators without summing
the same rows across retries. A missing, changed, or invalid latest receipt is a named gap, not a
fallback to older coverage. New dispatch starts and completed calls remain separate, so an
in-flight request is not zero work or completed coverage. Input-index retrieval, batch
source/citation resolution, and model-requested expansion are separate counters; worker metrics carried into independent review
are read once from the final report, not summed again from intermediate worker events.
`OWASP_MODEL_REUSED` records verified reuse with no new dispatch, and
`OWASP_RETRIEVAL_COMPLETED` distinguishes succeeded, denied, failed and budget-skipped requests.

The additive `review_flow` section retains control-evidence projection and package/lane publication
milestones, manifest pins, and the latest cell disposition per attempt/cell. Cell metrics distinguish
fresh work, verified reuse, and not-launched work. Historical retrieval counts on reused cells are
not fresh queries. Absent milestones mean unrecorded execution, not successful zero-work stages.
Generic task/step/operation events supply stage timing and failures across the entire graph.
`model_invocations` now retains role/persona, cell, batch/package/lane, job-attempt/task correlation,
transport status, and available served identities. Transport success does not establish valid
assessment output: the OWASP attempt/cell receipt retains that separate disposition. Provider token
usage stays nullable; invalid usage is named rather than aggregated as zero. Configured recording
replay is labelled separately and contributes neither new inference nor historical token usage
to fresh-call totals. Cell dispatch attempts remain distinct from that fresh-call count.
Neither model counts nor publication/cell success establish findings or safety, and scripted/recorded transports do not
establish live-provider efficacy. Raw prompts, responses, source, and exception text are not emitted
by the shared model-call measurement helper.

Version 4 adds the top-level `codeql` section (`appsec-review/codeql-execution-metrics/1`). Every
CodeQL action (database, analyze, compile, export) is one row derived from its
`TOOL_INVOCATION_COMPLETED`, `CODEQL_ACTION_SKIPPED`, or `CODEQL_ACTION_FAILED` event. Each event
carries language, source languages, build mode, action, query pack, pack version, and suite; runtime
comes from the hash-verified execution receipt. Rows are aggregated by query pack, by language, by
query pack x language, and by source language, each with per-status counts and runtime
total/min/max/p50/p95. Per-query rows come from the run-owned
`appsec-review/codeql-query-metrics/1` document named by the event's `query_metrics` identity;
an absent source is a named gap, never zero. See
[CodeQL execution telemetry](../operations/codeql-analysis.md#execution-telemetry).

The `review` section uses `appsec-review/review-metrics-semantics/1`. Source classification is
`appsec-review/source-counting/1`: language is extension-based; SLOC is the number of non-empty
UTF-8 physical lines (comments included); generated paths have a `generated` or `gen` segment;
vendored paths have a `vendor`, `vendors`, or `third_party` segment; and tests have a `test`,
`tests`, `spec`, or `specs` segment or a `test_`/`spec_` filename. `dist`, `build`, and
`node_modules` trees are excluded and reported as coverage gaps rather than silently counted.
Generated, vendored, and test files remain in language totals and are also reported as explicit
subtotals. Bounded, excluded, undecodable, or missing catalog input is a source coverage gap.

The additive `tree_sitter` view (`appsec-review/tree-sitter-metrics/1`) re-verifies correlated
start, execution and validated-output receipts, including invocation/run/job/attempt identity.
It reports per-invocation outcomes/resources/files/nodes/truncation, job-attempt groups and reuse;
timing separates summed invocation work, elapsed window, covered wall time and maximum concurrency.
Missing or conflicting receipts/resources keep explicit gaps, nulls and completeness flags.
`memory_peak_bytes` is the maximum individual container peak, not concurrent aggregate memory.

Build outcomes come from accepted language-build receipts. A reused successful receipt counts as
reuse rather than fresh success; any receipt with producer gaps also increments the gap count.
Artifact reference totals count each build-unit-to-artifact edge. Content-deduplicated totals count
one SHA-256 identity globally, while per-language/build-unit/family groups retain every reference.
Conflicting sizes for one digest are an integrity gap.

CodeQL database and query time resolve to immutable execution receipts; reused checkpoints resolve
to immutable checkpoint receipts and contribute zero work. Groups retain scope, language, project
root, build unit, profile, and query-suite identity. `summed_work_ms` sums producer work, while
`wall_span_ms` is the union of event intervals and therefore does not double-count concurrent work.
The view includes p50, p95, maximum, fresh/reused counts, and language/project/profile rollups.
Missing receipts, failed producers, and planned scopes without timing remain explicit gaps.

Raw SARIF/tool observations are not finding counts. The only authoritative defect/vulnerability
lifecycle metrics are the existing `FINDING_TRANSITION` state counts. TODO: before reporting
triaged-away/refuted and confirmed defect or vulnerability rates by taxonomy, implement immutable
transition receipts that bind a finding package to its observation identities, normalized defect
or vulnerability classification, prior and new state, actor class, reason hash, timestamp, and
supersession identity. Metrics must reject broken transition chains and must never infer candidates
or confirmation from observation volume.

For fleet/control-plane state, `python deploy/dagster/bin/run_report.py` reports the live Dagster
run list alongside bounded slow-operation rankings collected from available summaries. It separates
completed, queued, genuinely running, stale, and orphaned Dagster records. `--stale-seconds`
controls classification; the command is read-only.

## Evidence-completion tracking (commissioned)

The user requires telemetry and metrics from the first implementation of the
[completion lanes](evidence-completion-and-remediation.md#11-parallel-implementation-decisions),
not instrumentation added after rollout. Integration `b702eb7` adds completion aggregates and
remediation/dossier events to the existing system. Checkpoint `18eae9f` adds aggregate parity for
real PoC/native statuses, capability maps, flags and nonadditive limits. Remediation follow-up
`e769645f` preserves unknown token dimensions/null versus genuine measured zero and emits unavailable
metadata. Final `dd9c9ad` adds actual chain composition/challenge/publication, PoC outcome,
gate capability/admission and report assembly events. The table below records the complete tracking
requirement, not a claim that every producer emits every dimension or provider usage measurement.

Reuse [`EventLog.write`](../../src/appsec_review/observability/events.py) through `context.events`
and [`aggregate_run_metrics`](../../src/appsec_review/observability/telemetry.py), retaining the
canonical pipeline stream and regenerable `data/telemetry/summary.json`. No separate telemetry
backend or Azure service is requested.

[`observability/completion.py::completion_metrics`](../../src/appsec_review/observability/completion.py)
first added `completion` to `appsec-review/run-metrics/3`; combined source `6975aef2` retains
the same `completion-process-metrics/1` semantics in `run-metrics/4`, alongside the existing
review and new CodeQL/OWASP/review-flow/Tree-sitter views.
Its `semantics` is `appsec-review/completion-process-metrics/1`, with
`authority: observational_process_metrics_not_security_evidence`. Fixed lanes are
`attack_chains`, `poc_generation`, `remediation_planning`, `remediation_validation`, `dossiers`,
`publication_gate`, `report_publication`. Chains are selected by inference `step_id=attack_chains`
or the `INFERENCE_REVIEW_ATTACK_CHAIN` event prefix; other lanes map fixed job ids.

Each lane contains `observed` and `events`. Each event has the following closed aggregate shape:

| Field | Meaning and bounded dimensions |
| --- | --- |
| `count`, `counters`, `outcomes` | Event count, allowlisted attempted-work sums and closed statuses; outcome maps retain their `outcomes`, `outcome_counts`, `by_kind` or `by_status` prefix. All seven actual PoC statuses are accepted: `compile_verified`, `compile_failed`, `artifact_generated`, `policy_denied`, `insufficient_evidence`, `not_applicable`, `unsafe_to_attempt`. Native adapter outcomes include `passed`, `baseline_failed`, `patched_failed`, `unsafe`. |
| Capability maps | `attachment_counts`, `gap_counts`, `omitted_counts`, `certified_outcome_counts` become prefixed counters; `dispositions` become prefixed outcomes and Boolean `enabled` values become flags. Only `poc_generation`, `attack_chains`, `remediation_planning`, `remediation_validation`, `dossiers` are valid capabilities. These are event observations, not a replacement for frozen configuration or accepted manifests. |
| `flags` | Counts by Boolean value for `explicit_poc_admission`, `frontier_truncated`, `pdf_requested`, `render_failed`, `baseline_attempted`, `patched_attempted`, `usage_unavailable`, and the fixed capability `enabled` map. |
| `dimensions` | `kind`: `confirmed_finding`, `poc`, `refuter`, `weakest_link_verifier`; `adapter`: `native_syntax`; `role`: `remediation_writer`, `remediation_reviewer`. No arbitrary identity becomes a label. |
| `limits` | Per-event observed `{min,max}` ranges for `max_dossiers`, `max_source_excerpts`, `max_evidence_rows`. Configured limits are **never summed** across retries or counted as work. |
| `unavailable_token_measurements` | Number of explicit-null `input_tokens`, `output_tokens`, `cache_tokens` measurements, not missing turns. Separately, `counters.usage_unavailable_count`, when emitted by a producer, counts turns with unavailable usage. Omitted fields are not invented as zero or counted as explicit nulls. |
| `duration_ms` | `count`, `p50`, `p95`, `max`, `summed_work`; summaries are null when no duration was emitted. |

Capability `enabled`/`dispositions` maps are admitted only for
`FINAL_PUBLICATION_GATE_CAPABILITIES_VERIFIED` in the publication-gate lane (`b9e69d17`).
Generic step lifecycle disposition lists are not capability maps or measurement failures.
The [historical owner all-lane result](../reviews/evidence-completion-documentation-inventory.md#acceptance-ledger)
at `039b24e4` observes all seven lanes with zero measurement gaps while preserving legitimate
review/source/redaction gaps. It uses offline model/compiler/renderer boundary doubles, not live
runtime reproduction. Zero telemetry gaps does not establish complete evidence or current-main
acceptance.

Invalid/nonfinite/negative/oversized measurements and invalid capability/outcome mappings increment
`measurement_gap_count`; at most 200 named `measurement_gaps` are retained.
`COUNTERS`, `OUTCOMES`, `OUTCOME_FIELDS`, `LIMITS`, `CAPABILITIES`, `CAPABILITY_COUNTERS`, `FLAGS`
and `DIMENSIONS` are closed in the source module. Aggregator support for a field does not prove a
producer emitted it; synthetic metrics fixtures do not substitute for actual process observations.
Checkpoint `0ece65d3` adds the real chain challenge map's `not_launched` status to the aggregate
allowlist, with a full `CellStatus`-shaped regression. Its presence still does not establish
accepted challenge coverage. Aggregate counters
exclude arbitrary text, candidate ids, paths, provider prose and raw payloads.

These are event-scoped **attempted work**: retries count; neither stage totals nor overlapping
durations may be summed as unique candidates or end-to-end wall time. `observed=false` is not a
measured zero or a complete missing-producer audit. Producer manifests, frozen config and
integrity/coverage accounting remain necessary.

| Surface | Required process observations |
| --- | --- |
| Stages and attempts | Start/terminal correlation, duration, attempt/reuse and stage progress, enabled/disabled or empty-scope disposition, caps, gaps and failures; unmatched/conflicting lifecycle records remain explicit. |
| PoC candidates | Eligible and terminal candidate counts; policy refusal, unsupported/unavailable, compile outcome, cap/timeout and producer failure. Compilation remains distinct from runtime execution. |
| Chains | Seed/composition/challenge counts, terminal continuity decisions, bounds and missing-edge/verification gaps before ledger sealing. Metrics cannot replace the accepted chain manifest. |
| Remediation | Confirmed-only intake, proposal outcomes and byte-edit applicability; adapter selections, static/build/manual outcomes, rejections and adapter failures. No `fixed` or runtime-success counter follows from a static/build check. |
| Dossiers | Eligible confirmed-finding/PoC counts, source retention, per-item render status, PDF success/failure/timeout, output counts, duration, caps and cleanup gaps. A retained LaTeX source is not a successful PDF. |
| Gate and report | Accepted input/capability accounting, certified attachment counts, integrity failures and missing-producer/coverage gaps, without inventing target evidence from throughput. |
| Model work | Correlated model/retry/duration and provider usage where emitted. Unknown token/cache/cost data remains unknown, not an instrumented zero or an inferred bill. |

Use low-cardinality stage/lane/status/adapter/error-class aggregates. Exact run/attempt/candidate
and artifact hashes are diagnostic correlation fields, not unbounded metric-label dimensions.
Do not double-count per-item outcomes again as stage summaries or add overlapping inclusive
durations as wall time. Failed, skipped, capped and disabled work must remain distinguishable.

Producer fields must be allowlisted before `context.events.write`: its attempt log receives fields
before the central writer bounds/redacts them. Never emit source, patch or PoC payloads, raw prompts,
credentials or arbitrary model/compiler diagnostics into either stream. Use counts, closed statuses,
bounded error classes and resolving hashes instead; existing key-based redaction is not permission
to log arbitrary content under a different key. Metrics are operational accounting, not admissible
security evidence or a public dossier payload. See [metrics operations](../operations/metrics.md)
and the [dossier input inventory](dossier-data-inventory.md).
