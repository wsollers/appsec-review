---
title: "Job-local operational tuning"
kind: "operations"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_build_environment_analysis", "job_debug_symbol_indexing", "job_dossier_publication", "job_model_connectivity", "job_review_intake", "job_review_prioritization", "job_sanitizer_build", "job_source_history_analysis", "job_threat_model_generation"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# Job-local operational tuning

Operational compatibility preserves previously accepted work; it does not
rewrite its configuration, repair its gaps or execute additional coverage.
The exact declarations live in
[`config/operational.py`](../../src/appsec_review/config/operational.py).
Every undeclared difference remains material, even when its name contains
`timeout`, `workers`, `memory` or `limit`.

## Supported fields

Each path below is relative to `jobs.<job_id>`. Unless noted below, every supported old and new
value must be a positive integer and satisfy the existing job parser and
claim-time validators. Comma-separated leaf names mean separate declarations,
not permission to change the containing table.

| Job | Exact path(s) | Category | Existing bounds |
| --- | --- | --- | --- |
| `job_model_connectivity` | `settings.timeout_seconds` | execution | 1..600 seconds |
| `job_review_intake` | `settings.model_preflight.timeout_seconds` | execution | 1..600 seconds |
| `job_source_history_analysis` | `settings.github.timeout_seconds` | execution | 1..300 seconds |
| `job_review_prioritization` | `settings.syntax_metrics_reservation.cpu`, `settings.syntax_metrics_reservation.memory_mb`, `settings.syntax_metrics_reservation.admission_timeout_seconds` | execution | CPU 1..256; memory 1..1048576 MiB; admission wait 1..604800 seconds |
| `job_threat_model_generation` | `settings.reservation.cpu`, `settings.reservation.memory_mb`, `settings.reservation.admission_timeout_seconds` | execution | CPU 1..256; memory 1..1048576 MiB; admission wait 1..604800 seconds |
| `job_sanitizer_build` | `settings.workers`, `settings.command_timeout_seconds` | execution | Positive integers; resource admission unchanged |
| `job_debug_symbol_indexing` | `settings.reader.timeout_seconds` | execution | Finite number 1..1800 seconds, including fractions |
| `job_dossier_publication` | `settings.render_timeout_seconds` | execution | 1..600 seconds |
| `job_build_environment_analysis` | `settings.deadline_seconds` | coverage | 1..30 seconds; no increase of the parser maximum |

The existing `job_openvex_export.settings.timeout_seconds` declaration remains
unchanged. These declarations do not enable disabled jobs or change readiness
policy: model connectivity still executes for every graph dispatch.

## Historical and effective settings

The root `data/configuration/` snapshot keeps its original bytes and raw hash.
An admitted change creates a full immutable revision under
`data/configuration/revisions/<resolved-sha256>/`. Its manifest records the
original hash and each exact `job_id`, relative `path`, `category`, `before`
and `after` value. A new attempt pins that revision's raw hash in its claim.
Its `unit.job.config` supplies effective settings to the handlers; current-attempt
document readers use `context_configuration(context)`. A retained producer's
configuration must instead be resolved with that producer's pinned hash.

`configuration_snapshot(run_root, expected_sha256)` verifies the selected
document and manifest. Its `artifacts(run_root)` includes the revision and
original references. Do not construct revision paths to bypass verification,
edit old snapshots or replace a retained producer's limits with consumer settings.

Execution changes affect new attempts' transport, rendering, reader, build or
resource waits. Old timeout failures and accepted gaps remain historical facts.
Resource admission still checks host capacity; compatibility does not grant
resources, permissions or a larger parser maximum.

Coverage changes preserve accepted outputs with their old bounds and gaps in
either direction. For example, changing environment `deadline_seconds` from
1 to 30 does not remove an old `internal_environment_deadline` gap or assert
that another script was inspected. Expanded coverage requires an explicit
whole-producer rerun and downstream reconsideration using the existing
[recovery workflow](recovery-repair.md). A new sanitizer attempt likewise builds
every planned unit in its own attempt directories; it does not salvage cells
from a failed attempt.

The compatibility comparator is not a settings validator. It checks exact
differences and each declaration's numeric value kind; job parsers and input validators still
reject invalid values before execution. A compatible diff or repair preview
alone is not proof of valid settings, a successful execution or complete coverage.
Tuning is not permission to bypass runtime admission, reload or restart.

## Additional reviewed tuning

All following paths are relative to `jobs.<job_id>` unless called global.

| Job | Exact paths | Category |
| --- | --- | --- |
| Clang static analysis, C++ symbol index, CPG analysis, code-graph index | `settings.workers` | execution; effective pool size |
| Tree-sitter AST | `settings.workers` | coverage; also scales generated-source caps |
| CodeQL analysis | `settings.concurrency`, `settings.threads`, `settings.ram_mb`, `settings.inventory_timeout_seconds` | execution |
| CodeQL analysis | `settings.export_queries.compile_threads`, `settings.export_queries.compile_ram_mb`, `settings.export_queries.compile_timeout_seconds` | execution |
| CodeQL analysis | `settings.database_timeout_seconds`, `settings.query_timeout_seconds`, `settings.export_queries.timeout_seconds` | coverage |
| Project build | `settings.command_timeout_seconds`, `settings.image_build_timeout_seconds` | execution |
| Language build | `settings.command_timeout_seconds` | execution |
| Review prioritization | `settings.syntax_metrics_reservation.io_slots` | execution; integer zero allowed |
| Threat model generation | `settings.reservation.io_slots` | execution; integer zero allowed |
| Global runtime | `runtime.operation_progress_interval_seconds`, `runtime.operation_sample_interval_seconds` | execution; finite nonnegative seconds, including fractions and zero |
| Global Dagster | `orchestration.dagster.max_concurrent`, `orchestration.dagster.pools.<name>` | execution; positive integers for the exact ten existing pool names declared in code |

CodeQL, Tree-sitter and graph outputs/checkpoints are attempt-isolated. New attempts
compute the whole selected job without consulting older computation checkpoints.
Build-iteration transactions inherit the admitted revision and reconstruct it from
immutable configuration layers with exact hash verification. Existing parser limits
and host admission apply without enlargement. See the
[architecture contract](../architecture/runtime-interchange.md#operational-configuration-compatibility-and-attempt-ownership).

## Unsupported boundaries

There are no wildcard/table exemptions. Strings, sequences, booleans, review-policy
resource budgets, unreviewed global fields, missing/unknown paths and mixed material
changes remain refused. Profile/overlay metadata changes remain material even if a
leaf in the layer is operational. Edit an admitted exact leaf without changing layer
selection; this mechanism does not hide changed layer hashes.

Model/provider/reasoning, source/rules/schema identities, authority, signing, input
selection and scoring remain material. `job_change_context_analysis.settings.review.fast_review_seconds`
is scoring, not an execution wait. CodeQL step/task workers must remain 1.

Implementation and targeted regression cases were updated without executing regression
suites, per the owner request. Remaining validation is tracked by T-5273; no test-pass
or live-run claim is made.
