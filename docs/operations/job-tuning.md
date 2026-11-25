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

Each path below is relative to `jobs.<job_id>`. Every supported old and new
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
| `job_debug_symbol_indexing` | `settings.reader.timeout_seconds` | execution | Integer 1..1800 seconds; fractional parser values are not operationally compatible |
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
differences and positive-integer types; job parsers and input validators still
reject invalid values before execution. A compatible diff or repair preview
alone is not proof of valid settings, a successful execution or complete coverage.
Tuning is not permission to bypass a source freeze, reload or restart.

## Limits of this declaration set

There is no global-setting exemption, wildcard exemption or support here for
float, string, boolean, sequence or zero-valued changes. Reservation `io_slots`
remains undeclared even though its parser accepts zero. Unknown and missing
paths, as well as mixed operational/material edits, are refused.

Model/provider/reasoning, source/rules/schema identities, authority, signing,
input selection and scoring remain material. In particular,
`job_change_context_analysis.settings.review.fast_review_seconds` changes
scoring, not an execution wait. CodeQL step/task workers must remain 1.

CodeQL, Tree-sitter, the other analyzer/index pools, project-build and
language-build tuning are not included in this set. Their execution,
retained-producer provenance and existing internal checkpoint paths need a
whole-job-safe ownership handoff before further declarations. Tree-sitter
`settings.workers` multiplies generated-source file/byte caps and is a coverage
control, not just pool capacity. CodeQL database/query/export analysis deadlines
are coverage controls, not execution-only timeouts.
