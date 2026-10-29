# End-of-review telemetry report (LaTeX/PDF)

The telemetry report is **one PDF per review run**: an end-of-review rollup of the run's telemetry,
runtimes and metrics. The first pages describe the run as a whole; every job follows as supporting
detail. It is produced by `src/appsec_review/reporting/telemetry/` (document model) and
`src/appsec_review/reporting/telemetry_render.py` (`render_telemetry_report`), rendered by the same
pinned `tool-report-latex` image and template as the [report renderer](report-rendering.md), and
configured by `[reporting.telemetry_report]` in [`appsec-review.toml`](../../appsec-review.toml).

It is not the security report. For findings see [final publication](final-report.md) and the
[review report renderer](report-rendering.md); for the underlying events and summary see
[telemetry architecture](../architecture/telemetry.md) and [metrics operations](metrics.md).

## Inputs

The report reads only two run files, both read-only:

- `runs/<id>/data/logs/pipeline.jsonl` — the authoritative event log. Each record is validated; a
  torn final record is ignored and named.
- `runs/<id>/data/telemetry/summary.json` — the `appsec-review/run-metrics/5` summary, used when
  its `schema` and `run_id` match the run. Otherwise, if events were read, the summary is
  recomputed in memory with `aggregate_run_metrics` and is **never written back**.

Anything that cannot be read becomes a named gap (see [statuses and gaps](#statuses-and-named-gaps)).

## Structure

Title "Review run telemetry", the run id and a status badge from the last run/graph terminal event
(`SUCCEEDED`, `COMPLETED_WITH_GAPS`, `FAILED`, `CANCELLED`, `TIMED_OUT`, or `UNKNOWN`). The header
hash is labelled *metrics summary sha256* (`unavailable` when the summary was recomputed or absent).

**Part I — Run overview** (the main pages):

- **Cover and status** — key figures: completion, wall time, jobs, model calls, tokens (in + out),
  tool calls, finding transitions and named gaps, plus one line of attempt counts (succeeded,
  completed with gaps, failed, cancelled, still running). If some model calls recorded no usage the
  token total is marked as a lower bound.
- **Run timeline** — one lane per job attempt (up to 24) on a 0-to-wall-time axis from the run's
  first event, coloured by terminal status; running attempts extend to the last event.
- **Where the time went** — a bar chart of wall span per job (up to 16, from the summary's
  `job_family_wall_span_ms`, else from event-log spans); the critical-path candidate and its share
  of wall time; wall versus summed task time; queue delays; the slowest operations by p95.
- **Run-wide usage** — model usage by model and role, tool calls by tool, project image builds and
  finding-lifecycle transitions. A call counts as failed unless its `terminal_status` (or, for a
  tool, its `disposition`) is `SUCCEEDED`, `COMPLETED` or `ACCEPTED`.
- **Data quality** — summary source (`summary.json`, `recomputed` or `unavailable`), lifecycle
  accounting, event-log presence, torn tail, named gaps, lifecycle gaps and genuinely running work.

**Part II — Job details** (new page): per job in timeline order (first 40 jobs; the rest are
counted), each attempt's status, wall time, queue delay, event count, model calls, tokens, tool calls
and gap count; an
attempt box (id, start/end, event count); steps and tasks; model calls (role, model, duration,
tokens, cache, status, error class); tool invocations; project image builds and finding transitions
when present; and job gaps (non-terminal or failed attempts, matching lifecycle gaps and still
running work). Tables are bounded; a cut list says how many rows were omitted and their hash.

**Appendix — Provenance**: where every number came from (summary source and hash, event-log hash
and count, run start/end, renderer `appsec-review-telemetry-report/1`) and a short reading guide.

## When it is produced

The report is a best-effort completion hook that runs after the final `write_run_metrics` on every
terminal path — **including failed and cancelled runs**:

- Dagster: the completion op, and Dagster error and cancellation handling (after the receipt lock
  is released).
- Application orchestrator (`GraphRunner`): after `RUN_COMPLETED` or `GRAPH_FAILED` is written and
  the resume lock is released, the graph writes the final run metrics and then renders the report.
  The per-job metric refreshes in `JobRunner` do not trigger it.

The hook never raises, never changes the run's completion status or the error a failed run
re-raises, and never appends to `pipeline.jsonl`. A rendering problem is logged once and recorded
only in the report's own receipt. Resuming a run renders it again and replaces the earlier report.

Unit tests never start the report container: an autouse fixture in `tests/conftest.py` replaces the
renderer outside `tests/integration`, `tests/live` and `test_live_*` modules.

## Outputs and receipt

Everything is written under `runs/<id>/data/telemetry/report/`:

| File | Present when |
| --- | --- |
| `telemetry-report.tex` | the LaTeX was within `max_tex_bytes` |
| `telemetry-report.pdf` | status `rendered` |
| `report.log`, `report.pdfinfo.txt` | the renderer left them (bounded copies) |
| `receipt.json` | always, unless disabled |

The directory is assembled in a fresh sibling staging directory and swapped in by rename, so a
re-render replaces the whole directory and never mixes old and new files.

`receipt.json` is canonical JSON with schema `appsec-review/telemetry-report-receipt/1`:
`run_id`, `status`, `summary_source`, `summary_sha256`, `events_sha256`, `tex_sha256`, `pdf_sha256`,
`files`, `template` (template identity), `tool` (`id`, `image_tag`, `image_id`, and `version` and
`manifest_sha256` once the catalog was loaded), `renderer`, `source_date_epoch`, `settings_sha256`,
`execution` (container `terminal_status`, `exit_code`, `timed_out`, `oom_killed`,
`file_size_limit_reached`, `image_id`, or a redacted `error`; `null` when no PDF was attempted),
`named_gaps`, and `policy` (`network: none`, no shell escape, read-only input and template,
`run_evidence: read_only`).

## Statuses and named gaps

| Status | Meaning |
| --- | --- |
| `rendered` | LaTeX and a valid PDF were written. |
| `tex_only` | `render_pdf = false`; LaTeX only, gap `telemetry_report_pdf_disabled_by_policy`. |
| `failed` | No PDF (see the gap); the LaTeX is kept unless it was too large. |
| `disabled` | `enabled = false`: nothing is read or written, the receipt is returned but not persisted (gap `telemetry_report_disabled_by_policy`), and an earlier report directory is left as it was. |

Input gaps: `pipeline_event_log_missing`, `pipeline_event_log_unreadable`,
`pipeline_event_log_torn_tail_ignored`, `metrics_summary_missing`, `metrics_summary_unreadable`,
`metrics_summary_schema_mismatch`, `metrics_summary_recompute_failed`.

Render gaps: `telemetry_report_renderer_unavailable`, `telemetry_report_render_timeout`,
`telemetry_report_render_failed`, `telemetry_report_pdf_invalid`, `telemetry_report_tex_too_large`,
`telemetry_report_pdf_disabled_by_policy`, `telemetry_report_disabled_by_policy`.

## Configuration

```toml
[reporting.telemetry_report]
enabled = true          # false: no-op, status "disabled"
render_pdf = true       # false: LaTeX only, status "tex_only"
image_tag = "appsec-review/tool-report-latex:1.0.0"
image_id = "sha256:1dd77c969bba00168bc3128e5ee8290328dd06c09ecd4d845618c3c6336530e4"
timeout_seconds = 600   # 1..600
max_tex_bytes = 8388608 # 1..67108864
max_pdf_bytes = 16777216 # 1..67108864; also the renderer's file-size limit
```

The image pin is the same as the dossier job's. Unknown keys, non-boolean switches, out-of-range
integers, an `image_id` that is not `sha256:<64 hex>` and an empty tag fail configuration loading.
The resolved section is part of the run's frozen configuration; `settings_sha256` in the receipt
identifies it.

## Re-rendering a finished run

```text
python -m appsec_review.reporting telemetry --run <run-id|run-dir> [--runs-dir runs]
    [--format tex|pdf] [--out <dir>] [--config <appsec-review.toml>]
scripts/render-report.sh --kind telemetry --run <run-id> [--format pdf|tex]
scripts\render-report.ps1 -Kind telemetry -Run <run-id> [-Format pdf|tex]
```

`--kind` defaults to `review`, so existing script calls are unchanged. `--format` defaults to `tex`
when `--out` is given (written without Docker) and to `pdf` otherwise; `pdf` writes the receipted
report under `runs/<id>/data/telemetry/report/` and, with `--out`, also copies the files there.
Settings come from `--config`, else the run's `data/configuration/resolved.json`, else the defaults.
The exit code is 0 when a report was produced (`rendered` or `tex_only`), 1 when it was not
(`failed` or `disabled`) and 2 for a usage or input error. Re-rendering replaces the report
directory atomically and reads the run evidence read-only.

## Determinism

No clock, locale, network or randomness enters the document. `SOURCE_DATE_EPOCH` is the run's end:
the last run/graph terminal event, else the last event, else 0. It is passed to the image (which
sets `FORCE_SOURCE_DATE=1`), so the same inputs give byte-identical `telemetry-report.tex` and a
fixed PDF creation date. Ordering is by start offset, then job and attempt id.

## Trust boundary

- Telemetry is **observational process data, not security evidence**. Nothing in this report
  supports or refutes a finding.
- `unavailable` (shortened to `n/a` in narrow token columns) means the value was not recorded or
  could not be read; it is never zero work or a clean run. Missing coverage remains a named gap.
- The report is **read-only toward run evidence**: it never writes `pipeline.jsonl` or
  `summary.json`, and writes only under `data/telemetry/report/`. Run-derived strings (job, tool,
  model and operation names, error classes) are cleaned, bounded and escaped; the container runs
  with no network and no shell escape, with read-only `/input` and `/template` mounts.

## Troubleshooting

Start with `receipt.json` (`status`, `named_gaps`, `execution`) and then `report.log` (the XeTeX
log) in the report directory.

- `telemetry_report_renderer_unavailable` — the image is absent or its local identity does not match
  `image_id` (pin mismatch), or the catalog failed to load; `execution.error` holds a redacted
  reason. Build the image or fix the pin as in [image pin verification](image-pin-verification.md)
  and [report rendering](report-rendering.md#image-and-template), then re-render.
- `telemetry_report_render_timeout` — the container exceeded `timeout_seconds`; check `report.log`
  and the job and lane counts, then re-render (raise the timeout only within its bound).
- `telemetry_report_render_failed` — non-zero exit, OOM, file-size limit or no PDF; read
  `report.log` for the LaTeX error.
- `telemetry_report_tex_too_large` — the LaTeX exceeded `max_tex_bytes`; no `.tex` is kept.
- `telemetry_report_pdf_invalid` — the output was not a complete PDF or exceeded `max_pdf_bytes`.

A failed report never fails or reopens the review; re-render it once the cause is fixed.
