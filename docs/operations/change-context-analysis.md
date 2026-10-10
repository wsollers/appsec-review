# Change-context analysis operations

`job_change_context_analysis` turns accepted source history plus optional review, deployment, and
organization data into review-priority signals for files, functions, and components. Its output
orders review work; it is never a vulnerability finding. Missing data is a named gap, never a clean
result. Design: [`../architecture/change-context-analysis.md`](../architecture/change-context-analysis.md).

## Prerequisites

- An accepted `job_source_history_analysis` in the same run (the job fails without its handoff). If
  history was skipped, for example because the target has no `.git`, this job publishes
  `SKIPPED_NA` with every coverage row `unavailable`.
- The `tool-git` image (`python containers/build.py build tool-git`), used for bounded blame and
  fix-on-fix diffs. If it is unavailable, the affected rows are `*_execution_failed` gaps and the job
  is retried on resume.
- For function scope, an accepted `job_tree_sitter_ast` (Dagster `wave1_review`). The direct CLI
  graph runs this job last and has no Tree-sitter job, so function records are absent there with
  `function_spans_unavailable:tree_sitter_not_accepted`.
- On Windows, Python's `zoneinfo` needs the `tzdata` package for IANA zones. Without it a configured
  zone produces `time_zone_database_unavailable` and off-hours is unavailable.

## Configuration

Everything lives under `[jobs.job_change_context_analysis.settings]` in `appsec-review.toml`.

| Key | Default | Meaning |
|---|---|---|
| `ranking_top_files` / `_functions` / `_components` | 200 / 200 / 100 | bounded number of ranked records indexed and listed per scope |
| `supporting_change_limit` | 20 | linked changes per indexed record |
| `review.source` | `github_enrichment` | `github_enrichment`, `export`, or `none` |
| `review.export_path`, `review.export_sha256` | empty | review export when `source = "export"` |
| `review.fast_review_seconds` | 300 | fast approval/merge bound |
| `schedule.time_zone` | empty | IANA zone; empty makes off-hours unavailable |
| `schedule.business_hours_start` / `_end` | `08:00` / `18:00` | local business window, `[start, end)` |
| `schedule.weekend_days` | saturday, sunday | always off-hours |
| `deployments.enabled`, `export_path`, `export_sha256` | off | deployment events export |
| `deployments.environments` | `production` | environments whose successful events count |
| `deployments.pre_deployment_window_hours` | 24 | lead time that marks a change as pre-deployment |
| `scope_sprawl.min_unrelated_groups` | 3 | unrelated component groups needed to flag sprawl |
| `scope_sprawl.min_churn_lines` | 400 | churn needed to flag sprawl |
| `scope_sprawl.min_group_entropy` | 0.5 | churn must be spread across groups (0–1) |
| `scope_sprawl.related_component_min_support` | 3 | other co-changes that relate two components |
| `repeated_repairs.window_days`, `min_fix_changes` | 60, 4 | "more than three fixes in any rolling 60 days" |
| `repeated_repairs.fix_on_fix_max_checks` | 100 | fix/path pairs checked for exact same-line fix-on-fix; 0 disables |
| `test_association.enabled` | true | test-to-code churn |
| `test_association.production_extensions`, `test_patterns`, `contract_patterns` | see TOML | explicit path-role rules (`**`-aware globs, `{a,b}` alternatives) |
| `test_association.min_production_churn_lines` | 50 | churn needing associated tests |
| `ownership.dominant_owner_share`, `bus_factor_share` | 0.5, 0.5 | dominant-owner and bus-factor thresholds |
| `ownership.line_attribution_max_files`, `_max_file_bytes` | 50, 1 MiB | blame bound for function attribution |
| `organization.enabled`, `export_path`, `export_sha256` | off | organization membership export |
| `priority_weights` | see TOML | non-negative weights per signal; at least one positive |

### Review records

- **GitHub:** enable `[jobs.job_source_history_analysis.settings.github]` (see
  [`source-history-analysis.md`](source-history-analysis.md)). This job then reuses its accepted
  facts; it never calls GitHub itself. Budget exhaustion or rate limiting in history becomes
  `review_records_partial:<gap>` here.
- **Other hosts or offline runs:** set `review.source = "export"` and supply an
  `appsec-review/review-records/1` file keyed by mainline commit SHA.

### Exports

1. Place each export under the repository (for example `data/change-context/deployments.json`),
   never inside the target.
2. Pin it: `python -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" data/change-context/deployments.json`
   and set `export_sha256`.
3. Enable the source. Re-pin after every change to the file; a stale pin yields
   `*_export_hash_mismatch`, and the metric becomes unavailable rather than using unapproved data.

Organization exports identify people only by `identity_sha256`, the SHA-256 of the lowercased commit
email, for example `python -c "import hashlib;print(hashlib.sha256('dev@example.com'.lower().encode()).hexdigest())"`.
List only people whose status you know; unlisted principals are reported as unavailable, and
inactivity is never treated as departure.

Schemas are in the architecture document.

## Outputs and retrieval

- Accepted `change-context.json`: per-source status and gaps, coverage rows, rules, weights, the
  top-ranked records per scope, pinned export copies, and the index manifest.
- Retrieval shard `history/change-context`. Query with MCP `query_change_context`:

  ```json
  {"name": "query_change_context", "arguments": {"scope": "component", "limit": 10}}
  {"name": "query_change_context", "arguments": {"scope": "file", "signal": "repeated_repair_peak"}}
  {"name": "query_change_context", "arguments": {"scope": "function", "path": "src/auth/session.py"}}
  ```

  Each result carries the metric vector, availability, linked changes, the history hotspot rank, and a
  resolvable location for files and functions. `coverage_gaps` lists every incomplete source; check
  it before reading an absent or low-scoring unit as unremarkable. Use `trace` with
  `DERIVED_FROM` to reach supporting `change` entities, and `find` with kind `review_unit` or
  `deployment_event` for the linked artifacts.

## Recovery

The job reruns when its configuration (including export pins) or any accepted upstream handoff
changes. Failed Git executions are retriable on resume. Deterministic gaps (disabled sources,
unpinned or mismatched exports, no time zone, truncated or shallow lifetime history) persist until
configuration or inputs change. Use `--force-from job_change_context_analysis` in the direct graph
to rebuild only this job; do not edit accepted pointers or delete shards.
