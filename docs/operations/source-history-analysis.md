# Source history analysis operations

`job_source_history_analysis` runs after the accepted target catalog and before
`job_target_analysis_plan` in both the direct review graph and Dagster's `wave1_review`. It reads
the target's local Git history, optionally enriches it from GitHub, and publishes churn-led
priorities. Its output only orders review attention; it is never vulnerability evidence, and missing
history is an explicit skip or gap, never a clean result. Design:
[`../architecture/source-history-analysis.md`](../architecture/source-history-analysis.md).

## Prerequisites

Build the `tool-git` image before running against a Git target:

```powershell
python containers/build.py validate
python containers/build.py build tool-git
```

The image extracts only the `git` binary from the hash-pinned Ubuntu 24.04 `git` package in
`containers/tools/git/assets.lock.json`. If the image is unavailable, the job records
`git_execution_failed` gaps, publishes an `unavailable` coverage shard, and is retried on resume.

The target must be the repository working tree (`.git` at its root, or a `.git` file pointing inside
it). History follows the first-parent chain of `main`, else `master`, else `HEAD`. The tree under
review should be that mainline tip. Files that differ from it are reported as
`working_tree_divergent`, and files missing from it as `untracked_path`.

## Configuration

All settings live under `[jobs.job_source_history_analysis.settings]` in `appsec-review.toml`:

- `window_days`, `max_changes`: the history window, anchored to the mainline commit time.
- `bulk_change_file_threshold`: commits touching more files are kept for churn but excluded from
  ownership and co-change.
- `ranking_weights`: churn-led by default (`churn_lines`, `recency_weighted_churn`,
  `change_count`). Any signal in the design's signal table may be weighted. Unknown names and
  negative weights are rejected.
- `blame_max_files`, `blame_max_file_bytes`: bounds on per-file blame. Files beyond the bound are a
  `blame_bound_reached` gap.
- `[...settings.git] enabled`: set `false` to skip the lane by policy.

GitHub enrichment is off by default. To enable it, set `enabled = true` and
`repository = "owner/name"` under `[...settings.github]`, then export the token named by
`token_env` (default `GITHUB_TOKEN`) in the environment of the process that runs the job. A
read-only token with pull-request read access is enough. The repository identity always comes from
this configuration, never from the target's `remote.*.url`. The token is never written to argv,
logs, artifacts, or retrieval shards. Enrichment runs in the application process (like NVD sync),
not in the network-disabled Git container.

## Outputs and recovery

- The accepted `source-history.json` holds source decisions, binding status, gaps, observations,
  and the top-ranked files and components.
- The `history/git-history` retrieval shard holds file and component `history_signal` entities and
  `change` entities. Query it with `find`, `search`, `trace`, and `coverage`.
- The analysis plan's `history_priority` section lists accepted components and files in churn rank
  order.

Resume reruns the job when the mainline commit, object format, or shallow boundary changes, even if
the tree bytes did not. A rerun invalidates the plan and everything below it. GitHub rate limiting
and failed Git executions are marked retriable, so a later resume retries them. Deterministic gaps,
such as a shallow clone, divergent paths, or unsupported repository formats, persist until the
target itself changes. Do not edit accepted pointers or delete shards to force recovery; use
`--force-from job_source_history_analysis`.
