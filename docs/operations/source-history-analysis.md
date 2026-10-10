# Source history analysis operations

`job_source_history_analysis` runs after the accepted target catalog and before
`job_target_analysis_plan`, in both the direct review graph and Dagster's `wave1_review`. It reads
the target's local Git history and can optionally enrich it from GitHub. It then:

- scores files and functions with the 0–100 Security Instability Index (SII);
- assigns review tiers; and
- publishes a bounded hotspot index.

Its output only orders review attention; it is never vulnerability evidence. Missing history or
coverage is an explicit skip or a named gap, never a clean result. The design, every metric's
definition, and the index schema are in
[`../architecture/source-history-analysis.md`](../architecture/source-history-analysis.md).

## Prerequisites

Build the `tool-git` and `tool-tree-sitter` images before running against a Git target:

```powershell
python containers/build.py validate
python containers/build.py build tool-git
python containers/build.py build tool-tree-sitter
```

`tool-git` extracts only the `git` binary from the hash-pinned Ubuntu 24.04 `git` package in
`containers/tools/git/assets.lock.json`. If it is unavailable, the job records
`git_execution_failed` gaps, publishes an `unavailable` coverage shard, and is retried on resume.

`tool-tree-sitter` is the same pinned parser image that `job_tree_sitter_ast` uses. Without it, the
job still ranks files, but complexity is missing. Symbol hotspots, and `same_function` fix-on-fix
matching, are unavailable. These are reported as `tree_sitter_unavailable` or
`tree_sitter_execution_failed` (retriable) gaps.

The target must be the repository working tree, with `.git` at its root or a `.git` file pointing
inside it. History follows the first-parent chain of `main`, else `master`, else `HEAD`. The tree
under review should be that mainline tip:

- files that differ from it are reported as `working_tree_divergent`, and get no line history,
  symbols, or complexity; and
- files missing from it are reported as `untracked_path`.

## Configuration

All settings live under `[jobs.job_source_history_analysis.settings]` in `appsec-review.toml`.
Unknown keys and out-of-range values fail validation before the job runs.

| Setting | Default | Meaning |
|---|---|---|
| `history_window_months` (M) | `6` | Window length in calendar months (1–120). It ends at the mainline snapshot commit's committer time in UTC, not at wall-clock time. A start day that does not exist in its month clamps to the month's last day, so 31 August minus 6 months is 29 February in a leap year and 28 February otherwise. |
| `hotspot_count` (N) | `10` | The hotspot index holds the top N ranked files and the top N ranked symbols (1–100). |
| `ranking_top_n` | `200` | Length of the SII file ranking copied into the accepted document for the analysis plan. |
| `fix_on_fix.interval_days` | `30` | Maximum gap between two fixes matched as fix-on-fix (14–30). |
| `line_history.max_files`, `line_history.max_file_bytes` | `50`, 1 MiB | Bounds on per-file line-region history, applied to the highest-churn files. |
| `symbols.enabled`, `symbols.max_files`, `symbols.max_file_bytes`, `symbols.max_nodes_per_file` | `true`, `200`, 1 MiB, `200000` | Bounds on the Tree-sitter function spans and complexity. |
| `sii.weights` | churn 0.35, frequency 0.25, entropy 0.15, complexity 0.25 | SII weights. They must name exactly the four metrics, must be non-negative, and must include at least one positive weight. |
| `sii.complexity_metric` | `cyclomatic` | The complexity measure that enters the SII: `cyclomatic` or `cognitive`. Both are always published. |
| `sii.tier_1_share`, `sii.tier_2_share` | `0.05`, `0.15` | Tier sizes, rounded up. |
| `filters.*` | see TOML | Globs that exclude generated, lockfile, fixture, documentation, and vendored paths from ranking; `test` globs for production-to-test churn; `formatting_balance_tolerance`. |
| `max_changes`, `bulk_change_file_threshold` | `20000`, `500` | Walk bound, and the file count above which a change is bulk. Bulk changes are excluded from ranking. |
| `blame_max_files`, `blame_max_file_bytes` | `50`, 1 MiB | Bounds on per-file blame. Files beyond the bound get the `blame_bound_reached` gap. |
| `[...settings.git] enabled` | `true` | Set to `false` to skip the lane by policy. |

To change N or M, edit the TOML and resume the run from the job:

```powershell
appsec-review resume --run-id <run-id> --target <target> --force-from job_source_history_analysis
```

The job and everything below it rerun with the new settings.

GitHub enrichment is off by default. To enable it:

1. Set `enabled = true` and `repository = "owner/name"` under `[...settings.github]`.
2. Export the token named by `token_env` (default `GITHUB_TOKEN`) in the environment of the process
   that runs the job. A read-only token with pull-request read access is enough.

The repository identity always comes from this configuration, never from the target's
`remote.*.url`. The token is never written to argv, logs, artifacts, or retrieval shards.
Enrichment runs in the application process (like NVD sync), not in the network-disabled Git
container. Without enrichment, `review_bypass_count` is reported as an unavailable signal.

## Retrieving hotspots

Consumers, including inference, must read the bounded index. They must not rescan Git or the target
tree.

- **In process:**
  `appsec_review.jobs.job_source_history_analysis.load_accepted_hotspots(run_root)` returns the
  hash-verified `hotspots.json`. Its `entries` hold at most 2N items, in this order: files by rank,
  then symbols by rank.
- **Through retrieval (MCP or `RetrievalCore`):** in the `history` index, use:
  - `find(kind="hotspot", indexes=["history"])` for every hotspot entry;
  - `find(kind="hotspot", name="app/auth.py::check")` for one symbol;
  - `find(kind="hotspot", path="app/auth.py")` for a file's hotspots;
  - `trace` from a hotspot over `DERIVED_FROM` to reach its file or symbol `history_signal`, and
    from there its recent `change` entities; and
  - `coverage(indexes=["history"])` for the coverage rows.

Each entry carries:

- its identity (path, or symbol id and qualified name), `rank`, `tier`, and `score`;
- the full metric vector and the SII inputs (raw, transformed, and normalized values, weights,
  population, and tier bounds);
- the snapshot fingerprint and commit, the file SHA-256 and Git blob id, and a resolvable source
  span; and
- `coverage_gaps`.

## Interpreting tiers, scores, and gaps

- **Tiers.** Tier 1 is the top 5 % of the ranked population, rounded up, so every non-empty
  population has at least one Tier 1 unit. Tier 2 is the next 15 %, also rounded up, and can be
  empty for small populations. Tier 3 is the remainder.
  - Review Tier 1 hotspots first and give them deeper attention.
  - Tier 3 is not "safe": the tiers only order attention.
  - Files and symbols are separate populations, each with its own tiers.
- **Scores** are relative to one population, window, and run. Do not compare scores across runs or
  targets.
  - A score of 0 means the unit is lowest on every metric in this population, not that it is
    stable.
  - A constant metric, listed in `constant_metrics`, contributes nothing to any unit.
- **Missing inputs.** `weight_coverage < 1` means the score used fewer metrics, usually because
  complexity was unavailable. Read the matching `complexity_unavailable:<reason>` gap before
  comparing that unit with fully covered ones.
- **Fix-on-fix.** `fix_on_fix_count = null` with status `unavailable` or `partial` means at least
  one candidate pair of fixes could not be checked. It does not mean "no rework". Each undetermined
  pair names its reason, such as `line_history_bound_reached` or `symbol_language_unsupported`.
- **Exclusions.** Lockfiles, generated code, fixtures, documentation, and vendored code are listed
  with `rank_eligibility = excluded:<category>` and keep their metrics. To rank one of them, narrow
  the matching pattern in TOML.
- **Unavailable signals.** `pull_request_timing` and `deployment_timing` are always `unavailable`
  coverage rows. This lane does not acquire that data and never infers it from commit timestamps.
- **History gaps.** These include `shallow_history`, `history_window_truncated`, and
  `message_stream_misaligned`. Scores still reflect what was observed, but treat every entry as
  incomplete. A shallow clone needs a deeper clone (at least M months) to remove the gap.

### Coverage statuses

| Coverage row | `complete` | `partial` | `unavailable` |
|---|---|---|---|
| `git-history` | history read with no history gap | some history gap (shallow, divergent, truncated, blame bound, …) | no usable Git source; the gap names why |
| `github-enrichment` | enrichment succeeded | some requests failed or the budget ran out | disabled or no history |
| `line-history` | every ranked exact file within bounds has line regions | some files lack regions | no history |
| `symbol-spans` | every selected file parsed cleanly | unsupported languages, bounds, parse errors, or Tree-sitter failures | no history |
| `fix-on-fix` | every candidate fix pair was decided | some pairs are undetermined | no history |
| `history-hotspots` | the index was built with no gap | built, but some gap affects entries | no history |
| `pull-request-timing`, `deployment-timing` | — | — | always |

The job's terminal status is `PARTIAL` whenever any named gap exists.

## Outputs and recovery

- The accepted `source-history.json` holds:
  - source decisions and binding status;
  - the window and revision semantics;
  - the SII file ranking and component priorities;
  - the hotspot summary and the `hotspots.json` identity; and
  - gaps and observations.
- The `history/git-history` retrieval shard holds file, component, and symbol `history_signal`
  entities, `change` entities, `hotspot` entities, and the coverage rows above.
- The analysis plan's `history_priority` section lists accepted components and files in SII rank
  order.

Resume reruns the job when the mainline commit, object format, or shallow boundary changes, even if
the tree bytes did not. A rerun invalidates the plan and everything below it. These gaps are marked
retriable, so a later resume retries them:

- GitHub rate limiting;
- failed Git executions; and
- an unavailable or failed Tree-sitter execution.

Deterministic gaps persist until the target or the configuration changes. Examples are a shallow
clone, divergent paths, unsupported languages, and unsupported repository formats. Do not edit
accepted pointers or delete shards to force recovery; use
`--force-from job_source_history_analysis`.
