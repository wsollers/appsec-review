# Source history analysis operations

`job_source_history_analysis` runs after the accepted target catalog and before
`job_target_analysis_plan`, in both the direct review graph and Dagster's `wave1_review`. It reads
the eligible local Git sources discovered for the target and can enrich them from GitHub. It then:

- scores files and functions with the 0–100 Security Instability Index (SII);
- assigns review tiers; and
- publishes a bounded hotspot index.

Its output only orders review attention; it is never vulnerability evidence. Missing history or
coverage is an explicit skip or a named gap, never a clean result. The design, every metric's
definition, and the index schema are in
[`../architecture/source-history-analysis.md`](../architecture/source-history-analysis.md).

## Normal launch procedure

For an acquired system, configure its components once under `target_acquisition.systems` and
launch the review at the composed root:

```bash
appsec-review start --system storefront
```

Acquisition materializes `targets/storefront/<component>/`. History uses the accepted acquisition
manifest to resolve each component's repository and pinned revision; the composed root does not
need its own `.git`. Git and review-export checkouts are processed independently, so an unavailable
source does not discard another component's usable history. Perforce acquisition is supported,
but Perforce **history analysis** is not: it remains an explicit coverage gap.

For an existing checkout, use the normal target launch:

```bash
appsec-review start --target targets/my-app
```

Direct-target discovery checks bounded repository locations rather than requiring an acquisition
manifest. Neither launch needs a second repository-wiring option. Repeated `--system` and
`--component` options on `acquire-target` select what to acquire, not which history consumers to
connect. See [target acquisition](target-acquisition.md) for those selectors.

## Prerequisites and revision binding

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

Each eligible Git source must retain usable local Git metadata. Direct-target discovery checks
the target root, accepted catalog component roots, and bounded first-level locations; it does not
recursively search the target during inference. A `.git` file must resolve inside that source's
root; linked worktrees and unsupported repository formats remain named gaps.
Discovery is bounded to 4,096 catalog roots/first-level entries and 256 actual sources; reaching a
bound leaves explicit coverage gaps rather than silently declaring the remainder covered.

For an acquired component, history follows the first-parent chain ending at its **pinned acquired
revision**, not a different local `main` tip. For a direct checkout, it uses `main`, else `master`,
else `HEAD`. Binding compares the reviewed bytes with that source's selected revision:

- files that differ from it are reported as `working_tree_divergent`, and get no line history,
  symbols, or complexity; and
- files missing from it are reported as `untracked_path`.

## Configuration

All settings live under `[jobs.job_source_history_analysis.settings]` in `appsec-review.toml`.
Unknown keys and out-of-range values fail validation before the job runs.

| Setting | Default | Meaning |
|---|---|---|
| `history_window_months` (M) | `6` | Window length in calendar months (1–120), evaluated separately per source. It ends at the selected snapshot commit's committer time in UTC, not at wall-clock time. A start day that does not exist in its month clamps to the month's last day, so 31 August minus 6 months is 29 February in a leap year and 28 February otherwise. |
| `hotspot_count` (N) | `10` | Each source's hotspot index holds the top N ranked files and the top N ranked symbols (1–100). |
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
| `recency_half_life_days` | `90` | Half-life of the exponential decay behind `recency_weighted_churn` (1–3650). |
| `minor_author_share` | `0.05` | Authors below this share of a file's in-window commits count as minor authors (exclusive 0–1). |
| `young_line_days` | `30` | Blamed lines newer than this many days before the snapshot count toward `young_line_share` (1–3650). |
| `co_change_top_k`, `co_change_min_support` | `10`, `3` | Co-change partners kept per file (1–100), and the shared changes needed to report a pair (1–10000). |
| `fix_labels`, `security_labels` | `bug`, `fix`, `regression`; `security`, `vulnerability` | GitHub pull-request labels, matched case-insensitively, that mark a change as a fix or security fix (basis `github_label`); without a label match, commit-message heuristics apply. Each entry is 1–64 characters. |
| `[...settings.git] enabled` | `true` | Set to `false` to skip the lane by policy. |
| `[...settings.github] enabled` | `"auto"` | Discover eligible GitHub identities automatically. `true` also permits discovery; explicit `false` denies enrichment. |
| `[...settings.github] repository` | empty | Optional `owner/name` override for a single source, not a required mapping for every acquired component. |
| `[...settings.github] api_base`, `max_requests`, `timeout_seconds` | `https://api.github.com`, `2000`, `30` | GitHub enrichment endpoint (an `https` URL without query or fragment), request budget (1–100000), and per-request timeout in seconds (1–300). |
| `[...settings.github] per_page`, `max_pages`, `max_records` | `100`, `50`, `5000` | Bounded pagination: records per page, pages per collection, and records per collection. Reaching a bound leaves incomplete coverage. |

To change N, M, or any other setting, edit the TOML and start a new run. Existing runs are bound to
their resolved configuration under `data/configuration/`; resuming with different settings is
refused. `--force-from` reruns work under the same configuration, not with edited settings:

```powershell
appsec-review resume --run-id <run-id> --target <target> --force-from job_source_history_analysis
```

The job and everything below it rerun. Use `--system <id>` instead of `--target <target>` for an
acquired-system run.

The automatic GitHub default does not rewrite historical configurations. An existing run whose
frozen setting is `github.enabled = false` still denies enrichment, even when forced to rerun.
Start a new run with the updated central settings to adopt `"auto"`; do not edit run-owned
configuration or accepted pointers.

### GitHub identity, credentials, and network access

The default `github.enabled = "auto"` discovers repository identity from an approved acquisition
URL or the bounded `origin` URL in local Git metadata. With `api_base = "https://api.github.com"`,
the recognized repository host is `github.com`; with an enterprise API base, it is that configured
endpoint's host. Target metadata cannot supply a new API endpoint. Recognized forms include
`https://github.com/owner/repo.git`, `ssh://git@github.com/owner/repo.git`, and
`git@github.com:owner/repo.git` (the `.git` suffix is optional). Explicit ports, passwords, query
strings, fragments, and unsupported URL forms are not used for automatic identity resolution.
An unresolved or unsupported provider identity records `github_repository_unavailable`, not
permission to query an arbitrary host. Local Git history remains usable for non-GitHub sources.
The singular `github.repository` setting remains an optional override only when exactly one
source is discovered; it is not applied across a composed system's repositories.

Export the token named by `github.token_env` (default `GITHUB_TOKEN`) in the environment of the
process running the job, with read access to the relevant repositories and pull requests.
Without that credential, enrichment records `github_credentials_missing` and makes no network
request; local Git history can still be analyzed. Explicit `github.enabled = false` denies
enrichment even when a source and token exist.

In the Dagster deployment, jobs run in the `code-location` container, which takes `GITHUB_TOKEN`
from the shell that creates it. Export the token for the stack command only; never write it to
`deploy/dagster/.env` or any other file. From a Linux or WSL shell signed in with `gh`:

```bash
GITHUB_TOKEN="$(gh auth token)" scripts/stack-restart.sh --code-location-only
```

From PowerShell for a WSL stack, `WSLENV` carries the variable into the distribution:

```powershell
$env:GITHUB_TOKEN = gh auth token; $env:WSLENV = "GITHUB_TOKEN/u:$env:WSLENV"
.\scripts\stack-restart.ps1 -Wsl -CodeLocationOnly
Remove-Item Env:GITHUB_TOKEN
```

A native Windows stack omits `WSLENV` and `-Wsl`. A fine-grained personal access token with
read-only *Contents*, *Metadata*, and *Pull requests* access to the target repositories can stand
in for `gh auth token`. The value is fixed when Compose creates the container: a later
`stack-start`, `stack-restart`, or `stack-rebuild` run without the variable recreates the
`code-location` without it, and subsequent runs record `github_credentials_missing`. Anyone who
can run `docker inspect` on the host can read it. Only the application process uses it; model
workers (Claude CLI and Copilot SDK) and tool containers never receive it.

Discovery does not authorize credentialed access by itself. Requests use the configured API
endpoint and existing request, pagination, and timeout bounds; redirects are refused. The
token is never written to argv, logs, artifacts, or retrieval shards. Enrichment runs in the
application process, not in the network-disabled Git container. Git history does not execute
target hooks, credential helpers, configuration includes, or target-defined commands. Without
usable review enrichment, review-derived metrics are unavailable, not zero.

Request and pagination budgets apply separately to each source; the aggregate number of requests
can therefore exceed one source's `max_requests`.

Acquired review-export components already carry hash-pinned review records. Change-context uses
those records automatically under its default review source, without a second export-path/hash
configuration. This is separate from live GitHub access. Explicit `review.source = "none"` still
denies review signals, and `review.source = "export"` remains a single-source operator override; see
[change-context operations](change-context-analysis.md#review-records).

## Retrieving hotspots

Consumers, including inference, must read the bounded index. They must not rescan Git or the target
tree.

- **In process:**
  `appsec_review.jobs.job_source_history_analysis.load_accepted_hotspots(run_root)` returns the
  hash-verified `hotspots.json`. Each source contributes at most 2N entries: files by rank, then
  symbols by rank. A multi-source result is a collection of source-local top entries, not one
  global top-N ranking.
- **Through retrieval (MCP or `RetrievalCore`):** in the `history` index, use:
  - `find(kind="hotspot", indexes=["history"])` to list hotspots (follow pagination);
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

For composed targets, paths remain relative to the composed root, for example
`service/src/auth.py`, while the source-relative path is `src/auth.py`. Source-scoped records retain
`source_id`, repository/acquisition identity, the selected revision, and that path mapping.
Change and review identities are source-scoped too: the same path or commit id in two repositories
does not identify the same evidence. Follow the source's retained artifacts and coverage rather
than treating one component's success as coverage of the entire system.
When direct discovery finds nested repositories, each file belongs to the most specific discovered
source root, rather than being attributed to both the parent and nested repository.

## Interpreting tiers, scores, and gaps

- **Tiers.** Tier 1 is the top 5 % of the ranked population, rounded up, so every non-empty
  population has at least one Tier 1 unit. Tier 2 is the next 15 %, also rounded up, and can be
  empty for small populations. Tier 3 is the remainder.
  - Review Tier 1 hotspots first and give them deeper attention.
  - Tier 3 is not "safe": the tiers only order attention.
  - Files and symbols are separate populations, each with its own tiers.
- **Scores** are relative to one population, window, and run. Do not compare scores across runs or
  targets, or across independently ranked sources in a composed target.
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

Read coverage per source before interpreting the aggregate result. Common discovery and
integration reasons include:

| Reason | Operator interpretation |
|---|---|
| `history_backend_unsupported:perforce` | acquisition succeeded, but this history backend is not implemented |
| `acquisition_source_unavailable:<type>` | a pinned component record is missing, unreadable, or does not match the accepted acquisition |
| `acquisition_revision_invalid`, `acquisition_revision_mismatch` | the component cannot be bound to its approved revision; it is not silently replaced by local `main` or a remote |
| `history_metadata_discovery_bound_reached`, `history_source_count_bound_reached` | direct discovery exceeded a bound; unexamined sources are not covered |
| `github_repository_unavailable`, `github_credentials_missing` | live review enrichment is unavailable; local history may still be usable |
| `acquired_review_records_unavailable:<type>` | acquired review metadata could not be verified and retained |
| `source_failed:<unit>:<type>` | a source-specific execution failed; inspect that source's receipts and gaps |

Aggregate gaps are source-qualified. Successful peer sources still publish their available
results. Accepted-artifact integrity or publication failures still fail closed rather than
publishing an apparently complete aggregate.

| Coverage row | `complete` | `partial` | `unavailable` |
|---|---|---|---|
| `git-history` | history read with no history gap | some history gap (shallow, divergent, truncated, blame bound, …) | no usable Git source; the gap names why |
| `github-enrichment` | enrichment succeeded | an enrichment artifact exists but requests failed or a bound was reached | no enrichment artifact: disabled, no eligible identity/history, or missing credentials |
| `line-history` | every ranked exact file within bounds has line regions | some files lack regions | no history |
| `symbol-spans` | every selected file parsed cleanly | unsupported languages, bounds, parse errors, or Tree-sitter failures | no history |
| `fix-on-fix` | every candidate fix pair was decided | some pairs are undetermined | no history |
| `history-hotspots` | the index was built with no gap | built, but some gap affects entries | no history |
| `pull-request-timing`, `deployment-timing` | — | — | always |

The job's terminal status is `PARTIAL` whenever any named gap exists.

### Bounded symbol parsing

Source-history symbol extraction invokes the pinned Tree-sitter image sequentially, once per
selected file. Each request retains the configured per-file byte and node bounds; its scope node
bound equals `symbols.max_nodes_per_file`, rather than multiplying that bound by the number of
files in a language. All selected files are still processed, grouped by language in deterministic
order. The job validates and extracts each output before starting the next invocation, retaining
only the extracted symbols and statuses instead of accumulating raw syntax trees.

Requests, parser outputs, and execution receipts are retained separately under the symbol task's
`scratch/tree-sitter/<language>/<sha256-of-target-relative-path>/` directory. Identical basenames
in different directories have distinct scratch identities. Truncation, syntax errors, and missing
coverage retain their named gaps; per-file batching does not increase resource limits or silently
drop files. When stop-on-first-error is active, an unexpected parser failure stops admission before
any subsequent file is launched.

### Tree-sitter invocation metrics

Both source-history parsing and ordinary AST parsing publish invocation-linked telemetry.
Each actual execution has a distinct invocation ID, job/unit/attempt and scope identities,
requested paths/hashes, configured limits, timestamps, duration, and execution receipt link.
Retained receipts live under `data/telemetry/tree-sitter/<invocation-id>/`.

A hash-pinned, read-only-mounted stdlib supervisor runs in the existing pinned parser image,
under the same resource limits. It forwards termination to the parser and retains cgroup-v2
CPU time, memory peak, I/O, OOM events, and local cgroup limits before the container exits.
Measurements include supervisor/container overhead, not just parser computation. A missing
counter or a whole-container kill can prevent final capture; those values are explicitly
unavailable, never measured zeros. Configured limits are not measurements. The container's
private cgroup namespace does not expose ancestor limits: `local_limits` must not be interpreted
as the effective hierarchical budget. For example, an ancestor's zero swap limit still forbids
swap when the child-local limit is nonzero. Host-side enforcement verification must retain
ancestor evidence separately. Failed and canceled
invocations retain their available evidence before cleanup; no historical receipt is rewritten.

The existing run-metrics projection exposes one `tree_sitter` section in
`data/telemetry/summary.json`, including both callers and job/attempt breakdowns. It deduplicates
invocation identities, keeps retries as distinct executions, and reports shard/task reuse
separately. Summed invocation duration is distinct from the elapsed window, covered wall time,
and maximum observed concurrency. CPU and I/O totals carry measured/unavailable counts and
completeness. The memory statistic is the **maximum individual container peak**, not a sum of
peaks or a measurement of concurrent aggregate memory. Validated output receipts count files
accounted for, files parsed, emitted nodes, and truncations; absent output accounting remains
unknown. Missing completion, conflicting receipts, unavailable counters, and cancellation are
visible through incomplete-accounting fields.

## Outputs and recovery

- The accepted `source-history.json` holds:
  - source decisions and binding status;
  - the window and revision semantics;
  - the SII file ranking and component priorities;
  - the hotspot summary and the `hotspots.json` identity; and
  - gaps and observations.
- For composed/multi-source output, `sources.repositories[]` lists source descriptors, decisions,
  and hash-pinned source-document references; `ranking.scope = "per-source"`. Read those referenced
  documents for each source's binding, window, revision semantics, and detailed ranking rather than
  assuming one global window or snapshot commit. The aggregate `hotspots.json` retains schema
  `appsec-review/history-hotspots/1`, with `selection = "top entries per source"` and
  `sources[].artifact` references to the source-local hotspot indexes.
- Source-scoped `history` retrieval shards hold file, component, and symbol `history_signal`
  entities, `change` entities, `hotspot` entities, and their coverage rows. All accepted source
  shards are composed into the run's manifest.
- The analysis plan's `history_priority` section preserves the source identity and per-source
  ranks of accepted components and files.

Resume planning and source-history handoff publication re-probe the discovered sources, including
nested accepted catalog roots. A changed selected commit, source metadata/configuration, object
format, or shallow boundary can invalidate history even if the tree bytes did not. The input identity now uses
`appsec-review/source-history-identity/2`. Each history shard fingerprint binds the ranked signals,
hotspots, normalized changes, GitHub enrichment artifact, and exact retained Git log/message identities.
It also binds the actual Git image, configured resource bounds, and bounded stream-parser version,
while retaining the line-history, symbol, complexity, and SII identities. Identical rankings do not
permit reuse when their retained provenance changes.
As with other producers, deployment operators must bump the declared source-history component
release when deploying changed software; the runtime does not hash installed implementation files.

A rerun invalidates the plan and everything below it. These gaps are marked
retriable, so a later resume retries them:

- GitHub rate limiting;
- failed Git executions; and
- an unavailable or failed Tree-sitter execution.

Deterministic gaps persist until the target or the configuration changes. Examples are a shallow
clone, divergent paths, unsupported languages, and unsupported repository formats. Do not edit
accepted pointers or delete shards to force recovery; use
`--force-from job_source_history_analysis`.
