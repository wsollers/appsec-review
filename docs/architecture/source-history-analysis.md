# Source history analysis

Status: local Git and optional GitHub enrichment are implemented in
`src/appsec_review/jobs/job_source_history_analysis/`. Perforce is designed below but not built;
see [`../TODO.md`](../TODO.md). Operator guidance is in
[`../operations/source-history-analysis.md`](../operations/source-history-analysis.md).

## Purpose and boundary

`job_source_history_analysis` reads the version-control history behind the reviewed snapshot and
publishes bounded, resolvable *instability signals*. These identify files and components that
changed often or recently, were touched by many authors, went through fix and revert cycles, or
changed together with other files. The ranking is churn-led, and the analysis plan uses it to order
review attention.

The lane is a prioritization producer, not a vulnerability producer:

- A history signal is never a security claim. It may move a component or file earlier in review;
  it cannot create, support, or raise the severity of a finding by itself.
- Low churn is not evidence of stability or safety. Missing, shallow, unreadable, or out-of-window
  history is a named gap or an explicit skip, never a clean result.
- Commit messages, author identities, timestamps, refs, PR metadata, and repository configuration
  are target-controlled data, never instructions.
- The lane never executes target code, hooks, filters, diff drivers, credential helpers, or any
  command named by target-owned configuration.

| Source | Acquisition | Network | Status |
|---|---|---|---|
| Local Git (`.git` inside the target, any host) | fixed read-only argv in `tool-git` | none | implemented, enabled |
| GitHub enrichment | bounded REST reads of PR and review facts for known commits | configured API host | implemented, disabled by default |
| Perforce export bundle | operator-supplied, hash-pinned `p4 -ztag -Mj` export | none | planned |
| Perforce server | read-only `p4` queries in `tool-p4` | configured `P4PORT` only | planned |

GitHub-hosted, GitLab-hosted, and self-hosted Git repositories all use the local Git adapter.
GitHub only adds review-process facts on top of it.

## Decisions

- History follows the first-parent chain of `main`, else `master`, else `HEAD`. A `HEAD` that
  differs from the mainline is recorded as the `head_differs_from_mainline` observation.
- The ranking is churn-led. Its default weights use only `churn_lines`, `recency_weighted_churn`,
  and `change_count`. Every other signal is still published and can be given weight in TOML.
- `job_target_analysis_plan` consumes the ranking. A history change therefore reruns the plan and
  everything below it.
- A runtime input-identity probe lets resume planning detect changes to history alone.
- Scanning history for leaked secrets is out of scope.
- Following submodules is a TODO. For now each gitlink is a `submodule_history_not_followed` gap.

## Placement in the graph

```text
job_review_intake -> job_target_catalog -> job_source_history_analysis -> job_target_analysis_plan -> ...
                                       \-> job_ci_configuration_analysis ---/   (Dagster wave1_review)
```

The direct CLI graph runs the job between the catalog and the plan. In Dagster's `wave1_review` it
is a sibling of CI configuration analysis, and the plan waits for both. The job consumes:

- the accepted intake handoff and its `sha256-bounded-tree-v1` fingerprint; and
- the accepted catalog: inventory paths, sizes, hashes, and component roots.

The inventory excludes `.git`, so the source fingerprint does not cover history. A history-only
change, such as an amended message or a rewritten ancestor with the same tree, needs another check.
`Job.input_identity` is a cheap, deterministic probe that hashes the resolved source decision,
mainline ref, snapshot commit, object format, and shallow boundary. The runner records the probe
value in the claim and handoff. The resume planner re-probes against the graph target, and a
mismatch reruns the job and invalidates everything downstream. The job's publish unit re-probes
before publishing, so a history that changes mid-run fails the attempt instead of being accepted.

## Source resolution and snapshot binding

`resolve_history_source` produces exactly one Git decision, using the shared `SUCCEEDED`,
`SKIPPED_NA`, `SKIPPED_POLICY`, or `GAP` vocabulary. It reads only the following, each with a size
bound:

- `HEAD`, the loose ref or `packed-refs` entry, and `shallow`;
- `objects/info/alternates`; and
- format keys from `config` (`extensions.objectformat`, `extensions.refstorage`, partial-clone
  markers).

Nothing else in the target's configuration is used. The checks are:

- **Location:** a `.git` directory at the target root, or a `.git` file whose `gitdir:` resolves
  inside the target. A gitdir outside the target or a symlinked `.git` is
  `GAP: history_source_outside_target`. No `.git` is `SKIPPED_NA: no_git_metadata`, and
  `settings.git.enabled = false` is `SKIPPED_POLICY`.
- **Unsupported layouts:**
  - linked worktrees (`commondir`);
  - non-`files` ref storage;
  - unknown object formats;
  - partial clones;
  - absolute or escaping alternates; and
  - invalid `shallow` files.

  Each of these is a named `GAP`.
- **Observations:** replace refs, grafts, config includes, and relative in-target alternates are
  recorded and never honoured.

`bind_snapshot` lists the snapshot tree with `ls-tree -r -z` and compares each accepted inventory
file's Git blob id with it. The blob id is computed in application code (SHA-1 or SHA-256) after
re-verifying the catalog's SHA-256 of the bytes.

- Every file matches: binding `exact`.
- Some files differ (edits, CRLF conversion, clean filters, LFS pointers): binding `partial`. The
  run gets the `working_tree_divergent` gap, and those files' locations are marked ambiguous.
- A file is absent from the tree: `untracked_path`.
- No file matches: `history_not_of_snapshot`, and no file signals are published.
- A truncated tree listing: `tree_listing_truncated`.

## Git acquisition hardening

Git runs only in the pinned `tool-git` image. The image contains only the `git` binary extracted
from the hash-pinned Ubuntu 24.04 package. The container runs with no network, non-root, read-only
root and target, dropped capabilities, and bounded memory, PIDs, time, and output. The container
sees three mounts:

- `/target` (read-only);
- `/scratch` (per-execution, writable); and
- `/gitdir` (read-only), an application-written directory holding a minimal `config` with only the
  repository format, a detached `HEAD` at the snapshot commit, and the validated `shallow` file.

Execution is pinned down as follows:

- **Repository state:** `GIT_DIR=/gitdir` and `GIT_OBJECT_DIRECTORY=/target/<gitdir>/objects`. The
  target's config, hooks, `info/`, refs, reflogs, and replace refs are never repository state.
- **Environment:** `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_ATTR_NOSYSTEM=1`,
  `GIT_NO_REPLACE_OBJECTS=1`, `GIT_TERMINAL_PROMPT=0`, `GIT_OPTIONAL_LOCKS=0`, `GIT_PAGER=cat`,
  `XDG_CONFIG_HOME=/dev/null`.
- **Command-scope configuration:** `core.fsmonitor=false`, `core.hooksPath=/dev/null`,
  `core.attributesFile=/dev/null`, `core.pager=cat`, `log.showSignature=false`, and
  `safe.directory=*`.
- **Command flags:** `--no-ext-diff --no-textconv --no-mailmap` where applicable.
- **Commands:** four fixed argv builders: first-parent `log` with `--numstat -z`, first-parent
  message `log`, `ls-tree`, and per-file `blame --porcelain`. No target text is interpolated into
  options; paths follow `--`.

Parsing does not trust delimiters inside target text:

- Commit headers carry only hex ids, integers, and the author email; the email is the last field
  and cannot contain NUL.
- Numstat records are consumed by position, so paths may contain tabs, newlines, or control bytes.
- Message bodies are split at the known next commit id, so a NUL inside a body cannot misalign
  later commits.

The tests run real Git through the executor against a repository whose config names fsmonitor,
pager, textconv, clean and smudge filters, an SSH command, and a credential helper, and that has
executable hooks, `.gitattributes` routing, and a `.mailmap`. They assert that no canary file
appears and that identities are not rewritten.

## GitHub enrichment

GitHub enrichment is disabled by default. When enabled, the repository identity and API base come
only from central configuration, and the token comes from the environment variable named by
`token_env`. The job:

1. confirms that the snapshot commit exists in the configured repository; then
2. looks up the associated pull request for each in-window commit, newest first, until the request
   budget is spent.

For each pull request it retains only derived facts:

- whether the commit was a direct push;
- whether a reviewer other than the author approved it;
- whether the approval covered the merged head;
- whether the author merged it; and
- sanitized label names.

Titles, bodies, comments, and account names are not stored. Rate limiting is a retriable
`github_rate_limited` gap, so resume reruns the job. An exhausted budget, missing pulls, or
permission errors are named gaps. Enrichment runs in the application process over HTTPS, like NVD
sync, not in the network-disabled Git container.

## Signals

All windows are anchored to the snapshot commit's committer time, never to wall-clock time, so the
same inputs give byte-identical outputs. Git timestamps are claimed data. A commit whose time is
later than its first-parent child's is clamped to the child's time, and the count is recorded as a
`timestamp_anomaly` observation.

Commits are walked newest first. Renames are followed backward, so churn on `app/util.py` before a
rename counts toward the current `app/helpers.py`. A commit touching more than
`bulk_change_file_threshold` files is marked `bulk`; it still counts for churn but is excluded from
ownership and co-change. A shallow boundary inside the window is `shallow_history`, and reaching
`max_changes` before the window start is `history_window_truncated`.

| Signal | Unit | Definition |
|---|---|---|
| `change_count` | file, component | in-window first-parent changes touching the unit |
| `churn_lines` | file, component | added + deleted lines (`--numstat`; binary files count 0) |
| `relative_churn` | file | `churn_lines` / current non-blank lines |
| `recency_weighted_churn` | file, component | churn × 0.5^(age / `recency_half_life_days`) |
| `author_count`, `minor_author_count`, `top_author_share` | file (count also component) | non-bulk authors; authors below `minor_author_share`; largest share |
| `fix_change_count`, `security_fix_change_count` | file, component | changes classified as fixes / security fixes |
| `revert_count` | file, component | changes that revert, or are reverted by, another change |
| `retouch_interval_median_days` | file | median gap between successive changes |
| `young_line_share` | file | blamed lines newer than `young_line_days`, for the top `blame_max_files` files by churn |
| `co_change_partners` | file | top-K partners with support ≥ `co_change_min_support`, confidence, cross-component flag |
| `review_bypass_count` | file, component | GitHub only: direct pushes, merges without another reviewer's approval, or stale approvals |

Change classification is deterministic (`appsec-review/history-change-rules/1`), and each label
records its basis:

- `revert`:
  - `exact` when a `This reverts commit <id>` trailer names a walked commit; the target also gets
    `reverted_by`;
  - `heuristic` for a subject-only `Revert "…"` match.
- `security_fix`:
  - `github_label` when a merged PR label matches `security_labels`;
  - `heuristic` for CVE, GHSA, or CWE references or security vocabulary.

  Referenced identifiers are recorded.
- `fix`:
  - `github_label` when a PR label matches `fix_labels`;
  - `heuristic` for conventional `fix:` prefixes or fix vocabulary.

  Every security fix is also a fix.

No model is used. Exact matching of OSV `fixed` commit events is deferred, because the synchronized
OSV index does not yet key advisories by commit id.

### Attention ranking

`history-attention/1` ranks files and components that have in-window history. Each weighted signal
becomes a mid-rank percentile within the target's population. `retouch_interval_median_days` is
inverted, because a shorter interval means less stability. The score is the weighted mean of the
available percentiles, and ties break on path or component id. The full feature vector, percentiles,
weights, and ranking identity are published with every rank, and consumers never receive a bare
score. A file with no in-window history is unranked, not ranked last.

## Outputs

These are written per attempt, under the unit directories:

- `binding.json`: binding status, divergent, untracked, and submodule paths.
- `protected/log.bin`, `protected/messages.bin`: raw Git output, kept in the attempt and never
  indexed.
- `changes.json`: normalized changes with ids, times, author ordinals, per-path numstat, renames,
  and the bulk flag.
- `classification.json`, `github-enrichment.json`, `co-change.json`, and `signals.json`: per-file
  and per-component signals, ranks, and percentiles.
- `source-history.json`: the accepted document. It holds source decisions, binding status, window,
  top-N file and component ranking, gaps, observations, and the index manifest.

Outputs keep identity exposure low:

- **Authors:** ordinals assigned in walk order (`author-0001`). Names and emails exist only in the
  protected raw log.
- **Messages:** never indexed. Classification labels and referenced identifiers are indexed.
  Indexing subjects after gitleaks redaction is a TODO.
- **Retrieval:** a new `history` index name with one shard per run, `git-history`, which holds:
  - one `history_signal` entity per file, with a whole-file `SourceLocation` (non-exact and
    ambiguous for divergent files);
  - one `history_signal` entity per component;
  - `change` entities for each file's recent changes;
  - `DERIVED_FROM` relations from each file signal to its changes, and `CONTAINS` from each
    component to its files; and
  - coverage rows `git-history` and `github-enrichment`.

  The shard is composed into the accepted manifest and queryable through `find`, `search`,
  `trace`, and `coverage`.

## Consumers

- **Target analysis plan.** The plan reads the accepted history handoff and adds `history_priority`:
  status, history handoff hash, history identity, ranking identity, and accepted components and
  files in churn rank order. Validation rejects any component or file that is not an exact accepted
  catalog identity. Without history the section is `UNAVAILABLE` with a reason.
- **Inference security review (design).** History coverage and ranks feed the evidence map and
  hunt-package lead menus as context, never as message text or a search limit.
- **Final report.** The limitations section lists history coverage, binding status, and gaps.
- **Review prioritization.** `job_review_prioritization` uses each file's accepted attention score
  as its `history_hotspot` feature; functions inherit their file's value. See
  [`review-prioritization.md`](review-prioritization.md).

## Central TOML

```toml
[jobs.job_source_history_analysis.settings]
window_days = 365
max_changes = 20000
bulk_change_file_threshold = 500
recency_half_life_days = 90
minor_author_share = 0.05
young_line_days = 30
co_change_top_k = 10
co_change_min_support = 3
blame_max_files = 50
blame_max_file_bytes = 1048576
ranking_top_n = 200
fix_labels = ["bug", "fix", "regression"]
security_labels = ["security", "vulnerability"]

[jobs.job_source_history_analysis.settings.ranking_weights]
churn_lines = 3
recency_weighted_churn = 2
change_count = 1

[jobs.job_source_history_analysis.settings.git]
enabled = true

[jobs.job_source_history_analysis.settings.github]
enabled = false
api_base = "https://api.github.com"
repository = ""              # owner/name when enabled
token_env = "GITHUB_TOKEN"
max_requests = 2000
timeout_seconds = 30
```

Topology:

| Step | Tasks |
|---|---|
| `resolve_sources` | `resolve_history_source`, `bind_snapshot` |
| `acquire` | `git_history`, `normalize_changes`, `github_enrichment` |
| `analyze` | `classify_changes`, `compute_signals`, `blame_age`, `co_change`, `rank` |
| `publish` | `index_history`, `publish_handoff` |

Validation rejects:

- out-of-range bounds;
- unknown ranking signals, negative weights, or no positive weight;
- malformed label lists; and
- for enabled GitHub, a non-HTTPS API base, a malformed `owner/name`, or a `token_env` that is not
  an environment-variable name.

## Gap and decision taxonomy

| Code | Decision | Meaning |
|---|---|---|
| `no_git_metadata`, `no_commits` | `SKIPPED_NA` | Git does not apply |
| `git_history_disabled`, `github_enrichment_disabled` | `SKIPPED_POLICY` | turned off by configuration |
| `history_source_outside_target` | `GAP` | gitfile or `.git` symlink escapes the target |
| `linked_worktree_not_supported`, `unsupported_ref_storage`, `unsupported_object_format`, `shallow_file_invalid` | `GAP` | repository layout not supported |
| `partial_clone_objects_missing`, `alternates_unresolvable` | `GAP` | objects unreadable offline |
| `history_not_of_snapshot` | `GAP` | the mainline tree does not describe the reviewed files |
| `working_tree_divergent`, `untracked_path` | `GAP` | some file attribution unavailable or non-exact |
| `tree_listing_truncated` | `GAP` | tree listing exceeded the output bound |
| `submodule_history_not_followed` | `GAP` | gitlinks present (see TODO) |
| `shallow_history`, `history_window_truncated` | `GAP` | ancestry ends inside the window |
| `message_stream_misaligned` | `GAP` | message classification incomplete |
| `blame_bound_reached`, `blame_execution_failed` | `GAP` | young-line share incomplete |
| `git_execution_failed:<command>` | `GAP`, retriable | the Git container did not complete |
| `github_rate_limited` | `GAP`, retriable | enrichment throttled |
| `github_request_budget_exhausted`, `github_commit_pulls_unavailable`, `github_snapshot_commit_not_found`, `github_permission_denied` | `GAP` | enrichment incomplete |
| `replace_refs_ignored`, `grafts_ignored`, `config_includes_ignored`, `mainline_not_found_using_head`, `head_differs_from_mainline`, `timestamp_anomaly:<n>` | observation | recorded, never honoured |

Each of the following is a hard failure that blocks publication instead of creating a gap:

- changed accepted target bytes;
- a history that changed during the run;
- an artifact hash or path mismatch; and
- a corrupt manifest.

## Perforce design (planned)

Perforce will be a second source behind the same signals, ranking, shard, and plan contract:

- **Export mode first.** The job consumes an operator-produced, SHA-256-pinned `p4 -ztag -Mj`
  bundle, so the review itself needs no network or credentials. A hash mismatch is a hard failure.
- **Server mode.** Queries run in a pinned `tool-p4` image whose only egress is the configured
  `P4PORT`:
  - `ssl:` ports require a configured trust fingerprint;
  - the ticket comes from an environment-variable secret mounted as a run-owned `P4TICKETS`;
  - `P4CONFIG` is empty, `P4ENVIRO` is `/dev/null`, and the target's `.p4config` is ignored; and
  - only read commands run (`info`, `changes`, `describe -s/-ds`, `filelog`, `fstat`, `annotate`,
    `fixes`), scoped to the configured depot paths at a pinned changelist `@N`.
- **Binding.** Each inventory file is compared with `p4 fstat -Ol` digests at `@N`, with line
  endings normalized by file type. `ktext`, purged revisions, and paths hidden by protections are
  per-path gaps.
- **Signals.** `describe -ds` supplies churn, `p4 fixes` supplies exact fix classification, and
  bounded `filelog -i` follows integrations.
- **Identity probe.** The probe inputs extend to server identity, depot scope, changelist, and
  bundle hash.
- **Licensing.** The Helix Core CLI license must be reviewed before the image is cataloged.

## Implementation status

1. **Done:** local Git resolution and binding, the hardened `tool-git` image, first-parent churn,
   ownership, classification, reverts, co-change, blame age, churn-led ranking, the `history`
   shard, the plan's `history_priority`, the runtime input-identity probe, and GitHub enrichment.
2. **TODO:** Perforce export mode, then server mode.
3. **TODO:** submodules as independent sources.
4. **TODO:** exact OSV fix-commit matching, subject indexing after gitleaks redaction,
   function-level signals from Tree-sitter spans, and a `query_history` tool if consumers need one.
