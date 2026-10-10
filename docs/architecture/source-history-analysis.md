# Source history analysis

Status: local Git, optional GitHub enrichment, line-level fix-on-fix matching, Tree-sitter
function-level signals and complexity, the Security Instability Index (SII), and the bounded hotspot
index are implemented in `src/appsec_review/jobs/job_source_history_analysis/`. Perforce is designed below but not built;
see [`../TODO.md`](../TODO.md). Operator guidance is in
[`../operations/source-history-analysis.md`](../operations/source-history-analysis.md).

## Purpose and boundary

`job_source_history_analysis` reads the version-control history behind the reviewed snapshot and
publishes bounded, resolvable *instability signals*. These identify files and components that
changed often or recently, were touched by many authors, went through fix and revert cycles, or
changed together with other files. Files and functions are ranked by a 0–100 Security Instability
Index with Tier 1/2/3 bands. The top N of each are published as an immutable, retrieval-queryable
hotspot index, and the analysis plan uses the file ranking to order review attention.

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
- The ranking is the SII over relative churn, revision frequency, author entropy, and complexity,
  with weights in TOML. Every other signal is published alongside it, unweighted.
- Generated code, lockfiles, fixtures, documentation, vendored code, bulk changes, and formatting
  changes are excluded from ranking by explicit rules, and their metrics and exclusion reasons are
  kept.
- PR and deployment timing are not acquired. They are named unavailable signals and are never
  inferred from commit timestamps.
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
- **Commands:** five fixed argv builders: first-parent `log` with `--numstat -z`, first-parent
  message `log`, `ls-tree`, per-file `blame --porcelain`, and per-file first-parent
  `log --follow --unified=0` for line regions. No target text is interpolated into
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

### Window

The window is `history_window_months` (M, default 6) calendar months ending at the mainline
snapshot commit's committer time, read as UTC (`appsec-review/history-window/calendar-months-utc/1`).
Wall-clock time is never used, so the same inputs give byte-identical outputs. The start keeps the
anchor's day of month and time of day. When that day does not exist in the start month, it clamps to
the month's last day:

| Anchor (UTC) | M | Window start |
|---|---|---|
| 2024-08-31 12:00 | 6 | 2024-02-29 12:00 (leap year) |
| 2023-08-31 12:00 | 6 | 2023-02-28 12:00 |
| 2024-02-29 00:00:01 | 12 | 2023-02-28 00:00:01 |
| 2024-03-31 23:59:59 | 1 | 2024-02-29 23:59:59 |
| 2024-01-15 08:30 | 6 | 2023-07-15 08:30 |

Both ends are inclusive. A change is in the window when its effective time is at or after the start.

Git timestamps are claimed data. A commit whose time is later than its first-parent child's is
clamped to the child's time, and the count is recorded as a `timestamp_anomaly` observation.

Commits are walked newest first. Renames are followed backward, so churn on `app/util.py` before a
rename counts toward the current `app/helpers.py`. A shallow boundary inside the window is
`shallow_history`. Reaching `max_changes` before the window start is `history_window_truncated`.

### Revision semantics

History follows the mainline's first-parent chain. `change_count` therefore counts distinct
first-parent commits. A pull request merged with a merge commit counts once, and the commits on its
branch are not counted separately. Its diff is the merge's diff against the first parent. A
squash-merged or rebased pull request counts as the commits that land on the mainline. Every
document, signal set, and hotspot entry carries this as `revision_semantics`.

### Change exclusions and path filters

Two kinds of change keep their per-file values but are excluded from every ranking metric:

- **Bulk:** the change touches more than `bulk_change_file_threshold` files.
- **Formatting** (`appsec-review/history-formatting-rules/1`): the subject names formatting
  (`style:`, `format:`, `fmt:`, `lint:`, reformat, black, prettier, clang-format, gofmt, rustfmt,
  whitespace, line endings, indentation) *and* the change is balanced, meaning
  `|added - deleted| <= formatting_balance_tolerance * max(added, deleted)`. The basis is recorded
  as `heuristic`.

Each file's `changes` list keeps every in-window change with its `added`, `deleted`, time, author
ordinal, fix flag, and `excluded` reason (`bulk`, `formatting`, or `null`). `bulk_change_count`,
`formatting_change_count`, and `excluded_churn_lines` count what was set aside.

Path rules (`appsec-review/history-path-filters/1`) are POSIX globs in central TOML, grouped by
category and checked in this fixed order: `generated`, `lockfile`, `fixture`, `documentation`,
`vendored`. `**/` spans directories. `*` and `?` stay inside one segment. A pattern without `/`
matches the file name at any depth. A matching file keeps all its metrics but gets
`rank_eligibility = excluded:<category>` and an `exclusion` record that names the category, the
pattern, and the rules identity.

A file is rank-eligible only when it matches no rule, has at least one ranking change, and has a
non-zero count of current non-blank lines. Otherwise its eligibility is `no_ranking_changes` or
`zero_size`. Exclusion counts are published as `rank_exclusions` and in the hotspot index. Files
matching the `test` patterns are still ranked. The rule only classifies production-to-test churn.

### File and component metrics

All metrics use the M-month window and ranking changes only (in-window, first-parent, non-bulk,
non-formatting), unless the table says otherwise. The source is `git log --first-parent --numstat`
unless stated.

| Metric | Unit | Calculation | Limitations |
|---|---|---|---|
| `lines_added`, `lines_deleted` | lines; file, component, symbol | sum of numstat additions or deletions | binary files count 0 |
| `churn_lines` | lines | `lines_added + lines_deleted` | a moved line counts twice |
| `relative_churn` | ratio | `churn_lines / nonblank_lines`, where `nonblank_lines` is the current non-blank line count of the reviewed bytes (for symbols, of the symbol span) | `null` for zero-size units, which are not ranked |
| `change_count` | first-parent commits | distinct ranking changes touching the unit | see revision semantics |
| `revision_frequency` | commits per month | `change_count / M` | same as `change_count` |
| `recency_weighted_churn` | lines | churn × 0.5^(age days / `recency_half_life_days`), age from the anchor | |
| `author_count` | authors | distinct author ordinals (email-keyed, no mailmap) | one person with two emails counts twice |
| `author_commit_shares` | fraction per author | author's ranking changes / all ranking changes | ordinals only; no identities |
| `author_entropy` | bits | Shannon entropy `-Σ p log2 p` over `author_commit_shares`; one author is 0 | `null` without ranking changes |
| `minor_author_count`, `top_author_share` | authors, fraction | authors below `minor_author_share`; the largest share | |
| `fix_change_count`, `security_fix_change_count` | changes | changes classified as fixes or security fixes | classification is heuristic unless GitHub-labelled |
| `repeat_fix_count` | changes | fixes that follow another fix to the same file within `fix_on_fix.interval_days` | file granularity; see fix-on-fix for line and function matching |
| `fix_on_fix_count` | events | see [Fix-on-fix](#fix-on-fix) | `null` with a gap when undetermined |
| `revert_count` | changes | changes that revert, or are reverted by, another walked change | |
| `review_bypass_count` | changes | GitHub only: direct pushes, merges without another reviewer's approval, or stale approvals | a gap when enrichment is disabled or incomplete |
| `retouch_interval_median_days` | days | median gap between successive ranking changes | |
| `young_line_share` | fraction | blamed lines newer than `young_line_days`, top `blame_max_files` files by churn (source: `git blame --porcelain`) | `null` beyond the bound |
| `co_change_partners` | pairs | top-K partners with support ≥ `co_change_min_support`, confidence, and a cross-component flag | non-bulk, non-formatting changes only |
| `test_touch_change_count`, `test_touch_share` | changes, fraction | production files only: ranking changes that also touched a `test` path | path rule only; `null` for test files |
| `production_churn_lines`, `test_churn_lines`, `production_to_test_churn_ratio` | lines, ratio | per component, churn on non-test and test files; ratio `null` when no test churn | path rule only |
| `cyclomatic_complexity`, `cognitive_complexity` | count | see [Complexity](#complexity) | `null` with a gap without symbol coverage |

Components aggregate their non-excluded files. A component's priority is the highest SII of its
ranked files (`basis: max_file_sii`). Ties break on churn, then change count, then component id.

### Change classification

Change classification is deterministic (`appsec-review/history-change-rules/2`), and each label
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
- `formatting`: `heuristic`, as described above.

No model is used. Exact matching of OSV `fixed` commit events is deferred, because the synchronized
OSV index does not yet key advisories by commit id.

### Line history

For the `line_history.max_files` highest-churn rank-eligible files whose working-tree bytes equal
the snapshot blob, the job runs a fifth fixed command:

```text
git log --first-parent --diff-merges=first-parent --follow -M --unified=0 --no-ext-diff
        --no-textconv --no-mailmap --no-color --no-abbrev --max-count=<max_changes>
        --format=%x01%H HEAD -- <path>
```

Only commit headers and `@@ -a,b +c,d @@` hunk headers are parsed. Diff body lines always start with
`+`, `-`, a space, or a backslash, so target text cannot forge a header. A hunk touches old lines
`a..a+b-1` and new lines `c..c+d-1`. A zero-length side (a pure insertion or deletion) touches its
two neighbouring lines.

*Region mapping* (`appsec-review/history-line-regions/1`) carries a span into the next version:

- a line outside every hunk shifts by the net size of the hunks before it; and
- a line inside a hunk maps to that hunk's whole replacement region.

Rewritten code therefore still maps to the code that replaced it. This over-approximates and never
drops a touched region. Files that are divergent, too large, beyond the bound, truncated, or
unparseable get a per-file status (`unavailable:<reason>`) instead of line history.

### Fix-on-fix

`appsec-review/fix-on-fix/1` compares every ordered pair of classified fixes on the same
rank-eligible file whose effective times are at most `fix_on_fix.interval_days` apart. The interval
is configurable from 14 to 30 days, and the default is 30. A pair is an event when one of these
holds:

- **`line_overlap`:** the earlier fix's post-image regions, carried through every intervening
  commit to the later fix's parent, intersect the later fix's pre-image regions.
- **`same_function`:** the lines do not overlap, but both fixes' regions, carried to the snapshot,
  reach the same innermost symbol.

Each event records:

- the commits and the interval in days;
- the basis;
- the matching regions;
- the shared symbols; and
- the later fix's region at the snapshot as a source location.

A pair is *undetermined*, with a reason, in these cases:

- the line history is missing (`line_history_bound_reached`, `working_tree_divergent`, …);
- a commit in the chain is missing or binary (`line_history_incomplete`); or
- the lines do not overlap and the file has no symbol spans (the symbol status reason).

`fix_on_fix_status` is `complete`, `partial`, or `unavailable`. `fix_on_fix_count` is `null` whenever
undetermined pairs exist and no event was confirmed, so a gap is never published as zero. A file
with fewer than two fixes in the window has a complete count of 0.

### Symbols and function-level history

For the `symbols.max_files` highest-churn rank-eligible exact files in a supported language, the job
runs the pinned `tool-tree-sitter` image, the same image, grammar lock, request schema, and output
validation as `job_tree_sitter_ast`. The history job runs before the Tree-sitter job in the graph,
so it parses its own bounded file set, grouped by language. The container output must match the
locked tool identity and image id, name only requested paths, and carry their accepted SHA-256.

`appsec-review/history-symbols/1` derives innermost function symbols:

- **Function node types:** per language. Lambdas and closures are their own symbols.
- **Name:** the `name` field, the C/C++ declarator chain, or an assigned name. Otherwise
  `<anonymous:LINE>`.
- **Qualified name:** joins enclosing class and function names. The symbol id is
  `path::qualified.name`, with `#n` for duplicates in byte order.
- **Spans:** byte and point spans are exact Tree-sitter spans. `own_lines` excludes nested
  functions.

Each in-window ranking change's hunks are carried to the snapshot and attributed to every innermost
symbol whose own lines they reach. A hunk that reaches several symbols counts its full size toward
each of them. Symbol metrics follow the file table, restricted to attributed hunks. A change that
cannot be mapped (missing from the per-file log, or behind a binary commit) is listed in
`unmapped_changes`, and the file's symbols carry `symbol_attribution_incomplete`. Only touched
symbols are published. When a file has no symbol coverage, file-level analysis continues and the
symbol status becomes a named gap.

Limitations:

- Attribution uses snapshot spans only. A function that was renamed or moved keeps its snapshot
  identity, and deleted functions are not represented.
- Region mapping can over-attribute after large rewrites.

### Complexity

`appsec-review/complexity-rules/1` keeps two distinct, language-aware measures per symbol, using a
node-type table for Python, JavaScript, TypeScript, TSX, Java, C, C++, C#, Go, Rust, and PHP:

- **Cyclomatic (McCabe):** `1 +` decision points. Decision points are:
  - `if` and `else if`/`elif`;
  - loop heads;
  - non-default `case` labels and match arms;
  - `catch`/`except`;
  - conditional expressions;
  - comprehension `for`/`if` clauses; and
  - each short-circuit operator token (`&&`, `||`, `??`, `and`, `or`).
- **Cognitive (after SonarSource):**
  - `+1 + nesting` for each nesting structure (`if`, loops, `switch`/`match`, `catch`, conditional
    expressions);
  - `+1` for `else`, `elif`, `else if`, and `goto`; and
  - `+1` per run of the same boolean operator.

  Nested functions are measured separately and do not add nesting to their parent.

File totals add every function plus the decision points outside any function. `sii.complexity_metric`
selects the measure that enters the SII (default `cyclomatic`). Both are always published.

Gaps:

- Unsupported languages (Kotlin, Ruby, Swift, shell, configuration files, and so on) get
  `symbol_language_unsupported`, and their complexity is `null`.
- Inside a span, syntax errors give `parse_errors_in_span`, C/C++ and C# preprocessor conditionals
  give `preprocessor_branches_not_counted`, and node-limit truncation gives `node_limit_reached`.

Limitations:

- Recursion and labelled jumps are not counted.
- Node types that the locked grammar renames would silently stop matching. Live grammar probes
  belong with the Tree-sitter image update procedure.

### Security Instability Index

`appsec-review/security-instability-index/1` scores every rank-eligible file, and separately every
touched symbol, from 0 to 100.

1. **Inputs:** `relative_churn`, `revision_frequency`, `author_entropy`, and the selected
   `complexity`.
2. **Transform:** `log1p` for relative churn, frequency, and complexity, because they are
   heavy-tailed. Entropy uses the identity.
3. **Normalize:** min-max over the population's present values to `[0, 1]`. A metric whose
   transformed values are all equal (*constant*) cannot discriminate. It normalizes to 0 for every
   unit, keeps its weight in the denominator, and is listed in `constant_metrics`.
4. **Score:** `SII = 100 × Σ wᵢ·nᵢ / Σ wᵢ` over the unit's *present* metrics, rounded to four
   decimals. Default weights are relative churn 0.35, revision frequency 0.25, author entropy 0.15,
   and complexity 0.25.
5. **Missing inputs:** a unit without complexity (no symbol coverage, unsupported language) is
   scored over its remaining weights. It records `missing_inputs` and `weight_coverage` (0.75 with
   the default weights) and carries a `complexity_unavailable:<reason>` gap.
6. **Ties:** higher SII, then higher `churn_lines`, then higher `change_count`, then the ascending
   path or symbol id.

The edge cases behave as follows:

- **Zero-size files** are not ranked (`zero_size`).
- **A one-unit population** scores 0 with Tier 1.
- **Incomplete history** (`shallow_history`, `history_window_truncated`, `message_stream_misaligned`)
  still scores what was observed. Every affected entry names the gap.

Scores are only comparable inside one population, window, and run. They prioritize review and are
never vulnerability evidence.

### Tiers

With population P, Tier 1 holds ranks `1..ceil(P × tier_1_share)` and Tier 2 holds the ranks up to
`ceil(P × (tier_1_share + tier_2_share))`. The rest are Tier 3. The defaults are 5 % and 15 %. Shares
are parsed as exact decimal fractions, so `100 × 0.05` is exactly 5. Rounding up means that:

- every non-empty population has a Tier 1;
- small populations err toward review; and
- Tier 2 can be empty.

| P | Tier 1 ranks | Tier 2 ranks |
|---|---|---|
| 1–3 | 1 | none |
| 10 | 1 | 2 |
| 20 | 1 | 2–4 |
| 21 | 1–2 | 3–5 |
| 100 | 1–5 | 6–20 |

Tiers follow rank order. Units with equal scores on either side of a boundary are split by the
deterministic tie-break.

### Gap assessment after this change

| Requested statistic | Implementation |
|---|---|
| Six-month window | `history_window_months` (default 6) calendar months in UTC, anchored to the mainline snapshot commit, with month-end and leap-year clamping |
| Added, deleted, total churn | `lines_added`, `lines_deleted`, and `churn_lines` per file, component, and symbol; per-change values kept in each file's `changes`; `relative_churn` against current non-blank lines |
| Revision frequency | `change_count` (distinct first-parent commits) and `revision_frequency` (per month); first-parent semantics stated in every output. Individual commits on merged branches are still not counted |
| Developer ownership | `author_count`, `author_commit_shares`, Shannon `author_entropy`, `minor_author_count`, `top_author_share`, and recency-weighted churn |
| Fix-on-fix cadence | Implemented: pairs of classified fixes within 14–30 days (default 30) matched on `line_overlap` or `same_function`, with commits, interval, basis, regions, and snapshot location; undetermined pairs are gaps, not zeros. Fix classification remains heuristic unless GitHub-labelled |
| Function or symbol history | Implemented for languages with a locked Tree-sitter grammar, within `symbols.max_files` and `line_history.max_files`; file-level analysis continues with a named gap elsewhere. Function renames across history are not followed |
| 0–100 SII and 5/15/80 tiers | Implemented: normalized relative churn, revision frequency, author entropy, and complexity with configured weights, deterministic ties, and ceil-rounded tiers. The old percentile attention score is removed |
| PR and deployment timing | Not acquired; published as `pull_request_timing` and `deployment_timing` unavailable signals and coverage rows. They are never inferred from commit timestamps |

## Outputs

These are written per attempt, under the unit directories:

- `binding.json`: binding status, divergent, untracked, and submodule paths.
- `protected/log.bin`, `protected/messages.bin`: raw Git output, kept in the attempt and never
  indexed.
- `changes.json`: normalized changes with ids, times, author ordinals, per-path numstat, renames,
  the bulk flag, the window start, and the window identity.
- `classification.json`, `github-enrichment.json`, `co-change.json`, `raw-signals.json`.
- `line-history.json`: per-file statuses and newest-first hunk lists.
- `symbols.json`: per-file symbol status, symbols, spans, own lines, and complexities.
- `fix-on-fix.json`: per-file events, undetermined pairs, and status.
- `symbol-signals.json`: per-symbol metrics, attributed changes, and unmapped changes.
- `signals.json`: every file, component, and symbol with its full metric vector and SII record,
  plus the population metadata (weights, transforms, normalization bounds, constant metrics, and
  tier bounds).
- `hotspots.json`: the hotspot index (below).
- `source-history.json`: the accepted document. It holds:
  - source decisions and binding status;
  - the window and revision semantics;
  - the SII file ranking (`ranking_top_n`) and the component priorities;
  - the hotspot summary and the artifact identity;
  - unavailable signals, gaps, and observations; and
  - the index manifest.

Outputs keep identity exposure low:

- **Authors:** ordinals assigned in walk order (`author-0001`). Names and emails exist only in the
  protected raw log.
- **Messages:** never indexed. Classification labels and referenced identifiers are indexed.
  Indexing subjects after gitleaks redaction is a TODO.
- **Symbol names:** target-controlled text, sanitized to at most 128 word-like characters.

### Hotspot index

`hotspots.json` (`appsec-review/history-hotspots/1`) is immutable and run-owned. It is hash-pinned
by the accepted document and holds the top `hotspot_count` (N, default 10) ranked files and the top
N ranked symbols of the M-month window. Its JSON schema is
[`../schemas/history-hotspots.schema.json`](../schemas/history-hotspots.schema.json). Each entry
(`appsec-review/history-hotspot/1`) has:

| Field | Content |
|---|---|
| `scope` | `file` or `symbol` |
| `identity` | `path`, `symbol_id`, `qualified_name`, `kind`, and `component_id` |
| `rank`, `tier`, `score`, `sii` | position, tier, 0–100 score, and SII identity within the scope's population |
| `metrics` | the complete scalar metric vector |
| `changes` | the newest 100 per-change records, plus `changes_truncated`; all of them are in `signals.json` |
| `fix_on_fix_events` | up to 20 file events |
| `inputs` | per-metric raw, transformed, and normalized values with weights and status, plus `missing_inputs`, `weight_coverage`, normalization bounds, constant metrics, weights, the complexity metric, the population size, and tier bounds |
| `snapshot` | the target snapshot fingerprint, the snapshot commit, and the object format |
| `source` | the path, the SHA-256 of the reviewed bytes, and the Git blob id |
| `location` | a resolvable span: the whole file (`git-blob-binding`) or the exact Tree-sitter symbol span, with byte, line, and column bounds |
| `window`, `coverage_gaps`, `authority` | the window, every named gap that affects the entry, and the prioritization-only statement |

The document also carries:

- the populations, with normalization and tier bounds;
- the rank-exclusion counts;
- the unavailable signals; and
- the `signals.json` identity.

`load_accepted_hotspots(run_root)` returns the hash-verified index. Inference and other consumers
query this bounded index, or retrieval below, and never rescan Git or the target tree.

### Retrieval

The `history` index has one shard per run, `git-history`, which holds:

- a `history_signal` entity per file, with a whole-file `SourceLocation` (non-exact and ambiguous
  for divergent files);
- a `history_signal` entity per component;
- a `history_signal` entity per touched symbol, with its exact Tree-sitter span, named by
  `symbol_id`;
- `change` entities for each file's recent changes; and
- `hotspot` entities, one per hotspot entry, named by path or symbol id, whose payload is the full
  entry and whose location is the entry's span.

Relations are:

- `DERIVED_FROM` from file signals to changes, and from hotspots to their signals; and
- `CONTAINS` from components to files, and from files to symbols.

Coverage rows are:

- `git-history`: history gaps only;
- `github-enrichment`;
- `line-history`, `symbol-spans`, and `fix-on-fix`;
- `history-hotspots`; and
- `pull-request-timing` and `deployment-timing`, always `unavailable`.

The shard is composed into the accepted manifest and is queryable through `find`, `search`, `trace`,
and `coverage`. For example, `find(kind="hotspot", indexes=["history"])` returns at most 2N entries.

## Consumers

- **Target analysis plan.** The plan reads the accepted history handoff and adds `history_priority`:
  status, history handoff hash, history identity, ranking identity (now the SII identity), and
  accepted components and files in SII rank order. Validation rejects any component or file that is
  not an exact accepted catalog identity. Without history the section is `UNAVAILABLE` with a
  reason.
- **Inference security review (design).** The bounded hotspot index, history coverage, and ranks
  feed the evidence map and hunt-package lead menus as context, never as message text or a search
  limit.
- **Final report.** The limitations section lists history coverage, binding status, and gaps.

## Central TOML

All values below are the defaults in `appsec-review.toml`. `settings.py` parses them into a frozen
`HistorySettings` and rejects unknown keys, out-of-range bounds, and malformed tables.

```toml
[jobs.job_source_history_analysis.settings]
history_window_months = 6        # M, 1-120
hotspot_count = 10               # N, 1-100
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

[jobs.job_source_history_analysis.settings.fix_on_fix]
interval_days = 30               # 14-30

[jobs.job_source_history_analysis.settings.line_history]
max_files = 50
max_file_bytes = 1048576

[jobs.job_source_history_analysis.settings.symbols]
enabled = true
max_files = 200
max_file_bytes = 1048576
max_nodes_per_file = 200000

[jobs.job_source_history_analysis.settings.sii]
complexity_metric = "cyclomatic" # or "cognitive"
tier_1_share = 0.05
tier_2_share = 0.15

[jobs.job_source_history_analysis.settings.sii.weights]
relative_churn = 0.35
revision_frequency = 0.25
author_entropy = 0.15
complexity = 0.25

[jobs.job_source_history_analysis.settings.filters]
generated = ["**/generated/**", "*.pb.go", "*_pb2.py", "*.min.js", ...]
lockfile = ["package-lock.json", "yarn.lock", "Cargo.lock", "go.sum", "*.lock", ...]
fixture = ["**/fixtures/**", "**/testdata/**", "*.snap", ...]
documentation = ["*.md", "*.rst", "*.txt", "docs/**", ...]
vendored = ["**/vendor/**", "**/third_party/**", "**/node_modules/**"]
test = ["**/tests/**", "test_*", "*_test.*", "*.spec.*", ...]
formatting_balance_tolerance = 0.1

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
| `analyze` | `classify_changes`, `compute_signals`, `blame_age`, `co_change`, `line_history`, `symbol_spans`, `fix_on_fix`, `symbol_signals`, `rank` |
| `publish` | `index_history`, `publish_handoff` |

Validation rejects:

- unknown keys and out-of-range bounds;
- a fix-on-fix interval outside 14–30 days;
- SII weights that do not name exactly the four metrics, are negative, or are all zero;
- an unknown complexity metric;
- tier shares that leave no Tier 3;
- filter patterns that are absolute or contain empty or dot segments;
- malformed label lists; and
- for enabled GitHub, a non-HTTPS API base, a malformed `owner/name`, or a `token_env` that is not
  an environment-variable name.

The runtime identity covers the catalog entries for `tool-git` and `tool-tree-sitter`.

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
| `line_history_bound_reached`, `line_history_file_too_large`, `line_history_truncated`, `line_history_unparseable` | `GAP` | per-file line regions unavailable; fix-on-fix and symbol attribution for that file are undetermined |
| `line_history:git_execution_failed` | `GAP`, retriable | a per-file line-history execution failed |
| `symbol_spans_disabled` | `GAP` (policy) | `symbols.enabled = false`; complexity and symbol signals are missing |
| `symbol_language_unsupported`, `symbol_file_too_large`, `symbol_spans_bound_reached`, `symbol_file_truncated`, `tree_sitter_omitted_file` | `GAP` | no symbol spans or complexity for some ranked files |
| `tree_sitter_unavailable`, `tree_sitter_execution_failed` | `GAP`, retriable | the Tree-sitter image is missing or did not complete |
| `parse_errors_present`, `parse_errors_in_span`, `node_limit_reached`, `preprocessor_branches_not_counted` | `GAP` | complexity counts are incomplete |
| `fix_on_fix_undetermined` | `GAP` | at least one candidate fix pair could not be matched or ruled out |
| `symbol_attribution_incomplete` | `GAP` | some changes could not be mapped to snapshot symbols |
| `pr_timing_not_acquired`, `deployment_timing_not_acquired` | unavailable signal | never inferred from commit timestamps |
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

1. **Done:**
   - local Git resolution and binding, and the hardened `tool-git` image;
   - the calendar-month window and separate added, deleted, and relative churn;
   - ownership with entropy, classification with formatting, reverts, co-change, and blame age;
   - path and change exclusions;
   - line-region history and fix-on-fix matching;
   - Tree-sitter function-level signals and cyclomatic and cognitive complexity;
   - the SII with tiers, and the bounded hotspot index;
   - the `history` shard, the plan's `history_priority`, the runtime input-identity probe, and
     GitHub enrichment.
2. **TODO:** Perforce export mode, then server mode.
3. **TODO:** submodules as independent sources.
4. **TODO:**
   - exact OSV fix-commit matching;
   - subject indexing after gitleaks redaction;
   - PR and deployment timing acquisition;
   - following function renames across history;
   - recursion in cognitive complexity;
   - live grammar probes for the complexity node-type table; and
   - a `query_history` tool if consumers need one.
