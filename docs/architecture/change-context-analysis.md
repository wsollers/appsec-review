# Change-context analysis

Status: implemented in `src/appsec_review/jobs/job_change_context_analysis/`. Operator guidance is
in [`../operations/change-context-analysis.md`](../operations/change-context-analysis.md).

## Purpose and boundary

`job_change_context_analysis` asks *how* code changed, not how much. It complements the churn-led
hotspot ranking of [`source-history-analysis.md`](source-history-analysis.md) with review-process
and change-shape anomalies: fast or stale approvals, unreviewed mainline changes, off-hours and
pre-deployment changes, sprawling changes, repeated repairs, production churn without tests, and
concentrated or departed ownership.

The lane is a prioritization producer, like history:

- A change-context priority orders review work. It is never a vulnerability finding, never
  evidence for one, and never raises a finding's severity. Every accepted document, index payload,
  and MCP response carries that authority statement.
- A low score is not evidence of safety. Missing, disabled, incomplete, or untrusted data makes the
  affected metric `unavailable` or `partial` with a named gap; it is never replaced with zero or "no
  anomaly".
- Commit messages, identities, timestamps, review metadata, deployment records, and organization
  data are untrusted data, never instructions. Only identifiers, enumerations, numbers, and
  timestamps survive normalization; titles, bodies, names, and emails are never stored or indexed.
- Observed facts (review-host timestamps, approval commit ids, deployment events, organization
  status) are kept apart from heuristic classifications (fix labels, test association, off-hours
  policy), and every derived value records its basis.

## Placement and inputs

```text
job_target_catalog -> job_source_history_analysis -> job_target_analysis_plan -> job_tree_sitter_ast
                                                                                   \-> job_change_context_analysis -> job_codeql_analysis
```

In Dagster's `wave1_review` the job follows `job_tree_sitter_ast` and precedes
`job_codeql_analysis`, which composes its manifest like other siblings; security tagging lists it
among its fallback predecessors. The direct CLI graph runs it last, after
`job_evidence_collection`; that graph has no Tree-sitter job, so function-level attribution there is
the named gap `function_spans_unavailable:tree_sitter_not_accepted`.

The job does not rescan Git or re-derive history calculations. It consumes, through hash-verified
accepted handoffs:

| Input | From | Used for |
|---|---|---|
| normalized in-window changes, rename mapping, bulk flags | history `changes.json` | every per-change signal |
| change classification (`fix`, `security_fix`, basis) | history `classification.json` | repeated repairs, fix-on-fix |
| GitHub review facts | history `github-enrichment.json` | review speed when `review.source = "github_enrichment"` |
| raw first-parent log (protected) and walked-change count | history `acquire.git_history` | lifetime ownership only |
| snapshot binding (`exact` / divergent files) | history result | location reliability |
| hotspot attention ranks | history `signals.json` | published alongside, never weighted |
| component roots | accepted catalog | component scope and sprawl grouping |
| function node spans | accepted Tree-sitter shards (optional) | function scope |
| `bulk_change_file_threshold` | run-owned resolved configuration | lifetime normalization parity with history |

Its own Git work is limited to two bounded, fixed-argv operations in the hardened `tool-git`
container that history already uses: `blame --porcelain` at the snapshot for the top
`line_attribution_max_files` files (function attribution and surviving-line ownership), and, for up to
`fix_on_fix_max_checks` fix/path pairs, `diff -U0 <parent> <fix>` followed by a ranged
`blame --porcelain <parent>` (exact fix-on-fix lines).

## Data sources and requirements

| Source | Configuration | Required for | Without it |
|---|---|---|---|
| Local Git (via history) | always | sprawl, repeated repairs, fix-on-fix, test churn, lifetime ownership | whole lane `unavailable` with the history reason (for example `no_git_metadata`) |
| Review records | `review.source = "github_enrichment"` (default) or `"export"` | fast/stale approvals, unapproved mainline changes; observed `merged_at` landing time | review metrics `unavailable` (`review_records_disabled`, `review_records_unavailable:<reason>`); missing commits make them `partial` |
| Time zone | `schedule.time_zone` (IANA) | off-hours | `unavailable` (`time_zone_not_configured`, `time_zone_database_unavailable`) |
| Deployment events | `deployments.enabled`, pinned export | pre-deployment proximity | `unavailable` (`deployment_disabled`, `deployment_export_*`) |
| Test association rules | `test_association.enabled` | untested production/contract churn | `unavailable` (`test_association_disabled`) |
| Organization membership | `organization.enabled`, pinned export | departed dominant owner | `unavailable` (`organization_disabled`, `organization_export_*`) |
| Tree-sitter spans | accepted `job_tree_sitter_ast` | function scope | function scope empty; `function_spans_unavailable:*` or `function_mapping_unreliable` |

GitHub enrichment now also keeps the review timeline needed here: PR `created_at` and `merged_at`,
the final head SHA, the head commit's committer time, and every other-reviewer approval's
`submitted_at` and reviewed `commit_id` (no logins). One extra bounded request per PR reads the head
commit time.

Operator exports are read only from a path relative to the repository root, never from inside the
target, only when their SHA-256 matches `export_sha256`, and only into closed schemas. A copy of
each accepted export is kept in the attempt (`artifacts/inputs/<name>.json`) and listed under
`raw_exports` in the accepted document. Failures are named gaps: `*_export_unpinned`,
`*_export_missing`, `*_export_hash_mismatch`, `*_export_invalid`, `*_export_outside_repository`,
`*_export_inside_target`, `*_export_too_large`; rejected records add `deployment_events_rejected` or
`organization_members_rejected`.

Export schemas:

```json
{"schema": "appsec-review/review-records/1",
 "records": {"<mainline commit sha>": {
   "pull_request": 42, "direct_push": false,
   "created_at": "2024-03-01T09:00:00Z", "merged_at": "2024-03-01T10:00:00Z",
   "head_sha": "<sha>", "head_committed_at": "2024-03-01T08:58:00Z",
   "approvals": [{"submitted_at": "2024-03-01T09:02:00Z", "commit_id": "<sha>"}]}}}

{"schema": "appsec-review/deployment-events/1",
 "coverage": {"start": "2024-01-01T00:00:00Z", "end": "2024-06-30T23:59:59Z"},
 "events": [{"deployment_id": "rel-118", "environment": "production", "status": "success",
             "deployed_at": "2024-03-01T23:00:00-05:00", "commit": "<deployed mainline sha>"}]}

{"schema": "appsec-review/organization-membership/1", "as_of": "2024-06-30T00:00:00Z",
 "members": [{"identity_sha256": "<sha256 of lowercased commit email>", "status": "departed",
              "departed_at": "2024-02-01T00:00:00Z"}]}
```

`approvals` lists approvals by reviewers other than the PR author. A direct push is
`{"pull_request": null, "direct_push": true}`. Timestamps must be RFC 3339 with an explicit offset.
Organization identities are pseudonymous hashes, so the export never needs plaintext emails.

## Signals

All windows reuse history's anchor (the snapshot commit time) and in-window changes; nothing reads
wall-clock time or the host's time zone. Rule identity: `appsec-review/change-context-rules/1`.

### Per change (`change-records.json`)

Each record carries provenance: change id, first-parent position, review unit (`pr:<n>` or
`change:<id>`), claimed `commit_time`/`author_time`, history's clamped `effective_time`,
`landed_at` with its basis (`review_host_merged_at` when known, else `git_committer_time_claimed`),
the normalized review record, the snapshot commit, and the classification basis.

1. **Review speed** (`review`).
   - `creation_to_first_approval_seconds` = first other-reviewer approval − PR creation.
   - `final_head_to_approval_seconds` = first approval *of the merged head* − head commit time.
     The head time is claimed Git data and is labelled `git_committer_time_claimed`.
   - `merged_head_approved` is true when an approval's `commit_id` equals the merged head;
     `stale_approval` is true when the PR was approved only on earlier heads.
   - `fast_approval` (either interval below `fast_review_seconds`, default 300) and `fast_merge`
     (creation to merge below the same bound).
   - `unapproved_mainline` is true for a direct push or a merged PR with no other-reviewer approval.
   - Status is `known`, `incomplete` (a timeline field is missing), `missing` (no record for the
     commit), or `unavailable` (source off).
2. **Deployment proximity** (`deployment`). A deployment *ships* a change when its deployed commit
   is the change or a first-parent descendant of it in the walked mainline; only `success` events in
   the configured `environments` count. The first shipping deployment by time gives
   `lead_seconds = deployed_at − landed_at`; `pre_deployment` is `lead ≤ pre_deployment_window_hours`.
   Other states: `not_deployed_in_coverage`, `outside_coverage` (landed before the export's coverage
   start, so an earlier unseen deployment is possible), and `timestamp_inconsistent` (negative lead,
   never flagged). Deployed commits absent from the walked history are the
   `deployment_commit_not_in_history` gap. Commit time alone never implies deployment proximity.
3. **Off-hours** (`schedule`). `landed_at` converted to `schedule.time_zone` (DST-aware); off-hours
   means a configured weekend day or a local time outside `[business_hours_start, business_hours_end)`.
4. **Scope sprawl** (`sprawl`). Files, components, and total churn of the change. Touched components
   are merged into *related groups* when one root nests the other (the repository-root component is
   excluded, since it would relate everything) or when at least `related_component_min_support`
   *other* non-bulk in-window changes touched both. Reported: `unrelated_group_count`, per-group
   churn, `group_churn_entropy` (normalized Shannon entropy of churn across groups, 0–1), and
   `largest_group_churn_share`. `sprawling` requires all of: groups ≥ `min_unrelated_groups`, churn ≥
   `min_churn_lines`, and entropy ≥ `min_group_entropy`, so a large change with a token edit elsewhere
   is not sprawl.
5. **Test-to-code churn** (`tests`, rules `appsec-review/test-association/1`), evaluated over the
   change's review unit (all mainline commits of one PR):
   - roles come from explicit configuration: `test_patterns` first, then `contract_patterns`, then
     `production_extensions`; anything else is `other` and ignored;
   - a test file is associated by `subject` when its stem minus one leading (`test_`, `spec_`) and one
     trailing (`_test`, `Test`, `Tests`, `.spec`, `.test`, `_spec`) affix equals a production stem in
     the unit, else by `component` when it shares a catalog component with a production file;
   - a subject matching several production files associates with all of them and is reported in
     `ambiguous_test_files` (the record becomes `partial`); unassociated test churn is reported
     separately and never offsets production churn;
   - `untested_production` = production+contract churn ≥ `min_production_churn_lines` with zero
     associated test churn; `untested_contract` = any contract churn with no test churn in the unit.

### Per unit (file, function, component)

Files are history-eligible snapshot files with in-window changes; components are catalog
components; functions are Tree-sitter callable nodes in files whose binding is exact, whose parse has
no error nodes, and whose blame succeeded. A function's change set is the in-window changes that
still own at least one of its lines at the snapshot (`attribution: surviving-line`), an
under-approximation that misses changes whose lines were later rewritten.

| Signal | Definition | Availability |
|---|---|---|
| `fast_review_change_count` | changes with `fast_approval` or `fast_merge` | review source; `partial` when any change is `missing`/`incomplete` |
| `stale_approval_change_count` | changes approved only on an earlier head | same |
| `unapproved_mainline_change_count` | direct pushes and unapproved merged PRs | same |
| `off_hours_change_count` | changes landed off-hours | time zone |
| `pre_deployment_change_count` | changes shipped within the window | deployments; `partial` when any change is outside coverage or inconsistent |
| `sprawling_change_count` | sprawling changes touching the unit | Git |
| `repeated_repair_peak` | most fix-classified changes in any half-open `window_days` window (`[t, t+60d)`); flagged when ≥ `min_fix_changes` (4, i.e. more than three) | Git; `partial` when history classification has gaps |
| `fix_on_fix_event_count` | fix changes whose removed or modified lines were introduced by an earlier in-window fix (exact line blame at the parent) | Git; `partial` on bound or failures; `unavailable` at function scope |
| `untested_production_change_count` | changes with `untested_production` or `untested_contract` | test association |
| `lifetime_principal_author_share` | largest author share of lifetime non-bulk change touches | Git; `partial` when lifetime history is truncated or shallow |
| `departed_dominant_owner` | the principal author is `departed` in organization data and holds ≥ `dominant_owner_share` | organization data; `unavailable` when the principal is not listed |

`repeated_repair_peak` links the underlying changes in its earliest peak window (`details.repeated_repairs`)
and reports the classification basis counts (`heuristic` or `github_label`). It is distinct from
`fix_on_fix_event_count`: the first counts fixes touching the same unit in time; the second counts
exact same-line fix-after-fix events (`details` in `fix-on-fix.json` link both changes and the line
count). Fix-on-fix lines introduced before the window are counted as `prior_lines_outside_window`.

Ownership details also report `author_count`, `bus_factor` (fewest authors whose shares reach
`bus_factor_share`), and, for blamed files, `surviving_line_ownership` from blame. Function ownership
is surviving-line authorship. Lifetime ownership is separate from history's in-window
`top_author_share`. Departure is never inferred from Git inactivity.

## Priority score

`appsec-review/change-context-priority/1`, computed separately for files, functions, and components:

- **Normalization.** Each weighted signal is divided by its population maximum within the scope
  (booleans count 1, shares are already 0–1), so a unit with no observed anomaly scores 0 on that
  signal; an all-zero signal contributes 0 for everyone.
- **Score.** Weighted mean of the normalized signals that are not `None`. Unavailable signals are
  excluded from both numerator and denominator, never zero-filled. `coverage` is the share of total
  weight that was available, and `missing_signals` names the rest. Consumers should read a high
  score with low coverage as "less is known", not "riskier".
- **Ties.** Score descending, then coverage descending, then the stable key (path, function key, or
  component id). Ranking is byte-for-byte reproducible for the same inputs.
- **Relationship to the history hotspot.** The hotspot score is churn-led; this score deliberately
  excludes raw churn and change counts so the two are independent. Each file and component record
  carries `history_hotspot` (`rank`, `score`) for side-by-side ordering; neither score feeds the
  other, and combining them is a consumer decision.

## Index schema and retrieval

The job publishes the immutable shard `history/change-context` and composes it into the accepted
manifest (all upstream shards, including `history/git-history`, are retained).

| Entity kind | Native id | Content |
|---|---|---|
| `change_context_signal` | `file:<path>`, `function:<path>#<start>-<end>:<type>`, `component:<id>` | top `ranking_top_files`/`_functions`/`_components` units: `scope`, `metrics`, `availability`, `details`, `priority` (`rank`, `score`, `coverage`, `normalized`, `missing_signals`), `supporting_changes`, `history_hotspot`, `file_sha256`, `producer`, `rules`, `snapshot_commit`, `authority`; file records carry whole-file locations (`git-blob-binding`, or ambiguous `git-path-binding` when divergent), function records carry exact Tree-sitter spans (`tree-sitter-span+git-blame`) |
| `change` | commit id | the full per-change record and its `flags` |
| `review_unit` | `pr:<n>` | normalized review record and source |
| `deployment_event` | deployment id | environment, time, deployed commit |

Relations: unit `DERIVED_FROM` change (up to `supporting_change_limit`), review unit and deployment
`SUPPORTS` change, component `CONTAINS` file, file `CONTAINS` function. Coverage rows:
`git-change-context`, `review-records`, `deployment-events`, `off-hours-schedule`,
`test-association`, `organization-membership`, `function-attribution`, `fix-on-fix`.

Inference reads this index and never rescans Git, PR histories, or deployment records:

```json
{"tool": "query_change_context", "arguments": {"scope": "file", "limit": 10}}
{"tool": "query_change_context", "arguments": {"scope": "function", "path": "app/auth.py"}}
{"tool": "query_change_context", "arguments": {"signal": "stale_approval_change_count"}}
{"tool": "trace", "arguments": {"identity": "<change_context_signal id>", "relations": ["DERIVED_FROM"], "depth": 1}}
{"tool": "coverage", "arguments": {"indexes": ["history"]}}
```

`query_change_context` filters by `scope`, exact `path`, `component`, and a non-zero `signal`,
returns records in rank order, and attaches every non-complete coverage row of the shard as a
`coverage_gaps` entry, so an absent record is never mistaken for a clean unit. `read_excerpt` on a
function record returns the hash-verified span.

## Interpretation limits

- Review, deployment, and organization facts are only as good as their exporters; the pin proves the
  bytes are the ones the operator approved, not that they are complete.
- Git times are claimed. Off-hours uses `merged_at` when a review host observed it and otherwise the
  claimed committer time; the basis is recorded per change.
- Fix classification is history's heuristic unless a PR label matched; repeated repairs inherit
  that uncertainty. Fix-on-fix is exact at line level but bounded and window-limited.
- Function attribution only sees surviving lines and only for the top blamed files.
- Test association is path-based. It does not prove a test exercises the changed code.
- Bulk changes still count for sprawl and churn-based test signals but not for ownership.

## Outputs

Per attempt: `lifetime.json` (lifetime author counts and pseudonymous identity keys, never indexed),
`external-sources.json`, `inputs/*.json` (pinned export copies), `attribution.json`,
`fix-on-fix.json`, `change-records.json`, `units.json`, `signals.json` (ranked units), and the
accepted `change-context.json` (sources, coverage, gaps, rules, weights, top-N per scope, index
manifest, authority).

## Configuration and topology

All thresholds, weights, sources, and bounds live in
`[jobs.job_change_context_analysis.settings]` (see the operations guide for the full table). The
settings parser is closed: unknown keys, out-of-range bounds, malformed patterns, an enabled export
without a path, invalid zones, inverted business hours, unknown priority signals, negative weights,
or no positive weight fail validation.

| Step | Tasks |
|---|---|
| `load` | `accepted_history`, `external_sources` |
| `attribute` | `line_attribution`, `fix_on_fix` |
| `analyze` | `change_signals`, `unit_signals`, `rank` |
| `publish` | `index_change_context`, `publish_handoff` |

Failed Git executions (`line_attribution_execution_failed`, `fix_on_fix_execution_failed`) are
retriable dispositions. Changed accepted bytes, artifact hash mismatches, a Tree-sitter snapshot
mismatch, or a corrupt manifest are hard failures.
