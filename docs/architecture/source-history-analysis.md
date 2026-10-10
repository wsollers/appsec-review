# Source history analysis

Status: design only. No job, container, schema, retrieval shard, or configuration for this lane
exists yet.

## Purpose and boundary

`job_source_history_analysis` reads the version-control history behind the reviewed snapshot and
publishes bounded, resolvable *instability signals*: files, components, and line ranges that changed
often, recently, by many hands, through fix and revert cycles, or in lockstep with other files. Its
consumers use those signals to decide where review effort goes first.

The lane is a prioritization producer, not a vulnerability producer:

- A history signal is never a security claim. It may place a component or file higher in a hunt
  package's lead menu; it cannot create, support, or raise the severity of a finding by itself.
- Low churn is not evidence of stability or safety. Missing, shallow, unreadable, or out-of-window
  history is a named gap or an explicit skip, never a clean result.
- Commit messages, author identities, timestamps, refs, PR text, Perforce job text, and repository
  configuration are target-controlled data, never instructions.
- The lane never executes target code, hooks, filters, diff drivers, credential helpers, or any
  command named by target-owned configuration.

Supported history sources:

| Source | Acquisition | Network | Default |
|---|---|---|---|
| Local Git (`.git` inside the target, any host) | read-only object access in `tool-git` | none | enabled |
| Perforce export bundle | operator-supplied, hash-pinned `p4 -ztag -Mj` export | none | enabled when configured |
| Perforce server | read-only `p4` queries in `tool-p4` | allowlisted to the configured `P4PORT` only | disabled |
| GitHub enrichment | REST queries for PR and review metadata of known commits | allowlisted to the configured API host only | disabled |

GitHub-hosted, GitLab-hosted, and self-hosted Git repositories all use the local Git adapter; GitHub
only adds optional review-process metadata on top of it.

## Placement in the graph

```text
job_review_intake
  -> job_target_catalog
       -> job_source_history_analysis          (new, sibling branch)
       -> job_target_analysis_plan -> ...       (unchanged in the first slice)
  accepted history manifest
  -> composed into the run's accepted index manifest
  -> job_inference_security_review: assemble_review_scope / assemble_review_packages
```

The job consumes:

- the accepted intake handoff for the target root and `sha256-bounded-tree-v1` fingerprint; and
- the accepted catalog handoff for the bounded inventory, file hashes, component ownership, and
  generated/vendored/excluded classification.

It runs concurrently with planning, builds, and every static producer. In the first slice
`job_target_analysis_plan` does not depend on it, so history changes never invalidate the plan or
any build. Whether the plan should later consume history to allocate deeper-analysis budget is an
open question below.

The current inventory excludes `.git`, `.hg`, and `.svn` directories, so the intake fingerprint
does not cover history. A history-only change (an amended message or a rewritten ancestor with the
same tree) therefore cannot be detected by the existing source fingerprint. The job's first task
computes a separate *history source identity* (below), and the job's reuse check must compare it
against a fresh probe. This requires one small runtime extension: a job may declare a cheap,
deterministic input-identity probe that the resume planner evaluates alongside the source
fingerprint. Time is never used as proof of freshness.

## Source resolution and snapshot binding

### Resolution order

`resolve_history_source` produces exactly one decision per configured source, using the existing
`SUCCEEDED`, `SKIPPED_NA`, `SKIPPED_POLICY`, or `GAP` vocabulary:

1. **Git**: a `.git` directory at the target root, or a `.git` gitfile whose `gitdir:` resolves
   inside the target root after symlink-free path validation. A gitfile that escapes the target is
   `GAP: history_source_outside_target`. No `.git` is `SKIPPED_NA: no_git_metadata`.
2. **Perforce export**: configured bundle path and SHA-256. Hash mismatch is a hard integrity
   failure; a missing configuration is `SKIPPED_NA`.
3. **Perforce server**: configured `P4PORT`, depot scope, pinned changelist, and secret reference.
   Disabled is `SKIPPED_POLICY`; unreachable, untrusted fingerprint, or failed authentication is a
   `GAP`.
4. **GitHub enrichment**: configured owner/repo and API host. Disabled is `SKIPPED_POLICY`.

Target-owned locators are never trusted: the job ignores `remote.*.url` from `.git/config`,
`P4CONFIG`/`P4ENVIRO` files and `.p4config` in the tree, and any host, port, or credential named by
target content. Remote identities come only from central configuration.

If no source applies, the job still publishes an accepted handoff with a `history` coverage shard
of zero observations and the skip reasons, so consumers can tell "no history" from "not run".

### Git snapshot binding

History must describe the tree under review, not merely a repository that happens to sit beside
it. The application:

1. Reads `HEAD`, the referenced loose ref or `packed-refs` entry, `shallow`, and the allowlisted
   format keys (`core.repositoryformatversion`, `extensions.objectformat`) with bounded parsers.
   No other repository configuration is read or used.
2. Pins the *snapshot commit* to the resolved commit id. Every later query is the ancestry of that
   one id; other refs are not imported.
3. Compares each accepted inventory file's Git blob id, computed in application code with the
   repository's object format (SHA-1 or SHA-256), with the snapshot commit's tree entry.
   - All match: binding `exact`.
   - Some differ (uncommitted edits, CRLF conversion, clean filters, LFS pointers): binding
     `partial`; each differing path gets `GAP: working_tree_divergent` and its line-level
     attribution is marked non-exact.
   - Inventory files absent from the tree get `GAP: untracked_path`.
   - A snapshot tree that shares no blobs with the inventory is `GAP: history_not_of_snapshot`, and
     no file-level signals are published.

The history source identity is the snapshot commit id, the object format, the hash of the
validated `shallow` file, and the binding result.

### Perforce snapshot binding

Perforce history is bound to a pinned changelist `@N`; an unpinned server configuration is rejected
at configuration load. The adapter compares each inventory file with `p4 fstat -Ol` size and digest
at `@N`, normalizing line endings according to the reported file type. `ktext` keyword expansion,
`+S` purged revisions, and Unicode/UTF-16 types that cannot be compared exactly are per-path
non-exact gaps. The history source identity is the server identity reported by `p4 info`, the
depot scope, `@N`, and the binding result. For an export bundle it is the bundle SHA-256 plus the
same fields recorded inside the bundle.

## Acquisition hardening

### Git

`.git` contents are attacker-controlled. Repository configuration can name fsmonitor, pager, diff,
textconv, filter, editor, SSH, and credential commands; `.gitattributes` can route paths to those
drivers; replace refs and grafts can rewrite apparent history; `.mailmap` can rewrite identities;
alternates can point outside the target; and partial clones attempt lazy network fetches.

Git runs only inside a new pinned `tool-git` image under the central container policy: no network,
non-root, read-only root and target, dropped capabilities, bounded memory, PIDs, time, and output.
Inside the container:

- `GIT_DIR` is a run-owned scratch directory containing only an application-written `config` with
  the allowlisted format keys, a detached `HEAD` set to the snapshot commit, and the validated
  `shallow` file. The target's `config`, hooks, `info/`, refs, and `logs/` are never exposed as
  repository state.
- `GIT_OBJECT_DIRECTORY` points to the read-only mounted `.git/objects`.
  `objects/info/alternates` must be absent or resolve entirely inside the mounted target; otherwise
  the source is `GAP: alternates_unresolvable`.
- `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_ATTR_NOSYSTEM=1`,
  `GIT_NO_REPLACE_OBJECTS=1`, `GIT_TERMINAL_PROMPT=0`, `GIT_OPTIONAL_LOCKS=0`, and a scratch `HOME`.
- Every command passes `--no-ext-diff --no-textconv --no-mailmap` where applicable, plus
  `-c core.fsmonitor=false -c core.hooksPath=/dev/null -c log.showSignature=false` and
  `safe.directory` in command scope only.
- Commands come from a fixed argv allowlist (`log`, `rev-list`, `cat-file`, `ls-tree`,
  `diff-tree`, `blame`) built by application code; no target text is interpolated into options.
- Presence of replace refs, `info/grafts`, a promisor/partial-clone configuration, or submodule
  gitlinks is recorded. Missing promisor objects are `GAP: partial_clone_objects_missing`;
  submodules are `GAP: submodule_history_not_followed` per gitlink in the first slice.

### Perforce

The server adapter runs in a new pinned `tool-p4` image whose only egress is the configured
`P4PORT`. `ssl:` ports require a configured trust fingerprint. The ticket comes from a secret
reference mounted as a run-owned `P4TICKETS` file; `P4CONFIG` is empty, `P4ENVIRO` is
`/dev/null`, and `P4TRUST` is run-owned. Only read commands are allowed: `info`, `changes`,
`describe -s` and `describe -ds`, `filelog`, `fstat`, `annotate`, and `fixes`. Every command is
scoped to the configured depot paths at `@N` and to configured count bounds. Raw `-ztag -Mj`
responses are stored as a protected, hash-identified acquisition snapshot. Resume reuses that
snapshot unless the operator explicitly requests a refresh, which creates a new identity.

The export mode consumes the same record shapes from an operator-produced bundle, so the review
itself needs no network or credentials. The repository will ship the exact export command list as
operator documentation, not as an executable script invoked by the job.

Protections can hide files without any error. The adapter compares the inventory with the visible
depot files and records invisible paths as `GAP: p4_protections_limited`.

### GitHub enrichment

GitHub enrichment queries only commits already present in the bound local history. It first
confirms that the snapshot commit exists in the configured repository. It then collects, under call
and byte bounds: associated pull requests, review states at merge, merger versus author, whether
commits were pushed after the last approval, and linked issue labels. Responses are stored as a
protected, hash-identified acquisition snapshot, and reuse follows the same rule as Perforce.
Rate limiting, partial pagination, and permission errors are gaps. The token comes from a secret
reference and never appears in argv, logs, artifacts, or retrieval shards. GHSA and CVE linkage uses
the offline OSV data already synchronized by `job_third_party_data_sync`, not the live advisory
API.

## Signals

All windows are anchored to the snapshot commit's committer time or the changelist's server date,
never to wall-clock time, so identical inputs give identical outputs. Git timestamps are claimed
data: ordering uses topology, and non-monotonic or future timestamps are recorded as
`timestamp_anomaly` observations and clamped for window membership.

Git walks `--first-parent` ancestry with `--diff-merges=first-parent` and bounded rename detection.
Perforce walks submitted changelists in the depot scope and follows integrations with
`filelog -i` up to a configured depth. Generated, vendored, and excluded paths from the catalog are
counted separately and do not drive ranking. A commit touching more than `bulk_change_file_threshold`
files is flagged `bulk` and excluded from co-change and ownership, but still counted.

| Signal | Unit | Definition (first version) |
|---|---|---|
| `change_count` | file, component | changes touching the unit in the window |
| `churn_lines` | file, component | added + deleted lines (`--numstat` / `describe -ds`) |
| `relative_churn` | file | `churn_lines` / current non-blank lines from the catalog source metrics |
| `recency_weighted_churn` | file, component | churn with exponential decay, half-life from config |
| `author_count`, `minor_author_count` | file, component | distinct authors; authors under the minor-ownership share |
| `top_author_share` | file, component | largest single author's share of changes |
| `fix_change_count` | file, component | changes classified as fixes (below) |
| `security_fix_change_count` | file, component | fixes with security evidence (below) |
| `revert_count` | file, component | changes that are, or are reverted by, an exact revert pair |
| `retouch_interval_median_days` | file | median gap between successive changes |
| `young_line_share` | file | share of current lines whose blame age is under the configured threshold |
| `co_change_partners` | file pair | support and confidence of joint changes, top K per file, cross-component flagged |
| `review_bypass_count` | file, component | GitHub only: merged with no approving review, self-merged, or pushed after approval |

Change classification is deterministic, versioned, and reported with its basis:

- `fix`: Perforce `p4 fixes` job linkage; GitHub-linked issue labels from the configured label
  list; or the versioned message rule set (conventional `fix:` prefixes, configured issue-key
  patterns, and fix/bug vocabulary). Message-only classification is marked `heuristic`.
- `security_fix`: the change id appears as a `fixed` Git event in a synchronized OSV record for a
  package the catalog maps to this target (`exact`); or the message or linked issue references a
  CVE, GHSA, or CWE identifier (`heuristic`).
- `revert`: a Git `This reverts commit <id>` trailer whose id resolves in the bound history, or a
  Perforce undo record (`exact`); a subject-only `Revert "…"` match (`heuristic`).

No model is used in the first version. A later model-assisted classifier would follow the existing
inference contract: centrally configured, preflighted, validated against exact change ids, and
reported as a separate basis.

### Attention ranking

`history_attention` is a deterministic, versioned ranking per file and per component. Each signal
becomes a percentile within the target's eligible population. The rank is a weighted sum using
weights from central TOML, with ties broken by stable path order. The full feature vector, its
percentiles, the ranking version, and the configuration hash are published with every rank;
consumers never receive a bare score. A file with no eligible history gets no rank, not a rank of
zero.

## Outputs

Per attempt:

```text
runs/<run-id>/jobs/job_source_history_analysis/attempts/<attempt>/
  history-source.json        source decisions, identities, binding results, gaps
  acquisition/               protected raw git/p4/GitHub responses and receipts (hash-identified)
  changes.jsonl              normalized changes: id, parents, time, author ordinal, classification,
                             per-path numstat, rename pairs, redacted subject hash
  signals.jsonl              per-file, per-component, and per-pair signal records
  ranking.json               attention ranks with features, percentiles, version, config hash
  handoff.json
```

- **Identity minimization.** Authors are ordinals assigned by first appearance in topological order
  (`author-0001`). Names and emails stay only in the protected acquisition snapshot and are never
  indexed or logged.
- **Message handling.** Messages are untrusted and may contain secrets. Full messages stay
  protected. Subjects are indexed only after the existing gitleaks redaction pass and a byte bound.
  If gitleaks is unavailable, subjects are not indexed (`GAP: message_redaction_unavailable`) while
  numeric signals still publish.
- **Retrieval.** The job publishes one `history` shard per source and component partition, with
  shard ids such as `git/<snapshot-commit-prefix>/<component>`, plus a source-level coverage shard.
  New entity kinds are `change` and `history_signal`. Relations reuse the fixed vocabulary:
  `OBSERVED_AT` from a signal to the current source file or exact current span (via blame),
  `REFERENCES` from a change to CVE, GHSA, or CWE identities, `DERIVED_FROM` from a ranking to its
  signals, and `CONTRADICTS` where classifications disagree. Spans from blame that could not be
  exactly bound are non-exact with an ambiguity reason.
- **Query surface.** Shards are queryable through the existing `search`, `find`, `trace`, and
  `coverage` tools. A dedicated exact-filter `query_history` tool (path, component, change id,
  signal, rank range) is deferred until a consumer needs it, following the `query_build_security`
  precedent.

## Consumers

- **Inference security review.** `assemble_review_scope` lists history coverage and gaps in the
  evidence map. `assemble_review_packages` attaches each hunt package's top-ranked files and
  co-change partners as a bounded menu with change ids and resolving current locations, never as a
  search limit and never as message text. A claim may cite a change as context. Proof still
  requires resolving source lines or a tool artifact.
- **Final report.** The limitations section lists history coverage, binding status, and gaps.
- **Possible later consumers.** The OWASP control assessment could use review-bypass observations
  as process evidence. The analysis plan could use attention ranks for budget allocation. Both are
  open questions.

## Central TOML

```toml
[jobs.job_source_history_analysis]
name = "source_history_analysis"
workers = 4

[jobs.job_source_history_analysis.settings]
window_days = 365
max_changes = 20000
bulk_change_file_threshold = 500
rename_detection_max_files = 2000
recency_half_life_days = 90
minor_author_share = 0.05
young_line_days = 30
co_change_top_k = 10
co_change_min_support = 3
blame_max_files = 2000
blame_max_file_bytes = 1048576
subject_max_bytes = 200
fix_message_rules = "appsec-review/history-fix-rules/1"
fix_issue_labels = ["bug", "security"]
ranking_version = "appsec-review/history-attention/1"

[jobs.job_source_history_analysis.settings.ranking_weights]
recency_weighted_churn = 3
fix_change_count = 3
security_fix_change_count = 4
revert_count = 2
author_count = 1
young_line_share = 1
review_bypass_count = 2

[jobs.job_source_history_analysis.settings.git]
enabled = true

[jobs.job_source_history_analysis.settings.perforce]
mode = "disabled"            # disabled | export | server
export_path = ""
export_sha256 = ""
p4port = ""
trust_fingerprint = ""
depot_paths = []
changelist = 0
ticket_secret = ""
integration_depth = 3

[jobs.job_source_history_analysis.settings.github]
enabled = false
api_host = "api.github.com"
repository = ""              # owner/repo
token_secret = ""
max_requests = 2000

[jobs.job_source_history_analysis.steps.resolve_sources]
[jobs.job_source_history_analysis.steps.resolve_sources.tasks.resolve_history_source]
[jobs.job_source_history_analysis.steps.resolve_sources.tasks.bind_snapshot]

[jobs.job_source_history_analysis.steps.acquire]
[jobs.job_source_history_analysis.steps.acquire.tasks.git_history]
[jobs.job_source_history_analysis.steps.acquire.tasks.perforce_history]
[jobs.job_source_history_analysis.steps.acquire.tasks.github_enrichment]

[jobs.job_source_history_analysis.steps.analyze]
[jobs.job_source_history_analysis.steps.analyze.tasks.normalize_changes]
[jobs.job_source_history_analysis.steps.analyze.tasks.classify_changes]
[jobs.job_source_history_analysis.steps.analyze.tasks.compute_signals]
[jobs.job_source_history_analysis.steps.analyze.tasks.blame_age]
[jobs.job_source_history_analysis.steps.analyze.tasks.co_change]
[jobs.job_source_history_analysis.steps.analyze.tasks.rank]

[jobs.job_source_history_analysis.steps.publish]
[jobs.job_source_history_analysis.steps.publish.tasks.index_history]
[jobs.job_source_history_analysis.steps.publish.tasks.publish_handoff]
```

Configuration validation rejects:

- Perforce server mode without a pinned changelist, trust fingerprint for `ssl:` ports, or ticket
  secret;
- export mode without a SHA-256;
- GitHub enrichment without an explicit repository;
- negative or zero bounds; and
- unknown ranking signals.

The rule-set and ranking versions are code-owned identities, not free-form prompts.

## Fingerprints and invalidation

| Unit | Fingerprint binds |
|---|---|
| acquisition (per source) | history source identity, acquisition argv version, tool image id, bounds, configuration hash; for server/API sources the stored snapshot hash |
| normalized changes | acquisition hashes, normalizer version, accepted catalog manifest (classification of generated/vendored paths) |
| signals and ranking | normalized change hash, OSV snapshot identity, rule-set and ranking versions, settings hash |
| blame age | snapshot commit, the file's blob id, blame bounds, tool image id |
| retrieval shards | signal and ranking hashes, catalog component partition, schema version |

A new commit changes the snapshot commit and invalidates acquisition and everything below it. That
also means its tree changed, so the source fingerprint invalidates upstream jobs as usual. A
changed OSV snapshot invalidates only classification, signals, ranking, and shards. A ranking
weight change invalidates only ranking and shards. Blame is checkpointed per file and blob id, so
unchanged files reuse their blame.

## Gap and decision taxonomy

| Code | Decision | Meaning |
|---|---|---|
| `no_git_metadata`, `perforce_not_configured` | `SKIPPED_NA` | source does not apply |
| `perforce_disabled`, `github_enrichment_disabled` | `SKIPPED_POLICY` | turned off by configuration |
| `history_source_outside_target` | `GAP` | gitfile or alternates escape the target |
| `history_not_of_snapshot` | `GAP` | repository history does not describe the reviewed tree |
| `working_tree_divergent`, `untracked_path` | `GAP` (per path) | file-level attribution unavailable or non-exact |
| `shallow_history` | `GAP` | ancestry truncated at the shallow boundary before the window start |
| `history_window_truncated` | `GAP` | `max_changes` reached before the window start |
| `partial_clone_objects_missing`, `alternates_unresolvable` | `GAP` | objects unreadable offline |
| `submodule_history_not_followed` | `GAP` (per gitlink) | first-slice limitation |
| `replace_refs_ignored`, `grafts_ignored` | observation | rewrite mechanisms present and deliberately ignored |
| `rename_detection_bounded`, `blame_bound_reached` | `GAP` | bounded analysis did not cover every file |
| `p4_server_unavailable`, `p4_auth_failed`, `p4_trust_mismatch` | `GAP` | server acquisition failed |
| `p4_protections_limited`, `p4_digest_mismatch`, `p4_purged_revision` | `GAP` (per path) | depot visibility or binding incomplete |
| `github_rate_limited`, `github_permission_denied`, `github_pagination_incomplete` | `GAP` | enrichment incomplete |
| `message_redaction_unavailable` | `GAP` | subjects withheld from indexing |
| `timestamp_anomaly` | observation | claimed time inconsistent with topology |

Each of the following is a hard failure that blocks publication instead of creating a gap:

- an export-bundle hash mismatch;
- changed accepted target bytes;
- an escaping path in an artifact;
- an image-id mismatch; and
- a corrupt or schema-invalid acquisition snapshot.

## Proposed source, container, and schema locations

```text
src/appsec_review/jobs/job_source_history_analysis/
  job.py           topology, validators, units
  sources.py       resolution, bounded .git/HEAD/refs/shallow parsing, snapshot binding
  git.py           sanitized GIT_DIR assembly and fixed argv builders
  perforce.py      export reader and server argv builders
  github.py        bounded REST client with snapshot storage
  classify.py      versioned fix/security/revert rules
  signals.py       window, churn, ownership, retouch, co-change, blame age
  ranking.py       percentile normalization and weighted ranking
containers/tools/git/tool.toml        pinned git, network none
containers/tools/p4/tool.toml         pinned Helix Core CLI, egress to configured P4PORT only
docs/schemas/source-history-analysis.schema.json
docs/operations/source-history-analysis.md
```

The Helix Core command-line client is distributed under Perforce's own terms. Its license must be
reviewed before the image is cataloged, as with other non-open-source tools.

## Tests

Fixture repositories are created by the tests under `test/tmp/`, not committed as nested
repositories.

- **Unit tests:** bounded `HEAD`, `packed-refs`, `shallow`, and gitfile parsers; blob-id
  computation for SHA-1 and SHA-256; window anchoring and decay; percentile ranking and tie order;
  classification rules and their `exact`/`heuristic` basis; revert pairing; author ordinals; and
  configuration validation.
- **Determinism tests:** identical history gives byte-identical `changes.jsonl`, `signals.jsonl`,
  and `ranking.json` regardless of wall-clock time and worker count.
- **Adversarial tests:** a target `.git/config` naming `core.fsmonitor`, `core.pager`,
  `diff.external`, a textconv driver, a clean/smudge filter, `core.sshCommand`, and a credential
  helper, plus executable hooks and `.gitattributes` routing, must not create a canary file. Other
  cases cover escaping alternates and gitfiles, replace refs and grafts, forged and non-monotonic
  timestamps, a `.mailmap` impersonation, a huge bulk commit, prompt-injection text in messages and
  PR bodies, secrets in messages, a target `.p4config` naming another server, and LFS pointers.
- **Binding tests:** exact, partial, untracked, and unrelated-history targets, plus a shallow clone
  whose boundary falls inside the window.
- **Perforce tests:** a recorded export bundle exercises normalization, `fixes` linkage,
  integrations, `ktext` mismatch, and protections-limited paths without a live server. A
  server-mode test runs only when an operator-provided test server is configured.
- **Integration tests:** the Dagster graph runs the job as a sibling branch, reuses it when only an
  unrelated producer changes, invalidates it on a new commit, and composes its shards. MCP `search`
  and `coverage` return history records with resolving locations and gaps.

## Implementation slices

1. **Local Git, file and component churn.** Source resolution, snapshot binding, the hardened
   `tool-git` image, first-parent changes in the window, `change_count`, `churn_lines`,
   `relative_churn`, `recency_weighted_churn`, author counts, message-rule and OSV-exact
   classification, revert pairs, ranking, the coverage and `history` shards, the gap taxonomy, and
   the runtime input-identity probe.
2. **Depth.** Blame age with per-file checkpoints, co-change coupling, rename following, gitleaks
   subject redaction and indexing, and attachment to hunt packages.
3. **Perforce.** Export mode first, then server mode in `tool-p4`, with `fixes` linkage and
   integration following.
4. **GitHub enrichment.** PR and review metadata, `review_bypass_count`, and issue-label
   classification.
5. **Finer granularity.** Join blame spans to Tree-sitter function nodes for function-level
   signals; add `query_history` if consumers need exact filters.

## Open questions

- Should `job_target_analysis_plan` consume attention ranks to allocate deeper-analysis budget?
  That would let a history-only change invalidate the plan and every build below it.
- Should submodule histories be followed as independent sources, each bound to its gitlink commit?
- Is `--first-parent` the right default for merge-heavy repositories, or should a branch-aware mode
  attribute merged work to its original commits?
- Should secrets that exist only in history, through gitleaks history mode, be scanned here or as
  a separate evidence-collection producer? It is a real security signal, but it is evidence rather
  than prioritization, so it likely belongs in evidence collection and should only read this job's
  bound source identity.
