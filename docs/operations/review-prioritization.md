---
title: "Review prioritization operations"
kind: "operations"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_review_prioritization", "job_tree_sitter_ast"]
last reconciled: "ea03df9695991eafe37065717624278af845a74c"
---
# Review prioritization operations

`job_review_prioritization` ranks files and functions for LLM review from structural complexity,
import coupling, suppressions, boundary and privilege heuristics, CodeQL source-to-sink paths, and
accepted history hotspots. Its output orders review attention only; a ranked item is never a
finding, and missing coverage is a named gap. Design and metric definitions:
[`../architecture/review-prioritization.md`](../architecture/review-prioritization.md).

## Running

The job runs inside Dagster's `wave1_review` after CodeQL and before code-graph indexing, security
tagging and the default-enabled OWASP control assessment. Its rankings route OWASP work but are not control
proof. It is also the standalone Dagster job `review_prioritization`; launch it with the
`appsec/application_run_id` tag of a run that already has accepted intake, catalog, and Tree-sitter
handoffs. It needs no container image: it runs in the application process over accepted artifacts
and hash-verified target bytes. The direct CLI `start`/`resume` graph runs Tree-sitter first and
then this job after CodeQL.

Required inputs are the accepted intake, catalog, and `job_tree_sitter_ast` handoffs. History,
Semgrep (evidence collection), and CodeQL handoffs are optional. When one is absent or failed, the
job still publishes and names the gap (`history_hotspots_unavailable`,
`semgrep_review_signals_unavailable`, `semantic_paths_unavailable`), and the affected feature is
missing rather than zero. The review then ends `COMPLETED_WITH_GAPS`.

History may contain several accepted repository-specific signal documents. Their file/symbol
maps are merged with exact identities; overlapping paths fail rather than overwrite one source
with another. Per-source missing rankings remain gaps even when another source contributes.
See [composed history inputs](../architecture/review-prioritization.md#history-from-composed-sources).

The Semgrep pattern pack `rules/semgrep/review-signals.yml` runs in the existing evidence-collection
Semgrep execution next to `security.yml`; no extra tool run is needed.

## Configuration

All settings live under `[jobs.job_review_prioritization.settings]` in `appsec-review.toml`:

| Setting | Default | Effect |
|---|---|---|
| `max_files`, `max_file_bytes`, `max_functions` | 50000, 2 MiB, 500000 | bounds on scored files and units; reaching one is a named gap |
| `max_signals_per_file` | 200 | stored signal and suppression records per file (counts stay complete) |
| `max_import_records`, `max_semantic_paths`, `max_flow_steps_per_path` | 500000, 5000, 128 | import outcomes resolved; shortest bounded CodeQL paths and their steps kept |
| `cyclomatic_thresholds`, `scored_threshold` | `[10, 15]`, 15 | thresholds for "functions above threshold"; the score uses `scored_threshold` |
| `count_error_propagation` | `true` | count Rust `?` and Go `if err != nil { return }` as decisions (both or neither) |
| `min_edge_confidence` | 0.8 | lowest import-resolution confidence counted in Ca/Ce |
| `custom_parsing_min_operations`, `custom_parsing_min_density` | 6, 0.5 | dense manual decoding threshold per unit |
| `state_mutation_min_operations` | 3 | multi-mutation threshold per unit |
| `normalization_population` | `"run"` | `"language"` normalizes each language separately |
| `[…settings.priority_weights]` | see design | non-negative weight per feature; at least one positive; unknown names are rejected |
| `[…settings.index]` | 25% of files, 10% of functions, cap 5000 | `*_top_count > 0` selects an exact count instead of the fraction; `max_evidence_links_per_item` bounds evidence links and `max_graph_neighbors` bounds one-hop import context (default 5000) |
| `[…settings.sources]` | all `true` | `false` skips consuming history, Semgrep, or CodeQL by policy (a named gap) |
| `[…settings.syntax_metrics_reservation]` | `cpu = 1`, `memory_mb = 2048`, `io_slots = 0`, `admission_timeout_seconds = 3600` | resource admission lease held by `extract.syntax_metrics` for its whole extent, counted against `[review_policy.resources]` alongside scanner containers; a reservation larger than that budget fails the step before any work |

Validation rejects out-of-range bounds, unsorted or duplicate thresholds, a `scored_threshold` that
is not listed, unknown features, negative weights, a configuration without a positive weight, and a
reservation that is missing a key, has an extra key, or holds a non-integer or out-of-range value.

`extract.syntax_metrics` streams: it indexes the byte spans of accepted Tree-sitter rows in a scratch
SQLite file under the unit directory, loads one file's rows and bytes at a time, and writes
`syntax-facts.json` record by record. Its memory follows the largest scored file, not the target
tree. Files are pre-filtered from catalog metadata before any row or byte is read, and the step output
and `REVIEW_PRIORITIZATION_SYNTAX_EXTRACTED` event count them under `skipped`: `not_source` (no
catalog language, such as binary or media files), `out_of_delivery_scope`, and `file_byte_bound`
(larger than `max_file_bytes`; also a `file_byte_bound_reached` gap). A skipped file is unscored
coverage, never evidence that it is clean.

## Outputs

- `runs/<run-id>/data/jobs/job_review_prioritization/…/review-prioritization.json`: the accepted
  document with metric and rule identities, cognitive-complexity deviations, source dispositions,
  settings, per-language summaries, top files and functions, gaps, and the index manifest.
- Attempt artifacts: `syntax-facts.json`, `dependency-graph.json`, `semantic-evidence.json`, and
  `priority.json` (the complete ranking with every feature vector).
- Retrieval index `priority`, shard `review-prioritization`, composed into the accepted manifest.

### Promoted leads and hunt delivery

[T-5177](../TODO.md) publishes every promoted CI/artifact/SCA lead and every extracted
SAST-silence hunt candidate as a separate `review_signal` in the accepted `priority` shard.
`routing_kind` distinguishes `promoted_lead` from `hunt_candidate`; `routing_ordinal` retains the
producer's queue order. These populations retain their upstream/extraction bounds and are not
silently reduced to the selected `priority_item` prefix (`max_indexed_items`).

Each record is provisional navigation, not scanner evidence or a confirmed finding. It retains
the run, target snapshot, resolving ranking artifact hash, available source location, and, for
promoted leads, the original producer handoff/attempt pin. Hunt records retain the normalized
score contract and the item's coverage qualifications.

Package assembly reads these records through the existing `priority_items` input permission,
with dataset read receipts. It includes them as `priority` context in matching source/lead units
and lead packages; the full hunt population also contributes its normalized LPS to matching units.
Existing hunt selection, context and package-byte bounds still apply. Every routing entity not
delivered in a resulting package is a named, identity-specific truncation gap, including records
with no matching source or lead. This does not add worker tools, create scanner findings, or
grant workers access to the ranking artifact.

For an operation-specific unit, a function route must contain the operation's exact byte span
in the same source hash. The unique innermost matching function owns the route; line-only
containment cannot join byte-disjoint same-line siblings. Missing or conflicting ownership does
not contribute a function route or its LPS to the operation. Whole-file fallback context remains
available under its existing bounds.

## Retrieval examples

Use the generic retrieval tools; there is no prioritization-specific tool. In Python:

```python
from pathlib import Path
from appsec_review.retrieval import RetrievalCore

core = RetrievalCore(Path("runs"), "2026-10-10-0001")
# Highest-priority functions with their feature vectors and evidence ids.
core.search(query="review priority function", indexes=("priority",), kinds=("priority_item",), limit=20)
# The ranked items for one file.
core.find(kind="priority_item", path="go/server/handler.go", indexes=("priority",))
# Why an item ranks where it does: its signals, suppressions, and CodeQL paths.
core.trace(identity="asr:priority_item:<sha256>", relations=("DERIVED_FROM",), depth=1)
# Privilege-shift and semantic-path evidence across the indexed items.
core.search(query="privilege_shift insecure_verification", indexes=("priority",), kinds=("review_signal",))
core.search(query="semantic_path", indexes=("priority",), kinds=("review_signal",))
# Given a semantic-path review_signal identity, inspect the ordered graph and exact step locations.
core.trace(identity="asr:review_signal:<sha256>", relations=("CONTAINS", "FLOWS_TO"), depth=3)
core.find(kind="review_flow_step", indexes=("priority",), limit=20)
# What was not covered.
core.coverage(indexes=("priority",))
```

Through the MCP gateway the same calls are `search`, `find`, `trace`, and `coverage` with
`"indexes": ["priority"]`. Each `priority_item` payload carries `features`, `percentiles`,
`missing_features`, `feature_coverage`, `rank`, `score`, and bounded `evidence`; read
`missing_features` and the coverage rows before treating a low rank as low risk.

## Composite score contract

[T-5084](../TODO.md) defines `appsec-review/composite-prioritization-score/1`. The base
weighted-percentile score retains `appsec-review/llm-prioritization-score/1`; it is not a percentage.
For one frozen run configuration:

```text
raw_score = base_score + sum(composite_modifiers)
maximum = 1 + sum(enabled configured boost maxima)
score = raw_score / maximum
```

Each boost's factor is in `[0, 1]`, and each can reach one:

| Boost | Factor bound |
|---|---|
| change context | clamped upstream change score, including its security bonus |
| uncovered risk | uncovered ratio times clamped complexity/surface factor |
| profile hot path | clamped rank/population or count/max-count factor; function fallbacks only reduce it |
| SCA reachability | clamped reachability/FFI factor; function fallbacks only reduce it |
| SAST-silence hunt | reach, surface and complexity multipliers, each at most one |

Use the enabled weights rounded to the existing six-decimal modifier precision for the maxima
and sum them with the base maximum of one. Disabled sources contribute zero; enabled-but-missing
sources retain their configured maximum. With all default boosts enabled the divisor is `1.87`,
even when an upstream artifact is unavailable. Invalid/nonfinite weights or an overflowing
configured total are rejected. There is no new arbitrary weight ceiling.

`sast_silence_min_complexity` must be a non-negative integer. Zero retains the existing
no-complexity-floor behavior, and an omitted value uses the typed default of five. Explicit
negative, boolean, string, fractional, null or nonfinite values fail validation instead of
silently changing the hunt policy or falling back to five. No upper ceiling is added.
Within that fixed configuration, increasing a contribution cannot reduce the score. Scores from
different configurations have different divisors and are not absolute cross-run comparisons.

The producer retains `base_score`, every `composite_modifiers` term and `raw_score` for attribution,
orders by raw score with its existing deterministic tie-breakers, and does not round the normalized
quotient again. The ranking, indexed items, summary and hunt queue carry the normalized score.
`score_normalization` records the rule, maximum, per-boost maxima and SHA-256 of the exact job
settings. This metadata and the rule participate in the immutable index fingerprint; indexing and
summary publication reject cached rankings from another score rule or configuration.

Review units scale this explicitly versioned normalized score linearly to `ranking.lps`, retaining
the configured per-signal bound and existing integer-point rounding/tie-breakers. They never infer
this score's scale from whether it exceeds one. Unsupported versioned scores, including old raw
composite items (even those below one), remain unknown rather than being silently reinterpreted.
The existing unversioned legacy-signal conversion and history-signal conversion are unchanged.
Recompute old composite artifacts through the normal admitted rerun; do not relabel or edit them.

## Coverage limits

- Scored languages: C, C++, Java, C#, Go, JavaScript, TypeScript/TSX, Rust, PHP, Ruby
  (`SCORED_LANGUAGES` in `job_review_prioritization/job.py`). Other inventory
  languages, including Python, are `language_not_scored` gaps.
- A truncated or unparsed syntax tree removes the file from scoring (`ast_truncated`,
  `ast_unavailable`). Raise the Tree-sitter node bounds in `[jobs.job_tree_sitter_ast.settings]` and
  rerun from `job_tree_sitter_ast` to cover large files.
- Parse errors keep the file but flag affected units; preprocessor and macro control flow is not
  counted.
- Coupling is a lower bound wherever imports are unresolved or dynamic; build-system include paths,
  tsconfig aliases, and implicit same-package references are not evaluated.
- Import-budget omissions and resolved targets excluded from the syntax population carry explicit
  per-file counts and module-shared coupling gaps. Unexamined imports can affect incoming coupling
  in any module. Ca/Ce remain observed lower-bound counts; a qualified instability ratio is `null`,
  not an exact zero, for files, modules and components alike. Functions inherit their file's qualification.
- CodeQL coverage retains every scope/root/build-unit/query-profile disposition. A successful
  scope cannot hide a failed profile or another failed scope. Missing matching scope coverage is
  unknown. Path/step bounds, unbound paths and missing locations qualify affected items; positive
  path counts survive as lower bounds, but an unobserved zero becomes `null`.
- Signal and suppression evidence are bounded independently. `signals_truncated:N` and
  `suppressions_truncated:N` retain exact omitted-record counts while the extracted totals remain
  complete.
- Semantic function attribution ([T-5179](../TODO.md)) uses accepted byte offsets or columns
  resolved against hash-verified source bytes, choosing the unique containing innermost byte span.
  Same-line siblings and nested functions are not resolved by choosing the latest declaration.
  Line-only ambiguous locations, invalid positions, and non-ASCII columns whose encoding was
  not retained remain unassigned with `semantic_function_attribution_unavailable`; file-level
  evidence is preserved. Explicit byte offsets still resolve non-ASCII source positions.
  SARIF region provenance distinguishes absent columns from the normalizer's display default
  of column 1. Possible owning functions retain attribution gaps in their published feature
  vectors: zero without ownership evidence is `null`, and positive observed counts stay
  qualified rather than becoming complete coverage.

## Recovery

The job is deterministic over its accepted inputs. Resume reuses it while the Tree-sitter, history,
Semgrep, and CodeQL handoffs, configuration, and implementation are unchanged, and reruns it when any
upstream handoff changes. Do not edit accepted pointers or delete shards to force a rerun; rerun the
upstream job or launch from `job_review_prioritization`.

[T-5178](../TODO.md) keeps local index-build gaps in both the immutable shard coverage and an
attempt-owned `index-checkpoint-<fingerprint>.json`. Re-executing the index unit verifies the
checkpoint's shard digest and its exact local gaps before reuse; it does not erase dependency
context truncation on a cache hit. A missing checkpoint reconstructs and compares the deterministic
shard before recording it, while changed shard bytes or inconsistent checkpoint gaps fail closed.
The manifest carries all aggregate gap reasons; bounded display summaries are not substitutes for
that accounting. These are offline publication guarantees, not evidence that a live review passed.

## Fixture maintenance

`tests/fixtures/review_prioritization/target/` holds small multi-language sources, and
`ast-golden.json.gz` is the generated Tree-sitter output for them. After editing a fixture, run
`python tests/fixtures/review_prioritization/generate_ast.py` in an environment with the pinned
`tree-sitter==0.26.0` and `tree-sitter-language-pack==1.12.5` wheels. The tests fail if the golden
no longer matches the fixture bytes, and re-parse and compare when those wheels are installed.


## Tuning and whole-job recovery: `job_review_prioritization`

Defaults below are the checked-in base recipe; the admitted profile/overlay may override them.
Only the exact declared leaves are mutable; unknown and mixed material changes are refused.

| Exact path relative to this job (unless global) | Base default | Category | Bounds |
| --- | --- | --- | --- |
| `settings.index.max_evidence_links_per_item` | `50` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.index.max_graph_neighbors` | `5000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.index.max_indexed_items` | `5000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_file_bytes` | `2097152` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_files` | `50000` | coverage | 1..1000000; cross-field checks apply |
| `settings.max_flow_steps_per_path` | `128` | coverage | 2..10000; cross-field checks apply |
| `settings.max_functions` | `500000` | coverage | 1..5000000; cross-field checks apply |
| `settings.max_import_records` | `500000` | coverage | 1..5000000; cross-field checks apply |
| `settings.max_semantic_paths` | `5000` | coverage | 0..1000000; cross-field checks apply |
| `settings.max_signals_per_file` | `200` | coverage | 1..100000; cross-field checks apply |
| `settings.syntax_metrics_reservation.admission_timeout_seconds` | `3600` | execution | positive integer; exact parser/cross-field bounds† |
| `settings.syntax_metrics_reservation.cpu` | `1` | execution | 1..256; cross-field checks apply |
| `settings.syntax_metrics_reservation.io_slots` | `0` | execution | 0..256; cross-field checks apply |
| `settings.syntax_metrics_reservation.memory_mb` | `2048` | execution | positive integer; exact parser/cross-field bounds† |

† The [executing job/parser](../../src/appsec_review/jobs/job_review_prioritization/job.py) remains the bounds authority, including hard maxima, numeric types and cross-field checks; compatibility never widens it. A type-only range in this table is not permission to bypass stricter parser limits.

Execution changes affect only new attempts. Coverage changes preserve accepted results with their original limits and gaps; expanded coverage requires an explicit whole-job rerun and reconsideration of affected downstream jobs. New/failed attempts execute every unit, without salvaging earlier cells. Retained accepted jobs are validated with their original configuration. Global scheduler/resource tuning does not alter tool/sandbox authority or resize active leases. See [general tuning](../architecture/runtime-interchange.md#operational-configuration-compatibility-and-attempt-ownership).

### Specifically excluded candidates

| Exact setting | Technical reason it remains material |
| --- | --- |
| `workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `settings.scored_threshold` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.count_error_propagation` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `settings.min_edge_confidence` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.custom_parsing_min_operations` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.custom_parsing_min_density` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.state_mutation_min_operations` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.sast_silence_min_complexity` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.composite_weights.change_context_boost` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.composite_weights.uncovered_risk_boost` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.composite_weights.profile_hotpath_boost` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.composite_weights.sca_reachability_boost` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.composite_weights.sast_silence_hunt_boost` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.cyclomatic` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.cognitive` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.complexity_density` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.share_above_threshold` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.afferent_coupling` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.efferent_coupling` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.instability` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.suppression_density` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.ingress` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.sink` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.privilege_shift` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.sensitive_wrapper` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.state_mutation` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.custom_parsing` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.public_api` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.parser` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.validator` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.middleware` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.semantic_path` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.priority_weights.history_hotspot` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.index.file_top_fraction` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.index.file_top_count` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.index.function_top_fraction` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.index.function_top_count` | Changes scoring, graph-confidence predicates or rank-selection policy, rather than an execution/coverage ceiling. |
| `settings.sources.history` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `settings.sources.semgrep` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `settings.sources.codeql` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `steps.load.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.extract.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.prioritize.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.publish.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |

Source/rule/tool/schema identities, model/provider/reasoning, input selection and signing/authorization remain material even when not numeric.
