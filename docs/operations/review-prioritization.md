# Review prioritization operations

`job_review_prioritization` ranks files and functions for LLM review from structural complexity,
import coupling, suppressions, boundary and privilege heuristics, CodeQL source-to-sink paths, and
accepted history hotspots. Its output orders review attention only; a ranked item is never a
finding, and missing coverage is a named gap. Design and metric definitions:
[`../architecture/review-prioritization.md`](../architecture/review-prioritization.md).

## Running

The job runs inside Dagster's `wave1_review` after CodeQL and OWASP control assessment and before
security tagging. It is also the standalone Dagster job `review_prioritization`; launch it with the
`appsec/application_run_id` tag of a run that already has accepted intake, catalog, and Tree-sitter
handoffs. It needs no container image: it runs in the application process over accepted artifacts
and hash-verified target bytes. It is not part of the direct CLI `start`/`resume` graph, which does
not produce Tree-sitter ASTs.

Required inputs are the accepted intake, catalog, and `job_tree_sitter_ast` handoffs. History,
Semgrep (evidence collection), and CodeQL handoffs are optional. When one is absent or failed, the
job still publishes and names the gap (`history_hotspots_unavailable`,
`semgrep_review_signals_unavailable`, `semantic_paths_unavailable`), and the affected feature is
missing rather than zero. The review then ends `COMPLETED_WITH_GAPS`.

The Semgrep pattern pack `rules/semgrep/review-signals.yml` runs in the existing evidence-collection
Semgrep execution next to `security.yml`; no extra tool run is needed.

## Configuration

All settings live under `[jobs.job_review_prioritization.settings]` in `appsec-review.toml`:

| Setting | Default | Effect |
|---|---|---|
| `max_files`, `max_file_bytes`, `max_functions` | 50000, 2 MiB, 500000 | bounds on scored files and units; reaching one is a named gap |
| `max_signals_per_file` | 200 | stored signal and suppression records per file (counts stay complete) |
| `max_import_records`, `max_semantic_paths` | 500000, 5000 | import outcomes resolved; shortest CodeQL paths kept |
| `cyclomatic_thresholds`, `scored_threshold` | `[10, 15]`, 15 | thresholds for "functions above threshold"; the score uses `scored_threshold` |
| `count_error_propagation` | `true` | count Rust `?` and Go `if err != nil { return }` as decisions (both or neither) |
| `min_edge_confidence` | 0.8 | lowest import-resolution confidence counted in Ca/Ce |
| `custom_parsing_min_operations`, `custom_parsing_min_density` | 6, 0.5 | dense manual decoding threshold per unit |
| `state_mutation_min_operations` | 3 | multi-mutation threshold per unit |
| `normalization_population` | `"run"` | `"language"` normalizes each language separately |
| `[…settings.priority_weights]` | see design | non-negative weight per feature; at least one positive; unknown names are rejected |
| `[…settings.index]` | 25% of files, 10% of functions, cap 5000 | `*_top_count > 0` selects an exact count instead of the fraction; `max_evidence_links_per_item` bounds evidence links |
| `[…settings.sources]` | all `true` | `false` skips consuming history, Semgrep, or CodeQL by policy (a named gap) |

Validation rejects out-of-range bounds, unsorted or duplicate thresholds, a `scored_threshold` that
is not listed, unknown features, negative weights, and a configuration without a positive weight.

## Outputs

- `runs/<run-id>/data/jobs/job_review_prioritization/…/review-prioritization.json`: the accepted
  document with metric and rule identities, cognitive-complexity deviations, source dispositions,
  settings, per-language summaries, top files and functions, gaps, and the index manifest.
- Attempt artifacts: `syntax-facts.json`, `dependency-graph.json`, `semantic-evidence.json`, and
  `priority.json` (the complete ranking with every feature vector).
- Retrieval index `priority`, shard `review-prioritization`, composed into the accepted manifest.

## Retrieval examples

Use the generic retrieval tools; there is no prioritization-specific tool. In Python:

```python
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
# What was not covered.
core.coverage(indexes=("priority",))
```

Through the MCP gateway the same calls are `search`, `find`, `trace`, and `coverage` with
`"indexes": ["priority"]`. Each `priority_item` payload carries `features`, `percentiles`,
`missing_features`, `feature_coverage`, `rank`, `score`, and bounded `evidence`; read
`missing_features` and the coverage rows before treating a low rank as low risk.

## Coverage limits

- Scored languages: C, C++, Java, C#, Go, JavaScript, TypeScript/TSX, Rust, PHP. Other inventory
  languages, including Python, are `language_not_scored` gaps.
- A truncated or unparsed syntax tree removes the file from scoring (`ast_truncated`,
  `ast_unavailable`). Raise the Tree-sitter node bounds in `[jobs.job_tree_sitter_ast.settings]` and
  rerun from `job_tree_sitter_ast` to cover large files.
- Parse errors keep the file but flag affected units; preprocessor and macro control flow is not
  counted.
- Coupling is a lower bound wherever imports are unresolved or dynamic; build-system include paths,
  tsconfig aliases, and implicit same-package references are not evaluated.
- Semantic paths exist only for languages whose CodeQL path-problem queries succeeded.

## Recovery

The job is deterministic over its accepted inputs. Resume reuses it while the Tree-sitter, history,
Semgrep, and CodeQL handoffs, configuration, and implementation are unchanged, and reruns it when any
upstream handoff changes. Do not edit accepted pointers or delete shards to force a rerun; rerun the
upstream job or launch from `job_review_prioritization`.

## Fixture maintenance

`tests/fixtures/review_prioritization/target/` holds small multi-language sources, and
`ast-golden.json.gz` is the generated Tree-sitter output for them. After editing a fixture, run
`python tests/fixtures/review_prioritization/generate_ast.py` in an environment with the pinned
`tree-sitter==0.26.0` and `tree-sitter-language-pack==1.12.5` wheels. The tests fail if the golden
no longer matches the fixture bytes, and re-parse and compare when those wheels are installed.
