# CodeQL code-graph export pack

This directory holds the hash-pinned CodeQL export queries, the column contract and the
source/sink catalog for code-graph precomputation
([`docs/architecture/code-graph-precomputation.md`](../../docs/architecture/code-graph-precomputation.md),
chunk C1). It is rule data. It defines no job, prompt or worker guidance. Only C/C++ is covered in
this change.

| Path | Content |
|---|---|
| `cpp/` | The query pack `appsec-review/graph-export-cpp` 1.0.0: `qlpack.yml`, `graph-export.qls`, the shared library `GraphExport.qll` and the seven queries `CallSites`, `SinkSites`, `SourceSites`, `FlowSummaries`, `Paths`, `Guards` and `Ranges`. |
| `columns.json` | `appsec-review/codeql-graph-export-columns/1`: the closed, ordered column contract for every export `query_id`. This is the C1 → C3 format contract. |
| `catalog.json`, `catalog.schema.json` | `appsec-review/graph-catalog/1`: classifies export rows into the closed `SinkClass`/`SourceClass` vocabularies of `src/appsec_review/graph/contract.py`. |

## Status: live-unverified

The QL is written against the `codeql/cpp-all` library bundled with the pinned CodeQL 2.27.0 CLI,
but the repository's offline CI has no CodeQL image, so it has not been compiled.
`tests/live/test_codeql_graph_export_live.py` compiles and runs it on the pinned image and
compares the result with the native recording. The recorded fixtures are hand-authored until that
test refreshes the native one (see each fixture's `provenance.json`).

## Export contract

The export queries contain only `query predicate`s with primitive `string`/`int` columns. They
have no `select` clause and no entity columns, so no CodeQL element id leaves the database. Each
query predicate is one export, its result-set name is the `query_id`, and the export objects are:

| `query_id` | Query | Graph family |
|---|---|---|
| `call_sites` | `CallSites.ql` | `call_site` |
| `sink_sites` | `SinkSites.ql` | `sink_site` |
| `source_sites` | `SourceSites.ql` | `entry_point` |
| `flow_summaries` | `FlowSummaries.ql` | `flow_summary` |
| `path_flows`, `path_edges`, `path_sanitizers` | `Paths.ql` | `dataflow_path` |
| `guards` | `Guards.ql` | `guard_fact` |
| `ranges`, `range_conversions` | `Ranges.ql` | `range_fact` |

`columns.json` lists, for each `query_id`, the exact ordered column names, their type and their
meaning. The QL parameter names equal those names (enforced by
`tests/test_codeql_export_runner.py`). A column change is a contract change: it updates the QL,
`columns.json`, the lock entry, the recordings and the normalizer in one change.

Column conventions:

- A location is five columns, `<p>_path`, `<p>_start_line`, `<p>_start_column`, `<p>_end_line`
  and `<p>_end_column`. The path is relative to the CodeQL database source root
  (`File.getRelativePath()`, POSIX), lines and columns are 1-based, and the end column is
  inclusive. An element outside the source root exports path `""` and zero positions. Function
  locations export only path, start line and start column (`Function.getLocation()`, the
  declarator name). Byte offsets are not exported: the normalizer derives them from the accepted
  source bytes.
- Booleans are the strings `"true"` and `"false"`.
- A sink is keyed by its sink expression span plus `argument_index`. The sink expression is the
  call or the array write. `argument_index` is `-1` when the operand is not a call argument. A
  source is keyed by its dataflow-node span. `path_*` rows are keyed by the source key followed by
  the sink key. `guards`, `ranges` and `range_conversions` rows carry the sink key.
- `sink_sites` emits one row per `(sink, argument_index, model)`. A catalog API match (`model =
  "api"`) suppresses every model match on the same call.
- `guards` emits one `none` row per sink that no guard controls. Its condition columns are `""`
  and `0`. Non-dominating and post-dominating guards are listed only when they mention a variable
  of the sink operand.
- `ranges` emits `"unknown"` for a bound equal to the operand type's extreme. A finite bound is
  CodeQL's `float.toString()`, for example `"63.0"`. Non-integral operands have applicability
  `not_applicable` and empty bounds.
- `Paths.ql` exports every flow and every path-graph edge on a flow. The bounded selection of
  `max_paths_per_sink` shortest paths with at most `max_path_steps` steps is applied downstream
  over `path_edges`. The query configures no barrier, so a sanitized path stays visible and its
  sanitizer is listed in `path_sanitizers`.

Each raw export file is one `appsec-review/codeql-graph-export/1` object (`EXPORT_SCHEMA`,
checked by `contract.validate_export`) with exactly the keys `schema`, `query_id`, `columns`,
`rows`, `row_count`, `truncated` and `bqrs_sha256`. Rows are sorted by their tuple of `str(value)`.
`row_count` is CodeQL's total row count from `bqrs info`. `truncated` is true when that exceeds the
decoded rows, which are then the first `row_limit` rows in BQRS order.

## File layout and runner action

The runner action `export` (`containers/tools/codeql/codeql_runner.py`) runs inside the derived
CodeQL image with `--network none`. All of its paths are relative to the execution scratch:

```text
export --database <db-copy> --pack <staged-pack-dir> --columns <staged columns.json>
       --asset-lock <staged assets.lock.json> --language cpp --output-dir <dir>
       --row-limit <n> --max-bytes <n> --threads <n> --ram <mb>
```

`appsec_review.codeql.runtime.graph_export_arguments` builds this argv. The job stages a copy of
`cpp/` and of `columns.json` into scratch, together with a disposable copy of the database: the
pack is repository-owned and is not part of the licensed image. The runner then:

1. checks that the staged pack's location-independent tree hash (`sha256  relative/path` lines,
   sorted by relative path), file count, `qlpack.yml`, suite and `columns.json` equal
   `export_query_packs.cpp` in `containers/tools/codeql/assets.lock.json`;
2. runs `codeql database run-queries --threads --ram -- <db> <pack>/graph-export.qls`;
3. for each `query_id` in `columns.json` order, runs `codeql bqrs info --format=json` to get the
   true row count and the column arity, then `codeql bqrs decode --format=json --result-set
   <query_id> --rows <row-limit>`;
4. writes `<output-dir>/<query_id>.json` (canonical JSON) and `<output-dir>/export-manifest.json`.

`export-manifest.json` (`appsec-review/codeql-graph-export-manifest/1`) records the language, the
pack identity, the bounds, and for each export its `path`, `sha256`, `bytes`, `row_count`,
`exported_rows`, `truncated`, `bqrs_sha256` and `decode_ms`. The output directory holds exactly
these files. `appsec_review.codeql.runtime.load_graph_exports` re-verifies a directory against
its manifest and the export contract. Any extra, missing or changed file is a
`GraphExportIntegrityError`. Exceeding `--max-bytes`, a missing result set, an arity mismatch or a
non-primitive cell fails the action (exit 2), and the job records a scope gap.

## Catalog semantics (`appsec-review/graph-catalog/1`)

A rule's `match` names either a CodeQL model (`model`, plus `source_type` for sources) or an API
(`api`, `declared_in`, and `argument_index` for sinks or `index` for sources). A row matches an API
rule when `api` and the index are equal and any comma-separated basename in the row's
`declared_in` is listed in the rule. Classification of one row tries, in order:

1. API rules;
2. model rules with `source_type` (sources only), matched on `model` and `source_type`;
3. model-only rules, matched on `model`.

Within one tier, the first rule in file order wins, and the tests forbid two rules with the same
match. A row that no rule matches is `unclassified` and is never `direct_eligible`. The catalog
deliberately has no rule for `RemoteFlowSinkFunction` (data sent to the network), which is
therefore the reference unclassified sink. When two `sink_sites` rows share a sink key, the one
whose winning rule comes first in the tier order is kept. `attacker_reachable_sources` must equal
`contract.ATTACKER_REACHABLE_SOURCES`. Sanitizer rules list the APIs `SinkSites.ql` counts as
dominating sanitizers and `Paths.ql` lists on paths. The API names in `GraphExport.qll`
(`apiSinkArgument`, `apiSourceArgument`, `sanitizerApi`) must equal the catalog's API rules, and
the tests enforce this.

## Changing the pack or catalog

1. Edit the QL, `columns.json` or `catalog.json`.
2. Recompute the `export_query_packs.cpp` entry in `containers/tools/codeql/assets.lock.json`:
   the tree hash and file count of `cpp/`, and the SHA-256 of `qlpack.yml`, `graph-export.qls`,
   `columns.json` and `catalog.json`. `tests/test_codeql_export_runner.py` fails until they agree.
3. Update `jobs.job_codeql_analysis.settings.asset_lock_sha256` in `appsec-review.toml` to the
   new lock SHA-256.
4. Run the live tier and refresh `tests/fixtures/graph/codeql_export/native/` in the same change.
