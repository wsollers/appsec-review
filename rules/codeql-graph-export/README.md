# CodeQL code-graph export pack

This directory holds the hash-pinned CodeQL export queries, the column contract and the
source/sink catalog for code-graph precomputation
([`docs/architecture/code-graph-precomputation.md`](../../docs/architecture/code-graph-precomputation.md),
chunk C1). It is rule data. It defines no job, prompt or worker guidance. It covers C/C++, C#,
Go, Java/Kotlin, JavaScript/TypeScript, Python, Ruby, Rust and Swift, one pack per language.

| Path | Content |
|---|---|
| `cpp/` | The query pack `appsec-review/graph-export-cpp` 1.0.0: `qlpack.yml`, `graph-export.qls`, the shared library `GraphExport.qll`, the seven graph queries `CallSites`, `SinkSites`, `SourceSites`, `FlowSummaries`, `Paths`, `Guards` and `Ranges`, and the two seeded-scope reports `Seeds` and `Neighborhood`. |
| `csharp/`, `go/`, `java/`, `javascript/`, `python/`, `ruby/`, `rust/`, `swift/` | The same twelve files as `appsec-review/graph-export-<language>` 1.0.0 over that language's `codeql/<language>-all` library. `java/` also covers Kotlin and `javascript/` also covers TypeScript. |
| `columns.json` | `appsec-review/codeql-graph-export-columns/1`: the closed, ordered column contract for every export `query_id`, shared by every language. This is the C1 → C3 format contract. |
| `catalog.json`, `catalog.schema.json` | `appsec-review/graph-catalog/1`: classifies export rows into the closed `SinkClass`/`SourceClass` vocabularies of `src/appsec_review/graph/contract.py`. |

## Live verification

Every pack except Swift has been compiled and run with the CodeQL 2.27.0 CLI in
`audit-codeql:custom-2.27.0`, built from this repository on a Linux (WSL 2) Docker host with
`containers/tools/codeql/build-source-image.sh` (see
[`containers/tools/codeql/README.md`](../../containers/tools/codeql/README.md)). The library
versions bundled in that image equal the `library` pins in `rules/registry.toml`.

Each language has a synthetic recording under
`tests/fixtures/graph/codeql_export/<language>-synthetic/` (hand-authored, except Rust's, which is
a live recording) and an `expected-facts.json` that states
the semantic floor as rows that must exist. The offline test `tests/graph/test_<language>_export.py`
holds the recording to it, and the live test `tests/live/test_codeql_graph_export_<language>_live.py`
(C/C++: `tests/live/test_codeql_graph_export_live.py`) builds a real database from the fixture's
`source/` in the pinned image and holds the live export to the same file. The C/C++ native
recording (`tests/fixtures/graph/codeql_export/native/`) is copied from the live export; it is
refreshed, never hand-edited.

| Language | Live result | Notes |
|---|---|---|
| C/C++ | passes | Native recording refreshed from the live export (it includes the CMake compiler-id sources the build traces under `codeql-build/`). |
| Java/Kotlin | passes | |
| Python | QL fixed | `path_sanitizers` also matches a sanitizer call that the path graph steps over (`safe = realpath(filename)`). |
| Ruby | QL fixed | A concept anchored at its own operand (ActiveRecord `find_by_sql`) is reported at the receiving call, and catalog sanitizer calls get an argument-to-result taint step so flows through `File.basename` stay visible. |
| Go | expectation fixed | The cross-function flow enters `lookup` through a `call` edge; the hand-authored expectation of a `return` edge was wrong. |
| JavaScript/TypeScript | needs Node | CodeQL's TypeScript extractor needs Node.js, which the source image lacks; the live test runs in the `node` build profile. No live result is recorded in the repository. |
| C# | pinned, no recorded result | The pack is pinned with the others; the live test extracts in the `dotnet` build profile. No live result is recorded in the repository. |
| Rust | recorded live | Runs in the `rust` profile, whose `rust-wasm` build image ships `rust-src` so the extractor resolves `std`. `exports/` is the byte-exact live CodeQL 2.27.0 export (see the fixture's `provenance.json`). Closure calls export as `unresolved_indirect`. Two named gaps stay open in `expected-facts.json` `known_gaps` (`rust_summarized_body_prunes_remote_flow` for the remote-to-SQL, command, SSRF and deserialization paths; `rust_canonicalize_summary_does_not_propagate` for the `canonicalize` sanitizer); the live test fails once CodeQL closes either, so it is promoted to an expectation. |
| Swift | deferred | CodeQL extracts Swift only on macOS. The pack compiles but has no pin, `rules/registry.toml` keeps it `state = "deferred"`, and its live test skips on Linux. |

Live tests need the pinned images on the local Docker host and take 13-35 minutes each, most of it
database creation and a cold pack compile in a fresh test run.

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
| `seed_functions` | `Seeds.ql` | none (seeded-scope report) |
| `neighborhood` | `Neighborhood.ql` | none (seeded-scope report) |

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
- `guards` rows of a comparison also carry its two operands (`lhs_*`, `rhs_*`): the five location
  columns, `<role>_kind` (`variable | field | constant | sizeof | call | other`, syntactic only)
  and `<role>_value` (the decimal value of an integer compile-time constant, else `""`). A guard
  that is not a comparison, and every `none` row, has empty paths, zero positions, kind `other`
  and value `""`. The operand text is not exported; the normalizer slices it from the accepted
  source bytes. Inside a macro expansion an operand may be located at the whole expansion site.
- `destination_object_bytes` (last `guards` column) is the byte size of the destination object
  (argument 0) of a catalog memory-write API sink (`memcpy`, `memmove`, `memset`, `strcpy`,
  `strcat`, `strncpy`, `strncat`) when its unconverted type is a fixed-size array or it is the
  address of a variable or field of a complete type; `-1` otherwise and for every other sink. It
  is an object-size fact, not a safety claim, and the export classifies no relation between a
  guard and the sink or the destination.
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

## Export scope: whole program or seeded

Every query is restricted by the export scope
([`docs/architecture/seeded-codeql-neighborhoods.md`](../../docs/architecture/seeded-codeql-neighborhoods.md)).
`GraphExport.qll` declares two external predicates that the runner binds at evaluation time with
`codeql database run-queries --external=<name>=<file.csv>`; the compiled queries and the compile
cache are therefore identical for every scope:

| external predicate | CSV (no header) | content |
|---|---|---|
| `exportScope(string mode, int depth)` | `scope.csv` | one row, `whole_program,0` or `seeded,<n>` |
| `exportSeed(string path, int startLine, int endLine)` | `seeds.csv` | one row per seed, path relative to the database source root; empty in `whole_program` mode |

* `whole_program` exports everything, byte-identical to the pack before seeding existed.
* `seeded` exports the neighborhood of the seeds. `seedFunction(f)` holds for each source-root
  function whose definition (declarator through closing brace) overlaps a seed's lines; nested
  lambdas and the function enclosing them both seed. `near(f, d)` is the bidirectional closure
  over call edges (direct targets plus virtual overrides) with `d <= n`; `exported(f)` is
  `whole_program` or `near(f, _)`. Function-pointer targets are not edges of the closure.
* `call_sites` exports the calls of exported callers (the frontier callee appears as a target but
  is not expanded), and its function-pointer dataflow only sinks at calls in exported functions.
  `sink_sites`, `source_sites`, `guards`, `ranges` and `range_conversions` apply `exported` to the
  enclosing function in `GraphExport::sink` and `GraphExport::source`. `flow_summaries` applies it
  to the summarized function. `Paths.ql` restricts its sources and sinks the same way and makes
  every node outside an exported function a barrier, so the global flow stays inside the
  neighborhood.
* `seed_functions` and `neighborhood` report how the seeds resolved (the `neighborhood` depth is the
  minimum call-graph distance from a seed function). Both are empty in `whole_program` mode and
  belong to no graph family.

## File layout and runner action

The runner action `export` (`containers/tools/codeql/codeql_runner.py`) runs inside the derived
CodeQL image with `--network none`. All of its paths are relative to the execution scratch:

```text
export --database <db-copy> --pack <staged-pack-dir> --columns <staged columns.json>
       --asset-lock <staged assets.lock.json> --language cpp --output-dir <dir>
       --scope-file <scope.csv> --seeds-file <seeds.csv>
       --row-limit <n> --max-bytes <n> --threads <n> --ram <mb>
```

`appsec_review.codeql.runtime.graph_export_arguments` builds this argv. The job stages a copy of
the scope language's pack directory and of `columns.json` into scratch, together with a disposable
copy of the database: the pack is repository-owned and is not part of the licensed image. The
runner then:

1. checks that the staged pack's location-independent tree hash (`sha256  relative/path` lines,
   sorted by relative path), file count, `qlpack.yml`, suite and `columns.json` equal
   `export_query_packs.<language>` in `containers/tools/codeql/assets.lock.json`;
2. relies on the compile cache populated beforehand by the separate `compile` action (cold 10-22
   minutes, warm about 45 seconds). The cache volume is keyed by the declared CodeQL and runner
   releases and the runtime user, so it is shared across runs: a pack compiles cold only after
   one of those, or the pack's own bytes, change. It then compiles every query once (`codeql query
   compile`, a cache hit) and runs `codeql database run-queries
   --threads --ram --external=exportScope=<scope.csv> --external=exportSeed=<seeds.csv> -- <db>
   <pack>/<query>.ql` for each query file;
3. for each `query_id` in `columns.json` order, runs `codeql bqrs info --format=json` to get the
   true row count and the column arity, then `codeql bqrs decode --format=json --result-set
   <query_id> --rows <row-limit>`;
4. writes `<output-dir>/<query_id>.json` (canonical JSON) and `<output-dir>/export-manifest.json`.

`export-manifest.json` (`appsec-review/codeql-graph-export-manifest/1`) records the language, the
pack identity, the bounds, the export `scope` (`mode`, `depth`, `seed_count`; the runner validates
`scope.csv` and `seeds.csv` first, and a `whole_program` scope must have no seeds), and for each export its `path`, `sha256`, `bytes`, `row_count`,
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

1. Edit the QL, `columns.json` or `catalog.json`. Packs are hashed over their LF bytes
   (`.gitattributes` keeps `rules/codeql-graph-export/**` at `eol=lf` on every checkout).
2. Recompute the `export_query_packs.<language>` entry in `containers/tools/codeql/assets.lock.json`
   for every language the change touches (a `columns.json` or `catalog.json` change touches all of
   them): the tree hash and file count of `<language>/`, and the SHA-256 of `qlpack.yml`,
   `graph-export.qls`, `columns.json` and `catalog.json`. Mirror the same values in that language's
   `[[jobs.job_codeql_analysis.settings.languages.<language>.export_queries]]` block in
   `appsec-review.toml`. `tests/test_codeql_export_runner.py` fails until they agree.
3. Update `jobs.job_codeql_analysis.settings.asset_lock_sha256` in `appsec-review.toml` to the
   new lock SHA-256 (the lock is pinned by its exact LF bytes).
4. Run the language's live test on a Linux Docker host with the pinned image. For C/C++, copy the
   live native export over `tests/fixtures/graph/codeql_export/native/exports/` in the same change.
   When a live row legitimately differs from a hand-authored synthetic recording or expectation,
   fix the recording or `expected-facts.json` in the same change and regenerate the golden with
   `APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN=1`.
