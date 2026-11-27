---
title: "Seeded CodeQL neighborhoods"
kind: "architecture"
subsystem: "code intelligence"
status: "current"
jobs: ["job_code_graph_index", "job_codeql_analysis", "job_evidence_collection"]
last reconciled: "ea03df9695991eafe37065717624278af845a74c"
---
# Seeded CodeQL neighborhoods

Status: contract (2026-10-16). Extends [`code-graph-precomputation.md`](code-graph-precomputation.md)
(phase 3). Navigation: [`README.md`](README.md). Operations:
[`../operations/codeql-analysis.md`](../operations/codeql-analysis.md).

This page is the CodeQL specifics. The other producers (Clang AST/LLVM IR, Clang-Tidy/Static
Analyzer, CPG), the shared seeding module, the card's `producers` list and the flow, diagnostics and
symbols exposure are in [`seeded-neighborhoods.md`](seeded-neighborhoods.md).

## 1. Problem

The whole-program graph export (an action inside `execution.scopes` in `job_codeql_analysis`) evaluates every call
site, sink, source, flow summary, path, guard and range of a database. That is acceptable for a
small project and does not scale: a million-line C++ application makes the export the dominant cost
of the review, and almost none of it is ever read, because a review only asks about the code around
its findings.

## 2. Decision

CodeQL is run **from the findings outward**, not over the whole program.

1. Accepted upstream findings and the current scope's own normalized CodeQL observations provide
   located **seeds** (path, line range, scanner, rule). Bounded structural candidates fill unused
   capacity after those observations; they are navigation seeds, not findings.
2. The export is restricted to the **neighborhood** of the seeds: the functions within `seed_depth`
   call-graph steps (callers and callees, direct and virtual-override edges) of the function that
   contains each seed. `seed_depth` (n) is a job setting.
3. The seven existing graph queries are reused unchanged in shape and column contract. They only
   gain a scope predicate, so the normalizer, the graph families and `query_code_graph` need no new
   fact family. Two report queries (`seed_functions`, `neighborhood`) record how the seeds resolved.
4. The result is **precomputed** and published like the whole-program graph (same `graph` index, one
   shard per scope and family) plus one **database card** per scope. The card tells a model which
   database holds what: a project may have several (language, build unit), and the model must know
   which one to ask about.
5. Consumers reach the data through bounded retrieval tools: `list_codeql_databases` (discovery) and
   `query_codeql_neighborhood` (bounded expansion over the precomputed graph). **No MCP call runs
   CodeQL.** Anything outside the precomputed neighborhood is a named gap, never a negative
   conclusion. Review cells request these tools through the application-authorized in-process
   loop; external clients use MCP. See [retrieval surfaces](retrieval-surfaces.md).

`mode = "whole_program"` keeps the previous behavior and is still the reference for tests and for
small projects.

## 3. Settings (central TOML, `[jobs.job_codeql_analysis.settings.export_queries]`)

| key | default | meaning |
| --- | --- | --- |
| `mode` | `"seeded"` | `"seeded"` or `"whole_program"` |
| `seed_depth` | `3` | n: call-graph steps from each seed function (`0` = the seed functions only) |
| `max_seed_depth` | `8` | hard cap; `seed_depth` above it fails validation |
| `seed_limit` | `200` | maximum distinct seeds per scope; the overflow is a named gap |

`seed_depth`, `seed_limit` and `mode` are part of the export identity, so changing any of them
re-runs the export. The seed set (sorted `path,start_line,end_line`) is part of it too.

## 4. Seed extraction (`job_codeql_analysis`, before the export action)

* Source: `tool_observation` entities in the observation shards named by the plan's
  `upstream_manifests` (read with `ShardSet(...).entities(shards, kinds=("tool_observation",))`),
  excluding prior seeded-producer observations, including CodeQL, from that upstream pass.
  The scheduler separately supplies **this scope's own current normalized CodeQL shards** after
  all its query profiles have normalized. Those observations are seeds; other scopes' current
  shards are not read opportunistically, so completion order does not change the seed set.
  The observation's location gives the target-relative path and line range; `scanner_of`,
  `rule_of` and `normalize_reported_severity` give the ledger fields.
  Each source also records `origin` (`upstream_observation`, `current_observation` or `structural`),
  `tier` and `entity_kind`. The legacy `observation_id` field holds that entity's resolving identity;
  structural sources are not tool observations merely because that field keeps its old name.
* Structural fallback: CodeQL explicitly enables the shared extractor's structural candidates.
  After observation seeds, remaining slots up to the configured `seed_limit` are filled from
  admitted priority hotspots, Tree-sitter CFG functions and catalog symbols, in that order.
  Candidate availability is limited to the admitted manifests, not a new input grant. The typed
  `CodeQLExportSettings` has no separate structural-fallback policy switch; the shared helper's
  default argument is not a job configuration setting.
  Structural tiers are `priority_hotspot`, `cfg_function` and `catalog_symbol`; their `severity`
  is `null`, not an invented low/info vulnerability severity. Observation severity ranks and
  structural score/complexity ordering still select the same spans. Every tier selects query
  scope, never confirmed findings or new evidence authority.
* Shared preparation: the first export prepares one immutable candidate snapshot inside the
  execution attempt. It performs the admitted observation and structural passes once, retaining
  their actual read receipts; later scope exports combine it with only their own normalized shards.
  Candidate selection still applies `seed_limit` after that combination, not before. Snapshot reuse
  checks run root, manifest identities, scope/source identities and structural inclusion. There is no
  process-global cache or cross-attempt reuse, and no whole-plan normalization barrier.
* Mapping: the path is mapped to the database source root of each scope (scope root plus the
  accepted file list); a seed is assigned to every scope whose accepted files contain the path.
  Each export retains the **whole plan's** ownership map for `file_not_in_database` accounting,
  then selects its own scope's seeds. Findings belonging to another planned database are not
  reported as absent from every database.
  The export CSV carries the database-relative path. C/C++ uses `GraphExport.sourcePath`, which
  excludes paths matching `CMakeFiles/` so configure-time compiler probes do not become accepted
  project-source graph facts; the same path rule governs seed resolution.
* Normalization: a seed is the pair of lines `[start_line, end_line]` of the location (a point has
  `start_line == end_line`). Duplicates collapse. Order is deterministic (path, start, end). When
  more than `seed_limit` distinct seeds exist the highest severity wins, ties broken by path and
  line, and the dropped count is the gap `seed_limit_exceeded: N of M seeds dropped`.
* Per-seed ledger status: `resolved` (a function definition contains the lines), `unresolved`
  (the lines lie in no function body: file scope, macro, generated), `file_not_in_database`
  (no scope contains the path), `over_limit`. Only `resolved` seeds seed the neighborhood.
* No seeds at all (mode seeded): the export is **not run** for that scope. The record has
  `export_status = "SKIPPED"` and the gap `seeded export skipped: no finding locations map into
  this database`; downstream coverage is `unavailable` with that gap. Not clean.

## 5. QL contract (`rules/codeql-graph-export/cpp`)

Two files are written into the export staging directory next to the database and bound at
evaluation time with `codeql database run-queries --external=<name>=<file>` (the compile cache is
unaffected; the files are plain CSV with no header):

* `scope.csv`, one row: `<mode>,<depth>` for `external predicate exportScope(string mode, int depth)`.
* `seeds.csv`, rows `<path>,<start_line>,<end_line>` for
  `external predicate exportSeed(string path, int startLine, int endLine)`. Empty in
  `whole_program` mode.

`GraphExport.qll` defines `seedFunction(Function)`, `near(Function, int distance)` (bidirectional
closure over direct and virtual-override call edges, `distance <= depth`) and
`exported(Function f)` (`mode = "whole_program"` or `near(f, _)`). Every query restricts its rows
by `exported(...)` of the enclosing function; `sink_sites`, `source_sites`, `flow_summaries` and the
path queries apply it to the sink or source function. `call_sites` exports every call whose caller
is exported, so the frontier callee appears as an edge target and is not itself expanded.

Two new queries, both in `columns.json` (the normalizer rejects unknown query ids):

* `seed_functions(seed_path, seed_start_line, seed_end_line, function_name, function_path,
  function_start_line, function_start_column)`: one row per resolved (seed, function).
* `neighborhood(function_name, function_path, function_start_line, function_start_column, depth)`:
  one row per exported function with its minimum distance from a seed. Empty in `whole_program`.

Neither belongs to a graph family (`FAMILY_QUERIES` is unchanged); the graph job reads them for the
database card.

## 6. Export record and manifest additions

The export manifest (`appsec-review/codeql-graph-export-manifest/1`, extra keys tolerated) gains
`"scope": {"mode", "depth", "seed_count"}`. The per-scope export record consumed by
`job_code_graph_index` gains

```json
"seeded": {
  "mode": "seeded", "depth": 3, "seed_limit": 200,
  "seed_count": 12, "resolved_seed_count": 9,
  "neighborhood_function_count": 431, "depth_histogram": {"0": 9, "1": 40, "2": 150, "3": 232},
  "seeds": [{"path": "src/a.cpp", "start_line": 10, "end_line": 12, "status": "resolved",
             "functions": ["ns::f"], "sources": [{"scanner": "cppcheck", "rule": "bufferAccessOutOfBounds",
                                                  "severity": "high", "observation_id": "asr:tool_observation:<sha>"}]}],
  "gaps": ["..."]
}
```

`status_counts` retains its existing keys, but **is not a set of additive finding counts**.
`resolved`, `unresolved` and `over_limit` describe the selected scope; `file_not_in_database`
counts distinct outside-scope locations across the extraction's inputs. `accounting.meaning` is
`query_seeds_not_findings`. Its `shared` and `additional` records separately identify the shared
plan/candidates and current observation-shard batch, each with `aggregation = "non_additive"`,
`not_in_database` and `unlocated`. The same shared identity/counts repeat on multiple scope records:
do not sum them. Shared and additional inputs can also overlap on an outside location, so their
counts are not necessarily additive even within one extraction.
The shared accounting identity describes semantic candidates and coverage, so moving identical
inputs between private runs does not change it. The separate attempt-local snapshot admission key
still binds the exact run root, manifest pins and scope/source identities; the accounting identity
is not an evidence-admission token.

The run's graph-export index records shared preparation once as `seed_accounting`; scope ledgers
retain their additional-input accounting. This describes coverage, not proof of any final-report
overcount. Compact records retain bounded `accounting` and a `seed_sources` array aligned with the
existing compact seed rows; graph-card projection preserves these source origins and accounting
without promoting historical records that lack them. The existing card limits still apply.

`seeds` lists only resolved and unresolved locations and is bounded by `seed_limit`; `sources` per
seed is bounded (first 8, sorted). A
`whole_program` record has `"seeded": {"mode": "whole_program", "depth": null, ...}` with empty
`seeds`.

## 7. Publication (`job_code_graph_index`)

* Graph shards per (scope, family) are produced exactly as before. In a seeded scope every family's
  coverage row is `partial` with the gap
  `seeded_neighborhood: facts cover functions within <depth> call steps of <resolved> finding
  locations; absence outside it is not evidence`.
* One extra shard per scope (shard id `<scope_id>:database`, no family) holds a single
  `EntityKind.CODEQL_DATABASE` card, identity `asr:codeql_database:<sha256>` derived from
  (snapshot, scope id, database identity, export identity). Payload (`appsec-review/codeql-database/1`):
  `scope_id`, `language`, `source_languages`, `root`, `build_unit_id`, `component_id`,
  `database_identity`, `export_identity`, `mode`, `seed_depth`, `seed_limit`, the section 6
  `seeded` ledger, per-family fact counts and coverage states, and `gaps`. The card's
  `SOURCE_FILE` locations are the seed files (no whole-database file list).
  The payload also carries `producers: [{name, state, seeded, depth, gaps}]`, one entry per other
  producer (`clang-ast`, `llvm-ir`, `clang-static`, `clangd`, `joern-cpg`) built from the producers'
  compact records, and the scope gets a `producer_neighborhood` shard (`graph-<scope>-producers`); see
  [`seeded-neighborhoods.md`](seeded-neighborhoods.md) section 9.
* The card is the only new thing a model needs to know about: which databases exist, what each was
  seeded from, how deep, and what is not covered.

## 8. MCP tools (`mcp/schema.py`, `docs/schemas/retrieval-mcp-tools.json`)

Both are read-only, capability-checked through `graph_scopes` exactly like `query_code_graph`, and
never invoke CodeQL.

### `list_codeql_databases`

Arguments: `language` (optional), `limit` (default 20, max `MAX_TOOL_LIMIT`). Returns the cards:
`database` (identity), `scope_id`, `language`, `root`, `build_unit_id`, `mode`, `seed_depth`,
`seed_count`, `resolved_seed_count`, `neighborhood_function_count`, `coverage`, `gaps`, and the
bounded seed ledger. A project with several databases returns several cards; the caller picks one
and passes its `database` identity to the next tool.

### `query_codeql_neighborhood`

Arguments: `database` (required card identity); exactly one of `seed` (a ledger seed as
`path:start_line`), `symbol` (`asr:symbol:<sha256>` or qualified function name) or
`observation` (an `asr:tool_observation:<sha>` from the seed ledger); `direction`
(`callers` | `callees` | `both`, default `both`); `depth` (default and maximum
`min(card.seed_depth, MAX_TOOL_DEPTH)`); `limit` (max `MAX_TOOL_LIMIT`); `include` (subset of
`calls`, `sinks`, `entry_points`, `guards`, `ranges`, `paths`, and the producer extras `flow`,
`diagnostics`, `symbols`, `cpg`; default `["calls", "sinks"]`). The producer extras read the scope's
`producer_neighborhood` shard and are specified in
[`seeded-neighborhoods.md`](seeded-neighborhoods.md) section 9.
Returns the call closure from the subject over the stored `call_site` relation, with the requested
fact families for the functions in it, each item keeping its fact identity, source location and
resolving evidence. The result is `complete`, `partial` or `unavailable` and always names:

* `outside_precomputed_neighborhood`: the subject is not in the database's neighborhood;
* `depth_exceeds_precomputed`: a requested depth beyond `seed_depth` (clamped, and named);
* `frontier`: callees at the neighborhood boundary that were not expanded (their own callees are
  absent, not nonexistent);
* `limit_reached`, `depth_reached` as in `query_code_graph`;
* `database_unknown`: the identity names no card.

## 9. Coverage and soundness

* Seeded output is a **sample around findings**, never a claim about the program.
  Every seeded coverage row is `partial`.
* The neighborhood follows direct and virtual-override edges only. Function-pointer targets are
  resolved by the whole-database flow query in `whole_program` mode; in seeded mode they are
  resolved only for calls in exported functions.
* A widely used function makes the caller expansion large; the export's `row_limit` bounds it and
  the truncation is named by the existing `export_truncated` gap.
* Findings from tools that give no line (project-level) produce no seed; the ledger records them as
  `unresolved`.

## 10. Tests

Unit: seed extraction, mapping, limit and ledger statuses; export identity includes mode, depth and
seeds; runner passes both `--external` arguments; card publication and coverage; MCP schema parity
with `docs/schemas/retrieval-mcp-tools.json`; tool bounds and gap names. Live (opt-in, pinned
image): seeded run on the calibration database in `tests/fixtures/codeql/` returns a subset of the
whole-program rows and a neighborhood containing each resolved seed function at depth 0.
