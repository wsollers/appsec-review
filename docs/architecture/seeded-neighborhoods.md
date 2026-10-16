# Seeded neighborhoods (all producers)

Status: contract (2026-10-16). Generalizes [`seeded-codeql-neighborhoods.md`](seeded-codeql-neighborhoods.md)
(the CodeQL specifics) to the Clang AST / LLVM IR, Clang-Tidy / Clang Static Analyzer and CPG producers,
and exposes flow graphs, analyzer results and clangd symbols to models and workflows. Parent plan:
[`code-graph-precomputation.md`](code-graph-precomputation.md) section 13. Navigation:
[`README.md`](README.md).

## 1. Decision

Every producer that scales with the program runs **from the findings outward**: it analyzes only the
code around the finding locations ("seeds"), publishes that neighborhood into the existing `graph`
index as another producer, and names every bound it hit as a gap. A seeded scope is never `complete`.
There is no whole-program fallback in seeded mode: a seed no unit can carry is a named gap.

| Producer | Job | Seeded behavior |
|---|---|---|
| CodeQL | `job_codeql_analysis` | Reference implementation (`seeded-codeql-neighborhoods.md`). |
| Clang AST + LLVM IR + source CFG | `job_cpp_compiled_analysis` | Replays only translation units holding a seed. IR gives functions, calls and a flow graph; the `clang::CFG` dump adds a source-level graph to each matched function; AST is replayed for the units defining neighborhood functions, filtered to their names. |
| Clang-Tidy + Static Analyzer | `job_clang_static_analysis` | Analyzes only the units holding a seed. Every diagnostic in those units is kept and labelled against the seeds. A reviewed table maps some checks to a sink class (section 9, analyzer sinks). |
| CPG (enabled path only) | `job_cpg_analysis` | c2cpg builds a CPG of the seeded units only and `joern-export` writes a bounded `neo4jcsv` export that is reduced to one row per function (calls, branches, reaching-definition counts). Coverage is `partial`; a failed export is `unavailable`. Disabled state is unchanged and runs no container (Joern is deprecated and off by default). |
| clangd symbols | `job_cpp_symbol_index` | Production unchanged (whole tree). The seeded neighborhood filters what is read. |

## 2. Seeds and ordering

Seeds are `tool_observation` entities in hash-verified `observations` shards, as for CodeQL. The seed set
excludes every seeded producer's own observations, so it is identical for all producers and does not
depend on which of them already ran. Dagster ordering (`orchestration/dagster/adapter.py`) runs the
seeded producers after `job_evidence_collection`; the clang-static job additionally reads the accepted IR
function ranges when they exist, to label diagnostics against the neighborhood.

## 3. Settings

The **mode, depth and seed limit are defined once**, in
`[jobs.job_codeql_analysis.settings.export_queries]`. The loader (`config/loader.py`) copies them into a
`seeded` table of each Clang-family job, so a producer cannot disagree with CodeQL about what is seeded
(`config/seeding.py`, `SeededSettings`). A job whose settings carry no `seeded` table is `whole_program`.

Each producer names its own bounds in `[jobs.<job>.settings.seeded_bounds]`:

| Bound | Jobs | Meaning |
|---|---|---|
| `function_limit` | compiled | Neighborhood functions per project. |
| `unit_limit` | compiled, clang-static, cpg | Replayed or analyzed translation units per project. |
| `block_limit` | compiled | Basic blocks with instruction detail per function. |
| `include_scan_files` | compiled, clang-static, cpg | Files read when mapping a header seed to the units that include it. |

## 4. One shared seeding module

`appsec_review.seeding` is the only implementation of seed extraction, the **ledger statuses**
(`resolved`, `unresolved`, `file_not_in_database`, `over_limit`, defined only in `seeding/ledger.py`),
the call-graph `expand` walk (`seeding/neighborhood.py`), unit selection (`seeding/units.py`) and the
compact record (`seeding/record.py`). `jobs/cpp_seeded.py` is the compile-database selection shared by the
clang-static and CPG jobs. `tests/test_seeding_module.py` fails if a second module defines the ledger
statuses or reimplements these algorithms, or if a seeded producer does not import the shared module.

The **compact record** (`appsec-review/seeded-producer-record/1`, bounded) rides on each producer's index
identity so the graph job builds the card without opening any producer artifact. An unresolved seed keeps
a *reason* (`no_function`, `no_translation_unit`, `producer_failed`, `not_run`, `not_applicable`); the
reason never changes the status. Unit-granular producers list `unit:<path>` in the ledger `functions`.

## 5. Clang AST and LLVM IR (`job_cpp_compiled_analysis`)

1. `select_units` names the units whose main source is a seed file, plus every unit including a seed
   header (bounded by `include_scan_files`). Only those are replayed.
2. The IR of each replayed unit is parsed (`llvm_ir.parse_module`) into functions with source lines,
   calls to functions defined in the module, and a flow graph: blocks, successor edges, dominators,
   post-dominators, def-use lines and indirect-call count. Declared externals such as `memcpy` are not
   call edges. Past `block_limit` the structure (blocks and edges) is kept so the CFG stays valid, instruction
   detail is dropped, and the function carries `truncated: ["blocks"]`.
3. `expand` walks `depth` call steps from the seed functions over the observed edges; only that
   neighborhood is published. A function nobody observed is a `frontier`, not absent.
4. AST is replayed for the units defining neighborhood functions, so it depends on the IR result.
5. The `cfg` replay (`native.py` mode `cfg`, `clang --analyze -Xanalyzer -analyzer-checker=debug.DumpCFG`) runs
   for the same units. `clang_cfg.parse_cfgs` turns the dump into a source-level graph (short circuits, `?:`,
   loops, `switch`, destructor calls as blocks with a `T:` terminator and the source condition). It is
   matched to the IR function of the same name and published on the flow row as `source_cfg`. Clang's dump
   carries no positions, so blocks are not tied to lines (`source_cfg_no_block_lines`); overloads are not
   guessed apart (`source_cfg_ambiguous`); a failed or unparsable replay is `source_cfg_unavailable`, and the
   flow graph is still published.

## 6. Gap vocabulary and bounds

`limit_reached` (a count bound cut the walk or the rows), `depth_reached` (the depth bound stopped it),
`frontier` (a callee or caller lies in code that was not observed; the standing gap for callers in
translation units that were not replayed), `export_truncated` (a row-bounded export), plus the
producer-specific `producer_not_run`, `symbols_unlinked`, `outside_precomputed_neighborhood` (section 9),
the CPG export gaps `cpg_calls_name_matched` (no call edges: a callee is matched by name, and
`callee_resolved` says whether Joern itself resolved it), `cpg_no_cfg_edges`, `cpg_export_partial`,
`cpg_export_unavailable` and `cpg_export_limit`, the analyzer gaps `analyzer_only`, `analyzer_checks_unmapped`,
`analyzer_diagnostics_unlocated` and `analyzer_sinks_limit`, the source CFG gaps of section 5, and the zero-seed text `seeded export skipped: no finding locations map into this
database`. Every named bound produces a gap; none widens the selection.

## 7. Failure, not-applicable and zero-seed semantics

* **Zero seeds**: clean skip; no tool runs; the gap above is named; coverage is not `complete`; the job
  is `COMPLETED_WITH_GAPS`.
* **Compile or analyze failure**: a gap on exactly the seeds that unit carried; those seeds stay
  `unresolved` (reason `producer_failed`). A total failure is `unavailable` coverage. A failure is not
  checkpointed, so resume retries it.
* **Not applicable** (a unit the tool does not support): the seeds are `not_applicable`, neither failed
  nor clean.
* Neither a failure nor a not-applicable seed ever raises coverage.

## 8. Identity, resume and determinism

Each producer's checkpoint identity binds its own `seeded` identity (`SeededSettings.identity()`: mode,
depth, seed limit and its bounds) and the seed set. Changing mode, depth, limit or the seed set reruns only
the affected producer; an unchanged producer reuses its checkpoint, and CodeQL's identity is untouched
(`test_seeded_compiled.py`, `test_seeded_clang_static.py`, `test_seeded_cpg.py`). Shards and card payloads
are byte-identical across runs.

## 9. Publication and exposure

Producer facts enter the **existing `graph` index** as another producer (`clang-ast`, `llvm-ir`,
`clang-static`, `joern-cpg`) through the existing normalizer and eligibility rules. There is no new fact
family and no new model-facing claim.

**Card.** Each `codeql_database` card gains `producers: [{name, state, seeded, depth, gaps}]`, so a model
sees per scope which producers cover its neighborhood (`jobs/job_code_graph_index/producers.py`).

**Producers shard.** Beside the card the graph job publishes one `producer_neighborhood` shard per scope
(id `graph-<scope>-producers`), restoring the dropped secondary shards from the accepted handoffs of the
clangd, compiled, clang-static and joern jobs. Rows keep their producer's kinds and carry `payload.scope`:

* `flow`: one `ir_entity` row per IR function (blocks, edges, dominators, post-dominators, def-use, and the
  matched `source_cfg`);
* `diagnostics`: one `tool_observation` row per diagnostic with check id, severity, fix-it boolean (never
  applied), trace length, the bounded trace and the seed label;
* `symbols`: one `symbol` row per clangd symbol linked to a CodeQL symbol, with callers and callees;
* `cpg`: one `tool_observation` row (`fact: cpg`) per exported Joern function: path, lines, signature, calls
  (name, line, `callee_resolved`), branches with their condition expressions, operator-call and
  reaching-definition counts. Joern rows use `tool_observation` here because the graph index accepts only the
  family, symbol, `ir_entity` and `tool_observation` kinds; the Joern job's own shard uses `ast_node`.
  Joern is deprecated, so the rows are absent by default with a `producer_not_run` gap.

**Tool.** `query_codeql_neighborhood` gains `include` values `flow`, `diagnostics`, `symbols` and `cpg` (the
default `include` is unchanged). The seed's block is returned with `dominated_by`. A seed whose function
the producers did not cover yields an `outside_precomputed_neighborhood` gap. No MCP call runs an
analyzer. Schema parity: `docs/schemas/retrieval-mcp-tools.json`.

**Analyzer results.** `query_observations` gains `seed` (`path:line`), `function`, `fix_it` (boolean) and
`min_trace_length`, beside the existing `scanner`, `rule` and normalized `severity`. An observation that
carries none of these fields never matches them.

**Symbols audit.** A model reaches `job_cpp_symbol_index` data through `query_codeql_neighborhood` with
`include=["symbols"]`; there is no separate `query_symbols` tool (the neighborhood already resolves the
seed and its callers and callees, the capability grant is the scope check, and a second tool would add a
second grant surface). Rows are in the `clangd` identity space (`native_id` `clangd:<qualified name>`,
never a raw USR), a distinct space from CodeQL `symbol`s; the explicit `cross_reference` links the two
(`SAME_AS`). Unlinked clangd symbols are `symbols_unlinked`. A role without the scope grant cannot read
them (`review/capability.py`, `mcp/capability.py`).

**Analyzer sinks (`graph/analyzers.py`, rule `graph-analyzer-sinks/1`).** A diagnostic names a check, not a sink
class, so only checks in the reviewed table `CHECK_SINK_CLASS` (never message text) map to a `sink_class`.
During `crosscheck.scopes` a mapped diagnostic whose line falls inside the exact span of a CodeQL `sink_site`
of the same class adds `clang-static` as an agreeing cross-check producer (`analyzer-diagnostic-in-sink-lines`)
and recomputes admissibility; an analyzer can only confirm, never contradict, and a fact it does not mention
stays `not_covered`. Any other mapped diagnostic becomes an analyzer-only `sink_site` fact: inexact (the
location is the diagnostic point), `partial` coverage, cross-check `partial`, `argument_index` absent, never
direct-eligible, and named `analyzer_only` as missing CodeQL coverage rather than a CodeQL negative. An unmapped
check stays only in the `diagnostics` rows, counted in `analyzer_checks_unmapped`. No new fact family exists.
Because these facts are `sink_site` facts they appear in hunt-package `unit_context`; the review prompts
treat them as inexact leads.

**Workflow consumers.** Review source-SAST selection already reads the `job_clang_static_analysis`
observation shard (now the seeded subset, with its gaps); package assembly already reads `graph`
families per scope. The remaining consumers are listed in `docs/TODO.md`.

**Cross-check.** IR can only agree or be `NOT_COVERED`; only clangd can disagree. A seeded disagreement
emits a `CONTRADICTS` relation and makes the fact ineligible (`graph/crosscheck.py`).

## 10. Coverage and soundness

A seeded scope is `partial`. Missing facts outside the neighborhood, past the depth or beyond a bound are
named gaps, never evidence of absence. Clang-static labels diagnostics `at_seed`, `in_seed_function`,
`in_neighborhood`, `outside_neighborhood`, or `unclassified` with a named gap when no seeded IR
neighborhood exists; labels never change coverage.

## 11. Tests

* Shared module and ledger: `tests/test_seeding_module.py`, `tests/test_seeded_ir_and_record.py`.
* Producers: `tests/test_seeded_compiled.py`, `tests/test_clang_cfg.py`, `tests/test_seeded_clang_static.py`,
  `tests/test_clang_static_tool.py`, `tests/test_seeded_cpg.py`, `tests/test_cpg_export.py`,
  `tests/graph/test_analyzers.py` (12-unit fixture
  `tests/fixtures/seeded_clang/`, fake executors that record the replayed units).
* End to end: `tests/integration/test_seeded_neighborhoods_end_to_end.py` runs the real seeded handlers
  through injected executors on the multi-TU fixture, the real graph and indexing jobs, and the retrieval
  and scoped MCP adapters. It asserts the card producer list, the seeded set per producer, facts from more
  than one producer for a seed through `query_code_graph` and `query_codeql_neighborhood`, flow and
  diagnostics reachability, the symbols audit (granted and ungranted roles), the CONTRADICTS case, the
  enabled-Joern `cpg` rows (and their `producer_not_run` gap when Joern is off) and analyzer corroboration of
  a CodeQL sink.
  CodeQL is a generated seeded handoff and the review job itself is not run.

## 12. Live check

`tests/live/test_seeded_clang_live.py` is opt-in (`APPSEC_LIVE_SEEDED_CLANG=1`; needs `clang++-18`, docker
and the pinned `tool-native-cpp`, `tool-clang-static-analysis` and `tool-joern` images). It has two groups.

- Compiler: the host compiler re-emits IR, CFG and AST for the two seeded units and the production parsers'
  flow summary must equal the recording.
- Containers: the production handlers run the real `tool-native-cpp` (IR, AST, CFG), Clang-Tidy, the Static
  Analyzer and c2cpg plus `joern-export` on the 12-unit fixture, restricted to the two seeded units
  (`net.cpp`, `util.cpp`). Measured on host Zarathustra: 72 s for the six tests; 5 IR functions, 4 call
  edges, AST `COMPLETED_WITH_GAPS`, 6 CPG functions, 0 diagnostics, no static gaps.

The fixture project is clean, so zero diagnostics there is the correct answer and proves nothing about the
analyzers. A separate live test therefore drives the real `tool-clang-static-analysis` image through
`ContainerExecutor` on a small defective file (unbounded `strcpy`, null dereference). Clang-Tidy reported
`clang-analyzer-core.NullDereference` and `clang-analyzer-security.insecureAPI.strcpy`; the Static Analyzer
reported `core.NullDereference` and `security.insecureAPI.strcpy`; per-unit `units` entries were present, and
the `strcpy` check maps through `graph.analyzers.sink_class_of`. This is a handful of files, not a scale
measurement: seeded versus whole-program wall time on a 20k-100k LOC project is **not measured**.

## 13. Not done

Done since the first implementation: source-level `clang::CFG` (`native-cpp` cfg mode), the seeded CPG
export (`joern-export` neo4jcsv, bounded to the seeded units), and analyzer sink normalization
(`graph/analyzers.py`, rule `graph-analyzer-sinks/1`: corroborates a CodeQL sink or adds an inexact
`analyzer_only` sink).

Still open (details and entry points in `docs/TODO.md`):

- review-side consumers: prioritization, hunt-unit construction, scoring and package flow context;
- the `JOERN_CPG` call-site input to the graph cross-check (`graph/crosscheck.py` `SECONDARY_KINDS`);
- measurement on a 20k-100k LOC project, then tuning `seeded_bounds` and `seed_depth`;
- the seeded CPG shard still carries the generic `JOERN_GAP` text (`jobs/job_cpg_analysis/job.py`), which
  says no whole-program CPG coverage is claimed; that remains true, but the wording predates the export.
