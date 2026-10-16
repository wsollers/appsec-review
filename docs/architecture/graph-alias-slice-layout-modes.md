# Alias, slice, and type-layout graph modes (design)

Status: **proposed, not implemented.** Nothing in this document exists in the code, the central
TOML, `docs/schemas/retrieval-mcp-tools.json` or `docs/operations/`. It extends
[`code-graph-precomputation.md`](code-graph-precomputation.md) (the `graph` index and
`query_code_graph`) and [`svf-alias-producer.md`](svf-alias-producer.md) (the SVF points-to
producer) with five precomputed, read-only `query_code_graph` modes, and it decides against a
sixth. The companion record
[`../reviews/detector-coverage-checklist.md`](../reviews/detector-coverage-checklist.md) measures
the repository's detector coverage against the same external reference.

This document describes review-worker evidence and repository implementation work. It is not a
prompt for review workers, and nothing here widens worker authority: every record a worker sees is
data with a producer, a resolving location and named gaps.

## 1. Why, and what stays out of scope

The retrieval gateway was compared with CodeBadger (qcri/codebadger, GPL-3.0), a live Joern/CPGQL
query server for C/C++. Only the capability list was used for the comparison; no code or text was
taken from it. Three capabilities had no counterpart here:

| CodeBadger capability | What a reviewer uses it for | Nearest thing here today | Gap |
|---|---|---|---|
| variable flow with pointer aliasing | "does the check on `len` constrain the bytes written through `p`?" | `guard_fact.constrains_sink_operand`, which is `unknown` whenever the guard operand and the sink operand are not joined by CodeQL local flow | no alias answer, no citable record of why the join failed |
| backward and forward program slices | "what does this sink operand depend on, and what depends on this input?" | `dataflow_path` (catalog source to catalog sink only), `flow_summary` (per function, pairs only) | no dependency closure from an arbitrary accepted subject; nothing between a sink and a non-catalog definition |
| per-function CFG and type definitions | "is this `memcpy` in a loop, on an error path, and how big is its destination?" | `call_site.in_loop`, `guard_fact`, `range_fact` (operand interval, never destination capacity) | no destination capacity, no struct layout, no loop or error-path context for sinks |

Three properties of this repository's gateway are not negotiable and shape every decision below:

1. **Precomputed only.** No analyzer runs during retrieval. Every mode reads accepted,
   hash-verified, run-pinned `graph` shards (D2). Generating a graph on demand and arbitrary query
   execution (CPGQL, SQL, regex) stay out of scope by design.
2. **Closed vocabularies and exact subjects.** A mode is a closed enum value; a subject is an exact
   logical identity of a kind the mode accepts; filters are closed enums. No names, paths or text.
3. **Absence is a gap.** Every bound, unmapped operand, open-world module or missing shard is a
   named gap on the row and on a coverage row. No mode can say "no alias", "no dependency" or "no
   overflow" (4.9 of the code-graph design).

Out of scope here: Joern (deprecated, D1), on-demand analysis, a second taint producer, `saber`
leak and double-free findings, optimized-build analysis, and any change to the predicate
vocabulary (R4) or the adjudication table (R5).

## 2. Decisions

### G-D1 Five new modes over four new families; CFG gets no model-facing mode

| Mode | Family served | Primary producer | Admissibility |
|---|---|---|---|
| `aliases` | `points_to_set` (the SVF design's S0 kind) | `job_svf_alias_analysis`, republished by `job_code_graph_index` | indirect for every predicate |
| `slice_backward`, `slice_forward` | `program_slice` | CodeQL export `Slices.ql` | indirect for every predicate |
| `type_layout` | `type_layout` | CodeQL export `TypeLayouts.ql`, cross-checked by Clang record layouts | indirect for every predicate |
| `buffer_bounds` | `buffer_bound` | CodeQL export `BufferBounds.ql` over `TypeLayouts.ql` and allocation sites | indirect for every predicate in phase 1 (open question 1) |
| (none) | `control_flow` (internal, K5) | CodeQL export `ControlFlow.ql` | not model-facing, not citable |

Every new family is **indirect for every predicate**. D3 stands: a reviewer must not rebuild
reachability or guard sufficiency in prose from raw dependency, alias or layout rows. These rows
exist so that a cell can *cite the reason* a direct fact is weak (`constrains_sink_operand =
unknown`, `range_fact.interval = unknown`, an unresolved indirect call on a path) instead of
asserting it. The direct families stay the six of `graph-fact-predicates/1`.

### G-D2 CodeQL produces slices, layouts and buffer bounds; SVF produces aliases only

D1 of the code-graph design applies unchanged: CodeQL is the primary producer of every fact family
for every language it has a database for. Slices and layouts are derivable from the CodeQL
database with source-exact locations, the same scope identities, the same export, normalize and
publish path, and no new image. An LLVM or SVF def-use slice was considered and rejected as the
primary producer because it needs K1 (exact IR debug locations, planned), the unbuilt `tool-svf`
image, is C/C++ `-O0` only, and would create a second symbol and location space for every slice
node. The SVF design's own "no SVFG value-flow paths" exclusion therefore stands; section 9 keeps
an SVFG slice cross-check as a possible later chunk.

Aliases are the exception because CodeQL has no whole-program points-to answer: the producer is
`job_svf_alias_analysis` as designed, and this document only adds the model-facing mode that its
section 9 deferred ("indirect-only for every predicate and requires its own decision against D3").
The decision is G-D1: indirect only, served from the same `points_to_set` records the cross-check
already computes (S-D3), nothing new is analyzed for the mode.

### G-D3 No `variable_flow` mode: `slice_backward` restricted to data edges is the same question

CodeBadger's variable flow is a data-dependency walk from a variable. Here a variable is not an
entity; the exact subjects a reviewer holds are `sink_site`, `guard_fact`, `entry_point` and
`range_fact`. A backward slice from one of them with `edge_kinds = data` is the variable flow of
its operand, and the `aliases` mode supplies the points-to answer for the pointer operands it
passes through. One family, one identity rule and one bound set are better than two overlapping
modes.

### G-D4 Raw CFG stays internal; sinks gain CFG context instead

The retired `control_flow` query set (basic blocks, branch edges) is not restored as a model-facing
mode. Dominance already reaches reviewers as `guard_fact`; control dependence reaches them as
`control` edges inside slices (section 4.2); loop and error-path context reaches them as new
`sink_site.result.cfg_context` fields (section 4.5). What remains of a raw CFG, block lists and
successor edges, has no R4 predicate that consumes it, and publishing it would invite reachability
by prose (D3). K5's internal `control_flow` family is justified now, not as a mode, but because
three consumers need it: the slice producer (control edges), K3 (dominator cross-check) and the
`cfg_context` enrichment.

### G-D5 Types are first-class only where a memory sink needs them

`type_layout` facts are exported for record types that are the static type of a memory sink's
destination operand, a field of one, or the pointee of one, transitively to `max_layout_depth`.
A full layout dump of every type in a C++ build unit is unbounded and mostly irrelevant. The
`buffer_bound` family is the link the review needs: per memory sink, the destination's capacity in
bytes or elements with its basis. A `symbol` subject is accepted so that a reviewer can look up a
type named in a `buffer_bound` row, but only types the export selected are present; others are a
named gap (`type_not_exported`).

## 3. Shared contract additions (chunk G0)

Additions to `graph/contract.py`, `retrieval/model.py` and the mode table. Names are final once G0
is committed; chunks import them and never edit them.

| Vocabulary | Additions |
|---|---|
| `EntityKind` | `points_to_set` (owned by the SVF design's S0; G0 lands it if S0 has not), `program_slice`, `type_layout`, `buffer_bound`, `control_flow` |
| `Family` | the same five values |
| `Mode` | `aliases`, `slice_backward`, `slice_forward`, `type_layout`, `buffer_bounds` |
| `RelationKind` | none; `DERIVED_FROM`, `REFERENCES`, `CONTAINS`, `CONTRADICTS` and `SAME_AS` are reused |
| `Producer` | `svf` (from the SVF design's S0) |
| `EDGE_KINDS` (new, slices) | `data`, `control`, `summary`, `alias` |
| `SLICE_ROLES` (new) | `subject`, `definition`, `use`, `condition`, `parameter`, `argument`, `return`, `call`, `declaration_without_initializer`, `opaque_call`, `frontier` |
| `CAPACITY_BASIS` (new) | `array_type`, `record_size`, `field_size`, `flexible_array_member`, `allocation_constant`, `allocation_expression`, `string_literal`, `unknown` |
| `ALIAS_ANSWERS` (new) | `may_alias`, `no_alias`, `unknown` (the SVF design's 5.2 table) |

`MODE_SUBJECT_KINDS` additions:

| Mode | Accepted subject kinds |
|---|---|
| `aliases` | `sink_site`, `guard_fact`, `entry_point`, `points_to_set` |
| `slice_backward` | `sink_site`, `guard_fact`, `range_fact`, `entry_point` |
| `slice_forward` | `entry_point`, `sink_site`, `guard_fact` |
| `type_layout` | `sink_site`, `buffer_bound`, `symbol` |
| `buffer_bounds` | `sink_site`, `symbol` (function: every memory sink it contains) |

`GRAPH_FACT_PREDICATES` is unchanged: none of the five families is mapped, so `classify` returns
`INDIRECT` for them without a new rule version. `evidence-admissibility/2` therefore needs no
change in phase 1. The `GraphSettings` additions are in section 7.

Identities (`LogicalIdentity.derive(kind, target_snapshot, native)`):

| Kind | `native_identity` |
|---|---|
| `points_to_set` | `{scope_id, module_id, operand_path, operand_start_byte, operand_end_byte, operand_role}` |
| `program_slice` | `{scope_id, subject_identity, direction, edge_kinds, node_locations_sha256}` |
| `type_layout` | `{scope_id, definition_path, definition_start_byte, definition_end_byte, qualified_name}` |
| `buffer_bound` | `{scope_id, sink_identity, operand_index}` |
| `control_flow` | `{scope_id, function_symbol, rule_version}` (one record per function) |

`scope_id` is the CodeQL scope identity, so a rebuilt database replaces every fact. SVF module
identities join CodeQL scopes by `build_unit_id` (SVF design, S0). Native CodeQL ids, SVF node ids
and IR value names never enter an identity or a served payload.

## 4. Fact families

Common rules are those of the code-graph design, section 4: every fact names scope, producer and
upstream shard hashes; every location resolves or is `ambiguous` with its method; a bound that was
hit is a gap on the fact and on the coverage row; an empty family for a scope whose export failed is
`unavailable`.

### 4.1 `points_to_set` and the `aliases` mode

- **Producer.** `job_svf_alias_analysis` (SVF design, section 6) already computes one
  `points_to_set` per queried operand: the sink operand of every `memory_write`, `memory_read` and
  `allocation_size` sink and the condition operands of their guards. This design adds the pointer
  operands of catalog `entry_point`s in the same functions as a fourth query class
  (`operand_role = source`), bounded by `max_operand_queries_per_module`. `job_code_graph_index`
  republishes the accepted SVF shards' records into `graph` shards of family `points_to_set` after
  the cross-check step, so the mode reads only the accepted `graph` index (S-D1).
- **Result.**

  ```json
  {"operand": {"role": "sink" | "guard" | "source", "location": {…}, "display": "p->buf",
               "fact_identity": "asr:sink_site:…"},
   "module": {"module_id": "…", "closed_world": false, "open_world_reasons": ["unmodeled_external:curl_easy_perform"]},
   "mapping": "exact" | "ambiguous" | "unmapped",
   "points_to": [{"object": "obj-…", "kind": "stack" | "heap" | "global" | "function",
                  "alloc_site": {"location": {…}, "display": "malloc(n)"}, "field": 0}],
   "truncated": false, "incomplete_reasons": [],
   "alias_answers": [{"other": "asr:points_to_set:…", "other_role": "guard",
                      "answer": "may_alias" | "no_alias" | "unknown", "reasons": [],
                      "basis": "andersen" | "dda"}],
   "analysis": {"svf_version": "SVF-3.3", "andersen_completed": true, "dda_refined": false}}
  ```

  `alias_answers` lists the answer against every other `points_to_set` of the same sink (its guard
  operands) and, for a `source` operand, against the sink operands in the same function, up to
  `max_alias_answers_per_operand`. Answers come from the job (SVF design, 5.2); the mode computes
  nothing.
- **Mode.** `aliases(subject)` returns the `points_to_set` rows whose `operand.fact_identity` is the
  subject (`sink_site`, `guard_fact`, `entry_point`), or the row itself for a `points_to_set`
  subject. Order `(operand.role, identity)`. No `depth`, no class filter.
- **Gaps the row must publish.** `open_world:<reason>` per reason (the row stays queryable; only
  `no_alias` is affected), `points_to_truncated` (more than `max_pts_size` objects; the set is cut
  deterministically by object identity), `field_limit_collapsed` (fields merged, so two struct
  fields may show as one object), `andersen_budget_exhausted` (module `unavailable`; the row is a
  coverage-only gap, no objects), `dda_budget_exhausted` (answer stays `may_alias` from Andersen),
  `operand_unmapped` / `operand_ambiguous` (no points-to, answer `unknown`),
  `debug_info_upgraded_lossy`, `not_in_link_unit`, `module_link_failed`.
- **Combination with `dataflow_path`.** The normalizer joins each `points_to_set` whose operand
  span equals a `dataflow_path` step span with a `REFERENCES` relation (`points_to_set` →
  `dataflow_path`, payload `{step_n}`), so a cell that holds a path can ask `aliases` about any
  pointer step that is also a sink, guard or source operand. Steps that are none of those have no
  points-to row, which the path's `aliases` response states as the gap `step_not_queried`
  (S-D3 keeps the analysis query-driven; see open question 3).
- **Cross-check.** The `points_to_set` row is itself the cross-check input for `guard_fact` (SVF
  design, 7.2); it carries `cross_check.state = not_covered` and `producer.name = svf`. A
  `guard_fact` the SVF answer contradicted carries `CONTRADICTS` to this row, so `aliases` on that
  guard returns the row that made it ineligible.
- **R4 predicates.** Indirect for every predicate. It may qualify `missing_or_ineffective_guard`
  (a `may_alias` between a dominating guard's operand and the sink operand is the reason a blue
  cell may argue the guard applies; a `no_alias` is the reason a red cell may argue it does not).
  Neither is direct: a points-to set is not a guard.

### 4.2 `program_slice` and the `slice_backward` / `slice_forward` modes

- **Producer.** `Slices.ql` in `rules/codeql-graph-export/cpp`. For each slice subject (every
  exported `sink_site` operand, `guard_fact` condition, `range_fact` operand and `entry_point`
  node), the bounded transitive closure of:
  - `data` edges: `DataFlow::localFlowStep` in both directions (IR dataflow, field-sensitive to one
    level like `flow_summary`), plus the subject's reaching definitions;
  - `control` edges: from a node to each `GuardCondition` that controls its basic block (the same
    `controls(block, polarity)` the guards export uses), with the polarity;
  - `summary` edges: across at most `slice_call_hops` calls, through the callee's exported
    `flow_summary` pairs only (never a second global dataflow run), with the call and the matching
    parameter or return as `call`/`parameter`/`return` nodes;
  - `alias` edges: none from CodeQL; reserved for the SVF cross-check (section 9).

  Backward slices follow edges toward definitions; forward slices toward uses. Each slice is cut
  at `max_slice_depth` edges and `max_slice_nodes` nodes, deterministic by `(depth, location)`, and
  every node where a bound stopped expansion is kept with role `frontier`. A call to an
  `external_undefined` function on a data edge is an `opaque_call` node, never dropped. A
  definition that is a declaration without an initializer is a `declaration_without_initializer`
  node (this is what an uninitialized-read reviewer looks for; it is a node, not a verdict).
- **Result.**

  ```json
  {"subject": {"identity": "asr:sink_site:…", "role": "sink_operand", "location": {…}},
   "direction": "backward" | "forward", "edge_kinds": ["data", "control", "summary"],
   "nodes": [{"n": 0, "role": "subject" | "definition" | …, "location": {…}, "symbol": "…",
              "display": "len = ntohs(hdr->len)", "depth": 0}],
   "edges": [{"from": 0, "to": 3, "kind": "data" | "control" | "summary", "polarity": "true_branch" | null,
              "via_summary": "asr:flow_summary:…" | null}],
   "on_paths": [{"path": "asr:dataflow_path:…", "nodes": [2, 5]}],
   "guards": ["asr:guard_fact:…"], "ranges": ["asr:range_fact:…"],
   "node_count": 0, "edge_count": 0, "truncated_nodes": false, "truncated_depth": false,
   "call_hops_used": 1, "opaque_calls": 0}
  ```

  `on_paths` is the join with `dataflow_path`: a slice node whose span equals a path step span lists
  that path, so the slice and the path can be cited together and the validator can see they agree.
  `guards` lists the `guard_fact` identities whose condition is a `condition` node; the guard
  remains the citable direct fact, the slice only shows why it is there.
- **Modes.** `slice_backward(subject, limit?, cursor?)` and `slice_forward(subject, limit?,
  cursor?)` return the one `program_slice` row per `(subject, direction)` with
  `edge_kinds = [data, control, summary]`, and a second row with `edge_kinds = [data]` when the
  full slice was truncated and the data-only slice was not (so a reviewer always gets the variable
  flow even when control edges blew the bound). `limit` bounds the embedded `nodes` served per
  page: a cursor continues the same row's node list, which is the existing `_request_hash` cursor
  binding applied to a within-row offset. `depth` is rejected (`schema_violation`); slice depth is
  a producer bound, not a query parameter, because the stored slice is the only slice.
- **Gaps.** `slice_truncated_nodes`, `slice_truncated_depth`, `summary_hop_limit` (a data edge
  reached a call beyond `slice_call_hops`), `opaque_call:<display>`, `ambiguous_node_location`
  (macro-expanded nodes until K2), `subject_not_sliced` (a subject beyond
  `max_slices_per_scope`, chosen deterministically by identity; the coverage row is `partial`),
  `recursion_collapsed`.
- **Cross-check.** None in phase 1 (`not_covered`). Section 9 names the SVF SVFG backward slice as
  a possible `graph-cross-check/4` input for `data` edges on C/C++ pointer operands.
- **R4 predicates.** Indirect for every predicate. A slice may qualify
  `source_to_sink_reachability` (it shows the local dependency structure around a path step) and
  `missing_or_ineffective_guard` (its `condition` nodes are exactly the guards on the operand's
  dependency chain, including guards on *other* variables that `guard_fact` reports as
  `constrains_sink_operand = unknown`). It never supports reachability on its own: a slice is
  intraprocedural plus bounded summaries, and summaries are indirect (4.4 of the code-graph
  design).

### 4.3 `type_layout` and the `type_layout` mode

- **Producer.** `TypeLayouts.ql`: for each selected record type (G-D5), `Class.getSize()`,
  `getAlignment()`, each `Field`'s `getByteOffset()`, `getType().getSize()`, bit-field width and
  offset, array element type and `ArrayType.getArraySize()`, flexible array members (`[]` or `[0]`
  or `[1]` last member, reported with `flexible: true` and the idiom), unions (`is_union`), base
  classes with their offsets, virtual-table pointer presence, and packing or alignment attributes
  CodeQL records. The extractor computed these for the traced build, so they describe the compiled
  configuration, not a platform guess.
- **Result.**

  ```json
  {"type": {"qualified_name": "struct packet", "kind": "struct" | "class" | "union",
            "definition": {…}, "size_bytes": 72, "alignment": 8, "has_vtable": false, "packed": false},
   "fields": [{"index": 0, "name": "len", "type_display": "uint16_t", "offset_bytes": 0,
               "size_bytes": 2, "bit_offset": null, "bit_width": null,
               "array": {"element_type": "char", "element_count": 64, "element_size": 1} | null,
               "flexible": false, "nested_layout": "asr:type_layout:…" | null}],
   "bases": [{"qualified_name": "…", "offset_bytes": 0, "virtual": false}],
   "fields_truncated": false, "selected_because": ["sink_destination:asr:sink_site:…"]}
  ```
- **Mode.** `type_layout(subject)`: for a `sink_site`, the layouts of the destination operand's
  static type and its pointee, then nested layouts to `max_layout_depth`; for a `buffer_bound`, the
  layout its basis names; for a `symbol`, the layout whose definition span equals the symbol's
  definition (clangd type symbols join by `SAME_AS`, exact only when the byte span is equal). Order
  `(depth, identity)`.
- **Gaps.** `fields_truncated` (more than `max_layout_fields`), `layout_depth_limit`,
  `type_not_exported` (a `symbol` subject naming a type the export did not select),
  `template_dependent_size` (a dependent type with no instantiation in scope: sizes `null`),
  `incomplete_type`, `size_unknown`.
- **Cross-check (C/C++).** `tool-native-cpp` adds a `layouts` mode that runs the accepted compile
  command with `-Xclang -fdump-record-layouts-simple` for the TUs that define selected types, with
  no new network access. `graph-cross-check/4` compares `size_bytes`, `alignment` and every field
  offset by qualified name: all equal is `agree`; any difference is `disagree` with `CONTRADICTS`
  to the `ast_node` or a new `clang-ast` layout record and makes the fact ineligible for citation
  as exact (it stays indirect anyway; the state tells the reviewer the two compilers disagree,
  which usually means a different `-m` or packing flag was replayed); a type Clang did not print is
  `not_covered`.
- **R4 predicates.** Indirect for every predicate.

### 4.4 `buffer_bound` and the `buffer_bounds` mode

- **Producer.** `BufferBounds.ql`: for each `sink_site` of class `memory_write`, `memory_read` or
  `allocation_size`, the destination (or source, for reads) operand's capacity:

  | Basis | How computed | Exactness |
  |---|---|---|
  | `array_type` | the operand is an array-typed lvalue or its address; capacity is `getArraySize() * element size` | exact |
  | `field_size` | the operand is a field access; capacity is the field's size from `TypeLayouts.ql`, and `remaining_to_end_of_record` is also reported for the "overflow into the next field" question | exact |
  | `record_size` | the operand is a whole-record lvalue or pointer to one | exact |
  | `flexible_array_member` | the field is flexible; capacity depends on the allocation, reported as `unknown` with the allocation sites found by local flow | unknown |
  | `allocation_constant` | the operand locally flows from an `AllocationFunction` call whose size argument is a constant (or `sizeof` expression CodeQL evaluates) | exact |
  | `allocation_expression` | the size argument is not constant; the row carries the size expression's `range_fact`-style interval from `SimpleRangeAnalysis` and the expression display | over-approximate |
  | `string_literal` | the operand is a string literal; capacity is its length plus one | exact |
  | `unknown` | none of the above | unknown |

  One row per `(sink, operand_index)`, with every allocation site local flow found (bounded by
  `max_allocation_sites_per_operand`) when the basis is an allocation.
- **Result.**

  ```json
  {"sink": {"sink_site": "asr:sink_site:…", "sink_class": "memory_write"}, "operand_index": 0,
   "operand": {"location": {…}, "display": "pkt->payload", "type_display": "char[64]"},
   "capacity": {"bytes": 64, "elements": 64, "element_size": 1} | "unknown",
   "basis": "array_type", "layout": "asr:type_layout:…" | null,
   "remaining_to_end_of_record": 68 | null,
   "allocation_sites": [{"location": {…}, "display": "malloc(hdr->len)", "size_interval": {"lower": "0", "upper": "unknown"}}],
   "size_operand": {"operand_index": 2, "range_fact": "asr:range_fact:…"} | null,
   "precision": "exact" | "may_over_approximate" | "unknown"}
  ```

  `size_operand` joins the sink's length argument to its `range_fact`, so one row shows capacity
  and the interval that is written into it. The row does not compare them: the comparison is a
  review judgment over two citable facts (open question 1).
- **Mode.** `buffer_bounds(subject)`: all `buffer_bound` rows of a `sink_site`, or of every memory
  sink contained by a function `symbol`. Order `(operand_index, identity)`; `sink_class` filter is
  accepted for the `symbol` subject.
- **Gaps.** `capacity_unknown:<basis>`, `allocation_sites_truncated`, `multiple_allocation_sites`
  (different constants; the row reports the minimum and lists all), `interprocedural_allocation`
  (the buffer came in as a parameter; local flow cannot reach the allocation; the forward slice from
  the parameter is the follow-up), `layout_disagree` (inherited from a `disagree` layout).
- **Cross-check.** Through its `type_layout` row only. Constant allocation sizes are also an input
  K3 may confirm from IR when it lands.
- **R4 predicates.** Indirect for every predicate in phase 1.

### 4.5 `control_flow` (internal) and `sink_site.cfg_context`

- **Producer.** `ControlFlow.ql` (K5): for each function that contains an exported sink or guard,
  its `BasicBlock`s (span, successor edges with the branch condition and polarity, loop header
  flag, loop depth), `dominates` pairs between blocks that hold a sink or a guard only (not the
  full dominator relation), and the blocks that are post-dominated by a `return` of a negative or
  null constant or by a `goto` to a label whose block frees memory (`error_path_candidate`). Bounded
  by `max_cfg_blocks_per_function`; a function over the bound publishes a coverage-only gap.
- **Family.** `control_flow` is published in the `graph` index with
  `admissibility.direct_eligible = false` and the reason `not_model_facing`; no mode serves it;
  `trace` does not reach it from any model-facing row (no relations point at it). It is read by
  the slice producer (`control` edges), by K3 when it lands, and by the normalizer for the
  enrichment below. Its coverage row is `graph:<scope>:control_flow`.
- **`sink_site.result.cfg_context`** (a `graph-normalize/2` change): `{in_loop: bool | "unknown",
  loop_depth: int | null, error_path_candidate: bool | "unknown", block_dominated_by_free_of_operand:
  bool | "unknown"}`. The last field joins the sink operand's backward data slice to a call of a
  catalog `memory_free` API (checklist remediation R-UAF) in a dominating block. It is context, not a
  use-after-free finding: `"unknown"` is the default whenever the slice or CFG is incomplete.

This is the whole of what the retired `control_flow` query set returns to reviewers: three fields
on a sink and the `control` edges of a slice. Everything else about the CFG remains a producer
input.

## 5. `query_code_graph` contract changes

### 5.1 Schema

`mode.enum` gains `aliases`, `slice_backward`, `slice_forward`, `type_layout`, `buffer_bounds`.
No new parameter. `depth` stays `callers`/`callees` only. `sink_class` additionally applies to
`buffer_bounds` with a `symbol` subject. `limit` and `cursor` keep their meaning; for slice modes
they page within the row's `nodes` list (4.2). The `docs/schemas/retrieval-mcp-tools.json` mirror
changes only when G5 lands, together with the `TOOLS` equality test.

### 5.2 Mode table additions

| Mode | Accepted subject kinds | Returns | Order |
|---|---|---|---|
| `aliases` | `sink_site`, `guard_fact`, `entry_point`, `points_to_set` | `points_to_set` rows for the subject's operands, each with `alias_answers` | `(operand.role, identity)` |
| `slice_backward` | `sink_site`, `guard_fact`, `range_fact`, `entry_point` | the stored backward `program_slice` row(s) for the subject | `(edge_kinds, identity)` |
| `slice_forward` | `entry_point`, `sink_site`, `guard_fact` | the stored forward `program_slice` row(s) | `(edge_kinds, identity)` |
| `type_layout` | `sink_site`, `buffer_bound`, `symbol` | `type_layout` rows, nested to `max_layout_depth` | `(depth, identity)` |
| `buffer_bounds` | `sink_site`, `symbol` | `buffer_bound` rows, optional `sink_class` for `symbol` | `(operand_index, identity)` |

A subject kind a mode does not accept is a `schema_violation`, not an empty result.

### 5.3 Bounds, truncation, determinism

- Each mode reads only `graph` shards whose `producer.family` matches, in the capability's index
  allowlist. Cursors bind to the request hash and manifest as today.
- Rows are complete stored records; truncation inside a record (`truncated_nodes`,
  `fields_truncated`, `points_to_truncated`) is both a field and a gap. Paging a slice's nodes
  never re-expands the slice.
- Every response carries the subject scope's coverage rows for the family (`coverage_gaps`), the
  shard identities read and `truncated` when any bound was hit. A subject whose scope has no
  accepted shard of the family yields `[]` with `accepted graph <family> index is unavailable for
  <scope>`; for `aliases` the gap text additionally names whether `job_svf_alias_analysis` was
  disabled, produced no module for the scope, or published the module `unavailable`.
- Response byte bound truncation is recorded as a gap, as for every other mode.

### 5.4 Capability, roles and package scope

- `TOOL_INDEXES["query_code_graph"]` stays `{"graph"}`; the new rows are graph kinds, so
  `CellCapability.graph_scopes` and the scoped MCP adapter admit them exactly as today: a row
  outside the package's entity set is served only when its `payload.scope.scope_id` is in
  `retrieval.graph_scopes`, and the identities its payload references (`dataflow_path` ids in
  `on_paths`, `type_layout` ids, `guard_fact` ids) become addressable. No kind-wide or cross-scope
  grant is added.
- `retrieval.graph_families` lists the new families when their shards apply to the package scope in
  any state but `unavailable`. Packages embed none of the new rows in phase 1 (no new context
  roles); open question 4 covers a `buffer_bound` role for lane A memory leads.
- Role grants are unchanged: the four roles that hold `query_code_graph` get the modes with it.
  `pipeline/guidance/registry.json` and `_ROLE_TOOLS` do not change. The verifier's bounded prompt
  sentence does not change; no prompt may instruct a worker to treat a slice or alias row as a
  guard or path.
- `STRATEGY_SOURCES` is unchanged; no strategy unlocks on the new families.

## 6. Coverage rows, gaps and cross-checks

Per `(scope, family)` coverage row, states follow 7.4 of the code-graph design:

| Family | `complete` | `partial` | `unavailable` |
|---|---|---|---|
| `points_to_set` | every module of the scope closed-world and complete, every queried operand `exact` | any open-world module, truncated set, collapsed field, unmapped operand or DDA budget hit | SVF job disabled, no bitcode, every module `unavailable`, or K1 absent (operands cannot map) |
| `program_slice` | every subject sliced within bounds, every node exact | any truncated slice, ambiguous node, opaque call or unsliced subject | export failed or `Slices.ql` not in the pinned pack |
| `type_layout` | every selected type exported with a known size and cross-check `agree` or `not_covered` | truncated fields, unknown sizes, `disagree` | export failed |
| `buffer_bound` | every memory sink has a row with a known capacity | any `unknown` capacity or truncated allocation sites | export failed or `type_layout` unavailable |
| `control_flow` | every sink-bearing function within the block bound | any function over the bound | export failed |

Named gaps are enumerated per family in section 4. Rules of thumb that apply to every mode:

- A `partial` row never becomes `complete` because a cell did not ask about the missing part.
- A `complete` row plus an empty `aliases` result for a pointer operand means "SVF mapped no
  pointer value to this span", which is `operand_unmapped`, never "no alias".
- `no_alias` is served only from closed-world modules with two exact, complete sets (SVF design
  5.2). The row carries the `closed_world` flag so that the validator, not the cell, can check it.

Cross-check rule versions: `graph-cross-check/3` (SVF, owned by the SVF design) and
`graph-cross-check/4` (Clang record layouts, owned by G2 here). Both are additive over `/2` (K1).
Each bump changes only the fingerprints of the shards it touches.

## 7. Configuration (central TOML)

```toml
[jobs.job_codeql_analysis.settings.export_queries]
# existing: row_limit, max_bytes, timeout_seconds

[[jobs.job_codeql_analysis.settings.languages.cpp.export_queries]]
# existing entries; the pack suite gains Slices.ql, TypeLayouts.ql, BufferBounds.ql, ControlFlow.ql
# and columns.json gains their column contracts. The pack hash and catalog pin change together.

[jobs.job_code_graph_index.settings.graph]
# existing: max_call_depth, max_neighbors_per_function, max_paths_per_sink, max_path_steps,
#           max_guards_per_sink, max_facts_per_family_per_scope, max_export_bytes, export_timeout_seconds
max_slice_nodes = 200
max_slice_depth = 12
slice_call_hops = 1                     # 0 disables summary edges
max_slices_per_scope = 20000            # subjects beyond this are `subject_not_sliced`
max_layout_fields = 128
max_layout_depth = 3
max_allocation_sites_per_operand = 8
max_cfg_blocks_per_function = 400
max_alias_answers_per_operand = 16

[jobs.job_svf_alias_analysis.settings]
# existing (SVF design 6.3); additions:
query_source_operands = true            # fourth query class, 4.1
publish_points_to_sets = false          # opt-in: republish into the graph index for `aliases`
```

`GraphSettings` gains the new integers with the same positive-integer validation; `slice_call_hops`
is the one field allowed to be `0`. `RetrievalCore` reads them from the run-bound resolved
configuration (`graph/settings.py`) like `max_call_depth`. Nothing here is a prompt setting.

## 8. Job and shard topology

```text
job_codeql_analysis
  export.scopes  (pack gains Slices, TypeLayouts, BufferBounds, ControlFlow; one export checkpoint)
      |
job_svf_alias_analysis (SVF design; +source operands)
      |            \
job_code_graph_index
  load.accepted_inputs -> normalize.scopes (+4 families, cfg_context) -> crosscheck.scopes (/3 SVF, /4 layouts)
      -> correlate.scopes -> acceptance.publish_handoff (+points_to_set republication)
      ^ accepted: cpp_compiled_analysis (+`layouts` branch), svf_alias (when enabled)
```

- New export queries ride the existing `export.scopes` unit and checkpoint; a query timeout fails
  the whole scope export as today (code-graph design 8, fallbacks), so `Slices.ql` must be bounded
  inside the query (`max_slice_nodes` is applied in QL as well as in the normalizer) and its row
  bound set in `export_queries.row_limit`. An operator can leave the new queries out of the suite
  until the live tier shows their cost; the families are then `unavailable` with the reason
  `query_not_in_suite`.
- Shards: `graph-<scope_id>-program_slice`, `-type_layout`, `-buffer_bound`, `-control_flow`,
  `-points_to_set`. Relations live in the shard of their fact endpoint. Coverage rows as above.
- Checkpoint identity additions: the new rule versions, the new settings, the SVF shard identities
  read, the `layouts` branch shard identity.
- `job_cpp_compiled_analysis` gains a `layouts` branch (`-fdump-record-layouts-simple`, bounded
  text, retained as an `analysis` shard of `branch = layouts`), invalidated only by compile identity
  and the branch's own adapter version.
- Dagster: no new job for G1 to G3; `job_svf_alias_analysis` placement is the SVF design's.

## 9. Implementation chunks

Following `.claude/skills/parallel-implementation/SKILL.md`. G0 lands first. G1, G2 and G3 run in
parallel after G0 and are independent of SVF. G4 needs S0 to S4 of the SVF design and K1. G5 needs
the families of whichever producer chunks landed and can ship modes incrementally (a mode whose
family has no producer returns the `unavailable` gap, which is already the behavior for a missing
shard). G6 integrates.

| Chunk | Owned files | Done when |
|---|---|---|
| **G0** Contract | `graph/contract.py` (families, modes, vocabularies, identities, settings), `retrieval/model.py` (kinds), `tests/graph/test_contract.py` | enums closed and sorted-stable; identities deterministic; `GRAPH_FACT_PREDICATES` unchanged and asserted to exclude the new families; settings validate |
| **G1** Slices | `rules/codeql-graph-export/cpp/Slices.ql`, `columns.json`, `graph/normalize.py` (`program_slice`, `on_paths` join), `tests/graph/test_normalize_slices.py`, synthetic export fixtures | golden slices for: a sink whose operand flows from a parameter through one summary hop; a guard on another variable appearing as a `condition` node; a declaration without initializer; a slice cut at the node bound with `frontier` nodes; a path-step join; byte-identical across shuffled rows |
| **G2** Layouts and bounds | `TypeLayouts.ql`, `BufferBounds.ql`, `columns.json`, `graph/normalize.py` (two families), `graph/crosscheck.py` (`graph-cross-check/4`), `containers/tools/native-cpp/native.py` (`layouts` mode), `job_cpp_compiled_analysis` (`layouts` branch), `tests/graph/test_layouts.py`, `tests/test_cpp_layout_dump.py` | golden layouts for a packed struct, a union, a flexible array member, a class with a vtable and a base; every basis row of 4.4 has a fixture; a Clang offset that differs yields `disagree`; absent dump yields `not_covered` |
| **G3** CFG context | `ControlFlow.ql`, `graph/normalize.py` (`control_flow`, `cfg_context`, `graph-normalize/2`), `tests/graph/test_cfg_context.py` | `in_loop` and `error_path_candidate` match a hand-checked fixture; a function over the block bound publishes a coverage gap and `"unknown"` context; `control_flow` entities are never reachable through `trace` from a model-facing row |
| **G4** Aliases | `jobs/job_svf_alias_analysis` (source operands, `publish_points_to_sets`), `jobs/job_code_graph_index` (republication), `graph/normalize.py` (`REFERENCES` to path steps), `tests/graph/test_points_to_sets.py` | the six SVF fixture programs produce the expected `alias_answers`; an open-world module never yields `no_alias`; disabled publication leaves the family `unavailable` byte-identically |
| **G5** Retrieval modes | `retrieval/graph.py`, `mcp/schema.py`, `docs/schemas/retrieval-mcp-tools.json`, `tests/test_retrieval_code_graph.py` | every mode on fixture shards; subject-kind validation per mode; `depth` rejected; slice node paging with a bound cursor; scoped adapter withholds rows of unlisted scopes and admits referenced identities of listed ones; `TOOLS` equality test |
| **G6** Integration and docs | `tests/integration/test_code_graph_end_to_end.py` additions, `tests/live/test_code_graph_live.py` additions, `docs/operations/code-graph-index.md`, `docs/operations/retrieval-mcp.md`, `code-graph-precomputation.md` producer table, this document's status | offline: a lead package's verifier retrieves the sink's slice, bounds and layout and the claim stays `supported` with unchanged direct relations (the new rows are indirect and change no verdict); live: per-family export cost and row counts on the native fixture and the acceptance target recorded in the verification JSON |

Test tiers: every chunk is offline-first over hand-authored or recorded exports under
`tests/fixtures/graph/codeql_export/synthetic/`, with golden facts under
`tests/fixtures/graph/expected/`. The live tier (pinned CodeQL image, `tool-native-cpp` for
layouts, `tool-svf` for aliases) refreshes recordings and fails until a recording is updated in
the same change as the query, as C1 does today. All pytest sessions use a unique
`--basetemp=test/tmp/<chunk>`.

## 10. Risks, open questions, and what is deliberately not done

### Risks

| Risk | Mitigation |
|---|---|
| `Slices.ql` cost on large scopes (closure per subject) | QL-side node bound; `max_slices_per_scope`; the query can be left out of the suite per language until measured; a timeout fails only this scope's export, as today |
| Slices let a model argue reachability in prose | indirect for every predicate; `on_paths` points at the citable `dataflow_path`; the validator's direct set is unchanged |
| Record layouts differ between CodeQL's extractor and the replayed Clang (flags, target) | cross-check `/4` makes it visible as `disagree`; the layout stays indirect; the gap text names both sizes |
| Buffer bounds invite "fits, therefore safe" | the row never compares capacity to the size operand; both facts are cited and R5 decides; open question 1 keeps the promotion explicit |
| `points_to_set` rows expose SVF internals | abstract objects are allocation-site locations plus field index; no node ids or IR names are served (SVF design, section 4) |
| Schema growth of `query_code_graph` | five closed enum values, no new parameter; the mode table is the only place that grows |

### Open questions

1. **Promote `buffer_bound` + `range_fact` to a direct contradiction of
   `missing_or_ineffective_guard`?** A `graph-fact-predicates/2` rule could make a `buffer_bound`
   with exact capacity direct when the sink's `range_fact` upper bound is a known constant below
   it. Recommendation: not in phase 1; collect live rows first and decide with the same evidence
   the K-phase truth-up produces.
2. **`slice_forward` from `sink_site`:** useful for "what does the result of this read feed"
   (`memory_read` sinks), rarely for writes. Recommendation: accept the subject, bound by the same
   settings, and drop it if live use shows no citations.
3. **Query every `dataflow_path` pointer step in SVF, not only sink, guard and source operands?**
   This would remove `step_not_queried` at the cost of many more operand queries per module.
   Recommendation: no in phase 1; raise `max_operand_queries_per_module` before widening classes.
4. **Package context role `buffer_bound` for lane A memory leads?** It would put capacity next to
   the sink in the lead package. Recommendation: after G6's live counts, as a v5 package schema
   change with its own `max_context_entries` accounting.
5. **Catalog `memory_free` sink class and `memory_read` entries.** The checklist (R-UAF, R-OOB-R)
   proposes them; they are catalog changes with their own pin, not part of this design's chunks.
   Recommendation: land them as a catalog revision before G3 so `cfg_context` can use them.

### Deliberately not done

- No model-facing CFG mode, no block or edge rows for reviewers (G-D4).
- No `variable_flow` mode (G-D3); no second taint producer; no SVFG paths (SVF design, section 9).
- No new direct families, no change to R4, R5, `evidence-admissibility/2` or
  `graph-fact-predicates/1` in phase 1.
- No new parameter on `query_code_graph`; no free-text, name, path or depth for the new modes.
- No new role grants, prompts, personas or runtime skills.
- No LLVM/SVF slice producer; the `alias` edge kind is reserved and unused until a cross-check
  decision exists.
- No change to `docs/operations/*` or `docs/schemas/retrieval-mcp-tools.json` until the
  corresponding chunk lands.
