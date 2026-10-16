# SVF points-to producer

Status: **implemented 2026-10-16, opt-in.** It is verified offline against recorded real tool output,
and live against the pinned image on a synthetic fixture and on a copied multi-vulnerability C/C++
project. Section 7 adds finding-level context: an object-centric accessor index, and memory and
caller context joined to every C/C++ finding-lead package. Operations are in [`../operations/svf-alias-analysis.md`](../operations/svf-alias-analysis.md),
and the image is documented in [`containers/tools/svf/`](../../containers/tools/svf/README.md).

SVF (Static Value-Flow Analysis) is an independent C/C++ points-to producer that cross-checks
existing `graph` facts. It does not change which producer is primary. CodeQL stays the primary
producer of every fact family ([`code-graph-precomputation.md`](code-graph-precomputation.md) D1).
SVF joins clangd, LLVM IR and the Clang AST as a secondary producer, under the same eligibility and
contradiction rules.

Licence: SVF is `AGPL-3.0-or-later`. This repository uses it internally, does not redistribute it
and is not a commercial product, so the owner accepted the licence for this use. The image still
records the licence, the source and the third-party notices
([`LICENSE.md`](../../containers/tools/svf/LICENSE.md)).

## 1. What problem this solves

CodeQL leaves two specific holes in C/C++ graph facts, and both come from pointers:

| Hole | Where it shows | What points-to adds |
|---|---|---|
| Indirect calls with no resolved targets | `call_site` facts with `dispatch = unresolved_indirect`; `callers`/`callees` closures stop at them | a whole-module target set for each function-pointer call, computed from the linked program |
| A guard checks a pointer, but nothing links that pointer to the sink operand | `guard_fact` with `constrains_sink_operand = unknown` (4.6) | a may-alias or no-alias answer for the guard operand and the sink operand |

Callback tables, plugin structs and hand-rolled vtables in C code produce most of these holes, and
they are also where many memory-safety bugs live.

## 2. Decisions

### S-D1 SVF is a cross-check producer and adds no model-facing family

SVF output enters the `graph` index only through `job_code_graph_index`'s cross-check unit
(`graph/svf_crosscheck.py`), which runs after the clangd/IR/AST cross-check:

- Agreement sets the SVF producer state to `agree`. It never makes a fact eligible on its own.
- Disagreement sets `disagree`, adds a `CONTRADICTS` relation to the SVF record, and makes the fact
  ineligible.
- Evidence too weak to contradict is recorded as a `not_covered` producer entry with its detail.
  This covers open-world exclusions, SVF targets for an unresolved call, and an alias answer when
  CodeQL's constraint is `unknown`. It never changes the fact's state or eligibility, because
  `partial` already removes eligibility under `graph-fact-admissibility/1`.
- An unresolved CodeQL call that SVF resolves gains one `secondary_only` call-site fact per target
  (`producer = svf`, `direct_eligible = false`, linked `DERIVED_FROM` the SVF record).

Each SVF verdict is its own producer entry, `{"name": "svf", "rule": "svf-cross-check/1", ...}`,
inside the fact's unchanged `graph-cross-check/1` block. The block state is the most doubtful
producer state. `query_code_graph` gains no `aliases` mode and no new R4 predicate mapping (D3
applies).

### S-D2 Andersen, and only closed-world negatives contradict

The analysis is SVF's field-sensitive `AndersenWaveDiff`. It is flow-insensitive and
context-insensitive, and it runs over one linked module per link unit. Andersen over-approximates
the modeled program, so:

- **target ∈ set / may-alias** can only confirm or add doubt;
- **target ∉ set / no-alias** contradicts only when every consulted record is complete (not
  truncated, no incomplete reasons) and its module is closed-world (5.3).

SVF's demand-driven refinement (DDA) is not used.

### S-D3 The driver exports pointer sites; the cross-check joins by source span

This replaces the earlier plan to query only CodeQL-reported operands. The driver exports every
pointer site in the module and the cross-check joins by span, which keeps the job independent of
`job_codeql_analysis`: there is no DAG cycle and no dependency on a CodeQL export that has not run
live yet. The driver exports, within its bounds:

- dereferenced pointers: loads and stores whose address is not a direct local or global;
- pointer arguments of direct calls, with the argument index and callee name;
- both operands of pointer comparisons;
- every indirect call with its sorted, demangled target names.

Each site carries its own `DILocation` (inlined-at chains resolve to the outermost call). The
cross-check finds SVF records whose point lies inside a CodeQL span: the call expression for
`call_site`, the condition for `guard_fact`, and the sink expression filtered by sink class and
argument index for the sink operand. Mapping happens in the driver itself, so the planned K1 chunk
is not a prerequisite.

### S-D4 Bitcode comes from the compiler of record

The `tool-svf` runtime stage is `tool-native-cpp`. The wrapper replays each accepted compile command
with clang-18 at `-O0 -g` to bitcode, keeping every semantic flag and dropping output, optimization,
LTO, sanitizer, dependency-file and `-Werror` flags. LLVM 21.1, which SVF-3.3 requires, only links
and reads that bitcode. Every module goes through `llvm-link-21`, even a single unit, so the bitcode
upgrade is uniform. Its "ignoring invalid debug info" warnings are counted as
`debug_info_upgraded_lossy`. Neither `tool-native-cpp` nor `job_cpp_compiled_analysis` changes.

### S-D5 One linked module per link unit

`plan_modules` (`jobs/job_svf_alias_analysis/planning.py`) reads the accepted
`compile_commands[].output_path` and `link_commands`:

- each non-archive link command (executable or shared library) becomes one module, from the bitcode
  of exactly the objects it consumes;
- a static archive is expanded through its own captured archive command and is never a module of
  its own;
- a shared-library input stays external (noted); its functions reach the module only as externals,
  which the driver judges like any other;
- unresolved archives and inputs are named open-world reasons (`archive_members_unresolved`,
  `link_input_unresolved`);
- a compile unit no link consumes becomes a single-unit module with `not_in_link_unit`;
- modules beyond `max_modules_per_scope` are omitted with a gap.

## 3. Tool image `tool-svf`

`containers/tools/svf/`, catalog entry `tool-svf` pinned by `image_id`. The build is offline from
the hash-locked inputs: the SVF-3.3 source, the RTTI LLVM 21.1.0 and Z3 4.8.8 distributions SVF's
`build.sh` names, and a `.deb` tar of the zlib, zstd and libxml2 headers used only by the build
stage. The runtime contains:

- `svf.py`: `version`, and `run plan.json result.json`;
- `svf-alias-export`: the repository-owned driver, built inside the SVF tree against `SvfCore` and
  `SvfLLVM`;
- `llvm-link-21`, `libLLVM.so`, `libz3.so` and `extapi.bc`.

The image runs under the central container policy (no network, read-only root, non-root, 1 GiB,
600 s per scope). It does not get the larger allowance an earlier draft proposed.

The driver writes `appsec-review/svf-alias-output/1`. Abstract objects are keyed per module by
allocation site, name, field and SVF node. Stack objects take their name and line from
`dbg.declare` records, globals and functions from their debug metadata. String literals and constant
globals fold into SVF's one shared constant object, `obj:constant:shared`, which is a real read-only
object, not unknown memory. Black-hole and dummy objects add `unknown_object` to the site's
incomplete reasons instead of becoming keys.

## 4. Analysis contract

### 4.1 Plan (`appsec-review/svf-plan/1`) and run result (`appsec-review/svf-run/1`)

The job writes `/scratch/plan.json` with its planned modules (id, kind, label, compile indexes) and
the driver bounds. The wrapper writes `/scratch/result.json` with:

- one record per compile unit (`produced`, exit status, bounded stderr);
- one record per module, with `status` (`analyzed`, `no_bitcode`, `link_failed`, `too_large`,
  `andersen_time_limit`, `analysis_failed`), `gaps`, `debug_info_warnings` and the relative path of
  the driver document.

The job rejects an output path that escapes scratch, a malformed envelope and any bound overrun.

### 4.2 Published records (`appsec-review/svf-alias-record/1`)

| Entity kind | One record is | Key payload |
|---|---|---|
| `points_to_set` | one pointer site | `role` (`load`, `store`, `call_arg`, `compare`), `operand`, `callee`, `function`, `points_to` keys, referenced `objects`, `truncated`, `incomplete_reasons`, `complete` |
| `indirect_call_targets` | one indirect call | `function`, `targets` (`name`, `demangled`), `target_count`, `truncated`, `complete` |
| `memory_object` | one heap, stack or global abstract object referenced by a published site (4.4) | `object_key`, `kind`, `name`, `field`, `allocator` and `allocator_demangled`, `allocation`, `accessors`, `accessor_counts`, `accessor_total`, `accessors_outside_accepted_sources`, `truncated`, `complete` |

Every record also carries the module identity, kind and label, `module_closed_world`,
`open_world_reasons` and up to 64 `unmodeled_externals`. Locations are exact points (`llvm-dilocation`).
A column of 0 is an ambiguous whole-line location, which the cross-check skips. Sites outside
accepted sources, such as system headers, are counted and not published.

The driver records each heap object's allocating function, for example `malloc`, `_Znam`
(`operator new[]`) or a project wrapper. It also gives every site its function's demangled name.

### 4.3 When a negative answer is trustworthy (`closed_world`)

A module is closed-world only when none of these reasons apply:

- planner reasons: `not_in_link_unit`, `archive_members_unresolved`, `link_input_unresolved`;
- `missing_bitcode` for any of its units;
- driver reasons:
  - `dynamic_loading`: it references `dlopen`, `dlsym` or the Windows equivalents;
  - `pointer_inline_asm`: it contains inline assembly with pointer operands or results;
  - `unmodeled_external_functions`: it calls an external with a pointer argument or result that
    neither SVF's ExtAPI models nor the driver's explicit non-capturing list covers. That list holds
    deallocators, formatted output, read-only string and memory inspection, the `ato*` family,
    pthread mutex calls and exception helpers.

### 4.4 Object-centric accessor index (`svf-memory-object/1`)

A memory finding is judged by the other sites that touch the same object: a use after a free, a
second free, no free at all, or an array allocator paired with a scalar free. The job builds that
fan-in by inverting each module's points-to sets once. Andersen sets are already transitively
closed over copies, fields and calls, so a deeper walk would add nothing.

- **One `memory_object` record** per heap, stack or global object referenced by a published site.
  Functions and SVF's shared constant object get none.
- **Accessors.** Each accessor is the published site's identity, its class, role, callee, function
  and location. Classes are:
  - `free`: a pointer argument to `free`, `realloc` or any `operator delete` overload;
  - `write`: a store;
  - `read`: a load;
  - `compare`: a comparison;
  - `pass`: any other pointer argument.

  Accessors are ordered by class in that order, then by location. At most
  `max_accessors_per_object` are kept, `accessor_counts` and `accessor_total` count all of them,
  and `accessors_outside_accepted_sources` counts sites in system headers.
- **Relations.** Each accessor site has a `REFERENCES` relation to its object.
- **Completeness.** A list is `complete` only when it is untruncated, the module exported every
  site, and the module is closed-world. An incomplete list is never evidence that other accesses
  do not exist.
- **Object bound.** Objects beyond `max_objects_per_module` are not published, and the module's
  coverage names the bound.

## 5. Job `job_svf_alias_analysis`

```text
load.accepted_cpp -> analyze.scopes -> acceptance.publish_handoff
```

- **One container per accepted scope.** Module failures are module-level coverage rows and never
  stop sibling modules.
- **One `analysis` shard per scope, `svf-<scope_id>`.** It holds one coverage row per module
  (`svf:<project>:<label>`) and is published through `publish_scope_indexes` (prefix `svf`), the
  same way as `job_clang_static_analysis`.
- **Placement.** In Dagster the job depends on `job_cpp_compiled_analysis`. `job_codeql_analysis`
  and `job_code_graph_index` list it among their dependencies when it is registered. The graph job
  assigns SVF shards to CodeQL scopes by located paths, like the other secondary shards, and also
  restores them from the job's own accepted handoff.
- **Checkpoint identity.** It covers the accepted scope, link commands, settings, tool identity and
  adapter version. A reused checkpoint re-verifies every artifact it references.
- **Configuration.** The job is `enabled = false` in `appsec-review.toml`. Settings are listed in the
  operations page.

## 6. Cross-check rules (`svf-cross-check/1`)

### 6.1 `call_site` indirect calls

Indirect-call records are matched to a fact when their point lies inside its call span. Targets from
every module covering that span are unioned. Names are compared by unqualified function name
(`function_tail`), which strips parameter lists and template arguments by matching brackets from the
end, so `ns::(anonymous namespace)::f(unsigned long)` matches `f`.

| CodeQL fact | SVF result | Producer state |
|---|---|---|
| `function_pointer_resolved` or `virtual_resolved` | callee ∈ targets | `agree` |
| same | callee ∉ targets, all records complete and closed-world | `disagree`, `CONTRADICTS` to each record |
| same | callee ∉ targets otherwise | `not_covered`, with detail |
| `unresolved_indirect` | targets non-empty | `not_covered`, with detail; one `secondary_only` fact per target |
| any | no record inside the span | no SVF entry |

### 6.2 `guard_fact` operand aliasing

The guard's condition span supplies `compare` sites. The sink's expression span supplies sink-operand
sites: `store` or `call_arg` for `memory_write`, `load` or `call_arg` for `memory_read`, and
`call_arg` for `allocation_size`, with `call_arg` restricted to the sink's `argument_index`. Within
each module, operands with empty points-to sets (such as `NULL`) are dropped:

- **may-alias** when any compare set intersects any sink set;
- **no-alias** when all sets are disjoint and every record is complete and closed-world;
- **unknown** otherwise.

Across modules, any may-alias wins, and no-alias needs every module to agree.

| CodeQL `constrains_sink_operand` | SVF answer | Producer state |
|---|---|---|
| `true` | may-alias | `agree` |
| `true` | no-alias | `disagree`, `CONTRADICTS` to the consulted records |
| `false` | no-alias | `agree` |
| `false` | may-alias | `partial` |
| `unknown` | may-alias or no-alias | `not_covered`, with the answer in the detail |
| any | unknown, no pointer compare, or no SVF record | no SVF entry |

SVF never changes `constrains_sink_operand` or any other CodeQL result field.

## 7. Finding context in review packages

Packages are where finding information reaches a reviewer. Schema v5
([review-package contract](review-package-contract.md#memory-and-caller-context-version-5)) adds
two lead-level contexts. Both apply to every finding-lead package, from any scanner: CodeQL, the
Clang Static Analyzer, clang-tidy, cppcheck or Semgrep.

- **Memory context** (`review/memory_context.py`). For a C/C++ lead, the package embeds three roles
  joined by the lead's path and line, with no relation to any particular scanner needed:
  - `points_to`: the SVF pointer-site records on that line;
  - `indirect_call`: its indirect-call records;
  - `memory_object`: the objects those sites reference, with allocation site, allocator and
    accessor fan-in.

  Missing, open-world, incomplete and bounded context is a named `svf_points_to` gap.
- **Caller context** (`GraphContext.callers` in `review/packages.py`). The lead's enclosing function
  comes from the SVF records on its line, from `sink_site.enclosing_function`, or from `call_site`
  callers on that line. The package embeds the `call_site` facts reaching that function,
  breadth-first to `caller_depth` levels. This is a depth fan-out because call context really is
  transitive. SVF's `secondary_only` edges take part, so callers are found through function
  pointers. Name-based matches, truncation and an unknown enclosing function are named
  `code_graph_callers` gaps.

Two kinds of context get two shapes, deliberately. Alias context is a one-level fan-in by object,
because points-to is already a closure. Call context is a bounded depth walk, because each level
is new information.

### 7.1 Tunables

Depth and fan-out are configuration, not code constants. Each is a required key in
`appsec-review.toml`, validated when the job's configuration loads.

| Setting | Table | Controls | Shipped value | Bounds |
|---|---|---|---|---|
| `max_accessors_per_object` | `jobs.job_svf_alias_analysis.settings` | accessor fan-in kept per memory object | 64 | ≥ 1 |
| `max_objects_per_module` | `jobs.job_svf_alias_analysis.settings` | memory objects published per module | 5000 | ≥ 1 |
| `max_memory_context_entries` | `jobs.job_inference_security_review.settings.packages` | SVF entries per finding-lead package | 24 | 1–1000 |
| `max_callers` | `jobs.job_inference_security_review.settings.packages` | caller fan-out per finding-lead package | 16 | 1–1000 |
| `caller_depth` | `jobs.job_inference_security_review.settings.packages` | caller levels walked from the enclosing function | 2 | 1–4 |

The job's other export bounds (sites, points-to size, indirect calls, targets) are listed in the
[operations page](../operations/svf-alias-analysis.md). Raising a bound changes the identity of the
scope checkpoint (SVF job) or of the package input fingerprint (review job), so the affected
artifacts are rebuilt instead of reused.

## 8. Verification

| Tier | What it proves |
|---|---|
| `tests/test_svf_alias_analysis.py` | module planning (archives, shared libraries, unlinked units, bounds); scope analysis over recorded real output (records, exact points, closed-world marking, coverage rows); every failure mode (container exit, timeout, missing image, malformed or missing result, module failures, bound overruns, output escape, missing bitcode, lossy debug info, sites outside accepted sources); checkpoint reuse; settings and topology validation |
| `tests/test_svf_tool.py` | wrapper flag rewriting; compile, link and analysis outcomes, and plan validation, with the process runner faked |
| `tests/graph/test_svf_crosscheck.py` | every row of 6.1 and 6.2 over a shard the job publishes from recorded output; determinism; `function_tail`; graph-job routing of SVF shards |
| `tests/review/test_packages_memory_context.py` | v5 lead packages: a C/C++ lead from any scanner gets the SVF records at its line and their objects; callers to `caller_depth` with name-match, `max_callers` and depth gaps; a line without records, a file outside every module, a non-C lead and a run without SVF each get the right gap or none; `max_memory_context_entries` keeps objects first; open-world records are kept with a `partial` gap; reassembly is byte-identical; packages validate against the schema |
| `tests/live/test_svf_live.py` | the real pinned image through the real container executor. On the synthetic fixture (`containers/fixtures/svf`) the live output must equal the offline recordings. On `linux-calibration`, a static archive and a shared library link into two executables, and one source is compiled twice: three modules are planned and analyzed, two are closed-world, the function-pointer dispatch resolves to exactly its two targets, and the mismatched `new[]`/`delete` site carries its heap object, whose `memory_object` names allocator `_Znam` and lists the scalar `operator delete` as its first, `free`-class accessor |

## 9. Relationship to the proposed `aliases` mode

[`graph-alias-slice-layout-modes.md`](graph-alias-slice-layout-modes.md) proposes a reviewer-facing
`aliases` mode that republishes this job's records into `graph` shards. It was written against the
earlier, query-driven draft of this design, and the shared vocabulary matches: `points_to_set`,
`Producer.SVF`, and the `may_alias`/`no_alias`/`unknown` answers.

Three of its assumptions differ from what is implemented:

- **`operand.fact_identity`.** Records carry exact source points, not CodeQL operand identities
  (S-D3). The republishing step has to join by span, exactly as `graph/svf_crosscheck.py` does,
  rather than read an identity from the record.
- **DDA refinement and `dda_budget_exhausted`.** DDA is not run (S-D2).
- **`build_unit_id` join.** Scope assignment uses located paths, the same rule as the other
  secondary shards.

That design must reconcile these points before its G chunks start. Its G7 package chunk also
planned to claim package schema v5, which section 7 now uses, so G7 needs v6.

## 10. Risks and what is deliberately not done

| Risk | Mitigation |
|---|---|
| Andersen memory and time on large C++ modules | the central 1 GiB/600 s policy plus per-module limits; overruns are module gaps |
| SVF's C++ runtime coverage | unmodeled C++ runtime calls (threads, exceptions, `__cxa_atexit`) correctly make modules open-world, so SVF rarely contradicts on heavy C++; its value is highest for C |
| Debug metadata lost in the LLVM 18 → 21 upgrade | counted per module; a lost location only removes matches |
| Spurious may-alias from the context-insensitive heap | may-alias never contradicts |
| Upstream SVF API changes | one pinned release; a bump is a deliberate image rebuild, re-recording and repin |

Not done, on purpose:

- **No reviewer-facing `aliases` mode.** Lead packages already embed the records (section 7); a query
  mode would need its own decision against D3 and would be indirect-only.
- **No defect verdicts.** The object index exposes allocator and free pairing, accessor order and
  completeness. It never declares a mismatch, use-after-free or double free; judging them is the
  reviewer's job, cited from these records.
- **No SVFG value-flow paths.** Paths stay with CodeQL (`dataflow_path`).
- **No `saber` leak or double-free findings.** Those would be a source-SAST producer like K4.
- **No optimized-build analysis.** Like every IR producer here, this is `-O0` only.
