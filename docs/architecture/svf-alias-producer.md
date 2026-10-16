# SVF points-to producer

Status: **implemented 2026-10-16, opt-in.** It is verified offline against recorded real tool output,
and live against the pinned image on a synthetic fixture and on a copied multi-vulnerability C/C++
project. Operations are in [`../operations/svf-alias-analysis.md`](../operations/svf-alias-analysis.md),
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

Every record also carries the module identity, kind and label, `module_closed_world`,
`open_world_reasons` and up to 64 `unmodeled_externals`. Locations are exact points (`llvm-dilocation`).
A column of 0 is an ambiguous whole-line location, which the cross-check skips. Sites outside
accepted sources, such as system headers, are counted and not published.

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

## 7. Verification

| Tier | What it proves |
|---|---|
| `tests/test_svf_alias_analysis.py` | module planning (archives, shared libraries, unlinked units, bounds); scope analysis over recorded real output (records, exact points, closed-world marking, coverage rows); every failure mode (container exit, timeout, missing image, malformed or missing result, module failures, bound overruns, output escape, missing bitcode, lossy debug info, sites outside accepted sources); checkpoint reuse; settings and topology validation |
| `tests/test_svf_tool.py` | wrapper flag rewriting; compile, link and analysis outcomes, and plan validation, with the process runner faked |
| `tests/graph/test_svf_crosscheck.py` | every row of 6.1 and 6.2 over a shard the job publishes from recorded output; determinism; `function_tail`; graph-job routing of SVF shards |
| `tests/live/test_svf_live.py` | the real pinned image through the real container executor. On the synthetic fixture (`containers/fixtures/svf`) the live output must equal the offline recordings. On `linux-calibration`, a static archive and a shared library link into two executables, and one source is compiled twice: three modules are planned and analyzed, two are closed-world, the function-pointer dispatch resolves to exactly its two targets, and the mismatched `new[]`/`delete` site carries its heap object |

## 8. Relationship to the proposed `aliases` mode

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

That design must reconcile these points before its G chunks start.

## 9. Risks and what is deliberately not done

| Risk | Mitigation |
|---|---|
| Andersen memory and time on large C++ modules | the central 1 GiB/600 s policy plus per-module limits; overruns are module gaps |
| SVF's C++ runtime coverage | unmodeled C++ runtime calls (threads, exceptions, `__cxa_atexit`) correctly make modules open-world, so SVF rarely contradicts on heavy C++; its value is highest for C |
| Debug metadata lost in the LLVM 18 → 21 upgrade | counted per module; a lost location only removes matches |
| Spurious may-alias from the context-insensitive heap | may-alias never contradicts |
| Upstream SVF API changes | one pinned release; a bump is a deliberate image rebuild, re-recording and repin |

Not done, on purpose:

- **No reviewer-facing `aliases` mode.** It would need its own decision against D3 and would be
  indirect-only.
- **No SVFG value-flow paths.** Paths stay with CodeQL (`dataflow_path`).
- **No `saber` leak or double-free findings.** Those would be a source-SAST producer like K4.
- **No optimized-build analysis.** Like every IR producer here, this is `-O0` only.
