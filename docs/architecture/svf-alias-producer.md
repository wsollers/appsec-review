# SVF points-to producer (design)

Status: **proposed, not implemented.** This design adds SVF (Static Value-Flow Analysis) as an
independent C/C++ points-to producer that cross-checks existing `graph` facts. It does not change
which producer is primary. CodeQL stays the primary producer of every fact family
([`code-graph-precomputation.md`](code-graph-precomputation.md) D1). SVF joins clangd, LLVM IR and
the Clang AST as a secondary producer under the same cross-check, eligibility and contradiction
rules.

Licence: SVF is `AGPL-3.0-or-later`. This repository uses it internally, does not redistribute it
and is not a commercial product, so the licence has been accepted for this use. The image still
records the licence, its source and its third-party notices like every other tool image.

## 1. What problem this solves

CodeQL leaves two specific holes in C/C++ graph facts, and both come from pointers:

| Hole today | Where it shows | What points-to adds |
|---|---|---|
| Indirect calls with no resolved targets | `call_site` facts with `dispatch = unresolved_indirect`; `callers`/`callees` closures stop at them | A whole-module target set for each function-pointer call, computed from the actual linked program |
| A guard checks a pointer, but nothing links that pointer to the sink operand | `guard_fact` with `constrains_sink_operand = unknown` (4.6) | A may-alias or no-alias answer for the guard operand and the sink operand |

Callback tables, plugin structs and hand-rolled vtables in C code produce most of these holes, and
they are also where many memory-safety bugs live.

Out of scope: interprocedural taint (CodeQL's job), memory-SSA value-flow paths, and leak or
double-free checking with SVF's `saber`. Section 9 lists what is deliberately not done.

## 2. Decisions

### S-D1 SVF is a cross-check producer and adds no model-facing family

SVF output enters the `graph` index only through `job_code_graph_index`'s cross-check step. The
rules are the existing D1 rules:

- **Agreement** sets `cross_check.state = agree`. It never makes a fact eligible on its own.
- **Disagreement** sets `disagree`, adds a `CONTRADICTS` relation to the SVF record, and makes the
  fact ineligible.
- **SVF-only results** become `secondary_only` facts with `producer = svf` and
  `direct_eligible = false`.

No `aliases` mode is added to `query_code_graph`, and no new R4 predicate mapping is added. D3
applies: points-to sets are inputs to cross-checking, not something a reviewer should rebuild
reachability from in prose. Section 9 covers a possible later indirect-only mode.

### S-D2 Andersen first, demand-driven refinement only for queried operands

The main analysis is SVF's field-sensitive Andersen analysis (`AndersenWaveDiff`). It is
flow-insensitive and context-insensitive, and it runs over one linked module per link unit.
Andersen **over-approximates** relative to the modeled program, which sets what each answer means:

- **may-alias / target ∈ set** is weak evidence. It might be spurious, so it can confirm but never
  contradict.
- **no-alias / target ∉ set** is strong evidence, but *only when the query is closed-world*
  (section 5.3). It is the only SVF answer that can produce `disagree`.

Demand-driven refinement (SVF DDA, flow- and context-sensitive) is optional and runs only for
operands CodeQL facts actually ask about, each with its own budget (`dda_query_budget`). It can turn
a may-alias into a no-alias. It is off by default until live acceptance shows it helps.

### S-D3 The analysis is query-driven from CodeQL facts, not a full points-to dump

A full points-to dump of a real program is unbounded and mostly irrelevant. The job asks only
about:

1. every IR call instruction whose callee is not a constant function, so indirect-call target sets
   are complete for the module (bounded by `max_indirect_calls`);
2. the sink operand of each CodeQL `sink_site` in classes `memory_write`, `memory_read` and
   `allocation_size`;
3. the condition operands of each CodeQL `guard_fact` for those sinks.

Items 2 and 3 come from the accepted raw CodeQL export, which is why the job depends on
`job_codeql_analysis` (section 6).

### S-D4 Bitcode comes from the compiler of record; SVF's own LLVM only reads it

`tool-native-cpp` compiles with clang-18. SVF 3.3 (May 2026) builds against LLVM 21.1. Textual IR
(`.ll`) is not stable across LLVM major versions, but bitcode is readable by later versions. So:

- `native.py`'s `ir` mode additionally runs the image's `llvm-as-18` over each `tu-NNNN.ll` it
  already writes, producing `tu-NNNN.bc` from the **same** IR, without a second compile.
- The SVF image never compiles target code. It links (`llvm-link` 21) and analyzes the clang-18
  bitcode.
- LLVM's auto-upgrade may drop debug metadata it considers malformed. Each module's stripped
  `!dbg` count is recorded, and a non-zero count is the gap `debug_info_upgraded_lossy` on that
  module.

Rebuilding the target with clang-21 is rejected. It would analyze a program that is not the one
CodeQL and clangd saw.

### S-D5 One linked module per link unit

`job_cpp_compiled_analysis` already retains `normalized-link-commands.json`. Each link command
(executable or shared library) becomes one module: `llvm-link` over the bitcode of exactly the
object files that command consumes.

- A TU that no link command consumes is analyzed as a single-TU module, with the gap
  `not_in_link_unit`. Such a module is never closed-world.
- A link failure (duplicate definitions, ODR conflicts) makes the module `unavailable`, with the
  linker's bounded stderr kept as the gap text.
- Static archives are expanded to their member objects when the link database names them. When it
  does not, the gap is `archive_members_unresolved`.

## 3. Prerequisites

| Prerequisite | Why | State |
|---|---|---|
| K1 (exact IR debug locations) | Mapping a CodeQL source span to an IR value needs decoded `DILocation`s | planned ([`code-graph-precomputation.md`](code-graph-precomputation.md) section 12) |
| CodeQL export pack verified on a real database | Query operands come from real export rows, not hand-authored recordings | blocked on this host: pinned CodeQL and C++ build image IDs differ from the local images |
| Matching scope identities | SVF modules must join CodeQL scopes by `build_unit_id` | to verify in S0 (section 8) |

S1 and S2 can start before K1 lands. S3 and S4 need it.

## 4. Tool image `tool-svf`

`containers/tools/svf/`, registered in `containers/catalog.toml` with `dependencies = []` (it
carries its own LLVM).

| Item | Value |
|---|---|
| SVF | release tag `SVF-3.3`, source archive pinned by SHA-256 in `assets.lock.json` |
| LLVM | 21.1.0 RTTI build that SVF's `build.sh` expects, pinned by SHA-256 |
| Z3 | 4.15.4, pinned by SHA-256 |
| Build | multi-stage offline build from prefetched assets (`acquire_assets.sh`, the `native-cpp` pattern). No `git clone` and no network in the final stage |
| Driver | `/opt/appsec/svf-alias-export`: a small repository-owned C++ program linked against `libSvfLLVM`. It reads a JSON request and writes one bounded JSON result (`appsec-review/svf-alias-output/1`). Upstream `wpa`/`dvf` CLIs are not used, because their text output is not a stable contract |
| Wrapper | `/opt/appsec/svf.py`: `version`, `link` (runs `llvm-link`, reports stripped debug metadata), `analyze` (runs the driver under the time budget) |
| `tool.toml` | `license = "AGPL-3.0-or-later"`, `network = "none"`, `user = "10001:10001"`, read-only root, read-only target mount, scratch read-write, `drop-all`, `no-new-privileges`, `memory = "8g"`, `cpus = "2"`, `timeout_seconds = 1800` |
| `LICENSE.md` / `inventory.json` | SVF, LLVM (Apache-2.0 WITH LLVM-exception), Z3 (MIT), and SVF's vendored fastcluster, SparseBitVector and cJSON notices |

The driver is the only code in the image the repository writes, and it is small. It loads the
module, builds the SVF IR, runs Andersen, resolves each requested operand to a `PAG`/`SVFIR` node,
and emits points-to sets as abstract-object identities (allocation site plus field index) with
their `DILocation`. It never prints raw LLVM value names into retained fields that the index
serves.

## 5. Analysis contract

### 5.1 Request (per module)

```json
{"schema": "appsec-review/svf-alias-request/1",
 "module": "module.bc",
 "queries": [{"query_id": "q-…", "kind": "operand", "file": "src/codec.c", "line": 88, "column": 12,
              "operand_role": "sink" | "guard", "fact_identity": "asr:sink_site:…"},
             {"query_id": "q-…", "kind": "indirect_calls"}],
 "bounds": {"field_limit": 64, "max_pts_size": 256, "max_indirect_calls": 20000,
            "max_targets_per_call": 64, "andersen_time_limit_seconds": 900,
            "dda_query_budget": 0}}
```

### 5.2 Result (per module)

```json
{"schema": "appsec-review/svf-alias-output/1",
 "svf_version": "SVF-3.3", "llvm_version": "21.1.0",
 "module": {"sha256": "…", "functions": 0, "pointer_nodes": 0, "abstract_objects": 0,
            "closed_world": true, "open_world_reasons": []},
 "andersen": {"completed": true, "seconds": 0.0},
 "operand_results": [{"query_id": "q-…", "mapping": "exact" | "ambiguous" | "unmapped",
                      "points_to": [{"object": "obj-…", "alloc_site": {"file": "…", "line": 0, "column": 0},
                                     "kind": "stack" | "heap" | "global" | "function", "field": 0}],
                      "truncated": false, "incomplete_reasons": []}],
 "indirect_calls": [{"call": {"file": "…", "line": 0, "column": 0}, "caller": "…",
                     "targets": ["…"], "truncated": false, "incomplete_reasons": []}],
 "gaps": []}
```

Alias answers are computed in the job, not the driver, from two `operand_results` of the same
module:

| Condition | Answer |
|---|---|
| The sets intersect | `may_alias` |
| They are disjoint, both are complete (not truncated, no `incomplete_reasons`) and the module is `closed_world` | `no_alias` |
| Anything else | `unknown`, with the reasons |

### 5.3 When a no-answer is trustworthy (`closed_world`)

A module is `closed_world` only when all of these hold. Every reason it fails is listed in
`open_world_reasons`, and an open-world module can only produce `agree`, `partial` or
`not_covered`:

- every object its link command consumes was linked (no `not_in_link_unit`,
  `archive_members_unresolved` or missing bitcode);
- it does not reference `dlopen`, `dlsym`, `LoadLibrary` or `GetProcAddress`;
- every external function it calls with a pointer argument or result is modeled in SVF's ExtAPI
  table. Unmodeled ones are listed by name, up to a bound;
- it has no inline assembly that touches pointers;
- Andersen completed within its time budget.

Per query, `incomplete_reasons` also covers `points_to_truncated` (more than `max_pts_size`),
`field_limit_collapsed` (struct wider than `field_limit`, so fields merged) and `varargs`.

### 5.4 Mapping source spans to IR values

Each query uses K1's `DILocation` decoding. An operand is `exact` when exactly one IR
pointer-typed value's `DILocation` matches the CodeQL span's line and column for the expected role
(the store or load address for memory sinks, the compared value for guards). Zero matches is
`unmapped`; several is `ambiguous`. Neither may produce `disagree`. Macro-expanded spans use K2's
spelling ranges when they exist and are otherwise `ambiguous`.

## 6. Job `job_svf_alias_analysis`

### 6.1 Units

```text
job_svf_alias_analysis
  load.accepted_inputs -> plan.modules -> link.modules -> analyze.modules -> acceptance.publish_handoff
      ^ accepted: cpp_compiled_analysis (IR bitcode, normalized-link-commands.json, source hashes),
        codeql_analysis (graph export manifest and rows for sink_site and guard_fact)
```

- **`plan.modules`**: groups bitcode by link command (S-D5), builds each module's request from the
  CodeQL rows of the matching scope, and applies `max_modules_per_scope`.
- **`link.modules`** and **`analyze.modules`**: run one container per module, up to the job's
  `workers`. A failure is a module-level gap and never stops sibling modules.
- **`acceptance.publish_handoff`**: publishes one `alias` shard per `(scope, module)` with a
  coverage row, through `cpp_index_scopes.publish_scope_indexes` like
  `job_clang_static_analysis`.

### 6.2 Shard contents

New `EntityKind` values (contract chunk S0):

| Kind | One record is |
|---|---|
| `points_to_set` | one queried operand's bounded points-to set, located at the operand span, with the `fact_identity` it was asked for |
| `indirect_call_targets` | one IR indirect call instruction with its SVF target set, located at the call span |

Relations reuse existing kinds: `CALLS` from `indirect_call_targets` to each target `symbol`, when
a target resolves to an accepted clangd or graph symbol, and `DERIVED_FROM` to the `ir_entity` the
call came from.

### 6.3 Configuration (`appsec-review.toml`)

```toml
[jobs.job_svf_alias_analysis]
name = "svf_alias_analysis"
workers = 2

[jobs.job_svf_alias_analysis.settings]
enabled = false                    # opt-in until live acceptance passes
max_modules_per_scope = 32
max_module_bitcode_bytes = 268435456
field_limit = 64
max_pts_size = 256
max_indirect_calls = 20000
max_targets_per_call = 64
max_operand_queries_per_module = 5000
andersen_time_limit_seconds = 900
dda_query_budget = 0               # 0 disables demand-driven refinement
max_output_bytes = 33554432
```

The container memory limit stays in `tool.toml`. When it is disabled, the job is omitted from
execution plans, just like `job_cpg_analysis`.

### 6.4 Placement, fingerprints and resume

- **Dagster `wave1_review`.** The job depends on `job_cpp_compiled_analysis` and
  `job_codeql_analysis`. `job_code_graph_index` depends on it when it is registered, the same way
  it treats `job_clang_static_analysis`.
- **Module checkpoint identity.** It binds the bitcode hashes, the link command, the CodeQL export
  manifest hash, the request bounds, the image ID, the driver version and the job implementation
  hash. A changed CodeQL export reruns only `plan` and `analyze`. It never relinks, because module
  bytes are independent of queries.
- **Invalidation.** A SARIF suite change does not rerun this job. A changed export pack or catalog
  does, because the query set changes.

## 7. Cross-check rules (`graph-cross-check/3`)

K1 owns `graph-cross-check/2`. This design adds `/3` in `graph/crosscheck.py` and
`Producer.SVF = "svf"` in `graph/contract.py`.

### 7.1 `call_site` indirect calls

Matching is by exact call span. This needs K1, and calls without one are `not_covered`.

| CodeQL fact | SVF result | State |
|---|---|---|
| `function_pointer_resolved` or `virtual_resolved`, targets T | SVF set S ⊇ T | `agree` (extra SVF targets are listed in the cross-check record, not published as facts) |
| same | some t ∈ T is not in S, and both the module and the call are complete | `disagree`, with a `CONTRADICTS` relation to the `indirect_call_targets` record |
| same | some t ∈ T is not in S, but the call is incomplete or the module is open-world | `partial` |
| `unresolved_indirect` | S non-empty | one `secondary_only` `call_site` fact per target (`producer = svf`, `dispatch = function_pointer_resolved`, ineligible). The original fact keeps `unresolved_indirect` and links to the new facts with `DERIVED_FROM` |
| any | span unmapped, module unavailable or no SVF shard | `not_covered` |

The `callers`/`callees` closure (4.2) may traverse `secondary_only` SVF edges. Each row reached that
way carries `producer = svf` and stays ineligible, so the reviewer sees where the closure depends on
points-to.

### 7.2 `guard_fact` operand aliasing (pointer operands only)

| CodeQL `constrains_sink_operand` | SVF answer for (guard operand, sink operand) | State |
|---|---|---|
| `true` | `may_alias` | `agree` |
| `true` | `no_alias` (closed-world, both exact) | `disagree`, with `CONTRADICTS`, so the guard fact is ineligible |
| `unknown` | `may_alias` or `no_alias` | `partial`; the answer is recorded on the cross-check, and the fact stays `unknown` and ineligible as today |
| `false` | `may_alias` | `partial`; may-alias cannot overturn CodeQL's answer |
| any | `unknown`, non-pointer operands, or no SVF shard | `not_covered` |

SVF never sets `constrains_sink_operand` and never makes a fact eligible. It can only add doubt.
This follows R3: static evidence is a second opinion, and absence is a gap.

## 8. Implementation chunks

Following `.claude/skills/parallel-implementation/SKILL.md`. S0 lands first. After that, S1 and S2
run in parallel. S3 and S4 need S0, K1 and the live-verified CodeQL export. S5 integrates.

| Chunk | Owned files | Done when |
|---|---|---|
| **S0** Contract | `graph/contract.py` (`Producer.SVF`, `graph-cross-check/3` constant), `retrieval/model.py` (two entity kinds), `docs/schemas/svf-alias-*.schema.json`; a check that CodeQL and compiled-analysis scopes share `build_unit_id` | contract tests pass and schemas validate fixtures |
| **S1** Bitcode emission | `containers/tools/native-cpp/native.py` (`llvm-as-18` after each `.ll`), `job_cpp_compiled_analysis` (retain `.bc` as run-owned artifacts) | the native fixture yields `.bc` files whose hashes are recorded; `.ll` output is unchanged |
| **S2** Image | `containers/tools/svf/` (Dockerfile, `acquire_assets.sh`, `assets.lock.json`, `tool.toml`, `LICENSE.md`, `inventory.json`, `svf.py`, `driver/`), `containers/catalog.toml` | offline build; `version` matches; fixture modules give the expected JSON; the security acceptance (no network, read-only, non-root) passes |
| **S3** Job | `src/appsec_review/jobs/job_svf_alias_analysis/`, `appsec-review.toml`, Dagster adapter registration, `docs/operations/svf-alias-analysis.md` | recorded driver outputs drive unit tests for planning, bounds, every gap in 5.3 and resume; disabled-by-default omission is tested |
| **S4** Cross-check | `graph/crosscheck.py`, `tests/graph/test_svf_crosscheck.py` | every row of the tables in 7.1 and 7.2 has a test; no SVF shard leaves every fact `not_covered` with byte-identical output |
| **S5** Integration | `indexing/matrix.py` (`svf_alias` input row as a cross-check input), this doc's status, `code-graph-precomputation.md` producer table, `tests/live/test_svf_alias_live.py` | the live tier runs on the acceptance target and the status columns record what was observed |

Fixture programs (`containers/fixtures/svf/`), each with recorded expectations:

1. a callback table dispatched through a struct field, where CodeQL is `unresolved_indirect` and
   SVF resolves the targets;
2. two struct fields of the same object, which must stay distinct under the field limit;
3. a NULL check on an alias of the written pointer (`agree`), and on an unrelated pointer
   (`disagree`);
4. a `dlopen`/`dlsym` program, which must be open-world, so no `disagree` is possible;
5. two TUs defining the same symbol, which must produce a link failure gap;
6. a struct wider than the field limit, which must produce `field_limit_collapsed`.

## 9. Risks and what is deliberately not done

| Risk | Mitigation |
|---|---|
| Andersen memory and time grow quickly on large C++ modules | per-module time limit and container memory limit; over budget is a module `unavailable` gap; `max_module_bitcode_bytes` skips oversized modules up front |
| SVF's C++ modeling (templates, exceptions, `std::function`) is weaker than its C modeling | virtual-call cross-check uses only C++ functions whose SVF results are complete; the coverage row counts C++ modules separately; expected value is highest for C |
| Debug metadata lost in the LLVM 18 → 21 upgrade | counted per module (S-D4); a lost location makes queries `unmapped`, never wrong |
| Spurious may-alias from a context-insensitive heap | may-alias can never contradict (S-D2) |
| ExtAPI misses library functions | unmodeled externals make the module open-world (5.3) |
| Upstream SVF changes its API between releases | the driver pins one release; updating it is a deliberate image bump with fixture re-acceptance |

Not done, on purpose:

- **No `aliases` mode for reviewers yet.** If live use shows a need, it would be indirect-only for
  every predicate and require its own decision against D3.
- **No SVFG value-flow paths.** Paths stay CodeQL's (`dataflow_path`). A second path producer would
  need its own path-correlation rules.
- **No `saber` leak or double-free findings.** Those would be a source-SAST producer like K4, not a
  cross-check, and need their own severity normalization.
- **No optimized-build analysis.** Like every IR producer here, this is `-O0` only.
