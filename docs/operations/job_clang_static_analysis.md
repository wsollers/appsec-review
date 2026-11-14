---
title: "clang_static_analysis"
kind: "operations"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_clang_static_analysis"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# clang_static_analysis

## Purpose

Run clang-tidy and Clang's static analyzer over supported accepted compile units and retain
source-bound diagnostics, notes and fix-it presence. This supplies scanner judgments for later
review and graph corroboration, not confirmed vulnerabilities. Seeded mode covers only selected
translation units and explicitly labels diagnostics relative to seeds and their known neighborhood.

<!-- generated:begin job=job_clang_static_analysis -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

clang_static_analysis

Job: `job_clang_static_analysis`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_clang_static_analysis/job.py#L419) |
| `analyze` | `analyze.scopes` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_clang_static_analysis/job.py#L393) |
| `load` | `load.accepted_cpp` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_clang_static_analysis/job.py#L385) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_cpp_compiled_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
| `job_cpp_compiled_analysis` | `cpp_build_graph` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `clang_ast` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `llvm_ir` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `infer_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `binary_symbols` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `cpp_blocked_branches` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `cpp_plan_and_summary` | `appsec-review/cpp-compiled-analysis/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `cpp_case_material` | `application/octet-stream` | handoff | optional | gap |
| `job_evidence_collection` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_evidence_collection` | `static_tool_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_evidence_collection` | `static_tool_evidence` | `appsec-review/static-tool-evidence/2` | handoff | optional | gap |
| `job_evidence_collection` | `static_tool_io` | `appsec-review/container-execution/1` | handoff | optional | gap |
| `job_target_catalog` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_target_catalog` | `target_artifact_inputs` | `appsec-review/target-artifact-intake/1` | handoff | optional | gap |
| `job_target_catalog` | `source_files` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_target_catalog` | `declaration_symbols` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_target_catalog` | `components` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_target_catalog` | `target_documents` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_target_catalog` | `build_units` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_target_catalog` | `catalog_documents` | `appsec-review/target-catalog/1` | handoff | optional | gap |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `clang_static_observations` | `analyze` | `appsec-review/retrieval-index/2` | indexed | `observations` | `find`, `query_precomputed`, `search` |
| `clang_static_raw` | `analyze` | `application/json` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `clang_static_scope_coverage` | `acceptance` | `appsec-review/cpp-index-coverage/1` | indexed | `observations` | `coverage` |
| `clang_static_summary` | `acceptance` | `appsec-review/clang-static-analysis-handoff/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | None declared |
| integration | None declared |
| live | `tests/live/test_seeded_clang_live.py` |
| unit | `tests/test_clang_static_analysis.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_cpp_compiled_analysis`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_clang_static_analysis"]
  producer0["job_cpp_compiled_analysis"]
  input0["handoff"]
  input_schema0["appsec-review/job-handoff/2"]
  producer0 --> input0 --> job
  input0 -. schema .-> input_schema0
  producer1["job_cpp_compiled_analysis"]
  input1["cpp_build_graph"]
  input_schema1["appsec-review/retrieval-index/2"]
  producer1 --> input1 --> job
  input1 -. schema .-> input_schema1
  producer2["job_cpp_compiled_analysis"]
  input2["clang_ast"]
  input_schema2["appsec-review/retrieval-index/2"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_cpp_compiled_analysis"]
  input3["llvm_ir"]
  input_schema3["appsec-review/retrieval-index/2"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  producer4["job_cpp_compiled_analysis"]
  input4["infer_observations"]
  input_schema4["appsec-review/retrieval-index/2"]
  producer4 --> input4 --> job
  input4 -. schema .-> input_schema4
  producer5["job_cpp_compiled_analysis"]
  input5["binary_symbols"]
  input_schema5["appsec-review/retrieval-index/2"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_cpp_compiled_analysis"]
  input6["cpp_blocked_branches"]
  input_schema6["appsec-review/retrieval-index/2"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_cpp_compiled_analysis"]
  input7["cpp_plan_and_summary"]
  input_schema7["appsec-review/cpp-compiled-analysis/2"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_cpp_compiled_analysis"]
  input8["cpp_case_material"]
  input_schema8["application/octet-stream"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_evidence_collection"]
  input9["handoff"]
  input_schema9["appsec-review/job-handoff/2"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_evidence_collection"]
  input10["static_tool_observations"]
  input_schema10["appsec-review/retrieval-index/2"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_evidence_collection"]
  input11["static_tool_evidence"]
  input_schema11["appsec-review/static-tool-evidence/2"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_evidence_collection"]
  input12["static_tool_io"]
  input_schema12["appsec-review/container-execution/1"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_target_catalog"]
  input13["handoff"]
  input_schema13["appsec-review/job-handoff/2"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_target_catalog"]
  input14["target_artifact_inputs"]
  input_schema14["appsec-review/target-artifact-intake/1"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_target_catalog"]
  input15["source_files"]
  input_schema15["appsec-review/retrieval-index/2"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_target_catalog"]
  input16["declaration_symbols"]
  input_schema16["appsec-review/retrieval-index/2"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  producer17["job_target_catalog"]
  input17["components"]
  input_schema17["appsec-review/retrieval-index/2"]
  producer17 --> input17 --> job
  input17 -. schema .-> input_schema17
  producer18["job_target_catalog"]
  input18["target_documents"]
  input_schema18["appsec-review/retrieval-index/2"]
  producer18 --> input18 --> job
  input18 -. schema .-> input_schema18
  producer19["job_target_catalog"]
  input19["build_units"]
  input_schema19["appsec-review/retrieval-index/2"]
  producer19 --> input19 --> job
  input19 -. schema .-> input_schema19
  producer20["job_target_catalog"]
  input20["catalog_documents"]
  input_schema20["appsec-review/target-catalog/1"]
  producer20 --> input20 --> job
  input20 -. schema .-> input_schema20
  output0["clang_static_observations"]
  output_schema0["appsec-review/retrieval-index/2"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["clang_static_raw"]
  output_schema1["application/json"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["clang_static_scope_coverage"]
  output_schema2["appsec-review/cpp-index-coverage/1"]
  job --> output2
  output2 -. schema .-> output_schema2
  output3["clang_static_summary"]
  output_schema3["appsec-review/clang-static-analysis-handoff/1"]
  job --> output3
  output3 -. schema .-> output_schema3
```

<!-- generated:end -->

## Process

Source: [handler and diagnostic adapter](../../src/appsec_review/jobs/job_clang_static_analysis/job.py),
[seed selection](../../src/appsec_review/jobs/job_clang_static_analysis/seeded.py) and
[scope custody](../../src/appsec_review/jobs/cpp_index_scopes.py).

### `load`

1. Read accepted compiled-analysis catalogs and verify their manifest, compile databases, source
   mappings and target snapshot. Preserve failed or commandless projects as unavailable cases.
2. Freeze planned scope identities; no build is repeated by this job.

### `analyze`

1. Re-read and compare scope sets. Partition supported compile commands; do not launch scopes
   containing only unsupported inputs. In seeded mode, derive an admitted seed plan and the
   compiled-analysis neighborhood per scope.
2. Bind scope, adapter, settings, tool and optional seed/neighborhood identities to a checkpoint.
   Reuse only verified matching evidence. With no seeds or selected supported rows, run no engine
   and preserve the seeded ledger's omissions.
3. Invoke both engines through `tool-clang-static-analysis`, each in its own scratch directory
   with a file-size ceiling. On tool/image exception, timeout, OOM or truncated streams/output,
   discard that engine's result and record why. A failed exit is discarded except seeded per-unit failure reports allow
   successful units to survive.
4. Read bounded JSON diagnostics and per-unit results. Preserve parse/diagnostic-cap reasons.
   Resolve each diagnostic to accepted source; drop unresolved diagnostics with a reason.
   Publish observations, accepted source entities and `OBSERVED_AT` edges, including notes,
   reported severity and fix-it flag.
5. In seeded mode classify placement and record failed/unresolved seeds; never claim whole-scope
   coverage. Publish an observations shard and coverage row. Save full-mode results, but do not
   checkpoint seeded results with engine or translation-unit failures.

### `acceptance`

1. Compose scope shards and unavailable-scope coverage under the
   [retrieval manifest contract](../architecture/python-and-retrieval.md#accepted-index-sets).
2. Publish `clang-static-analysis-summary.json` with upstream identity, per-scope results,
   observation counts and reasons. No runnable scopes and no unavailable cases is not-applicable.

## Dataflow

```mermaid
flowchart LR
  cpp["accepted compile scopes"] --> job["job_clang_static_analysis"]
  seeds["optional admitted seeds + neighborhood"] --> analyze["analyze.scopes"]
  job --> analyze
  analyze --> engines["clang-tidy + clang --analyze"]
  engines --> mapping["bounded diagnostics + accepted source mapping"]
  mapping --> shard["observations + seeded ledger"]
  shard --> publish["acceptance.publish_handoff"]
  engines -. "failure / bounds" .-> gaps["partial or unavailable coverage"]
  mapping -. "unresolved diagnostic" .-> gaps
  gaps --> publish
  cpp -. "changed source or checkpoint evidence" .-> stop["integrity exception"]
```

## Gaps

This producer's text reasons become `producer_reported_gap` through
[interchange](../architecture/job-interchange.md#the-control-layer-beneath-the-envelope). Their
default non-retryable metadata is not advisory classification.

- Input absent/failed: unavailable compiled catalog, missing commands or upstream failure.
  Unsupported units are `SKIPPED_NA`, not failed Clang coverage.
- Tooling failure: unavailable tool/image, timeout, OOM, nonzero engine exit, and seeded per-unit
  failures; malformed/missing JSON is an adapter/output failure.
- Coverage missing: execution/output/diagnostic bounds; diagnostic path outside accepted source;
  no seeds, unselected/unsupported seed units, missing known neighborhood and unresolved seed
  dispositions. Seeded coverage stays partial, or unavailable when every executed engine failed.
- Changed accepted mappings/database or matching checkpoint artifacts raises an integrity error.
  The execution-safety policy may stop at a tool failure before the fallback gap is published.

Read [per-input support](../architecture/jobs-and-runtime.md#per-input-tool-support) separately from
coverage. None of these reasons is automatically expected in a walk.

## Acceptance

1. **A. Inputs:** Compare consumed compiled handoff and source/compile hashes, supported command
   set, and, for seeded mode, seed identities and neighborhood provenance.
2. **B. Independent comparison:** Count diagnostics in each raw engine JSON before normalization;
   reconcile accepted versus dropped locations against source bytes, traces and fix-it flags.
   Compare executed translation-unit lists and per-seed placement with the input plan.
3. **C. Gaps:** Group verified canonical outcomes by code and retained reason; compare failures to
   receipts and parser outputs, and seeded omissions to the ledger. Record the cost of any
   user-approved expected cause.
4. **D. Baseline:** At authorized acceptance, save `stepwise.py accept`, corpus namespace and baseline
   with per-engine diagnostic/coverage counts and seed disposition counts. No live engine run is
   claimed here.

## Resume and invalidation

Scope checkpoints include accepted source/compile identities, adapter version, central settings,
tool identity and seeded identities. Changing engine settings, tool pin, source, compile rows,
seeds or neighborhood invalidates the affected scope. Matching checkpoints verify referenced
evidence; seeded failed engines are deliberately retried rather than reused. Full-mode partial
results may be reused. Runtime unit-level reuse is separate
([resumability](../architecture/jobs-and-runtime.md#wave-1-resumability)).
Generated task/tool bindings remain [T-147](../TODO.md);
this is deterministic tool execution, not model inference.
