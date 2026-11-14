---
title: "cpg_analysis"
kind: "operations"
subsystem: "code intelligence"
status: "current"
jobs: ["job_cpg_analysis"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# cpg_analysis

## Purpose

Retain a bounded Joern CPG for accepted native scopes and, in seeded mode, expose the bounded
per-function export that was actually produced. A retained CPG binary is not usable CPG/PDG
coverage, a security observation, or a finding. The producer deliberately publishes a blocked
evidence marker and zero security observations even when a CPG exists.

<!-- generated:begin job=job_cpg_analysis -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

cpg_analysis

Job: `job_cpg_analysis`. Enabled in the dev recipe: **false**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_cpg_analysis/job.py#L355) |
| `generate` | `generate.scopes` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_cpg_analysis/job.py#L327) |
| `load` | `load.accepted_cpp` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_cpg_analysis/job.py#L318) |

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
| `cpg_binary` | `generate` | `application/octet-stream` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `cpg_graph_coverage` | `generate` | `appsec-review/retrieval-index/2` | indexed | `observations` | `coverage`, `find` |
| `cpg_scope_coverage` | `acceptance` | `appsec-review/cpp-index-coverage/1` | indexed | `observations` | `coverage` |
| `cpg_summary` | `acceptance` | `appsec-review/cpg-analysis/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | None declared |
| integration | None declared |
| live | None declared |
| unit | `tests/test_cpg_export.py`<br>`tests/test_cpp_index_jobs.py::test_cpg_job_retains_the_cpg_but_claims_no_coverage`<br>`tests/test_cpp_index_jobs.py::test_cpg_job_is_disabled_by_default_and_runs_no_joern` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **false**.

Declared predecessors: `job_cpp_compiled_analysis`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_cpg_analysis"]
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
  output0["cpg_binary"]
  output_schema0["application/octet-stream"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["cpg_graph_coverage"]
  output_schema1["appsec-review/retrieval-index/2"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["cpg_scope_coverage"]
  output_schema2["appsec-review/cpp-index-coverage/1"]
  job --> output2
  output2 -. schema .-> output_schema2
  output3["cpg_summary"]
  output_schema3["appsec-review/cpg-analysis/1"]
  job --> output3
  output3 -. schema .-> output_schema3
```

<!-- generated:end -->

## Process

Source: [job](../../src/appsec_review/jobs/job_cpg_analysis/job.py),
[seeded execution](../../src/appsec_review/jobs/job_cpg_analysis/seeded.py) and
[export reader](../../src/appsec_review/jobs/job_cpg_analysis/export.py).

### `load`

1. Read and verify accepted compiled-analysis scopes, compile databases, materialized sources and
   manifest via [scope helpers](../../src/appsec_review/jobs/cpp_index_scopes.py).
2. Require the current target snapshot and retain unavailable cases. Do not repair or rebuild them.

### `generate`

1. Re-read scopes and reject a changed plan. If disabled, launch nothing and return named disabled
   coverage for existing scopes. This describes the handler if dispatched; scheduling enablement
   is separate from the in-job flag.
2. If enabled, plan optional seeds and run bounded scope workers. No seeds, or no supported selected
   rows, yields a seeded ledger and blocked shard without running a container.
3. Verify a matching checkpoint or invoke `tool-joern` c2cpg on the accepted source root and
   rewritten compile database. Enforce `max_cpg_bytes` with `RLIMIT_FSIZE` at limit plus one;
   discard partial, oversized, empty or non-regular output. Record timeout, OOM and nonzero exits.
4. Retain a valid CPG and its manifest, accepted database, receipt and resource-limit disposition.
   Always carry `JOERN_GAP`: generation alone is not the missing general CPG/PDG export pipeline.
5. In seeded mode with a valid CPG, run the separate export command with per-file limits. Reject
   failed/missing export output; parse bounded CSV into `cpg-export.json`, retaining per-function
   facts and gaps, then discard raw export intermediates.
6. Publish a blocked evidence entity with zero observations. Exported functions add AST-node
   facts and partial coverage; otherwise coverage is unavailable. Attach seeded ledger/selection
   reasons. Do not checkpoint a failed seeded build; ordinary generated results can be checkpointed.

### `acceptance`

1. Compose scope shards and disabled/unavailable coverage; verify the full manifest.
2. Publish `cpg-analysis-summary.json` with scope, disabled and generated-CPG counts. Observation
   and item counts remain zero. Existing scopes always finish with gaps; no scopes/cases is
   not-applicable.

## Dataflow

```mermaid
flowchart LR
  cpp["accepted C++ scopes"] --> job["job_cpg_analysis"]
  job --> enabled{"generate.scopes: enabled?"}
  enabled -->|yes, selected input| cpg["c2cpg: bounded cpg.bin + manifest"]
  cpg -->|seeded only| export["bounded export: cpg-export.json"]
  export --> shard["observations shard: blocked marker + optional function facts"]
  cpg --> shard
  enabled -. "disabled / no seeds" .-> gaps["unavailable coverage + ledger"]
  cpg -. "failed / too large / no general export" .-> gaps
  export -. "failed / malformed / bounded" .-> gaps
  gaps --> publish["acceptance.publish_handoff"]
  shard --> publish
```

## Gaps

`JOERN_GAP`, `JOERN_DISABLED`, seeded export-scope/no-export/no-seed messages, selection omissions
and tool reasons are **legacy text**, not canonical gap-code names. The
[interchange layer](../architecture/job-interchange.md#the-control-layer-beneath-the-envelope)
wraps them as `producer_reported_gap` with default non-retryable metadata, not an advisory waiver.

- Coverage missing: disabled analysis, retained binary without general source-mapped CPG/PDG
  export, seeded-only extent, absent seeds, unsupported selected units and export parser bounds.
- Tooling failure: CPG/export timeout, OOM, exit failure, missing/empty output, file-size ceiling,
  missing export directory or unusable CSV. Partial CPG bytes are discarded, not evidence.
- Input absent/failed: upstream unavailable catalogs and commandless scopes. Changed accepted
  source/database or mismatched matching-checkpoint manifest raises an integrity exception.

The permanent-looking limitation is still a cost that a specific walk must explicitly approve.

## Acceptance

1. **A. Inputs:** Compare compiled handoff, scope/database/source identities, enabled flag and
   optional seed plan with admitted inputs and actual execution receipts.
2. **B. Independent comparison:** Hash and size-check retained CPG bytes against the manifest and
   limit disposition. In seeded mode compare bounded export function rows with indexed facts.
   Verify zero security observations and distinguish blocked markers from exported functions.
3. **C. Gaps:** Group verified outcomes and compare disabled/no-seed scopes, discarded binaries,
   export failures and inherited unavailable cases to receipts and ledgers. Reconcile all causes
   with the walk's approved expected list.
4. **D. Baseline:** On authorized acceptance, record corpus namespace and `stepwise.py accept`
   baseline with generated/exported/disabled counts and coverage. No CPG or live acceptance was
   produced by this documentation change.

## Resume and invalidation

The scope checkpoint binds accepted scope/database, container database hash, adapter/argv,
tool identity, CPG byte ceiling and seeded identities. Reuse validates receipt, database and CPG
manifest agreement, the retained file boundary and indexed artifacts. Failed seeded builds are
not reused; unseeded gap-bearing results may be. Disabled work must not reuse enabled success as
coverage. [Image pins](image-pin-verification.md) and [signing](signing.md) are shared gates.
The [source](../../src/appsec_review/jobs/job_cpg_analysis/job.py) is authoritative where legacy
operations prose says all export is absent: seeded per-function export exists, general CPG/PDG
coverage does not. Generated bindings remain
[T-147](../TODO.md).
