---
title: "debug_symbol_indexing"
kind: "operations"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_debug_symbol_indexing"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# debug_symbol_indexing

This page contains the generated contract; the authored process and acceptance description are tracked by [T-130](../TODO.md).

<!-- generated:begin job=job_debug_symbol_indexing -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

debug_symbol_indexing

Job: `job_debug_symbol_indexing`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_debug_symbol_indexing/job.py#L746) |
| `decide` | `decide.target` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_debug_symbol_indexing/job.py#L739) |
| `extract` | `extract.clang_dwarf` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_debug_symbol_indexing/job.py#L740) |
| `extract` | `extract.msvc_pdb` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_debug_symbol_indexing/job.py#L743) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_artifact_indexing` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_artifact_indexing` | `artifact_catalog` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_artifact_indexing` | `archive_members` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_artifact_indexing` | `artifact_relationships` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_artifact_indexing` | `artifact_index_summary` | `appsec-review/artifact-indexing/1` | handoff | optional | gap |
| `job_language_build` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_language_build` | `topology_refinement_inputs` | `appsec-review/build-topology-refinement/1` | handoff | optional | gap |
| `job_language_build` | `build_actions` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_language_build` | `jvm_build_actions` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_language_build` | `language_build_receipts` | `appsec-review/language-build-handoff/2` | handoff | optional | gap |
| `job_language_build` | `build_workspaces` | `application/octet-stream` | handoff | optional | gap |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `debug_symbol_summary` | `acceptance` | `appsec-review/debug-symbol-indexing/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `normalized_symbols` | `extract` | `appsec-review/retrieval-index/2` | indexed | `debug_symbols` | `query_debug_symbols` |
| `raw_artifact_refs` | `extract` | `appsec-review/debug-symbol-inputs/1` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `reader_executions` | `extract` | `appsec-review/container-execution/1` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `symbol_coverage` | `extract` | `appsec-review/debug-symbol-coverage/1` | artifact_only | Not indexed | `coverage`, `query_debug_symbols` |
| `target_decision` | `decide` | `appsec-review/debug-symbol-decision/2` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | None declared |
| integration | `tests/integration/job_debug_symbol_indexing/test_debug_symbol_indexing_graph.py`<br>`tests/integration/job_debug_symbol_indexing/test_debug_symbol_execution.py`<br>`tests/integration/job_debug_symbol_indexing/test_debug_symbol_end_to_end.py`<br>`tests/integration/job_artifact_indexing/test_artifact_indexing_scale.py` |
| live | None declared |
| unit | `tests/unit/job_debug_symbol_indexing/test_contract.py`<br>`tests/unit/job_debug_symbol_indexing/test_job_graph.py`<br>`tests/unit/job_debug_symbol_indexing/test_workflow.py`<br>`tests/unit/job_debug_symbol_indexing/test_settings.py`<br>`tests/unit/job_debug_symbol_indexing/test_host_bindings.py`<br>`tests/unit/job_debug_symbol_indexing/test_accepted_inputs.py`<br>`tests/unit/job_debug_symbol_indexing/test_decision.py`<br>`tests/unit/job_debug_symbol_indexing/test_probe_and_privacy.py`<br>`tests/unit/job_debug_symbol_indexing/test_sources.py`<br>`tests/unit/job_debug_symbol_indexing/test_source_bounds.py`<br>`tests/unit/job_debug_symbol_indexing/test_extract.py`<br>`tests/unit/job_debug_symbol_indexing/test_normalize.py`<br>`tests/unit/job_debug_symbol_indexing/test_publish.py`<br>`tests/unit/job_debug_symbol_indexing/test_accepted_loader.py`<br>`tests/unit/job_debug_symbol_indexing/test_metrics.py`<br>`tests/unit/runtime/test_wave1a_contracts.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_artifact_indexing`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_debug_symbol_indexing"]
  producer0["job_artifact_indexing"]
  input0["handoff"]
  input_schema0["appsec-review/job-handoff/2"]
  producer0 --> input0 --> job
  input0 -. schema .-> input_schema0
  producer1["job_artifact_indexing"]
  input1["artifact_catalog"]
  input_schema1["appsec-review/retrieval-index/2"]
  producer1 --> input1 --> job
  input1 -. schema .-> input_schema1
  producer2["job_artifact_indexing"]
  input2["archive_members"]
  input_schema2["appsec-review/retrieval-index/2"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_artifact_indexing"]
  input3["artifact_relationships"]
  input_schema3["appsec-review/retrieval-index/2"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  producer4["job_artifact_indexing"]
  input4["artifact_index_summary"]
  input_schema4["appsec-review/artifact-indexing/1"]
  producer4 --> input4 --> job
  input4 -. schema .-> input_schema4
  producer5["job_language_build"]
  input5["handoff"]
  input_schema5["appsec-review/job-handoff/2"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_language_build"]
  input6["topology_refinement_inputs"]
  input_schema6["appsec-review/build-topology-refinement/1"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_language_build"]
  input7["build_actions"]
  input_schema7["appsec-review/retrieval-index/2"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_language_build"]
  input8["jvm_build_actions"]
  input_schema8["appsec-review/retrieval-index/2"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_language_build"]
  input9["language_build_receipts"]
  input_schema9["appsec-review/language-build-handoff/2"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_language_build"]
  input10["build_workspaces"]
  input_schema10["application/octet-stream"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  output0["debug_symbol_summary"]
  output_schema0["appsec-review/debug-symbol-indexing/1"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["normalized_symbols"]
  output_schema1["appsec-review/retrieval-index/2"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["raw_artifact_refs"]
  output_schema2["appsec-review/debug-symbol-inputs/1"]
  job --> output2
  output2 -. schema .-> output_schema2
  output3["reader_executions"]
  output_schema3["appsec-review/container-execution/1"]
  job --> output3
  output3 -. schema .-> output_schema3
  output4["symbol_coverage"]
  output_schema4["appsec-review/debug-symbol-coverage/1"]
  job --> output4
  output4 -. schema .-> output_schema4
  output5["target_decision"]
  output_schema5["appsec-review/debug-symbol-decision/2"]
  job --> output5
  output5 -. schema .-> output_schema5
```

<!-- generated:end -->
