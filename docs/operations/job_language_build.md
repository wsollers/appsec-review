---
title: "language_build"
kind: "operations"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_language_build"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# language_build

This page contains the generated contract; the authored process and acceptance description are tracked by [T-130](../TODO.md).

<!-- generated:begin job=job_language_build -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

language_build

Job: `job_language_build`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L2051) |
| `execute` | `execute.dotnet` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1951) |
| `execute` | `execute.go` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1951) |
| `execute` | `execute.java` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1951) |
| `execute` | `execute.native` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1951) |
| `execute` | `execute.node` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1951) |
| `execute` | `execute.php` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1951) |
| `execute` | `execute.python` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1951) |
| `execute` | `execute.rust` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1951) |
| `execute` | `execute.wasm` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1951) |
| `iterations` | `iterations.dispatch` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1849) |
| `load` | `load.dotnet` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1861) |
| `load` | `load.go` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1861) |
| `load` | `load.java` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1861) |
| `load` | `load.native` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1861) |
| `load` | `load.node` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1861) |
| `load` | `load.php` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1861) |
| `load` | `load.python` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1861) |
| `load` | `load.rust` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1861) |
| `load` | `load.wasm` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1861) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_build_environment_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_build_environment_analysis` | `build_environment` | `appsec-review/build-environment-analysis/1` | handoff | optional | gap |
| `job_project_build` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
| `job_project_build` | `topology_refinement_inputs` | `appsec-review/build-topology-refinement/1` | handoff | optional | gap |
| `job_project_build` | `project_build_dispatch` | `appsec-review/project-build-dispatch/3` | handoff | optional | gap |
| `job_project_build` | `probe_workspaces` | `application/octet-stream` | handoff | optional | gap |
| `job_project_build` | `image_build_streams` | `text/plain` | handoff | optional | gap |
| `job_review_intake` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_review_intake` | `model_preflight` | `appsec-review/model-preflight/1` | handoff | optional | gap |
| `job_review_intake` | `binary_evidence` | `appsec-review/binary-evidence-intake/1` | handoff | optional | gap |
| `job_review_intake` | `review_intake` | `appsec-review/review-intake/1` | handoff | optional | gap |
| `job_target_analysis_plan` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_target_analysis_plan` | `planning_feedback_cache` | `appsec-review/target-analysis-proposal/3` | handoff | optional | gap |
| `job_target_analysis_plan` | `analysis_plan` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_target_analysis_plan` | `analysis_plan_documents` | `appsec-review/target-analysis-plan/1` | handoff | optional | gap |
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
| `build_actions` | `acceptance` | `appsec-review/retrieval-index/2` | indexed | `build` | `find`, `query_precomputed`, `trace` |
| `build_workspaces` | `execute` | `application/octet-stream` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `jvm_build_actions` | `execute` | `appsec-review/retrieval-index/2` | indexed | `build` | `find`, `trace` |
| `language_build_receipts` | `acceptance` | `appsec-review/language-build-handoff/2` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `topology_refinement_inputs` | `execute` | `appsec-review/build-topology-refinement/1` | protected | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | `tests/acceptance/job_project_build/test_family_project_builds.py` |
| integration | `tests/integration/job_language_build/test_language_build_graph.py`<br>`tests/integration/job_language_build/test_native_outputs_graph.py`<br>`tests/integration/job_language_build/test_go_graph.py`<br>`tests/integration/job_language_build/test_jvm_graph.py`<br>`tests/integration/job_language_build/test_node_graph.py`<br>`tests/integration/job_language_build/test_php_graph.py`<br>`tests/integration/job_language_build/test_python_graph.py`<br>`tests/integration/job_language_build/test_rust_graph.py`<br>`tests/integration/job_language_build/test_wasm_graph.py` |
| live | `tests/acceptance/job_language_build/test_live_build_toolchains.py`<br>`tests/acceptance/job_language_build/test_live_gradle_provenance.py` |
| unit | `tests/unit/job_language_build/test_contract.py`<br>`tests/unit/job_language_build/test_job_graph.py`<br>`tests/unit/job_language_build/test_job_helpers.py`<br>`tests/unit/job_language_build/test_receipts_and_paths.py`<br>`tests/unit/job_language_build/test_build_output_mapping.py`<br>`tests/unit/job_language_build/test_build_output_scope.py`<br>`tests/unit/job_language_build/test_captured_build_reconciliation.py`<br>`tests/unit/job_language_build/test_elf.py`<br>`tests/unit/job_language_build/test_go.py`<br>`tests/unit/job_language_build/test_go_build_facts.py`<br>`tests/unit/job_language_build/test_go_dependency_output_filtering.py`<br>`tests/unit/job_language_build/test_go_vendored.py`<br>`tests/unit/job_language_build/test_gradle_provenance.py`<br>`tests/unit/job_language_build/test_jvm.py`<br>`tests/unit/job_language_build/test_native_layout.py`<br>`tests/unit/job_language_build/test_native_outputs.py`<br>`tests/unit/job_language_build/test_node.py`<br>`tests/unit/job_language_build/test_node_dependency_output_filtering.py`<br>`tests/unit/job_language_build/test_node_installed.py`<br>`tests/unit/job_language_build/test_node_scripts.py`<br>`tests/unit/job_language_build/test_output_attribution.py`<br>`tests/unit/job_language_build/test_php.py`<br>`tests/unit/job_language_build/test_php_dependency_output_filtering.py`<br>`tests/unit/job_language_build/test_php_installed.py`<br>`tests/unit/job_language_build/test_python.py`<br>`tests/unit/job_language_build/test_rust.py`<br>`tests/unit/job_language_build/test_wasm.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_project_build`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_language_build"]
  producer0["job_build_environment_analysis"]
  input0["handoff"]
  input_schema0["appsec-review/job-handoff/2"]
  producer0 --> input0 --> job
  input0 -. schema .-> input_schema0
  producer1["job_build_environment_analysis"]
  input1["build_environment"]
  input_schema1["appsec-review/build-environment-analysis/1"]
  producer1 --> input1 --> job
  input1 -. schema .-> input_schema1
  producer2["job_project_build"]
  input2["handoff"]
  input_schema2["appsec-review/job-handoff/2"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_project_build"]
  input3["topology_refinement_inputs"]
  input_schema3["appsec-review/build-topology-refinement/1"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  producer4["job_project_build"]
  input4["project_build_dispatch"]
  input_schema4["appsec-review/project-build-dispatch/3"]
  producer4 --> input4 --> job
  input4 -. schema .-> input_schema4
  producer5["job_project_build"]
  input5["probe_workspaces"]
  input_schema5["application/octet-stream"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_project_build"]
  input6["image_build_streams"]
  input_schema6["text/plain"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_review_intake"]
  input7["handoff"]
  input_schema7["appsec-review/job-handoff/2"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_review_intake"]
  input8["model_preflight"]
  input_schema8["appsec-review/model-preflight/1"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_review_intake"]
  input9["binary_evidence"]
  input_schema9["appsec-review/binary-evidence-intake/1"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_review_intake"]
  input10["review_intake"]
  input_schema10["appsec-review/review-intake/1"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_target_analysis_plan"]
  input11["handoff"]
  input_schema11["appsec-review/job-handoff/2"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_target_analysis_plan"]
  input12["planning_feedback_cache"]
  input_schema12["appsec-review/target-analysis-proposal/3"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_target_analysis_plan"]
  input13["analysis_plan"]
  input_schema13["appsec-review/retrieval-index/2"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_target_analysis_plan"]
  input14["analysis_plan_documents"]
  input_schema14["appsec-review/target-analysis-plan/1"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_target_catalog"]
  input15["handoff"]
  input_schema15["appsec-review/job-handoff/2"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_target_catalog"]
  input16["target_artifact_inputs"]
  input_schema16["appsec-review/target-artifact-intake/1"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  producer17["job_target_catalog"]
  input17["source_files"]
  input_schema17["appsec-review/retrieval-index/2"]
  producer17 --> input17 --> job
  input17 -. schema .-> input_schema17
  producer18["job_target_catalog"]
  input18["declaration_symbols"]
  input_schema18["appsec-review/retrieval-index/2"]
  producer18 --> input18 --> job
  input18 -. schema .-> input_schema18
  producer19["job_target_catalog"]
  input19["components"]
  input_schema19["appsec-review/retrieval-index/2"]
  producer19 --> input19 --> job
  input19 -. schema .-> input_schema19
  producer20["job_target_catalog"]
  input20["target_documents"]
  input_schema20["appsec-review/retrieval-index/2"]
  producer20 --> input20 --> job
  input20 -. schema .-> input_schema20
  producer21["job_target_catalog"]
  input21["build_units"]
  input_schema21["appsec-review/retrieval-index/2"]
  producer21 --> input21 --> job
  input21 -. schema .-> input_schema21
  producer22["job_target_catalog"]
  input22["catalog_documents"]
  input_schema22["appsec-review/target-catalog/1"]
  producer22 --> input22 --> job
  input22 -. schema .-> input_schema22
  output0["build_actions"]
  output_schema0["appsec-review/retrieval-index/2"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["build_workspaces"]
  output_schema1["application/octet-stream"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["jvm_build_actions"]
  output_schema2["appsec-review/retrieval-index/2"]
  job --> output2
  output2 -. schema .-> output_schema2
  output3["language_build_receipts"]
  output_schema3["appsec-review/language-build-handoff/2"]
  job --> output3
  output3 -. schema .-> output_schema3
  output4["topology_refinement_inputs"]
  output_schema4["appsec-review/build-topology-refinement/1"]
  job --> output4
  output4 -. schema .-> output_schema4
```

<!-- generated:end -->
