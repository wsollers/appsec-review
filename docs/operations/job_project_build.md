---
title: "project_build"
kind: "operations"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_project_build"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# project_build

This page contains the generated contract; the authored process and acceptance description are tracked by [T-130](../TODO.md).

<!-- generated:begin job=job_project_build -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

project_build

Job: `job_project_build`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `build_dispatch` | `build_dispatch.dotnet` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `build_dispatch` | `build_dispatch.go` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `build_dispatch` | `build_dispatch.java` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `build_dispatch` | `build_dispatch.native` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `build_dispatch` | `build_dispatch.node` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `build_dispatch` | `build_dispatch.php` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `build_dispatch` | `build_dispatch.python` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `build_dispatch` | `build_dispatch.rust` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `build_dispatch` | `build_dispatch.wasm` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `image` | `image.dotnet` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `image` | `image.go` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `image` | `image.java` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `image` | `image.native` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `image` | `image.node` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `image` | `image.php` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `image` | `image.python` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `image` | `image.rust` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `image` | `image.wasm` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `plan` | `plan.load_recipes` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `probe` | `probe.dotnet` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `probe` | `probe.go` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `probe` | `probe.java` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `probe` | `probe.native` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `probe` | `probe.node` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `probe` | `probe.php` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `probe` | `probe.python` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `probe` | `probe.rust` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `probe` | `probe.wasm` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `static_dispatch` | `static_dispatch.dotnet` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `static_dispatch` | `static_dispatch.global` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `static_dispatch` | `static_dispatch.go` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `static_dispatch` | `static_dispatch.java` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `static_dispatch` | `static_dispatch.native` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `static_dispatch` | `static_dispatch.node` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `static_dispatch` | `static_dispatch.php` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `static_dispatch` | `static_dispatch.python` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `static_dispatch` | `static_dispatch.rust` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |
| `static_dispatch` | `static_dispatch.wasm` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_project_build/job.py#L1526) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_build_environment_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_build_environment_analysis` | `build_environment` | `appsec-review/build-environment-analysis/1` | handoff | optional | gap |
| `job_review_intake` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_review_intake` | `model_preflight` | `appsec-review/model-preflight/1` | handoff | optional | gap |
| `job_review_intake` | `binary_evidence` | `appsec-review/binary-evidence-intake/1` | handoff | optional | gap |
| `job_review_intake` | `review_intake` | `appsec-review/review-intake/1` | handoff | optional | gap |
| `job_target_analysis_plan` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
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
| `image_build_streams` | `image` | `text/plain` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `probe_workspaces` | `probe` | `application/octet-stream` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `project_build_dispatch` | `acceptance` | `appsec-review/project-build-dispatch/3` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `topology_refinement_inputs` | `plan` | `appsec-review/build-topology-refinement/1` | protected | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

These are job-level declarations; exact per-task selection is not declared ([T-147](../TODO.md)).

```json
{
  "model": {
    "enabled": true,
    "max_input_tokens": 16000,
    "max_output_tokens": 2000,
    "model": "claude-haiku-5-5",
    "provider": "claude-cli",
    "reasoning": "medium",
    "timeout_seconds": 180
  }
}
```

- Role template: `build_engineer_{family}`; family selected by the accepted build.
- Persona: [devops_engineer](../generated/guidance.md#personas-devops_engineer).
- Task prompt: `build_image_repair`.
- Runtime skill: [build-image-repair](../generated/guidance.md#runtime_skills-build-image-repair).

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | `tests/acceptance/job_project_build/test_project_build_graph.py`<br>`tests/acceptance/job_project_build/test_project_build_capture.py`<br>`tests/acceptance/job_project_build/test_family_project_builds.py`<br>`tests/acceptance/job_project_build/test_jvm_dotnet_project_builds.py`<br>`tests/acceptance/job_project_build/test_node_project_builds.py`<br>`tests/acceptance/job_project_build/test_native_build_output_layout.py`<br>`tests/acceptance/job_project_build/test_unity_project_builds.py` |
| integration | `tests/integration/job_project_build/test_executor.py`<br>`tests/integration/job_project_build/test_native_artifacts.py`<br>`tests/integration/job_project_build/test_capture_boundary.py`<br>`tests/integration/job_project_build/test_fixture_provenance.py` |
| live | None declared |
| unit | `tests/unit/job_project_build/test_job_graph.py`<br>`tests/unit/job_project_build/test_contract.py`<br>`tests/unit/job_project_build/test_project_build_helpers.py`<br>`tests/unit/job_project_build/test_repair.py`<br>`tests/unit/job_project_build/test_enforcement.py`<br>`tests/unit/job_project_build/test_build_recovery.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_target_analysis_plan`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_project_build"]
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
  producer2["job_review_intake"]
  input2["handoff"]
  input_schema2["appsec-review/job-handoff/2"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_review_intake"]
  input3["model_preflight"]
  input_schema3["appsec-review/model-preflight/1"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  producer4["job_review_intake"]
  input4["binary_evidence"]
  input_schema4["appsec-review/binary-evidence-intake/1"]
  producer4 --> input4 --> job
  input4 -. schema .-> input_schema4
  producer5["job_review_intake"]
  input5["review_intake"]
  input_schema5["appsec-review/review-intake/1"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_target_analysis_plan"]
  input6["handoff"]
  input_schema6["appsec-review/job-handoff/2"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_target_analysis_plan"]
  input7["planning_feedback_cache"]
  input_schema7["appsec-review/target-analysis-proposal/3"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_target_analysis_plan"]
  input8["analysis_plan"]
  input_schema8["appsec-review/retrieval-index/2"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_target_analysis_plan"]
  input9["analysis_plan_documents"]
  input_schema9["appsec-review/target-analysis-plan/1"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_target_catalog"]
  input10["handoff"]
  input_schema10["appsec-review/job-handoff/2"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_target_catalog"]
  input11["target_artifact_inputs"]
  input_schema11["appsec-review/target-artifact-intake/1"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_target_catalog"]
  input12["source_files"]
  input_schema12["appsec-review/retrieval-index/2"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_target_catalog"]
  input13["declaration_symbols"]
  input_schema13["appsec-review/retrieval-index/2"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_target_catalog"]
  input14["components"]
  input_schema14["appsec-review/retrieval-index/2"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_target_catalog"]
  input15["target_documents"]
  input_schema15["appsec-review/retrieval-index/2"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_target_catalog"]
  input16["build_units"]
  input_schema16["appsec-review/retrieval-index/2"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  producer17["job_target_catalog"]
  input17["catalog_documents"]
  input_schema17["appsec-review/target-catalog/1"]
  producer17 --> input17 --> job
  input17 -. schema .-> input_schema17
  output0["image_build_streams"]
  output_schema0["text/plain"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["probe_workspaces"]
  output_schema1["application/octet-stream"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["project_build_dispatch"]
  output_schema2["appsec-review/project-build-dispatch/3"]
  job --> output2
  output2 -. schema .-> output_schema2
  output3["topology_refinement_inputs"]
  output_schema3["appsec-review/build-topology-refinement/1"]
  job --> output3
  output3 -. schema .-> output_schema3
```

<!-- generated:end -->
