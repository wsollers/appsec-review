---
title: "target_catalog"
kind: "operations"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_target_catalog"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# target_catalog

This page contains the generated contract; the authored process and acceptance description are tracked by [T-130](../TODO.md).

<!-- generated:begin job=job_target_catalog -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

target_catalog

Job: `job_target_catalog`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `build_discovery` | `build_discovery.catalog_build_targets` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_catalog/job.py#L266) |
| `build_discovery` | `build_discovery.discover_build_systems` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_catalog/job.py#L218) |
| `build_discovery` | `build_discovery.discover_compile_commands` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_catalog/job.py#L258) |
| `component_discovery` | `component_discovery.catalog_components` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_catalog/job.py#L294) |
| `component_discovery` | `component_discovery.catalog_dependencies` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_catalog/job.py#L306) |
| `publish_catalog` | `publish_catalog.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_catalog/job.py#L568) |
| `publish_catalog` | `publish_catalog.validate_catalog` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_catalog/job.py#L555) |
| `repository_discovery` | `repository_discovery.census_languages` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_catalog/job.py#L186) |
| `repository_discovery` | `repository_discovery.discover_projects` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_catalog/job.py#L193) |
| `repository_discovery` | `repository_discovery.partition_repository` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_catalog/job.py#L143) |
| `retrieval_indexes` | `retrieval_indexes.build_component_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_catalog/job.py#L437) |
| `retrieval_indexes` | `retrieval_indexes.build_path_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_catalog/job.py#L339) |
| `retrieval_indexes` | `retrieval_indexes.build_symbol_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_catalog/job.py#L379) |
| `retrieval_indexes` | `retrieval_indexes.build_target_documents` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_catalog/job.py#L458) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_review_intake` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
| `job_review_intake` | `model_preflight` | `appsec-review/model-preflight/1` | handoff | optional | gap |
| `job_review_intake` | `binary_evidence` | `appsec-review/binary-evidence-intake/1` | handoff | optional | gap |
| `job_review_intake` | `review_intake` | `appsec-review/review-intake/1` | handoff | optional | gap |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `build_units` | `publish_catalog` | `appsec-review/retrieval-index/2` | indexed | `build` | `find`, `search` |
| `catalog_documents` | `publish_catalog` | `appsec-review/target-catalog/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `components` | `retrieval_indexes` | `appsec-review/retrieval-index/2` | indexed | `components` | `find`, `search` |
| `declaration_symbols` | `retrieval_indexes` | `appsec-review/retrieval-index/2` | indexed | `analysis` | `find`, `search`, `trace` |
| `source_files` | `retrieval_indexes` | `appsec-review/retrieval-index/2` | indexed | `source` | `find`, `read_excerpt`, `search` |
| `target_artifact_inputs` | `repository_discovery` | `appsec-review/target-artifact-intake/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `target_documents` | `retrieval_indexes` | `appsec-review/retrieval-index/2` | indexed | `documents` | `find`, `read_excerpt`, `search` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | None declared |
| integration | `tests/test_target_document_pipeline.py::test_catalog_publishes_northwind_documents_with_queryable_provenance_and_intent` |
| live | None declared |
| unit | `tests/test_cataloging_languages.py`<br>`tests/test_wave1_resume.py::test_catalog_path_index_accepts_structured_inventory_gaps` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_review_intake`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_target_catalog"]
  producer0["job_review_intake"]
  input0["handoff"]
  input_schema0["appsec-review/job-handoff/2"]
  producer0 --> input0 --> job
  input0 -. schema .-> input_schema0
  producer1["job_review_intake"]
  input1["model_preflight"]
  input_schema1["appsec-review/model-preflight/1"]
  producer1 --> input1 --> job
  input1 -. schema .-> input_schema1
  producer2["job_review_intake"]
  input2["binary_evidence"]
  input_schema2["appsec-review/binary-evidence-intake/1"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_review_intake"]
  input3["review_intake"]
  input_schema3["appsec-review/review-intake/1"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  output0["build_units"]
  output_schema0["appsec-review/retrieval-index/2"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["catalog_documents"]
  output_schema1["appsec-review/target-catalog/1"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["components"]
  output_schema2["appsec-review/retrieval-index/2"]
  job --> output2
  output2 -. schema .-> output_schema2
  output3["declaration_symbols"]
  output_schema3["appsec-review/retrieval-index/2"]
  job --> output3
  output3 -. schema .-> output_schema3
  output4["source_files"]
  output_schema4["appsec-review/retrieval-index/2"]
  job --> output4
  output4 -. schema .-> output_schema4
  output5["target_artifact_inputs"]
  output_schema5["appsec-review/target-artifact-intake/1"]
  job --> output5
  output5 -. schema .-> output_schema5
  output6["target_documents"]
  output_schema6["appsec-review/retrieval-index/2"]
  job --> output6
  output6 -. schema .-> output_schema6
```

<!-- generated:end -->
