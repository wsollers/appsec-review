---
title: "target_acquisition"
kind: "operations"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_target_acquisition"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# target_acquisition

This page contains the generated contract; the authored process and acceptance description are tracked by [T-130](../TODO.md).

<!-- generated:begin job=job_target_acquisition -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

target_acquisition

Job: `job_target_acquisition`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acquisition` | `acquisition.acquire_components` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_acquisition/job.py#L113) |
| `publication` | `publication.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_acquisition/job.py#L170) |
| `selection` | `selection.resolve_system` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_acquisition/job.py#L90) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `target_acquisition` | `publication` | `appsec-review/target-acquisition-job/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | None declared |
| integration | None declared |
| live | None declared |
| unit | `tests/test_target_acquisition.py::test_configuration_refuses_unsafe_or_incomplete_targets`<br>`tests/test_target_acquisition.py::test_configuration_refuses_duplicate_ids_and_escaping_directories`<br>`tests/test_target_acquisition.py::test_url_and_path_safety_primitives` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_image_pin_verification`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_target_acquisition"]
  output0["target_acquisition"]
  output_schema0["appsec-review/target-acquisition-job/1"]
  job --> output0
  output0 -. schema .-> output_schema0
```

<!-- generated:end -->
