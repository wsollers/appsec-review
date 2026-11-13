---
title: "model_connectivity"
kind: "operations"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_model_connectivity"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# model_connectivity

This page contains the generated contract; the authored process and acceptance description are tracked by [T-130](../TODO.md).

<!-- generated:begin job=job_model_connectivity -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

model_connectivity

Job: `job_model_connectivity`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `connectivity` | `connectivity.resolve_models` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_model_connectivity/job.py#L53) |
| `connectivity` | `connectivity.verify_models` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_model_connectivity/job.py#L59) |
| `publication` | `publication.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_model_connectivity/job.py#L89) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `model_connectivity` | `publication` | `appsec-review/model-preflight/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | None declared |
| integration | `tests/integration/job_model_connectivity/test_dispatch.py`<br>`tests/integration/job_model_connectivity/test_model_connectivity.py` |
| live | None declared |
| unit | `tests/unit/job_model_connectivity/test_contract.py`<br>`tests/unit/job_model_connectivity/test_job_graph.py`<br>`tests/unit/job_model_connectivity/test_steps.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: None.

### Declared dataflow

```mermaid
flowchart LR
  job["job_model_connectivity"]
  output0["model_connectivity"]
  output_schema0["appsec-review/model-preflight/1"]
  job --> output0
  output0 -. schema .-> output_schema0
```

<!-- generated:end -->
