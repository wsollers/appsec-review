---
title: "evidence_collection"
kind: "operations"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_evidence_collection"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# evidence_collection

This page contains the generated contract; the authored process and acceptance description are tracked by [T-130](../TODO.md).

<!-- generated:begin job=job_evidence_collection -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

evidence_collection

Job: `job_evidence_collection`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `binary_hardening` | `binary_hardening.blint_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `binary_hardening` | `binary_hardening.blint_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `binary_hardening` | `binary_hardening.blint_scan` | 1 | `scanner` | `tool-blint` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `configuration` | `configuration.checkov_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `configuration` | `configuration.checkov_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `configuration` | `configuration.checkov_scan` | 1 | `scanner` | `tool-checkov` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `configuration` | `configuration.hadolint_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `configuration` | `configuration.hadolint_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `configuration` | `configuration.hadolint_scan` | 1 | `scanner` | `tool-hadolint` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `configuration` | `configuration.trivy_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `configuration` | `configuration.trivy_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `configuration` | `configuration.trivy_scan` | 1 | `scanner` | `tool-trivy` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `configuration` | `configuration.zizmor_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `configuration` | `configuration.zizmor_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `configuration` | `configuration.zizmor_scan` | 1 | `scanner` | `tool-zizmor` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `evidence_publication` | `evidence_publication.assemble_manifest` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1340) |
| `evidence_publication` | `evidence_publication.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1342) |
| `secrets` | `secrets.gitleaks_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `secrets` | `secrets.gitleaks_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `secrets` | `secrets.gitleaks_scan` | 1 | `scanner` | `tool-gitleaks` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `software_inventory` | `software_inventory.syft_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `software_inventory` | `software_inventory.syft_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `software_inventory` | `software_inventory.syft_scan` | 1 | `scanner` | `tool-syft` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `source_sast` | `source_sast.cppcheck_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `source_sast` | `source_sast.cppcheck_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `source_sast` | `source_sast.cppcheck_scan` | 1 | `scanner` | `tool-cppcheck` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `source_sast` | `source_sast.gosec_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `source_sast` | `source_sast.gosec_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `source_sast` | `source_sast.gosec_scan` | 1 | `scanner` | `tool-gosec` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `source_sast` | `source_sast.mobsfscan_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `source_sast` | `source_sast.mobsfscan_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `source_sast` | `source_sast.mobsfscan_scan` | 1 | `scanner` | `tool-mobsfscan` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `source_sast` | `source_sast.opengrep_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `source_sast` | `source_sast.opengrep_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `source_sast` | `source_sast.opengrep_scan` | 1 | `scanner` | `tool-opengrep` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `source_sast` | `source_sast.phpcs_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `source_sast` | `source_sast.phpcs_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `source_sast` | `source_sast.phpcs_scan` | 1 | `scanner` | `tool-phpcs` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `source_sast` | `source_sast.phpstan_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `source_sast` | `source_sast.phpstan_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `source_sast` | `source_sast.phpstan_scan` | 1 | `scanner` | `tool-phpstan` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `source_sast` | `source_sast.pmd_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `source_sast` | `source_sast.pmd_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `source_sast` | `source_sast.pmd_scan` | 1 | `scanner` | `tool-pmd` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `source_sast` | `source_sast.psalm_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `source_sast` | `source_sast.psalm_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `source_sast` | `source_sast.psalm_scan` | 1 | `scanner` | `tool-psalm` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `source_sast` | `source_sast.semgrep_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `source_sast` | `source_sast.semgrep_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `source_sast` | `source_sast.semgrep_scan` | 1 | `scanner` | `tool-semgrep` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `source_sast` | `source_sast.shellcheck_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `source_sast` | `source_sast.shellcheck_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `source_sast` | `source_sast.shellcheck_scan` | 1 | `scanner` | `tool-shellcheck` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `source_sast` | `source_sast.spotbugs_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `source_sast` | `source_sast.spotbugs_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `source_sast` | `source_sast.spotbugs_scan` | 1 | `scanner` | `tool-spotbugs` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `vulnerability_matching` | `vulnerability_matching.grype_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `vulnerability_matching` | `vulnerability_matching.grype_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `vulnerability_matching` | `vulnerability_matching.grype_scan` | 1 | `scanner` | `tool-grype` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |
| `vulnerability_matching` | `vulnerability_matching.osv_scanner_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1334) |
| `vulnerability_matching` | `vulnerability_matching.osv_scanner_normalize` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1332) |
| `vulnerability_matching` | `vulnerability_matching.osv_scanner_scan` | 1 | `scanner` | `tool-osv-scanner` | [source](../../src/appsec_review/jobs/job_evidence_collection/job.py#L1310) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_build_environment_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_build_environment_analysis` | `build_environment` | `appsec-review/build-environment-analysis/1` | handoff | optional | gap |
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
| `job_third_party_data_sync` | `feed_snapshot` | `appsec-review/public-feed-use/1` | external | optional | gap |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `static_tool_evidence` | `evidence_publication` | `appsec-review/static-tool-evidence/2` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `static_tool_io` | `source_sast` | `appsec-review/container-execution/1` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `static_tool_observations` | `evidence_publication` | `appsec-review/retrieval-index/2` | indexed | `observations` | `find`, `query_precomputed`, `search` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | None declared |
| integration | `tests/integration/test_signal_job_acceptance.py` |
| live | None declared |
| unit | `tests/test_evidence_collection_job.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_target_analysis_plan`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_evidence_collection"]
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
  producer18["job_third_party_data_sync"]
  input18["feed_snapshot"]
  input_schema18["appsec-review/public-feed-use/1"]
  producer18 --> input18 --> job
  input18 -. schema .-> input_schema18
  output0["static_tool_evidence"]
  output_schema0["appsec-review/static-tool-evidence/2"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["static_tool_io"]
  output_schema1["appsec-review/container-execution/1"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["static_tool_observations"]
  output_schema2["appsec-review/retrieval-index/2"]
  job --> output2
  output2 -. schema .-> output_schema2
```

<!-- generated:end -->
