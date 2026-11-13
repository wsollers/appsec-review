---
title: "owasp_control_assessment"
kind: "operations"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_owasp_control_assessment"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# owasp_control_assessment

This page contains the generated contract; the authored process and acceptance description are tracked by [T-130](../TODO.md).

<!-- generated:begin job=job_owasp_control_assessment -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

owasp_control_assessment

Job: `job_owasp_control_assessment`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `applicability` | `applicability.build_matrix` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py#L148) |
| `batching` | `batching.build_packages` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py#L168) |
| `batching` | `batching.partition_work` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py#L160) |
| `characterization` | `characterization.classify_components` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py#L138) |
| `characterization` | `characterization.load_inputs` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py#L133) |
| `join` | `join.deterministic_join` | 1 | `owasp_verification` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py#L287) |
| `publication` | `publication.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py#L341) |
| `publication` | `publication.publish_indexes` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py#L294) |
| `standards_selection` | `standards_selection.ingest_catalogs` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py#L121) |
| `standards_selection` | `standards_selection.select_profiles` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py#L127) |
| `validation` | `validation.cell_01` | 1 | `owasp_validator` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py#L198) |
| `validation` | `validation.cell_02` | 1 | `owasp_validator` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py#L198) |
| `validation` | `validation.cell_03` | 1 | `owasp_validator` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py#L198) |
| `validation` | `validation.cell_04` | 1 | `owasp_validator` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py#L198) |
| `verification` | `verification.independent_review` | 1 | `owasp_verification` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py#L247) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_artifact_indexing` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_artifact_indexing` | `artifact_catalog` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_artifact_indexing` | `archive_members` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_artifact_indexing` | `artifact_relationships` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_artifact_indexing` | `artifact_index_summary` | `appsec-review/artifact-indexing/1` | handoff | optional | gap |
| `job_artifact_security_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_artifact_security_analysis` | `artifact_security_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_artifact_security_analysis` | `artifact_security_results` | `appsec-review/artifact-security-observation/1` | handoff | optional | gap |
| `job_artifact_security_analysis` | `artifact_scanner_io` | `appsec-review/container-execution/1` | handoff | optional | gap |
| `job_build_environment_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_build_environment_analysis` | `build_environment` | `appsec-review/build-environment-analysis/1` | handoff | optional | gap |
| `job_clang_static_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_clang_static_analysis` | `clang_static_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_clang_static_analysis` | `clang_static_scope_coverage` | `appsec-review/cpp-index-coverage/1` | handoff | optional | gap |
| `job_clang_static_analysis` | `clang_static_summary` | `appsec-review/clang-static-analysis-handoff/1` | handoff | optional | gap |
| `job_clang_static_analysis` | `clang_static_raw` | `application/json` | handoff | optional | gap |
| `job_code_graph_index` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_code_graph_index` | `code_graph_facts` | `appsec-review/graph-fact/1` | handoff | optional | gap |
| `job_code_graph_index` | `code_graph_stages` | `appsec-review/code-graph-stage/1` | handoff | optional | gap |
| `job_code_graph_index` | `code_graph_checkpoints` | `appsec-review/code-graph-checkpoint/1` | handoff | optional | gap |
| `job_code_graph_index` | `code_graph_summary` | `appsec-review/code-graph-index/1` | handoff | optional | gap |
| `job_codeql_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_codeql_analysis` | `codeql_predecessor_import` | `appsec-review/codeql-predecessor-import/1` | handoff | optional | gap |
| `job_codeql_analysis` | `codeql_graph_export` | `appsec-review/codeql-graph-export/1` | handoff | optional | gap |
| `job_codeql_analysis` | `codeql_observations` | `appsec-review/codeql-sarif-normalizer/3` | handoff | optional | gap |
| `job_codeql_analysis` | `codeql_plan_and_summary` | `appsec-review/codeql-analysis-handoff/1` | handoff | optional | gap |
| `job_codeql_analysis` | `codeql_scope_material` | `application/octet-stream` | handoff | optional | gap |
| `job_cpg_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_cpg_analysis` | `cpg_graph_coverage` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpg_analysis` | `cpg_scope_coverage` | `appsec-review/cpp-index-coverage/1` | handoff | optional | gap |
| `job_cpg_analysis` | `cpg_summary` | `appsec-review/cpg-analysis/1` | handoff | optional | gap |
| `job_cpg_analysis` | `cpg_binary` | `application/octet-stream` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `cpp_build_graph` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `clang_ast` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `llvm_ir` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `infer_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `binary_symbols` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `cpp_blocked_branches` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `cpp_plan_and_summary` | `appsec-review/cpp-compiled-analysis/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `cpp_case_material` | `application/octet-stream` | handoff | optional | gap |
| `job_cpp_symbol_index` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_cpp_symbol_index` | `clangd_symbols` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_symbol_index` | `clangd_coverage` | `appsec-review/cpp-index-coverage/1` | handoff | optional | gap |
| `job_cpp_symbol_index` | `clangd_summary` | `appsec-review/cpp-symbol-index/1` | handoff | optional | gap |
| `job_cpp_symbol_index` | `clangd_tool_io` | `appsec-review/container-execution/1` | handoff | optional | gap |
| `job_dependency_intelligence` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_discovery` | `appsec-review/native-discovery/1` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_component_curation` | `appsec-review/native-component-curation/1` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_metadata_investigation` | `appsec-review/native-metadata-investigation/1` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_inference_metrics` | `appsec-review/native-inference-metrics/1` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_spdx` | `SPDX-2.3` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_sbom_provenance` | `appsec-review/native-sbom-provenance/1` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_sbom_metrics` | `appsec-review/native-sbom-metrics/1` | handoff | optional | gap |
| `job_dependency_intelligence` | `dependency_context` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_dependency_intelligence` | `scorecard_responses` | `application/json` | handoff | optional | gap |
| `job_dependency_intelligence` | `dependency_intelligence_handoff` | `appsec-review/dependency-intelligence-handoff/1` | handoff | optional | gap |
| `job_evidence_collection` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_evidence_collection` | `static_tool_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_evidence_collection` | `static_tool_evidence` | `appsec-review/static-tool-evidence/2` | handoff | optional | gap |
| `job_evidence_collection` | `static_tool_io` | `appsec-review/container-execution/1` | handoff | optional | gap |
| `job_language_build` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_language_build` | `topology_refinement_inputs` | `appsec-review/build-topology-refinement/1` | handoff | optional | gap |
| `job_language_build` | `build_actions` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_language_build` | `jvm_build_actions` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_language_build` | `language_build_receipts` | `appsec-review/language-build-handoff/2` | handoff | optional | gap |
| `job_language_build` | `build_workspaces` | `application/octet-stream` | handoff | optional | gap |
| `job_post_build_security_assessment` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_post_build_security_assessment` | `build_security` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_post_build_security_assessment` | `build_security_documents` | `appsec-review/post-build-security-assessment/1` | handoff | optional | gap |
| `job_project_build` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_project_build` | `topology_refinement_inputs` | `appsec-review/build-topology-refinement/1` | handoff | optional | gap |
| `job_project_build` | `project_build_dispatch` | `appsec-review/project-build-dispatch/3` | handoff | optional | gap |
| `job_project_build` | `probe_workspaces` | `application/octet-stream` | handoff | optional | gap |
| `job_project_build` | `image_build_streams` | `text/plain` | handoff | optional | gap |
| `job_review_intake` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_review_intake` | `model_preflight` | `appsec-review/model-preflight/1` | handoff | optional | gap |
| `job_review_intake` | `binary_evidence` | `appsec-review/binary-evidence-intake/1` | handoff | optional | gap |
| `job_review_intake` | `review_intake` | `appsec-review/review-intake/1` | handoff | optional | gap |
| `job_review_prioritization` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_review_prioritization` | `priority_items` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_review_prioritization` | `prioritization_documents` | `appsec-review/review-prioritization/1` | handoff | optional | gap |
| `job_security_tagging` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_security_tagging` | `tag_assignments` | `appsec-review/tag-assignment/1` | handoff | optional | gap |
| `job_security_tagging` | `tagging_documents` | `appsec-review/security-tagging-handoff/1` | handoff | optional | gap |
| `job_source_history_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_source_history_analysis` | `history_signals` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_source_history_analysis` | `history_documents` | `appsec-review/source-history-analysis/2` | handoff | optional | gap |
| `job_source_history_analysis` | `raw_git_history` | `application/octet-stream` | handoff | optional | gap |
| `job_source_history_analysis` | `history_tool_io` | `appsec-review/container-execution/1` | handoff | optional | gap |
| `job_svf_alias_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_svf_alias_analysis` | `svf_alias_sets` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_svf_alias_analysis` | `svf_alias_scope_coverage` | `appsec-review/cpp-index-coverage/1` | handoff | optional | gap |
| `job_svf_alias_analysis` | `svf_alias_summary` | `appsec-review/svf-alias-analysis-handoff/1` | handoff | optional | gap |
| `job_svf_alias_analysis` | `svf_alias_raw` | `application/json` | handoff | optional | gap |
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
| `job_tree_sitter_ast` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_tree_sitter_ast` | `tree_sitter_ast` | `appsec-review/tree-sitter-normalizer/1` | handoff | optional | gap |
| `job_tree_sitter_ast` | `tree_sitter_coverage` | `appsec-review/tree-sitter-ast/1` | handoff | optional | gap |
| `job_tree_sitter_ast` | `tree_sitter_node_shards` | `appsec-review/tree-sitter-ast/1` | handoff | optional | gap |
| `job_tree_sitter_ast` | `generated_source_backing` | `appsec-review/generated-source-backing/1` | handoff | optional | gap |
| `job_tree_sitter_ast` | `tree_sitter_tool_io` | `appsec-review/container-execution/1` | handoff | optional | gap |
| `job_third_party_data_sync` | `feed_snapshot` | `appsec-review/public-feed-use/1` | external | optional | gap |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `owasp_documents` | `publication` | `appsec-review/owasp-workbench-result/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `owasp_model_receipts` | `verification` | `appsec-review/owasp-model-receipt/1` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `owasp_workbench` | `publication` | `appsec-review/owasp-index-shard/1` | indexed | `standards`, `component-classification`, `applicability`, `validation-work`, `control-result`, `finding-package` | `query_owasp_workbench`, `query_precomputed` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

These are job-level declarations; exact per-task selection is not declared ([T-147](../TODO.md)).

```json
{
  "model": {
    "enabled": true,
    "max_input_tokens": 24000,
    "max_output_tokens": 6000,
    "model": "claude-haiku-5-5",
    "provider": "claude-cli",
    "reasoning": "medium",
    "retries": 1,
    "timeout_seconds": 120
  },
  "models": {
    "reviewer": {
      "enabled": true,
      "max_input_tokens": 24000,
      "max_output_tokens": 6000,
      "model": "claude-haiku-5-5",
      "provider": "claude-cli",
      "reasoning": "medium",
      "retries": 1,
      "timeout_seconds": 120
    }
  }
}
```


### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | `tests/acceptance/job_owasp_control_assessment/test_subject_selection.py` |
| integration | `tests/integration/job_owasp_control_assessment/test_subject_selection.py` |
| live | None declared |
| unit | `tests/test_owasp_assessment_job.py`<br>`tests/unit/job_owasp_control_assessment/test_subject_selection.py`<br>`tests/unit/job_owasp_control_assessment/test_subject_acceptance.py`<br>`tests/unit/job_owasp_control_assessment/test_discovery_boundaries.py`<br>`tests/unit/job_owasp_control_assessment/test_subject_settings.py`<br>`tests/unit/job_owasp_control_assessment/test_package_projection.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_security_tagging`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_owasp_control_assessment"]
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
  producer5["job_artifact_security_analysis"]
  input5["handoff"]
  input_schema5["appsec-review/job-handoff/2"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_artifact_security_analysis"]
  input6["artifact_security_observations"]
  input_schema6["appsec-review/retrieval-index/2"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_artifact_security_analysis"]
  input7["artifact_security_results"]
  input_schema7["appsec-review/artifact-security-observation/1"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_artifact_security_analysis"]
  input8["artifact_scanner_io"]
  input_schema8["appsec-review/container-execution/1"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_build_environment_analysis"]
  input9["handoff"]
  input_schema9["appsec-review/job-handoff/2"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_build_environment_analysis"]
  input10["build_environment"]
  input_schema10["appsec-review/build-environment-analysis/1"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_clang_static_analysis"]
  input11["handoff"]
  input_schema11["appsec-review/job-handoff/2"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_clang_static_analysis"]
  input12["clang_static_observations"]
  input_schema12["appsec-review/retrieval-index/2"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_clang_static_analysis"]
  input13["clang_static_scope_coverage"]
  input_schema13["appsec-review/cpp-index-coverage/1"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_clang_static_analysis"]
  input14["clang_static_summary"]
  input_schema14["appsec-review/clang-static-analysis-handoff/1"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_clang_static_analysis"]
  input15["clang_static_raw"]
  input_schema15["application/json"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_code_graph_index"]
  input16["handoff"]
  input_schema16["appsec-review/job-handoff/2"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  producer17["job_code_graph_index"]
  input17["code_graph_facts"]
  input_schema17["appsec-review/graph-fact/1"]
  producer17 --> input17 --> job
  input17 -. schema .-> input_schema17
  producer18["job_code_graph_index"]
  input18["code_graph_stages"]
  input_schema18["appsec-review/code-graph-stage/1"]
  producer18 --> input18 --> job
  input18 -. schema .-> input_schema18
  producer19["job_code_graph_index"]
  input19["code_graph_checkpoints"]
  input_schema19["appsec-review/code-graph-checkpoint/1"]
  producer19 --> input19 --> job
  input19 -. schema .-> input_schema19
  producer20["job_code_graph_index"]
  input20["code_graph_summary"]
  input_schema20["appsec-review/code-graph-index/1"]
  producer20 --> input20 --> job
  input20 -. schema .-> input_schema20
  producer21["job_codeql_analysis"]
  input21["handoff"]
  input_schema21["appsec-review/job-handoff/2"]
  producer21 --> input21 --> job
  input21 -. schema .-> input_schema21
  producer22["job_codeql_analysis"]
  input22["codeql_predecessor_import"]
  input_schema22["appsec-review/codeql-predecessor-import/1"]
  producer22 --> input22 --> job
  input22 -. schema .-> input_schema22
  producer23["job_codeql_analysis"]
  input23["codeql_graph_export"]
  input_schema23["appsec-review/codeql-graph-export/1"]
  producer23 --> input23 --> job
  input23 -. schema .-> input_schema23
  producer24["job_codeql_analysis"]
  input24["codeql_observations"]
  input_schema24["appsec-review/codeql-sarif-normalizer/3"]
  producer24 --> input24 --> job
  input24 -. schema .-> input_schema24
  producer25["job_codeql_analysis"]
  input25["codeql_plan_and_summary"]
  input_schema25["appsec-review/codeql-analysis-handoff/1"]
  producer25 --> input25 --> job
  input25 -. schema .-> input_schema25
  producer26["job_codeql_analysis"]
  input26["codeql_scope_material"]
  input_schema26["application/octet-stream"]
  producer26 --> input26 --> job
  input26 -. schema .-> input_schema26
  producer27["job_cpg_analysis"]
  input27["handoff"]
  input_schema27["appsec-review/job-handoff/2"]
  producer27 --> input27 --> job
  input27 -. schema .-> input_schema27
  producer28["job_cpg_analysis"]
  input28["cpg_graph_coverage"]
  input_schema28["appsec-review/retrieval-index/2"]
  producer28 --> input28 --> job
  input28 -. schema .-> input_schema28
  producer29["job_cpg_analysis"]
  input29["cpg_scope_coverage"]
  input_schema29["appsec-review/cpp-index-coverage/1"]
  producer29 --> input29 --> job
  input29 -. schema .-> input_schema29
  producer30["job_cpg_analysis"]
  input30["cpg_summary"]
  input_schema30["appsec-review/cpg-analysis/1"]
  producer30 --> input30 --> job
  input30 -. schema .-> input_schema30
  producer31["job_cpg_analysis"]
  input31["cpg_binary"]
  input_schema31["application/octet-stream"]
  producer31 --> input31 --> job
  input31 -. schema .-> input_schema31
  producer32["job_cpp_compiled_analysis"]
  input32["handoff"]
  input_schema32["appsec-review/job-handoff/2"]
  producer32 --> input32 --> job
  input32 -. schema .-> input_schema32
  producer33["job_cpp_compiled_analysis"]
  input33["cpp_build_graph"]
  input_schema33["appsec-review/retrieval-index/2"]
  producer33 --> input33 --> job
  input33 -. schema .-> input_schema33
  producer34["job_cpp_compiled_analysis"]
  input34["clang_ast"]
  input_schema34["appsec-review/retrieval-index/2"]
  producer34 --> input34 --> job
  input34 -. schema .-> input_schema34
  producer35["job_cpp_compiled_analysis"]
  input35["llvm_ir"]
  input_schema35["appsec-review/retrieval-index/2"]
  producer35 --> input35 --> job
  input35 -. schema .-> input_schema35
  producer36["job_cpp_compiled_analysis"]
  input36["infer_observations"]
  input_schema36["appsec-review/retrieval-index/2"]
  producer36 --> input36 --> job
  input36 -. schema .-> input_schema36
  producer37["job_cpp_compiled_analysis"]
  input37["binary_symbols"]
  input_schema37["appsec-review/retrieval-index/2"]
  producer37 --> input37 --> job
  input37 -. schema .-> input_schema37
  producer38["job_cpp_compiled_analysis"]
  input38["cpp_blocked_branches"]
  input_schema38["appsec-review/retrieval-index/2"]
  producer38 --> input38 --> job
  input38 -. schema .-> input_schema38
  producer39["job_cpp_compiled_analysis"]
  input39["cpp_plan_and_summary"]
  input_schema39["appsec-review/cpp-compiled-analysis/2"]
  producer39 --> input39 --> job
  input39 -. schema .-> input_schema39
  producer40["job_cpp_compiled_analysis"]
  input40["cpp_case_material"]
  input_schema40["application/octet-stream"]
  producer40 --> input40 --> job
  input40 -. schema .-> input_schema40
  producer41["job_cpp_symbol_index"]
  input41["handoff"]
  input_schema41["appsec-review/job-handoff/2"]
  producer41 --> input41 --> job
  input41 -. schema .-> input_schema41
  producer42["job_cpp_symbol_index"]
  input42["clangd_symbols"]
  input_schema42["appsec-review/retrieval-index/2"]
  producer42 --> input42 --> job
  input42 -. schema .-> input_schema42
  producer43["job_cpp_symbol_index"]
  input43["clangd_coverage"]
  input_schema43["appsec-review/cpp-index-coverage/1"]
  producer43 --> input43 --> job
  input43 -. schema .-> input_schema43
  producer44["job_cpp_symbol_index"]
  input44["clangd_summary"]
  input_schema44["appsec-review/cpp-symbol-index/1"]
  producer44 --> input44 --> job
  input44 -. schema .-> input_schema44
  producer45["job_cpp_symbol_index"]
  input45["clangd_tool_io"]
  input_schema45["appsec-review/container-execution/1"]
  producer45 --> input45 --> job
  input45 -. schema .-> input_schema45
  producer46["job_dependency_intelligence"]
  input46["handoff"]
  input_schema46["appsec-review/job-handoff/2"]
  producer46 --> input46 --> job
  input46 -. schema .-> input_schema46
  producer47["job_dependency_intelligence"]
  input47["native_discovery"]
  input_schema47["appsec-review/native-discovery/1"]
  producer47 --> input47 --> job
  input47 -. schema .-> input_schema47
  producer48["job_dependency_intelligence"]
  input48["native_component_curation"]
  input_schema48["appsec-review/native-component-curation/1"]
  producer48 --> input48 --> job
  input48 -. schema .-> input_schema48
  producer49["job_dependency_intelligence"]
  input49["native_metadata_investigation"]
  input_schema49["appsec-review/native-metadata-investigation/1"]
  producer49 --> input49 --> job
  input49 -. schema .-> input_schema49
  producer50["job_dependency_intelligence"]
  input50["native_inference_metrics"]
  input_schema50["appsec-review/native-inference-metrics/1"]
  producer50 --> input50 --> job
  input50 -. schema .-> input_schema50
  producer51["job_dependency_intelligence"]
  input51["native_spdx"]
  input_schema51["SPDX-2.3"]
  producer51 --> input51 --> job
  input51 -. schema .-> input_schema51
  producer52["job_dependency_intelligence"]
  input52["native_sbom_provenance"]
  input_schema52["appsec-review/native-sbom-provenance/1"]
  producer52 --> input52 --> job
  input52 -. schema .-> input_schema52
  producer53["job_dependency_intelligence"]
  input53["native_sbom_metrics"]
  input_schema53["appsec-review/native-sbom-metrics/1"]
  producer53 --> input53 --> job
  input53 -. schema .-> input_schema53
  producer54["job_dependency_intelligence"]
  input54["dependency_context"]
  input_schema54["appsec-review/retrieval-index/2"]
  producer54 --> input54 --> job
  input54 -. schema .-> input_schema54
  producer55["job_dependency_intelligence"]
  input55["scorecard_responses"]
  input_schema55["application/json"]
  producer55 --> input55 --> job
  input55 -. schema .-> input_schema55
  producer56["job_dependency_intelligence"]
  input56["dependency_intelligence_handoff"]
  input_schema56["appsec-review/dependency-intelligence-handoff/1"]
  producer56 --> input56 --> job
  input56 -. schema .-> input_schema56
  producer57["job_evidence_collection"]
  input57["handoff"]
  input_schema57["appsec-review/job-handoff/2"]
  producer57 --> input57 --> job
  input57 -. schema .-> input_schema57
  producer58["job_evidence_collection"]
  input58["static_tool_observations"]
  input_schema58["appsec-review/retrieval-index/2"]
  producer58 --> input58 --> job
  input58 -. schema .-> input_schema58
  producer59["job_evidence_collection"]
  input59["static_tool_evidence"]
  input_schema59["appsec-review/static-tool-evidence/2"]
  producer59 --> input59 --> job
  input59 -. schema .-> input_schema59
  producer60["job_evidence_collection"]
  input60["static_tool_io"]
  input_schema60["appsec-review/container-execution/1"]
  producer60 --> input60 --> job
  input60 -. schema .-> input_schema60
  producer61["job_language_build"]
  input61["handoff"]
  input_schema61["appsec-review/job-handoff/2"]
  producer61 --> input61 --> job
  input61 -. schema .-> input_schema61
  producer62["job_language_build"]
  input62["topology_refinement_inputs"]
  input_schema62["appsec-review/build-topology-refinement/1"]
  producer62 --> input62 --> job
  input62 -. schema .-> input_schema62
  producer63["job_language_build"]
  input63["build_actions"]
  input_schema63["appsec-review/retrieval-index/2"]
  producer63 --> input63 --> job
  input63 -. schema .-> input_schema63
  producer64["job_language_build"]
  input64["jvm_build_actions"]
  input_schema64["appsec-review/retrieval-index/2"]
  producer64 --> input64 --> job
  input64 -. schema .-> input_schema64
  producer65["job_language_build"]
  input65["language_build_receipts"]
  input_schema65["appsec-review/language-build-handoff/2"]
  producer65 --> input65 --> job
  input65 -. schema .-> input_schema65
  producer66["job_language_build"]
  input66["build_workspaces"]
  input_schema66["application/octet-stream"]
  producer66 --> input66 --> job
  input66 -. schema .-> input_schema66
  producer67["job_post_build_security_assessment"]
  input67["handoff"]
  input_schema67["appsec-review/job-handoff/2"]
  producer67 --> input67 --> job
  input67 -. schema .-> input_schema67
  producer68["job_post_build_security_assessment"]
  input68["build_security"]
  input_schema68["appsec-review/retrieval-index/2"]
  producer68 --> input68 --> job
  input68 -. schema .-> input_schema68
  producer69["job_post_build_security_assessment"]
  input69["build_security_documents"]
  input_schema69["appsec-review/post-build-security-assessment/1"]
  producer69 --> input69 --> job
  input69 -. schema .-> input_schema69
  producer70["job_project_build"]
  input70["handoff"]
  input_schema70["appsec-review/job-handoff/2"]
  producer70 --> input70 --> job
  input70 -. schema .-> input_schema70
  producer71["job_project_build"]
  input71["topology_refinement_inputs"]
  input_schema71["appsec-review/build-topology-refinement/1"]
  producer71 --> input71 --> job
  input71 -. schema .-> input_schema71
  producer72["job_project_build"]
  input72["project_build_dispatch"]
  input_schema72["appsec-review/project-build-dispatch/3"]
  producer72 --> input72 --> job
  input72 -. schema .-> input_schema72
  producer73["job_project_build"]
  input73["probe_workspaces"]
  input_schema73["application/octet-stream"]
  producer73 --> input73 --> job
  input73 -. schema .-> input_schema73
  producer74["job_project_build"]
  input74["image_build_streams"]
  input_schema74["text/plain"]
  producer74 --> input74 --> job
  input74 -. schema .-> input_schema74
  producer75["job_review_intake"]
  input75["handoff"]
  input_schema75["appsec-review/job-handoff/2"]
  producer75 --> input75 --> job
  input75 -. schema .-> input_schema75
  producer76["job_review_intake"]
  input76["model_preflight"]
  input_schema76["appsec-review/model-preflight/1"]
  producer76 --> input76 --> job
  input76 -. schema .-> input_schema76
  producer77["job_review_intake"]
  input77["binary_evidence"]
  input_schema77["appsec-review/binary-evidence-intake/1"]
  producer77 --> input77 --> job
  input77 -. schema .-> input_schema77
  producer78["job_review_intake"]
  input78["review_intake"]
  input_schema78["appsec-review/review-intake/1"]
  producer78 --> input78 --> job
  input78 -. schema .-> input_schema78
  producer79["job_review_prioritization"]
  input79["handoff"]
  input_schema79["appsec-review/job-handoff/2"]
  producer79 --> input79 --> job
  input79 -. schema .-> input_schema79
  producer80["job_review_prioritization"]
  input80["priority_items"]
  input_schema80["appsec-review/retrieval-index/2"]
  producer80 --> input80 --> job
  input80 -. schema .-> input_schema80
  producer81["job_review_prioritization"]
  input81["prioritization_documents"]
  input_schema81["appsec-review/review-prioritization/1"]
  producer81 --> input81 --> job
  input81 -. schema .-> input_schema81
  producer82["job_security_tagging"]
  input82["handoff"]
  input_schema82["appsec-review/job-handoff/2"]
  producer82 --> input82 --> job
  input82 -. schema .-> input_schema82
  producer83["job_security_tagging"]
  input83["tag_assignments"]
  input_schema83["appsec-review/tag-assignment/1"]
  producer83 --> input83 --> job
  input83 -. schema .-> input_schema83
  producer84["job_security_tagging"]
  input84["tagging_documents"]
  input_schema84["appsec-review/security-tagging-handoff/1"]
  producer84 --> input84 --> job
  input84 -. schema .-> input_schema84
  producer85["job_source_history_analysis"]
  input85["handoff"]
  input_schema85["appsec-review/job-handoff/2"]
  producer85 --> input85 --> job
  input85 -. schema .-> input_schema85
  producer86["job_source_history_analysis"]
  input86["history_signals"]
  input_schema86["appsec-review/retrieval-index/2"]
  producer86 --> input86 --> job
  input86 -. schema .-> input_schema86
  producer87["job_source_history_analysis"]
  input87["history_documents"]
  input_schema87["appsec-review/source-history-analysis/2"]
  producer87 --> input87 --> job
  input87 -. schema .-> input_schema87
  producer88["job_source_history_analysis"]
  input88["raw_git_history"]
  input_schema88["application/octet-stream"]
  producer88 --> input88 --> job
  input88 -. schema .-> input_schema88
  producer89["job_source_history_analysis"]
  input89["history_tool_io"]
  input_schema89["appsec-review/container-execution/1"]
  producer89 --> input89 --> job
  input89 -. schema .-> input_schema89
  producer90["job_svf_alias_analysis"]
  input90["handoff"]
  input_schema90["appsec-review/job-handoff/2"]
  producer90 --> input90 --> job
  input90 -. schema .-> input_schema90
  producer91["job_svf_alias_analysis"]
  input91["svf_alias_sets"]
  input_schema91["appsec-review/retrieval-index/2"]
  producer91 --> input91 --> job
  input91 -. schema .-> input_schema91
  producer92["job_svf_alias_analysis"]
  input92["svf_alias_scope_coverage"]
  input_schema92["appsec-review/cpp-index-coverage/1"]
  producer92 --> input92 --> job
  input92 -. schema .-> input_schema92
  producer93["job_svf_alias_analysis"]
  input93["svf_alias_summary"]
  input_schema93["appsec-review/svf-alias-analysis-handoff/1"]
  producer93 --> input93 --> job
  input93 -. schema .-> input_schema93
  producer94["job_svf_alias_analysis"]
  input94["svf_alias_raw"]
  input_schema94["application/json"]
  producer94 --> input94 --> job
  input94 -. schema .-> input_schema94
  producer95["job_target_analysis_plan"]
  input95["handoff"]
  input_schema95["appsec-review/job-handoff/2"]
  producer95 --> input95 --> job
  input95 -. schema .-> input_schema95
  producer96["job_target_analysis_plan"]
  input96["planning_feedback_cache"]
  input_schema96["appsec-review/target-analysis-proposal/3"]
  producer96 --> input96 --> job
  input96 -. schema .-> input_schema96
  producer97["job_target_analysis_plan"]
  input97["analysis_plan"]
  input_schema97["appsec-review/retrieval-index/2"]
  producer97 --> input97 --> job
  input97 -. schema .-> input_schema97
  producer98["job_target_analysis_plan"]
  input98["analysis_plan_documents"]
  input_schema98["appsec-review/target-analysis-plan/1"]
  producer98 --> input98 --> job
  input98 -. schema .-> input_schema98
  producer99["job_target_catalog"]
  input99["handoff"]
  input_schema99["appsec-review/job-handoff/2"]
  producer99 --> input99 --> job
  input99 -. schema .-> input_schema99
  producer100["job_target_catalog"]
  input100["target_artifact_inputs"]
  input_schema100["appsec-review/target-artifact-intake/1"]
  producer100 --> input100 --> job
  input100 -. schema .-> input_schema100
  producer101["job_target_catalog"]
  input101["source_files"]
  input_schema101["appsec-review/retrieval-index/2"]
  producer101 --> input101 --> job
  input101 -. schema .-> input_schema101
  producer102["job_target_catalog"]
  input102["declaration_symbols"]
  input_schema102["appsec-review/retrieval-index/2"]
  producer102 --> input102 --> job
  input102 -. schema .-> input_schema102
  producer103["job_target_catalog"]
  input103["components"]
  input_schema103["appsec-review/retrieval-index/2"]
  producer103 --> input103 --> job
  input103 -. schema .-> input_schema103
  producer104["job_target_catalog"]
  input104["target_documents"]
  input_schema104["appsec-review/retrieval-index/2"]
  producer104 --> input104 --> job
  input104 -. schema .-> input_schema104
  producer105["job_target_catalog"]
  input105["build_units"]
  input_schema105["appsec-review/retrieval-index/2"]
  producer105 --> input105 --> job
  input105 -. schema .-> input_schema105
  producer106["job_target_catalog"]
  input106["catalog_documents"]
  input_schema106["appsec-review/target-catalog/1"]
  producer106 --> input106 --> job
  input106 -. schema .-> input_schema106
  producer107["job_tree_sitter_ast"]
  input107["handoff"]
  input_schema107["appsec-review/job-handoff/2"]
  producer107 --> input107 --> job
  input107 -. schema .-> input_schema107
  producer108["job_tree_sitter_ast"]
  input108["tree_sitter_ast"]
  input_schema108["appsec-review/tree-sitter-normalizer/1"]
  producer108 --> input108 --> job
  input108 -. schema .-> input_schema108
  producer109["job_tree_sitter_ast"]
  input109["tree_sitter_coverage"]
  input_schema109["appsec-review/tree-sitter-ast/1"]
  producer109 --> input109 --> job
  input109 -. schema .-> input_schema109
  producer110["job_tree_sitter_ast"]
  input110["tree_sitter_node_shards"]
  input_schema110["appsec-review/tree-sitter-ast/1"]
  producer110 --> input110 --> job
  input110 -. schema .-> input_schema110
  producer111["job_tree_sitter_ast"]
  input111["generated_source_backing"]
  input_schema111["appsec-review/generated-source-backing/1"]
  producer111 --> input111 --> job
  input111 -. schema .-> input_schema111
  producer112["job_tree_sitter_ast"]
  input112["tree_sitter_tool_io"]
  input_schema112["appsec-review/container-execution/1"]
  producer112 --> input112 --> job
  input112 -. schema .-> input_schema112
  producer113["job_third_party_data_sync"]
  input113["feed_snapshot"]
  input_schema113["appsec-review/public-feed-use/1"]
  producer113 --> input113 --> job
  input113 -. schema .-> input_schema113
  output0["owasp_documents"]
  output_schema0["appsec-review/owasp-workbench-result/1"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["owasp_model_receipts"]
  output_schema1["appsec-review/owasp-model-receipt/1"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["owasp_workbench"]
  output_schema2["appsec-review/owasp-index-shard/1"]
  job --> output2
  output2 -. schema .-> output_schema2
```

<!-- generated:end -->
