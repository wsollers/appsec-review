---
title: "security_tagging"
kind: "operations"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_security_tagging"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---

# security_tagging

## Purpose

Publish evidence-bound security routing tags and a tag-cloud view from accepted source, graph,
observation and coverage records. An observed or invoked capability is not a vulnerability;
a crosswalk-derived tag means applicable, not present or satisfied. The handoff deliberately
publishes an empty `security_findings` list.

<!-- generated:begin job=job_security_tagging -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

security_tagging

Job: `job_security_tagging`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `collation` | `collation.collate_facets` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_security_tagging/job.py#L316) |
| `collation` | `collation.model_pass` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_security_tagging/job.py#L333) |
| `collection` | `collection.coverage_gaps` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_security_tagging/job.py#L311) |
| `collection` | `collection.observation_facts` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_security_tagging/job.py#L305) |
| `collection` | `collection.source_facts` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_security_tagging/job.py#L294) |
| `crosswalk` | `crosswalk.apply_crosswalk` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_security_tagging/job.py#L358) |
| `integrity` | `integrity.validate_assignments` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_security_tagging/job.py#L392) |
| `publication` | `publication.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_security_tagging/job.py#L435) |
| `publication` | `publication.publish_index` | 1 | `index` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_security_tagging/job.py#L411) |
| `publication` | `publication.publish_tag_cloud` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_security_tagging/job.py#L428) |
| `scope` | `scope.resolve_inputs` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_security_tagging/job.py#L274) |
| `taxonomy` | `taxonomy.load_taxonomy` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_security_tagging/job.py#L263) |

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
| `job_binary_evidence_indexing` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_binary_evidence_indexing` | `binary_functions` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_binary_evidence_indexing` | `binary_pseudo_c` | `appsec-review/binary-source-backing/1` | handoff | optional | gap |
| `job_binary_evidence_indexing` | `binary_evidence_summary` | `appsec-review/binary-evidence-index/1` | handoff | optional | gap |
| `job_change_context_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_change_context_analysis` | `change_context` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_change_context_analysis` | `change_context_documents` | `appsec-review/change-context-analysis/1` | handoff | optional | gap |
| `job_change_context_analysis` | `operator_exports` | `application/json` | handoff | optional | gap |
| `job_change_context_analysis` | `change_context_tool_io` | `appsec-review/container-execution/1` | handoff | optional | gap |
| `job_ci_configuration_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_ci_configuration_analysis` | `ci_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_ci_configuration_analysis` | `ci_findings` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_ci_configuration_analysis` | `ci_documents` | `appsec-review/ci-configuration-analysis-handoff/1` | handoff | optional | gap |
| `job_ci_configuration_analysis` | `ci_tool_io` | `appsec-review/container-execution/1` | handoff | optional | gap |
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
| `job_code_graph_index` | `alternate_cpg_index` | `appsec-review/alternate-cpg/1` | handoff | when_output_declared | not_applicable |
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
| `job_debug_symbol_indexing` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_debug_symbol_indexing` | `normalized_symbols` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_debug_symbol_indexing` | `symbol_coverage` | `appsec-review/debug-symbol-coverage/1` | handoff | optional | gap |
| `job_debug_symbol_indexing` | `target_decision` | `appsec-review/debug-symbol-decision/2` | handoff | optional | gap |
| `job_debug_symbol_indexing` | `raw_artifact_refs` | `appsec-review/debug-symbol-inputs/1` | handoff | optional | gap |
| `job_debug_symbol_indexing` | `reader_executions` | `appsec-review/container-execution/1` | handoff | optional | gap |
| `job_debug_symbol_indexing` | `debug_symbol_summary` | `appsec-review/debug-symbol-indexing/1` | handoff | optional | gap |
| `job_dependency_intelligence` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_discovery` | `appsec-review/native-discovery/1` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_component_curation` | `appsec-review/native-component-curation/1` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_metadata_investigation` | `appsec-review/native-metadata-investigation/1` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_inference_metrics` | `appsec-review/native-inference-metrics/1` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_spdx` | `SPDX-2.3` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_sbom_provenance` | `appsec-review/native-sbom-provenance/1` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_sbom_metrics` | `appsec-review/native-sbom-metrics/1` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_advisory_observations` | `appsec-review/retrieval-index/2` | handoff | when_output_declared | not_applicable |
| `job_dependency_intelligence` | `native_advisory_lookup` | `appsec-review/native-advisory-lookup/1` | handoff | when_output_declared | not_applicable |
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
| `job_profile_data` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_profile_data` | `profile_data` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_profile_data` | `profile_data_handoff` | `appsec-review/profile-data-handoff/1` | handoff | optional | gap |
| `job_review_prioritization` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_review_prioritization` | `priority_items` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_review_prioritization` | `prioritization_documents` | `appsec-review/review-prioritization/1` | handoff | optional | gap |
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
| `job_test_coverage` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_test_coverage` | `test_coverage` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_test_coverage` | `test_coverage_handoff` | `appsec-review/test-coverage-handoff/1` | handoff | optional | gap |
| `job_tree_sitter_ast` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_tree_sitter_ast` | `tree_sitter_ast` | `appsec-review/tree-sitter-normalizer/1` | handoff | optional | gap |
| `job_tree_sitter_ast` | `tree_sitter_coverage` | `appsec-review/tree-sitter-ast/1` | handoff | optional | gap |
| `job_tree_sitter_ast` | `tree_sitter_node_shards` | `appsec-review/tree-sitter-normalizer/1` | handoff | optional | gap |
| `job_tree_sitter_ast` | `generated_source_backing` | `appsec-review/generated-source-backing/1` | handoff | optional | gap |
| `job_tree_sitter_ast` | `tree_sitter_tool_io` | `appsec-review/container-execution/1` | handoff | optional | gap |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `tag_assignments` | `publication` | `appsec-review/tag-assignment/1` | indexed | `tags` | `find`, `search`, `trace` |
| `tagging_documents` | `publication` | `appsec-review/security-tagging-handoff/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

These are job-level declarations; exact per-task selection is not declared ([T-147](../TODO.md)).

```json
{}
```

- Role: [unit_purpose_collator](../generated/guidance.md#roles-unit_purpose_collator).
- Task prompt: `unit_purpose_collation`.
- Runtime skill: [unit-purpose-collation](../generated/guidance.md#runtime_skills-unit-purpose-collation).

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | `tests/acceptance/job_security_tagging/test_behavioral_tags.py` |
| integration | `tests/integration/job_security_tagging/test_behavioral_tags.py`<br>`tests/integration/job_security_tagging/test_security_tagging_jobrunner.py` |
| live | None declared |
| unit | `tests/unit/job_security_tagging/test_audit_semantics.py`<br>`tests/unit/job_security_tagging/test_behavioral_tags.py`<br>`tests/unit/job_security_tagging/test_collation.py`<br>`tests/unit/job_security_tagging/test_contract.py`<br>`tests/unit/job_security_tagging/test_handler.py`<br>`tests/unit/job_security_tagging/test_model_pass.py`<br>`tests/unit/job_security_tagging/test_native_language_aliases.py`<br>`tests/unit/job_security_tagging/test_reader.py`<br>`tests/unit/job_security_tagging/test_rules_and_roles.py`<br>`tests/orchestration/dagster/test_security_tagging.py`<br>`tests/test_security_tagging.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_code_graph_index`, `job_binary_evidence_indexing`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_security_tagging"]
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
  producer9["job_binary_evidence_indexing"]
  input9["handoff"]
  input_schema9["appsec-review/job-handoff/2"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_binary_evidence_indexing"]
  input10["binary_functions"]
  input_schema10["appsec-review/retrieval-index/2"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_binary_evidence_indexing"]
  input11["binary_pseudo_c"]
  input_schema11["appsec-review/binary-source-backing/1"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_binary_evidence_indexing"]
  input12["binary_evidence_summary"]
  input_schema12["appsec-review/binary-evidence-index/1"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_change_context_analysis"]
  input13["handoff"]
  input_schema13["appsec-review/job-handoff/2"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_change_context_analysis"]
  input14["change_context"]
  input_schema14["appsec-review/retrieval-index/2"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_change_context_analysis"]
  input15["change_context_documents"]
  input_schema15["appsec-review/change-context-analysis/1"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_change_context_analysis"]
  input16["operator_exports"]
  input_schema16["application/json"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  producer17["job_change_context_analysis"]
  input17["change_context_tool_io"]
  input_schema17["appsec-review/container-execution/1"]
  producer17 --> input17 --> job
  input17 -. schema .-> input_schema17
  producer18["job_ci_configuration_analysis"]
  input18["handoff"]
  input_schema18["appsec-review/job-handoff/2"]
  producer18 --> input18 --> job
  input18 -. schema .-> input_schema18
  producer19["job_ci_configuration_analysis"]
  input19["ci_observations"]
  input_schema19["appsec-review/retrieval-index/2"]
  producer19 --> input19 --> job
  input19 -. schema .-> input_schema19
  producer20["job_ci_configuration_analysis"]
  input20["ci_findings"]
  input_schema20["appsec-review/retrieval-index/2"]
  producer20 --> input20 --> job
  input20 -. schema .-> input_schema20
  producer21["job_ci_configuration_analysis"]
  input21["ci_documents"]
  input_schema21["appsec-review/ci-configuration-analysis-handoff/1"]
  producer21 --> input21 --> job
  input21 -. schema .-> input_schema21
  producer22["job_ci_configuration_analysis"]
  input22["ci_tool_io"]
  input_schema22["appsec-review/container-execution/1"]
  producer22 --> input22 --> job
  input22 -. schema .-> input_schema22
  producer23["job_clang_static_analysis"]
  input23["handoff"]
  input_schema23["appsec-review/job-handoff/2"]
  producer23 --> input23 --> job
  input23 -. schema .-> input_schema23
  producer24["job_clang_static_analysis"]
  input24["clang_static_observations"]
  input_schema24["appsec-review/retrieval-index/2"]
  producer24 --> input24 --> job
  input24 -. schema .-> input_schema24
  producer25["job_clang_static_analysis"]
  input25["clang_static_scope_coverage"]
  input_schema25["appsec-review/cpp-index-coverage/1"]
  producer25 --> input25 --> job
  input25 -. schema .-> input_schema25
  producer26["job_clang_static_analysis"]
  input26["clang_static_summary"]
  input_schema26["appsec-review/clang-static-analysis-handoff/1"]
  producer26 --> input26 --> job
  input26 -. schema .-> input_schema26
  producer27["job_clang_static_analysis"]
  input27["clang_static_raw"]
  input_schema27["application/json"]
  producer27 --> input27 --> job
  input27 -. schema .-> input_schema27
  producer28["job_code_graph_index"]
  input28["handoff"]
  input_schema28["appsec-review/job-handoff/2"]
  producer28 --> input28 --> job
  input28 -. schema .-> input_schema28
  producer29["job_code_graph_index"]
  input29["code_graph_facts"]
  input_schema29["appsec-review/graph-fact/1"]
  producer29 --> input29 --> job
  input29 -. schema .-> input_schema29
  producer30["job_code_graph_index"]
  input30["code_graph_stages"]
  input_schema30["appsec-review/code-graph-stage/1"]
  producer30 --> input30 --> job
  input30 -. schema .-> input_schema30
  producer31["job_code_graph_index"]
  input31["code_graph_checkpoints"]
  input_schema31["appsec-review/code-graph-checkpoint/1"]
  producer31 --> input31 --> job
  input31 -. schema .-> input_schema31
  producer32["job_code_graph_index"]
  input32["code_graph_summary"]
  input_schema32["appsec-review/code-graph-index/1"]
  producer32 --> input32 --> job
  input32 -. schema .-> input_schema32
  producer33["job_code_graph_index"]
  input33["alternate_cpg_index"]
  input_schema33["appsec-review/alternate-cpg/1"]
  producer33 --> input33 --> job
  input33 -. schema .-> input_schema33
  producer34["job_codeql_analysis"]
  input34["handoff"]
  input_schema34["appsec-review/job-handoff/2"]
  producer34 --> input34 --> job
  input34 -. schema .-> input_schema34
  producer35["job_codeql_analysis"]
  input35["codeql_predecessor_import"]
  input_schema35["appsec-review/codeql-predecessor-import/1"]
  producer35 --> input35 --> job
  input35 -. schema .-> input_schema35
  producer36["job_codeql_analysis"]
  input36["codeql_graph_export"]
  input_schema36["appsec-review/codeql-graph-export/1"]
  producer36 --> input36 --> job
  input36 -. schema .-> input_schema36
  producer37["job_codeql_analysis"]
  input37["codeql_observations"]
  input_schema37["appsec-review/codeql-sarif-normalizer/3"]
  producer37 --> input37 --> job
  input37 -. schema .-> input_schema37
  producer38["job_codeql_analysis"]
  input38["codeql_plan_and_summary"]
  input_schema38["appsec-review/codeql-analysis-handoff/1"]
  producer38 --> input38 --> job
  input38 -. schema .-> input_schema38
  producer39["job_codeql_analysis"]
  input39["codeql_scope_material"]
  input_schema39["application/octet-stream"]
  producer39 --> input39 --> job
  input39 -. schema .-> input_schema39
  producer40["job_cpg_analysis"]
  input40["handoff"]
  input_schema40["appsec-review/job-handoff/2"]
  producer40 --> input40 --> job
  input40 -. schema .-> input_schema40
  producer41["job_cpg_analysis"]
  input41["cpg_graph_coverage"]
  input_schema41["appsec-review/retrieval-index/2"]
  producer41 --> input41 --> job
  input41 -. schema .-> input_schema41
  producer42["job_cpg_analysis"]
  input42["cpg_scope_coverage"]
  input_schema42["appsec-review/cpp-index-coverage/1"]
  producer42 --> input42 --> job
  input42 -. schema .-> input_schema42
  producer43["job_cpg_analysis"]
  input43["cpg_summary"]
  input_schema43["appsec-review/cpg-analysis/1"]
  producer43 --> input43 --> job
  input43 -. schema .-> input_schema43
  producer44["job_cpg_analysis"]
  input44["cpg_binary"]
  input_schema44["application/octet-stream"]
  producer44 --> input44 --> job
  input44 -. schema .-> input_schema44
  producer45["job_cpp_compiled_analysis"]
  input45["handoff"]
  input_schema45["appsec-review/job-handoff/2"]
  producer45 --> input45 --> job
  input45 -. schema .-> input_schema45
  producer46["job_cpp_compiled_analysis"]
  input46["cpp_build_graph"]
  input_schema46["appsec-review/retrieval-index/2"]
  producer46 --> input46 --> job
  input46 -. schema .-> input_schema46
  producer47["job_cpp_compiled_analysis"]
  input47["clang_ast"]
  input_schema47["appsec-review/retrieval-index/2"]
  producer47 --> input47 --> job
  input47 -. schema .-> input_schema47
  producer48["job_cpp_compiled_analysis"]
  input48["llvm_ir"]
  input_schema48["appsec-review/retrieval-index/2"]
  producer48 --> input48 --> job
  input48 -. schema .-> input_schema48
  producer49["job_cpp_compiled_analysis"]
  input49["infer_observations"]
  input_schema49["appsec-review/retrieval-index/2"]
  producer49 --> input49 --> job
  input49 -. schema .-> input_schema49
  producer50["job_cpp_compiled_analysis"]
  input50["binary_symbols"]
  input_schema50["appsec-review/retrieval-index/2"]
  producer50 --> input50 --> job
  input50 -. schema .-> input_schema50
  producer51["job_cpp_compiled_analysis"]
  input51["cpp_blocked_branches"]
  input_schema51["appsec-review/retrieval-index/2"]
  producer51 --> input51 --> job
  input51 -. schema .-> input_schema51
  producer52["job_cpp_compiled_analysis"]
  input52["cpp_plan_and_summary"]
  input_schema52["appsec-review/cpp-compiled-analysis/2"]
  producer52 --> input52 --> job
  input52 -. schema .-> input_schema52
  producer53["job_cpp_compiled_analysis"]
  input53["cpp_case_material"]
  input_schema53["application/octet-stream"]
  producer53 --> input53 --> job
  input53 -. schema .-> input_schema53
  producer54["job_cpp_symbol_index"]
  input54["handoff"]
  input_schema54["appsec-review/job-handoff/2"]
  producer54 --> input54 --> job
  input54 -. schema .-> input_schema54
  producer55["job_cpp_symbol_index"]
  input55["clangd_symbols"]
  input_schema55["appsec-review/retrieval-index/2"]
  producer55 --> input55 --> job
  input55 -. schema .-> input_schema55
  producer56["job_cpp_symbol_index"]
  input56["clangd_coverage"]
  input_schema56["appsec-review/cpp-index-coverage/1"]
  producer56 --> input56 --> job
  input56 -. schema .-> input_schema56
  producer57["job_cpp_symbol_index"]
  input57["clangd_summary"]
  input_schema57["appsec-review/cpp-symbol-index/1"]
  producer57 --> input57 --> job
  input57 -. schema .-> input_schema57
  producer58["job_cpp_symbol_index"]
  input58["clangd_tool_io"]
  input_schema58["appsec-review/container-execution/1"]
  producer58 --> input58 --> job
  input58 -. schema .-> input_schema58
  producer59["job_debug_symbol_indexing"]
  input59["handoff"]
  input_schema59["appsec-review/job-handoff/2"]
  producer59 --> input59 --> job
  input59 -. schema .-> input_schema59
  producer60["job_debug_symbol_indexing"]
  input60["normalized_symbols"]
  input_schema60["appsec-review/retrieval-index/2"]
  producer60 --> input60 --> job
  input60 -. schema .-> input_schema60
  producer61["job_debug_symbol_indexing"]
  input61["symbol_coverage"]
  input_schema61["appsec-review/debug-symbol-coverage/1"]
  producer61 --> input61 --> job
  input61 -. schema .-> input_schema61
  producer62["job_debug_symbol_indexing"]
  input62["target_decision"]
  input_schema62["appsec-review/debug-symbol-decision/2"]
  producer62 --> input62 --> job
  input62 -. schema .-> input_schema62
  producer63["job_debug_symbol_indexing"]
  input63["raw_artifact_refs"]
  input_schema63["appsec-review/debug-symbol-inputs/1"]
  producer63 --> input63 --> job
  input63 -. schema .-> input_schema63
  producer64["job_debug_symbol_indexing"]
  input64["reader_executions"]
  input_schema64["appsec-review/container-execution/1"]
  producer64 --> input64 --> job
  input64 -. schema .-> input_schema64
  producer65["job_debug_symbol_indexing"]
  input65["debug_symbol_summary"]
  input_schema65["appsec-review/debug-symbol-indexing/1"]
  producer65 --> input65 --> job
  input65 -. schema .-> input_schema65
  producer66["job_dependency_intelligence"]
  input66["handoff"]
  input_schema66["appsec-review/job-handoff/2"]
  producer66 --> input66 --> job
  input66 -. schema .-> input_schema66
  producer67["job_dependency_intelligence"]
  input67["native_discovery"]
  input_schema67["appsec-review/native-discovery/1"]
  producer67 --> input67 --> job
  input67 -. schema .-> input_schema67
  producer68["job_dependency_intelligence"]
  input68["native_component_curation"]
  input_schema68["appsec-review/native-component-curation/1"]
  producer68 --> input68 --> job
  input68 -. schema .-> input_schema68
  producer69["job_dependency_intelligence"]
  input69["native_metadata_investigation"]
  input_schema69["appsec-review/native-metadata-investigation/1"]
  producer69 --> input69 --> job
  input69 -. schema .-> input_schema69
  producer70["job_dependency_intelligence"]
  input70["native_inference_metrics"]
  input_schema70["appsec-review/native-inference-metrics/1"]
  producer70 --> input70 --> job
  input70 -. schema .-> input_schema70
  producer71["job_dependency_intelligence"]
  input71["native_spdx"]
  input_schema71["SPDX-2.3"]
  producer71 --> input71 --> job
  input71 -. schema .-> input_schema71
  producer72["job_dependency_intelligence"]
  input72["native_sbom_provenance"]
  input_schema72["appsec-review/native-sbom-provenance/1"]
  producer72 --> input72 --> job
  input72 -. schema .-> input_schema72
  producer73["job_dependency_intelligence"]
  input73["native_sbom_metrics"]
  input_schema73["appsec-review/native-sbom-metrics/1"]
  producer73 --> input73 --> job
  input73 -. schema .-> input_schema73
  producer74["job_dependency_intelligence"]
  input74["native_advisory_observations"]
  input_schema74["appsec-review/retrieval-index/2"]
  producer74 --> input74 --> job
  input74 -. schema .-> input_schema74
  producer75["job_dependency_intelligence"]
  input75["native_advisory_lookup"]
  input_schema75["appsec-review/native-advisory-lookup/1"]
  producer75 --> input75 --> job
  input75 -. schema .-> input_schema75
  producer76["job_dependency_intelligence"]
  input76["dependency_context"]
  input_schema76["appsec-review/retrieval-index/2"]
  producer76 --> input76 --> job
  input76 -. schema .-> input_schema76
  producer77["job_dependency_intelligence"]
  input77["scorecard_responses"]
  input_schema77["application/json"]
  producer77 --> input77 --> job
  input77 -. schema .-> input_schema77
  producer78["job_dependency_intelligence"]
  input78["dependency_intelligence_handoff"]
  input_schema78["appsec-review/dependency-intelligence-handoff/1"]
  producer78 --> input78 --> job
  input78 -. schema .-> input_schema78
  producer79["job_evidence_collection"]
  input79["handoff"]
  input_schema79["appsec-review/job-handoff/2"]
  producer79 --> input79 --> job
  input79 -. schema .-> input_schema79
  producer80["job_evidence_collection"]
  input80["static_tool_observations"]
  input_schema80["appsec-review/retrieval-index/2"]
  producer80 --> input80 --> job
  input80 -. schema .-> input_schema80
  producer81["job_evidence_collection"]
  input81["static_tool_evidence"]
  input_schema81["appsec-review/static-tool-evidence/2"]
  producer81 --> input81 --> job
  input81 -. schema .-> input_schema81
  producer82["job_evidence_collection"]
  input82["static_tool_io"]
  input_schema82["appsec-review/container-execution/1"]
  producer82 --> input82 --> job
  input82 -. schema .-> input_schema82
  producer83["job_language_build"]
  input83["handoff"]
  input_schema83["appsec-review/job-handoff/2"]
  producer83 --> input83 --> job
  input83 -. schema .-> input_schema83
  producer84["job_language_build"]
  input84["topology_refinement_inputs"]
  input_schema84["appsec-review/build-topology-refinement/1"]
  producer84 --> input84 --> job
  input84 -. schema .-> input_schema84
  producer85["job_language_build"]
  input85["build_actions"]
  input_schema85["appsec-review/retrieval-index/2"]
  producer85 --> input85 --> job
  input85 -. schema .-> input_schema85
  producer86["job_language_build"]
  input86["jvm_build_actions"]
  input_schema86["appsec-review/retrieval-index/2"]
  producer86 --> input86 --> job
  input86 -. schema .-> input_schema86
  producer87["job_language_build"]
  input87["language_build_receipts"]
  input_schema87["appsec-review/language-build-handoff/2"]
  producer87 --> input87 --> job
  input87 -. schema .-> input_schema87
  producer88["job_language_build"]
  input88["build_workspaces"]
  input_schema88["application/octet-stream"]
  producer88 --> input88 --> job
  input88 -. schema .-> input_schema88
  producer89["job_post_build_security_assessment"]
  input89["handoff"]
  input_schema89["appsec-review/job-handoff/2"]
  producer89 --> input89 --> job
  input89 -. schema .-> input_schema89
  producer90["job_post_build_security_assessment"]
  input90["build_security"]
  input_schema90["appsec-review/retrieval-index/2"]
  producer90 --> input90 --> job
  input90 -. schema .-> input_schema90
  producer91["job_post_build_security_assessment"]
  input91["build_security_documents"]
  input_schema91["appsec-review/post-build-security-assessment/1"]
  producer91 --> input91 --> job
  input91 -. schema .-> input_schema91
  producer92["job_profile_data"]
  input92["handoff"]
  input_schema92["appsec-review/job-handoff/2"]
  producer92 --> input92 --> job
  input92 -. schema .-> input_schema92
  producer93["job_profile_data"]
  input93["profile_data"]
  input_schema93["appsec-review/retrieval-index/2"]
  producer93 --> input93 --> job
  input93 -. schema .-> input_schema93
  producer94["job_profile_data"]
  input94["profile_data_handoff"]
  input_schema94["appsec-review/profile-data-handoff/1"]
  producer94 --> input94 --> job
  input94 -. schema .-> input_schema94
  producer95["job_review_prioritization"]
  input95["handoff"]
  input_schema95["appsec-review/job-handoff/2"]
  producer95 --> input95 --> job
  input95 -. schema .-> input_schema95
  producer96["job_review_prioritization"]
  input96["priority_items"]
  input_schema96["appsec-review/retrieval-index/2"]
  producer96 --> input96 --> job
  input96 -. schema .-> input_schema96
  producer97["job_review_prioritization"]
  input97["prioritization_documents"]
  input_schema97["appsec-review/review-prioritization/1"]
  producer97 --> input97 --> job
  input97 -. schema .-> input_schema97
  producer98["job_source_history_analysis"]
  input98["handoff"]
  input_schema98["appsec-review/job-handoff/2"]
  producer98 --> input98 --> job
  input98 -. schema .-> input_schema98
  producer99["job_source_history_analysis"]
  input99["history_signals"]
  input_schema99["appsec-review/retrieval-index/2"]
  producer99 --> input99 --> job
  input99 -. schema .-> input_schema99
  producer100["job_source_history_analysis"]
  input100["history_documents"]
  input_schema100["appsec-review/source-history-analysis/2"]
  producer100 --> input100 --> job
  input100 -. schema .-> input_schema100
  producer101["job_source_history_analysis"]
  input101["raw_git_history"]
  input_schema101["application/octet-stream"]
  producer101 --> input101 --> job
  input101 -. schema .-> input_schema101
  producer102["job_source_history_analysis"]
  input102["history_tool_io"]
  input_schema102["appsec-review/container-execution/1"]
  producer102 --> input102 --> job
  input102 -. schema .-> input_schema102
  producer103["job_svf_alias_analysis"]
  input103["handoff"]
  input_schema103["appsec-review/job-handoff/2"]
  producer103 --> input103 --> job
  input103 -. schema .-> input_schema103
  producer104["job_svf_alias_analysis"]
  input104["svf_alias_sets"]
  input_schema104["appsec-review/retrieval-index/2"]
  producer104 --> input104 --> job
  input104 -. schema .-> input_schema104
  producer105["job_svf_alias_analysis"]
  input105["svf_alias_scope_coverage"]
  input_schema105["appsec-review/cpp-index-coverage/1"]
  producer105 --> input105 --> job
  input105 -. schema .-> input_schema105
  producer106["job_svf_alias_analysis"]
  input106["svf_alias_summary"]
  input_schema106["appsec-review/svf-alias-analysis-handoff/1"]
  producer106 --> input106 --> job
  input106 -. schema .-> input_schema106
  producer107["job_svf_alias_analysis"]
  input107["svf_alias_raw"]
  input_schema107["application/json"]
  producer107 --> input107 --> job
  input107 -. schema .-> input_schema107
  producer108["job_target_analysis_plan"]
  input108["handoff"]
  input_schema108["appsec-review/job-handoff/2"]
  producer108 --> input108 --> job
  input108 -. schema .-> input_schema108
  producer109["job_target_analysis_plan"]
  input109["planning_feedback_cache"]
  input_schema109["appsec-review/target-analysis-proposal/3"]
  producer109 --> input109 --> job
  input109 -. schema .-> input_schema109
  producer110["job_target_analysis_plan"]
  input110["analysis_plan"]
  input_schema110["appsec-review/retrieval-index/2"]
  producer110 --> input110 --> job
  input110 -. schema .-> input_schema110
  producer111["job_target_analysis_plan"]
  input111["analysis_plan_documents"]
  input_schema111["appsec-review/target-analysis-plan/1"]
  producer111 --> input111 --> job
  input111 -. schema .-> input_schema111
  producer112["job_target_catalog"]
  input112["handoff"]
  input_schema112["appsec-review/job-handoff/2"]
  producer112 --> input112 --> job
  input112 -. schema .-> input_schema112
  producer113["job_target_catalog"]
  input113["target_artifact_inputs"]
  input_schema113["appsec-review/target-artifact-intake/1"]
  producer113 --> input113 --> job
  input113 -. schema .-> input_schema113
  producer114["job_target_catalog"]
  input114["source_files"]
  input_schema114["appsec-review/retrieval-index/2"]
  producer114 --> input114 --> job
  input114 -. schema .-> input_schema114
  producer115["job_target_catalog"]
  input115["declaration_symbols"]
  input_schema115["appsec-review/retrieval-index/2"]
  producer115 --> input115 --> job
  input115 -. schema .-> input_schema115
  producer116["job_target_catalog"]
  input116["components"]
  input_schema116["appsec-review/retrieval-index/2"]
  producer116 --> input116 --> job
  input116 -. schema .-> input_schema116
  producer117["job_target_catalog"]
  input117["target_documents"]
  input_schema117["appsec-review/retrieval-index/2"]
  producer117 --> input117 --> job
  input117 -. schema .-> input_schema117
  producer118["job_target_catalog"]
  input118["build_units"]
  input_schema118["appsec-review/retrieval-index/2"]
  producer118 --> input118 --> job
  input118 -. schema .-> input_schema118
  producer119["job_target_catalog"]
  input119["catalog_documents"]
  input_schema119["appsec-review/target-catalog/1"]
  producer119 --> input119 --> job
  input119 -. schema .-> input_schema119
  producer120["job_test_coverage"]
  input120["handoff"]
  input_schema120["appsec-review/job-handoff/2"]
  producer120 --> input120 --> job
  input120 -. schema .-> input_schema120
  producer121["job_test_coverage"]
  input121["test_coverage"]
  input_schema121["appsec-review/retrieval-index/2"]
  producer121 --> input121 --> job
  input121 -. schema .-> input_schema121
  producer122["job_test_coverage"]
  input122["test_coverage_handoff"]
  input_schema122["appsec-review/test-coverage-handoff/1"]
  producer122 --> input122 --> job
  input122 -. schema .-> input_schema122
  producer123["job_tree_sitter_ast"]
  input123["handoff"]
  input_schema123["appsec-review/job-handoff/2"]
  producer123 --> input123 --> job
  input123 -. schema .-> input_schema123
  producer124["job_tree_sitter_ast"]
  input124["tree_sitter_ast"]
  input_schema124["appsec-review/tree-sitter-normalizer/1"]
  producer124 --> input124 --> job
  input124 -. schema .-> input_schema124
  producer125["job_tree_sitter_ast"]
  input125["tree_sitter_coverage"]
  input_schema125["appsec-review/tree-sitter-ast/1"]
  producer125 --> input125 --> job
  input125 -. schema .-> input_schema125
  producer126["job_tree_sitter_ast"]
  input126["tree_sitter_node_shards"]
  input_schema126["appsec-review/tree-sitter-normalizer/1"]
  producer126 --> input126 --> job
  input126 -. schema .-> input_schema126
  producer127["job_tree_sitter_ast"]
  input127["generated_source_backing"]
  input_schema127["appsec-review/generated-source-backing/1"]
  producer127 --> input127 --> job
  input127 -. schema .-> input_schema127
  producer128["job_tree_sitter_ast"]
  input128["tree_sitter_tool_io"]
  input_schema128["appsec-review/container-execution/1"]
  producer128 --> input128 --> job
  input128 -. schema .-> input_schema128
  output0["tag_assignments"]
  output_schema0["appsec-review/tag-assignment/1"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["tagging_documents"]
  output_schema1["appsec-review/security-tagging-handoff/1"]
  job --> output1
  output1 -. schema .-> output_schema1
```

<!-- generated:end -->

## Process

See the [handler](../../src/appsec_review/jobs/job_security_tagging/job.py),
[collectors](../../src/appsec_review/jobs/job_security_tagging/producers.py),
[collation collector](../../src/appsec_review/jobs/job_security_tagging/collation.py),
[model pass](../../src/appsec_review/jobs/job_security_tagging/model_pass.py),
[taxonomy validator](../../src/appsec_review/jobs/job_security_tagging/taxonomy.py) and
[crosswalk evaluator](../../src/appsec_review/jobs/job_security_tagging/crosswalk.py).

### `taxonomy`

1. In `taxonomy.load_taxonomy`, verify configured vocabulary, capability-rule and crosswalk file
   hashes. Reject unknown settings, invalid bounds or incompatible taxonomy.
2. Record identities, namespace status and crosswalk count. Proposed/fixture namespaces do not
   acquire active or authoritative status merely by being loaded.

### `scope`

1. In `scope.resolve_inputs`, verify the accepted index manifest and target fingerprint.
2. Resolve project/component subjects under explicit ownership rules, recording bounded component
   coverage and a component-topology hash. Freeze manifest, topology and ownership identities.

### `collection`

1. In `collection.source_facts`, collect catalog language/path facts and eligible graph entry/sink
   facts. For invoked tags, verify graph schema, admissibility, mapped class, exact source span
   and component ownership; reject or qualify nonresolving facts with named reasons.
2. In `collection.observation_facts`, map only configured producer/rule combinations and bounded
   observations. Preserve reported weakness/severity basis; do not turn a scanner assertion into
   independent confirmation.
3. In `collection.coverage_gaps`, turn noncomplete upstream coverage and missing required index
   families into reported gap tags. Merge duplicate assignment identities and enforce the
   assignment ceiling; overflow fails rather than silently dropping tags.

### `collation`

1. In `collation.collate_facets`, classify accepted source files under the resolved
   `source_dispositions` table (`[jobs.job_security_tagging.settings.collation]`), read only
   hash-verified first-party source bytes within configured per-file and per-component bounds,
   evaluate lexical/path, tag-to-facet and facet-to-facet rules across the closed `role`,
   `exposure`, `trust`, `mechanism`, `asset` and `state` namespaces, roll up facets per component,
   derive `target:*` classes and publish `collation.json` (`appsec-review/collation-pass/1`) and
   `facet-facts.json` (indexed under shard `facets`).
2. In `collation.model_pass`, publish a disabled `unit-purposes.json` record with zero model calls
   unless `settings.collation.model_pass.enabled` is true (`false` in every shipped profile). When
   enabled, dispatch one bounded `unit_purpose` model request per first-party component and accept
   `unit-purpose-proposal/1` claims only when every `role`/`asset` value is in the pinned
   vocabulary, every claim cites a supplied `path:line` excerpt or deterministic assignment ID and
   `purpose` is within 600 characters; rejected proposals or transport errors record a named gap
   without altering deterministic facets.

### `crosswalk`

1. In `crosswalk.apply_crosswalk`, group observed inputs only by the rule's supported scope:
   same subject, component, project or supported CI-job context.
2. Emit derived tags with rule identity and `derived_from` inputs. If a resulting namespace uses
   a catalog fixture, emit `gap:catalog-fixture`; do not present the fixture as a live feed.

### `integrity`

1. In `integrity.validate_assignments`, merge collectors and derived records.
2. Validate namespace/basis rules and assignment identity; every derived input must exist and
   every nonderived assignment must cite evidence. Compute basis/family counts only after this check.

### `publication`

1. In `publication.publish_index`, write immutable family shards with assignment, subject and
   derivation relationships. Bind taxonomy, topology, input manifest and content fingerprints;
   verify the combined manifest.
2. In `publication.publish_tag_cloud`, roll up distinct subjects/components and strongest
   assignment basis, not raw hit count. Retain the vocabulary's namespace rollup gaps.
3. In `publication.publish_handoff`, join standing and collector/rollup gaps, gap tags, counts,
   ownership policy and artifact references. Publish routing facts, never security findings.

## Dataflow

```mermaid
flowchart LR
  job["job_security_tagging"] --> tax["taxonomy.load_taxonomy"]
  tax --> scope["scope.resolve_inputs"]
  source["job_target_catalog / source_files"] --> scope
  graph["job_code_graph_index / code_graph_facts"] --> scope
  scope --> src["collection.source_facts"]
  scope --> obs["collection.observation_facts"]
  scope --> cov["collection.coverage_gaps"]
  src --> col["collation.collate_facets"]
  col --> mpass["collation.model_pass"]
  col --> cross["crosswalk.apply_crosswalk"]
  mpass --> valid["integrity.validate_assignments"]
  obs --> cross
  cov --> cross
  cross --> valid
  valid --> idx["publication.publish_index"]
  valid --> cloud["publication.publish_tag_cloud"]
  idx --> pub["publication.publish_handoff"]
  cloud --> pub
  pub --> tags["tag_assignments"]
  pub --> docs["tagging_documents"]
  src -. "ineligible / unlocated / bounded" .-> gaps["gaps"]
  gaps --> pub
  valid -. "basis or derivation invalid" .-> reject["reject publication"]
```

Tag lookup follows [accepted retrieval](../architecture/python-and-retrieval.md#query-boundary);
the [typed input contract](../architecture/job-input-contracts.md#admission-and-read-receipts)
does not grant authority merely because tags share a combined manifest.

## Gaps

Source constructors emit legacy strings and gap tags, not bespoke canonical codes or retryability
classifications. Interpret their canonical projection through
[interchange](../architecture/job-interchange.md#the-control-layer-beneath-the-envelope).

| Source reason family | Scope and cost |
| --- | --- |
| Component, source-file and observation bound messages | Named shard population was capped. |
| Disabled Swift and `language has no lang tag mapping` | Language facts are unsupported or policy-excluded. |
| `graph-capability:missing_graph`, `producer_coverage`, `producer_fact_gap`, `entity_bound`, `missing_site_facts` | Graph capability coverage is incomplete or absent. |
| `graph-capability:conflicting_fact`, `malformed_fact`, `ineligible_fact`, `unsupported_language`, `unmapped_class` | Named fact cannot supply an invoked tag. |
| `graph-capability:source_unresolved`, `source_span_mismatch`, `component_scope_disagreement`, `component_ownership` | Exact source/ownership association failed or is ambiguous/unowned. |
| Required index unavailable; upstream coverage gap tags | Missing evidence family or inherited producer coverage, not negative security evidence. |
| Standing invoked-capability, deferred MITRE crosswalk and unimplemented crosswalk-scope statements | Only eligible mapped graph classes are covered; `taint_path`, `iac_resource`, `k8s_object` and `container_stage` scopes are not implemented. |
| `gap:catalog-fixture` and `<namespace>: <rollup_gap>` | Inspect fixture assignments and namespace rollup limitations; these views are not complete external taxonomy coverage. |

Invalid taxonomy hashes, assignment basis/derivation, accepted-manifest changes and assignment
overflow are failures, not advisory gaps.

## Acceptance

1. **A. Inputs:** Compare claim/manifest pins, vocabulary/rules/crosswalk hashes and component
   ownership/topology identity. Record the eligible input populations and collector bounds.
2. **B. Independent comparison:** Independently enumerate accepted graph entry/sink facts,
   source-file rows and observation rule matches. Trace sampled assignments to original
   evidence and exact spans; compare deduplicated assignment IDs, basis/family totals and every
   derived input. Verify the tag cloud does not imply findings.
3. **C. Gaps:** Reconcile canonical outcomes, gap-family assignments and rollup notes with source
   omissions and rejected facts. Record standing capability/crosswalk costs; stop on unexpected
   causes, even when the job completed with gaps.
4. **D. Baseline:** Save an authorized `stepwise.py accept` baseline and corpus namespace with
   taxonomy/topology hashes, assignment IDs, basis counts and gap-tag sets. Distinguish changed
   classification rules from changed target evidence.

## Resume and invalidation

Each tag-family shard fingerprint binds assignment content, target snapshot, vocabulary,
capability rules, crosswalk, component topology and accepted manifest. Changed ownership or
taxonomy invalidates the affected tagging projection; stale scope/taxonomy is rechecked within
the attempt. The [runtime key](../architecture/jobs-and-runtime.md#wave-1-resumability) also
requires exact upstream/configuration/component identities. Artifact-bearing results cannot be
transplanted as portable failed-attempt checkpoints. When `settings.collation.model_pass.enabled`
is `false` (the default), this path dispatches no model; when enabled, `collation.model_pass`
executes through the recorded inference transport after deterministic collation.

## Model usage

Deterministic capability collection, `collation.collate_facets` and crosswalk derivation dispatch
no model. Optional model usage lives solely in `collation.model_pass`
([T-5008](../architecture/collation-pass.md#6-optional-model-pass-stage-4-default-off)), which is
disabled by default (`[jobs.job_security_tagging.settings.collation.model_pass] enabled = false`
in every shipped profile). When enabled, `collation.model_pass` invokes the specialized worker
`unit_purpose` (role `unit_purpose_collator`, task `unit_purpose_collation`, runtime skill
`unit-purpose-collation`, zero MCP tools) once per first-party component up to `max_components`
through the application's recorded inference transport. Each request supplies only deterministic
facet tags with assignment IDs, first-party paths, closed `role`/`asset` vocabulary values and
bounded `path:line` excerpts (`max_excerpt_lines`). Replies must satisfy `unit-purpose-proposal/1`
and cite supplied `path:line` spans or deterministic assignment IDs; accepted claims emit
`reported` facet assignments (`producer = collation-model-pass`) and record the bounded component
purpose in `unit-purposes.json`. Local proposal rejection and standalone failure handling retain
deterministic facets with named gaps. Under active execution admission, provider failure,
cancellation and integrity/contract failure instead preserve the global stop; optional enrichment
does not authorize continued execution or publication. Retained deterministic artifacts do not
constitute a successful handoff. See the [failure policy](../architecture/collation-pass.md).
