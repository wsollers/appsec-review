---
title: "inference_security_review"
kind: "operations"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_inference_security_review"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# inference_security_review

This page contains the generated contract; the authored process and acceptance description are tracked by [T-130](../TODO.md).

<!-- generated:begin job=job_inference_security_review -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

inference_security_review

Job: `job_inference_security_review`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `adjudicate` | `adjudicate.apply_policy` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L484) |
| `attack_chains` | `attack_chains.compose_candidates` | 1 | `inference_teams` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L538) |
| `attack_chains` | `attack_chains.refute_edges` | 1 | `inference_teams` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L573) |
| `attack_chains` | `attack_chains.verify_weakest_links` | 1 | `inference_teams` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L573) |
| `completeness` | `completeness.audit` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L613) |
| `hunt_review` | `hunt_review.teams` | 1 | `inference_teams` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L419) |
| `lead_review` | `lead_review.teams` | 1 | `inference_teams` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L419) |
| `merge` | `merge.claims` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L472) |
| `packages` | `packages.assemble_hunt_packages` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L344) |
| `packages` | `packages.assemble_lead_packages` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L344) |
| `publication` | `publication.publish_claim_ledger` | 1 | `lifecycle` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L648) |
| `publication` | `publication.publish_handoff` | 1 | `lifecycle` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L671) |
| `scope` | `scope.accept_manifest` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L273) |
| `scope` | `scope.assemble_scope` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L286) |
| `scoring` | `scoring.score_claims` | 1 | `inference_score` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L503) |
| `triage` | `triage.lead_severity` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_inference_security_review/job.py#L299) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_threat_model_generation` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_threat_model_generation` | `generated_dfd` | `appsec-review/generated-dfd/1` | handoff | optional | gap |
| `job_threat_model_generation` | `generated_threat_model` | `appsec-review/generated-threat-model/1` | handoff | optional | gap |
| `job_threat_model_generation` | `generated_model_evidence` | `appsec-review/generated-model-evidence/1` | handoff | optional | gap |
| `job_threat_model_generation` | `threat_model_documents` | `appsec-review/threat-model-generation/1` | handoff | optional | gap |
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
| `job_review_data_indexing` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
| `job_review_data_indexing` | `accepted_input_summary` | `appsec-review/review-data-indexing-inputs/2` | handoff | optional | gap |
| `job_review_data_indexing` | `cross_domain_links` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_review_data_indexing` | `precomputed_products` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_review_data_indexing` | `derived_checkpoints` | `appsec-review/derived-shard/1` | handoff | optional | gap |
| `job_review_data_indexing` | `fts_image_validation` | `appsec-review/sqlite-fts-validation/1` | handoff | optional | gap |
| `job_review_data_indexing` | `dataset_audit_report` | `appsec-review/dataset-inventory/1` | handoff | optional | gap |
| `job_review_data_indexing` | `coverage_matrices` | `appsec-review/coverage-matrices/2` | handoff | optional | gap |
| `job_review_data_indexing` | `dataset_inventory` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_review_package_assembly` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
| `job_review_package_assembly` | `review_packages` | `appsec-review/review-package-manifest/2` | handoff | optional | gap |
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
| `job_test_coverage` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_test_coverage` | `test_coverage` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_test_coverage` | `test_coverage_handoff` | `appsec-review/test-coverage-handoff/1` | handoff | optional | gap |
| `job_tree_sitter_ast` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_tree_sitter_ast` | `tree_sitter_ast` | `appsec-review/tree-sitter-normalizer/1` | handoff | optional | gap |
| `job_tree_sitter_ast` | `tree_sitter_coverage` | `appsec-review/tree-sitter-ast/1` | handoff | optional | gap |
| `job_tree_sitter_ast` | `tree_sitter_node_shards` | `appsec-review/tree-sitter-ast/1` | handoff | optional | gap |
| `job_tree_sitter_ast` | `generated_source_backing` | `appsec-review/generated-source-backing/1` | handoff | optional | gap |
| `job_tree_sitter_ast` | `tree_sitter_tool_io` | `appsec-review/container-execution/1` | handoff | optional | gap |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `accepted_scope` | `scope` | `appsec-review/inference-review-accepted-scope/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `attack_chains` | `attack_chains` | `appsec-review/attack-chain-manifest/1` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `claim_ledger` | `publication` | `appsec-review/ledger-event/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `lead_triage` | `triage` | `application/json` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `review_cells` | `lead_review` | `appsec-review/cell-attempt-receipt/1` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `review_packages` | `packages` | `appsec-review/review-package/6` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `scores_and_findings` | `publication` | `appsec-review/finding-package/2` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

These are job-level declarations; exact per-task selection is not declared ([T-147](../TODO.md)).

```json
{
  "budgets": {
    "budget_team_packages": 200,
    "max_input_tokens": 60000000,
    "max_model_turns": 12000,
    "max_output_tokens": 6000000,
    "max_retrieval_queries": 40000,
    "timeout_seconds": 28800
  },
  "models": {
    "default": {
      "max_input_tokens": 32000,
      "max_output_tokens": 8000,
      "max_queries": 40,
      "max_turns": 12,
      "model": "claude-haiku-5-5",
      "provider": "claude-cli",
      "reasoning": "high",
      "timeout_seconds": 600
    },
    "triage": {
      "max_input_tokens": 64000,
      "max_output_tokens": 16000,
      "max_queries": 0,
      "max_turns": 1,
      "model": "claude-haiku-5-5",
      "provider": "claude-cli",
      "reasoning": "medium",
      "timeout_seconds": 600
    }
  },
  "retry": {
    "backoff_seconds": [
      2,
      10
    ],
    "max_attempts": 2,
    "retry_on_invalid_output": true,
    "retry_on_provider_error": true,
    "retry_on_timeout": true
  },
  "roles": {
    "adjudication_judge": {
      "enabled": true,
      "judges_per_claim": 1,
      "max_cited_row_chars": 400,
      "max_cited_rows_per_side": 12,
      "max_why_chars": 600,
      "model_profile": "default",
      "require_distinct_from_roles": [
        "hypothesis_hunter",
        "red_team_analyst",
        "blue_team_refuter"
      ],
      "when": "all",
      "workers": 4
    },
    "independent_verifier": {
      "model_profile": "default",
      "require_distinct_from_roles": [
        "hypothesis_hunter",
        "red_team_analyst",
        "blue_team_refuter"
      ],
      "workers": 4
    }
  },
  "teams": {
    "blue_per_team": 2,
    "red_per_team": 3,
    "review_teams": 3,
    "verifier_per_team": 1
  },
  "triage": {
    "batch_size": 20,
    "enabled": true,
    "max_excerpt_lines": 24,
    "max_leads": 200,
    "max_reason_chars": 200,
    "model_profile": "triage",
    "rules": [
      {
        "basis": "rule_semantics",
        "reason": "Hard-coded credential in the repository (CWE-798): everyone who can read the source holds it; real exposure depends on its scope.",
        "rule": "*",
        "scanner": "gitleaks",
        "severity": "high"
      },
      {
        "basis": "rule_semantics",
        "cwe": "CWE-798",
        "reason": "Use of hard-coded credentials (CWE-798): the secret travels with the source.",
        "scanner": "*",
        "severity": "high"
      },
      {
        "basis": "rule_semantics",
        "reason": "OS command built from untrusted input (CWE-78): the catalog impact is execution of unauthorized commands.",
        "rule": "cpp/command-line-injection",
        "scanner": "codeql",
        "severity": "high"
      },
      {
        "basis": "rule_semantics",
        "reason": "Untrusted format string (CWE-134) can read or write memory.",
        "rule": "cpp/tainted-format-string",
        "scanner": "codeql",
        "severity": "high"
      },
      {
        "basis": "rule_semantics",
        "reason": "Untrusted input selects the process or library to run (CWE-114).",
        "rule": "cpp/uncontrolled-process-operation",
        "scanner": "codeql",
        "severity": "high"
      },
      {
        "basis": "rule_semantics",
        "reason": "Untrusted allocation size (CWE-789) leads to resource exhaustion or size arithmetic faults.",
        "rule": "cpp/uncontrolled-allocation-size",
        "scanner": "codeql",
        "severity": "medium"
      },
      {
        "basis": "rule_semantics",
        "reason": "Non-constant format string (CWE-134): exploitable only when the string is attacker influenced.",
        "rule": "cpp/non-constant-format",
        "scanner": "codeql",
        "severity": "medium"
      },
      {
        "basis": "rule_semantics",
        "reason": "Null pointer dereference (CWE-476): a crash on the analysed path, rarely more.",
        "rule": "core.NullDereference",
        "scanner": "clang-static-analysis",
        "severity": "medium"
      },
      {
        "basis": "rule_semantics",
        "reason": "Null pointer dereference (CWE-476): a crash on the analysed path, rarely more.",
        "rule": "clang-analyzer-core.NullDereference",
        "scanner": "clang-static-analysis",
        "severity": "medium"
      },
      {
        "basis": "rule_semantics",
        "reason": "Use after free or double free on the analysed path (CWE-416, CWE-415): memory corruption.",
        "rule": "cplusplus.NewDelete",
        "scanner": "clang-static-analysis",
        "severity": "high"
      },
      {
        "basis": "rule_semantics",
        "reason": "Use after free or double free on the analysed path (CWE-416, CWE-415): memory corruption.",
        "rule": "clang-analyzer-cplusplus.NewDelete",
        "scanner": "clang-static-analysis",
        "severity": "high"
      },
      {
        "basis": "rule_semantics",
        "reason": "Call to the command processor (CERT ENV33-C): command injection when the string is influenced.",
        "rule": "cert-env33-c",
        "scanner": "clang-static-analysis",
        "severity": "medium"
      },
      {
        "basis": "rule_semantics",
        "reason": "Non-literal format string diagnostic (CWE-134): exploitable only with attacker influence.",
        "rule": "clang-diagnostic-format-security",
        "scanner": "clang-static-analysis",
        "severity": "medium"
      },
      {
        "basis": "rule_semantics",
        "reason": "Unchecked return value of a library call (CERT ERR33-C): a robustness gap.",
        "rule": "cert-err33-c",
        "scanner": "clang-static-analysis",
        "severity": "low"
      },
      {
        "basis": "rule_semantics",
        "reason": "Unchecked string-to-number conversion (CERT ERR34-C): a robustness gap.",
        "rule": "cert-err34-c",
        "scanner": "clang-static-analysis",
        "severity": "low"
      },
      {
        "basis": "rule_semantics",
        "reason": "Thread-unsafe library call: a reliability gap unless threads are attacker driven.",
        "rule": "concurrency-mt-unsafe",
        "scanner": "clang-static-analysis",
        "severity": "low"
      },
      {
        "basis": "rule_semantics",
        "reason": "Readability warning on a signature; no security consequence.",
        "rule": "bugprone-easily-swappable-parameters",
        "scanner": "clang-static-analysis",
        "severity": "info"
      },
      {
        "basis": "rule_semantics",
        "reason": "No non-root user is created (CWE-250): a container escape or file write runs as root.",
        "rule": "CKV_DOCKER_3",
        "scanner": "checkov",
        "severity": "medium"
      },
      {
        "basis": "rule_semantics",
        "reason": "The last USER is root (CWE-250): the container process keeps full privileges.",
        "rule": "CKV_DOCKER_8",
        "scanner": "checkov",
        "severity": "medium"
      },
      {
        "basis": "rule_semantics",
        "reason": "Port 22 is exposed: a remote login surface inside the container.",
        "rule": "CKV_DOCKER_1",
        "scanner": "checkov",
        "severity": "medium"
      },
      {
        "basis": "rule_semantics",
        "reason": "No HEALTHCHECK: an availability and operations gap.",
        "rule": "CKV_DOCKER_2",
        "scanner": "checkov",
        "severity": "low"
      },
      {
        "basis": "rule_semantics",
        "reason": "ADD instead of COPY can fetch remote content or unpack archives unexpectedly.",
        "rule": "CKV_DOCKER_4",
        "scanner": "checkov",
        "severity": "low"
      },
      {
        "basis": "rule_semantics",
        "reason": "The base image is not pinned to a version tag: builds are not reproducible.",
        "rule": "CKV_DOCKER_7",
        "scanner": "checkov",
        "severity": "low"
      },
      {
        "basis": "rule_semantics",
        "reason": "The last USER is root (CWE-250): the container process keeps full privileges.",
        "rule": "DL3002",
        "scanner": "hadolint",
        "severity": "medium"
      },
      {
        "basis": "rule_semantics",
        "reason": "sudo inside a container image hides privilege use and widens what a compromise can do.",
        "rule": "DL3004",
        "scanner": "hadolint",
        "severity": "medium"
      },
      {
        "basis": "rule_semantics",
        "reason": "The image is not tagged with an explicit version: builds are not reproducible.",
        "rule": "DL3006",
        "scanner": "hadolint",
        "severity": "low"
      },
      {
        "basis": "rule_semantics",
        "reason": "The image uses the latest tag: builds are not reproducible.",
        "rule": "DL3007",
        "scanner": "hadolint",
        "severity": "low"
      },
      {
        "basis": "rule_semantics",
        "reason": "ADD instead of COPY can fetch remote content or unpack archives unexpectedly.",
        "rule": "DL3020",
        "scanner": "hadolint",
        "severity": "low"
      },
      {
        "basis": "rule_semantics",
        "reason": "A pipe without pipefail can hide a failed step in the image build.",
        "rule": "DL4006",
        "scanner": "hadolint",
        "severity": "low"
      },
      {
        "basis": "rule_semantics",
        "reason": "Style: consecutive RUN instructions could be merged.",
        "rule": "DL3059",
        "scanner": "hadolint",
        "severity": "info"
      },
      {
        "basis": "rule_semantics",
        "reason": "Unquoted expansion splits and globs (CWE-78 when the value is influenced).",
        "rule": "SC2086",
        "scanner": "shellcheck",
        "severity": "medium"
      },
      {
        "basis": "rule_semantics",
        "reason": "Unquoted command substitution splits and globs (CWE-78 when the value is influenced).",
        "rule": "SC2046",
        "scanner": "shellcheck",
        "severity": "medium"
      },
      {
        "basis": "rule_semantics",
        "reason": "cd without a failure branch continues in the wrong directory.",
        "rule": "SC2164",
        "scanner": "shellcheck",
        "severity": "low"
      },
      {
        "basis": "rule_semantics",
        "reason": "Unused variable: no security consequence.",
        "rule": "SC2034",
        "scanner": "shellcheck",
        "severity": "info"
      },
      {
        "basis": "rule_semantics",
        "reason": "Declare and assign separately to keep the exit status: a style point.",
        "rule": "SC2155",
        "scanner": "shellcheck",
        "severity": "info"
      }
    ]
  }
}
```


### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | `tests/acceptance/test_prompt_competence.py::test_live_prompt_competence`<br>`tests/acceptance/review_behavior/test_behavioral_review.py` |
| integration | `tests/integration/test_review_consumer_acceptance.py`<br>`tests/integration/review_behavior/test_package_join.py` |
| live | None declared |
| unit | `tests/unit/review_behavior/test_contract_and_view.py`<br>`tests/unit/review_behavior/test_handler_wiring.py`<br>`tests/unit/review_behavior/test_coverage.py`<br>`tests/unit/review_behavior/test_model_context.py`<br>`tests/unit/review_behavior/test_operations.py`<br>`tests/unit/review_behavior/test_publication_bindings.py`<br>`tests/unit/observability_findings/test_actionability_evidence.py`<br>`tests/review/test_discovery_competence.py`<br>`tests/review/test_prompt_competence.py`<br>`tests/review/test_team_handler.py::test_lane_allocation_is_fair_share_work_conserving_and_timing_free`<br>`tests/review/test_team_handler.py::test_all_packages_allocation_has_no_lane_quota`<br>`tests/review/test_team_handler.py::test_closed_schema_validator_agrees_with_jsonschema`<br>`tests/test_inference_fixture_contracts.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_document_issue_analysis`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_inference_security_review"]
  producer0["job_threat_model_generation"]
  input0["handoff"]
  input_schema0["appsec-review/job-handoff/2"]
  producer0 --> input0 --> job
  input0 -. schema .-> input_schema0
  producer1["job_threat_model_generation"]
  input1["generated_dfd"]
  input_schema1["appsec-review/generated-dfd/1"]
  producer1 --> input1 --> job
  input1 -. schema .-> input_schema1
  producer2["job_threat_model_generation"]
  input2["generated_threat_model"]
  input_schema2["appsec-review/generated-threat-model/1"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_threat_model_generation"]
  input3["generated_model_evidence"]
  input_schema3["appsec-review/generated-model-evidence/1"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  producer4["job_threat_model_generation"]
  input4["threat_model_documents"]
  input_schema4["appsec-review/threat-model-generation/1"]
  producer4 --> input4 --> job
  input4 -. schema .-> input_schema4
  producer5["job_artifact_indexing"]
  input5["handoff"]
  input_schema5["appsec-review/job-handoff/2"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_artifact_indexing"]
  input6["artifact_catalog"]
  input_schema6["appsec-review/retrieval-index/2"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_artifact_indexing"]
  input7["archive_members"]
  input_schema7["appsec-review/retrieval-index/2"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_artifact_indexing"]
  input8["artifact_relationships"]
  input_schema8["appsec-review/retrieval-index/2"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_artifact_indexing"]
  input9["artifact_index_summary"]
  input_schema9["appsec-review/artifact-indexing/1"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_artifact_security_analysis"]
  input10["handoff"]
  input_schema10["appsec-review/job-handoff/2"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_artifact_security_analysis"]
  input11["artifact_security_observations"]
  input_schema11["appsec-review/retrieval-index/2"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_artifact_security_analysis"]
  input12["artifact_security_results"]
  input_schema12["appsec-review/artifact-security-observation/1"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_artifact_security_analysis"]
  input13["artifact_scanner_io"]
  input_schema13["appsec-review/container-execution/1"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_binary_evidence_indexing"]
  input14["handoff"]
  input_schema14["appsec-review/job-handoff/2"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_binary_evidence_indexing"]
  input15["binary_functions"]
  input_schema15["appsec-review/retrieval-index/2"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_binary_evidence_indexing"]
  input16["binary_pseudo_c"]
  input_schema16["appsec-review/binary-source-backing/1"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  producer17["job_binary_evidence_indexing"]
  input17["binary_evidence_summary"]
  input_schema17["appsec-review/binary-evidence-index/1"]
  producer17 --> input17 --> job
  input17 -. schema .-> input_schema17
  producer18["job_change_context_analysis"]
  input18["handoff"]
  input_schema18["appsec-review/job-handoff/2"]
  producer18 --> input18 --> job
  input18 -. schema .-> input_schema18
  producer19["job_change_context_analysis"]
  input19["change_context"]
  input_schema19["appsec-review/retrieval-index/2"]
  producer19 --> input19 --> job
  input19 -. schema .-> input_schema19
  producer20["job_change_context_analysis"]
  input20["change_context_documents"]
  input_schema20["appsec-review/change-context-analysis/1"]
  producer20 --> input20 --> job
  input20 -. schema .-> input_schema20
  producer21["job_change_context_analysis"]
  input21["operator_exports"]
  input_schema21["application/json"]
  producer21 --> input21 --> job
  input21 -. schema .-> input_schema21
  producer22["job_change_context_analysis"]
  input22["change_context_tool_io"]
  input_schema22["appsec-review/container-execution/1"]
  producer22 --> input22 --> job
  input22 -. schema .-> input_schema22
  producer23["job_ci_configuration_analysis"]
  input23["handoff"]
  input_schema23["appsec-review/job-handoff/2"]
  producer23 --> input23 --> job
  input23 -. schema .-> input_schema23
  producer24["job_ci_configuration_analysis"]
  input24["ci_observations"]
  input_schema24["appsec-review/retrieval-index/2"]
  producer24 --> input24 --> job
  input24 -. schema .-> input_schema24
  producer25["job_ci_configuration_analysis"]
  input25["ci_findings"]
  input_schema25["appsec-review/retrieval-index/2"]
  producer25 --> input25 --> job
  input25 -. schema .-> input_schema25
  producer26["job_ci_configuration_analysis"]
  input26["ci_documents"]
  input_schema26["appsec-review/ci-configuration-analysis-handoff/1"]
  producer26 --> input26 --> job
  input26 -. schema .-> input_schema26
  producer27["job_ci_configuration_analysis"]
  input27["ci_tool_io"]
  input_schema27["appsec-review/container-execution/1"]
  producer27 --> input27 --> job
  input27 -. schema .-> input_schema27
  producer28["job_clang_static_analysis"]
  input28["handoff"]
  input_schema28["appsec-review/job-handoff/2"]
  producer28 --> input28 --> job
  input28 -. schema .-> input_schema28
  producer29["job_clang_static_analysis"]
  input29["clang_static_observations"]
  input_schema29["appsec-review/retrieval-index/2"]
  producer29 --> input29 --> job
  input29 -. schema .-> input_schema29
  producer30["job_clang_static_analysis"]
  input30["clang_static_scope_coverage"]
  input_schema30["appsec-review/cpp-index-coverage/1"]
  producer30 --> input30 --> job
  input30 -. schema .-> input_schema30
  producer31["job_clang_static_analysis"]
  input31["clang_static_summary"]
  input_schema31["appsec-review/clang-static-analysis-handoff/1"]
  producer31 --> input31 --> job
  input31 -. schema .-> input_schema31
  producer32["job_clang_static_analysis"]
  input32["clang_static_raw"]
  input_schema32["application/json"]
  producer32 --> input32 --> job
  input32 -. schema .-> input_schema32
  producer33["job_code_graph_index"]
  input33["handoff"]
  input_schema33["appsec-review/job-handoff/2"]
  producer33 --> input33 --> job
  input33 -. schema .-> input_schema33
  producer34["job_code_graph_index"]
  input34["code_graph_facts"]
  input_schema34["appsec-review/graph-fact/1"]
  producer34 --> input34 --> job
  input34 -. schema .-> input_schema34
  producer35["job_code_graph_index"]
  input35["code_graph_stages"]
  input_schema35["appsec-review/code-graph-stage/1"]
  producer35 --> input35 --> job
  input35 -. schema .-> input_schema35
  producer36["job_code_graph_index"]
  input36["code_graph_checkpoints"]
  input_schema36["appsec-review/code-graph-checkpoint/1"]
  producer36 --> input36 --> job
  input36 -. schema .-> input_schema36
  producer37["job_code_graph_index"]
  input37["code_graph_summary"]
  input_schema37["appsec-review/code-graph-index/1"]
  producer37 --> input37 --> job
  input37 -. schema .-> input_schema37
  producer38["job_codeql_analysis"]
  input38["handoff"]
  input_schema38["appsec-review/job-handoff/2"]
  producer38 --> input38 --> job
  input38 -. schema .-> input_schema38
  producer39["job_codeql_analysis"]
  input39["codeql_predecessor_import"]
  input_schema39["appsec-review/codeql-predecessor-import/1"]
  producer39 --> input39 --> job
  input39 -. schema .-> input_schema39
  producer40["job_codeql_analysis"]
  input40["codeql_graph_export"]
  input_schema40["appsec-review/codeql-graph-export/1"]
  producer40 --> input40 --> job
  input40 -. schema .-> input_schema40
  producer41["job_codeql_analysis"]
  input41["codeql_observations"]
  input_schema41["appsec-review/codeql-sarif-normalizer/3"]
  producer41 --> input41 --> job
  input41 -. schema .-> input_schema41
  producer42["job_codeql_analysis"]
  input42["codeql_plan_and_summary"]
  input_schema42["appsec-review/codeql-analysis-handoff/1"]
  producer42 --> input42 --> job
  input42 -. schema .-> input_schema42
  producer43["job_codeql_analysis"]
  input43["codeql_scope_material"]
  input_schema43["application/octet-stream"]
  producer43 --> input43 --> job
  input43 -. schema .-> input_schema43
  producer44["job_cpg_analysis"]
  input44["handoff"]
  input_schema44["appsec-review/job-handoff/2"]
  producer44 --> input44 --> job
  input44 -. schema .-> input_schema44
  producer45["job_cpg_analysis"]
  input45["cpg_graph_coverage"]
  input_schema45["appsec-review/retrieval-index/2"]
  producer45 --> input45 --> job
  input45 -. schema .-> input_schema45
  producer46["job_cpg_analysis"]
  input46["cpg_scope_coverage"]
  input_schema46["appsec-review/cpp-index-coverage/1"]
  producer46 --> input46 --> job
  input46 -. schema .-> input_schema46
  producer47["job_cpg_analysis"]
  input47["cpg_summary"]
  input_schema47["appsec-review/cpg-analysis/1"]
  producer47 --> input47 --> job
  input47 -. schema .-> input_schema47
  producer48["job_cpg_analysis"]
  input48["cpg_binary"]
  input_schema48["application/octet-stream"]
  producer48 --> input48 --> job
  input48 -. schema .-> input_schema48
  producer49["job_cpp_compiled_analysis"]
  input49["handoff"]
  input_schema49["appsec-review/job-handoff/2"]
  producer49 --> input49 --> job
  input49 -. schema .-> input_schema49
  producer50["job_cpp_compiled_analysis"]
  input50["cpp_build_graph"]
  input_schema50["appsec-review/retrieval-index/2"]
  producer50 --> input50 --> job
  input50 -. schema .-> input_schema50
  producer51["job_cpp_compiled_analysis"]
  input51["clang_ast"]
  input_schema51["appsec-review/retrieval-index/2"]
  producer51 --> input51 --> job
  input51 -. schema .-> input_schema51
  producer52["job_cpp_compiled_analysis"]
  input52["llvm_ir"]
  input_schema52["appsec-review/retrieval-index/2"]
  producer52 --> input52 --> job
  input52 -. schema .-> input_schema52
  producer53["job_cpp_compiled_analysis"]
  input53["infer_observations"]
  input_schema53["appsec-review/retrieval-index/2"]
  producer53 --> input53 --> job
  input53 -. schema .-> input_schema53
  producer54["job_cpp_compiled_analysis"]
  input54["binary_symbols"]
  input_schema54["appsec-review/retrieval-index/2"]
  producer54 --> input54 --> job
  input54 -. schema .-> input_schema54
  producer55["job_cpp_compiled_analysis"]
  input55["cpp_blocked_branches"]
  input_schema55["appsec-review/retrieval-index/2"]
  producer55 --> input55 --> job
  input55 -. schema .-> input_schema55
  producer56["job_cpp_compiled_analysis"]
  input56["cpp_plan_and_summary"]
  input_schema56["appsec-review/cpp-compiled-analysis/2"]
  producer56 --> input56 --> job
  input56 -. schema .-> input_schema56
  producer57["job_cpp_compiled_analysis"]
  input57["cpp_case_material"]
  input_schema57["application/octet-stream"]
  producer57 --> input57 --> job
  input57 -. schema .-> input_schema57
  producer58["job_cpp_symbol_index"]
  input58["handoff"]
  input_schema58["appsec-review/job-handoff/2"]
  producer58 --> input58 --> job
  input58 -. schema .-> input_schema58
  producer59["job_cpp_symbol_index"]
  input59["clangd_symbols"]
  input_schema59["appsec-review/retrieval-index/2"]
  producer59 --> input59 --> job
  input59 -. schema .-> input_schema59
  producer60["job_cpp_symbol_index"]
  input60["clangd_coverage"]
  input_schema60["appsec-review/cpp-index-coverage/1"]
  producer60 --> input60 --> job
  input60 -. schema .-> input_schema60
  producer61["job_cpp_symbol_index"]
  input61["clangd_summary"]
  input_schema61["appsec-review/cpp-symbol-index/1"]
  producer61 --> input61 --> job
  input61 -. schema .-> input_schema61
  producer62["job_cpp_symbol_index"]
  input62["clangd_tool_io"]
  input_schema62["appsec-review/container-execution/1"]
  producer62 --> input62 --> job
  input62 -. schema .-> input_schema62
  producer63["job_debug_symbol_indexing"]
  input63["handoff"]
  input_schema63["appsec-review/job-handoff/2"]
  producer63 --> input63 --> job
  input63 -. schema .-> input_schema63
  producer64["job_debug_symbol_indexing"]
  input64["normalized_symbols"]
  input_schema64["appsec-review/retrieval-index/2"]
  producer64 --> input64 --> job
  input64 -. schema .-> input_schema64
  producer65["job_debug_symbol_indexing"]
  input65["symbol_coverage"]
  input_schema65["appsec-review/debug-symbol-coverage/1"]
  producer65 --> input65 --> job
  input65 -. schema .-> input_schema65
  producer66["job_debug_symbol_indexing"]
  input66["target_decision"]
  input_schema66["appsec-review/debug-symbol-decision/2"]
  producer66 --> input66 --> job
  input66 -. schema .-> input_schema66
  producer67["job_debug_symbol_indexing"]
  input67["raw_artifact_refs"]
  input_schema67["appsec-review/debug-symbol-inputs/1"]
  producer67 --> input67 --> job
  input67 -. schema .-> input_schema67
  producer68["job_debug_symbol_indexing"]
  input68["reader_executions"]
  input_schema68["appsec-review/container-execution/1"]
  producer68 --> input68 --> job
  input68 -. schema .-> input_schema68
  producer69["job_debug_symbol_indexing"]
  input69["debug_symbol_summary"]
  input_schema69["appsec-review/debug-symbol-indexing/1"]
  producer69 --> input69 --> job
  input69 -. schema .-> input_schema69
  producer70["job_dependency_intelligence"]
  input70["handoff"]
  input_schema70["appsec-review/job-handoff/2"]
  producer70 --> input70 --> job
  input70 -. schema .-> input_schema70
  producer71["job_dependency_intelligence"]
  input71["native_discovery"]
  input_schema71["appsec-review/native-discovery/1"]
  producer71 --> input71 --> job
  input71 -. schema .-> input_schema71
  producer72["job_dependency_intelligence"]
  input72["native_component_curation"]
  input_schema72["appsec-review/native-component-curation/1"]
  producer72 --> input72 --> job
  input72 -. schema .-> input_schema72
  producer73["job_dependency_intelligence"]
  input73["native_metadata_investigation"]
  input_schema73["appsec-review/native-metadata-investigation/1"]
  producer73 --> input73 --> job
  input73 -. schema .-> input_schema73
  producer74["job_dependency_intelligence"]
  input74["native_inference_metrics"]
  input_schema74["appsec-review/native-inference-metrics/1"]
  producer74 --> input74 --> job
  input74 -. schema .-> input_schema74
  producer75["job_dependency_intelligence"]
  input75["native_spdx"]
  input_schema75["SPDX-2.3"]
  producer75 --> input75 --> job
  input75 -. schema .-> input_schema75
  producer76["job_dependency_intelligence"]
  input76["native_sbom_provenance"]
  input_schema76["appsec-review/native-sbom-provenance/1"]
  producer76 --> input76 --> job
  input76 -. schema .-> input_schema76
  producer77["job_dependency_intelligence"]
  input77["native_sbom_metrics"]
  input_schema77["appsec-review/native-sbom-metrics/1"]
  producer77 --> input77 --> job
  input77 -. schema .-> input_schema77
  producer78["job_dependency_intelligence"]
  input78["dependency_context"]
  input_schema78["appsec-review/retrieval-index/2"]
  producer78 --> input78 --> job
  input78 -. schema .-> input_schema78
  producer79["job_dependency_intelligence"]
  input79["scorecard_responses"]
  input_schema79["application/json"]
  producer79 --> input79 --> job
  input79 -. schema .-> input_schema79
  producer80["job_dependency_intelligence"]
  input80["dependency_intelligence_handoff"]
  input_schema80["appsec-review/dependency-intelligence-handoff/1"]
  producer80 --> input80 --> job
  input80 -. schema .-> input_schema80
  producer81["job_evidence_collection"]
  input81["handoff"]
  input_schema81["appsec-review/job-handoff/2"]
  producer81 --> input81 --> job
  input81 -. schema .-> input_schema81
  producer82["job_evidence_collection"]
  input82["static_tool_observations"]
  input_schema82["appsec-review/retrieval-index/2"]
  producer82 --> input82 --> job
  input82 -. schema .-> input_schema82
  producer83["job_evidence_collection"]
  input83["static_tool_evidence"]
  input_schema83["appsec-review/static-tool-evidence/2"]
  producer83 --> input83 --> job
  input83 -. schema .-> input_schema83
  producer84["job_evidence_collection"]
  input84["static_tool_io"]
  input_schema84["appsec-review/container-execution/1"]
  producer84 --> input84 --> job
  input84 -. schema .-> input_schema84
  producer85["job_language_build"]
  input85["handoff"]
  input_schema85["appsec-review/job-handoff/2"]
  producer85 --> input85 --> job
  input85 -. schema .-> input_schema85
  producer86["job_language_build"]
  input86["topology_refinement_inputs"]
  input_schema86["appsec-review/build-topology-refinement/1"]
  producer86 --> input86 --> job
  input86 -. schema .-> input_schema86
  producer87["job_language_build"]
  input87["build_actions"]
  input_schema87["appsec-review/retrieval-index/2"]
  producer87 --> input87 --> job
  input87 -. schema .-> input_schema87
  producer88["job_language_build"]
  input88["jvm_build_actions"]
  input_schema88["appsec-review/retrieval-index/2"]
  producer88 --> input88 --> job
  input88 -. schema .-> input_schema88
  producer89["job_language_build"]
  input89["language_build_receipts"]
  input_schema89["appsec-review/language-build-handoff/2"]
  producer89 --> input89 --> job
  input89 -. schema .-> input_schema89
  producer90["job_language_build"]
  input90["build_workspaces"]
  input_schema90["application/octet-stream"]
  producer90 --> input90 --> job
  input90 -. schema .-> input_schema90
  producer91["job_post_build_security_assessment"]
  input91["handoff"]
  input_schema91["appsec-review/job-handoff/2"]
  producer91 --> input91 --> job
  input91 -. schema .-> input_schema91
  producer92["job_post_build_security_assessment"]
  input92["build_security"]
  input_schema92["appsec-review/retrieval-index/2"]
  producer92 --> input92 --> job
  input92 -. schema .-> input_schema92
  producer93["job_post_build_security_assessment"]
  input93["build_security_documents"]
  input_schema93["appsec-review/post-build-security-assessment/1"]
  producer93 --> input93 --> job
  input93 -. schema .-> input_schema93
  producer94["job_profile_data"]
  input94["handoff"]
  input_schema94["appsec-review/job-handoff/2"]
  producer94 --> input94 --> job
  input94 -. schema .-> input_schema94
  producer95["job_profile_data"]
  input95["profile_data"]
  input_schema95["appsec-review/retrieval-index/2"]
  producer95 --> input95 --> job
  input95 -. schema .-> input_schema95
  producer96["job_profile_data"]
  input96["profile_data_handoff"]
  input_schema96["appsec-review/profile-data-handoff/1"]
  producer96 --> input96 --> job
  input96 -. schema .-> input_schema96
  producer97["job_review_data_indexing"]
  input97["handoff"]
  input_schema97["appsec-review/job-handoff/2"]
  producer97 --> input97 --> job
  input97 -. schema .-> input_schema97
  producer98["job_review_data_indexing"]
  input98["accepted_input_summary"]
  input_schema98["appsec-review/review-data-indexing-inputs/2"]
  producer98 --> input98 --> job
  input98 -. schema .-> input_schema98
  producer99["job_review_data_indexing"]
  input99["cross_domain_links"]
  input_schema99["appsec-review/retrieval-index/2"]
  producer99 --> input99 --> job
  input99 -. schema .-> input_schema99
  producer100["job_review_data_indexing"]
  input100["precomputed_products"]
  input_schema100["appsec-review/retrieval-index/2"]
  producer100 --> input100 --> job
  input100 -. schema .-> input_schema100
  producer101["job_review_data_indexing"]
  input101["derived_checkpoints"]
  input_schema101["appsec-review/derived-shard/1"]
  producer101 --> input101 --> job
  input101 -. schema .-> input_schema101
  producer102["job_review_data_indexing"]
  input102["fts_image_validation"]
  input_schema102["appsec-review/sqlite-fts-validation/1"]
  producer102 --> input102 --> job
  input102 -. schema .-> input_schema102
  producer103["job_review_data_indexing"]
  input103["dataset_audit_report"]
  input_schema103["appsec-review/dataset-inventory/1"]
  producer103 --> input103 --> job
  input103 -. schema .-> input_schema103
  producer104["job_review_data_indexing"]
  input104["coverage_matrices"]
  input_schema104["appsec-review/coverage-matrices/2"]
  producer104 --> input104 --> job
  input104 -. schema .-> input_schema104
  producer105["job_review_data_indexing"]
  input105["dataset_inventory"]
  input_schema105["appsec-review/retrieval-index/2"]
  producer105 --> input105 --> job
  input105 -. schema .-> input_schema105
  producer106["job_review_package_assembly"]
  input106["handoff"]
  input_schema106["appsec-review/job-handoff/2"]
  producer106 --> input106 --> job
  input106 -. schema .-> input_schema106
  producer107["job_review_package_assembly"]
  input107["review_packages"]
  input_schema107["appsec-review/review-package-manifest/2"]
  producer107 --> input107 --> job
  input107 -. schema .-> input_schema107
  producer108["job_review_prioritization"]
  input108["handoff"]
  input_schema108["appsec-review/job-handoff/2"]
  producer108 --> input108 --> job
  input108 -. schema .-> input_schema108
  producer109["job_review_prioritization"]
  input109["priority_items"]
  input_schema109["appsec-review/retrieval-index/2"]
  producer109 --> input109 --> job
  input109 -. schema .-> input_schema109
  producer110["job_review_prioritization"]
  input110["prioritization_documents"]
  input_schema110["appsec-review/review-prioritization/1"]
  producer110 --> input110 --> job
  input110 -. schema .-> input_schema110
  producer111["job_security_tagging"]
  input111["handoff"]
  input_schema111["appsec-review/job-handoff/2"]
  producer111 --> input111 --> job
  input111 -. schema .-> input_schema111
  producer112["job_security_tagging"]
  input112["tag_assignments"]
  input_schema112["appsec-review/tag-assignment/1"]
  producer112 --> input112 --> job
  input112 -. schema .-> input_schema112
  producer113["job_security_tagging"]
  input113["tagging_documents"]
  input_schema113["appsec-review/security-tagging-handoff/1"]
  producer113 --> input113 --> job
  input113 -. schema .-> input_schema113
  producer114["job_source_history_analysis"]
  input114["handoff"]
  input_schema114["appsec-review/job-handoff/2"]
  producer114 --> input114 --> job
  input114 -. schema .-> input_schema114
  producer115["job_source_history_analysis"]
  input115["history_signals"]
  input_schema115["appsec-review/retrieval-index/2"]
  producer115 --> input115 --> job
  input115 -. schema .-> input_schema115
  producer116["job_source_history_analysis"]
  input116["history_documents"]
  input_schema116["appsec-review/source-history-analysis/2"]
  producer116 --> input116 --> job
  input116 -. schema .-> input_schema116
  producer117["job_source_history_analysis"]
  input117["raw_git_history"]
  input_schema117["application/octet-stream"]
  producer117 --> input117 --> job
  input117 -. schema .-> input_schema117
  producer118["job_source_history_analysis"]
  input118["history_tool_io"]
  input_schema118["appsec-review/container-execution/1"]
  producer118 --> input118 --> job
  input118 -. schema .-> input_schema118
  producer119["job_svf_alias_analysis"]
  input119["handoff"]
  input_schema119["appsec-review/job-handoff/2"]
  producer119 --> input119 --> job
  input119 -. schema .-> input_schema119
  producer120["job_svf_alias_analysis"]
  input120["svf_alias_sets"]
  input_schema120["appsec-review/retrieval-index/2"]
  producer120 --> input120 --> job
  input120 -. schema .-> input_schema120
  producer121["job_svf_alias_analysis"]
  input121["svf_alias_scope_coverage"]
  input_schema121["appsec-review/cpp-index-coverage/1"]
  producer121 --> input121 --> job
  input121 -. schema .-> input_schema121
  producer122["job_svf_alias_analysis"]
  input122["svf_alias_summary"]
  input_schema122["appsec-review/svf-alias-analysis-handoff/1"]
  producer122 --> input122 --> job
  input122 -. schema .-> input_schema122
  producer123["job_svf_alias_analysis"]
  input123["svf_alias_raw"]
  input_schema123["application/json"]
  producer123 --> input123 --> job
  input123 -. schema .-> input_schema123
  producer124["job_target_analysis_plan"]
  input124["handoff"]
  input_schema124["appsec-review/job-handoff/2"]
  producer124 --> input124 --> job
  input124 -. schema .-> input_schema124
  producer125["job_target_analysis_plan"]
  input125["planning_feedback_cache"]
  input_schema125["appsec-review/target-analysis-proposal/3"]
  producer125 --> input125 --> job
  input125 -. schema .-> input_schema125
  producer126["job_target_analysis_plan"]
  input126["analysis_plan"]
  input_schema126["appsec-review/retrieval-index/2"]
  producer126 --> input126 --> job
  input126 -. schema .-> input_schema126
  producer127["job_target_analysis_plan"]
  input127["analysis_plan_documents"]
  input_schema127["appsec-review/target-analysis-plan/1"]
  producer127 --> input127 --> job
  input127 -. schema .-> input_schema127
  producer128["job_target_catalog"]
  input128["handoff"]
  input_schema128["appsec-review/job-handoff/2"]
  producer128 --> input128 --> job
  input128 -. schema .-> input_schema128
  producer129["job_target_catalog"]
  input129["target_artifact_inputs"]
  input_schema129["appsec-review/target-artifact-intake/1"]
  producer129 --> input129 --> job
  input129 -. schema .-> input_schema129
  producer130["job_target_catalog"]
  input130["source_files"]
  input_schema130["appsec-review/retrieval-index/2"]
  producer130 --> input130 --> job
  input130 -. schema .-> input_schema130
  producer131["job_target_catalog"]
  input131["declaration_symbols"]
  input_schema131["appsec-review/retrieval-index/2"]
  producer131 --> input131 --> job
  input131 -. schema .-> input_schema131
  producer132["job_target_catalog"]
  input132["components"]
  input_schema132["appsec-review/retrieval-index/2"]
  producer132 --> input132 --> job
  input132 -. schema .-> input_schema132
  producer133["job_target_catalog"]
  input133["target_documents"]
  input_schema133["appsec-review/retrieval-index/2"]
  producer133 --> input133 --> job
  input133 -. schema .-> input_schema133
  producer134["job_target_catalog"]
  input134["build_units"]
  input_schema134["appsec-review/retrieval-index/2"]
  producer134 --> input134 --> job
  input134 -. schema .-> input_schema134
  producer135["job_target_catalog"]
  input135["catalog_documents"]
  input_schema135["appsec-review/target-catalog/1"]
  producer135 --> input135 --> job
  input135 -. schema .-> input_schema135
  producer136["job_test_coverage"]
  input136["handoff"]
  input_schema136["appsec-review/job-handoff/2"]
  producer136 --> input136 --> job
  input136 -. schema .-> input_schema136
  producer137["job_test_coverage"]
  input137["test_coverage"]
  input_schema137["appsec-review/retrieval-index/2"]
  producer137 --> input137 --> job
  input137 -. schema .-> input_schema137
  producer138["job_test_coverage"]
  input138["test_coverage_handoff"]
  input_schema138["appsec-review/test-coverage-handoff/1"]
  producer138 --> input138 --> job
  input138 -. schema .-> input_schema138
  producer139["job_tree_sitter_ast"]
  input139["handoff"]
  input_schema139["appsec-review/job-handoff/2"]
  producer139 --> input139 --> job
  input139 -. schema .-> input_schema139
  producer140["job_tree_sitter_ast"]
  input140["tree_sitter_ast"]
  input_schema140["appsec-review/tree-sitter-normalizer/1"]
  producer140 --> input140 --> job
  input140 -. schema .-> input_schema140
  producer141["job_tree_sitter_ast"]
  input141["tree_sitter_coverage"]
  input_schema141["appsec-review/tree-sitter-ast/1"]
  producer141 --> input141 --> job
  input141 -. schema .-> input_schema141
  producer142["job_tree_sitter_ast"]
  input142["tree_sitter_node_shards"]
  input_schema142["appsec-review/tree-sitter-ast/1"]
  producer142 --> input142 --> job
  input142 -. schema .-> input_schema142
  producer143["job_tree_sitter_ast"]
  input143["generated_source_backing"]
  input_schema143["appsec-review/generated-source-backing/1"]
  producer143 --> input143 --> job
  input143 -. schema .-> input_schema143
  producer144["job_tree_sitter_ast"]
  input144["tree_sitter_tool_io"]
  input_schema144["appsec-review/container-execution/1"]
  producer144 --> input144 --> job
  input144 -. schema .-> input_schema144
  output0["accepted_scope"]
  output_schema0["appsec-review/inference-review-accepted-scope/1"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["attack_chains"]
  output_schema1["appsec-review/attack-chain-manifest/1"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["claim_ledger"]
  output_schema2["appsec-review/ledger-event/1"]
  job --> output2
  output2 -. schema .-> output_schema2
  output3["lead_triage"]
  output_schema3["application/json"]
  job --> output3
  output3 -. schema .-> output_schema3
  output4["review_cells"]
  output_schema4["appsec-review/cell-attempt-receipt/1"]
  job --> output4
  output4 -. schema .-> output_schema4
  output5["review_packages"]
  output_schema5["appsec-review/review-package/6"]
  job --> output5
  output5 -. schema .-> output_schema5
  output6["scores_and_findings"]
  output_schema6["appsec-review/finding-package/2"]
  job --> output6
  output6 -. schema .-> output_schema6
```

<!-- generated:end -->
