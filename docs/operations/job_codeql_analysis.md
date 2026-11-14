---
title: "codeql_analysis"
kind: "operations"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_codeql_analysis"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# codeql_analysis

This page contains the generated contract; the authored process and acceptance description are tracked by [T-130](../TODO.md).

<!-- generated:begin job=job_codeql_analysis -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

codeql_analysis

Job: `job_codeql_analysis`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_codeql_analysis/job.py#L1685) |
| `execution` | `execution.scopes` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_codeql_analysis/job.py#L1597) |
| `plan` | `plan.inventory` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_codeql_analysis/job.py#L1509) |

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
| `job_change_context_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_change_context_analysis` | `change_context` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_change_context_analysis` | `change_context_documents` | `appsec-review/change-context-analysis/1` | handoff | optional | gap |
| `job_change_context_analysis` | `operator_exports` | `application/json` | handoff | optional | gap |
| `job_change_context_analysis` | `change_context_tool_io` | `appsec-review/container-execution/1` | handoff | optional | gap |
| `job_clang_static_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_clang_static_analysis` | `clang_static_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_clang_static_analysis` | `clang_static_scope_coverage` | `appsec-review/cpp-index-coverage/1` | handoff | optional | gap |
| `job_clang_static_analysis` | `clang_static_summary` | `appsec-review/clang-static-analysis-handoff/1` | handoff | optional | gap |
| `job_clang_static_analysis` | `clang_static_raw` | `application/json` | handoff | optional | gap |
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

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `codeql_graph_export` | `execution` | `appsec-review/codeql-graph-export/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `codeql_observations` | `execution` | `appsec-review/codeql-sarif-normalizer/3` | indexed | `observations` | `query_codeql`, `query_hotspots` |
| `codeql_plan_and_summary` | `acceptance` | `appsec-review/codeql-analysis-handoff/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `codeql_predecessor_import` | `execution` | `appsec-review/codeql-predecessor-import/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `codeql_scope_material` | `execution` | `application/octet-stream` | protected | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | None declared |
| integration | None declared |
| live | `tests/live/test_codeql_analysis_wave1_live.py` |
| unit | `tests/test_codeql_analysis.py::test_materialized_workspace_staging_omits_manifest_backed_npm_symlink`<br>`tests/test_codeql_analysis.py::test_materialized_workspace_staging_omits_container_owned_node_modules_symlink`<br>`tests/test_codeql_analysis.py::test_materialized_workspace_staging_rejects_unsafe_directory_links` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_debug_symbol_indexing`, `job_artifact_security_analysis`, `job_clang_static_analysis`, `job_cpp_symbol_index`, `job_cpg_analysis`, `job_svf_alias_analysis`, `job_post_build_security_assessment`, `job_change_context_analysis`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_codeql_analysis"]
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
  producer9["job_change_context_analysis"]
  input9["handoff"]
  input_schema9["appsec-review/job-handoff/2"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_change_context_analysis"]
  input10["change_context"]
  input_schema10["appsec-review/retrieval-index/2"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_change_context_analysis"]
  input11["change_context_documents"]
  input_schema11["appsec-review/change-context-analysis/1"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_change_context_analysis"]
  input12["operator_exports"]
  input_schema12["application/json"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_change_context_analysis"]
  input13["change_context_tool_io"]
  input_schema13["appsec-review/container-execution/1"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_clang_static_analysis"]
  input14["handoff"]
  input_schema14["appsec-review/job-handoff/2"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_clang_static_analysis"]
  input15["clang_static_observations"]
  input_schema15["appsec-review/retrieval-index/2"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_clang_static_analysis"]
  input16["clang_static_scope_coverage"]
  input_schema16["appsec-review/cpp-index-coverage/1"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  producer17["job_clang_static_analysis"]
  input17["clang_static_summary"]
  input_schema17["appsec-review/clang-static-analysis-handoff/1"]
  producer17 --> input17 --> job
  input17 -. schema .-> input_schema17
  producer18["job_clang_static_analysis"]
  input18["clang_static_raw"]
  input_schema18["application/json"]
  producer18 --> input18 --> job
  input18 -. schema .-> input_schema18
  producer19["job_cpg_analysis"]
  input19["handoff"]
  input_schema19["appsec-review/job-handoff/2"]
  producer19 --> input19 --> job
  input19 -. schema .-> input_schema19
  producer20["job_cpg_analysis"]
  input20["cpg_graph_coverage"]
  input_schema20["appsec-review/retrieval-index/2"]
  producer20 --> input20 --> job
  input20 -. schema .-> input_schema20
  producer21["job_cpg_analysis"]
  input21["cpg_scope_coverage"]
  input_schema21["appsec-review/cpp-index-coverage/1"]
  producer21 --> input21 --> job
  input21 -. schema .-> input_schema21
  producer22["job_cpg_analysis"]
  input22["cpg_summary"]
  input_schema22["appsec-review/cpg-analysis/1"]
  producer22 --> input22 --> job
  input22 -. schema .-> input_schema22
  producer23["job_cpg_analysis"]
  input23["cpg_binary"]
  input_schema23["application/octet-stream"]
  producer23 --> input23 --> job
  input23 -. schema .-> input_schema23
  producer24["job_cpp_compiled_analysis"]
  input24["handoff"]
  input_schema24["appsec-review/job-handoff/2"]
  producer24 --> input24 --> job
  input24 -. schema .-> input_schema24
  producer25["job_cpp_compiled_analysis"]
  input25["cpp_build_graph"]
  input_schema25["appsec-review/retrieval-index/2"]
  producer25 --> input25 --> job
  input25 -. schema .-> input_schema25
  producer26["job_cpp_compiled_analysis"]
  input26["clang_ast"]
  input_schema26["appsec-review/retrieval-index/2"]
  producer26 --> input26 --> job
  input26 -. schema .-> input_schema26
  producer27["job_cpp_compiled_analysis"]
  input27["llvm_ir"]
  input_schema27["appsec-review/retrieval-index/2"]
  producer27 --> input27 --> job
  input27 -. schema .-> input_schema27
  producer28["job_cpp_compiled_analysis"]
  input28["infer_observations"]
  input_schema28["appsec-review/retrieval-index/2"]
  producer28 --> input28 --> job
  input28 -. schema .-> input_schema28
  producer29["job_cpp_compiled_analysis"]
  input29["binary_symbols"]
  input_schema29["appsec-review/retrieval-index/2"]
  producer29 --> input29 --> job
  input29 -. schema .-> input_schema29
  producer30["job_cpp_compiled_analysis"]
  input30["cpp_blocked_branches"]
  input_schema30["appsec-review/retrieval-index/2"]
  producer30 --> input30 --> job
  input30 -. schema .-> input_schema30
  producer31["job_cpp_compiled_analysis"]
  input31["cpp_plan_and_summary"]
  input_schema31["appsec-review/cpp-compiled-analysis/2"]
  producer31 --> input31 --> job
  input31 -. schema .-> input_schema31
  producer32["job_cpp_compiled_analysis"]
  input32["cpp_case_material"]
  input_schema32["application/octet-stream"]
  producer32 --> input32 --> job
  input32 -. schema .-> input_schema32
  producer33["job_cpp_symbol_index"]
  input33["handoff"]
  input_schema33["appsec-review/job-handoff/2"]
  producer33 --> input33 --> job
  input33 -. schema .-> input_schema33
  producer34["job_cpp_symbol_index"]
  input34["clangd_symbols"]
  input_schema34["appsec-review/retrieval-index/2"]
  producer34 --> input34 --> job
  input34 -. schema .-> input_schema34
  producer35["job_cpp_symbol_index"]
  input35["clangd_coverage"]
  input_schema35["appsec-review/cpp-index-coverage/1"]
  producer35 --> input35 --> job
  input35 -. schema .-> input_schema35
  producer36["job_cpp_symbol_index"]
  input36["clangd_summary"]
  input_schema36["appsec-review/cpp-symbol-index/1"]
  producer36 --> input36 --> job
  input36 -. schema .-> input_schema36
  producer37["job_cpp_symbol_index"]
  input37["clangd_tool_io"]
  input_schema37["appsec-review/container-execution/1"]
  producer37 --> input37 --> job
  input37 -. schema .-> input_schema37
  producer38["job_debug_symbol_indexing"]
  input38["handoff"]
  input_schema38["appsec-review/job-handoff/2"]
  producer38 --> input38 --> job
  input38 -. schema .-> input_schema38
  producer39["job_debug_symbol_indexing"]
  input39["normalized_symbols"]
  input_schema39["appsec-review/retrieval-index/2"]
  producer39 --> input39 --> job
  input39 -. schema .-> input_schema39
  producer40["job_debug_symbol_indexing"]
  input40["symbol_coverage"]
  input_schema40["appsec-review/debug-symbol-coverage/1"]
  producer40 --> input40 --> job
  input40 -. schema .-> input_schema40
  producer41["job_debug_symbol_indexing"]
  input41["target_decision"]
  input_schema41["appsec-review/debug-symbol-decision/2"]
  producer41 --> input41 --> job
  input41 -. schema .-> input_schema41
  producer42["job_debug_symbol_indexing"]
  input42["raw_artifact_refs"]
  input_schema42["appsec-review/debug-symbol-inputs/1"]
  producer42 --> input42 --> job
  input42 -. schema .-> input_schema42
  producer43["job_debug_symbol_indexing"]
  input43["reader_executions"]
  input_schema43["appsec-review/container-execution/1"]
  producer43 --> input43 --> job
  input43 -. schema .-> input_schema43
  producer44["job_debug_symbol_indexing"]
  input44["debug_symbol_summary"]
  input_schema44["appsec-review/debug-symbol-indexing/1"]
  producer44 --> input44 --> job
  input44 -. schema .-> input_schema44
  producer45["job_evidence_collection"]
  input45["handoff"]
  input_schema45["appsec-review/job-handoff/2"]
  producer45 --> input45 --> job
  input45 -. schema .-> input_schema45
  producer46["job_evidence_collection"]
  input46["static_tool_observations"]
  input_schema46["appsec-review/retrieval-index/2"]
  producer46 --> input46 --> job
  input46 -. schema .-> input_schema46
  producer47["job_evidence_collection"]
  input47["static_tool_evidence"]
  input_schema47["appsec-review/static-tool-evidence/2"]
  producer47 --> input47 --> job
  input47 -. schema .-> input_schema47
  producer48["job_evidence_collection"]
  input48["static_tool_io"]
  input_schema48["appsec-review/container-execution/1"]
  producer48 --> input48 --> job
  input48 -. schema .-> input_schema48
  producer49["job_language_build"]
  input49["handoff"]
  input_schema49["appsec-review/job-handoff/2"]
  producer49 --> input49 --> job
  input49 -. schema .-> input_schema49
  producer50["job_language_build"]
  input50["topology_refinement_inputs"]
  input_schema50["appsec-review/build-topology-refinement/1"]
  producer50 --> input50 --> job
  input50 -. schema .-> input_schema50
  producer51["job_language_build"]
  input51["build_actions"]
  input_schema51["appsec-review/retrieval-index/2"]
  producer51 --> input51 --> job
  input51 -. schema .-> input_schema51
  producer52["job_language_build"]
  input52["jvm_build_actions"]
  input_schema52["appsec-review/retrieval-index/2"]
  producer52 --> input52 --> job
  input52 -. schema .-> input_schema52
  producer53["job_language_build"]
  input53["language_build_receipts"]
  input_schema53["appsec-review/language-build-handoff/2"]
  producer53 --> input53 --> job
  input53 -. schema .-> input_schema53
  producer54["job_language_build"]
  input54["build_workspaces"]
  input_schema54["application/octet-stream"]
  producer54 --> input54 --> job
  input54 -. schema .-> input_schema54
  producer55["job_post_build_security_assessment"]
  input55["handoff"]
  input_schema55["appsec-review/job-handoff/2"]
  producer55 --> input55 --> job
  input55 -. schema .-> input_schema55
  producer56["job_post_build_security_assessment"]
  input56["build_security"]
  input_schema56["appsec-review/retrieval-index/2"]
  producer56 --> input56 --> job
  input56 -. schema .-> input_schema56
  producer57["job_post_build_security_assessment"]
  input57["build_security_documents"]
  input_schema57["appsec-review/post-build-security-assessment/1"]
  producer57 --> input57 --> job
  input57 -. schema .-> input_schema57
  producer58["job_project_build"]
  input58["handoff"]
  input_schema58["appsec-review/job-handoff/2"]
  producer58 --> input58 --> job
  input58 -. schema .-> input_schema58
  producer59["job_project_build"]
  input59["topology_refinement_inputs"]
  input_schema59["appsec-review/build-topology-refinement/1"]
  producer59 --> input59 --> job
  input59 -. schema .-> input_schema59
  producer60["job_project_build"]
  input60["project_build_dispatch"]
  input_schema60["appsec-review/project-build-dispatch/3"]
  producer60 --> input60 --> job
  input60 -. schema .-> input_schema60
  producer61["job_project_build"]
  input61["probe_workspaces"]
  input_schema61["application/octet-stream"]
  producer61 --> input61 --> job
  input61 -. schema .-> input_schema61
  producer62["job_project_build"]
  input62["image_build_streams"]
  input_schema62["text/plain"]
  producer62 --> input62 --> job
  input62 -. schema .-> input_schema62
  producer63["job_review_intake"]
  input63["handoff"]
  input_schema63["appsec-review/job-handoff/2"]
  producer63 --> input63 --> job
  input63 -. schema .-> input_schema63
  producer64["job_review_intake"]
  input64["model_preflight"]
  input_schema64["appsec-review/model-preflight/1"]
  producer64 --> input64 --> job
  input64 -. schema .-> input_schema64
  producer65["job_review_intake"]
  input65["binary_evidence"]
  input_schema65["appsec-review/binary-evidence-intake/1"]
  producer65 --> input65 --> job
  input65 -. schema .-> input_schema65
  producer66["job_review_intake"]
  input66["review_intake"]
  input_schema66["appsec-review/review-intake/1"]
  producer66 --> input66 --> job
  input66 -. schema .-> input_schema66
  producer67["job_svf_alias_analysis"]
  input67["handoff"]
  input_schema67["appsec-review/job-handoff/2"]
  producer67 --> input67 --> job
  input67 -. schema .-> input_schema67
  producer68["job_svf_alias_analysis"]
  input68["svf_alias_sets"]
  input_schema68["appsec-review/retrieval-index/2"]
  producer68 --> input68 --> job
  input68 -. schema .-> input_schema68
  producer69["job_svf_alias_analysis"]
  input69["svf_alias_scope_coverage"]
  input_schema69["appsec-review/cpp-index-coverage/1"]
  producer69 --> input69 --> job
  input69 -. schema .-> input_schema69
  producer70["job_svf_alias_analysis"]
  input70["svf_alias_summary"]
  input_schema70["appsec-review/svf-alias-analysis-handoff/1"]
  producer70 --> input70 --> job
  input70 -. schema .-> input_schema70
  producer71["job_svf_alias_analysis"]
  input71["svf_alias_raw"]
  input_schema71["application/json"]
  producer71 --> input71 --> job
  input71 -. schema .-> input_schema71
  producer72["job_target_analysis_plan"]
  input72["handoff"]
  input_schema72["appsec-review/job-handoff/2"]
  producer72 --> input72 --> job
  input72 -. schema .-> input_schema72
  producer73["job_target_analysis_plan"]
  input73["planning_feedback_cache"]
  input_schema73["appsec-review/target-analysis-proposal/3"]
  producer73 --> input73 --> job
  input73 -. schema .-> input_schema73
  producer74["job_target_analysis_plan"]
  input74["analysis_plan"]
  input_schema74["appsec-review/retrieval-index/2"]
  producer74 --> input74 --> job
  input74 -. schema .-> input_schema74
  producer75["job_target_analysis_plan"]
  input75["analysis_plan_documents"]
  input_schema75["appsec-review/target-analysis-plan/1"]
  producer75 --> input75 --> job
  input75 -. schema .-> input_schema75
  producer76["job_target_catalog"]
  input76["handoff"]
  input_schema76["appsec-review/job-handoff/2"]
  producer76 --> input76 --> job
  input76 -. schema .-> input_schema76
  producer77["job_target_catalog"]
  input77["target_artifact_inputs"]
  input_schema77["appsec-review/target-artifact-intake/1"]
  producer77 --> input77 --> job
  input77 -. schema .-> input_schema77
  producer78["job_target_catalog"]
  input78["source_files"]
  input_schema78["appsec-review/retrieval-index/2"]
  producer78 --> input78 --> job
  input78 -. schema .-> input_schema78
  producer79["job_target_catalog"]
  input79["declaration_symbols"]
  input_schema79["appsec-review/retrieval-index/2"]
  producer79 --> input79 --> job
  input79 -. schema .-> input_schema79
  producer80["job_target_catalog"]
  input80["components"]
  input_schema80["appsec-review/retrieval-index/2"]
  producer80 --> input80 --> job
  input80 -. schema .-> input_schema80
  producer81["job_target_catalog"]
  input81["target_documents"]
  input_schema81["appsec-review/retrieval-index/2"]
  producer81 --> input81 --> job
  input81 -. schema .-> input_schema81
  producer82["job_target_catalog"]
  input82["build_units"]
  input_schema82["appsec-review/retrieval-index/2"]
  producer82 --> input82 --> job
  input82 -. schema .-> input_schema82
  producer83["job_target_catalog"]
  input83["catalog_documents"]
  input_schema83["appsec-review/target-catalog/1"]
  producer83 --> input83 --> job
  input83 -. schema .-> input_schema83
  producer84["job_tree_sitter_ast"]
  input84["handoff"]
  input_schema84["appsec-review/job-handoff/2"]
  producer84 --> input84 --> job
  input84 -. schema .-> input_schema84
  producer85["job_tree_sitter_ast"]
  input85["tree_sitter_ast"]
  input_schema85["appsec-review/tree-sitter-normalizer/1"]
  producer85 --> input85 --> job
  input85 -. schema .-> input_schema85
  producer86["job_tree_sitter_ast"]
  input86["tree_sitter_coverage"]
  input_schema86["appsec-review/tree-sitter-ast/1"]
  producer86 --> input86 --> job
  input86 -. schema .-> input_schema86
  producer87["job_tree_sitter_ast"]
  input87["tree_sitter_node_shards"]
  input_schema87["appsec-review/tree-sitter-ast/1"]
  producer87 --> input87 --> job
  input87 -. schema .-> input_schema87
  producer88["job_tree_sitter_ast"]
  input88["generated_source_backing"]
  input_schema88["appsec-review/generated-source-backing/1"]
  producer88 --> input88 --> job
  input88 -. schema .-> input_schema88
  producer89["job_tree_sitter_ast"]
  input89["tree_sitter_tool_io"]
  input_schema89["appsec-review/container-execution/1"]
  producer89 --> input89 --> job
  input89 -. schema .-> input_schema89
  output0["codeql_graph_export"]
  output_schema0["appsec-review/codeql-graph-export/1"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["codeql_observations"]
  output_schema1["appsec-review/codeql-sarif-normalizer/3"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["codeql_plan_and_summary"]
  output_schema2["appsec-review/codeql-analysis-handoff/1"]
  job --> output2
  output2 -. schema .-> output_schema2
  output3["codeql_predecessor_import"]
  output_schema3["appsec-review/codeql-predecessor-import/1"]
  job --> output3
  output3 -. schema .-> output_schema3
  output4["codeql_scope_material"]
  output_schema4["application/octet-stream"]
  job --> output4
  output4 -. schema .-> output_schema4
```

<!-- generated:end -->
