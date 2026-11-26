---
title: "Job-local operational tuning"
kind: "operations"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_artifact_indexing", "job_artifact_security_analysis", "job_binary_evidence_indexing", "job_build_environment_analysis", "job_build_iteration", "job_cbmc_analysis", "job_change_context_analysis", "job_ci_configuration_analysis", "job_clang_static_analysis", "job_code_graph_index", "job_codeql_analysis", "job_cpg_analysis", "job_cpp_compiled_analysis", "job_cpp_symbol_index", "job_debug_symbol_indexing", "job_dependency_intelligence", "job_document_issue_analysis", "job_dossier_publication", "job_evidence_collection", "job_final_publication_gate", "job_final_report_publication", "job_image_pin_verification", "job_inference_security_review", "job_language_build", "job_model_connectivity", "job_openvex_export", "job_owasp_control_assessment", "job_poc_generation", "job_post_build_security_assessment", "job_profile_data", "job_project_build", "job_remediation_planning", "job_remediation_validation", "job_review_data_indexing", "job_review_intake", "job_review_package_assembly", "job_review_prioritization", "job_sanitizer_build", "job_security_tagging", "job_source_history_analysis", "job_svf_alias_analysis", "job_target_acquisition", "job_target_analysis_plan", "job_target_catalog", "job_test_coverage", "job_third_party_data_sync", "job_threat_model_generation", "job_tree_sitter_ast"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# All-job operational tuning

Every configured job is accounted for below. Forty-five have exact declared local or
inherited controls; three expose no independent mutable job setting. This is not
blanket compatibility for every field in those jobs.

The authoritative declarations are in
[`config/operational.py`](../../src/appsec_review/config/operational.py).
The [architecture](../architecture/runtime-interchange.md#operational-configuration-compatibility-and-attempt-ownership)
defines execution, coverage, material/authority and source-layer provenance handling.
Each linked job section lists exact paths, checked-in base defaults, value/parser bounds,
whole-job/downstream impact and specifically excluded candidates. Profile/overlay
values can differ from the base defaults; immutable revisions retain their exact layers.

| Configured job | Declared local/inherited fields | Canonical tuning/recovery documentation |
| --- | ---: | --- |
| `job_artifact_indexing` | 0 | [artifact-indexing](artifact-indexing.md#tuning-and-whole-job-recovery-job_artifact_indexing) |
| `job_artifact_security_analysis` | 5 | [artifact-security-analysis](artifact-security-analysis.md#tuning-and-whole-job-recovery-job_artifact_security_analysis) |
| `job_binary_evidence_indexing` | 20 | [binary-decompilation](binary-decompilation.md#tuning-and-whole-job-recovery-job_binary_evidence_indexing) |
| `job_build_environment_analysis` | 5 | [build-environment-analysis](build-environment-analysis.md#tuning-and-whole-job-recovery-job_build_environment_analysis) |
| `job_build_iteration` | 0 | [language-build](language-build.md#tuning-and-whole-job-recovery-job_build_iteration) |
| `job_cbmc_analysis` | 15 | [job_cbmc_analysis](job_cbmc_analysis.md#tuning-and-whole-job-recovery-job_cbmc_analysis) |
| `job_change_context_analysis` | 7 | [change-context-analysis](change-context-analysis.md#tuning-and-whole-job-recovery-job_change_context_analysis) |
| `job_ci_configuration_analysis` | 3 | [ci-configuration-analysis](ci-configuration-analysis.md#tuning-and-whole-job-recovery-job_ci_configuration_analysis) |
| `job_clang_static_analysis` | 5 | [clang-static-analysis](clang-static-analysis.md#tuning-and-whole-job-recovery-job_clang_static_analysis) |
| `job_code_graph_index` | 4 | [code-graph-index](code-graph-index.md#tuning-and-whole-job-recovery-job_code_graph_index) |
| `job_codeql_analysis` | 17 | [codeql-analysis](codeql-analysis.md#tuning-and-whole-job-recovery-job_codeql_analysis) |
| `job_cpg_analysis` | 4 | [cpp-index-jobs](cpp-index-jobs.md#tuning-and-whole-job-recovery-job_cpg_analysis) |
| `job_cpp_compiled_analysis` | 4 | [cpp-compiled-analysis](cpp-compiled-analysis.md#tuning-and-whole-job-recovery-job_cpp_compiled_analysis) |
| `job_cpp_symbol_index` | 5 | [cpp-index-jobs](cpp-index-jobs.md#tuning-and-whole-job-recovery-job_cpp_symbol_index) |
| `job_debug_symbol_indexing` | 6 | [debug-symbol-indexing](../architecture/debug-symbol-indexing.md#tuning-and-whole-job-recovery-job_debug_symbol_indexing) |
| `job_dependency_intelligence` | 44 | [dependency-intelligence](dependency-intelligence.md#tuning-and-whole-job-recovery-job_dependency_intelligence) |
| `job_document_issue_analysis` | 2 | [document-issue-analysis](document-issue-analysis.md#tuning-and-whole-job-recovery-job_document_issue_analysis) |
| `job_dossier_publication` | 9 | [dossier-publication](dossier-publication.md#tuning-and-whole-job-recovery-job_dossier_publication) |
| `job_evidence_collection` | 4 | [static-analysis](static-analysis.md#tuning-and-whole-job-recovery-job_evidence_collection) |
| `job_final_publication_gate` | 1 | [final-report](final-report.md#tuning-and-whole-job-recovery-job_final_publication_gate) |
| `job_final_report_publication` | 7 | [final-report](final-report.md#tuning-and-whole-job-recovery-job_final_report_publication) |
| `job_image_pin_verification` | 0 | [image-pin-verification](image-pin-verification.md#tuning-and-whole-job-recovery-job_image_pin_verification) |
| `job_inference_security_review` | 90 | [inference-security-review](../architecture/inference-security-review.md#tuning-and-whole-job-recovery-job_inference_security_review) |
| `job_language_build` | 12 | [language-build](language-build.md#tuning-and-whole-job-recovery-job_language_build) |
| `job_model_connectivity` | 1 | [jobs-and-runtime](../architecture/jobs-and-runtime.md#tuning-and-whole-job-recovery-job_model_connectivity) |
| `job_openvex_export` | 7 | [openvex-export](../architecture/openvex-export.md#tuning-and-whole-job-recovery-job_openvex_export) |
| `job_owasp_control_assessment` | 20 | [owasp-control-assessment](owasp-control-assessment.md#tuning-and-whole-job-recovery-job_owasp_control_assessment) |
| `job_poc_generation` | 22 | [poc-generation](poc-generation.md#tuning-and-whole-job-recovery-job_poc_generation) |
| `job_post_build_security_assessment` | 4 | [post-build-security-assessment](post-build-security-assessment.md#tuning-and-whole-job-recovery-job_post_build_security_assessment) |
| `job_profile_data` | 5 | [profile-data](profile-data.md#tuning-and-whole-job-recovery-job_profile_data) |
| `job_project_build` | 8 | [project-build](project-build.md#tuning-and-whole-job-recovery-job_project_build) |
| `job_remediation_planning` | 15 | [remediation](remediation.md#tuning-and-whole-job-recovery-job_remediation_planning) |
| `job_remediation_validation` | 15 | [remediation](remediation.md#tuning-and-whole-job-recovery-job_remediation_validation) |
| `job_review_data_indexing` | 8 | [review-data-indexing](review-data-indexing.md#tuning-and-whole-job-recovery-job_review_data_indexing) |
| `job_review_intake` | 15 | [jobs-and-runtime](../architecture/jobs-and-runtime.md#tuning-and-whole-job-recovery-job_review_intake) |
| `job_review_package_assembly` | 1 | [review-package-contract](../architecture/review-package-contract.md#tuning-and-whole-job-recovery-job_review_package_assembly) |
| `job_review_prioritization` | 14 | [review-prioritization](review-prioritization.md#tuning-and-whole-job-recovery-job_review_prioritization) |
| `job_sanitizer_build` | 5 | [sanitizer-build](sanitizer-build.md#tuning-and-whole-job-recovery-job_sanitizer_build) |
| `job_security_tagging` | 6 | [security-tagging](security-tagging.md#tuning-and-whole-job-recovery-job_security_tagging) |
| `job_source_history_analysis` | 25 | [source-history-analysis](source-history-analysis.md#tuning-and-whole-job-recovery-job_source_history_analysis) |
| `job_svf_alias_analysis` | 16 | [svf-alias-analysis](svf-alias-analysis.md#tuning-and-whole-job-recovery-job_svf_alias_analysis) |
| `job_target_acquisition` | 9 | [target-acquisition](target-acquisition.md#tuning-and-whole-job-recovery-job_target_acquisition) |
| `job_target_analysis_plan` | 18 | [target-analysis-planning](target-analysis-planning.md#tuning-and-whole-job-recovery-job_target_analysis_plan) |
| `job_target_catalog` | 8 | [target-analysis-planning](target-analysis-planning.md#tuning-and-whole-job-recovery-job_target_catalog) |
| `job_test_coverage` | 5 | [test-coverage-ingestion](test-coverage-ingestion.md#tuning-and-whole-job-recovery-job_test_coverage) |
| `job_third_party_data_sync` | 16 | [third-party-data-sync](third-party-data-sync.md#tuning-and-whole-job-recovery-job_third_party_data_sync) |
| `job_threat_model_generation` | 11 | [threat-model-generation](threat-model-generation.md#tuning-and-whole-job-recovery-job_threat_model_generation) |
| `job_tree_sitter_ast` | 6 | [tree-sitter-ast](tree-sitter-ast.md#tuning-and-whole-job-recovery-job_tree_sitter_ast) |

## Global controls

Exact global declarations cover runtime observation intervals; existing named Dagster
pools and maximum concurrency; the four review resource capacities; reviewed target
acquisition waits/parallelism/coverage ceilings; inventory file bytes; pre-review binary
resource and analysis limits; and telemetry-render waits/output ceilings. Each still
passes its typed parser and resource admission. Resource tuning cannot resize or bypass
incompatible active, persistent or quarantined leases.

Memory strings are accepted only for explicitly declared memory fields. Review backoff
uses the existing nondecreasing integer-array parser (including empty arrays); declared
retry booleans are coverage, not authority. Layer changes are compatible only when all
changed layer leaves and the full effective configuration remain operational. Raw
profile/overlay bytes, digests and the original snapshot are preserved.

## Remaining material boundaries

* CodeQL step/task workers remain fixed at one; use `settings.concurrency`. Structural
  worker fields elsewhere are not substitutes for actual job-local pool controls.
* `target_acquisition.max_path_bytes` bounds safe path parsing;
  `target_acquisition.max_submodule_depth` selects source traversal scope.
* `binary_decompilation.min_string_length` changes interpretation, not execution cost.
* Global and job-local `build_capture` argv/env/path/event/raw-trace limits participate
  in required kernel evidence, redaction and secret-handling custody; they are not
  ordinary resource ceilings. Capture mode/backend/env collection/retention likewise
  remain material or authority settings.
* Archive expansion/ratio/member/depth admission remains a decompression safety boundary.
  CBMC unwind limits, SVF field abstraction, graph path/guard traversal, CodeQL seed/query
  selection, required PoC forms and sandbox grants, scoring thresholds, freshness rules,
  participant composition and stable package partition identities retain their specific
  material meanings, as detailed on the job pages.
* `containers/runtime-policy.toml` and tool manifests are measured tooling/release inputs,
  not resolved central-TOML fields; changing them still changes that release identity.
  This pass does not bypass source/signing verification to disguise those changes.
* Optional image-builder endpoint/tenant/release/cleanup controls and workspace retention
  are authority/lifecycle settings, not permission for an operational revision to delete
  evidence or provision services.

## Execution and verification

Admit the changed configuration through the existing repair mechanism, then explicitly
request the affected whole producer/downstream reruns when new coverage is wanted.
An accepted job retained under tuning keeps its original typed configuration and gaps.
No individual failed cells are imported into a new job attempt. The model readiness
check remains always-executed; feed maintenance and pre-review binary publication remain
separate explicitly requested operations.

Focused unit regressions cover operational compatibility, layer provenance, and
attempt-local whole-job re-execution; live reviews and targeted restarts remain manual
operator validation.
