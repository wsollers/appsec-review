# Mythos design-parity report

Status: **PASS**

Manifest schema: `appsec-review/design-parity-manifest/1.0`
Lifecycle jobs: **53**
Design capabilities: **15**

## Readiness summary

| State | Jobs |
|---|---:|
| `implemented_and_qualified` | 3 |
| `implemented_not_qualified` | 3 |
| `missing_prerequisites` | 36 |
| `registered_planned_not_executable` | 7 |
| `supplied_artifact_gate` | 4 |

## Lifecycle inventory

| Job | Graph implemented | Binding | Readiness | Pool |
|---|---:|---|---|---|
| `00-intake` | true | `controller` | `implemented_and_qualified` | `cpu` |
| `02-ossf-scorecard` | true | `actual_worker` | `implemented_and_qualified` | `network` |
| `02-repository-partition-discovery` | false | `supplied_gate` | `supplied_artifact_gate` | `cpu` |
| `02-dev-project-discovery` | false | `supplied_gate` | `supplied_artifact_gate` | `cpu` |
| `02-devops-project-discovery` | false | `supplied_gate` | `supplied_artifact_gate` | `cpu` |
| `02-sre-operations-topology` | false | `supplied_gate` | `supplied_artifact_gate` | `cpu` |
| `02-build-index` | true | `actual_worker` | `implemented_not_qualified` | `cpu` |
| `02-build-classify` | true | `actual_worker` | `implemented_not_qualified` | `persona_llm` |
| `02-evidence-assembly` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `01-component-characterization` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `03-threat-model-dfd-stride` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `04-asvs-masvs` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `05-native-memory` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `06-cve-reachability` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `13-fuzz-target-triage` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `15-deployment-hardening` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `07-red-team-adversarial` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `08-blue-team-refutation` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `09-independent-verification` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `11-remediation-proposal` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `12-scoring-prioritization` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `10-synthesis-report` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-api-collection-intelligence-ingest` | false | `blocked_op` | `registered_planned_not_executable` | `unassigned` |
| `02-binary-intelligence-ingest` | false | `blocked_op` | `registered_planned_not_executable` | `unassigned` |
| `02-doc-intelligence-ingest` | false | `blocked_op` | `registered_planned_not_executable` | `unassigned` |
| `02-standards-source-ingest` | false | `blocked_op` | `registered_planned_not_executable` | `unassigned` |
| `02-test-intelligence-ingest` | false | `blocked_op` | `registered_planned_not_executable` | `unassigned` |
| `04-owasp-validation-worklist` | false | `blocked_op` | `registered_planned_not_executable` | `unassigned` |
| `15-stig-srg-validation-worklist` | false | `blocked_op` | `registered_planned_not_executable` | `unassigned` |
| `02-build-configure` | false | `actual_worker` | `implemented_not_qualified` | `docker` |
| `02-native-build` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-source-sast` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-native-sast` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-ir-capture` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-ir-link` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-ir-facts` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-debug-symbol-index` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-binary-triage` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-binary-cfg` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-test-execution` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-test-result-ingest` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-test-coverage-ingest` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-operations-doc-ingest` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-evidence-index` | true | `actual_worker` | `implemented_and_qualified` | `memory` |
| `02-secrets-inventory` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-iac-config-scan` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-container-image-inventory` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-sbom-inventory` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-sca-vulnerability-match` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-license-scan` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-dependency-lifecycle` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-binary-hardening` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |
| `02-mobile-sast` | false | `blocked_op` | `missing_prerequisites` | `unassigned` |

## Explicit gaps

- 01-component-characterization: missing_dedicated_output_schema
- 01-component-characterization: missing_output_contract
- 01-component-characterization: missing_registry_composition
- 01-component-characterization: missing_validator
- 01-component-characterization: missing_worker
- 01-component-characterization: no qualification evidence
- 01-component-characterization: no_qualification
- 01-component-characterization: resource pool unassigned
- 01-component-characterization: unassigned_resource_pool
- 02-api-collection-intelligence-ingest: missing_dedicated_output_schema
- 02-api-collection-intelligence-ingest: missing_validator
- 02-api-collection-intelligence-ingest: missing_worker
- 02-api-collection-intelligence-ingest: no qualification evidence
- 02-api-collection-intelligence-ingest: no_qualification
- 02-api-collection-intelligence-ingest: resource pool unassigned
- 02-api-collection-intelligence-ingest: unassigned_resource_pool
- 02-binary-cfg: missing_dedicated_output_schema
- 02-binary-cfg: missing_output_contract
- 02-binary-cfg: missing_registry_composition
- 02-binary-cfg: missing_validator
- 02-binary-cfg: missing_worker
- 02-binary-cfg: no qualification evidence
- 02-binary-cfg: no_qualification
- 02-binary-cfg: resource pool unassigned
- 02-binary-cfg: unassigned_resource_pool
- 02-binary-hardening: missing_registry_composition
- 02-binary-hardening: missing_validator
- 02-binary-hardening: missing_worker
- 02-binary-hardening: no qualification evidence
- 02-binary-hardening: no_qualification
- 02-binary-hardening: resource pool unassigned
- 02-binary-hardening: unassigned_resource_pool
- 02-binary-intelligence-ingest: missing_dedicated_output_schema
- 02-binary-intelligence-ingest: missing_validator
- 02-binary-intelligence-ingest: missing_worker
- 02-binary-intelligence-ingest: no qualification evidence
- 02-binary-intelligence-ingest: no_qualification
- 02-binary-intelligence-ingest: resource pool unassigned
- 02-binary-intelligence-ingest: unassigned_resource_pool
- 02-binary-triage: missing_dedicated_output_schema
- 02-binary-triage: missing_output_contract
- 02-binary-triage: missing_registry_composition
- 02-binary-triage: missing_validator
- 02-binary-triage: missing_worker
- 02-binary-triage: no qualification evidence
- 02-binary-triage: no_qualification
- 02-binary-triage: resource pool unassigned
- 02-binary-triage: unassigned_resource_pool
- 02-build-classify: not_yet_live_qualified
- 02-build-configure: graph_implemented_flag_false
- 02-build-configure: missing_dedicated_output_schema
- 02-build-configure: missing_output_contract
- 02-build-configure: missing_registry_composition
- 02-build-configure: no qualification evidence
- 02-build-configure: no_live_full_review_qualification
- 02-build-index: not_yet_live_qualified
- 02-container-image-inventory: missing_registry_composition
- 02-container-image-inventory: missing_validator
- 02-container-image-inventory: missing_worker
- 02-container-image-inventory: no qualification evidence
- 02-container-image-inventory: no_qualification
- 02-container-image-inventory: resource pool unassigned
- 02-container-image-inventory: unassigned_resource_pool
- 02-debug-symbol-index: missing_dedicated_output_schema
- 02-debug-symbol-index: missing_output_contract
- 02-debug-symbol-index: missing_registry_composition
- 02-debug-symbol-index: missing_validator
- 02-debug-symbol-index: missing_worker
- 02-debug-symbol-index: no qualification evidence
- 02-debug-symbol-index: no_qualification
- 02-debug-symbol-index: resource pool unassigned
- 02-debug-symbol-index: unassigned_resource_pool
- 02-dependency-lifecycle: missing_registry_composition
- 02-dependency-lifecycle: missing_validator
- 02-dependency-lifecycle: missing_worker
- 02-dependency-lifecycle: no qualification evidence
- 02-dependency-lifecycle: no_qualification
- 02-dependency-lifecycle: resource pool unassigned
- 02-dependency-lifecycle: unassigned_resource_pool
- 02-dev-project-discovery: no qualification evidence
- 02-dev-project-discovery: not_automatic_analysis_dispatch
- 02-dev-project-discovery: supplied_result_required
- 02-devops-project-discovery: no qualification evidence
- 02-devops-project-discovery: not_automatic_analysis_dispatch
- 02-devops-project-discovery: supplied_result_required
- 02-doc-intelligence-ingest: missing_dedicated_output_schema
- 02-doc-intelligence-ingest: missing_validator
- 02-doc-intelligence-ingest: missing_worker
- 02-doc-intelligence-ingest: no qualification evidence
- 02-doc-intelligence-ingest: no_qualification
- 02-doc-intelligence-ingest: resource pool unassigned
- 02-doc-intelligence-ingest: unassigned_resource_pool
- 02-evidence-assembly: missing_dedicated_output_schema
- 02-evidence-assembly: missing_output_contract
- 02-evidence-assembly: missing_registry_composition
- 02-evidence-assembly: missing_validator
- 02-evidence-assembly: missing_worker
- 02-evidence-assembly: no qualification evidence
- 02-evidence-assembly: no_qualification
- 02-evidence-assembly: resource pool unassigned
- 02-evidence-assembly: unassigned_resource_pool
- 02-evidence-index: missing_dedicated_output_schema
- 02-iac-config-scan: missing_registry_composition
- 02-iac-config-scan: missing_validator
- 02-iac-config-scan: missing_worker
- 02-iac-config-scan: no qualification evidence
- 02-iac-config-scan: no_qualification
- 02-iac-config-scan: resource pool unassigned
- 02-iac-config-scan: unassigned_resource_pool
- 02-ir-capture: missing_dedicated_output_schema
- 02-ir-capture: missing_output_contract
- 02-ir-capture: missing_registry_composition
- 02-ir-capture: missing_validator
- 02-ir-capture: missing_worker
- 02-ir-capture: no qualification evidence
- 02-ir-capture: no_qualification
- 02-ir-capture: resource pool unassigned
- 02-ir-capture: unassigned_resource_pool
- 02-ir-facts: missing_dedicated_output_schema
- 02-ir-facts: missing_output_contract
- 02-ir-facts: missing_registry_composition
- 02-ir-facts: missing_validator
- 02-ir-facts: missing_worker
- 02-ir-facts: no qualification evidence
- 02-ir-facts: no_qualification
- 02-ir-facts: resource pool unassigned
- 02-ir-facts: unassigned_resource_pool
- 02-ir-link: missing_dedicated_output_schema
- 02-ir-link: missing_output_contract
- 02-ir-link: missing_registry_composition
- 02-ir-link: missing_validator
- 02-ir-link: missing_worker
- 02-ir-link: no qualification evidence
- 02-ir-link: no_qualification
- 02-ir-link: resource pool unassigned
- 02-ir-link: unassigned_resource_pool
- 02-license-scan: missing_registry_composition
- 02-license-scan: missing_validator
- 02-license-scan: missing_worker
- 02-license-scan: no qualification evidence
- 02-license-scan: no_qualification
- 02-license-scan: resource pool unassigned
- 02-license-scan: unassigned_resource_pool
- 02-mobile-sast: missing_registry_composition
- 02-mobile-sast: missing_validator
- 02-mobile-sast: missing_worker
- 02-mobile-sast: no qualification evidence
- 02-mobile-sast: no_qualification
- 02-mobile-sast: resource pool unassigned
- 02-mobile-sast: unassigned_resource_pool
- 02-native-build: missing_dedicated_output_schema
- 02-native-build: missing_output_contract
- 02-native-build: missing_registry_composition
- 02-native-build: missing_validator
- 02-native-build: missing_worker
- 02-native-build: no qualification evidence
- 02-native-build: no_qualification
- 02-native-build: resource pool unassigned
- 02-native-build: unassigned_resource_pool
- 02-native-sast: missing_dedicated_output_schema
- 02-native-sast: missing_output_contract
- 02-native-sast: missing_registry_composition
- 02-native-sast: missing_validator
- 02-native-sast: missing_worker
- 02-native-sast: no qualification evidence
- 02-native-sast: no_qualification
- 02-native-sast: resource pool unassigned
- 02-native-sast: unassigned_resource_pool
- 02-operations-doc-ingest: missing_dedicated_output_schema
- 02-operations-doc-ingest: missing_output_contract
- 02-operations-doc-ingest: missing_registry_composition
- 02-operations-doc-ingest: missing_validator
- 02-operations-doc-ingest: missing_worker
- 02-operations-doc-ingest: no qualification evidence
- 02-operations-doc-ingest: no_qualification
- 02-operations-doc-ingest: resource pool unassigned
- 02-operations-doc-ingest: unassigned_resource_pool
- 02-repository-partition-discovery: not_automatic_analysis_dispatch
- 02-repository-partition-discovery: supplied_result_required
- 02-sbom-inventory: missing_registry_composition
- 02-sbom-inventory: missing_validator
- 02-sbom-inventory: missing_worker
- 02-sbom-inventory: no qualification evidence
- 02-sbom-inventory: no_qualification
- 02-sbom-inventory: resource pool unassigned
- 02-sbom-inventory: unassigned_resource_pool
- 02-sca-vulnerability-match: missing_registry_composition
- 02-sca-vulnerability-match: missing_validator
- 02-sca-vulnerability-match: missing_worker
- 02-sca-vulnerability-match: no qualification evidence
- 02-sca-vulnerability-match: no_qualification
- 02-sca-vulnerability-match: resource pool unassigned
- 02-sca-vulnerability-match: unassigned_resource_pool
- 02-secrets-inventory: missing_registry_composition
- 02-secrets-inventory: missing_validator
- 02-secrets-inventory: missing_worker
- 02-secrets-inventory: no qualification evidence
- 02-secrets-inventory: no_qualification
- 02-secrets-inventory: resource pool unassigned
- 02-secrets-inventory: unassigned_resource_pool
- 02-source-sast: missing_dedicated_output_schema
- 02-source-sast: missing_output_contract
- 02-source-sast: missing_registry_composition
- 02-source-sast: missing_validator
- 02-source-sast: missing_worker
- 02-source-sast: no qualification evidence
- 02-source-sast: no_qualification
- 02-source-sast: resource pool unassigned
- 02-source-sast: unassigned_resource_pool
- 02-sre-operations-topology: no qualification evidence
- 02-sre-operations-topology: not_automatic_analysis_dispatch
- 02-sre-operations-topology: supplied_result_required
- 02-standards-source-ingest: missing_dedicated_output_schema
- 02-standards-source-ingest: missing_validator
- 02-standards-source-ingest: missing_worker
- 02-standards-source-ingest: no qualification evidence
- 02-standards-source-ingest: no_qualification
- 02-standards-source-ingest: resource pool unassigned
- 02-standards-source-ingest: unassigned_resource_pool
- 02-test-coverage-ingest: missing_dedicated_output_schema
- 02-test-coverage-ingest: missing_output_contract
- 02-test-coverage-ingest: missing_registry_composition
- 02-test-coverage-ingest: missing_validator
- 02-test-coverage-ingest: missing_worker
- 02-test-coverage-ingest: no qualification evidence
- 02-test-coverage-ingest: no_qualification
- 02-test-coverage-ingest: resource pool unassigned
- 02-test-coverage-ingest: unassigned_resource_pool
- 02-test-execution: missing_dedicated_output_schema
- 02-test-execution: missing_output_contract
- 02-test-execution: missing_registry_composition
- 02-test-execution: missing_validator
- 02-test-execution: missing_worker
- 02-test-execution: no qualification evidence
- 02-test-execution: no_qualification
- 02-test-execution: resource pool unassigned
- 02-test-execution: unassigned_resource_pool
- 02-test-intelligence-ingest: missing_dedicated_output_schema
- 02-test-intelligence-ingest: missing_validator
- 02-test-intelligence-ingest: missing_worker
- 02-test-intelligence-ingest: no qualification evidence
- 02-test-intelligence-ingest: no_qualification
- 02-test-intelligence-ingest: resource pool unassigned
- 02-test-intelligence-ingest: unassigned_resource_pool
- 02-test-result-ingest: missing_dedicated_output_schema
- 02-test-result-ingest: missing_output_contract
- 02-test-result-ingest: missing_registry_composition
- 02-test-result-ingest: missing_validator
- 02-test-result-ingest: missing_worker
- 02-test-result-ingest: no qualification evidence
- 02-test-result-ingest: no_qualification
- 02-test-result-ingest: resource pool unassigned
- 02-test-result-ingest: unassigned_resource_pool
- 03-threat-model-dfd-stride: missing_dedicated_output_schema
- 03-threat-model-dfd-stride: missing_output_contract
- 03-threat-model-dfd-stride: missing_registry_composition
- 03-threat-model-dfd-stride: missing_validator
- 03-threat-model-dfd-stride: missing_worker
- 03-threat-model-dfd-stride: no qualification evidence
- 03-threat-model-dfd-stride: no_qualification
- 03-threat-model-dfd-stride: resource pool unassigned
- 03-threat-model-dfd-stride: unassigned_resource_pool
- 04-asvs-masvs: missing_dedicated_output_schema
- 04-asvs-masvs: missing_output_contract
- 04-asvs-masvs: missing_registry_composition
- 04-asvs-masvs: missing_validator
- 04-asvs-masvs: missing_worker
- 04-asvs-masvs: no qualification evidence
- 04-asvs-masvs: no_qualification
- 04-asvs-masvs: resource pool unassigned
- 04-asvs-masvs: unassigned_resource_pool
- 04-owasp-validation-worklist: missing_dedicated_output_schema
- 04-owasp-validation-worklist: missing_validator
- 04-owasp-validation-worklist: missing_worker
- 04-owasp-validation-worklist: no qualification evidence
- 04-owasp-validation-worklist: no_qualification
- 04-owasp-validation-worklist: resource pool unassigned
- 04-owasp-validation-worklist: unassigned_resource_pool
- 05-native-memory: missing_dedicated_output_schema
- 05-native-memory: missing_output_contract
- 05-native-memory: missing_registry_composition
- 05-native-memory: missing_validator
- 05-native-memory: missing_worker
- 05-native-memory: no qualification evidence
- 05-native-memory: no_qualification
- 05-native-memory: resource pool unassigned
- 05-native-memory: unassigned_resource_pool
- 06-cve-reachability: missing_dedicated_output_schema
- 06-cve-reachability: missing_output_contract
- 06-cve-reachability: missing_registry_composition
- 06-cve-reachability: missing_validator
- 06-cve-reachability: missing_worker
- 06-cve-reachability: no qualification evidence
- 06-cve-reachability: no_qualification
- 06-cve-reachability: resource pool unassigned
- 06-cve-reachability: unassigned_resource_pool
- 07-red-team-adversarial: missing_dedicated_output_schema
- 07-red-team-adversarial: missing_output_contract
- 07-red-team-adversarial: missing_registry_composition
- 07-red-team-adversarial: missing_validator
- 07-red-team-adversarial: missing_worker
- 07-red-team-adversarial: no qualification evidence
- 07-red-team-adversarial: no_qualification
- 07-red-team-adversarial: resource pool unassigned
- 07-red-team-adversarial: unassigned_resource_pool
- 08-blue-team-refutation: missing_dedicated_output_schema
- 08-blue-team-refutation: missing_output_contract
- 08-blue-team-refutation: missing_registry_composition
- 08-blue-team-refutation: missing_validator
- 08-blue-team-refutation: missing_worker
- 08-blue-team-refutation: no qualification evidence
- 08-blue-team-refutation: no_qualification
- 08-blue-team-refutation: resource pool unassigned
- 08-blue-team-refutation: unassigned_resource_pool
- 09-independent-verification: missing_dedicated_output_schema
- 09-independent-verification: missing_output_contract
- 09-independent-verification: missing_registry_composition
- 09-independent-verification: missing_validator
- 09-independent-verification: missing_worker
- 09-independent-verification: no qualification evidence
- 09-independent-verification: no_qualification
- 09-independent-verification: resource pool unassigned
- 09-independent-verification: unassigned_resource_pool
- 10-synthesis-report: missing_dedicated_output_schema
- 10-synthesis-report: missing_output_contract
- 10-synthesis-report: missing_registry_composition
- 10-synthesis-report: missing_validator
- 10-synthesis-report: missing_worker
- 10-synthesis-report: no qualification evidence
- 10-synthesis-report: no_qualification
- 10-synthesis-report: resource pool unassigned
- 10-synthesis-report: unassigned_resource_pool
- 11-remediation-proposal: missing_dedicated_output_schema
- 11-remediation-proposal: missing_output_contract
- 11-remediation-proposal: missing_registry_composition
- 11-remediation-proposal: missing_validator
- 11-remediation-proposal: missing_worker
- 11-remediation-proposal: no qualification evidence
- 11-remediation-proposal: no_qualification
- 11-remediation-proposal: resource pool unassigned
- 11-remediation-proposal: unassigned_resource_pool
- 12-scoring-prioritization: missing_dedicated_output_schema
- 12-scoring-prioritization: missing_output_contract
- 12-scoring-prioritization: missing_registry_composition
- 12-scoring-prioritization: missing_validator
- 12-scoring-prioritization: missing_worker
- 12-scoring-prioritization: no qualification evidence
- 12-scoring-prioritization: no_qualification
- 12-scoring-prioritization: resource pool unassigned
- 12-scoring-prioritization: unassigned_resource_pool
- 13-fuzz-target-triage: missing_dedicated_output_schema
- 13-fuzz-target-triage: missing_output_contract
- 13-fuzz-target-triage: missing_registry_composition
- 13-fuzz-target-triage: missing_validator
- 13-fuzz-target-triage: missing_worker
- 13-fuzz-target-triage: no qualification evidence
- 13-fuzz-target-triage: no_qualification
- 13-fuzz-target-triage: resource pool unassigned
- 13-fuzz-target-triage: unassigned_resource_pool
- 15-deployment-hardening: missing_dedicated_output_schema
- 15-deployment-hardening: missing_output_contract
- 15-deployment-hardening: missing_registry_composition
- 15-deployment-hardening: missing_validator
- 15-deployment-hardening: missing_worker
- 15-deployment-hardening: no qualification evidence
- 15-deployment-hardening: no_qualification
- 15-deployment-hardening: resource pool unassigned
- 15-deployment-hardening: unassigned_resource_pool
- 15-stig-srg-validation-worklist: missing_dedicated_output_schema
- 15-stig-srg-validation-worklist: missing_validator
- 15-stig-srg-validation-worklist: missing_worker
- 15-stig-srg-validation-worklist: no qualification evidence
- 15-stig-srg-validation-worklist: no_qualification
- 15-stig-srg-validation-worklist: resource pool unassigned
- 15-stig-srg-validation-worklist: unassigned_resource_pool
- claim-ledger-routing: append_only_claim_ledger_missing
- claim-ledger-routing: candidate_routing_missing
- claim-ledger-routing: resource pool unassigned
- common-worker-result-envelope: container_persona_pool_controller_adapters_not_implemented
- common-worker-result-envelope: remaining_workers_not_yet_migrated
- common-worker-result-envelope: resource pool unassigned
- completeness-feedback: completeness_auditor_missing
- completeness-feedback: coverage_feedback_missing
- completeness-feedback: resource pool unassigned
- dedicated-resource-pools: lifecycle_jobs_without_workers_remain_unassigned
- dedicated-resource-pools: live_worker_loss_injection_pending
- dedicated-resource-pools: manifest_job_pool_not_cross_checked_against_op_pool
- dedicated-resource-pools: no_load_evidence_limits_must_not_be_raised
- dedicated-resource-pools: resource pool unassigned
- deterministic-pool-merge: persona_merge_missing
- deterministic-pool-merge: resource pool unassigned
- deterministic-pool-merge: tool_evidence_merge_missing
- disa-nsa-hardening-model: platform_applicability_precedence_tailoring_and_reference_storage_undecided
- disa-nsa-hardening-model: resource pool unassigned
- dynamic-rescope: bounded_rescope_controller_missing
- dynamic-rescope: classification_dependency_index_missing
- dynamic-rescope: resource pool unassigned
- evidence-qualified-quorum: diversity_accounting_missing
- evidence-qualified-quorum: quorum_controller_missing
- evidence-qualified-quorum: resource pool unassigned
- final-publication-gate: completion_validator_missing
- final-publication-gate: full_report_publication_missing
- final-publication-gate: human_final_signoff_ledger_missing
- final-publication-gate: resource pool unassigned
- owasp-checklist-model: owasp_versions_profiles_applicability_and_promotion_rules_undecided
- owasp-checklist-model: resource pool unassigned
- persona-tool-pool-dispatch: no_lifecycle_job_consumes_pool_specification
- persona-tool-pool-dispatch: pool_launcher_missing
- persona-tool-pool-dispatch: resource pool unassigned
- remediation-retest-feedback: fix_reverification_loop_missing
- remediation-retest-feedback: resource pool unassigned
- remediation-retest-feedback: same_environment_retest_missing
- synthetic-hypothesis-resynthesis: resource pool unassigned
- synthetic-hypothesis-resynthesis: resynthesis_loop_missing
- synthetic-hypothesis-resynthesis: synthetic_hypothesis_routing_missing
- threat-model-standard: resource pool unassigned
- threat-model-standard: threat_model_schema_and_scope_undecided
- wait-all-rendezvous: chain_independence_not_implemented
- wait-all-rendezvous: in_process_caps_do_not_see_other_rendezvous
- wait-all-rendezvous: no_dagster_op_runs_the_rendezvous
- wait-all-rendezvous: resource pool unassigned

## Validation errors

- None.
