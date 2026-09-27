# Implementation status: initial

Generated: `2026-09-27T12:47:11.073890+00:00`

Source: `codex/master-hello-full-review` at `69244bd5d6c55312bc7038fa2ca00f80fe991f29`

Inventory: 66 lifecycle jobs and 16 design capabilities.

Remaining `blocked_op` bindings: 41.

## Validator results

- `python3 appsec-review-process/validate_design_parity.py --check-generated-views`: **FAILED** (exit 9009) — The documented python3 executable is unavailable on this Windows host.
- `python3 docs/processes/job_catalog.py --check`: **FAILED** (exit 9009) — The documented python3 executable is unavailable on this Windows host.
- `python3 -B images/tool_pins.py check`: **FAILED** (exit 9009) — The documented python3 executable is unavailable on this Windows host.
- `python -B appsec-review-process/validate_design_parity.py --check-generated-views`: **FAILED** (exit 2) — The documented --check-generated-views option is not implemented by the validator.
- `python -B docs/processes/job_catalog.py --check`: **PASSED** (exit 0) — The generated job catalog is current.
- `python -B images/tool_pins.py check`: **FAILED** (exit 1) — tool-checkov, tool-mobsfscan and tool-semgrep pip locks differ from their pins; tool-gosec public-key bytes do not match public_key_sha256.

## Complete feature inventory

| Feature | Type | Graph | Binding | Automatic inputs | Pool | Status | Exact remaining work |
|---|---|---:|---|---|---|---|---|
| `00-intake` | lifecycle_job | True | controller | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_QUALIFIED** | Pool assigned (cpu, B15). Re-run the live pool qualification's worker-loss step (docs/pools/resource-pools.md step 8). |
| `02-ossf-scorecard` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | network | **INTEGRATED_QUALIFIED** | Pool assigned (network, B15); the network pool has not been observed under contention. |
| `02-repository-partition-discovery` | lifecycle_job | False | supplied_gate | SUPPLIED_ARTIFACT_REQUIRED | cpu | **INTEGRATED_UNQUALIFIED** | Implement the shared persona dispatch runtime while retaining supplied-artifact mode. |
| `02-dev-project-discovery` | lifecycle_job | False | supplied_gate | SUPPLIED_ARTIFACT_REQUIRED | cpu | **INTEGRATED_UNQUALIFIED** | Implement the shared persona dispatch runtime while retaining supplied-artifact mode. |
| `02-devops-project-discovery` | lifecycle_job | False | supplied_gate | SUPPLIED_ARTIFACT_REQUIRED | cpu | **INTEGRATED_UNQUALIFIED** | Implement the shared persona dispatch runtime while retaining supplied-artifact mode. |
| `02-sre-operations-topology` | lifecycle_job | False | supplied_gate | SUPPLIED_ARTIFACT_REQUIRED | cpu | **INTEGRATED_UNQUALIFIED** | Implement the shared persona dispatch runtime while retaining supplied-artifact mode. |
| `02-build-index` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Run live fault-recovery qualification for reuse, tamper rejection, and newer-failure blocking. |
| `02-build-classify` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | persona_llm | **INTEGRATED_UNQUALIFIED** | Run live fault-recovery qualification for reuse, tamper rejection, and newer-failure blocking. |
| `02-build-plan` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | persona_llm | **INTEGRATED_UNQUALIFIED** | Run live fault-recovery qualification for reuse, tamper rejection, and newer-failure blocking. |
| `02-build-resolution` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_QUALIFIED** | Run fault-recovery qualification for stages 14-16 and integrate the remaining source-language tools. |
| `02-evidence-assembly` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Implement the remaining required producers, bind the trusted C01/C02 pool context, then add the Dagster lifecycle and live qualification. |
| `01-component-characterization` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | persona_llm | **INTEGRATED_UNQUALIFIED** | Publish an accepted COMPLETE 02-evidence-assembly envelope, then run live persona qualification. |
| `02-full-review-input-assembly` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_QUALIFIED** | Reinvoke the deterministic assembler after SBOM, license, and SCA prerequisites publish so later dependency waves remain evidence-bound. |
| `03-threat-model-dfd-stride` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_QUALIFIED** | Run the accepted L6A/L6B path against a real Freeciv F03/F02 generation and route candidate hypotheses to the claim ledger. |
| `03-threat-model-reconciliation` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_QUALIFIED** | Run against a real accepted Freeciv generation and route reconciliation actions into the review control loop. |
| `04-asvs-masvs` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_QUALIFIED** | Derive dispatch facts automatically from the accepted OWASP lane instead of requiring the explicit qualified facts file. |
| `05-native-memory` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | cpu | **STANDALONE_ONLY** | Build the lifecycle input assembler from accepted native evidence, replace the blocked full-review op, and complete live qualification. |
| `06-cve-reachability` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | cpu | **STANDALONE_ONLY** | Build the full-review input assembler and complete live static-evidence qualification. |
| `13-fuzz-target-triage` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | cpu | **STANDALONE_ONLY** | Build the lifecycle input assembler from accepted component, threat, native-memory and reachability evidence, then complete live qualification. |
| `15-deployment-hardening` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | cpu | **STANDALONE_ONLY** | Build the lifecycle input assembler from accepted deployment configuration and STIG/SRG worklist evidence, then complete live qualification. |
| `07-red-team-adversarial` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Add common-envelope lifecycle publication, bind the qualified core to shared Dagster execution, assign its resource pool, and complete live qualification. |
| `08-blue-team-refutation` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Add common-envelope lifecycle publication, bind the qualified core to shared Dagster execution, assign its resource pool, and complete live qualification. |
| `09-independent-verification` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Add common-envelope lifecycle publication, bind the qualified core to shared Dagster execution, assign its resource pool, and complete live qualification. |
| `11-remediation-proposal` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **NOT_IMPLEMENTED** | Add registry composition, worker, validator, contract, lifecycle binding, pool, and qualification. |
| `12-scoring-prioritization` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Add common-envelope lifecycle publication, bind the qualified core to shared Dagster execution, assign its resource pool, and complete live qualification. |
| `10-synthesis-report` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_QUALIFIED** | Run the qualified publisher against the real accepted upstream chain, then pass its draft to the separate final publication gate. |
| `02-api-collection-intelligence-ingest` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Bind the qualified source-only core into the shared Dagster lifecycle and complete live fixture qualification. |
| `02-binary-intelligence-ingest` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Bind the qualified core into the shared Dagster lifecycle and complete its declared live prerequisite. |
| `02-doc-intelligence-ingest` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Bind the qualified source-only core into the shared Dagster lifecycle and complete live fixture qualification. |
| `02-standards-source-ingest` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Bind the qualified offline core into the shared Dagster lifecycle and complete live fixture qualification. |
| `02-test-intelligence-ingest` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Bind the qualified source-only core into the shared Dagster lifecycle and complete live fixture qualification. |
| `04-owasp-validation-worklist` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | cpu | **STANDALONE_ONLY** | Build the lifecycle input assembler from accepted OWASP source and applicability evidence, replace the blocked full-review op, and complete live qualification. |
| `15-stig-srg-validation-worklist` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | cpu | **STANDALONE_ONLY** | Build the lifecycle input assembler from accepted STIG/SRG source and platform evidence, replace the blocked full-review op, and complete live qualification. |
| `02-build-configure` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Run live fault-recovery qualification for reuse, tamper rejection, and newer-failure blocking. |
| `02-native-build` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Run live fault-recovery qualification for reuse, tamper rejection, and newer-failure blocking. |
| `02-source-sast` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_QUALIFIED** | Run live fault-recovery qualification; retain the explicit C/C++ rule-family coverage limitation. |
| `02-code-property-graph` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Qualify the registered Dagster lifecycle op and full-review handoff. |
| `02-native-sast` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Bind the qualified core into the shared Dagster lifecycle and complete its declared live prerequisite. |
| `02-ir-capture` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Qualify the registered Dagster lifecycle op against an accepted native build. |
| `02-ir-link` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Qualify the registered Dagster lifecycle op against accepted capture evidence. |
| `02-ir-facts` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Qualify the registered Dagster lifecycle op against accepted linked IR. |
| `02-debug-symbol-index` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Bind the qualified core into the shared Dagster lifecycle and complete its declared live prerequisite. |
| `02-binary-triage` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Bind the qualified core into the shared Dagster lifecycle and complete its declared live prerequisite. |
| `02-binary-cfg` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Bind the qualified core into the shared Dagster lifecycle and complete its declared live prerequisite. |
| `02-test-execution` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Bind the qualified core into the shared Dagster lifecycle, stage the authorized test control, and complete live qualification. |
| `02-test-result-ingest` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Bind the qualified core into the shared Dagster lifecycle, stage the authorized test control, and complete live qualification. |
| `02-test-coverage-ingest` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Bind the qualified core into the shared Dagster lifecycle, stage the authorized test control, and complete live qualification. |
| `02-operations-doc-ingest` | lifecycle_job | False | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | unassigned | **STANDALONE_ONLY** | Bind the qualified source-only core into the shared Dagster lifecycle and complete live fixture qualification. |
| `02-evidence-index` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | memory | **INTEGRATED_UNQUALIFIED** | Stage accepted derived-producer selections, migrate the legacy publication to the common envelope, and requalify the enriched lifecycle live. |
| `02-secrets-inventory` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | docker | **STANDALONE_ONLY** | Build the full-review input assembler and complete live Docker qualification; standalone execution is available with explicit run-owned paths. |
| `02-iac-config-scan` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | docker | **STANDALONE_ONLY** | Build the full-review input assembler and complete live Docker qualification; standalone execution is available with explicit run-owned paths. |
| `02-container-image-inventory` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | docker | **STANDALONE_ONLY** | Build the full-review input assembler and complete live Docker qualification; standalone execution is available with explicit run-owned paths. |
| `02-sbom-inventory` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | docker | **STANDALONE_ONLY** | Bind the common-envelope publication to the legacy vendor-prepass full-attempt validator, build the full-review input assembler, and complete live Docker qualification. |
| `02-sca-vulnerability-match` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | docker | **STANDALONE_ONLY** | Bind the common-envelope publication to the legacy vendor-prepass full-attempt validator, build the full-review input assembler, and qualify both supplied offline snapshot consumers live. |
| `02-license-scan` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | docker | **STANDALONE_ONLY** | Bind the common-envelope publication to the legacy vendor-prepass full-attempt validator, build the full-review input assembler, and complete live Docker qualification. |
| `02-dependency-lifecycle` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | cpu | **STANDALONE_ONLY** | Bind the common-envelope publication to the legacy vendor-prepass full-attempt validator, build the full-review input assembler, and qualify a supplied current reference table live. |
| `02-binary-hardening` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_QUALIFIED** | Exercise this accepted path in the next complete retained full-review run. |
| `02-mobile-sast` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | docker | **STANDALONE_ONLY** | Build the full-review input assembler and complete live Docker qualification; standalone execution is available with explicit run-owned paths. |
| `persona-tool-pool-dispatch` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | persona_llm | **STANDALONE_ONLY** | Build the full-review pool specification assembler and complete live persona qualification. |
| `deterministic-pool-merge` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | cpu | **STANDALONE_ONLY** | Bind the verified C02 pool from full-review orchestration. |
| `evidence-qualified-quorum` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | cpu | **STANDALONE_ONLY** | Bind the accepted deterministic merge reference in full review. |
| `dynamic-rescope` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | cpu | **STANDALONE_ONLY** | Bind classification changes in full review. |
| `completeness-audit` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | cpu | **STANDALONE_ONLY** | Bind the draft report obligation inventory in full review. |
| `synthetic-hypothesis-resynthesis` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | cpu | **STANDALONE_ONLY** | Bind accepted completeness audit input in full review. |
| `remediation-retest-feedback` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | cpu | **STANDALONE_ONLY** | Bind verified claims and retest evidence in full review. |
| `final-publication-gate` | lifecycle_job | True | blocked_op | NOT_CONSTRUCTED_FOR_FULL_REVIEW | cpu | **STANDALONE_ONLY** | Bind exact accepted completion references and operator signoff in full review. |
| `common-worker-result-envelope` | design_capability | None | capability | CAPABILITY_DEPENDENT | unassigned | **INTEGRATED_UNQUALIFIED** | Add the next bounded contract-specific validation slice without broad worker migration. |
| `pinned-container-adapter-runtime` | design_capability | None | capability | CAPABILITY_DEPENDENT | docker | **INTEGRATED_QUALIFIED** | Adopt the qualified adapter in 02-build-resolution, then the bounded scanner workers. |
| `dedicated-resource-pools` | design_capability | None | capability | CAPABILITY_DEPENDENT | unassigned | **INTEGRATED_UNQUALIFIED** | Run live qualification step 8 (kill -9 of a run worker; docs/pools/resource-pools.md), then cross-check each manifest job pool against its op pool. |
| `persona-tool-pool-dispatch` | design_capability | None | capability | CAPABILITY_DEPENDENT | persona_llm | **STANDALONE_ONLY** | Build the full-review pool specification assembler and complete live persona qualification. |
| `wait-all-rendezvous` | design_capability | None | capability | CAPABILITY_DEPENDENT | persona_llm | **STANDALONE_ONLY** | Bind full-review pool specifications and qualify the launcher live. |
| `deterministic-pool-merge` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **STANDALONE_ONLY** | Bind the verified C02 pool from full-review orchestration. |
| `evidence-qualified-quorum` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **STANDALONE_ONLY** | Bind the accepted deterministic merge reference in full review. |
| `claim-ledger-routing` | design_capability | None | capability | CAPABILITY_DEPENDENT | unassigned | **STANDALONE_ONLY** | Bind accepted OWASP and decision-stage publications to the qualified ledger core, then add shared lifecycle and live qualification. |
| `remediation-retest-feedback` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **STANDALONE_ONLY** | Bind verified claims and retest evidence in full review. |
| `dynamic-rescope` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **STANDALONE_ONLY** | Bind classification changes in full review. |
| `completeness-audit-control` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **STANDALONE_ONLY** | Bind the draft report obligation inventory in full review. |
| `synthetic-hypothesis-resynthesis` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **STANDALONE_ONLY** | Bind accepted completeness audit input in full review. |
| `threat-model-standard` | design_capability | None | capability | CAPABILITY_DEPENDENT | unassigned | **CORE_ONLY** | Resolve Workstream G1; do not infer DFD/STRIDE versus composed overlays. |
| `owasp-checklist-model` | design_capability | None | capability | CAPABILITY_DEPENDENT | unassigned | **CORE_ONLY** | Resolve Workstream G2 and pin licensed sources. |
| `disa-nsa-hardening-model` | design_capability | None | capability | CAPABILITY_DEPENDENT | unassigned | **CORE_ONLY** | Resolve Workstream G3 and pin authoritative references. |
| `final-publication-gate` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **STANDALONE_ONLY** | Bind exact accepted completion references and operator signoff in full review. |

The JSON companion contains implementation files, upstream/downstream bindings, envelope, permissions, qualification and retained-evidence fields for every row.
