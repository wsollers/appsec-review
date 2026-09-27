# Implementation status: before-run

Generated: `2026-09-27T14:45:01.540746+00:00`

Source: `codex/master-hello-full-review` at `28a18c70fb9b8b84eae6bfb18251eae3861cb008`

Inventory: 67 lifecycle jobs and 16 design capabilities.

Remaining `blocked_op` bindings: 0.

## Validator results

- `python3 appsec-review-process/validate_design_parity.py --check-generated-views`: **PASSED** (exit 0) — PASS for 67 lifecycle jobs and 16 design capabilities; explicit qualification gaps remain recorded.
- `python3 docs/processes/job_catalog.py --check`: **PASSED** (exit 0) — The generated job and artifact catalog is current.
- `python3 -B images/tool_pins.py check`: **PASSED** (exit 0) — All 14 pinned tool definitions verify against their retained locks and keys.
- `python3 -B images/registry_records.py check`: **PASSED** (exit 0) — All 21 host-local pinned image records verify against Docker and their successful build states.

## Complete feature inventory

| Feature | Type | Graph | Binding | Automatic inputs | Pool | Status | Exact remaining work |
|---|---|---:|---|---|---|---|---|
| `00-intake` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_QUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `02-ossf-scorecard` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_QUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `02-repository-partition-discovery` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_QUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `02-dev-project-discovery` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `02-devops-project-discovery` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `02-sre-operations-topology` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `02-build-index` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_QUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-build-classify` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | persona_llm | **INTEGRATED_QUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-build-plan` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | persona_llm | **INTEGRATED_QUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-build-resolution` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_QUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `02-evidence-assembly` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | persona_llm | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `01-component-characterization` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | persona_llm | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-full-review-input-assembly` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `03-threat-model-dfd-stride` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `03-threat-model-reconciliation` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `04-asvs-masvs` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | persona_llm | **INTEGRATED_UNQUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `05-native-memory` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `06-cve-reachability` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `13-fuzz-target-triage` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `15-deployment-hardening` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `claim-ledger-routing` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `07-red-team-adversarial` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | persona_llm | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `08-blue-team-refutation` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | persona_llm | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `09-independent-verification` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | persona_llm | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `11-remediation-proposal` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `12-scoring-prioritization` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | persona_llm | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `10-synthesis-report` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-api-collection-intelligence-ingest` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-binary-intelligence-ingest` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-doc-intelligence-ingest` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-standards-source-ingest` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-test-intelligence-ingest` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `04-owasp-validation-worklist` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `15-stig-srg-validation-worklist` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-build-configure` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_QUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-native-build` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_QUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-source-sast` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_QUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-code-property-graph` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-native-sast` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-ir-capture` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-ir-link` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-ir-facts` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-debug-symbol-index` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-binary-triage` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-binary-cfg` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-test-execution` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-test-result-ingest` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-test-coverage-ingest` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-operations-doc-ingest` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-evidence-index` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-secrets-inventory` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-iac-config-scan` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-container-image-inventory` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-sbom-inventory` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-sca-vulnerability-match` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-license-scan` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-dependency-lifecycle` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `02-binary-hardening` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `02-mobile-sast` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | docker | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `persona-tool-pool-dispatch` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | persona_llm | **INTEGRATED_UNQUALIFIED** | Close the retained qualification and coverage gaps listed for this job. |
| `deterministic-pool-merge` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `evidence-qualified-quorum` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `dynamic-rescope` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `completeness-audit` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `synthetic-hypothesis-resynthesis` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `remediation-retest-feedback` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `final-publication-gate` | lifecycle_job | True | actual_worker | LIFECYCLE_CONSTRUCTED | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this worker in the fresh Hello full_review run. |
| `common-worker-result-envelope` | design_capability | None | capability | CAPABILITY_DEPENDENT | unassigned | **INTEGRATED_UNQUALIFIED** | Add the next bounded contract-specific validation slice without broad worker migration. |
| `pinned-container-adapter-runtime` | design_capability | None | capability | CAPABILITY_DEPENDENT | docker | **INTEGRATED_QUALIFIED** | Adopt the qualified adapter in 02-build-resolution, then the bounded scanner workers. |
| `dedicated-resource-pools` | design_capability | None | capability | CAPABILITY_DEPENDENT | unassigned | **INTEGRATED_UNQUALIFIED** | Run live qualification step 8 (kill -9 of a run worker; docs/pools/resource-pools.md), then cross-check each manifest job pool against its op pool. |
| `persona-tool-pool-dispatch` | design_capability | None | capability | CAPABILITY_DEPENDENT | persona_llm | **INTEGRATED_UNQUALIFIED** | Execute and retain this capability in the fresh Hello full_review run. |
| `wait-all-rendezvous` | design_capability | None | capability | CAPABILITY_DEPENDENT | persona_llm | **INTEGRATED_UNQUALIFIED** | Execute and retain this capability in the fresh Hello full_review run. |
| `deterministic-pool-merge` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this capability in the fresh Hello full_review run. |
| `evidence-qualified-quorum` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this capability in the fresh Hello full_review run. |
| `claim-ledger-routing` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this capability in the fresh Hello full_review run. |
| `remediation-retest-feedback` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this capability in the fresh Hello full_review run. |
| `dynamic-rescope` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this capability in the fresh Hello full_review run. |
| `completeness-audit-control` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this capability in the fresh Hello full_review run. |
| `synthetic-hypothesis-resynthesis` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this capability in the fresh Hello full_review run. |
| `threat-model-standard` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this capability in the fresh Hello full_review run. |
| `owasp-checklist-model` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this capability in the fresh Hello full_review run. |
| `disa-nsa-hardening-model` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this capability in the fresh Hello full_review run. |
| `final-publication-gate` | design_capability | None | capability | CAPABILITY_DEPENDENT | cpu | **INTEGRATED_UNQUALIFIED** | Execute and retain this capability in the fresh Hello full_review run. |

The JSON companion contains implementation files, upstream/downstream bindings, envelope, permissions, qualification and retained-evidence fields for every row.
