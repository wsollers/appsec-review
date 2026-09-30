# ADR-0028 appendix: fingerprint comparison before and after the registry move

This file was generated for brief K by a one-off harness that is not kept in the repo. It compares
`main` at `54ab6ce` with branch `registry-move`. For every job it computes the parts of the prod
fingerprint that do not depend on a run:

- each lifecycle's implementation-hash map (`_code_hashes`, `code_hashes`, `_code`), for each job
  the lifecycle serves;
- `job_executor.own_hashes` and `related_hashes` for each item;
- `job_graph.definition_hash` for each template the graph names;
- `persona_invocation.composition_sha256` for each job template.

Hashes are the first 12 hex digits of the sha256 of the canonical JSON. For a changed map, the Cause
column lists the keys renamed from `registry/` to `pipeline/` (their file hashes are identical) and
the files whose content changed. A changed schema, contract or template would be marked
**NON-CODE VALUE CHANGED**; no row is.

Not covered because they need a run: the inline `code` maps in `ossf_scorecard.current_inputs` and
`critical_findings_sarif.current_inputs`, and `create_job_handoff` source records. All three key by
path, so they change the same way (see ADR-0028).

106 identical, 149 changed, of 255 fingerprint components.

| Component (lifecycle function and job/key) | Before | After | Cause |
|---|---|---|---|
| `analysis_feature_lifecycle._code(05-native-memory)` | `00a13bedad8c` | `9258cccc8d77` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `analysis_feature_lifecycle.py`, `dependency_workers.py` |
| `analysis_feature_lifecycle._code(06-cve-reachability)` | `5f154967ad5f` | `d5213e49adb5` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `analysis_feature_lifecycle.py`, `dependency_workers.py` |
| `analysis_feature_lifecycle._code(13-fuzz-target-triage)` | `afb16be0ab4c` | `79b4b715aa3a` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `analysis_feature_lifecycle.py`, `dependency_workers.py` |
| `attack_chain_composition._code_hashes()` | `fae27f9c1cdd` | `64bf8db56752` | 7 key(s) renamed registry/→pipeline/ (same hash); edited: `attack_chain_composition.py`, `attack_chain_pool.py`, `claim_ledger.py`, `mitre_feed.py` |
| `attack_chain_pool.code_hashes()` | `eae8a3ade19b` | `e97b1913b4be` | 5 key(s) renamed registry/→pipeline/ (same hash); edited: `attack_chain_pool.py`, `claim_ledger.py`, `mitre_feed.py`, `persona_invocation.py` |
| `attack_chain_refutation._code_hashes()` | `24c73bb44e85` | `febccd3d7cf9` | 8 key(s) renamed registry/→pipeline/ (same hash); edited: `attack_chain_composition.py`, `attack_chain_pool.py`, `attack_chain_refutation.py`, `claim_ledger.py`, `mitre_feed.py` |
| `b13_harmless._code_hashes()` | `d3f278b39df6` | `12db7b518c32` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `b13_harmless.py` |
| `binary_evidence_core._code_hashes(02-binary-cfg)` | `30741d54890a` | `9582234bfed1` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `binary_evidence_core.py` |
| `binary_evidence_core._code_hashes(02-binary-intelligence-ingest)` | `e49e93a5a853` | `46c1c966e3f9` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `binary_evidence_core.py` |
| `binary_evidence_core._code_hashes(02-binary-triage)` | `3ce2440baba3` | `4d9028b58f7f` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `binary_evidence_core.py` |
| `binary_evidence_core._code_hashes(02-debug-symbol-index)` | `77416662347c` | `276246466393` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `binary_evidence_core.py` |
| `build_classify._code_hashes()` | `12ef65201a8b` | `0288ca69b099` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `build_classify.py`, `build_index.py` |
| `build_index._code_hashes()` | `013e2010f69f` | `177f835d31db` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `build_index.py`, `intake.py`, `phase1.py` |
| `build_plan._code_hashes()` | `5cf683514ddf` | `4cd4be0ec366` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `build_classify.py`, `build_index.py`, `build_plan.py` |
| `build_replay._code_hashes(02-build-configure)` | `35e6d6554798` | `5cf9245e44b4` | 1 key(s) renamed registry/→pipeline/ (same hash); edited: `build_replay.py` |
| `build_replay._code_hashes(02-native-build)` | `306465b4e95f` | `7c5a380ad787` | 1 key(s) renamed registry/→pipeline/ (same hash); edited: `build_replay.py` |
| `build_resolution._code_hashes()` | `76bc489fa36b` | `0a53c29b4f08` | 1 key(s) renamed registry/→pipeline/ (same hash); edited: `build_plan.py`, `build_resolution.py` |
| `claim_ledger._code_hashes()` | `73f8d4b81f1f` | `79b24351dbba` | 4 key(s) renamed registry/→pipeline/ (same hash); edited: `claim_ledger.py`, `threat_model_core.py` |
| `claim_review_lifecycle._code_hashes(07-red-team-adversarial)` | `6e61c846da8c` | `0dc8d9917e60` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `claim_review_lifecycle.py`, `mitre_feed.py` |
| `claim_review_lifecycle._code_hashes(08-blue-team-refutation)` | `de038fabc019` | `715e83394b93` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `claim_review_lifecycle.py` |
| `claim_review_lifecycle._code_hashes(09-independent-verification)` | `005472915747` | `dc49f0710a0e` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `claim_review_lifecycle.py` |
| `claim_review_lifecycle._code_hashes(12-scoring-prioritization)` | `10404b6517ba` | `5edbb9b9d1d6` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `claim_review_lifecycle.py` |
| `claim_reviewer_pool._code_hashes()` | `4c869bc4836d` | `5d9610236933` | 4 key(s) renamed registry/→pipeline/ (same hash); edited: `claim_review_lifecycle.py`, `claim_reviewer_pool.py` |
| `codeql_sast._code_hashes(cpp)` | `a431ee810423` | `07e2cafc88b1` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `codeql_sast.py`, `native_sast.py` |
| `codeql_sast._code_hashes(csharp)` | `9cb767745b74` | `f486516b68e7` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `codeql_sast.py`, `native_sast.py` |
| `codeql_sast._code_hashes(go)` | `82c482ff3e03` | `641528843821` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `codeql_sast.py`, `native_sast.py` |
| `codeql_sast._code_hashes(java)` | `179816952506` | `c562045d1397` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `codeql_sast.py`, `native_sast.py` |
| `codeql_sast._code_hashes(javascript)` | `05e41159cece` | `93ed5bffad68` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `codeql_sast.py`, `native_sast.py` |
| `codeql_sast._code_hashes(python)` | `a5e1ae340ab0` | `37223749c5e7` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `codeql_sast.py`, `native_sast.py` |
| `codeql_sast._code_hashes(ruby)` | `08307480118d` | `7574111559ae` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `codeql_sast.py`, `native_sast.py` |
| `codeql_sast._code_hashes(rust)` | `fb6a70afa698` | `80c77848b9db` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `codeql_sast.py`, `native_sast.py` |
| `component_characterization._code_hashes()` | `5286c8f1c25e` | `20649b633357` | 4 key(s) renamed registry/→pipeline/ (same hash); edited: `component_characterization.py` |
| `control_feature_lifecycle._code(completeness-audit)` | `47356a3420a7` | `f4c49ceebf66` | 1 key(s) renamed registry/→pipeline/ (same hash); edited: `control_feature_lifecycle.py` |
| `control_feature_lifecycle._code(deterministic-pool-merge)` | `859a92bc6971` | `3861ce953248` | 1 key(s) renamed registry/→pipeline/ (same hash); edited: `control_feature_lifecycle.py` |
| `control_feature_lifecycle._code(dynamic-rescope)` | `ab0be56649ea` | `18d048c7d330` | 1 key(s) renamed registry/→pipeline/ (same hash); edited: `control_feature_lifecycle.py` |
| `control_feature_lifecycle._code(evidence-qualified-quorum)` | `1bea44c9e42e` | `3ec2988625dc` | 1 key(s) renamed registry/→pipeline/ (same hash); edited: `control_feature_lifecycle.py` |
| `control_feature_lifecycle._code(final-publication-preparation)` | `a4b974a2e065` | `2af0add30dab` | 1 key(s) renamed registry/→pipeline/ (same hash); edited: `control_feature_lifecycle.py` |
| `control_feature_lifecycle._code(remediation-retest-feedback)` | `f97ce8ab4c74` | `a6d75ded1c42` | 1 key(s) renamed registry/→pipeline/ (same hash); edited: `control_feature_lifecycle.py` |
| `control_feature_lifecycle._code(synthetic-hypothesis-resynthesis)` | `781655930b25` | `957ee912dd50` | 1 key(s) renamed registry/→pipeline/ (same hash); edited: `control_feature_lifecycle.py` |
| `evidence_assembly._code_hashes()` | `d1d30378da8b` | `366820e35efc` | 4 key(s) renamed registry/→pipeline/ (same hash); edited: `evidence_assembly.py` |
| `hypothesis_discovery._code_hashes()` | `c5dd4fdf1338` | `09e740e636d2` | 7 key(s) renamed registry/→pipeline/ (same hash); edited: `claim_ledger.py`, `hypothesis_discovery.py` |
| `ir_evidence._code_hashes(02-ir-capture)` | `6d127cc5840f` | `8a5e450b0097` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `ir_evidence.py` |
| `ir_evidence._code_hashes(02-ir-facts)` | `ec4ddee77ce2` | `cb1d60f5ed3b` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `ir_evidence.py` |
| `ir_evidence._code_hashes(02-ir-link)` | `15345d3313e7` | `526250ba72a0` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `ir_evidence.py` |
| `job_executor.own_hashes(02-operations-doc-ingest)` | `46f051409e28` | `985e871aa0e9` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `items/02-operations-doc-ingest/item.json`, `static_intelligence_core.py` |
| `job_executor.related_hashes(02-operations-doc-ingest)` | `44136fa355b3` | `44136fa355b3` | identical |
| `job_graph.definition_hash(00-intake)` | `00c4e0f48c88` | `efbd9d87a9cb` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(00-validation)` | `00ae8225948c` | `09eeef0ebcd2` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(01-component-characterization)` | `8e7c9c50fb89` | `3f5135d052d9` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-api-collection-intelligence-ingest)` | `32f3b84fe285` | `c0941ceb57ea` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-binary-cfg)` | `e026844ede02` | `a2bd3de64f0c` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-binary-hardening)` | `dfa334043fad` | `405dd17b4af8` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-binary-intelligence-ingest)` | `3554c48e19f5` | `a9d1873edfaf` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-binary-triage)` | `0fa059924336` | `e56dd2cb704c` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-build-classify)` | `342afafdc530` | `a3bb04447b88` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-build-configure)` | `5328df65e604` | `46bf3f71dbcf` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-build-index)` | `d3958615f111` | `63d0fdc1aa85` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-build-plan)` | `1d708f273516` | `60a8b7f71625` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-build-resolution)` | `790cbdf1fb9b` | `535022874b75` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-code-property-graph)` | `45df47905eca` | `cdae437c7e76` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-codeql-cpp)` | `d28c03f681a2` | `607dde501461` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-codeql-csharp)` | `460fde3a1511` | `216d397dca02` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-codeql-go)` | `3ffe1f1a2034` | `4233252c94e0` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-codeql-java)` | `37e57c190893` | `fb246fc521af` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-codeql-javascript)` | `373dd0c0dbeb` | `8f3adccccaf8` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-codeql-python)` | `179651e5e73d` | `1aaf196f8ace` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-codeql-ruby)` | `803f03242d8d` | `656d60fd9eff` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-codeql-rust)` | `01a47cbfdc2a` | `56411885ad32` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-container-image-inventory)` | `4809318f4615` | `7b5eb405e076` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-debug-symbol-index)` | `5c66b84f84a7` | `e6f78808dc34` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-dependency-lifecycle)` | `2e5fa12220c5` | `856f0aa9a251` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-dev-project-discovery)` | `91ee4f27a868` | `8e0bbea9cffb` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-devops-project-discovery)` | `118bed28f8be` | `28d444360cf5` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-doc-intelligence-ingest)` | `28470538dc45` | `393e723de0af` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-evidence-assembly)` | `cf92a7bac908` | `716bdc7ed739` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-evidence-index)` | `70a2fe096d40` | `60e1abf485b5` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-full-review-input-assembly)` | `236fc11ca3cb` | `268303aa2e59` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-iac-config-scan)` | `d821903cbeda` | `8e657119c789` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-ir-capture)` | `f86a2d2f6993` | `40e41bed4128` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-ir-facts)` | `8ecb19a3ba24` | `b133f6e903c8` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-ir-link)` | `07ab2b143b04` | `56ac5458cf06` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-license-scan)` | `6833bd7e6711` | `364f487aa93c` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-mobile-sast)` | `a763e2baa565` | `b3c1a33718a9` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-native-build)` | `3acbb4c7a94e` | `f7572d2c446a` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-native-sast)` | `8ca304bfaca6` | `9a8f5ca24728` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-operations-doc-ingest)` | `863d13c16172` | `260381521362` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-ossf-scorecard)` | `a4c614dccd14` | `8e27e863a444` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-repository-partition-discovery)` | `e99eead896cd` | `815c3b325e2b` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-sbom-inventory)` | `af9f64c8e1e3` | `9dbd37986eaf` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-sca-vulnerability-match)` | `ccdaeb2d8f67` | `73ed1cc3e4f2` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-secrets-inventory)` | `556d1253f9de` | `865c08a0e62b` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-source-sast)` | `76c2c8f3f492` | `47e6391182c9` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-sre-operations-topology)` | `3cad93d98dd0` | `660ac1368352` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-standards-source-ingest)` | `565f9e60ab12` | `fc6bca1c2198` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-test-coverage-ingest)` | `baff2ce2f584` | `fdf58461f95f` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-test-execution)` | `cb5439e347ea` | `0a4e91d26ca2` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-test-intelligence-ingest)` | `fcb7ea2fbd9b` | `915cc87d3004` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(02-test-result-ingest)` | `1e0e909d830e` | `528bb31fb58f` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(03-threat-model-dfd-stride)` | `0e49348cd07c` | `7acf2164775b` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(03-threat-model-reconciliation)` | `0faeea17745b` | `d36fd6198161` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(04-asvs-masvs)` | `37857d399289` | `1b3536c972d2` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(04-owasp-validation-worklist-core)` | `bae6c59d05a7` | `fd6fd834e9b1` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(05-native-memory)` | `2ca48e9ccfba` | `91e28b8b07c2` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(06-cve-reachability)` | `c696dcf96e00` | `2c97d2eb8706` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(06-reachability-codeql)` | `5615a8c10beb` | `7dfa7db03ca3` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(06-reachability-ir)` | `e7b3e681a724` | `4752162cd24f` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(07-hypothesis-discovery)` | `c0fe896b6c99` | `ae762ec4cbb5` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(07-red-team-adversarial)` | `036c1023d9a7` | `6268883305d6` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(08-blue-team-refutation)` | `5bd1f608bf95` | `995f341d715d` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(09-independent-verification)` | `9a27aa646711` | `287f808677de` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(10-synthesis-report)` | `58851d3ee1e9` | `27c43c252010` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(11-remediation-proposal)` | `c419009a2b90` | `c47a2bcef9ac` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(12-scoring-prioritization)` | `24fdae9281c9` | `947b37ab08c0` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(12b-poc-and-fix)` | `8ead66127fe3` | `6958f93f91d3` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(13-fuzz-target-triage)` | `a2cf757b6ff3` | `79ae34c3ffb4` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(14-attack-chain-composition)` | `cf50bdcc97a4` | `75123728db00` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(14-attack-chain-refutation)` | `39581609e1d2` | `d31a2f267064` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(15-deployment-hardening)` | `597a62874c81` | `8a694f5083c4` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(15-stig-srg-validation-worklist-core)` | `53ee62730dcd` | `e02087a914e3` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(claim-ledger-routing)` | `c62a323b6086` | `0eeba5003e90` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(completeness-audit)` | `7441cf8fa207` | `a0f7aedba3e3` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(deterministic-pool-merge)` | `02b33d721271` | `566b346eb100` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(dynamic-rescope)` | `16a3b277122b` | `95f916465307` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(evidence-qualified-quorum)` | `260c89b5c9f4` | `7d6f25197c68` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(final-publication-gate)` | `90891ae919c9` | `2f9fc8ab8db2` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(persona-tool-pool-dispatch)` | `bfab6770e280` | `d5dde326361b` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(remediation-retest-feedback)` | `06b5c0308bbf` | `c6de74b213bc` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `job_graph.definition_hash(synthetic-hypothesis-resynthesis)` | `e4b4de1c361d` | `2d1bc16bd548` | `files` key `appsec-review-process/job-graph.json` → `.../pipeline/job-graph.json`; `phase1.py`, `intake.py`, `job_graph.py`, `execution_state.py`, `orchestrator/dagster/definitions.py` edited |
| `joern_cpg._code()` | `b886260b69ee` | `2d948e300cb8` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `container_execution.py`, `joern_cpg.py` |
| `native_sast._code_hashes()` | `fc5afd8bebbc` | `55d4da18fa4c` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `native_sast.py` |
| `owasp_join_publisher._code_hashes()` | `2e5fd2fa96ac` | `44f585cee872` | 1 key(s) renamed registry/→pipeline/ (same hash); edited: `owasp_join_publisher.py` |
| `persona_invocation.composition_sha256(00-intake)` | `ce7fe12571c9` | `ce7fe12571c9` | identical |
| `persona_invocation.composition_sha256(00-validation)` | `5873b473b607` | `5873b473b607` | identical |
| `persona_invocation.composition_sha256(01-component-characterization)` | `3df0c8d06f9e` | `3df0c8d06f9e` | identical |
| `persona_invocation.composition_sha256(02-api-collection-intelligence-ingest)` | `804daedb9fde` | `804daedb9fde` | identical |
| `persona_invocation.composition_sha256(02-binary-cfg)` | `cf924ac8a30e` | `cf924ac8a30e` | identical |
| `persona_invocation.composition_sha256(02-binary-hardening)` | `4a58fd7be86e` | `4a58fd7be86e` | identical |
| `persona_invocation.composition_sha256(02-binary-intelligence-ingest)` | `f650c3c0a298` | `f650c3c0a298` | identical |
| `persona_invocation.composition_sha256(02-binary-triage)` | `a9799968bc1e` | `a9799968bc1e` | identical |
| `persona_invocation.composition_sha256(02-build-classify)` | `e00778d54677` | `e00778d54677` | identical |
| `persona_invocation.composition_sha256(02-build-configure)` | `cef822d15237` | `cef822d15237` | identical |
| `persona_invocation.composition_sha256(02-build-index)` | `39ba31427624` | `39ba31427624` | identical |
| `persona_invocation.composition_sha256(02-build-plan)` | `fa11d2fcafd5` | `fa11d2fcafd5` | identical |
| `persona_invocation.composition_sha256(02-build-resolution)` | `5b05410e64c5` | `5b05410e64c5` | identical |
| `persona_invocation.composition_sha256(02-code-property-graph)` | `530847ee9052` | `530847ee9052` | identical |
| `persona_invocation.composition_sha256(02-codeql-cpp)` | `76356c87db69` | `76356c87db69` | identical |
| `persona_invocation.composition_sha256(02-codeql-csharp)` | `293c4ec465b9` | `293c4ec465b9` | identical |
| `persona_invocation.composition_sha256(02-codeql-go)` | `dd9ada5415ea` | `dd9ada5415ea` | identical |
| `persona_invocation.composition_sha256(02-codeql-java)` | `3700fa887cb9` | `3700fa887cb9` | identical |
| `persona_invocation.composition_sha256(02-codeql-javascript)` | `08f29a6371d8` | `08f29a6371d8` | identical |
| `persona_invocation.composition_sha256(02-codeql-python)` | `d4ee41981497` | `d4ee41981497` | identical |
| `persona_invocation.composition_sha256(02-codeql-ruby)` | `b97c1d0e2237` | `b97c1d0e2237` | identical |
| `persona_invocation.composition_sha256(02-codeql-rust)` | `3ff483fbe7c9` | `3ff483fbe7c9` | identical |
| `persona_invocation.composition_sha256(02-container-image-inventory)` | `76dcb4b910ce` | `76dcb4b910ce` | identical |
| `persona_invocation.composition_sha256(02-debug-symbol-index)` | `dec492e3f72e` | `dec492e3f72e` | identical |
| `persona_invocation.composition_sha256(02-dependency-lifecycle)` | `27102e43de19` | `27102e43de19` | identical |
| `persona_invocation.composition_sha256(02-dev-project-discovery)` | `b7497183afd8` | `b7497183afd8` | identical |
| `persona_invocation.composition_sha256(02-devops-project-discovery)` | `402802d3b79d` | `402802d3b79d` | identical |
| `persona_invocation.composition_sha256(02-doc-intelligence-ingest)` | `35f928b864b0` | `35f928b864b0` | identical |
| `persona_invocation.composition_sha256(02-evidence-assembly)` | `fd07420d9051` | `fd07420d9051` | identical |
| `persona_invocation.composition_sha256(02-evidence-index)` | `a230b91ae0b1` | `a230b91ae0b1` | identical |
| `persona_invocation.composition_sha256(02-evidence-producer-binding)` | `4a2bb448643c` | `4a2bb448643c` | identical |
| `persona_invocation.composition_sha256(02-full-review-input-assembly)` | `e9831f391118` | `e9831f391118` | identical |
| `persona_invocation.composition_sha256(02-iac-config-scan)` | `8297a0710df0` | `8297a0710df0` | identical |
| `persona_invocation.composition_sha256(02-ir-capture)` | `3845b4259dae` | `3845b4259dae` | identical |
| `persona_invocation.composition_sha256(02-ir-facts)` | `520233ada89c` | `520233ada89c` | identical |
| `persona_invocation.composition_sha256(02-ir-link)` | `0d9a8f8e0d20` | `0d9a8f8e0d20` | identical |
| `persona_invocation.composition_sha256(02-license-scan)` | `bda1cff8bf15` | `bda1cff8bf15` | identical |
| `persona_invocation.composition_sha256(02-mobile-sast)` | `eacddf19ac62` | `eacddf19ac62` | identical |
| `persona_invocation.composition_sha256(02-native-build)` | `f58406e8a86e` | `f58406e8a86e` | identical |
| `persona_invocation.composition_sha256(02-native-sast)` | `5694c3401811` | `5694c3401811` | identical |
| `persona_invocation.composition_sha256(02-operations-doc-ingest)` | `4e113754edb6` | `4e113754edb6` | identical |
| `persona_invocation.composition_sha256(02-ossf-scorecard)` | `6ab89498168a` | `6ab89498168a` | identical |
| `persona_invocation.composition_sha256(02-repository-partition-discovery)` | `9a500f785b8e` | `9a500f785b8e` | identical |
| `persona_invocation.composition_sha256(02-sbom-inventory)` | `29023f179416` | `29023f179416` | identical |
| `persona_invocation.composition_sha256(02-sca-vulnerability-match)` | `99d4fae28682` | `99d4fae28682` | identical |
| `persona_invocation.composition_sha256(02-secrets-inventory)` | `59c53fadd20c` | `59c53fadd20c` | identical |
| `persona_invocation.composition_sha256(02-semantic-recall-index)` | `bf2a017ca778` | `bf2a017ca778` | identical |
| `persona_invocation.composition_sha256(02-source-sast)` | `3d8fefc895d3` | `3d8fefc895d3` | identical |
| `persona_invocation.composition_sha256(02-sre-operations-topology)` | `f5205e972d6c` | `f5205e972d6c` | identical |
| `persona_invocation.composition_sha256(02-standards-source-ingest)` | `1bb4d312a44f` | `1bb4d312a44f` | identical |
| `persona_invocation.composition_sha256(02-test-coverage-ingest)` | `fc088b1503dd` | `fc088b1503dd` | identical |
| `persona_invocation.composition_sha256(02-test-execution)` | `c50a9c61fdb8` | `c50a9c61fdb8` | identical |
| `persona_invocation.composition_sha256(02-test-intelligence-ingest)` | `cf84ac32ce04` | `cf84ac32ce04` | identical |
| `persona_invocation.composition_sha256(02-test-result-ingest)` | `a640aabd23d9` | `a640aabd23d9` | identical |
| `persona_invocation.composition_sha256(03-threat-model-dfd-stride)` | `7ed4bd6634e8` | `7ed4bd6634e8` | identical |
| `persona_invocation.composition_sha256(03-threat-model-reconciliation)` | `cd77cab41e95` | `cd77cab41e95` | identical |
| `persona_invocation.composition_sha256(04-asvs-masvs)` | `eb70bc842257` | `eb70bc842257` | identical |
| `persona_invocation.composition_sha256(04-owasp-component-routing)` | `b25b6ea4b640` | `b25b6ea4b640` | identical |
| `persona_invocation.composition_sha256(04-owasp-validation-worklist)` | `c5e76f3f24d8` | `c5e76f3f24d8` | identical |
| `persona_invocation.composition_sha256(04-owasp-validation-worklist-core)` | `f5fffc38213c` | `f5fffc38213c` | identical |
| `persona_invocation.composition_sha256(04-owasp-validator-cell)` | `d077efbf2711` | `d077efbf2711` | identical |
| `persona_invocation.composition_sha256(05-native-memory)` | `32cf5811ad45` | `32cf5811ad45` | identical |
| `persona_invocation.composition_sha256(06-cve-reachability)` | `b93a3ac6a354` | `b93a3ac6a354` | identical |
| `persona_invocation.composition_sha256(06-reachability-codeql)` | `4d6c9202d91c` | `4d6c9202d91c` | identical |
| `persona_invocation.composition_sha256(06-reachability-ir)` | `61fd9d9a6533` | `61fd9d9a6533` | identical |
| `persona_invocation.composition_sha256(07-hypothesis-discovery)` | `52eb0faa99f0` | `52eb0faa99f0` | identical |
| `persona_invocation.composition_sha256(07-red-team-adversarial)` | `de88cc7eed22` | `de88cc7eed22` | identical |
| `persona_invocation.composition_sha256(08-blue-team-refutation)` | `44823369e48e` | `44823369e48e` | identical |
| `persona_invocation.composition_sha256(09-independent-verification)` | `0bcb98c2d4ce` | `0bcb98c2d4ce` | identical |
| `persona_invocation.composition_sha256(10-critical-findings-sarif)` | `6d4a49c1b97f` | `6d4a49c1b97f` | identical |
| `persona_invocation.composition_sha256(10-report-input-assembly)` | `9028655358ca` | `9028655358ca` | identical |
| `persona_invocation.composition_sha256(10-synthesis-report)` | `7b905632f98a` | `7b905632f98a` | identical |
| `persona_invocation.composition_sha256(11-remediation-proposal)` | `0621e80df3cf` | `0621e80df3cf` | identical |
| `persona_invocation.composition_sha256(12-scoring-prioritization)` | `4a4643540ca3` | `4a4643540ca3` | identical |
| `persona_invocation.composition_sha256(12b-poc-and-fix)` | `2d689187c761` | `2d689187c761` | identical |
| `persona_invocation.composition_sha256(13-fuzz-target-triage)` | `dc430b5715ab` | `dc430b5715ab` | identical |
| `persona_invocation.composition_sha256(14-attack-chain-composition)` | `2d2642778d24` | `2d2642778d24` | identical |
| `persona_invocation.composition_sha256(14-attack-chain-refutation)` | `2357f52b6474` | `2357f52b6474` | identical |
| `persona_invocation.composition_sha256(15-deployment-hardening)` | `9deb8b38c69b` | `9deb8b38c69b` | identical |
| `persona_invocation.composition_sha256(15-stig-srg-validation-worklist)` | `43a5a3255368` | `43a5a3255368` | identical |
| `persona_invocation.composition_sha256(15-stig-srg-validation-worklist-core)` | `cae0fc3b1d19` | `cae0fc3b1d19` | identical |
| `persona_invocation.composition_sha256(attack-chain-composition-cell)` | `d9d74a00ea3b` | `d9d74a00ea3b` | identical |
| `persona_invocation.composition_sha256(attack-chain-refutation-cell)` | `3d0caf5ec733` | `3d0caf5ec733` | identical |
| `persona_invocation.composition_sha256(claim-ledger-routing)` | `7ba80b8f90b0` | `7ba80b8f90b0` | identical |
| `persona_invocation.composition_sha256(claim-review-pool-cell)` | `69d498e6c8bc` | `69d498e6c8bc` | identical |
| `persona_invocation.composition_sha256(completeness-audit)` | `73dc34d176ce` | `73dc34d176ce` | identical |
| `persona_invocation.composition_sha256(completeness-feedback)` | `4067cac890f1` | `4067cac890f1` | identical |
| `persona_invocation.composition_sha256(deterministic-pool-merge)` | `130939affc4e` | `130939affc4e` | identical |
| `persona_invocation.composition_sha256(dynamic-rescope)` | `4a2f7f3ce7ba` | `4a2f7f3ce7ba` | identical |
| `persona_invocation.composition_sha256(evidence-qualified-quorum)` | `558379f8b2cc` | `558379f8b2cc` | identical |
| `persona_invocation.composition_sha256(final-publication-gate)` | `4b181b234757` | `4b181b234757` | identical |
| `persona_invocation.composition_sha256(final-publication-preparation)` | `785f1c794cf0` | `785f1c794cf0` | identical |
| `persona_invocation.composition_sha256(hypothesis-hunt-general)` | `7a7540bf1d25` | `7a7540bf1d25` | identical |
| `persona_invocation.composition_sha256(hypothesis-hunt-known-list)` | `585ee612e5b3` | `585ee612e5b3` | identical |
| `persona_invocation.composition_sha256(intake-review-pool-cell)` | `ccf89a49c0a7` | `ccf89a49c0a7` | identical |
| `persona_invocation.composition_sha256(intake-review-pool-independent-cell)` | `bee70b3e942f` | `bee70b3e942f` | identical |
| `persona_invocation.composition_sha256(persona-tool-pool-dispatch)` | `8d17a36f795a` | `8d17a36f795a` | identical |
| `persona_invocation.composition_sha256(poc-and-fix-cell)` | `b9b79a77eab0` | `b9b79a77eab0` | identical |
| `persona_invocation.composition_sha256(remediation-retest-feedback)` | `e954e049fdf8` | `e954e049fdf8` | identical |
| `persona_invocation.composition_sha256(synthetic-hypothesis-resynthesis)` | `4c1088122684` | `4c1088122684` | identical |
| `persona_invocation.composition_sha256(threat-workbench-abuse-scenario-analyst)` | `2151614999b9` | `2151614999b9` | identical |
| `persona_invocation.composition_sha256(threat-workbench-attack-tree-builder)` | `8740d7b77693` | `8740d7b77693` | identical |
| `persona_invocation.composition_sha256(threat-workbench-deployment-topology-mapper)` | `ad0258c046a6` | `ad0258c046a6` | identical |
| `persona_invocation.composition_sha256(threat-workbench-pii-user-data-mapper)` | `0c85338efea0` | `0c85338efea0` | identical |
| `persona_invocation.composition_sha256(threat-workbench-supply-chain-specialist)` | `87d7cced311a` | `87d7cced311a` | identical |
| `persona_tool_pool_lifecycle._code_hashes()` | `c3e824e6533f` | `2de20a76c0b8` | 4 key(s) renamed registry/→pipeline/ (same hash); edited: `claim_reviewer_pool.py`, `control_lane_orchestration.py`, `persona_tool_pool_lifecycle.py` |
| `poc_fix_pool.code_hashes()` | `15902d94898c` | `95dbc5f7bc88` | 4 key(s) renamed registry/→pipeline/ (same hash); edited: `persona_invocation.py`, `poc_fix_pool.py` |
| `poc_fix_worker._code_hashes()` | `32c5fae44f93` | `dd6795a467a4` | 6 key(s) renamed registry/→pipeline/ (same hash); edited: `poc_fix_pool.py`, `poc_fix_worker.py` |
| `reachability_engine_jobs._code(codeql)` | `f3507267e0f7` | `d86ee791f7a2` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `codeql_sast.py`, `reachability_engine_jobs.py` |
| `reachability_engine_jobs._code(ir)` | `5d032d56d7e9` | `665cc2dc2f0f` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `codeql_sast.py`, `reachability_engine_jobs.py` |
| `remediation_proposal._code_hashes()` | `47491a23a550` | `89b01158eafc` | 1 key(s) renamed registry/→pipeline/ (same hash); edited: `build_replay.py`, `remediation_proposal.py` |
| `source_sast._code_hashes()` | `dcbd0f3355b9` | `a918ed8168f9` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `source_sast.py` |
| `standards_source_ingest._code_hashes()` | `8c99fc6681fe` | `9624f4da5443` | 4 key(s) renamed registry/→pipeline/ (same hash); edited: `standards_source_ingest.py` |
| `static_intelligence_core._code_hashes(02-api-collection-intelligence-ingest)` | `5b739d3ae0b9` | `57ffd51da6b8` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `static_intelligence_core.py` |
| `static_intelligence_core._code_hashes(02-doc-intelligence-ingest)` | `bb9d0adc4709` | `35bb3d1080e6` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `static_intelligence_core.py` |
| `static_intelligence_core._code_hashes(02-operations-doc-ingest)` | `d8e8149af950` | `48998fcae473` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `static_intelligence_core.py` |
| `static_intelligence_core._code_hashes(02-test-intelligence-ingest)` | `b96fd5d23d12` | `68418812506d` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `static_intelligence_core.py` |
| `synthesis_report_worker._code_hashes()` | `ec68056f7865` | `a5d2d04b4c25` | 2 key(s) renamed registry/→pipeline/ (same hash); edited: `synthesis_report.py`, `synthesis_report_worker.py` |
| `test_evidence.code_hashes(02-test-coverage-ingest)` | `71fc66e6a11e` | `ea75fefde6c6` | 3 key(s) renamed registry/→pipeline/ (same hash); edited: `container_execution.py`, `permission_capabilities.py`, `test_evidence.py` |
| `test_evidence.code_hashes(02-test-execution)` | `2e91dd2669a9` | `7a7f8a559c43` | 3 key(s) renamed registry/→pipeline/ (same hash); edited: `container_execution.py`, `permission_capabilities.py`, `test_evidence.py` |
| `test_evidence.code_hashes(02-test-result-ingest)` | `7ac02b06e859` | `b3938dd21667` | 3 key(s) renamed registry/→pipeline/ (same hash); edited: `container_execution.py`, `permission_capabilities.py`, `test_evidence.py` |
| `threat_model_core._code_hashes()` | `a2226bf1991c` | `e5a6e59eeb70` | 12 key(s) renamed registry/→pipeline/ (same hash); edited: `component_characterization.py`, `threat_model_core.py`, `threat_workbench.py` |
| `threat_model_reconciliation._code_hashes()` | `3da3f6255b55` | `fe5d82e95a62` | 4 key(s) renamed registry/→pipeline/ (same hash); edited: `component_characterization.py`, `threat_model_core.py`, `threat_model_reconciliation.py` |
| `threat_workbench.code_hashes()` | `307d730db361` | `08d9d22dcdbd` | 8 key(s) renamed registry/→pipeline/ (same hash); edited: `threat_workbench.py` |
