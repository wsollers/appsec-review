---
title: "final_publication_gate"
kind: "operations"
subsystem: "reporting and metrics"
status: "current"
jobs: ["job_final_publication_gate"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# final_publication_gate

## Purpose

Certify a publication partition over the accepted inference review and commissioned completion
artifacts. Confirmed findings may be publishable, supported findings remain an unconfirmed
verification backlog, and unverifiable referenced outcome classes are withheld. The gate does
not re-adjudicate claims, recompute scores, change shipment decisions or certify runtime proof.

<!-- generated:begin job=job_final_publication_gate -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

final_publication_gate

Job: `job_final_publication_gate`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_final_publication_gate/job.py#L131) |
| `gate` | `gate.classify` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_final_publication_gate/job.py#L124) |
| `load` | `load.verify_review` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_final_publication_gate/job.py#L64) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_language_build` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_dossier_publication` | `handoff` | `appsec-review/job-handoff/2` | handoff | when_producer_enabled | reject |
| `job_dossier_publication` | `dossier_publications` | `appsec-review/dossier-publication/1` | handoff | optional | gap |
| `job_inference_security_review` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
| `job_inference_security_review` | `accepted_scope` | `appsec-review/inference-review-accepted-scope/1` | handoff | optional | gap |
| `job_inference_security_review` | `lead_triage` | `application/json` | handoff | optional | gap |
| `job_inference_security_review` | `review_packages` | `appsec-review/review-package/6` | handoff | optional | gap |
| `job_inference_security_review` | `review_cells` | `appsec-review/cell-attempt-receipt/1` | handoff | optional | gap |
| `job_inference_security_review` | `claim_ledger` | `appsec-review/ledger-event/1` | handoff | optional | gap |
| `job_inference_security_review` | `attack_chains` | `appsec-review/attack-chain-manifest/1` | handoff | optional | gap |
| `job_inference_security_review` | `scores_and_findings` | `appsec-review/finding-package/2` | handoff | optional | gap |
| `job_inference_security_review` | `review_audit_metadata` | `appsec-review/review-audit-publication/1` | handoff | when_output_declared | gap |
| `job_inference_security_review` | `review_decision_audit` | `appsec-review/review-audit-manifest/1` | handoff | when_output_declared | not_applicable |
| `job_inference_security_review` | `review_decisions` | `appsec-review/review-decision/1` | handoff | when_output_declared | not_applicable |
| `job_inference_security_review` | `review_verification_coverage` | `appsec-review/verification-coverage/1` | handoff | when_output_declared | not_applicable |
| `job_inference_security_review` | `review_decision_bases` | `appsec-review/decision-basis/1` | handoff | when_output_declared | not_applicable |
| `job_inference_security_review` | `review_audit_continuations` | `application/x-ndjson` | handoff | when_output_declared | not_applicable |
| `job_poc_generation` | `handoff` | `appsec-review/job-handoff/2` | handoff | when_producer_enabled | reject |
| `job_poc_generation` | `poc_generation_summary` | `appsec-review/poc-generation-handoff/2` | handoff | optional | gap |
| `job_poc_generation` | `poc_writer_cells` | `appsec-review/poc-writer-receipt/1` | handoff | optional | gap |
| `job_poc_generation` | `poc_reproducers` | `appsec-review/poc-provenance/2` | handoff | optional | gap |
| `job_remediation_planning` | `handoff` | `appsec-review/job-handoff/2` | handoff | when_producer_enabled | reject |
| `job_remediation_planning` | `remediation_planning_summary` | `appsec-review/remediation-planning/1` | handoff | optional | gap |
| `job_remediation_planning` | `remediation_proposals` | `appsec-review/remediation-plan/1` | handoff | optional | gap |
| `job_remediation_validation` | `handoff` | `appsec-review/job-handoff/2` | handoff | when_producer_enabled | reject |
| `job_remediation_validation` | `remediation_validation_summary` | `appsec-review/remediation-validations/1` | handoff | optional | gap |
| `job_remediation_validation` | `remediation_validation_receipts` | `appsec-review/remediation-validation/1` | handoff | optional | gap |
| `job_artifact_security_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_artifact_security_analysis` | `artifact_security_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_ci_configuration_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_ci_configuration_analysis` | `ci_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_clang_static_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_clang_static_analysis` | `clang_static_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_codeql_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_codeql_analysis` | `codeql_observations` | `appsec-review/codeql-sarif-normalizer/3` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `infer_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_evidence_collection` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_evidence_collection` | `static_tool_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_post_build_security_assessment` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_post_build_security_assessment` | `build_security` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_review_data_indexing` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_review_data_indexing` | `precomputed_products` | `appsec-review/retrieval-index/2` | handoff | optional | gap |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `publication_gate_decisions` | `acceptance` | `appsec-review/final-publication-gate/2` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | `tests/test_final_report.py::test_gate_accounts_for_every_package_in_exactly_one_bucket` |
| integration | None declared |
| live | None declared |
| unit | `tests/test_final_report.py::test_a_clean_review_is_publishable_and_not_run_stages_never_change_that`<br>`tests/test_final_report.py::test_package_counts_reject_a_package_in_no_bucket`<br>`tests/test_final_report.py::test_unrated_unscored_and_empty_reviews_are_named_gaps`<br>`tests/unit/review_decision_audit_wiring/test_classification.py`<br>`tests/unit/review_decision_audit_wiring/test_gate_handler.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_dossier_publication`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_final_publication_gate"]
  producer0["job_language_build"]
  input0["handoff"]
  input_schema0["appsec-review/job-handoff/2"]
  producer0 --> input0 --> job
  input0 -. schema .-> input_schema0
  producer1["job_dossier_publication"]
  input1["handoff"]
  input_schema1["appsec-review/job-handoff/2"]
  producer1 --> input1 --> job
  input1 -. schema .-> input_schema1
  producer2["job_dossier_publication"]
  input2["dossier_publications"]
  input_schema2["appsec-review/dossier-publication/1"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_inference_security_review"]
  input3["handoff"]
  input_schema3["appsec-review/job-handoff/2"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  producer4["job_inference_security_review"]
  input4["accepted_scope"]
  input_schema4["appsec-review/inference-review-accepted-scope/1"]
  producer4 --> input4 --> job
  input4 -. schema .-> input_schema4
  producer5["job_inference_security_review"]
  input5["lead_triage"]
  input_schema5["application/json"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_inference_security_review"]
  input6["review_packages"]
  input_schema6["appsec-review/review-package/6"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_inference_security_review"]
  input7["review_cells"]
  input_schema7["appsec-review/cell-attempt-receipt/1"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_inference_security_review"]
  input8["claim_ledger"]
  input_schema8["appsec-review/ledger-event/1"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_inference_security_review"]
  input9["attack_chains"]
  input_schema9["appsec-review/attack-chain-manifest/1"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_inference_security_review"]
  input10["scores_and_findings"]
  input_schema10["appsec-review/finding-package/2"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_inference_security_review"]
  input11["review_audit_metadata"]
  input_schema11["appsec-review/review-audit-publication/1"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_inference_security_review"]
  input12["review_decision_audit"]
  input_schema12["appsec-review/review-audit-manifest/1"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_inference_security_review"]
  input13["review_decisions"]
  input_schema13["appsec-review/review-decision/1"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_inference_security_review"]
  input14["review_verification_coverage"]
  input_schema14["appsec-review/verification-coverage/1"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_inference_security_review"]
  input15["review_decision_bases"]
  input_schema15["appsec-review/decision-basis/1"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_inference_security_review"]
  input16["review_audit_continuations"]
  input_schema16["application/x-ndjson"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  producer17["job_poc_generation"]
  input17["handoff"]
  input_schema17["appsec-review/job-handoff/2"]
  producer17 --> input17 --> job
  input17 -. schema .-> input_schema17
  producer18["job_poc_generation"]
  input18["poc_generation_summary"]
  input_schema18["appsec-review/poc-generation-handoff/2"]
  producer18 --> input18 --> job
  input18 -. schema .-> input_schema18
  producer19["job_poc_generation"]
  input19["poc_writer_cells"]
  input_schema19["appsec-review/poc-writer-receipt/1"]
  producer19 --> input19 --> job
  input19 -. schema .-> input_schema19
  producer20["job_poc_generation"]
  input20["poc_reproducers"]
  input_schema20["appsec-review/poc-provenance/2"]
  producer20 --> input20 --> job
  input20 -. schema .-> input_schema20
  producer21["job_remediation_planning"]
  input21["handoff"]
  input_schema21["appsec-review/job-handoff/2"]
  producer21 --> input21 --> job
  input21 -. schema .-> input_schema21
  producer22["job_remediation_planning"]
  input22["remediation_planning_summary"]
  input_schema22["appsec-review/remediation-planning/1"]
  producer22 --> input22 --> job
  input22 -. schema .-> input_schema22
  producer23["job_remediation_planning"]
  input23["remediation_proposals"]
  input_schema23["appsec-review/remediation-plan/1"]
  producer23 --> input23 --> job
  input23 -. schema .-> input_schema23
  producer24["job_remediation_validation"]
  input24["handoff"]
  input_schema24["appsec-review/job-handoff/2"]
  producer24 --> input24 --> job
  input24 -. schema .-> input_schema24
  producer25["job_remediation_validation"]
  input25["remediation_validation_summary"]
  input_schema25["appsec-review/remediation-validations/1"]
  producer25 --> input25 --> job
  input25 -. schema .-> input_schema25
  producer26["job_remediation_validation"]
  input26["remediation_validation_receipts"]
  input_schema26["appsec-review/remediation-validation/1"]
  producer26 --> input26 --> job
  input26 -. schema .-> input_schema26
  producer27["job_artifact_security_analysis"]
  input27["handoff"]
  input_schema27["appsec-review/job-handoff/2"]
  producer27 --> input27 --> job
  input27 -. schema .-> input_schema27
  producer28["job_artifact_security_analysis"]
  input28["artifact_security_observations"]
  input_schema28["appsec-review/retrieval-index/2"]
  producer28 --> input28 --> job
  input28 -. schema .-> input_schema28
  producer29["job_ci_configuration_analysis"]
  input29["handoff"]
  input_schema29["appsec-review/job-handoff/2"]
  producer29 --> input29 --> job
  input29 -. schema .-> input_schema29
  producer30["job_ci_configuration_analysis"]
  input30["ci_observations"]
  input_schema30["appsec-review/retrieval-index/2"]
  producer30 --> input30 --> job
  input30 -. schema .-> input_schema30
  producer31["job_clang_static_analysis"]
  input31["handoff"]
  input_schema31["appsec-review/job-handoff/2"]
  producer31 --> input31 --> job
  input31 -. schema .-> input_schema31
  producer32["job_clang_static_analysis"]
  input32["clang_static_observations"]
  input_schema32["appsec-review/retrieval-index/2"]
  producer32 --> input32 --> job
  input32 -. schema .-> input_schema32
  producer33["job_codeql_analysis"]
  input33["handoff"]
  input_schema33["appsec-review/job-handoff/2"]
  producer33 --> input33 --> job
  input33 -. schema .-> input_schema33
  producer34["job_codeql_analysis"]
  input34["codeql_observations"]
  input_schema34["appsec-review/codeql-sarif-normalizer/3"]
  producer34 --> input34 --> job
  input34 -. schema .-> input_schema34
  producer35["job_cpp_compiled_analysis"]
  input35["handoff"]
  input_schema35["appsec-review/job-handoff/2"]
  producer35 --> input35 --> job
  input35 -. schema .-> input_schema35
  producer36["job_cpp_compiled_analysis"]
  input36["infer_observations"]
  input_schema36["appsec-review/retrieval-index/2"]
  producer36 --> input36 --> job
  input36 -. schema .-> input_schema36
  producer37["job_evidence_collection"]
  input37["handoff"]
  input_schema37["appsec-review/job-handoff/2"]
  producer37 --> input37 --> job
  input37 -. schema .-> input_schema37
  producer38["job_evidence_collection"]
  input38["static_tool_observations"]
  input_schema38["appsec-review/retrieval-index/2"]
  producer38 --> input38 --> job
  input38 -. schema .-> input_schema38
  producer39["job_post_build_security_assessment"]
  input39["handoff"]
  input_schema39["appsec-review/job-handoff/2"]
  producer39 --> input39 --> job
  input39 -. schema .-> input_schema39
  producer40["job_post_build_security_assessment"]
  input40["build_security"]
  input_schema40["appsec-review/retrieval-index/2"]
  producer40 --> input40 --> job
  input40 -. schema .-> input_schema40
  producer41["job_review_data_indexing"]
  input41["handoff"]
  input_schema41["appsec-review/job-handoff/2"]
  producer41 --> input41 --> job
  input41 -. schema .-> input_schema41
  producer42["job_review_data_indexing"]
  input42["precomputed_products"]
  input_schema42["appsec-review/retrieval-index/2"]
  producer42 --> input42 --> job
  input42 -. schema .-> input_schema42
  output0["publication_gate_decisions"]
  output_schema0["appsec-review/final-publication-gate/2"]
  job --> output0
  output0 -. schema .-> output_schema0
```

<!-- generated:end -->

## Process

See the [handler](../../src/appsec_review/jobs/job_final_publication_gate/job.py),
[attachment verifier](../../src/appsec_review/jobs/job_final_publication_gate/attachments.py) and
[classifier](../../src/appsec_review/jobs/job_final_publication_gate/classify.py).

### `load`

1. In `load.verify_review`, reverify the accepted review from bound bytes, including ledger,
   projection, packages, scores, evidence and coverage; enforce the package bound.
2. Read and bind the frozen configuration. Determine enabled completion producers from it;
   attack-chain work is always part of the accepted review. An explicit PoC upstream pin also
   commissions that otherwise optional producer.
3. Verify attachments and their exact review/finding identities. Reject missing enabled producer
   handoffs under the typed contract and reject corrupt, mismatched or unbound attachments.
   Disabled producers are not silently discovered as evidence.
4. Write the verified snapshot with capabilities, attachments and every binding.

### `gate`

1. In `gate.classify`, preserve each accepted claim state and ship-block result.
2. Withhold a package if its referenced PoC outcome or attack-chain identity is unavailable.
   Otherwise place confirmed intake in `publishable` and supported intake in
   `verification_backlog`. Reject a package outside its accepted partition.
3. Count exact, disjoint buckets. Derive ordered limitations from review/lane completeness,
   ledger gaps, coverage, scores, independence, duplicate pairs and completion capability status.
   Keep `gap`, `not_run` and `notice` distinct.

### `acceptance`

1. In `acceptance.publish_handoff`, rebuild the gate document and reverify the loaded snapshot.
2. Validate its schema and require bucket totals to equal the package count.
3. Publish the immutable `publication_gate_decisions` artifact. Only limitations of kind `gap`
   enter the handler's gap list; notices do not turn into execution claims or clean-target proof.

## Dataflow

```mermaid
flowchart LR
  job["job_final_publication_gate"] --> load["load.verify_review"]
  review["job_inference_security_review / scores_and_findings"] --> load
  artifacts["job_dossier_publication / dossier_publications"] --> load
  load --> classify["gate.classify"]
  classify --> buckets["publishable / verification_backlog / withheld"]
  buckets --> accept["acceptance.publish_handoff"]
  classify -. "gap / not_run / notice" .-> limitations["limitations"]
  limitations --> accept
  accept --> out["publication_gate_decisions"]
  load -. "failed admission or integrity" .-> reject["reject publication"]
  accept -. "partition mismatch" .-> reject
```

The generated contract lists all possible completion inputs; the
[accepted-input boundary](../architecture/job-input-contracts.md#admission-and-read-receipts)
decides which bytes this attempt may use. Verified bindings are not new retrieval grants.

## Gaps

The classifier emits limitation IDs, not new `producer-gap/1` codes. Handler gap strings have
no source-supplied retryability classification. See
[interchange outcomes](../architecture/job-interchange.md#the-control-layer-beneath-the-envelope).

| Limitation IDs or reason | Scope and walk meaning |
| --- | --- |
| `review_degraded`, `review_empty`, `review_incomplete`, `lane_degraded` | Review/lane completion; emptiness or failed coverage is never clean. |
| `gaps_recorded`, `coverage_incomplete` | Ledger gap classes and nonreviewed hunt-coverage rows. |
| `pending_distinct_verification` | Finding cannot receive the stronger shipment disposition without required independent verification. |
| `technical_severity_unrated`, `decision_pending`, `findings_without_scores` | Missing scoring or decision evidence, not low severity. |
| `withheld_packages`, `possible_duplicates` | Referenced outcome class unavailable, or unresolved duplicate pair. |
| `poc_generation_gap`, `attack_chains_gap`, `remediation_planning_gap`, `remediation_validation_gap`, `dossiers_gap` | Accepted completion capability has gaps/omissions. |
| `poc_lane_not_run`, `attack_chain_composition_not_run`, `remediation_planning_not_run`, `remediation_validation_not_run`, `dossiers_not_run` | `not_run` limitations when the capability is policy-skipped; not converted to handler gaps. |
| `compile_only_nonexecution` | Notice: generated PoCs, controls and remediation regressions were not executed. |

Withheld reasons are `poc_outcome_unavailable` and `attack_chain_unavailable`. Corrupt referenced
bytes or failed enabled-input admission are errors, not withheld-success substitutes.

## Acceptance

1. **A. Inputs:** Compare the claim's review and commissioned-producer pins with verified handoffs;
   verify frozen configuration, explicit PoC admission and the complete attachment binding set.
2. **B. Independent comparison:** Independently enumerate the accepted review's confirmed and
   supported partitions. Reconcile every finding-package ID into exactly one gate bucket, compare
   hashes and unchanged state/score/ship-block values, and resolve each withheld reason against the
   accepted PoC/chain manifests.
3. **C. Gaps:** Group verified canonical outcomes and compare limitation IDs/counts with ledger
   gaps, coverage rows, score absence and completion omissions. Record `not_run` and notices
   separately; stop for unconfirmed expected causes.
4. **D. Baseline:** Save an authorized `stepwise.py accept` baseline with corpus namespace, gate
   hash, input hashes, bucket memberships and limitation counts. A later partition diff must
   identify the changed accepted evidence, not merely a different display status.

## Resume and invalidation

There is no model or gate-specific semantic cache. Exact accepted handoffs, frozen configuration,
component identities and bindings govern [runtime reuse](../architecture/jobs-and-runtime.md#wave-1-resumability).
Changing review evidence, commissioned producer identity or enablement requires recertification;
unchanged upstream computation need not be rerun just to rebuild this projection. The publication
unit rechecks the snapshot rather than trusting its earlier classification. Artifact-bearing
results are not portable failed-attempt checkpoints.
