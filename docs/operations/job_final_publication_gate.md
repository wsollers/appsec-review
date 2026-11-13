---
title: "final_publication_gate"
kind: "operations"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_final_publication_gate"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# final_publication_gate

This page contains the generated contract; the authored process and acceptance description are tracked by [T-130](../TODO.md).

<!-- generated:begin job=job_final_publication_gate -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

final_publication_gate

Job: `job_final_publication_gate`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_final_publication_gate/job.py#L123) |
| `gate` | `gate.classify` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_final_publication_gate/job.py#L116) |
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
| `job_inference_security_review` | `review_audit_metadata` | `appsec-review/review-audit-publication/1` | handoff | optional | gap |
| `job_inference_security_review` | `review_decision_audit` | `appsec-review/review-audit-manifest/1` | handoff | optional | not_applicable |
| `job_inference_security_review` | `review_decisions` | `appsec-review/review-decision/1` | handoff | optional | not_applicable |
| `job_inference_security_review` | `review_verification_coverage` | `appsec-review/verification-coverage/1` | handoff | optional | not_applicable |
| `job_inference_security_review` | `review_decision_bases` | `appsec-review/decision-basis/1` | handoff | optional | not_applicable |
| `job_inference_security_review` | `review_audit_continuations` | `application/x-ndjson` | handoff | optional | not_applicable |
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
| unit | `tests/test_final_report.py::test_a_clean_review_is_publishable_and_not_run_stages_never_change_that`<br>`tests/test_final_report.py::test_package_counts_reject_a_package_in_no_bucket`<br>`tests/test_final_report.py::test_unrated_unscored_and_empty_reviews_are_named_gaps` |

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
  output0["publication_gate_decisions"]
  output_schema0["appsec-review/final-publication-gate/2"]
  job --> output0
  output0 -. schema .-> output_schema0
```

<!-- generated:end -->
