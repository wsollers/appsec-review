---
title: "openvex_export"
kind: "operations"
subsystem: "reporting and metrics"
status: "current"
jobs: ["job_openvex_export"]
last reconciled: "ea03df9695991eafe37065717624278af845a74c"
---

# openvex_export

## Purpose

The primary document exports all and only the accepted gate's publishable confirmed packages as
OpenVEX `affected` statements, one per package. A protected companion accounts for backlog and
withheld packages, evidence, scoring, shipment decisions and coverage. This projection cannot infer `fixed`,
`not_affected` or runtime exploitation; automatic tool authorship is not vendor attestation.

<!-- generated:begin job=job_openvex_export -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

openvex_export

Job: `job_openvex_export`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_openvex_export/job.py#L247) |
| `export` | `export.assemble` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_openvex_export/job.py#L247) |
| `load` | `load.verify_inputs` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_openvex_export/job.py#L247) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_review_intake` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | not_applicable |
| `job_dependency_intelligence` | `sca_reachability` | `appsec-review/sca-reachability/1` | handoff | optional | not_applicable |
| `job_final_publication_gate` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
| `job_final_publication_gate` | `publication_gate_decisions` | `appsec-review/final-publication-gate/2` | handoff | optional | gap |
| `job_inference_security_review` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
| `job_inference_security_review` | `accepted_scope` | `appsec-review/inference-review-accepted-scope/1` | handoff | optional | gap |
| `job_inference_security_review` | `lead_triage` | `application/json` | handoff | optional | gap |
| `job_inference_security_review` | `review_packages` | `appsec-review/review-package/7` | handoff | optional | gap |
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
| `job_dependency_intelligence` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_dependency_intelligence` | `native_advisory_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_evidence_collection` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_evidence_collection` | `static_tool_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_post_build_security_assessment` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_post_build_security_assessment` | `build_security` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_review_data_indexing` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_review_data_indexing` | `precomputed_products` | `appsec-review/retrieval-index/2` | handoff | optional | gap |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `openvex_dependency_accounting` | `export` | `appsec-review/openvex-dependencies/1` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `openvex_dependency_documents` | `export` | `https://openvex.dev/ns/v0.2.0` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `openvex_documents` | `export` | `https://openvex.dev/ns/v0.2.0` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `openvex_export_accounting` | `acceptance` | `appsec-review/openvex-export-result/1` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `openvex_verified_inputs` | `load` | `appsec-review/openvex-verified-inputs/1` | protected | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | None declared |
| integration | None declared |
| live | None declared |
| unit | `tests/test_openvex_contracts.py`<br>`tests/test_openvex_inputs.py`<br>`tests/test_openvex_job_units.py`<br>`tests/test_openvex_metrics.py`<br>`tests/test_openvex_projection.py`<br>`tests/test_openvex_settings.py`<br>`tests/test_openvex_wiring.py`<br>`tests/unit/job_openvex_export/test_coverage_edges.py`<br>`tests/unit/job_openvex_export/test_dependency_publication.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_final_publication_gate`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_openvex_export"]
  producer0["job_review_intake"]
  input0["handoff"]
  input_schema0["appsec-review/job-handoff/2"]
  producer0 --> input0 --> job
  input0 -. schema .-> input_schema0
  producer1["job_dependency_intelligence"]
  input1["sca_reachability"]
  input_schema1["appsec-review/sca-reachability/1"]
  producer1 --> input1 --> job
  input1 -. schema .-> input_schema1
  producer2["job_final_publication_gate"]
  input2["handoff"]
  input_schema2["appsec-review/job-handoff/2"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_final_publication_gate"]
  input3["publication_gate_decisions"]
  input_schema3["appsec-review/final-publication-gate/2"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  producer4["job_inference_security_review"]
  input4["handoff"]
  input_schema4["appsec-review/job-handoff/2"]
  producer4 --> input4 --> job
  input4 -. schema .-> input_schema4
  producer5["job_inference_security_review"]
  input5["accepted_scope"]
  input_schema5["appsec-review/inference-review-accepted-scope/1"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_inference_security_review"]
  input6["lead_triage"]
  input_schema6["application/json"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_inference_security_review"]
  input7["review_packages"]
  input_schema7["appsec-review/review-package/7"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_inference_security_review"]
  input8["review_cells"]
  input_schema8["appsec-review/cell-attempt-receipt/1"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_inference_security_review"]
  input9["claim_ledger"]
  input_schema9["appsec-review/ledger-event/1"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_inference_security_review"]
  input10["attack_chains"]
  input_schema10["appsec-review/attack-chain-manifest/1"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_inference_security_review"]
  input11["scores_and_findings"]
  input_schema11["appsec-review/finding-package/2"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_inference_security_review"]
  input12["review_audit_metadata"]
  input_schema12["appsec-review/review-audit-publication/1"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_inference_security_review"]
  input13["review_decision_audit"]
  input_schema13["appsec-review/review-audit-manifest/1"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_inference_security_review"]
  input14["review_decisions"]
  input_schema14["appsec-review/review-decision/1"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_inference_security_review"]
  input15["review_verification_coverage"]
  input_schema15["appsec-review/verification-coverage/1"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_inference_security_review"]
  input16["review_decision_bases"]
  input_schema16["appsec-review/decision-basis/1"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  producer17["job_inference_security_review"]
  input17["review_audit_continuations"]
  input_schema17["application/x-ndjson"]
  producer17 --> input17 --> job
  input17 -. schema .-> input_schema17
  producer18["job_artifact_security_analysis"]
  input18["handoff"]
  input_schema18["appsec-review/job-handoff/2"]
  producer18 --> input18 --> job
  input18 -. schema .-> input_schema18
  producer19["job_artifact_security_analysis"]
  input19["artifact_security_observations"]
  input_schema19["appsec-review/retrieval-index/2"]
  producer19 --> input19 --> job
  input19 -. schema .-> input_schema19
  producer20["job_ci_configuration_analysis"]
  input20["handoff"]
  input_schema20["appsec-review/job-handoff/2"]
  producer20 --> input20 --> job
  input20 -. schema .-> input_schema20
  producer21["job_ci_configuration_analysis"]
  input21["ci_observations"]
  input_schema21["appsec-review/retrieval-index/2"]
  producer21 --> input21 --> job
  input21 -. schema .-> input_schema21
  producer22["job_clang_static_analysis"]
  input22["handoff"]
  input_schema22["appsec-review/job-handoff/2"]
  producer22 --> input22 --> job
  input22 -. schema .-> input_schema22
  producer23["job_clang_static_analysis"]
  input23["clang_static_observations"]
  input_schema23["appsec-review/retrieval-index/2"]
  producer23 --> input23 --> job
  input23 -. schema .-> input_schema23
  producer24["job_codeql_analysis"]
  input24["handoff"]
  input_schema24["appsec-review/job-handoff/2"]
  producer24 --> input24 --> job
  input24 -. schema .-> input_schema24
  producer25["job_codeql_analysis"]
  input25["codeql_observations"]
  input_schema25["appsec-review/codeql-sarif-normalizer/3"]
  producer25 --> input25 --> job
  input25 -. schema .-> input_schema25
  producer26["job_cpp_compiled_analysis"]
  input26["handoff"]
  input_schema26["appsec-review/job-handoff/2"]
  producer26 --> input26 --> job
  input26 -. schema .-> input_schema26
  producer27["job_cpp_compiled_analysis"]
  input27["infer_observations"]
  input_schema27["appsec-review/retrieval-index/2"]
  producer27 --> input27 --> job
  input27 -. schema .-> input_schema27
  producer28["job_dependency_intelligence"]
  input28["handoff"]
  input_schema28["appsec-review/job-handoff/2"]
  producer28 --> input28 --> job
  input28 -. schema .-> input_schema28
  producer29["job_dependency_intelligence"]
  input29["native_advisory_observations"]
  input_schema29["appsec-review/retrieval-index/2"]
  producer29 --> input29 --> job
  input29 -. schema .-> input_schema29
  producer30["job_evidence_collection"]
  input30["handoff"]
  input_schema30["appsec-review/job-handoff/2"]
  producer30 --> input30 --> job
  input30 -. schema .-> input_schema30
  producer31["job_evidence_collection"]
  input31["static_tool_observations"]
  input_schema31["appsec-review/retrieval-index/2"]
  producer31 --> input31 --> job
  input31 -. schema .-> input_schema31
  producer32["job_post_build_security_assessment"]
  input32["handoff"]
  input_schema32["appsec-review/job-handoff/2"]
  producer32 --> input32 --> job
  input32 -. schema .-> input_schema32
  producer33["job_post_build_security_assessment"]
  input33["build_security"]
  input_schema33["appsec-review/retrieval-index/2"]
  producer33 --> input33 --> job
  input33 -. schema .-> input_schema33
  producer34["job_review_data_indexing"]
  input34["handoff"]
  input_schema34["appsec-review/job-handoff/2"]
  producer34 --> input34 --> job
  input34 -. schema .-> input_schema34
  producer35["job_review_data_indexing"]
  input35["precomputed_products"]
  input_schema35["appsec-review/retrieval-index/2"]
  producer35 --> input35 --> job
  input35 -. schema .-> input_schema35
  output0["openvex_dependency_accounting"]
  output_schema0["appsec-review/openvex-dependencies/1"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["openvex_dependency_documents"]
  output_schema1["https://openvex.dev/ns/v0.2.0"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["openvex_documents"]
  output_schema2["https://openvex.dev/ns/v0.2.0"]
  job --> output2
  output2 -. schema .-> output_schema2
  output3["openvex_export_accounting"]
  output_schema3["appsec-review/openvex-export-result/1"]
  job --> output3
  output3 -. schema .-> output_schema3
  output4["openvex_verified_inputs"]
  output_schema4["appsec-review/openvex-verified-inputs/1"]
  job --> output4
  output4 -. schema .-> output_schema4
```

<!-- generated:end -->

## Process

See the [handler](../../src/appsec_review/jobs/job_openvex_export/job.py),
[bounded verifier](../../src/appsec_review/jobs/job_openvex_export/inputs.py) and
[pure projector](../../src/appsec_review/jobs/job_openvex_export/projection.py).

### `load`

1. In `load.verify_inputs`, require enabled typed settings and a valid attempt deadline.
   Verify accepted gate/review identities, source scope, frozen configuration, finding partitions
   and every certified binding through the bounded input reader.
2. Measure the input inventory and reprove it. Missing, stale, tampered or escaping inputs fail
   closed. Input-byte ceilings are not enforced: the legacy `max_artifact_bytes` and
   `max_total_input_bytes` settings remain in frozen configurations, but do not reject larger
   admitted inputs. Hash-only inventory checks stream their bytes rather than retain whole
   artifacts in memory. Binding/package counts, deadlines and output-size limits still apply;
   no package is skipped to make the export fit.
3. Verify and copy the pinned offline schema resources, upstream lock and license into this
   attempt. Write immutable `openvex_verified_inputs`; no network schema lookup occurs.

The optional dependency companion reads `sca_reachability` from the admitted
`job_dependency_intelligence` handoff's `outputs["acceptance.publish_handoff"]`.
An unsupplied dependency handoff produces no companion; a supplied handoff without the
reachability reference is rejected. Its accepted bytes must match the certified configuration
and target snapshot; a newer accepted pointer does not replace the admitted handoff.

This companion is separate from the confirmed-finding export. Its CVE decisions distinguish
`affected`, `not_affected` and `under_investigation`; `not_affected` requires an explicit
`unreachable_in_target` determination with complete, gap-free target coverage. Missing or
degraded evidence cannot supply that negative. The current bounded static source-use producer
retains its static-only coverage limitation, so absence of a call is not such a determination.
Both companion bytes and its admitted source identity are rechecked at acceptance; its gaps
remain separate from the primary document's statement count.

### `export`

1. In `export.assemble`, reprove the loaded inventory and schema copies. Check source/configuration
   identities and exact gate counts/bucket membership.
2. Derive product identity from reviewed repository identity, target snapshot and resolved
   configuration. Use the gate completion timestamp, not the current export clock.
3. Emit an `affected` statement for each `publishable` package. Retain all other packages as
   exclusions with `gate_verification_backlog` or `gate_withheld`, not alternate VEX statuses.
4. If no statements exist, emit result and companion only, with `document = null`.
   Otherwise emit canonical document bytes. Validate schema and semantic accounting, then write
   exclusive immutable outputs with byte/size/hash verification.

### `acceptance`

1. In `acceptance.publish_handoff`, reprove inputs and reassemble the expected export from
   the same frozen settings and exporter release.
2. Compare result identity and every emitted file byte for byte with the canonical assembly.
   For an empty export, reject even an unexpected document file or symlink.
3. Reprove inputs again and enforce the deadline. Publish the hash-bound accounting reference
   with inherited gate gaps and the no-statements reason where applicable.

## Dataflow

```mermaid
flowchart LR
  job["job_openvex_export"] --> load["load.verify_inputs"]
  gate["job_final_publication_gate / publication_gate_decisions"] --> load
  review["job_inference_security_review / scores_and_findings"] --> load
  dependency["optional admitted sca_reachability"] --> load
  load --> inputs["openvex_verified_inputs"]
  inputs --> assemble["export.assemble"]
  assemble --> documents["openvex_documents"]
  assemble --> companion["separate dependency CVE document + accounting"]
  companion --> accept
  assemble -. "no publishable confirmed packages" .-> empty["document = null"]
  documents --> accept["acceptance.publish_handoff"]
  empty --> accept
  accept --> result["openvex_export_accounting"]
  load -. "admission / integrity / bounds" .-> reject["reject publication"]
  accept -. "canonical bytes differ" .-> reject
```

This is a deterministic artifact projection: no model, scanner, subprocess or container is
dispatched. See [input admission](../architecture/job-input-contracts.md#admission-and-read-receipts),
[signing versus byte binding](signing.md#mechanism) and the existing
[specification qualification](../architecture/openvex-export.md#3-verified-upstream-specification-and-validation-pin).

## Gaps

Successful result gaps are legacy IDs without a source-supplied retryability classification:
the gate's limitation IDs of kind `gap`, and
`openvex_no_publishable_confirmed_findings` when the document is absent. `no_statements` is
accounted absence, not a clean-product declaration. `not_run` limitations and the compile-only
notice stay in companion context, not the export gap set.

`configuration_invalid`, `input_missing`, `input_stale`, `input_tampered`, `identity_conflict`,
`schema_invalid`, `semantic_invalid`, `bound_exceeded`, `timed_out`, `io_error` and
`internal_error` are failure-event reason values from `ExportFailureReason`, **not**
source-emitted producer-gap codes. They fail the attempt; there is no success-shaped partial
export for corrupted inputs. Interpret canonical
[outcomes](../architecture/job-interchange.md#the-control-layer-beneath-the-envelope) separately.

## Acceptance

1. **A. Inputs:** Compare gate/review handoff pins, accepted manifest, source snapshot, full resolved
   configuration hash, semantic review settings and schema resource hashes with the verified
   inventory. Confirm author/action/source identity come from the frozen policy.
2. **B. Independent comparison:** Independently enumerate gate publishable IDs and require an
   exact one-to-one statement mapping. Check backlog/withheld exclusion totals and all package
   evidence/score references. Recompute product, timestamp and canonical document identities;
   zero eligible packages must mean no document, not an empty document called success.
3. **C. Gaps:** Compare canonical outcomes and companion gap IDs with gate gap limitations.
   Account for no-statements explicitly; do not count `not_run` or nonexecution notices as new
   vulnerability evidence. Any failed verification stops the walk.
4. **D. Baseline:** Save an authorized `stepwise.py accept` baseline with corpus namespace,
   gate/export hashes, source/configuration identity, included/excluded IDs and statement counts.
   Retain historical immutable output when a newer gate makes current export status stale.

## Resume and invalidation

There is no exporter-specific semantic cache or sub-job unit salvage. Whole-job
[runtime admission](../architecture/jobs-and-runtime.md#wave-1-resumability) and streaming input
reproof bind accepted gate/review handoffs, source/configuration (including compatible operational
configuration revisions), dataset contract, settings, ten pinned schema/license/lock digests and
exporter release; any failed or invalidated export re-executes in full inside a fresh
`attempts/<attempt_id>/` workspace, refusing development-tainted inputs and never overwriting
different historical bytes. See [job-local operational tuning](job-tuning.md) and
[openvex-export](../architecture/openvex-export.md#tuning-and-whole-job-recovery-job_openvex_export).
