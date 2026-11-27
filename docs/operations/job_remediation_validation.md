---
title: "remediation_validation"
kind: "operations"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_remediation_validation"]
last reconciled: "ea03df9695991eafe37065717624278af845a74c"
---

# remediation_validation

## Purpose

Validate an accepted inert remediation proposal through exact scratch application, independent
semantic assessment and, where commissioned and safe, before/after native syntax checks.
`build_checked` is not runtime proof, a fixed finding or a changed ship-block decision.
Generated regression specifications remain unexecuted.

The static artifact is `appsec-review/remediation-static-patch-validation/2`. It reports lexical
checks, Python-only AST parsing, detected function-name retention and added guard-like text.
Other languages have unknown syntax validity, not a clean AST. Function names do not prove
signature preservation; guard patterns do not prove dominance or a corrected sink. Supplied
patched text alone does not prove diff applicability; the job separately verifies exact edits.
This artifact can report only `static_checked` or `rejected`, retains its limitations and
`runtime_verified: false`, and cannot promote the independent semantic or native-build result.

<!-- generated:begin job=job_remediation_validation -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

remediation_validation

Job: `job_remediation_validation`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `lifecycle` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_remediation_validation/job.py#L328) |
| `assess` | `assess.validate` | 1 | `inference_teams` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_remediation_validation/job.py#L311) |
| `load` | `load.verify_inputs` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_remediation_validation/job.py#L84) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_inference_security_review` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
| `job_inference_security_review` | `accepted_scope` | `appsec-review/inference-review-accepted-scope/1` | handoff | optional | gap |
| `job_inference_security_review` | `lead_triage` | `application/json` | handoff | optional | gap |
| `job_inference_security_review` | `review_packages` | `appsec-review/review-package/7` | handoff | optional | gap |
| `job_inference_security_review` | `review_cells` | `appsec-review/cell-attempt-receipt/1` | handoff | optional | gap |
| `job_inference_security_review` | `claim_ledger` | `appsec-review/ledger-event/1` | handoff | optional | gap |
| `job_inference_security_review` | `attack_chains` | `appsec-review/attack-chain-manifest/1` | handoff | optional | gap |
| `job_inference_security_review` | `scores_and_findings` | `appsec-review/finding-package/2` | handoff | optional | gap |
| `job_language_build` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_language_build` | `topology_refinement_inputs` | `appsec-review/build-topology-refinement/1` | handoff | optional | gap |
| `job_language_build` | `build_actions` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_language_build` | `jvm_build_actions` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_language_build` | `language_build_receipts` | `appsec-review/language-build-handoff/2` | handoff | optional | gap |
| `job_language_build` | `build_workspaces` | `application/octet-stream` | handoff | optional | gap |
| `job_remediation_planning` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
| `job_remediation_planning` | `remediation_planning_summary` | `appsec-review/remediation-planning/1` | handoff | optional | gap |
| `job_remediation_planning` | `remediation_proposals` | `appsec-review/remediation-plan/1` | handoff | optional | gap |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `remediation_validation_receipts` | `assess` | `appsec-review/remediation-validation/1` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `remediation_validation_summary` | `acceptance` | `appsec-review/remediation-validations/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

These are job-level declarations; exact per-task selection is not declared ([T-147](../TODO.md)).

```json
{}
```

- Role: [remediation_reviewer](../generated/guidance.md#roles-remediation_reviewer).
- Task prompt: `remediation_assessment`.
- Runtime skill: [stateful-invariant-analysis](../generated/guidance.md#runtime_skills-stateful-invariant-analysis).

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | `tests/test_remediation_jobs.py::test_real_runner_publishes_build_checked_without_changing_original_state_or_shipment` |
| integration | None declared |
| live | None declared |
| unit | `tests/unit/job_remediation_validation/test_source_context.py`<br>`tests/unit/job_remediation_validation/test_patch_lexical_edges.py`<br>`tests/test_cpp_memory_safety_rules.py`<br>`tests/test_remediation_compiler.py`<br>`tests/test_remediation_models.py`<br>`tests/test_remediation_patches.py`<br>`tests/unit/job_remediation_validation/test_coverage_edges.py`<br>`tests/unit/job_remediation_validation/test_execution_receipts.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_remediation_planning`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_remediation_validation"]
  producer0["job_inference_security_review"]
  input0["handoff"]
  input_schema0["appsec-review/job-handoff/2"]
  producer0 --> input0 --> job
  input0 -. schema .-> input_schema0
  producer1["job_inference_security_review"]
  input1["accepted_scope"]
  input_schema1["appsec-review/inference-review-accepted-scope/1"]
  producer1 --> input1 --> job
  input1 -. schema .-> input_schema1
  producer2["job_inference_security_review"]
  input2["lead_triage"]
  input_schema2["application/json"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_inference_security_review"]
  input3["review_packages"]
  input_schema3["appsec-review/review-package/7"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  producer4["job_inference_security_review"]
  input4["review_cells"]
  input_schema4["appsec-review/cell-attempt-receipt/1"]
  producer4 --> input4 --> job
  input4 -. schema .-> input_schema4
  producer5["job_inference_security_review"]
  input5["claim_ledger"]
  input_schema5["appsec-review/ledger-event/1"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_inference_security_review"]
  input6["attack_chains"]
  input_schema6["appsec-review/attack-chain-manifest/1"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_inference_security_review"]
  input7["scores_and_findings"]
  input_schema7["appsec-review/finding-package/2"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_language_build"]
  input8["handoff"]
  input_schema8["appsec-review/job-handoff/2"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_language_build"]
  input9["topology_refinement_inputs"]
  input_schema9["appsec-review/build-topology-refinement/1"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_language_build"]
  input10["build_actions"]
  input_schema10["appsec-review/retrieval-index/2"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_language_build"]
  input11["jvm_build_actions"]
  input_schema11["appsec-review/retrieval-index/2"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_language_build"]
  input12["language_build_receipts"]
  input_schema12["appsec-review/language-build-handoff/2"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_language_build"]
  input13["build_workspaces"]
  input_schema13["application/octet-stream"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_remediation_planning"]
  input14["handoff"]
  input_schema14["appsec-review/job-handoff/2"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_remediation_planning"]
  input15["remediation_planning_summary"]
  input_schema15["appsec-review/remediation-planning/1"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_remediation_planning"]
  input16["remediation_proposals"]
  input_schema16["appsec-review/remediation-plan/1"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  output0["remediation_validation_receipts"]
  output_schema0["appsec-review/remediation-validation/1"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["remediation_validation_summary"]
  output_schema1["appsec-review/remediation-validations/1"]
  job --> output1
  output1 -. schema .-> output_schema1
```

<!-- generated:end -->

## Process

See the [handler](../../src/appsec_review/jobs/job_remediation_validation/job.py),
[compiler adapter](../../src/appsec_review/jobs/job_remediation_validation/compiler.py) and
[workspace custody](../../src/appsec_review/jobs/job_remediation_validation/workspace.py).

### `load`

1. In `load.verify_inputs`, verify the accepted review and planning handoff, including their
   exact confirmed-finding partition and planning-to-review identity.
2. Record bounded candidate/proposal counts and write an immutable input snapshot.
   Missing required producers or incompatible accepted artifacts fail admission.

### `assess`

1. In `assess.validate`, emit one outcome for every planning item. Candidate overflow and missing
   proposals remain `manual_validation_required` with explicit reasons.
2. Verify each plan, adjudication, evidence relations and source context against the accepted
   finding. Parse the exact patch; reject changed baseline hashes, fuzzy edits or invalid scope.
3. Re-admit the complete source context against validation's own `max_source_files`,
   `max_source_bytes` and `max_file_bytes`, even if planning used larger limits. Compare exact
   UTF-8 bytes, source hashes and build identities with the run-owned accepted workspace.
   Refuse an over-budget context before source copying or model dispatch, with a named
   manual-validation reason; never truncate, normalize line endings or silently drop evidence.
   Require a single accepted build identity, distinct from an individual translation-unit
   command identity. Select the affected compile context from patch paths; unmodified related
   files in that same build do not make a proposal multi-build. Foreign-build contexts and
   executable build/tool configuration mutations still require manual validation.
4. Materialize bounded baseline and patched scratch workspaces. Apply exact declared edits only;
   verify untouched files and absence proofs. Check UTF-8 source policy, NUL bytes, new conflict
   markers and the declared edit set.
   Exact-patch baseline reads also enforce `max_file_bytes` before hashing, including during
   scope verification after source admission. Growth past the bound is refused, not fully read
   merely because an earlier admission fit the budget.
5. Ask the independent reviewer about the accepted invariant, evidence and patch. Missing/unresolved
   review is `inconclusive`; contradiction is `rejected`. A supported assessment permits
   `static_checked`, not an assertion of a successful fix.
6. Only if `native_syntax` is commissioned and every changed file is the accepted exact
   translation unit, compare identical pinned before/after syntax checks. Baseline failure is
   inconclusive; patched failure is rejected; unsafe replay needs manual validation.
   The command's cwd comes from the hash-bound protected compile row's recorded
   `working_directory`, mapped from `/workspace` or a canonical workspace-relative directory.
   Recipe build directories, relative include flags and source roots are not substitutes.
   Relative include options use that cwd; the source's own header directory is already
   workspace-relative and is not prefixed with the cwd a second time.
   Historical rows without a resolvable recorded cwd have no usable compile command; they
   retain an explicit source/command gap rather than an invented exact context.
   Both passing gives `build_checked`, with no linking or runtime regression.
   The adapter admits compiler exit `1` as a negative comparison result under first-error
   safety, not a review-wide stop or compile success. Abnormal exits, timeouts, transport and
   cleanup failures, and explicit cancellation still stop; `ReviewStopped` is never swallowed.
7. Always clean scratch state and retain cleanup/check receipts. Failed cleanup or compiler
   modification of source is an integrity failure. Preserve regression-compile and runtime
   dimensions as not performed rather than filling them with a passing value.
   Bounded compiler streams and outcome receipts live in the protected host-only
   `<item>/compiler-execution/<container>/` sibling of `scratch/`; each attempted phase in
   `build-comparison.json` binds those files through `execution_evidence` references.
   The receipt directory cannot overlap any container mount. Full baseline/patched manifest
   comparison remains exact, including `.appsec-*` additions or modifications.

### `acceptance`

1. In `acceptance.publish_handoff`, reload review and planning and require both accepted pins to
   match the loaded snapshot. Reverify review and validation/check/cleanup references.
2. Require exactly one ordered outcome for each planning finding triple; validate each document.
3. Publish immutable `remediation_validation_summary` with row gaps. Empty intake is `SKIPPED_NA`;
   neither empty nor build-checked output modifies adjudication or shipment state.

## Dataflow

```mermaid
flowchart LR
  job["job_remediation_validation"] --> load["load.verify_inputs"]
  plans["job_remediation_planning / remediation_planning_summary"] --> load
  review["job_inference_security_review / scores_and_findings"] --> load
  load --> assess["assess.validate"]
  builds["job_language_build / build_workspaces"] --> assess
  assess --> receipts["remediation_validation_receipts"]
  receipts --> accept["acceptance.publish_handoff"]
  accept --> summary["remediation_validation_summary"]
  assess -. "manual / inconclusive / rejected / static only" .-> gaps["gap_ids"]
  gaps --> accept
  assess -. "baseline / undeclared edit / cleanup integrity" .-> reject["reject publication"]
```

Source access follows [accepted input admission](../architecture/job-input-contracts.md#admission-and-read-receipts).
Native execution uses the accepted build's [pinned image](image-pin-verification.md#the-gate)
and [signing enforcement](signing.md#container-images), not an arbitrary compiler command.

## Gaps

These are legacy row/plan strings, without a producer-supplied retryability classification.
See [canonical outcome semantics](../architecture/job-interchange.md#the-control-layer-beneath-the-envelope).

| Reason or outcome | Scope and walk meaning |
| --- | --- |
| `remediation_validation:<claim>:candidate_bound_reached`, `proposal_unavailable` | Candidate never reached substantive validation. |
| `remediation_validation:<claim>:<status>` for non-`build_checked` status | Named candidate lacks the strongest commissioned compile-only result. |
| `run_owned_source_unavailable`, `multi_build_proposal_requires_manual_validation`, workspace-limit reason | Source or adapter scope unavailable. |
| `source_file_bound_reached`, `source_byte_bound_reached` | Complete accepted context exceeds validation's own source/file budget; no reviewer or compiler was dispatched. |
| `unsafe_build_configuration_mutation`, `patch_scope_not_covered_by_native_adapter`, `accepted_build_profile_uncommissioned`, `accepted_build_replay_unsafe` | Manual validation boundary, not a successful bypass. |
| `patch_rejected`, `static_patch_policy_failed`, `analyst_assessed_contradicted`, `patched_build_failed` | Proposal rejected; the original vulnerability claim is not refuted by this. |
| `independent_semantic_review_unavailable`, `analyst_assessed_unresolved`, `baseline_build_failed` | Inconclusive evidence, not proof the patch fails or succeeds. |
| `selected_static_checks_only`, `build_unavailable_static_checks_only` | Static/semantic subset only; inspect individual check states. |
| Inherited plan/source gaps | Retain planning coverage limitations. |

The runtime-regression policy notice and uncommissioned regression compilation are explicit check
dimensions, not invented producer-gap codes. Integrity/admission failures block publication.
Cross-revision fixed-state verification is separately tracked by [T-061/T-074](../TODO.md);
this compile-only job does not implement that verdict.

## Acceptance

1. **A. Inputs:** Compare review/planning pins, finding/adjudication identities, patch/source hashes,
   build command/image identity and configured adapters with the admitted snapshot.
2. **B. Independent comparison:** Independently enumerate planning items and require one validation
   row each. Compare exact edits and scratch manifests with the accepted baseline; inspect
   semantic citations and before/after compiler receipts. Require identical compiler conditions,
   unchanged original source, successful cleanup and explicit nonexecution dimensions.
3. **C. Gaps:** Reconcile canonical outcomes with row reasons and each check's status. Distinguish
   baseline failure, patch failure, manual policy boundary and static-only coverage. Stop on
   unexpected causes; `build_checked` never substitutes for runtime proof.
4. **D. Baseline:** Save an authorized `stepwise.py accept` baseline and corpus namespace with
   plan/validation hashes, outcome partition and per-check evidence. Preserve the unchanged
   review state and shipment decisions in the comparison.

## Resume and invalidation

No standalone validation semantic cache or sub-job unit salvage is implemented. Whole-job
[runtime reuse](../architecture/jobs-and-runtime.md#wave-1-resumability) binds accepted
review/planning/build handoffs, source, configuration (up to compatible `[operational.*]` tuning),
dataset contract, and implementation/schema/validation identities. Any failed or invalidated job
re-executes in a fresh `attempts/<attempt_id>/` workspace with clean scratch trees, reloads
accepted inputs at publication, and refuses to overwrite attempt-owned artifacts.

The capture serializer `src/appsec_review/jobs/job_language_build/native.py` is mounted application
source (`PYTHONPATH=/opt/app/src` in [`deploy/dagster/Dockerfile`](../../deploy/dagster/Dockerfile)
and [`compose.yaml`](../../deploy/dagster/compose.yaml)), deployed via signed-source reload at an
explicit run boundary without rewriting immutable compile rows, whereas changes to
`containers/tools/native-cpp/native.py` ([Dockerfile](../../containers/tools/native-cpp/Dockerfile))
require a `tool-native-cpp` image rollout. See [job-local operational tuning](job-tuning.md) and
[remediation](remediation.md#tuning-and-whole-job-recovery-job_remediation_validation).
## In-memory patch checks

C++ numeric digit separators are recognized as numeric tokens rather than character quotes;
character/string closure, comment stripping and prohibited-call checks remain separate lexical
checks, not a C++ parser or compiler verdict. The production job still uses `apply_exact` and
passes `after_text` to its static validator.

The exported `apply_unified_diff_in_memory` helper is a separate, nonexecuting API, not the
production job's application path. It anchors zero-context insertions after the named old
line, checks both old/new ranges and counts, preserves line endings and explicit no-final-newline
markers, and refuses truncated hunk records or overlapping/mismatched context. An unterminated
patch payload is not an implicit no-final-newline marker. Passing its unit tests does not establish
that a live validation job used unified diffs.

## Model usage

The selected [remediation_reviewer](../generated/guidance.md#roles-remediation_reviewer) receives
accepted evidence, the invariant and exact patch, independently of the planning conversation.
No persona or stack is selected. Its closed answer cites accepted relation IDs and classifies
semantic support, contradiction or uncertainty; it cannot change claim state or commission
runtime tests. See [worker contracts](../architecture/worker-prompt-contracts.md#dispatch-inventory)
and [pinned guidance](../architecture/guidance-procedures.md#selection-and-provenance).
