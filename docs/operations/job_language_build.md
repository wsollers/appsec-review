---
title: "language_build"
kind: "operations"
subsystem: "target acquisition and build"
status: "current"
jobs: ["job_language_build"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---

# language_build

## Purpose

What did the admitted build units actually execute and produce, with what source, toolchain,
capture and product dependencies? Language-build publishes verified receipts and build indices,
reusing project-owned native/Unity executions where appropriate. It refuses to call a successful
driver exit complete compiler capture, an existing file a newly built output, or a compiled
artifact proof of runtime shipment, reachability or security.

<!-- generated:begin job=job_language_build -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

language_build

Job: `job_language_build`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L2084) |
| `execute` | `execute.dotnet` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1980) |
| `execute` | `execute.go` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1980) |
| `execute` | `execute.java` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1980) |
| `execute` | `execute.native` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1980) |
| `execute` | `execute.node` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1980) |
| `execute` | `execute.php` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1980) |
| `execute` | `execute.python` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1980) |
| `execute` | `execute.rust` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1980) |
| `execute` | `execute.wasm` | 1 | `cpp_build` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1980) |
| `iterations` | `iterations.dispatch` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1876) |
| `load` | `load.dotnet` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1888) |
| `load` | `load.go` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1888) |
| `load` | `load.java` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1888) |
| `load` | `load.native` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1888) |
| `load` | `load.node` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1888) |
| `load` | `load.php` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1888) |
| `load` | `load.python` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1888) |
| `load` | `load.rust` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1888) |
| `load` | `load.wasm` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_language_build/job.py#L1888) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_build_environment_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_build_environment_analysis` | `build_environment` | `appsec-review/build-environment-analysis/1` | handoff | optional | gap |
| `job_project_build` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
| `job_project_build` | `topology_refinement_inputs` | `appsec-review/build-topology-refinement/1` | handoff | optional | gap |
| `job_project_build` | `project_build_dispatch` | `appsec-review/project-build-dispatch/3` | handoff | optional | gap |
| `job_project_build` | `probe_workspaces` | `application/octet-stream` | handoff | optional | gap |
| `job_project_build` | `image_build_streams` | `text/plain` | handoff | optional | gap |
| `job_review_intake` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_review_intake` | `model_preflight` | `appsec-review/model-preflight/1` | handoff | optional | gap |
| `job_review_intake` | `binary_evidence` | `appsec-review/binary-evidence-intake/1` | handoff | optional | gap |
| `job_review_intake` | `review_intake` | `appsec-review/review-intake/1` | handoff | optional | gap |
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

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `build_actions` | `acceptance` | `appsec-review/retrieval-index/2` | indexed | `build` | `find`, `query_precomputed`, `trace` |
| `build_workspaces` | `execute` | `application/octet-stream` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `jvm_build_actions` | `execute` | `appsec-review/retrieval-index/2` | indexed | `build` | `find`, `trace` |
| `language_build_receipts` | `acceptance` | `appsec-review/language-build-handoff/2` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `topology_refinement_inputs` | `execute` | `appsec-review/build-topology-refinement/1` | protected | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | `tests/acceptance/job_project_build/test_family_project_builds.py` |
| integration | `tests/integration/job_language_build/test_language_build_graph.py`<br>`tests/integration/job_language_build/test_native_outputs_graph.py`<br>`tests/integration/job_language_build/test_go_graph.py`<br>`tests/integration/job_language_build/test_jvm_graph.py`<br>`tests/integration/job_language_build/test_node_graph.py`<br>`tests/integration/job_language_build/test_php_graph.py`<br>`tests/integration/job_language_build/test_python_graph.py`<br>`tests/integration/job_language_build/test_rust_graph.py`<br>`tests/integration/job_language_build/test_wasm_graph.py`<br>`tests/integration/job_language_build/test_elf_host.py` |
| live | `tests/acceptance/job_language_build/test_live_build_toolchains.py`<br>`tests/acceptance/job_language_build/test_live_gradle_provenance.py` |
| unit | `tests/unit/job_language_build/test_contract.py`<br>`tests/unit/job_language_build/test_job_graph.py`<br>`tests/unit/job_language_build/test_job_helpers.py`<br>`tests/unit/job_language_build/test_receipts_and_paths.py`<br>`tests/unit/job_language_build/test_build_output_mapping.py`<br>`tests/unit/job_language_build/test_build_output_scope.py`<br>`tests/unit/job_language_build/test_captured_build_reconciliation.py`<br>`tests/unit/job_language_build/test_elf.py`<br>`tests/unit/job_language_build/test_go.py`<br>`tests/unit/job_language_build/test_go_build_facts.py`<br>`tests/unit/job_language_build/test_go_dependency_output_filtering.py`<br>`tests/unit/job_language_build/test_go_vendored.py`<br>`tests/unit/job_language_build/test_gradle_provenance.py`<br>`tests/unit/job_language_build/test_jvm.py`<br>`tests/unit/job_language_build/test_native_layout.py`<br>`tests/unit/job_language_build/test_native_outputs.py`<br>`tests/unit/job_language_build/test_node.py`<br>`tests/unit/job_language_build/test_node_dependency_output_filtering.py`<br>`tests/unit/job_language_build/test_node_installed.py`<br>`tests/unit/job_language_build/test_node_scripts.py`<br>`tests/unit/job_language_build/test_output_attribution.py`<br>`tests/unit/job_language_build/test_php.py`<br>`tests/unit/job_language_build/test_php_dependency_output_filtering.py`<br>`tests/unit/job_language_build/test_php_installed.py`<br>`tests/unit/job_language_build/test_python.py`<br>`tests/unit/job_language_build/test_rust.py`<br>`tests/unit/job_language_build/test_wasm.py`<br>`tests/unit/job_language_build/test_upstream_gap_contract.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_project_build`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_language_build"]
  producer0["job_build_environment_analysis"]
  input0["handoff"]
  input_schema0["appsec-review/job-handoff/2"]
  producer0 --> input0 --> job
  input0 -. schema .-> input_schema0
  producer1["job_build_environment_analysis"]
  input1["build_environment"]
  input_schema1["appsec-review/build-environment-analysis/1"]
  producer1 --> input1 --> job
  input1 -. schema .-> input_schema1
  producer2["job_project_build"]
  input2["handoff"]
  input_schema2["appsec-review/job-handoff/2"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_project_build"]
  input3["topology_refinement_inputs"]
  input_schema3["appsec-review/build-topology-refinement/1"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  producer4["job_project_build"]
  input4["project_build_dispatch"]
  input_schema4["appsec-review/project-build-dispatch/3"]
  producer4 --> input4 --> job
  input4 -. schema .-> input_schema4
  producer5["job_project_build"]
  input5["probe_workspaces"]
  input_schema5["application/octet-stream"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_project_build"]
  input6["image_build_streams"]
  input_schema6["text/plain"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_review_intake"]
  input7["handoff"]
  input_schema7["appsec-review/job-handoff/2"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_review_intake"]
  input8["model_preflight"]
  input_schema8["appsec-review/model-preflight/1"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_review_intake"]
  input9["binary_evidence"]
  input_schema9["appsec-review/binary-evidence-intake/1"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_review_intake"]
  input10["review_intake"]
  input_schema10["appsec-review/review-intake/1"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_target_analysis_plan"]
  input11["handoff"]
  input_schema11["appsec-review/job-handoff/2"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_target_analysis_plan"]
  input12["planning_feedback_cache"]
  input_schema12["appsec-review/target-analysis-proposal/3"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_target_analysis_plan"]
  input13["analysis_plan"]
  input_schema13["appsec-review/retrieval-index/2"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_target_analysis_plan"]
  input14["analysis_plan_documents"]
  input_schema14["appsec-review/target-analysis-plan/1"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_target_catalog"]
  input15["handoff"]
  input_schema15["appsec-review/job-handoff/2"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_target_catalog"]
  input16["target_artifact_inputs"]
  input_schema16["appsec-review/target-artifact-intake/1"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  producer17["job_target_catalog"]
  input17["source_files"]
  input_schema17["appsec-review/retrieval-index/2"]
  producer17 --> input17 --> job
  input17 -. schema .-> input_schema17
  producer18["job_target_catalog"]
  input18["declaration_symbols"]
  input_schema18["appsec-review/retrieval-index/2"]
  producer18 --> input18 --> job
  input18 -. schema .-> input_schema18
  producer19["job_target_catalog"]
  input19["components"]
  input_schema19["appsec-review/retrieval-index/2"]
  producer19 --> input19 --> job
  input19 -. schema .-> input_schema19
  producer20["job_target_catalog"]
  input20["target_documents"]
  input_schema20["appsec-review/retrieval-index/2"]
  producer20 --> input20 --> job
  input20 -. schema .-> input_schema20
  producer21["job_target_catalog"]
  input21["build_units"]
  input_schema21["appsec-review/retrieval-index/2"]
  producer21 --> input21 --> job
  input21 -. schema .-> input_schema21
  producer22["job_target_catalog"]
  input22["catalog_documents"]
  input_schema22["appsec-review/target-catalog/1"]
  producer22 --> input22 --> job
  input22 -. schema .-> input_schema22
  output0["build_actions"]
  output_schema0["appsec-review/retrieval-index/2"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["build_workspaces"]
  output_schema1["application/octet-stream"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["jvm_build_actions"]
  output_schema2["appsec-review/retrieval-index/2"]
  job --> output2
  output2 -. schema .-> output_schema2
  output3["language_build_receipts"]
  output_schema3["appsec-review/language-build-handoff/2"]
  job --> output3
  output3 -. schema .-> output_schema3
  output4["topology_refinement_inputs"]
  output_schema4["appsec-review/build-topology-refinement/1"]
  job --> output4
  output4 -. schema .-> output_schema4
```

<!-- generated:end -->

## Process

Source: [handlers and generic executor](../../src/appsec_review/jobs/job_language_build/job.py),
[capture reconciliation](../../src/appsec_review/jobs/job_language_build/capture.py),
[JVM](../../src/appsec_review/jobs/job_language_build/jvm.py) and
[Wasm](../../src/appsec_review/jobs/job_language_build/wasm.py) adapters.
[Language-build operations](language-build.md) owns family details; shared
[topology/iterations](../architecture/build-topology-and-iterations.md) and
[capture semantics](../architecture/build-environments-and-execution-capture.md) are linked rather
than redefined here.

### `iterations`

1. Read accepted project-build dispatches and revalidate source, workflow, unique unit IDs,
   recipe/profile/dependency identities, preparation references and topology refinement.
   Refuse graphless/legacy execution modes and changed source bytes.
2. Select explicit recipe revisions and processing decisions. Retain upstream image failures
   and platform/policy exclusions as receipts. Consume project-owned native receipts without
   scheduling a second execution.
3. Construct `BuildIterations` from the admitted graph, selected dispatches, configuration,
   releases and output policy. Schedule serial dependency-ready nodes in the shared complete
   target/install workspace; verify product interfaces, not just predecessor statuses.
4. Invoke each production transaction through `job_build_iteration`. Generic, JVM or Wasm
   execution uses the same admitted workspace/interfaces. Configure/build commands are bounded
   by time, streams, artifact counts and family policy; no model supplies new commands here.
5. Capture applicable native/Rust/.NET/Go/Node/Python/PHP process execution. Reconcile only successful
   `process_exec` events as compiler authority; preserve incomplete capture, redaction and
   missing tool execution. Use family parsers for package, generated-source and output facts.
6. Recheck target identity, classify output trees and bookkeeping, validate native/Go target
   evidence, retain protected argv/streams and immutable artifact bytes. Failed build outputs
   are not accepted products. Commit only successful product transactions with confirmed cleanup;
   preserve diagnostics. Sibling continuation after failure requires a prepared receipt and
   confirmed cleanup; pre-receipt refusals can stop the controller even after rollback, and
   uncertain cleanup prevents safe workspace progress.

### `load`

1. Re-read accepted dispatch authority for each configured family and enforce its typed
   settings. Shared envelope/identity errors are hard failures, not missing family coverage.
2. Select Wasm output producers from configured rules rather than equating output format with
   source language. Other family selections exclude those Wasm-routed dispatches.
3. Retain native/project-owned and Unity engine receipts, unavailable upstream units and
   explicit platform/policy dispositions. Validate accepted Go/Rust and other family-specific
   recipe requirements; do not silently omit a planned unit whose preparation failed.
4. Record processing applicability and any unmatched configured Wasm producer reason.

### `execute`

1. In the admitted iterative path, collect the controller's receipts by output family and add
   the one-time Unity receipts. Do not rebuild after `iterations.dispatch`.
2. Carry both receipt gaps and delivery gaps into the family result. A family with no receipts
   is `NOT_APPLICABLE`; a failed planned unit remains a named receipt, not an absent lane.
3. Return per-family counts and statuses. The retained non-iterative implementation is not
   authority to bypass the earlier iterative-mode admission.

### `acceptance`

1. Join family receipts, controller graph and processing decisions. Name dispatch families
   outside the supported executor set rather than silently dropping them.
2. Write `accepted-language-builds.json` with the exact upstream project handoff hash.
3. Build the aggregate `build` shard from actual commands, invocations and artifact references;
   compose it with JVM and upstream shards under a verified manifest.
4. Publish receipt and index datasets only after framework validation. Keep workspaces and
   exact command material protected, distinct from sanitized queryable build actions.

## Dataflow

```mermaid
flowchart LR
  prepared["project_build_dispatch"] --> job["job_language_build"]
  job --> controller["iterations.dispatch"]
  controller --> transaction["job_build_iteration"]
  transaction --> receipts["language-build-receipt"]
  owned["project-owned native / Unity receipts"] --> load["load"]
  prepared --> load
  controller --> load
  load --> execute["execute"]
  receipts --> execute
  execute --> publish["acceptance.publish_handoff"]
  publish --> outputs["language_build_receipts + build_actions + jvm_build_actions"]
  transaction --> protected["build_workspaces"]
  receipts -. "capture / product / delivery gaps" .-> gaps["outcomes"]
```

## Gaps

This job mixes preserved typed records with legacy strings. Legacy values become canonical
`producer_reported_gap`, `retryable=False`; native enforcement records also use that code and
default false. Nested failed/blocked receipt status alone does not set canonical retryability.
The framework reads the unit's own status and explicit dispositions, including processing `GAP`
dispositions, for status-derived retry accounting. Inspect canonical outcomes rather than
labeling all build gaps either retryable or advisory.

Canonical upstream causes retain their identity, code, unit/scope, retryability and evidence
references through receipt and control propagation. Cause groups are validated before merging;
identical records are deduplicated without discarding distinct or conflicting causes. The first
readable reason is presentation only, not a replacement for the retained causes. Malformed
records and foreign-unit re-declarations remain accounting failures. Legacy text keeps its
registered representation until the normal publication boundary.

| Boundary | Source-derived omissions or failures |
| --- | --- |
| Dispatch/controller | Missing immutable image/release/refinement/product evidence; unsupported/unresolved topology; unavailable dependency; selected policy/capability gaps; retained upstream preparation failure. |
| Command execution | Nonzero exit, timeout, command failure and unconfirmed cleanup. Failed command artifacts are withheld; unconfirmed cleanup stops workspace progress. |
| Capture/reconciliation | Missing or truncated capture, disabled environment capture, secret-redacted records, failed/unmatched execution, missing required compiler/linker evidence and incomplete wrapper/provenance joins. |
| Family interpretation | Invalid/unsupported .NET platform or recipe; Go catalog/metadata/target mismatch; Rust metadata or linker evidence missing; Node dependency/lifecycle or invocation/output gaps; Python package/frontend or archive mapping gaps; PHP Composer/autoload/native-tool gaps; JVM provenance and Wasm producer/output gaps. |
| Output/enforcement | Artifact bounds, unresolved source/output/delivery mapping, missing expected outputs, invalid native target proof or compiler profile, unsupported native product closure, and processing artifact-validation/evidence gaps. |

These are reason families emitted by the linked adapters, not invented producer-gap codes.
The `appsec-review/elf-loader-dependencies/3` reader accepts string tables across adjacent
loadable mappings only when their virtual coverage and file bytes are contiguous. Gaps,
BSS-only tails, overlapping mappings, overflow and unbacked bytes remain unparseable coverage,
not resolved dependency evidence.
Absent supported work may be `NOT_APPLICABLE`; a Windows-only or otherwise unsupported planned
unit can still carry named coverage loss. Accepted input bytes are not new compiler outputs.
Source drift, corrupt retained captures/manifests, recipe identity mismatches and invalid shared
authority fail closed; they are not successful publication with a warning.
See [job interchange](../architecture/job-interchange.md). A walk must separately approve every
actual cause and its cost, including deterministic capability limitations.

## Acceptance

1. **A. Inputs:** Match project/plan/catalog/environment handoff reads, selected recipe revision,
   image preparation and product-interface pins to the claim. Verify project-owned receipt
   hashes instead of treating reused execution as newly observed work.
2. **B. Independent comparison:** Account for every selected unit once as executed, reused,
   blocked, failed or not applicable. Compare command exits and successful exec-event counts
   with raw captures; compare retained output hashes/sizes, machine/format and source mappings
   against independent byte inspection. Compare workspace and installed-product counts.
3. **C. Gaps:** Group verified outcomes by unit, family and cause; reconcile output/delivery and
   capture omissions with receipts. Check rejected/failed products did not enter accepted
   artifacts. Stop on any cause outside the walk's expected-gaps list.
4. **D. Baseline:** After comparison, use `stepwise.py accept`; record corpus namespace and saved
   baseline of selected units, command/capture/output counts, reused products and coverage.

## Resume and invalidation

The global controller binds source/topology, selected recipe, image, configuration, releases,
execution/output policy and upstream product hashes. It verifies committed products and
receipt artifacts before reuse; changing a producer invalidates dependent nodes while retaining
admissible unrelated checkpoints.

The generic private build fingerprint additionally includes dependency files, preparation,
project handoff, capture/executor identity, processing facts/decisions/modes, family options and
execution bounds; exact interfaces are added to the key. This generic private cache is used only
outside the shared-workspace path and requires success, complete capture and verified artifacts.
Project-owned native execution disables that private cache. JVM/Wasm fingerprints also bind
their specialized toolchain/provenance/layout or producer selections and upstream dependencies.
That generic cache's completeness rule is not a blanket claim about every family adapter or
controller product checkpoint. Whole-job admission rechecks
topology and immutable artifacts under
[Wave 1 resumability](../architecture/jobs-and-runtime.md#wave-1-resumability).

The ELF parser identity labels freshly interpreted facts; it does not itself invalidate the
generic private receipt cache, whose key does not include that label. Reused receipts may retain
older loader facts. This repair neither reparses nor purges stored receipts, and unit validation
does not establish that reuse across a parser change is appropriate.
