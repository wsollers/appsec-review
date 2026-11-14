---
title: "threat_model_generation"
kind: "operations"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_threat_model_generation"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# threat_model_generation

## Purpose

Derive an evidence-linked DFD and candidate threat questions from accepted structure and interaction
facts. Outputs are artifact-only routing context, not findings or proof that mitigations are
absent; candidate mitigation state remains `not_examined`. This deterministic slice is disabled
by default. The current inference behavior loader can use an admitted generated model as routing
context, but must return to original evidence to establish claim predicates.

<!-- generated:begin job=job_threat_model_generation -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

threat_model_generation

Job: `job_threat_model_generation`. Enabled in the dev recipe: **false**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `assembly` | `assembly.dfd` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_threat_model_generation/job.py#L245) |
| `facts` | `facts.interactions` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_threat_model_generation/job.py#L240) |
| `facts` | `facts.structure` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_threat_model_generation/job.py#L236) |
| `load` | `load.accepted_inputs` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_threat_model_generation/job.py#L205) |
| `publication` | `publication.publish_handoff` | 1 | `lifecycle` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_threat_model_generation/job.py#L286) |
| `publication` | `publication.render` | 1 | `lifecycle` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_threat_model_generation/job.py#L276) |
| `threats` | `threats.enumerate` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_threat_model_generation/job.py#L255) |
| `validation` | `validation.resolve_citations` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_threat_model_generation/job.py#L262) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_artifact_indexing` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_artifact_indexing` | `artifact_catalog` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_artifact_indexing` | `artifact_relationships` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_code_graph_index` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_code_graph_index` | `code_graph_facts` | `appsec-review/graph-fact/1` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `cpp_build_graph` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_language_build` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_language_build` | `build_actions` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_review_prioritization` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_review_prioritization` | `priority_items` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_target_catalog` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
| `job_target_catalog` | `source_files` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_target_catalog` | `components` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_target_catalog` | `build_units` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_tree_sitter_ast` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_tree_sitter_ast` | `tree_sitter_ast` | `appsec-review/tree-sitter-normalizer/1` | handoff | optional | gap |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `generated_dfd` | `publication` | `appsec-review/generated-dfd/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `generated_model_evidence` | `publication` | `appsec-review/generated-model-evidence/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `generated_model_views` | `publication` | `text/markdown` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `generated_threat_model` | `publication` | `appsec-review/generated-threat-model/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `threat_model_documents` | `publication` | `appsec-review/threat-model-generation/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | `tests/acceptance/test_threat_model_generation.py` |
| integration | `tests/integration/test_threat_model_generation.py` |
| live | None declared |
| unit | `tests/test_threat_model_generation_job.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **false**.

Declared predecessors: `job_owasp_control_assessment`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_threat_model_generation"]
  producer0["job_artifact_indexing"]
  input0["handoff"]
  input_schema0["appsec-review/job-handoff/2"]
  producer0 --> input0 --> job
  input0 -. schema .-> input_schema0
  producer1["job_artifact_indexing"]
  input1["artifact_catalog"]
  input_schema1["appsec-review/retrieval-index/2"]
  producer1 --> input1 --> job
  input1 -. schema .-> input_schema1
  producer2["job_artifact_indexing"]
  input2["artifact_relationships"]
  input_schema2["appsec-review/retrieval-index/2"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_code_graph_index"]
  input3["handoff"]
  input_schema3["appsec-review/job-handoff/2"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  producer4["job_code_graph_index"]
  input4["code_graph_facts"]
  input_schema4["appsec-review/graph-fact/1"]
  producer4 --> input4 --> job
  input4 -. schema .-> input_schema4
  producer5["job_cpp_compiled_analysis"]
  input5["handoff"]
  input_schema5["appsec-review/job-handoff/2"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_cpp_compiled_analysis"]
  input6["cpp_build_graph"]
  input_schema6["appsec-review/retrieval-index/2"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_language_build"]
  input7["handoff"]
  input_schema7["appsec-review/job-handoff/2"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_language_build"]
  input8["build_actions"]
  input_schema8["appsec-review/retrieval-index/2"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_review_prioritization"]
  input9["handoff"]
  input_schema9["appsec-review/job-handoff/2"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_review_prioritization"]
  input10["priority_items"]
  input_schema10["appsec-review/retrieval-index/2"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_target_catalog"]
  input11["handoff"]
  input_schema11["appsec-review/job-handoff/2"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_target_catalog"]
  input12["source_files"]
  input_schema12["appsec-review/retrieval-index/2"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_target_catalog"]
  input13["components"]
  input_schema13["appsec-review/retrieval-index/2"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_target_catalog"]
  input14["build_units"]
  input_schema14["appsec-review/retrieval-index/2"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_tree_sitter_ast"]
  input15["handoff"]
  input_schema15["appsec-review/job-handoff/2"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_tree_sitter_ast"]
  input16["tree_sitter_ast"]
  input_schema16["appsec-review/tree-sitter-normalizer/1"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  output0["generated_dfd"]
  output_schema0["appsec-review/generated-dfd/1"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["generated_model_evidence"]
  output_schema1["appsec-review/generated-model-evidence/1"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["generated_model_views"]
  output_schema2["text/markdown"]
  job --> output2
  output2 -. schema .-> output_schema2
  output3["generated_threat_model"]
  output_schema3["appsec-review/generated-threat-model/1"]
  job --> output3
  output3 -. schema .-> output_schema3
  output4["threat_model_documents"]
  output_schema4["appsec-review/threat-model-generation/1"]
  job --> output4
  output4 -. schema .-> output_schema4
```

<!-- generated:end -->

## Process

The [handler](../../src/appsec_review/jobs/job_threat_model_generation/job.py) uses
[bounded index views](../../src/appsec_review/threat_model/index_view.py), not a checkout or model.
The consumer boundary is explicit in [review behavior context](../../src/appsec_review/review/behavior.py).

### `load`

1. In `load.accepted_inputs`, verify the three reference-data files and require an authenticated
   evidence target snapshot. Record run/attempt/snapshot/reference hashes in the origin.
2. Open declared inputs not read by either fact lane to record their input-ledger states.
   Record the unregistered deployment-inventory producer and an `input_unavailable` gap.
3. Write attempt-owned canonical working records; missing or changed admitted bytes fail.

### `facts`

1. In `facts.structure`, hold the configured resource reservation while reading bounded catalog,
   artifact and build evidence. Derive process/structure facts with provenance, input counts and
   explicit unknowns; do not infer deployed architecture merely from a directory name.
2. In `facts.interactions`, read eligible graph entry/sink, syntax-call and priority-signal rows
   using the pinned interaction catalog. Retain evidence basis and location limitations.
3. Each lane reports only its own unavailable/partial inputs, truncations, empty result and
   provenance/location gaps. Write immutable working references for later assembly.

### `assembly`

1. In `assembly.dfd`, recheck reference hashes and join both lanes into elements, flows,
   boundaries, entry points, actors and unknowns.
2. Apply deterministic identity/merge and bound rules, retaining stronger evidence first.
   Record truncated flow/entry populations instead of claiming a complete DFD.

### `threats`

1. In `threats.enumerate`, match the assembled model to pinned threat templates/crosswalks.
2. Keep bounded candidate questions with cited evidence and unexamined mitigations. Record
   a reached threat bound; do not convert template applicability into a confirmed finding.

### `validation`

1. In `validation.resolve_citations`, resolve cited identities against admitted inputs.
2. Remove records with no resolving support and demote them to `citation_unresolved` unknowns;
   propagate dependent removals without reporting the same causing gap repeatedly.
3. Write the validated assembly and remaining threats, with citation and demotion counts.

### `publication`

1. In `publication.render`, render Markdown/Mermaid from validated records and joined prior gaps.
   If the rendering bound is reached, add its truncation gap and rerender so the view names it.
2. In `publication.publish_handoff`, assemble DFD, threat-model, evidence and result documents;
   validate schemas, cross-references, counts and artifact bindings.
3. Re-render all views and compare exact bytes with the earlier output. Reject changed working
   files or nonpure document assembly. Write final canonical documents and artifact references.
   The final unit returns no duplicate gaps: originating units already reported each one.

## Dataflow

```mermaid
flowchart LR
  job["job_threat_model_generation"] --> load["load.accepted_inputs"]
  catalog["job_target_catalog / build_units / components / source_files"] --> load
  load --> structure["facts.structure"]
  load --> interactions["facts.interactions"]
  structure --> assembly["assembly.dfd"]
  interactions --> assembly
  assembly --> threats["threats.enumerate"]
  threats --> resolve["validation.resolve_citations"]
  resolve --> render["publication.render"]
  render --> publish["publication.publish_handoff"]
  publish --> dfd["generated_dfd"]
  publish --> tm["generated_threat_model"]
  publish --> evidence["generated_model_evidence"]
  publish --> views["generated_model_views"]
  publish --> result["threat_model_documents"]
  load -. "input_unavailable" .-> gaps["producer-gap/1"]
  resolve -. "location_unresolved" .-> gaps
  gaps --> result
  publish -. "schema / reference / rerender failure" .-> reject["reject publication"]
```

Each input read follows [accepted-upstream admission](../architecture/job-input-contracts.md#admission-and-read-receipts);
index custody is described in [accepted index sets](../architecture/python-and-retrieval.md#accepted-index-sets).
No model, scanner, network or target execution is commissioned.

## Gaps

This job sets strict gaps. The [constructors](../../src/appsec_review/threat_model/view.py)
use real `producer-gap/1` codes, all with `retryable = false` here. Re-running this consumer over
the same accepted inputs cannot repair upstream coverage. **Nonretryable does not mean advisory.**
See [canonical gap semantics](../architecture/job-interchange.md#the-control-layer-beneath-the-envelope).

| Code | Scope and walk meaning |
| --- | --- |
| `input_unavailable` | Absent, disabled or unregistered producer; includes deployment inventory on every current execution. [T-108](../TODO.md) names that producer gap. |
| `output_missing` | Declared producer/dataset published no material. |
| `producer_reported_gap` | Dataset accepted with partial upstream coverage; readable, not complete. |
| `truncated` | Named query, process/entry/flow/threat bound or `publication.max_render_nodes`. |
| `empty_result` | Structure/interactions lane read inputs but established no facts. |
| `provenance_unavailable` | Structure names/paths were redacted or truncated by the index; affected processes are identified by record instead of name. |
| `location_unresolved` | Interaction fact lacks a usable location, or final cited record is demoted. |

Reference-data corruption, admitted-input tampering, malformed working records and invalid final
documents fail publication. The always-present deployment gap means the current job cannot be
accepted as complete coverage even though the final publishing unit itself returns `SUCCEEDED`.

## Acceptance

1. **A. Inputs:** Compare claim pins and input-ledger states/hashes with accepted catalog, artifact,
   build, graph, syntax and priority inputs. Verify target snapshot and three reference hashes;
   distinguish declared-but-unread rows from records actually read.
2. **B. Independent comparison:** Independently count relevant accepted structure/interaction
   rows and resolve sample DFD elements, flows and entry points to them. Reconcile retained,
   capped and demoted records with model counts. Verify evidence-set membership, unexamined
   mitigation state and byte-identical fresh rendering of views.
3. **C. Gaps:** Group verified outcomes by the seven codes above, preserving originating unit and
   scope. Compare the joined result without double counting. Record the deployment gap's cost;
   stop for any unexpected cause rather than treating `retryable = false` as acceptance.
4. **D. Baseline:** Save an authorized `stepwise.py accept` baseline and corpus namespace, with
   origin hashes, ledger states/read counts, model identities, unknowns and demotions.
   A later comparison must name changed evidence, reference data or bounds.

## Resume and invalidation

[Runtime reuse](../architecture/jobs-and-runtime.md#wave-1-resumability) binds resolved
configuration, contract, target snapshot, releases and admitted upstream digests. A repaired
producer changes its pin and invalidates this consumer without rerunning unrelated producers.
Reference hashes are checked repeatedly within the attempt. Working artifacts are path/hash-bound
to that attempt, so failed-attempt unit portability does not permit copying them into another
attempt. Reference, schema or render changes require fresh validation and view comparison.
