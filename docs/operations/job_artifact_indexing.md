---
title: "artifact_indexing"
kind: "operations"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_artifact_indexing"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# artifact_indexing

## Purpose

Give accepted build outputs and separately admitted target artifacts stable retrieval identities,
archive-member membership and bounded producing/linking relationships. The question is what bytes
were retained and how strongly their provenance is known, not whether an artifact is safe,
delivered to production, or uniquely attributable to a compiler action.

<!-- generated:begin job=job_artifact_indexing -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

artifact_indexing

Job: `job_artifact_indexing`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_artifact_indexing/job.py#L1004) |
| `index` | `index.catalogs` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_artifact_indexing/job.py#L591) |
| `index` | `index.members` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_artifact_indexing/job.py#L783) |
| `index` | `index.relationships` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_artifact_indexing/job.py#L906) |
| `load` | `load.accepted_builds` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_artifact_indexing/job.py#L980) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_language_build` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
| `job_language_build` | `topology_refinement_inputs` | `appsec-review/build-topology-refinement/1` | handoff | optional | gap |
| `job_language_build` | `build_actions` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_language_build` | `jvm_build_actions` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_language_build` | `language_build_receipts` | `appsec-review/language-build-handoff/2` | handoff | required | reject |
| `job_language_build` | `build_workspaces` | `application/octet-stream` | handoff | optional | gap |
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
| `archive_members` | `index` | `appsec-review/retrieval-index/2` | indexed | `artifacts` | `query_artifacts` |
| `artifact_catalog` | `index` | `appsec-review/retrieval-index/2` | indexed | `artifacts` | `query_artifacts`, `query_precomputed` |
| `artifact_index_summary` | `acceptance` | `appsec-review/artifact-indexing/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `artifact_relationships` | `index` | `appsec-review/retrieval-index/2` | indexed | `artifacts` | `query_artifacts`, `trace` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | `tests/acceptance/job_artifact_indexing/test_artifact_index_shard_layout.py`<br>`tests/acceptance/test_dependency_output_bounds.py::test_artifact_index_count_is_bounded_by_the_classified_catalog` |
| integration | `tests/integration/job_artifact_indexing/test_artifact_indexing_graph.py`<br>`tests/integration/job_artifact_indexing/test_artifact_indexing_throughput.py`<br>`tests/integration/job_artifact_indexing/test_artifact_input_contracts.py`<br>`tests/integration/job_artifact_indexing/test_artifact_indexing_scale.py` |
| live | None declared |
| unit | `tests/unit/job_artifact_indexing/test_contract.py`<br>`tests/unit/job_artifact_indexing/test_handler_wiring.py`<br>`tests/unit/job_artifact_indexing/test_job_graph.py`<br>`tests/unit/job_artifact_indexing/test_identities.py`<br>`tests/unit/job_artifact_indexing/test_receipt_validation.py`<br>`tests/unit/job_artifact_indexing/test_target_artifacts.py`<br>`tests/unit/job_artifact_indexing/test_catalogs.py`<br>`tests/unit/job_artifact_indexing/test_members.py`<br>`tests/unit/job_artifact_indexing/test_relationships.py`<br>`tests/unit/job_artifact_indexing/test_shards.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_language_build`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_artifact_indexing"]
  producer0["job_language_build"]
  input0["handoff"]
  input_schema0["appsec-review/job-handoff/2"]
  producer0 --> input0 --> job
  input0 -. schema .-> input_schema0
  producer1["job_language_build"]
  input1["topology_refinement_inputs"]
  input_schema1["appsec-review/build-topology-refinement/1"]
  producer1 --> input1 --> job
  input1 -. schema .-> input_schema1
  producer2["job_language_build"]
  input2["build_actions"]
  input_schema2["appsec-review/retrieval-index/2"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_language_build"]
  input3["jvm_build_actions"]
  input_schema3["appsec-review/retrieval-index/2"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  producer4["job_language_build"]
  input4["language_build_receipts"]
  input_schema4["appsec-review/language-build-handoff/2"]
  producer4 --> input4 --> job
  input4 -. schema .-> input_schema4
  producer5["job_language_build"]
  input5["build_workspaces"]
  input_schema5["application/octet-stream"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_target_catalog"]
  input6["handoff"]
  input_schema6["appsec-review/job-handoff/2"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_target_catalog"]
  input7["target_artifact_inputs"]
  input_schema7["appsec-review/target-artifact-intake/1"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_target_catalog"]
  input8["source_files"]
  input_schema8["appsec-review/retrieval-index/2"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_target_catalog"]
  input9["declaration_symbols"]
  input_schema9["appsec-review/retrieval-index/2"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_target_catalog"]
  input10["components"]
  input_schema10["appsec-review/retrieval-index/2"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_target_catalog"]
  input11["target_documents"]
  input_schema11["appsec-review/retrieval-index/2"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_target_catalog"]
  input12["build_units"]
  input_schema12["appsec-review/retrieval-index/2"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_target_catalog"]
  input13["catalog_documents"]
  input_schema13["appsec-review/target-catalog/1"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  output0["archive_members"]
  output_schema0["appsec-review/retrieval-index/2"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["artifact_catalog"]
  output_schema1["appsec-review/retrieval-index/2"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["artifact_index_summary"]
  output_schema2["appsec-review/artifact-indexing/1"]
  job --> output2
  output2 -. schema .-> output_schema2
  output3["artifact_relationships"]
  output_schema3["appsec-review/retrieval-index/2"]
  job --> output3
  output3 -. schema .-> output_schema3
```

<!-- generated:end -->

## Process

The [handler](../../src/appsec_review/jobs/job_artifact_indexing/job.py) consumes receipts and
member manifests; it does not unpack archives or invoke a scanner. Generated tool bindings remain
[T-147](../TODO.md).

### `load`

1. Load accepted language-build publication and its bound verified manifest. Require this target
   snapshot; validate receipt schema and unique build-unit identities.
2. For unsuccessful receipts, retain reasons but require no published artifacts. For successful
   receipts verify the workspace manifest, every artifact's canonical workspace path, bytes,
   size and manifest membership, including retained shared-object references.
3. Validate Node-specific build-unit, exact-mapping, origin and package-integrity metadata. Reject
   duplicate canonical artifacts or inconsistent receipt identities; these are integrity failures.
4. Optionally read accepted target-artifact intake from the catalog. Require target-intake origin,
   unknown scope/delivery status, exact target mapping and retained-object custody; attach catalog
   provenance. Missing/legacy inventory and unknown delivery are explicit reasons.

### `index`

1. In `index.catalogs`, group each receipt's validated artifacts by family and publish one catalog
   shard per family. Publish a separate target-intake shard with partial delivery coverage.
2. In `index.members`, join receipt `package_members` by package path, never scan an archive.
   Validate member paths/size/identity, reject duplicate members and create `CONTAINS` edges.
   Missing member manifests remain coverage gaps.
3. In `index.relationships`, join artifacts to recorded actions and output invocations. Preserve
   exact versus heuristic attribution. Prefer exact link inputs, deduplicate link edges and retain
   only bounded provenance observations. If no action maps but actions exist, relate to every
   candidate with low confidence and an ambiguity reason; if none exist, record missing provenance.
4. Greedily pack sorted member/relationship rows into deterministic build-unit batches bounded by
   artifact and row counts. A single oversized artifact occupies its own batch: the packing target
   is not a hard per-artifact row cap. Under a shard lock, verify metadata and SQLite integrity
   before reusing a completed shard, otherwise build it.

### `acceptance`

1. Replace inherited artifacts indices with the newly built set while preserving other index names.
   Write and verify `artifact-indexing-<attempt>.json`.
2. Write `accepted-index.json` with upstream handoff hashes, target artifacts, artifact/shard/reused
   counts and deduplicated reasons. Item count is shards, not artifacts; reasons yield
   completed-with-gaps.

## Dataflow

```mermaid
flowchart LR
  builds["accepted language-build receipts + workspace manifests"] --> job["job_artifact_indexing"]
  intake["accepted target_artifact_inputs"] --> job
  job --> load["load.accepted_builds"]
  load --> catalogs["index.catalogs: artifact_catalog"]
  load --> members["index.members: archive_members"]
  load --> relations["index.relationships: artifact_relationships"]
  catalogs --> publish["acceptance.publish_handoff: artifact_index_summary"]
  members --> publish
  relations --> publish
  load -. "absent receipts / unknown delivery" .-> gaps["legacy reasons"]
  members -. "member manifest absent" .-> gaps
  relations -. "missing / ambiguous / capped provenance" .-> gaps
  gaps --> publish
  load -. "identity or custody violation" .-> stop["integrity exception"]
```

## Gaps

This job emits legacy reasons; [interchange](../architecture/job-interchange.md#the-control-layer-beneath-the-envelope)
wraps them as `producer_reported_gap`, normally non-retryable. That bit does not make them advisory.

- Input absent/failed: no accepted receipts, successful build without artifact entries, unavailable
  target intake, legacy catalog without target inventory, inherited build/catalog reasons and
  missing archive-member manifest.
- Coverage missing: unknown target-artifact delivery, ambiguous producing-action mapping, no
  producing-action receipt and link provenance exceeding its observation bound.
- Invalid schema, duplicate unit/artifact/member, escaping path, missing/changed artifact or
  workspace manifest, invalid Node integrity metadata and corrupt existing shards raise
  `ArtifactIndexIntegrityError`. Lock exhaustion is an execution failure, not a clean empty index.

Archive-intake omissions are inherited rather than repaired here. A known missing member manifest
does not imply approval by the current walk.

## Acceptance

1. **A. Inputs:** Match language-build and optional catalog handoff pins, workspace manifests and
   shared-object references; ensure unsuccessful receipts contributed no artifact bytes.
2. **B. Independent comparison:** Count receipt artifacts by build unit/family and target inventory
   entries independently; compare canonical identities, hashes and sizes. Count package-member
   rows and `CONTAINS` edges, then check a producing/link edge against its exact invocation
   inputs/outputs and confidence. Compare logical counts separately from batch-shard counts.
3. **C. Gaps:** Group verified outcome records and reconcile inherited failures, unknown delivery,
   missing members and ambiguous/capped provenance against receipts and the approved expected list.
4. **D. Baseline:** At authorized acceptance save `stepwise.py accept`, corpus namespace and baseline
   with artifact/member/relationship identities and shard counts. No live acceptance is claimed here.

## Resume and invalidation

Catalog fingerprints bind snapshot, artifact path/hash/size/family, producing actions and
invocations, dependencies, toolchain/image and parser/extractor/normalizer/mapping identities.
Member/relationship batches also bind layout and row content; target-intake fingerprints bind its
accepted records. Unchanged batches reuse verified immutable SQLite shards; changed membership
can repartition later batches without invalidating unrelated build units. See
[accepted index sets](../architecture/python-and-retrieval.md#accepted-index-sets) and
[input read receipts](../architecture/job-input-contracts.md#admission-and-read-receipts) for the
shared boundaries.
