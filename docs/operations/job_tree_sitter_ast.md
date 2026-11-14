---
title: "tree_sitter_ast"
kind: "operations"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_tree_sitter_ast"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# tree_sitter_ast

## Purpose

Provide source-bound syntax nodes and containment for accepted target and retained generated
sources, with a bounded language-neutral syntax projection where implemented. Parsing is not type
checking, name/import resolution, call-target resolution or vulnerability analysis. A parseable
tree and a complete AST shard do not imply a complete semantic projection.

<!-- generated:begin job=job_tree_sitter_ast -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

tree_sitter_ast

Job: `job_tree_sitter_ast`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_tree_sitter_ast/job.py#L208) |
| `load` | `load.accepted_inputs` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_tree_sitter_ast/job.py#L122) |
| `parse` | `parse.dynamic_scopes` | 8 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_tree_sitter_ast/job.py#L171) |
| `plan` | `plan.route_scopes` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_tree_sitter_ast/job.py#L135) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_language_build` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_language_build` | `topology_refinement_inputs` | `appsec-review/build-topology-refinement/1` | handoff | optional | gap |
| `job_language_build` | `build_actions` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_language_build` | `jvm_build_actions` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_language_build` | `language_build_receipts` | `appsec-review/language-build-handoff/2` | handoff | optional | gap |
| `job_language_build` | `build_workspaces` | `application/octet-stream` | handoff | optional | gap |
| `job_review_intake` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_review_intake` | `model_preflight` | `appsec-review/model-preflight/1` | handoff | optional | gap |
| `job_review_intake` | `binary_evidence` | `appsec-review/binary-evidence-intake/1` | handoff | optional | gap |
| `job_review_intake` | `review_intake` | `appsec-review/review-intake/1` | handoff | optional | gap |
| `job_target_catalog` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
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
| `generated_source_backing` | `load` | `appsec-review/generated-source-backing/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `tree_sitter_ast` | `parse` | `appsec-review/tree-sitter-normalizer/1` | indexed | `analysis` | `find`, `query_syntax`, `search`, `trace` |
| `tree_sitter_coverage` | `acceptance` | `appsec-review/tree-sitter-ast/1` | indexed | `analysis` | `coverage` |
| `tree_sitter_node_shards` | `parse` | `appsec-review/tree-sitter-ast/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `tree_sitter_tool_io` | `parse` | `appsec-review/container-execution/1` | protected | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | None declared |
| integration | None declared |
| live | None declared |
| unit | `tests/test_tree_sitter_ast.py::test_scope_routing_is_project_translation_and_language_specific`<br>`tests/test_tree_sitter_ast.py::test_scope_routing_chunks_large_partitions_deterministically`<br>`tests/test_tree_sitter_ast.py::test_normalization_preserves_spans_fields_malformed_flags_and_truncation` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_language_build`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_tree_sitter_ast"]
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
  producer6["job_review_intake"]
  input6["handoff"]
  input_schema6["appsec-review/job-handoff/2"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_review_intake"]
  input7["model_preflight"]
  input_schema7["appsec-review/model-preflight/1"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_review_intake"]
  input8["binary_evidence"]
  input_schema8["appsec-review/binary-evidence-intake/1"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_review_intake"]
  input9["review_intake"]
  input_schema9["appsec-review/review-intake/1"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_target_catalog"]
  input10["handoff"]
  input_schema10["appsec-review/job-handoff/2"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_target_catalog"]
  input11["target_artifact_inputs"]
  input_schema11["appsec-review/target-artifact-intake/1"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_target_catalog"]
  input12["source_files"]
  input_schema12["appsec-review/retrieval-index/2"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_target_catalog"]
  input13["declaration_symbols"]
  input_schema13["appsec-review/retrieval-index/2"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_target_catalog"]
  input14["components"]
  input_schema14["appsec-review/retrieval-index/2"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_target_catalog"]
  input15["target_documents"]
  input_schema15["appsec-review/retrieval-index/2"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_target_catalog"]
  input16["build_units"]
  input_schema16["appsec-review/retrieval-index/2"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  producer17["job_target_catalog"]
  input17["catalog_documents"]
  input_schema17["appsec-review/target-catalog/1"]
  producer17 --> input17 --> job
  input17 -. schema .-> input_schema17
  output0["generated_source_backing"]
  output_schema0["appsec-review/generated-source-backing/1"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["tree_sitter_ast"]
  output_schema1["appsec-review/tree-sitter-normalizer/1"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["tree_sitter_coverage"]
  output_schema2["appsec-review/tree-sitter-ast/1"]
  job --> output2
  output2 -. schema .-> output_schema2
  output3["tree_sitter_node_shards"]
  output_schema3["appsec-review/tree-sitter-ast/1"]
  job --> output3
  output3 -. schema .-> output_schema3
  output4["tree_sitter_tool_io"]
  output_schema4["appsec-review/container-execution/1"]
  job --> output4
  output4 -. schema .-> output_schema4
```

<!-- generated:end -->

## Process

Source: [job](../../src/appsec_review/jobs/job_tree_sitter_ast/job.py),
[scope planning](../../src/appsec_review/jobs/job_tree_sitter_ast/model.py),
[execution](../../src/appsec_review/jobs/job_tree_sitter_ast/scope_execution.py) and
[normalization](../../src/appsec_review/jobs/job_tree_sitter_ast/normalize.py).

### `load`

1. Read accepted intake and catalog publications, then partition, components and build targets.
   Verify schemas and snapshot agreement.
2. Load only admitted generated-source artifacts through the
   [generated-source reader](../../src/appsec_review/jobs/job_tree_sitter_ast/generated_sources.py),
   with metadata, file, byte and lane bounds. Keep generated backing and build provenance;
   reject logical-path collisions with target sources.
3. Load the repository's grammar lock and resolve the pinned Tree-sitter image. Invalid lock,
   untrusted input identity or snapshot mismatch stops; image/signature policy remains in
   [image verification](image-pin-verification.md) and [signing](signing.md).

### `plan`

1. Select source-in-scope catalog files with languages. Assign the deepest component/build root,
   separate generated translation scopes, route TSX explicitly, and chunk sorted files by count
   and source bytes. Include relevant catalog exclusions in scope identity.
2. Remove Swift scopes when policy disables Swift; partition other scopes by locked grammar.
   Preserve missing grammars, generated-source gaps and exclusions outside any source scope as
   unavailable/partial dispositions, not silently unplanned files.

### `parse`

1. Use completed per-scope dynamic results when present, otherwise run bounded parallel parsing.
   Require target and generated files to have separate source mounts.
2. Reuse a verified fingerprinted JSONL/index pair or stage a bounded parser request. Generated
   bytes are immutable read-only backing, not writable aliases to scratch.
3. Invoke the parser container; nonzero exit, timeout or OOM yields a failed scope. Missing declared
   output, wrong grammar/image/lock identity or malformed trusted structure raises an exception.
4. Normalize accepted file records into located nodes and `CONTAINS` relationships; emit JSONL
   and analysis SQLite. Retain parse diagnostics, node limits, omitted files and exclusions.
   Add syntax-projection coverage separately: a supported mapping is still a bounded unresolved
   syntax subset; an unmapped grammar has unavailable projection.
5. Sort dispositions and aggregate files/bytes/nodes/diagnostics and reasons. Successful scope
   count includes partial scopes with an index, not just completely parsed scopes.

### `acceptance`

1. Publish one attempt coverage shard across all dispositions, including unavailable scopes, and
   compose successful AST shards with the upstream manifest, replacing this producer's old shards.
2. Write `accepted-tree-sitter-ast.json` with lock/image, generated-source backing, build handoff,
   per-scope dispositions, counts, reasons and manifest. Item count is parsed nodes.

## Dataflow

```mermaid
flowchart LR
  inputs["accepted intake + catalog + generated sources"] --> job["job_tree_sitter_ast"]
  job --> plan["plan.route_scopes: component / translation / grammar"]
  plan --> parse["parse.dynamic_scopes: locked parser"]
  parse --> ast["JSONL nodes + analysis shards"]
  ast --> projection["bounded syntax projection coverage"]
  projection --> publish["acceptance.publish_handoff"]
  plan -. "disabled / grammar absent / exclusions" .-> gaps["scope dispositions"]
  parse -. "failed / diagnostics / limits / omitted files" .-> gaps
  gaps --> publish
  inputs -. "identity collision or changed bytes" .-> stop["integrity exception"]
```

## Gaps

The source emits text and scope dispositions, converted by
[interchange](../architecture/job-interchange.md#the-control-layer-beneath-the-envelope) into canonical
outcomes; legacy text becomes `producer_reported_gap` with default non-retryable metadata, not
an advisory classification.

- Input absent/failed: generated-source producer unavailable or unsuccessful build, inherited
  catalog/build gaps, container omission of an accepted file.
- Present but unsupported: unavailable grammar, disabled Swift, generated bytes not UTF-8, and no
  syntax projection for a locked grammar.
- Coverage missing: catalog exclusions/large files, generated metadata/file-byte/lane bounds,
  parser truncation or node limits, parse diagnostics, and projection-specific limitations.
- Tooling failure: parser failed exit/timeout/OOM. Accepted input hash/schema/lock mismatch,
  source-domain mixing and missing/invalid declared parser output raise rather than publishing
  successful gap evidence.

Projection reasons live in coverage rows even when not duplicated into the top-level reasons.
Compare both surfaces; none is automatically on a walk's approved expected list.

## Acceptance

1. **A. Inputs:** Compare intake/catalog/build pins and generated backing identities; reconcile
   source-in-scope files, exclusions and grammar assignments against the admitted catalog.
2. **B. Independent comparison:** Count requested versus returned files and native parser nodes;
   compare JSONL and SQLite counts. Independently resolve sampled byte/line spans and parent-child
   ordinals against retained source, including generated backing. Inspect syntax-projection
   completeness separately from AST completeness.
3. **C. Gaps:** Group verified canonical outcomes and reconcile scope dispositions plus projection
   coverage with omissions, diagnostics, truncation and disabled/unsupported languages. Compare
   every observed cause with the walk's expected list.
4. **D. Baseline:** On authorized acceptance save corpus namespace and `stepwise.py accept` baseline
   with file/node counts, grammar/image identities and coverage. No live parser acceptance is
   established by this page.

## Resume and invalidation

Scope fingerprints bind snapshot, component/translation membership, file hashes and delivery/source
backing, exclusions, grammar lock, image, normalizer, syntax-projection schema and parser limits.
Verify both JSONL and SQLite hashes before reuse; stale/missing shard pairs are reparsed.
Chunk-membership changes invalidate affected scopes. Attempt-level dynamic results and unit
checkpoints remain governed by [runtime resumability](../architecture/jobs-and-runtime.md#wave-1-resumability),
not by the mere existence of a parser artifact.
Generated task and language/applicability metadata limitations remain
[T-147](../TODO.md) and [T-157](../TODO.md);
the source route/lock determines actual coverage.
