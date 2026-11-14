---
title: "target_analysis_plan"
kind: "operations"
subsystem: "target acquisition and build"
status: "current"
jobs: ["job_target_analysis_plan"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---

# target_analysis_plan

## Purpose

Which accepted source scopes need which scanners and build recipes, and which build
relationships can deterministic evidence establish? The planner publishes validated scope,
recipe and topology decisions for later admission. It refuses to let model suggestions suppress
mandatory baseline coverage, invent source ownership/dependencies, authorize execution or
turn advisory environment/history context into native target proof.

<!-- generated:begin job=job_target_analysis_plan -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

target_analysis_plan

Job: `job_target_analysis_plan`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `analysis_decisions` | `analysis_decisions.apply_deterministic_rules` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_analysis_plan/job.py#L303) |
| `analysis_decisions` | `analysis_decisions.resolve_ambiguity` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_analysis_plan/job.py#L326) |
| `catalog_summary` | `catalog_summary.load_accepted_catalog` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_analysis_plan/job.py#L275) |
| `catalog_summary` | `catalog_summary.summarize_components` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_analysis_plan/job.py#L290) |
| `plan_acceptance` | `plan_acceptance.index_plan` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_analysis_plan/job.py#L528) |
| `plan_acceptance` | `plan_acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_analysis_plan/job.py#L620) |
| `plan_acceptance` | `plan_acceptance.validate_plan` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_target_analysis_plan/job.py#L516) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_build_environment_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | when_producer_enabled | gap |
| `job_build_environment_analysis` | `build_environment` | `appsec-review/build-environment-analysis/1` | handoff | optional | gap |
| `job_review_intake` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_review_intake` | `model_preflight` | `appsec-review/model-preflight/1` | handoff | optional | gap |
| `job_review_intake` | `binary_evidence` | `appsec-review/binary-evidence-intake/1` | handoff | optional | gap |
| `job_review_intake` | `review_intake` | `appsec-review/review-intake/1` | handoff | optional | gap |
| `job_source_history_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_source_history_analysis` | `history_signals` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_source_history_analysis` | `history_documents` | `appsec-review/source-history-analysis/2` | handoff | optional | gap |
| `job_source_history_analysis` | `raw_git_history` | `application/octet-stream` | handoff | optional | gap |
| `job_source_history_analysis` | `history_tool_io` | `appsec-review/container-execution/1` | handoff | optional | gap |
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
| `analysis_plan` | `plan_acceptance` | `appsec-review/retrieval-index/2` | indexed | `analysis` | `find`, `search`, `trace` |
| `analysis_plan_documents` | `plan_acceptance` | `appsec-review/target-analysis-plan/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `planning_feedback_cache` | `analysis_decisions` | `appsec-review/target-analysis-proposal/3` | protected | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

These are job-level declarations; exact per-task selection is not declared ([T-147](../TODO.md)).

```json
{
  "model": {
    "enabled": true,
    "max_input_tokens": 32000,
    "max_output_tokens": 32000,
    "model": "claude-haiku-5-5",
    "provider": "claude-cli",
    "reasoning": "medium",
    "retries": 3,
    "timeout_seconds": 300,
    "workers": 6
  }
}
```

- Role template: `build_engineer_{family}`; family selected by the accepted build.
- Persona: [devops_engineer](../generated/guidance.md#personas-devops_engineer).
- Task prompt: `target_analysis_planning`.
- Runtime skill: [target-analysis-planning](../generated/guidance.md#runtime_skills-target-analysis-planning).

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | None declared |
| integration | None declared |
| live | None declared |
| unit | `tests/test_target_analysis_plan.py::test_guidance_bundles_are_group_scoped_immutable_and_reusable`<br>`tests/test_target_analysis_plan.py::test_buildable_project_names_disabled_model_as_a_gap` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_ci_configuration_analysis`, `job_source_history_analysis`, `job_build_environment_analysis`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_target_analysis_plan"]
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
  producer2["job_review_intake"]
  input2["handoff"]
  input_schema2["appsec-review/job-handoff/2"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_review_intake"]
  input3["model_preflight"]
  input_schema3["appsec-review/model-preflight/1"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  producer4["job_review_intake"]
  input4["binary_evidence"]
  input_schema4["appsec-review/binary-evidence-intake/1"]
  producer4 --> input4 --> job
  input4 -. schema .-> input_schema4
  producer5["job_review_intake"]
  input5["review_intake"]
  input_schema5["appsec-review/review-intake/1"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_source_history_analysis"]
  input6["handoff"]
  input_schema6["appsec-review/job-handoff/2"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_source_history_analysis"]
  input7["history_signals"]
  input_schema7["appsec-review/retrieval-index/2"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_source_history_analysis"]
  input8["history_documents"]
  input_schema8["appsec-review/source-history-analysis/2"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_source_history_analysis"]
  input9["raw_git_history"]
  input_schema9["application/octet-stream"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_source_history_analysis"]
  input10["history_tool_io"]
  input_schema10["appsec-review/container-execution/1"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_target_catalog"]
  input11["handoff"]
  input_schema11["appsec-review/job-handoff/2"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_target_catalog"]
  input12["target_artifact_inputs"]
  input_schema12["appsec-review/target-artifact-intake/1"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_target_catalog"]
  input13["source_files"]
  input_schema13["appsec-review/retrieval-index/2"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_target_catalog"]
  input14["declaration_symbols"]
  input_schema14["appsec-review/retrieval-index/2"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_target_catalog"]
  input15["components"]
  input_schema15["appsec-review/retrieval-index/2"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_target_catalog"]
  input16["target_documents"]
  input_schema16["appsec-review/retrieval-index/2"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  producer17["job_target_catalog"]
  input17["build_units"]
  input_schema17["appsec-review/retrieval-index/2"]
  producer17 --> input17 --> job
  input17 -. schema .-> input_schema17
  producer18["job_target_catalog"]
  input18["catalog_documents"]
  input_schema18["appsec-review/target-catalog/1"]
  producer18 --> input18 --> job
  input18 -. schema .-> input_schema18
  output0["analysis_plan"]
  output_schema0["appsec-review/retrieval-index/2"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["analysis_plan_documents"]
  output_schema1["appsec-review/target-analysis-plan/1"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["planning_feedback_cache"]
  output_schema2["appsec-review/target-analysis-proposal/3"]
  job --> output2
  output2 -. schema .-> output_schema2
```

<!-- generated:end -->

## Process

Source: [handlers](../../src/appsec_review/jobs/job_target_analysis_plan/job.py) and
[planning/feedback validation](../../src/appsec_review/jobs/job_target_analysis_plan/planning.py).
Detailed operator interpretation lives in [target analysis planning](target-analysis-planning.md);
the [topology architecture](../architecture/build-topology-and-iterations.md) owns build-graph semantics.

### `catalog_summary`

1. Read the accepted catalog and hash-verify its child documents and schemas. Require the
   catalog snapshot to equal the claim, not just a plausible target path.
2. Read available accepted source history as routing context; explicitly mark another snapshot
   stale. Load the signed environment availability contract; missing expected-current evidence
   blocks instead of silently becoming optional.
3. Apply Swift execution policy to planning inputs. Summarize components, files, descriptors,
   build units and compile databases under configured item/byte/prefix bounds.
4. Publish `catalog-summary.json` and a truncation reason if the summary was bounded. The
   summary is model context, not a replacement for full accepted descriptor authority.

### `analysis_decisions`

1. Derive scanner scopes and mandatory non-selections deterministically from exact accepted
   paths/hashes. Account for each build unit once, initially without a recipe, and retain
   source-only scopes, compile-database availability and history priority.
2. Compile `build_topology.executable_graph`, its evidence bundle and planning refinement from
   accepted declarations. Keep actions `executable=False`; the graph describes relationships,
   not a launch permit.
3. If there are no ambiguities, keep the deterministic plan. If the configured model is
   disabled or unwired, publish a named model-assistance gap without dropping baseline scanners.
4. Otherwise partition non-Unity units by family, build system and required image profile;
   enforce scope/unit bounds and recursively bisect oversized multi-unit requests. An
   oversized singleton gets a bounded-feedback gap, not a larger allowance.
5. Assemble hash-pinned guidance and closed allowlists. Run `bounded_feedback` with one shared
   per-scope call/deadline/byte budget for initial responses, repairs and evidence rounds.
   `need_evidence` may request only allowed inventory paths and exact raw hashes; verify bytes,
   withhold sensitive content and reject nonprogressing or unsupported requests.
6. Validate `final` recipes or explicit abstentions against accepted units and image/command
   policy. Merge accepted recipes, record contradictions and omissions, and recompile the
   whole graph; a model hint cannot become scheduling or compiler authority.
7. Cache only a complete validated final without abstentions. Recognized response/provider/
   timeout failures consume the finite budget and yield named exhaustion; unexpected
   application/integrity errors propagate.

### `plan_acceptance`

1. Validate source identity, exact scanner scopes, mandatory baseline accounting, accepted
   components/history paths, one action per build unit and unmodified descriptor facts.
2. Validate every recipe, reject inferred Unity recipes, and reproduce the graph from the
   whole accepted declaration set. Reject foreign identities or a different graph.
3. Write `accepted-analysis-plan.json`; index components, selections, build actions and
   source-backed topology facts in the `target-analysis-plan` shard of `analysis`.
4. Verify the composed manifest and publish counts, gaps, plan identity and topology identity.
   Preserve unrelated upstream shards; an invalid index or plan prevents accepted publication.

## Dataflow

```mermaid
flowchart LR
  catalog["catalog_documents"] --> job["job_target_analysis_plan"]
  history["history_documents"] --> load["catalog_summary.load_accepted_catalog"]
  environment["build_environment"] --> load
  job --> load
  load --> summary["catalog_summary.summarize_components"]
  summary --> rules["analysis_decisions.apply_deterministic_rules"]
  rules --> resolve["analysis_decisions.resolve_ambiguity"]
  feedback["bounded_feedback + planning_feedback_cache"] <--> resolve
  resolve --> validate["plan_acceptance.validate_plan"]
  validate --> index["plan_acceptance.index_plan"]
  index --> output["analysis_plan + analysis_plan_documents"]
  feedback -. "bounds / abstention / invalid response" .-> gaps["coverage_gaps"]
  rules -. "unresolved topology" .-> gaps
```

## Gaps

This pinned job returns legacy strings in unit `gaps`; canonical outcomes convert them to
`producer_reported_gap`, `retryable=False`. They are not dedicated registered codes named
after feedback errors, and false is not an advisory waiver.

| Where | Causes retained in the plan or unit |
| --- | --- |
| Summary/deterministic rules | Summary truncation, inherited catalog omissions, disabled Swift, unavailable/stale history context, missing recognized build systems or compile databases, and the distinction between descriptor targets and compiled link outputs. |
| Environment/topology compilation | Partial/unavailable environment context; compiler-produced graph reasons for unsupported/unresolved ownership/products, cycles, dynamic declarations and incomplete dependency discovery. |
| Ambiguity resolution | Disabled/unavailable model, omitted bounded scopes, explicit model abstentions and bounded-feedback exhaustion. |
| `bounded_feedback` | Internal deadline, request/response byte bounds, call/evidence-round exhaustion, timeout/provider/output/schema errors, sensitive output rejection, invalid/out-of-scope/hash-mismatched evidence requests, repeated requests, document/additive byte bounds, unsupported encoding and sensitive evidence withheld. |

These are coverage reasons; a malformed cache, changed accepted evidence, escaped path,
invalid mandatory coverage or graph that fails reproduction raises instead of becoming a
safe fallback. Unexpected provider/application errors and external cancellation are not a
successful bounded exhaustion. A walk must establish every cause against source and its
approved expected-gaps list; deterministic unknowns still have a review cost.
Canonical outcome semantics are in [job interchange](../architecture/job-interchange.md).

## Acceptance

1. **A. Inputs:** Match catalog, history and environment read receipts to admitted handoff pins.
   Verify summary provenance, environment mode/reference and every additional evidence hash.
2. **B. Independent comparison:** Compare the plan's build-unit IDs/count against catalog
   descriptors, scanner scopes against independent applicability checks and graph edges
   against source declaration lines. Reproduce the deterministic graph from its evidence
   bundle; inspect selected recipe cwd/inputs/outputs without executing them.
3. **C. Gaps:** Group verified outcomes and inspect topology/feedback reasons, omitted scopes,
   null recipes and abstentions. A model-disabled run is not complete recipe coverage.
   Stop for any cause not authorized by the walk.
4. **D. Baseline:** After those checks, use `stepwise.py accept`; record corpus namespace and
   saved baseline of scoped units, selections, graph identity, recipe dispositions and gaps.

## Resume and invalidation

Whole-job admission binds catalog/history/environment, target and frozen configuration; planner
reuse additionally compares current environment availability with the stored plan.
`bounded_feedback` keys include the actual request/allowlists, accepted units, source,
guidance/model identity, whole evidence bundle, environment, profiles, rules, feedback limits
and call timeout. Complete-cache reads revalidate evidence, scopes, redaction and proposal;
partial/abstained/failed conversations are not reusable finals. The analysis shard binds the
accepted plan artifact plus parser/normalizer/mapping identities. A source change need not
rebuild unrelated jobs, but changed semantic inputs invalidate their downstream closure under
[Wave 1 resumability](../architecture/jobs-and-runtime.md#wave-1-resumability).

## Model usage

`build_planning` selects the [DevOps persona](../generated/guidance.md#personas-devops_engineer)
with the family-specific Build Engineer role because the bounded question is how to prepare
that family's accepted build unit, not whether the application is vulnerable. Roles cover
[native](../generated/guidance.md#roles-build_engineer_native),
[Rust](../generated/guidance.md#roles-build_engineer_rust),
[Go](../generated/guidance.md#roles-build_engineer_go),
[Java](../generated/guidance.md#roles-build_engineer_java),
[Node](../generated/guidance.md#roles-build_engineer_node),
[.NET](../generated/guidance.md#roles-build_engineer_dotnet),
[Python](../generated/guidance.md#roles-build_engineer_python),
[PHP](../generated/guidance.md#roles-build_engineer_php) and
[Wasm](../generated/guidance.md#roles-build_engineer_wasm).
The [registered planning procedure](../generated/guidance.md#runtime_skills-target-analysis-planning)
is selected through the governed worker boundary; Unity is excluded from generic inference.
Request allowlists grant no scanner/component choices in this path. See
[worker prompt contracts](../architecture/worker-prompt-contracts.md) for assembly and authority;
generated declarations above identify model settings without proving a call occurred.
