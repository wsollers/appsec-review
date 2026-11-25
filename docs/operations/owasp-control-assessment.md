---
title: "Operating the OWASP control-assessment stage"
kind: "operations"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_owasp_control_assessment"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# Operating the OWASP control-assessment stage

`job_owasp_control_assessment` is **enabled by default** in `mode = "assessment"` across all
shipped profiles. Its worker and reviewer profiles are enabled.
It performs bounded accepted-index/source assessment, never target execution or a compliance audit.
See the [workbench architecture](../architecture/owasp-control-workbench.md) for proof boundaries.
The [assignment table](../architecture/owasp-control-workbench.md#control-area-persona-role-and-runtime-skill-assignment)
documents the seven control-area personas and the assessor/reviewer runtime skills. Inspect the
run's pinned guidance bundles to see the exact assignments used.

## Prerequisites and placement

In Dagster's `wave1_review`, the enabled job waits for accepted component/source/evidence/build
information, CodeQL, artifact-security analysis, Tree-sitter and post-build assessment, plus
review prioritization, code-graph indexing and security tagging when registered. The tag cloud,
classification and graph context route work; they do not prove control outcomes. OWASP then
precedes review data indexing, package assembly, hunting, red/blue review and independent
verification. Prioritization and tagging do not depend on OWASP.

With the collation pass (T-5008, [design](../architecture/collation-pass.md)) the workbench no
longer classifies components itself: it reads the component's `target:*` class and facet tags
from the accepted `tags` index, derives the component roles from them (the control side's roles come
from the chapter role map, since the ingested catalogs carry none), and gates applicability on
the class. A component that is not `target:web-api` gets every selected ASVS control as
`not_applicable` with the target-class citation, except that `target:network-service` (a non-HTTP
listener) admits the transport-agnostic ASVS 5.0 chapters V1, V2, V5, V7 and V16 (ledger verdict
`partially_applicable`, rows carry `admitted_chapters`); one that is not `target:mobile` is
`not_applicable` for MASVS; such a component produces no batch, no `OWASP_WORKER_STARTED` event and
no `control_evidence` fact, and the job ends `SUCCEEDED` with a not-applicable ledger when the
pinned catalogs report no gap of their own. This is implemented: `classify_components` reads the
tags (`tag_assignment` rows of the `tags` index under `max_tag_records`; priority/graph rows are a
separately capped `graph_context`), `build_applicability` applies the class gate first
(`applicability-rules/4`, rows carry `target_classes`, `target_class_citations`, `basis_class` and
`admitted_chapters`), `target-class-ledger.json` records the per-family verdict per component, a
component whose accepted sources no recogniser reads (Python and C/C++ are read; T-5013) is
`unsupported_missing_evidence` ("no supported source language for this component") on every
admitted row, an admitted control with no procedure for the component's languages is
`unsupported_missing_evidence` naming the missing recogniser ("no C/C++ recogniser for this
control"), and a component without a `target:*` tag is `cannot_determine` for every control and
is not dispatched; when the tag cap dropped a target or facet record the reason is "target class
not read: routing cap omitted tag records" and the component carries a gap. Review data indexing
projects only attempted or reused, subject-bound assessments into `control_evidence`.
`not_applicable`, `cannot_determine`, `unsupported_missing_evidence`, unassessed and subjectless rows
stay in the workbench coverage ledger; omitted unresolved rows retain a counted coverage gap.
Applicable rows without a supported subject have explicit `non_dispatch_dispositions`, no
`OWASP_WORKER_STARTED` event, no model call and no failed batch. Such batches do not consume
`max_batches`; missing coverage remains unresolved.
The handoff's `gaps` are missing coverage (catalog and result gaps); the method limitations stay
under `limitations`; `coverage_disposition` is `partial` while any row is unresolved and
`complete` otherwise. `selection.json` records a `reasons` list per family.
Unit control outputs use `ProducerStatus` and strict `appsec-review/producer-gap/1` records,
including the publication receipt's complete gap list. Domain rows and the workbench result
artifact retain their descriptive gap text; those payloads are not additional control records.

Direct CLI `start`, `resume` and `plan-resume` also select security tagging and OWASP after
prioritization/code-graph indexing and before review data indexing. Normal enabled-job filtering
applies: OWASP is selected by default, and `resume`/`plan-resume --force-from` can name tagging
or OWASP only when that job is enabled. Both drivers now use the same typed review-job contracts,
including enabled CI/post-build producers; third-party sync remains standalone. A standalone dispatch must use the run's accepted
upstream handoffs and snapshot, not an arbitrary source tree.
The job opens its explicit producer/index source view before payload validation. The manifest
path and hash must be pinned explicitly; selected reads never fall back to an ambient accepted pointer.
The original manifest and ancestry identities remain authenticated; excluded and superseded ancestor payloads are not
opened or recorded as reads. Selected shards still need the exact admitted dataset owner, schema,
authority and handoff pin. Generated-source and binary-source backing records are separate admitted
custody dependencies; absent grants or unresolved relation endpoints fail closed. The input record
keeps the original manifest hash, a separate view identity and named `not_selected` exclusions.
Default retrieval callers without a selection retain full-manifest verification.
Private publication receipts are checked again on later selected reads, including named bindings,
producer-receipt chains and declared dependencies. A missing, replaced or mutated receipt is an
integrity failure. A dependency outside the selected/admitted inputs is refused before its bytes
are read; it is not silently added to the query surface or to the job's input grants. Required
publication metadata is identified from authenticated producer contracts, never target labels.

For assessment, retain `enabled = true`, `mode = "assessment"` and enabled worker/reviewer profiles,
and configure the intended provider, models and budgets before freezing a new run. Set
`jobs.job_owasp_control_assessment.settings.enabled = false` in central configuration to opt out;
model profiles do not override this gate. Assessment rejects qualification catalogs and a run-owned qualification input.
An unsupported provider or invalid bounds fail configuration validation.

Qualification requires explicit `mode = "qualification"`, both selected model profiles disabled,
and `runs/<run-id>/data/inputs/owasp-workbench.json`. File presence never changes modes. It is a
synthetic integration exercise, visibly qualification-only, with no production-eligible leads.

## Settings

All keys live under `[jobs.job_owasp_control_assessment.settings]` in `appsec-review.toml`.
The closed typed settings parser rejects missing required keys, unknown keys and out-of-range
values. `max_discovery_files`, `max_discovery_bytes`, `max_tag_records` and
`source_dispositions` are optional and receive their typed defaults.

| Key | Default | Allowed | Meaning |
|---|---|---|---|
| `enabled` | true | boolean | Generic job dispatch gate; false explicitly opts out |
| `mode` | `assessment` | `assessment`, `qualification` | Accepted target assessment or explicit synthetic exercise |
| `reviewer_profile` | `reviewer` | configured `models` key | Fresh blinded reviewer model profile |
| `asvs_level` | 2 | 1, 2, 3 | Upstream ASVS level selection |
| `masvs_profile` | `L2` | `L1`, `L2` | Local aliases, both selecting all 24 MASVS 2 controls; not upstream levels |
| `max_batch_size` | 12 | 1–64 | Control-component rows per batch |
| `max_components_per_batch` | 5 | 1–16 | Distinct components per batch |
| `max_components` | 128 | 1–128 | Components accepted for tag-based classification |
| `max_discovery_files` | 512 | 1–4096 | Candidate accepted source files per component; omission counts remain explicit |
| `max_discovery_bytes` | 8388608 | 1–16777216 | Total accepted source bytes inspected per component |
| `max_evidence_per_component` | 60 | 1–200 | Accepted evidence, tag-record and priority/graph context bounds per component; a dropped component-level target/facet record is a gap |
| `max_tag_records` | 20000 | 1–200000 | `tag_assignment` rows read from the `tags` index for classification; reaching it is a gap |
| `max_source_lines` | 120 | 1–500 | Source materialization cap, recorded in publication `assessment_bounds` |
| `max_subjects_per_control` | 8 | 1–32 | Named proof subjects per control |
| (derived) package evidence budget | `model.max_input_tokens` × 4 ÷ 2 ÷ rows in the batch | bytes | Evidence excerpts carried per package; obligations' own records first, the rest through expansion |
| `max_batches` | 200 | 1–10000 | Admitted validation batches; excluded work remains gaps |
| `max_turns` | 4 | 1–16 | Turns per bounded investigation |
| `max_queries` | 12 | 1–100 | Model-requested retrieval budget per investigation |
| `dynamic_authorized` | false | boolean | Authorization policy, not adapter availability; no runtime/manual evidence adapter is implemented |
| `model.*` | enabled, `claude-cli`, `claude-haiku-5-5`, `medium`, 24000 / 6000 tokens, 120 s, 1 retry | complete selected model profile | Worker policy; separate job-level gate controls dispatch |
| `models.reviewer.*` | same as worker | complete selected model profile | Separate fresh request context using original evidence, no prior worker answer/transcript |
| `parser_versions.*` | component rules `"2"`; applicability rules `"4"`; batching rules `"1"`; evidence binding `"4"`; subject selection `"2"`; result validator `"4"` | strings | Must equal the versions the code implements (`owasp_workbench/versions.py`); the job's input validator refuses any other value |
| `standards.<family>` | complete catalog pins in TOML | pinned catalog path/hash and upstream identity | Reviewed ASVS, MASVS, MASTG and risk-context catalogs |

Selected model profiles require `enabled`, `provider`, `model`, `reasoning`, `max_input_tokens`,
`max_output_tokens`, `timeout_seconds` and `retries`. Fully assembled requests undergo a second
size check: oversized batches split, and oversized single rows trim bounded context in recorded
order while retaining subject/reference identities. Inspect each part's receipt, estimates,
trim/non-dispatch gaps and independent turn/query budget, not just the original batch count.
See [request assembly](../architecture/owasp-control-workbench.md) for the exact trimming order.
Enabling assessment requires both selected
profiles enabled; enabling qualification requires both disabled. Token estimates bound requests;
provider output, time, turn and retrieval limits are enforced. No prompt may widen these bounds.

## Catalog checks and supported assessment

The complete pinned catalogs contain 345 ASVS controls, 24 MASVS controls, 292 MASTG supporting
test documents (including `tests-beta`), and 10 records in each Top 10 risk catalog. Independent
Git tree/blob/ID inventories and reviewed normalized-content/license pins validate completeness.
Retain attribution, license text and change notices on redistribution. Replacing a catalog hash
alone cannot authorize changed source text, metadata or an incomplete inventory. Acquisition is an
explicit separate operation in `owasp_workbench.acquisition`; ordinary jobs/tests do not refresh
upstream data. No new live upstream revalidation is claimed by offline acceptance.

Inventory completeness is not procedure coverage. The reviewed static procedures are the four
**Python** ones (ASVS `V1.2.4`, `V6.2.1`, `V8.2.1`, `V8.3.1`) and nineteen **C/C++** ones for the
chapters a network service admits (`V1.2.5`, `V1.3.3`, `V1.3.10`, `V1.4.1`, `V1.4.2`, `V1.4.3`,
`V2.2.1`, `V5.3.2`, `V7.2.2`, `V7.2.3`, `V7.3.1`, `V7.3.2`, `V7.4.1`, `V16.2.1`, `V16.2.5`,
`V16.3.4`, `V16.4.1`, `V16.5.1`, `V16.5.3`), each bound to one recogniser family whose subject is a
complete function with its entry and sink lines. Recognition is narrow and lexical; excerpts must be
materially complete, parseable or scannable, and unredacted. A control without a procedure for the
component's languages, an unsupported language and a scanner gap (macro bodies, K&R definitions,
unbalanced braces) remain unassessed/unresolved and say so. `MASVS-NETWORK-1` has no runtime adapter
even if authorization is enabled. Inspect the architecture's procedure tables before interpreting
results.

## Outputs and interpretation

Inspect these run-owned paths after a run:

- `data/configuration/resolved.json` and configuration manifest: frozen global settings identity;
- `data/guidance/<sha256>/`: exact hash-pinned worker/reviewer bundles;
- `data/indexes/owasp/accepted.json`: accepted immutable shard manifest, mode, upstream identity
  and resolved `assessment_bounds`;
- `data/indexes/owasp/receipts/<semantic-key>.json`: shared-namespace model receipts;
- the attempt's `artifacts/owasp-workbench/`: `standards-manifest.json`, `selection.json`,
  `component-classifications.json`, `target-class-ledger.json`, `applicability.json`,
  `validation-work.json`, `finding-packages.json`, `verified-results.json`,
  `control-results.json` and `owasp-workbench-result.json`; and
- `data/logs/pipeline.jsonl`: task/worker lifecycle, correlated model attempts, reuse and expansion
  dispositions; and
- `data/telemetry/summary.json`: regenerated by `appsec-review metrics --run-id <id>`, including
  receipt-backed `owasp` coverage, `model_invocations`, and downstream `review_flow` milestones.

Reconcile catalog inventory, profile selection, applicability, dispatched rows, independently
reviewed rows, unresolved rows and eligible leads as **different denominators**. Per-row dispatch
and review-attempt counts include only rows actually sent, not unready neighbors in the same
batch. Check `model_calls`/attempts, requested provider/model and available served identities,
reported versus estimated tokens, unknown-usage attempts, retries, source-resolution work and
`model_requested_retrievals` separately. Unknown usage/cost is `None`, not measured zero; verified
reuse records zero **new calls**, not zero historical cost.

Both worker and blinded reviewer requests emit standard model start/terminal events, including
provider failure, timeout and interruption. Their role/persona, batch/cell, job attempt and task
remain correlated through the central stream. Downstream lead/hunt red, blue, verifier and judge
calls use the same measurement helper; completed cells record fresh/reused/not-launched disposition.
Stage timing and failures remain on the existing generic task/step/operation lifecycle. Projection
and package publication retain counts and manifest pins so operators can locate a delivery gap
without interpreting a model proposal as a finding. See [telemetry semantics](../architecture/telemetry.md).

`not_satisfied` is not exploit confirmation. `satisfied` is scoped counterevidence, not a safety
claim. Failed/unsupported/`not_assessed`/`cannot_verify` work is unresolved coverage, not evidence
of a missing control. Dissent, assumptions, evidence requests and limitations must remain visible.
High/Critical or ship-blocking hypotheses are still provisional.

Review data indexing projects results into PRECOMPUTED `control_evidence`; eligible adverse
hypotheses become provisional `owasp_control` leads and enter lead/hunt packages. Original refs,
scope, independent counterevidence and authority links remain intact. Every PRECOMPUTED
interpretation is indirect for every final predicate; red/blue/verifier roles must retrieve original
evidence and establish their own predicates. They do not inherit an OWASP verdict as direct proof.
Control context is attached only to the same component and resolved primary subject source, not
every package in the component. Worker-facing references use
`query_precomputed query_set=control_evidence`; `query_owasp_workbench` is an application/operator
route, not a new worker tool grant. Its finding-package component/project/control filters resolve
the package's nested identities.

## Failure, reuse and acceptance limits

A completed join must contain every selected control-component row exactly once. Missing,
duplicate or unexpected rows block publication. Cell failure is a scoped gap, not permission to
discard successful siblings. Resume the same application run through its normal accepted-handoff
lifecycle; do not edit immutable publications or fabricate a successful reviewer record.

Semantic receipts bind mode, local evidence/routing, catalog/proof/rules, guidance, model policy,
bounds and scope. Reuse verifies provenance and rebinds current accepted references. Unrelated
manifest re-pins can reuse unchanged work with no new model calls; relevant source/context,
guidance or model changes invalidate it. Downstream verified expansion is operation-local only
and retains run/snapshot/pin, citation and duplicate-ambiguity checks.
Packages pin assessor and blinded reviewer bundles once in `guidance_by_role`; calls authenticate
and render those pins rather than composing different guidance. Publication fingerprints and
`publication.publish_indexes.invocation_guidance` bind the per-role bundles actually used by
dispatched or reused investigations, excluding merely prepared, undispatched roles.

Scripted offline acceptance covers actual full-catalog publications through projection, packages
and red/blue/verifier request bodies with source retrieval and indirect-proof guards. It is not
live-provider efficacy validation, real-host target execution, runtime-adapter acceptance, exploit
confirmation or customer safety certification.


## Tuning and whole-job recovery: `job_owasp_control_assessment`

Defaults below are the checked-in base recipe; the admitted profile/overlay may override them.
Only the exact declared leaves are mutable; unknown and mixed material changes are refused.

| Exact path relative to this job (unless global) | Base default | Category | Bounds |
| --- | --- | --- | --- |
| `settings.max_batch_size` | `12` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_batches` | `200` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_components` | `128` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_components_per_batch` | `5` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_discovery_bytes` | `8388608` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_discovery_files` | `512` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_evidence_per_component` | `60` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_queries` | `12` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_source_lines` | `120` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_subjects_per_control` | `8` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_tag_records` | `20000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_turns` | `4` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.model.max_input_tokens` | `24000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.model.max_output_tokens` | `6000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.model.retries` | `1` | coverage | integer >=0; exact parser/cross-field bounds? |
| `settings.model.timeout_seconds` | `120` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.models.reviewer.max_input_tokens` | `24000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.models.reviewer.max_output_tokens` | `6000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.models.reviewer.retries` | `1` | coverage | integer >=0; exact parser/cross-field bounds? |
| `settings.models.reviewer.timeout_seconds` | `120` | coverage | positive integer; exact parser/cross-field bounds? |

? The [executing job/parser](../../src/appsec_review/jobs/job_owasp_control_assessment/job.py) remains the bounds authority, including hard maxima, numeric types and cross-field checks; compatibility never widens it. A type-only range in this table is not permission to bypass stricter parser limits.

Execution changes affect only new attempts. Coverage changes preserve accepted results with their original limits and gaps; expanded coverage requires an explicit whole-job rerun and reconsideration of affected downstream jobs. New/failed attempts execute every unit, without salvaging earlier cells. Retained accepted jobs are validated with their original configuration. Global scheduler/resource tuning does not alter tool/sandbox authority or resize active leases. See [general tuning](../architecture/runtime-interchange.md#operational-configuration-compatibility-and-attempt-ownership).

### Specifically excluded candidates

| Exact setting | Technical reason it remains material |
| --- | --- |
| `workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `settings.enabled` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `settings.asvs_level` | ASVS level and selected model/framework change the required assessment/control set. |
| `settings.dynamic_authorized` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `settings.model.enabled` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `settings.model.provider` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `settings.model.model` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `settings.model.reasoning` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `settings.models.reviewer.enabled` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `settings.models.reviewer.provider` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `settings.models.reviewer.model` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `settings.models.reviewer.reasoning` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `steps.standards_selection.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.characterization.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.applicability.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.batching.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.validation.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.verification.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.join.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.publication.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |

Source/rule/tool/schema identities, model/provider/reasoning, input selection and signing/authorization remain material even when not numeric.

### Reading input-budget calibration

`parts[].input_tokens_estimated` is the planning estimate for one part. Each dispatched
attempt records its own `estimated_input_tokens` for the actual turn, including retries and
the current transcript. Compare it with `input_tokens`: a positive `input_estimate_delta`
means the estimator overestimated. `output_tokens` and `cache_tokens` are separate provider
measurements, not deductions. Part and batch calibration totals cover new dispatches once,
not once per row; a missing provider report makes the corresponding total and delta unknown.
A reused receipt or an undispatched part has no new measured usage.
