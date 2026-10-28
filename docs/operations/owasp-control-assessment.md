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

Direct CLI `start`, `resume` and `plan-resume` also select security tagging and OWASP after
prioritization/code-graph indexing and before review data indexing. Normal enabled-job filtering
applies: OWASP is selected by default, and `resume`/`plan-resume --force-from` can name tagging
or OWASP only when that job is enabled. This does not add Dagster's CI/post-build branches or
standalone third-party sync to the direct graph. A standalone dispatch must use the run's accepted
upstream handoffs and snapshot, not an arbitrary source tree.

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
The closed typed settings parser rejects missing/unknown keys and out-of-range values.

| Key | Default | Allowed | Meaning |
|---|---|---|---|
| `enabled` | true | boolean | Generic job dispatch gate; false explicitly opts out |
| `mode` | `assessment` | `assessment`, `qualification` | Accepted target assessment or explicit synthetic exercise |
| `reviewer_profile` | `reviewer` | configured `models` key | Fresh blinded reviewer model profile |
| `asvs_level` | 2 | 1, 2, 3 | Upstream ASVS level selection |
| `masvs_profile` | `L2` | `L1`, `L2` | Local aliases, both selecting all 24 MASVS 2 controls; not upstream levels |
| `max_batch_size` | 12 | 1–64 | Control-component rows per batch |
| `max_components_per_batch` | 5 | 1–16 | Distinct components per batch |
| `max_components` | 128 | 1–128 | Components accepted for classification |
| `max_evidence_per_component` | 60 | 1–200 | Accepted evidence/routing bounds; omissions remain named |
| `max_source_lines` | 120 | 1–500 | Source materialization cap, recorded in publication `assessment_bounds` |
| `max_subjects_per_control` | 8 | 1–32 | Named proof subjects per control |
| `max_batches` | 200 | 1–10000 | Admitted validation batches; excluded work remains gaps |
| `max_turns` | 4 | 1–16 | Turns per bounded investigation |
| `max_queries` | 12 | 1–100 | Model-requested retrieval budget per investigation |
| `dynamic_authorized` | false | boolean | Authorization policy, not adapter availability; no runtime/manual evidence adapter is implemented |
| `model.*` | enabled, `claude-cli`, `claude-haiku-5-5`, `medium`, 24000 / 6000 tokens, 120 s, 1 retry | complete selected model profile | Worker policy; separate job-level gate controls dispatch |
| `models.reviewer.*` | same as worker | complete selected model profile | Separate fresh request context using original evidence, no prior worker answer/transcript |
| `parser_versions.*` | `component_rules`, `applicability_rules`, `batching_rules`, `result_validator` = `"1"` | strings | Versioned parser/validator fingerprint inputs |
| `standards.<family>` | complete catalog pins in TOML | pinned catalog path/hash and upstream identity | Reviewed ASVS, MASVS, MASTG and risk-context catalogs |

Selected model profiles require `enabled`, `provider`, `model`, `reasoning`, `max_input_tokens`,
`max_output_tokens`, `timeout_seconds` and `retries`. Enabling assessment requires both selected
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

Inventory completeness is not procedure coverage. Exactly four reviewed **Python static**
procedures exist: ASVS `V1.2.4`, `V6.2.1`, `V8.2.1`, `V8.3.1`, with narrow subject recognition and
materially complete, parseable, unredacted source requirements. Unsupported controls/languages
remain unassessed/unresolved. `MASVS-NETWORK-1` has no runtime adapter even if authorization is
enabled. Inspect the architecture's procedure table before interpreting results.

## Outputs and interpretation

Inspect these run-owned paths after a run:

- `data/configuration/resolved.json` and configuration manifest: frozen global settings identity;
- `data/guidance/<sha256>/`: exact hash-pinned worker/reviewer bundles;
- `data/indexes/owasp/accepted.json`: accepted immutable shard manifest, mode, upstream identity
  and resolved `assessment_bounds`;
- `data/indexes/owasp/receipts/<semantic-key>.json`: shared-namespace model receipts;
- the attempt's `artifacts/owasp-workbench/`: selection, classification, applicability, batches,
  model results, independent review, join, publication and metrics; and
- `data/logs/pipeline.jsonl`: worker lifecycle and actual model attempts.

Reconcile catalog inventory, profile selection, applicability, dispatched rows, independently
reviewed rows, unresolved rows and eligible leads as **different denominators**. Per-row dispatch
and review-attempt counts include only rows actually sent, not unready neighbors in the same
batch. Check `model_calls`/attempts, requested provider/model and available served identities,
reported versus estimated tokens, unknown-usage attempts, retries, source-resolution work and
`model_requested_retrievals` separately. Unknown usage/cost is `None`, not measured zero; verified
reuse records zero **new calls**, not zero historical cost.

`not_satisfied` is not exploit confirmation. `satisfied` is scoped counterevidence, not a safety
claim. Failed/unsupported/`not_assessed`/`cannot_verify` work is unresolved coverage, not evidence
of a missing control. Dissent, assumptions, evidence requests and limitations must remain visible.
High/Critical or ship-blocking hypotheses are still provisional.

Review data indexing projects results into PRECOMPUTED `control_evidence`; eligible adverse
hypotheses become provisional `owasp_control` leads and enter lead/hunt packages. Original refs,
scope, independent counterevidence and authority links remain intact. Every PRECOMPUTED
interpretation is indirect for every final predicate; red/blue/verifier roles must retrieve original
evidence and establish their own predicates. They do not inherit an OWASP verdict as direct proof.

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

Scripted offline acceptance covers actual full-catalog publications through projection, packages
and red/blue/verifier request bodies with source retrieval and indirect-proof guards. It is not
live-provider efficacy validation, real-host target execution, runtime-adapter acceptance, exploit
confirmation or customer safety certification.
