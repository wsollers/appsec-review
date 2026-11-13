---
title: "Threat-driven hunting: evidence-bound coverage and budget allocation"
kind: "architecture"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_inference_security_review", "job_review_data_indexing", "job_review_package_assembly", "job_review_prioritization", "job_security_tagging", "job_threat_model_generation"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Threat-driven hunting enhancement

**PROPOSED — NOT IMPLEMENTED OR APPROVED.** This is the additional design resulting from the
[2026-11-13 subsystem review](../reviews/2026-11-13-threat-driven-hunting-review.md), whose
source baseline is 5926171238607e27a948bc7d40ce190a853b3d0c. It does not change run configuration,
worker authority, target files, finding adjudication, launch permissions or existing accepted
artifacts.

[T-146](../tasks/2026-11-13-behavior-oriented-review.md) was approved and in flight during
inspection, and landed before registry integration at main
`2612ee80f305970707520ad92774d1e1c1336c1c`.
**Extend its operation identities, fallback accounting, observed tags and optional generated-map
context; do not create another operation map or another generated-model consumer.** The exact
landed T-146 contract, documented in its
[implementation record](../tasks/2026-11-13-behavior-oriented-review.md#implementation-and-verification-record),
must be reconciled when implementing each slice. This document proposes additive
records and measurement semantics, not an incompatible fork of that contract.

## Outcome, non-goals and tradeoffs

The desired user-visible answer is:

> Of the source-anchored attack-surface opportunities we could discover in this snapshot and
> configuration, these bounded questions were investigated with these evidence reads; these
> were not, for these reasons; these independently supported findings were additional to the
> scanner baseline.

Measurable outcomes:

1. Every discovered operation/fallback subject remains in an exact, bounded scope-accounting
   partition before and after selection. No cutoff or view limit silently changes the denominator.
2. A completed worker cannot mark an unaddressed operation, unread excerpt, or same-file sibling
   operation as investigated. Existing execution coverage remains separately reportable.
3. A pinned selection policy gives less-instrumented and fallback strata a declared opportunity
   without silently raising budgets or shrinking mandatory lead admission.
4. Every retained question and evidence request has a scoped disposition; missing source,
   deployment, policy, budget or authority remains uncertainty.
5. Paired, independently labeled evaluations establish whether verified hunt-only yield and
   known-surface coverage improve at comparable cost. Structural checks alone cannot do this.

Non-goals: whole-program exposure proof; inventing owner intent; executing targets; automatically
commissioning new builds, scans, deployments or dynamic evidence; new worker tools; reducing
reviewer counts; replacing verifier/judge/proof obligations; redefining finding severity; changing
lane A admission; new canonical buckets; cross-package variants or attack-chain redesign.

Tradeoffs are explicit. Fairness spends some attention away from the top score. Additional
receipts consume storage and validation time. Conservative coverage will initially look lower
than today's package-success proxy. Source-only fallback is valuable but cannot substitute for
compiled semantic facts. Retaining unknown dimensions reduces apparently complete dashboards
while improving honesty. These costs require measurement, not an assertion that more prompts
or more recorded surfaces automatically improve findings.

## Extension points and evidence authority

The reviewed base is documented in the review's
[flow table](../reviews/2026-11-13-threat-driven-hunting-review.md#current-end-to-end-flow).
T-146 is expected to provide a stable operation anchor, component/build scope, original source
references, applicable behavioral context, optional generated-map references, fallback reason
and all-source accounting. Reuse those fields and identities wherever they land.

The additional object is a **coverage obligation**, not a second operation. It says:
“Investigate question Q about existing operation O under evidence/configuration scope S.”
The application selects it; the worker cannot change its scope by claiming the excerpt is
complete. Multiple obligations may reference one operation; multiple producer observations
of one site do not create independent opportunities.

### Cross-design ownership decision

The 2026-11-13 cross-design integration decision assigns **TRI-C**, in the
[triage/verifier design](triage-verifier-enhancement.md), the single claim evidence-obligation
identity, canonical evidence-request identity/deduplication, deterministic warranted resolution
and ledger terminal closure. HUNT coverage obligations identify operation/questions, not claim
evidence obligations. They reference TRI-C's canonical IDs and outcomes; they never replace them.

**HUNT-C** owns operation/question coverage dispositions and actual transport, served and
delivery receipts. It must not implement a second evidence-request state machine, deduplicator
or semantic closure rule. **Served or delivered is not resolved.** **TRI-A** consumes HUNT-C's
coverage receipts in its decision audit rather than producing another copy of them.

HUNT-C may publish useful delivered-span and legacy-resolution-unknown receipts before TRI-C
lands. Those records retain original transport/request references with canonical resolution
unavailable; they cannot claim resolved evidence. HUNT-C's final integrated resolved-evidence
acceptance depends on TRI-C. This agreed ownership boundary does not approve runtime
implementation of either design.

Authority remains layered:

- Original accepted source/producer records carry evidence. A valid source location must resolve
  to the pinned snapshot/file bytes; artifact facts retain producing attempt and digest.
- Syntax proves the written construct, not dispatch resolution or deployed exposure. A graph
  fact is limited by its exactness, source model, build scope, seed ledger and coverage state.
- Static API/deployment documents are declarations. Operator-selected deployment/configuration
  facts are separately attributed, never guessed from a file name or default.
- Tags, rank, generated actors, boundaries, STRIDE templates and the obligation itself are
  routing context. They cannot directly satisfy vulnerability predicates.
- A cell receipt proves a bounded execution/delivery event. A validated investigation disposition
  proves a recorded answer addressed a bounded question; neither proves correctness, safety,
  internal model attention or absence of missed bugs.
- Verification, adjudication and certified reporting keep their current authority.

### Identity and scope

Proposed wire names below are **design examples**, not registered datasets or schemas:

```text
attack_surface_obligations  appsec-review/attack-surface-obligations/1
hunt_selection_plan        appsec-review/hunt-selection-plan/1
hunt_investigation_receipts appsec-review/hunt-investigation-receipt/1
hunt_coverage_projection    appsec-review/hunt-coverage-projection/1
```

The first record is a projection of T-146's units, not an independent discovery job:

```text
coverage_obligation_id = H(contract_version, operation_id, source_content_identity,
                           question_template_version, relevant_scope_identity)
# Different identity domain from TRI-C's canonical claim evidence obligations.

operation_ref:
  operation_id             # reuse T-146 identity; no copy with a different key
  source_refs[]            # logical ID, path, exact span, file hash, publication pins
  component_refs[]         # resolved, shared, ambiguous or unknown attribution
  build_scope:
    catalog_unit_id
    producing_action_refs[]
    artifact_refs[]
    build_variant_ref      # nullable; never default "shipping"
    catalogued / built / extracted / shipped_evidence  # distinct typed facets
  discovery:
    source_kind            # graph, syntax, declaration or bounded fallback
    producer_refs[]
    language
    seed_scope_ref
    completeness
    omitted_or_unknown_reasons[]

question:
  template_id/version
  bounded_subject_refs[]
  input_or_entry_refs[]
  sensitive_operation_or_resource_refs[]
  candidate_boundary_refs[] # T-146 optional generated context, still routing-only
  attacker_position: {value?, basis, refs[], unknown_reason?}
  input_control: {value?, basis, refs[], unknown_reason?}
  ownership: {value?, basis, refs[], unknown_reason?}
  deployment: {declaration?, effective_observation?, selection_ref?, unknown_reason?}
  policy_or_asset_sensitivity: {value?, basis, refs[], unknown_reason?}
  required_evidence_classes[]
  disconfirming_questions[]
  coverage_scope           # application-established complete subject or partial/fallback
  gaps[]
```

Use the existing T-070/T-076 closed finding vocabularies where applicable; generic source classes
and candidate attacker positions are separate fields, not fabricated finding dimensions.
For example `remote` does not choose client→server versus server→client, and file input does not
establish a hostile supplier. Technical source attribution is separate from product ownership
and actor ownership of a protected resource.

Stable within-snapshot identity includes content and scope; reuse additionally pins all admitted
publication digests, relevant configuration, extractor/mapping/template versions and T-146
assembly semantics. Display labels, order of returned rows, model prose and timestamps are
excluded. Moving a site or changing configuration may change identity; cross-revision similarity
is a separate linkage with uncertainty, not a license to reuse a completed investigation.
Ambiguous shared-library ownership retains multiple candidate owners without multiplying
the same question's selection weight.

### Coverage obligations, not a generic checklist

Create questions only from evidenced anchors and explicit unknowns. Keep the existing family
proof-obligation vocabulary; a routing question does not add a new adjudication predicate.

| Anchor | Bounded investigation question | Required original evidence / named uncertainty |
| --- | --- | --- |
| Remote handler plus resource mutation | Which established actor may request which resource transition, and where is that policy enforced? | Entry and mutation source, guard/policy source, configuration when relevant; actor privilege and ownership may be unknown |
| Hostile-content candidate plus parser operation | Can supplier-controlled size/offset/lifetime exceed the accepted object's bound at this operation? | Loader/parser/arithmetic/lifetime source, accepted range/path facts if available; file supplier and compilation scope remain separate |
| Process/code-loading sink | Which input reaches the interpreter/module boundary and which control constrains it? | Source-to-operation evidence, parser/quoting/allowlist counterevidence; co-location or callee-name match cannot prove flow |
| Resource-intensive operation | What attacker work produces what bounded CPU/memory/storage cost under this configuration? | Loop/allocation/resource-limit source; runtime cost unmeasured unless commissioned evidence already exists |
| Source-only fallback subject | What input/control/resource boundary can be established in this complete source subject, and what cannot? | Exact delivered source; unknown language/graph/build gaps; no automatic semantic-path obligation closure |

Deduplicate by operation, question family and relevant configuration, not by number of tags,
STRIDE templates, scanners or personas. A question with no sufficient evidence path is retained
as blocked/unknown, not discarded as irrelevant. Do not infer not-applicable from missing
data. Each non-applicable disposition requires a positive, scope-bound applicability reason.

## Intelligence product contracts and retrieval

Bucket names in this section are **provisional Stage 3 examples** from
[the documentation program](../tasks/2026-11-13-docs-program-prompt.md#stage-3-intelligence-buckets-and-the-two-matrices).
T-129 owns the final mapping to catalog tool IDs and typed output kinds. No “attack surface”
or subsystem-name bucket is introduced. Exact proposed wire identifiers are listed in the
fenced example above; their final versions must be assigned against the landed T-146 schemas.

### P1 — Operation-bound surface obligations

- **Producer / conceptual bucket:** `job_inference_security_review`, existing packages stage;
  provisional `review_claims`. Pure projection of T-146 units and already admitted context.
- **Dataset/schema:** proposed attack_surface_obligations / version-1 contract above; extend
  inference `review_packages` with obligation IDs and a scoped question projection. Do not
  change the separate catalog `document_hunt` producer to emit a competing operation inventory.
- **Publication/query route:** immutable artifact under the producer attempt, declared
  artifact-only with the explicit exception “pre-cutoff planning record, consumed by package
  assembly and accepted coverage reader; no unrestricted worker discovery route.” Selected
  rows appear in the existing model-facing package and hash-referenced package files with
  bounded `expand` file paging. The operator/coverage adapter reads the accepted artifact by
  obligation ID, not a target-tree scan. **No upstream precomputed index is invented after the
  indexing stage** and no circular dependency on review output is added.
- **Source/provenance/ceiling:** original source/build/graph/declaration pins plus T-146 operation
  ID, mapping/template versions, input-read receipts and routing-only generated references.
  Authority is routing_context; it never becomes a direct finding citation.
- **Consumer/value:** package assembler/router and hypothesis hunter get one explicit question;
  refuter/verifier see its bounded scope without inheriting an answer. T-073 gets the full
  discovered denominator, including below-cutoff/fallback subjects.
- **Bounds/gaps/redaction:** per-component and run candidate caps; bounded refs/questions/bytes;
  exact eligible counts when enumerated, otherwise lower bounds plus unenumerated scope.
  Unsupported language and ambiguous ownership are separate states. No raw secrets, deployment
  values or full target prose in indexed metadata. Redaction that hides security-relevant facts
  prevents a complete disposition.
- **Invalidation:** source/build/variant, operation, accepted-input, question-template and
  selection-relevant scope changes invalidate; optional missing versus supplied context changes
  the basis. Never rewrite historical runs to create obligations.

### P2 — Budgeted selection and omission plan

- **Producer / bucket:** same inference packages stage; provisional `metrics`.
- **Dataset/schema:** proposed hunt_selection_plan; existing package manifest enriched with
  selected obligation IDs, plan digest and precise omission references.
- **Route:** immutable artifact-only plan, accepted readers in execution and T-073 coverage;
  selected rationale appears in package-local context, sanitized aggregate plan in operator
  reporting. No new MCP-wide tool. This is execution/routing bookkeeping with a named consumer,
  not an unqueried intelligence dump.
- **Provenance/ceiling:** exact P1 digest, T-146 rank basis, typed budget/fairness settings, stable
  ordering/tie-breaker, group membership and planned package partition cost. Routing only.
- **Consumer/value:** scheduler knows the intended sequence and reservation cost; operator can
  explain why an operation was selected, displaced, too large or below the budget.
- **Bounds/gaps/redaction:** bounded group count and plan rows; all dropped work retains reason
  and scope; no full source/secret values. Cannot use generated threat severity or model
  confidence as an independent risk score. Upstream unenumerated scope is not silently assigned
  zero eligible operations.
- **Invalidation:** P1/rank/limits/grouping/policy versions and package partition rules enter the
  fingerprint. Execution stop receipts do not mutate the frozen plan.

### P3 — Investigation and evidence-request receipts

- **Producer / bucket:** existing inference cells/teams/publication stages; provisional
  `review_claims` for the protected evidence-bearing receipt.
- **Dataset/schema:** proposed hunt_investigation_receipts, derived from existing `review_cells`
  and claim-ledger records, referencing their hashes rather than copying transcripts. Any
  required change to the closed cell receipt/result schema is versioned.
- **Route:** protected immutable artifacts; only declared downstream readers can inspect full
  details. Workers receive only their package-local outstanding request/disposition context in
  later rounds, through the existing capability. P4 supplies sanitized operator coverage.
- **Provenance/ceiling:** obligation/plan/package/view hashes; role/persona/strategy; actual cell
  attempt/reuse receipt; exact input delivery and bounded retrieval identities/spans; cited
  original refs; accepted operation/question coverage disposition. Canonical claim
  evidence-obligation/request IDs and resolution/closure outcomes are read-only TRI-C references
  with their ledger/receipt hashes. Execution and provisional reasoning, not a finding or an
  independently resolved evidence request.
- **Consumer/value:** follow-up knows whether a request was served, not merely repeated; verifier
  can re-resolve source; coverage can distinguish an attempted question from an addressed one.
  TRI-C consumes delivery receipts as inputs to its warranted-resolution rule; TRI-A references
  these same coverage receipts in its decision audit instead of duplicating their production.
- **Bounds/gaps/redaction:** per-cell/round request and result caps, bounded source interval lists,
  no raw request text in public summaries. Preserve denial, unsupported evidence, truncation,
  unresolved mapping and cost cutoffs. Secret-bearing locators remain protected.
- **Invalidation:** bind the exact worker guidance/model/executor/validator/capability plus P1/P2
  and delivered-view identity. Any joined TRI-C outcome binds its canonical identity, rule
  version and ledger/receipt digest. Reuse preserves original provenance and consumes no
  invented new model work. Older receipts without question/delivery fields remain
  legacy-execution-only. New delivery-only receipts may precede TRI-C, explicitly marked
  legacy-resolution-unknown; integrated resolved-evidence acceptance cannot.

### P4 — Source and surface coverage projection

- **Producer / bucket:** inference publication emits sanitized hunt_coverage_projection;
  `observability/findings/coverage_adapter.py` and scorecard remain derived offline consumers.
  Provisional `metrics`.
- **Dataset/schema/route:** proposed version-1 projection, artifact-only accepted-reader route
  for offline scorecards and final reporting. Extend existing `scores_and_findings`/publication
  bindings only where needed; public report keeps sanitized aggregates and protected references.
  Do not expose protected review cells through `query_dataset_inventory`. If general operator
  querying is later needed, T-129/indexing owners must explicitly register a post-review query
  route; absence of such a route is not represented as indexed.
- **Provenance/ceiling:** P1 denominator, P2 plan, P3 receipts, original catalog/source identities,
  accepted build/extraction coverage and finding links; TRI-C canonical outcomes when available.
  Missing canonical outcomes mean resolution unknown, not resolved because evidence was served.
  This measures recorded scope/behavior, not correctness or whole-target safety.
- **Consumer/value:** operator sees known entry/sensitive-operation coverage and causes of gaps;
  finding metrics use an honest denominator and keep execution, investigation and confirmed
  yield separate. Lifecycle “not covered” decisions must use matching scope, not another
  operation's success in the same file.
- **Bounds/gaps/redaction:** full totals with bounded detail pages and omitted-detail counts;
  unenumerated discovery remains unknown. Low-cardinality public dimensions; file paths,
  symbols and cell/request IDs only in protected drill-down. Evidence errors fail or mark the
  projection unavailable, never zero.
- **Invalidation:** all referenced accepted artifacts plus coverage derivation rule version.
  Recomputable without target reads; changed denominator versions are not silently compared.

### Existing products enriched elsewhere, not duplicated

| Existing owner | Product/interface reused | Required additional decision value |
| --- | --- | --- |
| T-107 | `generated_dfd`, `generated_threat_model`, `generated_model_evidence`; generated model schemas version 1; artifact-only accepted route | Preserve source/site identities, flow ownership basis, query clipping, actor candidates and mitigation state when T-146 supplies context. Further declaration/mitigation lanes stay in T-107. |
| T-108 | Static deployment inventory library → accepted declaration publication, schema already defined in `deployment/schemas.py` | Freeze selected variant, exact descriptor hashes and conflicts; publish sanitized declarations with a typed accepted route, not effective-runtime assertions. The proposed producer remains unregistered at this baseline. |
| T-146 / T-086 | Operation/fallback units, observed tag records, all-source manifests and generated-map package context | Supply stable anchor and source-accounting fields to P1; do not require a generated map or successful build for fallback. |
| T-070 / T-076 | Existing finding/snapshot attacker-position, ownership and build-configuration vocabularies | Carry independently established facts to findings; candidate values in P1 cannot auto-fill these. |
| T-129 | Tool/dataset bucket registry and generated availability matrices | Map P1–P4 and actual declared routes once; distinguish internal artifact readers from worker query tools. |

The static deployment producer's name is a **proposed interface**, not a current registered job:

```text
T-108: job_deployment_inventory
       deployment_inventory
       appsec-review/deployment-inventory/1
       accepted source descriptors -> bounded static declarations
       proposed sanitized precomputed deployment-context route, if approved by T-108
```

Hunting can ship with deployment unknown. T-108 is an optional-enrichment dependency, not a hard
prerequisite that would exclude source-only subjects. The exact publication/index route remains
T-108's decision; P1 must accept its declared contract or an explicit unavailable state.

For these existing interfaces, retain the owning producer's bounds and invalidation rather than
silently widening them: T-107's process/site/flow/threat/query/evidence caps and input ledger;
T-108's per-document/total-byte/parser/record limits, exact descriptor hashes and selected variant;
and T-146's subject/package/context caps and assembly identity. Missing or clipped context
propagates into P1, while damaged supplied evidence is an integrity failure. Only sanitized
declaration values and original resolving references reach package context; source secrets,
raw build environments and protected worker material do not. New template, taxonomy, parser,
configuration or source identities invalidate the corresponding derived context and its
consumer fingerprint. This design does not commission the remaining T-107/T-108 producer lanes.

## Deterministic fair selection under fixed budgets

Retain T-146's deduplicated opportunity score and the existing between-lane
`FairShareScheduler`. Change only candidate allocation **inside lane B**:

1. Enumerate P1 from the T-146 accounting universe before the hunt cutoff. Define one stable
   primary stratum per obligation: component, surface/input class and evidence tier. Retain
   secondary facets for reporting, not duplicate queue membership.
2. Collapse equivalent operation/question/variant candidates. Never let extra tags, templates,
   source files, lead-menu entries or matching producers multiply a site's scheduling weight.
3. Freeze a typed policy with bounded per-stratum minimums, a fallback/unknown reserve and a
   maximum group count. Allocation values are an operator design decision to be compared
   offline, not arbitrary defaults justified by this review. A zero reserve remains visible.
4. Take the reserved pass deterministically, then fill remaining capacity by existing opportunity
   score. Within a pass rotate components/surface classes using stable IDs; ties use obligation
   identity. Release unused reserve only when its queue is known empty, not when discovery
   failed. Record every allocation, release and unmet floor.
5. Plan bounded packages/questions before dispatch. One unit's many lead-menu partitions do not
   consume all first-pass hunt allocations before another selected unit gets one. Retain exact
   lead accounting; do not delete leads to make the package smaller. Planned costs include
   required panel work and permitted follow-up bounds, with source/view limits explicit.
6. The existing job budget remains authoritative for actual team, turn, token, query and time
   admission. A plan is not a reservation or guarantee. Record prefix/order, rejected launch,
   underestimated cost and unserved planned work. Do not increase limits automatically.
7. Persist next-work order before dispatch. Concurrent completions must not reorder the frozen
   selection plan. Shared-budget/provider timing can still change how much work finishes;
   record that nondeterminism instead of claiming identical outcomes.

If budget is smaller than the number of eligible strata, publish unsatisfied allocation floors
with a deterministic order; never assert universal fair coverage. An optional future rotating
seed must be operator-supplied and pinned; no cross-run memory or hidden randomness is required
for this first design. Do not train selection on private answer-key labels.

## Bounded investigation and evidence requests

The worker receives the operation's original evidence, one bounded question, relevant knowns and
unknowns, disconfirming questions and current capabilities. Persona describes expertise; the
question describes the task; neither supplies new authority. Keep all current reviewer counts.

Add a closed per-coverage-obligation result partition to the existing red result contract:

```text
addressed_with_proposal    # links existing proposal; still needs verification
addressed_no_proposal      # scoped rationale + original evidence/counterevidence
blocked                   # exact missing evidence/authority/request
partial                   # addressed sub-scope + omitted sub-scope
not_attempted             # budget, view, prerequisite or dispatch reason
```

This is not a new claim/finding or evidence-request lifecycle or ProducerStatus. Each expected
operation/question coverage obligation must
appear exactly once per applicable result, with no invented IDs. A no-proposal answer is not
a clean verdict. An empty answer or generic “reviewed” statement earns no addressed credit.
Complete-subject status comes from the application and source spans; a worker cannot upgrade
clipped/redacted input.

TRI-C owns evidence-request creation, canonical identity, deduplication, deterministic warranted
resolution and terminal ledger closure. HUNT-C records transport observations keyed to those
canonical IDs, joining them to its operation/question coverage obligation. These are receipt
fields, **not another state machine**:

```text
coverage_obligation_id
canonical_claim_evidence_obligation_ref?  # issued by TRI-C, never synthesized by HUNT
canonical_request_ref?                   # issued/deduplicated by TRI-C
origin_transport_request_ref             # retained even before TRI-C exists
transport_receipt_ref                    # actual admission/denial/failure/cutoff observation
served_response_ref?                     # response hash and bounded result identity
delivered_view_or_retrieval_ref?          # exact content/spans delivered, including omissions
citation_and_coverage_disposition_refs[]
canonical_resolution_ref?                # TRI-C outcome + ledger/receipt hash
resolution_basis                        # TRI-C reference or legacy-resolution-unknown
```

“Served” means the application obtained bounded evidence; “delivered” means the recorded content
was supplied to the worker. Neither establishes the requested fact or closes an obligation.
Only TRI-C's warranted resolution and ledger closure supply that semantic outcome. HUNT-C
structurally validates source/receipt bindings and coverage partitions, not a competing
resolution rule. Canonical outcomes may be shared by several coverage questions; preserve every
question's reference and original transport provenance without locally deduplicating requests.

Anchor-outside-package requests retain actual denial or operator-visible request receipts,
never a new grant. Convergence, citation, successful transport, red-cell success or a worker's
assertion cannot close an unserved request. Before TRI-C, retain useful delivery evidence with
resolution unknown. After integration, coverage projects TRI-C's unresolved/closed outcome
without changing it. The final resolved-evidence acceptance requires this canonical join.

The current package-local follow-up can consume these receipts. Cross-package variant/chain
work may later use obligation ID, original source/build pins, claim/adjudication IDs, request
scope and independent evidence status. Those are **interface dependencies only**; no chain
search expansion, cross-package grants or new chain scheduler is designed here.

## From selection to actual coverage

Maintain distinct facts rather than a single mutable “reviewed” flag:

| Observation | Required binding | What it does not establish |
| --- | --- | --- |
| Discovered | source-anchored T-146 operation/fallback plus discovery limits | exhaustive target or deployment inventory |
| Eligible / selected | P1/P2 policy, rank and omission reason | a package was launched |
| Packaged / supplied | exact package and rendered-view hashes, granted IDs and omitted rows | source text was read or delivered |
| Launched / completed | existing terminal cell and execution receipt | each subject/question was addressed |
| Read / delivered | application read receipt; separately exact initial-view/retrieval source spans, result hashes, clipping and denials | mental attention, citation or correctness |
| Addressed | accepted operation/question coverage disposition with bound source evidence, scoped rationale and no hidden incomplete subject; any claim evidence-resolution outcome is referenced from TRI-C | finding validity, code safety or independent semantic closure of an evidence request |
| Cited / verified | re-resolved citations and existing verifier/adjudication evidence | coverage of other questions/sites in the file |

The primary investigation denominator is **known, source-anchored obligations** within an
explicit discovery scope. Unknown/unmapped/unparsed/unbuilt/seed-excluded scope appears beside
it, not removed to improve the percentage. Generated threat counts are not the denominator.
Report a source-anchored entry coverage view and a broader sensitive-operation/fallback view;
do not label a syntax-only candidate a deployed entry point.

For a source file, union delivered source intervals by exact hash and report addressed-operation
counts separately. Reading one interval cannot mark its entire file reviewed. Reading every
byte still cannot establish that every relevant operation was investigated. For an entry point,
join its original stable anchor to question receipts, not merely file path. For a build scope,
report catalogued, successful build, extracted and declared/observed configuration coverage
independently; a source-only question can be addressed while compiled evidence remains missing.

Coverage reasons must distinguish discovery limits, unsupported language, ambiguous identity,
producer unavailable, not built, not extracted, below cutoff, planned but not admitted, no worker,
view clipping, source redaction, invalid result, evidence request unserved and question unanswered.
Caps on detail lists report omitted counts; caps on discovery report unknown remainder rather
than a fabricated total.

Historical reports remain interpretable as **legacy package execution coverage**. Do not
retroactively reclassify them as investigation coverage or invalidate accepted findings solely
because they predate the new receipt schema.

## Required implementation changes

| Surface | Bounded change and invariant |
| --- | --- |
| Contracts and schemas | Extend the landed T-146 package/unit interface, `docs/schemas/review-packages.schema.json`, inference red result and cell-receipt schemas with closed operation/question coverage and receipt joins. Add P1–P4 validators for those products; reference TRI-C's canonical claim evidence-obligation/request IDs, warranted resolution and ledger closure rather than defining replacements. Preserve existing adjudication predicates and `ProducerStatus`; canonical producer gaps remain `producer-gap/1`. |
| Dataset/registry/topology | Declare P1–P4 in `jobs/job_inference_security_review/datasets.py` with explicit sensitivity, authority, ownership and artifact routes. No new hunting job or dependency cycle. Add exact optional T-108 accepted inputs only after registration; change downstream coverage/reporting contracts only for outputs actually read. Keep runtime registry/config/topology parity and existing target-access policy. |
| Configuration and identities | Add typed fairness, obligation, request and receipt caps to `config/inference_review.py` and central TOML. Reject unknown/invalid keys. Version rank/assembly/coverage rules and fingerprints; do not rewrite frozen runs or silently enable T-107/T-108. |
| Discovery/planning source | Extend `review/units.py`, `ranking.py`, `packages.py` and `scope.py` after T-146 integration. Derive P1 from its operation/fallback universe; no duplicate source scan, DFD parser or entry inventory. Keep exact source/lead partitions through cuts. |
| Routing/execution | Extend `guidance/routing.py`, `review/teams.py`, inference `teams.py`/`job.py` for pinned within-hunt plan, question assignment and result accounting; retain outer lane fairness, current role counts and atomic `review/budget.py` admission. |
| Guidance | Register any bounded question templates/tasks in `pipeline/guidance/registry.json` and approved task/persona fragments. Use existing bundle composition/pinning and closed schemas. No global instruction duplication, new model tools or development-skill content in worker prompts. |
| Retrieval and requests | Extend `package_view.py`, `cells.py`, `cell_retrieval.py`, `capability.py` and `red_discovery.py` only for scoped question context and actual transport/served/delivered receipts referencing TRI-C canonical requests/outcomes. No second request state machine, deduplicator or semantic closure rule. Existing `find`, `read_excerpt`, `expand` (including package-local file paging) and graph routes remain capability-bound. No target traversal during inference. |
| Metrics/reporting | Refine `observability/findings/coverage_adapter.py`, `coverage.py`, `scorecard.py`, accepted review/final report projections and inference `stages.py`. Add P4 with separate discovery/selection/delivery/investigation axes and referenced TRI-C resolution. TRI-A's decision audit consumes HUNT-C coverage receipts, not duplicated producers. Coordinate T-070/T-076; do not create another dossier or finding authority. |
| Inventory/docs | Update `indexing/input_matrix.py`, dataset audit consumers and T-129's eventual registry to describe artifact readers honestly. The current matrix's planned deployment-topology placeholder must be reconciled by T-108, not treated as an implemented producer. Update only owning architecture/operations docs and regenerate generated material through its owner. |
| Tests | Focused independent units for real identity joins, bounds, fair allocation, closed results, receipt projections, rendering and invalidation; separate authored integration and manual efficacy acceptance below. No automatic live validation. |

## Verification and empirical evaluation

### Unit and offline contract checks

Run the smallest affected unit selectors after implementation; independent cases must finish
under ten seconds, with shuffled bounded parallel verification before integration. Tests should
exercise actual functions and validators, faking only external boundaries:

- Multiple operations in one file, shared code across variants, identical tag evidence from
  multiple producers, ambiguous ownership, missing source hash and stale/foreign publications.
- Accepted graph versus syntax/declaration fallback; seeded partial graph; no build/graph/model/
  deployment evidence; parser candidates without an asserted hostile supplier.
- Reordering all inputs leaves identities/plans byte-identical; duplicated tags/templates do
  not increase weight; explicit strata receive the declared opportunity when capacity allows.
- Budget smaller than groups, oversized subject, many menu partitions, zero hunt capacity,
  unavailable strategy and failure after partial execution retain exact omission partitions.
- Successful cell with no obligation response; response citing another same-file operation;
  clipped/redacted source; forged view/ref; unserved/out-of-scope request; retried/reused result.
  None earns complete investigation credit.
- Served/delivered evidence with TRI-C resolution absent or still unresolved cannot become
  resolved. One canonical request can serve several coverage questions without a HUNT
  deduplicator; forged/stale canonical outcome references fail. Delivery-only receipts remain
  useful with legacy-resolution-unknown, and TRI-A references the same HUNT-C receipt hashes.
- Genuine addressed-no-proposal with scoped original counterevidence is accounted without
  becoming a “safe” finding. Proposal coverage does not bypass independent verification.
- Legacy receipts remain execution-only. Source intervals are unioned without double counting;
  below-cutoff source IDs survive; absent discovery/build denominator yields null with a reason.
- Generated context never satisfies a proof obligation, changes target-owned document status,
  chooses a deployment variant or sets attacker/ownership fields without original evidence.

Existing reviewed tests are linked in the
[review contract inventory](../reviews/2026-11-13-threat-driven-hunting-review.md#contract-evidence-and-task-reconciliation).
Saved responses/offline simulations establish deterministic wiring and coverage accounting,
not precision, recall or real model efficacy.

### Separately authorized integration and live acceptance

Author integration cases for accepted catalog→syntax/graph→T-146 package→cell receipt→P4 joins
using real local publication/index custody and inert recorded worker boundaries. Include changed
bytes, foreign snapshot, optional producer absent, protected-data denial and exact downstream
input receipts. **Do not run integration, acceptance or live review without separate user
authorization.** Passing these joins still does not establish useful hunts.

For a later explicitly authorized efficacy study:

1. Freeze independent labels for source entry surfaces, sensitive operations, expected actor
   positions/configuration and known vulnerable/fixed cases. Use T-067/private-holdout and
   T-070 game cases where applicable. Independent reviewers label unresolved cases as such.
   Never mount labels, expected findings or answer-key metadata into worker inputs, prompts,
   retrieval, selection/ranking or model-readable package names.
2. Compare the **landed T-146 baseline**, not only the older path-batch baseline, against each
   additive arm: P1/questions, P2/fair selection, then P3/P4 accounting. Pin target, build,
   tool/feed/guidance/model identities and caps. Do not credit T-146's gains to this proposal.
3. Include network services, native hostile-file loaders, client/server mutations and fallback
   languages/scopes. Hold out targets and build variants, not just alternate names of training
   cases. Independently document build/extraction gaps.
4. Use matched budgets and at least five repeated comparable runs for stochastic detection
   rates; retain incomplete/cutoff runs with their actual spend, not only successful runs.
   Predeclare acceptance margins and cost ceilings before seeing labels/results.
5. Produce the following paired scorecard, with numerator, denominator and uncertainty:

| Metric | Definition and guardrail |
| --- | --- |
| Discovered-surface recall | Independently labeled source surfaces discovered / labeled in-scope surfaces; report unknown labels, unenumerated scope and by-language/configuration deficits |
| Known-surface investigation | Labeled surfaces with valid addressed obligations / labeled in-scope surfaces; also report discovered-denominator share to separate discovery loss from selection/execution loss |
| Hunt-only verified yield | Independently correct, verified unique root causes found by hunting but absent from the matched scanner baseline; report confirmed versus supported, per known cost and per addressed obligation |
| Missed known cases | FN partition: undiscovered, below cutoff, not launched, unread/clipped, unanswered, verifier/adjudication miss, or unresolved; no model dismissal becomes a label |
| Fallback coverage | Eligible fallback subjects selected/delivered/addressed, with graphless and unsupported-language strata; successful source work does not erase compiled-evidence gaps |
| Uncertainty calibration | Unknown actor/owner/deployment/policy rates and independently checked false assertions; report whether useful evidence requests reduce uncertainty without inflating claims |
| Repeatability and cost | Plan identity stability, addressed-scope overlap, per-defect detection rates, verified finding stability, token/query/time/team spend and unknown usage |

Use binomial intervals for independently labeled case proportions; do not put sampling
confidence intervals on a complete manifest census. For ambiguous scanner/root-cause matching,
report unknown backing separately rather than using the current ±2-line proxy as truth.
Severity, developer actionability and final finding correctness remain shared measures with the
triage/verifier design, not independently redefined here.

Release acceptance should require no lost scope/accounting invariants, no increase in fabricated
actor/deployment assertions, a predeclared coverage benefit for poorly instrumented strata and
non-inferior independently verified yield at the agreed cost. The exact margins and reserve
policy require approval; this review supplies no empirical basis for a numeric promise.

## Implementation sequence and existing task ownership

This is a dependency plan, not an alternate backlog. Scheduling state belongs only in
[docs/TODO.md](../TODO.md). The design slice names map to these canonical tasks:

| Design slice | Implementation task |
| --- | --- |
| HUNT-A: operation-bound questions | [T-151](../TODO.md#t-151-bind-hunt-coverage-obligations-to-accepted-operation-identities) |
| HUNT-B: bounded fair allocation | [T-155](../TODO.md#t-155-allocate-bounded-hunt-work-fairly-across-surface-and-evidence-strata) |
| HUNT-C: receipt-backed coverage | [T-156](../TODO.md#t-156-bind-hunt-investigation-and-omission-coverage-to-execution-receipts) |

The shared TRI-C evidence-resolution interface is
[T-153](../TODO.md#t-153-reconcile-bounded-evidence-obligations-with-verified-resolutions);
TRI-A's decision-audit consumer is
[T-150](../TODO.md#t-150-publish-complete-protected-review-decision-products).

| Stage | Scope and prerequisite | Completion evidence |
| --- | --- | --- |
| Reconcile existing work | T-146 lands first; reconcile T-086 source/entry accounting and T-073 adapter interface. Update stale T-107 status without closing its live acceptance. T-129 owns bucket/route registration. | Exact landed schema/operation IDs named; no duplicate operation mapper or generated-model consumer |
| HUNT-A: bind obligations to operations | P1 and bounded question contracts on T-146; hard dependencies T-146 and T-086. T-108 enriches optionally. | Original identity/unknown/boundary ceilings preserved; every candidate/fallback accounted; scoped questions reach existing packages |
| HUNT-B: allocate hunt work fairly | P2 on HUNT-A; reuse existing rank and outer scheduler, fixed budgets | Deterministic allocation and unmet-floor/omission records, no lead loss or budget enlargement; offline simulations compare opportunity/cost |
| HUNT-C: receipt actual investigation | P3/P4 on HUNT-A and HUNT-B; **TRI-C is required for final integrated resolved-evidence acceptance**. Delivery-only/legacy-resolution-unknown receipts may land earlier. Reuse T-073 for adapter/report integration and T-070/T-076 for finding dimensions. | Exact operation/question coverage dispositions and actual transport/served/delivery receipts; canonical request IDs, warranted resolution and ledger closure referenced only from TRI-C. TRI-A consumes these coverage receipts. No duplicate request lifecycle/deduplicator/closure rule. |
| Existing efficacy work | Refine T-068/T-070/T-073 acceptance with the evaluation above; T-126 retains graph expansion | Separately authorized independent-label evidence, with findings/coverage/cost and unresolved gaps reported together |

Decisions required before implementation: approved allocation/reserve policy and quality/cost
margins; final landed T-146 version/fields; agreement that historical “reviewed” means execution
proxy; T-086's graph-versus-syntax entry classification; T-108's static declaration route; and
T-129's canonical bucket assignments. These decisions do not block source-only design review,
but do block claiming the enhancement is implemented, effective or accepted.
