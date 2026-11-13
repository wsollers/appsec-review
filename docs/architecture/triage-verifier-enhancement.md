---
title: "Proposed triage and verifier decision-product enhancements"
kind: "architecture"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_dossier_publication", "job_final_publication_gate", "job_final_report_publication", "job_inference_security_review"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Proposed triage and verifier decision-product enhancements

## Status, scope and non-goals

**Proposed design, not implemented or approved.** Written 2026-11-13 against code
`5926171238607e27a948bc7d40ce190a853b3d0c`; the
[source-backed review](../reviews/2026-11-13-triage-verifier-review.md) records the
shared-working-tree limitation and evidence. Frontmatter status means this is the
current proposal, not that the proposed runtime exists. Scheduling/progress belongs
only in [the TODO registry](../TODO.md).

T-146 landed before this registry handoff at main
`2612ee80f305970707520ad92774d1e1c1336c1c`. Its
[delivered interfaces](../tasks/2026-11-13-behavior-oriented-review.md#implementation-and-verification-record)
are the implementation baseline; references to the review's earlier in-flight state are not
new work to schedule. No new empirical evaluation of that landing is claimed here.

Improve the usefulness of review decisions without widening model authority:

- Preserve one canonical claim ledger, R5 state authority, R6 blind verification,
  confirmed-only remediation and the one final publication gate.
- Preserve current role counts, judge selection and judge-dependent compile-only PoC
  eligibility. No automatic runtime evidence generation, follow-up job dispatch,
  provider changes, deployment changes or live reviews.
- Treat no-claim as different from reasoned dismissal; unknown/null as different from
  zero; model confidence as different from a correctness label.
- Keep original accepted evidence authoritative. Generated operation maps, narratives,
  verdicts, metrics and audit products do not become proof by being indexed.
- Reuse T-146 operation anchors, bounded context and developer projection. It owns
  package restructuring, observed tags and actionability corrections; this proposal
  contributes decision provenance and counterevidence interfaces, not parallel versions.

## 1. Product and authority model

The first delivery is a **deterministic decision-audit projection**, not a new reviewer
or new truth store. It joins accepted lead collection/admission, protected cell results,
lane triage/accounting, canonical relations, adjudications, scores and final publication.
Every row points back to its authority. A missing input produces a coverage entry;
it never produces an empty successful population.
TRI-A references HUNT-C's operation/question coverage and transport receipts; it does
not produce a second copy of those receipts or infer delivery from package membership.

Canonical bucket names are not defined yet. **review_claims** and **metrics** below are
provisional conceptual groupings only. T-129 maps concrete tool IDs and typed
dataset/output-kind IDs to its canonical taxonomy. It must not treat a documentation
subsystem label or the proposed dataset names as an already implemented bucket.

### Product routes

The dataset IDs and new protected query route in this table are **proposed**. They are
names to register during implementation, not current typed declarations.

| Product / conceptual group | Producer and concrete publication route | Index / retrieval route | Consumer and decision benefit | Evidence ceiling |
| --- | --- | --- | --- | --- |
| Decision audit / review_claims | Inference publication emits proposed review_decisions JSONL plus manifest under its attempt's publish_handoff directory | Initially bound artifact reader; subsequently a protected SQLite audit artifact, not a globally granted evidence shard | Operator, lead adapter, final gate; explain every admitted/unadmitted/proposal-only/claim outcome | Derived decision record, never new source evidence |
| Predicate warrants and verification coverage / review_claims | Inference relation resolution/adjudication emits proposed predicate_warrants and verification_coverage artifacts, referenced by audit rows | Same protected audit route, indexed by claim/predicate/evidence identity | Adjudicator, scorer, independent verifier's own evidence evaluation, operator | Only application-validated commissioned facts can support R5; audit row itself cannot |
| Evidence obligations and resolutions / review_claims | Inference package rounds and ledger seal emit proposed evidence_obligations artifact, bound to existing request/claim IDs | Same protected audit route; in-package application supplies only admitted requests to later rounds | Existing red/blue follow-up capability; operator locates the next missing fact | Question/resolution metadata; never an instruction to run a new tool |
| Decision basis in developer briefs / review_claims | Finding attachment and accepted-review projection; existing dossier/gate/report producers bind it | Protected dossier detail plus sanitized final summaries; no new public raw-evidence endpoint | Developer, remediation planner for confirmed findings; preserve relevant counterevidence and limits | Immutable accepted decision plus original citations; not a new claim state |
| Outcome attribution / metrics | Offline finding adapters emit a versioned operator metric document with source-product hashes | Existing offline snapshot/history/scorecard paths; no worker input | Operator and independent evaluator; measure loss, confusion and cost | Derived measurements and externally admitted labels, never evidence for adjudication |
| Stratified audit/evaluation manifest / metrics | Offline evaluator exports population/selection/label bindings | Protected operator artifact, intentionally excluded from review capabilities | Human annotators and experiment analysis; estimate dismissal misses without tuning on holdout | Independent labels stay outside the review run's readable scope |

The audit SQLite artifact should be built from immutable JSONL, versioned and hash-bound.
It is a **proposed protected application query adapter**, not a new member of
`retrieval/index.py::INDEX_NAMES` granted to all roles. Queries are fixed templates:
lead trace, claim decision basis, predicate coverage, open obligations and bounded
stage/family populations. Exact accepted handoff pin and caller authorization are required.
It must use declared consumption and actual read receipts, never discover another job's
latest publication. T-129 records this distinct route truthfully.
The query materialization exposes allowlisted, redacted decision metadata and resolving
references, not raw worker-response text or an arbitrary protected-stream reader.

The blind verifier must **not** receive the audit's red/blue positions, judge verdict,
prior verifier answer or independent labels. It gets original admitted evidence and
application-defined claim obligations only. The judge retains its explicitly approved
A/B view. Later packages may not query audit content to evade current cross-package
seed/referral limits. Bounded retrieval for operators and final consumers is valuable
without silently increasing worker capabilities.

## 2. Proposed record contracts and identities

All new schemas below are **fenced design examples**. They do not exist at the inspected
base. Names/versions must be allocated and registered with closed validators before
publication. The field contracts below are normative for the proposed slices.

```text
PROPOSED schema families, NOT registered:
appsec-review/review-decision/1
appsec-review/predicate-warrant/1
appsec-review/verification-coverage/1
appsec-review/evidence-obligation/1
appsec-review/decision-basis/1
appsec-review/review-audit-manifest/1
appsec-review/stratified-review-audit/1
```

### 2.1 Common envelope and identity

Each decision artifact carries:

- `run_id`, `review_attempt_id`, `target_snapshot`, `accepted_manifest_sha256`,
  `review_handoff_sha256` where available, `ledger_head_sha256`, package-manifest hash,
  configuration/guidance/implementation identities and projection policy version/hash.
- Original `lead_id`, `proposal_ref`, `claim_id`, `adjudication_id`,
  `finding_package_id`, `cell_id` and `round` where applicable. Nullable links carry a
  closed absence reason; a pre-claim proposal does not get a fabricated claim identity.
- `source_refs`: run-relative path/hash/record ID for every input used.
  `coverage`: expected, emitted, omitted and unavailable counts with named reasons.
- `visibility`: protected audit or sanitized summary; structured identities separate
  from bounded redacted explanatory text.

Use canonical serialization and content-addressed hashes. A `decision_id` hashes the
schema/policy, subject identity, stage, attempt, input-reference hashes and outcome.
An event/decision identity is not a cross-revision defect identity. Preserve existing
canonical claim IDs and offline root-cause fingerprints. Record `origin_proposals`
before exact merging; semantic duplicate nominations require independent review.
Never silently split/merge historical findings under a new projection version.

Do not introduce a handoff hash cycle: pre-handoff artifacts bind the ledger and inputs;
the handoff references their manifest. A downstream overlay can add the accepted
handoff hash without mutating those artifacts.

### 2.2 Lead and proposal decision

```json
{
  "schema": "appsec-review/review-decision/1",
  "decision_id": "<content identity>",
  "subject": {
    "lead_id": "<accepted observation or eligible control identity>",
    "proposal_ref": null,
    "claim_ids": [],
    "package_id": null,
    "operation_id": null,
    "component_id": "<accepted component or null>",
    "build_scope_id": null
  },
  "stage": "admission",
  "outcome": "not_admitted",
  "reason_code": "severity_below_admission",
  "reason_text": "<bounded explanation, not evidence>",
  "severity": {
    "reported": "unknown",
    "assessed": "medium",
    "effective": "medium",
    "basis": "model_triage",
    "assessment_ref": "<hash-bound triage row>"
  },
  "basis_relation_ids": [],
  "source_refs": ["<hash-bound original records>"],
  "gap_ids": [],
  "unknowns": [],
  "visibility": "protected_audit"
}
```

Closed `stage` values: collection, severity_triage, admission, package_assembly,
red_discovery, proposal_normalization, claim_cap, blue_review, independent_verification,
judge_review, adjudication, scoring and publication. Use stage-specific outcome enums,
not new producer terminal statuses or new claim states.

Red outcomes include proposed, explicit_no_claim, blocked, invalid, timed_out,
not_launched and proposal_rejected. Preserve original raw outcome and its cell receipt
alongside the normalized stage record. `explicit_no_claim` may have
`basis_status = unstated | narrative_only | cited_nondeciding | scoped_warrant`.
Even scoped_warrant **does not** turn red silence into an R4 dismissal; red cannot
author decisive contradictions. A reason absent from a bare no_claim label is unstated,
not “safe.” Omitted leads remain blocked, never defaulted to no-claim.

For adjudicated removals record `deciding_row`, `required_predicates`,
`counted_support_ids`, `counted_contradiction_ids`, `qualifying_relation_ids`,
`noncounted_relation_ids` with reasons, and `deciding_actor_roles` as a set. Record
all jointly sufficient contradiction sources instead of assigning causal credit by
blue-first precedence. Distinguish application scope removal from role-produced
refutation. For a lead with several claims, retain each claim's outcome and compute the
existing lead disposition without hiding a surviving or unresolved sibling.

Unadmitted rows retain producer/family/scanner/rule identity even without a package.
Preserve accepted artifact/control locations when source lines are unavailable; do not
fake a source location merely to obtain a metric fingerprint.

### 2.3 Predicate warrant and counterevidence

```json
{
  "schema": "appsec-review/predicate-warrant/1",
  "warrant_id": "<content identity>",
  "claim_id": "<canonical claim>",
  "predicate": "missing_or_ineffective_guard",
  "requested_relation": "contradicts",
  "effective_relation": "qualifies",
  "subject_binding": {
    "affected_entity_ids": ["<claim entity>"],
    "operation_id": null,
    "sink_id": "<accepted sink>",
    "build_scope_id": "<accepted scope>"
  },
  "basis": "structured_guard_check",
  "evidence_refs": ["<entity, shard hash, content hash, locator, receipt>"],
  "rule": "<versioned deterministic rule>",
  "result": "not_established",
  "reason_code": "destination_bound_unproved",
  "coverage": "complete_for_supplied_facts"
}
```

The warrant answers three separate questions: authentic content? relevant to this
subject/configuration? supports or contradicts **this exact proposition**?
It preserves the worker's requested stance even when policy downgrades it.

Initial implementation covers only existing structured presence/build facts and
graph guard/range destination checks. Required safeguards:

1. A source location's existence cannot alone contradict affected_construct.
   Structured presence may support the appropriately bound construct, not an arbitrary
   condition elsewhere in the package.
2. Check both guard polarities. A fact shown to bound this destination cannot support
   “missing or ineffective”; lack of a demonstrated bound does not itself prove a
   missing guard. Inconclusive facts qualify and name the missing comparison.
3. Match sink, path/build configuration and claim subject. A bound for another buffer,
   revision, build or operand cannot decide this claim. Ambiguous links remain gaps.
4. Numeric comparisons use supplied machine facts with operand identities, widths,
   units, signedness and configuration where required. O1 alone is a report citation,
   not a computed arithmetic certificate. Unsupported calculation remains unresolved.
5. Reuse the same warrant result in R5 and scoring; do not let an effective guard count
   as absent in one surface and be excluded in the other.

General authorization policy, races or resource-exhaustion semantics need commissioned
evidence methods before new direct warrants are added. T-146's family-specific questions
are interfaces to those future methods, not themselves facts. Narrative counterevidence
can be valuable and must be retained, labelled analyst-assessed rather than deciding.

Policy tightening changes evidence/adjudication fingerprints and requires approval,
focused counterexamples and separate efficacy evaluation. Existing frozen runs are read
under their original policy; do not reinterpret or rewrite their accepted states.

### 2.4 Independent-verification coverage

Record one row for every expected verifier cell/claim, including failure:

```text
claim_id, verifier_cell_id, attempt, round, status, receipt_ref
blindness: {actor_distinct, conversation_fresh, prior_response_absent,
            shared_actor_cache_absent, request_check_ref, passed}
diversity: {provider_distinct, model_profile_distinct, resolved_model_revision|null,
            revision_unknown_reason|null}
predicates: [{predicate, required, own_read_refs, own_support_warrant_ids,
              own_contradiction_warrant_ids, own_qualifying_ids, coverage_state}]
evidence_overlap: {same_upstream_artifact_ids, distinct_upstream_producer_ids,
                   comparison_available}
confirmation_eligible, gap_ids
```

Separate structural blindness from support completeness. A blind verifier that
successfully refutes a claim is not “non-independent” merely because it supplied no
affirming support for a required predicate; it can be structurally independent while
not confirmation-eligible. Preserve the existing aggregate R6 boolean for existing
consumers until a versioned change is approved. No provider/model difference proves
evidence independence or accuracy; no same-evidence reread is billed as a new producer.

### 2.5 Evidence obligation and resolution

**Single owner:** TRI-C owns the claim evidence-obligation identity, deduplication,
deterministic warranted resolution and ledger terminal closure. HUNT-C owns operation/
question coverage dispositions and actual transport, delivery and served receipts.
It references the canonical TRI-C request identity and outcome; it does not implement
another evidence-request state machine, deduplicator or semantic closure rule.

```text
obligation_id, origin_request_ids[], claim_id, predicate, subject_binding, anchors[]
question, requested_kind, requested_specialist|null, origin_cell_ids[], round_opened
required_evidence_class, admissible_producer_ids[], scope_ceiling, completeness_required
state: open | satisfied | unsatisfied | superseded | withdrawn
resolution: {relation_ids[], warrant_ids[], read_receipt_refs[], evaluated_round,
             resolution_rule, reason_code, superseded_by|null}
coverage_receipt_refs[], remaining_gap_ids[], attempted_retrieval_ids[], budget_disposition
```

`obligation_id` hashes claim/predicate/scope, requested kind, canonical question and
obligation-policy version, excluding originating actor and round. Repeated equivalent
requests link to one obligation but retain all original request IDs and histories.
This obligation ID is the **canonical request ID** shared with HUNT-C: its
`canonical_request_id` reference must equal this ID, not hash another identity.
`origin_request_ids` retain the existing per-cell submissions and are not separate
semantic obligations. `coverage_receipt_refs` bind HUNT-C receipt IDs and artifact
hashes; TRI-C consumes them as evidence of transport/coverage only.
Matching only a predicate string is not sufficient to satisfy a different question.

At each round boundary, reconcile against accepted new or already available evidence:
scope, predicate/polarity, completeness and deterministic warrant must match.
Satisfaction can be evidence for either side; it means the question was answered,
not that the claim was confirmed. Contradictory answers remain disputed rather than
arbitrarily selecting one. Existing unsatisfied/superseded/withdrawn terminal semantics
are retained; closure must cite its basis.
**Served or delivered is not resolved.** A HUNT-C receipt showing delivered spans can
establish what reached a worker, not that an obligation was satisfied, independently
verified or used in adjudication. Only TRI-C's bound resolution supplies that outcome.

HUNT-C may publish useful delivered-span and legacy-resolution-unknown receipts before
TRI-C exists. Such receipts retain original submission references, a null canonical
request reference with an explicit unavailable reason, and no inferred semantic
resolution. Later integration binds them to TRI-C's canonical request/outcome without
rewriting historical receipts. HUNT-C's **integrated resolved-evidence acceptance depends
on TRI-C**; its initial transport-only slice does not. TRI-C does not depend on HUNT-C
to resolve obligations from existing accepted evidence, and TRI-A's initial audit
remains useful with a named absence of HUNT-C receipts, avoiding a dependency cycle.

Terminal reason codes distinguish evidence_unavailable, outside_package,
producer_uncommissioned, retrieval_cap, model_budget, timed_out, invalid_response,
incomplete_mapping, unresolved_contradiction and no_decisive_evidence. These are proposed
record reasons, **not** new job terminal-status values.

No obligation opens a new job or expands the manifest. A specialist suggestion is a
bounded cue; scheduling requires existing commissioning authority. Reserve follow-up
effort only inside the current package/team budget, with explicit skipped obligations
when it is exhausted. Stop on no semantic evidence delta; more actors or repeated
receipts are not progress.

### 2.6 Decision-basis attachment and uncertainty

Bind a protected decision-basis attachment to the exact finding/adjudication/ledger
hashes. It contains supporting and opposing/qualifying relation IDs, application
explanations of what counted and what did not, required/missing predicates, open
obligations, verification coverage reference and judge verdict references. Preserve
counterevidence even when it did not alter the accepted state.

For severity, carry existing score provider/configuration, scored factors and citations,
severity floor/ceiling, unresolved factors, and reported-versus-triaged lead severity.
Do not add an uncalibrated numeric model-confidence field to claim state. If model
confidence is ever captured for an approved experiment, isolate it as self-report and
exclude it from warrants, correctness labels and production state.

Use the existing protected dossier for developer detail, with a bounded
“why this conclusion / what could invalidate it” view. The sanitized gate/report
contains only counts, approved labels, references and limitations. A missing audit
attachment does not silently change confirmed/supported policy; it becomes an explicit
capability gap under the approved publication contract. Artifact hash disagreement
remains an integrity failure. T-146/T-076 own the wider actionability brief.

## 3. Bounds, redaction, invalidation and coverage

### Proposed defaults, subject to configuration review

- Projection is model-free. Page size 50, maximum 200; request filters must constrain
  run/attempt and a lead/claim/predicate or named bounded population.
- One manifest accounts for every collected lead and expected cell. Split large
  products into deterministic shards of at most 5,000 rows or 8 MiB each; never drop
  accounting rows to fit a text cap.
- Each decision has at most 2,000 characters of protected explanation and 256 inline
  relation/request references. Excess references use hash-bound continuation shards
  and explicit omission counts in bounded views, not silent truncation.
- No added model calls for projection/metrics. Obligation reconciliation uses the
  already bounded relation set. Any lookup beyond it consumes existing retrieval
  budgets. Candidate setting names belong in typed central configuration, not prompts.
- Evaluation has explicit case/repeat/cost ceilings and a separate approval to call
  models. No scheduled canary or fix recheck is enabled by implementing these records.

Protected text is still untrusted. Redact secrets and sensitive artifact payloads with
existing redaction policy before durable projection; retain hashes/identity references
and a redaction reason. Public summaries never copy raw no-claim rationales, proprietary
source, generated code or worker transcripts. Do not persist a whole prompt to prove
blindness: keep checked request hashes and the existing request-check receipts.

Fingerprints must cover projection/warrant/obligation schema and rule versions, admitted
source identities, build/sink bindings, evidence-map versions, capability and redaction
rules. Cell semantic changes also bind compact schema/expander, validator and pinned
guidance. A model/policy/evidence change invalidates affected decisions, not unrelated
source indices. A changed label set invalidates only offline evaluation artifacts;
labels never invalidate or influence a worker request because they never enter it.

Track available, supplied, read and cited separately per evidence identity. Record
unknown coverage as unknown, not zero. A bounded query that omits rows returns a
continuation and named truncation; a wholly absent artifact returns unavailable.
A missing source location does not remove a finding from population totals; metrics
that require a location disclose their narrower eligible denominator.

## 4. Required implementation surfaces and interfaces

| Surface | Required change | Boundary / dependency |
| --- | --- | --- |
| Lead collection/admission | Emit original family/rule/severity and admission basis even without a package | `review/lead_families.py`, `lead_triage.py`, `packages.py`; consume T-146 operation IDs only when present |
| Compact outputs and normalization | Optional bounded no-claim explanation/citations; persist pre-claim rejections and original proposal membership | `review/compact.py`, `red_discovery.py`, closed review schemas; absence still legal and labelled unstated |
| Evidence/adjudication/scoring | Typed scoped polarity warrants; reuse in deciding relations and factor extraction | `review/evidence.py`, `admission.py`, `obligations.py`, `adjudication.py`, `scoring/factors.py`; no new proof engines |
| Team/ledger lifecycle | Record stage events, verification coverage, obligation reconciliation and terminal reasons | `jobs/job_inference_security_review/teams.py`, `stages.py`, `review/ledger.py`, `accounting.py`; preserve exact partitions |
| Hunting coverage interface | Reference HUNT-C operation/question dispositions and transport/delivery/served receipts | HUNT-C produces receipts; TRI-A references them; TRI-C alone owns canonical request identity, deduplication, warranted resolution and ledger closure |
| Publication/contracts | Declare new output kinds/closed schemas and handoff bindings; version readers | Inference datasets, `jobs/accepted_review.py`, gate/dossier contracts; follow development job-contract checklist at implementation |
| Index/query | Immutable protected audit index and fixed bounded read templates over accepted products | Separate application audit adapter; register T-129 route; no blind-verifier access to prior positions or labels |
| Guidance/configuration | Explain scoped dismissal basis and request-resolution semantics; keep role authorities and budgets | Registered role tasks/procedures and pinned schema/bundle; use runtime-guidance development checklist, never repository instructions in prompts |
| Reporting | Attach counterevidence and uncertainty through existing protected dossier; sanitized references through gate | T-146/T-076 developer projection, no second report/ticket state |
| Metrics | Consume stage records and separate judge dissent, verifier refutation and confirmation coverage | T-071/T-077; retain completed triage/severity/outcome formulas |
| Testing | Real deterministic parsers/joins/warrants with external boundaries faked; labelled offline experiments | Existing focused review/finding tests plus independent fixtures; no implicit live tier |

T-129 is **nonblocking documentation mapping and reconciliation**, not an implementation
prerequisite. Implement and register concrete typed datasets, closed schemas and accepted
read routes in their owning runtime contracts without waiting for the canonical bucket
taxonomy. Coordinate those identities with T-129 and reconcile its mapping when available;
do not omit local dataset/route documentation while it is pending.
Dependency-intelligence and hunting enhancements should
supply their existing lead/operation/evidence identities and producer coverage through
these interfaces. Neither subsystem supplies a correctness label. Do not duplicate
their producers, cross-package hunt design, or T-146's generated-map work.

## 5. Independent evaluation design

### Populations and labels

Freeze target revision, corpus/key identity, supported scope, implementation,
configuration, model/profile, guidance, policy, budget and cache mode. Keep keys outside
all worker-readable input roots. Use T-067 fix-pair/holdout work rather than creating a
second corpus registry. Developer outcomes and human audit labels use the existing
admission/conflict machinery; accepted risk or a duplicate is not automatically a
correctness label. No model confidence or reviewer agreement becomes ground truth.

Label at three units: lead, canonical independently reviewed root cause and corpus
defect/control case. Source-location overlap from the existing key adapter is a useful
scope match, not proof that every unrelated alert in that scope is the same defect.
Ambiguous matches need unresolved labels and separate scope-match coverage.

Keep the existing resolved-lead retention/removal formulas and their names. Add clearly
named complementary **all-labelled-collected** and **all-labelled-admitted** retention
views, exposing unresolved and unadmitted counts. Do not change a denominator without
versioning and stating it.

### Required paired measurements

| Question | Measurement and counterweight | Attribution required |
| --- | --- | --- |
| Were true leads retained? | Existing true-lead retention beside false-lead removal; all-collected/admitted retention beside unresolved and unadmitted shares | Severity/admission, explicit no-claim, cap, malformed/timeout, R4 deciding role set and scope policy |
| Were false claims confirmed? | Independently false confirmed root causes / labelled confirmed root causes, plus control-case false confirmation / eligible controls | Keep supported, disputed, withheld and unresolved populations separate |
| Is severity calibrated? | Exact/over/under severity agreement, high/critical precision and unrated share | Catalog/model triage versus final score, family, configuration and missing factors |
| Is verification useful? | Blindness coverage, independent support completeness, actual verifier contradictions and judge dissent separately | Full expected verifier population, not just published survivors; missing role evidence stays unknown |
| Are results repeatable? | Existing candidate/verified/published stability and defect detection intervals | Fresh model calls separated from receipt replay and blue memo reuse; same upstream evidence overlap reported |
| Is the result worth its cost? | Known cost and latency per independently actionable deduplicated finding, alongside absolute actionable yield and coverage | Cost provenance/unknown portions; shared cells not counted repeatedly across duplicate claims |
| Are dismissals sound? | Stratified human-audit miss estimates with decided/unresolved labels, selection probability and intervals | Separate no-claim, R4 dismissal, admission exclusion and budget loss |

Extend the existing deterministic audit exporter rather than replacing it. Predeclare
strata by removal mechanism, family, severity basis, build/operation coverage and
evidence strength; include undersampled strata explicitly. Preserve population size,
sample size, seeded selection order, inclusion probability, nonresponse and label
provenance. Weight estimates by stratum population; do not report an unweighted enriched
sample as population prevalence. For very small strata, report exact counts and wide
uncertainty rather than a confident aggregate. Audit unadmitted and unresolved leads as
separate populations, not as “dismissed.”

### Experiments and acceptance decisions

First compare old versus new **projection only**: state, scores, shipment policy and
PoC eligibility must remain byte-equivalent apart from declared new attachments.
Then evaluate approved warrant-policy changes on paired positive/negative controls,
configuration variants, effective/ineffective guards and deliberately mismatched
subject facts. Report newly unresolved outcomes as well as corrected decisions.

The bounded role evaluator remains a useful proxy but must use current family
obligations or label its deliberate deviation. Add an end-to-end offline path through
real compact expansion, evidence resolution, independence, R5 and projections.
Deterministic fixture responses prove contract behavior only; model-quality claims
require independently labelled real responses under separate authorization.

Panel-size changes, disagreement-only judging, different model profiles and stronger
refutation independence are **alternatives to test**, not defaults to implement.
Predeclare cost/coverage budgets, acceptable true-lead loss and false-confirmation
non-inferiority margins with the owner before running comparisons. Compare PoC
documentation eligibility as well as claim state. Use multiple fresh repeats and an
untuned holdout; no universal numeric improvement threshold is invented here.

## 6. Implementation slices

Slice names below identify parts of this design. Scheduling state and dependencies live
only in the central registry:

| Design slice | Implementation task |
| --- | --- |
| TRI-A: protected decision products | [T-150](../TODO.md#t-150-publish-complete-protected-review-decision-products) |
| TRI-B: scoped evidence warrants | [T-152](../TODO.md#t-152-bind-decisive-evidence-to-scoped-propositions-and-polarity) |
| TRI-C: evidence-obligation resolution | [T-153](../TODO.md#t-153-reconcile-bounded-evidence-obligations-with-verified-resolutions) |
| TRI-D: stratified stage-loss audit | [T-154](../TODO.md#t-154-audit-labelled-stage-loss-and-dismissals-by-stratum) |

HUNT-C is [T-156](../TODO.md#t-156-bind-hunt-investigation-and-omission-coverage-to-execution-receipts)
in the [hunting design](threat-driven-hunting-enhancement.md). It consumes TRI-C's
canonical resolution rather than creating a second evidence-request lifecycle.

### TRI-A — Publish complete protected decision products

Produce stage-attributed lead/proposal/claim records, original proposal membership,
counterevidence bindings and separate verification-coverage axes. Add deterministic
manifests, closed validators and the accepted-review reader; then add the bounded
protected audit query adapter and dossier decision-basis attachment.
Reference HUNT-C's hash-bound coverage/transport receipts when available, rather than
duplicating their production. Missing receipts remain a named audit coverage limitation.

Runtime prerequisites: no additional backlog prerequisite for the initial artifact-only
vertical slice. First implement its typed datasets, validators and bound readers, then
the protected query adapter and dossier attachment under those concrete contracts.
T-129 mapping/reconciliation is nonblocking throughout that sequence. Coordinate
T-146/T-076 operation/context and developer-projection interfaces without duplicating
their work; the first slice does not wait for operation IDs because null with reason is
valid. T-077 consumes these records rather than reconstructing actor attribution
heuristically.

Done when every collected lead, expected cell and emitted proposal is traceable to a
terminal decision or named omission; no-claim reasons and nondeciding counterevidence
are retrievable; adding the product changes no R5/score/PoC result; blinded roles cannot
query prior decisions; protected/public redaction and receipt tests pass.

### TRI-B — Bind decisive evidence to scoped propositions and polarity

Introduce typed warrants for the limited existing structured fact families. Align
guard checks in evidence resolution and scoring; bind construct/configuration/sink and
numeric facts; downgrade unsupported stance to qualification/gap rather than infer
truth. Record requested/effective stance, policy and reason.

Dependency: TRI-A's identities/provenance interface; implementation can develop its pure
validator independently, but publication consumes that interface. A policy activation
decision and independent labelled evaluation are required. No historical run rewrite.

Done when real validators reject wrong-subject/wrong-configuration/wrong-polarity
evidence, handle both effective-guard directions consistently, preserve legitimate
direct cases, and produce named uncertainty for uncommissioned evidence.

### TRI-C — Reconcile bounded evidence obligations

Replace unconditional unsatisfied closure with scope-bound deterministic reconciliation,
deduplicated obligation identity, original request membership and specific terminal
reasons. Reuse the existing package rounds and budgets; do not add a scheduler.
This is the single semantic evidence-request lifecycle shared with HUNT-C. Supply its
canonical request IDs and warranted outcomes to HUNT-C's coverage projection; delivered
or served receipts never close an obligation by themselves.

Dependencies: TRI-A record bindings; TRI-B warrant interface for decisive resolution.
Existing generic request support can be migrated without claiming a previously
unsupported evidence question is answered.
HUNT-C's final integrated resolved-evidence acceptance must list TRI-C as a dependency.
Its transport-only/legacy-resolution-unknown receipts may ship earlier. TRI-C's own
dependencies do not include HUNT-C; its receipts are optional provenance inputs.

Done when a later resolving fact closes the matching obligation with receipt/warrant,
an irrelevant same-predicate fact does not, conflicting facts remain disputed, identical
requests do not multiply work, and caps/timeout/out-of-scope requests remain terminally
accounted without granting new capabilities. HUNT-C receipt references preserve actual
delivery while only TRI-C resolution controls semantic closure; unknown legacy
resolution cannot become satisfied through a coverage projection.

### TRI-D — Measure labelled stage loss and audit dismissals by stratum

Extend existing offline metrics with population-complete attribution, stratified audit
selection and experiment manifests. Consume TRI-A products, update the role evaluator's
family-policy interface, and connect already implemented rates rather than recreating
them. Keep metric-source correction under T-071 and lead-adapter/display completion
under T-077.

Dependencies: TRI-A, T-071, T-077; T-067 blocks holdout/fix-pair efficacy conclusions,
not deterministic offline implementation. Evaluating TRI-B/TRI-C requires their ready
versions and separately approved experiments.

Done when a keyed recorded corpus yields distinguishable admission loss, silence,
refutation, invalid/timeout and unresolved populations; judge disagreement never counts
as verifier overturn; stratified selection/weighting is reproducible and honest about
unlabelled cases; reports pair effectiveness, coverage, uncertainty and known cost.

## 7. Validation and authorization

### Unit and offline contracts

Author independent tests using real changed logic, sorted parametrization and
per-test budgets under ten seconds. Before implementation handoff, run only the
affected files shuffled and with bounded parallelism through the repository harness
when appropriate. Record commands, elapsed times, counts and gaps.

Required fixtures include:

- successful confirmation, reasoned dismissal, bare no-claim, blocked omission,
  active/per-package cap, schema-invalid, timeout and not-launched cells;
- a lead with both dismissed and surviving/unresolved claims; joint blue/verifier
  contradiction; exact duplicate and possible semantic duplicate;
- qualified counterevidence omitted from support lists but present in the new brief;
  judge dissent on a confirmed claim without fabricated verifier overturn;
- effective guard cited as support for missing guard, ineffective/unproved guard
  cited as contradiction, wrong buffer/build/configuration, missing numeric facts;
- fresh blind verifier with same versus distinct upstream artifact and model profile;
  failed verifier, partial support and conflicting facts;
- repeated requests, later satisfied requests, misleading predicate-only match,
  no-semantic-delta stopping, omitted/redacted evidence and exhausted budget;
- HUNT-C served/delivered-but-unresolved receipts, early legacy-resolution-unknown
  receipts, exact canonical request/outcome joins and TRI-A reference-only coverage;
- stale schema/policy/bundle/source cache keys, valid blue memo reuse and forbidden
  verifier decision-product access;
- unlocated artifact-only findings, absent role-citation inputs, null denominators,
  stratified inclusion probabilities, label conflicts and no-label unavailability.

### Integration/acceptance designs — separate explicit authorization

**Not run by this design task or an ordinary implementation gate.**
When explicitly commissioned, verify real local accepted-publication → audit index →
bounded query → dossier/gate/report joins, corrupt/stale/foreign references, atomic
publication, exact populations and redaction. Integration tests use declared budgets;
they do not require live models to prove deterministic joins.

Acceptance consumes an explicitly supplied run and independently checks the decision
product against original evidence and terminal partitions. A customer/live comparison,
fresh repeated model series, private holdout use, fix recheck or canary requires its
own user authorization, corpus access and predeclared budget. Compile-only artifacts
remain non-runtime proof.

### Decisions required before activation

1. Approve precise predicate-warrant policies and the narrow initial family coverage;
   do not broaden direct evidence through prose.
2. Approve the protected audit adapter's callers and redaction/retention ceilings,
   with no blind-verifier access to prior positions.
3. Agree evaluation strata, independent labels, non-inferiority margins and known-cost
   treatment before any model-panel or admission-policy experiment.
4. Reconcile concrete schemas/dataset names and T-146/T-129 interfaces during serialized
   integration. No change here authorizes changing role counts, public finding policy,
   target state or live execution.
