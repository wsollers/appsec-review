---
title: "Proposed triage and verifier decision-product enhancements"
kind: "architecture"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_dossier_publication", "job_final_publication_gate", "job_final_report_publication", "job_inference_security_review"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# Proposed triage and verifier decision-product enhancements

## Status, scope and non-goals

**T-150 is implemented; later policy slices remain proposals.** The original design was written against code
`5926171238607e27a948bc7d40ce190a853b3d0c`; the
[source-backed review](../reviews/2026-11-13-triage-verifier-review.md) records the
shared-working-tree limitation and evidence. Frontmatter status means this is the
current design, not that every proposed runtime exists. Scheduling/progress belongs
only in [the TODO registry](../TODO.md).

The 2026-11-13 sync checkpoint added only the reviewed pure
[record contract](../../src/appsec_review/review/decision_audit/contracts.py),
[closed schema](../schemas/review-decision-audit.schema.json) and focused unit regressions.
It did not change configuration defaults, register audit outputs or consumers, add audit reads,
or wire runtime publication. The later T-150 source boundary and verification are recorded
[below](#t-150-implementation-record). This implementation does not establish review efficacy or
claim that any live run produced an audit. Later evidence-adjudication and hunt-allocation changes
remain opt-in, as selected by the user; integration and acceptance execution remain prohibited
for this implementation.

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

### T-150 implementation decisions, 2026-11-13

The user authorized chunked implementation with unit coverage and final code review before
commit/push, and explicitly prohibited integration and acceptance execution. The first wave is
the behavior-preserving T-150 foundation; the other proposed policy changes are not activated
by these decisions.

For later evidence-adjudication and hunt-allocation waves, the user explicitly selected
**implement as opt-in**, preserving current defaults until separately authorized efficacy
validation. Implementing those policies does not authorize activating them or running
integration, acceptance or live evaluation.

1. **One decision authority.** Produce model-free audit projections from accepted review inputs
   and existing ledger/cell/lead records. Do not change admission, claim state, evidence policy,
   scores, role counts, ship-block status or judge/PoC eligibility.
2. **Closed shared contracts first.** Use versioned, independently validated decision,
   verification-coverage, decision-basis and manifest records with canonical content identities.
   Preserve original run/attempt/lead/proposal/claim/cell identities and exact input references;
   never synthesize a claim identity for a rejected or capped proposal.
3. **Protected allowlisted data.** Project bounded redacted fields and references, never raw
   prompts, transcripts or arbitrary worker dictionaries. Counterevidence remains labelled by
   its existing role and admissibility; its inclusion in an audit does not make it direct proof.
4. **Existing lifecycle.** Publish through declared datasets and the existing job/attempt
   machinery. Readers verify accepted publication pins, hashes, scope and record membership.
   The existing handoff publication creates the audit after writing the original inner review
   handoff, under the attempt's separate `artifacts/decision-audit/` subtree. Its generic unit
   output retains the existing `metadata_path` control field, pointing to protected
   `publication.json`. Explicit `audit_metadata_artifact`, `audit_artifacts` and
   `audit_source_artifacts` references make the runner pin the sidecar and its attempt-owned
   source closure: the artifact collector does not open referenced JSON to discover nested
   sources. Upstream inputs remain observed reads, not re-owned outputs.
   The descriptor binds the audit manifest and frozen policy;
   the audit binds the inner handoff and ledger. An unpinned metadata path is never readable.
   The runner's control allowlist is unchanged. This avoids
   a hash cycle, overlapping dataset ownership, a new task, or changes to existing finding/
   inner-handoff bytes merely to attach the audit. The final gate retains every certified
   read and inserts the frozen-configuration binding idempotently; a conflicting digest
   fails rather than being overwritten.
5. **Explicit compatibility.** Historical absence is an unavailable audit capability with its
   reason. Do not fabricate old reads, rewrite accepted artifacts or silently reinterpret old
   schema/policy identities. New records have their own closed schemas and fingerprints.
   An absent decision-audit settings table disables the optional publication for frozen
   configurations. New shipped configuration enables the projection. Audit bounds remain in
   full resolved configuration and the audit policy hash, but are excluded from model-cell/
   lane/round semantic fingerprints and are not permitted capacity-overlay settings.
   Audit origin uses the full frozen resolved-configuration digest from the attempt claim/
   accepted wrapper, not the inner handoff's model-semantic digest. Readers independently
   derive origin from the accepted wrapper, scope, handoff and frozen settings. No exact
   aggregate guidance/implementation digest is currently commissioned for this sidecar:
   those links explicitly say not produced; opaque implementation labels are not hashed
   and presented as measured source identity.
   The explicit `when_output_declared` input mode admits historical dataset-declaration
   absence without changing ordinary optional/required behavior. Present declarations must
   still match schema and known authority; admitted absence never permits reading
   undeclared bytes. Old serialized job-contract field shapes and hashes remain unchanged.
6. **Bounded operator/application consumers.** Start with a declared accepted-artifact reader
   and fixed query templates plus the existing protected dossier. No new worker/MCP grant,
   arbitrary SQL, target traversal or blind-verifier access to prior decision narratives/labels.
7. **Separate future semantics.** T-152 owns warrants, T-153 owns semantic request resolution,
   and T-156 owns delivered-span/question-coverage receipts. References to unavailable future
   products remain explicitly absent; T-150 does not duplicate or pretend to implement them.
8. **Reviewed chunks.** Each isolated chunk supplies actual-logic unit regressions and changed
   line/branch coverage. The coordinator reviews each contract/chunk before local commits and
   reviews the combined code before serialized main integration and the requested push.
   Integration, acceptance, live models, target execution and deployment reload remain unrun.

The first delivery is a **deterministic decision-audit projection**, not a new reviewer
or new truth store. It joins accepted lead collection/admission, protected cell results,
lane triage/accounting, canonical relations, adjudications, scores and final publication.
Every row points back to its authority. A missing input produces a coverage entry;
it never produces an empty successful population.
TRI-A references HUNT-C's operation/question coverage and transport receipts; it does
not produce a second copy of those receipts or infer delivery from package membership.

T-129 released the [canonical taxonomy](../intelligence-buckets.json) after the initial review.
The runtime-neutral checkpoint added no audit datasets. The six declared output kinds belong to **review_products**, retaining their protected
disposition, operational authority and sanitized-metadata-only inventory route. Offline
measurements remain **metrics**. Future warrant/obligation products are still proposals,
not produced datasets. Bucket membership never grants a worker or MCP capability.

### Product routes

The table distinguishes declared T-150 interfaces from future T-152/T-153 proposals.
A declaration is not evidence that a run produced, consumed or accepted the product;
delivery state remains in T-150 and its implementation verification record.

| Product / conceptual group | Producer and concrete publication route | Index / retrieval route | Consumer and decision benefit | Evidence ceiling |
| --- | --- | --- | --- | --- |
| Decision audit / review_products | Declared review_decisions JSONL, review_decision_audit manifest and review_audit_metadata descriptor under attempt/artifacts/decision-audit | Bounded accepted-artifact reader and fixed operator query templates; no globally granted evidence shard | Operator and final gate; lead-adapter completion remains T-077; explain admitted/unadmitted/proposal-only/claim outcomes and omissions | Derived decision record, never new source evidence |
| Verification coverage / review_products | Declared review_verification_coverage rows referenced by the audit manifest | Protected accepted-artifact route by claim/cell/evidence identity | Operator and authorized application readers; separate blindness, diversity and support completeness | Observed verification metadata, not new proof or a vote |
| Predicate warrants / proposed review_products placement | Proposed predicate_warrants from T-152 relation resolution/adjudication | Future protected references; no new worker query grant | Adjudicator, scorer and verifier's own evidence evaluation | Only application-validated commissioned facts can support R5; audit row itself cannot |
| Evidence obligations and resolutions / proposed review_products placement | Proposed T-153 evidence_obligations artifact, bound to existing request/claim IDs | Protected route; in-package application supplies only admitted requests to later rounds | Existing red/blue follow-up capability; operator locates the next missing fact | Question/resolution metadata; never an instruction to run a new tool |
| Decision basis in developer briefs / review_products | Declared review_decision_bases; existing dossier/gate bind exact accepted finding/claim references | Protected dossier detail plus sanitized bindings; no new public raw-evidence endpoint | Developer and authorized application readers; preserve counterevidence and limits | Immutable accepted decision plus original citations; not a new claim state |
| Reference continuations / review_products | Declared review_audit_continuations JSONL, bound by field and manifest | Validated with the complete bundle before consumption | Authorized readers retain complete provenance beyond inline bounds | References retain original authority; continuation storage adds none |
| Outcome attribution / metrics | Offline finding adapters emit a versioned operator metric document with source-product hashes | Existing offline snapshot/history/scorecard paths; no worker input | Operator and independent evaluator; measure loss, confusion and cost | Derived measurements and externally admitted labels, never evidence for adjudication |
| Stratified audit/evaluation manifest / metrics | Offline evaluator exports population/selection/label bindings | Protected operator artifact, intentionally excluded from review capabilities | Human annotators and experiment analysis; estimate dismissal misses without tuning on holdout | Independent labels stay outside the review run's readable scope |

The first implementation uses bounded, hash-bound artifact readers and fixed query templates;
the earlier SQLite materialization option is not a requirement or a new storage service.
This is a **protected application query adapter**, not a new member of
`retrieval/index.py::INDEX_NAMES` granted to all roles. Queries are fixed templates:
`lead_trace`, `claim_basis`, `verification_coverage` and `population`. Population filters are
stage and producing role; coverage filters are claim and predicate. Open-obligation and
family-specific queries remain future proposals, not implemented templates.
Exact accepted handoff pin and caller authorization are required.
It must use declared consumption and actual read receipts, never discover another job's
latest publication. T-129 records this distinct route truthfully.
The query materialization exposes allowlisted, redacted decision metadata and resolving
references, not raw worker-response text or an arbitrary protected-stream reader.

Audit consumers also need explicit permissions for original scanner/control source shards,
not just the inference sidecar. Their bounded canonical source selection does not widen
the shared source-context defaults or PoC/remediation/worker/MCP access. An explicitly
supplied review handoff closes only declared original-producer inputs at that review's
exact pins; conflicting lineages fail. The existing untagged standalone selector still
selects current accepted pointers and does not promise automatic stale-review reconciliation.

The blind verifier must **not** receive the audit's red/blue positions, judge verdict,
prior verifier answer or independent labels. It gets original admitted evidence and
application-defined claim obligations only. The judge retains its explicitly approved
A/B view. Later packages may not query audit content to evade current cross-package
seed/referral limits. Bounded retrieval for operators and final consumers is valuable
without silently increasing worker capabilities.

## 2. Record contracts and proposed extensions

The examples below retain the original design, not executable payload fixtures. The four
T-150 families now have closed [codecs](../../src/appsec_review/review/decision_audit/contracts.py)
and a [schema](../schemas/review-decision-audit.schema.json); those definitions, rather than
the early examples, are authoritative for implemented fields and invariants. The separate
[publication descriptor](../schemas/review-audit-publication.schema.json) binds availability
and frozen policy. Warrants, obligation resolution and stratified evaluation remain proposals
owned by T-152, T-153 and T-154.

```text
T-150 closed schema families:
appsec-review/review-decision/1
appsec-review/verification-coverage/1
appsec-review/decision-basis/1
appsec-review/review-audit-manifest/1
appsec-review/review-audit-publication/1

PROPOSED schema families, NOT registered:
appsec-review/predicate-warrant/1
appsec-review/evidence-obligation/1
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

T-150 avoids a handoff hash cycle by writing the original inner review handoff first.
The sidecar binds that handoff and original sources; the existing accepted wrapper then
pins both. No downstream overlay rewrites either artifact.

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

Closed `stage` values: collection, severity_triage, admission, package_assembly, cell_execution,
red_discovery, proposal_normalization, claim_cap, blue_review, independent_verification,
judge_review, adjudication, scoring and publication. Use stage-specific outcome enums,
not new producer terminal statuses or new claim states.

The separate cell_execution stage copies the original CellStatus and nondeciding actor_role.
It requires the original cell identity, carries no deciding roles/row and never turns a successful
red cell into a proposal/no-claim conclusion or a successful judge into a verdict. Semantic
decision rows remain distinct; expected-cell coverage counts unique cells, not decision rows.

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

### T-150 bounds and future evaluation constraints

- Projection is model-free. Page size 50, maximum 200; request filters must constrain
  run/attempt and a lead/claim/predicate or named bounded population.
- One manifest accounts for every collected lead and expected cell. Split large
  products into deterministic shards of at most 5,000 rows or 8 MiB each; never drop
  accounting rows to fit a text cap.
- Each decision has at most 2,000 characters of protected explanation and 256 inline
  relation/request references. Excess references use hash-bound continuation shards
  and explicit omission counts in bounded views, not silent truncation.
- Typed `decision_audit` defaults bound unique input bytes to 64 MiB and records to
  100,000. The frozen setting, not a local capacity overlay or today's configuration,
  controls the sidecar. Missing inputs or exhausted publication capacity produce a
  reasoned unavailable descriptor, not a successful empty audit.
- Readers authenticate the descriptor, full frozen configuration and original scope/
  handoff/projection anchors under a fixed 64 MiB control-bootstrap ceiling. A valid
  unavailable descriptor returns its frozen settings and certified reads without opening
  audit payloads, even when its optional audit budget is smaller than those controls.
  An available audit charges all bootstrap bytes against that configured budget before
  reading its manifest, shards or continuations. Malformed, foreign, unpinned or changed
  controls fail in either case; unavailability is not an integrity-error fallback.
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

T-129 is **nonblocking documentation mapping and reconciliation**, not a runtime prerequisite.
Its canonical mapping now covers the six declared T-150 products under review_products.
Register any future concrete datasets, schemas and accepted read routes with their owning
contracts and update that single mapping, rather than inventing new conceptual bucket names.
Do not treat a taxonomy entry as runtime authority.
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

This is the validation plan for all four slices, not a claim that the future warrant,
obligation or labelled-evaluation cases are implemented by T-150.

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

### Decisions for later policy activation

1. Approve precise predicate-warrant policies and the narrow initial family coverage;
   do not broaden direct evidence through prose.
2. Approve any additional audit-adapter callers or redaction/retention changes.
   T-150's host-operator, dossier and gate readers grant no blind-verifier access.
3. Agree evaluation strata, independent labels, non-inferiority margins and known-cost
   treatment before any model-panel or admission-policy experiment.
4. Reconcile future schemas/dataset names and T-146/T-129 interfaces during serialized
   integration. No change here authorizes changing role counts, public finding policy,
   target state or live execution.

## T-150 implementation record

The complete runtime/test source boundary is
`08d50a742aa52f0a2c574243c2d10fbb50d646fa`, incorporating the committed main documentation
boundary `adc9853a5ce050f4b44193bd90cabdb56469f755`. Source identity is separate from main
integration, deployment, image identity and evidence that a review actually ran.

Implemented surfaces are the [projection and immutable publisher](../../src/appsec_review/review/decision_audit/publication.py),
[inference publication adapter](../../src/appsec_review/jobs/job_inference_security_review/audit.py),
[accepted reader](../../src/appsec_review/review/decision_audit/reader.py),
[fixed queries](../../src/appsec_review/review/decision_audit/query.py), existing protected dossier
and final gate. The [operator command](../operations/finding-metrics.md#9-inspect-a-protected-decision-audit)
exposes those verified products without dispatching a review or granting worker tools.

`cell_execution` records actual cell status, not a proposal, no-claim answer or verdict.
Producing roles remain distinct from roles decisive for the recorded adjudication row.
Proposal identities are receipt-path/local-ID pairs; lead traces require exact original
membership and cannot borrow another cell's proposals. An authoritative empty collection
is zero; missing historical collection evidence is unknown. Counterevidence and judge
dissent stay separate from original supporting proof and cannot alter claim or score state.

Final-gate limitations distinguish disabled/historical `not_run`, fresh unavailable or
partial audit gaps, and scope limitations. Population-class counts are not added together
as if leads, cells and decisions shared a denominator. The private audit summary does not
become a new public `/2` field; certified bindings are retained and reverified.

Focused source records include reviewed producer `c57327418c8f581cba620f512955be2b54d5b59a`,
consumer `cc03cf42b5caa9aa60a77d6c908cc148fa9e37a9`, wiring
`5cf9b33325c1a1f21fb5485b351b8d946c6e2b80`, control-budget correction
`248c2d7f4fec618b0378af8e2e45297128b541bd`, cold-import correction
`7f1ce25a48a44a7f3eb82712cf8703ce69e186cb`, explicit historical-admission API
`f72460e4cc8a75ed7753321b195af4bc147fcb93` and original-source permissions
`303976afd5a548b3976a01ea879dcd840048cb03`. The source boundary above adds the actual
six-input consumer adoption and legacy dossier regressions.

The earlier combined gate at `b954c4c49f2586aadae63bfd84ed52d0bcf02e6f` passed 1,076
unit cases in 315.17 seconds, with no case over ten seconds. It covered all 1,721 added
executable lines and 660/662 changed branch edges relative to the synchronized main boundary.
Two focused legacy-dossier cases subsequently covered both remaining edges; all eight
cold-import cases passed in 4.90 seconds. Separate source-permission and admission gates
passed 35 and 127 cases, and the actual consumer-contract adoption passed 20 cases.
These counts overlap; they are not summed as distinct cases.

The final focused command for the complete source boundary is:

```bash
mapfile -t audit_tests < <(git ls-files 'tests/unit/review_decision_audit*/test_*.py')
COVERAGE_FILE=test/tmp/t150-final-unit.coverage scripts/run-tests.sh \
  --expect-tests 1245 --max-tests 1245 --timeout-seconds 600 \
  --parallel --test-workers 2 --shuffle-seed 1510 --coverage appsec_review -- \
  tests/test_000_unit_environment_guard.py tests/test_job_contracts.py \
  "${audit_tests[@]}" \
  tests/test_final_report.py::test_package_counts_reject_a_package_in_no_bucket
```

Result: **1,245 passed in 333.20 seconds**, with no failures, skips or case over ten
seconds. Relative to the synchronized main boundary, all **1,752/1,752 added executable
lines and 676/676 changed branch edges** were covered. This is changed-code coverage,
not a whole-application coverage or review-quality claim. The fixed report is
`test/tmp/reports/tests-custom-20261113-215432-427067-30991.json`; its matching coverage,
JUnit and timing artifacts remain under `test/tmp/`.

Integration, acceptance, joined producer-to-consumer pipeline execution, live models,
target execution and deployment/reload are **NOT RUN**. The four previously observed
whole-team unit cases over ten seconds remain the T-113 owner's fixture-cost work; they
were not rerun or counted as compliant.

The documentation/TODO gate recorded **119 passed, one failed and one existing T-148
archive-citation skip in 10.65 seconds**, with no slow cases. The single failure,
`tests/docs/test_docs_links.py::test_current_and_available_historical_links_resolve`,
checks unchanged links to the user-owned `targets/appsec-multi-vuln` README and project
matrix: both exist in main but are absent from this isolated checkout. No target is acquired,
copied or modified to make that check pass. Generated-document checks and scoped
metadata/link/identifier checks for the changed documents pass; whole-repository source
coverage for archived citations remains the named T-148 gap.

### Post-landing downstream fixture correction, 2026-11-14

The original focused gate omitted `tests/test_downstream_input_contracts.py`. Its
pre-audit synthetic review publisher inherited every dataset from the current registry
without producing an audit descriptor, so five dossier/gate cases correctly failed
the declared-publication guard after T-150 landed. All five reproduced on
`24484feb670ee694d18d7476ff5ba25c04b00f28` in 15.11 seconds, with no slow cases.

The shared fixture now explicitly declares its seven pre-audit output capabilities.
It remains a legacy accepted review, not a claim that the current inference publisher
produced an audit. The duplicate declaration-filtering workaround in the audit consumer
fixture was removed. Two new real typed-runner cases prove that gate and dossier
consumers still reject a producer that declares audit metadata but omits publication.
No production code, publication guard or source permission was changed.

```bash
scripts/run-tests.sh --expect-tests 44 --max-tests 44 --timeout-seconds 180 \
  --parallel --test-workers 2 --shuffle-seed 1551 -- \
  tests/test_000_unit_environment_guard.py tests/test_downstream_input_contracts.py \
  tests/unit/review_decision_audit/test_datasets.py \
  tests/unit/review_decision_audit_consumers/test_accepted_review.py \
  tests/unit/review_decision_audit_consumers/test_reader_edges.py::test_new_declared_audit_missing_metadata_is_not_legacy
```

Result: **44 passed in 44.85 seconds**, with no failures, skips or case over ten seconds.
The report is `test/tmp/reports/tests-custom-20261114-113616-609700-97527.json`.
Integration, acceptance, live and deployment checks remain **NOT RUN**.
