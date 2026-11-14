---
title: "Lead triage and red-blue-verifier efficacy review"
kind: "review"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_dossier_publication", "job_final_publication_gate", "job_final_report_publication", "job_inference_security_review", "job_poc_generation", "job_remediation_planning", "job_remediation_validation"]
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Lead triage and red-blue-verifier efficacy review

## Charter and evidence boundary

**Review date:** 2026-11-13. **Inspected code base:**
`5926171238607e27a948bc7d40ce190a853b3d0c`, local `main`; ancestry was verified and
HEAD equalled that commit at inspection. The shared checkout already contained extensive
unrelated documentation and documentation-tool edits. Those edits were read as context,
not evidence of deployed behavior, and were not changed. In-flight T-146 lives on separate
branches and is an interface dependency, not an implemented premise of this review.

Integration note: that describes the inspection baseline. T-146 subsequently landed on main,
verified at `2612ee80f305970707520ad92774d1e1c1336c1c`; see its
[implementation record](../tasks/2026-11-13-behavior-oriented-review.md#implementation-and-verification-record).
The new tasks exclude its delivered operation/map/actionability changes. Registration does not
relabel this source review as a fresh efficacy assessment of the later implementation.

The assignment is a product/architecture review and enhancement **design**, not a
vulnerability audit, runtime implementation, or authorization to review a customer target.
The objectives are true-defect retention, sound confirmation and refutation, independent
verification, severity calibration, and developer usefulness. This review followed the
lead-to-publication trace directly in source and inspected focused tests. No models,
containers, target files, review runs, integration tests, acceptance tests, or live tests
were executed. Examples below are source-derived cases, not observed production frequencies.

Read alongside the [proposed enhancement design](../architecture/triage-verifier-enhancement.md),
[inference contract](../architecture/inference-security-review.md),
[red output contract](../architecture/red-discovery-output.md),
[judge/PoC contract](../architecture/review-judge-and-poc.md),
[completion contract](../architecture/evidence-completion-and-remediation.md), and
[finding metrics](../architecture/finding-metrics.md). Current code, rather than older
design diagrams or generated views, establishes implemented behavior.

## Executive assessment

The valuable core already exists: authentic evidence re-resolution, per-predicate
admissibility, non-voting adjudication, fresh blind verification, immutable receipts,
failure accounting, and confirmed-only remediation. The largest opportunity is **better
decision products and their use**, not more agreeing reviewers.

Four bounded enhancements are warranted:

1. Retain every lead's decision trail, counterevidence and uncertainty in a protected,
   queryable audit product, including leads that never become claims.
2. Bind decisive evidence to the claim subject, configuration and proposition's polarity,
   rather than treating an authentic admissible kind as sufficient semantic justification.
3. Give evidence requests verifiable, useful terminal outcomes; avoid declaring every
   request unsatisfied regardless of later evidence.
4. Evaluate independent labels across the entire funnel, with stratified dismissal audits
   and separate judge, verifier, admission and budget effects.

These are not findings that the system's real-world accuracy is low: that requires the
independent evaluation below. They are source-backed limitations in what the system can
justify, retain, measure and deliver.

## 1. Current dataflow and decision state machine

Paths in the following trace are relative to `src/appsec_review/`.

### 1.1 Extraction, severity and admission

1. `jobs/job_inference_security_review/job.py::_scope` accepts one immutable index
   manifest and checks its identity throughout the attempt. Evaluator roots are rejected;
   target guidance identities are removed from cell capabilities.
2. `review/lead_families.py::collect_leads` reads accepted observation shards and the
   explicitly mapped families, plus post-build failures and eligible OWASP control
   assessments. Unknown producers and missing families produce gaps. Scanner duplicates
   and suppression status are retained as context, not silently deleted.
3. `review/lead_triage.py::run_triage` handles **unknown reported severity only**:
   most-specific rule table, pinned CWE consequence-derived impact class, then bounded
   tool-free model batches. The scanner severity remains separate from the assessed value.
   Caps, timeout, invalid output and insufficient context keep severity unknown with a
   named gap. Deterministic catalog severity is a class-level routing estimate, not a
   demonstrated target impact.
4. Numeric reasons are checked in `_from_item`: uncited detected numeric reasoning stays
   unknown. `tool_facts` supplies only scanner observation `O1`; its citation proves which
   tool report was supplied, not that every numerical inference in the reason follows
   from that report. Cached assessments pass the same guardrail.
5. `review/packages.py::admission_reasons` and `admitted_leads` apply reported/assessed
   severity, KEV admission and optional medium/low exploration. At this base,
   `appsec-review.toml:2866-2876` admits critical, high and unknown, admits KEV, and disables
   exploration. Consequently, an unknown lead assessed medium/low can lose lane-A
   admission. That is an intentional routing effect requiring false-negative measurement,
   not proof that the lead was refuted.
6. `_Assembler.finding_lead` creates one bounded lead package with original entities,
   correlated paths, graph/build/memory context, callers, control context and omission
   accounting. `_Assembler.trim_neighborhood` removes non-anchor slice lines first, then
   bounded contextual rows. Missing or ambiguous context stays a gap. `audit_membership`
   and the package manifest account for admitted and unadmitted leads.

The separate `job_review_package_assembly` is not the final lead-admission authority in
this trace: the inference job itself assembles its lane packages. T-146 owns changing
those units toward operation/boundary-oriented packages, observed behavioral tags,
generated-map routing context and truthful actionability. This review does not duplicate
that work or assume it has landed.

### 1.2 Cells, proposal normalization and rounds

`jobs/job_inference_security_review/teams.py::route` records stack, persona, facts,
expected/missing specialists and the routing basis. Lane A uses one routed persona and
three red task lenses; lane B uses a bounded strategy/persona panel. A lead's first
sorted CWE participates in lane-A persona routing. A routed persona is a viewpoint, not
proof that the relevant expertise was effective.

`_team_body` launches red cells, normalizes their proposals, applies caps, then creates
two blue tasks and a blind verifier for each admitted claim. The checked-in panel is
three red, two blue and one verifier; the judge is additional. Blue receives the
normalized statement and package, not red's relation rationales or another blue answer.
The verifier receives claim identity fields and the package, not the statement or
red/blue narrative. It still sees shared original producer context; blindness is not
independent upstream evidence generation.

`review/compact.py::expand_red` expands compact labels into the closed red contract.
Explicit `no_claim` can be a bare lead label or label plus `why`. Omitted leads become
blocked with a named gap. `review/red_discovery.py` validates exact lead accounting,
reference closure, scope, topology and output bounds. Neither no-proposal nor a
successful empty worker is a clean verdict.

`_normalize` derives canonical claims from affected entities, CWE, security predicate
and closed preconditions. Exact identities merge; prose and role count do not vote.
`review/claims.py::possible_duplicates` only nominates overlapping-entity pairs with
different CWEs. It does not resolve semantic duplicates. The caller does not pass
`normalize_claim` an enclosing-symbol lookup here, so optional span-to-symbol
normalization is not automatically exercised.

`_triage` records caps and rejection reasons. A normalized claim admitted to the
active set but excluded by a per-package cap remains a claim without its group's
relations/requests being installed; it ultimately remains unresolved. A proposal beyond
the active-claim limit can remain only in the lane triage record and protected receipt,
not the canonical claim set. Closed-vocabulary failures likewise retain a gap and
proposal reference, not a claim. This distinction matters to denominators.

`_run_rounds` repeats within the same package until semantic stability or the existing
budgets/round cap. Supported/confirmed claims can provide accepted context; only
confirmed claims seed variants. `_pending_requests` carries bounded requests anchored
inside the package. Cross-package/cross-lane variants and unresolved specialist referrals
are explicitly gaps; no worker delegates new tasks or expands its authority.

### 1.3 Evidence, verifier and judge

`review/evidence.py::resolve_relation` re-resolves canonical identities, source bytes,
shards and evidence artifacts. Truncation makes a relation incomplete.
`review/admission.py::ADMISSION_TABLE` distinguishes direct, analyst-assessed and indirect
content per predicate. Source text is direct for construct presence, not automatically
for attacker control, reachability, guards or impact. Tool observations use the
versioned rule map; graph facts require eligible structured facts and mapped predicates.
Advisories, derived tags and generated context cannot independently satisfy predicates.

The family's requirements come from `review/obligations.py::required_predicates_for`.
Memory/input claims normally owe construct, control, reachability and guard evidence;
secrets/cryptography, configuration and supply-chain claims have different sets.
Configuration-scoped preconditions and affected build entities add configuration
requirements. Security impact is derived rather than required as a direct citation.

`review/independence.py::verify_independence` checks distinct actor and fresh conversation,
no shared actor cache/prior response, absence of forbidden markers from verifier request
bytes, and independently retrieved complete direct support for **each** required
predicate. `teams.py::_review` persists the result and failures.

Three distinct axes must not be conflated:

| Axis | Current evidence | Limit |
| --- | --- | --- |
| Actor/conversation blindness | Cell identities, request checks, own receipts | Does not establish independent model errors |
| Model/provider diversity | Recorded profile comparisons | Same-model confirmation is allowed; distinct-model policy gates ship-blocking, not claim confirmation |
| Evidence independence | Verifier re-retrieves eligible support | May be the same scanner/graph artifact as red; no claim that a second producer reproduced the fact |

`teams.py::_plan_judges` presents bounded, deterministically shuffled A/B red and blue
positions. The judge does not inspect the verifier's reasoning. `_judged` records a
verdict and model distinctness after the request-identity check. Judge relations carry
`adjudication_judge` provenance and `review/adjudication.py::_predicate_statuses` excludes
them from every deciding predicate. Judge disagreement is retained in finding packages.
It can affect PoC eligibility, not R5 truth.

### 1.4 Deterministic state transitions

`review/adjudication.py::adjudicate` applies the first matching row:

| Row | Predicate/identity result | Terminal state and meaning |
| --- | --- | --- |
| R1 | Canonical duplicate already exists | `duplicate`; refer to the canonical claim |
| R2 | No affected entity in admitted scope | `out_of_scope`; scope decision, not a false-positive label |
| R3 | Required predicate has both direct support and contradiction | `insufficient_evidence`, with unresolved-contradiction gaps |
| R4 | Required predicate contradicted without direct support | `not_reachable`, `not_exploitable_in_observed_configuration`, or `contradicted` |
| R5 | All required predicates supported and R6 passes | `confirmed` |
| R6 | Some required direct support | `supported`, with missing-evidence gaps where applicable |
| R7 | No required direct support | `insufficient_evidence` |

`stages.py::apply_policy` records legal ledger transitions. Confirmation and the two
configuration/reachability refutations pass through `supported`; downstream counts must
use final state, not the number of transition events. Refutation under R4 does not
require an independent confirming verifier. That asymmetry is current policy, not an
invitation to silently add/remove reviewers.

### 1.5 Scores, publication and consumers

`stages.py::score_claims` scores supported/confirmed claims independently of worker
severity opinions. `review/scoring/factors.py` derives cited factors; the numeric guard
extractor excludes unsupported code-based numeric reasoning. The application risk
matrix retains missing-factor intervals: if possible bands differ, severity is unrated,
not lowered. CWE impact is class-level; environmental tags are not deployment facts.
EPSS is excluded as a scoring input; advisory CVSS remains reference context.

`stages.py::finding_packages` emits supported/confirmed packages, direct support,
analyst-assessed support, missing predicates, independence, judge dissent, score IDs and
gaps. `remediation_partition` sends only confirmed findings to remediation and supported
findings to the unconfirmed verification backlog. Rejected/insufficient claims remain
in the ledger rather than becoming developer findings.

`poc_candidates` additionally requires an accepted judge verdict, a resolved red basis,
and configured severity. Therefore changing judge selection can change developer PoC
availability even when R5 outcomes are unchanged. PoCs remain compile-only, never run.
Pre-seal chain checks are separately accounted and cannot manufacture base-claim support.

`jobs/accepted_review.py` verifies hashes, ledger replay, manifest and partition
agreement. `job_final_publication_gate/classify.py` preserves claim state and places every
finding package in exactly one of publishable, verification backlog or withheld.
Withholding concerns unavailable referenced PoC/chain outcomes, not a new truth state.
`job_final_report_publication` reads only the gate-certified snapshot.
`job_dossier_publication` produces protected confirmed-finding and PoC dossiers, not a
general dismissal or unresolved-claim audit.

## 2. Intelligence products and real retrieval routes

**There is no canonical bucket taxonomy at this review's kickoff.** T-129 owns
`docs/intelligence-buckets.json`. The labels **review_claims** and **metrics** below are
provisional conceptual groupings, not physical indexes or new canonical bucket IDs.
Documentation subsystem names are not buckets either.

Typed dataset IDs are taken from producer `datasets.py` declarations. Physical names are
from `retrieval/index.py::INDEX_NAMES`; neither review_claims nor metrics appears there.
Availability in an index, supply in a package, actual read and final citation are distinct.

| Conceptual grouping | Producer / concrete dataset | Schema or format; stage | Physical route | Actual consumer / retained value | Loss or limit |
| --- | --- | --- | --- | --- | --- |
| Evidence inputs, not a new bucket assignment | Accepted original producer shards; review accepted_scope | Accepted scope/evidence map; scope | `source`, `observations`, `graph`, `build`, `compiled`, `artifacts`, `evidence`, `binary`, plus bounded context indexes | Triage, package assembly and capability-granted cells; original entity/shard provenance | Missing families and clipped context remain gaps |
| review_claims, provisional | Inference lead_triage | JSON; triage | Protected attempt artifact/shared result receipt; no review-outcome index | Package admission and lead menus; assessed/reported severity, reason and gap | Model numeric citation is only supplied scanner fact membership |
| review_claims, provisional | Inference review_packages | `appsec-review/review-package/6`; packages | Artifact-only package manifest | Red/blue/verifier/judge bounded labelled views | Package supply is not proof of read or review completeness |
| review_claims, provisional | Inference review_cells | `appsec-review/cell-attempt-receipt/1`; lanes/cells | Protected receipts and lane documents | Reuse, accounting, audit adapters; valid results and retrieval transcript | No-proposal reason is in result receipt, not lane summary; dropped labels are feedback |
| review_claims, provisional | Inference claim_ledger | `appsec-review/ledger-event/1`, projection and adjudications; publication | Immutable JSONL/JSON artifacts, not FTS | R5/scoring, accepted-review reader, metrics; contradictions, qualifications, verdicts, requests, gaps | No complete pre-claim disposition product; request closure is uniformly unsatisfied |
| review_claims, provisional | Inference scores_and_findings | `appsec-review/finding-package/2`, score packages, handoff; publication | Artifact-only | PoC, remediation, dossiers, gate; score uncertainty and state | Finding support lists do not carry the full counterevidence set |
| review_claims, provisional | Dossier dossier_publications | Protected dossier files and publication summary | Protected publication, not evidence facts | Developer brief from accepted projection and attachments | See G4: selected evidence currently support-only |
| review_claims, provisional | Final gate publication_gate_decisions; report final_report_publications | `appsec-review/final-publication-gate/2`; `appsec-review/final-report/2` | Hash-bound gate/report JSON and Markdown | Report, OpenVEX via its admitted inputs, offline accepted-report reader | No automatic general-purpose sanitized finding index is built by the report job |
| metrics, provisional | Offline finding adapters and scorecard | `finding-snapshot/1`, `finding-metrics/1`; operator derivation | Operator output and content-addressed finding history, not a job retrieval index | Operator quality/trend analysis; independent labels | Does not feed workers or alter adjudication; some role measurements still require supplied input |

The concrete dossier dataset names are declared by
`jobs/job_dossier_publication/datasets.py`; inference declarations are in
`jobs/job_inference_security_review/datasets.py`. The report declaration explicitly says
indexing sanitized findings is later work; its `job.py` only verifies, assembles, renders
and publishes. Architecture prose describing a finding-index publisher must not be read
as evidence that one currently runs.

Catalog tools produce upstream evidence rather than the decision records in this
matrix. Relevant catalog identities include `audit-codeql`, `tool-infer`,
`tool-clang-static-analysis`, `tool-svf` and `tool-semgrep`; they are not interchangeable
with observation scanner labels or graph producer names. T-129 must map the actual
catalog IDs and typed output kinds from those producers, not create an invented “red
tool” or “verifier tool.” Read routes are the retrieval core's bounded capabilities,
including graph queries where granted, not direct arbitrary database/target access.

## 3. Strengths and source-backed gaps

### Strengths to preserve

- **Agreement is not evidence.** Adjudication ignores vote counts and judge provenance;
  direct support/contradiction conflicts remain unresolved.
- **Missing is not clean.** Unmapped leads, absent producers, skipped packages, incomplete
  evidence, invalid workers, unfilled obligations and withheld outcomes retain gaps.
- **Custody survives retries.** Content-addressed package/cell identities, immutable
  receipts, deterministic merge and publication cross-checks prevent silent substitution.
- **Policy authority is centralized.** Models nominate; configuration controls budgets
  and roles; typed validators and application policy decide admission/state.
- **Uncertainty is already represented.** Severity intervals, missing factors,
  verification backlog and distinct-model-pending shipment status must not be replaced
  with deceptively simple confidence percentages.
- **Quality formulas already exist.** T-062/T-064/T-065/T-066/T-068/T-069 delivered
  substantial offline metrics. This design extends acquisition/attribution, not a second
  scoring framework.

### G1 — Stage decisions exist, but no complete decision product joins them

**Static evidence:** `teams.py::_normalize`, `_triage`, `_seal`, `_lead_summary`;
`compact.py::expand_red`; `observability/findings/lead_adapter.py::lead_records`.
No-claim reasons survive in protected cell results but `_lead_summary` retains only
outcome per cell. Rejected proposal references and cap outcomes live outside canonical
claims. Unadmitted lead records have no family/scanner in the current adapter, because
those are recovered from admitted package menus. Attribution reduces deciding
contradiction roles to blue first, otherwise verifier; mixed claim stages become
unattributed.

**Impact:** an operator can reconstruct some decisions by reading multiple artifacts,
but cannot directly ask which evidence, admission reason, cap, worker failure or joint
refutation removed a population of leads. Silence is correctly distinguished in metrics,
yet cannot be audited as a structured reasoned dismissal. This reduces the usefulness
of review_claims intelligence without proving a particular false-negative rate.

### G2 — Admissibility is stronger than citation validity but not a full semantic warrant

**Static evidence:** `evidence.py::classify`, `resolve_relation`, `guard_relation_kind`;
`admission.py::ADMISSION_TABLE`; `graph/contract.py::GRAPH_FACT_PREDICATES`;
`adjudication.py::_predicate_statuses`; `scoring/factors.py::GuardAbsentExtractor`.
The general classifier receives kind and predicate, not a claim-scoped proposition or
polarity. Source-span presence can be classified direct for affected_construct even
when the worker marks it contradicts. A direct-eligible guard/range fact maps to
missing_or_ineffective_guard; destination-bound checking currently specializes the
**contradicts** direction. A **supports** citation of an effective guard does not receive
the same check in relation resolution, although the scoring factor extractor excludes
that effective guard from guard-absent scoring.

**Impact:** current typed admissibility prevents many irrelevant citations, but can
retain a polarity/subject mismatch as deciding support or contradiction. R5 trusts the
relation qualification; a second actor re-reading the same fact is not itself a semantic
cross-check. This is a deterministic contract gap inferred from the code paths, not an
observed exploit or a claim that particular published findings are wrong.

**Bounded response:** add proposition-specific, application-validated warrants for the
already commissioned fact families. Do not solve this by treating more model prose as
direct or by inventing tool results. Uncommissioned semantics remain analyst-assessed.

### G3 — Evidence requests are retained but never recognized as resolved

**Static evidence:** `teams.py::_pending_requests` forwards bounded in-package requests;
`_seal` opens every accumulated request and unconditionally closes it UNSATISFIED with
“bounded package rounds ended without a verified request resolution.”
`ledger.py::EvidenceRequestView` and request outcome enums already support a richer
lifecycle; exact accounting requires terminality, not effective completion.

**Impact:** the records cannot distinguish “later evidence answered this question”
from unavailable evidence, wrong scope, exhausted budget or a need for a separately
commissioned producer. More rounds do not automatically improve this diagnostic.
Semantic repetition/retrieval cache hits must not be counted as new evidence.

### G4 — Counterevidence survives the ledger, not the full developer projection

**Static evidence:** `ledger.py::relation_json` and `project` retain contradictions and
qualifications, including judge provenance. `stages.py::finding_packages` builds
direct_evidence from supporting relation IDs and analyst_assessed_evidence from
supporting analyst-assessed relations. `reporting/dossiers.py::build_dossier` selects
only those lists, and dossier `_excerpts` retrieves only the same selected entities.
Judge dissent survives separately, but its full predicate basis is not in the sanitized
finding projection.

**Impact:** a confirmed finding can carry qualified counterevidence in the ledger that
the developer brief does not show. Dismissed/insufficient claims receive no ordinary
finding dossier. Avoid describing this as “counterevidence is lost everywhere”; it is a
projection/queryability gap. Coordinate its brief interface with T-146/T-076 rather than
creating another report authority.

### G5 — Reviewer integrity attribution confuses judge dissent with verifier overturn

**Static evidence:** `observability/findings/run_adapter.py::findings_from_documents`
sets verification.verifier_overturned from judge_verdict.disagrees_with_state.
`integrity.py::verification` labels that flag a verifier-overturn rate and only measures
published findings. `tests/test_finding_run_adapter.py::test_actionability_and_verification_are_read_not_inferred`
currently asserts the same mapping. A genuine verifier refutation that prevents
publication is outside that population. `scorecard.Inputs.role_citations` is optional;
`integrity.citation_resolution_by_role` already computes the rate when supplied.

**Impact:** the current metric can measure the wrong actor and survivor population.
This needs a source/adapter correction and explicit metric identity, not merely a
renamed chart. T-071 should own this correction; T-077 already owns real-run lead
attribution and operator display. T-146 separately owns the adapter's missing-predicate
shortcut for path actionability; do not duplicate that fix.

### G6 — Severity-based admission and numerical reasons need independent calibration

**Static evidence:** `lead_triage.py::catalog_decision`, `tool_facts`, `_from_item`;
`packages.py::admission_reasons`; `appsec-review.toml:2866-2876`.
The numeric guardrail detects selected patterns and checks that O1 was supplied; it
does not validate quantitative entailment. Catalog impacts and model triage can change
lane admission before deeper review. The final score does retain uncertainty, but that
does not recover a lead never admitted.

**Empirical question:** how often does severity triage remove a true lead, and are
unknown-versus-assessed severity bands calibrated by family? Preserve original severity,
assessed basis, numeric fact content hashes and admission decisions in the audit
product. No recommendation to automatically admit all leads, inflate severity, or
weaken the existing guardrail follows from this static review.

### G7 — Existing quality metrics need broader populations, not replacement formulas

**Static evidence:** `triage.py::_paired` computes retention/removal over labelled
**resolved** leads, separately reporting true/false unresolved counts.
`labels.py::export_audit_sample` is deterministic but samples all removed leads by one
seeded order, without stratification. `lead_adapter.py::_observation_locations` reads
observation entities only; non-observation leads can lack labelable locations.
`run_adapter.py::findings_from_documents` omits findings with no source location from
fingerprinted snapshots and records a gap. `review/evaluation.py::task_input` hardcodes
the generic predicate set including security_impact, unlike current family-specific
obligations; `assess` is explicitly a label-citation proxy, not production R5.

**Impact:** labelled resolved-lead rates cannot alone measure end-to-end retention or
false-confirmation risk. Artifact-only findings, admission losses, unsupported
dismissals and unresolved cases need visible population/coverage accounting. Evaluation
must exercise the actual family policy as well as retain the existing bounded role
proxy, labelled as such. Independent holdout labels cannot be replaced by model
confidence, citation presence, consensus or a successful tool exit.

### G8 — Duplicates and shared evidence limit claims about independent yield

**Static evidence:** `claims.py::claim_identity`, `possible_duplicates`;
`teams.py::_normalize`; `independence.py::verify_independence`;
`observability/findings/identity.py` and `run_adapter.py`.
Identity excludes prose/mechanism and combines affected identities/CWE/predicate/
preconditions. Different mechanisms at the same broad entity may merge; the same
mechanism with different anchors/preconditions may remain separate. The offline
cross-revision fingerprint is distinct from canonical claim identity.

**Impact/hypothesis:** measure over/under-clustering with independently labelled
root causes before changing identities. Record original proposal membership and
producer-overlap evidence so a second citation/cell is not misreported as a second
defect or independent reproduction. No automatic fuzzy merge is proposed.

## 4. Representative accounting traces

These are deterministic path examples, not model-quality measurements.

| Case | Local progression | Published accounting / downstream outcome |
| --- | --- | --- |
| Supported and independently verified | Admitted lead → valid red proposal → all family predicates supported → verifier re-retrieves each → R5 | Confirmed finding, score or explicit unrated status, confirmed remediation intake; judge gate separately determines PoC eligibility |
| Sound dismissal | Red proposal → one required direct contradiction without conflicting direct support → R4 | Canonical contradicted/not-reachable/configuration state; lead dismissed only if all its claims dismissed; no finding package; deciding relations remain ledger data |
| Explicit no-claim | All successful red lenses say no-proposal, no claim | Lead summary no_proposal; metric no_claim_raised, not reasoned dismissal or false-positive label; reason accessible only through receipt |
| Unresolved/blocked | Omitted lead → blocked gap, or partial support → supported, or no support → insufficient | Blocked/unaccounted remain unresolved; supported enters verification backlog; insufficient remains ledger-only; neither is reduced as a false lead |
| Invalid/timeout/budget | Failed schema/provider/timeout with configured retry bounds, or cell/package not launched | Terminal cell and named gap; no successful red account becomes unaccounted; surviving support cannot independently confirm after verifier failure |
| Disputed evidence | Complete direct support and contradiction on a required predicate | R3 insufficient_evidence, explicit conflict, no majority vote or judge override |
| Judge dissent only | R5/R6 confirm; judge says blue-correct/neither | Finding remains confirmed with dissent; PoC generally not selected; current verifier-overturn metric misattributes this case (G5) |
| Capped proposal | Normalized claim exceeds per-package review cap or active limit | Claim unresolved or proposal-only cap record respectively; must not appear as no-claim or cleanly dismissed |
| Duplicate | Exact canonical identities collapse across red cells/lanes | Origin/proposal counts retained; duplicate lead follows canonical claim; possible semantic duplicates remain nominations |
| Withheld | Confirmed/supported finding references an unavailable required attachment outcome | Gate lists withheld reason without changing accepted claim state; absent optional work is a limitation, not automatically withholding |

`review/accounting.py::exact_accounting` checks claim/cell/request partitions;
`observability/triage_reduction.py` separately partitions admitted leads. Ordinary gaps
degrade rather than silently erase work; integrity failures block publication. Execution
safety can also stop processing on first failure depending on the active runtime policy;
the existence of typed gaps is not a promise that every later cell will run.

## 5. Reuse, failure and efficacy boundaries

`review/cells.py::cell_fingerprint` binds package dependency basis, readable evidence,
task input, role/persona, model/reasoning, guidance, capability, budgets, round and
validator versions. Successful own-cell receipts may be revalidated and reused.
`review/result_cache.py::memo_key` supports only explicitly eligible blue tasks and
removes round-bearing fields, not substantive request context. Shared memoization does
not apply to red, verifier or judge. Verifier own-cell reuse additionally checks the
stored blindness-marker sidecar; changed or unverifiable markers fail closed.

Cached outputs remain judgments, not fresh measurements or additional reviewers.
New records/policy must bind their version and evidence dependencies into the relevant
reuse keys. Provider model name stability does not establish backend revision stability;
T-071's user-owned canary work remains necessary. Recorded source tests cover receipt
reuse and invalidation but cannot establish statistical repeatability of fresh models.

Existing focused tests include `tests/review/test_adjudication.py`,
`test_independence.py`, `test_evidence.py`, `test_lead_triage.py`,
`test_team_handler.py`, `test_judge.py`, `test_result_cache.py`,
`tests/test_triage_reduction_metrics.py`, and `tests/test_finding_lead_adapter.py`.
They were inspected, **not run** for this documentation-only assignment. They validate
many contract invariants, not real-target precision, recall or severity accuracy.

## 6. Scheduling and evaluation handoff

The [design](../architecture/triage-verifier-enhancement.md#6-implementation-slices)
defines bounded slices; [the central registry](../TODO.md) remains the only backlog.
TRI-A/TRI-B/TRI-C/TRI-D are registered as T-150/T-152/T-153/T-154 respectively,
with direct registry links in that design section.
T-129 owns canonical bucket registration. T-146 owns operation/context/actionability
interfaces and preserves panel counts/judge-PoC dependencies. T-077 should consume the
new decision product and finish its paired operator display; T-071 should correct role
attribution and ingest failure/citation coverage. Completed T-062/T-064/T-069 formulas
stay completed; new provenance or stratified-evaluation scope is incremental.
T-067 owns the independent fix-pair/holdout corpus. T-061/T-074 own opt-in fix rechecks;
absence from this review must never become a fixed label or an automatic recheck.

The decisive evaluation is paired true-lead retention and false-lead removal across
all admission/disposition stages, false confirmation beside unresolved share, severity
agreement, fresh-run repeatability, cost per independently actionable root cause, and
stratified human audits of dismissal/no-claim populations. Static findings above justify
better records and tests; they do not justify reducing panels or claiming an efficacy
improvement before those measurements exist.

## 7. Documentation verification record

The scoped check ran with `PYTHONDONTWRITEBYTECODE=1 python3 -`, using
`scripts.docs_support.frontmatter`, `validate_frontmatter`, `identifier_errors`,
`link_errors` and `anchors` over only this review and its enhancement design. It also
validated the coordinator proposal JSON's required fields, existing TODO/dependency
IDs, file references and heading anchors, and checked both documents for LF and
trailing whitespace.

- Initial document-link check: **failed**, 0.035 s; corrected the numbered design
  section anchor.
- Expanded proposal-reference check: **failed**, 0.066 s; corrected five proposal
  anchors, including the Markdown em-dash slug form.
- Corrected scoped check: **passed**, 0.069 s; two documents, four proposed slices,
  six existing-item recommendations.

The generated inventory was used only as the documentation identifier validator's
input, not as evidence of runtime implementation. Root/package/source/runtime changes,
unit suites, integration, acceptance and live evaluation were **not performed**.
This record describes the agent's pre-integration checks. The coordinating session owns
central TODO registration; the documentation owner owns ledger/generated-index reconciliation.
