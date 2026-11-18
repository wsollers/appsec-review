# Job 38/47 — job_inference_security_review

## Identity, result, and limits

- Authorized source: clean `main`, **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, `/home/wsollers/projects/appsec-review`, Ubuntu-22.04. Initial, pre-test, and final checks agreed. Import resolved to this checkout's `src/appsec_review/__init__.py`.
- Read the complete updated audit brief, authorized `AGENTS.md`, and coordination skill. Used `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu` and the authorized UNC source view, not the default Windows checkout.
- **Five new functional findings: one high, four medium.** Inherited graph admission, prioritization scaling, and document-result delivery seams are attributed separately, not counted again.
- **26 focused units passed in 16.37 s**, two workers, shuffle seed `38047`; wrapper total **23.532098 s**. No failures, skips, or cases over ten seconds. Four additional bounded Python executions produced eight numbered observations/reproductions in **0.978800 s** combined.
- No source/configuration/shared-environment edits, installs, subagents, real model/provider/tool/target execution, services, integration, acceptance, live reviews, commits, or pushes. Removed only this auditor's reproduction tree; retained private test-harness evidence.

**This is not a correctness certificate.** All 17 declared tasks and their immediate dispatch paths were traced. The large package/slicing, retrieval, scoring, audit-projection and policy matrices were not exhaustively read or tested. No actual findings quality, connected producer-to-consumer run, or final-gate certification was verified.

Abbreviations below: `job.py`, `teams.py`, `stages.py`, `chains.py`, `audit.py`, `schemas.py`, `datasets.py`, and `evidence_fulfillment.py` denote files under `src/appsec_review/jobs/job_inference_security_review/`. Other abbreviated Python paths are relative to `src/appsec_review/`. Findings provide full primary paths.

## Registration, configuration, and accepted contract

`runtime/registry.py:106,177` imports/registers the factory; `job_is_enabled(load_config(), JOB_ID)` returned **True**. `build_job` declares 11 steps/17 tasks, validates exact configured ordering and typed settings, and installs `DATASETS`/`CONTRACT` (`job.py:900-933`). The contract uses `REVIEW_GRAPH`, `ACCEPTED_EVIDENCE`, `always_execute=False`, and propagating handoff; `schedule_after` names document-issue analysis (`datasets.py:431-434`). Actual graph edges also incorporate `CONSUMES`, remove disabled nodes, and reduce transitive edges (`orchestration/topology.py:46-81`).

Observed dev settings, not inferred from older documentation:

- Teams: three concurrent teams; one red worker, blue setting one, verifier setting one. A positive blue setting constructs **two** distinct blue questions; the combined blue/verifier executor has `blue_per_team + verifier_per_team` workers.
- One round, one stable-round requirement, 500 active claims, 50 attack chains. Default one round never reaches the Round-2 fulfillment branch in F01.
- Lead admission critical/high, `either` reported/assessed basis, KEV enabled, exploration disabled; lead budget share 0.5; ten hunt units; three/five lead/hunt claims per package; incomplete-gap threshold 0.25.
- Team-package budget 200; 12,000 model turns, 480M input/48M output tokens, 40,000 retrieval queries, 28,800 seconds.
- Analyst/default: Claude Haiku 5.5, high, 128k/32k, 40 queries/four turns. Verifier: Claude Sonnet 5.5 with the same caps. Planner: Sonnet, zero queries/two turns. Triage: Haiku medium, zero queries/one turn.
- Judge enabled, `when=all`, one per claim, default model, four judge workers. Hunt planning enabled: four agents/eight areas. The campaign planner currently selects existing lane units; the separate campaign producer remains T-5030, not implemented by this job.
- Chains: six links, 100 expansion pairs, eight composition candidates, 100 challenge cells, 12 queries/four turns; no commissioned continuity producers by default, only `same_native_executable` derivation.

### Declared inputs versus actual reads

The contract contains **150 requirements over 29 producers**. All use the handoff channel. Required/reject envelopes are `job_review_data_indexing/handoff` and `job_review_package_assembly/handoff`; dependency native-advisory outputs are when-declared/not-applicable. Remaining inputs are optional/gap. Declaration counts include each producer's envelope:

| Producers | Requirement counts | Consumer use / authority |
|---|---|---|
| Artifact indexing; artifact security; binary evidence | 5; 4; 4 | Artifact/source backing, scanner observations, binary evidence. Producer evidence; binary kind-wide grant only when a configured binary is represented. |
| Change context; source history; prioritization; security tagging | 5; 5; 3; 3 | Routing context, not direct predicate proof. Priority reaches hunt unit ranking; RP-01 remains inherited. |
| CI; Clang static; code graph; CodeQL; CPG | 5; 5; 5; 6; 5 | Original analysis/observations and graph facts. Missing alternate-CPG declaration remains CGI-F12. |
| Compiled C++; C++ symbols; debug symbols; SVF | 9; 5; 7; 5 | Accepted compiled/symbol/alias context and backing. No compiler or analyzer dispatch in this job. |
| Dependency intelligence; evidence collection | 13; 4 | Dependency/scanner evidence plus bounded original IO/backing declarations. Advisory reference context is not target exploit proof. |
| Language build; post-build assessment; profile; tests | 6; 3; 3; 3 | Build/workspace/security and profile/test evidence. Not every declared payload is opened by every task. |
| Review data indexing | 9 | Required accepted retrieval authority; scope/index/precomputed/coverage products. |
| Review package assembly | 2 | Required upstream declaration, but this job **builds separate lane packages** from accepted scope rather than consuming that producer's package manifest as its team work list. |
| Target plan; target catalog; Tree-sitter | 4; 8; 6 | Source/build/component/document/AST inputs, plan and backing. |
| Threat-model generation | 5 | Generated models explicitly routing context; `review.behavior.load_model` binds model context during hunt ranking. |
| Document-issue analysis | 3 | Provisional envelope/ledger/drift declarations. No actual JSON-to-inference package/query path: inherited DI-F02. |

`job.py:137-149` resolves the attempt-pinned manifest, accepts it with frozen source dispositions, compares its digest to `scope.accept_manifest`, and checks evaluator-root isolation. `_check_embedded` verifies **all** embedded shards before producer selection (`review/scope.py:345-400`); shard opens retain original producer/dataset ownership through the input-read context. `runtime/inputs.py:359-366` rejects undeclared datasets, and `:368-379` records actual reads independently of supplied handoffs/citations. These checks are not replaced by topology ancestry.

Scope separately records components, build languages, source languages, sorted evidence-map tuples, coverage/freshness gaps and source dispositions. Target-owned guidance source identities are removed from team capability membership (`job.py:88-92,151-154,420-425`); evaluator-root input fails rather than becoming readable context.

The accepted input dataset list is not a promise that every underlying producer ran or that every optional artifact was read. OWASP workbench itself is not an in-process cell tool; `control_evidence`/`query_owasp_gaps` route through accepted derived products. Absence of an OWASP direct-producer declaration alone was therefore **not** reported as a new defect.

## Every declared task

| Task | Actual handler and processing | Validation/publication and limitation |
|---|---|---|
| `scope.accept_manifest` | `job.py:280-292`, `_scope`: immutable manifest/shard acceptance, isolation, snapshot-bearing scope record. | `accepted-scope.json`; clean admission tested with synthetic indexes. Inherited alternate-CPG seam can fail here before a model query. |
| `scope.assemble_scope` | `:293-304`: evidence map, components/languages and scope gaps. | Bound `evidence-map.json`; free-text handler summary is distinct from domain gap records. |
| `triage.lead_severity` | `:306-344`: disabled path; otherwise scoped lead collection, CWE reference, pinned triager guidance, bounded source excerpt, deterministic rule/catalog assessment followed by model assessment of remaining unknowns. | Cache/shared receipts and `lead-triage.json`; unresolved remains unknown. Model profile disable defect F04. No team `JobBudget` is passed to the separate triage execution. |
| `packages.plan_hunt_campaign` | `:352-395`: disabled path or accepted attack-surface brief, ranked candidate units, no-tool planner, validated/clamped area plan, fallback rank/gap. | Brief and plan artifacts; both lane assemblers consume plan selection. Planner is not a running hunting campaign. |
| `packages.assemble_lead_packages` | `:398-494`: assemble both lanes from the same accepted scope, triaged collection, source slices and behavior context; select lead records; freeze membership, rule predicates, CWE vocabulary and reuse basis. | Package/manifest hashes and `excluded-leads.json`. `review/packages.py:2291-2412` checks exact admitted lead membership, source scope, manifest schema and identity. |
| `packages.assemble_hunt_packages` | Same closure, select hunt lane; unit position ordering, shared unit-context-backed package bodies. | Exact hunt menu partition membership (`review/packages.py:2237-2252`), unit cutoff/area reasons. Deep neighborhood/slicing assembly remains sampled, not exhaustive. |
| `lead_review.teams` | `job.py:498-546`; `teams.run_lane`: deterministic quota/order, team semaphore, red proposals, admission, blue questions, blind verifier, optional judges, rounds and sealed shard. | Cell/schema/citation/receipt checks; ordinary lane failures become accounted gaps unless execution safety stops continuation. F02–F05 affect these boundaries. |
| `hunt_review.teams` | Same closure; bounded strategy/persona panel rather than lead lens; hunt citation gate before common blue/verifier/judge flow. | Per-cell/strategy/persona gaps, no-claim lead accounting, source-limited seeds, separate sealed lane. Cross-lane seeds intentionally unavailable during parallel lanes; a gap is retained. F01 affects configured follow-up rounds. |
| `merge.claims` | `job.py:582-609`, `stages.py:166-215`: verifies both shards in both enumeration orders; exact proposal membership; deterministic scope location/re-homing; duplicates and independence records. | `merge.json`; does not merge by prose similarity. Re-homing is explicit, and unrelated entities remain out of scope. |
| `adjudicate.apply_policy` | `job.py:611-623`, `stages.py:233-284`: checks prior ledger head; optional lane warrants; ordered deterministic R5 table and transitions. | Sealed adjudication shard and states. Full support plus independent verification alone yields confirmed; judge provenance is excluded from deciding relations. F02 can supply an incorrect independence Boolean. |
| `scoring.score_claims` | `job.py:632-657`, `stages.py:429-505`: supported/confirmed only, configured deterministic providers, re-resolved factors/tags, CWE catalog and reference distinctions. | Schema-validated score packages; unavailable provider gaps in ledger. EPSS omitted as score input; score does not change state. Full factor/provider matrix not rerun. |
| `attack_chains.compose_candidates` | `job.py:668-705`, `chains.py:169-313`: adjudicated components, severity-qualified extra-verifier selection, seed hints and predicate-ranked bounded pairs; model candidates only when continuity source is available. | Known components/endpoints/pairs, caps, deterministic continuity and proposal artifacts. Narrative cannot fill continuity. No nonempty chain job workflow was executed here. |
| `attack_chains.refute_edges` | `job.py:707-735`, `chains.py:316-407`: independent refuter, exact edge × five-dimension checks; scoped references; query/dispatch caps. | Terminal challenges and ledger; bad/missing evidence does not establish continuity. |
| `attack_chains.verify_weakest_links` | Same closure, conditional extra independent verifier; then `chains.publish`. | Chain status separate from component status; manifest/artifact/ledger/actor receipts revalidated by `chains.py:492-559`. Composition severity helpers sampled; complete continuity policy matrix unread. |
| `completeness.audit` | `job.py:747-779`: writes cutoff/producer/reference/admission gaps; exact cells/claims/requests; checks chain accounting separately and excludes enhancement gaps from base review completeness. | Ledger/projection pins, coverage matrix, COMPLETE/DEGRADED/EMPTY. Expected-cell membership is obtained from sealed lane records, not an independent external execution census. |
| `publication.publish_claim_ledger` | `job.py:782-803`: reaccept scope, verify package manifests, recompute ledger/projection and audited hashes, check terminal receipt bytes/chains. | Canonical ledger/projection/head. Attempt-zero cells may lack receipts; attempted cells may not. |
| `publication.publish_handoff` | `job.py:805-898`: exact re-audit, byte-for-byte ledger reproduction, findings/scores/chains, ship-block policy, remediation/backlog partition and PoC selection; then model-free audit sidecar. | Inner `/3` handoff plus common publication metadata/source pins. Audit integrity rejects; disabled/capacity/input unavailability yields explicit descriptor. F03 concerns eligibility, not PoC execution. |

`UnitExecutor` records successful handler execution separately from returned disposition; exceptions fail the unit and block its dependents (`runtime/units.py:142-211`). This job remains a legacy free-text handler-gap producer, while ledger gaps use `GapClass`; it does not set `strict_gaps=True`. That known boundary is documented, not a new status invention.

## All role/task and stage bindings

The complete 17 task-prompt files under `pipeline/guidance/tasks/inference-security-review/` and all eight dispatched role fragments were read as **data**. Registry paths/role tool lists were compared with immediate construction.

| Stage | Exact role/task binding | Actual authority |
|---|---|---|
| Severity routing | `lead_triager / lead_severity` | `lead_triage.load_triage_guidance`, profile selected by `triage.model_profile`, no retrieval tools. Deterministic rules/catalog precede model; result never confirms a claim. |
| Hunt plan | `hunt_planner / hunt_campaign_plan` | Pinned no-tool brief-only planner; profile selected by hunting settings. Area/agent plan orders existing packages. |
| Lead analysis | `red_team_analyst / lead_red_stack`, `lead_red_preconditions`, `lead_red_failure_modes` | `LEAD_LENSES[:red_per_team]`, routed persona/stack. Default only the first lens. All three files exist; configuration values above three cannot create additional distinct lead lenses. |
| Hunt analysis | `hypothesis_hunter / sink_up`, `entry_down`, `control_gap`, `persona_sweep`, `variant` | `hunt_panel` chooses strategy/persona pairs from available per-unit families and run control context; variant needs accepted seeds. Missing strategies/specialists are explicit. |
| Refutation | `blue_team_refuter / blue_control`, `blue_reachability` | Both questions constructed if blue setting is positive; each sees claim statement and original package, not sibling answer. Only contradicts/qualifies relations allowed. |
| Verification | `independent_verifier / blind_verifier` | Neutral claim identity/hypothesis plus original package; own retrieval, no blue/red argument. Actual request blindness, receipt support and actor freshness checked separately from model/provider distinctness. F02 affects unavailable reused request checks. |
| Judgment | `adjudication_judge / adjudicate_claim` | Blinded A/B sides, fixed ordering, bounded cited rows, generalist persona; verdict relations tagged with judge provenance and excluded from R5/scoring. Failure leaves no verdict; F03 incorrectly interprets that absence later. |
| Chains | `attack_chain_analyst / chain_composer`; `blue_team_refuter / chain_refuter`; `independent_verifier / chain_weakest_link_verifier` | Generalist/generic, adjudicated components/neutral proposals, normal bounded cell transport, no new standalone claims. Chain models explicitly check profile.enabled; ordinary team and tool-free paths do not. |
| Decide/score/completeness | Deterministic Python stages | Similarly named registry roles do not imply model dispatch. No separate autonomous “decider” was found. |

`teams.py:209-239,518-571` assembles/hash-pins bundles, attaches the registered evidence-querying runtime procedure, intersects role tools with the in-process catalog, and issues package/role/round/manifest-bound capabilities. `expand` is explicit application navigation. Binary kind grants require configured binary evidence; graph scope grants remain scoped. Result schemas are compact model shapes expanded to closed full results before admission.

`review/capability.py:37-95,173-219` closes tool/index/entity/graph/page/depth/byte bounds. `review/cells.py:138-167` fingerprints package/dependency evidence, task input, role/persona/stack/strategy, guidance/model, budgets and schema/validator versions; retries/concurrency deliberately do not change identity. `reuse_or_run:283-332` revalidates succeeded receipts, vocabulary/citations and shared custody. Blue memoization is separately restricted; verifiers and judges do not use that memo.

Claim `/3` identity binds normalized affected constructs, CWE and predicate, excluding prose, preconditions, lane and package; folded site identities may resolve to enclosing symbols. Preconditions/origins merge, possible duplicates are separately reported (`review/claims.py:58-169`). Findings get content-derived IDs; score/adjudication/ledger/source hashes remain separate. None of this establishes semantic truth without resolving the deciding evidence.

## New findings

### ISR-F01 — Medium — Round-2 fulfillment consumes incompatible request and retrieval wire formats

- **Evidence:** `src/appsec_review/jobs/job_inference_security_review/evidence_fulfillment.py:95-113,119-143,162-176,182-186`; caller `teams.py:1224-1248`. Actual pending requests are emitted by `src/appsec_review/review/evidence_obligations.py:1301-1313`; actual rows by `src/appsec_review/retrieval/core.py:454-478`.
- **Trigger:** configure a follow-up round, retain an open evidence obligation, and resolve an in-package anchor. Default `max_rounds=1` does not reach this branch.
- **Expected / actual:** pending requests carry `obligation_id` and `question`; helper expects `request_id` and `need`. Retrieval rows carry `identity` and `location`; helper requires `entity_id` and reads `source_location`. **R1** used a real `RetrievalCore.find` row from this audit's synthetic accepted index and a request produced by the real `pending_followup_requests`: anchored fulfillment raises **`KeyError('entity_id')`**. **R2**, the same real request without anchors, reports zero fulfilled/one unfulfilled because its question is ignored.
- **Impact:** anchored follow-up aborts remaining rounds through the team's ordinary failure branch (`teams.py:1091-1112`), retaining prior work with a worker gap rather than doing requested investigation. Unanchored requests cannot text-match their actual question. Even a partial key fix leaves blank request identity, lost source locations and unreliable citation metadata.
- **Confidence:** high for the incompatible adapter and observed exception; no production second-round run executed.
- **Smallest correction:** consume the canonical obligation request and `RetrievalCore` row types, retain obligation identity, resolve shard/content hashes through accepted metadata, and add a real-row Round-2 wiring regression rather than the current alternate-shape fake.
- **TODO overlap:** T-173 (done) claims automatic fulfillment; T-153 (done) defines canonical obligations. Exact adapter mismatch was not found as a separately recorded item. Existing T-173 test invents both `entity_id`/`source_location` and `request_id`/`need`, hiding the seam.

### ISR-F02 — High — Missing verifier blindness receipt can still yield independent confirmation

- **Evidence:** `src/appsec_review/jobs/job_inference_security_review/teams.py:806-807,1754-1760,1777-1801`; `src/appsec_review/review/independence.py:65-87`; `src/appsec_review/review/adjudication.py:226-229`.
- **Trigger:** a reused successful verifier has no verifiable request-check sidecar, and all prior red/blue narrative markers are shorter than 16 characters (or otherwise absent). Reuse sends no fresh request bytes.
- **Expected / actual:** unavailable structural independence evidence must fail closed with an independence gap. `_verifier_request_bytes` returns the sentinel `b'\x00unverified-verifier-request'` when there is no marker to return; `verify_independence` recognizes no sentinel and only searches for supplied markers/other actor IDs. **R5** returns `independent=True`, no gaps, with a missing sidecar. **R5b** used the actual four required predicates for a SQL-injection claim; all synthetic direct relations supported those predicates and R5 adjudication returned **`confirmed`** despite the unavailable request check.
- **Impact:** an unverified blindness check is converted into affirmative independence and may promote supported evidence to confirmed. This is a demonstrated pipeline-state error, **not** a demonstrated false target vulnerability or a verified final-gate acceptance.
- **Confidence:** high for control flow and deterministic reproduction. Missing-sidecar recovery/corruption plus the short-marker condition is required; normal fresh request capture is not implicated.
- **Smallest correction:** return an explicit unavailable/failed request-check result and propagate an independence gap; never encode missing verification as ordinary request bytes.
- **TODO overlap:** closest are T-150 protected verification observations and T-152/T-153 evidence work. No exact empty-marker/unavailable-sidecar case found in the inspected entries.

### ISR-F03 — Medium — Failed judges are relabeled “not convened” and become PoC candidates

- **Evidence:** `src/appsec_review/jobs/job_inference_security_review/teams.py:1518-1536` drops failed/untrusted judge results; `stages.py:618-626,685-688,727-735,757-772` maps no verdict to `not_convened`. Consumer `src/appsec_review/jobs/accepted_review.py:177-194,284-292` accepts that same conflation. Explicit contrary failure behavior: `docs/operations/inference-security-review.md:1023-1027`.
- **Trigger:** a judge is selected but fails, times out, has invalid output, or fails its blindness check; the independently supported/confirmed finding otherwise has an eligible severity and usable basis.
- **Expected / actual:** the deliberately unselected/disabled judge path is distinct from failed attempted judgment. **R4** provided a FAILED judge terminal cell, used real finding publication and candidate selection, and obtained one candidate marked **`not_convened`**. **R4b** confirmed the candidate parser and finding-consistency check accept a complete version of that candidate.
- **Impact:** the next PoC job is offered work the documented failure policy excludes, with inaccurate provenance about whether a judge was commissioned. Claim state itself is unchanged; no PoC was built or executed in this audit.
- **Confidence:** high; this is not an objection to the intentional unjudged-candidate feature.
- **Smallest correction:** retain judge selection/attempt/terminal availability separately from verdict value and admit the fallback only for genuinely unselected/disabled judgments. Preserve failed/invalid/untrusted outcomes distinctly through handoff and downstream consistency checks.
- **TODO overlap:** related to the T-5033 measurement configuration, T-5035 escalation direction and judge/PoC implementation decisions. No inspected item covers conflating failed judgment with nonselection.

### ISR-F04 — Medium — `models.<profile>.enabled=false` is ignored outside chain dispatch

- **Evidence:** typed flag accepted at `src/appsec_review/config/inference_review.py:595-597`; profile lookup `:538-542`. Tool-free calls pass the raw infer function at `job.py:329-334,384-388`; `review/lead_triage.py:694-748` and `review/hunt_plan.py:586-647` never check the flag. Team construction/execution `teams.py:536-570,676-690` similarly discards it. Contrast explicit chain check `chains.py:84-91`.
- **Trigger:** disable a selected model profile while leaving the job/stage/role enabled.
- **Expected / actual:** no new model dispatch through a disabled profile, with a clear disabled/unavailable outcome. **R3** supplied the typed disabled triage profile to the real conversation helper; its fake infer was called twice. **R6** shows ordinary team construction also carries no enabled state into `CellSpec`; subsequent team dispatch has no matching check.
- **Impact:** a seemingly disabled profile can still incur provider calls/cost, with different semantics from the chain path that uses the same typed profile. No actual provider call was made here.
- **Confidence:** high, dynamic for triage; static tracing for planner and ordinary teams.
- **Smallest correction:** enforce profile activation consistently before all new dispatches, or reject unsupported disabled-profile bindings during configuration validation. Do not silently run a disabled profile.
- **TODO overlap:** central typed configuration and T-173 budget/dispatch work are adjacent; no exact disabled-profile issue found.

### ISR-F05 — Medium — Configured zero retrieval queries silently becomes one

- **Evidence:** `src/appsec_review/config/inference_review.py:592` explicitly accepts zero; `src/appsec_review/jobs/job_inference_security_review/teams.py:547` uses `max(1, profile.max_queries)`; `chains.py:59` similarly wraps the minimum with one. Capability validation requires positive caps (`src/appsec_review/review/capability.py:213-217`).
- **Trigger:** select a profile with `max_queries=0` for an ordinary review or chain cell.
- **Expected / actual:** zero queries must remain no retrieval, or the unsupported assignment must be rejected explicitly. **R6** constructed the real team cell with a zero-query profile; its issued capability had **`max_queries=1`**.
- **Impact:** the application widens a valid configured retrieval bound instead of preserving or rejecting it. The no-tool triage/planner paths are not the widened path.
- **Confidence:** high, real capability construction; no retrieval/model execution required.
- **Smallest correction:** support a zero-query/final-only capability or reject zero for roles requiring positive retrieval capability at typed validation. Remove silent lower-bound widening.
- **TODO overlap:** T-173 and T-5025 cover bounded querying/cell caps, but not this exact accepted-zero widening.

## Inherited seams and non-findings

1. **CGI-F12 / OCA-F01 — high, not new.** The graph report already reproduced inference's undeclared `alternate_cpg_index` read. Declaration comparison here found this is the **only missing indexed output among inference's declared producers**. `datasets.py:180-189` omits it. Because `_scope` checks every embedded shard, this can also reject scope admission before advertised `query_call_paths`/`query_cpg_slice` usage. No producer was re-audited.
2. **RP-01 — inherited ranking seam.** Prioritization scores above one are divided by 100 at `review/units.py:188-196,433-437`; this job consumes those unit ranks via `rank_hunt_candidates`. Prior report owns its 356→11 reproduction. Not rerun or counted.
3. **DI-F02 / C10-F04 — inherited delivery seam.** Document ledger/drift outputs are declared but not read into this job's separate package assembly or observation-backed `query_doc_drift`. Confirmed by the immediate assembly trace and prior document report. DI-F01's canonical document-payload skip further limits producer output; that producer was not re-audited.
4. The current implementation intentionally preserves two review lanes and named unavailable cross-lane seeds; the future campaign/one-review architecture is explicitly migration work (T-5030 and review-protocol-v3 M3/M4). Not reported as a newly missing implemented feature.
5. `lead_triage._converse` and `hunt_plan.run_planner` use a fixed one-call-plus-repair policy and no team `JobBudget` argument; R3 observed two physical calls with profile `max_turns=1`. Since retries versus per-attempt turns have separate semantics and these helpers document one repair, **the call count alone is not asserted as a separate cap violation**. Full job-wide budget accounting for these paths remains unverified.
6. Lead package ordering collapses all noncritical effective severities to rank one (`job.py:443-447`); role worker/cardinality settings are not a simple one-setting/one-role mapping. These were recorded as configuration/ordering coverage limits, not separately proven findings in this bounded audit.

### Documentation drift observed separately

- The operations page's blanket “unjudged claims are never PoC candidates” text is stale relative to the intentional `not_convened` feature; its separate statement that **failed** judges do not produce candidates is the policy distinction implicated by F03.
- Red/hunter role fragments say no chain is composed without a seed, but `chains.compose` also commissions admissible predicate-ranked pairs without seed hints.
- Generated task-binding labels remain “Undeclared (T-147)”; this does not mean handlers do not exist. Older text describes three red lenses/default model uniformity, while the observed dev recipe has one red worker and a separate verifier profile.

## Publication, schemas, downstream and certification

All **13 dataset declarations** were read:

| Output | Authority/access and actual storage |
|---|---|
| `accepted_scope` | Artifact-only routing scope/evidence-map task files. |
| `lead_triage` | Protected provisional triage result, attempt shared receipts, legacy job cache. |
| `review_packages` | Artifact-only routing inputs; all package-step artifacts, including plan, manifests, shared unit contexts and exclusions. |
| `review_cells` | Protected provisional cells and lead/hunt lane artifacts, budgets and queue/semaphore material. |
| `claim_ledger` | Artifact-only merge/adjudication/completeness and publication-ledger task artifacts. |
| `attack_chains` | Protected provisional proposal/challenge/terminal manifest material. |
| `scores_and_findings` | Artifact-only scoring and final inner-handoff/finding task artifacts. |
| `review_audit_metadata`, `review_decision_audit`, `review_decisions`, `review_verification_coverage`, `review_decision_bases`, `review_audit_continuations` | Protected operational descriptor/manifest/bounded shards/continuations under attempt `artifacts/decision-audit`. Not model evidence or an MCP payload grant. |

The immediate write paths match these broad declarations. Full generic publication inventory/custody closure was not independently replayed. Dataset schema labels do not mean every referenced heterogeneous payload shares that schema.

`schemas.py` implements the closed schema subset with unsupported-keyword errors. There are **28** inference schema documents; tests loaded them, but this audit did not manually inspect every JSON property/combination. Inner handoff is `inference-review-handoff/3`, finding package `/2`, review package `/7`, lane-package envelope `/1`, score set `/3`, ledger-event `/1`; compact role schemas expand before result validation. Finding/handoff top levels are closed.

Ledger merge verifies every shard and order independence; publication hashes canonical ledger/projection bytes. Completeness verifies final claims, exact supplied expected-cell accounting, evidence-request terminal closure and chain enhancement accounting. Gap ratios count gapped cells/packages, while unreviewed producer/unit/claim facts remain separately named; these are not a whole-target coverage percentage.

`audit.trusted_origin:49-133` verifies executing attempt, claim/source/target/input manifest, full frozen configuration and original scope/ledger/package anchors. `_publish:156-333` verifies lane membership, warrants/obligations, original receipts/checks, findings and source closure before projecting protected records. Disabled/capacity/input-unavailable projection is explicit; integrity errors are not recoverable audit gaps. The large decision-audit projection/publication modules beyond this adapter were not read in full.

`jobs/accepted_review.py:115-298` re-verifies hashes, package manifests, ledger/projection reproduction, scores/findings, chain memberships, judge verdicts, PoC package agreement and remediation/backlog partition. Remediation intake is confirmed only; supported findings remain the verification backlog. PoC consumes explicit eligible candidates. Final report consumes the later gate-certified snapshot, not an independently authorized raw review handoff. **This job does not itself issue the final publication certificate**, and no gate/dossier/remediation/PoC execution was performed.

## Focused validation and reproductions

### Safety inspection

Read the four selected test files fully before execution. Handler tests inject `ScriptedInfer`/`ChainInfer`; synthetic index builder creates local fixture source/index/feed bytes, does not execute target code. Feed publisher uses `_NvdClient` and local archives, not HTTP. Inspected common pytest environment preflight and image-verifier substitutes. The wrapper used its normal unique microsecond/PID directory, not a shared default temp and not a renamed global wrapper path. No environment variables were changed to make tests pass.

### Exact collection command

Executed in the authorized checkout through the brief's base64 SSH transport:

```bash
.venv/bin/python -m pytest --collect-only -q \
  --basetemp=test/tmp/job-audit-inference-38-collection-20261118a \
  tests/unit/job_inference_security_review/test_contract.py \
  tests/unit/job_inference_security_review/test_handlers.py \
  tests/unit/job_inference_security_review/test_stages_and_schemas.py \
  tests/unit/job_inference_security_review/test_t173_evidence_and_budgets.py
```

**26 collected in 0.94 s**, exit 0. Breakdown: five contract, six handlers, five stages/schemas, ten T-173 cases. Environment guard also runs as session preflight; it is not an extra collected test in this count.

### Exact execution command

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 38047 \
  --max-tests 26 --expect-tests 26 --timeout-seconds 180 -- \
  tests/unit/job_inference_security_review/test_contract.py \
  tests/unit/job_inference_security_review/test_handlers.py \
  tests/unit/job_inference_security_review/test_stages_and_schemas.py \
  tests/unit/job_inference_security_review/test_t173_evidence_and_budgets.py
```

Before both commands:

```bash
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
```

Wrapper private base temp: `test/tmp/tests-custom-20261118-133318-755006-3424493`.

- Internal preflight: 26, 2.176729 s; execution supervisor: 20.991944 s; pytest: **26 passed, 16.37 s**.
- Wrapper total: **23.532098 s**; cleanup confirmed for collection/execution; zero failures/skips/slow tests.
- Log: `test/tmp/logs/tests-custom-20261118-133318-755006-3424493.log`.
- Collection log: same stem, `.collection.log`; manifest: `test/tmp/tests-custom-20261118-133318-755006-3424493.collection.json`.
- JUnit: `test/tmp/tests-custom-20261118-133318-755006-3424493.junit.xml`.
- Timings: `test/tmp/tests-custom-20261118-133318-755006-3424493.timings.sqlite`.
- Fixed report: `test/tmp/reports/tests-custom-20261118-133318-755006-3424493.json`.

### Cheap reproduction observations

All were `.venv/bin/python - <<'PY' ... PY` via the same SSH/base64 transport, with fake external boundaries or pure functions. No external inference/tool execution occurred.

| Invocation | Real code exercised / bounded setup | Exact observation | Elapsed |
|---|---|---|---|
| R1/R2 | `RetrievalCore` reads this audit's `isr-unit-index-template`; source `native/src/parse.c`; `pending_followup_requests` receives one OPEN synthetic obligation, predicate `affected_construct`, question `Inspect native/src/parse.c:3`, first with its exact source identity as anchor, then no anchors. Pass result to `fulfill_evidence_requests`. | Real row keys `identity,index,kind,location,name,native_id,payload,shard_id`; pending keys `anchors,claim_id,obligation_id,predicate,question,requested_kind`; anchored `KeyError('entity_id')`; unanchored fulfilled 0/unfulfilled 1. | 0.219246 s |
| R3 | Load actual dev settings/guidance/schema; replace triage profile `enabled=False,max_turns=1`; call real `_converse` with an empty bounded group and fake `ModelResult(proposal={'bad':'shape'}, input_tokens=1, output_tokens=1)`. | `actual_fake_calls=2`, `reported_turns=2`, `triage_failed:invalid_output`. Disabled flag did not suppress dispatch. | 0.614570 s |
| R4/R5 | Real `finding_packages` from synthetic supported claim, high risk score, FAILED judge terminal record/no verdict; then real `poc_candidates`. Separately request bytes for a reused verifier with no sidecar and no markers, then real independence check with direct supporting relation. | Candidate count 1, verdict `not_convened`; sentinel `b'\x00unverified-verifier-request'`, independent true, gaps empty. | 0.015115 s |
| R4b/R5b/R6 | Complete R4 basis to the real candidate parser/consistency checker; supply all actual required predicates for R5 and call real adjudicator; build real `_cell` with typed zero-query profile and a synthetic bundle/core facade, no dispatch. | Parser accepted 1, consistency errors `[]`; four predicates, empty markers, independent true, adjudication `confirmed`; configured queries 0, issued 1; `CellSpec` has no enabled field. | 0.129869 s |

R4/R5/R6 used `test/tmp/job-audit-inference-38-repro-20261118a`; it was created exclusively and removed after inspection. These synthetic records demonstrate state/adapter behavior, not source entailment or a real target finding.

Inspection-only commands encountered unavailable Linux `rg`, a guessed nonexistent pipeline-job directory, `JobConfig.enabled` and `DatasetDeclaration.schema_identity` AttributeErrors, and an initial file-versus-package guess for `chain_composition`. Replaced them with available `grep`, actual registry selection/schema fields and package paths. These were **not unit failures**, did not prompt installs/edits, and do not invalidate the recorded test run.

## Read coverage and substantial unread scope

### Fully read

- Brief, authorized `AGENTS.md`, canonical coordination skill.
- All nine Python files in `jobs/job_inference_security_review/` (including `__init__`); all four selected test files.
- Canonical job operations page, all 17 task prompts, all eight dispatched role fragments, shared worker governing rules.
- `review/claims.py`, `review/independence.py`, `review/accounting.py`; exact core sections of adjudication plus full immediate stage application.

### Sampled / targeted

- `config/inference_review.py`: settings dataclasses, profile/role resolution, semantic identity and relevant parsers; actual resolved settings inspected. Scoring/PoC/audit policy subparsers not all read.
- `review/scope.py`: selectors/header and complete acceptance/embedded-shard path; `review/packages.py`: assembly/ranking/membership orchestration. The remaining roughly two thousand lines of package neighborhood/slicing implementation were not fully read.
- `review/cells.py`, `capability.py`, `budget.py`, `inference/execution.py`: fingerprints, reuse, capability construction and call accounting/transport boundaries, not every tool dispatch/retry/cancellation permutation.
- Triage/planner request construction and execution; their full catalog/rule, brief selection, salvage and cache matrices were not exhaustively read.
- Chain elevation composer through main evaluation/DFS setup; remaining chain-composition implementation and full `review/attack_chains.py`/native continuity policy were not audited independently.
- Registry task/role sections, runtime input-reader enforcement, UnitExecutor, topology, accepted-review and PoC consumer consistency paths.
- Synthetic test builder/reference-feed/stub setup and wrapper/common pytest setup, not every fixture helper.
- Prior graph/OWASP/prioritization cumulative evidence and relevant document-issue report; matching TODO sections/states, not the entire TODO registry.

### Material gaps

- **35 mapped unit files exist; only three mapped files plus the unmapped T-173 file were selected here.** Most review-team, behavior, warrant, audit-projection, prompt-competence and execution-budget combinations remain unexecuted.
- Handler templates use one round, minimal package budget, zero claims and no hunt units for several late-stage tests. Passing those handler tests does **not** prove nonempty production adjudication/scoring/chain/audit publication or Round-2 correctness.
- No exhaustive 150-input schema/owner/custody cross-product, all persona × stack × strategy combinations, all 28 schema property combinations, all score providers/factors, all chain continuity dimensions/failure cells, or all sidecar capacity/resume/race paths.
- No actual model output quality, native graph/CPG source correctness, provider/model distinctness behavior, or target exploitability was verified.
- No integration/acceptance/live/Dagster execution, final certification, actual remediation, or PoC generation/build. Final source stayed clean at the assigned revision.
