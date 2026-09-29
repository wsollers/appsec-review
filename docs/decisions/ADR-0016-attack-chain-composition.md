# ADR-0016: Attack chains are composed from reviewed claims after verification

Status: **Accepted** (2026-09-29, William, recommended defaults: lane 14 parallel to 12, `supported`
ceiling, optional input of 10, default bounds, job names as below). **Implemented** on branch
`kill-chains`: seeding, composer and refuter pools, derive and merge rules, attack-chain ledger, job
graph and Dagster wiring (plan slices S1-S3). **Open:** report section (plan S4), live acceptance (S5),
later slices (S6). Builds on ADR-0015.

Implementation plan: [`docs/proposals/attack-chains/implementation-plan.md`](../proposals/attack-chains/implementation-plan.md).

## Context

The claim review lanes decide one claim at a time. After ADR-0015 the ledger holds every accepted
tool lead as well as the STRIDE and OWASP candidates, and 07 → 08 → 09 → 12 give each one a
disposition. Nothing in the running flow asks how claims combine. A report on
`appsec-multi-vuln` can list `strcpy` into a 16-byte stack buffer at
`projects/cpp/case-001/main.cpp:7` as a finding without saying that `argv[1]` (line 6) is the
attacker-controlled entry that reaches it; a report on `freeciv21` cannot say whether a
client-reachable weakness leads into the server.

The pieces for composition already exist but are not connected:

- **Design authority.** `docs/architecture/design-v3.md` L14 (§5 table, "Cross-lane synthesis")
  and §15.2: integrators correlate only verified facts into attack/control chains and "may not
  invent factual predicates absent from the verified fact graph". §23.3: an inferred missing edge is
  a `SYNTHETIC_HYPOTHESIS`, and any chain containing one stays `CHAIN_HYPOTHESIS` until the edge is
  independently confirmed. §23.1: `VERIFIED_PRIMITIVE` confirms a local mechanism without asserting
  attack-chain consequence.
- **Legacy kill-chain prompts.** `07-red-team-adversarial/config.md` and `prompt.md` define a
  `kill-chain` red-team mode (ordered steps, taint source and sink); `08-blue-team-refutation/
  config.md` "Answering a kill-chain claim" requires a per-step disposition and says one refuted step
  normally breaks the chain; `09-independent-verification/subprompts.md` "Kill Chain Verification"
  says a chain is verified only if every link and the composition are confirmed, refuted if any link
  is refuted, unresolved otherwise. These texts predate the claim-review pool; the pool task
  (`claim-review-pool-task.md`) reviews single claims and never enters that mode.
- **Ledger fields.** `claim_ledger.py` carries `causal_route_ids` on every candidate and
  `causal_claim_ids` on every entry, with dangling-reference and cycle checks in `claim_ledger.py`,
  `claim_lifecycle_core.py` (`_validate_ledger`), `report_input_assembly.py` and
  `synthesis_report.py`. Every candidate source sets them to `[]`.
- **Ledger ordering rule.** `report_input_assembly._lifecycle_origin` blocks a ledger in which a
  candidate admission follows a lifecycle decision: the claim ledger is closed to new claims once
  07 starts deciding.
- **Attack trees.** ADR-0008 designs AND/OR attack trees with per-leaf prerequisites and
  `leaf_support` (`evidence` / `assumption` / `unresolved`), abuse scenarios and an
  `attack-tree-builder` persona, and uses "exploit-chain support" as a ranking factor. It is a
  design gate only; the workbench is not built. `03-threat-model-dfd-stride` is today the
  deterministic `threat_model_core.py`: it turns F03 component relationships into DFD flows and
  trust boundaries (`evidence_class: STRONG_INFERENCE`) and emits STRIDE hypotheses per flow. No
  model runs there and no attack tree is produced. `synthesis-report.schema.json` has
  `threat_model.attack_trees` (a string list) and no chain section.
- **Evidence for edges.** ADR-0015's supporting-evidence menu (`supporting_evidence_menu.py`) pins
  IR facts (functions, calls, memory operations with file/line), the code property graph records,
  the debug-symbol index, the component map and the integrated threat model for every reviewer.
  Those are the facts a link-to-link edge can cite.
- **Persona-facing vs final schemas.** ADR-0015's `claim_review_derive.py` has the model return
  judgment only (`claim-review-pool-persona.schema.json`); Python derives identity, citations,
  obligations and the final record, and bounces unresolvable replies through the invoker's repair
  loop.

## Decision

### 1. Placement: a new lane `14-attack-chain`, after 09, joined by 10

Two jobs, both in lane `14-attack-chain` (14 is the only unused lane number; lane numbers are not
execution order, compare 13 and 15 running before 07):

| Job | Depends on (contract) | Does |
|---|---|---|
| `14-attack-chain-composition` | `09-independent-verification` (required), `03-threat-model-dfd-stride` (`threat-model-core`), `01-component-characterization` (`component-map`) | Python seeds; red-team composer pool proposes chains; Python derives chain records |
| `14-attack-chain-refutation` | `14-attack-chain-composition` (required) | Blue-team pool tries to break each chain's weakest link; Python computes final chain state and publishes the chain ledger |

`10-synthesis-report` gains a dependency on `14-attack-chain-refutation` with
`allowed_skip_reasons: ["not-applicable-no-chain-seeds"]`. `12-scoring-prioritization` is
**not** changed: it runs in parallel with lane 14, scores claims as today, and chain ranking reads
its link severities at report assembly. (The brief proposed "before 12"; keeping 12 untouched
avoids changing its fingerprint, pool and contract, and 12 scores claims, which chains are not.)

### 2. Inputs

- The accepted 09 result (`independent-verification.json`): every claim with its preserved ledger
  fields and its 09 status; with it, through the 09 upstream binding, the ledger head.
- Link candidates are claims whose latest state is `verified`, `narrowed` or open
  (`candidate`/`under_review`/`unresolved`, 09 `UNRESOLVED`/`BLOCKED`). `refuted` and
  `superseded` claims are excluded.
- ADR-0015's supporting-evidence menu, unchanged, plus a chain workspace (below).
- The integrated threat model (elements, flows, trust boundaries) and the component map.
- When the ADR-0008 workbench exists: its attack trees (decision 11).

### 3. Chain model

A chain is an ordered list of **links** joined by **edges**, with an objective and an impact.

- **Stage vocabulary** (closed enum, order enforced by Python): `entry` → `execution` →
  `privilege_gain` → `persistence` | `lateral_movement` → `impact`. `impact` has a closed
  sub-kind: `code_execution`, `data_disclosure`, `data_tampering`, `denial_of_service`,
  `credential_theft`, `exfiltration`. Stages may be skipped but not reordered; a chain has exactly
  one `entry` and ends with exactly one `impact` link. `persistence` and `lateral_movement` may
  appear in either order and repeat once each.
- **Link.** Cites exactly one of: a ledger `claim_id`, or a **fact ref** (a menu item id plus a
  record locator: an IR-facts function/call record, a CPG record, a threat-model element or flow,
  a component-map relationship). A fact ref is how an entry such as `argv[1]` is represented when
  no claim describes it. Each link carries `prerequisites[]` (text, plus prerequisite link indexes
  within the chain) and the model's `citation_ids`, resolved by Python against that claim's or
  fact's own citations.
- **Edge.** Joins link *i* to link *i+1* and has a `basis`:
  - `code_fact`: an IR call/memory record or CPG call/data-flow record whose endpoints resolve to
    the two links' locations;
  - `model_flow`: a threat-model flow or component relationship between the links' components
    (`STRONG_INFERENCE`, not verified);
  - `synthetic`: the composer asserts the connection without a resolvable fact
    (design-v3 §23.3 `SYNTHETIC_HYPOTHESIS`).
  Python, not the model, decides the basis: a claimed `code_fact`/`model_flow` whose ref does not
  resolve to both endpoints is downgraded to `synthetic` and the downgrade is recorded.
- **Identity.** `chain_id = "chain-" + digest(ordered link refs, edge refs)[:24]`; the same chain
  proposed twice (by two cells, or two orderings of prerequisites) is one record.

### 4. Link and chain state are computed by Python

Link state comes from the ledger / 09 result, never from the model: `verified` (claim verified,
or a fact ref to a deterministic tool record), `narrowed`, `open`, `refuted`. Fact refs to a
threat-model element or flow count as `open` (they are `STRONG_INFERENCE`).

Chain state is the weakest of its links, its edges and its refutation outcome, on this order:

| Chain state | Condition |
|---|---|
| `refuted` | any link `refuted` (cannot arise from inputs, since refuted claims are excluded, but kept for re-derivation), or 14-refutation broke a link or edge with resolvable citations |
| `hypothesis` | any link `open`, or any edge `synthetic` (design-v3 `CHAIN_HYPOTHESIS`) |
| `plausible` | all links `verified`/`narrowed`, edges `code_fact`/`model_flow`, and at least one `narrowed` link or `model_flow` edge, or refutation did not run |
| `supported` | every link `verified`, every edge `code_fact`, refutation ran and the chain held |

A chain is never more verified than its weakest link. `supported` is the ceiling in this ADR: it
means "composed from verified parts along tool-recorded edges and not broken by an adversarial
reviewer". It is not a verified finding and never enters `verified_findings`; design-v3's
end-to-end composition proof (09 "Kill Chain Verification") is a later step (decision 12, open
question). The **weakest link** is the link or edge that sets the state; ties break by stage order
(earliest first). Python records it on the chain; the refuter is pointed at it.

### 5. Red-team composition (`14-attack-chain-composition`)

1. **Seeds (Python).** Build an adjacency graph over link candidates: two claims or facts are
   adjacent when an IR/CPG record connects their locations (same function, caller→callee, or a
   data-flow record), when a threat-model flow connects their components, or when they share a
   component and file. Seed an `entry` set: fact refs for recognised external inputs in IR/CPG
   records (`main` argv/env, `recv`/`read`/`fread` family, HTTP/packet handler parameters the CPG
   labels), threat-model elements of kind `actor`/`external_system`, and claims whose component is
   in a `public_ingress` or `client_device` zone. Clusters are the connected components that
   contain at least one entry seed and one P1 or verified claim.
2. **Composer pool.** One `attack-chain-composer` persona cell per cluster (C01 pool, persona
   pool slots, `probe`/`standard`/`full` budgets as for 07). The request carries the cluster's
   claims (ids, hypotheses, state, citations), its seeds and adjacency with their fact refs, the
   evidence menu, and the chain bounds. The persona returns chains in the persona-facing schema
   (judgment only: which links, which stage, which edge ref, prerequisites, objective, impact
   narrative) or an explicit `no_chain` with a reason per cluster.
3. **Derive (Python).** Resolve every claim id, fact ref and citation id; enforce the stage order,
   bounds and one-entry/one-impact rule; decide edge basis; assign ids; dedupe; compute state and
   weakest link. Unknown ids or illegal stage order go back through the invoker repair loop, as in
   `claim_review_derive.py`. A chain that still fails after repair is dropped and recorded as a
   composition gap for its cluster.

### 6. Blue-team chain refutation (`14-attack-chain-refutation`)

One `attack-chain-refuter` cell per chain batch (a different persona and, where the model registry
allows, a different model family from the composer, as ADR-0008 requires of challengers). For
each chain the request names the weakest link and asks the refuter to **break it first**, then
any other link or edge it can break. The persona returns, per chain, one of `broken` (with the
link/edge index, mechanism and citation ids), `narrowed` (a precondition that restricts the
chain), `holds`, or `cannot_assess`. Rules from `08-blue-team-refutation/config.md` carry over: a
tainted-data chain is broken only by a cited sanitisation, validation or block at a specific hop;
"the sink looks safe" is not a refutation. The refuter cannot change a link claim's ledger state;
it decides only the chain. Python validates citations and computes the final state (decision 4).

### 7. Ledger representation

The claim ledger stays closed after 07 (the `_lifecycle_origin` rule is kept). Lane 14 publishes
its own hash-linked **attack-chain ledger** (`attack-chain-ledger.json`), bound to the claim
ledger head and the 09 accepted pointer it read. Each chain record carries
`causal_claim_ids` (the ordered link claim ids, same name and meaning as in the claim ledger, with
the same resolve and acyclicity checks) plus `fact_refs` for fact links. Events:
`chain_composed`, `chain_refutation`, `chain_state_derived`. `causal_route_ids` on the claim
ledger is used in one place: when a later iteration re-opens the ledger
(`synthetic-hypothesis-resynthesis`, decision 10), a chain can be admitted as a fourth candidate
source with `causal_route_ids` = its link route ids, so 07/08/09 review the composition as a
claim. That re-admission is a later slice, not part of the first rollout.

### 8. Bounds and cost controls

New tunables in `registry/tunables.json` (defaults to be tuned on multi-vuln and freeciv21):

| Tunable | Default | Meaning |
|---|---|---|
| `chain_clusters_max` | 24 | composer cells per run; clusters beyond it are ranked (P1 count, verified count, boundary crossings) and the rest recorded as a gap |
| `chain_cluster_claims_max` | 40 | claims per cluster request; excess P3 claims dropped first, recorded |
| `chain_links_max` | 6 | links per chain |
| `chains_per_cluster_max` | 4 | chains a composer may return per cluster |
| `chains_refuted_max` | 48 | chains sent to refutation (ranked); the rest capped at `plausible`/`hypothesis` with a gap |
| `chain_refutation_batch` | 6 | chains per refuter cell |
| `chains_reported_max` | 20 | chains in the report body; the rest in an appendix table |

Cost controls: clusters without an entry seed or without a P1/verified claim get no cell; P3
claims are never seeds; the accepted-pointer fingerprint covers the 09 pointer, threat model,
component map, menu hash and tunables, so an unchanged 09 reuses lane 14; the persona result cache
(`persona_result_cache`) keys each cell on its request hash, so an unchanged cluster reuses its
composer reply even when another cluster changed. Budget class follows the run (`probe` → one
composer cell and no refutation, recorded as a gap).

### 9. Report section and ranking

`synthesis-report.schema.json` gains a top-level `attack_chains` section (and the report
template an "Attack chains" section after verified findings): for each chain its id, objective,
impact kind, state, weakest link, the stage strip with each link's claim title or fact label and
state, each edge's basis, and the refutation outcome with citations; plus `chain_gaps`. Ranking is
deterministic, computed at report assembly: state (`supported` > `plausible` > `hypothesis`),
then impact kind (`code_execution` first), then the highest 12 severity among verified links, then
trust boundaries crossed, then fewer links, then `chain_id`. Chains are prioritisation context,
not severity; the report says so. `refuted` chains are counted, not listed.

### 10. Failure modes are gaps (ADR-0013, ADR-0014)

| Situation | Outcome |
|---|---|
| No link candidates, or no cluster has an entry seed | both jobs SKIPPED `not-applicable-no-chain-seeds`; report says "no chain composed" and why |
| A composer cell fails, times out or exhausts repair | gap for that cluster; other clusters continue |
| A refuter cell fails | its chains are capped at `plausible` (or stay `hypothesis`) with a gap |
| A chain cites an unresolvable id after repair | chain dropped, gap recorded with the reason |
| Synthetic edge | chain stays `hypothesis`; the edge is listed as a synthetic-hypothesis route for `synthetic-hypothesis-resynthesis` |
| Native lane did not build (no IR/CPG) | no `code_fact` edges possible; gap "chains limited to model flows" |

Neither job fails a run for any of these; they fail only on a broken input binding (tamper,
missing accepted pointer), as other lifecycle jobs do.

### 11. Relation to ADR-0008 attack trees

- **Reused:** ADR-0008's AND/OR + prerequisites structure (chain link `prerequisites`), its
  challenger-is-a-different-persona rule, and its claim limits (no finding, severity or runtime
  claim from composition).
- **Distinct:** an attack tree is a pre-review *design* artefact over the threat model (`03`,
  before 07); a chain is a post-review *composition* over decided claims (after 09). A tree leaf
  with `leaf_support: evidence` is not a verified link.
- **Feeding:** when the workbench is built, each root-to-leaf AND path of an attack tree becomes a
  **chain template** in lane 14's seeds: its leaves are matched to ledger claims (by threat id /
  route id, component and location) and its objective becomes the chain objective. The composer
  fills or rejects the template; the chain's state is still computed from the matched claims'
  states. OR nodes give alternative templates. Tree leaves with no matching claim become
  `hypothesis` links through a fact ref to the tree node.
- **Superseded:** ADR-0008's "exploit-chain support" ranking factor remains a pre-review signal
  for `ranked-threat-scenarios.json` only; report-level chain ranking is decision 9. The legacy
  `kill-chain` mode text in 07/08/09 `config.md`/`prompt.md`/`subprompts.md` is superseded for
  the pool path by the composer and refuter tasks; its rules (per-step disposition, one broken link
  breaks the chain, tainted-path evidence) move into those task files.

### 12. Deterministic vs model

| Python (bookkeeping) | Model (judgment) |
|---|---|
| link candidate selection and exclusion by state | whether claims form a plausible attack path |
| seeds, adjacency, clusters and their ranking | stage assignment per link, prerequisites, objective, impact narrative |
| chain id, dedupe, ordering, stage-order and bounds checks | which edge ref justifies each hop |
| citation, claim id and fact-ref resolution | refutation: which link/edge breaks and why |
| edge basis (`code_fact`/`model_flow`/`synthetic`) | |
| link state, chain state, weakest link | |
| ranking, report projection, gaps | |

Later (not in this ADR's rollout): an independent composition verifier (design-v3 L7 on the
composed path, the 09 "Kill Chain Verification" text) that could promote `supported` to a
`verified` chain, through chain re-admission to the claim ledger (decision 7).

## Consequences

- Reports gain an "Attack chains" section. On deliberately vulnerable corpora it will mostly show
  short intra-file chains (argv → `strcpy`); cross-component chains depend on the native lane
  producing IR/CPG and on F03 relationships, and will often be `hypothesis` until those improve.
- Two new persona pools add cost after 09, bounded by the tunables; under `probe` there is one
  composer cell and no refutation. Review cost of 07/08/09 is unchanged.
- New shared surfaces: `job-graph.json`, `dagster_workflow.py`, `synthesis-report.schema.json`,
  `report_input_assembly.py`, `synthesis_report.py` and the report templates. 10's fingerprint
  changes when the dependency is added, so every run past 10 re-runs report assembly.
- The claim ledger's single-generation, admissions-before-decisions rule is kept; chains live in
  their own ledger until re-admission is designed.
- `design-v3.md` L14 gets a concrete owner (lane 14) and should say so at the next docs milestone
  (ADR-0013 decision 6).

## Alternatives considered

1. **Compose before review (after `claim-ledger-routing`, before 07)** and admit chains as ledger
   candidates with `causal_route_ids`, reviewed by 07/08/09 in their existing kill-chain modes.
   Reuses every pool and keeps one ledger, but composes over ~150 unreviewed candidates (mostly
   noise), doubles 07/08/09 work on chain claims, and cannot know which links survive. Kept as the
   re-admission path for a later iteration (decision 7).
2. **Chains inside 07 (red-team `kill-chain` mode per claim).** The pool reviews one claim per
   decision; a chain spans claims across cells and shards, so no cell sees the cluster. The legacy
   prompts are the evidence this was intended but never ran in the pool path.
3. **Deterministic-only chains (graph search over verified claims and CPG/IR edges).** Cheap and
   reproducible but cannot judge stage, prerequisites or impact, and would flood the report with
   every connected pair. Kept as the seed step.
4. **Chains in 12 (scoring the whole path).** Mixes prioritisation with composition, changes 12's
   contract and fingerprint, and gives no adversarial check. 12 may score `supported` chains later
   (open question).
5. **Wait for the ADR-0008 workbench and use its attack trees.** Trees are pre-review and the
   workbench is gated on B14/M01; chains are needed now for the four report targets. Trees feed
   lane 14 when built (decision 11).
6. **Admit chains to the claim ledger after 09 (relax `_lifecycle_origin`).** One ledger, but it
   breaks the invariant that report assembly and synthesis rely on, and gives chains a claim
   status vocabulary (`verified`) they cannot honestly reach statically. Rejected for now.
