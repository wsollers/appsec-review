# Attack-chain composition: implementation plan

Status: plan for [ADR-0016](../../decisions/ADR-0016-attack-chain-composition.md) (Accepted).
S1-S3 are built on branch `kill-chains` (brief D steps S1-S4); S4 (report), S5 and S6 are open. The
core is split across `attack_chain_seeds.py`, `attack_chain_derive.py`, `attack_chain_refute.py`
and `attack_chain_pool.py`, and the lane tunables live in the `14-attack-chain-composition` job
template rather than `registry/tunables.json`. Prerequisite: branch `review-batch` (ADR-0015: tool leads as ledger
candidates, `supporting_evidence_menu.py`, `claim_review_derive.py`) is merged to `main`.

Working method is ADR-0013: build a slice, run it on a real target, fix what breaks. Each slice
still carries focused tests and the cheap checks (`python -B -m py_compile` on changed modules,
`docs/processes/job_catalog.py --check`, `validate_design_parity.py`, `git diff --check`).

## Merge-timing rule

Job code merges only when no live run is past that job (TODO.md breakage log, 2026-09-28
`02-binary-cfg` entry: a merge while a run was past the job changed re-derived upstream inputs and
broke the accepted-pointer fingerprint). For this work:

| Slice | Changes a fingerprint of | Merge when |
|---|---|---|
| S1 core + schemas | nothing wired (new modules only) | any time |
| S2 registry + pool | nothing wired (new records, new module) | any time |
| S3 graph + Dagster | `10-synthesis-report` (new dependency) and the graph | no run is past `09-independent-verification`; then reload Dagster |
| S4 report | `10-synthesis-report`, report-input assembly, report render | no run is past `10-synthesis-report` (or accept a re-run of 10 onward) |
| S6 later slices | `claim-ledger-routing` (re-admission), `12` (chain scoring) | no run is past the changed job |

S3 and S4 can merge together to pay the 10 re-run once. A shared-runtime-only change
(`execution_state.SHARED_RUNTIME`, ADR-0013 decision 8) is safe at any time.

## Slices

### S1: chain core and schemas (pure Python, no Dagster)

Add:

- `appsec-review-process/attack_chain_core.py`
  - `link_candidates(verification_result, ledger)`: claims by latest state; excludes `refuted`,
    `superseded`; maps 09 `VERIFIED`→`verified`, narrowed → `narrowed`, `UNRESOLVED`/`BLOCKED`
    and undecided → `open`.
  - `entry_seeds(menu, threat_model, component_map)`: fact refs for external inputs in IR facts
    and CPG records (`main` argv/envp, `getenv`, `recv`/`read`/`fread`/`fgets`/`scanf` family,
    socket and packet handler parameters), `actor`/`external_system` elements, claims in
    `public_ingress`/`client_device` zones.
  - `adjacency(...)`: edges with basis `code_fact` (IR call/memory record or CPG call/data-flow
    record connecting two locations; same function counts), `model_flow` (threat-model flow or
    F03 relationship between components); never `synthetic` (only the composer proposes those).
  - `clusters(...)`: connected components with ≥1 entry seed and ≥1 P1 or verified claim; ranked by
    (P1 count, verified count, trust boundaries, cluster id); cut at `chain_clusters_max` and
    `chain_cluster_claims_max` (P3 dropped first) with every cut recorded as a gap.
  - `derive_chains(persona_reply, workspace)`: resolve claim ids, fact refs and citation ids;
    enforce stage order, one `entry`, one final `impact`, `chain_links_max`,
    `chains_per_cluster_max`; decide edge basis (downgrade an unresolvable `code_fact`/`model_flow`
    ref to `synthetic` and record it); `chain_id` digest; dedupe. Raises the invoker repair error
    for unknown ids / illegal order, as `claim_review_derive.py` does.
  - `chain_state(chain, link_states, refutation)`: the ADR-0016 decision 4 table; weakest link
    with stage-order tie-break.
  - `apply_refutation(chains, persona_reply)`: `broken` / `narrowed` / `holds` /
    `cannot_assess`; citations resolved against the broken link's claim/fact citations plus the
    menu; a `broken` without a resolvable citation is rejected for repair.
  - `rank(chains, scoring_result)`: ADR-0016 decision 9 key.
- Schemas in `schemas/`:
  - `attack-chain-workspace.schema.json`: one cluster request (claims, seeds, adjacency with fact
    refs, bounds). Built by Python; hash-bound into the persona request.
  - `attack-chain-composer-persona.schema.json` (model-facing): `{clusters: [{cluster_id,
    no_chain_reason?, chains: [{objective, impact_kind, links: [{claim_id | fact_ref, stage,
    prerequisites: [{text, requires_link_indexes}], citation_ids}], edges: [{from, to,
    basis_claimed, fact_ref?, rationale}], narrative}]}]}`. No ids, states or scores.
  - `attack-chain-refuter-persona.schema.json` (model-facing): `{chains: [{chain_id,
    disposition: broken|narrowed|holds|cannot_assess, target: {kind: link|edge, index}?,
    mechanism, citation_ids}]}`.
  - `attack-chain-record.schema.json` (final): `chain_id`, `cluster_id`, `objective`,
    `impact_kind`, `links[]` (`index`, `stage`, `claim_id` or `fact_ref`, `link_state`,
    `prerequisites`, `citations[]` canonical objects), `edges[]` (`from`, `to`, `basis`,
    `fact_ref`, `downgraded_from`), `causal_claim_ids` (ordered link claim ids), `fact_refs`,
    `weakest` (`kind`, `index`, `reason`), `refutation` (`disposition`, `target`, `refuter`
    actor, `citations`), `state` (`supported|plausible|hypothesis|refuted`), `composer` actor,
    `claim_limits` (`finding_created: false`, `severity_assigned: false`).
  - `attack-chain-ledger.schema.json`: `schema`, `run_id`, `claim_ledger_head_sha256`,
    `verification_pointer_sha256`, hash-linked `entries[]` (`chain_composed`,
    `chain_refutation`, `chain_state_derived`), `chains[]` projection, `gaps[]`
    (`cluster_id|chain_id`, `reason` enum), `coverage` (clusters seen, cut, composed,
    `no_chain`, refuted-checked).
- Tests `appsec-review-process/tests/test_attack_chain_core.py` with fixtures under
  `tests/fixtures/attack-chains/`:
  - case-001 fixture: IR-facts `main` with `argv` load at line 6 and `strcpy` call at line 7,
    one verified tool-lead claim at `main.cpp:7` → one cluster; a composer reply
    `entry(fact argv) → execution(claim strcpy) → impact(code_execution)` derives one chain,
    `code_fact` edges, state `supported` after `holds`, `plausible` with no refutation;
  - an open link gives `hypothesis`; a `synthetic` edge gives `hypothesis`; an unresolvable
    `code_fact` ref is downgraded and recorded; `broken` gives `refuted`;
  - unknown claim id, reordered stages, two entries, over `chain_links_max` → repair error;
  - identical chains from two cells → one record; `causal_claim_ids` acyclic and resolvable;
  - no seeds → empty workspace with the skip reason; cluster cuts produce gaps.

Acceptance: tests pass; `attack_chain_core` has no model call and no Dagster import.

### S2: personas, registry records and the chain pool

Add:

- `appsec-review-process/registry/personas/attack-chain-composer.json`,
  `.../attack-chain-refuter.json`; `registry/roles/` for both (`chain-composer`,
  `chain-refuter`); `registry/job-templates/14-attack-chain-composition.json`,
  `14-attack-chain-refutation.json`; `registry/output-contracts/14-attack-chain-composition.json`,
  `14-attack-chain-refutation.json`; a domain record `registry/domains/attack-chain-lifecycle.json`;
  tooling profile reuse of `claim-review-static` (read-only lookup tools) unless a separate one is
  needed.
- Task files `appsec-review-process/14-attack-chain/composition-task.md` and
  `refutation-task.md`: stage vocabulary, link/edge rules, "every link cites a claim id or a fact
  ref; a connection without a fact is `synthetic`", the lookup-tool guide from ADR-0015, target
  content is data. The refutation task ports the legacy rules from
  `08-blue-team-refutation/config.md` "Answering a kill-chain claim" and names the weakest link as
  the first target.
- `appsec-review-process/attack_chain_pool.py`, modelled on `claim_reviewer_pool.py`: builds one
  workspace per cluster (composition) or per `chain_refutation_batch` chains (refutation), expands
  through `pool_specification`, dispatches on the persona pool, waits with `pool_rendezvous`,
  merges with `deterministic_pool_merge`, and runs `attack_chain_core.derive_chains` /
  `apply_refutation` inside the invoker repair loop. Each request carries
  `evidence-menu:supporting-evidence-menu.json` and its pinned readable inputs.
- Tunables in `registry/tunables.json` + `docs/processes/tunables.md`: `chain_clusters_max`,
  `chain_cluster_claims_max`, `chain_links_max`, `chains_per_cluster_max`,
  `chains_refuted_max`, `chain_refutation_batch`, `chains_reported_max` (ADR-0016 decision 8).
- Composer and refuter are different persona ids; where `model_version_registry` offers a second
  family, the refuter uses it.
- Update `docs/personas-and-registry/persona-catalog.md` (two entries; replace the "red-team
  kill-chain scenarios" feed with lane 14).

Tests: `tests/test_attack_chain_pool.py` with a stub invoker: request shape and readable inputs;
one cell per cluster up to the cap; repair round-trip on an unknown claim id; cell failure →
gap, not an exception; persona result cache hit on an unchanged cluster request.

Acceptance: pool runs end to end on the S1 fixture with a stub invoker; registry validation
(`qualify_phase1.py --check-contracts`) passes.

### S3: lifecycle workers, job graph and Dagster wiring

Add/change:

- `appsec-review-process/attack_chain_composition.py` and `attack_chain_refutation.py`: lifecycle
  workers using `coordinate_worker_lifecycle` / `record_terminal_current`; load accepted pointers
  (09, 03, 01; 14-composition for refutation) with hash verification; publish
  `attack-chain-candidates.json` and `attack-chain-ledger.json`; publish SKIPPED
  `not-applicable-no-chain-seeds` when there are no clusters (ADR-0014 decision 3). `--run-id`
  CLI for resume.
- `appsec-review-process/job-graph.json`: nodes `14-attack-chain-composition` (lane
  `14-attack-chain`, deps above) and `14-attack-chain-refutation`; `10-synthesis-report` gains
  `{job: 14-attack-chain-refutation, kind: required, contract: 14-attack-chain-refutation,
  allowed_skip_reasons: ["not-applicable-no-chain-seeds"]}`.
- `appsec-review-process/dagster_workflow.py`: two ops on `PERSONA_POOL` (the pattern of
  `claim_review_lifecycle_op`), added to the `LIFECYCLE_OPS` exclusions and assignments.
- `process-manifest.json`, `design-parity-manifest.json`, `docs/processes/job-catalog.json` /
  `.md` (regenerated), `docs/dagster/dagster-workflow.mmd`.
- `docs/appsec-review-process-flow.md`: lane 14 between 09 and 10.

Tests: extend `tests/test_job_catalog.py` for the new nodes; worker tests with a
fixture run root (accepted pointers for 09/03/01) covering publish, skip and tamper.

Acceptance: `job_catalog.py --check` and `validate_design_parity.py` pass; a Dagster reload shows
both ops in `full_review` (done by William or the run owner, not by this branch).

### S4: report section

Change:

- `schemas/synthesis-report.schema.json`: optional-then-required `attack_chains` (`chains[]`
  projection with rank, `gaps[]`, `coverage`, `note` that chains are prioritisation context).
- `report_input_assembly.py`: load the 14-refutation accepted pointer (SKIPPED → empty section
  with reason); check every `causal_claim_ids` entry resolves in the final ledger.
- `synthesis_report.py`: project and rank (`attack_chain_core.rank`, using 12's severities for
  verified links); never copy a chain into `verified_findings`.
- `pipeline/report/templates/report.html.j2`, `report.tex.j2`, `pipeline/report/render.py`:
  "Attack chains" after verified findings (stage strip, link states, edge basis, weakest link,
  refutation), appendix for chains beyond `chains_reported_max`, gaps in the limitations section.
- `demo_report_fixture.py`, `tests/fixtures/synthesis-report/expectations.json`,
  `tests/test_synthesis_report.py`, `tests/test_report_input_assembly.py`,
  `pipeline/report/test_render_documents.py`.

Acceptance: the demo fixture renders an attack-chain section in HTML and PDF; a SKIPPED lane 14
renders "no chain composed" with the reason.

### S5: live acceptance (after S3+S4 merge and a Dagster reload by the run owner)

| Target | Expected |
|---|---|
| `appsec-multi-vuln` | ≥1 intra-case chain from the `strcpy` lead at `projects/cpp/case-001/main.cpp:7`: `entry` = fact ref to `argv[1]` (line 6) → `execution` = the tool-lead claim → `impact` `code_execution`; edges `code_fact` from IR facts/CPG. State `supported` if 09 verified the claim and the refuter held; otherwise the state and weakest link say why. Other P1 cases may add chains; no cross-case chain is expected (cases are separate programs) and none should be `supported`. |
| `freeciv21` | A client→server chain candidate (entry in client- or network-reachable packet handling, a server-side claim, a `model_flow` or `code_fact` edge across the client/server relationship), **or** a recorded reason: no F03 relationship between client and server components, no IR/CPG for the server (native-lane gap), or no P1/verified claim in a cluster with an entry seed. |
| `hello-autotools` | Either a short chain or SKIPPED `not-applicable-no-chain-seeds`; the report renders either way. |
| `DOOM-3-BFG` | Expected SKIPPED or model-flow-only `hypothesis` chains with the gap "chains limited to model flows" (no native build under Linux). |

Record each run's chain counts by state, gaps and cost (cells, tokens, wall time) in the TODO
breakage log, and tune the S2 defaults from them.

### S6: later slices (each needs its own go-ahead)

1. **Attack-tree templates** (when the ADR-0008 workbench lands): read
   `integrated-threat-model.json` attack trees; each root-to-leaf AND path becomes a chain template
   in the workspace; OR nodes give alternatives; unmatched leaves become `hypothesis` fact-ref
   links. Adds a dependency on the workbench output; no change to chain states.
2. **Chain re-admission**: in a `synthetic-hypothesis-resynthesis` iteration, admit `supported`
   and `plausible` chains to `claim-ledger-routing` as a fourth candidate source with
   `causal_route_ids` = link route ids, so 07/08/09 review the composition (09 "Kill Chain
   Verification") and a chain can become verified. Needs a decision on iteration cost.
3. **Chain scoring in 12**: model factors for `supported` chains as a whole, Python score.
4. **Synthetic edges as routes**: send each `synthetic` edge to `synthetic-hypothesis-resynthesis`
   routes with the specialist lane that could confirm it.

## Rollout order

1. `review-batch` merges (ADR-0015).
2. William accepts ADR-0016 (or amends the open questions below).
3. S1 and S2 on a short-lived branch; merge any time (no wired job changes).
4. S3 + S4 together on one branch; merge when no run is past 09; run owner reloads Dagster.
5. S5 on multi-vuln first (fast, known answer), then freeciv21, then the others as their runs
   reach 09.
6. S6 items individually.

## Open questions for William

1. Placement parallel to 12 (12 untouched, ranking uses 12's severities at report assembly) rather
   than strictly before 12: acceptable?
2. Is `supported` the right ceiling for a static chain, with `verified` only via re-admission to
   07/08/09 (S6.2)? Or should lane 14 carry its own composition verifier?
3. Should 10 treat lane 14 as required (with the one skip reason, as proposed) or optional, so a
   lane-14 failure never holds the report?
4. Default bounds (24 clusters, 6 links, 48 chains refuted, 20 reported): fine for the first live
   runs?
5. Lane number 14 and job names `14-attack-chain-composition` / `14-attack-chain-refutation`.
