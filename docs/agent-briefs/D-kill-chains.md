# Brief D: attack-chain composition, lane 14 (branch `kill-chains`) - CLOUD agent

Goal: implement steps S1-S4 of `docs/proposals/attack-chains/implementation-plan.md` per `docs/decisions/ADR-0016-attack-chain-composition.md`. READ BOTH FULLY FIRST, then `docs/decisions/ADR-0013*`, `ADR-0018*` (hunters), `ADR-0021*` (sharded reviewers) and `appsec-review-process/claim_ledger.py`, `claim_review_*`, `hypothesis_hunt_derive*` as the closest existing patterns.

## Decisions (William accepted the recommended defaults; the five ADR-0016 questions are answered as follows)
- Lane 14 runs parallel to lane 12 (after 09 verification), not inside it.
- Ceiling: chains are `supported` at most (never `verified`); a chain is only as strong as its weakest link.
- Lane 14 is OPTIONAL input to `10-synthesis-report` (report renders a "Chains" section only when lane 14 published; absence is a recorded gap, not a failure).
- Bounds: max 24 chain candidates seeded, 6 chains composed per composer instance, 48 total links, 20 published chains. Names: jobs `14-attack-chain-composition` and `14-attack-chain-refutation`.
- Shape follows the ADR: Python seeds candidates from verified findings + graph adjacency (shared component, data flow, trust boundary, same reachability witness); a composer persona pool proposes chains using ONLY seeded findings; a refuter pool tries to break each chain; Python derives ids, links, CWE/CVSS carry-over and the final status. The model never invents a finding, file, line or hash: every link cites an existing verified finding id.

## Steps (commit per step)
S1 Seeding (`attack_chain_seeds.py` + schema + tests). S2 Composer persona + schema + `attack_chain_derive.py` (ADR-0013: mechanical fields derived). S3 Refutation persona/pool + merge rules (weakest-link ceiling, refuted chains dropped with a recorded reason). S4 Job wiring: job-graph node(s), registry job templates, output contracts, design-parity manifest rows, Dagster op(s) in `dagster_workflow.py`/`definitions.py` following how `07-hypothesis-discovery` was wired, `full_review` dependency edges, optional edge into `10-synthesis-report`. Regenerate catalogs (`docs/processes/job_catalog.py`, `validate_design_parity.py --write-generated-views`).
S5/S6 (report rendering, live qualification) are OUT of scope unless S1-S4 are done and tested; then do S5 (report section) behind the optional edge.

## Rules
- Follow `docs/agent-briefs/00-common.md` (branch `kill-chains`; clone from GitHub; you MAY push `origin kill-chains`, never `main`).
- You own: new `attack_chain_*.py`, their schemas/tests, registry/job-graph/parity entries for lane 14, and the ADR status line (mark implemented parts). Do not edit `claim_ledger.py`, `claim_review_*`, `review_cli.py`, `component_characterization.py`, `owasp_*`, `osv_*`, `native_*`.
- No live model calls in tests: use recorded/fake persona results like the hunter tests do.
- Safety: chains are descriptions of how verified weaknesses combine; do NOT generate exploit code or payloads (a separate, later lane produces the static PoC). Narrative fields are capped and must cite finding ids.
- Report back per 00-common.md item 12; list every design choice not fixed by the ADR.
