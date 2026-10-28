# Near-terminal inference review migration accounting

This is design/migration accounting, not a runtime registry. It records how narrowly reviewed
archived concepts map to
[`job_inference_security_review`](../architecture/inference-security-review.md). Nothing under
`old/` is restored or executed. "Slice 1 implemented" means the replacement runs in the registered
job and is exercised by `tests/review/` and the Dagster acceptance in
`tests/orchestration/dagster/test_inference_security_review.py` with an injected deterministic
`Infer` double; no live-model acceptance has run.

| Archived source/concept | Disposition | Destination | Verification state |
|---|---|---|---|
| `07-hypothesis-discovery`, `07-red-team-adversarial` | replace | scope/package assembly, `hypothesis_hunter`, `red_team_analyst`, package-local normalization, lane B triage gate | slice 1 implemented; deterministic-double acceptance only |
| `08-blue-team-refutation` | replace | claim-level `blue_control` and `blue_reachability` cells that never see each other | slice 1 implemented; deterministic-double acceptance only |
| `09-independent-verification` | replace | blind verifier cells (request bytes checked under R6) plus deterministic R5 adjudication | slice 1 implemented; deterministic-double acceptance only |
| claim reviewer pools | merge | bounded in-unit cells keyed by `cell/v1` fingerprints behind visible Dagster units (design R1) | slice 1 implemented |
| deterministic pool merge | port concept | `merge.claims` over reverified ledger shards; a merge that depends on shard order blocks publication | slice 1 implemented |
| evidence-qualified quorum | replace | predicate/evidence/independence policy; no producer voting | slice 1 implemented (R4/R5/R6) |
| `12-scoring-prioritization` and CVSS v4 calculation | replace/port | versioned `ScoringProvider` registry; `application_risk_matrix/1` only, with labelled NVD CVSS/KEV/EPSS reference inputs and the KEV one-band confidence rule | slice 1 implemented for `application_risk_matrix/1` (reference inputs unit-tested; no acceptance claim reaches scoring with them); CVSS v4 not started |
| CWE reference and advisory intelligence (no archived equivalent) | new | pinned MITRE CWE catalog for claim CWE validation and `weaknesses` blocks; `dependency_advisories/2` joins to pinned NVD (`index/nvd.sqlite`), CISA KEV and FIRST EPSS; lane A KEV admission; lane B KEV/EPSS rank signals | implemented; unit tests plus Dagster acceptance over offline fixture feeds published by the real sync code; live feed downloads unverified |
| `12b-poc-and-fix` | replace | eligibility, typed policy, benign plan, isolated execution, independent verification, regression conversion | design only; execution disabled by default |
| attack-chain composition/refutation | replace/port | single-ledger chain objects, five continuity dimensions, independent refutation, separate chain score | design only |
| completeness audit/feedback, synthetic resynthesis, dynamic rescope | merge | `completeness.audit` exact accounting and the lane B coverage matrix (round 0); delta-driven rounds later | slice 1 accounting implemented; rounds design only |
| persona/role prompt composition | replace/port | one role plus one routed persona and stack profile, immutable bundle hashes pinned per run, conflict validation | slice 1 implemented |
| pool rendezvous | replace | Dagster pools over visible units, the review-team semaphore, application-owned terminal receipts and serialized publication | slice 1 implemented |
| archived claim/chain/PoC/scoring schemas | replace | closed schemas under `docs/schemas/inference-security-review/` | claim, ledger, cell, gap, result, adjudication, score, finding and handoff schemas in use; PoC and chain schemas absent |

## Required implementation work

1. Done for slice 1: the claim-ledger and Dagster vertical slice, with both lanes, review teams,
   failure-as-gap, exact accounting, one scorer, and serialized publication.
2. Done for slice 1: capability-scoped in-process retrieval and evaluator-root/target-guidance
   isolation. MCP is still not exposed to workers.
3. Add CVSS v4 conformance after `application_risk_matrix/1` (slice 2).
4. Add PoC eligibility and plan-only denial before any isolated executor.
5. Add attack-chain continuity and independent refutation.
6. Add bounded resynthesis rounds and variant hunts, then additional providers, personas and PoC
   strategies only after acceptance.

## Explicit gaps

- Only round 0 runs. Evidence requests are recorded and closed `unsatisfied`; no resolution round,
  variant hunt, `entry_down`, or `control_gap` strategy exists, and `sink_up` needs an accepted
  `symbol_links` query set.
- Claim CWEs validate against the run-pinned MITRE CWE catalog. When it is unpinned, mismatched or
  stale, validation falls back to the CWE ids named by accepted lead rules and the security-tagging
  crosswalk, and a `reference:mitre_cwe` coverage gap is recorded. Live CISA KEV, FIRST EPSS, NVD
  and MITRE downloads, and their current file formats, have not been exercised; tests use offline
  fixture files.
- Acceptance uses a scripted deterministic `Infer` double. Live-model acceptance, budgets and schema
  repair against a real provider, and a live Dagster/container deployment remain open.
- Downstream remediation and final-publication consumers do not exist; the job publishes its own
  accepted handoff only.
- OWASP now has complete pinned catalogs and offline full-catalog publications delivered through
  real projection, lead/hunt packages and scripted red/blue/verifier requests. This supersedes the
  abridged-catalog gap, not the live-model efficacy gate. Only four narrow Python static procedures
  are implemented; unsupported controls/languages and runtime adapters remain unresolved. Results
  are provisional context, indirect for every final predicate. See
  [the current workbench design](../architecture/owasp-control-workbench.md). Joern/CPG remains a
  separate upstream gap, not OWASP acceptance.
- Organization ship-blocking policy, PoC authorization workflow, evidence freshness windows, and
  final downstream job names require owner decisions.

Superseded in part (2026-10-15): the owner decisions above were recorded on 2026-10-12 and
`ship-block-policy/1`, verifier model distinctness, remediation intake, the planned downstream job
names, the closed `security-predicates/1` vocabulary and the `red-discovery-result/1` contract are
implemented (`src/appsec_review/review/ship_block.py`, `independence.py`, `models.py`,
`red_discovery.py`); see "Decisions and open questions" in
[`../architecture/inference-security-review.md`](../architecture/inference-security-review.md#decisions-and-open-questions).
PoC authorization (decision 3) remains open and no PoC execution path exists.
