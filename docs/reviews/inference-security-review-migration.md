# Near-terminal inference review migration accounting

This is design/migration accounting, not a runtime registry. It records how narrowly reviewed
archived concepts map to the proposed
[`job_inference_security_review`](../architecture/inference-security-review.md). Nothing under
`old/` is restored or executed.

| Archived source/concept | Disposition | Proposed destination | Verification state |
|---|---|---|---|
| `07-hypothesis-discovery`, `07-red-team-adversarial` | replace | scope/package assembly, `hypothesis_hunter`, `red_team_analyst`, normalized claim shards | design only |
| `08-blue-team-refutation` | replace | claim-level blind-safe blue falsification cells | design only |
| `09-independent-verification` | replace | blind verifier cells plus deterministic evidence-qualified adjudication | design only |
| claim reviewer pools | merge | Dagster dynamic cells keyed by claim × role × round × manifest | design only |
| deterministic pool merge | port concept | deterministic normalized merge over reverified cell receipts | design only |
| evidence-qualified quorum | replace | predicate/evidence/independence policy; no producer voting | design only |
| `12-scoring-prioritization` and CVSS v4 calculation | replace/port | versioned `ScoringProvider` registry; retain standard-vector provenance | design only |
| `12b-poc-and-fix` | replace | eligibility, typed policy, benign plan, isolated execution, independent verification, regression conversion | design only; execution disabled by default |
| attack-chain composition/refutation | replace/port | single-ledger chain objects, five continuity dimensions, independent refutation, separate chain score | design only |
| completeness audit/feedback, synthetic resynthesis, dynamic rescope | merge | delta-driven bounded rounds and dependency-based selective invalidation | design only |
| persona/role prompt composition | replace/port | one role plus zero/one persona, immutable bundle hashes, conflict validation | design only |
| pool rendezvous | replace | Dagster pools/dynamic mapping plus application-owned terminal receipts and serialized manifest publication | design only |
| archived claim/chain/PoC/scoring schemas | replace | closed schemas under `docs/schemas/inference-security-review/` | pending implementation |

## Required implementation work

1. Build the minimum claim-ledger and Dagster vertical slice described in the design.
2. Add capability-scoped accepted-manifest retrieval views and target-guide/evaluator-root isolation.
3. Add the scoring-provider interface and one application-risk provider, then CVSS v4 conformance.
4. Add PoC eligibility and plan-only denial before any isolated executor.
5. Add attack-chain continuity and independent refutation.
6. Add bounded resynthesis, additional providers/personas/PoC strategies only after acceptance.

## Explicit gaps

- Near-terminal inference-review worker skills and guidance bundles are absent from the rebuilt
  tree; the existing repository skills cover target planning, build-image repair, and post-build
  assessment only.
- The runtime job, schemas, guidance bundles, scorer plugins, PoC isolation runner, and downstream
  remediation/publication consumers do not yet exist.
- Live full-catalog OWASP/model validation, a pinned Joern/CPG closure, and live acceptance of the
  proposed inference-review Dagster/container graph remain upstream dependencies or gaps.
- Organization ship-blocking policy, PoC authorization workflow, evidence freshness windows, and
  final downstream job names require owner decisions.
