# ADR-0034: Per-shard claim review cycles (07 → 08 → 09)

Status: **Proposed** (2026-10-01; awaiting William).

## Context

Claim review runs as three stage-wide barriers. `07-red-team-adversarial`, `08-blue-team-refutation` and
`09-independent-verification` each:

1. load the whole accepted upstream population (`claim_review_lifecycle._load_upstream`);
2. re-plan shards from that stage's own input (`claim_reviewer_pool.plan`, `claim_review_pool_instances`,
   default 3);
3. dispatch one reviewer persona per shard and wait for all of them (`wait_all: true`);
4. publish only if every upstream claim has exactly one decision (`decisions_from_pool`). A single failed
   shard blocks the stage (`claim_reviewer_pool.py`, `unreviewed_claim_ids` → `Blocked`).

Consequences seen and expected:

- One slow or failed reviewer instance stalls 07, 08, 09, 12, 14 and the report.
- 08 cannot start on any claim until the slowest 07 shard finishes; 09 likewise waits on 08. Wall-clock time
  is the sum of three slowest-shard times, not the time of the slowest end-to-end shard.
- Shard boundaries can move between stages, because each stage re-plans from its own input.
- Cost and failure exposure grow with target size (TODO breakage log, 2026-09-28 claim-ledger-routing:
  "watch persona budget/cost on large targets").

The decisions themselves do not need the whole population. `claim_review_sharding._atomic_units` already
keeps claims linked by `causal_claim_ids` or `supersedes_claim_id` in one unit and groups claims by
component. Reviewer independence (`claim_lifecycle_core._independent`) and the stage rules apply per claim.
Only the stages after 09 work across claims: `12-scoring-prioritization`, `14-attack-chain-composition` and
`evidence-qualified-quorum`.

## Decision

1. **Plan shards once, at `claim-ledger-routing`.** The routing result carries a shard plan (shard id,
   claim ids, shard sha256) built by `claim_review_sharding` with the same atomic-unit and size rules.
   07, 08 and 09 use that plan and never re-plan. A shard keeps its id through all three stages.
2. **Run each shard as its own cycle `07 → 08 → 09`.** In Dagster the routing op emits one `DynamicOutput`
   per shard and the cycle is `.map()`ped over them; shards run in parallel up to
   `claim_review_pool_max_parallel` on the `persona_llm` pool. A shard's 08 starts as soon as its own 07
   is accepted.
3. **Per-shard accepted results.** Each cycle stage publishes under
   `data/jobs/<stage>/shards/<shard_id>/` with its own attempts, fingerprint and accepted pointer. The
   "every and only upstream claim" rule applies to the shard's claims. Per-stage persona pools, reviewer
   independence and roles (ADR-0021, ADR-0024) are unchanged.
4. **Deterministic stage join after 09.** A `.collect()` join publishes the stage-level
   `07-red-team-adversarial`, `08-blue-team-refutation` and `09-independent-verification` results, in the
   existing schemas, by merging accepted shard results in shard-plan order. The join checks the shards
   cover the population exactly once. 12, 14, quorum and the report read only the joined results, so their
   contracts do not change.
5. **A failed shard blocks the join, not its siblings.** Other shards finish and are accepted. The join
   names the failed shard, its stage and its claim ids. A rerun re-executes only that shard's cycle; accepted
   shards validate from their pointers. Publishing the join with explicit `UNREVIEWED` decisions for a
   failed shard stays a separate decision (TODO, Personas and reviewer pools).
6. **The shard plan is an input.** A change to the population or to the sharding tunables changes the plan
   and re-executes the affected shards only. Claims that did not move keep their accepted shard results.

## Consequences

- Wall-clock time for claim review falls toward the slowest single shard cycle, and the stages overlap.
- Failures, reruns and budget caps are per shard.
- Graph, registry, catalog and output-contract changes (new per-shard scope, the join, the shard plan in the
  routing contract) go through `validate_design_parity.py --check-generated-views` and
  `job_catalog.py --check`.
- Fingerprints for 07, 08, 09 and claim-ledger-routing move; accepted runs re-run claim review once.
- Shard results no longer see claims from other shards. That is already true today inside one stage's pool,
  so reviewer context does not shrink.
- `12-scoring-prioritization` stays a stage-wide barrier. It could join the cycle later, but scoring is
  compared across claims and benefits from one view.

## Not decided here

- Running several independent 07/08/09 passes over the same claims and requiring agreement. That is a
  quorum question for `evidence-qualified-quorum`, not a graph change, and it multiplies cost.
