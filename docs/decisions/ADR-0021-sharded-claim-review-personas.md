# ADR-0021: Claim review is sharded across persona-distinct reviewer instances

Status: **Proposed** (2026-09-28; awaiting William). Implementation: merged to `main` from `ws-personas`
(`195683f`, 2026-09-28); no live run yet.

## Context

The 07/08/09/12 reviewer pool (`claim_reviewer_pool.py`) launched exactly one model call per stage,
always as the generic `claim-reviewer` persona, over the whole claim ledger (150 claims for
appsec-multi-vuln since ADR-0015). William: "The individual agents in red and blue teams were supposed
to have different personas; just about every model call that was looking for something is supposed
to have a persona and role." He decided the pool size is configurable (default 3, a job-config
tunable) and that the pool **shards only**: each claim is reviewed once per stage, not by every
instance. 48 of the 54 personas in `docs/personas-and-registry/persona-catalog.md` also had no
registry record, so no job could run as them.

## Decision

1. **Catalog personas are registry records.** `catalog_personas.py generate` writes a
   `registry/personas/<id>.json` for every catalog section without a hand-authored record, derived
   mechanically from the catalog text and marked `provenance.generated_by = catalog_personas.py`,
   `reviewed: false`. `check` (and `tests/test_claim_review_sharding.py`) fails when a catalog persona
   has no record or a generated record is stale. A hand-edited record drops `provenance` to take
   ownership; the generator then leaves it alone.
2. **A job template may declare persona variants.** `persona_variants` lists the registry personas an
   instance of that template may run as besides its composed persona. `persona_invocation.load_composition`
   accepts a listed variant (and only a listed one); the persona record is still loaded, schema-checked
   and hash-pinned like any other, and role, domain, tooling profile and output contract stay the
   template's own, so the claim ceiling is unchanged. `persona_prompt_assembly.assemble_outer_prompt(...,
   persona_id=)` renders the persona section for that variant into its own cached, pinned prompt.
3. **Stage reviewer pools come from the registry.** `claim-review-pool-cell.stage_personas` names an
   ordered persona list per stage, disjoint across stages: attackers for 07, defenders/refuters for
   08, independent verifiers for 09, scorers/risk owners for 12.
4. **Shard, don't replicate.** `claim_review_sharding.plan_shards` splits the stage's claims across
   `claim_review_pool_instances` (template tunable, default 3) instances: causally linked or superseding
   claims are atomic (the stage rules check those links inside one population); claims of the same cited
   file, else the same component set, stay together; oversized groups split at the balanced share; groups
   are assigned largest-first to the lightest shard; shards are numbered by their smallest claim id.
   If any shard's estimated input (claim JSON bytes / 4) exceeds `claim_review_shard_input_units_max`,
   more instances are planned (up to the pool limits) until each fits. Each instance reads only its
   shard file (root `stage-upstream`, `shard-NN.json`) and the shared supporting-evidence menu.
5. **Persona per shard, deterministically.** `assign_personas` gives each shard the unused stage persona
   whose record text best overlaps the shard's claim text (hypothesis, route, components, cited files,
   producers), ties broken by the stage list rotated per shard. Distinct within a stage until the list is
   exhausted. Python decides the bookkeeping; the model only judges.
6. **Merge and gaps.** Shard outputs merge through `deterministic_pool_merge` unchanged; the full
   population then goes through the stage lifecycle rules as before. `shard-coverage.json` records
   each shard's persona, claims and unreviewed claims. The stage contract requires one decision per
   claim (07's red-team case and citations cannot be synthesized honestly), so a failed instance cannot
   be published as a partial stage: the pool attempt fails with the unreviewed claim ids named, and the
   rerun re-asks only that shard because the persona result cache answers the unchanged shards.

## Consequences

- The `deterministic-pool-merge` job's code fingerprint for 07/08/09/12 changes (new module, template,
  persona records); each stage re-runs once. The stage lifecycle jobs' own fingerprints do not change.
- Up to `claim_review_pool_max_parallel` (default 3) model calls per stage run at once (was 1), still
  bounded by the Dagster `persona_llm` pool.
- Actor `role_id` in decisions stays the stage role (`red-team-adversary`, ...); the persona is recorded
  per worker in the merge (`producer_ids`) and in `shard-coverage.json`.

## Open questions for William

- Generated persona records are unreviewed prose conversions; which should be hand-owned first?
- Should a failed shard instead publish the stage with explicit `UNREVIEWED` decisions? That needs a new
  decision form in `claim-review-decision.schema.json` and the 08/09/12 upstream rules.
- Stage roles are still the generic `claim-reviewer` registry role plus the runtime stage role; separate
  registry roles per stage would need role variants as well.
