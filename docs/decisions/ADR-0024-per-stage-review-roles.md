# ADR-0024: Per-stage registry roles for the claim review pool (role variants)

Status: **Proposed** (2026-09-29, brief J, branch `personas-folder`; awaiting William). No live run yet.

## Context

ADR-0021 gave every 07/08/09/12 reviewer instance its own persona, but every instance still ran under
the generic `claim-reviewer` registry role. The stage role (`red-team-adversary`, `blue-team-refuter`,
`independent-verifier`) existed only in the trusted runtime block and the decision actor, and stage 12
had none. The role is what bounds the claim ceiling, so a 07 reviewer was allowed `refutation` and
`verification_observation` as well as `candidate_only`; only the stage lifecycle rejected them later.
ADR-0021 noted that separate registry roles per stage "would need role variants as well".

## Decision

1. **Four registry roles**, one per stage: `red-team-adversary` (07), `blue-team-refuter` (08),
   `independent-verifier` (09), `scorer` (12). Each is `claim-reviewer` narrowed to the stage's pool
   claim class (`claim_review_lifecycle.POOL_CLASSES`) plus the stage rule the runtime block already
   gives, and "decide claims outside its own shard" in `must_not`.
2. **A job template may declare role variants.** `role_variants` works exactly like ADR-0021's
   `persona_variants`: `persona_invocation.load_composition` accepts a listed role (and only a listed
   one), the role record is loaded, schema-checked and hash-pinned like any other, and the claim ceiling
   is derived from the role the instance actually runs as. The registry survey loads every listed role
   and checks that the composition with it is invocable. `persona_prompt_assembly.assemble_outer_prompt(...,
   role_id=)` renders the role section for that variant into its own pinned cache file.
3. **`claim-review-pool-cell.stage_roles`** names the role per stage (all four must be named);
   `claim_reviewer_pool` builds every instance's request with it. The template's composed role stays
   `claim-reviewer`, as its composed persona stays `claim-reviewer`.
4. **Unchanged:** a failed reviewer shard still fails the stage (no partial publication, ADR-0021 §6);
   the runtime block's `reviewer_role` and the decision actor's `role_id` are as before (12 has no
   decision actor role).

## Consequences

- A pool reviewer's prompt differs from before only in its Role section; its request's
  `allowed_claim_classes` is the single stage class. The `deterministic-pool-merge` code fingerprint for
  07/08/09/12 changes (template and role files); each stage re-runs once.
- The code-reading hypothesis hunters (`hypothesis-hunt-general`, `hypothesis-hunt-known-list`) already
  run as their own role, `vulnerability-hypothesis-hunter`; no `hypothesis-hunter` role was added and
  their prompts did not change.

## Open questions for William

- Should the 12 runtime block and decision actor also carry `scorer`?
- Should `vulnerability-hypothesis-hunter` be renamed `hypothesis-hunter` (changes the hunter prompts)?
