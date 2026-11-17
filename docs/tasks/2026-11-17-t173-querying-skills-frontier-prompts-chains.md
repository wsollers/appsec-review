---
title: "Task plan T-173: Publish common querying skills rebalance frontier prompts and widen attack chains"
kind: "task"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_inference_security_review", "job_owasp_control_assessment", "job_poc_generation", "job_remediation_planning", "job_remediation_validation", "job_review_package_assembly"]
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
---
# Task plan T-173: Publish common querying skills rebalance frontier prompts and widen attack chains

This plan implements **T-173** (`docs/TODO.md`, addressing `T-5079`): publishing the canonical
hosted querying and indexing skills architecture, registering the runtime worker skill
`evidence-and-graph-querying`, applying frontier-model prompting best practices across all nine
LLM-enabled jobs, fulfilling Round 2 `requests_evidence` automatically from `RetrievalCore`,
sizing model output token budgets for thinking-capable models, and widening cross-service attack
chaining.

## Problem and motivation

- Our prompt and role audit across all 9 LLM-enabled jobs found five systemic bottlenecks:
  1. **No unified multi-shard querying playbook:** Review, OWASP, PoC, and remediation workers
     lacked a shared hash-pinned runtime skill teaching optimal multi-hop traversal across the
     alternate Tree-sitter + CodeQL CPG/CFG and newly indexed domain shards.
  2. **Asymmetric refutation bias in `blue` and `independent_verifier`:** Defensive prompts rewarded
     speculative caller assumptions as refutations instead of requiring exact source-line proof of
     a dominating barrier (`governing-rules.md`).
  3. **Unfulfilled Round 2 `requests_evidence`:** Round 1 cells emitted structured
     `requests_evidence` items that were not automatically resolved against `RetrievalCore` before
     Round 2 convergence.
  4. **Thinking-token starvation (`T-5079`):** Tight `max_output_tokens` caps (6,000–8,000 on OWASP,
     PoC, and remediation validation) counted internal reasoning tokens against output caps,
     causing `model_token_cap` truncations before structured JSON closed.
  5. **Over-narrow attack-chain assembly:** `attack_chain_analyst` restricted chains to
     `critical`/`high` findings inside a single unit (`max_steps = 4`), missing classic
     `medium` + `medium` -> `critical` chains across adjacent components.

## Technical design and dataflow changes

1. **Register runtime skill `evidence-and-graph-querying` (`pipeline/skills/` &
   `pipeline/guidance/registry.json`):**
   - Author `pipeline/skills/evidence-and-graph-querying/SKILL.md` with
     `metadata.audience: runtime-worker` and register allowed jobs in `pipeline/guidance/registry.json`
     (`job_inference_security_review`, `job_owasp_control_assessment`, `job_poc_generation`,
     `job_remediation_planning`, `job_remediation_validation`), loaded strictly via
     `load_runtime_skill`.
2. **Frontier-model prompt rebalancing (`pipeline/prompt-fragments/`):**
   - Structure `red`, `hunter`, `blue`, `independent_verifier`, `judge`, and `attack_chain_analyst`
     fragments around explicit hypothesis testing:
     - **Affirmation standard:** exact `source_id:line` attacker entry/source, propagation path
       (semantic CPG or source-verified syntactic edge), sink trigger condition, and impact.
     - **Refutation standard:** a refutation is valid **only** when citing an exact dominating
       barrier/sanitizer/type-bound at `source_id:line` (`guard_fact` or verified `read_excerpt`);
       unverified upstream validation is `uncertain` + `requests_evidence`, never `refuted`.
   - Right-size `max_output_tokens` in `appsec-review.toml` (minimum `16384`–`32768` for
     thinking-capable OWASP, PoC, and remediation validation roles; `49152`–`64000` for complex
     multi-lead hunt/review cells) with unit tests verifying headroom above thinking budgets.
3. **Automated inter-round `requests_evidence` fulfillment & wider attack chains:**
   - Between Round 1 and Round 2 in `job_inference_security_review`, resolve structured
     `requests_evidence` symbol/caller/guard requests via `RetrievalCore` within package scope
     bounds and attach labelled receipts to the Round 2 turn input.
   - Allow `attack_chain_analyst` to chain corroborated `medium`+`medium` findings across trust-zone
     adjacent units up to `max_steps = 6` when post-condition capabilities match pre-conditions.

## Schema and telemetry specification

```text
New / updated versioned schemas:
- appsec-review/evidence-fulfillment-receipt/1 (round_1_request_id, tool_executed, resolved_rows[])
- appsec-review/attack-chain/2                 (supports cross_unit_links[], max_steps=6, medium_primitives)

Telemetry & metrics recorded per attempt:
- review.round1_evidence_requests_total, review.round1_evidence_requests_fulfilled,
  review.token_cap_truncations_by_role, review.verifier_refutations_with_proven_barrier,
  review.attack_chains_cross_unit_count, guidance.pinned_skill_hashes
```

## Seven-point acceptance criteria

1. **Documentation & dataflow updates:** Publish [`../architecture/querying-and-indexing-skills.md`](../architecture/querying-and-indexing-skills.md),
   update [`../architecture/guidance-procedures.md`](../architecture/guidance-procedures.md),
   [`../architecture/review-inference-and-guidance.md`](../architecture/review-inference-and-guidance.md),
   [`../operations/inference-security-review.md`](../operations/inference-security-review.md),
   `docs/docs-ledger.json`, and run `scripts/generate-docs.py`.
2. **Full indexing for downstream inference:** Ensure `evidence-and-graph-querying` and inter-round
   fulfillment query all indexed shards (`syntax`, `code_graph`, `observations`, `debug_symbols`,
   `build_security`, `hotspots`, `precomputed`) deterministically.
3. **Fast, isolated unit tests (`<10s`):** Exercise `compose_bundle`, `verify_bundle`,
   `render_prompt`, `pin_bundle`, `tests/test_skill_separation.py`, Round 2 fulfillment, output
   token-cap sizing, and cross-unit medium-to-critical attack chaining in `<10s` per test with
   canned responses (zero live LLM calls).
4. **Common querying & indexing skills doc alignment:** Keep `evidence-and-graph-querying/SKILL.md`
   and [`../architecture/querying-and-indexing-skills.md`](../architecture/querying-and-indexing-skills.md)
   in strict 1-to-1 tool and dataset parity.
5. **Frontier prompting, roles & skills alignment:** Verify `numeric-reasoning-guardrail/1`
   preservation, zero authority widening, closed output schemas, and explicit barrier-citation
   requirements across all updated roles.
6. **Metrics & telemetry:** Track `model_token_cap` occurrences, Round 2 evidence fulfillment hit
   rates, and cross-unit attack-chain synthesis counts.
7. **Proper schema versioning:** Validate `evidence-fulfillment-receipt` v1 and `attack-chain` v2
   at publication while maintaining v1 replay readers.
