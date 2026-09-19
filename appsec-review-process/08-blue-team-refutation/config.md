# Config — Blue Team Refutation

This lane pairs with `07-red-team-adversarial`. As of 2026-09-17, `07` tags every claim with a
design lane (`L4` AppSec discovery or `L5` vendor/insider malfeasance) in addition to its
general/known-list mode; carry that tag through refutation so downstream synthesis can report
disposition separately per design lane.

## Required Inputs

- red-team claim
- red-team design lane: `L4` or `L5`
- red-team mode: `general`, `known-list`, or `kill-chain`
- cited source/evidence
- component map
- known issue catalog, when answering known-list red-team claims
- relevant tool artifacts

## Required Outputs

- design lane answered: `L4` or `L5` (carried through from the red-team claim)
- refutation or partial refutation
- defense and mitigation analysis
- missing evidence
- residual risk
- recommended disposition

## Answering a `kill-chain` claim (added 2026-09-18)

A kill-chain claim lists ordered steps. Refuting the overall narrative is not enough and refuting
one step is not automatically a full refutation either -- be explicit about scope:

- Address **each step** with its own disposition (refuted / not refuted / partially mitigated),
  citing evidence per step, the same as any other claim.
- State explicitly whether breaking one step breaks the whole chain (usually yes -- a chain with a
  refuted link is refuted overall) or whether the red team's chain has an alternate path around
  that step (rare, but call it out if evidence supports it rather than assuming the chain is dead).
- For a tainted-data chain, a refutation must show the taint is actually sanitized, validated, or
  blocked at a specific hop with cited evidence -- "the sink looks safe" is not a refutation if the
  path to reach it with attacker-controlled data was never addressed.
- Do not mark a kill-chain claim `NOT_APPLICABLE` just because one step looks like a design
  limitation (the way `L5-GEN-002`-style single-step claims can be); a design limitation at one
  step can still be a real, usable link in a chain if it is genuinely reachable with tainted data.

## Blue-Team Modes

- `refutation`: attempt to disprove or narrow the claim using source, config, deployment scope,
  invariants, and deterministic tool evidence.
- `defense-mitigation`: assume the claim may be real and identify existing defenses, compensating
  controls, detection, monitoring, blast-radius reducers, and remediation options.
- `known-list-response`: respond to catalog-driven hypotheses by mapping each known issue class to
  evidence, coverage, controls, and minimum verification steps.
