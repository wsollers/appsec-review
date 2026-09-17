# Config — Blue Team Refutation

This lane pairs with `07-red-team-adversarial`. As of 2026-09-17, `07` tags every claim with a
design lane (`L4` AppSec discovery or `L5` vendor/insider malfeasance) in addition to its
general/known-list mode; carry that tag through refutation so downstream synthesis can report
disposition separately per design lane.

## Required Inputs

- red-team claim
- red-team design lane: `L4` or `L5`
- red-team mode: `general` or `known-list`
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

## Blue-Team Modes

- `refutation`: attempt to disprove or narrow the claim using source, config, deployment scope,
  invariants, and deterministic tool evidence.
- `defense-mitigation`: assume the claim may be real and identify existing defenses, compensating
  controls, detection, monitoring, blast-radius reducers, and remediation options.
- `known-list-response`: respond to catalog-driven hypotheses by mapping each known issue class to
  evidence, coverage, controls, and minimum verification steps.
