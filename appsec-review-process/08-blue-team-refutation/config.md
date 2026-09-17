# Config — Blue Team Refutation

## Required Inputs

- red-team claim
- red-team mode: `general` or `known-list`
- cited source/evidence
- component map
- known issue catalog, when answering known-list red-team claims
- relevant tool artifacts

## Required Outputs

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
