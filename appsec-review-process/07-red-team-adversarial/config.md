# Config — Red Team / Adversarial

## Required Inputs

- stated business goal
- component-purpose map
- component taxonomy / component cloud
- known issue catalog
- evidence package
- current findings
- known coverage gaps

## Required Outputs

- general adversarial scenarios from open-ended inference
- known-list adversarial scenarios from `known-issue-catalog.md`
- strongest exploitability arguments
- hostile-vendor placement hypotheses
- component-mapped known-issue hypotheses
- minimum checks required to defeat each scenario
- red-team mode used: `general`, `known-list`, or `combined`

## Red-Team Modes

- `general`: open-ended hostile review. Look for surprising ways issues could survive the pipeline,
  including design, trust-boundary, coverage, and process gaps not named in the known catalog.
- `known-list`: systematic catalog-driven review. Walk applicable entries from
  `known-issue-catalog.md` against the component cloud and produce evidence-backed hypotheses or
  negative evidence.
- `combined`: allowed only for small targets or synthesis. Keep general and known-list findings in
  separate sections so downstream blue teams can answer them independently.
