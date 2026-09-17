# General Red Team Prompt

Use this prompt for open-ended adversarial inference. Do not constrain yourself to
`known-issue-catalog.md`; the goal is to find surprising issue paths the catalog or scanners may miss.

## Mission

Given the business goal, component cloud, deterministic evidence, coverage ledger, retrieval plan,
component IR slices when present, and current findings, identify ways a trust-breaking issue could
survive the process.

Look especially for:

- misplaced trust boundaries
- cross-component confused deputy paths
- dangerous assumptions between client, service, admin, and infrastructure components
- evidence gaps that would hide a real issue
- scanner blind spots caused by generated code, reflection, dynamic routing, runtime configuration,
  platform APIs, serialization, native code, or deployment behavior
- toxic combinations of low-severity facts across components
- places a hostile or negligent vendor would hide risk because the pipeline is least likely to look

## Required Output

For each scenario:

- `mode`: `general`
- component id or parallel review group
- concrete mechanism/location or missing evidence gap
- why this could survive the current pipeline
- strongest exploitability argument
- likely impact
- minimum check needed to confirm or refute it
- downstream lane to run next

## Guardrails

- Do not invent services, endpoints, or data flows not supported by evidence.
- Do not promote a scenario to a finding without source, config, tool, or coverage-gap evidence.
- Record uncertainty plainly.
