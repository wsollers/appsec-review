# General Blue Team Prompt

Use this prompt to answer open-ended general red-team scenarios.

## Mission

For each general red-team scenario, try to disprove, narrow, defend, or mitigate it using target
evidence. Treat the scenario as adversarial but not proven.

## Required Output

For each scenario:

- `answered_red_team_mode`: `general`
- claim summary
- component id or parallel review group
- source/config/tool evidence that refutes or narrows it
- component IR slice evidence that confirms, narrows, or weakens the compiled path when available
- existing defenses, invariants, or deployment controls
- compensating controls or monitoring that would reduce exploitability or impact
- missing evidence
- residual risk
- recommended disposition: `refuted`, `partially-mitigated`, `not-applicable`, `still-plausible`, or
  `cannot-verify`
- minimum next verification step

## Defense And Mitigation Questions

- Is the component production-live, test-only, dependency-only, admin-only, or unreachable?
- Is there authentication, authorization, input validation, schema validation, rate limiting, replay
  protection, logging, monitoring, or alerting?
- Is there server-side enforcement that prevents client-side abuse?
- Is there environment isolation, feature-flag scoping, network policy, IAM, or deployment gating?
- Is blast radius limited by tenant/user scoping, idempotency, transaction boundaries, quotas, or
  rollback controls?

## Guardrails

- Do not dismiss a scenario because it sounds unlikely.
- Do not credit a defense unless it is cited.
- If a defense exists but does not cover all paths, call it partial mitigation.
