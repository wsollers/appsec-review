# Subprompts — Blue Team Refutation

## Mode Selection

Use `general-blue-team.md` for open-ended red-team scenarios. Use `known-list-blue-team.md` for
catalog-driven red-team hypotheses. If both are present, answer them in separate sections so generic
inference and known-list coverage do not blur together.

## Source Refutation

Search for bounds checks, auth checks, validation, feature flags, deployment exclusions, or dead-code
evidence that refutes the claim.

## Scope Refutation

Determine whether the affected component is production/live, sample/test, vendored, or unreachable.

## Residual Risk

If mitigated, state what remains uncertain and what evidence would close it.

## Defense And Mitigation

Even if a claim cannot be refuted, look for defenses that reduce exploitability or impact: server-side
checks, schema validation, rate limits, replay controls, audit logging, monitoring, deployment
segmentation, IAM/RBAC, feature gates, transaction boundaries, quotas, rollback controls, or release
signing.
