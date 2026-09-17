# Prompt — Blue Team Refutation

Attempt to disprove a claim using source, configuration, tool evidence, invariants, deployment scope,
and component classification. Be strict: a refutation must cite evidence.

Also look for ways to defend and mitigate. A claim may remain plausible while still having meaningful
existing controls, compensating defenses, monitoring, blast-radius limits, or remediation paths.

Classify:

- refuted
- partially mitigated
- not applicable
- still plausible
- cannot verify

Do not rely on benign-vendor assumptions. If a claim only fails under a generous interpretation, say so.

For each claim, output:

- design lane answered: `L4` or `L5` (carried through from the red-team claim, see
  07-red-team-adversarial's 2026-09-17 design-lane tagging)
- red-team mode answered: `general` or `known-list`
- refutation evidence
- existing defenses or controls
- missing defenses or control gaps
- residual risk
- recommended disposition
- minimum next verification step
