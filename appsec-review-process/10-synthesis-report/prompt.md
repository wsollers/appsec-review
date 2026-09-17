# Prompt — Cross-Lane Synthesis And Report

Synthesize only verified facts, explicitly unresolved risks, and cited coverage gaps. Do not promote
unverified hypotheses to findings.

Produce:

- merged findings
- severity, confidence, and priority rank (consumed from `12-scoring-prioritization`'s output — do
  not re-derive CVSS vectors or ranking here; if that lane's output is missing, report it as a
  limitation instead of scoring ad hoc)
- affected components
- evidence references
- remediation guidance
- limitations
- go/no-go recommendation tied to the user's stated decision

Preserve dissent: if red-team and blue-team disagree, state the unresolved dependency.

