# Config — Scoring And Prioritization (L8)

Added 2026-09-17: extracts scoring/prioritization out of `10-synthesis-report` into its own step,
ahead of synthesis, per design-v3.md L8. This was judged cheap once the CVSS 4.0 deterministic-
derivation mapping existed (design-v3.md §14, folded in 2026-09-17) — this lane is the mapping's
first consumer, not a new scoring methodology.

Runs after `09-independent-verification` (and `11-remediation-proposal`, when run) and before
`10-synthesis-report`: synthesis should consume this lane's scores rather than deriving them itself.

## Required Inputs

- verified findings (from `09-independent-verification`)
- the CVSS 4.0 deterministic-derivation mapping (design-v3.md §14): which verified-fact attributes
  map directly to which CVSS 4.0 metrics (trust boundary crossed → Attack Vector, authentication
  evidence → Privileges Required/User Interaction, blast-radius evidence → Vulnerable/Subsequent
  System impact metrics, etc.)
- EPSS/KEV data, where applicable
- exposure and deployment context (from `15-deployment-hardening` and `03-threat-model-dfd-stride`,
  where available)

## Required Outputs

- per-finding CVSS 4.0 vector, with each metric marked either "derived" (cite the verified-fact
  attribute it came from) or "LLM-assigned" (only for metrics with no direct verified-fact mapping)
- per-finding confidence classification (carried from the verifying lane's disposition, not
  re-derived here)
- per-finding trust classification
- EPSS/KEV annotation where applicable, with a note when neither applies
- a priority ranking of verified findings, with the ranking rationale stated (not just the score)
- exact JSON/table shape `10-synthesis-report` consumes, so synthesis does not need to re-score
