# Subprompts — Scoring And Prioritization (L8)

## Derivation Pass

Walk each verified finding against design-v3.md §14's mapping table and fill in every CVSS 4.0
metric that has a direct verified-fact mapping. Cite the fact for each. Leave unmapped metrics
blank for the next subprompt rather than guessing early.

## Residual Assignment

For metrics the Derivation Pass left blank, assign a value using the finding's evidence and mark it
`LLM-assigned`. Never overwrite a `derived` metric here.

## EPSS/KEV Annotation

Look up EPSS and CISA KEV status for any finding with a CVE identifier. State "not applicable" for
findings with no CVE (e.g. a native memory-safety finding with no assigned CVE) rather than leaving
the field blank.

## Priority Ranking

Rank all scored findings. State the rationale per finding, not just the resulting rank — severity,
exposure, confidence, and known remediation cost/availability all factor in.
