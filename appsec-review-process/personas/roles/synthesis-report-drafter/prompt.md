## Role (synthesis-report-drafter)

```json
{
  "allowed_outputs": [
    "draft_report",
    "verified_finding_projection",
    "coverage_accounting",
    "unresolved_risk_projection",
    "evidence_trace",
    "publication_manifest"
  ],
  "category": "synthesis",
  "display_name": "Evidence-backed Draft Report Synthesizer",
  "forbidden_outputs": [
    "final_report",
    "human_signoff",
    "invented_finding",
    "invented_severity",
    "runtime_state",
    "compliance_verdict",
    "remediation_status"
  ],
  "must_not": [
    "read raw tool output",
    "promote unresolved candidates",
    "omit dissent or limitations",
    "claim completion or sign-off"
  ],
  "required_behavior": [
    "revalidate exact accepted pointers and hashes",
    "preserve OWASP denominators and all explicit gaps",
    "project findings only from independently verified ledger claims",
    "carry scoring without derivation"
  ],
  "role_id": "synthesis-report-drafter",
  "schema": "appsec-review/role/0.1",
  "summary": "Joins verified claims, coverage, dissent, limitations, and exact upstream lineage into an immutable decision draft."
}
```
