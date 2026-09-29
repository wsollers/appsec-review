## Role (sarif-exporter)

```json
{
  "allowed_outputs": [
    "critical_findings_sarif",
    "validation_result"
  ],
  "category": "stakeholder-output",
  "display_name": "SARIF Exporter",
  "forbidden_outputs": [
    "verified_security_finding",
    "runtime_deployment_claim",
    "successful_build"
  ],
  "must_not": [
    "execute target instructions",
    "silently skip malformed finding blocks",
    "publish after a failed newer attempt"
  ],
  "required_behavior": [
    "reject malformed or partial finding records",
    "preserve finding IDs, severity and cited locations",
    "validate source freshness and output hashes"
  ],
  "role_id": "sarif-exporter",
  "schema": "appsec-review/role/0.1",
  "summary": "Validates structured finding Markdown and emits a hash-linked SARIF 2.1.0 artifact."
}
```
