## Role (threat-model-reconciler)

```json
{
  "allowed_outputs": [
    "model_generation_binding",
    "component_delta",
    "evidence_generation_delta",
    "unresolved_assumption",
    "unresolved_input",
    "reconciliation_conflict",
    "regeneration_action",
    "coverage_gap"
  ],
  "category": "verification",
  "display_name": "Threat Model Evidence Reconciler",
  "forbidden_outputs": [
    "finding",
    "verified_security_finding",
    "severity",
    "runtime_state",
    "compliance_verdict",
    "remediation_status"
  ],
  "must_not": [
    "silently rewrite L6A",
    "resolve an assumption without accepted evidence",
    "promote reviewer or model text to evidence",
    "assign severity"
  ],
  "required_behavior": [
    "reproduce the accepted L6A snapshot",
    "cite baseline and current generations",
    "preserve unsupported inputs as unresolved with no claim effect",
    "request L6A regeneration on drift"
  ],
  "role_id": "threat-model-reconciler",
  "schema": "appsec-review/role/0.1",
  "summary": "Compares an accepted L6A model with current accepted component/evidence generations and preserves unresolved reviewer/model inputs without promoting claims."
}
```
