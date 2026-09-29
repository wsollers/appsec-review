## Role (threat-model-core)

```json
{
  "allowed_outputs": [
    "modeled_architecture",
    "modeled_data_flow",
    "trust_boundary",
    "candidate_threat_hypothesis",
    "assumption",
    "coverage_gap",
    "rescope_trigger"
  ],
  "category": "discovery",
  "display_name": "Static Threat Model Core",
  "forbidden_outputs": [
    "finding",
    "verified_security_finding",
    "severity",
    "runtime_state",
    "compliance_verdict",
    "remediation_status"
  ],
  "must_not": [
    "promote a hypothesis to a finding",
    "claim runtime behavior",
    "assign severity",
    "hide an unresolved crossing or component"
  ],
  "required_behavior": [
    "cite exact accepted F03 and F02 evidence",
    "account for every component and trust-boundary crossing",
    "attach proof obligations to each candidate hypothesis"
  ],
  "role_id": "threat-model-core",
  "schema": "appsec-review/role/0.1",
  "summary": "Builds an evidence-backed DFD and candidate STRIDE worklist from accepted component evidence."
}
```
