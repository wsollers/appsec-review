## Role (data-flow-modeler)

```json
{
  "allowed_outputs": [
    "candidate_only"
  ],
  "category": "discovery",
  "display_name": "Threat Workbench Data And Deployment Modeler",
  "forbidden_outputs": [
    "finding",
    "verified_security_finding",
    "severity",
    "runtime_state",
    "compliance_verdict",
    "remediation_status",
    "malicious_intent"
  ],
  "must_not": [
    "promote a candidate to a finding",
    "assign severity",
    "claim compliance",
    "invent evidence"
  ],
  "required_behavior": [
    "key every record to base DFD element and flow ids",
    "cite evidence refs for every record",
    "record unknowns as notes or gaps"
  ],
  "role_id": "data-flow-modeler",
  "schema": "appsec-review/role/0.1",
  "summary": "Adds data-class, personal-data-flow, LINDDUN privacy and deployment-zone overlays keyed to base DFD ids."
}
```
