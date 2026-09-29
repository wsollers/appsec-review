## Role (attack-modeler)

```json
{
  "allowed_outputs": [
    "candidate_only"
  ],
  "category": "discovery",
  "display_name": "Threat Workbench Attack-Tree Modeler",
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
    "give every leaf a support value",
    "cite evidence refs for every evidence leaf",
    "keep prerequisites explicit"
  ],
  "role_id": "attack-modeler",
  "schema": "appsec-review/role/0.1",
  "summary": "Adds AND/OR attack trees whose leaves are evidence, assumption or unresolved."
}
```
