## Role (abuse-modeler)

```json
{
  "allowed_outputs": [
    "candidate_only"
  ],
  "category": "discovery",
  "display_name": "Threat Workbench Abuse Modeler",
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
    "state actor, capability, harm and preconditions",
    "cite evidence refs for every scenario",
    "record unknowns as notes or gaps"
  ],
  "role_id": "abuse-modeler",
  "schema": "appsec-review/role/0.1",
  "summary": "Adds attacker-objective abuse scenarios keyed to base DFD and wave-1 data-class ids."
}
```
