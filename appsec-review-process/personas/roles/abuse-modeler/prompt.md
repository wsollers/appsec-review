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
    "restate, rename or invent base DFD or wave-1 ids",
    "promote a candidate to a finding or assign severity"
  ],
  "required_behavior": [
    "give each scenario an objective, actor, capability, harm, preconditions and the controls not found",
    "give every scenario at least one evidence ref: a target-repository path with lines, or a pinned file",
    "put what cannot be placed on a base or wave-1 id into notes or gaps"
  ],
  "role_id": "abuse-modeler",
  "schema": "appsec-review/role/0.1",
  "summary": "Returns one threat-workbench cell reply of attacker-objective abuse scenarios, each keyed to base DFD elements or flows and wave-1 data classes. The 03 join merges it into the threat model, where the scenarios are ranked with privacy threats and attack trees; the claim ledger and report read them as candidates."
}
```
