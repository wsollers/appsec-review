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
    "restate, rename or invent base DFD or wave-1 ids",
    "promote a candidate to a finding or assign severity"
  ],
  "required_behavior": [
    "give every leaf a support value, and every evidence leaf at least one resolvable evidence ref",
    "put each prerequisite on the node that needs it",
    "put what cannot be placed on a base or wave-1 id into notes or gaps"
  ],
  "role_id": "attack-modeler",
  "schema": "appsec-review/role/0.1",
  "summary": "Returns one threat-workbench cell reply of AND/OR attack trees (attack-tree-builder), or of supply-chain abuse scenarios and attack trees (supply-chain-specialist), keyed to base DFD and wave-1 ids. The 03 join merges it into the threat model; attack-chain composition starts from the tree nodes, and the claim ledger and report read the records as candidates."
}
```
