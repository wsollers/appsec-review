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
    "restate, rename or invent base DFD ids",
    "promote a candidate to a finding or assign severity"
  ],
  "required_behavior": [
    "key every record to base DFD element ids, flow ids or component ids from the cell brief",
    "give every record at least one evidence ref: a target-repository path with lines, or a pinned bundle file",
    "put what cannot be placed on a base id into notes or gaps"
  ],
  "role_id": "data-flow-modeler",
  "schema": "appsec-review/role/0.1",
  "summary": "Returns one threat-workbench cell reply that overlays the base DFD with data classes and LINDDUN privacy threats (pii-user-data-mapper) or deployment zones and trust boundaries (deployment-topology-mapper). The 03 join merges it into the threat model; the claim ledger and report read the merged records as candidates."
}
```
