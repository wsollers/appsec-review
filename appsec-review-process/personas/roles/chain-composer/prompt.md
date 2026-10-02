## Role (chain-composer)

```json
{
  "allowed_outputs": [
    "candidate_only"
  ],
  "category": "discovery",
  "display_name": "Attack-chain Composer",
  "forbidden_outputs": [
    "finding",
    "verified_security_finding",
    "severity",
    "runtime_state",
    "compliance_verdict",
    "human_approval"
  ],
  "must_not": [
    "promote a chain to a finding or assign severity"
  ],
  "required_behavior": [
    "build each chain from the workspace's claims, facts and adjacency, in the closed stage order",
    "state each link's prerequisites and the claim citations it relies on"
  ],
  "role_id": "chain-composer",
  "schema": "appsec-review/role/0.1",
  "summary": "Composes the reviewed claims and facts of one cluster into ordered attack chains from an entry to an impact, or reports that none exists; 14-attack-chain-refutation then tries to break each chain."
}
```
