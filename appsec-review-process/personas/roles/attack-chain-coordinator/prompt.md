## Role (attack-chain-coordinator)

```json
{
  "allowed_outputs": [
    "candidate_hypothesis",
    "coverage_gap"
  ],
  "category": "discovery",
  "display_name": "Attack-chain Pool Coordinator",
  "forbidden_outputs": [
    "finding",
    "verified_security_finding",
    "severity",
    "runtime_state",
    "compliance_verdict"
  ],
  "must_not": [
    "invent a link, edge or citation",
    "promote a chain to a verified finding",
    "assign severity"
  ],
  "required_behavior": [
    "bind the accepted 09 result, threat model and component map",
    "record every cut, failed cell and synthetic edge as a gap",
    "compute chain state from link, edge and refutation state, never above supported"
  ],
  "role_id": "attack-chain-coordinator",
  "schema": "appsec-review/role/0.1",
  "summary": "Seed clusters from reviewed claims, dispatch the composer and refuter pools, derive every chain's links, edges and state, and publish the hash-linked attack-chain ledger."
}
```
