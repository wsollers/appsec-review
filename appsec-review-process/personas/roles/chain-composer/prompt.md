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
    "invent links, edges or evidence",
    "promote a chain to a finding",
    "copy orchestrator bookkeeping (ids, states, hashes)",
    "write exploit code or payloads"
  ],
  "required_behavior": [
    "cite only workspace claim ids and fact refs",
    "give each link a stage in the closed order",
    "name the fact ref that justifies each hop or mark it synthetic",
    "name the chain's claim ids in the narrative"
  ],
  "role_id": "chain-composer",
  "schema": "appsec-review/role/0.1",
  "summary": "Propose how the reviewed claims and entry facts of one cluster combine into ordered attack chains."
}
```
