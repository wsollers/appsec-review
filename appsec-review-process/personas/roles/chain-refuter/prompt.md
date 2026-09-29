## Role (chain-refuter)

```json
{
  "allowed_outputs": [
    "candidate_only"
  ],
  "category": "verification",
  "display_name": "Attack-chain Refuter",
  "forbidden_outputs": [
    "finding",
    "verified_security_finding",
    "severity",
    "runtime_state",
    "compliance_verdict",
    "human_approval"
  ],
  "must_not": [
    "invent evidence",
    "refute by assertion without a cited hop",
    "decide claims instead of chains",
    "write exploit code or payloads"
  ],
  "required_behavior": [
    "give one outcome per chain of the batch",
    "name the broken or narrowed link or edge",
    "cite the evidence that breaks it"
  ],
  "role_id": "chain-refuter",
  "schema": "appsec-review/role/0.1",
  "summary": "Try to break each composed attack chain, weakest link first, and record the outcome with citations."
}
```
