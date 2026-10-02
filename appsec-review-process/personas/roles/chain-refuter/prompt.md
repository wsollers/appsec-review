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
    "decide a claim's review state instead of the chain"
  ],
  "required_behavior": [
    "start with the link or edge the chain names as weakest, then try the others",
    "ground every break in a check, sanitisation, validation or precondition at a named hop"
  ],
  "role_id": "chain-refuter",
  "schema": "appsec-review/role/0.1",
  "summary": "Tries to break each composed attack chain of one batch, weakest link first, and records whether it is broken, narrowed, holds or cannot be assessed; a broken chain is dropped from the report."
}
```
