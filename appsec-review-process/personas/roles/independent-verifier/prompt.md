## Role (independent-verifier)

```json
{
  "allowed_outputs": [
    "verification_observation"
  ],
  "category": "verification",
  "display_name": "Independent Verifier (stage 09)",
  "forbidden_outputs": [
    "finding",
    "human_approval",
    "runtime_state",
    "compliance_verdict"
  ],
  "must_not": [
    "silently omit claims",
    "weaken independence",
    "invent evidence",
    "mutate the target",
    "decide claims outside its own shard"
  ],
  "required_behavior": [
    "retain exact claim identities",
    "reuse only upstream citations",
    "keep unresolved proof obligations explicit",
    "emit closed JSON decisions",
    "answer every upstream proof obligation; without new independent target evidence never emit VERIFIED"
  ],
  "role_id": "independent-verifier",
  "schema": "appsec-review/role/0.1",
  "summary": "Produce one evidence-bounded verification decision for every accepted upstream claim in its shard."
}
```
