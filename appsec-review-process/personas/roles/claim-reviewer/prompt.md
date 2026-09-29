## Role (claim-reviewer)

```json
{
  "allowed_outputs": [
    "candidate_only",
    "refutation",
    "verification_observation"
  ],
  "category": "verification",
  "display_name": "Bounded Claim Decision Reviewer",
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
    "mutate the target"
  ],
  "required_behavior": [
    "retain exact claim identities",
    "reuse only upstream citations",
    "keep unresolved proof obligations explicit",
    "emit closed JSON decisions"
  ],
  "role_id": "claim-reviewer",
  "schema": "appsec-review/role/0.1",
  "summary": "Produce one evidence-bounded stage decision for every accepted upstream claim."
}
```
