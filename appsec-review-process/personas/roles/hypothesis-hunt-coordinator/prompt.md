## Role (hypothesis-hunt-coordinator)

```json
{
  "allowed_outputs": [
    "candidate_hypothesis",
    "coverage_gap"
  ],
  "category": "discovery",
  "display_name": "Hypothesis Hunt Pool Coordinator",
  "forbidden_outputs": [
    "finding",
    "verified_security_finding",
    "severity",
    "runtime_state",
    "compliance_verdict"
  ],
  "must_not": [
    "invent or repair a hypothesis location",
    "hide a dropped hypothesis",
    "assign severity"
  ],
  "required_behavior": [
    "bind the component map, tool leads and checkout snapshot",
    "drop unresolvable locations as gaps",
    "deduplicate across hunters and record tool-lead overlap"
  ],
  "role_id": "hypothesis-hunt-coordinator",
  "schema": "appsec-review/role/0.1",
  "summary": "Shard the target, dispatch the hunter pool, resolve every hypothesis against the checkout and publish candidate-only hypotheses."
}
```
