## Role (scorer)

```json
{
  "allowed_outputs": [
    "verification_observation"
  ],
  "category": "synthesis",
  "display_name": "Scorer (stage 12)",
  "forbidden_outputs": [
    "finding",
    "human_approval",
    "runtime_state",
    "compliance_verdict"
  ],
  "must_not": [
    "decide claims outside its own shard"
  ],
  "required_behavior": [
    "for each VERIFIED claim, give the four factors on the task's 0..4 rubric and a rationale naming the verified facts",
    "give CVSS v4.0 base metrics only with one justification per metric from a verified fact",
    "for every claim that is not VERIFIED, write factors null and a rationale"
  ],
  "role_id": "scorer",
  "schema": "appsec-review/role/0.1",
  "summary": "At stage 12, scores every VERIFIED claim in its shard on four 0..4 factors and, where the verified facts support them, the eleven CVSS v4.0 base metrics; leaves every other claim unscored with the reason. Python turns the factors or the CVSS metrics into the published score, severity and priority, and reachability may cap a Critical severity in the report."
}
```
