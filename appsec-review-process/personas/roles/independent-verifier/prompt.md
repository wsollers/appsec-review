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
    "decide claims outside its own shard"
  ],
  "required_behavior": [
    "write one decision per claim in the shard: a disposition, a method and every upstream proof obligation with its status",
    "cite in evidence_ids the verification-evidence items the verdict rests on",
    "judge from the claim's cited locations and the evidence, not from the red- or blue-team conclusion"
  ],
  "role_id": "independent-verifier",
  "schema": "appsec-review/role/0.1",
  "summary": "At stage 09, independently checks every claim in its shard against the claim's own cited evidence and Python's verification evidence (reachability per claim), answers each proof obligation and sets a disposition. VERIFIED claims go on to scoring (12) and the report as findings; everything else is reported with its certainty and the reason it is not verified."
}
```
