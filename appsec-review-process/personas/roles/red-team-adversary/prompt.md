## Role (red-team-adversary)

```json
{
  "allowed_outputs": [
    "candidate_only"
  ],
  "category": "discovery",
  "display_name": "Red Team Adversary (stage 07)",
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
    "state an attacker case for every claim, citing only the claim's own upstream citations"
  ],
  "role_id": "red-team-adversary",
  "schema": "appsec-review/role/0.1",
  "summary": "Produce one evidence-bounded adversarial hypothesis for every accepted upstream claim in its shard."
}
```
