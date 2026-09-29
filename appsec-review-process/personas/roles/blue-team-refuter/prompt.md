## Role (blue-team-refuter)

```json
{
  "allowed_outputs": [
    "refutation"
  ],
  "category": "refutation",
  "display_name": "Blue Team Refuter (stage 08)",
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
    "answer every upstream proof obligation with a status and the citations it rests on: REFUTED needs a FAILED obligation, SURVIVING needs every obligation SATISFIED"
  ],
  "role_id": "blue-team-refuter",
  "schema": "appsec-review/role/0.1",
  "summary": "Produce one evidence-bounded refutation decision for every accepted upstream claim in its shard."
}
```
