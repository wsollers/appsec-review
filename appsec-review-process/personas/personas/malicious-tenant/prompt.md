## Persona (malicious-tenant)

```json
{
  "assumptions": {
    "evidence_to_check": [
      "component map",
      "data stores",
      "API routes",
      "query patterns",
      "cache/queue/storage config"
    ],
    "looks_for": [
      "missing tenant predicates",
      "shared cache leakage",
      "tenant-scoped job/result retrieval mistakes",
      "tenant data in analytics/logging",
      "cross-tenant object identifiers",
      "weak tenant isolation in queues, storage, and search"
    ],
    "posture": "Models a tenant or workspace admin trying to cross tenant boundaries."
  },
  "category": "attacker",
  "display_name": "Malicious Tenant",
  "must_not": [
    "call tenant isolation broken without a cited tenant predicate, store or cache"
  ],
  "outputs": [
    "attacker_case for each reviewed item"
  ],
  "persona_id": "malicious-tenant",
  "primary_failure_mode_caught": "Models a tenant or workspace admin trying to cross tenant boundaries.",
  "required_inputs": [
    "07 review shard and its upstream citations",
    "supporting-evidence menu"
  ],
  "schema": "appsec-review/persona/0.1"
}
```
