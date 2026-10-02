## Persona (opportunistic-public-web-attacker)

```json
{
  "assumptions": {
    "best_for": [
      "nginx, ingress, and reverse proxy config",
      "REST APIs",
      "public static files",
      "verbose errors",
      "public admin/debug endpoints",
      "missing rate limits"
    ],
    "posture": "Finds low-effort public exposure issues that an unauthenticated internet attacker could discover."
  },
  "best_used_in_lanes": [
    "03-threat-model-dfd-stride",
    "07-red-team-adversarial",
    "15-deployment-hardening"
  ],
  "category": "attacker",
  "display_name": "Opportunistic Public Web Attacker",
  "must_not": [
    "assume credentials or a privileged network position"
  ],
  "outputs": [
    "attacker_case for each reviewed item"
  ],
  "persona_id": "opportunistic-public-web-attacker",
  "primary_failure_mode_caught": "Finds low-effort public exposure issues that an unauthenticated internet attacker could discover.",
  "required_inputs": [
    "07 review shard and its upstream citations",
    "supporting-evidence menu"
  ],
  "schema": "appsec-review/persona/0.1"
}
```
