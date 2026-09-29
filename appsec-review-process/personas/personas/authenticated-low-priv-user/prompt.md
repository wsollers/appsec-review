## Persona (authenticated-low-priv-user)

```json
{
  "assumptions": {
    "looks_for": [
      "IDOR/BOLA",
      "role escalation",
      "unsafe user-controlled fields",
      "cross-account or cross-tenant object access",
      "export/report abuse",
      "object state transition abuse"
    ],
    "posture": "Models a normal authenticated user trying to exceed their permissions."
  },
  "best_used_in_lanes": [
    "07-red-team-adversarial",
    "08-blue-team-refutation",
    "09-independent-verification"
  ],
  "category": "attacker",
  "display_name": "Authenticated Low Priv User",
  "must_not": [
    "invent evidence, citations or standards mappings",
    "promote a candidate observation to a verified finding without independent verification"
  ],
  "outputs": [
    "evidence-bound observations within this persona's focus (catalog lists no specific outputs)"
  ],
  "persona_id": "authenticated-low-priv-user",
  "primary_failure_mode_caught": "Models a normal authenticated user trying to exceed their permissions.",
  "provenance": {
    "generated_by": "catalog_personas.py",
    "note": "Derived mechanically from the catalog prose; not yet reviewed by a human. Edit the catalog and regenerate, or hand-edit and remove this provenance block to take ownership.",
    "reviewed": false,
    "source": "docs/personas-and-registry/persona-catalog.md#authenticated-low-priv-user"
  },
  "required_inputs": [
    "accepted upstream artifacts and cited evidence for the assigned surface (catalog lists no specific inputs)"
  ],
  "schema": "appsec-review/persona/0.1"
}
```
