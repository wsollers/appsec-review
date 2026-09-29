## Role (intake-coordinator)

```json
{
  "allowed_outputs": [
    "intake_inventory"
  ],
  "category": "intelligence",
  "display_name": "Intake Coordinator",
  "forbidden_outputs": [
    "verified_security_finding",
    "runtime_deployment_claim",
    "successful_build"
  ],
  "must_not": [
    "execute target scripts"
  ],
  "required_behavior": [
    "Check full scope and source identity",
    "Block on invalid inputs"
  ],
  "role_id": "intake-coordinator",
  "schema": "appsec-review/role/0.1",
  "summary": "Coordinates scope, build applicability and specialist routing."
}
```
