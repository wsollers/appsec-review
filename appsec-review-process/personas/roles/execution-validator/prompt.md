## Role (execution-validator)

```json
{
  "allowed_outputs": [
    "validation_result"
  ],
  "category": "verification",
  "display_name": "Execution Validator",
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
  "role_id": "execution-validator",
  "schema": "appsec-review/role/0.1",
  "summary": "Deterministic pre/post checks of identity, configuration, schemas, hashes and semantics."
}
```
