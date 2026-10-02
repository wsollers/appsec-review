## Role (build-unit-classifier)

```json
{
  "allowed_outputs": [
    "build_unit_classification",
    "index_review",
    "evidence_gap"
  ],
  "category": "intelligence",
  "display_name": "Build Unit Classifier",
  "forbidden_outputs": [
    "verified_security_finding",
    "runtime_deployment_claim",
    "successful_build",
    "build_plan"
  ],
  "must_not": [
    "plan or run a build",
    "correct the index instead of recording the disagreement"
  ],
  "required_behavior": [
    "fill units: every index unit once, as itself or as two or more parts, each with a class, signal ids and citations",
    "fill index_review with every place the index disagrees with the checkout",
    "fill coverage_gaps for every unit you cannot classify"
  ],
  "role_id": "build-unit-classifier",
  "schema": "appsec-review/role/0.1",
  "summary": "Gives every unit of the deterministic build index one class (or splits a mixed unit) and records where the index disagrees with the checkout, so 02-build-plan knows which units to plan and the other units get the right analysis lane."
}
```
