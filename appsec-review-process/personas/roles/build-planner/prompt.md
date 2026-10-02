## Role (build-planner)

```json
{
  "allowed_outputs": [
    "build_unit_plan",
    "evidence_gap"
  ],
  "category": "intelligence",
  "display_name": "Build Planner",
  "forbidden_outputs": [
    "verified_security_finding",
    "runtime_deployment_claim",
    "successful_build",
    "build_unit_classification"
  ],
  "must_not": [
    "plan any unit other than the one in plan-unit.json"
  ],
  "required_behavior": [
    "fill exactly one plans entry for the unit in plan-unit.json: build system, feasibility tier, image, commands, compile-database method, signal ids and citations",
    "fill coverage_gaps when the unit cannot be built here (tier C) and say why"
  ],
  "role_id": "build-planner",
  "schema": "appsec-review/role/0.1",
  "summary": "Writes the build plan for one classified unit: base image, extra packages, and the ordered configure and build commands, so 02-build-resolution can render the image and run a trial build with the review's fixed clang."
}
```
