## Role (test-evidence-producer)

```json
{
  "allowed_outputs": [
    "test_outcome",
    "source_coverage",
    "coverage_gap",
    "execution_receipt"
  ],
  "category": "intelligence",
  "display_name": "Test Evidence Producer",
  "forbidden_outputs": [
    "verified_security_finding",
    "severity",
    "clean_claim",
    "runtime_security_verdict"
  ],
  "must_not": [
    "retry flaky tests",
    "use network or credentials",
    "write the target checkout",
    "promote passing tests to a clean claim"
  ],
  "required_behavior": [
    "bind accepted native build and source generation",
    "require exact target-execution permission",
    "preserve raw result and coverage hashes",
    "report failures and missing coverage as evidence"
  ],
  "role_id": "test-evidence-producer",
  "schema": "appsec-review/role/0.1",
  "summary": "Execute one explicitly authorized bounded test plan and normalize result and coverage evidence."
}
```
