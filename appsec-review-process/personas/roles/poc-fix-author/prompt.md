## Role (poc-fix-author)

```json
{
  "allowed_outputs": [
    "candidate_only"
  ],
  "category": "remediation",
  "display_name": "PoC-and-fix Author",
  "forbidden_outputs": [
    "finding",
    "verified_security_finding",
    "severity",
    "runtime_state",
    "compliance_verdict",
    "human_approval"
  ],
  "must_not": [
    "claim the PoC ran or the fix works"
  ],
  "required_behavior": [
    "walk the reachability witness from entry to sink before writing the PoC",
    "prefer the smallest input, call or test, and say when no honest PoC exists"
  ],
  "role_id": "poc-fix-author",
  "schema": "appsec-review/role/0.1",
  "summary": "For one verified, Critical, reachable finding, shows the code's owner how the defect happens with a light static PoC and proposes the change that removes it; both stay unvalidated."
}
```
