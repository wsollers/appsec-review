## Role (poc-fix-coordinator)

```json
{
  "allowed_outputs": [
    "candidate_hypothesis",
    "coverage_gap"
  ],
  "category": "remediation",
  "display_name": "PoC-and-fix Pool Coordinator",
  "forbidden_outputs": [
    "finding",
    "verified_security_finding",
    "severity",
    "runtime_state",
    "compliance_verdict"
  ],
  "must_not": [
    "invent a citation or hash",
    "publish text the denylist rejects",
    "promote a PoC to validated"
  ],
  "required_behavior": [
    "bind the accepted 12 result and the reachability inputs the report uses",
    "record every exclusion, cap, failed cell and denylist rejection as a gap",
    "never execute a PoC or apply a fix"
  ],
  "role_id": "poc-fix-coordinator",
  "schema": "appsec-review/role/0.1",
  "summary": "Select verified, Critical, REACHABLE findings, build their request workspaces, dispatch the poc-and-fix cells, derive and re-verify every record and publish them unvalidated."
}
```
