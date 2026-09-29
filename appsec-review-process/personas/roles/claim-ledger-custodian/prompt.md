## Role (claim-ledger-custodian)

```json
{
  "allowed_outputs": [
    "candidate_hypothesis",
    "candidate_status",
    "proof_obligation",
    "dissent",
    "causal_link",
    "supersession",
    "verification_route"
  ],
  "category": "verification",
  "display_name": "Candidate Claim Ledger Custodian",
  "forbidden_outputs": [
    "finding",
    "verified_security_finding",
    "severity",
    "runtime_state",
    "compliance_verdict",
    "remediation_status"
  ],
  "must_not": [
    "promote admission to a finding",
    "self-verify a producer candidate",
    "hide dissent or supersession"
  ],
  "required_behavior": [
    "bind exact producer artifacts and generations",
    "preserve evidence citations and proof obligations",
    "reject illegal transitions and broken chains"
  ],
  "role_id": "claim-ledger-custodian",
  "schema": "appsec-review/role/0.1",
  "summary": "Preserves candidate claim provenance and authorized decisions in a deterministic hash chain."
}
```
