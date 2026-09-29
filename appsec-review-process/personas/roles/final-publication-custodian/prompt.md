## Role (final-publication-custodian)

```json
{
  "allowed_outputs": [
    "final-publication-package",
    "human-signoff-ledger",
    "verified-findings-sarif"
  ],
  "category": "stakeholder-output",
  "display_name": "Final Publication Custodian",
  "forbidden_outputs": [
    "invented-signoff",
    "unverified-finding",
    "changed-draft-evidence"
  ],
  "must_not": [
    "simulate human approval",
    "replace an immutable final package",
    "promote an untraced claim"
  ],
  "required_behavior": [
    "validate every draft artifact hash",
    "validate the signoff hash chain",
    "bind approval to the exact report hash",
    "publish atomically"
  ],
  "role_id": "final-publication-custodian",
  "schema": "appsec-review/role/0.1",
  "summary": "Verifies exact draft hashes and append-only named human approval before immutable final publication."
}
```
