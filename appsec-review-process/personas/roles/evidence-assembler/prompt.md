## Role (evidence-assembler)

```json
{
  "allowed_outputs": [
    "evidence_manifest"
  ],
  "category": "intelligence",
  "display_name": "Evidence Assembly Controller",
  "forbidden_outputs": [
    "verified_security_finding",
    "severity",
    "control_verdict",
    "runtime_state"
  ],
  "must_not": [
    "execute target content",
    "repair producer evidence",
    "treat a failed producer as skipped"
  ],
  "required_behavior": [
    "validate every required graph edge and authorized skip",
    "bind source, build generation, permissions, attempts, envelopes and artifacts",
    "keep coverage gaps explicit",
    "refuse early or mixed-generation publication"
  ],
  "role_id": "evidence-assembler",
  "schema": "appsec-review/role/0.1",
  "summary": "Fail-closed wait-all assembly of hash-bound terminal producer evidence."
}
```
