## Role (ir-evidence-producer)

```json
{
  "allowed_outputs": [
    "bitcode_module",
    "linked_module",
    "debug_location",
    "pointer_memory_fact",
    "coverage_gap"
  ],
  "category": "intelligence",
  "display_name": "LLVM IR Evidence Producer",
  "forbidden_outputs": [
    "verified_security_finding",
    "severity",
    "runtime_state"
  ],
  "must_not": [
    "promote facts to findings",
    "execute built targets",
    "hide partial capture"
  ],
  "required_behavior": [
    "bind exact native-build lineage",
    "hash every module and fact input",
    "report uncovered compile units"
  ],
  "role_id": "ir-evidence-producer",
  "schema": "appsec-review/role/0.1",
  "summary": "Capture, link and extract deterministic LLVM pointer/memory evidence without verdict promotion."
}
```
