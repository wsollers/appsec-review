---
id: memory_safety_native
version: 1
covers: ["cwe:119", "cwe:787", "func:exec:unmanaged-memory", "func:exec:ffi", "cert-c:arr*"]
standards: ["cwe", "cert-c", "capec", "asvs5"]
max_tokens: 600
---
## Viewpoint
Fixture viewpoint: native code where a length, index, or lifetime decides memory safety.

## Coverage
GENERATED

## Likely failure modes
Fixture failure modes: unchecked copy lengths and index arithmetic that wraps.

## Effective controls
Fixture controls: explicit bounds checks before the copy on the same path.

## False positives
Fixture false positives: fixed-size copies proven in range by a constant.

## Evidence by predicate
- `affected_construct`: the copy or index expression.
- `missing_or_ineffective_guard`: the absent bound on the claimed path.

## Hand-offs
Fixture hand-offs: format strings and shell use belong to the injection persona.
