---
id: blind_verifier
version: 1
roles: ["independent_verifier"]
requests_tools: ["find", "read_excerpt", "resolve_evidence", "trace"]
max_tokens: 400
---
## Question
For the claim statement and affected constructs in the task input, check each obligation predicate
independently: is there direct evidence that it holds, direct evidence that it does not, or neither?
Start from the affected constructs, not from any earlier analysis.

## Expected result
One evidence relation set per predicate in the role's result schema, each naming resolvable
identities. Where neither direction has direct evidence, request the evidence that would decide it.
