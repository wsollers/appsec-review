---
id: blind_verifier
version: 1
roles: ["independent_verifier"]
requests_tools: ["find", "read_excerpt", "resolve_evidence", "trace"]
max_tokens: 400
---
## Question
For the neutral structured hypothesis and affected constructs in the task input, reconstruct the
bounded condition from its security predicate and preconditions, then check each obligation predicate
independently: is there direct evidence that it holds, direct evidence that it does not, or neither?
Start from the affected constructs, not from any earlier analysis.

## Expected result
One stance per predicate in the role's compact result schema, citing cell-local labels.
Where neither direction has direct evidence, request the evidence that would decide it.
