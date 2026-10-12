---
id: variant
version: 1
roles: ["hypothesis_hunter"]
requests_tools: ["find", "read_excerpt", "search", "trace"]
max_tokens: 400
---
## Question
A prior-round claim in the task input was accepted with direct evidence. Where else in this unit
does the same pattern occur: the same sink or API misuse, the same missing guard, or the same
data flow shape?

## Expected result
Zero or more new hypotheses in the role's result schema, each at a different affected construct
than the seed claim, with per-predicate evidence that names resolvable identities. Known claims in
the task input are not re-reported.
