---
id: persona_sweep
version: 1
roles: ["hypothesis_hunter"]
requests_tools: ["find", "query_hotspots", "read_excerpt", "search", "trace"]
max_tokens: 400
---
## Question
Review this unit as the assigned specialist. Using the persona's coverage and likely failure
modes, look for the weaknesses that specialist would expect in a unit with these tags and this
stack.

## Expected result
Zero or more hypotheses in the role's result schema with per-predicate evidence that names
resolvable identities. Known claims in the task input are not re-reported. Finding nothing is a
valid result and never a statement that the unit is free of defects.
