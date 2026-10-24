---
id: persona_sweep
version: 2
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
cell-local labels. Known claims in the task input are not re-reported. Finding nothing is a
valid result and never a statement that the unit is free of defects.
Account for every lead on the package menu exactly once; not developing a lead is never a
statement that it is safe. Each hypothesis names its security consequence from the closed
vocabulary. Label every taint hop by its basis: a hop resting on an accepted tool path, an accepted
graph fact, or source-mapped analysis cites it; an inferred hop stays a hypothesis, paired with an
evidence request and a gap.
