---
id: variant
version: 2
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
than the seed claim, with per-predicate evidence that cites cell-local labels. Known claims in
the task input are not re-reported.
Account for every lead on the package menu exactly once; not developing a lead is never a
statement that it is safe. Each hypothesis names its security consequence from the closed
vocabulary. Label every taint hop by its basis: a hop resting on an accepted tool path, an accepted
graph fact, or source-mapped analysis cites it; an inferred hop stays a hypothesis, paired with an
evidence request and a gap.
