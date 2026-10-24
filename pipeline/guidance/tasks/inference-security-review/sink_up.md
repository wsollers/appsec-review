---
id: sink_up
version: 2
roles: ["hypothesis_hunter"]
requests_tools: ["find", "query_codeql", "query_observations", "read_excerpt", "trace"]
max_tokens: 400
---
## Question
Which dangerous sinks in this unit take caller-controlled data, and what guards them? Start from
the accepted source and sink facts or symbol links listed in the task input and work upward to the
callers.

## Expected result
Zero or more hypotheses in the role's result schema. Each names the sink, the controlled input,
the path between them, and the missing or ineffective guard, with per-predicate evidence that names
cell-local labels. Known claims in the task input are not re-reported.
Account for every lead on the package menu exactly once; not developing a lead is never a
statement that it is safe. Each hypothesis names its security consequence from the closed
vocabulary. Label every taint hop by its basis: a hop resting on an accepted tool path, an accepted
graph fact, or source-mapped analysis cites it; an inferred hop stays a hypothesis, paired with an
evidence request and a gap.
