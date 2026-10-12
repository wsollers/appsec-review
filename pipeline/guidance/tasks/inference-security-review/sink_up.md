---
id: sink_up
version: 1
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
resolvable identities. Known claims in the task input are not re-reported.
