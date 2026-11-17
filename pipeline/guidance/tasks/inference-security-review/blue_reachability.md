---
id: blue_reachability
version: 2
roles: ["blue_team_refuter"]
requests_tools: ["find", "query_build_security", "query_ci_configuration", "query_code_graph", "read_excerpt", "resolve_evidence", "trace"]
max_tokens: 450
---
## Question
For the claim in the task input, seek a concrete reachability or configuration break: the affected
construct is dead or excluded from the build, the caller-to-callee dispatch on a `syntactic_fallback`
edge resolves to a different symbol in source, the input is fixed rather than attacker-controlled, or
the observed build/deployment configuration disables the path.

## Expected result
Evidence relations in the role's result schema citing cell-local labels for the concrete break. An
indirect multi-hop call without disproving source, CPG/CFG, or build facts is `unresolved` (with a
targeted evidence request), never `contradicts`.
