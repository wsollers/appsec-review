---
id: blue_reachability
version: 1
roles: ["blue_team_refuter"]
requests_tools: ["find", "query_build_security", "query_ci_configuration", "read_excerpt", "resolve_evidence", "trace"]
max_tokens: 400
---
## Question
For the claim in the task input, seek a reachability or configuration break: the affected construct
is dead or not built, the input is not attacker-controlled, the path is cut, or the observed build
and deployment configuration disables the claimed behaviour.

## Expected result
Evidence relations in the role's result schema. Each names the predicate it bears on and a
cell-local label for the break.
