---
id: blue_control
version: 2
roles: ["blue_team_refuter"]
requests_tools: ["find", "query_code_graph", "read_excerpt", "resolve_evidence", "trace"]
max_tokens: 450
---
## Question
For the claim in the task input, seek an effective dominating guard or control on the claimed path:
a `null_check`, `bounds_check` backed by a graph fact or CodeQL range fact, `auth_or_role_check`,
`sanitization_guard`, parameterized API, or framework enforcement that prevents the claimed behaviour.

## Expected result
Evidence relations in the role's result schema. Each names the predicate it bears on and cites
cell-local labels for both the `path:line` guard and its CFG/CPG guard fact. A guard refutes only
when its polarity dominates every incoming path to the sink on the tainted variable itself, enforces
actual destination or authorization constraints, and survives aliasing or mutation; an unrelated
check, single-branch check, or dead guard is `unresolved` or `qualifies`, never `contradicts`.
