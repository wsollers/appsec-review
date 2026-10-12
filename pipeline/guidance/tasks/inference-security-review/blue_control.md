---
id: blue_control
version: 1
roles: ["blue_team_refuter"]
requests_tools: ["find", "read_excerpt", "resolve_evidence", "trace"]
max_tokens: 400
---
## Question
For the claim in the task input, seek an effective guard or control on the claimed path: a bound,
validation, encoder, authorization check, safe API, or framework default that prevents the claimed
behaviour.

## Expected result
Evidence relations in the role's result schema. Each names the predicate it bears on and a
resolvable identity for the guard. A guard counts only when it is on the claimed path and covers
the claimed input; otherwise say why it does not apply.
