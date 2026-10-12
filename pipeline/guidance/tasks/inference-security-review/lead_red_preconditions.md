---
id: lead_red_preconditions
version: 1
roles: ["red_team_analyst"]
requests_tools: ["find", "query_ci_configuration", "read_excerpt", "trace"]
max_tokens: 400
---
## Question
The package holds one admitted finding lead. Through the attacker-preconditions lens, determine
what an attacker must control or already hold for the reported behaviour to matter: which input,
which identity or privilege, which configuration or deployment state. Express each precondition
in the closed precondition vocabulary.

## Expected result
Zero or more claims in the role's result schema, each listing its preconditions and per-predicate
evidence that names resolvable identities. A configuration-scoped precondition needs evidence for
the configuration predicate.
