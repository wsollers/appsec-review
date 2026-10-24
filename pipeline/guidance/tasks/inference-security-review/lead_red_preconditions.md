---
id: lead_red_preconditions
version: 2
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
Zero or more proposals in the role's result schema, each listing its preconditions and
per-predicate evidence that cites cell-local labels. A configuration-scoped precondition needs
evidence for the configuration predicate.
Account for the package lead exactly once: developed into a proposal, not developed by this lens
(never a statement that it is safe), or blocked by a named gap. Each proposal names its security
consequence from the closed vocabulary and its preconditions from the closed precondition
vocabulary. Label every taint hop by its basis: a hop resting on an accepted tool path, an accepted
graph fact, or source-mapped analysis cites it; an inferred hop stays a hypothesis, paired with an
evidence request and a gap.
