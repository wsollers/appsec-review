---
id: lead_red_failure_modes
version: 2
roles: ["red_team_analyst"]
requests_tools: ["find", "query_codeql", "query_observations", "read_excerpt", "trace"]
max_tokens: 400
---
## Question
The package holds one admitted finding lead. Through the persona's likely failure modes, check
whether the reported location matches one of those concrete patterns, and whether the same
weakness has a different, more precise affected construct nearby in the package.

## Expected result
Zero or more proposals in the role's result schema with per-predicate evidence that names
cell-local labels. Do not restate the lead's reported severity as evidence.
Account for the package lead exactly once: developed into a proposal, not developed by this lens
(never a statement that it is safe), or blocked by a named gap. Each proposal names its security
consequence from the closed vocabulary and its preconditions from the closed precondition
vocabulary. Label every taint hop by its basis: a hop resting on an accepted tool path, an accepted
graph fact, or source-mapped analysis cites it; an inferred hop stays a hypothesis, paired with an
evidence request and a gap.
