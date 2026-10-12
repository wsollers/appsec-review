---
id: lead_red_failure_modes
version: 1
roles: ["red_team_analyst"]
requests_tools: ["find", "query_codeql", "query_observations", "read_excerpt", "trace"]
max_tokens: 400
---
## Question
The package holds one admitted finding lead. Through the persona's likely failure modes, check
whether the reported location matches one of those concrete patterns, and whether the same
weakness has a different, more precise affected construct nearby in the package.

## Expected result
Zero or more claims in the role's result schema with per-predicate evidence that names resolvable
identities. Do not restate the lead's reported severity as evidence.
