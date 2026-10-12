---
id: lead_red_stack
version: 1
roles: ["red_team_analyst"]
requests_tools: ["find", "query_build_security", "read_excerpt", "trace"]
max_tokens: 400
---
## Question
The package holds one admitted finding lead. Through the stack profile lens, decide whether the
reported location is a real weakness in this runtime, framework, and build: which idiomatic
mechanism should apply here, is it present on this path, and does a stack-specific pitfall make
the reported behaviour reachable?

## Expected result
Zero or more claims in the role's result schema. For every claim, give per-predicate evidence that
names resolvable identities from the package or this cell's retrieval transcript. When the lead
does not hold in this stack, return no claim and state which stack fact rules it out.
