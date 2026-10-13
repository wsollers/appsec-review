---
id: lead_red_stack
version: 2
roles: ["red_team_analyst"]
requests_tools: ["find", "query_build_security", "read_excerpt", "trace"]
max_tokens: 400
---
## Question
The package holds one admitted finding lead. Through the stack profile lens, decide whether the
reported location is a real weakness in this runtime, framework, and build: which idiomatic
mechanism should apply here, is it present on this path, and does a stack-specific pitfall make
the reported behaviour reachable? For a dependency or artifact advisory lead the package carries
advisory context from pinned feeds (NVD CVSS vector and weakness ids, CISA KEV listing, EPSS
percentile, OSV fixed versions). Treat it as reference context about the advisory: establish the
resolved version and any reachable use of the affected API from target evidence.

## Expected result
Zero or more proposals in the role's result schema. For every proposal, give per-predicate
evidence that names resolvable identities from the package or this cell's retrieval transcript.
When the lead does not hold in this stack, propose nothing and state which stack fact rules it out.
Account for the package lead exactly once: developed into a proposal, not developed by this lens
(never a statement that it is safe), or blocked by a named gap. Each proposal names its security
consequence from the closed vocabulary and its preconditions from the closed precondition
vocabulary. Label every taint hop by its basis: a hop resting on an accepted tool path, an accepted
graph fact, or source-mapped analysis cites it; an inferred hop stays a hypothesis, paired with an
evidence request and a gap.
