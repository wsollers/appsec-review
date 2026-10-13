---
id: control_gap
version: 2
roles: ["hypothesis_hunter"]
requests_tools: ["find", "query_owasp_workbench", "read_excerpt", "trace"]
max_tokens: 400
---
## Question
The accepted control-assessment result in the task input reports a control that failed or is
missing in this unit. What can an attacker do here because of that gap, and through which
concrete code path?

## Expected result
Zero or more hypotheses in the role's result schema with per-predicate evidence that names
resolvable identities. A control failure alone is not a weakness: show the affected construct and
the path. Known claims in the task input are not re-reported.
Account for every lead on the package menu exactly once; not developing a lead is never a
statement that it is safe. Each hypothesis names its security consequence from the closed
vocabulary. Label every taint hop by its basis: a hop resting on an accepted tool path, an accepted
graph fact, or source-mapped analysis cites it; an inferred hop stays a hypothesis, paired with an
evidence request and a gap.
