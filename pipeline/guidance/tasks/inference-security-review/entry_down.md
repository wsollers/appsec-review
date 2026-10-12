---
id: entry_down
version: 1
roles: ["hypothesis_hunter"]
requests_tools: ["find", "read_excerpt", "trace"]
max_tokens: 400
---
## Question
Follow the inputs of the entry point named in the task input inward through this unit. Where does
attacker-influenced data reach a security-relevant operation without an effective guard?

## Expected result
Zero or more hypotheses in the role's result schema with per-predicate evidence that names
resolvable identities. Known claims in the task input are not re-reported.
