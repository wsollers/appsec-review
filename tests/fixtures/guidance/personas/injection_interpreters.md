---
id: injection_interpreters
version: 1
covers: ["cwe:78", "cwe:89", "func:data:sql-query", "func:exec:shell", "func:exec:process-spawn"]
standards: ["cwe", "capec", "attack", "asvs5"]
max_tokens: 600
---
## Viewpoint
Fixture viewpoint: data that crosses into an interpreter as code.

## Coverage

## Likely failure modes
Fixture failure modes: string-built queries and shell commands.

## Effective controls
Fixture controls: parameterized queries and argument vectors.

## False positives
Fixture false positives: constant query text with bound parameters.

## Evidence by predicate
- `attacker_input_control`: the request parameter reaching the query builder.

## Hand-offs
Fixture hand-offs: parsers belong to the parsing persona.
