---
id: chain_composer
version: 1
roles: ["attack_chain_analyst"]
requests_tools: ["find", "read_excerpt", "resolve_evidence", "trace"]
max_tokens: 700
---
## Question
Which simple ordered paths through the supplied component claims could achieve one concrete
objective in this observed environment? Compose from the supplied components first: seed hints,
then admitted pairs whose predicates plausibly chain. Consider only the admitted pairs, which are
ordered for you. Seed hints are search suggestions, not evidence. Name the exact output and input
entities on each edge from the components' affected entities. Retrieve only to settle one specific
doubt about one edge; continuity is resolved by the application from accepted facts after you answer.

## Expected result
The chain-composer-result object: candidates with objective, component_claim_ids, edges
(output_entity and input_entity), prerequisites and rationale, plus named gaps.
Do not treat rationale as continuity proof. Empty candidates with explicit missing evidence are
appropriate when no meaningful path can be proposed. Identity, privilege, trust boundary,
artifact/deployment and temporal continuity are separate obligations.
